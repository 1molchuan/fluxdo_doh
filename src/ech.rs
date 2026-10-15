//! ECH (Encrypted Client Hello) TLS connection handling
//!
//! When the `ech` feature is enabled, this uses aws-lc-rs for HPKE support
//! and enables true ECH encryption of the SNI field.

use crate::dns::{DnsCacheRecord, DnsCacheStats, DnsResolver};
use crate::select::Selector;
use crate::error::{DohProxyError, Result};
use crate::upstream::connect_tunnel;
use crate::{BoxStream, UpstreamProxyConfig};
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, TlsConnector};
use tracing::{debug, info, warn};

#[cfg(feature = "ech")]
use rustls::client::EchConfig;

/// 服务端 retry_configs 给的新钥匙在 resolver 里覆盖多久
#[cfg(feature = "ech")]
const ECH_OVERRIDE_TTL_SECS: u64 = 21600;

/// ECH-enabled TLS connector
pub struct DohTlsConnector {
    dns_resolver: Option<Arc<DnsResolver>>,
    enable_doh: bool,
    root_store: RootCertStore,
    timeout: Duration,
    upstream_proxy: Option<UpstreamProxyConfig>,
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
    /// 用户指定的服务端 IP，跳过 DNS 解析
    server_ip: Option<std::net::IpAddr>,
    /// TLS ClientConfig 缓存，复用以启用 TLS 会话恢复
    tls_config_cache: Arc<tokio::sync::Mutex<std::collections::HashMap<String, Arc<ClientConfig>>>>,
}

impl DohTlsConnector {
    /// Create a new ECH connector
    pub fn new(
        dns_resolver: Option<Arc<DnsResolver>>,
        enable_doh: bool,
        timeout: Duration,
        upstream_proxy: Option<UpstreamProxyConfig>,
        server_ip: Option<String>,
    ) -> Self {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let crypto_provider = Arc::new(crate::tls_crypto::build_provider());

        let parsed_ip = server_ip
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .and_then(|s| {
                s.parse::<std::net::IpAddr>().ok().or_else(|| {
                    warn!("Invalid server_ip '{}', ignoring", s);
                    None
                })
            });

        Self {
            dns_resolver,
            enable_doh,
            root_store,
            timeout,
            upstream_proxy,
            crypto_provider,
            server_ip: parsed_ip,
            tls_config_cache: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    pub fn dns_cache_stats(&self) -> DnsCacheStats {
        self.dns_resolver
            .as_ref()
            .map(|resolver| resolver.cache_stats())
            .unwrap_or_default()
    }

    pub fn dns_cache_records(&self) -> Vec<DnsCacheRecord> {
        self.dns_resolver
            .as_ref()
            .map(|resolver| resolver.cache_records())
            .unwrap_or_default()
    }

    /// Establish raw TCP tunnel to target host
    ///
    /// 无上游代理时优先用 DoH 解析目标 IP（不经系统 DNS），逐个尝试连接；
    /// 无 DoH resolver（enable_doh=false）或解析失败时回退系统 DNS。
    /// CF 验证域名（challenges.cloudflare.com）以隧道方式直连时走此路径：
    /// 既保证与真 CF 端到端 TLS，又不把域名泄漏给系统 DNS。
    pub async fn connect_tcp(&self, host: &str, port: u16) -> Result<BoxStream> {
        // 有上游代理：交给上游隧道，由上游负责解析
        if let Some(proxy) = self
            .upstream_proxy
            .as_ref()
            .filter(|proxy| proxy.is_valid())
        {
            let stream = tokio::time::timeout(self.timeout, connect_tunnel(proxy, host, port))
                .await
                .map_err(|_| DohProxyError::Timeout)??;
            return Ok(stream);
        }

        // host 本身是 IP 字面量：直接连
        if let Ok(ip) = host.parse::<IpAddr>() {
            let stream = self.tcp_connect_addr(SocketAddr::new(ip, port)).await?;
            return Ok(Box::new(stream));
        }

        // 优先 DoH 解析（不走系统 DNS），按 RTT 排序后逐个尝试
        if let Some(resolver) = self.dns_resolver.as_ref() {
            match resolver.lookup_ip(host).await {
                Ok(addrs) if !addrs.is_empty() => {
                    let ordered = resolver.order_addrs_by_rtt(addrs);
                    let mut last_err: Option<DohProxyError> = None;
                    for ip in ordered {
                        match self.tcp_connect_addr(SocketAddr::new(ip, port)).await {
                            Ok(stream) => return Ok(Box::new(stream)),
                            Err(e) => {
                                warn!("Tunnel TCP connect to {} failed: {}", ip, e);
                                last_err = Some(e);
                            }
                        }
                    }
                    return Err(last_err.unwrap_or_else(|| {
                        DohProxyError::Dns(format!("No reachable IP for {}", host))
                    }));
                }
                Ok(_) => warn!(
                    "DoH returned no IP for {}, falling back to system DNS",
                    host
                ),
                Err(e) => warn!(
                    "DoH lookup failed for {} ({}), falling back to system DNS",
                    host, e
                ),
            }
        }

        // 回退系统 DNS（enable_doh=false 或 DoH 不可用）
        let stream = tokio::time::timeout(self.timeout, TcpStream::connect((host, port)))
            .await
            .map_err(|_| DohProxyError::Timeout)?
            .map_err(DohProxyError::Io)?;
        Ok(Box::new(stream))
    }

    /// 系统 DNS 解析（DoH 不可用时的回退）
    async fn system_lookup_ip(&self, host: &str, port: u16) -> Result<Vec<IpAddr>> {
        let addrs = tokio::time::timeout(self.timeout, tokio::net::lookup_host((host, port)))
            .await
            .map_err(|_| DohProxyError::Timeout)?
            .map_err(|e| {
                DohProxyError::Dns(format!("System DNS lookup failed for {}: {}", host, e))
            })?;
        let mut ips: Vec<IpAddr> = Vec::new();
        for addr in addrs {
            if !ips.contains(&addr.ip()) {
                ips.push(addr.ip());
            }
        }
        if ips.is_empty() {
            return Err(DohProxyError::Dns(format!("No IP found for {}", host)));
        }
        Ok(ips)
    }

    /// 连接单个已解析的地址（带超时）
    async fn tcp_connect_addr(&self, addr: SocketAddr) -> Result<TcpStream> {
        tokio::time::timeout(self.timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| DohProxyError::Timeout)?
            .map_err(DohProxyError::Io)
    }

    /// Connect to a server using ECH if available
    /// Returns a TLS stream that can be used for bidirectional I/O
    pub async fn connect(&self, host: &str, port: u16) -> Result<TlsStream<BoxStream>> {
        self.connect_inner(host, port, false).await
    }

    /// Connect with HTTP/2 ALPN negotiation (for gateway reverse proxy)
    pub async fn connect_h2(&self, host: &str, port: u16) -> Result<TlsStream<BoxStream>> {
        self.connect_inner(host, port, true).await
    }

    pub fn root_store(&self) -> &RootCertStore {
        &self.root_store
    }

    pub fn crypto_provider(&self) -> Arc<rustls::crypto::CryptoProvider> {
        self.crypto_provider.clone()
    }

    /// 优选覆盖的域名才拿全局 Selector
    fn selector_for_host(host: &str) -> Option<Arc<Selector>> {
        if !DnsResolver::is_covered_host(host) {
            return None;
        }
        Selector::global()
    }

    /// 从建连错误里取 ECH retry_configs：(地址, ECHConfigList 字节)
    #[cfg(feature = "ech")]
    fn ech_retry_from_err(error: &DohProxyError) -> Option<(Option<SocketAddr>, Vec<u8>)> {
        match error {
            DohProxyError::EchRetry { addr, configs } => Some((Some(*addr), configs.clone())),
            DohProxyError::Io(e) => crate::probe::ech_retry_configs(e)
                .filter(|configs| !configs.is_empty())
                .map(|configs| {
                    (
                        None,
                        crate::probe::encode_ech_config_list(&configs)
                            .as_ref()
                            .to_vec(),
                    )
                }),
            _ => None,
        }
    }

    /// 采纳服务端给的新钥匙：写进 resolver 覆盖（6 h）并交给 Selector，返回钥匙
    #[cfg(feature = "ech")]
    fn adopt_retry_key(
        &self,
        host: &str,
        configs: Vec<u8>,
    ) -> rustls::pki_types::EchConfigListBytes<'static> {
        let key = rustls::pki_types::EchConfigListBytes::from(configs);
        if let Some(resolver) = &self.dns_resolver {
            resolver.override_ech_config(
                host,
                key.clone(),
                Duration::from_secs(ECH_OVERRIDE_TTL_SECS),
            );
        }
        if let Some(selector) = Selector::global() {
            selector.adopt_ech_key(&key, crate::select::EchKeySource::RetryConfigs);
        }
        info!(
            "ECH retry_configs adopted for {}: {} bytes",
            host,
            key.as_ref().len()
        );
        key
    }

    fn apply_alpn(config: Arc<ClientConfig>, h2: bool) -> Arc<ClientConfig> {
        if !h2 {
            return config;
        }
        let mut cfg = (*config).clone();
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Arc::new(cfg)
    }

    async fn connect_inner(
        &self,
        host: &str,
        port: u16,
        h2_alpn: bool,
    ) -> Result<TlsStream<BoxStream>> {
        let start = std::time::Instant::now();
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|_| DohProxyError::InvalidUrl(format!("Invalid server name: {}", host)))?;

        if !self.enable_doh {
            info!(
                "DoH disabled for {}, using upstream/direct tunnel only",
                host
            );
            let tls_config = self
                .get_or_build_tls_config(
                    #[cfg(feature = "ech")]
                    None,
                )
                .await?;
            let connector = TlsConnector::from(Self::apply_alpn(tls_config, h2_alpn));
            let tcp_stream = self.connect_tcp(host, port).await?;
            let tls_stream = self
                .finish_tls(&connector, server_name, tcp_stream, host, port)
                .await?;
            debug!(
                "TLS connect to {}:{} completed in {} ms",
                host,
                port,
                start.elapsed().as_millis()
            );
            return Ok(tls_stream);
        }

        let dns_resolver = self
            .dns_resolver
            .as_ref()
            .ok_or_else(|| DohProxyError::Dns("DoH resolver is not initialized".to_string()))?;

        // 1. 并行查询 ECH 配置和 IP 地址
        let (ech_config, ip_result) = if self.server_ip.is_some() {
            // server_ip 已指定，只需查 ECH 配置
            let ech_result = match dns_resolver.lookup_ech_config(host).await {
                Ok(config) => config,
                Err(e) => {
                    warn!(
                        "ECH lookup failed for {}, proceeding without ECH: {}",
                        host, e
                    );
                    None
                }
            };
            (ech_result, Ok(vec![self.server_ip.unwrap()]))
        } else {
            dns_resolver.lookup_ech_and_ip(host).await
        };

        #[cfg(feature = "ech")]
        if ech_config.is_some() {
            info!("ECH config found for {}, enabling ECH", host);
        } else {
            info!("No ECH config for {}, using standard TLS", host);
        }

        #[cfg(not(feature = "ech"))]
        {
            let _ = &ech_config;
        }

        // Build TLS config (with or without ECH), 使用缓存以启用 TLS 会话恢复
        let tls_config = self
            .get_or_build_tls_config(
                #[cfg(feature = "ech")]
                ech_config.as_ref(),
            )
            .await?;
        let connector = TlsConnector::from(Self::apply_alpn(tls_config, h2_alpn));

        if self
            .upstream_proxy
            .as_ref()
            .filter(|proxy| proxy.is_valid())
            .is_some()
        {
            let tcp_stream = self.connect_tcp(host, port).await?;
            let tls_stream = self
                .finish_tls(&connector, server_name, tcp_stream, host, port)
                .await?;
            debug!(
                "TLS connect to {}:{} via upstream proxy completed in {} ms",
                host,
                port,
                start.elapsed().as_millis()
            );
            return Ok(tls_stream);
        }

        // 2. Prefer recently successful IP for this host (shared with query mode)
        //    preferred_host_ip 已按地址族亲和过滤：亲和切换前记下的另一族粘性 IP 不会再用
        let selector = Self::selector_for_host(host);
        let winner_ip = selector.as_ref().and_then(|s| s.winner_ip());
        // 优选有赢家：所有覆盖域名一律先连赢家，不看各自的粘性 IP 和当前地址族亲和。
        // cf_clearance 绑定出口 IP，双栈下 v4/v6 出口是两个地址，linux.do 与其子域
        // 必须是同一个边缘 IP、同一个地址族，否则必撞盾
        let sticky = match winner_ip {
            Some(winner) => Some(winner),
            None => dns_resolver.preferred_host_ip(host),
        };
        #[allow(unused_mut)]
        let mut connector = connector;
        if let Some(cached_addr) = sticky {
            let socket_addr = SocketAddr::new(cached_addr, port);
            debug!("Trying sticky IP for {}:{} via {}", host, port, socket_addr);
            #[allow(unused_mut)]
            let mut attempt = self
                .try_connect(&connector, socket_addr, host, server_name.clone())
                .await;
            // ECH 被拒且带 retry_configs：换钥匙后同地址重试一次
            #[cfg(feature = "ech")]
            if let Some((_, configs)) = attempt.as_ref().err().and_then(Self::ech_retry_from_err) {
                let key = self.adopt_retry_key(host, configs);
                if let Ok(tls_config) = self.get_or_build_tls_config(Some(&key)).await {
                    connector = TlsConnector::from(Self::apply_alpn(tls_config, h2_alpn));
                    attempt = self
                        .try_connect(&connector, socket_addr, host, server_name.clone())
                        .await;
                }
            }
            match attempt {
                Ok(stream) => {
                    if let Some(selector) = &selector {
                        selector.record_connect_result(socket_addr.ip(), true);
                    }
                    dns_resolver.record_host_success(host, socket_addr.ip());
                    dns_resolver.record_ip_rtt(socket_addr.ip(), start.elapsed());
                    // 赢家连通即把亲和强制定到赢家的地址族，后续所有域名跟着走
                    dns_resolver.record_family_affinity(socket_addr.ip(), winner_ip.is_some());
                    #[cfg(feature = "ech")]
                    {
                        let (_, conn) = stream.get_ref();
                        let ech_status = conn.ech_status();
                        info!(
                            "Connected to {}:{} via {} (ECH status: {:?})",
                            host, port, socket_addr, ech_status
                        );
                    }
                    #[cfg(not(feature = "ech"))]
                    {
                        info!("Connected to {}:{} via {}", host, port, socket_addr);
                    }
                    debug!(
                        "TLS connect to {}:{} completed in {} ms",
                        host,
                        port,
                        start.elapsed().as_millis()
                    );
                    return Ok(stream);
                }
                Err(e) => {
                    warn!(
                        "Sticky IP failed for {}:{} via {}: {}",
                        host, port, socket_addr, e
                    );
                    if let Some(selector) = &selector {
                        selector.record_connect_result(socket_addr.ip(), false);
                    }
                    dns_resolver.clear_preferred_host_ip(host);
                }
            }
        }

        // 3. 使用 IP 列表连接；DoH 查不到时回退系统 DNS，不让请求直接失败
        let addrs = match ip_result {
            Ok(addrs) if !addrs.is_empty() => addrs,
            Ok(_) => {
                warn!(
                    "DoH returned no IP for {}, falling back to system DNS",
                    host
                );
                self.system_lookup_ip(host, port).await?
            }
            Err(e) => {
                warn!(
                    "DoH lookup failed for {} ({}), falling back to system DNS",
                    host, e
                );
                self.system_lookup_ip(host, port).await?
            }
        };
        let addrs = dns_resolver.order_addrs_by_rtt(addrs);

        let (v6_addrs, v4_addrs): (Vec<_>, Vec<_>) =
            addrs.into_iter().partition(|addr| addr.is_ipv6());
        // 地址族亲和：首次建连后固定出站地址族，所有域名共用，保证 cf_clearance
        // 绑定的出口 IP 在 linux.do 与其子域之间一致（见 DnsResolver::family_affinity）
        let affinity = dns_resolver.family_affinity();
        let prefer_ipv6 = affinity.unwrap_or(dns_resolver.prefer_ipv6());
        let (primary, secondary) = if prefer_ipv6 {
            (v6_addrs, v4_addrs)
        } else {
            (v4_addrs, v6_addrs)
        };
        let family_name = |is_ipv6: bool| if is_ipv6 { "IPv6" } else { "IPv4" };

        // 某一族没有地址（如只有 AAAA 的域名）：直接连另一族，不做空赛跑——否则
        // 空族立刻报 "No addresses" 并盖掉另一族的真实错误。这不算亲和族失败。
        // 亲和已定：只连亲和族，整族失败才由另一族接管并切换亲和。
        // 亲和未定（首次建连）：Happy Eyeballs 两族赛跑，赢家确定亲和。
        // 结果里的 bool 表示「是在亲和族整族失败后由另一族接管」。
        let result = if primary.is_empty() {
            self.connect_to_addrs(&connector, server_name.clone(), host, port, secondary)
                .await
                .map(|ok| (ok, false))
        } else if secondary.is_empty() {
            self.connect_to_addrs(&connector, server_name.clone(), host, port, primary)
                .await
                .map(|ok| (ok, false))
        } else if affinity.is_some() {
            match self
                .connect_to_addrs(&connector, server_name.clone(), host, port, primary)
                .await
            {
                Ok(ok) => Ok((ok, false)),
                Err(primary_err) => {
                    warn!(
                        "All {} addresses failed for {}:{} ({}), trying {}",
                        family_name(prefer_ipv6),
                        host,
                        port,
                        primary_err,
                        family_name(!prefer_ipv6)
                    );
                    match self
                        .connect_to_addrs(&connector, server_name.clone(), host, port, secondary)
                        .await
                    {
                        Ok(ok) => Ok((ok, true)),
                        Err(secondary_err) => {
                            warn!(
                                "{} fallback also failed for {}:{}: {}",
                                family_name(!prefer_ipv6),
                                host,
                                port,
                                secondary_err
                            );
                            Err(primary_err)
                        }
                    }
                }
            }
        } else {
            let mut primary_fut = Box::pin(self.connect_to_addrs(
                &connector,
                server_name.clone(),
                host,
                port,
                primary,
            ));

            let mut secondary_fut = Box::pin(async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                self.connect_to_addrs(&connector, server_name.clone(), host, port, secondary)
                    .await
            });

            let mut primary_done = false;
            let mut secondary_done = false;
            let mut primary_err: Option<DohProxyError> = None;
            let mut secondary_err: Option<DohProxyError> = None;

            loop {
                tokio::select! {
                    res = &mut primary_fut, if !primary_done => {
                        primary_done = true;
                        match res {
                            Ok(ok) => break Ok((ok, false)),
                            Err(e) => {
                                primary_err = Some(e);
                                if secondary_done {
                                    break Err(primary_err.or(secondary_err).unwrap_or_else(|| {
                                        DohProxyError::Proxy(format!("Failed to connect to {}:{}", host, port))
                                    }));
                                }
                            }
                        }
                    }
                    res = &mut secondary_fut, if !secondary_done => {
                        secondary_done = true;
                        match res {
                            Ok(ok) => break Ok((ok, false)),
                            Err(e) => {
                                secondary_err = Some(e);
                                if primary_done {
                                    break Err(primary_err.or(secondary_err).unwrap_or_else(|| {
                                        DohProxyError::Proxy(format!("Failed to connect to {}:{}", host, port))
                                    }));
                                }
                            }
                        }
                    }
                }
            }
        };

        // 赛跑里有节点拒绝 ECH 并给了 retry_configs：采纳新钥匙后对该地址单次重试
        #[cfg(feature = "ech")]
        let result = match result {
            Err(DohProxyError::EchRetry { addr, configs }) => {
                let key = self.adopt_retry_key(host, configs);
                let tls_config = self.get_or_build_tls_config(Some(&key)).await?;
                let retry_connector = TlsConnector::from(Self::apply_alpn(tls_config, h2_alpn));
                let retry_start = std::time::Instant::now();
                self.try_connect(&retry_connector, addr, host, server_name.clone())
                    .await
                    .map(|stream| ((stream, addr, retry_start.elapsed()), false))
            }
            other => other,
        };

        match result {
            Ok(((stream, socket_addr, rtt), switched_family)) => {
                if let Some(selector) = &selector {
                    selector.record_connect_result(socket_addr.ip(), true);
                }
                dns_resolver.record_host_success(host, socket_addr.ip());
                dns_resolver.record_ip_rtt(socket_addr.ip(), rtt);
                dns_resolver.record_family_affinity(socket_addr.ip(), switched_family);
                #[cfg(feature = "ech")]
                {
                    let (_, conn) = stream.get_ref();
                    let ech_status = conn.ech_status();
                    info!(
                        "Connected to {}:{} via {} (ECH status: {:?})",
                        host, port, socket_addr, ech_status
                    );
                }
                #[cfg(not(feature = "ech"))]
                {
                    info!("Connected to {}:{} via {}", host, port, socket_addr);
                }
                debug!(
                    "TLS connect to {}:{} completed in {} ms",
                    host,
                    port,
                    start.elapsed().as_millis()
                );
                Ok(stream)
            }
            Err(e) => {
                // 赢家在列表首位先试过，整体失败就记它一次
                if let (Some(selector), Some(winner_ip)) = (&selector, winner_ip) {
                    selector.record_connect_result(winner_ip, false);
                }
                Err(e)
            }
        }
    }

    /// Build TLS config with optional ECH
    #[cfg(feature = "ech")]
    fn build_tls_config(
        &self,
        ech_config_bytes: Option<&rustls::pki_types::EchConfigListBytes<'static>>,
    ) -> Result<Arc<ClientConfig>> {
        use rustls::client::EchMode;

        if let Some(ech_bytes) = ech_config_bytes {
            // Try to parse and use ECH config
            let hpke_suites = rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;

            match EchConfig::new(ech_bytes.clone(), hpke_suites) {
                Ok(ech_config) => {
                    let ech_mode = EchMode::Enable(ech_config);

                    // with_ech sets TLS 1.3 implicitly (ECH requires TLS 1.3)
                    let config = ClientConfig::builder_with_provider(self.crypto_provider.clone())
                        .with_ech(ech_mode)
                        .map_err(|e| DohProxyError::Proxy(format!("ECH config error: {}", e)))?
                        .with_root_certificates(self.root_store.clone())
                        .with_no_client_auth();

                    return Ok(Arc::new(config));
                }
                Err(e) => {
                    warn!(
                        "Failed to parse ECH config, falling back to standard TLS: {}",
                        e
                    );
                }
            }
        }

        // Fall back to standard TLS 1.3
        let config = ClientConfig::builder_with_provider(self.crypto_provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(DohProxyError::Tls)?
            .with_root_certificates(self.root_store.clone())
            .with_no_client_auth();

        Ok(Arc::new(config))
    }

    /// Build TLS config without ECH support
    #[cfg(not(feature = "ech"))]
    fn build_tls_config(&self) -> Result<Arc<ClientConfig>> {
        let config = ClientConfig::builder_with_provider(self.crypto_provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(DohProxyError::Tls)?
            .with_root_certificates(self.root_store.clone())
            .with_no_client_auth();

        Ok(Arc::new(config))
    }

    /// 获取或构建 TLS 配置（带缓存，复用以启用 TLS 会话恢复）
    #[cfg(feature = "ech")]
    async fn get_or_build_tls_config(
        &self,
        ech_config_bytes: Option<&rustls::pki_types::EchConfigListBytes<'static>>,
    ) -> Result<Arc<ClientConfig>> {
        let cache_key = match ech_config_bytes {
            Some(bytes) => format!("ech:{:?}", bytes.as_ref()),
            None => "no_ech".to_string(),
        };

        {
            let cache = self.tls_config_cache.lock().await;
            if let Some(config) = cache.get(&cache_key) {
                return Ok(config.clone());
            }
        }

        let config = self.build_tls_config(ech_config_bytes)?;

        let mut cache = self.tls_config_cache.lock().await;
        cache.insert(cache_key, config.clone());
        // 限制缓存大小
        if cache.len() > 32 {
            let keys: Vec<String> = cache.keys().cloned().collect();
            if let Some(key) = keys.first() {
                cache.remove(key);
            }
        }

        Ok(config)
    }

    /// 获取或构建 TLS 配置（无 ECH 支持版本）
    #[cfg(not(feature = "ech"))]
    async fn get_or_build_tls_config(&self) -> Result<Arc<ClientConfig>> {
        let cache_key = "no_ech".to_string();

        {
            let cache = self.tls_config_cache.lock().await;
            if let Some(config) = cache.get(&cache_key) {
                return Ok(config.clone());
            }
        }

        let config = self.build_tls_config()?;

        let mut cache = self.tls_config_cache.lock().await;
        cache.insert(cache_key, config.clone());

        Ok(config)
    }

    /// Try to establish a TLS connection with separate TCP/TLS timeouts
    async fn try_connect(
        &self,
        connector: &TlsConnector,
        addr: SocketAddr,
        tunnel_host: &str,
        server_name: ServerName<'static>,
    ) -> Result<TlsStream<BoxStream>> {
        // TCP 连接阶段：5s 超时
        let tcp_stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr))
            .await
            .map_err(|_| DohProxyError::Timeout)?
            .map_err(DohProxyError::Io)?;

        // TLS 握手阶段：10s 超时
        tokio::time::timeout(
            Duration::from_secs(10),
            self.finish_tls(
                connector,
                server_name,
                Box::new(tcp_stream),
                tunnel_host,
                addr.port(),
            ),
        )
        .await
        .map_err(|_| DohProxyError::Timeout)?
    }

    /// 交错并行连接多个地址，每个地址间 250ms 延迟启动，先成功者胜出
    async fn connect_to_addrs(
        &self,
        connector: &TlsConnector,
        server_name: ServerName<'static>,
        host: &str,
        port: u16,
        addrs: Vec<std::net::IpAddr>,
    ) -> Result<(TlsStream<BoxStream>, SocketAddr, Duration)> {
        if addrs.is_empty() {
            return Err(DohProxyError::Proxy(format!(
                "No addresses for {}:{}",
                host, port
            )));
        }

        // 只有一个地址时直接连接
        if addrs.len() == 1 {
            let socket_addr = SocketAddr::new(addrs[0], port);
            debug!("Trying to connect to {}:{} via {}", host, port, socket_addr);
            let attempt_start = std::time::Instant::now();
            let stream = self
                .try_connect(connector, socket_addr, host, server_name)
                .await?;
            return Ok((stream, socket_addr, attempt_start.elapsed()));
        }

        // 多地址交错并行：每个地址延迟 250ms 启动
        use tokio::sync::mpsc;
        let (tx, mut rx) = mpsc::channel(1);
        let attempt_start = std::time::Instant::now();

        for (i, addr) in addrs.iter().enumerate() {
            let socket_addr = SocketAddr::new(*addr, port);
            let connector = connector.clone();
            let server_name = server_name.clone();
            let host = host.to_string();
            let tx = tx.clone();

            tokio::spawn(async move {
                if i > 0 {
                    tokio::time::sleep(Duration::from_millis(250 * i as u64)).await;
                }
                debug!("Trying to connect to {}:{} via {}", host, port, socket_addr);
                let start = std::time::Instant::now();
                // TCP 连接：5s 超时
                let tcp_result =
                    tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(socket_addr))
                        .await;
                let tcp_stream = match tcp_result {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        warn!("TCP connect failed to {}: {}", socket_addr, e);
                        let _ = tx.send(Err(DohProxyError::Io(e))).await;
                        return;
                    }
                    Err(_) => {
                        warn!("TCP connect timed out to {}", socket_addr);
                        let _ = tx.send(Err(DohProxyError::Timeout)).await;
                        return;
                    }
                };
                // TLS 握手：10s 超时
                let tls_result = tokio::time::timeout(
                    Duration::from_secs(10),
                    connector.connect(server_name, Box::new(tcp_stream) as BoxStream),
                )
                .await;
                match tls_result {
                    Ok(Ok(stream)) => {
                        let rtt = start.elapsed();
                        let _ = tx.send(Ok((stream, socket_addr, rtt))).await;
                    }
                    Ok(Err(e)) => {
                        match crate::probe::ech_retry_configs(&e).filter(|c| !c.is_empty()) {
                            Some(configs) => {
                                warn!(
                                    "ECH rejected by {} with retry_configs (public_name {:?})",
                                    socket_addr,
                                    crate::probe::ech_public_names(&configs)
                                );
                                let configs = crate::probe::encode_ech_config_list(&configs)
                                    .as_ref()
                                    .to_vec();
                                let _ = tx
                                    .send(Err(DohProxyError::EchRetry {
                                        addr: socket_addr,
                                        configs,
                                    }))
                                    .await;
                            }
                            None => {
                                warn!("TLS handshake failed to {}: {}", socket_addr, e);
                                let _ = tx.send(Err(DohProxyError::Io(e))).await;
                            }
                        }
                    }
                    Err(_) => {
                        warn!("TLS handshake timed out to {}", socket_addr);
                        let _ = tx.send(Err(DohProxyError::Timeout)).await;
                    }
                }
            });
        }
        drop(tx);

        let mut last_error = None;
        let total = addrs.len();
        let mut received = 0;
        while let Some(result) = rx.recv().await {
            received += 1;
            match result {
                Ok((stream, socket_addr, rtt)) => {
                    debug!(
                        "Connected to {}:{} via {} in {} ms",
                        host,
                        port,
                        socket_addr,
                        attempt_start.elapsed().as_millis()
                    );
                    return Ok((stream, socket_addr, rtt));
                }
                Err(e) => {
                    // ECH 被拒（带 retry_configs）优先保留，调用方据此换钥匙重试
                    if !matches!(last_error, Some(DohProxyError::EchRetry { .. })) {
                        last_error = Some(e);
                    }
                    if received >= total {
                        break;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            DohProxyError::Proxy(format!("Failed to connect to {}:{}", host, port))
        }))
    }

    async fn finish_tls(
        &self,
        connector: &TlsConnector,
        server_name: ServerName<'static>,
        tcp_stream: BoxStream,
        host: &str,
        port: u16,
    ) -> Result<TlsStream<BoxStream>> {
        let tls_stream =
            tokio::time::timeout(self.timeout, connector.connect(server_name, tcp_stream))
                .await
                .map_err(|_| DohProxyError::Timeout)?
                .map_err(|e| DohProxyError::Io(e))?;

        let (_, conn) = tls_stream.get_ref();
        debug!(
            "TLS connection established for {}:{}, protocol: {:?}",
            host,
            port,
            conn.protocol_version()
        );

        Ok(tls_stream)
    }
}
