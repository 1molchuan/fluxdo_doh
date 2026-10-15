//! ECH (Encrypted Client Hello) TLS connection handling
//!
//! When the `ech` feature is enabled, this uses aws-lc-rs for HPKE support
//! and enables true ECH encryption of the SNI field.

use crate::dns::{DnsCacheRecord, DnsCacheStats, DnsResolver};
use crate::edge_pin::{EdgePin, Outcome, Route};
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

    /// 建连用的 resolver（DoH 关闭时为 None）
    pub fn dns_resolver(&self) -> Option<&Arc<DnsResolver>> {
        self.dns_resolver.as_ref()
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
    /// 无上游代理时优先用 DoH 解析目标 IP（不经系统 DNS），按 EdgePin 排好的顺序逐个连接，
    /// 和 TLS 主路径同一套钉选：覆盖域名有赢家时先连赢家，其余先亲和族；结果回报给 EdgePin。
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

        // 优先 DoH 解析（不走系统 DNS），按 EdgePin 的计划逐个尝试
        if let Some(resolver) = self.dns_resolver.as_ref() {
            match resolver.lookup_ip(host).await {
                Ok(addrs) if !addrs.is_empty() => {
                    let edge = resolver.edge_pin();
                    let route = edge.route(host, addrs);
                    return self.connect_tcp_route(host, port, edge, &route).await;
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

    /// 按 EdgePin 的计划逐个连 TCP：先 `first`（赢家 / 粘性 IP），再首选族，
    /// 首选族整族连不上才轮到另一族（这时算接管，亲和跟着切换）
    async fn connect_tcp_route(
        &self,
        host: &str,
        port: u16,
        edge: &EdgePin,
        route: &Route,
    ) -> Result<BoxStream> {
        let mut last_err: Option<DohProxyError> = None;
        if let Some(ip) = route.first {
            match self.tcp_connect_addr(SocketAddr::new(ip, port)).await {
                Ok(stream) => {
                    // 只到 TCP，没有可比的 RTT
                    edge.report(
                        host,
                        ip,
                        Outcome::Connected {
                            rtt: None,
                            took_over: false,
                        },
                    );
                    return Ok(Box::new(stream));
                }
                Err(e) => {
                    warn!("Tunnel TCP connect to {} failed: {}", ip, e);
                    edge.report(host, ip, Outcome::Failed);
                    last_err = Some(e);
                }
            }
        }
        let (primary, secondary) = route.split();
        let primary_tried = !primary.is_empty()
            || route
                .first
                .is_some_and(|ip| ip.is_ipv6() == route.primary_is_v6);
        for ip in primary.iter().chain(secondary.iter()) {
            if Some(*ip) == route.first {
                continue;
            }
            match self.tcp_connect_addr(SocketAddr::new(*ip, port)).await {
                Ok(stream) => {
                    let took_over = route.family_decided
                        && primary_tried
                        && ip.is_ipv6() != route.primary_is_v6;
                    edge.report(
                        host,
                        *ip,
                        Outcome::Connected {
                            rtt: None,
                            took_over,
                        },
                    );
                    return Ok(Box::new(stream));
                }
                Err(e) => {
                    warn!("Tunnel TCP connect to {} failed: {}", ip, e);
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| DohProxyError::Dns(format!("No reachable IP for {}", host))))
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
        if let Some(selector) = crate::select::Selector::global() {
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

        // 2. 先单独试 EdgePin 给的首选地址：覆盖域名有赢家时是赢家（不看各自的粘性 IP
        //    和当前地址族亲和），否则是该域名验证过、与亲和族一致的粘性 IP
        let edge = dns_resolver.edge_pin();
        let doh_addrs = match &ip_result {
            Ok(addrs) => addrs.clone(),
            Err(_) => Vec::new(),
        };
        let route = edge.route(host, doh_addrs);
        let pinned_winner = route.first.filter(|_| route.pinned);
        #[allow(unused_mut)]
        let mut connector = connector;
        if let Some(cached_addr) = route.first {
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
                    // 经赢家连通时 EdgePin 把亲和强制定到赢家的地址族，后续所有域名跟着走
                    edge.report(
                        host,
                        socket_addr.ip(),
                        Outcome::Connected {
                            rtt: Some(start.elapsed()),
                            took_over: false,
                        },
                    );
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
                    edge.report(host, socket_addr.ip(), Outcome::Failed);
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
        // 失败回报后重新问一次：亲和可能刚被别的连接改过。
        // 地址族亲和：首次建连后固定出站地址族，所有域名共用，保证 cf_clearance
        // 绑定的出口 IP 在 linux.do 与其子域之间一致（见 edge_pin.rs）
        let route = edge.route(host, addrs);
        let (primary, secondary) = route.split();
        let prefer_ipv6 = route.primary_is_v6;
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
        } else if route.family_decided {
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
                edge.report(
                    host,
                    socket_addr.ip(),
                    Outcome::Connected {
                        rtt: Some(rtt),
                        took_over: switched_family,
                    },
                );
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
                if let Some(winner_ip) = pinned_winner {
                    edge.report(host, winner_ip, Outcome::Failed);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge_pin::Pin;
    use tokio::net::TcpListener;

    async fn connector() -> (DohTlsConnector, Arc<EdgePin>) {
        let resolver = Arc::new(
            DnsResolver::with_resolver_config(
                hickory_resolver::config::ResolverConfig::new(),
                false,
            )
            .await
            .unwrap(),
        );
        let edge = resolver.edge_pin().clone();
        let connector =
            DohTlsConnector::new(Some(resolver), true, Duration::from_secs(2), None, None);
        (connector, edge)
    }

    /// 隧道（connect_tcp）与 TLS 主路径同一套钉选：覆盖域名有赢家就连赢家，连通回报给 EdgePin
    /// （粘性 IP、亲和）；赢家连不上计入它的连败
    #[tokio::test]
    async fn tunnel_to_covered_host_goes_through_edge_pin() {
        let winner: IpAddr = "127.0.0.1".parse().unwrap();
        let listener = TcpListener::bind((winner, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { while listener.accept().await.is_ok() {} });
        let (connector, edge) = connector().await;
        edge.set_pin(Pin::Winner(winner));

        connector
            .connect_tcp("connect.linux.do", port)
            .await
            .unwrap();
        assert_eq!(edge.sticky("connect.linux.do"), Some(winner));
        assert_eq!(edge.affinity(), Some(false));

        // 换一个没人监听的端口：赢家连不上，计一次连败
        let closed = TcpListener::bind((winner, 0)).await.unwrap();
        let closed_port = closed.local_addr().unwrap().port();
        drop(closed);
        assert!(connector
            .connect_tcp("cdk.linux.do", closed_port)
            .await
            .is_err());
        assert_eq!(edge.winner_fail_streak(), 1);
    }
}
