//! ECH (Encrypted Client Hello) TLS connection handling
//!
//! When the `ech` feature is enabled, this uses aws-lc-rs for HPKE support
//! and enables true ECH encryption of the SNI field.

use crate::dns::{DnsCacheRecord, DnsCacheStats, DnsResolver};
use crate::edge_pin::{EdgePin, Outcome, Route};
use crate::error::{DohProxyError, Result};
use crate::stats::STATS;
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
    /// 无 DoH resolver（enable_doh=false）或解析失败时回退系统 DNS（覆盖域名除外：
    /// 它们的系统 DNS 兜底在 lookup_ip 里、过了 CF 网段检查）。
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
                // 覆盖域名的系统 DNS 兜底和 CF 网段检查已在 lookup_ip 里做完：不再按域名直连
                Ok(_) if EdgePin::is_covered(host) => {
                    return Err(DohProxyError::Dns(format!("No IP found for {}", host)));
                }
                Err(e) if EdgePin::is_covered(host) => return Err(e),
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
        let _ = stream.set_nodelay(true);
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
        let result = self.connect_tcp_route_inner(host, port, edge, route).await;
        if result.is_ok() {
            STATS.tunnel_ok.inc();
        } else {
            STATS.tunnel_fail.inc();
        }
        result
    }

    async fn connect_tcp_route_inner(
        &self,
        host: &str,
        port: u16,
        edge: &EdgePin,
        route: &Route,
    ) -> Result<BoxStream> {
        let first = route.first;
        let (primary, secondary) = route.split();
        let mut primary_plan: Vec<IpAddr> = first.into_iter().collect();
        for ip in primary {
            if !primary_plan.contains(&ip) {
                primary_plan.push(ip);
            }
        }
        let secondary_plan: Vec<IpAddr> = secondary
            .into_iter()
            .filter(|ip| Some(*ip) != first)
            .collect();
        let head_start = first
            .map(|ip| race_head_start(edge.rtt(ip)))
            .unwrap_or(RACE_STAGGER);
        let tcp_race = |plan: Vec<IpAddr>, head_start: Duration| {
            race_staggered(
                plan.into_iter().map(|ip| SocketAddr::new(ip, port)).collect(),
                head_start,
                RACE_STAGGER,
                |addr| async move {
                    timed_tcp_connect(addr, ATTEMPT_TCP_TIMEOUT)
                        .await
                        .inspect_err(|e| warn!("Tunnel TCP connect to {} failed: {}", addr, e))
                },
            )
        };

        let mut failed = Vec::new();
        let mut result = Err(DohProxyError::Dns(format!("No reachable IP for {}", host)));
        let mut took_over = false;
        if !primary_plan.is_empty() {
            let outcome = tcp_race(primary_plan, head_start).await;
            failed.extend(outcome.failed);
            result = outcome.result;
        }
        if result.is_err() && !secondary_plan.is_empty() {
            let primary_tried = !failed.is_empty();
            let outcome = tcp_race(secondary_plan, RACE_STAGGER).await;
            failed.extend(outcome.failed);
            took_over = route.family_decided && primary_tried;
            if outcome.result.is_ok() || !primary_tried {
                result = outcome.result;
            }
        }
        if let Some(first) = first {
            if failed.iter().any(|addr| addr.ip() == first) {
                edge.report(host, first, Outcome::Failed);
            }
        }
        let (stream, addr, _) = result?;
        // 只到 TCP，没有可比的 RTT
        edge.report(
            host,
            addr.ip(),
            Outcome::Connected {
                rtt: None,
                took_over,
            },
        );
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
        timed_tcp_connect(addr, self.timeout).await
    }

    /// Connect to a server using ECH if available
    /// Returns a TLS stream that can be used for bidirectional I/O
    pub async fn connect(&self, host: &str, port: u16) -> Result<TlsStream<BoxStream>> {
        Self::counted(self.connect_inner(host, port, false))
            .await
            .map(|(stream, _)| stream)
    }

    /// Connect with HTTP/2 ALPN negotiation (for gateway reverse proxy)
    pub async fn connect_h2(&self, host: &str, port: u16) -> Result<TlsStream<BoxStream>> {
        Self::counted(self.connect_inner(host, port, true))
            .await
            .map(|(stream, _)| stream)
    }

    /// 同 [`Self::connect_h2`]，另给出对端地址（经上游代理时为 None）：连接池按它核对地址族
    pub async fn connect_h2_with_peer(
        &self,
        host: &str,
        port: u16,
    ) -> Result<(TlsStream<BoxStream>, Option<SocketAddr>)> {
        Self::counted(self.connect_inner(host, port, true)).await
    }

    async fn counted<T>(connect: impl std::future::Future<Output = Result<T>>) -> Result<T> {
        let start = std::time::Instant::now();
        let result = connect.await;
        match &result {
            Ok(_) => {
                STATS.connect_ok.inc();
                STATS.connect.record(start.elapsed());
            }
            Err(_) => STATS.connect_fail.inc(),
        }
        result
    }

    pub fn root_store(&self) -> &RootCertStore {
        &self.root_store
    }

    pub fn crypto_provider(&self) -> Arc<rustls::crypto::CryptoProvider> {
        self.crypto_provider.clone()
    }

    /// 采纳服务端给的新钥匙：写进 resolver 覆盖（6 h）并交给 Selector，返回钥匙
    #[cfg(feature = "ech")]
    fn adopt_retry_key(
        &self,
        host: &str,
        configs: Vec<u8>,
    ) -> rustls::pki_types::EchConfigListBytes<'static> {
        STATS.ech_retry_adopted.inc();
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
    ) -> Result<(TlsStream<BoxStream>, Option<SocketAddr>)> {
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
            return Ok((tls_stream, None));
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
            return Ok((tls_stream, None));
        }

        // 2. 赛跑建连：EdgePin 给的首选地址（覆盖域名的赢家 / 粘性 IP）先跑、领先一段时间，
        //    之后同族候选每 250 ms 起跑一个；任一失败立即放行下一个，任一成功立即中止其余。
        //    亲和已定时首选族整族失败才由另一族接管；未定时两族赛跑，赢家定亲和。
        //    ECH 被拒且带 retry_configs：中止整轮、采纳新钥匙后整轮重跑一次
        let edge = dns_resolver.edge_pin();
        let (resolved, mut resolve_error) = match ip_result {
            Ok(addrs) => (addrs, None),
            Err(e) => (Vec::new(), Some(e)),
        };
        #[allow(unused_mut)]
        let mut connector = connector;
        #[cfg(feature = "ech")]
        let mut ech_retried = false;
        loop {
            let result = self
                .race_route(
                    &connector,
                    &server_name,
                    host,
                    port,
                    edge,
                    &resolved,
                    &mut resolve_error,
                )
                .await;
            match result {
                Ok(won) => {
                    edge.report(
                        host,
                        won.addr.ip(),
                        Outcome::Connected {
                            rtt: Some(won.rtt),
                            took_over: won.took_over,
                        },
                    );
                    #[cfg(feature = "ech")]
                    {
                        let (_, conn) = won.stream.get_ref();
                        info!(
                            "Connected to {}:{} via {} (ECH status: {:?})",
                            host,
                            port,
                            won.addr,
                            conn.ech_status()
                        );
                    }
                    #[cfg(not(feature = "ech"))]
                    {
                        info!("Connected to {}:{} via {}", host, port, won.addr);
                    }
                    debug!(
                        "TLS connect to {}:{} completed in {} ms",
                        host,
                        port,
                        start.elapsed().as_millis()
                    );
                    return Ok((won.stream, Some(won.addr)));
                }
                #[cfg(feature = "ech")]
                Err(DohProxyError::EchRetry { configs, .. }) if !ech_retried => {
                    ech_retried = true;
                    let key = self.adopt_retry_key(host, configs);
                    let tls_config = self.get_or_build_tls_config(Some(&key)).await?;
                    connector = TlsConnector::from(Self::apply_alpn(tls_config, h2_alpn));
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// 一次建连的赛跑计划与执行（见 [`Self::connect_inner`] 第 2 步）。首选地址失败回报 EdgePin
    /// 一次（被别人赢下而中止的不算），成功由调用方回报
    #[allow(clippy::too_many_arguments)]
    async fn race_route(
        &self,
        connector: &TlsConnector,
        server_name: &ServerName<'static>,
        host: &str,
        port: u16,
        edge: &EdgePin,
        resolved: &[IpAddr],
        resolve_error: &mut Option<DohProxyError>,
    ) -> Result<Won> {
        let mut addrs = resolved.to_vec();
        // DoH 查不到时回退系统 DNS，不让请求直接失败。覆盖域名的系统 DNS 兜底和 CF 网段检查
        // 已在 lookup_ip 里做完，这里再查只会拿回假地址
        if addrs.is_empty() && !EdgePin::is_covered(host) {
            match resolve_error.as_ref() {
                Some(e) => warn!(
                    "DoH lookup failed for {} ({}), falling back to system DNS",
                    host, e
                ),
                None => warn!(
                    "DoH returned no IP for {}, falling back to system DNS",
                    host
                ),
            }
            match self.system_lookup_ip(host, port).await {
                Ok(system) => addrs = system,
                Err(e) if edge.route(host, Vec::new()).first.is_none() => return Err(e),
                Err(_) => {}
            }
        }
        // 地址族亲和：首次建连后固定出站地址族，所有域名共用，保证 cf_clearance
        // 绑定的出口 IP 在 linux.do 与其子域之间一致（见 edge_pin.rs）
        let route = edge.route(host, addrs);
        let first = route.first;
        let (primary, secondary) = route.split();
        let mut primary_plan: Vec<IpAddr> = first.into_iter().collect();
        for ip in primary {
            if !primary_plan.contains(&ip) {
                primary_plan.push(ip);
            }
        }
        let secondary_plan: Vec<IpAddr> = secondary
            .into_iter()
            .filter(|ip| Some(*ip) != first)
            .collect();
        if primary_plan.is_empty() && secondary_plan.is_empty() {
            return Err(resolve_error
                .take()
                .unwrap_or_else(|| DohProxyError::Dns(format!("No IP found for {}", host))));
        }
        let head_start = first
            .map(|ip| race_head_start(edge.rtt(ip)))
            .unwrap_or(RACE_STAGGER);
        let family_name = |is_ipv6: bool| if is_ipv6 { "IPv6" } else { "IPv4" };
        let tls_race = |plan: Vec<IpAddr>, head_start: Duration| {
            let connector = connector.clone();
            let server_name = server_name.clone();
            race_staggered(
                plan.into_iter().map(|ip| SocketAddr::new(ip, port)).collect(),
                head_start,
                RACE_STAGGER,
                move |addr| attempt_tls(connector.clone(), addr, server_name.clone()),
            )
        };

        let mut failed = Vec::new();
        let result = if primary_plan.is_empty() {
            // 某一族没有地址（如只有 AAAA 的域名）：直接连另一族，这不算亲和族失败
            let outcome = tls_race(secondary_plan, RACE_STAGGER).await;
            failed.extend(outcome.failed);
            outcome.result.map(|won| (won, false))
        } else if secondary_plan.is_empty() || route.family_decided {
            let outcome = tls_race(primary_plan, head_start).await;
            failed.extend(outcome.failed);
            match outcome.result {
                Ok(won) => Ok((won, false)),
                Err(e @ DohProxyError::EchRetry { .. }) => Err(e),
                Err(primary_err) if !secondary_plan.is_empty() => {
                    warn!(
                        "All {} addresses failed for {}:{} ({}), trying {}",
                        family_name(route.primary_is_v6),
                        host,
                        port,
                        primary_err,
                        family_name(!route.primary_is_v6)
                    );
                    let outcome = tls_race(secondary_plan, RACE_STAGGER).await;
                    failed.extend(outcome.failed);
                    match outcome.result {
                        // 亲和族整族连不上、由另一族接管：亲和跟着切换
                        Ok(won) => Ok((won, true)),
                        Err(e @ DohProxyError::EchRetry { .. }) => Err(e),
                        Err(secondary_err) => {
                            warn!(
                                "{} fallback also failed for {}:{}: {}",
                                family_name(!route.primary_is_v6),
                                host,
                                port,
                                secondary_err
                            );
                            Err(primary_err)
                        }
                    }
                }
                Err(e) => Err(e),
            }
        } else {
            // 亲和未定（首次建连）：Happy Eyeballs，另一族晚 50 ms 起跑，先连上的定亲和
            let primary_race = tls_race(primary_plan, head_start);
            let secondary_race = async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                tls_race(secondary_plan, RACE_STAGGER).await
            };
            tokio::pin!(primary_race, secondary_race);
            let mut primary_done: Option<DohProxyError> = None;
            let mut secondary_done: Option<DohProxyError> = None;
            loop {
                tokio::select! {
                    outcome = &mut primary_race, if primary_done.is_none() => {
                        failed.extend(outcome.failed);
                        match outcome.result {
                            Ok(won) => break Ok((won, false)),
                            Err(e @ DohProxyError::EchRetry { .. }) => break Err(e),
                            Err(e) => primary_done = Some(e),
                        }
                    }
                    outcome = &mut secondary_race, if secondary_done.is_none() => {
                        failed.extend(outcome.failed);
                        match outcome.result {
                            Ok(won) => break Ok((won, false)),
                            Err(e @ DohProxyError::EchRetry { .. }) => break Err(e),
                            Err(e) => secondary_done = Some(e),
                        }
                    }
                }
                if let (Some(_), Some(_)) = (&primary_done, &secondary_done) {
                    break Err(primary_done
                        .take()
                        .unwrap_or_else(|| DohProxyError::Proxy(format!("Failed to connect to {}:{}", host, port))));
                }
            }
        };

        // 首选地址（赢家 / 粘性 IP）这次确实失败了才记它一次；被别的候选赢下而中止的不算
        if let Some(first) = first {
            if failed.iter().any(|addr| addr.ip() == first) {
                warn!("First choice {} failed for {}:{}", first, host, port);
                edge.report(host, first, Outcome::Failed);
            }
        }
        result.map(|((stream, addr, rtt), took_over)| Won {
            stream,
            addr,
            rtt,
            took_over,
        })
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

    async fn finish_tls(
        &self,
        connector: &TlsConnector,
        server_name: ServerName<'static>,
        tcp_stream: BoxStream,
        host: &str,
        port: u16,
    ) -> Result<TlsStream<BoxStream>> {
        let start = std::time::Instant::now();
        let tls_stream =
            tokio::time::timeout(self.timeout, connector.connect(server_name, tcp_stream))
                .await
                .map_err(|_| DohProxyError::Timeout)
                .and_then(|result| result.map_err(DohProxyError::Io))
                .inspect_err(|_| STATS.tls_fail.inc())?;

        let (_, conn) = tls_stream.get_ref();
        crate::stats::record_handshake(conn, start.elapsed());
        debug!(
            "TLS connection established for {}:{}, protocol: {:?}",
            host,
            port,
            conn.protocol_version()
        );

        Ok(tls_stream)
    }
}

/// 同族候选之间的起跑间隔
const RACE_STAGGER: Duration = Duration::from_millis(250);
/// 单个地址的 TCP / TLS 超时
const ATTEMPT_TCP_TIMEOUT: Duration = Duration::from_secs(5);
const ATTEMPT_TLS_TIMEOUT: Duration = Duration::from_secs(10);
/// 首选地址的领先时间：它历史握手耗时的两倍，限制在 300 ms～1.5 s；没有记录时 600 ms
const HEAD_START_MIN: Duration = Duration::from_millis(300);
const HEAD_START_MAX: Duration = Duration::from_millis(1500);
const HEAD_START_DEFAULT: Duration = Duration::from_millis(600);

fn race_head_start(rtt: Option<Duration>) -> Duration {
    rtt.map(|rtt| (rtt * 2).clamp(HEAD_START_MIN, HEAD_START_MAX))
        .unwrap_or(HEAD_START_DEFAULT)
}

/// 赛跑赢下的连接
struct Won {
    stream: TlsStream<BoxStream>,
    addr: SocketAddr,
    /// 这次尝试本身的耗时（TCP + TLS），进 EdgePin 的 RTT 表
    rtt: Duration,
    took_over: bool,
}

/// 一轮赛跑的结果；`failed` 是确实失败了的地址（被中止的不在内）
pub(crate) struct RaceOutcome<T> {
    pub result: Result<(T, SocketAddr, Duration)>,
    pub failed: Vec<SocketAddr>,
}

/// 交错赛跑（Happy Eyeballs 的结构）：`addrs[0]` 立即起跑，领先 `head_start` 后其余按
/// `stagger` 间隔逐个起跑；任一失败立即放行下一个；任一成功立即中止其余（含没起跑的）。
/// 遇到 ECH 被拒（带 retry_configs）中止整轮返回，由调用方换钥匙重跑
pub(crate) async fn race_staggered<T, F, Fut>(
    addrs: Vec<SocketAddr>,
    head_start: Duration,
    stagger: Duration,
    attempt: F,
) -> RaceOutcome<T>
where
    T: Send + 'static,
    F: Fn(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = Result<T>> + Send + 'static,
{
    let mut pending: std::collections::VecDeque<SocketAddr> = addrs.into();
    let mut failed = Vec::new();
    let mut last_error: Option<DohProxyError> = None;
    let mut set = tokio::task::JoinSet::new();
    let spawn = |set: &mut tokio::task::JoinSet<_>, addr: SocketAddr| {
        STATS.race_spawned.inc();
        let attempt = attempt(addr);
        set.spawn(async move {
            let start = std::time::Instant::now();
            let result = attempt.await;
            (addr, result, start.elapsed())
        });
    };
    let Some(addr) = pending.pop_front() else {
        return RaceOutcome {
            result: Err(DohProxyError::Proxy("No addresses to connect".to_string())),
            failed,
        };
    };
    spawn(&mut set, addr);
    let mut next_at = tokio::time::Instant::now() + head_start;
    loop {
        tokio::select! {
            joined = set.join_next(), if !set.is_empty() => {
                let Some(joined) = joined else { continue };
                match joined {
                    Ok((addr, Ok(value), elapsed)) => {
                        for _ in 0..set.len() {
                            STATS.race_aborted.inc();
                        }
                        set.abort_all();
                        STATS.race_won.inc();
                        return RaceOutcome {
                            result: Ok((value, addr, elapsed)),
                            failed,
                        };
                    }
                    Ok((addr, Err(error), _)) => {
                        failed.push(addr);
                        if matches!(error, DohProxyError::EchRetry { .. }) {
                            set.abort_all();
                            return RaceOutcome {
                                result: Err(error),
                                failed,
                            };
                        }
                        last_error = Some(error);
                    }
                    Err(join_error) => {
                        last_error = Some(DohProxyError::Proxy(format!(
                            "connect task failed: {}",
                            join_error
                        )));
                    }
                }
                // 有人失败：下一个立即起跑，不等间隔
                if let Some(next) = pending.pop_front() {
                    spawn(&mut set, next);
                    next_at = tokio::time::Instant::now() + stagger;
                }
            }
            _ = tokio::time::sleep_until(next_at), if !pending.is_empty() => {
                if let Some(next) = pending.pop_front() {
                    spawn(&mut set, next);
                }
                next_at = tokio::time::Instant::now() + stagger;
            }
            else => break,
        }
    }
    RaceOutcome {
        result: Err(last_error
            .unwrap_or_else(|| DohProxyError::Proxy("All connection attempts failed".to_string()))),
        failed,
    }
}

/// 单个地址：TCP（5 s）+ TLS（10 s）。ECH 被拒且带 retry_configs 时返回 [`DohProxyError::EchRetry`]
async fn attempt_tls(
    connector: TlsConnector,
    addr: SocketAddr,
    server_name: ServerName<'static>,
) -> Result<TlsStream<BoxStream>> {
    let tcp = match timed_tcp_connect(addr, ATTEMPT_TCP_TIMEOUT).await {
        Ok(tcp) => tcp,
        Err(e) => {
            warn!("TCP connect to {} failed: {}", addr, e);
            return Err(e);
        }
    };
    let start = std::time::Instant::now();
    match tokio::time::timeout(
        ATTEMPT_TLS_TIMEOUT,
        connector.connect(server_name, Box::new(tcp) as BoxStream),
    )
    .await
    {
        Ok(Ok(stream)) => {
            crate::stats::record_handshake(stream.get_ref().1, start.elapsed());
            STATS.race_handshake_ok.inc();
            Ok(stream)
        }
        Ok(Err(e)) => {
            STATS.tls_fail.inc();
            match crate::probe::ech_retry_configs(&e).filter(|c| !c.is_empty()) {
                Some(configs) => {
                    warn!(
                        "ECH rejected by {} with retry_configs (public_name {:?})",
                        addr,
                        crate::probe::ech_public_names(&configs)
                    );
                    Err(DohProxyError::EchRetry {
                        addr,
                        configs: crate::probe::encode_ech_config_list(&configs)
                            .as_ref()
                            .to_vec(),
                    })
                }
                None => {
                    warn!("TLS handshake failed to {}: {}", addr, e);
                    Err(DohProxyError::Io(e))
                }
            }
        }
        Err(_) => {
            STATS.tls_fail.inc();
            warn!("TLS handshake timed out to {}", addr);
            Err(DohProxyError::Timeout)
        }
    }
}

/// 带超时的 TCP 连接（TCP_NODELAY），计入连通耗时 / 失败数
async fn timed_tcp_connect(addr: SocketAddr, timeout: Duration) -> Result<TcpStream> {
    let start = std::time::Instant::now();
    let result = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| DohProxyError::Timeout)
        .and_then(|result| result.map_err(DohProxyError::Io));
    match &result {
        Ok(stream) => {
            STATS.tcp_connect.record(start.elapsed());
            // 握手与小请求都是小包往返，关掉 Nagle
            let _ = stream.set_nodelay(true);
        }
        Err(_) => STATS.tcp_fail.inc(),
    }
    result
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

    fn race_addr(n: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::from([192, 0, 2, n]), 443)
    }

    /// 尝试被中止（future 被丢弃）时计数
    struct DropFlag(Arc<std::sync::atomic::AtomicUsize>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// 按地址末位给出假尝试：(多久之后, 成功与否)；None = 永不完成
    fn fake_race(
        plan: &'static [(u8, Option<(u64, bool)>)],
        started: Arc<parking_lot::Mutex<Vec<u8>>>,
        dropped: Arc<std::sync::atomic::AtomicUsize>,
    ) -> impl Fn(SocketAddr) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<u8>> + Send>>
    {
        move |addr: SocketAddr| {
            let started = started.clone();
            let dropped = dropped.clone();
            let n = match addr.ip() {
                IpAddr::V4(v4) => v4.octets()[3],
                IpAddr::V6(_) => 0,
            };
            let behavior = plan.iter().find(|(id, _)| *id == n).and_then(|(_, b)| *b);
            Box::pin(async move {
                started.lock().push(n);
                let _flag = DropFlag(dropped);
                match behavior {
                    Some((ms, ok)) => {
                        tokio::time::sleep(Duration::from_millis(ms)).await;
                        if ok {
                            Ok(n)
                        } else {
                            Err(DohProxyError::Timeout)
                        }
                    }
                    None => std::future::pending().await,
                }
            })
        }
    }

    /// 首选地址领先期内赢下：还在跑的候选被中止，没起跑的永不起跑
    #[tokio::test(start_paused = true)]
    async fn race_aborts_losers_and_never_starts_the_rest() {
        let started = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let dropped = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        static PLAN: [(u8, Option<(u64, bool)>); 3] = [(1, Some((300, true))), (2, None), (3, None)];
        let outcome = race_staggered(
            vec![race_addr(1), race_addr(2), race_addr(3)],
            Duration::from_millis(100),
            Duration::from_millis(250),
            fake_race(&PLAN, started.clone(), dropped.clone()),
        )
        .await;
        let (winner, addr, _) = outcome.result.unwrap();
        assert_eq!((winner, addr), (1, race_addr(1)));
        assert!(outcome.failed.is_empty());
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(*started.lock(), vec![1, 2]);
        assert_eq!(dropped.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    /// 首选地址失败立即放行下一个，不等领先期
    #[tokio::test(start_paused = true)]
    async fn race_failure_releases_the_next_candidate_immediately() {
        let started = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let dropped = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        static PLAN: [(u8, Option<(u64, bool)>); 2] = [(1, Some((10, false))), (2, Some((50, true)))];
        let begin = tokio::time::Instant::now();
        let outcome = race_staggered(
            vec![race_addr(1), race_addr(2)],
            Duration::from_millis(1000),
            Duration::from_millis(250),
            fake_race(&PLAN, started, dropped),
        )
        .await;
        assert_eq!(outcome.result.unwrap().0, 2);
        assert_eq!(outcome.failed, vec![race_addr(1)]);
        assert!(begin.elapsed() < Duration::from_millis(100), "{:?}", begin.elapsed());
    }

    /// 首选地址卡住：领先期一过下一个起跑；首选被中止，不算失败
    #[tokio::test(start_paused = true)]
    async fn race_head_start_bounds_a_stuck_first_choice() {
        let started = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let dropped = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        static PLAN: [(u8, Option<(u64, bool)>); 2] = [(1, None), (2, Some((10, true)))];
        let begin = tokio::time::Instant::now();
        let outcome = race_staggered(
            vec![race_addr(1), race_addr(2)],
            Duration::from_millis(600),
            Duration::from_millis(250),
            fake_race(&PLAN, started, dropped),
        )
        .await;
        assert_eq!(outcome.result.unwrap().0, 2);
        assert!(outcome.failed.is_empty());
        let elapsed = begin.elapsed();
        assert!(elapsed >= Duration::from_millis(600) && elapsed < Duration::from_millis(700), "{:?}", elapsed);
    }

    /// ECH 被拒（带 retry_configs）：整轮中止交给调用方换钥匙
    #[tokio::test(start_paused = true)]
    async fn race_stops_on_ech_retry() {
        let dropped = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let attempt = {
            let dropped = dropped.clone();
            move |addr: SocketAddr| {
                let dropped = dropped.clone();
                async move {
                    let _flag = DropFlag(dropped);
                    if addr == race_addr(1) {
                        tokio::time::sleep(Duration::from_millis(400)).await;
                        Err(DohProxyError::EchRetry {
                            addr,
                            configs: vec![1, 2, 3],
                        })
                    } else {
                        tokio::time::sleep(Duration::from_millis(1000)).await;
                        Ok(())
                    }
                }
            }
        };
        let outcome = race_staggered(
            vec![race_addr(1), race_addr(2)],
            Duration::from_millis(300),
            Duration::from_millis(250),
            attempt,
        )
        .await;
        assert!(matches!(outcome.result, Err(DohProxyError::EchRetry { .. })));
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(dropped.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn head_start_is_twice_the_handshake_time_within_bounds() {
        assert_eq!(race_head_start(None), Duration::from_millis(600));
        assert_eq!(race_head_start(Some(Duration::from_millis(50))), Duration::from_millis(300));
        assert_eq!(race_head_start(Some(Duration::from_millis(400))), Duration::from_millis(800));
        assert_eq!(race_head_start(Some(Duration::from_secs(3))), Duration::from_millis(1500));
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
