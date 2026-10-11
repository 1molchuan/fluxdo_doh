//! DNS resolver with DOH and HTTPS record support for ECH config retrieval

use crate::error::{DohProxyError, Result};
use crate::UpstreamProxyConfig;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    proto::rr::rdata::HTTPS,
    TokioAsyncResolver,
};
use http::Uri;
use parking_lot::RwLock;
use reqwest::Client;
use rustls::pki_types::EchConfigListBytes;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::net::lookup_host;
use tokio::sync::{Mutex, Notify, RwLock as AsyncRwLock};
use tracing::{debug, info, warn};

/// 缓存条目上限
const MAX_CACHE_SIZE: usize = 1000;
/// TTL 下限（秒）
const MIN_TTL_SECS: u64 = 60;
/// TTL 上限（秒）
const MAX_TTL_SECS: u64 = 1800;
/// 默认 TTL（秒），无法获取时使用
const DEFAULT_TTL_SECS: u64 = 300;
/// 每隔多少次查询清理一次过期缓存
const CLEANUP_INTERVAL: u64 = 100;
/// 成功连通后的 host -> ip 粘性缓存时长
const STICKY_IP_TTL_SECS: u64 = 600;
/// ECH 负结果（确定无 ECH）缓存时长，取短值以便域名启用 ECH 后尽快生效
const ECH_NEGATIVE_TTL_SECS: u64 = 60;
/// 有备用节点时，主客户端（系统 DNS）的连接超时（含 DNS 解析和 TLS 握手），超时即改走备用节点
const DOH_PRIMARY_CONNECT_TIMEOUT_SECS: u64 = 3;
/// 备用节点客户端的连接超时，按节点数平分到每个 IP
const DOH_BOOTSTRAP_CONNECT_TIMEOUT_SECS: u64 = 4;
/// 主客户端失败、备用节点成功后，优先走备用节点的时长；到期后重新先试系统 DNS
const DOH_BOOTSTRAP_PREFER_SECS: u64 = 600;
/// DoH 服务器连续这么多次连不上（期间没有任何响应）就暂停使用，查询直接失败、由调用方回退系统 DNS
const DOH_FAILURES_BEFORE_COOLDOWN: u32 = 4;
/// DoH 服务器暂停使用的时长，到期后再试
const DOH_COOLDOWN_SECS: u64 = 30;
/// 同域名并发查询时，跟随者等待领头查询的上限，避免错过通知后一直挂起
const INFLIGHT_WAIT_TIMEOUT_SECS: u64 = 15;

static SHARED_RESOLVERS: OnceLock<Arc<AsyncRwLock<HashMap<String, Arc<DnsResolver>>>>> =
    OnceLock::new();

/// DoH 服务器域名 -> 备用节点 IP，由启动配置登记
static DOH_BOOTSTRAP_IPS: OnceLock<RwLock<HashMap<String, Vec<IpAddr>>>> = OnceLock::new();

/// DoH 上游。主客户端用系统 DNS 解析 DoH 域名；登记了备用节点 IP 时另建一个直连节点的客户端
/// （只替换连接地址，SNI 和 Host 不变），主客户端连不上时改用它重试。
#[derive(Clone)]
struct DohUpstream {
    uri: Uri,
    client: Client,
    bootstrap_client: Option<Client>,
    health: Arc<parking_lot::Mutex<DohUpstreamHealth>>,
}

#[derive(Default)]
struct DohUpstreamHealth {
    /// 在此时间之前先走备用节点，避免每次查询都先等系统 DNS 失败
    prefer_bootstrap_until: Option<std::time::Instant>,
    /// 连续连不上的次数，收到任何 HTTP 响应即清零
    consecutive_failures: u32,
    /// 在此时间之前不再请求 DoH 服务器
    cooldown_until: Option<std::time::Instant>,
}

impl DohUpstream {
    fn new(uri: Uri, client: Client, bootstrap_client: Option<Client>) -> Self {
        Self {
            uri,
            client,
            bootstrap_client,
            health: Arc::new(parking_lot::Mutex::new(DohUpstreamHealth::default())),
        }
    }

    async fn get(&self, url: &str) -> Result<reqwest::Response> {
        let (bootstrap_first, cooling_down) = {
            let health = self.health.lock();
            let now = std::time::Instant::now();
            (
                health
                    .prefer_bootstrap_until
                    .is_some_and(|until| until > now),
                health.cooldown_until.is_some_and(|until| until > now),
            )
        };
        if cooling_down {
            return Err(DohProxyError::Dns(format!(
                "DoH server {} is cooling down after repeated failures",
                self.uri.host().unwrap_or_default()
            )));
        }

        let result = self.send_with_fallback(url, bootstrap_first).await;

        let mut health = self.health.lock();
        let now = std::time::Instant::now();
        match result {
            Ok((response, used_bootstrap)) => {
                health.consecutive_failures = 0;
                health.cooldown_until = None;
                if used_bootstrap != bootstrap_first {
                    health.prefer_bootstrap_until = used_bootstrap
                        .then(|| now + Duration::from_secs(DOH_BOOTSTRAP_PREFER_SECS));
                }
                Ok(response)
            }
            Err(error) => {
                health.consecutive_failures += 1;
                if health.consecutive_failures >= DOH_FAILURES_BEFORE_COOLDOWN {
                    warn!(
                        "DoH server {} failed {} times in a row, pausing for {}s",
                        self.uri.host().unwrap_or_default(),
                        health.consecutive_failures,
                        DOH_COOLDOWN_SECS
                    );
                    health.cooldown_until = Some(now + Duration::from_secs(DOH_COOLDOWN_SECS));
                }
                Err(DohProxyError::Dns(format!("DoH GET failed: {}", error)))
            }
        }
    }

    /// 返回响应以及是否经由备用节点
    async fn send_with_fallback(
        &self,
        url: &str,
        bootstrap_first: bool,
    ) -> std::result::Result<(reqwest::Response, bool), reqwest::Error> {
        let send = |client: &Client| {
            client
                .get(url)
                .header("accept", "application/dns-message")
                .send()
        };
        let Some(bootstrap_client) = self.bootstrap_client.as_ref() else {
            return send(&self.client).await.map(|response| (response, false));
        };

        let (first, second) = if bootstrap_first {
            (bootstrap_client, &self.client)
        } else {
            (&self.client, bootstrap_client)
        };
        match send(first).await {
            Ok(response) => Ok((response, bootstrap_first)),
            // 只有连接层失败才换路；HTTP 错误码说明服务器已连通，换节点也一样
            Err(error) => {
                warn!(
                    "DoH GET via {} failed, retrying via {}: {}",
                    if bootstrap_first {
                        "bootstrap IPs"
                    } else {
                        "system DNS"
                    },
                    if bootstrap_first {
                        "system DNS"
                    } else {
                        "bootstrap IPs"
                    },
                    error
                );
                send(second)
                    .await
                    .map(|response| (response, !bootstrap_first))
            }
        }
    }
}

/// DNS resolver with ECH config caching
pub struct DnsResolver {
    resolver: TokioAsyncResolver,
    // IP 解析用（A/AAAA 查询）
    doh_ip: Option<DohUpstream>,
    force_doh_get_ip: bool,
    // ECH 配置用（HTTPS 记录查询）
    doh_ech: Option<DohUpstream>,
    force_doh_get_ech: bool,
    /// Cache for ECH configs (domain -> ECHConfigList)
    ech_cache: Arc<RwLock<HashMap<String, CachedEchConfig>>>,
    /// 确定无 ECH 的域名负缓存 (domain -> 过期时间)，避免每次 connect 重查 HTTPS 记录
    ech_negative_cache: Arc<RwLock<HashMap<String, std::time::Instant>>>,
    /// Cache for IP addresses
    ip_cache: Arc<RwLock<HashMap<String, CachedIpAddrs>>>,
    ech_inflight: Arc<Mutex<HashMap<String, Arc<Notify>>>>,
    ip_inflight: Arc<Mutex<HashMap<String, Arc<Notify>>>>,
    ip_rtt_cache: Arc<RwLock<HashMap<IpAddr, CachedIpRtt>>>,
    preferred_host_ip_cache: Arc<RwLock<HashMap<String, CachedPreferredHostIp>>>,
    prefer_ipv6: bool,
    resolve_timeout: Duration,
    /// 查询计数器，用于定期清理缓存
    query_count: AtomicU64,
}

pub struct LookupHostResult {
    pub addrs: Vec<IpAddr>,
    pub ech_config: Option<EchConfigListBytes<'static>>,
    pub preferred_ip: Option<IpAddr>,
    pub ttl: Duration,
}

#[derive(Default, Clone, Copy)]
pub struct DnsCacheStats {
    pub resolver_count: usize,
    pub host_count: usize,
    pub ip_count: usize,
    pub ech_count: usize,
    pub ech_negative_count: usize,
    pub ip_rtt_count: usize,
    pub preferred_ip_count: usize,
}

impl DnsCacheStats {
    pub fn total_entries(&self) -> usize {
        self.ip_count
            + self.ech_count
            + self.ech_negative_count
            + self.ip_rtt_count
            + self.preferred_ip_count
    }
}

pub struct DnsCacheRecord {
    pub host: String,
    pub kind: &'static str,
    pub values: Vec<String>,
    pub ttl_ms: u64,
}

struct CachedEchConfig {
    config: EchConfigListBytes<'static>,
    expires_at: std::time::Instant,
}

struct CachedIpAddrs {
    addrs: Vec<IpAddr>,
    expires_at: std::time::Instant,
}

struct CachedIpRtt {
    rtt_ms: u128,
    expires_at: std::time::Instant,
}

struct CachedPreferredHostIp {
    addr: IpAddr,
    expires_at: std::time::Instant,
}

/// HTTPS 记录中提取的 hint 信息
#[derive(Default)]
pub struct HttpsHints {
    pub ech_config: Option<EchConfigListBytes<'static>>,
    pub ipv4_hints: Vec<IpAddr>,
    pub ipv6_hints: Vec<IpAddr>,
}

impl DnsResolver {
    fn shared_cache_key(
        doh_url: &str,
        doh_url_ech: Option<&str>,
        prefer_ipv6: bool,
        upstream_proxy: Option<&UpstreamProxyConfig>,
    ) -> String {
        let upstream_key = upstream_proxy
            .map(UpstreamProxyConfig::cache_key)
            .unwrap_or_default();
        let bootstrap_key = |url: Option<&str>| {
            url.map(Self::bootstrap_ips_for_url)
                .unwrap_or_default()
                .iter()
                .map(IpAddr::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };
        // 备用节点变化后要换新的 resolver，所以也纳入 key
        format!(
            "{}|{}|{}|{}|{}|{}",
            doh_url,
            doh_url_ech.unwrap_or(""),
            if prefer_ipv6 { "v6" } else { "v4" },
            upstream_key,
            bootstrap_key(Some(doh_url)),
            bootstrap_key(doh_url_ech),
        )
    }

    fn bootstrap_registry() -> &'static RwLock<HashMap<String, Vec<IpAddr>>> {
        DOH_BOOTSTRAP_IPS.get_or_init(|| RwLock::new(HashMap::new()))
    }

    fn doh_url_host(doh_url: &str) -> Option<String> {
        let uri: Uri = doh_url.trim().parse().ok()?;
        uri.host()
            .map(|host| host.trim_matches(['[', ']']).to_ascii_lowercase())
    }

    /// 登记 DoH 服务器的备用节点 IP（按 DoH 域名）；ips 为空时取消登记。
    /// 系统 DNS 解析不出或连不上 DoH 域名时，直连这些 IP（SNI 不变）。
    pub fn set_bootstrap_ips(doh_url: &str, ips: &[String]) {
        let Some(host) = Self::doh_url_host(doh_url) else {
            return;
        };
        let parsed: Vec<IpAddr> = ips
            .iter()
            .filter_map(|ip| match ip.trim().parse::<IpAddr>() {
                Ok(ip) => Some(ip),
                Err(_) => {
                    warn!("Ignoring invalid DoH bootstrap IP for {}: {}", host, ip);
                    None
                }
            })
            .collect();

        let mut registry = Self::bootstrap_registry().write();
        if parsed.is_empty() {
            registry.remove(&host);
        } else {
            info!("DoH bootstrap IPs for {}: {:?}", host, parsed);
            registry.insert(host, parsed);
        }
    }

    fn bootstrap_ips_for_url(doh_url: &str) -> Vec<IpAddr> {
        Self::doh_url_host(doh_url)
            .and_then(|host| Self::bootstrap_registry().read().get(&host).cloned())
            .unwrap_or_default()
    }

    fn shared_resolver_holder() -> &'static Arc<AsyncRwLock<HashMap<String, Arc<DnsResolver>>>> {
        SHARED_RESOLVERS.get_or_init(|| Arc::new(AsyncRwLock::new(HashMap::new())))
    }

    pub async fn shared(
        doh_url: &str,
        doh_url_ech: Option<&str>,
        prefer_ipv6: bool,
        upstream_proxy: Option<UpstreamProxyConfig>,
    ) -> Result<Arc<Self>> {
        let normalized_doh_url_ech = doh_url_ech.filter(|value| *value != doh_url);
        let cache_key = Self::shared_cache_key(
            doh_url,
            normalized_doh_url_ech,
            prefer_ipv6,
            upstream_proxy.as_ref(),
        );

        {
            let guard = Self::shared_resolver_holder().read().await;
            if let Some(resolver) = guard.get(&cache_key) {
                return Ok(resolver.clone());
            }
        }

        let resolver = Arc::new(
            Self::new(
                doh_url,
                normalized_doh_url_ech,
                prefer_ipv6,
                upstream_proxy.clone(),
            )
            .await?,
        );

        let mut guard = Self::shared_resolver_holder().write().await;
        Ok(guard
            .entry(cache_key)
            .or_insert_with(|| resolver.clone())
            .clone())
    }

    pub async fn clear_shared_caches() {
        let guard = Self::shared_resolver_holder().read().await;
        for resolver in guard.values() {
            resolver.clear_all_caches();
        }
    }

    pub async fn shared_cache_stats() -> DnsCacheStats {
        let guard = Self::shared_resolver_holder().read().await;
        let mut stats = DnsCacheStats {
            resolver_count: guard.len(),
            ..Default::default()
        };
        for resolver in guard.values() {
            let item = resolver.cache_stats();
            stats.host_count += item.host_count;
            stats.ip_count += item.ip_count;
            stats.ech_count += item.ech_count;
            stats.ech_negative_count += item.ech_negative_count;
            stats.ip_rtt_count += item.ip_rtt_count;
            stats.preferred_ip_count += item.preferred_ip_count;
        }
        stats
    }

    pub async fn shared_cache_records() -> Vec<DnsCacheRecord> {
        let guard = Self::shared_resolver_holder().read().await;
        let mut records = Vec::new();
        for resolver in guard.values() {
            records.extend(resolver.cache_records());
        }
        records
    }

    /// Create a new DNS resolver using Cloudflare DOH
    pub async fn new_cloudflare(prefer_ipv6: bool) -> Result<Self> {
        Self::with_resolver_config(ResolverConfig::cloudflare_https(), prefer_ipv6).await
    }

    /// Create a new DNS resolver with custom DOH server URL
    ///
    /// Supported URL formats:
    /// - `https://dns.example.com/dns-query` - Custom DOH server
    /// - `cloudflare` - Use Cloudflare DOH
    /// - `google` - Use Google DOH
    /// - `quad9` - Use Quad9 DOH
    ///
    /// `doh_url_ech` specifies a separate DOH server for ECH config (HTTPS records).
    /// When None, ECH queries use the same server as DNS queries.
    pub async fn new(
        doh_url: &str,
        doh_url_ech: Option<&str>,
        prefer_ipv6: bool,
        upstream_proxy: Option<UpstreamProxyConfig>,
    ) -> Result<Self> {
        let bootstrap_ips = Self::bootstrap_ips_for_url(doh_url);
        let (config, doh_uri_ip) =
            Self::parse_doh_url(doh_url, prefer_ipv6, &bootstrap_ips).await?;
        let mut resolver = Self::with_resolver_config(config, prefer_ipv6).await?;
        if let Some(uri) = doh_uri_ip {
            let upstream = Self::build_doh_upstream(
                uri,
                &bootstrap_ips,
                resolver.resolve_timeout,
                upstream_proxy.as_ref(),
            )?;
            resolver.doh_ip = Some(upstream.clone());
            resolver.force_doh_get_ip = true;

            // ECH 客户端：如果指定了独立 URL 则解析，否则复用 IP 客户端配置
            if let Some(ech_url) = doh_url_ech {
                let ech_bootstrap_ips = Self::bootstrap_ips_for_url(ech_url);
                match Self::parse_doh_url(ech_url, prefer_ipv6, &ech_bootstrap_ips).await {
                    Ok((_, Some(ech_uri))) => {
                        resolver.doh_ech = Some(Self::build_doh_upstream(
                            ech_uri,
                            &ech_bootstrap_ips,
                            resolver.resolve_timeout,
                            upstream_proxy.as_ref(),
                        )?);
                    }
                    Ok((_, None)) => {
                        // ECH URL 解析未产生 URI（不应发生），回退复用
                        resolver.doh_ech = Some(upstream);
                    }
                    Err(e) => {
                        // ECH 服务器不可用不影响 IP 解析，回退复用
                        warn!(
                            "ECH DoH server {} unavailable, reusing DNS server: {}",
                            ech_url, e
                        );
                        resolver.doh_ech = Some(upstream);
                    }
                }
            } else {
                // 未指定独立 ECH 服务器，复用 IP 客户端
                resolver.doh_ech = Some(upstream);
            }
            resolver.force_doh_get_ech = true;
        }
        Ok(resolver)
    }

    /// Parse DOH URL to ResolverConfig
    async fn parse_doh_url(
        doh_url: &str,
        prefer_ipv6: bool,
        bootstrap_ips: &[IpAddr],
    ) -> Result<(ResolverConfig, Option<Uri>)> {
        use hickory_resolver::config::{NameServerConfig, NameServerConfigGroup, Protocol};
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        // Handle built-in providers
        let url_lower = doh_url.to_lowercase();

        // Cloudflare
        if url_lower == "cloudflare" || url_lower.contains("cloudflare-dns.com") {
            info!("Using Cloudflare DOH");
            return Ok((
                ResolverConfig::cloudflare_https(),
                Some("https://cloudflare-dns.com/dns-query".parse().unwrap()),
            ));
        }

        // Google
        if url_lower == "google" || url_lower.contains("dns.google") {
            info!("Using Google DOH");
            return Ok((
                ResolverConfig::google_https(),
                Some("https://dns.google/dns-query".parse().unwrap()),
            ));
        }

        // Quad9
        if url_lower == "quad9" || url_lower.contains("dns.quad9.net") {
            info!("Using Quad9 DOH");
            return Ok((
                ResolverConfig::quad9_https(),
                Some("https://dns.quad9.net/dns-query".parse().unwrap()),
            ));
        }

        // DNSPod (doh.pub)
        if url_lower.contains("doh.pub") {
            info!("Using DNSPod DOH");
            // DNSPod DOH: 1.12.12.12, 120.53.53.53
            let mut group = NameServerConfigGroup::new();
            for ip in &["1.12.12.12", "120.53.53.53"] {
                if let Ok(addr) = ip.parse::<Ipv4Addr>() {
                    group.push(NameServerConfig {
                        socket_addr: SocketAddr::new(IpAddr::V4(addr), 443),
                        protocol: Protocol::Https,
                        tls_dns_name: Some("doh.pub".to_string()),
                        trust_negative_responses: true,
                        tls_config: None,
                        bind_addr: None,
                    });
                }
            }
            return Ok((
                ResolverConfig::from_parts(None, vec![], group),
                Some("https://doh.pub/dns-query".parse().unwrap()),
            ));
        }

        // Tencent DNS (dns.pub)
        if url_lower.contains("dns.pub") {
            info!("Using Tencent DOH");
            // Tencent DOH: 119.29.29.29, 119.28.28.28
            let mut group = NameServerConfigGroup::new();
            for ip in &["119.29.29.29", "119.28.28.28"] {
                if let Ok(addr) = ip.parse::<Ipv4Addr>() {
                    group.push(NameServerConfig {
                        socket_addr: SocketAddr::new(IpAddr::V4(addr), 443),
                        protocol: Protocol::Https,
                        tls_dns_name: Some("dns.pub".to_string()),
                        trust_negative_responses: true,
                        tls_config: None,
                        bind_addr: None,
                    });
                }
            }
            return Ok((
                ResolverConfig::from_parts(None, vec![], group),
                Some("https://dns.pub/dns-query".parse().unwrap()),
            ));
        }

        // Alibaba DNS (dns.alidns.com)
        if url_lower.contains("alidns.com") {
            info!("Using Alibaba DOH");
            // Alibaba DOH: 223.5.5.5, 223.6.6.6
            let mut group = NameServerConfigGroup::new();
            for ip in &["223.5.5.5", "223.6.6.6"] {
                if let Ok(addr) = ip.parse::<Ipv4Addr>() {
                    group.push(NameServerConfig {
                        socket_addr: SocketAddr::new(IpAddr::V4(addr), 443),
                        protocol: Protocol::Https,
                        tls_dns_name: Some("dns.alidns.com".to_string()),
                        trust_negative_responses: true,
                        tls_config: None,
                        bind_addr: None,
                    });
                }
            }
            return Ok((
                ResolverConfig::from_parts(None, vec![], group),
                Some("https://dns.alidns.com/dns-query".parse().unwrap()),
            ));
        }

        let uri: Uri = doh_url.parse().map_err(|e| {
            DohProxyError::InvalidUrl(format!("Invalid DOH URL '{}': {}", doh_url, e))
        })?;

        let scheme = uri
            .scheme_str()
            .ok_or_else(|| DohProxyError::InvalidUrl(format!("Missing URL scheme: {}", doh_url)))?;
        if scheme != "https" {
            return Err(DohProxyError::InvalidUrl(format!(
                "Unsupported DOH URL scheme '{}': {}",
                scheme, doh_url
            )));
        }

        let host = uri.host().ok_or_else(|| {
            DohProxyError::InvalidUrl(format!("Missing host in DOH URL: {}", doh_url))
        })?;
        let port = uri.port_u16().unwrap_or(443);
        let mut path = uri.path();
        if path.is_empty() {
            path = "/dns-query";
        }
        if !path.is_empty() && path != "/dns-query" {
            warn!(
                "Custom DOH path '{}' is not supported; hickory uses /dns-query",
                path
            );
        }

        let mut ips = Vec::new();
        if let Ok(ip) = host.parse::<IpAddr>() {
            ips.push(ip);
        } else if !bootstrap_ips.is_empty() {
            // 有备用节点时不在构造期查系统 DNS，系统 DNS 解析不出 DoH 域名也能正常启动
            ips.extend_from_slice(bootstrap_ips);
        } else {
            let addrs = lookup_host((host, port)).await.map_err(|e| {
                DohProxyError::Dns(format!("Failed to resolve DOH host {}: {}", host, e))
            })?;
            ips.extend(addrs.map(|addr| addr.ip()));
        }

        if ips.is_empty() {
            return Err(DohProxyError::Dns(format!(
                "No IP addresses resolved for DOH host: {}",
                host
            )));
        }

        if prefer_ipv6 {
            ips.sort_by_key(|a| if a.is_ipv6() { 0 } else { 1 });
        } else {
            ips.sort_by_key(|a| if a.is_ipv4() { 0 } else { 1 });
        }

        let group = NameServerConfigGroup::from_ips_https(&ips, port, host.to_string(), true);
        Ok((ResolverConfig::from_parts(None, vec![], group), Some(uri)))
    }

    /// Create a new DNS resolver with ResolverConfig
    pub async fn with_resolver_config(config: ResolverConfig, prefer_ipv6: bool) -> Result<Self> {
        let mut opts = ResolverOpts::default();
        opts.use_hosts_file = false;
        let resolve_timeout = Duration::from_secs(5);
        opts.timeout = resolve_timeout;
        opts.attempts = 2;

        let resolver = TokioAsyncResolver::tokio(config, opts);

        Ok(Self {
            resolver,
            doh_ip: None,
            force_doh_get_ip: false,
            doh_ech: None,
            force_doh_get_ech: false,
            ech_cache: Arc::new(RwLock::new(HashMap::new())),
            ech_negative_cache: Arc::new(RwLock::new(HashMap::new())),
            ip_cache: Arc::new(RwLock::new(HashMap::new())),
            ech_inflight: Arc::new(Mutex::new(HashMap::new())),
            ip_inflight: Arc::new(Mutex::new(HashMap::new())),
            ip_rtt_cache: Arc::new(RwLock::new(HashMap::new())),
            preferred_host_ip_cache: Arc::new(RwLock::new(HashMap::new())),
            prefer_ipv6,
            resolve_timeout,
            query_count: AtomicU64::new(0),
        })
    }

    /// Lookup ECH config for a domain via HTTPS DNS record
    pub async fn lookup_ech_config(
        &self,
        domain: &str,
    ) -> Result<Option<EchConfigListBytes<'static>>> {
        // 定期清理过期缓存
        self.maybe_cleanup_caches();

        // Check cache first
        {
            let cache = self.ech_cache.read();
            if let Some(cached) = cache.get(domain) {
                if cached.expires_at > std::time::Instant::now() {
                    debug!("ECH config cache hit for {}", domain);
                    return Ok(Some(cached.config.clone()));
                }
            }
        }

        // 命中负缓存（确定无 ECH）则直接返回，避免重复查 HTTPS 记录
        if self.ech_negative_hit(domain) {
            debug!("ECH negative cache hit for {}", domain);
            return Ok(None);
        }

        info!("Looking up HTTPS record for ECH config: {}", domain);

        let (notify, is_leader) = {
            let mut inflight = self.ech_inflight.lock().await;
            if let Some(existing) = inflight.get(domain) {
                (existing.clone(), false)
            } else {
                let notify = Arc::new(Notify::new());
                inflight.insert(domain.to_string(), notify.clone());
                (notify, true)
            }
        };

        if !is_leader {
            // 领头查询可能在这里注册等待前就已通知，设上限避免一直挂起
            let _ = tokio::time::timeout(
                Duration::from_secs(INFLIGHT_WAIT_TIMEOUT_SECS),
                notify.notified(),
            )
            .await;
            let cache = self.ech_cache.read();
            if let Some(cached) = cache.get(domain) {
                if cached.expires_at > std::time::Instant::now() {
                    debug!("ECH config cache hit for {}", domain);
                    return Ok(Some(cached.config.clone()));
                }
            }
            return Ok(None);
        }

        if self.force_doh_get_ech {
            let result = self.lookup_ech_config_via_doh_get(domain).await;
            let mut inflight = self.ech_inflight.lock().await;
            inflight.remove(domain);
            notify.notify_waiters();
            return result;
        }

        let start = std::time::Instant::now();
        // Query HTTPS record
        let lookup = match tokio::time::timeout(
            self.resolve_timeout,
            self.resolver
                .lookup(domain, hickory_resolver::proto::rr::RecordType::HTTPS),
        )
        .await
        {
            Ok(result) => match result {
                Ok(lookup) => lookup,
                Err(e) => {
                    warn!(
                        "ECH HTTPS lookup failed for {}, falling back to DoH GET: {}",
                        domain, e
                    );
                    return self.lookup_ech_config_via_doh_get(domain).await;
                }
            },
            Err(_) => {
                warn!("ECH HTTPS lookup timed out for {}, skipping ECH", domain);
                let result = self.lookup_ech_config_via_doh_get(domain).await;
                let mut inflight = self.ech_inflight.lock().await;
                inflight.remove(domain);
                notify.notify_waiters();
                return result;
            }
        };

        // 从 lookup 中提取 TTL
        let ttl_duration = lookup
            .valid_until()
            .checked_duration_since(std::time::Instant::now())
            .unwrap_or(Duration::from_secs(DEFAULT_TTL_SECS));
        let ttl_secs = ttl_duration.as_secs().clamp(MIN_TTL_SECS, MAX_TTL_SECS);

        // Extract ECH config from SVCB/HTTPS records
        for record in lookup.iter() {
            if let Some(https) = record.as_https() {
                if let Some(ech_config) = self.extract_ech_from_https(https) {
                    info!(
                        "Found ECH config for {} ({} bytes)",
                        domain,
                        ech_config.len()
                    );

                    // Cache with DNS TTL
                    self.put_ech_cache(domain, ech_config.clone(), Duration::from_secs(ttl_secs));

                    debug!(
                        "ECH HTTPS lookup succeeded for {} in {} ms (TTL: {}s)",
                        domain,
                        start.elapsed().as_millis(),
                        ttl_secs,
                    );
                    let mut inflight = self.ech_inflight.lock().await;
                    inflight.remove(domain);
                    notify.notify_waiters();
                    return Ok(Some(ech_config));
                }
            }
        }

        warn!("No ECH config found in HTTPS record for {}", domain);
        let result = self.lookup_ech_config_via_doh_get(domain).await;
        let mut inflight = self.ech_inflight.lock().await;
        inflight.remove(domain);
        notify.notify_waiters();
        result
    }

    /// 从 HTTPS/SVCB 记录中提取 ECH 配置和 IP hint
    fn extract_hints_from_https(&self, https: &HTTPS) -> HttpsHints {
        use hickory_resolver::proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};

        let mut hints = HttpsHints::default();

        for (key, value) in https.svc_params().iter() {
            match key {
                SvcParamKey::EchConfig => {
                    if let SvcParamValue::EchConfig(ech_config) = value {
                        let bytes = Self::ensure_ech_config_list_len_prefix(ech_config.0.clone());
                        hints.ech_config = Some(EchConfigListBytes::from(bytes));
                    }
                }
                SvcParamKey::Ipv4Hint => {
                    if let SvcParamValue::Ipv4Hint(ipv4_hint) = value {
                        hints
                            .ipv4_hints
                            .extend(ipv4_hint.0.iter().map(|ip| IpAddr::V4(**ip)));
                    }
                }
                SvcParamKey::Ipv6Hint => {
                    if let SvcParamValue::Ipv6Hint(ipv6_hint) = value {
                        hints
                            .ipv6_hints
                            .extend(ipv6_hint.0.iter().map(|ip| IpAddr::V6(**ip)));
                    }
                }
                _ => {}
            }
        }

        hints
    }

    /// 兼容旧接口：仅提取 ECH 配置
    fn extract_ech_from_https(&self, https: &HTTPS) -> Option<EchConfigListBytes<'static>> {
        self.extract_hints_from_https(https).ech_config
    }

    fn ensure_ech_config_list_len_prefix(bytes: Vec<u8>) -> Vec<u8> {
        if bytes.len() >= 2 {
            let declared = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
            if declared == bytes.len().saturating_sub(2) {
                return bytes;
            }
        }

        if bytes.len() > u16::MAX as usize {
            warn!(
                "ECH config list too large ({} bytes), returning as-is",
                bytes.len()
            );
            return bytes;
        }

        let mut prefixed = Vec::with_capacity(bytes.len() + 2);
        let len = bytes.len() as u16;
        prefixed.extend_from_slice(&len.to_be_bytes());
        prefixed.extend_from_slice(&bytes);
        prefixed
    }

    /// Lookup IP addresses for a domain
    pub async fn lookup_ip(&self, domain: &str) -> Result<Vec<IpAddr>> {
        // 定期清理过期缓存
        self.maybe_cleanup_caches();

        // Check cache first
        {
            let cache = self.ip_cache.read();
            if let Some(cached) = cache.get(domain) {
                if cached.expires_at > std::time::Instant::now() {
                    debug!("IP cache hit for {}", domain);
                    return Ok(cached.addrs.clone());
                }
            }
        }

        debug!("Looking up IP for {}", domain);

        let (notify, is_leader) = {
            let mut inflight = self.ip_inflight.lock().await;
            if let Some(existing) = inflight.get(domain) {
                (existing.clone(), false)
            } else {
                let notify = Arc::new(Notify::new());
                inflight.insert(domain.to_string(), notify.clone());
                (notify, true)
            }
        };

        if !is_leader {
            // 领头查询可能在这里注册等待前就已通知，设上限避免一直挂起
            let _ = tokio::time::timeout(
                Duration::from_secs(INFLIGHT_WAIT_TIMEOUT_SECS),
                notify.notified(),
            )
            .await;
            let cache = self.ip_cache.read();
            if let Some(cached) = cache.get(domain) {
                if cached.expires_at > std::time::Instant::now() {
                    debug!("IP cache hit for {}", domain);
                    return Ok(cached.addrs.clone());
                }
            }
            return Err(DohProxyError::Dns(format!("No IP found for {}", domain)));
        }

        if self.force_doh_get_ip {
            let result = self.lookup_ip_via_doh_get(domain).await;
            let mut inflight = self.ip_inflight.lock().await;
            inflight.remove(domain);
            notify.notify_waiters();
            return result;
        }

        let start = std::time::Instant::now();
        let lookup =
            match tokio::time::timeout(self.resolve_timeout, self.resolver.lookup_ip(domain)).await
            {
                Ok(result) => match result {
                    Ok(lookup) => lookup,
                    Err(e) => {
                        warn!(
                            "IP lookup failed for {}, falling back to DoH GET: {}",
                            domain, e
                        );
                        let result = self.lookup_ip_via_doh_get(domain).await;
                        let mut inflight = self.ip_inflight.lock().await;
                        inflight.remove(domain);
                        notify.notify_waiters();
                        return result;
                    }
                },
                Err(_) => {
                    warn!(
                        "IP lookup timed out for {}, falling back to DoH GET",
                        domain
                    );
                    let result = self.lookup_ip_via_doh_get(domain).await;
                    let mut inflight = self.ip_inflight.lock().await;
                    inflight.remove(domain);
                    notify.notify_waiters();
                    return result;
                }
            };

        let mut addrs: Vec<IpAddr> = lookup.iter().collect();

        // 从 lookup 中提取 TTL（valid_until 与当前时间的差）
        let ttl_duration = lookup
            .valid_until()
            .checked_duration_since(std::time::Instant::now())
            .unwrap_or(Duration::from_secs(DEFAULT_TTL_SECS));
        let ttl_secs = ttl_duration.as_secs().clamp(MIN_TTL_SECS, MAX_TTL_SECS);

        // Sort by preference
        if self.prefer_ipv6 {
            addrs.sort_by_key(|a| if a.is_ipv6() { 0 } else { 1 });
        } else {
            addrs.sort_by_key(|a| if a.is_ipv4() { 0 } else { 1 });
        }

        // Cache the result with DNS TTL
        self.put_ip_cache(domain, addrs.clone(), Duration::from_secs(ttl_secs));

        debug!(
            "IP lookup succeeded for {} in {} ms (TTL: {}s)",
            domain,
            start.elapsed().as_millis(),
            ttl_secs,
        );
        let mut inflight = self.ip_inflight.lock().await;
        inflight.remove(domain);
        notify.notify_waiters();
        Ok(addrs)
    }

    /// 并行查询 ECH 配置和 IP 地址
    /// 如果 HTTPS 记录中包含 ipv4hint/ipv6hint，将 hint IP 合并到结果前面
    pub async fn lookup_ech_and_ip(
        &self,
        domain: &str,
    ) -> (Option<EchConfigListBytes<'static>>, Result<Vec<IpAddr>>) {
        let (ech_result, ip_result) =
            tokio::join!(self.lookup_ech_config(domain), self.lookup_ip(domain),);

        let ech_config = match ech_result {
            Ok(config) => config,
            Err(e) => {
                warn!("ECH lookup failed for {}: {}", domain, e);
                None
            }
        };

        // 尝试从 HTTPS 记录中获取 IP hint 并合并
        let ip_result = match ip_result {
            Ok(addrs) => Ok(addrs),
            Err(e) => Err(e),
        };

        (ech_config, ip_result)
    }

    pub async fn lookup_host(&self, domain: &str, force_refresh: bool) -> Result<LookupHostResult> {
        if force_refresh {
            self.clear_host_cache(domain);
        }

        let (ech_config, ip_result) = self.lookup_ech_and_ip(domain).await;
        let addrs = match ip_result {
            Ok(addrs) => self.order_addrs_by_rtt(addrs),
            Err(error) => {
                if ech_config.is_none() {
                    return Err(error);
                }
                warn!(
                    "IP lookup failed for {}, keeping ECH-only result: {}",
                    domain, error
                );
                Vec::new()
            }
        };
        // 只返回已经“实际连通验证过”的 sticky IP。
        // 冷启动时不要把排序后的首个地址直接提升为 preferred_ip，
        // 否则 query 模式会把一个未验证的单 IP 提前钉死给 rhttp，
        // 一旦这个边缘节点不稳定，就会持续触发连接重置/超时。
        let preferred_ip = self.preferred_host_ip_for_addrs(domain, &addrs);
        let ttl = self
            .remaining_ttl_for_host(domain)
            .unwrap_or_else(|| Duration::from_secs(DEFAULT_TTL_SECS));

        Ok(LookupHostResult {
            addrs,
            ech_config,
            preferred_ip,
            ttl,
        })
    }

    /// Set IPv6 preference
    pub fn set_prefer_ipv6(&mut self, prefer: bool) {
        self.prefer_ipv6 = prefer;
        // Clear IP cache when preference changes
        self.ip_cache.write().clear();
    }

    pub fn prefer_ipv6(&self) -> bool {
        self.prefer_ipv6
    }

    pub fn clear_host_cache(&self, domain: &str) {
        self.ip_cache.write().remove(domain);
        self.ech_cache.write().remove(domain);
        self.ech_negative_cache.write().remove(domain);
        self.preferred_host_ip_cache.write().remove(domain);
    }

    pub fn clear_all_caches(&self) {
        self.ip_cache.write().clear();
        self.ech_cache.write().clear();
        self.ech_negative_cache.write().clear();
        self.ip_rtt_cache.write().clear();
        self.preferred_host_ip_cache.write().clear();
    }

    pub fn cache_stats(&self) -> DnsCacheStats {
        let now = std::time::Instant::now();
        let mut hosts = HashSet::new();

        let ip_count = {
            let cache = self.ip_cache.read();
            cache
                .iter()
                .filter(|(_, entry)| entry.expires_at > now)
                .map(|(domain, _)| {
                    hosts.insert(domain.clone());
                })
                .count()
        };
        let ech_count = {
            let cache = self.ech_cache.read();
            cache
                .iter()
                .filter(|(_, entry)| entry.expires_at > now)
                .map(|(domain, _)| {
                    hosts.insert(domain.clone());
                })
                .count()
        };
        let ech_negative_count = {
            let cache = self.ech_negative_cache.read();
            cache
                .iter()
                .filter(|(_, expires_at)| **expires_at > now)
                .map(|(domain, _)| {
                    hosts.insert(domain.clone());
                })
                .count()
        };
        let preferred_ip_count = {
            let cache = self.preferred_host_ip_cache.read();
            cache
                .iter()
                .filter(|(_, entry)| entry.expires_at > now)
                .map(|(domain, _)| {
                    hosts.insert(domain.clone());
                })
                .count()
        };

        DnsCacheStats {
            resolver_count: 1,
            host_count: hosts.len(),
            ip_count,
            ech_count,
            ech_negative_count,
            ip_rtt_count: self
                .ip_rtt_cache
                .read()
                .values()
                .filter(|entry| entry.expires_at > now)
                .count(),
            preferred_ip_count,
        }
    }

    pub fn cache_records(&self) -> Vec<DnsCacheRecord> {
        let now = std::time::Instant::now();
        let mut records = Vec::new();

        {
            let cache = self.ip_cache.read();
            for (host, entry) in cache.iter() {
                if entry.expires_at <= now {
                    continue;
                }
                records.push(DnsCacheRecord {
                    host: host.clone(),
                    kind: "ip",
                    values: entry.addrs.iter().map(|addr| addr.to_string()).collect(),
                    ttl_ms: Self::remaining_ttl_ms(entry.expires_at, now),
                });
            }
        }

        {
            let cache = self.ech_cache.read();
            for (host, entry) in cache.iter() {
                if entry.expires_at <= now {
                    continue;
                }
                records.push(DnsCacheRecord {
                    host: host.clone(),
                    kind: "ech",
                    values: vec![STANDARD.encode(entry.config.as_ref())],
                    ttl_ms: Self::remaining_ttl_ms(entry.expires_at, now),
                });
            }
        }

        {
            let cache = self.ech_negative_cache.read();
            for (host, expires_at) in cache.iter() {
                if *expires_at <= now {
                    continue;
                }
                records.push(DnsCacheRecord {
                    host: host.clone(),
                    kind: "ech_negative",
                    values: Vec::new(),
                    ttl_ms: Self::remaining_ttl_ms(*expires_at, now),
                });
            }
        }

        {
            let cache = self.preferred_host_ip_cache.read();
            for (host, entry) in cache.iter() {
                if entry.expires_at <= now {
                    continue;
                }
                records.push(DnsCacheRecord {
                    host: host.clone(),
                    kind: "preferred_ip",
                    values: vec![entry.addr.to_string()],
                    ttl_ms: Self::remaining_ttl_ms(entry.expires_at, now),
                });
            }
        }

        records.sort_by(|a, b| a.host.cmp(&b.host).then(a.kind.cmp(b.kind)));
        records
    }

    fn remaining_ttl_ms(expires_at: std::time::Instant, now: std::time::Instant) -> u64 {
        let ms = expires_at
            .checked_duration_since(now)
            .unwrap_or_default()
            .as_millis();
        ms.min(u64::MAX as u128) as u64
    }

    pub fn preferred_host_ip(&self, domain: &str) -> Option<IpAddr> {
        let now = std::time::Instant::now();
        self.preferred_host_ip_cache
            .read()
            .get(domain)
            .filter(|entry| entry.expires_at > now)
            .map(|entry| entry.addr)
    }

    pub fn preferred_host_ip_for_addrs(&self, domain: &str, addrs: &[IpAddr]) -> Option<IpAddr> {
        let preferred = self.preferred_host_ip(domain)?;
        if addrs.iter().any(|addr| *addr == preferred) {
            Some(preferred)
        } else {
            self.clear_preferred_host_ip(domain);
            None
        }
    }

    pub fn record_host_success(&self, domain: &str, addr: IpAddr) {
        self.preferred_host_ip_cache.write().insert(
            domain.to_string(),
            CachedPreferredHostIp {
                addr,
                expires_at: std::time::Instant::now() + Duration::from_secs(STICKY_IP_TTL_SECS),
            },
        );
    }

    pub fn record_host_preference(&self, domain: &str, addr: IpAddr, ttl: Duration) {
        let ttl = if ttl > Duration::from_secs(STICKY_IP_TTL_SECS) {
            Duration::from_secs(STICKY_IP_TTL_SECS)
        } else if ttl < Duration::from_secs(MIN_TTL_SECS) {
            Duration::from_secs(MIN_TTL_SECS)
        } else {
            ttl
        };

        self.preferred_host_ip_cache.write().insert(
            domain.to_string(),
            CachedPreferredHostIp {
                addr,
                expires_at: std::time::Instant::now() + ttl,
            },
        );
    }

    pub fn clear_preferred_host_ip(&self, domain: &str) {
        self.preferred_host_ip_cache.write().remove(domain);
    }

    pub fn record_ip_rtt(&self, addr: IpAddr, rtt: Duration) {
        let cached = CachedIpRtt {
            rtt_ms: rtt.as_millis(),
            expires_at: std::time::Instant::now() + Duration::from_secs(600),
        };
        self.ip_rtt_cache.write().insert(addr, cached);
    }

    pub fn order_addrs_by_rtt(&self, mut addrs: Vec<IpAddr>) -> Vec<IpAddr> {
        let now = std::time::Instant::now();
        let cache = self.ip_rtt_cache.read();
        addrs.sort_by_key(|addr| {
            let rtt = cache
                .get(addr)
                .filter(|entry| entry.expires_at > now)
                .map(|entry| entry.rtt_ms)
                .unwrap_or(u128::MAX);
            let family_bias = if self.prefer_ipv6 {
                if addr.is_ipv6() {
                    0
                } else {
                    1
                }
            } else {
                if addr.is_ipv4() {
                    0
                } else {
                    1
                }
            };
            (rtt, family_bias)
        });
        addrs
    }

    /// 写入 IP 缓存，超过上限时淘汰过期条目
    fn put_ip_cache(&self, domain: &str, addrs: Vec<IpAddr>, ttl: Duration) {
        let mut cache = self.ip_cache.write();
        cache.insert(
            domain.to_string(),
            CachedIpAddrs {
                addrs,
                expires_at: std::time::Instant::now() + ttl,
            },
        );
        if cache.len() > MAX_CACHE_SIZE {
            Self::evict_expired(&mut cache);
        }
    }

    /// 写入 ECH 缓存，超过上限时淘汰过期条目
    fn put_ech_cache(&self, domain: &str, config: EchConfigListBytes<'static>, ttl: Duration) {
        // 找到 ECH，清除可能存在的负缓存
        self.ech_negative_cache.write().remove(domain);
        let mut cache = self.ech_cache.write();
        cache.insert(
            domain.to_string(),
            CachedEchConfig {
                config,
                expires_at: std::time::Instant::now() + ttl,
            },
        );
        if cache.len() > MAX_CACHE_SIZE {
            Self::evict_expired_ech(&mut cache);
        }
    }

    /// 写入 ECH 负缓存（确定无 ECH 时调用）
    fn put_ech_negative(&self, domain: &str) {
        let expires_at = std::time::Instant::now() + Duration::from_secs(ECH_NEGATIVE_TTL_SECS);
        let mut cache = self.ech_negative_cache.write();
        cache.insert(domain.to_string(), expires_at);
        if cache.len() > MAX_CACHE_SIZE {
            let now = std::time::Instant::now();
            cache.retain(|_, exp| *exp > now);
        }
    }

    /// 查询 ECH 负缓存是否命中且未过期
    fn ech_negative_hit(&self, domain: &str) -> bool {
        let now = std::time::Instant::now();
        self.ech_negative_cache
            .read()
            .get(domain)
            .map(|exp| *exp > now)
            .unwrap_or(false)
    }

    /// 淘汰过期 IP 缓存条目
    fn evict_expired(cache: &mut HashMap<String, CachedIpAddrs>) {
        let now = std::time::Instant::now();
        cache.retain(|_, v| v.expires_at > now);
        // 仍然超限，淘汰最早过期的条目
        if cache.len() > MAX_CACHE_SIZE {
            let remove_count = cache.len() - MAX_CACHE_SIZE + MAX_CACHE_SIZE / 10;
            let mut entries: Vec<_> = cache
                .iter()
                .map(|(k, v)| (k.clone(), v.expires_at))
                .collect();
            entries.sort_by_key(|(_, exp)| *exp);
            for (key, _) in entries.into_iter().take(remove_count) {
                cache.remove(&key);
            }
        }
    }

    /// 淘汰过期 ECH 缓存条目
    fn evict_expired_ech(cache: &mut HashMap<String, CachedEchConfig>) {
        let now = std::time::Instant::now();
        cache.retain(|_, v| v.expires_at > now);
        if cache.len() > MAX_CACHE_SIZE {
            let remove_count = cache.len() - MAX_CACHE_SIZE + MAX_CACHE_SIZE / 10;
            let mut entries: Vec<_> = cache
                .iter()
                .map(|(k, v)| (k.clone(), v.expires_at))
                .collect();
            entries.sort_by_key(|(_, exp)| *exp);
            for (key, _) in entries.into_iter().take(remove_count) {
                cache.remove(&key);
            }
        }
    }

    /// 定期清理所有过期缓存
    fn maybe_cleanup_caches(&self) {
        let count = self.query_count.fetch_add(1, Ordering::Relaxed);
        if count % CLEANUP_INTERVAL != 0 {
            return;
        }
        let now = std::time::Instant::now();
        self.ip_cache.write().retain(|_, v| v.expires_at > now);
        self.ech_cache.write().retain(|_, v| v.expires_at > now);
        self.ech_negative_cache.write().retain(|_, exp| *exp > now);
        self.ip_rtt_cache.write().retain(|_, v| v.expires_at > now);
        self.preferred_host_ip_cache
            .write()
            .retain(|_, v| v.expires_at > now);
    }

    fn remaining_ttl_for_host(&self, domain: &str) -> Option<Duration> {
        let now = std::time::Instant::now();
        let ip_ttl = self
            .ip_cache
            .read()
            .get(domain)
            .and_then(|entry| entry.expires_at.checked_duration_since(now));
        let ech_ttl = self
            .ech_cache
            .read()
            .get(domain)
            .and_then(|entry| entry.expires_at.checked_duration_since(now));

        match (ip_ttl, ech_ttl) {
            (Some(ip), Some(ech)) => Some(ip.min(ech)),
            (Some(ip), None) => Some(ip),
            (None, Some(ech)) => Some(ech),
            (None, None) => None,
        }
    }

    /// 将 TTL 秒数限制在合理范围内
    fn clamp_ttl(ttl_secs: u32) -> Duration {
        let clamped = (ttl_secs as u64).clamp(MIN_TTL_SECS, MAX_TTL_SECS);
        Duration::from_secs(clamped)
    }

    fn build_doh_upstream(
        uri: Uri,
        bootstrap_ips: &[IpAddr],
        timeout: Duration,
        upstream_proxy: Option<&UpstreamProxyConfig>,
    ) -> Result<DohUpstream> {
        // 走上游代理时由代理解析 DoH 域名，备用节点没有意义
        let bootstrap_host = uri
            .host()
            .filter(|host| host.parse::<IpAddr>().is_err())
            .filter(|_| !bootstrap_ips.is_empty() && upstream_proxy.is_none());

        let Some(host) = bootstrap_host else {
            let client = Self::build_doh_client(Client::builder(), timeout, upstream_proxy)?;
            return Ok(DohUpstream::new(uri, client, None));
        };

        let port = uri.port_u16().unwrap_or(443);
        let addrs: Vec<std::net::SocketAddr> = bootstrap_ips
            .iter()
            .map(|ip| std::net::SocketAddr::new(*ip, port))
            .collect();
        let client = Self::build_doh_client(
            Client::builder()
                .connect_timeout(Duration::from_secs(DOH_PRIMARY_CONNECT_TIMEOUT_SECS)),
            timeout,
            None,
        )?;
        let bootstrap_client = Self::build_doh_client(
            Client::builder()
                .connect_timeout(Duration::from_secs(DOH_BOOTSTRAP_CONNECT_TIMEOUT_SECS))
                .resolve_to_addrs(host, &addrs),
            timeout,
            None,
        )?;
        Ok(DohUpstream::new(uri, client, Some(bootstrap_client)))
    }

    fn build_doh_client(
        builder: reqwest::ClientBuilder,
        timeout: Duration,
        upstream_proxy: Option<&UpstreamProxyConfig>,
    ) -> Result<Client> {
        let mut builder = builder.timeout(timeout);
        if let Some(proxy) = upstream_proxy
            .filter(|proxy| proxy.is_valid() && (proxy.is_http() || proxy.is_socks5()))
        {
            let mut reqwest_proxy = reqwest::Proxy::all(proxy.reqwest_proxy_url())
                .map_err(|e| DohProxyError::Proxy(format!("Invalid upstream proxy URL: {}", e)))?;
            if proxy.is_http() {
                if let (Some(username), Some(password)) = (
                    proxy
                        .username
                        .as_deref()
                        .filter(|value| !value.trim().is_empty()),
                    proxy
                        .password
                        .as_deref()
                        .filter(|value| !value.trim().is_empty()),
                ) {
                    reqwest_proxy = reqwest_proxy.basic_auth(username, password);
                }
            }
            builder = builder.proxy(reqwest_proxy);
        }

        builder
            // Keep connections alive to reuse TLS/HTTP2 sessions.
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(8)
            .tcp_keepalive(Duration::from_secs(60))
            .http2_keep_alive_interval(Duration::from_secs(30))
            .http2_keep_alive_timeout(Duration::from_secs(10))
            .http2_keep_alive_while_idle(true)
            .build()
            .map_err(|e| DohProxyError::Proxy(format!("Failed to build DoH client: {}", e)))
    }

    async fn lookup_ech_config_via_doh_get(
        &self,
        domain: &str,
    ) -> Result<Option<EchConfigListBytes<'static>>> {
        let start = std::time::Instant::now();
        let Some(message) = self
            .doh_get_message_with(
                self.doh_ech.as_ref(),
                domain,
                hickory_resolver::proto::rr::RecordType::HTTPS,
            )
            .await?
        else {
            return Ok(None);
        };

        for record in message.answers() {
            if let Some(hickory_resolver::proto::rr::RData::HTTPS(https)) = record.data() {
                if let Some(ech_config) = self.extract_ech_from_https(https) {
                    let ttl = Self::clamp_ttl(record.ttl());
                    self.put_ech_cache(domain, ech_config.clone(), ttl);
                    debug!(
                        "ECH DoH GET lookup succeeded for {} in {} ms (TTL: {}s)",
                        domain,
                        start.elapsed().as_millis(),
                        ttl.as_secs(),
                    );
                    return Ok(Some(ech_config));
                }
            }
        }

        // 收到响应但记录中没有 ECH 参数：确定无 ECH，写入负缓存
        self.put_ech_negative(domain);
        Ok(None)
    }

    async fn lookup_ip_via_doh_get(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let start = std::time::Instant::now();
        let mut addrs = Vec::new();
        let mut min_ttl = MAX_TTL_SECS as u32;

        let (a_result, aaaa_result) = tokio::join!(
            self.doh_get_message_with(
                self.doh_ip.as_ref(),
                domain,
                hickory_resolver::proto::rr::RecordType::A,
            ),
            self.doh_get_message_with(
                self.doh_ip.as_ref(),
                domain,
                hickory_resolver::proto::rr::RecordType::AAAA,
            ),
        );

        if let Ok(Some(message)) = a_result {
            for record in message.answers() {
                if let Some(hickory_resolver::proto::rr::RData::A(a)) = record.data() {
                    addrs.push(IpAddr::V4(a.0));
                    min_ttl = min_ttl.min(record.ttl());
                }
            }
        }

        if let Ok(Some(message)) = aaaa_result {
            for record in message.answers() {
                if let Some(hickory_resolver::proto::rr::RData::AAAA(aaaa)) = record.data() {
                    addrs.push(IpAddr::V6(aaaa.0));
                    min_ttl = min_ttl.min(record.ttl());
                }
            }
        }

        if addrs.is_empty() {
            return Err(DohProxyError::Dns(format!("No IP found for {}", domain)));
        }

        if self.prefer_ipv6 {
            addrs.sort_by_key(|a| if a.is_ipv6() { 0 } else { 1 });
        } else {
            addrs.sort_by_key(|a| if a.is_ipv4() { 0 } else { 1 });
        }

        let ttl = Self::clamp_ttl(min_ttl);
        self.put_ip_cache(domain, addrs.clone(), ttl);

        debug!(
            "IP DoH GET lookup succeeded for {} in {} ms (TTL: {}s)",
            domain,
            start.elapsed().as_millis(),
            ttl.as_secs(),
        );
        Ok(addrs)
    }

    async fn doh_get_message_with(
        &self,
        upstream: Option<&DohUpstream>,
        domain: &str,
        record_type: hickory_resolver::proto::rr::RecordType,
    ) -> Result<Option<hickory_resolver::proto::op::Message>> {
        let Some(upstream) = upstream else {
            return Ok(None);
        };
        let uri = &upstream.uri;
        let start = std::time::Instant::now();

        use hickory_resolver::proto::op::{Edns, Message, Query};
        use hickory_resolver::proto::rr::Name;
        use std::str::FromStr;

        let fqdn = if domain.ends_with('.') {
            domain.to_string()
        } else {
            format!("{}.", domain)
        };
        let name = Name::from_str(&fqdn)
            .map_err(|e| DohProxyError::Dns(format!("Invalid domain {}: {}", domain, e)))?;

        let mut request = Message::new();
        request.add_query(Query::query(name, record_type));
        request.set_recursion_desired(true);
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        *request.extensions_mut() = Some(edns);

        let bytes = request
            .to_vec()
            .map_err(|e| DohProxyError::Dns(format!("Failed to encode DNS query: {}", e)))?;
        let encoded = URL_SAFE_NO_PAD.encode(bytes);

        let scheme = uri.scheme_str().unwrap_or("https");
        let authority = uri
            .authority()
            .ok_or_else(|| DohProxyError::InvalidUrl("Missing DOH authority".to_string()))?;
        let path = uri.path();
        let url = format!("{}://{}{}?dns={}", scheme, authority, path, encoded);

        let response = upstream.get(&url).await?;

        if !response.status().is_success() {
            return Err(DohProxyError::Dns(format!(
                "DoH GET http error: {}",
                response.status()
            )));
        }

        if let Some(content_type) = response.headers().get(reqwest::header::CONTENT_TYPE) {
            let content_type = content_type
                .to_str()
                .map_err(|e| DohProxyError::Dns(format!("Bad Content-Type: {}", e)))?;
            if !content_type.starts_with("application/dns-message") {
                return Err(DohProxyError::Dns(format!(
                    "Unsupported Content-Type: {}",
                    content_type
                )));
            }
        }

        let body = response
            .bytes()
            .await
            .map_err(|e| DohProxyError::Dns(format!("DoH GET read failed: {}", e)))?;
        let message = hickory_resolver::proto::op::Message::from_vec(&body)
            .map_err(|e| DohProxyError::Dns(format!("Invalid DNS response: {}", e)))?;

        debug!(
            "DoH GET {} {} completed in {} ms",
            domain,
            record_type,
            start.elapsed().as_millis()
        );
        Ok(Some(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::config::ResolverConfig;
    use hickory_resolver::proto::op::{Message, MessageType};
    use hickory_resolver::proto::rr::{rdata::A, RData, Record, RecordType};
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const FAKE_ANSWER: Ipv4Addr = Ipv4Addr::new(1, 2, 3, 4);

    /// 本地假 DoH 服务器（明文 HTTP）：A 查询回 1.2.3.4，其他类型回空应答
    async fn spawn_fake_doh() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let request = String::from_utf8_lossy(&buf[..n]).to_string();
                    let encoded = request
                        .split("dns=")
                        .nth(1)
                        .and_then(|rest| rest.split(' ').next())
                        .unwrap_or_default();
                    let query =
                        Message::from_vec(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap();
                    let question = query.queries()[0].clone();
                    let mut response = Message::new();
                    response
                        .set_id(query.id())
                        .set_message_type(MessageType::Response)
                        .add_query(question.clone());
                    if question.query_type() == RecordType::A {
                        response.add_answer(Record::from_rdata(
                            question.name().clone(),
                            120,
                            RData::A(A(FAKE_ANSWER)),
                        ));
                    }
                    let body = response.to_vec().unwrap();
                    let head = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/dns-message\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(head.as_bytes()).await;
                    let _ = stream.write_all(&body).await;
                });
            }
        });
        port
    }

    async fn closed_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    }

    /// 主地址是系统 DNS 解析不出的 .invalid 域名，备用节点指向本机 port
    fn unresolvable_upstream(port: u16) -> DohUpstream {
        let uri: Uri = format!("http://doh-bootstrap-test.invalid:{}/v1/lookup", port)
            .parse()
            .unwrap();
        DnsResolver::build_doh_upstream(
            uri,
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
            Duration::from_secs(5),
            None,
        )
        .unwrap()
    }

    async fn resolver_with(upstream: DohUpstream) -> DnsResolver {
        let mut resolver = DnsResolver::with_resolver_config(ResolverConfig::new(), false)
            .await
            .unwrap();
        resolver.doh_ip = Some(upstream.clone());
        resolver.doh_ech = Some(upstream);
        resolver.force_doh_get_ip = true;
        resolver.force_doh_get_ech = true;
        resolver
    }

    #[test]
    fn bootstrap_registry_is_keyed_by_doh_host() {
        let url = "https://Registry-Test.Example/v1/lookup";
        let key_before = DnsResolver::shared_cache_key(url, None, false, None);

        DnsResolver::set_bootstrap_ips(url, &["203.0.113.1".into(), "not-an-ip".into()]);
        assert_eq!(
            DnsResolver::bootstrap_ips_for_url("https://registry-test.example/dns-query"),
            vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))]
        );
        assert_ne!(
            DnsResolver::shared_cache_key(url, None, false, None),
            key_before
        );

        DnsResolver::set_bootstrap_ips(url, &[]);
        assert!(DnsResolver::bootstrap_ips_for_url(url).is_empty());
        assert_eq!(
            DnsResolver::shared_cache_key(url, None, false, None),
            key_before
        );
    }

    #[tokio::test]
    async fn custom_server_with_bootstrap_starts_without_system_dns() {
        let url = "https://startup-test.invalid/v1/lookup";
        DnsResolver::set_bootstrap_ips(url, &["203.0.113.2".into()]);
        let resolver = DnsResolver::new(url, None, false, None).await;
        DnsResolver::set_bootstrap_ips(url, &[]);
        let resolver = resolver.expect("bootstrap IPs should avoid system DNS at startup");
        assert!(resolver.doh_ip.as_ref().unwrap().bootstrap_client.is_some());
    }

    #[tokio::test]
    async fn falls_back_to_bootstrap_ips_and_prefers_them() {
        let port = spawn_fake_doh().await;
        let upstream = unresolvable_upstream(port);
        let resolver = resolver_with(upstream.clone()).await;

        let addrs = resolver.lookup_ip("example.com").await.unwrap();
        assert_eq!(addrs, vec![IpAddr::V4(FAKE_ANSWER)]);

        let health = upstream.health.lock();
        assert!(health.prefer_bootstrap_until.is_some());
        assert_eq!(health.consecutive_failures, 0);
    }

    #[tokio::test]
    async fn cools_down_after_repeated_failures() {
        let upstream = unresolvable_upstream(closed_port().await);
        let url = format!("{}?dns=AAAA", upstream.uri);
        for _ in 0..DOH_FAILURES_BEFORE_COOLDOWN {
            assert!(upstream.get(&url).await.is_err());
        }

        let start = std::time::Instant::now();
        let error = upstream.get(&url).await.unwrap_err();
        assert!(error.to_string().contains("cooling down"), "{}", error);
        assert!(start.elapsed() < Duration::from_millis(50));
    }

    #[tokio::test]
    async fn lookup_failure_does_not_hang() {
        let resolver = resolver_with(unresolvable_upstream(closed_port().await)).await;
        let result = tokio::time::timeout(
            Duration::from_secs(20),
            resolver.lookup_ech_and_ip("example.com"),
        )
        .await
        .expect("lookup should finish");
        assert!(result.1.is_err());
    }

    /// 连真实的 cfluxdo 加速节点：主地址故意指向黑洞，验证走备用节点能查到 linux.do。
    /// 需要外网，手动运行：cargo test -- --ignored edge_doh
    #[tokio::test]
    #[ignore]
    async fn edge_doh_via_bootstrap_nodes() {
        let host = "cfluxdotest01.wq.1molchuan.top";
        let uri: Uri = format!("https://{}/v1/lookup", host).parse().unwrap();
        let nodes: Vec<std::net::SocketAddr> = [
            "156.239.232.8",
            "156.239.232.72",
            "203.168.131.145",
            "103.199.103.204",
        ]
        .iter()
        .map(|ip| std::net::SocketAddr::new(ip.parse().unwrap(), 443))
        .collect();
        let blackhole = [std::net::SocketAddr::new("192.0.2.1".parse().unwrap(), 443)];
        let timeout = Duration::from_secs(5);
        let client = DnsResolver::build_doh_client(
            Client::builder()
                .connect_timeout(Duration::from_secs(DOH_PRIMARY_CONNECT_TIMEOUT_SECS))
                .resolve_to_addrs(host, &blackhole),
            timeout,
            None,
        )
        .unwrap();
        let bootstrap = DnsResolver::build_doh_client(
            Client::builder()
                .connect_timeout(Duration::from_secs(DOH_BOOTSTRAP_CONNECT_TIMEOUT_SECS))
                .resolve_to_addrs(host, &nodes),
            timeout,
            None,
        )
        .unwrap();
        let upstream = DohUpstream::new(uri, client, Some(bootstrap));
        let resolver = resolver_with(upstream.clone()).await;

        let addrs = resolver.lookup_ip("linux.do").await.unwrap();
        println!("linux.do -> {:?}", addrs);
        assert!(!addrs.is_empty());
        assert!(upstream.health.lock().prefer_bootstrap_until.is_some());
    }
}
