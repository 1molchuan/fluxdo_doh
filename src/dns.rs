//! DNS resolver with DOH and HTTPS record support for ECH config retrieval

use crate::error::{DohProxyError, Result};
use crate::select::{Selector, SELECT_LOOKUP_WAIT_SECS};
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
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{Arc, OnceLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
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
/// DoH 服务器拒绝令牌（401/403）后暂停使用的时长；换了新令牌会立即恢复
const DOH_AUTH_REJECTED_COOLDOWN_SECS: u64 = 60;
/// DoH 请求固定带的 User-Agent：安卓上最常见的 HTTP 库，混在普通 App 流量里不显眼。
/// 只用于 DoH 查询，不影响经代理转发的站点请求。
const DOH_USER_AGENT: &str = "okhttp/4.12.0";
/// DNS 查询报文用 EDNS(0) Padding 填充到这个长度的整倍数（RFC 8467 推荐值），去掉报文长度特征
const DNS_QUERY_PAD_BLOCK: usize = 128;
/// 没有可用路由表时，查询最多等首次拉取这么久（秒），超时就走 DoH
const ROUTES_INITIAL_WAIT_SECS: u64 = 4;
/// 路由表拉取失败后的退避时长（秒），期间查询直接走 DoH，不再每次等待
const ROUTES_RETRY_BACKOFF_SECS: u64 = 30;
/// 路由表拉取请求的总超时（秒）
const ROUTES_FETCH_TIMEOUT_SECS: u64 = 10;
/// App 经 Rust 发出的加速接口请求（令牌申请/续期等）的总超时（秒）
const ACCEL_REQUEST_TIMEOUT_SECS: u64 = 10;
/// 签名节点列表的内嵌公钥：kid -> Ed25519 公钥（32 字节）。换钥时追加新 kid，老钥保留到老客户端退场
const NODE_LIST_PUBKEYS: &[(&str, [u8; 32])] = &[
    // 2026-10-12 服务端生成，base64 为 0nnkUa5f1lPKHnSKFMc5N/vZlBIp+jRQJnP+OFelaCI=
    (
        "2026-10",
        [
            0xd2, 0x79, 0xe4, 0x51, 0xae, 0x5f, 0xd6, 0x53, 0xca, 0x1e, 0x74, 0x8a, 0x14, 0xc7,
            0x39, 0x37, 0xfb, 0xd9, 0x94, 0x12, 0x29, 0xfa, 0x34, 0x50, 0x26, 0x73, 0xfe, 0x38,
            0x57, 0xa5, 0x68, 0x22,
        ],
    ),
];

static SHARED_RESOLVERS: OnceLock<Arc<AsyncRwLock<HashMap<String, Arc<DnsResolver>>>>> =
    OnceLock::new();

/// DoH 服务器域名 -> 备用节点 IP，由启动配置登记
static DOH_BOOTSTRAP_IPS: OnceLock<RwLock<HashMap<String, Vec<IpAddr>>>> = OnceLock::new();

/// DoH 服务器域名 -> 访问令牌，由启动配置登记；查询时放在 `Authorization: Bearer` 里
static DOH_AUTH_TOKENS: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();

/// 有 DoH 服务器拒绝了令牌，等 App 取走后重新申请
static DOH_AUTH_REJECTED: AtomicBool = AtomicBool::new(false);

/// DoH 服务器域名 -> 路由表（查表模式），由启动配置登记；没登记的服务器行为不变
static DOH_ROUTE_TABLES: OnceLock<RwLock<HashMap<String, Arc<RouteTableStore>>>> =
    OnceLock::new();

/// 已验签接受的节点列表：加速域名 -> 当前节点 IP，优先级高于启动登记的种子 IP
static NODE_LIST: OnceLock<RwLock<Option<Arc<NodeList>>>> = OnceLock::new();

/// 等 App 取走并持久化的更新：路由表原文、节点列表
static ACCEL_UPDATE: OnceLock<parking_lot::Mutex<AccelUpdate>> = OnceLock::new();

/// `accel_request` 用的客户端缓存：scheme://authority -> 上游（复用连接，与 DoH 同一套 TLS 栈）
static ACCEL_UPSTREAMS: OnceLock<RwLock<HashMap<String, DohUpstream>>> = OnceLock::new();

/// 除 linux.do 外也由本地优选覆盖的主机名（atlas、cfhub6），由启动配置登记
static EXTRA_COVERED_HOSTS: OnceLock<RwLock<Vec<String>>> = OnceLock::new();

/// 测试用的额外公钥（kid -> 公钥），与 `NODE_LIST_PUBKEYS` 一起查
#[cfg(test)]
static TEST_NODE_LIST_PUBKEYS: OnceLock<RwLock<Vec<(String, [u8; 32])>>> = OnceLock::new();

/// 当前 unix 时间（秒）
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 解 base64：先按标准（带填充），再兼容 url-safe / 无填充
pub(crate) fn decode_base64_lenient(value: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE};
    let value = value.trim();
    STANDARD
        .decode(value)
        .or_else(|_| STANDARD_NO_PAD.decode(value))
        .or_else(|_| URL_SAFE.decode(value))
        .or_else(|_| URL_SAFE_NO_PAD.decode(value))
        .ok()
}

/// reqwest 的 DNS 解析器：建连时才取 DoH 域名当前的备用节点 IP
/// （已下发的节点列表 > 启动登记的种子 > 构造期传入的 `initial`），节点列表更新后不用重建客户端。
/// 返回的端口为 0，由 hyper 换成 URL 里的端口。
struct BootstrapResolver {
    host: String,
    initial: Vec<IpAddr>,
}

impl BootstrapResolver {
    fn current(&self) -> Vec<IpAddr> {
        let ips = DnsResolver::bootstrap_ips_for_host(&self.host);
        if ips.is_empty() {
            self.initial.clone()
        } else {
            ips
        }
    }
}

impl reqwest::dns::Resolve for BootstrapResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let requested = name.as_str().trim_end_matches('.').to_ascii_lowercase();
        let addrs: Vec<SocketAddr> = if requested == self.host {
            self.current()
                .into_iter()
                .map(|ip| SocketAddr::new(ip, 0))
                .collect()
        } else {
            Vec::new()
        };
        Box::pin(async move {
            if addrs.is_empty() {
                let error: Box<dyn std::error::Error + Send + Sync> = Box::new(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("no bootstrap IPs for {}", requested),
                ));
                Err(error)
            } else {
                Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
            }
        })
    }
}

/// 经 DoH 上游客户端发出的请求：DNS 查询报文，或 App 的加速接口 HTTP 请求（同一套 TLS 栈和备用节点）
enum DohRequest<'a> {
    Dns {
        message: &'a [u8],
        endpoint: &'a str,
    },
    Http {
        method: reqwest::Method,
        url: &'a str,
        headers: &'a [(String, String)],
        body: Option<&'a [u8]>,
        /// 调用方没给 Authorization 时，是否带上登记的令牌
        registry_auth: bool,
        /// 带登记令牌被 401/403 时是否打「令牌被拒」标记
        flag_auth_rejected: bool,
    },
}

impl DohRequest<'_> {
    fn is_dns(&self) -> bool {
        matches!(self, DohRequest::Dns { .. })
    }
}

/// DoH 上游。主客户端用系统 DNS 解析 DoH 域名；域名型地址另建一个直连备用节点的客户端
/// （只替换连接地址，SNI 和 Host 不变），主客户端连不上且当前有备用节点时改用它重试。
#[derive(Clone)]
pub(crate) struct DohUpstream {
    uri: Uri,
    client: Client,
    bootstrap_client: Option<Client>,
    /// 备用节点来源；None 表示 `bootstrap_client` 自带固定地址（测试用）
    bootstrap: Option<Arc<BootstrapResolver>>,
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
    /// 被服务器拒绝的令牌；登记的令牌换掉后解除暂停
    rejected_token: Option<String>,
    /// 服务器不接受 POST（回 405/415）后改用 GET `?dns=` 查询
    get_only: bool,
}

impl DohUpstream {
    fn new(uri: Uri, client: Client, bootstrap_client: Option<Client>) -> Self {
        Self {
            uri,
            client,
            bootstrap_client,
            bootstrap: None,
            health: Arc::new(parking_lot::Mutex::new(DohUpstreamHealth::default())),
        }
    }

    fn with_bootstrap(mut self, bootstrap: Arc<BootstrapResolver>) -> Self {
        self.bootstrap = Some(bootstrap);
        self
    }

    /// 当前是否有可用的备用节点地址
    fn bootstrap_available(&self) -> bool {
        match &self.bootstrap {
            Some(bootstrap) => !bootstrap.current().is_empty(),
            None => true,
        }
    }

    fn host(&self) -> &str {
        self.uri.host().unwrap_or_default()
    }

    /// 不带查询参数的请求地址：scheme://authority/path
    fn endpoint(&self) -> Result<String> {
        let scheme = self.uri.scheme_str().unwrap_or("https");
        let authority = self
            .uri
            .authority()
            .ok_or_else(|| DohProxyError::InvalidUrl("Missing DOH authority".to_string()))?;
        Ok(format!("{}://{}{}", scheme, authority, self.uri.path()))
    }

    /// 发送 DNS 查询报文。默认 POST（报文放请求体，二进制 body 比 `?dns=` 更像普通 API 调用）；
    /// 服务器回 405/415 说明只支持 GET，改为 GET `?dns=` 重发一次，之后该服务器一直用 GET。
    pub(crate) async fn query(&self, message: &[u8]) -> Result<reqwest::Response> {
        let endpoint = self.endpoint()?;
        let request = DohRequest::Dns {
            message,
            endpoint: &endpoint,
        };
        loop {
            let (response, retry_with_get) = self.send_once(&request).await?;
            if !retry_with_get {
                return Ok(response);
            }
        }
    }

    /// 发送普通 HTTP 请求（路由表拉取、App 的加速接口调用），复用 DoH 的客户端、备用节点和健康状态。
    /// 不检查 DoH 的暂停状态：调用方各有自己的退避。
    async fn send_http(
        &self,
        method: reqwest::Method,
        url: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
        registry_auth: bool,
        flag_auth_rejected: bool,
    ) -> Result<reqwest::Response> {
        let request = DohRequest::Http {
            method,
            url,
            headers,
            body,
            registry_auth,
            flag_auth_rejected,
        };
        let (response, _) = self.send_once(&request).await?;
        Ok(response)
    }

    /// 返回响应，以及是否刚切到 GET、需要重发（只对 DNS 查询）
    async fn send_once(&self, request: &DohRequest<'_>) -> Result<(reqwest::Response, bool)> {
        let is_dns = request.is_dns();
        let wants_registry_token = match request {
            DohRequest::Dns { .. } => true,
            DohRequest::Http { registry_auth, .. } => *registry_auth,
        };
        let auth_token = wants_registry_token
            .then(|| DnsResolver::auth_token_for_uri(&self.uri))
            .flatten();
        let (bootstrap_first, cooling_down, use_get) = {
            let mut health = self.health.lock();
            let now = Instant::now();
            if is_dns && health.rejected_token.is_some() && health.rejected_token != auth_token {
                health.rejected_token = None;
                health.cooldown_until = None;
            }
            (
                health
                    .prefer_bootstrap_until
                    .is_some_and(|until| until > now),
                health.cooldown_until.is_some_and(|until| until > now),
                health.get_only,
            )
        };
        if is_dns && cooling_down {
            return Err(DohProxyError::Dns(format!(
                "DoH server {} is cooling down",
                self.host()
            )));
        }

        let result = self
            .send_with_fallback(request, use_get, bootstrap_first, auth_token.as_deref())
            .await;

        let mut health = self.health.lock();
        let now = Instant::now();
        match result {
            Ok((response, used_bootstrap)) => {
                health.consecutive_failures = 0;
                if is_dns {
                    health.cooldown_until = None;
                }
                if used_bootstrap != bootstrap_first {
                    health.prefer_bootstrap_until = used_bootstrap
                        .then(|| now + Duration::from_secs(DOH_BOOTSTRAP_PREFER_SECS));
                }
                let status = response.status();
                let auth_rejected = auth_token.is_some()
                    && (status == reqwest::StatusCode::UNAUTHORIZED
                        || status == reqwest::StatusCode::FORBIDDEN);
                match request {
                    DohRequest::Dns { .. } => {
                        if !use_get
                            && (status == reqwest::StatusCode::METHOD_NOT_ALLOWED
                                || status == reqwest::StatusCode::UNSUPPORTED_MEDIA_TYPE)
                        {
                            warn!(
                                "DoH server {} does not accept POST ({}), switching to GET",
                                self.host(),
                                status
                            );
                            health.get_only = true;
                            return Ok((response, true));
                        }
                        if auth_rejected {
                            warn!(
                                "DoH server {} rejected the auth token ({}), pausing for {}s",
                                self.host(),
                                status,
                                DOH_AUTH_REJECTED_COOLDOWN_SECS
                            );
                            health.rejected_token = auth_token;
                            health.cooldown_until =
                                Some(now + Duration::from_secs(DOH_AUTH_REJECTED_COOLDOWN_SECS));
                            DOH_AUTH_REJECTED.store(true, Ordering::Relaxed);
                        }
                    }
                    DohRequest::Http {
                        flag_auth_rejected,
                        ..
                    } => {
                        if auth_rejected && *flag_auth_rejected {
                            warn!(
                                "Accel server {} rejected the auth token ({})",
                                self.host(),
                                status
                            );
                            DOH_AUTH_REJECTED.store(true, Ordering::Relaxed);
                        }
                    }
                }
                Ok((response, false))
            }
            Err(error) => {
                health.consecutive_failures += 1;
                if is_dns && health.consecutive_failures >= DOH_FAILURES_BEFORE_COOLDOWN {
                    warn!(
                        "DoH server {} failed {} times in a row, pausing for {}s",
                        self.host(),
                        health.consecutive_failures,
                        DOH_COOLDOWN_SECS
                    );
                    health.cooldown_until = Some(now + Duration::from_secs(DOH_COOLDOWN_SECS));
                }
                Err(DohProxyError::Dns(format!(
                    "{} request failed: {}",
                    if is_dns { "DoH" } else { "Accel" },
                    error
                )))
            }
        }
    }

    /// 按请求类型构造 reqwest 请求。不打印 headers/body。
    fn build_request(
        client: &Client,
        request: &DohRequest<'_>,
        use_get: bool,
        auth_token: Option<&str>,
    ) -> reqwest::RequestBuilder {
        match request {
            DohRequest::Dns { message, endpoint } => {
                let builder = if use_get {
                    client.get(format!(
                        "{}?dns={}",
                        endpoint,
                        URL_SAFE_NO_PAD.encode(message)
                    ))
                } else {
                    client
                        .post(*endpoint)
                        .header("content-type", "application/dns-message")
                        .body(message.to_vec())
                }
                .header("accept", "application/dns-message");
                match auth_token {
                    Some(token) => builder.bearer_auth(token),
                    None => builder,
                }
            }
            DohRequest::Http {
                method,
                url,
                headers,
                body,
                ..
            } => {
                let mut builder = client.request(method.clone(), *url);
                let mut has_accept = false;
                let mut has_auth = false;
                for (name, value) in headers.iter() {
                    has_accept |= name.eq_ignore_ascii_case("accept");
                    has_auth |= name.eq_ignore_ascii_case("authorization");
                    builder = builder.header(name.as_str(), value.as_str());
                }
                if !has_accept {
                    builder = builder.header("accept", "application/json");
                }
                if !has_auth {
                    if let Some(token) = auth_token {
                        builder = builder.bearer_auth(token);
                    }
                }
                if let Some(body) = body {
                    builder = builder.body(body.to_vec());
                }
                builder
            }
        }
    }

    /// 返回响应以及是否经由备用节点
    async fn send_with_fallback(
        &self,
        request: &DohRequest<'_>,
        use_get: bool,
        bootstrap_first: bool,
        auth_token: Option<&str>,
    ) -> std::result::Result<(reqwest::Response, bool), reqwest::Error> {
        let send = |client: &Client| Self::build_request(client, request, use_get, auth_token).send();
        let bootstrap_client = self
            .bootstrap_client
            .as_ref()
            .filter(|_| self.bootstrap_available());
        let Some(bootstrap_client) = bootstrap_client else {
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
                    "DoH request via {} failed, retrying via {}: {}",
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
    /// 服务端 retry_configs 给的新钥匙：domain -> (钥匙, 过期时间)，优先于表和缓存
    ech_overrides: Arc<RwLock<HashMap<String, (EchConfigListBytes<'static>, std::time::Instant)>>>,
    ech_inflight: Arc<Mutex<HashMap<String, Arc<Notify>>>>,
    ip_inflight: Arc<Mutex<HashMap<String, Arc<Notify>>>>,
    ip_rtt_cache: Arc<RwLock<HashMap<IpAddr, CachedIpRtt>>>,
    preferred_host_ip_cache: Arc<RwLock<HashMap<String, CachedPreferredHostIp>>>,
    /// 出站地址族亲和：首次成功建连后固定下来（`true` = IPv6），之后所有域名都
    /// 优先用同一个地址族，只有该族整体连不上才切换。
    ///
    /// CF 的 cf_clearance 绑定出口 IP，而双栈网络下 v4 与 v6 的出口是两个地址。
    /// 以前 Happy Eyeballs 让两族赛跑、谁赢谁做该域名的粘性 IP，结果 `linux.do`
    /// 可能走 v6、`credit.linux.do` 走 v4：WebView 在 linux.do 过盾铸出的 clearance
    /// 到了 credit.linux.do 的请求上就被 CF 判成另一个 IP，稳定 403。
    family_affinity: Arc<RwLock<Option<bool>>>,
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

/// 签名节点列表信封：服务端随路由表下发，App 持久化后启动时原样回传重新验签
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodesEnvelope {
    pub kid: String,
    /// base64(JSON)
    pub payload: String,
    /// base64(Ed25519 对 payload 解码后原始字节的签名)
    pub sig: String,
}

/// 节点列表 payload 的 JSON 形态
#[derive(Deserialize)]
struct NodeListJson {
    serial: u64,
    not_after: u64,
    #[serde(default)]
    hosts: HashMap<String, NodeHostJson>,
}

#[derive(Deserialize, Default)]
struct NodeHostJson {
    #[serde(default)]
    v4: Vec<String>,
    #[serde(default)]
    v6: Vec<String>,
}

/// 已验签的节点列表
pub struct NodeList {
    serial: u64,
    not_after: u64,
    /// (域名, 节点 IP)，按域名长度降序，匹配时最长后缀优先
    hosts: Vec<(String, Vec<IpAddr>)>,
    /// payload 解码后的 JSON 原文，交给 App 持久化/展示
    payload_json: String,
}

impl NodeList {
    /// 域名相等或以 `.<key>` 结尾即命中
    fn ips_for(&self, host: &str) -> Option<&[IpAddr]> {
        self.hosts
            .iter()
            .find(|(key, _)| {
                host == key
                    || host
                        .strip_suffix(key.as_str())
                        .is_some_and(|prefix| prefix.ends_with('.'))
            })
            .map(|(_, ips)| ips.as_slice())
    }

    fn is_expired(&self, now_unix: u64) -> bool {
        self.not_after <= now_unix
    }
}

/// 等 App 取走并持久化的更新
#[derive(Default, Debug)]
pub struct AccelUpdate {
    /// 新拉到的路由表原文（JSON）
    pub route_table: Option<String>,
    /// 新接受的节点列表 payload（JSON，已验签）
    pub nodes: Option<String>,
    /// 新接受的节点列表信封，App 持久化后启动时回传
    pub nodes_envelope: Option<NodesEnvelope>,
    /// 本地优选的最新状态 JSON（赢家、钥匙、atlas 缓存等）
    pub select_state: Option<String>,
    /// 上报被 cfhub 拒绝（401/403）：App 要清令牌、关开关
    pub report_auth_rejected: bool,
}

impl AccelUpdate {
    fn is_empty(&self) -> bool {
        self.route_table.is_none()
            && self.nodes.is_none()
            && self.nodes_envelope.is_none()
            && self.select_state.is_none()
            && !self.report_auth_rejected
    }
}

/// 加速接口请求的响应
pub struct AccelResponse {
    pub status: u16,
    pub body: String,
}

/// 路由表 JSON 形态（加速服务端 `GET /v1/routes` 的响应）
#[derive(Deserialize)]
struct RouteTableJson {
    /// 表生成时刻（unix 秒），持久化后用来算年龄
    #[serde(default)]
    generated: Option<u64>,
    #[serde(default)]
    serial: Option<u64>,
    /// 新鲜期（秒）
    ttl: u64,
    /// 过期后仍可继续用旧表的时长（秒），期间后台刷新
    #[serde(default)]
    max_stale: u64,
    /// 表外域名的解析顺序：`system_first`（缺省）/ `doh_first`
    #[serde(default)]
    miss: Option<String>,
    #[serde(default)]
    routes: Vec<RouteEntryJson>,
    #[serde(default)]
    nodes: Option<NodesEnvelope>,
}

#[derive(Deserialize)]
struct RouteEntryJson {
    name: String,
    /// true 表示 name 本身和所有 *.name 都命中
    #[serde(default)]
    wildcard: bool,
    #[serde(default)]
    v4: Vec<String>,
    #[serde(default)]
    v6: Vec<String>,
    /// base64 的 ECHConfigList，可省
    #[serde(default)]
    ech: Option<String>,
}

/// 表外域名的解析顺序
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MissPolicy {
    /// 先系统 DNS，失败再 DoH
    SystemFirst,
    /// 先 DoH（原有行为）
    DohFirst,
}

pub(crate) struct RouteEntry {
    pub(crate) addrs: Vec<IpAddr>,
    pub(crate) ech: Option<EchConfigListBytes<'static>>,
}

/// 域名 -> IP 的路由表：命中的域名不再查 DoH
pub(crate) struct RouteTable {
    exact: HashMap<String, RouteEntry>,
    wildcard: HashMap<String, RouteEntry>,
    /// 新鲜期截止；之后仍可用，但要后台刷新
    expires_at: Instant,
    /// 可用期截止（ttl + max_stale）；之后当没有表
    stale_until: Instant,
    miss_policy: MissPolicy,
}

impl RouteTable {
    /// `age` 是表生成到现在的时长：持久化的表按 `generated` 算，刚拉到的按 0。
    /// 不用 `Instant - age`：安卓开机不久的单调钟减大数会下溢
    fn from_json(json: &RouteTableJson, age: Duration) -> Self {
        let now = Instant::now();
        let fresh = Duration::from_secs(json.ttl);
        let usable = Duration::from_secs(json.ttl.saturating_add(json.max_stale));
        let mut exact = HashMap::new();
        let mut wildcard = HashMap::new();
        for route in &json.routes {
            let name = route.name.trim().trim_end_matches('.').to_ascii_lowercase();
            if name.is_empty() {
                continue;
            }
            let addrs: Vec<IpAddr> = route
                .v4
                .iter()
                .chain(route.v6.iter())
                .filter_map(|ip| ip.trim().parse::<IpAddr>().ok())
                .collect();
            let ech = route
                .ech
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .and_then(decode_base64_lenient)
                .map(|bytes| {
                    EchConfigListBytes::from(DnsResolver::ensure_ech_config_list_len_prefix(bytes))
                });
            if route.wildcard {
                wildcard.insert(
                    name.clone(),
                    RouteEntry {
                        addrs: addrs.clone(),
                        ech: ech.clone(),
                    },
                );
            }
            exact.insert(name, RouteEntry { addrs, ech });
        }
        let miss_policy = match json.miss.as_deref().map(str::trim) {
            Some("doh_first") => MissPolicy::DohFirst,
            _ => MissPolicy::SystemFirst,
        };
        Self {
            exact,
            wildcard,
            expires_at: now + fresh.saturating_sub(age),
            stale_until: now + usable.saturating_sub(age),
            miss_policy,
        }
    }

    /// 精确匹配，再逐级去掉最左一段查通配
    pub(crate) fn lookup(&self, host: &str) -> Option<&RouteEntry> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if let Some(entry) = self.exact.get(&host) {
            return Some(entry);
        }
        let mut rest = host.as_str();
        while let Some((_, parent)) = rest.split_once('.') {
            if let Some(entry) = self.wildcard.get(parent) {
                return Some(entry);
            }
            rest = parent;
        }
        None
    }

    fn is_fresh(&self, now: Instant) -> bool {
        self.expires_at > now
    }

    fn is_usable(&self, now: Instant) -> bool {
        self.stale_until > now
    }

    /// 给 App 的缓存时长：到新鲜期截止的剩余时间，下限 MIN_TTL_SECS
    fn ttl_hint(&self, now: Instant) -> Duration {
        self.expires_at
            .saturating_duration_since(now)
            .max(Duration::from_secs(MIN_TTL_SECS))
    }

    fn len(&self) -> usize {
        self.exact.len()
    }
}

/// 某个 DoH 服务器的路由表：拉取、缓存、后台刷新
struct RouteTableStore {
    routes_url: String,
    proxy_key: String,
    upstream: DohUpstream,
    table: RwLock<Option<Arc<RouteTable>>>,
    /// 是否有拉取在进行（single-flight）
    refreshing: AtomicBool,
    /// 拉取结束（无论成败）时唤醒等待的查询
    refreshed: Notify,
    last_failure: parking_lot::Mutex<Option<Instant>>,
}

/// 拉取结束时复位 single-flight 标记并唤醒等待者，任务被取消也会执行
struct RefreshGuard(Arc<RouteTableStore>);

impl Drop for RefreshGuard {
    fn drop(&mut self) {
        self.0.refreshing.store(false, Ordering::Release);
        self.0.refreshed.notify_waiters();
    }
}

impl RouteTableStore {
    fn new(routes_url: &str, upstream_proxy: Option<&UpstreamProxyConfig>) -> Result<Self> {
        let uri: Uri = routes_url.parse().map_err(|e| {
            DohProxyError::InvalidUrl(format!("Invalid routes URL '{}': {}", routes_url, e))
        })?;
        if uri.host().is_none() || !matches!(uri.scheme_str(), Some("http") | Some("https")) {
            return Err(DohProxyError::InvalidUrl(format!(
                "Routes URL must be http(s) with a host: {}",
                routes_url
            )));
        }
        let bootstrap_ips = DnsResolver::bootstrap_ips_for_url(routes_url);
        let upstream = DnsResolver::build_doh_upstream(
            uri,
            &bootstrap_ips,
            Duration::from_secs(ROUTES_FETCH_TIMEOUT_SECS),
            upstream_proxy,
        )?;
        Ok(Self {
            routes_url: routes_url.to_string(),
            proxy_key: upstream_proxy
                .map(UpstreamProxyConfig::cache_key)
                .unwrap_or_default(),
            upstream,
            table: RwLock::new(None),
            refreshing: AtomicBool::new(false),
            refreshed: Notify::new(),
            last_failure: parking_lot::Mutex::new(None),
        })
    }

    fn host(&self) -> &str {
        self.upstream.host()
    }

    /// 解析并存入一份表。`persisted`：App 回传的旧表，按 `generated` 算年龄且不再通知 App；
    /// 否则是刚拉到的，年龄按 0 并记入待取更新。返回条目数
    fn apply_raw(&self, raw: &str, persisted: bool) -> Result<usize> {
        let json: RouteTableJson = serde_json::from_str(raw)
            .map_err(|e| DohProxyError::Parse(format!("Invalid route table: {}", e)))?;
        let age = if persisted {
            let now = now_unix();
            Duration::from_secs(now.saturating_sub(json.generated.or(json.serial).unwrap_or(now)))
        } else {
            Duration::ZERO
        };
        let table = RouteTable::from_json(&json, age);
        let now = Instant::now();
        if !table.is_usable(now) {
            return Err(DohProxyError::Parse(
                "Route table is older than ttl + max_stale".to_string(),
            ));
        }
        let count = table.len();
        let fresh_for = table.expires_at.saturating_duration_since(now);
        let miss_policy = table.miss_policy;
        *self.table.write() = Some(Arc::new(table));

        if let Some(envelope) = &json.nodes {
            match DnsResolver::accept_node_list_inner(envelope, !persisted) {
                Ok(true) => {}
                Ok(false) => debug!(
                    "Node list in route table from {} is not newer, ignored",
                    self.host()
                ),
                Err(error) => warn!(
                    "Node list in route table from {} rejected: {}",
                    self.host(),
                    error
                ),
            }
        }
        if !persisted {
            DnsResolver::accel_update().lock().route_table = Some(raw.to_string());
        }
        info!(
            "Route table for {} loaded: {} entries, fresh for {}s, miss policy {:?}",
            self.host(),
            count,
            fresh_for.as_secs(),
            miss_policy
        );
        Ok(count)
    }

    fn in_backoff(&self, now: Instant) -> bool {
        self.last_failure.lock().is_some_and(|at| {
            now.saturating_duration_since(at) < Duration::from_secs(ROUTES_RETRY_BACKOFF_SECS)
        })
    }

    /// 当前可用的表：新鲜直接用；过期但未超 max_stale 先用旧表、后台刷新；
    /// 没有表或已超 max_stale 时等一次拉取（上限 ROUTES_INITIAL_WAIT_SECS），退避期内直接放弃
    async fn current(self: &Arc<Self>) -> Option<Arc<RouteTable>> {
        let now = Instant::now();
        let table = self.table.read().clone();
        if let Some(table) = table {
            if table.is_fresh(now) {
                return Some(table);
            }
            if table.is_usable(now) {
                self.spawn_refresh();
                return Some(table);
            }
        }
        if self.in_backoff(now) {
            return None;
        }
        // 先登记等待再触发拉取，避免错过通知
        let notified = self.refreshed.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        self.spawn_refresh();
        let _ = tokio::time::timeout(
            Duration::from_secs(ROUTES_INITIAL_WAIT_SECS),
            notified,
        )
        .await;
        let now = Instant::now();
        self.table
            .read()
            .clone()
            .filter(|table| table.is_usable(now))
    }

    fn spawn_refresh(self: &Arc<Self>) {
        if self.in_backoff(Instant::now()) {
            return;
        }
        if self
            .refreshing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let store = self.clone();
        tokio::spawn(async move {
            let _guard = RefreshGuard(store.clone());
            match store.fetch_once().await {
                Ok(_) => {
                    *store.last_failure.lock() = None;
                }
                Err(error) => {
                    warn!(
                        "Route table fetch from {} failed, retrying after {}s: {}",
                        store.host(),
                        ROUTES_RETRY_BACKOFF_SECS,
                        error
                    );
                    *store.last_failure.lock() = Some(Instant::now());
                }
            }
        });
    }

    async fn fetch_once(&self) -> Result<usize> {
        let response = self
            .upstream
            .send_http(reqwest::Method::GET, &self.routes_url, &[], None, true, true)
            .await?;
        let status = response.status();
        if !status.is_success() {
            return Err(DohProxyError::Dns(format!(
                "Route table http error: {}",
                status
            )));
        }
        let raw = response
            .text()
            .await
            .map_err(|e| DohProxyError::Dns(format!("Route table read failed: {}", e)))?;
        self.apply_raw(&raw, false)
    }
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
        // 备用节点在建连时动态读取，不纳入 key；节点变化不用换 resolver
        format!(
            "{}|{}|{}|{}",
            doh_url,
            doh_url_ech.unwrap_or(""),
            if prefer_ipv6 { "v6" } else { "v4" },
            upstream_key,
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
            .map(|host| Self::bootstrap_ips_for_host(&host))
            .unwrap_or_default()
    }

    /// 某域名当前的备用 IP：已验签且未过期的节点列表优先，再补启动时登记的种子（去重）。
    /// 每次建连都重新读取，节点列表更新后无需重建 client
    fn bootstrap_ips_for_host(host: &str) -> Vec<IpAddr> {
        let host = host.trim().trim_matches(['[', ']']).to_ascii_lowercase();
        let mut ips: Vec<IpAddr> = Self::node_list_holder()
            .read()
            .as_ref()
            .filter(|list| !list.is_expired(now_unix()))
            .and_then(|list| list.ips_for(&host).map(<[IpAddr]>::to_vec))
            .unwrap_or_default();
        if let Some(seeds) = Self::bootstrap_registry().read().get(&host) {
            for ip in seeds {
                if !ips.contains(ip) {
                    ips.push(*ip);
                }
            }
        }
        ips
    }

    fn node_list_holder() -> &'static RwLock<Option<Arc<NodeList>>> {
        NODE_LIST.get_or_init(|| RwLock::new(None))
    }

    pub(crate) fn accel_update() -> &'static parking_lot::Mutex<AccelUpdate> {
        ACCEL_UPDATE.get_or_init(|| parking_lot::Mutex::new(AccelUpdate::default()))
    }

    fn node_list_pubkey(kid: &str) -> Option<[u8; 32]> {
        #[cfg(test)]
        {
            if let Some((_, key)) = TEST_NODE_LIST_PUBKEYS
                .get_or_init(|| RwLock::new(Vec::new()))
                .read()
                .iter()
                .find(|(k, _)| k == kid)
            {
                return Some(*key);
            }
        }
        NODE_LIST_PUBKEYS
            .iter()
            .find(|(k, _)| *k == kid)
            .map(|(_, key)| *key)
    }

    /// 验签并解析节点列表（纯函数，不碰全局状态）：
    /// kid 必须在内嵌公钥表里，Ed25519 签名必须对上 payload 原始字节，且未过期
    fn verify_node_list(envelope: &NodesEnvelope, now_unix: u64) -> Result<NodeList> {
        let kid = envelope.kid.trim();
        let pubkey = Self::node_list_pubkey(kid).ok_or_else(|| {
            DohProxyError::Parse(format!("Unknown node list key id '{}'", kid))
        })?;
        let payload = decode_base64_lenient(envelope.payload.trim())
            .ok_or_else(|| DohProxyError::Parse("Node list payload is not base64".to_string()))?;
        let sig = decode_base64_lenient(envelope.sig.trim())
            .ok_or_else(|| DohProxyError::Parse("Node list signature is not base64".to_string()))?;
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &pubkey)
            .verify(&payload, &sig)
            .map_err(|_| DohProxyError::Parse("Node list signature mismatch".to_string()))?;

        let json: NodeListJson = serde_json::from_slice(&payload)
            .map_err(|e| DohProxyError::Parse(format!("Invalid node list payload: {}", e)))?;
        if json.not_after <= now_unix {
            return Err(DohProxyError::Parse(format!(
                "Node list serial {} expired at {}",
                json.serial, json.not_after
            )));
        }
        let mut hosts: Vec<(String, Vec<IpAddr>)> = json
            .hosts
            .iter()
            .filter_map(|(name, entry)| {
                let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
                if name.is_empty() {
                    return None;
                }
                let ips: Vec<IpAddr> = entry
                    .v4
                    .iter()
                    .chain(entry.v6.iter())
                    .filter_map(|ip| ip.trim().parse::<IpAddr>().ok())
                    .collect();
                Some((name, ips))
            })
            .collect();
        // 最长后缀优先
        hosts.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));
        let payload_json = String::from_utf8(payload)
            .map_err(|_| DohProxyError::Parse("Node list payload is not UTF-8".to_string()))?;
        Ok(NodeList {
            serial: json.serial,
            not_after: json.not_after,
            hosts,
            payload_json,
        })
    }

    /// 验签通过且 serial 比已存的大才接受；`notify_app` 为 true 时记入待取更新让 App 持久化。
    /// 返回 Ok(false) 表示不比现有的新
    fn accept_node_list_inner(envelope: &NodesEnvelope, notify_app: bool) -> Result<bool> {
        let list = Self::verify_node_list(envelope, now_unix())?;
        {
            let mut holder = Self::node_list_holder().write();
            if holder.as_ref().is_some_and(|current| current.serial >= list.serial) {
                return Ok(false);
            }
            info!(
                "Accepted node list serial {} ({} hosts, valid until {})",
                list.serial,
                list.hosts.len(),
                list.not_after
            );
            let payload_json = list.payload_json.clone();
            *holder = Some(Arc::new(list));
            if notify_app {
                let mut update = Self::accel_update().lock();
                update.nodes = Some(payload_json);
                update.nodes_envelope = Some(envelope.clone());
            }
        }
        Ok(true)
    }

    /// 接受服务端刚下发的签名节点列表（会通知 App 持久化）
    pub fn accept_node_list(envelope: &NodesEnvelope) -> Result<bool> {
        Self::accept_node_list_inner(envelope, true)
    }

    /// 启动时回灌 App 持久化的签名信封（JSON `{kid,payload,sig}`），重新验签，不通知 App
    pub fn load_node_list_json(raw: &str) -> Result<bool> {
        let envelope: NodesEnvelope = serde_json::from_str(raw)
            .map_err(|e| DohProxyError::Parse(format!("Invalid node list envelope: {}", e)))?;
        Self::accept_node_list_inner(&envelope, false)
    }

    /// 取出并清空待 App 持久化的更新（路由表原文 / 节点列表）
    pub fn take_accel_update() -> Option<AccelUpdate> {
        let mut update = Self::accel_update().lock();
        if update.is_empty() {
            return None;
        }
        Some(std::mem::take(&mut *update))
    }

    fn route_table_registry() -> &'static RwLock<HashMap<String, Arc<RouteTableStore>>> {
        DOH_ROUTE_TABLES.get_or_init(|| RwLock::new(HashMap::new()))
    }

    /// 登记某 DoH 服务器的路由表接口。`routes_url` 为 None 时取消登记（关掉查表模式）；
    /// 同 URL、同代理则复用已拉到的表
    pub fn set_routes_url(
        doh_url: &str,
        routes_url: Option<&str>,
        upstream_proxy: Option<&UpstreamProxyConfig>,
    ) -> Result<()> {
        let Some(host) = Self::doh_url_host(doh_url) else {
            return Ok(());
        };
        let routes_url = routes_url.map(str::trim).filter(|url| !url.is_empty());
        let Some(routes_url) = routes_url else {
            if Self::route_table_registry().write().remove(&host).is_some() {
                info!("Route table disabled for {}", host);
            }
            return Ok(());
        };
        let proxy_key = upstream_proxy
            .map(UpstreamProxyConfig::cache_key)
            .unwrap_or_default();
        {
            let registry = Self::route_table_registry().read();
            if registry
                .get(&host)
                .is_some_and(|store| store.routes_url == routes_url && store.proxy_key == proxy_key)
            {
                return Ok(());
            }
        }
        let store = Arc::new(RouteTableStore::new(routes_url, upstream_proxy)?);
        info!("Route table for {} will be fetched from {}", host, store.host());
        Self::route_table_registry().write().insert(host, store);
        Ok(())
    }

    /// 启动时回灌 App 持久化的路由表原文；必须先 `set_routes_url`
    pub fn load_route_table_json(doh_url: &str, raw: &str) -> Result<()> {
        let Some(host) = Self::doh_url_host(doh_url) else {
            return Err(DohProxyError::InvalidUrl(format!(
                "Invalid DoH URL: {}",
                doh_url
            )));
        };
        let store = Self::route_table_registry().read().get(&host).cloned();
        let Some(store) = store else {
            return Err(DohProxyError::Dns(format!(
                "No route table registered for {}",
                host
            )));
        };
        store.apply_raw(raw, true).map(|_| ())
    }

    /// 当前 resolver 可用的路由表；没登记、拉不到或已超 max_stale 时为 None
    pub(crate) async fn active_route_table(&self) -> Option<Arc<RouteTable>> {
        let host = self.doh_ip.as_ref()?.host().to_string();
        let store = Self::route_table_registry().read().get(&host).cloned()?;
        store.current().await
    }

    fn accel_upstreams() -> &'static RwLock<HashMap<String, DohUpstream>> {
        ACCEL_UPSTREAMS.get_or_init(|| RwLock::new(HashMap::new()))
    }

    /// 加速接口（令牌申请/续期等）用的 HTTP 客户端：和 DoH 同一套 reqwest/rustls 栈，
    /// 按 scheme://authority 缓存，不挂上游代理
    fn accel_upstream_for(uri: &Uri) -> Result<DohUpstream> {
        let host = uri.host().ok_or_else(|| {
            DohProxyError::InvalidUrl(format!("Accel URL has no host: {}", uri))
        })?;
        let key = format!(
            "{}://{}",
            uri.scheme_str().unwrap_or("https"),
            uri.authority().map(|a| a.as_str()).unwrap_or(host)
        );
        if let Some(upstream) = Self::accel_upstreams().read().get(&key) {
            return Ok(upstream.clone());
        }
        let bootstrap_ips = Self::bootstrap_ips_for_host(host);
        let upstream = Self::build_doh_upstream(
            uri.clone(),
            &bootstrap_ips,
            Duration::from_secs(ACCEL_REQUEST_TIMEOUT_SECS),
            None,
        )?;
        let upstream = Self::accel_upstreams()
            .write()
            .entry(key)
            .or_insert(upstream)
            .clone();
        Ok(upstream)
    }

    /// 经 DoH 同一套客户端发加速接口请求。只记录方法、主机、路径和状态码，不记录头和 body
    pub async fn accel_request(
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> Result<AccelResponse> {
        let uri: Uri = url
            .parse()
            .map_err(|e| DohProxyError::InvalidUrl(format!("Invalid accel URL '{}': {}", url, e)))?;
        if !matches!(uri.scheme_str(), Some("http") | Some("https")) {
            return Err(DohProxyError::InvalidUrl(format!(
                "Accel URL must be http(s): {}",
                url
            )));
        }
        let method = reqwest::Method::from_bytes(method.trim().to_ascii_uppercase().as_bytes())
            .map_err(|_| DohProxyError::InvalidUrl(format!("Invalid HTTP method: {}", method)))?;
        // 优选覆盖的主机（atlas / cfhub6 / *.linux.do）先经赢家 IP + ECH 发，失败再走 reqwest
        if let Some(host) = uri.host().filter(|host| Self::is_covered_host(host)) {
            if let Some(selector) = Selector::global() {
                let header_refs: Vec<(&str, &str)> = headers
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_str()))
                    .collect();
                let path = uri
                    .path_and_query()
                    .map(|pq| pq.as_str())
                    .unwrap_or("/");
                if let Some(reply) = selector
                    .https_via_winner(host, method.as_str(), path, &header_refs, body.map(<[u8]>::to_vec))
                    .await
                {
                    debug!(
                        "Accel {} {}{} -> {} via selector winner",
                        method, host, path, reply.status
                    );
                    return Ok(AccelResponse {
                        status: reply.status,
                        body: String::from_utf8_lossy(&reply.body).into_owned(),
                    });
                }
            }
        }
        let upstream = Self::accel_upstream_for(&uri)?;
        let start = Instant::now();
        let response = upstream
            .send_http(method.clone(), url, headers, body, false, false)
            .await?;
        let status = response.status().as_u16();
        let body = response
            .text()
            .await
            .map_err(|e| DohProxyError::Dns(format!("Accel response read failed: {}", e)))?;
        debug!(
            "Accel {} {}{} -> {} in {} ms",
            method,
            uri.host().unwrap_or(""),
            uri.path(),
            status,
            start.elapsed().as_millis()
        );
        Ok(AccelResponse { status, body })
    }

    fn auth_token_registry() -> &'static RwLock<HashMap<String, String>> {
        DOH_AUTH_TOKENS.get_or_init(|| RwLock::new(HashMap::new()))
    }

    /// 登记 DoH 服务器的访问令牌（按 DoH 域名）；token 为空时取消登记。
    /// 每次查询时读取，换令牌不需要重建 resolver，也不清 DNS 缓存。
    pub fn set_auth_token(doh_url: &str, token: Option<&str>) {
        let Some(host) = Self::doh_url_host(doh_url) else {
            return;
        };
        let token = token.map(str::trim).filter(|token| !token.is_empty());
        let mut registry = Self::auth_token_registry().write();
        match token {
            Some(token) if http::HeaderValue::from_str(&format!("Bearer {}", token)).is_ok() => {
                registry.insert(host, token.to_string());
            }
            Some(_) => {
                warn!("Ignoring invalid DoH auth token for {}", host);
                registry.remove(&host);
            }
            None => {
                registry.remove(&host);
            }
        }
    }

    fn auth_token_for_uri(uri: &Uri) -> Option<String> {
        let host = uri.host()?.trim_matches(['[', ']']).to_ascii_lowercase();
        Self::auth_token_registry().read().get(&host).cloned()
    }

    /// 取出并清除「令牌被拒」标记：返回 true 说明需要重新申请令牌
    pub fn take_auth_rejected() -> bool {
        DOH_AUTH_REJECTED.swap(false, Ordering::Relaxed)
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
            ech_overrides: Arc::new(RwLock::new(HashMap::new())),
            ech_inflight: Arc::new(Mutex::new(HashMap::new())),
            ip_inflight: Arc::new(Mutex::new(HashMap::new())),
            ip_rtt_cache: Arc::new(RwLock::new(HashMap::new())),
            preferred_host_ip_cache: Arc::new(RwLock::new(HashMap::new())),
            family_affinity: Arc::new(RwLock::new(None)),
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
        // IP 字面量没有 HTTPS 记录
        if domain.trim_matches(['[', ']']).parse::<IpAddr>().is_ok() {
            return Ok(None);
        }

        // 定期清理过期缓存
        self.maybe_cleanup_caches();

        // 服务端 retry_configs 给的新钥匙优先
        if let Some(key) = self.ech_override(domain) {
            debug!("ECH override used for {}", domain);
            return Ok(Some(key));
        }
        // 优选覆盖的域名用 Selector 当前钥匙（含自愈后的新钥匙）
        if Self::is_covered_host(domain) {
            if let Some(key) = Selector::global().and_then(|s| s.current_ech_key()) {
                debug!("Selector ECH key used for {}", domain);
                return Ok(Some(key));
            }
        }

        // 查表模式：表里有就用表里的 ECH，没有按无 ECH 处理，都不再查 DoH
        if let Some(table) = self.active_route_table().await {
            return Ok(table.lookup(domain).and_then(|entry| entry.ech.clone()));
        }

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
        Self::parse_https_hints(https)
    }

    /// 同上，不依赖 resolver 实例（优选模块经公共 DoH 查 HTTPS 记录时用）
    pub(crate) fn parse_https_hints(https: &HTTPS) -> HttpsHints {
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

    pub(crate) fn ensure_ech_config_list_len_prefix(bytes: Vec<u8>) -> Vec<u8> {
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
        // IP 字面量不用解析
        if let Ok(ip) = domain.trim_matches(['[', ']']).parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let lookup_start = Instant::now();

        // 定期清理过期缓存
        self.maybe_cleanup_caches();

        // 查表模式：命中直接用表里的地址，不发 DoH；表外域名按表的 miss 策略
        let table = self.active_route_table().await;

        // 一等：优选覆盖的域名先用赢家 IP，表地址跟在后面兜底；
        // 等待竞速与等待拉表共用从 lookup 开始算的同一个 deadline
        if Self::is_covered_host(domain) {
            if let Some(selector) = Selector::global() {
                let deadline = lookup_start + Duration::from_secs(SELECT_LOOKUP_WAIT_SECS);
                if let Some(winner) = selector.winner_for_lookup(deadline).await {
                    let mut addrs = vec![winner.ip];
                    if let Some(entry) = table.as_ref().and_then(|table| table.lookup(domain)) {
                        let mut extra = entry.addrs.clone();
                        self.sort_addrs_by_preference(&mut extra);
                        for ip in extra {
                            if !addrs.contains(&ip) {
                                addrs.push(ip);
                            }
                        }
                    }
                    debug!("Selector winner first for {}", domain);
                    return Ok(addrs);
                }
            }
        }
        if let Some(entry) = table.as_ref().and_then(|table| table.lookup(domain)) {
            if !entry.addrs.is_empty() {
                let mut addrs = entry.addrs.clone();
                self.sort_addrs_by_preference(&mut addrs);
                debug!("Route table hit for {}", domain);
                return Ok(addrs);
            }
        }
        let system_first = table
            .as_ref()
            .is_some_and(|table| table.miss_policy == MissPolicy::SystemFirst);

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

        // 表外域名先走系统 DNS，解析不出再落到 DoH
        if system_first {
            match self.system_lookup_ip(domain).await {
                Ok(addrs) => {
                    self.put_ip_cache(domain, addrs.clone(), Duration::from_secs(MIN_TTL_SECS));
                    let mut inflight = self.ip_inflight.lock().await;
                    inflight.remove(domain);
                    notify.notify_waiters();
                    return Ok(addrs);
                }
                Err(error) => {
                    debug!(
                        "System DNS lookup failed for {}, falling back to DoH: {}",
                        domain, error
                    );
                }
            }
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
        self.sort_addrs_by_preference(&mut addrs);

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

    fn sort_addrs_by_preference(&self, addrs: &mut [IpAddr]) {
        if self.prefer_ipv6 {
            addrs.sort_by_key(|a| if a.is_ipv6() { 0 } else { 1 });
        } else {
            addrs.sort_by_key(|a| if a.is_ipv4() { 0 } else { 1 });
        }
    }

    /// 用系统 DNS 解析（查表模式下表外域名的首选路径）
    async fn system_lookup_ip(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let host = domain.trim_end_matches('.').to_string();
        let resolved = tokio::time::timeout(self.resolve_timeout, lookup_host((host, 0)))
            .await
            .map_err(|_| DohProxyError::Timeout)?
            .map_err(|e| DohProxyError::Dns(format!("System DNS failed for {}: {}", domain, e)))?;
        let mut addrs: Vec<IpAddr> = Vec::new();
        for addr in resolved {
            let ip = addr.ip();
            if !addrs.contains(&ip) {
                addrs.push(ip);
            }
        }
        if addrs.is_empty() {
            return Err(DohProxyError::Dns(format!(
                "System DNS returned no address for {}",
                domain
            )));
        }
        self.sort_addrs_by_preference(&mut addrs);
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
        // 表命中的域名不进 ip_cache，缓存时长按表的新鲜期给
        let table_ttl = match self.active_route_table().await {
            Some(table) if table.lookup(domain).is_some_and(|e| !e.addrs.is_empty()) => {
                Some(table.ttl_hint(Instant::now()))
            }
            _ => None,
        };
        let ttl = table_ttl
            .or_else(|| self.remaining_ttl_for_host(domain))
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

    /// 登记额外由本地优选覆盖的主机名（atlas、cfhub6）
    pub fn set_extra_covered_hosts(hosts: &[String]) {
        let normalized: Vec<String> = hosts
            .iter()
            .map(|h| h.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|h| !h.is_empty())
            .collect();
        *EXTRA_COVERED_HOSTS
            .get_or_init(|| RwLock::new(Vec::new()))
            .write() = normalized;
    }

    /// 是否由本地优选覆盖：linux.do / *.linux.do，以及登记的额外主机名。
    /// 不按「表内地址在 CF 网段」扩展：别的 zone 可能用 CF 专用边缘，赢家 IP 对它们是 403，
    /// 会把无关失败算到赢家头上
    pub(crate) fn is_covered_host(host: &str) -> bool {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host == "linux.do" || host.ends_with(".linux.do") {
            return true;
        }
        EXTRA_COVERED_HOSTS
            .get()
            .is_some_and(|hosts| hosts.read().contains(&host))
    }

    /// 写入服务端 retry_configs 给的新钥匙，覆盖表和缓存里的旧钥匙
    pub fn override_ech_config(&self, domain: &str, key: EchConfigListBytes<'static>, ttl: Duration) {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        self.ech_overrides
            .write()
            .insert(domain, (key, std::time::Instant::now() + ttl));
    }

    fn ech_override(&self, domain: &str) -> Option<EchConfigListBytes<'static>> {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        let now = std::time::Instant::now();
        self.ech_overrides
            .read()
            .get(&domain)
            .filter(|(_, expires_at)| *expires_at > now)
            .map(|(key, _)| key.clone())
    }

    pub fn clear_host_cache(&self, domain: &str) {
        self.ip_cache.write().remove(domain);
        self.ech_overrides.write().remove(domain);
        self.ech_cache.write().remove(domain);
        self.ech_negative_cache.write().remove(domain);
        self.preferred_host_ip_cache.write().remove(domain);
    }

    pub fn clear_all_caches(&self) {
        self.ip_cache.write().clear();
        self.ech_overrides.write().clear();
        self.ech_cache.write().clear();
        self.ech_negative_cache.write().clear();
        self.ip_rtt_cache.write().clear();
        self.preferred_host_ip_cache.write().clear();
        // 网络切换后地址族可能变化（如 Wi-Fi 双栈 → 蜂窝 v4-only），亲和一并重置
        *self.family_affinity.write() = None;
    }

    /// 当前出站地址族亲和（`Some(true)` = IPv6 优先），未建连过时为 `None`
    pub fn family_affinity(&self) -> Option<bool> {
        *self.family_affinity.read()
    }

    /// 本次建连应优先的地址族：有亲和用亲和，否则按配置的 prefer_ipv6
    pub fn effective_prefer_ipv6(&self) -> bool {
        self.family_affinity().unwrap_or(self.prefer_ipv6)
    }

    /// 记录一次成功建连所用的地址族。`force` 为 false 时只在尚无亲和时写入；
    /// 为 true 表示原亲和族已整体连不上、由另一族接管，强制切换。
    pub fn record_family_affinity(&self, addr: IpAddr, force: bool) {
        let is_ipv6 = addr.is_ipv6();
        let mut affinity = self.family_affinity.write();
        match *affinity {
            Some(current) if current == is_ipv6 => {}
            Some(_) if !force => {}
            Some(_) => {
                info!(
                    "Address family affinity switched to {}",
                    if is_ipv6 { "IPv6" } else { "IPv4" }
                );
                *affinity = Some(is_ipv6);
            }
            None => {
                info!(
                    "Address family affinity set to {}",
                    if is_ipv6 { "IPv6" } else { "IPv4" }
                );
                *affinity = Some(is_ipv6);
            }
        }
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
        let addr = self
            .preferred_host_ip_cache
            .read()
            .get(domain)
            .filter(|entry| entry.expires_at > now)
            .map(|entry| entry.addr)?;
        // 粘性 IP 与当前地址族亲和不一致（亲和切换前记下的）：作废，按亲和重连
        if let Some(prefer_ipv6) = self.family_affinity() {
            if addr.is_ipv6() != prefer_ipv6 {
                debug!(
                    "Dropping sticky IP {} for {}: address family differs from affinity",
                    addr, domain
                );
                self.clear_preferred_host_ip(domain);
                return None;
            }
        }
        Some(addr)
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
        self.ech_overrides.write().retain(|_, (_, exp)| *exp > now);
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

    pub(crate) fn build_doh_upstream(
        uri: Uri,
        bootstrap_ips: &[IpAddr],
        timeout: Duration,
        upstream_proxy: Option<&UpstreamProxyConfig>,
    ) -> Result<DohUpstream> {
        // 走上游代理时由代理解析 DoH 域名，备用节点没有意义；IP 字面量也不需要
        let bootstrap_host = uri
            .host()
            .filter(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().is_err())
            .filter(|_| upstream_proxy.is_none())
            .map(|host| host.to_ascii_lowercase());

        let Some(host) = bootstrap_host else {
            let client = Self::build_doh_client(Client::builder(), timeout, upstream_proxy)?;
            return Ok(DohUpstream::new(uri, client, None));
        };

        // 备用客户端总是建好：建连时才读当前节点（已下发列表 > 登记种子 > 这里的 initial），
        // 首装没有任何备用 IP 时节点列表一到就能用，不用重建。
        // 主客户端只在一开始就有备用节点时缩短连接超时，第三方 DoH 行为不变
        let primary_builder = if bootstrap_ips.is_empty() {
            Client::builder()
        } else {
            Client::builder()
                .connect_timeout(Duration::from_secs(DOH_PRIMARY_CONNECT_TIMEOUT_SECS))
        };
        let client = Self::build_doh_client(primary_builder, timeout, None)?;
        let resolver = Arc::new(BootstrapResolver {
            host,
            initial: bootstrap_ips.to_vec(),
        });
        let bootstrap_client = Self::build_doh_client(
            Client::builder()
                .connect_timeout(Duration::from_secs(DOH_BOOTSTRAP_CONNECT_TIMEOUT_SECS))
                .dns_resolver(resolver.clone()),
            timeout,
            None,
        )?;
        Ok(DohUpstream::new(uri, client, Some(bootstrap_client)).with_bootstrap(resolver))
    }

    fn build_doh_client(
        builder: reqwest::ClientBuilder,
        timeout: Duration,
        upstream_proxy: Option<&UpstreamProxyConfig>,
    ) -> Result<Client> {
        let mut builder = builder.timeout(timeout).user_agent(DOH_USER_AGENT);
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
        let start = std::time::Instant::now();

        let bytes = Self::encode_query(domain, record_type)?;

        let response = upstream.query(&bytes).await?;

        if !response.status().is_success() {
            return Err(DohProxyError::Dns(format!(
                "DoH http error: {}",
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
            .map_err(|e| DohProxyError::Dns(format!("DoH read failed: {}", e)))?;
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

    /// 编码一条 DNS 查询报文：RD=1、EDNS(0) 1232 字节，并按 RFC 8467 用 Padding 选项
    /// 把整个报文填到 `DNS_QUERY_PAD_BLOCK` 的整倍数，去掉报文长度特征
    pub(crate) fn encode_query(
        domain: &str,
        record_type: hickory_resolver::proto::rr::RecordType,
    ) -> Result<Vec<u8>> {
        use hickory_resolver::proto::op::{Edns, Message, Query};
        use hickory_resolver::proto::rr::rdata::opt::EdnsOption;
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

        let unpadded_len = request
            .to_vec()
            .map_err(|e| DohProxyError::Dns(format!("Failed to encode DNS query: {}", e)))?
            .len();
        // Padding 选项自身占 4 字节（code + length）
        let pad = (DNS_QUERY_PAD_BLOCK - (unpadded_len + 4) % DNS_QUERY_PAD_BLOCK)
            % DNS_QUERY_PAD_BLOCK;
        if let Some(edns) = request.extensions_mut().as_mut() {
            edns.options_mut()
                .insert(EdnsOption::Unknown(12, vec![0; pad]));
        }

        request
            .to_vec()
            .map_err(|e| DohProxyError::Dns(format!("Failed to encode DNS query: {}", e)))
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

    /// 读完整的 HTTP 请求：头部文本，以及按 content-length 读满的请求体
    async fn read_request(stream: &mut tokio::net::TcpStream) -> (String, Vec<u8>) {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let header_end = loop {
            let n = stream.read(&mut chunk).await.unwrap_or(0);
            if n == 0 {
                break buf.len();
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
        };
        let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
        let content_length = header_value(&head, "content-length")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        while buf.len() < header_end + content_length {
            let n = stream.read(&mut chunk).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        (head, buf[header_end..].to_vec())
    }

    /// 本机上有别的程序会探测新开的端口（见过 Go-http-client 的 `GET /`），
    /// 不是打到查询路径的请求一律回 404 并忽略，避免干扰断言
    async fn is_doh_request(stream: &mut tokio::net::TcpStream, head: &str) -> bool {
        if head.contains(" /v1/lookup") {
            return true;
        }
        let _ = stream
            .write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            .await;
        false
    }

    fn header_value(head: &str, name: &str) -> Option<String> {
        head.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name)
                .then(|| value.trim().to_string())
        })
    }

    /// 从请求里取出 DNS 查询报文：POST 看请求体，GET 看 `?dns=`
    fn query_message(head: &str, body: &[u8]) -> Message {
        if head.starts_with("POST ") {
            return Message::from_vec(body).unwrap();
        }
        let encoded = head
            .split("dns=")
            .nth(1)
            .and_then(|rest| rest.split(' ').next())
            .unwrap_or_default();
        Message::from_vec(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap()
    }

    /// A 查询回 1.2.3.4，其他类型回空应答
    async fn write_dns_answer(stream: &mut tokio::net::TcpStream, query: &Message) {
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
    }

    /// 本地假 DoH 服务器（明文 HTTP），GET/POST 都接受；返回端口和收到的每个请求头部
    async fn spawn_fake_doh() -> (u16, Arc<parking_lot::Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let seen_by_server = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let seen = seen_by_server.clone();
                tokio::spawn(async move {
                    let (head, body) = read_request(&mut stream).await;
                    if !is_doh_request(&mut stream, &head).await {
                        return;
                    }
                    seen.lock().push(head.clone());
                    let query = query_message(&head, &body);
                    write_dns_answer(&mut stream, &query).await;
                });
            }
        });
        (port, seen)
    }

    /// 只支持 GET 的假 DoH 服务器：POST 一律回 405；返回端口和收到的每个请求头部
    async fn spawn_get_only_doh() -> (u16, Arc<parking_lot::Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let seen_by_server = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let seen = seen_by_server.clone();
                tokio::spawn(async move {
                    let (head, body) = read_request(&mut stream).await;
                    if !is_doh_request(&mut stream, &head).await {
                        return;
                    }
                    seen.lock().push(head.clone());
                    if head.starts_with("POST ") {
                        let _ = stream
                            .write_all(
                                b"HTTP/1.1 405 Method Not Allowed\r\nallow: GET\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                            )
                            .await;
                        return;
                    }
                    let query = query_message(&head, &body);
                    write_dns_answer(&mut stream, &query).await;
                });
            }
        });
        (port, seen)
    }

    /// 只认 `Bearer good-token` 的假 DoH 服务器：其他令牌回 401，并记下收到的 Authorization 头
    async fn spawn_auth_doh() -> (u16, Arc<parking_lot::Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let seen_by_server = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let seen = seen_by_server.clone();
                tokio::spawn(async move {
                    let (head, body) = read_request(&mut stream).await;
                    if !is_doh_request(&mut stream, &head).await {
                        return;
                    }
                    let auth = header_value(&head, "authorization").unwrap_or_default();
                    seen.lock().push(auth.clone());
                    if auth != "Bearer good-token" {
                        let _ = stream
                            .write_all(
                                b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                            )
                            .await;
                        return;
                    }
                    let query = query_message(&head, &body);
                    write_dns_answer(&mut stream, &query).await;
                });
            }
        });
        (port, seen)
    }

    async fn closed_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    }

    /// 主地址是系统 DNS 解析不出的 .invalid 域名，备用节点指向本机 port
    fn unresolvable_upstream(port: u16) -> DohUpstream {
        unresolvable_upstream_named("doh-bootstrap-test.invalid", port)
    }

    /// 同上，但 DoH 域名由调用方指定：路由表、令牌登记都按域名全局登记，
    /// 各测试并行跑，每个用自己的域名互不干扰
    fn unresolvable_upstream_named(host: &str, port: u16) -> DohUpstream {
        let uri: Uri = format!("http://{}:{}/v1/lookup", host, port)
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

    /// 本地假 JSON 接口（明文 HTTP）：只响应 `path` 上的请求，按顺序回 `responses`（用完重复最后一个）；
    /// 返回端口和收到的每个请求头部
    async fn spawn_fake_json(
        path: &'static str,
        responses: Vec<(u16, String)>,
    ) -> (u16, Arc<parking_lot::Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let seen_by_server = seen.clone();
        let responses = Arc::new(responses);
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let seen = seen_by_server.clone();
                let responses = responses.clone();
                let counter = counter.clone();
                tokio::spawn(async move {
                    let (head, _body) = read_request(&mut stream).await;
                    let request_path = head.split(' ').nth(1).unwrap_or("");
                    if request_path != path {
                        let _ = stream
                            .write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                            .await;
                        return;
                    }
                    seen.lock().push(head.clone());
                    let index = counter
                        .fetch_add(1, Ordering::SeqCst)
                        .min(responses.len().saturating_sub(1));
                    let (status, body) = &responses[index];
                    let reason = match status {
                        200 => "OK",
                        401 => "Unauthorized",
                        404 => "Not Found",
                        500 => "Internal Server Error",
                        _ => "Status",
                    };
                    let response = format!(
                        "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        status,
                        reason,
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        (port, seen)
    }

    const TABLE_V4: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);
    const TABLE_V6: std::net::Ipv6Addr = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10);

    /// 只含 `linux.do`（wildcard）一条的路由表 JSON
    fn route_table_json(
        generated: u64,
        ttl: u64,
        max_stale: u64,
        miss: Option<&str>,
        nodes: Option<serde_json::Value>,
    ) -> String {
        let mut json = serde_json::json!({
            "generated": generated,
            "serial": generated,
            "ttl": ttl,
            "max_stale": max_stale,
            "routes": [
                {
                    "name": "linux.do",
                    "wildcard": true,
                    "v4": [TABLE_V4.to_string()],
                    "v6": [TABLE_V6.to_string()],
                    "ttl": 300
                }
            ]
        });
        if let Some(miss) = miss {
            json["miss"] = miss.into();
        }
        if let Some(nodes) = nodes {
            json["nodes"] = nodes;
        }
        json.to_string()
    }

    /// 查表模式的 resolver：DoH 和路由表接口都挂在 `name` 这个解析不出的域名上，备用节点指向本机
    async fn table_mode_resolver(
        name: &str,
        doh_port: u16,
        routes_port: u16,
    ) -> (DnsResolver, String) {
        let doh_url = format!("http://{}:{}/v1/lookup", name, doh_port);
        let routes_url = format!("http://{}:{}/v1/routes", name, routes_port);
        DnsResolver::set_bootstrap_ips(&doh_url, &["127.0.0.1".into()]);
        DnsResolver::set_routes_url(&doh_url, Some(&routes_url), None).unwrap();
        let resolver = resolver_with(unresolvable_upstream_named(name, doh_port)).await;
        (resolver, doh_url)
    }

    /// 生成一对测试用 Ed25519 密钥，并把公钥按 kid 登记到测试公钥表
    fn test_keypair(kid: &str) -> ring::signature::Ed25519KeyPair {
        use ring::signature::{Ed25519KeyPair, KeyPair};
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(keypair.public_key().as_ref());
        TEST_NODE_LIST_PUBKEYS
            .get_or_init(|| RwLock::new(Vec::new()))
            .write()
            .push((kid.to_string(), pubkey));
        keypair
    }

    fn signed_envelope(
        keypair: &ring::signature::Ed25519KeyPair,
        kid: &str,
        payload_json: &str,
    ) -> NodesEnvelope {
        NodesEnvelope {
            kid: kid.to_string(),
            payload: STANDARD.encode(payload_json.as_bytes()),
            sig: STANDARD.encode(keypair.sign(payload_json.as_bytes()).as_ref()),
        }
    }

    /// 等到条件成立或超时
    async fn wait_until(mut condition: impl FnMut() -> bool, limit: Duration) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < limit {
            if condition() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        condition()
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
        // 备用节点在建连时动态读取，登记与否都不换 resolver
        assert_eq!(
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

    /// `DOH_AUTH_REJECTED` 是进程全局标记，会碰它的测试串行跑
    static AUTH_FLAG_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn sends_auth_token_and_recovers_after_token_change() {
        let _serial = AUTH_FLAG_LOCK.lock().await;
        let (port, seen) = spawn_auth_doh().await;
        let url = format!("http://auth-test.invalid:{}/v1/lookup", port);
        let upstream = DnsResolver::build_doh_upstream(
            url.parse().unwrap(),
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
            Duration::from_secs(5),
            None,
        )
        .unwrap();
        let resolver = resolver_with(upstream.clone()).await;

        // 令牌被拒：查询失败，打上标记并暂停，暂停期间不再发请求
        DnsResolver::set_auth_token(&url, Some("bad-token"));
        DnsResolver::take_auth_rejected();
        assert!(resolver.lookup_ip("example.com").await.is_err());
        assert!(DnsResolver::take_auth_rejected());
        assert!(!DnsResolver::take_auth_rejected());
        let requests_before = seen.lock().len();
        assert!(resolver.lookup_ip("example.org").await.is_err());
        assert_eq!(seen.lock().len(), requests_before);

        // 换成有效令牌后立即恢复，不用等暂停结束
        DnsResolver::set_auth_token(&url, Some("good-token"));
        let addrs = resolver.lookup_ip("example.net").await.unwrap();
        assert_eq!(addrs, vec![IpAddr::V4(FAKE_ANSWER)]);
        assert!(seen.lock().iter().any(|auth| auth == "Bearer good-token"));
        assert!(!DnsResolver::take_auth_rejected());

        // 取消登记后不再带 Authorization 头
        DnsResolver::set_auth_token(&url, None);
        let _ = resolver.lookup_ip("example.edu").await;
        assert_eq!(seen.lock().last().map(String::as_str), Some(""));
    }

    #[test]
    fn invalid_auth_token_is_not_registered() {
        let url = "https://token-test.example/v1/lookup";
        let uri: Uri = url.parse().unwrap();
        DnsResolver::set_auth_token(url, Some("ok-token"));
        assert_eq!(
            DnsResolver::auth_token_for_uri(&uri).as_deref(),
            Some("ok-token")
        );
        DnsResolver::set_auth_token(url, Some("bad\r\ntoken"));
        assert!(DnsResolver::auth_token_for_uri(&uri).is_none());
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
        let (port, _) = spawn_fake_doh().await;
        let upstream = unresolvable_upstream(port);
        let resolver = resolver_with(upstream.clone()).await;

        let addrs = resolver.lookup_ip("example.com").await.unwrap();
        assert_eq!(addrs, vec![IpAddr::V4(FAKE_ANSWER)]);

        let health = upstream.health.lock();
        assert!(health.prefer_bootstrap_until.is_some());
        assert_eq!(health.consecutive_failures, 0);
    }

    /// 查询默认用 POST：报文放请求体，带 content-type/accept 和固定 UA，地址里没有 `dns=`
    #[tokio::test]
    async fn posts_dns_message_with_fixed_user_agent() {
        let (port, seen) = spawn_fake_doh().await;
        let resolver = resolver_with(unresolvable_upstream(port)).await;

        let addrs = resolver.lookup_ip("example.com").await.unwrap();
        assert_eq!(addrs, vec![IpAddr::V4(FAKE_ANSWER)]);

        let heads = seen.lock();
        assert!(!heads.is_empty());
        for head in heads.iter() {
            assert!(head.starts_with("POST /v1/lookup HTTP/1.1"), "{}", head);
            assert!(!head.contains("dns="), "{}", head);
            assert_eq!(
                header_value(head, "content-type").as_deref(),
                Some("application/dns-message")
            );
            assert_eq!(
                header_value(head, "accept").as_deref(),
                Some("application/dns-message")
            );
            assert_eq!(
                header_value(head, "user-agent").as_deref(),
                Some(DOH_USER_AGENT)
            );
        }
    }

    /// 服务器回 405 时立刻改用 GET 重发，之后一直用 GET
    #[tokio::test]
    async fn falls_back_to_get_when_post_is_rejected() {
        let (port, seen) = spawn_get_only_doh().await;
        let upstream = unresolvable_upstream(port);
        let resolver = resolver_with(upstream.clone()).await;

        let addrs = resolver.lookup_ip("example.com").await.unwrap();
        assert_eq!(addrs, vec![IpAddr::V4(FAKE_ANSWER)]);
        assert!(upstream.health.lock().get_only);
        let first_round = seen.lock().len();
        {
            let heads = seen.lock();
            assert!(heads.iter().any(|head| head.starts_with("POST ")));
            assert!(heads
                .iter()
                .any(|head| head.starts_with("GET /v1/lookup?dns=")));
        }

        let addrs = resolver.lookup_ip("example.org").await.unwrap();
        assert_eq!(addrs, vec![IpAddr::V4(FAKE_ANSWER)]);
        let heads = seen.lock();
        assert!(heads.len() > first_round);
        assert!(heads[first_round..]
            .iter()
            .all(|head| head.starts_with("GET /v1/lookup?dns=")));
    }

    #[tokio::test]
    async fn cools_down_after_repeated_failures() {
        let upstream = unresolvable_upstream(closed_port().await);
        let message = b"not-a-real-query";
        for _ in 0..DOH_FAILURES_BEFORE_COOLDOWN {
            assert!(upstream.query(message).await.is_err());
        }

        let start = std::time::Instant::now();
        let error = upstream.query(message).await.unwrap_err();
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

    /// 查询报文带 EDNS Padding，整体填到 128 字节整倍数，问题段和类型不受影响
    #[test]
    fn pads_query_to_128_byte_multiple() {
        use hickory_resolver::proto::rr::rdata::opt::EdnsCode;
        let domains = [
            "a.io",
            "linux.do",
            "some-rather-long-subdomain-name.cdn.example-domain-with-many-labels.co.uk",
        ];
        for domain in domains {
            for record_type in [RecordType::A, RecordType::AAAA, RecordType::HTTPS] {
                let bytes = DnsResolver::encode_query(domain, record_type).unwrap();
                assert_eq!(
                    bytes.len() % DNS_QUERY_PAD_BLOCK,
                    0,
                    "{} {} -> {} bytes",
                    domain,
                    record_type,
                    bytes.len()
                );
                let message = Message::from_vec(&bytes).unwrap();
                let question = &message.queries()[0];
                assert_eq!(question.name().to_utf8(), format!("{}.", domain));
                assert_eq!(question.query_type(), record_type);
                assert!(message.recursion_desired());
                let edns = message.extensions().as_ref().expect("EDNS present");
                assert_eq!(edns.max_payload(), 1232);
                assert!(edns.option(EdnsCode::Padding).is_some());
            }
        }
    }

    /// 表命中：直接用表里的地址，DoH 服务器收不到任何查询；表请求带 JSON accept 和固定 UA
    #[tokio::test]
    async fn route_table_hit_skips_doh() {
        let (doh_port, doh_seen) = spawn_fake_doh().await;
        let table = route_table_json(now_unix(), 600, 86400, None, None);
        let (routes_port, routes_seen) = spawn_fake_json("/v1/routes", vec![(200, table)]).await;
        let (resolver, _) = table_mode_resolver("table-hit.invalid", doh_port, routes_port).await;

        let result = resolver.lookup_host("linux.do", false).await.unwrap();
        assert_eq!(
            result.addrs,
            vec![IpAddr::V4(TABLE_V4), IpAddr::V6(TABLE_V6)]
        );
        assert!(result.ech_config.is_none());
        assert!(result.ttl >= Duration::from_secs(MIN_TTL_SECS));
        assert!(result.ttl <= Duration::from_secs(600));

        // 通配：子域名也命中
        let addrs = resolver.lookup_ip("cdn.linux.do").await.unwrap();
        assert_eq!(addrs[0], IpAddr::V4(TABLE_V4));
        let (ech, ip) = resolver.lookup_ech_and_ip("connect.linux.do").await;
        assert!(ech.is_none());
        assert_eq!(ip.unwrap()[0], IpAddr::V4(TABLE_V4));

        assert!(doh_seen.lock().is_empty(), "{:?}", doh_seen.lock());
        let heads = routes_seen.lock();
        assert_eq!(heads.len(), 1);
        assert!(heads[0].starts_with("GET /v1/routes HTTP/1.1"), "{}", heads[0]);
        assert_eq!(
            header_value(&heads[0], "accept").as_deref(),
            Some("application/json")
        );
        assert_eq!(
            header_value(&heads[0], "user-agent").as_deref(),
            Some(DOH_USER_AGENT)
        );
        assert!(header_value(&heads[0], "authorization").is_none());
    }

    /// 通配只向下匹配，精确条目不向下匹配；ech 字段解成带长度前缀的 ECHConfigList
    #[test]
    fn route_table_wildcard_matches_subdomains() {
        let json: RouteTableJson = serde_json::from_str(
            &serde_json::json!({
                "generated": now_unix(),
                "ttl": 600,
                "max_stale": 86400,
                "routes": [
                    {"name": "Linux.do", "wildcard": true, "v4": ["203.0.113.10"]},
                    {"name": "cdn.linux.do", "wildcard": false, "v4": ["203.0.113.11"], "ech": STANDARD.encode([0xfe, 0x0d, 0x00, 0x00])},
                    {"name": "exact.example", "v4": ["203.0.113.12"], "ech": ""}
                ]
            })
            .to_string(),
        )
        .unwrap();
        let table = RouteTable::from_json(&json, Duration::ZERO);
        assert_eq!(table.len(), 3);
        assert_eq!(table.miss_policy, MissPolicy::SystemFirst);

        let hit = |host: &str| table.lookup(host).map(|entry| entry.addrs[0]);
        assert_eq!(hit("linux.do"), Some("203.0.113.10".parse().unwrap()));
        assert_eq!(hit("LINUX.DO."), Some("203.0.113.10".parse().unwrap()));
        assert_eq!(hit("a.b.linux.do"), Some("203.0.113.10".parse().unwrap()));
        // 更具体的精确条目优先
        assert_eq!(hit("cdn.linux.do"), Some("203.0.113.11".parse().unwrap()));
        // 精确条目的子域名回落到通配
        assert_eq!(hit("x.cdn.linux.do"), Some("203.0.113.10".parse().unwrap()));
        assert_eq!(hit("exact.example"), Some("203.0.113.12".parse().unwrap()));
        assert_eq!(hit("sub.exact.example"), None);
        assert_eq!(hit("notlinux.do"), None);

        let ech = table.lookup("cdn.linux.do").unwrap().ech.as_ref().unwrap();
        assert_eq!(ech.as_ref(), &[0x00, 0x04, 0xfe, 0x0d, 0x00, 0x00]);
        assert!(table.lookup("exact.example").unwrap().ech.is_none());
        assert!(table.lookup("linux.do").unwrap().ech.is_none());
    }

    /// 表外域名缺省先走系统 DNS（localhost 不碰 DoH），系统 DNS 解析不出才落到 DoH
    #[tokio::test]
    async fn route_table_miss_uses_system_dns_first() {
        let (doh_port, doh_seen) = spawn_fake_doh().await;
        let table = route_table_json(now_unix(), 600, 86400, None, None);
        let (routes_port, _) = spawn_fake_json("/v1/routes", vec![(200, table)]).await;
        let (resolver, _) = table_mode_resolver("table-miss.invalid", doh_port, routes_port).await;

        let addrs = resolver.lookup_ip("localhost").await.unwrap();
        assert!(!addrs.is_empty());
        assert!(addrs.iter().all(IpAddr::is_loopback), "{:?}", addrs);
        assert!(doh_seen.lock().is_empty());

        let addrs = resolver.lookup_ip("nx-table-miss.invalid").await.unwrap();
        assert_eq!(addrs, vec![IpAddr::V4(FAKE_ANSWER)]);
        assert!(!doh_seen.lock().is_empty());
    }

    /// `miss: doh_first` 时表外域名和以前一样直接走 DoH
    #[tokio::test]
    async fn route_table_doh_first_policy_skips_system_dns() {
        let (doh_port, doh_seen) = spawn_fake_doh().await;
        let table = route_table_json(now_unix(), 600, 86400, Some("doh_first"), None);
        let (routes_port, _) = spawn_fake_json("/v1/routes", vec![(200, table)]).await;
        let (resolver, _) =
            table_mode_resolver("table-dohfirst.invalid", doh_port, routes_port).await;

        let addrs = resolver.lookup_ip("localhost").await.unwrap();
        assert_eq!(addrs, vec![IpAddr::V4(FAKE_ANSWER)]);
        assert!(!doh_seen.lock().is_empty());
    }

    /// 过了 ttl 但没超 max_stale：旧表照用，同时后台重新拉一次
    #[tokio::test]
    async fn stale_route_table_is_still_used_and_refreshed() {
        let (doh_port, doh_seen) = spawn_fake_doh().await;
        let table = route_table_json(now_unix(), 1, 600, None, None);
        let (routes_port, routes_seen) = spawn_fake_json("/v1/routes", vec![(200, table)]).await;
        let (resolver, _) =
            table_mode_resolver("table-stale.invalid", doh_port, routes_port).await;

        let addrs = resolver.lookup_ip("linux.do").await.unwrap();
        assert_eq!(addrs[0], IpAddr::V4(TABLE_V4));
        assert_eq!(routes_seen.lock().len(), 1);

        tokio::time::sleep(Duration::from_millis(1500)).await;
        let start = std::time::Instant::now();
        let addrs = resolver.lookup_ip("linux.do").await.unwrap();
        assert_eq!(addrs[0], IpAddr::V4(TABLE_V4));
        assert!(start.elapsed() < Duration::from_secs(1));

        assert!(wait_until(|| routes_seen.lock().len() >= 2, Duration::from_secs(5)).await);
        assert!(doh_seen.lock().is_empty());
    }

    /// 没有可用的表（持久化的已超 max_stale、接口又连不上）：退回 DoH，而且退避期内不再等待
    #[tokio::test]
    async fn route_table_beyond_max_stale_falls_back_to_doh() {
        let (doh_port, doh_seen) = spawn_fake_doh().await;
        let routes_port = closed_port().await;
        let (resolver, doh_url) =
            table_mode_resolver("table-expired.invalid", doh_port, routes_port).await;

        let old = route_table_json(now_unix() - 100_000, 600, 3600, None, None);
        assert!(DnsResolver::load_route_table_json(&doh_url, &old).is_err());

        let start = std::time::Instant::now();
        let addrs = resolver.lookup_ip("linux.do").await.unwrap();
        assert_eq!(addrs, vec![IpAddr::V4(FAKE_ANSWER)]);
        assert!(start.elapsed() < Duration::from_secs(ROUTES_INITIAL_WAIT_SECS + 6));
        assert!(!doh_seen.lock().is_empty());

        let start = std::time::Instant::now();
        let addrs = resolver.lookup_ip("cdn.linux.do").await.unwrap();
        assert_eq!(addrs, vec![IpAddr::V4(FAKE_ANSWER)]);
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    /// 表接口回 401：打上「令牌被拒」标记，查询退回 DoH
    #[tokio::test]
    async fn routes_401_sets_auth_rejected() {
        let _serial = AUTH_FLAG_LOCK.lock().await;
        let (doh_port, _) = spawn_fake_doh().await;
        let body = r#"{"error":{"code":"unauthorized","message":"invalid or missing API key"}}"#;
        let (routes_port, routes_seen) =
            spawn_fake_json("/v1/routes", vec![(401, body.to_string())]).await;
        let (resolver, doh_url) =
            table_mode_resolver("table-401.invalid", doh_port, routes_port).await;
        DnsResolver::set_auth_token(&doh_url, Some("stale-token"));
        DnsResolver::take_auth_rejected();

        let addrs = resolver.lookup_ip("linux.do").await.unwrap();
        assert_eq!(addrs, vec![IpAddr::V4(FAKE_ANSWER)]);
        assert!(DnsResolver::take_auth_rejected());
        let heads = routes_seen.lock();
        assert_eq!(
            header_value(&heads[0], "authorization").as_deref(),
            Some("Bearer stale-token")
        );
    }

    /// App 回灌的表没过期就直接用，不先拉接口；缓存时长按表剩余新鲜期
    #[tokio::test]
    async fn persisted_route_table_is_used_immediately() {
        let (doh_port, doh_seen) = spawn_fake_doh().await;
        let (routes_port, routes_seen) =
            spawn_fake_json("/v1/routes", vec![(500, "{}".to_string())]).await;
        let (resolver, doh_url) =
            table_mode_resolver("table-persist.invalid", doh_port, routes_port).await;
        let persisted = route_table_json(now_unix() - 30, 600, 86400, None, None);
        DnsResolver::load_route_table_json(&doh_url, &persisted).unwrap();

        let result = resolver.lookup_host("linux.do", false).await.unwrap();
        assert_eq!(result.addrs[0], IpAddr::V4(TABLE_V4));
        assert!(result.ttl > Duration::from_secs(500), "{:?}", result.ttl);
        assert!(result.ttl <= Duration::from_secs(570), "{:?}", result.ttl);
        assert!(routes_seen.lock().is_empty());
        assert!(doh_seen.lock().is_empty());

        // 取消登记后回到普通 DoH
        DnsResolver::set_routes_url(&doh_url, None, None).unwrap();
        let addrs = resolver.lookup_ip("linux.do").await.unwrap();
        assert_eq!(addrs, vec![IpAddr::V4(FAKE_ANSWER)]);
    }

    /// 节点列表：坏签名 / 未知 kid / 过期一律拒绝；serial 不比已存的大不接受；
    /// 接受后建连用的备用 IP 立即变化，并与登记的种子合并去重
    #[tokio::test]
    async fn node_list_signature_serial_and_expiry() {
        let kid = "test-2026";
        let keypair = test_keypair(kid);
        let other = test_keypair("other-2026");
        let now = now_unix();
        let payload = |serial: u64, not_after: u64, ips: &[&str]| {
            serde_json::json!({
                "serial": serial,
                "not_after": not_after,
                "hosts": {"node-test.invalid": {"v4": ips, "v6": ["2001:db8::9"]}}
            })
            .to_string()
        };
        let resolver = BootstrapResolver {
            host: "abc.node-test.invalid".to_string(),
            initial: Vec::new(),
        };
        assert!(resolver.current().is_empty());

        let bad_sig = signed_envelope(&other, kid, &payload(10, now + 3600, &["203.0.113.9"]));
        assert!(DnsResolver::verify_node_list(&bad_sig, now).is_err());
        let unknown_kid =
            signed_envelope(&keypair, "nope", &payload(10, now + 3600, &["203.0.113.9"]));
        assert!(DnsResolver::verify_node_list(&unknown_kid, now).is_err());
        let expired = signed_envelope(&keypair, kid, &payload(10, now - 1, &["203.0.113.9"]));
        assert!(DnsResolver::verify_node_list(&expired, now).is_err());
        let mut tampered = signed_envelope(&keypair, kid, &payload(10, now + 3600, &["203.0.113.9"]));
        tampered.payload = STANDARD.encode(payload(99, now + 3600, &["203.0.113.9"]));
        assert!(DnsResolver::verify_node_list(&tampered, now).is_err());

        let good = signed_envelope(&keypair, kid, &payload(10, now + 3600, &["203.0.113.9"]));
        assert!(DnsResolver::accept_node_list(&good).unwrap());
        let expected: Vec<IpAddr> = vec![
            "203.0.113.9".parse().unwrap(),
            "2001:db8::9".parse().unwrap(),
        ];
        assert_eq!(resolver.current(), expected);
        assert_eq!(DnsResolver::bootstrap_ips_for_host("node-test.invalid"), expected);
        assert_eq!(DnsResolver::bootstrap_ips_for_host("NODE-TEST.invalid"), expected);
        assert!(DnsResolver::bootstrap_ips_for_host("xnode-test.invalid").is_empty());
        assert!(DnsResolver::bootstrap_ips_for_host("other-node.invalid").is_empty());

        assert!(!DnsResolver::accept_node_list(&good).unwrap());
        let older = signed_envelope(&keypair, kid, &payload(9, now + 3600, &["203.0.113.8"]));
        assert!(!DnsResolver::accept_node_list(&older).unwrap());
        assert_eq!(resolver.current(), expected);

        // 更新的 serial 生效；登记的种子排在后面并去重
        DnsResolver::set_bootstrap_ips(
            "https://abc.node-test.invalid/v1/lookup",
            &["203.0.113.19".into(), "203.0.113.20".into()],
        );
        let newer = signed_envelope(&keypair, kid, &payload(11, now + 3600, &["203.0.113.19"]));
        assert!(DnsResolver::accept_node_list(&newer).unwrap());
        assert_eq!(
            resolver.current(),
            vec![
                "203.0.113.19".parse::<IpAddr>().unwrap(),
                "2001:db8::9".parse().unwrap(),
                "203.0.113.20".parse().unwrap(),
            ]
        );
        // url-safe 无填充的 base64 也认
        let mut url_safe = newer.clone();
        url_safe.payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(STANDARD.decode(&newer.payload).unwrap());
        url_safe.sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(STANDARD.decode(&newer.sig).unwrap());
        assert_eq!(
            DnsResolver::verify_node_list(&url_safe, now).unwrap().serial,
            11
        );
        // 持久化回灌：验签要过，但同 serial 不算更新
        assert!(!DnsResolver::load_node_list_json(&serde_json::to_string(&newer).unwrap()).unwrap());
        assert!(DnsResolver::load_node_list_json("{\"kid\":\"x\"}").is_err());

        let update = DnsResolver::take_accel_update().expect("node list update pending");
        assert_eq!(update.nodes_envelope.as_ref(), Some(&newer));
        assert!(update.nodes.unwrap().contains("203.0.113.19"));
    }

    /// 加速接口请求走 DoH 同一套客户端：固定 UA、调用方的头原样带上、缺省 accept JSON、经备用节点可达
    #[tokio::test]
    async fn accel_request_sends_json_with_doh_client_path() {
        let (port, seen) = spawn_fake_json("/v1/token", vec![(200, r#"{"ok":true}"#.to_string())]).await;
        DnsResolver::set_bootstrap_ips(
            &format!("http://accel-test.invalid:{}/v1/lookup", port),
            &["127.0.0.1".into()],
        );
        let headers = vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("authorization".to_string(), "Bearer abc".to_string()),
        ];
        let response = DnsResolver::accel_request(
            "post",
            &format!("http://accel-test.invalid:{}/v1/token", port),
            &headers,
            Some(br#"{"a":1}"#),
        )
        .await
        .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, r#"{"ok":true}"#);

        let heads = seen.lock();
        assert_eq!(heads.len(), 1);
        assert!(heads[0].starts_with("POST /v1/token HTTP/1.1"), "{}", heads[0]);
        assert_eq!(
            header_value(&heads[0], "content-type").as_deref(),
            Some("application/json")
        );
        assert_eq!(
            header_value(&heads[0], "authorization").as_deref(),
            Some("Bearer abc")
        );
        assert_eq!(
            header_value(&heads[0], "accept").as_deref(),
            Some("application/json")
        );
        assert_eq!(
            header_value(&heads[0], "user-agent").as_deref(),
            Some(DOH_USER_AGENT)
        );
        assert_eq!(header_value(&heads[0], "content-length").as_deref(), Some("7"));

        assert!(DnsResolver::accel_request("GET", "ftp://x", &[], None)
            .await
            .is_err());
        assert!(DnsResolver::accel_request("GET", "https://", &[], None)
            .await
            .is_err());
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

    /// 地址族亲和：首次成功建连定下地址族，之后另一族的粘性 IP 作废；
    /// 非强制记录不改亲和，强制记录（亲和族整族失败）才切换；清缓存重置
    #[tokio::test]
    async fn family_affinity_pins_address_family_across_hosts() {
        let resolver = DnsResolver::with_resolver_config(ResolverConfig::new(), false)
            .await
            .unwrap();
        let v4: IpAddr = "198.51.100.10".parse().unwrap();
        let v6: IpAddr = "2001:db8::10".parse().unwrap();

        assert_eq!(resolver.family_affinity(), None);
        assert!(!resolver.effective_prefer_ipv6());

        // 首次建连走了 v6（Happy Eyeballs 赛跑赢家）：亲和定为 v6
        resolver.record_host_success("linux.do", v6);
        resolver.record_family_affinity(v6, false);
        assert_eq!(resolver.family_affinity(), Some(true));
        assert!(resolver.effective_prefer_ipv6());
        assert_eq!(resolver.preferred_host_ip("linux.do"), Some(v6));

        // 另一域名早先记下的 v4 粘性 IP 与亲和不一致：读取时作废
        resolver.record_host_success("credit.linux.do", v4);
        assert_eq!(resolver.preferred_host_ip("credit.linux.do"), None);
        assert_eq!(resolver.preferred_host_ip("credit.linux.do"), None);

        // 只有 A 记录的域名走 v4 成功，不是亲和族失败：亲和不变
        resolver.record_family_affinity(v4, false);
        assert_eq!(resolver.family_affinity(), Some(true));

        // 亲和族整族失败、v4 接管：切换亲和，原 v6 粘性 IP 作废
        resolver.record_family_affinity(v4, true);
        assert_eq!(resolver.family_affinity(), Some(false));
        assert_eq!(resolver.preferred_host_ip("linux.do"), None);

        // 网络切换清缓存：亲和重置
        resolver.clear_all_caches();
        assert_eq!(resolver.family_affinity(), None);
    }
}
