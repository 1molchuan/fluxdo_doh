//! 本地动态优选：客户端自己在 Cloudflare 共享池里找能连上目标站的 IP + ECH 钥匙。
//!
//! 一等链路。候选来自粘性赢家、atlas 池、大厂 Cloudflare 域名（经国内公共 DoH 解析）、
//! 社区优选域名和 CF 网段随机抽样；并发做 ECH 握手 + `/cdn-cgi/trace` 判通，最低延迟者为赢家。
//! 赢家与钥匙经 `AccelUpdate.select_state` 交给 App 落盘，下次启动回灌。
//!
//! 日志前缀 `select:`。可以记 IP、延迟、来源、钥匙长度、状态码；绝不记钥匙字节、bearer、上报正文。

use crate::cfnet;
use crate::dns::{DnsResolver, DohUpstream};
use crate::edge_pin::{
    EdgePin, Outcome, Pin, PinListener, WINNER_FAIL_THRESHOLD, WINNER_FAIL_WINDOW_SECS,
};
use crate::error::{DohProxyError, Result};
use crate::probe::{self, HttpsReply, ProbeFailure, ProbeOutcome, ProbeTarget, ProbeTimeouts};
use crate::{ProxyConfig, Secret};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hickory_resolver::proto::op::Message;
use hickory_resolver::proto::rr::{RData, RecordType};
use parking_lot::Mutex;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::EchConfigListBytes;
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Semaphore;
use tokio::task::{AbortHandle, JoinSet};
use tracing::{debug, info, warn};

/// 同时进行的探测数
const SELECT_CONCURRENCY: usize = 8;
/// 首个通过后再等这么久收更快的，然后收敛
const SELECT_GRACE_MS: u64 = 400;
/// 累计这么多个通过即收敛
const SELECT_MAX_PASSES: usize = 4;
/// 一轮探测的总预算
const SELECT_RACE_TOTAL_MS: u64 = 4000;
/// 候选收集（公共 DoH + atlas）的总预算
const SELECT_GATHER_TIMEOUT_MS: u64 = 4500;
/// 候选总数上限
const SELECT_MAX_CANDIDATES: usize = 32;
/// atlas 表里最多取这么多个 IP
const ATLAS_MAX_CANDIDATES: usize = 10;
/// 每个域名最多取这么多个 IP
const VENDOR_MAX_PER_DOMAIN: usize = 4;
/// 大厂域名 / 社区域名各自的总配额，给随机抽样留位置
const VENDOR_MAX_TOTAL: usize = 10;
const COMMUNITY_MAX_TOTAL: usize = 4;
/// 随机抽样的 v4 / v6 个数
const RANDOM_V4_SAMPLES: usize = 12;
const RANDOM_V6_SAMPLES: usize = 4;
/// 公共 DoH 单次查询超时与并发
const PUBLIC_DOH_TIMEOUT_MS: u64 = 3000;
const PUBLIC_DOH_CONCURRENCY: usize = 6;
/// 这么多家都说没有这种记录就不再等其余的
const PUBLIC_DOH_NEGATIVE_VOTES: usize = 3;
/// atlas 最短拉取间隔、429 退避下限/上限、正文上限
const ATLAS_MIN_FETCH_INTERVAL_SECS: u64 = 120;
const ATLAS_BACKOFF_429_SECS: u64 = 60;
const ATLAS_BACKOFF_MAX_SECS: u64 = 600;
const ATLAS_MAX_BODY: usize = 256 * 1024;
/// 自动发车：最小间隔、每小时上限；手动冷却；Failed 后重试间隔
const SELECT_MIN_RACE_INTERVAL_SECS: u64 = 60;
const SELECT_MAX_AUTO_RACES_PER_HOUR: usize = 4;
const SELECT_MANUAL_COOLDOWN_SECS: u64 = 10;
const SELECT_FAILED_RETRY_SECS: u64 = 300;
/// 网络变化防抖
const SELECT_NETCHANGE_DEBOUNCE_MS: u64 = 1500;
/// 钥匙池上限
const ECH_KEYS_MAX: usize = 3;
/// 持久化钥匙超过这么久就不再回灌：CF 几小时到一天换一次 config_id，老钥匙只有有限宽限期
const ECH_KEY_MAX_AGE_SECS: u64 = 48 * 3600;
/// 探测 TLS 配置缓存上限（按钥匙字节）
const TLS_CONFIG_CACHE_MAX: usize = 8;
/// 上报最短间隔与超时
const REPORT_MIN_INTERVAL_SECS: u64 = 1800;
const REPORT_TIMEOUT_MS: u64 = 5000;
/// 探测的内层 SNI / 期望的 `h=`
const PROBE_INNER_SNI: &str = "linux.do";
/// 冷启动时 lookup 最多等竞速这么久
pub const SELECT_LOOKUP_WAIT_SECS: u64 = 4;

/// 经公共 DoH 解析的大厂 Cloudflare 域名（只查这些，从不查目标站本身）
const VENDOR_DOMAINS: &[&str] = &[
    "www.visa.com.hk",
    "www.visa.com.sg",
    "www.visa.com.tw",
    "openai.com",
    "www.shopify.com",
    "www.digitalocean.com",
    "www.udemy.com",
    "icook.tw",
    "japan.com",
];
/// 社区优选域名，低优先附加
const COMMUNITY_DOMAINS: &[&str] = &["cf.090227.xyz", "skk.moe", "cloudflare.182682.xyz", "cf.877774.xyz"];
/// 另查 HTTPS 记录当备用钥匙来源的域名
const HTTPS_KEY_DOMAINS: &[&str] = &["icook.tw", "skk.moe", "japan.com"];
/// 内置的公共 DoH 端点（厂商, URL）：全部用 IP 字面量，证书都带 IP SAN，完全不经系统 DNS。
/// 每次查询对全部端点并发竞速，首个通过投毒检查的答案胜出；连不上的端点由 DoH 健康状态自动暂停
const PUBLIC_DOH_ENDPOINTS: &[(&str, &str)] = &[
    ("DNSPod", "https://1.12.12.12/dns-query"),
    ("DNSPod", "https://120.53.53.53/dns-query"),
    ("AliDNS", "https://223.5.5.5/dns-query"),
    ("AliDNS", "https://223.6.6.6/dns-query"),
    ("360", "https://101.226.4.6/dns-query"),
    ("Cloudflare", "https://1.1.1.1/dns-query"),
    ("Cloudflare", "https://1.0.0.1/dns-query"),
    ("Google", "https://8.8.8.8/dns-query"),
    ("Google", "https://8.8.4.4/dns-query"),
    ("Quad9", "https://9.9.9.9/dns-query"),
    ("Quad9", "https://149.112.112.112/dns-query"),
    ("OpenDNS", "https://208.67.222.222/dns-query"),
    ("AdGuard", "https://94.140.14.14/dns-query"),
    ("DNS.SB", "https://185.222.222.222/dns-query"),
];

/// 优选模式
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectMode {
    /// 不做优选（DoH 关闭 / 上游代理 / 非网关模式时由 Dart 传入）
    Off,
    /// 本地优选 + atlas 池一起竞速（默认）
    LocalAtlas,
    /// 只用 atlas 池
    AtlasOnly,
}

impl SelectMode {
    pub fn parse(value: &str) -> Self {
        match value.trim() {
            "off" => Self::Off,
            "atlas_only" => Self::AtlasOnly,
            "local_atlas" | "" => Self::LocalAtlas,
            other => {
                warn!("select: unknown mode '{}', using local_atlas", other);
                Self::LocalAtlas
            }
        }
    }

    pub fn wire(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::LocalAtlas => "local_atlas",
            Self::AtlasOnly => "atlas_only",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Idle,
    Verifying,
    Racing,
    Ready,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EchKeySource {
    Persisted,
    Atlas,
    HttpsRecord,
    Table,
    RetryConfigs,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateSource {
    Sticky,
    Atlas,
    Vendor,
    Community,
    Random,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Winner {
    pub ip: IpAddr,
    pub latency_ms: u32,
    pub verified_at: u64,
    pub source: CandidateSource,
    pub ech_source: EchKeySource,
}

/// 钥匙按 base64 持久化
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EchKey {
    pub b64: String,
    pub source: EchKeySource,
    pub seen_at: u64,
}

impl EchKey {
    fn new(bytes: &EchConfigListBytes<'static>, source: EchKeySource) -> Self {
        Self {
            b64: STANDARD.encode(bytes.as_ref()),
            source,
            seen_at: now_unix(),
        }
    }

    fn bytes(&self) -> Option<EchConfigListBytes<'static>> {
        STANDARD
            .decode(&self.b64)
            .ok()
            .filter(|bytes| !bytes.is_empty())
            .map(EchConfigListBytes::from)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtlasCache {
    pub fetched_at: u64,
    pub ttl: u64,
    pub candidates: Vec<IpAddr>,
}

/// 持久化状态（v=1）
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SelectState {
    #[serde(default)]
    pub v: u8,
    #[serde(default)]
    pub network_sig: Option<String>,
    #[serde(default)]
    pub winner: Option<Winner>,
    #[serde(default)]
    pub ech_keys: Vec<EchKey>,
    #[serde(default)]
    pub atlas: Option<AtlasCache>,
    #[serde(default)]
    pub last_race_at: u64,
    #[serde(default)]
    pub last_report_at: u64,
    #[serde(default)]
    pub fail_streak: u8,
    /// 近期发车时刻（unix 秒），用于每小时预算
    #[serde(default)]
    pub races_log: Vec<u64>,
}

impl SelectState {
    fn from_json(raw: &str) -> Option<Self> {
        let mut state: Self = serde_json::from_str(raw).ok()?;
        if state.v != 1 {
            return None;
        }
        let now = now_unix();
        state
            .ech_keys
            .retain(|key| now.saturating_sub(key.seen_at) < ECH_KEY_MAX_AGE_SECS);
        Some(state)
    }
}

/// 一个带来源的候选
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub ip: IpAddr,
    pub source: CandidateSource,
}

/// 公共 DoH 竞速里对单个答案的裁定
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    Accept,
    /// 投毒：有地址但不全在 Cloudflare 网段
    Poisoned,
    /// 错误响应（SERVFAIL / REFUSED 等）
    Reject,
    /// 正常响应但没有要的记录
    Negative,
}

/// 单个公共 DoH 端点的答案计数（Selector 建起来之后累计，只增不减）。
/// 诊断国内解析器投毒用：只有厂商名、端点地址和次数，不含查询的域名或任何用户数据。
/// 首个可用答案胜出后其余查询即被取消，没来得及回的端点不计
struct PublicDohStats {
    vendor: String,
    host: String,
    /// 通过检查、胜出被采用的答案
    accepted: AtomicU64,
    /// 投毒答案（A/AAAA 不全在 CF 网段）
    rejected: AtomicU64,
    /// 正常响应但没有要的记录
    negative: AtomicU64,
}

impl PublicDohStats {
    fn new(vendor: &str, host: &str) -> Self {
        Self {
            vendor: vendor.to_string(),
            host: host.to_string(),
            accepted: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            negative: AtomicU64::new(0),
        }
    }

    fn record(&self, verdict: Verdict) {
        let counter = match verdict {
            Verdict::Accept => &self.accepted,
            Verdict::Poisoned => &self.rejected,
            Verdict::Negative => &self.negative,
            Verdict::Reject => return,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "vendor": self.vendor,
            "host": self.host,
            "accepted": self.accepted.load(Ordering::Relaxed),
            "rejected": self.rejected.load(Ordering::Relaxed),
            "negative": self.negative.load(Ordering::Relaxed),
        })
    }
}

/// 发车原因，决定预算规则
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RaceTrigger {
    Start,
    Auto,
    Network,
    Manual,
    Failed,
}

struct AtlasEndpoint {
    host: String,
    path: String,
}

struct ReportEndpoint {
    host: String,
    path: String,
    version: String,
}

/// 测试用假探测：(ip, 钥匙字节) -> 结果
pub type ProbeFn = Arc<dyn Fn(IpAddr, Vec<u8>) -> ProbeOutcome + Send + Sync>;

enum Prober {
    Real,
    #[cfg_attr(not(test), allow(dead_code))]
    Fake(ProbeFn),
}

struct Inner {
    state: SelectState,
    phase: Phase,
    last_error: Option<String>,
    current_sig: Option<String>,
    atlas_backoff_until: Option<Instant>,
    last_manual_race: Option<Instant>,
    failed_at: Option<Instant>,
    netchange_gen: u64,
    /// 本次竞速结束后待上报的结果
    report_pending: bool,
}

pub struct Selector {
    mode: SelectMode,
    inner: Mutex<Inner>,
    /// 出站钉选：赢家只经它交给建连路径，赢家的地址族按它的亲和挑
    edge: Arc<EdgePin>,
    /// shutdown 后为 false：不再改钉住状态，也不响应 EdgePin 回调
    alive: AtomicBool,
    /// single-flight：竞速或校验进行中
    racing: AtomicBool,
    tls_cache: Mutex<Vec<(Vec<u8>, Arc<ClientConfig>)>>,
    roots: RootCertStore,
    provider: Arc<CryptoProvider>,
    /// (厂商, 上游)，查询时全部并发竞速
    public_doh: Vec<(String, DohUpstream)>,
    /// 与 `public_doh` 按下标一一对应的答案计数
    public_doh_stats: Vec<PublicDohStats>,
    atlas: Option<AtlasEndpoint>,
    report: Option<ReportEndpoint>,
    report_bearer: Mutex<Option<Secret>>,
    share: AtomicBool,
    prober: Prober,
    /// 备用钥匙来源：二等表 / DoH 的 ECH 查询
    resolver: Option<Arc<DnsResolver>>,
    tasks: Mutex<Vec<AbortHandle>>,
    generation: AtomicU64,
}

static SELECTOR: OnceLock<parking_lot::RwLock<Option<Arc<Selector>>>> = OnceLock::new();

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn holder() -> &'static parking_lot::RwLock<Option<Arc<Selector>>> {
    SELECTOR.get_or_init(|| parking_lot::RwLock::new(None))
}

/// 钥匙的可记日志描述：各条目的 config_id 与 public_name（不含钥匙字节）
pub(crate) fn describe_key(key: &EchConfigListBytes<'static>) -> String {
    use rustls::internal::msgs::codec::{Codec, Reader};
    use rustls::internal::msgs::handshake::EchConfigPayload;
    match Vec::<EchConfigPayload>::read(&mut Reader::init(key.as_ref())) {
        Ok(configs) => configs
            .iter()
            .map(|config| match config {
                EchConfigPayload::V18(contents) => format!(
                    "id{}@{}",
                    contents.key_config.config_id,
                    contents.public_name.as_ref()
                ),
                EchConfigPayload::Unknown { version, .. } => format!("unknown{:?}", version),
            })
            .collect::<Vec<_>>()
            .join(","),
        Err(_) => format!("unparsable({}B)", key.as_ref().len()),
    }
}

/// 从 URL 拆出主机名和路径
fn split_url(url: &str) -> Option<(String, String)> {
    let uri: http::Uri = url.trim().parse().ok()?;
    if uri.scheme_str() != Some("https") {
        return None;
    }
    let host = uri.host()?.to_ascii_lowercase();
    let path = match uri.path_and_query() {
        Some(pq) => pq.as_str().to_string(),
        None => "/".to_string(),
    };
    Some((host, path))
}

/// 竞速结束时复位 single-flight，任务被取消也会执行
struct RaceGuard(Arc<Selector>);

impl Drop for RaceGuard {
    fn drop(&mut self) {
        self.0.racing.store(false, Ordering::Release);
    }
}

impl Selector {
    /// 安装为全局实例
    pub fn install(selector: Arc<Self>) {
        *holder().write() = Some(selector);
    }

    /// 卸载全局实例（会 shutdown）
    pub fn uninstall() {
        if let Some(old) = holder().write().take() {
            old.shutdown();
        }
    }

    pub fn global() -> Option<Arc<Self>> {
        holder().read().clone()
    }

    /// 按启动配置构造；模式 off、DoH 关闭、配了上游代理或非网关模式时返回 None。
    /// 赢家交给 `resolver` 的 EdgePin（也就是网关建连用的那份）
    pub fn new(
        config: &ProxyConfig,
        roots: RootCertStore,
        provider: Arc<CryptoProvider>,
        resolver: Option<Arc<DnsResolver>>,
    ) -> Option<Arc<Self>> {
        let mode = SelectMode::parse(&config.select_mode);
        if mode == SelectMode::Off || !config.enable_doh || !config.gateway_mode {
            return None;
        }
        if config
            .upstream_proxy
            .as_ref()
            .is_some_and(|proxy| proxy.is_valid())
        {
            return None;
        }
        let edge = resolver.as_ref()?.edge_pin().clone();
        let public_doh = Self::build_public_doh_list(&config.public_doh);
        let atlas = config
            .atlas_routes_url
            .as_deref()
            .and_then(split_url)
            .map(|(host, path)| AtlasEndpoint { host, path });
        let report = config
            .report_url
            .as_deref()
            .and_then(split_url)
            .map(|(host, path)| ReportEndpoint {
                host,
                path,
                version: format!(
                    "cfluxdo/{}",
                    config.app_version.as_deref().unwrap_or("unknown")
                ),
            });
        let state = config
            .select_state_json
            .as_deref()
            .and_then(SelectState::from_json)
            .unwrap_or_default();
        let selector = Self::build(
            mode,
            state,
            config.network_sig.clone(),
            roots,
            provider,
            public_doh,
            atlas,
            report,
            resolver,
            edge,
            Prober::Real,
        );
        if config.share_measurements {
            selector.set_share(true, config.report_bearer.clone());
        }
        Some(selector)
    }

    /// 不依赖 ProxyConfig 的构造，供 example 与测试
    pub fn standalone(
        mode: SelectMode,
        atlas_routes_url: Option<&str>,
        state_json: Option<&str>,
        network_sig: Option<&str>,
    ) -> Arc<Self> {
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let provider = Arc::new(crate::tls_crypto::build_provider());
        let public_doh = Self::build_public_doh_list(&[]);
        let atlas = atlas_routes_url
            .and_then(split_url)
            .map(|(host, path)| AtlasEndpoint { host, path });
        let state = state_json
            .and_then(SelectState::from_json)
            .unwrap_or_default();
        Self::build(
            mode,
            state,
            network_sig.map(str::to_string),
            roots,
            provider,
            public_doh,
            atlas,
            None,
            None,
            Arc::new(EdgePin::new(false)),
            Prober::Real,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        mode: SelectMode,
        state: SelectState,
        current_sig: Option<String>,
        roots: RootCertStore,
        provider: Arc<CryptoProvider>,
        public_doh: Vec<(String, DohUpstream)>,
        atlas: Option<AtlasEndpoint>,
        report: Option<ReportEndpoint>,
        resolver: Option<Arc<DnsResolver>>,
        edge: Arc<EdgePin>,
        prober: Prober,
    ) -> Arc<Self> {
        let public_doh_stats = public_doh
            .iter()
            .map(|(vendor, upstream)| PublicDohStats::new(vendor, upstream.host()))
            .collect();
        let selector = Arc::new(Self {
            mode,
            inner: Mutex::new(Inner {
                state,
                phase: Phase::Idle,
                last_error: None,
                current_sig,
                atlas_backoff_until: None,
                last_manual_race: None,
                failed_at: None,
                netchange_gen: 0,
                report_pending: false,
            }),
            edge,
            alive: AtomicBool::new(true),
            racing: AtomicBool::new(false),
            tls_cache: Mutex::new(Vec::new()),
            roots,
            provider,
            public_doh,
            public_doh_stats,
            atlas,
            report,
            report_bearer: Mutex::new(None),
            share: AtomicBool::new(false),
            prober,
            resolver,
            tasks: Mutex::new(Vec::new()),
            generation: AtomicU64::new(0),
        });
        let listener: Weak<dyn PinListener> = Arc::downgrade(&selector) as Weak<dyn PinListener>;
        selector.edge.attach(listener);
        selector.sync_pin();
        selector
    }

    /// 公共 DoH 上游列表：内置端点 + Dart 传入的（按其引导 IP 建 IP 字面量地址），按 URL 去重
    fn build_public_doh_list(extra: &[crate::PublicDohServerConfig]) -> Vec<(String, DohUpstream)> {
        let mut urls: Vec<(String, String)> = PUBLIC_DOH_ENDPOINTS
            .iter()
            .map(|(vendor, url)| (vendor.to_string(), url.to_string()))
            .collect();
        for server in extra {
            let Ok(uri) = server.url.trim().parse::<http::Uri>() else {
                continue;
            };
            let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/dns-query");
            let vendor = uri.host().unwrap_or("custom").to_string();
            for ip in &server.bootstrap_ips {
                let Ok(ip) = ip.trim().parse::<IpAddr>() else {
                    continue;
                };
                let authority = match ip {
                    IpAddr::V4(ip) => ip.to_string(),
                    IpAddr::V6(ip) => format!("[{}]", ip),
                };
                let url = format!("https://{}{}", authority, path);
                if !urls.iter().any(|(_, u)| *u == url) {
                    urls.push((vendor.clone(), url));
                }
            }
        }
        // 诊断用：SELECT_DOH_PROXY=http://host:port 让公共 DoH 查询也经代理（复现某条出口）；安卓上不生效
        let diag_proxy: Option<crate::UpstreamProxyConfig> = if cfg!(target_os = "android") {
            None
        } else {
            std::env::var("SELECT_DOH_PROXY")
                .ok()
                .and_then(|v| v.parse::<http::Uri>().ok())
                .and_then(|u| {
                    Some(crate::UpstreamProxyConfig {
                        protocol: "http".to_string(),
                        host: u.host()?.to_string(),
                        port: u.port_u16()?,
                        username: None,
                        password: None,
                        cipher: None,
                    })
                })
        };
        urls.into_iter()
            .filter_map(|(vendor, url)| {
                let uri: http::Uri = url.parse().ok()?;
                match DnsResolver::build_doh_upstream(
                    uri,
                    &[],
                    Duration::from_millis(PUBLIC_DOH_TIMEOUT_MS),
                    diag_proxy.as_ref(),
                ) {
                    Ok(upstream) => Some((vendor, upstream)),
                    Err(error) => {
                        warn!("select: public DoH {} unusable: {}", url, error);
                        None
                    }
                }
            })
            .collect()
    }

    pub fn mode(&self) -> SelectMode {
        self.mode
    }

    pub fn phase(&self) -> Phase {
        self.inner.lock().phase
    }

    // ---------- 启动 / 状态 ----------

    /// 启动：有持久化赢家先校验，否则直接竞速
    pub fn start(self: &Arc<Self>) {
        let (winner, sig) = {
            let inner = self.inner.lock();
            (inner.state.winner.clone(), inner.current_sig.clone())
        };
        info!(
            "select: start mode={} persisted_winner={} keys={} sig={}",
            self.mode.wire(),
            winner
                .as_ref()
                .map(|w| w.ip.to_string())
                .unwrap_or_else(|| "none".to_string()),
            self.inner.lock().state.ech_keys.len(),
            sig.as_deref().unwrap_or("-")
        );
        if winner.is_some() {
            self.spawn_verify();
        } else {
            self.spawn_race(RaceTrigger::Start);
        }
    }

    pub fn shutdown(&self) {
        self.alive.store(false, Ordering::Release);
        self.generation.fetch_add(1, Ordering::AcqRel);
        for handle in self.tasks.lock().drain(..) {
            handle.abort();
        }
        let mut inner = self.inner.lock();
        inner.phase = Phase::Idle;
        drop(inner);
        self.racing.store(false, Ordering::Release);
        // 停了就不再钉住：EdgePin 可能还被下一个 Selector / FFI 用着
        self.edge.set_pin(Pin::None);
    }

    fn track(&self, handle: AbortHandle) {
        let mut tasks = self.tasks.lock();
        tasks.retain(|task| !task.is_finished());
        tasks.push(handle);
    }

    /// 可用的赢家：Ready，或 Verifying 且网络签名未变（乐观沿用）
    pub fn winner_ip(&self) -> Option<IpAddr> {
        match Self::pin_of(&self.inner.lock()) {
            Pin::Winner(ip) => Some(ip),
            _ => None,
        }
    }

    /// 当前状态对应的钉住状态：可用赢家 → 钉住；竞速 / 校验中（签名变了）→ 待定，
    /// 冷启动的解析可以等；Idle / Failed → 没有
    fn pin_of(inner: &Inner) -> Pin {
        let winner = inner.state.winner.as_ref().map(|w| w.ip);
        match inner.phase {
            Phase::Ready => winner.map(Pin::Winner).unwrap_or(Pin::None),
            Phase::Verifying if inner.state.network_sig == inner.current_sig => {
                winner.map(Pin::Winner).unwrap_or(Pin::Pending)
            }
            Phase::Verifying | Phase::Racing => Pin::Pending,
            Phase::Idle | Phase::Failed => Pin::None,
        }
    }

    /// 把当前赢家状态交给 EdgePin。phase / 赢家 / 网络签名变了都要调
    fn sync_pin(&self) {
        if !self.alive.load(Ordering::Acquire) {
            return;
        }
        let pin = Self::pin_of(&self.inner.lock());
        self.edge.set_pin(pin);
    }

    /// 当前首选钥匙（钥匙池第一把）
    pub fn current_ech_key(&self) -> Option<EchConfigListBytes<'static>> {
        self.inner
            .lock()
            .state
            .ech_keys
            .iter()
            .find_map(EchKey::bytes)
    }

    fn key_pool(&self) -> Vec<EchConfigListBytes<'static>> {
        self.inner
            .lock()
            .state
            .ech_keys
            .iter()
            .filter_map(EchKey::bytes)
            .collect()
    }

    /// 把一把钥匙放到池首（去重、截断），并通知 App 落盘
    pub fn adopt_ech_key(&self, key: &EchConfigListBytes<'static>, source: EchKeySource) {
        let changed = {
            let mut inner = self.inner.lock();
            let b64 = STANDARD.encode(key.as_ref());
            let already_first = inner
                .state
                .ech_keys
                .first()
                .is_some_and(|first| first.b64 == b64);
            if already_first {
                false
            } else {
                inner.state.ech_keys.retain(|k| k.b64 != b64);
                inner.state.ech_keys.insert(0, EchKey::new(key, source));
                inner.state.ech_keys.truncate(ECH_KEYS_MAX);
                true
            }
        };
        if changed {
            info!(
                "select: ech key adopted ({} bytes, source {:?}, {})",
                key.as_ref().len(),
                source,
                describe_key(key)
            );
            self.push_state();
        }
    }

    /// 把状态 JSON 放进待取更新，由 App 落盘
    fn push_state(&self) {
        let json = {
            let mut inner = self.inner.lock();
            inner.state.v = 1;
            serde_json::to_string(&inner.state).ok()
        };
        if let Some(json) = json {
            DnsResolver::accel_update().lock().select_state = Some(json);
            debug!("select: state pushed");
        }
    }

    pub fn state_json(&self) -> String {
        let mut inner = self.inner.lock();
        inner.state.v = 1;
        serde_json::to_string(&inner.state).unwrap_or_default()
    }

    pub fn status_json(&self) -> serde_json::Value {
        let inner = self.inner.lock();
        serde_json::json!({
            "ok": true,
            "mode": self.mode.wire(),
            "phase": inner.phase,
            "winner": inner.state.winner,
            "last_race_at": inner.state.last_race_at,
            "last_error": inner.last_error,
            "fail_streak": self.edge.winner_fail_streak(),
            "share": self.share.load(Ordering::Relaxed),
            "keys": inner.state.ech_keys.len(),
            "network_sig": inner.current_sig,
            "public_doh": self
                .public_doh_stats
                .iter()
                .map(PublicDohStats::to_json)
                .collect::<Vec<_>>(),
        })
    }

    /// 网络变化（Dart 传入结果集签名）：防抖后有赢家校验、无赢家竞速
    pub fn on_network_changed(self: &Arc<Self>, sig: &str) {
        let sig = sig.trim().to_string();
        let gen = {
            let mut inner = self.inner.lock();
            if inner.current_sig.as_deref() == Some(sig.as_str()) {
                return;
            }
            // 启动时 Dart 还没拿到连接类型，首个签名只是补登记：启动那轮校验/竞速已经在当前网络上跑了
            if inner.current_sig.is_none() {
                info!("select: network signature known: {}", sig);
                inner.current_sig = Some(sig.clone());
                let settled = inner.phase == Phase::Ready || inner.phase == Phase::Verifying;
                if settled {
                    inner.state.network_sig = Some(sig);
                }
                drop(inner);
                if settled {
                    self.push_state();
                }
                // 校验中的赢家签名对上了：从待定转为钉住
                self.sync_pin();
                return;
            }
            info!(
                "select: network changed {} -> {}",
                inner.current_sig.as_deref().unwrap_or("-"),
                sig
            );
            inner.current_sig = Some(sig);
            inner.netchange_gen += 1;
            inner.netchange_gen
        };
        // 旧网络上的失败不再算到赢家头上；校验中的赢家签名对不上了就转为待定
        self.edge.network_changed();
        self.sync_pin();
        let selector = self.clone();
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(SELECT_NETCHANGE_DEBOUNCE_MS)).await;
            let (stale, has_winner) = {
                let inner = selector.inner.lock();
                (inner.netchange_gen != gen, inner.state.winner.is_some())
            };
            if stale {
                return;
            }
            if has_winner {
                selector.spawn_verify();
            } else {
                selector.spawn_race(RaceTrigger::Network);
            }
        })
        .abort_handle();
        self.track(handle);
    }

    /// 请求重新优选；manual 绕过自动预算但有冷却。返回是否发车
    pub fn request_rerace(self: &Arc<Self>, manual: bool) -> bool {
        if manual {
            {
                let mut inner = self.inner.lock();
                if inner.last_manual_race.is_some_and(|at| {
                    at.elapsed() < Duration::from_secs(SELECT_MANUAL_COOLDOWN_SECS)
                }) {
                    return false;
                }
                inner.last_manual_race = Some(Instant::now());
            }
            self.spawn_race(RaceTrigger::Manual)
        } else {
            self.spawn_race(RaceTrigger::Auto)
        }
    }

    pub fn set_share(&self, on: bool, bearer: Option<Secret>) {
        let has_bearer = bearer.as_ref().is_some_and(|b| !b.0.trim().is_empty());
        *self.report_bearer.lock() = if on { bearer } else { None };
        self.share.store(on && has_bearer, Ordering::Relaxed);
        info!(
            "select: share measurements {}",
            if on && has_bearer { "on" } else { "off" }
        );
    }

    pub fn share_enabled(&self) -> bool {
        self.share.load(Ordering::Relaxed)
    }

    // ---------- 发车 ----------

    /// 预算检查后 spawn 一轮竞速。返回是否真的发车
    fn spawn_race(self: &Arc<Self>, trigger: RaceTrigger) -> bool {
        {
            let inner = self.inner.lock();
            let now = now_unix();
            if matches!(trigger, RaceTrigger::Auto | RaceTrigger::Failed) {
                let recent = inner
                    .state
                    .races_log
                    .iter()
                    .filter(|at| now.saturating_sub(**at) < 3600)
                    .count();
                if recent >= SELECT_MAX_AUTO_RACES_PER_HOUR {
                    debug!("select: auto race skipped, {} races in the last hour", recent);
                    return false;
                }
                if now.saturating_sub(inner.state.last_race_at) < SELECT_MIN_RACE_INTERVAL_SECS {
                    debug!("select: auto race skipped, last race too recent");
                    return false;
                }
            }
        }
        if self
            .racing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            debug!("select: race already in progress");
            return false;
        }
        {
            let mut inner = self.inner.lock();
            inner.phase = Phase::Racing;
            inner.last_error = None;
        }
        self.sync_pin();
        info!("select: racing ({:?})", trigger);
        let selector = self.clone();
        let generation = self.generation.load(Ordering::Acquire);
        let handle = tokio::spawn(async move {
            let _guard = RaceGuard(selector.clone());
            if selector.generation.load(Ordering::Acquire) != generation {
                return;
            }
            selector.run_race().await;
        })
        .abort_handle();
        self.track(handle);
        true
    }

    /// 校验持久化赢家：通过 → Ready，失败 → 竞速
    fn spawn_verify(self: &Arc<Self>) {
        if self
            .racing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let winner = {
            let mut inner = self.inner.lock();
            inner.phase = Phase::Verifying;
            inner.state.winner.clone()
        };
        self.sync_pin();
        let Some(winner) = winner else {
            self.racing.store(false, Ordering::Release);
            self.spawn_race(RaceTrigger::Start);
            return;
        };
        let selector = self.clone();
        let handle = tokio::spawn(async move {
            let guard = RaceGuard(selector.clone());
            let outcome = selector.probe_with_pool(winner.ip).await;
            match outcome {
                Some(outcome) if outcome.ok => {
                    info!(
                        "select: verify winner {} ok {} ms",
                        winner.ip,
                        outcome.latency.as_millis()
                    );
                    let sig_changed = {
                        let mut inner = selector.inner.lock();
                        if let Some(w) = inner.state.winner.as_mut() {
                            w.latency_ms = outcome.latency.as_millis().min(u32::MAX as u128) as u32;
                            w.verified_at = now_unix();
                        }
                        let changed = inner.state.network_sig != inner.current_sig;
                        inner.state.network_sig = inner.current_sig.clone();
                        inner.phase = Phase::Ready;
                        inner.last_error = None;
                        changed
                    };
                    selector.sync_pin();
                    if sig_changed {
                        selector.push_state();
                    }
                }
                other => {
                    let reason = other
                        .and_then(|o| o.failure)
                        .map(|f| f.to_string())
                        .unwrap_or_else(|| "no ech key".to_string());
                    warn!("select: verify winner {} failed: {} -> racing", winner.ip, reason);
                    drop(guard);
                    selector.spawn_race(RaceTrigger::Start);
                }
            }
        })
        .abort_handle();
        self.track(handle);
    }

    // ---------- 探测 ----------

    fn probe_timeouts() -> ProbeTimeouts {
        ProbeTimeouts::default()
    }

    /// 取 / 建某把钥匙的探测 TLS 配置
    fn tls_for_key(&self, key: &EchConfigListBytes<'static>) -> Result<Arc<ClientConfig>> {
        let bytes = key.as_ref().to_vec();
        if let Some((_, config)) = self.tls_cache.lock().iter().find(|(k, _)| *k == bytes) {
            return Ok(config.clone());
        }
        let config = probe::build_probe_tls_config(Some(key), &self.roots, self.provider.clone())?;
        let mut cache = self.tls_cache.lock();
        if cache.len() >= TLS_CONFIG_CACHE_MAX {
            cache.remove(0);
        }
        cache.push((bytes, config.clone()));
        Ok(config)
    }

    /// 用一把钥匙探测一个 IP
    async fn probe_ip(&self, ip: IpAddr, key: &EchConfigListBytes<'static>) -> ProbeOutcome {
        match &self.prober {
            Prober::Fake(f) => f(ip, key.as_ref().to_vec()),
            Prober::Real => {
                debug!("select: probing {} with key {}", ip, describe_key(key));
                let tls = match self.tls_for_key(key) {
                    Ok(tls) => tls,
                    Err(error) => {
                        return ProbeOutcome {
                            ip,
                            latency: Duration::ZERO,
                            ok: false,
                            failure: Some(ProbeFailure::Tls(error.to_string())),
                            ech_accepted: false,
                        }
                    }
                };
                let target = ProbeTarget {
                    ip,
                    inner_sni: PROBE_INNER_SNI,
                };
                probe::probe_once(&target, tls, &Self::probe_timeouts()).await
            }
        }
    }

    /// 带自愈的探测：ECH 被拒且带 retry_configs → 采纳并同 IP 重探一次；
    /// 被拒无 retry_configs → 换池里下一把钥匙重探一次。池空返回 None
    /// 诊断用：先收集候选把钥匙入池，再用池里的钥匙探测指定 IP
    pub async fn diagnose_ip(self: &Arc<Self>, ip: IpAddr) -> Option<ProbeOutcome> {
        if let Ok(b64) = std::env::var("SELECT_ECH_B64") {
            if let Ok(bytes) = STANDARD.decode(b64.trim()) {
                let key = EchConfigListBytes::from(bytes);
                let tls = self.tls_for_key(&key).ok()?;
                let target = ProbeTarget {
                    ip,
                    inner_sni: PROBE_INNER_SNI,
                };
                return Some(probe::probe_once(&target, tls, &Self::probe_timeouts()).await);
            }
        }
        let _ = self.gather().await;
        self.probe_with_pool(ip).await
    }

    /// 诊断用：在给定的流（如经代理隧道）上用池首钥匙探测 `ip`
    pub async fn diagnose_on_stream(
        self: &Arc<Self>,
        ip: IpAddr,
        stream: crate::BoxStream,
    ) -> Option<ProbeOutcome> {
        let _ = self.gather().await;
        // SELECT_ECH_B64：诊断时直接注入一把钥匙（可以是改过 config_id 的过期钥匙）
        if let Ok(b64) = std::env::var("SELECT_ECH_B64") {
            if let Ok(bytes) = STANDARD.decode(b64.trim()) {
                let key = EchConfigListBytes::from(bytes);
                let tls = self.tls_for_key(&key).ok()?;
                let target = ProbeTarget {
                    ip,
                    inner_sni: PROBE_INNER_SNI,
                };
                return Some(
                    probe::probe_once_on(stream, &target, Instant::now(), tls, &Self::probe_timeouts())
                        .await,
                );
            }
        }
        let pool = self.key_pool();
        let index = std::env::var("SELECT_KEY_INDEX")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
        let sources: Vec<EchKeySource> = self.inner.lock().state.ech_keys.iter().map(|k| k.source).collect();
        debug!("select: diagnose key pool {:?}, using index {}", sources, index);
        let key = pool.get(index).cloned()?;
        let tls = self.tls_for_key(&key).ok()?;
        let target = ProbeTarget {
            ip,
            inner_sni: PROBE_INNER_SNI,
        };
        Some(probe::probe_once_on(stream, &target, Instant::now(), tls, &Self::probe_timeouts()).await)
    }

    async fn probe_with_pool(self: &Arc<Self>, ip: IpAddr) -> Option<ProbeOutcome> {
        let keys = self.key_pool();
        let first = keys.first()?;
        let outcome = self.probe_ip(ip, first).await;
        match &outcome.failure {
            Some(ProbeFailure::EchRejected {
                retry_configs: Some(bytes),
            }) => {
                let key = EchConfigListBytes::from(bytes.clone());
                self.adopt_ech_key(&key, EchKeySource::RetryConfigs);
                debug!("select: {} rejected ech with retry_configs, retrying", ip);
                Some(self.probe_ip(ip, &key).await)
            }
            Some(ProbeFailure::EchRejected {
                retry_configs: None,
            })
            | Some(ProbeFailure::Tls(_)) => match keys.get(1) {
                // 被拒无 retry_configs，或 TLS 层失败（典型：钥匙的 public_name 不对，被拒后按错名校验证书）：
                // 换池里下一把再试一次；通过就把它提到池首
                Some(next) => {
                    debug!(
                        "select: {} failed with first key ({}), retrying with next key",
                        ip,
                        outcome.failure.as_ref().map(|f| f.to_string()).unwrap_or_default()
                    );
                    let retry = self.probe_ip(ip, next).await;
                    if retry.ok {
                        let source = self
                            .inner
                            .lock()
                            .state
                            .ech_keys
                            .get(1)
                            .map(|k| k.source)
                            .unwrap_or(EchKeySource::Persisted);
                        self.adopt_ech_key(next, source);
                    }
                    Some(retry)
                }
                None => Some(outcome),
            },
            _ => Some(outcome),
        }
    }

    // ---------- 候选收集 ----------

    /// 经公共 DoH 查一个域名的一种记录：全部端点并发竞速，首个通过 `accept` 的答案胜出，
    /// 其余立即取消。被劫持的快答案过不了检查，不会抢赢
    async fn public_query(
        self: &Arc<Self>,
        name: &str,
        rtype: RecordType,
        accept: fn(&Message) -> Verdict,
    ) -> Option<Message> {
        let bytes = Arc::new(DnsResolver::encode_query(name, rtype).ok()?);
        let start = Instant::now();
        let mut set: JoinSet<Option<(usize, Message)>> = JoinSet::new();
        for (index, (_, upstream)) in self.public_doh.iter().enumerate() {
            let upstream = upstream.clone();
            let bytes = bytes.clone();
            set.spawn(async move {
                let response = tokio::time::timeout(
                    Duration::from_millis(PUBLIC_DOH_TIMEOUT_MS),
                    upstream.query(&bytes),
                )
                .await
                .ok()?
                .ok()?;
                if !response.status().is_success() {
                    return None;
                }
                let body = response.bytes().await.ok()?;
                Message::from_vec(&body).ok().map(|message| (index, message))
            });
        }
        let deadline = start + Duration::from_millis(PUBLIC_DOH_TIMEOUT_MS);
        let mut rejected = 0usize;
        let mut negatives = 0usize;
        while let Ok(Some(result)) =
            tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), set.join_next())
                .await
        {
            if let Ok(Some((index, message))) = result {
                let verdict = accept(&message);
                if let Some(stats) = self.public_doh_stats.get(index) {
                    stats.record(verdict);
                }
                match verdict {
                    Verdict::Accept => {
                        debug!(
                            "select: {} {} answered by {} in {} ms",
                            name,
                            rtype,
                            self.public_doh[index].0,
                            start.elapsed().as_millis()
                        );
                        set.abort_all();
                        return Some(message);
                    }
                    Verdict::Poisoned | Verdict::Reject => rejected += 1,
                    Verdict::Negative => negatives += 1,
                }
                // 多家都说没有这种记录：不用等到超时
                if negatives >= PUBLIC_DOH_NEGATIVE_VOTES {
                    break;
                }
            }
        }
        set.abort_all();
        debug!(
            "select: {} {} no acceptable answer ({} rejected, {} negative) in {} ms",
            name,
            rtype,
            rejected,
            negatives,
            start.elapsed().as_millis()
        );
        None
    }

    /// 投毒检查：A/AAAA 答案全在 Cloudflare 网段才接受；有答案但不全在 CF 网段是投毒；
    /// 正常响应但没有地址记录是否定票
    fn accept_cf_answer(message: &Message) -> Verdict {
        let answers: Vec<IpAddr> = message
            .answers()
            .iter()
            .filter_map(|record| match record.data() {
                Some(RData::A(a)) => Some(IpAddr::V4(a.0)),
                Some(RData::AAAA(aaaa)) => Some(IpAddr::V6(aaaa.0)),
                _ => None,
            })
            .collect();
        if answers.is_empty() {
            return if message.response_code() == hickory_resolver::proto::op::ResponseCode::NoError
                || message.response_code() == hickory_resolver::proto::op::ResponseCode::NXDomain
            {
                Verdict::Negative
            } else {
                Verdict::Reject
            };
        }
        if cfnet::all_cloudflare(&answers) {
            Verdict::Accept
        } else {
            Verdict::Poisoned
        }
    }

    /// HTTPS 记录里带 ech 才接受；正常响应但没有带 ech 的记录是否定票
    fn accept_ech_answer(message: &Message) -> Verdict {
        let has_ech = message.answers().iter().any(|record| match record.data() {
            Some(RData::HTTPS(https)) => DnsResolver::parse_https_hints(https).ech_config.is_some(),
            _ => false,
        });
        if has_ech {
            Verdict::Accept
        } else if message.response_code() == hickory_resolver::proto::op::ResponseCode::NoError
            || message.response_code() == hickory_resolver::proto::op::ResponseCode::NXDomain
        {
            Verdict::Negative
        } else {
            Verdict::Reject
        }
    }

    /// 解析域名的 A/AAAA（按本机地址族），做投毒检查，返回去重后的 CF 地址
    async fn resolve_cf_domain(self: &Arc<Self>, name: &str, family: cfnet::FamilySupport) -> Vec<IpAddr> {
        let mut types = Vec::new();
        if family.v4 {
            types.push(RecordType::A);
        }
        if family.v6 {
            types.push(RecordType::AAAA);
        }
        // A 与 AAAA 并发查，别让两次串行超时吃掉收集预算
        let mut results = Vec::with_capacity(types.len());
        match types.as_slice() {
            [single] => results.push((
                *single,
                self.public_query(name, *single, Self::accept_cf_answer).await,
            )),
            [first, second] => {
                let (a, b) = tokio::join!(
                    self.public_query(name, *first, Self::accept_cf_answer),
                    self.public_query(name, *second, Self::accept_cf_answer)
                );
                results.push((*first, a));
                results.push((*second, b));
            }
            _ => {}
        }
        let mut out = Vec::new();
        for (rtype, message) in results {
            let Some(message) = message else {
                continue;
            };
            let answers: Vec<IpAddr> = message
                .answers()
                .iter()
                .filter_map(|record| match record.data() {
                    Some(RData::A(a)) => Some(IpAddr::V4(a.0)),
                    Some(RData::AAAA(aaaa)) => Some(IpAddr::V6(aaaa.0)),
                    _ => None,
                })
                .collect();
            if answers.is_empty() {
                continue;
            }
            if !cfnet::all_cloudflare(&answers) {
                debug!("select: {} {} answer not all Cloudflare, dropped", name, rtype);
                continue;
            }
            for ip in answers {
                if !out.contains(&ip) && !cfnet::is_skipped(ip) {
                    out.push(ip);
                }
            }
        }
        out
    }

    /// 查 HTTPS 记录拿 ECH 钥匙
    async fn resolve_ech_key(self: &Arc<Self>, name: &str) -> Option<EchConfigListBytes<'static>> {
        let message = self
            .public_query(name, RecordType::HTTPS, Self::accept_ech_answer)
            .await?;
        message.answers().iter().find_map(|record| match record.data() {
            Some(RData::HTTPS(https)) => DnsResolver::parse_https_hints(https).ech_config,
            _ => None,
        })
    }

    /// 并发解析一组域名，每域最多 `per_domain` 个；结果边到边写进 `sink`，
    /// 收集超时时调用方直接取 sink 里已有的，不丢已拿到的候选
    async fn resolve_domains(
        self: &Arc<Self>,
        domains: &[&'static str],
        family: cfnet::FamilySupport,
        per_domain: usize,
        sink: Arc<Mutex<Vec<IpAddr>>>,
    ) {
        let semaphore = Arc::new(Semaphore::new(PUBLIC_DOH_CONCURRENCY));
        let mut set = JoinSet::new();
        for domain in domains {
            let selector = self.clone();
            let semaphore = semaphore.clone();
            let sink = sink.clone();
            let domain = *domain;
            set.spawn(async move {
                let Ok(_permit) = semaphore.acquire_owned().await else {
                    return;
                };
                let mut ips = selector.resolve_cf_domain(domain, family).await;
                ips.truncate(per_domain);
                debug!("select: {} -> {} candidates", domain, ips.len());
                let mut out = sink.lock();
                for ip in ips {
                    if !out.contains(&ip) {
                        out.push(ip);
                    }
                }
            });
        }
        while set.join_next().await.is_some() {}
    }

    /// 拉 atlas 池：缓存新鲜或退避期内直接用缓存；否则经公共 DoH 解析 atlas、只用 ECH 拉表。
    /// 返回候选与（可能的）新钥匙
    async fn fetch_atlas(
        self: &Arc<Self>,
        family: cfnet::FamilySupport,
    ) -> (Vec<IpAddr>, Option<EchConfigListBytes<'static>>) {
        let Some(atlas) = &self.atlas else {
            return (Vec::new(), None);
        };
        let cached = {
            let inner = self.inner.lock();
            let now = now_unix();
            let in_backoff = inner
                .atlas_backoff_until
                .is_some_and(|until| until > Instant::now());
            match &inner.state.atlas {
                Some(cache)
                    if in_backoff
                        || now.saturating_sub(cache.fetched_at)
                            < cache.ttl.max(ATLAS_MIN_FETCH_INTERVAL_SECS) =>
                {
                    Some(cache.candidates.clone())
                }
                _ if in_backoff => Some(Vec::new()),
                _ => None,
            }
        };
        if let Some(candidates) = cached {
            debug!("select: atlas cache used ({} candidates)", candidates.len());
            return (candidates, None);
        }

        // 引导地址：公共 DoH 解析 atlas 自己（投毒检查），再补赢家 IP；HTTPS 记录同时查
        let (mut bootstrap, record_key) = tokio::join!(
            self.resolve_cf_domain(&atlas.host, family),
            self.resolve_ech_key(&atlas.host)
        );
        bootstrap.truncate(3);
        if let Some(winner) = self.inner.lock().state.winner.as_ref().map(|w| w.ip) {
            if !bootstrap.contains(&winner) {
                bootstrap.push(winner);
            }
        }
        // 钥匙：atlas 的 HTTPS 记录优先（和目标站同一把 CF 钥匙），再用池里的
        let mut keys: Vec<EchConfigListBytes<'static>> = Vec::new();
        if let Some(key) = &record_key {
            // 钥匙一到手就入池且置顶：刚从 DNS 拿到的比持久化的新
            self.adopt_ech_key(key, EchKeySource::HttpsRecord);
            keys.push(key.clone());
        }
        for key in self.key_pool() {
            if !keys.iter().any(|k| k.as_ref() == key.as_ref()) {
                keys.push(key);
            }
        }
        if bootstrap.is_empty() || keys.is_empty() {
            debug!(
                "select: atlas skipped (bootstrap {}, keys {})",
                bootstrap.len(),
                keys.len()
            );
            return (self.atlas_cached_candidates(), record_key);
        }
        let timeouts = ProbeTimeouts {
            tcp: Duration::from_millis(2000),
            tls: Duration::from_millis(3000),
            http: Duration::from_millis(3000),
        };
        let mut reply: Option<HttpsReply> = None;
        'outer: for ip in &bootstrap {
            for key in &keys {
                let Ok(tls) = self.tls_for_key(key) else {
                    continue;
                };
                match probe::https_request(
                    *ip,
                    &atlas.host,
                    "GET",
                    &atlas.path,
                    &[("accept", "application/json")],
                    None,
                    tls,
                    &timeouts,
                    ATLAS_MAX_BODY,
                )
                .await
                {
                    Ok(r) => {
                        reply = Some(r);
                        break 'outer;
                    }
                    Err(error) => debug!("select: atlas via {} failed: {}", ip, error),
                }
            }
        }
        let Some(reply) = reply else {
            warn!("select: atlas unreachable via {} bootstrap IPs", bootstrap.len());
            return (self.atlas_cached_candidates(), record_key);
        };
        if reply.status == 429 {
            let backoff = reply
                .retry_after_secs
                .unwrap_or(ATLAS_BACKOFF_429_SECS)
                .clamp(ATLAS_BACKOFF_429_SECS, ATLAS_BACKOFF_MAX_SECS);
            warn!("select: atlas 429, backing off {}s", backoff);
            self.inner.lock().atlas_backoff_until = Some(Instant::now() + Duration::from_secs(backoff));
            return (self.atlas_cached_candidates(), record_key);
        }
        if reply.status != 200 {
            warn!("select: atlas http {}", reply.status);
            return (self.atlas_cached_candidates(), record_key);
        }
        let Some((ttl, candidates, table_key)) = parse_atlas_routes(&reply.body, family) else {
            warn!("select: atlas table unparsable");
            return (self.atlas_cached_candidates(), record_key);
        };
        info!("select: atlas table ok, {} candidates, ttl {}s", candidates.len(), ttl);
        if let Some(key) = &table_key {
            self.adopt_ech_key(key, EchKeySource::Atlas);
        }
        {
            let mut inner = self.inner.lock();
            inner.state.atlas = Some(AtlasCache {
                fetched_at: now_unix(),
                ttl,
                candidates: candidates.clone(),
            });
        }
        self.push_state();
        (candidates, table_key.or(record_key))
    }

    fn atlas_cached_candidates(&self) -> Vec<IpAddr> {
        self.inner
            .lock()
            .state
            .atlas
            .as_ref()
            .map(|cache| cache.candidates.clone())
            .unwrap_or_default()
    }

    /// 收集候选与钥匙（含超时）
    async fn gather(self: &Arc<Self>) -> (Vec<Candidate>, Vec<EchConfigListBytes<'static>>) {
        let family = cfnet::local_family_support();
        let family = if family.v4 || family.v6 {
            family
        } else {
            cfnet::FamilySupport { v4: true, v6: false }
        };
        let sticky = self.inner.lock().state.winner.as_ref().map(|w| w.ip);
        let vendor_sink: Arc<Mutex<Vec<IpAddr>>> = Arc::new(Mutex::new(Vec::new()));
        let community_sink: Arc<Mutex<Vec<IpAddr>>> = Arc::new(Mutex::new(Vec::new()));

        // 候选和钥匙都边到边落：atlas 进 state.atlas 缓存、域名进 sink、钥匙进池；
        // 超时只是停止等待，不丢已经拿到的
        let gather_all = async {
            let atlas_task = self.fetch_atlas(family);
            if self.mode == SelectMode::AtlasOnly {
                let _ = atlas_task.await;
            } else {
                let vendor_task = self.resolve_domains(
                    VENDOR_DOMAINS,
                    family,
                    VENDOR_MAX_PER_DOMAIN,
                    vendor_sink.clone(),
                );
                let community_task = self.resolve_domains(
                    COMMUNITY_DOMAINS,
                    family,
                    VENDOR_MAX_PER_DOMAIN,
                    community_sink.clone(),
                );
                let keys_task = async {
                    let mut found = 0usize;
                    for domain in HTTPS_KEY_DOMAINS {
                        if let Some(key) = self.resolve_ech_key(domain).await {
                            self.adopt_ech_key(&key, EchKeySource::HttpsRecord);
                            found += 1;
                            if found >= 2 {
                                break;
                            }
                        }
                    }
                };
                tokio::join!(atlas_task, vendor_task, community_task, keys_task);
            }
        };
        if tokio::time::timeout(Duration::from_millis(SELECT_GATHER_TIMEOUT_MS), gather_all)
            .await
            .is_err()
        {
            warn!("select: candidate gathering timed out, using what we have");
        }
        let atlas_ips = self.atlas_cached_candidates();
        let vendor: Vec<IpAddr> = vendor_sink.lock().clone();
        let community: Vec<IpAddr> = community_sink.lock().clone();

        let mut candidates: Vec<Candidate> = Vec::new();
        let mut seen: HashSet<IpAddr> = HashSet::new();
        let mut push = |ip: IpAddr, source: CandidateSource, candidates: &mut Vec<Candidate>| {
            let family_ok = (ip.is_ipv4() && family.v4) || (ip.is_ipv6() && family.v6);
            if family_ok
                && cfnet::is_cloudflare(ip)
                && !cfnet::is_skipped(ip)
                && seen.insert(ip)
                && candidates.len() < SELECT_MAX_CANDIDATES
            {
                candidates.push(Candidate { ip, source });
            }
        };
        if let Some(ip) = sticky {
            push(ip, CandidateSource::Sticky, &mut candidates);
        }
        for ip in atlas_ips.into_iter().take(ATLAS_MAX_CANDIDATES) {
            push(ip, CandidateSource::Atlas, &mut candidates);
        }
        let (vendor_n, community_n, random_n) = if self.mode == SelectMode::AtlasOnly {
            (0, 0, 0)
        } else {
            let before = candidates.len();
            for ip in vendor.into_iter().take(VENDOR_MAX_TOTAL) {
                push(ip, CandidateSource::Vendor, &mut candidates);
            }
            let vendor_n = candidates.len() - before;
            let before = candidates.len();
            for ip in community.into_iter().take(COMMUNITY_MAX_TOTAL) {
                push(ip, CandidateSource::Community, &mut candidates);
            }
            let community_n = candidates.len() - before;
            let before = candidates.len();
            let rng = ring::rand::SystemRandom::new();
            if family.v4 {
                for ip in cfnet::sample_v4_one_per_24(RANDOM_V4_SAMPLES, &rng) {
                    push(ip, CandidateSource::Random, &mut candidates);
                }
            }
            if family.v6 {
                for ip in cfnet::sample_v6(RANDOM_V6_SAMPLES, &rng) {
                    push(ip, CandidateSource::Random, &mut candidates);
                }
            }
            (vendor_n, community_n, candidates.len() - before)
        };
        info!(
            "select: candidates total={} sticky={} atlas={} vendor={} community={} random={} (v4 {}, v6 {})",
            candidates.len(),
            candidates.iter().filter(|c| c.source == CandidateSource::Sticky).count(),
            candidates.iter().filter(|c| c.source == CandidateSource::Atlas).count(),
            vendor_n,
            community_n,
            random_n,
            family.v4,
            family.v6
        );

        // 钥匙池：持久化 > atlas > HTTPS 记录（都已在收集期间入池）> 二等表 / DoH 的 linux.do ECH
        if self.key_pool().is_empty() {
            if let Some(resolver) = &self.resolver {
                if let Ok(Some(key)) = tokio::time::timeout(
                    Duration::from_millis(PUBLIC_DOH_TIMEOUT_MS),
                    resolver.lookup_ech_config(PROBE_INNER_SNI),
                )
                .await
                .unwrap_or(Ok(None))
                .map(Some)
                .unwrap_or(None)
                .map(Ok::<_, ()>)
                .unwrap_or(Ok(None))
                {
                    self.append_ech_key(&key, EchKeySource::Table);
                }
            }
        }
        (candidates, self.key_pool())
    }

    /// 把钥匙追加到池尾（持久化的在前），去重、截断
    fn append_ech_key(&self, key: &EchConfigListBytes<'static>, source: EchKeySource) {
        let mut inner = self.inner.lock();
        let b64 = STANDARD.encode(key.as_ref());
        if inner.state.ech_keys.iter().any(|k| k.b64 == b64) {
            return;
        }
        inner.state.ech_keys.push(EchKey::new(key, source));
        inner.state.ech_keys.truncate(ECH_KEYS_MAX);
        drop(inner);
        info!(
            "select: ech key added (source {:?}, {})",
            source,
            describe_key(key)
        );
    }

    // ---------- 竞速 ----------

    async fn run_race(self: &Arc<Self>) {
        let (candidates, keys) = self.gather().await;
        self.race_candidates(candidates, keys).await;
    }

    /// 对给定候选跑一轮：并发 8，首通过后 400 ms 或 4 个通过或 4 s 收敛；最低延迟者为赢家
    pub(crate) async fn race_candidates(
        self: &Arc<Self>,
        candidates: Vec<Candidate>,
        keys: Vec<EchConfigListBytes<'static>>,
    ) {
        {
            let mut inner = self.inner.lock();
            let now = now_unix();
            inner.state.last_race_at = now;
            inner.state.races_log.push(now);
            inner.state.races_log.retain(|at| now.saturating_sub(*at) < 3600);
        }
        if keys.is_empty() {
            warn!("select: no ech key available, falling back to tier 2");
            self.finish_failed("no ech key");
            return;
        }
        {
            let sources: Vec<String> = self
                .inner
                .lock()
                .state
                .ech_keys
                .iter()
                .map(|k| format!("{:?}", k.source))
                .collect();
            let described: Vec<String> = keys.iter().map(describe_key).collect();
            info!(
                "select: key pool [{}] {}",
                sources.join(","),
                described.join(" | ")
            );
        }
        if candidates.is_empty() {
            warn!("select: no candidates, falling back to tier 2");
            self.finish_failed("no candidates");
            return;
        }

        let start = Instant::now();
        let total = Duration::from_millis(SELECT_RACE_TOTAL_MS);
        let semaphore = Arc::new(Semaphore::new(SELECT_CONCURRENCY));
        let mut set: JoinSet<(Candidate, Option<ProbeOutcome>)> = JoinSet::new();
        for candidate in candidates {
            let selector = self.clone();
            let semaphore = semaphore.clone();
            set.spawn(async move {
                let Ok(_permit) = semaphore.acquire_owned().await else {
                    return (candidate, None);
                };
                let outcome = selector.probe_with_pool(candidate.ip).await;
                (candidate, outcome)
            });
        }

        let mut passes: Vec<(Candidate, ProbeOutcome)> = Vec::new();
        let mut all: Vec<ProbeOutcome> = Vec::new();
        let mut first_pass_at: Option<Instant> = None;
        loop {
            let now = Instant::now();
            let mut deadline = start + total;
            if let Some(at) = first_pass_at {
                deadline = deadline.min(at + Duration::from_millis(SELECT_GRACE_MS));
            }
            if passes.len() >= SELECT_MAX_PASSES || now >= deadline {
                break;
            }
            match tokio::time::timeout(deadline - now, set.join_next()).await {
                Ok(Some(Ok((candidate, Some(outcome))))) => {
                    debug!(
                        "select: {} ({:?}) -> {} {} ms{}",
                        candidate.ip,
                        candidate.source,
                        if outcome.ok { "ok" } else { "fail" },
                        outcome.latency.as_millis(),
                        outcome
                            .failure
                            .as_ref()
                            .map(|f| format!(" ({})", f))
                            .unwrap_or_default()
                    );
                    if outcome.ok {
                        first_pass_at.get_or_insert(Instant::now());
                        passes.push((candidate, outcome.clone()));
                    }
                    all.push(outcome);
                }
                Ok(Some(Ok((_, None)))) | Ok(Some(Err(_))) => continue,
                Ok(None) => break,
                Err(_) => break,
            }
        }
        set.abort_all();

        // 先按地址族，再按延迟。地址族优先沿用连接层当前的亲和（已经用它铸过 cf_clearance），
        // 没有亲和才看配置偏好：重新优选不能把整个 App 翻到另一个出口 IP 上
        let prefer_ipv6 = self.edge.effective_prefer_ipv6();
        let Some((best, outcome)) = passes
            .iter()
            .min_by_key(|(candidate, outcome)| {
                (candidate.ip.is_ipv6() != prefer_ipv6, outcome.latency)
            })
            .cloned()
        else {
            // 安卓日志只到 info，这里把失败原因按类型汇总，方便真机排障
            let mut kinds: Vec<(String, usize)> = Vec::new();
            for outcome in &all {
                let kind = match &outcome.failure {
                    Some(ProbeFailure::Tls(_)) => "tls".to_string(),
                    Some(ProbeFailure::Http(_)) => "http".to_string(),
                    Some(ProbeFailure::HttpStatus(code)) => format!("http_{}", code),
                    Some(ProbeFailure::EchRejected { retry_configs }) => {
                        if retry_configs.is_some() {
                            "ech_rejected_retry".to_string()
                        } else {
                            "ech_rejected".to_string()
                        }
                    }
                    Some(other) => other.to_string().replace(' ', "_"),
                    None => "unknown".to_string(),
                };
                match kinds.iter_mut().find(|(k, _)| *k == kind) {
                    Some((_, n)) => *n += 1,
                    None => kinds.push((kind, 1)),
                }
            }
            let summary: Vec<String> = kinds.iter().map(|(k, n)| format!("{}={}", k, n)).collect();
            let sample: Vec<String> = all
                .iter()
                .filter_map(|o| o.failure.as_ref().map(|f| format!("{} {}", o.ip, f)))
                .take(3)
                .collect();
            warn!(
                "select: no candidate passed ({} probed in {} ms): {} | e.g. {}",
                all.len(),
                start.elapsed().as_millis(),
                summary.join(" "),
                sample.join("; ")
            );
            self.finish_failed("no candidate passed");
            return;
        };
        let ech_source = self
            .inner
            .lock()
            .state
            .ech_keys
            .first()
            .map(|k| k.source)
            .unwrap_or(EchKeySource::Persisted);
        info!(
            "select: winner {} {} ms source={:?} ech={:?} ({} passed of {} probed in {} ms)",
            best.ip,
            outcome.latency.as_millis(),
            best.source,
            ech_source,
            passes.len(),
            all.len(),
            start.elapsed().as_millis()
        );
        {
            let mut inner = self.inner.lock();
            inner.state.winner = Some(Winner {
                ip: best.ip,
                latency_ms: outcome.latency.as_millis().min(u32::MAX as u128) as u32,
                verified_at: now_unix(),
                source: best.source,
                ech_source,
            });
            inner.state.network_sig = inner.current_sig.clone();
            inner.state.fail_streak = 0;
            inner.failed_at = None;
            inner.phase = Phase::Ready;
            inner.last_error = None;
            inner.report_pending = passes.len() >= 2;
        }
        self.sync_pin();
        self.push_state();
        self.maybe_report(&all).await;
    }

    fn finish_failed(&self, reason: &str) {
        let mut inner = self.inner.lock();
        inner.state.winner = None;
        inner.phase = Phase::Failed;
        inner.failed_at = Some(Instant::now());
        inner.last_error = Some(reason.to_string());
        drop(inner);
        self.sync_pin();
        self.push_state();
    }

    // ---------- 上报 ----------

    /// 竞速后把握手测量结果分享给 cfhub：默认关；≥2 个通过；≥30 min 一次；经赢家 IP + ECH；失败静默
    async fn maybe_report(self: &Arc<Self>, outcomes: &[ProbeOutcome]) {
        if !self.share.load(Ordering::Relaxed) {
            return;
        }
        let Some(report) = &self.report else {
            return;
        };
        let bearer = self.report_bearer.lock().clone();
        let Some(bearer) = bearer.filter(|b| !b.0.trim().is_empty()) else {
            return;
        };
        let (winner, pending, last_report_at) = {
            let inner = self.inner.lock();
            (
                inner.state.winner.clone(),
                inner.report_pending,
                inner.state.last_report_at,
            )
        };
        let Some(winner) = winner else {
            return;
        };
        if !pending || now_unix().saturating_sub(last_report_at) < REPORT_MIN_INTERVAL_SECS {
            return;
        }
        let Some(key) = self.current_ech_key() else {
            return;
        };
        let Ok(tls) = self.tls_for_key(&key) else {
            return;
        };
        let timeouts = ProbeTimeouts {
            tcp: Duration::from_millis(REPORT_TIMEOUT_MS / 2),
            tls: Duration::from_millis(REPORT_TIMEOUT_MS),
            http: Duration::from_millis(REPORT_TIMEOUT_MS),
        };
        let auth = format!("Bearer {}", bearer.0.trim());
        {
            let mut inner = self.inner.lock();
            inner.state.last_report_at = now_unix();
            inner.report_pending = false;
        }
        for family in [4u8, 6u8] {
            let Some(body) = build_report_body(family, &report.version, outcomes) else {
                continue;
            };
            // hub 按连接的地址判断网段和运营商：family 6 的上报必须走 IPv6 连接、family 4 走 IPv4。
            // 赢家同族就用赢家，否则用本轮该族里延迟最低的通过者；该族没有通过者就不报
            let is_family = |ip: IpAddr| (family == 4 && ip.is_ipv4()) || (family == 6 && ip.is_ipv6());
            let report_ip = if is_family(winner.ip) {
                Some(winner.ip)
            } else {
                outcomes
                    .iter()
                    .filter(|o| o.ok && is_family(o.ip))
                    .min_by_key(|o| o.latency)
                    .map(|o| o.ip)
            };
            let Some(report_ip) = report_ip else {
                debug!("select: report v{} skipped, no passing IP of that family", family);
                continue;
            };
            let result = probe::https_request(
                report_ip,
                &report.host,
                "POST",
                &report.path,
                &[
                    ("authorization", auth.as_str()),
                    ("content-type", "application/json"),
                ],
                Some(body),
                tls.clone(),
                &timeouts,
                4096,
            )
            .await;
            match result {
                Ok(reply) => {
                    info!("select: report v{} status={}", family, reply.status);
                    if reply.status == 401 || reply.status == 403 {
                        self.share.store(false, Ordering::Relaxed);
                        *self.report_bearer.lock() = None;
                        DnsResolver::accel_update().lock().report_auth_rejected = true;
                        break;
                    }
                }
                Err(error) => {
                    debug!("select: report v{} failed: {}", family, error);
                }
            }
        }
        self.push_state();
    }

    // ---------- 经赢家的小请求 ----------

    /// 经赢家 IP + 当前钥匙向 `host` 发请求（内层 SNI 为 host）；无赢家 / 无钥匙 / 失败返回 None。
    /// 和网关建连同一套钉选：只有 EdgePin 把 `host` 钉在赢家上才走，结果回报给 EdgePin
    /// （连通强制亲和到赢家的族；TCP 连不上计入赢家连败）
    pub async fn https_via_winner(
        &self,
        host: &str,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<Vec<u8>>,
    ) -> Option<HttpsReply> {
        let route = self.edge.route(host, Vec::new());
        let ip = route.first.filter(|_| route.pinned)?;
        let key = self.current_ech_key()?;
        let tls = self.tls_for_key(&key).ok()?;
        let timeouts = ProbeTimeouts {
            tcp: Duration::from_millis(2000),
            tls: Duration::from_millis(3000),
            http: Duration::from_millis(8000),
        };
        let first = probe::https_request(
            ip,
            host,
            method,
            path,
            headers,
            body.clone(),
            tls,
            &timeouts,
            ATLAS_MAX_BODY,
        )
        .await;
        let result = match first {
            // 钥匙过期被拒且服务端给了新钥匙：采纳后同地址重试一次（和 ech.rs 主路径一致）
            Err(DohProxyError::EchRetry { configs, .. }) => {
                let key = EchConfigListBytes::from(configs);
                self.adopt_ech_key(&key, EchKeySource::RetryConfigs);
                match self.tls_for_key(&key) {
                    Ok(tls) => {
                        probe::https_request(ip, host, method, path, headers, body, tls, &timeouts, ATLAS_MAX_BODY)
                            .await
                    }
                    Err(error) => Err(error),
                }
            }
            other => other,
        };
        match &result {
            Ok(_) => self.edge.report(
                host,
                ip,
                Outcome::Connected {
                    rtt: None,
                    took_over: false,
                },
            ),
            // 只算 TCP 层：TLS 失败可能只是别的 zone（atlas / cfhub6）在这个 IP 上不服务
            Err(DohProxyError::Unreachable { .. }) => self.edge.report(host, ip, Outcome::Failed),
            Err(_) => {}
        }
        match result {
            Ok(reply) => {
                info!("select: {} {}{} via winner {} -> {}", method, host, path, ip, reply.status);
                Some(reply)
            }
            Err(error) => {
                info!("select: {} via winner {} failed: {}", host, ip, error);
                None
            }
        }
    }
}

/// EdgePin 的回调：赢家连败降级、覆盖域名要赢家时没有
impl PinListener for Selector {
    /// 赢家在窗口内连败达阈值（EdgePin 已解除钉住）：降级并重跑，预算不够就转 Failed
    fn winner_failed(self: Arc<Self>, ip: IpAddr) {
        if !self.alive.load(Ordering::Acquire) {
            return;
        }
        let demote = {
            let mut inner = self.inner.lock();
            if inner.state.winner.as_ref().map(|w| w.ip) == Some(ip) {
                warn!(
                    "select: winner {} failed {} times within {}s, demoting",
                    ip, WINNER_FAIL_THRESHOLD, WINNER_FAIL_WINDOW_SECS
                );
                inner.state.winner = None;
                inner.state.fail_streak = 0;
                true
            } else {
                false
            }
        };
        if !demote {
            self.sync_pin();
            return;
        }
        self.push_state();
        if !self.spawn_race(RaceTrigger::Auto) {
            {
                let mut inner = self.inner.lock();
                inner.phase = Phase::Failed;
                inner.failed_at = Some(Instant::now());
                inner.last_error = Some("race budget exhausted".to_string());
            }
            self.sync_pin();
        }
    }

    /// 覆盖域名要建连但没有赢家：Failed 过了重试间隔就顺手发车
    fn pin_missed(self: Arc<Self>) {
        if !self.alive.load(Ordering::Acquire) {
            return;
        }
        let retry = {
            let inner = self.inner.lock();
            inner.phase == Phase::Failed
                && inner.failed_at.is_some_and(|at| {
                    at.elapsed() >= Duration::from_secs(SELECT_FAILED_RETRY_SECS)
                })
        };
        if retry {
            self.spawn_race(RaceTrigger::Failed);
        }
    }
}

/// atlas `GET /v1/routes` 响应里本模块关心的部分
#[derive(Deserialize)]
struct AtlasRoutesJson {
    #[serde(default)]
    ttl: u64,
    #[serde(default)]
    routes: Vec<AtlasRouteJson>,
}

#[derive(Deserialize)]
struct AtlasRouteJson {
    #[serde(default)]
    name: String,
    #[serde(default)]
    v4: Vec<String>,
    #[serde(default)]
    v6: Vec<String>,
    #[serde(default)]
    ech: Option<String>,
}

/// 解析 atlas 表：(ttl, 候选 IP ≤16, 目标站条目的 ech)。所有 IP 必须在 CF 网段
pub(crate) fn parse_atlas_routes(
    body: &[u8],
    family: cfnet::FamilySupport,
) -> Option<(u64, Vec<IpAddr>, Option<EchConfigListBytes<'static>>)> {
    let json: AtlasRoutesJson = serde_json::from_slice(body).ok()?;
    let mut candidates = Vec::new();
    let mut key = None;
    for route in &json.routes {
        let name = route.name.trim().trim_end_matches('.').to_ascii_lowercase();
        for ip in route.v4.iter().chain(route.v6.iter()) {
            let Ok(ip) = ip.trim().parse::<IpAddr>() else {
                continue;
            };
            let family_ok = (ip.is_ipv4() && family.v4) || (ip.is_ipv6() && family.v6);
            if family_ok
                && cfnet::is_cloudflare(ip)
                && !cfnet::is_skipped(ip)
                && !candidates.contains(&ip)
            {
                candidates.push(ip);
            }
        }
        if key.is_none() || name == PROBE_INNER_SNI {
            if let Some(ech) = route
                .ech
                .as_deref()
                .filter(|v| !v.trim().is_empty())
                .and_then(crate::dns::decode_base64_lenient)
            {
                key = Some(EchConfigListBytes::from(
                    DnsResolver::ensure_ech_config_list_len_prefix(ech),
                ));
            }
        }
    }
    candidates.truncate(ATLAS_MAX_CANDIDATES);
    Some((json.ttl, candidates, key))
}

/// 按地址族组装上报正文：`{"family":4,"version":"cfluxdo/x","ips":[{ip,median_ms,ok,rounds}]}`；
/// 不足 2 个 IP 返回 None
pub(crate) fn build_report_body(
    family: u8,
    version: &str,
    outcomes: &[ProbeOutcome],
) -> Option<Vec<u8>> {
    let ips: Vec<serde_json::Value> = outcomes
        .iter()
        .filter(|o| (family == 4 && o.ip.is_ipv4()) || (family == 6 && o.ip.is_ipv6()))
        .filter(|o| cfnet::is_cloudflare(o.ip))
        .map(|o| {
            serde_json::json!({
                "ip": o.ip.to_string(),
                "median_ms": o.latency.as_millis().min(u32::MAX as u128) as u32,
                "ok": if o.ok { 1 } else { 0 },
                "rounds": 1,
            })
        })
        .collect();
    if ips.len() < 2 {
        return None;
    }
    serde_json::to_vec(&serde_json::json!({
        "family": family,
        "version": version,
        "ips": ips,
    }))
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn key(byte: u8) -> EchConfigListBytes<'static> {
        EchConfigListBytes::from(vec![0, 3, byte, byte, byte])
    }

    fn outcome(ip: IpAddr, ok: bool, ms: u64, failure: Option<ProbeFailure>) -> ProbeOutcome {
        ProbeOutcome {
            ip,
            latency: Duration::from_millis(ms),
            ok,
            failure,
            ech_accepted: ok,
        }
    }

    /// 用假探测构造一个 selector；`f(ip, key_bytes)` 决定结果
    fn fake_selector(mode: SelectMode, state: SelectState, f: ProbeFn) -> Arc<Selector> {
        fake_selector_with(mode, state, f, Arc::new(EdgePin::new(false)))
    }

    /// 同上，赢家交给指定的 EdgePin
    fn fake_selector_with(
        mode: SelectMode,
        state: SelectState,
        f: ProbeFn,
        edge: Arc<EdgePin>,
    ) -> Arc<Selector> {
        let roots = RootCertStore::empty();
        let provider = Arc::new(crate::tls_crypto::build_provider());
        Selector::build(
            mode,
            state,
            Some("wifi".to_string()),
            roots,
            provider,
            Vec::new(),
            None,
            Some(ReportEndpoint {
                host: "cfhub6.example".to_string(),
                path: "/api/v1/probe/report".to_string(),
                version: "cfluxdo/test".to_string(),
            }),
            None,
            edge,
            Prober::Fake(f),
        )
    }

    /// 只带公共 DoH 列表的 selector（探测不会被调用）
    fn selector_with_public_doh(public_doh: Vec<(String, DohUpstream)>) -> Arc<Selector> {
        Selector::build(
            SelectMode::LocalAtlas,
            SelectState::default(),
            Some("wifi".to_string()),
            RootCertStore::empty(),
            Arc::new(crate::tls_crypto::build_provider()),
            public_doh,
            None,
            None,
            None,
            Arc::new(EdgePin::new(false)),
            Prober::Fake(Arc::new(|ip, _| outcome(ip, false, 1, None))),
        )
    }

    /// 指向本机假 DoH 的上游（IP 字面量，不经任何 DNS）
    async fn fake_public_doh(vendor: &str, answers: &[&str]) -> (String, DohUpstream) {
        let (port, _) = crate::dns::tests::spawn_fake_doh_answering(
            answers.iter().map(|text| ip(text)).collect(),
        )
        .await;
        let uri: http::Uri = format!("http://127.0.0.1:{}/v1/lookup", port).parse().unwrap();
        let upstream =
            DnsResolver::build_doh_upstream(uri, &[], Duration::from_secs(3), None).unwrap();
        (vendor.to_string(), upstream)
    }

    fn doh_counts(selector: &Arc<Selector>, vendor: &str) -> (u64, u64, u64) {
        let status = selector.status_json();
        let entry = status["public_doh"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["vendor"] == vendor)
            .unwrap_or_else(|| panic!("no counters for {}", vendor))
            .clone();
        assert_eq!(entry["host"], "127.0.0.1");
        (
            entry["accepted"].as_u64().unwrap(),
            entry["rejected"].as_u64().unwrap(),
            entry["negative"].as_u64().unwrap(),
        )
    }

    /// 公共 DoH 计数：投毒答案记 rejected、空应答记 negative、通过检查的记 accepted，
    /// 按端点（厂商 + 地址）分开累计；状态 JSON 里带出来
    #[tokio::test]
    async fn public_doh_counters_track_verdicts_per_endpoint() {
        let selector = selector_with_public_doh(vec![
            fake_public_doh("Poisoner", &["31.13.94.36"]).await,
            fake_public_doh("Empty", &[]).await,
        ]);
        assert!(selector
            .public_query("www.visa.com.hk", RecordType::A, Selector::accept_cf_answer)
            .await
            .is_none());
        assert!(selector
            .public_query("openai.com", RecordType::A, Selector::accept_cf_answer)
            .await
            .is_none());
        assert_eq!(doh_counts(&selector, "Poisoner"), (0, 2, 0));
        assert_eq!(doh_counts(&selector, "Empty"), (0, 0, 2));

        let selector = selector_with_public_doh(vec![
            fake_public_doh("Clean", &["104.21.0.30"]).await,
        ]);
        assert!(selector
            .public_query("www.visa.com.hk", RecordType::A, Selector::accept_cf_answer)
            .await
            .is_some());
        assert_eq!(doh_counts(&selector, "Clean"), (1, 0, 0));
    }

    fn state_with_key(byte: u8) -> SelectState {
        SelectState {
            v: 1,
            ech_keys: vec![EchKey::new(&key(byte), EchKeySource::Persisted)],
            ..Default::default()
        }
    }

    fn candidates(ips: &[&str]) -> Vec<Candidate> {
        ips.iter()
            .map(|text| Candidate {
                ip: ip(text),
                source: CandidateSource::Vendor,
            })
            .collect()
    }

    async fn wait_phase(selector: &Arc<Selector>, phase: Phase) {
        let start = Instant::now();
        while selector.phase() != phase && start.elapsed() < Duration::from_secs(5) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(selector.phase(), phase);
    }

    #[test]
    fn mode_parsing_defaults_to_local_atlas() {
        assert_eq!(SelectMode::parse("off"), SelectMode::Off);
        assert_eq!(SelectMode::parse("atlas_only"), SelectMode::AtlasOnly);
        assert_eq!(SelectMode::parse("local_atlas"), SelectMode::LocalAtlas);
        assert_eq!(SelectMode::parse(""), SelectMode::LocalAtlas);
        assert_eq!(SelectMode::parse("bogus"), SelectMode::LocalAtlas);
    }

    #[test]
    fn state_json_roundtrip_keeps_keys_and_winner() {
        let mut state = state_with_key(7);
        state.winner = Some(Winner {
            ip: ip("104.21.58.192"),
            latency_ms: 87,
            verified_at: 1,
            source: CandidateSource::Atlas,
            ech_source: EchKeySource::Atlas,
        });
        state.network_sig = Some("wifi".to_string());
        let json = serde_json::to_string(&state).unwrap();
        let back = SelectState::from_json(&json).unwrap();
        assert_eq!(back.winner, state.winner);
        assert_eq!(back.ech_keys[0].bytes().unwrap().as_ref(), key(7).as_ref());
        assert_eq!(back.network_sig.as_deref(), Some("wifi"));
        // 版本不对的状态丢弃
        assert!(SelectState::from_json(r#"{"v":2}"#).is_none());
        assert!(SelectState::from_json("not json").is_none());
    }

    #[tokio::test]
    async fn race_picks_lowest_latency_after_grace() {
        let selector = fake_selector(
            SelectMode::LocalAtlas,
            state_with_key(1),
            Arc::new(|ip, _| match ip.to_string().as_str() {
                "104.21.0.1" => outcome(ip, true, 120, None),
                "104.21.0.2" => outcome(ip, true, 40, None),
                _ => outcome(ip, false, 10, Some(ProbeFailure::TcpConnect)),
            }),
        );
        selector
            .race_candidates(candidates(&["104.21.0.1", "104.21.0.2", "104.21.0.3"]), selector.key_pool())
            .await;
        assert_eq!(selector.phase(), Phase::Ready);
        let winner = selector.inner.lock().state.winner.clone().unwrap();
        assert_eq!(winner.ip, ip("104.21.0.2"));
        assert_eq!(winner.latency_ms, 40);
        assert_eq!(selector.winner_ip(), Some(ip("104.21.0.2")));
        // 状态已推给 App
        let update = DnsResolver::take_accel_update();
        assert!(update.is_some_and(|u| u.select_state.is_some()));
    }

    #[tokio::test]
    async fn winner_follows_connection_family_affinity() {
        // 连接层已把亲和定在 IPv6：即使 v4 候选更快，赢家也要选 v6，否则整个 App 会翻到另一个出口 IP
        let edge = Arc::new(EdgePin::new(false));
        edge.report(
            "linux.do",
            ip("2606:4700::1"),
            crate::edge_pin::Outcome::Connected {
                rtt: None,
                took_over: false,
            },
        );
        let selector = fake_selector_with(
            SelectMode::LocalAtlas,
            state_with_key(1),
            Arc::new(|ip, _| {
                if ip.is_ipv4() {
                    outcome(ip, true, 10, None)
                } else {
                    outcome(ip, true, 60, None)
                }
            }),
            edge,
        );
        selector
            .race_candidates(
                candidates(&["104.21.0.1", "2606:4700::6810:1", "104.21.0.2"]),
                selector.key_pool(),
            )
            .await;
        assert_eq!(selector.winner_ip(), Some(ip("2606:4700::6810:1")));
        // 没有亲和时按配置偏好（这里是 v4）
        let selector = fake_selector(
            SelectMode::LocalAtlas,
            state_with_key(1),
            Arc::new(|ip, _| {
                if ip.is_ipv4() {
                    outcome(ip, true, 60, None)
                } else {
                    outcome(ip, true, 10, None)
                }
            }),
        );
        selector
            .race_candidates(
                candidates(&["104.21.0.1", "2606:4700::6810:1"]),
                selector.key_pool(),
            )
            .await;
        assert_eq!(selector.winner_ip(), Some(ip("104.21.0.1")));
        // 没有亲和、配置偏好 v6：v4 更快也选 v6
        let selector = fake_selector_with(
            SelectMode::LocalAtlas,
            state_with_key(1),
            Arc::new(|ip, _| {
                if ip.is_ipv4() {
                    outcome(ip, true, 10, None)
                } else {
                    outcome(ip, true, 60, None)
                }
            }),
            Arc::new(EdgePin::new(true)),
        );
        selector
            .race_candidates(
                candidates(&["104.21.0.1", "2606:4700::6810:1"]),
                selector.key_pool(),
            )
            .await;
        assert_eq!(selector.winner_ip(), Some(ip("2606:4700::6810:1")));
        // 赢家交给了 EdgePin：覆盖域名钉到它
        assert_eq!(
            selector.edge.route("linux.do", Vec::new()).first,
            Some(ip("2606:4700::6810:1"))
        );
    }

    /// 赢家死了：三个覆盖域名在 60 s 内各失败一次 → EdgePin 解除钉住、Selector 降级重赛；
    /// 降级到重赛出结果之间没有覆盖域名回到旧赢家，重赛出的新赢家所有覆盖域名一起换过去
    #[tokio::test]
    async fn winner_failures_move_all_covered_hosts_together() {
        let old = ip("104.21.0.1");
        let new = ip("104.21.0.2");
        let alive = Arc::new(Mutex::new(old));
        let alive_in = alive.clone();
        let mut state = state_with_key(1);
        // 重赛的候选从 atlas 缓存里来
        state.atlas = Some(AtlasCache {
            fetched_at: now_unix(),
            ttl: 3600,
            candidates: vec![new],
        });
        let edge = Arc::new(EdgePin::new(false));
        let selector = fake_selector_with(
            SelectMode::LocalAtlas,
            state,
            Arc::new(move |ip, _| {
                if ip == *alive_in.lock() {
                    outcome(ip, true, 20, None)
                } else {
                    outcome(ip, false, 5, Some(ProbeFailure::TcpConnect))
                }
            }),
            edge.clone(),
        );
        selector
            .race_candidates(candidates(&["104.21.0.1"]), selector.key_pool())
            .await;
        let hosts = [
            "linux.do",
            "connect.linux.do",
            "cdk.linux.do",
            "cdn.linux.do",
        ];
        for host in hosts {
            assert_eq!(edge.route(host, Vec::new()).first, Some(old));
            edge.report(
                host,
                old,
                Outcome::Connected {
                    rtt: None,
                    took_over: false,
                },
            );
        }
        selector.inner.lock().state.last_race_at = 0;

        *alive.lock() = new;
        for host in &hosts[..3] {
            edge.report(host, old, Outcome::Failed);
        }
        // 降级即解除：cdn.linux.do 没失败过，粘性 IP 也不能再把它带回旧赢家
        for host in hosts {
            assert_ne!(edge.route(host, Vec::new()).first, Some(old), "{}", host);
        }
        wait_phase(&selector, Phase::Ready).await;
        assert_eq!(selector.winner_ip(), Some(new));
        for host in hosts {
            let route = edge.route(host, Vec::new());
            assert_eq!(route.first, Some(new), "{}", host);
            assert!(route.pinned);
        }
    }

    #[tokio::test]
    async fn race_without_passes_is_failed_and_lookup_returns_none() {
        let selector = fake_selector(
            SelectMode::LocalAtlas,
            state_with_key(1),
            Arc::new(|ip, _| outcome(ip, false, 5, Some(ProbeFailure::HttpStatus(403)))),
        );
        selector
            .race_candidates(candidates(&["104.21.0.1", "104.21.0.2"]), selector.key_pool())
            .await;
        assert_eq!(selector.phase(), Phase::Failed);
        assert!(selector.winner_ip().is_none());
        let got = selector
            .edge
            .settled_winner("linux.do", Instant::now() + Duration::from_millis(50))
            .await;
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn race_without_keys_is_failed() {
        let selector = fake_selector(
            SelectMode::LocalAtlas,
            SelectState::default(),
            Arc::new(|ip, _| outcome(ip, true, 5, None)),
        );
        selector
            .race_candidates(candidates(&["104.21.0.1"]), Vec::new())
            .await;
        assert_eq!(selector.phase(), Phase::Failed);
        assert_eq!(
            selector.inner.lock().last_error.as_deref(),
            Some("no ech key")
        );
    }

    #[tokio::test]
    async fn ech_rejection_with_retry_configs_adopts_key_and_retries_same_ip() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_in = calls.clone();
        let selector = fake_selector(
            SelectMode::LocalAtlas,
            state_with_key(1),
            Arc::new(move |ip, key_bytes| {
                calls_in.fetch_add(1, Ordering::SeqCst);
                if key_bytes == key(1).as_ref() {
                    outcome(
                        ip,
                        false,
                        30,
                        Some(ProbeFailure::EchRejected {
                            retry_configs: Some(key(9).as_ref().to_vec()),
                        }),
                    )
                } else {
                    outcome(ip, true, 50, None)
                }
            }),
        );
        selector
            .race_candidates(candidates(&["104.21.0.1"]), selector.key_pool())
            .await;
        assert_eq!(selector.phase(), Phase::Ready);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        let current = selector.current_ech_key().unwrap();
        assert_eq!(current.as_ref(), key(9).as_ref());
        let winner = selector.inner.lock().state.winner.clone().unwrap();
        assert_eq!(winner.ech_source, EchKeySource::RetryConfigs);
    }

    #[tokio::test]
    async fn ech_rejection_without_retry_configs_tries_next_key() {
        let mut state = state_with_key(1);
        state.ech_keys.push(EchKey::new(&key(2), EchKeySource::Atlas));
        let selector = fake_selector(
            SelectMode::LocalAtlas,
            state,
            Arc::new(|ip, key_bytes| {
                if key_bytes == key(1).as_ref() {
                    outcome(
                        ip,
                        false,
                        30,
                        Some(ProbeFailure::EchRejected {
                            retry_configs: None,
                        }),
                    )
                } else {
                    outcome(ip, true, 60, None)
                }
            }),
        );
        selector
            .race_candidates(candidates(&["104.21.0.1"]), selector.key_pool())
            .await;
        assert_eq!(selector.phase(), Phase::Ready);
    }

    #[tokio::test]
    async fn fail_streak_demotes_winner_and_reraces() {
        // 只有原赢家能通过；降级后它已不在候选里，重赛（随机抽样）必然全败
        let selector = fake_selector(
            SelectMode::LocalAtlas,
            state_with_key(1),
            Arc::new(|ip, _| {
                if ip == "104.21.0.1".parse::<IpAddr>().unwrap() {
                    outcome(ip, true, 20, None)
                } else {
                    outcome(ip, false, 5, Some(ProbeFailure::TcpConnect))
                }
            }),
        );
        selector
            .race_candidates(candidates(&["104.21.0.1"]), selector.key_pool())
            .await;
        assert_eq!(selector.phase(), Phase::Ready);
        // 把 last_race_at 拨回去，让自动发车不被最小间隔挡住
        selector.inner.lock().state.last_race_at = 0;
        let winner = ip("104.21.0.1");
        let edge = selector.edge.clone();
        let failed = crate::edge_pin::Outcome::Failed;
        edge.report("linux.do", ip("104.21.0.9"), failed); // 非赢家不计
        edge.report("example.com", winner, failed); // 非覆盖域名不计
        edge.report("linux.do", winner, failed);
        edge.report("linux.do", winner, failed);
        assert_eq!(edge.winner_fail_streak(), 2);
        assert_eq!(selector.status_json()["fail_streak"], 2);
        edge.report(
            "linux.do",
            winner,
            crate::edge_pin::Outcome::Connected {
                rtt: None,
                took_over: false,
            },
        );
        assert_eq!(edge.winner_fail_streak(), 0);
        for _ in 0..3 {
            edge.report("linux.do", winner, failed);
        }
        // 降级后发车：run_race 走 gather（无公共 DoH、无 atlas）→ 无候选 → Failed
        wait_phase(&selector, Phase::Failed).await;
    }

    #[tokio::test]
    async fn auto_race_budget_is_enforced() {
        let mut state = state_with_key(1);
        let now = now_unix();
        state.races_log = vec![now - 10, now - 20, now - 30, now - 40];
        state.last_race_at = now - 10;
        let selector = fake_selector(
            SelectMode::LocalAtlas,
            state,
            Arc::new(|ip, _| outcome(ip, true, 20, None)),
        );
        assert!(!selector.request_rerace(false));
        // 手动不受每小时预算限制，但有冷却
        assert!(selector.request_rerace(true));
        assert!(!selector.request_rerace(true));
    }

    #[tokio::test]
    async fn concurrent_rerace_runs_once() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_in = calls.clone();
        let selector = fake_selector(
            SelectMode::LocalAtlas,
            state_with_key(1),
            Arc::new(move |ip, _| {
                calls_in.fetch_add(1, Ordering::SeqCst);
                outcome(ip, true, 20, None)
            }),
        );
        selector.inner.lock().state.last_race_at = 0;
        let first = selector.request_rerace(false);
        let second = selector.request_rerace(false);
        assert!(first);
        assert!(!second);
    }

    #[tokio::test]
    async fn network_change_same_signature_is_ignored() {
        let selector = fake_selector(
            SelectMode::LocalAtlas,
            state_with_key(1),
            Arc::new(|ip, _| outcome(ip, true, 20, None)),
        );
        selector.on_network_changed("wifi");
        assert_eq!(selector.inner.lock().netchange_gen, 0);
        selector.on_network_changed("mobile");
        assert_eq!(selector.inner.lock().netchange_gen, 1);
        assert_eq!(
            selector.inner.lock().current_sig.as_deref(),
            Some("mobile")
        );
    }

    #[tokio::test]
    async fn verifying_returns_persisted_winner_only_when_signature_matches() {
        let mut state = state_with_key(1);
        state.winner = Some(Winner {
            ip: ip("104.21.0.1"),
            latency_ms: 30,
            verified_at: 1,
            source: CandidateSource::Sticky,
            ech_source: EchKeySource::Persisted,
        });
        state.network_sig = Some("wifi".to_string());
        let selector = fake_selector(SelectMode::LocalAtlas, state.clone(), Arc::new(|ip, _| outcome(ip, true, 20, None)));
        selector.inner.lock().phase = Phase::Verifying;
        selector.sync_pin();
        assert_eq!(selector.winner_ip(), Some(ip("104.21.0.1")));
        let got = selector
            .edge
            .settled_winner("linux.do", Instant::now() + Duration::from_millis(10))
            .await;
        assert!(got.is_some());

        let selector = fake_selector(SelectMode::LocalAtlas, state, Arc::new(|ip, _| outcome(ip, true, 20, None)));
        selector.inner.lock().current_sig = Some("mobile".to_string());
        selector.inner.lock().phase = Phase::Verifying;
        selector.sync_pin();
        assert!(selector.winner_ip().is_none());
        let got = selector
            .edge
            .settled_winner("linux.do", Instant::now() + Duration::from_millis(10))
            .await;
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn start_with_persisted_winner_verifies_then_ready() {
        let mut state = state_with_key(1);
        state.winner = Some(Winner {
            ip: ip("104.21.0.1"),
            latency_ms: 30,
            verified_at: 1,
            source: CandidateSource::Sticky,
            ech_source: EchKeySource::Persisted,
        });
        let selector = fake_selector(
            SelectMode::LocalAtlas,
            state,
            Arc::new(|ip, _| outcome(ip, true, 25, None)),
        );
        selector.start();
        wait_phase(&selector, Phase::Ready).await;
        assert_eq!(
            selector.inner.lock().state.winner.as_ref().unwrap().latency_ms,
            25
        );
    }

    #[test]
    fn atlas_routes_parsing_filters_non_cloudflare_and_takes_key() {
        let body = serde_json::json!({
            "ttl": 600,
            "routes": [
                {"name": "linux.do", "v4": ["104.21.58.192", "31.13.94.36"], "v6": ["2606:4700::1"], "ech": "AAMBAQE="},
                {"name": "other.example", "v4": ["172.64.229.140", "104.16.1.1"]}
            ]
        })
        .to_string();
        let (ttl, ips, key) = parse_atlas_routes(
            body.as_bytes(),
            cfnet::FamilySupport { v4: true, v6: false },
        )
        .unwrap();
        assert_eq!(ttl, 600);
        assert_eq!(ips, vec![ip("104.21.58.192"), ip("172.64.229.140")]);
        assert!(key.is_some());
        assert!(parse_atlas_routes(b"nope", cfnet::FamilySupport { v4: true, v6: true }).is_none());
    }

    #[test]
    fn report_body_contract() {
        let outcomes = vec![
            outcome(ip("104.21.0.1"), true, 50, None),
            outcome(ip("104.21.0.2"), false, 2000, Some(ProbeFailure::TcpTimeout)),
            outcome(ip("2606:4700::1"), true, 70, None),
            outcome(ip("8.8.8.8"), true, 10, None),
        ];
        let body = build_report_body(4, "cfluxdo/1.1.0", &outcomes).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["family"], 4);
        assert_eq!(json["version"], "cfluxdo/1.1.0");
        let ips = json["ips"].as_array().unwrap();
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0]["ok"], 1);
        assert_eq!(ips[1]["ok"], 0);
        assert_eq!(ips[0]["rounds"], 1);
        assert!(ips[0]["median_ms"].is_u64());
        // v6 只有一个、不足 2 个不发
        assert!(build_report_body(6, "cfluxdo/1.1.0", &outcomes).is_none());
    }

    #[tokio::test]
    async fn report_is_skipped_without_share_or_bearer() {
        let selector = fake_selector(
            SelectMode::LocalAtlas,
            state_with_key(1),
            Arc::new(|ip, _| outcome(ip, true, 20, None)),
        );
        selector
            .race_candidates(candidates(&["104.21.0.1", "104.21.0.2"]), selector.key_pool())
            .await;
        assert_eq!(selector.inner.lock().state.last_report_at, 0);
        selector.set_share(true, None);
        assert!(!selector.share_enabled());
        selector.set_share(true, Some(Secret("cfp_x".to_string())));
        assert!(selector.share_enabled());
        selector.set_share(false, None);
        assert!(!selector.share_enabled());
    }

    /// 实网：VPS 上跑一轮真实竞速
    #[tokio::test]
    #[ignore]
    async fn live_race_local_atlas() {
        let selector = Selector::standalone(
            SelectMode::LocalAtlas,
            Some("https://atlas.1molchuan.top/v1/routes"),
            None,
            Some("test"),
        );
        selector.run_race().await;
        println!("{}", selector.status_json());
        assert_eq!(selector.phase(), Phase::Ready);
    }
}
