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
/// 全部超时后放宽时限复核的候选数（上次的赢家优先）
const SELECT_PATIENT_RETRY_MAX: usize = 4;
/// 首个通过后再等这么久收更快的，然后收敛
const SELECT_GRACE_MS: u64 = 400;
/// 首个通过来自非首选地址族、首选族还有探测在途时，最多再等首选族这么久（Happy Eyeballs 式让先）
const SELECT_FAMILY_GRACE_MS: u64 = 1500;
/// 自动地址族：IPv6 最快者比 IPv4 最快者慢出一倍以上（且多出至少这么多）才让给 IPv4
const V6_TOLERANCE_MIN_MS: u64 = 300;
/// 某个网络上按 IPv6 偏好竞速过的结论多久内有效（见 [`Selector::family_rerace_due`]）
const FAMILY_CHECK_TTL_SECS: u64 = 24 * 3600;
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
/// 自定义节点：清单最多收几条
pub const CUSTOM_MAX_ENTRIES: usize = 8;
/// 自定义节点一轮最多几个候选（不超过探测并发：全在首批里起跑，都不通也只多等一次建连超时）
const CUSTOM_MAX_CANDIDATES: usize = 8;
/// 自定义节点在这个网络上都没通过、或被实际流量打掉之后，隔多久再给它们优先
const CUSTOM_RETRY_SECS: u64 = 3600;
/// 随机抽样的 v4 / v6 个数；首选 IPv6 时 v6 多抽些
const RANDOM_V4_SAMPLES: usize = 12;
const RANDOM_V6_SAMPLES: usize = 4;
const RANDOM_V6_SAMPLES_PREFERRED: usize = 8;
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

/// 挑赢家时的地址族偏好（App「IP 协议」设置）
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FamilyPref {
    /// IPv4 优先：有 IPv4 通过就不用 IPv6
    V4,
    /// IPv6 优先：有 IPv6 通过就用它，不论多慢
    V6,
    /// 自动（默认）：本机有 IPv6 路由、这个网络上没验出 IPv6 不通时偏好 IPv6，
    /// 但 IPv6 比 IPv4 慢太多（见 [`V6_TOLERANCE_MIN_MS`]）时让给 IPv4。
    /// 双栈网络的 IPv4 出口多是运营商 NAT 共享地址，CF 风险分高、频繁弹盾；IPv6 多为独享地址
    Auto,
}

impl FamilyPref {
    pub fn from_config(prefer_ipv6: bool, ipv6_auto: bool) -> Self {
        if prefer_ipv6 {
            Self::V6
        } else if ipv6_auto {
            Self::Auto
        } else {
            Self::V4
        }
    }

    pub fn wire(self) -> &'static str {
        match self {
            Self::V4 => "v4",
            Self::V6 => "v6",
            Self::Auto => "auto",
        }
    }
}

/// 一轮竞速按哪一族挑赢家
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RaceFamily {
    prefer_v6: bool,
    /// 首选族慢太多时可以让给另一族（只有自动模式、且不受亲和约束时）
    tolerant: bool,
    /// 首选族来自连接层亲和（铸过 cf_clearance 的出口），不是配置
    bound: bool,
}

/// 某个网络上按 IPv6 偏好竞速过的结论
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilyCheck {
    /// 那次竞速时的网络签名
    #[serde(default)]
    pub sig: Option<String>,
    pub at: u64,
    /// 那次有 IPv6 候选通过
    pub v6_ok: bool,
}

impl FamilyCheck {
    fn fresh_for(&self, sig: &Option<String>, now: u64) -> bool {
        self.sig == *sig && now.saturating_sub(self.at) < FAMILY_CHECK_TTL_SECS
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
    /// 用户自己填的节点：有通过的就只在它们里挑赢家（见 [`Selector::race_with`]）
    Custom,
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
    /// 自动 / IPv6 优先：最近一次不受亲和约束、按 IPv6 偏好跑完的竞速结论
    #[serde(default)]
    pub family_check: Option<FamilyCheck>,
    /// 自定义节点最近一次参与竞速的结论
    #[serde(default)]
    pub custom_check: Option<CustomCheck>,
    /// 被实际流量打掉的自定义节点（见 [`PinListener::winner_failed`]）
    #[serde(default)]
    pub custom_demoted: Vec<CustomDemotion>,
    /// 赢家是自定义节点时，它出自清单里的哪一条（原文）：那一条被拿掉了就不再用它
    #[serde(default)]
    pub custom_entry: Option<String>,
}

impl SelectState {
    fn from_json(raw: &str) -> Option<Self> {
        let mut state: Self = serde_json::from_str(raw).ok()?;
        if state.v != 1 {
            return None;
        }
        let now = now_unix();
        // 用不了的钥匙（旧版把握手失败的占位当新钥匙存了下来）读回时就丢掉
        state.ech_keys.retain(|key| {
            now.saturating_sub(key.seen_at) < ECH_KEY_MAX_AGE_SECS
                && key.bytes().is_some_and(|bytes| ech_key_usable(bytes.as_ref()))
        });
        Some(state)
    }
}

/// 一个带来源的候选
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub ip: IpAddr,
    pub source: CandidateSource,
}

/// 自定义节点清单里的一条
#[derive(Clone, Debug, PartialEq, Eq)]
enum CustomEntry {
    Ip(IpAddr),
    /// 优选域名（小写），竞速前经公共 DoH 解析
    Domain(String),
}

/// 用户自己填的 Cloudflare 节点（IP 或优选域名）。随启动配置来，运行期不变——清单改了
/// 由 App 重启网关。只收 Cloudflare 网段里的地址：别的地址是第三方中转，论坛看到的出口
/// 就不是本机了，那是上游代理的事
#[derive(Clone, Debug, Default)]
pub struct CustomNodes {
    /// (原文, 解析结果)，已去重、截断到 [`CUSTOM_MAX_ENTRIES`]
    entries: Vec<(String, CustomEntry)>,
    /// 写法不对（既不是 IP 也不是域名）的原文
    invalid: Vec<String>,
}

impl CustomNodes {
    pub fn parse(raw: &[String]) -> Self {
        let mut out = Self::default();
        for text in raw {
            let text = text.trim();
            if text.is_empty() {
                continue;
            }
            let Some(entry) = Self::parse_entry(text) else {
                if !out.invalid.iter().any(|seen| seen == text) {
                    out.invalid.push(text.to_string());
                }
                continue;
            };
            if out.entries.iter().any(|(_, seen)| *seen == entry) {
                continue;
            }
            if out.entries.len() < CUSTOM_MAX_ENTRIES {
                out.entries.push((text.to_string(), entry));
            }
        }
        out
    }

    /// 认 `1.2.3.4`、`2606:4700::1`、`[2606:4700::1]`、`cf.example.com`，以及它们带 `:443` 的写法。
    /// 别的端口网关用不上（只连 443），算写错
    fn parse_entry(text: &str) -> Option<CustomEntry> {
        let unbracket = |s: &str| {
            s.strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .and_then(|s| s.parse::<std::net::Ipv6Addr>().ok())
                .map(|ip| CustomEntry::Ip(IpAddr::V6(ip)))
        };
        if let Ok(ip) = text.parse::<IpAddr>() {
            return Some(CustomEntry::Ip(ip));
        }
        if text.starts_with('[') {
            return unbracket(text).or_else(|| text.strip_suffix(":443").and_then(unbracket));
        }
        let host = text.strip_suffix(":443").unwrap_or(text);
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            return Some(CustomEntry::Ip(IpAddr::V4(ip)));
        }
        let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
        Self::valid_domain(&host).then_some(CustomEntry::Domain(host))
    }

    fn valid_domain(host: &str) -> bool {
        let labels: Vec<&str> = host.split('.').collect();
        host.len() <= 253
            && labels.len() >= 2
            && labels.iter().all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
            // 末段全是数字的是写坏了的 IP（如 `1.2.3`、`300.1.1.1`），不当域名去查
            && labels
                .last()
                .is_some_and(|tld| !tld.bytes().all(|b| b.is_ascii_digit()))
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn domains(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter_map(|(_, entry)| match entry {
                CustomEntry::Domain(name) => Some(name.clone()),
                CustomEntry::Ip(_) => None,
            })
            .collect()
    }

    /// 清单里在 Cloudflare 网段内的字面 IP
    fn cloudflare_ips(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.entries.iter().filter_map(|(_, entry)| match entry {
            CustomEntry::Ip(ip) if cfnet::is_cloudflare(*ip) => Some(*ip),
            _ => None,
        })
    }

    /// 清单 + IP 协议偏好的指纹：两者任一变了，之前的结论就不算数
    fn fingerprint(&self, family: FamilyPref) -> String {
        let items: Vec<String> = self
            .entries
            .iter()
            .map(|(_, entry)| match entry {
                CustomEntry::Ip(ip) => ip.to_string(),
                CustomEntry::Domain(name) => name.clone(),
            })
            .collect();
        format!("{}|{}", family.wire(), items.join(","))
    }
}

/// 一条自定义节点的结论
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustomState {
    /// 探测通过
    Ok,
    /// 探了，没通过（`detail` 是失败类型）
    Failed,
    /// 不在 Cloudflare 网段，不用
    NotCloudflare,
    /// 本机没有这一族的出口（如只有 IPv4 的网络上填了 IPv6）
    NoFamily,
    /// 用着的时候连不上被换掉了，暂时不再优先
    Demoted,
    /// 域名没解析出 Cloudflare 地址
    Unresolved,
    /// 写法不对
    Invalid,
    /// 还没测过
    Pending,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomResult {
    /// 清单里的原文
    pub entry: String,
    pub state: CustomState,
    /// 通过的（域名取最快的那个）或探过的地址
    #[serde(default)]
    pub ip: Option<IpAddr>,
    #[serde(default)]
    pub latency_ms: Option<u32>,
    #[serde(default)]
    pub detail: Option<String>,
}

/// 自定义节点最近一次参与竞速的结论
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomCheck {
    /// 那时的清单指纹（见 [`CustomNodes::fingerprint`]）
    pub list: String,
    /// 那次竞速时的网络签名
    #[serde(default)]
    pub sig: Option<String>,
    pub at: u64,
    /// 那次有自定义节点通过
    pub ok: bool,
    #[serde(default)]
    pub results: Vec<CustomResult>,
}

/// 被实际流量打掉的自定义节点：[`CUSTOM_RETRY_SECS`] 内不再进候选
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomDemotion {
    pub ip: IpAddr,
    pub at: u64,
}

/// 一轮竞速里某条自定义节点对应哪些候选；`skip` 是没进候选的原因
#[derive(Clone, Debug)]
struct CustomPlanItem {
    entry: String,
    ips: Vec<IpAddr>,
    skip: Option<CustomState>,
}

/// 探测失败的类型（日志汇总、自定义节点的结论里用）
fn failure_kind(failure: Option<&ProbeFailure>) -> String {
    match failure {
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
    }
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
    /// 赢家能用但地址族不是这里该用的：后台竞速，期间赢家照常钉住（见 spawn_background_race）
    Family,
    /// 赢家能用但不是按现在的自定义节点清单挑的：同样后台竞速，自定义节点没通过就不动赢家
    Custom,
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
    /// 最近一次发车的原因：换网 / 启动的竞速不受旧亲和约束（见 [`Selector::race_family`]）
    race_trigger: RaceTrigger,
}

pub struct Selector {
    mode: SelectMode,
    family_pref: FamilyPref,
    /// 测试用：覆盖本机地址族探测
    family_override: Mutex<Option<cfnet::FamilySupport>>,
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
    /// 用户自己填的节点
    custom: CustomNodes,
    custom_fp: String,
    /// 最近一次收集候选时，每条自定义节点对应哪些候选
    custom_plan: Mutex<Vec<CustomPlanItem>>,
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

/// 这串字节能不能当 ECH 钥匙用：ECHConfigList 语法完整（不多不少），且至少有一份认识的版本。
///
/// 服务端给的新钥匙、落盘读回的钥匙都先过这一关。BoringSSL 在握手不是因 ECH 被拒而失败时
/// 去取 retry_configs，会故意拿到一段解析不了的占位（fe0d ffffff）；这种东西进了钥匙池，
/// 之后每次按浏览器指纹握手都在构造阶段就失败（INVALID_ECH_CONFIG_LIST）
pub(crate) fn ech_key_usable(key: &[u8]) -> bool {
    use rustls::internal::msgs::codec::{Codec, Reader};
    use rustls::internal::msgs::handshake::EchConfigPayload;
    let mut reader = Reader::init(key);
    match Vec::<EchConfigPayload>::read(&mut reader) {
        Ok(configs) => {
            !reader.any_left()
                && configs
                    .iter()
                    .any(|config| matches!(config, EchConfigPayload::V18(_)))
        }
        Err(_) => false,
    }
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

/// 两族交替排（首选族先），族内保持原顺序；排在最前的粘性赢家和自定义节点不动。
/// 并发探测按顺序领号，交替后首批里就有首选族，不用等另一族探完一批才轮到
fn interleave_families(candidates: Vec<Candidate>, prefer_v6: bool) -> Vec<Candidate> {
    let mut rest = candidates.into_iter().peekable();
    let mut out = Vec::new();
    while let Some(head) = rest.next_if(|c| {
        matches!(c.source, CandidateSource::Sticky | CandidateSource::Custom)
    }) {
        out.push(head);
    }
    let (preferred, other): (Vec<Candidate>, Vec<Candidate>) =
        rest.partition(|c| c.ip.is_ipv6() == prefer_v6);
    let (mut preferred, mut other) = (preferred.into_iter(), other.into_iter());
    loop {
        match (preferred.next(), other.next()) {
            (None, None) => break,
            (a, b) => out.extend(a.into_iter().chain(b)),
        }
    }
    out
}

/// 挑赢家：首选族优先、族内最低延迟。`tolerant`（自动模式）时首选族最快者比另一族最快者
/// 慢出一倍以上、且多出至少 [`V6_TOLERANCE_MIN_MS`]，就让给另一族
fn pick_winner(
    passes: &[(Candidate, ProbeOutcome)],
    family: RaceFamily,
) -> Option<(Candidate, ProbeOutcome)> {
    let fastest = |v6: bool| {
        passes
            .iter()
            .filter(|(candidate, _)| candidate.ip.is_ipv6() == v6)
            .min_by_key(|(_, outcome)| outcome.latency)
    };
    let pick = match (fastest(family.prefer_v6), fastest(!family.prefer_v6)) {
        (Some(preferred), Some(other))
            if family.tolerant
                && preferred.1.latency
                    > other.1.latency
                        + other.1.latency.max(Duration::from_millis(V6_TOLERANCE_MIN_MS)) =>
        {
            other
        }
        (Some(preferred), _) => preferred,
        (None, other) => other?,
    };
    Some(pick.clone())
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
            FamilyPref::from_config(config.prefer_ipv6, config.ipv6_auto),
            state,
            config.network_sig.clone(),
            roots,
            provider,
            public_doh,
            atlas,
            report,
            resolver,
            edge,
            CustomNodes::parse(&config.custom_nodes),
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
        family_pref: FamilyPref,
        atlas_routes_url: Option<&str>,
        state_json: Option<&str>,
        network_sig: Option<&str>,
    ) -> Arc<Self> {
        Self::standalone_custom(mode, family_pref, atlas_routes_url, state_json, network_sig, &[])
    }

    /// 同 [`Self::standalone`]，带自定义节点清单
    pub fn standalone_custom(
        mode: SelectMode,
        family_pref: FamilyPref,
        atlas_routes_url: Option<&str>,
        state_json: Option<&str>,
        network_sig: Option<&str>,
        custom_nodes: &[String],
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
            family_pref,
            state,
            network_sig.map(str::to_string),
            roots,
            provider,
            public_doh,
            atlas,
            None,
            None,
            Arc::new(EdgePin::new(family_pref == FamilyPref::V6)),
            CustomNodes::parse(custom_nodes),
            Prober::Real,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        mode: SelectMode,
        family_pref: FamilyPref,
        state: SelectState,
        current_sig: Option<String>,
        roots: RootCertStore,
        provider: Arc<CryptoProvider>,
        public_doh: Vec<(String, DohUpstream)>,
        atlas: Option<AtlasEndpoint>,
        report: Option<ReportEndpoint>,
        resolver: Option<Arc<DnsResolver>>,
        edge: Arc<EdgePin>,
        custom: CustomNodes,
        prober: Prober,
    ) -> Arc<Self> {
        let custom_fp = custom.fingerprint(family_pref);
        let public_doh_stats = public_doh
            .iter()
            .map(|(vendor, upstream)| PublicDohStats::new(vendor, upstream.host()))
            .collect();
        let selector = Arc::new(Self {
            mode,
            family_pref,
            family_override: Mutex::new(None),
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
                race_trigger: RaceTrigger::Auto,
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
            custom,
            custom_fp,
            custom_plan: Mutex::new(Vec::new()),
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

    pub fn family_pref(&self) -> FamilyPref {
        self.family_pref
    }

    pub fn phase(&self) -> Phase {
        self.inner.lock().phase
    }

    // ---------- 地址族 ----------

    /// 本机出站地址族；两族都探不到时当作只有 IPv4
    fn local_family(&self) -> cfnet::FamilySupport {
        let family = self
            .family_override
            .lock()
            .unwrap_or_else(cfnet::local_family_support);
        if family.v4 || family.v6 {
            family
        } else {
            cfnet::FamilySupport { v4: true, v6: false }
        }
    }

    #[cfg(test)]
    fn set_local_family(&self, family: cfnet::FamilySupport) {
        *self.family_override.lock() = Some(family);
    }

    /// 这一轮按哪一族挑赢家。会话中途的重赛（赢家坏了、手动）沿用连接层亲和：
    /// 那一族的出口上铸过 cf_clearance，翻族就要重新过盾。启动和换网的竞速不受旧亲和约束——
    /// 启动时是新进程（或设置变了重启网关），换网后出口本来就变了，clearance 反正要重铸。
    /// 不受约束时按配置：IPv4 / IPv6 优先严格按族；自动 → 本机有 IPv6 路由、这个网络上
    /// 24 小时内没验出 IPv6 不通就偏好 IPv6，慢太多时让给 IPv4
    fn race_family(&self) -> RaceFamily {
        let trigger = self.inner.lock().race_trigger;
        if !matches!(
            trigger,
            RaceTrigger::Start | RaceTrigger::Network | RaceTrigger::Family | RaceTrigger::Custom
        ) {
            if let Some(v6) = self.edge.affinity() {
                return RaceFamily {
                    prefer_v6: v6,
                    tolerant: false,
                    bound: true,
                };
            }
        }
        let prefer_v6 = match self.family_pref {
            FamilyPref::V4 => false,
            FamilyPref::V6 => true,
            FamilyPref::Auto => self.local_family().v6 && !self.v6_known_broken(),
        };
        RaceFamily {
            prefer_v6,
            tolerant: self.family_pref == FamilyPref::Auto,
            bound: false,
        }
    }

    /// 这个网络上 24 小时内按 IPv6 偏好竞速过、而 IPv6 一个都没通过
    fn v6_known_broken(&self) -> bool {
        let inner = self.inner.lock();
        inner
            .state
            .family_check
            .as_ref()
            .is_some_and(|check| !check.v6_ok && check.fresh_for(&inner.current_sig, now_unix()))
    }

    /// 赢家的地址族不是这里该用的，校验通过后在后台再竞速一轮（见 [`Self::spawn_background_race`]）：
    /// - IPv4 优先而赢家是 IPv6（从自动切回来）：本机有 IPv4 就换回去；
    /// - 自动 / IPv6 优先而赢家是 IPv4（升级到自动后首次启动、换到有 IPv6 的网络）：真换到
    ///   IPv6 出口要重新过一次盾，所以同一个网络 24 小时内只折腾一次——自动模式下这个网络上
    ///   竞速过就不再来（不论那次选了哪一族）；IPv6 优先模式下只在那次 IPv6 不通时不再来
    fn family_rerace_due(&self, winner: IpAddr) -> bool {
        // 赢家是用户自己填的节点：选它的那一轮已经在自定义节点里按 IP 协议偏好挑过了，
        // 再跑一轮还是它（IP 协议偏好改了由 custom_rerace_due 负责）
        if self.winner_is_custom() {
            return false;
        }
        let local = self.local_family();
        if self.family_pref == FamilyPref::V4 {
            return winner.is_ipv6() && local.v4;
        }
        if winner.is_ipv6() || !local.v6 {
            return false;
        }
        let inner = self.inner.lock();
        match inner
            .state
            .family_check
            .as_ref()
            .filter(|check| check.fresh_for(&inner.current_sig, now_unix()))
        {
            Some(check) => self.family_pref == FamilyPref::V6 && check.v6_ok,
            None => true,
        }
    }

    // ---------- 自定义节点 ----------

    fn winner_is_custom(&self) -> bool {
        self.inner
            .lock()
            .state
            .winner
            .as_ref()
            .is_some_and(|w| w.source == CandidateSource::Custom)
    }

    /// 还在降级期里的自定义节点
    fn demoted_custom_ips(state: &SelectState, now: u64) -> Vec<IpAddr> {
        state
            .custom_demoted
            .iter()
            .filter(|d| now.saturating_sub(d.at) < CUSTOM_RETRY_SECS)
            .map(|d| d.ip)
            .collect()
    }

    /// 启动时把持久化状态和现在的清单对一遍：清单（或 IP 协议偏好）变了，旧的降级记录作废；
    /// 赢家是自定义节点、而它出自的那一条已经从清单里拿掉了，就不再用它
    fn reconcile_custom(&self) {
        let mut inner = self.inner.lock();
        let now = now_unix();
        let same_list = inner
            .state
            .custom_check
            .as_ref()
            .is_some_and(|check| check.list == self.custom_fp);
        if !same_list {
            inner.state.custom_demoted.clear();
        }
        inner
            .state
            .custom_demoted
            .retain(|d| now.saturating_sub(d.at) < CUSTOM_RETRY_SECS);
        if self.custom.is_empty() {
            inner.state.custom_check = None;
        }
        let custom_winner = inner
            .state
            .winner
            .as_ref()
            .filter(|w| w.source == CandidateSource::Custom)
            .map(|w| w.ip);
        let stale_winner = custom_winner.is_some_and(|ip| match &inner.state.custom_entry {
            Some(entry) => !self.custom.entries.iter().any(|(text, _)| text == entry),
            // 没记出处：清单里没有域名时还能按地址判断
            None => {
                self.custom.domains().is_empty()
                    && !self.custom.cloudflare_ips().any(|listed| listed == ip)
            }
        });
        if stale_winner {
            info!("select: persisted winner was a custom node that is no longer listed, dropped");
            inner.state.winner = None;
        }
        if stale_winner || custom_winner.is_none() {
            inner.state.custom_entry = None;
        }
    }

    /// 配了自定义节点、而现在的赢家不是按这份清单挑出来的：校验通过后在后台再竞速一轮
    /// （见 [`Self::spawn_background_race`]）。清单或 IP 协议偏好变了总要重来；赢家已经是
    /// 自定义节点就不折腾；这个网络上一小时内验过它们都不通、或者它们都在降级期里，也先不来
    fn custom_rerace_due(&self) -> bool {
        let has_domains = !self.custom.domains().is_empty();
        if !has_domains && self.custom.cloudflare_ips().next().is_none() {
            return false;
        }
        let now = now_unix();
        let inner = self.inner.lock();
        let Some(check) = inner
            .state
            .custom_check
            .as_ref()
            .filter(|check| check.list == self.custom_fp)
        else {
            return true;
        };
        if inner
            .state
            .winner
            .as_ref()
            .is_some_and(|w| w.source == CandidateSource::Custom)
        {
            return false;
        }
        if !check.ok
            && check.sig == inner.current_sig
            && now.saturating_sub(check.at) < CUSTOM_RETRY_SECS
        {
            return false;
        }
        let demoted = Self::demoted_custom_ips(&inner.state, now);
        has_domains || self.custom.cloudflare_ips().any(|ip| !demoted.contains(&ip))
    }

    /// 这一轮要不要等自定义节点出结果再收敛：这个网络上一小时内刚验过它们都不通就不等
    /// （照样探测，赶在收敛前通过仍然算数）；手动重新优选总是等
    fn custom_worth_waiting(&self) -> bool {
        let inner = self.inner.lock();
        if inner.race_trigger == RaceTrigger::Manual {
            return true;
        }
        !inner.state.custom_check.as_ref().is_some_and(|check| {
            !check.ok
                && check.list == self.custom_fp
                && check.sig == inner.current_sig
                && now_unix().saturating_sub(check.at) < CUSTOM_RETRY_SECS
        })
    }

    /// 按最近一次收集候选时的对应关系，把探测结果归到清单的每一条上。`timed_out`：这一轮
    /// 跑满了总时限——到那时还没出结果的就是超时；提前收敛时没出结果的只是没等它
    fn custom_results(&self, outcomes: &[ProbeOutcome], timed_out: bool) -> Vec<CustomResult> {
        let plan = self.custom_plan.lock().clone();
        plan.into_iter()
            .map(|item| {
                if let Some(state) = item.skip {
                    return CustomResult {
                        entry: item.entry,
                        state,
                        ip: None,
                        latency_ms: None,
                        detail: None,
                    };
                }
                let probed: Vec<&ProbeOutcome> = outcomes
                    .iter()
                    .filter(|o| item.ips.contains(&o.ip))
                    .collect();
                match probed.iter().filter(|o| o.ok).min_by_key(|o| o.latency) {
                    Some(best) => CustomResult {
                        entry: item.entry,
                        state: CustomState::Ok,
                        ip: Some(best.ip),
                        latency_ms: Some(best.latency.as_millis().min(u32::MAX as u128) as u32),
                        detail: None,
                    },
                    None => match probed.first() {
                        Some(outcome) => CustomResult {
                            entry: item.entry,
                            state: CustomState::Failed,
                            ip: Some(outcome.ip),
                            latency_ms: None,
                            detail: Some(failure_kind(outcome.failure.as_ref())),
                        },
                        None if timed_out => CustomResult {
                            entry: item.entry,
                            state: CustomState::Failed,
                            ip: item.ips.first().copied(),
                            latency_ms: None,
                            detail: Some("timeout".to_string()),
                        },
                        // 提前收敛时还没出结果（比通过的那个慢）：不算失败，留到下次重测
                        None => CustomResult {
                            entry: item.entry,
                            state: CustomState::Pending,
                            ip: item.ips.first().copied(),
                            latency_ms: None,
                            detail: None,
                        },
                    },
                }
            })
            .collect()
    }

    /// 状态里的自定义节点一节：清单每一条现在是什么情况。没配返回 null
    fn custom_status(&self, inner: &Inner) -> serde_json::Value {
        if self.custom.entries.is_empty() && self.custom.invalid.is_empty() {
            return serde_json::Value::Null;
        }
        let now = now_unix();
        let check = inner
            .state
            .custom_check
            .as_ref()
            .filter(|check| check.list == self.custom_fp);
        let demoted = Self::demoted_custom_ips(&inner.state, now);
        // 正钉着的赢家是自定义节点（校验中、网络没变时也算在用）
        let pinned = matches!(Self::pin_of(inner), Pin::Winner(_));
        let active = inner
            .state
            .winner
            .as_ref()
            .filter(|w| w.source == CandidateSource::Custom && pinned)
            .map(|w| (w.ip, w.latency_ms));
        let mut nodes: Vec<serde_json::Value> = Vec::new();
        for (text, entry) in &self.custom.entries {
            let tested = check.and_then(|check| check.results.iter().find(|r| r.entry == *text));
            let mut result = match entry {
                CustomEntry::Ip(ip) if !cfnet::is_cloudflare(*ip) => CustomResult {
                    entry: text.clone(),
                    state: CustomState::NotCloudflare,
                    ip: None,
                    latency_ms: None,
                    detail: None,
                },
                CustomEntry::Ip(ip) if demoted.contains(ip) => CustomResult {
                    entry: text.clone(),
                    state: CustomState::Demoted,
                    ip: Some(*ip),
                    latency_ms: None,
                    detail: None,
                },
                // 上一轮记的「暂时停用」过了降级期就不算数了，等下一轮重测
                _ => tested
                    .filter(|result| result.state != CustomState::Demoted)
                    .cloned()
                    .unwrap_or(CustomResult {
                        entry: text.clone(),
                        state: CustomState::Pending,
                        ip: None,
                        latency_ms: None,
                        detail: None,
                    }),
            };
            // 正用着的那条：延迟以赢家最近一次校验为准
            let in_use = match (active, entry) {
                (Some((winner, _)), CustomEntry::Ip(ip)) => winner == *ip,
                (Some((winner, _)), CustomEntry::Domain(_)) => result.ip == Some(winner),
                (None, _) => false,
            };
            if let (true, Some((winner, latency))) = (in_use, active) {
                result.state = CustomState::Ok;
                result.ip = Some(winner);
                result.latency_ms = Some(latency);
                result.detail = None;
            }
            let mut value = serde_json::to_value(&result).unwrap_or_default();
            if let Some(map) = value.as_object_mut() {
                map.insert("active".to_string(), serde_json::Value::Bool(in_use));
            }
            nodes.push(value);
        }
        for text in &self.custom.invalid {
            nodes.push(serde_json::json!({
                "entry": text,
                "state": CustomState::Invalid,
                "active": false,
            }));
        }
        serde_json::json!({
            "nodes": nodes,
            "checked_at": check.map(|check| check.at),
        })
    }

    // ---------- 启动 / 状态 ----------

    /// 启动：有持久化赢家先校验，否则直接竞速
    pub fn start(self: &Arc<Self>) {
        self.reconcile_custom();
        let (winner, sig) = {
            let inner = self.inner.lock();
            (inner.state.winner.clone(), inner.current_sig.clone())
        };
        info!(
            "select: start mode={} family={} custom_nodes={} persisted_winner={} keys={} sig={}",
            self.mode.wire(),
            self.family_pref.wire(),
            self.custom.entries.len(),
            winner
                .as_ref()
                .map(|w| w.ip.to_string())
                .unwrap_or_else(|| "none".to_string()),
            self.inner.lock().state.ech_keys.len(),
            sig.as_deref().unwrap_or("-")
        );
        if winner.is_some() {
            self.spawn_verify(RaceTrigger::Start);
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

    /// 把一把钥匙放到池首（去重、截断），并通知 App 落盘；用不了的钥匙不收
    pub fn adopt_ech_key(&self, key: &EchConfigListBytes<'static>, source: EchKeySource) {
        if !ech_key_usable(key.as_ref()) {
            warn!(
                "select: ech key not adopted ({} bytes, source {:?}, {})",
                key.as_ref().len(),
                source,
                describe_key(key)
            );
            return;
        }
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
        let local = self.local_family();
        let affinity = self.edge.affinity();
        let inner = self.inner.lock();
        serde_json::json!({
            "ok": true,
            "mode": self.mode.wire(),
            "family": {
                "pref": self.family_pref.wire(),
                "local_v4": local.v4,
                "local_v6": local.v6,
                "affinity": affinity.map(|v6| if v6 { "v6" } else { "v4" }),
                "check": inner.state.family_check,
            },
            "phase": inner.phase,
            "winner": inner.state.winner,
            "last_race_at": inner.state.last_race_at,
            "last_error": inner.last_error,
            "fail_streak": self.edge.winner_fail_streak(),
            "share": self.share.load(Ordering::Relaxed),
            "keys": inner.state.ech_keys.len(),
            "network_sig": inner.current_sig,
            "custom": self.custom_status(&inner),
            // 正在竞速或校验（含不改阶段的后台竞速），界面用来显示「正在测试」
            "busy": self.racing.load(Ordering::Acquire),
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
                selector.spawn_verify(RaceTrigger::Network);
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
                // 手动点的就是要重测：被换掉的自定义节点也重新给机会
                inner.state.custom_demoted.clear();
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
            inner.race_trigger = trigger;
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

    /// 校验持久化赢家：通过 → Ready（地址族不是这里该用的、或者配了自定义节点而赢家不是
    /// 按这份清单挑的，就再后台竞速一轮，见 [`Self::family_rerace_due`] /
    /// [`Self::custom_rerace_due`]），失败 → 竞速。`trigger` 是改为竞速时的发车原因
    fn spawn_verify(self: &Arc<Self>, trigger: RaceTrigger) {
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
            self.spawn_race(trigger);
            return;
        };
        let selector = self.clone();
        let handle = tokio::spawn(async move {
            let guard = RaceGuard(selector.clone());
            let mut outcome = selector
                .probe_with_pool(winner.ip, &Self::probe_timeouts())
                .await;
            // 只是没等到（冷启动时网络还没热、移动网络刚唤醒）：放宽时限再探一次，
            // 别因为一次超时就扔掉上次的赢家、整轮重新优选（冷启动要多等好几秒）
            if outcome
                .as_ref()
                .and_then(|o| o.failure.as_ref())
                .is_some_and(ProbeFailure::is_timeout)
            {
                info!(
                    "select: verify winner {} timed out, retrying with patient timeouts",
                    winner.ip
                );
                outcome = selector
                    .probe_with_pool(winner.ip, &ProbeTimeouts::patient())
                    .await;
            }
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
                    if selector.family_rerace_due(winner.ip) {
                        drop(guard);
                        selector.spawn_background_race(RaceTrigger::Family);
                    } else if selector.custom_rerace_due() {
                        drop(guard);
                        selector.spawn_background_race(RaceTrigger::Custom);
                    }
                }
                other => {
                    let reason = other
                        .and_then(|o| o.failure)
                        .map(|f| f.to_string())
                        .unwrap_or_else(|| "no ech key".to_string());
                    warn!("select: verify winner {} failed: {} -> racing", winner.ip, reason);
                    drop(guard);
                    selector.spawn_race(trigger);
                }
            }
        })
        .abort_handle();
        self.track(handle);
    }

    /// 后台竞速（换族 / 试自定义节点）：当前赢家照常钉住、阶段不变，解析不用等；出了结果
    /// 再换过去，一个都没通过就当没发生过。先不动赢家是因为它的出口上铸着 cf_clearance——
    /// 竞速要是还选它这一族，就不必为换族多过一次盾
    fn spawn_background_race(self: &Arc<Self>, trigger: RaceTrigger) {
        if self
            .racing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        self.inner.lock().race_trigger = trigger;
        if trigger == RaceTrigger::Custom {
            info!("select: winner was not picked from the custom nodes, racing in background");
        } else {
            info!(
                "select: winner's address family is not the preferred one here (family={}), racing in background",
                self.family_pref.wire()
            );
        }
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
    }

    /// 一轮没出赢家：后台竞速当没发生过（当前赢家照常用），否则转 Failed
    fn race_failed(&self, reason: &str) {
        let trigger = self.inner.lock().race_trigger;
        if matches!(trigger, RaceTrigger::Family | RaceTrigger::Custom) {
            warn!(
                "select: background race ({:?}) found no winner ({}), keeping the current one",
                trigger, reason
            );
            return;
        }
        self.finish_failed(reason);
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
    async fn probe_ip(
        &self,
        ip: IpAddr,
        key: &EchConfigListBytes<'static>,
        timeouts: &ProbeTimeouts,
    ) -> ProbeOutcome {
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
                probe::probe_once(&target, tls, timeouts).await
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
        self.probe_with_pool(ip, &Self::probe_timeouts()).await
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

    async fn probe_with_pool(
        self: &Arc<Self>,
        ip: IpAddr,
        timeouts: &ProbeTimeouts,
    ) -> Option<ProbeOutcome> {
        let keys = self.key_pool();
        let first = keys.first()?;
        let outcome = self.probe_ip(ip, first, timeouts).await;
        match &outcome.failure {
            Some(ProbeFailure::EchRejected {
                retry_configs: Some(bytes),
            }) => {
                let key = EchConfigListBytes::from(bytes.clone());
                self.adopt_ech_key(&key, EchKeySource::RetryConfigs);
                debug!("select: {} rejected ech with retry_configs, retrying", ip);
                Some(self.probe_ip(ip, &key, timeouts).await)
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
                    let retry = self.probe_ip(ip, next, timeouts).await;
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
        self.resolve_cf_domain_with(name, family, false).await
    }

    /// 同上；`keep_own` 为 true 时不丢 Cloudflare 自家资产段的地址（自定义节点：用户点名要的，
    /// 能不能用交给探测）
    async fn resolve_cf_domain_with(
        self: &Arc<Self>,
        name: &str,
        family: cfnet::FamilySupport,
        keep_own: bool,
    ) -> Vec<IpAddr> {
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
                if !out.contains(&ip) && (keep_own || !cfnet::is_skipped(ip)) {
                    out.push(ip);
                }
            }
        }
        out
    }

    /// 解析自定义节点里的域名，每个最多 [`VENDOR_MAX_PER_DOMAIN`] 个地址；结果边到边写进 `sink`
    async fn resolve_custom_domains(
        self: &Arc<Self>,
        domains: Vec<String>,
        family: cfnet::FamilySupport,
        sink: Arc<Mutex<Vec<(String, Vec<IpAddr>)>>>,
    ) {
        let mut set = JoinSet::new();
        for domain in domains {
            let selector = self.clone();
            let sink = sink.clone();
            set.spawn(async move {
                let mut ips = selector.resolve_cf_domain_with(&domain, family, true).await;
                ips.truncate(VENDOR_MAX_PER_DOMAIN);
                debug!("select: custom {} -> {} candidates", domain, ips.len());
                sink.lock().push((domain, ips));
            });
        }
        while set.join_next().await.is_some() {}
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

    /// 把自定义节点清单排成这一轮的候选：字面 IP 要在 Cloudflare 网段里、本机有这一族的出口、
    /// 不在降级期；域名用解析结果。各条轮流出一个地址，凑到 [`CUSTOM_MAX_CANDIDATES`] 为止
    /// （每条至少轮到一个）。顺手记下每条对应哪些候选，竞速完按它归结果。
    /// `sticky` 是上次的赢家：它是自定义节点、而它出自的那个域名这一轮没解析出来时，仍当作
    /// 那个域名的地址留下——多半是 DNS 一时没答上，别因此丢掉正用着的节点
    fn plan_custom(
        &self,
        family: cfnet::FamilySupport,
        resolved: &[(String, Vec<IpAddr>)],
        sticky: Option<(IpAddr, CandidateSource)>,
    ) -> Vec<IpAddr> {
        let (demoted, winner_entry) = {
            let inner = self.inner.lock();
            (
                Self::demoted_custom_ips(&inner.state, now_unix()),
                inner.state.custom_entry.clone(),
            )
        };
        let family_ok = |ip: &IpAddr| (ip.is_ipv4() && family.v4) || (ip.is_ipv6() && family.v6);
        let mut plan: Vec<CustomPlanItem> = Vec::new();
        // 每条能出的地址（还没按上限截）
        let mut pools: Vec<Vec<IpAddr>> = Vec::new();
        for (text, entry) in &self.custom.entries {
            let (ips, skip) = match entry {
                CustomEntry::Ip(ip) => {
                    if !cfnet::is_cloudflare(*ip) {
                        (Vec::new(), Some(CustomState::NotCloudflare))
                    } else if !family_ok(ip) {
                        (Vec::new(), Some(CustomState::NoFamily))
                    } else if demoted.contains(ip) {
                        (Vec::new(), Some(CustomState::Demoted))
                    } else {
                        (vec![*ip], None)
                    }
                }
                CustomEntry::Domain(name) => {
                    let ips: Vec<IpAddr> = resolved
                        .iter()
                        .find(|(domain, _)| domain == name)
                        .map(|(_, ips)| ips.clone())
                        .unwrap_or_default();
                    if ips.is_empty() {
                        (Vec::new(), Some(CustomState::Unresolved))
                    } else {
                        let usable: Vec<IpAddr> =
                            ips.into_iter().filter(|ip| !demoted.contains(ip)).collect();
                        if usable.is_empty() {
                            (Vec::new(), Some(CustomState::Demoted))
                        } else {
                            (usable, None)
                        }
                    }
                }
            };
            pools.push(ips);
            plan.push(CustomPlanItem {
                entry: text.clone(),
                ips: Vec::new(),
                skip,
            });
        }
        if let Some((ip, CandidateSource::Custom)) = sticky {
            let listed = pools.iter().any(|pool| pool.contains(&ip));
            let usable = cfnet::is_cloudflare(ip) && family_ok(&ip) && !demoted.contains(&ip);
            let unresolved = plan.iter().position(|item| {
                item.skip == Some(CustomState::Unresolved)
                    && winner_entry.as_deref() == Some(item.entry.as_str())
            });
            if let (false, true, Some(index)) = (listed, usable, unresolved) {
                pools[index] = vec![ip];
                plan[index].skip = None;
            }
        }
        let mut out: Vec<IpAddr> = Vec::new();
        let mut round = 0usize;
        while out.len() < CUSTOM_MAX_CANDIDATES && pools.iter().any(|pool| pool.len() > round) {
            for (index, pool) in pools.iter().enumerate() {
                let Some(ip) = pool.get(round) else {
                    continue;
                };
                if out.len() >= CUSTOM_MAX_CANDIDATES {
                    break;
                }
                // 两条指到同一个地址（域名解析出了清单里已有的 IP）：两条都认这个候选
                if !out.contains(ip) {
                    out.push(*ip);
                }
                plan[index].ips.push(*ip);
            }
            round += 1;
        }
        *self.custom_plan.lock() = plan;
        out
    }

    /// 收集候选与钥匙（含超时）
    async fn gather(self: &Arc<Self>) -> (Vec<Candidate>, Vec<EchConfigListBytes<'static>>) {
        let family = self.local_family();
        let prefer_v6 = self.race_family().prefer_v6;
        let sticky = self
            .inner
            .lock()
            .state
            .winner
            .as_ref()
            .map(|w| (w.ip, w.source));
        let vendor_sink: Arc<Mutex<Vec<IpAddr>>> = Arc::new(Mutex::new(Vec::new()));
        let community_sink: Arc<Mutex<Vec<IpAddr>>> = Arc::new(Mutex::new(Vec::new()));
        let custom_sink: Arc<Mutex<Vec<(String, Vec<IpAddr>)>>> = Arc::new(Mutex::new(Vec::new()));

        // 候选和钥匙都边到边落：atlas 进 state.atlas 缓存、域名进 sink、钥匙进池；
        // 超时只是停止等待，不丢已经拿到的
        let gather_all = async {
            let atlas_task = self.fetch_atlas(family);
            // 自定义节点里的域名，两种模式都解析
            let custom_task =
                self.resolve_custom_domains(self.custom.domains(), family, custom_sink.clone());
            if self.mode == SelectMode::AtlasOnly {
                let _ = tokio::join!(atlas_task, custom_task);
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
                tokio::join!(atlas_task, vendor_task, community_task, keys_task, custom_task);
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
            // Cloudflare 自家资产段一般不服务别的站，池里的候选直接跳过；
            // 用户点名要的自定义节点照探，能不能用由探测说了算
            if family_ok
                && cfnet::is_cloudflare(ip)
                && (source == CandidateSource::Custom || !cfnet::is_skipped(ip))
                && seen.insert(ip)
                && candidates.len() < SELECT_MAX_CANDIDATES
            {
                candidates.push(Candidate { ip, source });
            }
        };
        let custom_ips = self.plan_custom(family, &custom_sink.lock(), sticky);
        match sticky {
            Some((ip, _)) if custom_ips.contains(&ip) => {
                push(ip, CandidateSource::Custom, &mut candidates)
            }
            // 上次的赢家是自定义节点、现在已经不在清单里了：不再当粘性候选
            Some((_, CandidateSource::Custom)) => {}
            Some((ip, _)) => push(ip, CandidateSource::Sticky, &mut candidates),
            None => {}
        }
        for ip in custom_ips {
            push(ip, CandidateSource::Custom, &mut candidates);
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
            // 首选 IPv6 时先抽 v6、多抽几个：否则随机 v4 先把候选上限占满，v6 根本排不上
            let v6_first = prefer_v6 && family.v6;
            if v6_first {
                for ip in cfnet::sample_v6(RANDOM_V6_SAMPLES_PREFERRED, &rng) {
                    push(ip, CandidateSource::Random, &mut candidates);
                }
            }
            if family.v4 {
                for ip in cfnet::sample_v4_one_per_24(RANDOM_V4_SAMPLES, &rng) {
                    push(ip, CandidateSource::Random, &mut candidates);
                }
            }
            if family.v6 && !v6_first {
                for ip in cfnet::sample_v6(RANDOM_V6_SAMPLES, &rng) {
                    push(ip, CandidateSource::Random, &mut candidates);
                }
            }
            (vendor_n, community_n, candidates.len() - before)
        };
        info!(
            "select: candidates total={} sticky={} custom={} atlas={} vendor={} community={} random={} (v4 {}, v6 {}, ipv6 candidates {}, prefer {})",
            candidates.len(),
            candidates.iter().filter(|c| c.source == CandidateSource::Sticky).count(),
            candidates.iter().filter(|c| c.source == CandidateSource::Custom).count(),
            candidates.iter().filter(|c| c.source == CandidateSource::Atlas).count(),
            vendor_n,
            community_n,
            random_n,
            family.v4,
            family.v6,
            candidates.iter().filter(|c| c.ip.is_ipv6()).count(),
            if prefer_v6 { "IPv6" } else { "IPv4" }
        );
        let candidates = if prefer_v6 {
            interleave_families(candidates, true)
        } else {
            candidates
        };

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

    /// 把钥匙追加到池尾（持久化的在前），去重、截断；用不了的钥匙不收
    fn append_ech_key(&self, key: &EchConfigListBytes<'static>, source: EchKeySource) {
        if !ech_key_usable(key.as_ref()) {
            warn!(
                "select: ech key not added (source {:?}, {})",
                source,
                describe_key(key)
            );
            return;
        }
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
        self.race_with(candidates, keys, Self::probe_timeouts(), true)
            .await;
    }

    /// 一轮探测。[patient_retry]：全部只是超时（网络慢，不是地址坏）时，
    /// 挑前几个候选（上次的赢家优先）放宽时限再探一次，再不行才判失败
    async fn race_with(
        self: &Arc<Self>,
        candidates: Vec<Candidate>,
        keys: Vec<EchConfigListBytes<'static>>,
        timeouts: ProbeTimeouts,
        patient_retry: bool,
    ) {
        if keys.is_empty() {
            warn!("select: no ech key available, falling back to tier 2");
            self.race_failed("no ech key");
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
            self.race_failed("no candidates");
            return;
        }

        let start = Instant::now();
        let total = Duration::from_millis(SELECT_RACE_TOTAL_MS);
        let family = self.race_family();
        let trigger = self.inner.lock().race_trigger;
        // 自定义节点：有通过的就只在它们里挑赢家，池里的再快也不算；所以它们没出结果前先不收敛
        let custom_ips: HashSet<IpAddr> = candidates
            .iter()
            .filter(|c| c.source == CandidateSource::Custom)
            .map(|c| c.ip)
            .collect();
        let wait_custom = !custom_ips.is_empty() && self.custom_worth_waiting();
        // 手动重测和后台竞速不赶时间：等自定义节点全出结果（清单里每一条都有个准话）；
        // 其余是有请求在等的竞速，有一个通过后只再等一小会儿
        let custom_thorough = matches!(
            trigger,
            RaceTrigger::Manual | RaceTrigger::Family | RaceTrigger::Custom
        );
        let set_family_count = candidates
            .iter()
            .filter(|c| c.ip.is_ipv6() == family.prefer_v6)
            .count();
        let semaphore = Arc::new(Semaphore::new(SELECT_CONCURRENCY));
        let mut set: JoinSet<(Candidate, Option<ProbeOutcome>)> = JoinSet::new();
        let mut retry_pool: Vec<Candidate> = candidates
            .iter()
            .filter(|c| c.source == CandidateSource::Sticky)
            .chain(candidates.iter().filter(|c| c.source != CandidateSource::Sticky))
            .take(SELECT_PATIENT_RETRY_MAX)
            .cloned()
            .collect();
        for candidate in candidates {
            let selector = self.clone();
            let semaphore = semaphore.clone();
            set.spawn(async move {
                let Ok(_permit) = semaphore.acquire_owned().await else {
                    return (candidate, None);
                };
                let outcome = selector.probe_with_pool(candidate.ip, &timeouts).await;
                (candidate, outcome)
            });
        }

        let mut passes: Vec<(Candidate, ProbeOutcome)> = Vec::new();
        let mut all: Vec<ProbeOutcome> = Vec::new();
        let mut first_pass_at: Option<Instant> = None;
        // 首选族还没出结果的探测数、是否已有首选族通过、IPv6 出了几个结果
        let mut preferred_pending = set_family_count;
        let mut preferred_passed = false;
        let mut v6_outcomes = 0usize;
        // 还没出结果的自定义节点数、首个自定义节点通过的时刻
        let mut custom_pending = custom_ips.len();
        let mut custom_pass_at: Option<Instant> = None;
        loop {
            let now = Instant::now();
            let mut deadline = start + total;
            // 首选族还没有通过、又还有探测在途：首个通过（另一族的）之后多等首选族一会儿
            let await_preferred = !preferred_passed && preferred_pending > 0;
            // 自定义节点还有在途的、又一个都没通过：先不按池里的通过收敛，最多等到总时限
            let await_custom = wait_custom && custom_pending > 0 && custom_pass_at.is_none();
            if let Some(at) = custom_pass_at {
                // 赢家只在自定义节点里挑了：它们出齐就收；有请求在等时最多再等一小会儿
                if custom_pending == 0 {
                    break;
                }
                if !custom_thorough {
                    deadline = deadline.min(at + Duration::from_millis(SELECT_GRACE_MS));
                }
            } else if !await_custom {
                if let Some(at) = first_pass_at {
                    let grace = if await_preferred {
                        SELECT_FAMILY_GRACE_MS
                    } else {
                        SELECT_GRACE_MS
                    };
                    deadline = deadline.min(at + Duration::from_millis(grace));
                }
            }
            let enough = custom_pass_at.is_none()
                && !await_custom
                && passes.len() >= SELECT_MAX_PASSES
                && !await_preferred;
            if enough || now >= deadline {
                break;
            }
            match tokio::time::timeout(deadline - now, set.join_next()).await {
                Ok(Some(Ok((candidate, outcome)))) => {
                    let preferred = candidate.ip.is_ipv6() == family.prefer_v6;
                    if preferred {
                        preferred_pending = preferred_pending.saturating_sub(1);
                    }
                    let is_custom = candidate.source == CandidateSource::Custom;
                    if is_custom {
                        custom_pending = custom_pending.saturating_sub(1);
                    }
                    let Some(outcome) = outcome else {
                        continue;
                    };
                    if candidate.ip.is_ipv6() {
                        v6_outcomes += 1;
                    }
                    if outcome.ok && preferred {
                        preferred_passed = true;
                    }
                    // 安卓日志只到 info：自定义节点的结果单独记一行，「填了没用上」时看得到原因
                    if is_custom {
                        info!(
                            "select: custom node {} -> {} {} ms{}",
                            candidate.ip,
                            if outcome.ok { "ok" } else { "fail" },
                            outcome.latency.as_millis(),
                            outcome
                                .failure
                                .as_ref()
                                .map(|f| format!(" ({})", f))
                                .unwrap_or_default()
                        );
                    }
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
                        if is_custom {
                            custom_pass_at.get_or_insert(Instant::now());
                        }
                        passes.push((candidate, outcome.clone()));
                    }
                    all.push(outcome);
                }
                Ok(Some(Err(_))) => continue,
                Ok(None) => break,
                Err(_) => break,
            }
        }
        set.abort_all();
        // 跑满了总时限：到这会儿还没出结果的自定义节点按超时算
        let timed_out = start.elapsed() >= total;

        // 自定义节点有通过的就只在它们里挑，没有才看全部。先按地址族（见 race_family：会话中途
        // 沿用亲和，不把整个 App 翻到另一个出口 IP 上），再按延迟；自动模式下首选族慢太多时
        // 让给另一族
        let custom_passes: Vec<(Candidate, ProbeOutcome)> = passes
            .iter()
            .filter(|(candidate, _)| candidate.source == CandidateSource::Custom)
            .cloned()
            .collect();
        let custom_ok = !custom_passes.is_empty();
        // 后台试自定义节点的那一轮：它们没通过就不动现在的赢家（换成池里别的地址只是白折腾，
        // 还可能翻到另一族、多过一次盾），只记下这个网络上它们不通
        if trigger == RaceTrigger::Custom && !custom_ok {
            if !passes.is_empty() {
                self.record_custom_check(false, &all, timed_out);
                self.push_state();
            }
            info!(
                "select: no custom node passed ({} of {} probed, {} others passed), keeping the current winner",
                all.iter().filter(|o| custom_ips.contains(&o.ip)).count(),
                custom_ips.len(),
                passes.len()
            );
            return;
        }
        let picked = pick_winner(&custom_passes, family).or_else(|| pick_winner(&passes, family));
        let Some((best, outcome)) = picked else {
            // 安卓日志只到 info，这里把失败原因按类型汇总，方便真机排障
            let mut kinds: Vec<(String, usize)> = Vec::new();
            for outcome in &all {
                let kind = failure_kind(outcome.failure.as_ref());
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
            let all_timeouts = !all.is_empty()
                && all
                    .iter()
                    .all(|o| o.failure.as_ref().is_some_and(ProbeFailure::is_timeout));
            if patient_retry && all_timeouts {
                // 只留真探过、且只是超时的地址（没轮到的不算）
                retry_pool.retain(|c| all.iter().any(|o| o.ip == c.ip));
                if !retry_pool.is_empty() {
                    info!(
                        "select: every probe timed out, retrying {} candidates with patient timeouts",
                        retry_pool.len()
                    );
                    Box::pin(self.race_with(retry_pool, keys, ProbeTimeouts::patient(), false))
                        .await;
                    return;
                }
            }
            self.race_failed("no candidate passed");
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
        let v6_passed = passes.iter().filter(|(c, _)| c.ip.is_ipv6()).count();
        // 赢家是自定义节点：记下它出自清单的哪一条
        let custom_entry = (best.source == CandidateSource::Custom)
            .then(|| {
                self.custom_plan
                    .lock()
                    .iter()
                    .find(|item| item.ips.contains(&best.ip))
                    .map(|item| item.entry.clone())
            })
            .flatten();
        info!(
            "select: winner {} {} ms source={:?} ech={:?} ({} passed of {} probed in {} ms; IPv6 {} passed of {}, family={} prefer={}{})",
            best.ip,
            outcome.latency.as_millis(),
            best.source,
            ech_source,
            passes.len(),
            all.len(),
            start.elapsed().as_millis(),
            v6_passed,
            v6_outcomes,
            self.family_pref.wire(),
            if family.prefer_v6 { "IPv6" } else { "IPv4" },
            if family.bound { " (affinity)" } else { "" }
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
            inner.state.custom_entry = custom_entry;
            inner.state.network_sig = inner.current_sig.clone();
            inner.state.fail_streak = 0;
            inner.failed_at = None;
            inner.phase = Phase::Ready;
            inner.last_error = None;
            // 自定义节点的测量不分享：只报池里候选的结果
            inner.report_pending = passes
                .iter()
                .filter(|(candidate, _)| candidate.source != CandidateSource::Custom)
                .count()
                >= 2;
            // 按 IPv6 偏好、不受亲和约束地探过 IPv6：记下这个网络上的结论（见 family_rerace_due）。
            // 自定义节点赢的那一轮收得早，IPv6 候选多半没探完，不算数
            if !family.bound
                && self.family_pref != FamilyPref::V4
                && v6_outcomes > 0
                && !custom_ok
            {
                inner.state.family_check = Some(FamilyCheck {
                    sig: inner.current_sig.clone(),
                    at: now_unix(),
                    v6_ok: v6_passed > 0,
                });
            }
        }
        if !self.custom.is_empty() {
            self.record_custom_check(custom_ok, &all, timed_out);
        }
        self.sync_pin();
        self.push_state();
        let shareable: Vec<ProbeOutcome> = all
            .iter()
            .filter(|outcome| !custom_ips.contains(&outcome.ip))
            .cloned()
            .collect();
        self.maybe_report(&shareable).await;
    }

    /// 记下自定义节点这一轮的结论（见 [`Self::custom_rerace_due`]）
    fn record_custom_check(&self, ok: bool, outcomes: &[ProbeOutcome], timed_out: bool) {
        let results = self.custom_results(outcomes, timed_out);
        let mut inner = self.inner.lock();
        inner.state.custom_check = Some(CustomCheck {
            list: self.custom_fp.clone(),
            sig: inner.current_sig.clone(),
            at: now_unix(),
            ok,
            results,
        });
    }

    /// 本轮没选出赢家。上次的赢家**留在持久化状态里**（不钉住，Failed 下
    /// pin 为 None）：一轮全失败多半是此刻网络不通，不说明它坏了；下次启动 /
    /// 换网先校验它，也作为下一轮的 Sticky 候选。真被实际流量连续打挂的赢家
    /// 由 [PinListener::winner_failed] 清掉
    fn finish_failed(&self, reason: &str) {
        let mut inner = self.inner.lock();
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
                // 自定义节点被实际流量打掉：一段时间内不再进候选，免得下一轮探测通过又选回来
                if inner
                    .state
                    .winner
                    .as_ref()
                    .is_some_and(|w| w.source == CandidateSource::Custom)
                {
                    let now = now_unix();
                    inner
                        .state
                        .custom_demoted
                        .retain(|d| d.ip != ip && now.saturating_sub(d.at) < CUSTOM_RETRY_SECS);
                    inner.state.custom_demoted.push(CustomDemotion { ip, at: now });
                }
                inner.state.custom_entry = None;
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

    /// 一份结构完整的 ECHConfigList（V18，X25519 + HKDF-SHA256 / AES-128-GCM）；
    /// config_id 与公钥都取 `byte`，不同的 byte 是不同的钥匙
    fn key(byte: u8) -> EchConfigListBytes<'static> {
        let public_name = b"cloudflare-ech.com";
        let mut contents = vec![byte];
        contents.extend_from_slice(&0x0020u16.to_be_bytes());
        contents.extend_from_slice(&32u16.to_be_bytes());
        contents.extend_from_slice(&[byte; 32]);
        contents.extend_from_slice(&4u16.to_be_bytes());
        contents.extend_from_slice(&0x0001u16.to_be_bytes());
        contents.extend_from_slice(&0x0001u16.to_be_bytes());
        contents.push(0);
        contents.push(public_name.len() as u8);
        contents.extend_from_slice(public_name);
        contents.extend_from_slice(&0u16.to_be_bytes());
        let mut config = 0xfe0du16.to_be_bytes().to_vec();
        config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        config.extend_from_slice(&contents);
        let mut list = (config.len() as u16).to_be_bytes().to_vec();
        list.extend_from_slice(&config);
        EchConfigListBytes::from(list)
    }

    /// BoringSSL 在握手不是因 ECH 被拒而失败时，SSL_get0_ech_retry_configs 给的占位
    const BORINGSSL_RETRY_PLACEHOLDER: [u8; 5] = [0xfe, 0x0d, 0xff, 0xff, 0xff];

    fn placeholder_key() -> EchConfigListBytes<'static> {
        EchConfigListBytes::from(BORINGSSL_RETRY_PLACEHOLDER.to_vec())
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
        // 地址族偏好跟 EdgePin 的配置走（老用例用 EdgePin::new(true) 表示「IPv6 优先」）
        let family_pref = if edge.prefer_ipv6() {
            FamilyPref::V6
        } else {
            FamilyPref::V4
        };
        fake_selector_family(mode, family_pref, state, f, edge)
    }

    /// 同上，指定地址族偏好
    fn fake_selector_family(
        mode: SelectMode,
        family_pref: FamilyPref,
        state: SelectState,
        f: ProbeFn,
        edge: Arc<EdgePin>,
    ) -> Arc<Selector> {
        fake_selector_custom(mode, family_pref, state, f, edge, Vec::new(), &[])
    }

    /// 同上，带公共 DoH 列表和自定义节点清单
    fn fake_selector_custom(
        mode: SelectMode,
        family_pref: FamilyPref,
        state: SelectState,
        f: ProbeFn,
        edge: Arc<EdgePin>,
        public_doh: Vec<(String, DohUpstream)>,
        custom: &[&str],
    ) -> Arc<Selector> {
        let roots = RootCertStore::empty();
        let provider = Arc::new(crate::tls_crypto::build_provider());
        let custom: Vec<String> = custom.iter().map(|text| text.to_string()).collect();
        Selector::build(
            mode,
            family_pref,
            state,
            Some("wifi".to_string()),
            roots,
            provider,
            public_doh,
            None,
            Some(ReportEndpoint {
                host: "cfhub6.example".to_string(),
                path: "/api/v1/probe/report".to_string(),
                version: "cfluxdo/test".to_string(),
            }),
            None,
            edge,
            CustomNodes::parse(&custom),
            Prober::Fake(f),
        )
    }

    /// 只带公共 DoH 列表的 selector（探测不会被调用）
    fn selector_with_public_doh(public_doh: Vec<(String, DohUpstream)>) -> Arc<Selector> {
        Selector::build(
            SelectMode::LocalAtlas,
            FamilyPref::V4,
            SelectState::default(),
            Some("wifi".to_string()),
            RootCertStore::empty(),
            Arc::new(crate::tls_crypto::build_provider()),
            public_doh,
            None,
            None,
            None,
            Arc::new(EdgePin::new(false)),
            CustomNodes::default(),
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

    #[test]
    fn ech_key_usable_only_accepts_complete_lists() {
        assert!(ech_key_usable(key(1).as_ref()));
        assert!(!ech_key_usable(&BORINGSSL_RETRY_PLACEHOLDER));
        assert!(!ech_key_usable(&[]));
        // 空列表、长度对但内容不是 ECHConfig、末尾多出字节
        assert!(!ech_key_usable(&[0, 0]));
        assert!(!ech_key_usable(&[0, 3, 1, 1, 1]));
        let mut trailing = key(1).as_ref().to_vec();
        trailing.push(0);
        assert!(!ech_key_usable(&trailing));
    }

    #[test]
    fn unusable_persisted_keys_are_dropped_on_load() {
        // 旧版把握手失败的占位当新钥匙采纳并落了盘
        let mut state = state_with_key(1);
        state
            .ech_keys
            .insert(0, EchKey::new(&placeholder_key(), EchKeySource::RetryConfigs));
        let back = SelectState::from_json(&serde_json::to_string(&state).unwrap()).unwrap();
        assert_eq!(back.ech_keys.len(), 1);
        assert_eq!(back.ech_keys[0].bytes().unwrap().as_ref(), key(1).as_ref());
    }

    #[tokio::test]
    async fn unusable_key_is_never_adopted() {
        let selector = fake_selector(
            SelectMode::LocalAtlas,
            state_with_key(1),
            Arc::new(|ip, _| outcome(ip, true, 50, None)),
        );
        selector.adopt_ech_key(&placeholder_key(), EchKeySource::RetryConfigs);
        selector.append_ech_key(&placeholder_key(), EchKeySource::Table);
        assert_eq!(selector.key_pool().len(), 1);
        assert_eq!(selector.current_ech_key().unwrap().as_ref(), key(1).as_ref());
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
    async fn failed_race_keeps_last_winner_for_next_start_but_unpinned() {
        let mut state = state_with_key(1);
        state.winner = Some(Winner {
            ip: ip("104.21.0.9"),
            latency_ms: 30,
            verified_at: 1,
            source: CandidateSource::Atlas,
            ech_source: EchKeySource::Persisted,
        });
        let selector = fake_selector(
            SelectMode::LocalAtlas,
            state,
            Arc::new(|ip, _| outcome(ip, false, 5, Some(ProbeFailure::HttpStatus(403)))),
        );
        selector
            .race_candidates(candidates(&["104.21.0.1"]), selector.key_pool())
            .await;
        assert_eq!(selector.phase(), Phase::Failed);
        assert!(selector.winner_ip().is_none(), "失败后不再钉住");
        let persisted = SelectState::from_json(&selector.state_json()).unwrap();
        assert_eq!(persisted.winner.map(|w| w.ip), Some(ip("104.21.0.9")));
    }

    #[tokio::test]
    async fn all_timeouts_get_one_patient_retry_with_sticky_first() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let probed: Arc<Mutex<Vec<IpAddr>>> = Arc::new(Mutex::new(Vec::new()));
        let (c, p) = (calls.clone(), probed.clone());
        let selector = fake_selector(
            SelectMode::LocalAtlas,
            state_with_key(1),
            Arc::new(move |ip, _| {
                p.lock().push(ip);
                // 第一轮三个都超时，复核时才通
                if c.fetch_add(1, Ordering::SeqCst) < 3 {
                    outcome(ip, false, 2000, Some(ProbeFailure::TcpTimeout))
                } else {
                    outcome(ip, true, 40, None)
                }
            }),
        );
        let mut list = candidates(&["104.21.0.1", "104.21.0.2"]);
        list.push(Candidate {
            ip: ip("104.21.0.7"),
            source: CandidateSource::Sticky,
        });
        selector.race_candidates(list, selector.key_pool()).await;
        assert_eq!(selector.phase(), Phase::Ready);
        assert!(selector.winner_ip().is_some());
        let probed = probed.lock().clone();
        assert_eq!(probed.len(), 6, "三个各探一次，再三个复核一次");
        assert_eq!(probed[3], ip("104.21.0.7"), "复核先探上次的赢家");
        assert_eq!(selector.inner.lock().state.races_log.len(), 1, "复核不另算一轮");
    }

    #[tokio::test]
    async fn non_timeout_failures_are_not_retried() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = calls.clone();
        let selector = fake_selector(
            SelectMode::LocalAtlas,
            state_with_key(1),
            Arc::new(move |ip, _| {
                c.fetch_add(1, Ordering::SeqCst);
                outcome(ip, false, 5, Some(ProbeFailure::TcpConnect))
            }),
        );
        selector
            .race_candidates(candidates(&["104.21.0.1", "104.21.0.2"]), selector.key_pool())
            .await;
        assert_eq!(selector.phase(), Phase::Failed);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn verify_timeout_retries_patiently_and_keeps_winner() {
        let mut state = state_with_key(1);
        state.winner = Some(Winner {
            ip: ip("104.21.0.1"),
            latency_ms: 30,
            verified_at: 1,
            source: CandidateSource::Atlas,
            ech_source: EchKeySource::Persisted,
        });
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = calls.clone();
        let selector = fake_selector(
            SelectMode::LocalAtlas,
            state,
            Arc::new(move |ip, _| {
                if c.fetch_add(1, Ordering::SeqCst) == 0 {
                    outcome(ip, false, 2000, Some(ProbeFailure::TlsTimeout))
                } else {
                    outcome(ip, true, 180, None)
                }
            }),
        );
        selector.start();
        wait_phase(&selector, Phase::Ready).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(selector.winner_ip(), Some(ip("104.21.0.1")));
        assert_eq!(
            selector.inner.lock().state.winner.as_ref().unwrap().latency_ms,
            180
        );
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
        assert_eq!(edge.winner_fail_streak(), 1);
        assert_eq!(selector.status_json()["fail_streak"], 1);
        edge.report(
            "linux.do",
            winner,
            crate::edge_pin::Outcome::Connected {
                rtt: None,
                took_over: false,
            },
        );
        assert_eq!(edge.winner_fail_streak(), 0);
        for _ in 0..WINNER_FAIL_THRESHOLD {
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

    const DUAL_STACK: cfnet::FamilySupport = cfnet::FamilySupport { v4: true, v6: true };
    const V4_ONLY: cfnet::FamilySupport = cfnet::FamilySupport { v4: true, v6: false };

    /// v4 / v6 各自固定延迟都通过的假探测
    fn by_family(v4_ms: u64, v6_ms: u64) -> ProbeFn {
        Arc::new(move |ip, _| {
            outcome(ip, true, if ip.is_ipv6() { v6_ms } else { v4_ms }, None)
        })
    }

    fn auto_selector(state: SelectState, f: ProbeFn, local: cfnet::FamilySupport) -> Arc<Selector> {
        let selector = fake_selector_family(
            SelectMode::LocalAtlas,
            FamilyPref::Auto,
            state,
            f,
            Arc::new(EdgePin::new(false)),
        );
        selector.set_local_family(local);
        selector
    }

    fn v4_winner_state() -> SelectState {
        let mut state = state_with_key(1);
        state.winner = Some(Winner {
            ip: ip("104.21.0.1"),
            latency_ms: 30,
            verified_at: 1,
            source: CandidateSource::Sticky,
            ech_source: EchKeySource::Persisted,
        });
        state.network_sig = Some("wifi".to_string());
        state
    }

    #[test]
    fn family_pref_from_config() {
        assert_eq!(FamilyPref::from_config(true, true), FamilyPref::V6);
        assert_eq!(FamilyPref::from_config(true, false), FamilyPref::V6);
        assert_eq!(FamilyPref::from_config(false, true), FamilyPref::Auto);
        assert_eq!(FamilyPref::from_config(false, false), FamilyPref::V4);
        // 老的状态 JSON 没有 family_check，照常读
        let state = SelectState::from_json(r#"{"v":1}"#).unwrap();
        assert!(state.family_check.is_none());
    }

    #[test]
    fn interleave_keeps_sticky_first_and_alternates_families() {
        let mut list = vec![Candidate {
            ip: ip("104.21.0.9"),
            source: CandidateSource::Sticky,
        }];
        list.extend(candidates(&[
            "104.21.0.1",
            "104.21.0.2",
            "104.21.0.3",
            "2606:4700::1",
            "2606:4700::2",
        ]));
        let order: Vec<String> = interleave_families(list, true)
            .iter()
            .map(|c| c.ip.to_string())
            .collect();
        assert_eq!(
            order,
            [
                "104.21.0.9",
                "2606:4700::1",
                "104.21.0.1",
                "2606:4700::2",
                "104.21.0.2",
                "104.21.0.3"
            ]
        );
    }

    #[test]
    fn pick_winner_tolerance_only_in_auto() {
        let passes: Vec<(Candidate, ProbeOutcome)> = [("104.21.0.1", 20), ("2606:4700::1", 300)]
            .iter()
            .map(|(text, ms)| {
                (
                    Candidate {
                        ip: ip(text),
                        source: CandidateSource::Vendor,
                    },
                    outcome(ip(text), true, *ms, None),
                )
            })
            .collect();
        let family = |tolerant| RaceFamily {
            prefer_v6: true,
            tolerant,
            bound: false,
        };
        // 自动：v6 300 ms 在 v4 20 ms + 300 ms 之内，仍选 v6
        assert!(pick_winner(&passes, family(true)).unwrap().0.ip.is_ipv6());
        let mut slow = passes.clone();
        slow[1].1.latency = Duration::from_millis(400);
        // 自动：v6 慢出 320 ms 以上，让给 v4
        assert!(pick_winner(&slow, family(true)).unwrap().0.ip.is_ipv4());
        // IPv6 优先：再慢也选 v6
        assert!(pick_winner(&slow, family(false)).unwrap().0.ip.is_ipv6());
        // 只有另一族通过：用另一族
        assert!(pick_winner(&slow[..1], family(false)).unwrap().0.ip.is_ipv4());
        assert!(pick_winner(&[], family(true)).is_none());
    }

    #[tokio::test]
    async fn auto_prefers_ipv6_on_dual_stack_and_records_the_check() {
        let selector = auto_selector(state_with_key(1), by_family(20, 60), DUAL_STACK);
        selector
            .race_candidates(
                candidates(&["104.21.0.1", "2606:4700::6810:1"]),
                selector.key_pool(),
            )
            .await;
        assert_eq!(selector.winner_ip(), Some(ip("2606:4700::6810:1")));
        let check = selector.inner.lock().state.family_check.clone().unwrap();
        assert!(check.v6_ok);
        assert_eq!(check.sig.as_deref(), Some("wifi"));
        // 只有 IPv4 路由的网络：自动等于 IPv4 优先
        let selector = auto_selector(state_with_key(1), by_family(60, 20), V4_ONLY);
        selector
            .race_candidates(
                candidates(&["104.21.0.1", "2606:4700::6810:1"]),
                selector.key_pool(),
            )
            .await;
        assert_eq!(selector.winner_ip(), Some(ip("104.21.0.1")));
    }

    #[tokio::test]
    async fn auto_yields_to_ipv4_when_ipv6_is_much_slower_or_dead() {
        let selector = auto_selector(state_with_key(1), by_family(20, 900), DUAL_STACK);
        selector
            .race_candidates(
                candidates(&["104.21.0.1", "2606:4700::6810:1"]),
                selector.key_pool(),
            )
            .await;
        assert_eq!(selector.winner_ip(), Some(ip("104.21.0.1")));
        assert!(selector.inner.lock().state.family_check.as_ref().unwrap().v6_ok);

        // IPv6 一个都不通：记下这个网络上 IPv6 不通，之后自动模式在这里按 IPv4 排
        let selector = auto_selector(
            state_with_key(1),
            Arc::new(|ip, _| {
                if ip.is_ipv6() {
                    outcome(ip, false, 5, Some(ProbeFailure::TcpConnect))
                } else {
                    outcome(ip, true, 30, None)
                }
            }),
            DUAL_STACK,
        );
        selector
            .race_candidates(
                candidates(&["104.21.0.1", "2606:4700::6810:1"]),
                selector.key_pool(),
            )
            .await;
        assert_eq!(selector.winner_ip(), Some(ip("104.21.0.1")));
        assert!(!selector.inner.lock().state.family_check.as_ref().unwrap().v6_ok);
        assert!(selector.v6_known_broken());
        assert!(!selector.race_family().prefer_v6);
        // 换了网络，结论不适用
        selector.inner.lock().current_sig = Some("mobile".to_string());
        assert!(selector.race_family().prefer_v6);
    }

    #[tokio::test]
    async fn race_waits_for_preferred_family_beyond_max_passes() {
        // 四个 v4 先通过（以前凑满四个就收敛，v6 根本没机会），IPv6 优先要等到 v6
        let selector = fake_selector_family(
            SelectMode::LocalAtlas,
            FamilyPref::V6,
            state_with_key(1),
            by_family(10, 80),
            Arc::new(EdgePin::new(true)),
        );
        selector.set_local_family(DUAL_STACK);
        selector
            .race_candidates(
                candidates(&[
                    "104.21.0.1",
                    "104.21.0.2",
                    "104.21.0.3",
                    "104.21.0.4",
                    "104.21.0.5",
                    "2606:4700::6810:1",
                ]),
                selector.key_pool(),
            )
            .await;
        assert_eq!(selector.winner_ip(), Some(ip("2606:4700::6810:1")));
    }

    #[tokio::test]
    async fn midsession_rerace_keeps_affinity_but_network_change_does_not() {
        let edge = Arc::new(EdgePin::new(false));
        edge.report(
            "linux.do",
            ip("104.21.0.7"),
            crate::edge_pin::Outcome::Connected {
                rtt: None,
                took_over: false,
            },
        );
        let selector = fake_selector_family(
            SelectMode::LocalAtlas,
            FamilyPref::Auto,
            state_with_key(1),
            by_family(60, 20),
            edge,
        );
        selector.set_local_family(DUAL_STACK);
        // 会话中途（赢家坏了的重赛）：沿用 IPv4 亲和，也不记结论
        selector
            .race_candidates(
                candidates(&["104.21.0.1", "2606:4700::6810:1"]),
                selector.key_pool(),
            )
            .await;
        assert_eq!(selector.winner_ip(), Some(ip("104.21.0.1")));
        assert!(selector.inner.lock().state.family_check.is_none());
        // 换网后的竞速：旧亲和不算数，按自动偏好选 IPv6
        selector.inner.lock().race_trigger = RaceTrigger::Network;
        selector
            .race_candidates(
                candidates(&["104.21.0.1", "2606:4700::6810:1"]),
                selector.key_pool(),
            )
            .await;
        assert_eq!(selector.winner_ip(), Some(ip("2606:4700::6810:1")));
    }

    #[test]
    fn family_rerace_due_rules() {
        let now = now_unix();
        let check = |v6_ok| {
            Some(FamilyCheck {
                sig: Some("wifi".to_string()),
                at: now,
                v6_ok,
            })
        };
        let selector = auto_selector(v4_winner_state(), by_family(20, 20), DUAL_STACK);
        let v4 = ip("104.21.0.1");
        // 自动：IPv4 赢家、有 IPv6、这个网络上没竞速过 → 重赛
        assert!(selector.family_rerace_due(v4));
        assert!(!selector.family_rerace_due(ip("2606:4700::1")));
        // 竞速过（不论结果）→ 24 小时内不再来
        selector.inner.lock().state.family_check = check(true);
        assert!(!selector.family_rerace_due(v4));
        selector.inner.lock().state.family_check = check(false);
        assert!(!selector.family_rerace_due(v4));
        // 结论过期或换了网络 → 再来
        selector.inner.lock().state.family_check = Some(FamilyCheck {
            sig: Some("wifi".to_string()),
            at: now - FAMILY_CHECK_TTL_SECS - 1,
            v6_ok: false,
        });
        assert!(selector.family_rerace_due(v4));
        selector.inner.lock().state.family_check = check(true);
        selector.inner.lock().current_sig = Some("mobile".to_string());
        assert!(selector.family_rerace_due(v4));
        // 没有 IPv6 路由 → 不来
        selector.set_local_family(V4_ONLY);
        assert!(!selector.family_rerace_due(v4));

        // IPv6 优先：只在那次 IPv6 不通时不再来
        let selector = fake_selector_family(
            SelectMode::LocalAtlas,
            FamilyPref::V6,
            v4_winner_state(),
            by_family(20, 20),
            Arc::new(EdgePin::new(true)),
        );
        selector.set_local_family(DUAL_STACK);
        selector.inner.lock().state.family_check = check(true);
        assert!(selector.family_rerace_due(v4));
        selector.inner.lock().state.family_check = check(false);
        assert!(!selector.family_rerace_due(v4));

        // IPv4 优先：IPv4 赢家不动；从自动切回来、赢家还是 IPv6 时换回 IPv4（本机得有 IPv4）
        let selector = fake_selector(SelectMode::LocalAtlas, v4_winner_state(), by_family(20, 20));
        selector.set_local_family(DUAL_STACK);
        assert!(!selector.family_rerace_due(v4));
        assert!(selector.family_rerace_due(ip("2606:4700::1")));
        selector.set_local_family(cfnet::FamilySupport { v4: false, v6: true });
        assert!(!selector.family_rerace_due(ip("2606:4700::1")));
    }

    #[tokio::test]
    async fn switching_back_to_ipv4_moves_an_ipv6_winner_in_background() {
        let mut state = v4_winner_state();
        state.winner.as_mut().unwrap().ip = ip("2606:4700::6810:1");
        let selector = fake_selector(SelectMode::LocalAtlas, state, by_family(60, 20));
        selector.set_local_family(DUAL_STACK);
        selector.start();
        wait_phase(&selector, Phase::Ready).await;
        wait_idle(&selector).await;
        assert!(selector.winner_ip().unwrap().is_ipv4(), "IPv4 优先：v6 再快也换回 v4");
        // IPv4 优先不记 IPv6 结论
        assert!(selector.inner.lock().state.family_check.is_none());
    }

    /// 等后台竞速（single-flight 标记）结束
    async fn wait_idle(selector: &Arc<Selector>) {
        let start = Instant::now();
        while selector.racing.load(Ordering::Acquire) && start.elapsed() < Duration::from_secs(5) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!selector.racing.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn verified_ipv4_winner_is_kept_while_auto_races_for_ipv6_in_background() {
        let selector = auto_selector(v4_winner_state(), by_family(20, 40), DUAL_STACK);
        selector.start();
        // 先照常校验旧赢家：校验中就乐观钉住它，解析不用等
        assert_eq!(selector.phase(), Phase::Verifying);
        assert_eq!(selector.winner_ip(), Some(ip("104.21.0.1")));
        wait_phase(&selector, Phase::Ready).await;
        // 后台换族竞速期间阶段不变、旧赢家一直钉着；出结果后换到 IPv6
        wait_idle(&selector).await;
        assert_eq!(selector.phase(), Phase::Ready);
        assert!(selector.winner_ip().unwrap().is_ipv6());
        assert!(selector.inner.lock().state.family_check.as_ref().unwrap().v6_ok);

        // 同一个网络上竞速过：下次启动照常校验，不再后台竞速
        let mut state = v4_winner_state();
        state.family_check = Some(FamilyCheck {
            sig: Some("wifi".to_string()),
            at: now_unix(),
            v6_ok: true,
        });
        let selector = auto_selector(state, by_family(20, 40), DUAL_STACK);
        selector.start();
        assert_eq!(selector.phase(), Phase::Verifying);
        wait_phase(&selector, Phase::Ready).await;
        wait_idle(&selector).await;
        assert_eq!(selector.winner_ip(), Some(ip("104.21.0.1")));
    }

    #[tokio::test]
    async fn background_family_race_without_winner_keeps_the_current_one() {
        // 旧赢家校验能过，其余一律不通：后台竞速一无所获，旧赢家照用，不转 Failed
        let selector = auto_selector(
            v4_winner_state(),
            Arc::new(|ip, _| {
                if ip == "104.21.0.1".parse::<IpAddr>().unwrap() {
                    outcome(ip, true, 30, None)
                } else {
                    outcome(ip, false, 5, Some(ProbeFailure::TcpConnect))
                }
            }),
            DUAL_STACK,
        );
        selector.start();
        wait_phase(&selector, Phase::Ready).await;
        wait_idle(&selector).await;
        // 粘性赢家自己也在候选里：它通过，仍是赢家；IPv6 一个都没通过，记下不通
        assert_eq!(selector.phase(), Phase::Ready);
        assert_eq!(selector.winner_ip(), Some(ip("104.21.0.1")));
        assert!(!selector.inner.lock().state.family_check.as_ref().unwrap().v6_ok);

        // 后台竞速连赢家都没通过（网络正抖）：当没发生过
        let selector = auto_selector(v4_winner_state(), by_family(20, 40), DUAL_STACK);
        selector.inner.lock().phase = Phase::Ready;
        selector.sync_pin();
        selector.inner.lock().race_trigger = RaceTrigger::Family;
        selector.race_failed("no candidate passed");
        assert_eq!(selector.phase(), Phase::Ready);
        assert_eq!(selector.winner_ip(), Some(ip("104.21.0.1")));
    }

    // ---------- 自定义节点 ----------

    const CUSTOM_A: &str = "104.18.0.9";
    const CUSTOM_B: &str = "172.67.0.9";

    /// 自定义节点用例的 selector：IPv4 优先、本机只有 IPv4（候选里不掺随机 IPv6）
    fn custom_selector(state: SelectState, custom: &[&str], f: ProbeFn) -> Arc<Selector> {
        let selector = fake_selector_custom(
            SelectMode::LocalAtlas,
            FamilyPref::V4,
            state,
            f,
            Arc::new(EdgePin::new(false)),
            Vec::new(),
            custom,
        );
        selector.set_local_family(V4_ONLY);
        selector
    }

    /// 自定义节点按 `custom_ms` 通过（None = 连不上），其余候选一律 `pool_ms` 通过
    fn custom_probe(custom: &'static [&'static str], custom_ms: Option<u64>, pool_ms: u64) -> ProbeFn {
        Arc::new(move |ip, _| {
            if custom.iter().any(|text| ip == text.parse::<IpAddr>().unwrap()) {
                match custom_ms {
                    Some(ms) => outcome(ip, true, ms, None),
                    None => outcome(ip, false, 5, Some(ProbeFailure::TcpConnect)),
                }
            } else {
                outcome(ip, true, pool_ms, None)
            }
        })
    }

    fn custom_node(selector: &Arc<Selector>, index: usize) -> serde_json::Value {
        selector.status_json()["custom"]["nodes"][index].clone()
    }

    fn winner_of(selector: &Arc<Selector>) -> Winner {
        selector.inner.lock().state.winner.clone().unwrap()
    }

    #[test]
    fn custom_nodes_parsing() {
        let raw: Vec<String> = [
            " 104.18.0.9 ",
            "104.18.0.9:443",     // 和上一条是同一个
            "172.67.0.9:443",
            "[2606:4700::1]",
            "[2606:4700::2]:443",
            "2606:4700::443",     // 以 :443 结尾的合法 IPv6
            "CF.Example.com.",
            "cf.example.com:443", // 和上一条是同一个
            "",
            "1.2.3",              // 写坏的 IP
            "300.1.1.1",
            "104.18.0.9:8443",    // 别的端口用不上
            "http://cf.example.com",
            "localhost",
            "-bad.example.com",
        ]
        .iter()
        .map(|text| text.to_string())
        .collect();
        let nodes = CustomNodes::parse(&raw);
        let entries: Vec<CustomEntry> = nodes.entries.iter().map(|(_, entry)| entry.clone()).collect();
        assert_eq!(
            entries,
            vec![
                CustomEntry::Ip(ip("104.18.0.9")),
                CustomEntry::Ip(ip("172.67.0.9")),
                CustomEntry::Ip(ip("2606:4700::1")),
                CustomEntry::Ip(ip("2606:4700::2")),
                CustomEntry::Ip(ip("2606:4700::443")),
                CustomEntry::Domain("cf.example.com".to_string()),
            ]
        );
        assert_eq!(
            nodes.invalid,
            vec![
                "1.2.3",
                "300.1.1.1",
                "104.18.0.9:8443",
                "http://cf.example.com",
                "localhost",
                "-bad.example.com"
            ]
        );
        // 指纹跟着清单和 IP 协议偏好变
        assert_ne!(nodes.fingerprint(FamilyPref::V4), nodes.fingerprint(FamilyPref::Auto));
        assert_ne!(
            nodes.fingerprint(FamilyPref::V4),
            CustomNodes::parse(&raw[..1]).fingerprint(FamilyPref::V4)
        );
        // 清单最多收 CUSTOM_MAX_ENTRIES 条
        let many: Vec<String> = (1..=20).map(|n| format!("104.18.0.{}", n)).collect();
        assert_eq!(CustomNodes::parse(&many).entries.len(), CUSTOM_MAX_ENTRIES);
        assert!(CustomNodes::parse(&[]).is_empty());
    }

    #[test]
    fn interleave_keeps_custom_nodes_in_front() {
        let list = vec![
            Candidate { ip: ip("104.21.0.1"), source: CandidateSource::Sticky },
            Candidate { ip: ip(CUSTOM_A), source: CandidateSource::Custom },
            Candidate { ip: ip(CUSTOM_B), source: CandidateSource::Custom },
            Candidate { ip: ip("104.21.0.2"), source: CandidateSource::Atlas },
            Candidate { ip: ip("2606:4700::7"), source: CandidateSource::Random },
        ];
        let out: Vec<IpAddr> = interleave_families(list, true).into_iter().map(|c| c.ip).collect();
        assert_eq!(
            out,
            vec![
                ip("104.21.0.1"),
                ip(CUSTOM_A),
                ip(CUSTOM_B),
                ip("2606:4700::7"),
                ip("104.21.0.2")
            ]
        );
    }

    #[tokio::test]
    async fn custom_node_wins_over_faster_pool_candidates() {
        // 自定义节点 300 ms、池里的 20 ms：照样用自定义的
        let selector = custom_selector(
            state_with_key(1),
            &[CUSTOM_A],
            custom_probe(&[CUSTOM_A], Some(300), 20),
        );
        selector.start();
        wait_phase(&selector, Phase::Ready).await;
        let winner = winner_of(&selector);
        assert_eq!(winner.ip, ip(CUSTOM_A));
        assert_eq!(winner.source, CandidateSource::Custom);
        assert_eq!(selector.winner_ip(), Some(ip(CUSTOM_A)));
        let node = custom_node(&selector, 0);
        assert_eq!(node["entry"], CUSTOM_A);
        assert_eq!(node["state"], "ok");
        assert_eq!(node["active"], true);
        assert_eq!(node["latency_ms"], 300);
        let check = selector.inner.lock().state.custom_check.clone().unwrap();
        assert!(check.ok);
        assert_eq!(check.sig.as_deref(), Some("wifi"));
        assert_eq!(selector.inner.lock().state.custom_entry.as_deref(), Some(CUSTOM_A));
        // 赢家是自定义节点：不把这一轮当成 IPv6 结论，也不为换族再折腾
        assert!(selector.inner.lock().state.family_check.is_none());
        assert!(!selector.family_rerace_due(ip(CUSTOM_A)));
        assert!(!selector.custom_rerace_due());
    }

    #[tokio::test]
    async fn race_waits_for_custom_nodes_before_converging() {
        // 池里先出了 5 个通过（够数了），自定义节点排在最后才出结果：不能提前收敛
        let pool = ["104.21.0.1", "104.21.0.2", "104.21.0.3", "104.21.0.4", "104.21.0.5"];
        let order = || {
            let mut list = candidates(&pool);
            list.push(Candidate { ip: ip(CUSTOM_A), source: CandidateSource::Custom });
            list
        };
        let selector = custom_selector(
            state_with_key(1),
            &[CUSTOM_A],
            custom_probe(&[CUSTOM_A], Some(300), 20),
        );
        selector.race_candidates(order(), selector.key_pool()).await;
        assert_eq!(winner_of(&selector).ip, ip(CUSTOM_A));

        // 这个网络上一小时内刚验过自定义节点都不通：不等它们，池里够数就收
        let mut state = state_with_key(1);
        state.custom_check = Some(CustomCheck {
            list: format!("v4|{}", CUSTOM_A),
            sig: Some("wifi".to_string()),
            at: now_unix(),
            ok: false,
            results: Vec::new(),
        });
        let selector = custom_selector(state.clone(), &[CUSTOM_A], custom_probe(&[CUSTOM_A], Some(300), 20));
        assert!(!selector.custom_worth_waiting());
        selector.race_candidates(order(), selector.key_pool()).await;
        assert_ne!(winner_of(&selector).ip, ip(CUSTOM_A));

        // 手动重新优选总是等
        let selector = custom_selector(state, &[CUSTOM_A], custom_probe(&[CUSTOM_A], Some(300), 20));
        selector.inner.lock().race_trigger = RaceTrigger::Manual;
        selector.race_candidates(order(), selector.key_pool()).await;
        assert_eq!(winner_of(&selector).ip, ip(CUSTOM_A));
    }

    #[tokio::test]
    async fn fastest_custom_node_wins_among_several() {
        let selector = custom_selector(
            state_with_key(1),
            &[CUSTOM_A, CUSTOM_B],
            Arc::new(|ip, _| match ip.to_string().as_str() {
                CUSTOM_A => outcome(ip, true, 180, None),
                CUSTOM_B => outcome(ip, true, 90, None),
                _ => outcome(ip, true, 20, None),
            }),
        );
        selector.start();
        wait_phase(&selector, Phase::Ready).await;
        assert_eq!(winner_of(&selector).ip, ip(CUSTOM_B));
        assert_eq!(custom_node(&selector, 0)["active"], false);
        assert_eq!(custom_node(&selector, 0)["latency_ms"], 180);
        assert_eq!(custom_node(&selector, 1)["active"], true);
        // 自定义节点的测量不分享：只有它们通过算不上「够报」
        let selector = custom_selector(
            state_with_key(1),
            &[CUSTOM_A, CUSTOM_B],
            Arc::new(|ip, _| match ip.to_string().as_str() {
                CUSTOM_A | CUSTOM_B => outcome(ip, true, 90, None),
                _ => outcome(ip, false, 5, Some(ProbeFailure::TcpConnect)),
            }),
        );
        selector.start();
        wait_phase(&selector, Phase::Ready).await;
        assert!(!selector.inner.lock().report_pending);
    }

    #[tokio::test]
    async fn failing_custom_nodes_fall_back_to_the_pool() {
        let selector = custom_selector(
            state_with_key(1),
            &[CUSTOM_A],
            custom_probe(&[CUSTOM_A], None, 20),
        );
        selector.start();
        wait_phase(&selector, Phase::Ready).await;
        let winner = winner_of(&selector);
        assert_ne!(winner.ip, ip(CUSTOM_A));
        assert_ne!(winner.source, CandidateSource::Custom);
        let node = custom_node(&selector, 0);
        assert_eq!(node["state"], "failed");
        assert_eq!(node["detail"], "tcp_connect_failed");
        assert_eq!(node["active"], false);
        let check = selector.inner.lock().state.custom_check.clone().unwrap();
        assert!(!check.ok);
        // 这个网络上刚验过不通：一小时内不为它们再后台竞速
        assert!(!selector.custom_rerace_due());
        selector.inner.lock().state.custom_check.as_mut().unwrap().at = now_unix() - CUSTOM_RETRY_SECS - 1;
        assert!(selector.custom_rerace_due());
        // 换了网络也重试
        selector.inner.lock().state.custom_check.as_mut().unwrap().at = now_unix();
        selector.inner.lock().current_sig = Some("cellular".to_string());
        assert!(selector.custom_rerace_due());
    }

    #[tokio::test]
    async fn custom_nodes_outside_cloudflare_are_never_probed() {
        let probed: Arc<Mutex<Vec<IpAddr>>> = Arc::new(Mutex::new(Vec::new()));
        let log = probed.clone();
        let selector = custom_selector(
            state_with_key(1),
            &["1.2.3.4", "104.16.0.9", "2606:4700::9", "bad entry"],
            Arc::new(move |ip, _| {
                log.lock().push(ip);
                outcome(ip, true, 20, None)
            }),
        );
        // 只有网段外的地址时，不值得为它们后台竞速
        assert!(custom_selector(state_with_key(1), &["1.2.3.4"], by_family(20, 20)).custom.cloudflare_ips().next().is_none());
        assert!(!custom_selector(state_with_key(1), &["1.2.3.4"], by_family(20, 20)).custom_rerace_due());
        selector.start();
        wait_phase(&selector, Phase::Ready).await;
        assert!(!probed.lock().contains(&ip("1.2.3.4")));
        assert!(!probed.lock().contains(&ip("2606:4700::9")));
        // Cloudflare 自家资产段的地址池里不要，用户点名的照探
        assert_eq!(winner_of(&selector).ip, ip("104.16.0.9"));
        assert_eq!(custom_node(&selector, 0)["state"], "not_cloudflare");
        assert_eq!(custom_node(&selector, 1)["state"], "ok");
        // 本机只有 IPv4：IPv6 节点这一轮用不上
        assert_eq!(custom_node(&selector, 2)["state"], "no_family");
        assert_eq!(custom_node(&selector, 3)["state"], "invalid");
        assert_eq!(custom_node(&selector, 3)["entry"], "bad entry");
    }

    #[tokio::test]
    async fn verified_pool_winner_yields_to_custom_node_in_background() {
        // 上次的赢家是池里的；这次启动配了自定义节点：先照常校验旧赢家（不让冷启动多等），
        // 再后台竞速换到自定义节点
        let selector = custom_selector(
            v4_winner_state(),
            &[CUSTOM_A],
            custom_probe(&[CUSTOM_A], Some(300), 20),
        );
        selector.start();
        assert_eq!(selector.phase(), Phase::Verifying);
        assert_eq!(selector.winner_ip(), Some(ip("104.21.0.1")));
        wait_phase(&selector, Phase::Ready).await;
        wait_idle(&selector).await;
        assert_eq!(selector.phase(), Phase::Ready);
        assert_eq!(selector.winner_ip(), Some(ip(CUSTOM_A)));
        let state = selector.inner.lock().state.clone();
        assert_eq!(state.races_log.len(), 1);

        // 下次启动：赢家已经是自定义节点，校验通过就完事，不再竞速
        // （自动 + 双栈下赢家是 IPv4 也不为换族折腾）
        let selector = fake_selector_custom(
            SelectMode::LocalAtlas,
            FamilyPref::Auto,
            SelectState {
                custom_check: Some(CustomCheck {
                    list: format!("auto|{}", CUSTOM_A),
                    ..state.custom_check.clone().unwrap()
                }),
                ..state
            },
            custom_probe(&[CUSTOM_A], Some(300), 20),
            Arc::new(EdgePin::new(false)),
            Vec::new(),
            &[CUSTOM_A],
        );
        selector.set_local_family(DUAL_STACK);
        selector.start();
        assert_eq!(selector.phase(), Phase::Verifying);
        wait_phase(&selector, Phase::Ready).await;
        wait_idle(&selector).await;
        assert_eq!(selector.winner_ip(), Some(ip(CUSTOM_A)));
        assert_eq!(selector.inner.lock().state.races_log.len(), 1);
        assert_eq!(custom_node(&selector, 0)["active"], true);
    }

    #[tokio::test]
    async fn background_custom_race_keeps_the_winner_when_custom_nodes_fail() {
        // 自定义节点不通、池里别的地址比现在的赢家还快：后台这一轮不换赢家，只记下不通
        let selector = custom_selector(
            v4_winner_state(),
            &[CUSTOM_A],
            Arc::new(|ip, _| match ip.to_string().as_str() {
                CUSTOM_A => outcome(ip, false, 5, Some(ProbeFailure::TcpTimeout)),
                "104.21.0.1" => outcome(ip, true, 200, None),
                _ => outcome(ip, true, 20, None),
            }),
        );
        selector.start();
        wait_phase(&selector, Phase::Ready).await;
        wait_idle(&selector).await;
        assert_eq!(selector.phase(), Phase::Ready);
        assert_eq!(selector.winner_ip(), Some(ip("104.21.0.1")));
        let state = selector.inner.lock().state.clone();
        assert_eq!(state.races_log.len(), 1);
        assert!(!state.custom_check.as_ref().unwrap().ok);
        assert_eq!(custom_node(&selector, 0)["state"], "failed");
        assert_eq!(custom_node(&selector, 0)["detail"], "tcp_timeout");

        // 同一个网络上再启动：一小时内不再为它们后台竞速
        let selector = custom_selector(state, &[CUSTOM_A], custom_probe(&[CUSTOM_A], None, 20));
        selector.start();
        wait_phase(&selector, Phase::Ready).await;
        wait_idle(&selector).await;
        assert_eq!(selector.inner.lock().state.races_log.len(), 1);
    }

    #[tokio::test]
    async fn custom_winner_knocked_out_by_traffic_is_benched() {
        let selector = custom_selector(
            state_with_key(1),
            &[CUSTOM_A],
            custom_probe(&[CUSTOM_A], Some(60), 20),
        );
        selector.start();
        wait_phase(&selector, Phase::Ready).await;
        assert_eq!(selector.winner_ip(), Some(ip(CUSTOM_A)));
        // 探测能过、实际连接连不上：连败到阈值被换掉
        selector.inner.lock().state.last_race_at = 0;
        for _ in 0..WINNER_FAIL_THRESHOLD {
            selector
                .edge
                .report("linux.do", ip(CUSTOM_A), crate::edge_pin::Outcome::Failed);
        }
        wait_idle(&selector).await;
        wait_phase(&selector, Phase::Ready).await;
        // 重赛里它不再进候选（否则探测一过又选回来）
        let winner = winner_of(&selector);
        assert_ne!(winner.ip, ip(CUSTOM_A));
        assert_eq!(selector.inner.lock().state.custom_demoted.len(), 1);
        assert!(selector.inner.lock().state.custom_entry.is_none());
        assert_eq!(custom_node(&selector, 0)["state"], "demoted");
        assert!(!selector.custom_rerace_due());
        // 降级记录跟着状态落盘：下次启动校验完池里的赢家，也不为它后台竞速
        let state = selector.inner.lock().state.clone();
        let restarted = custom_selector(state.clone(), &[CUSTOM_A], custom_probe(&[CUSTOM_A], Some(60), 20));
        restarted.start();
        wait_phase(&restarted, Phase::Ready).await;
        wait_idle(&restarted).await;
        assert_eq!(restarted.winner_ip(), Some(winner.ip));
        // 过了降级期再启动：重新给它机会
        let mut later = state;
        later.custom_demoted[0].at = now_unix() - CUSTOM_RETRY_SECS - 1;
        later.custom_check.as_mut().unwrap().at = now_unix() - CUSTOM_RETRY_SECS - 1;
        let restarted = custom_selector(later, &[CUSTOM_A], custom_probe(&[CUSTOM_A], Some(60), 20));
        restarted.start();
        wait_phase(&restarted, Phase::Ready).await;
        wait_idle(&restarted).await;
        assert_eq!(restarted.winner_ip(), Some(ip(CUSTOM_A)));

        // 手动重新优选：立刻重新给机会
        assert!(selector.request_rerace(true));
        wait_idle(&selector).await;
        wait_phase(&selector, Phase::Ready).await;
        assert_eq!(selector.winner_ip(), Some(ip(CUSTOM_A)));
        assert!(selector.inner.lock().state.custom_demoted.is_empty());
    }

    #[tokio::test]
    async fn removed_custom_winner_is_not_used_again() {
        let custom_winner_state = || {
            let mut state = state_with_key(1);
            state.winner = Some(Winner {
                ip: ip(CUSTOM_A),
                latency_ms: 60,
                verified_at: 1,
                source: CandidateSource::Custom,
                ech_source: EchKeySource::Persisted,
            });
            state.network_sig = Some("wifi".to_string());
            state.custom_check = Some(CustomCheck {
                list: format!("v4|{}", CUSTOM_A),
                sig: Some("wifi".to_string()),
                at: now_unix(),
                ok: true,
                results: Vec::new(),
            });
            state
        };
        let probed: Arc<Mutex<Vec<IpAddr>>> = Arc::new(Mutex::new(Vec::new()));
        let recording = |probed: &Arc<Mutex<Vec<IpAddr>>>| -> ProbeFn {
            let log = probed.clone();
            Arc::new(move |ip, _| {
                log.lock().push(ip);
                outcome(ip, true, 20, None)
            })
        };
        // 清单清空了：不校验、不再用它，直接按平常的规则优选
        let selector = custom_selector(custom_winner_state(), &[], recording(&probed));
        selector.start();
        assert_eq!(selector.phase(), Phase::Racing);
        wait_phase(&selector, Phase::Ready).await;
        assert!(!probed.lock().contains(&ip(CUSTOM_A)));
        assert_ne!(winner_of(&selector).source, CandidateSource::Custom);
        assert!(selector.inner.lock().state.custom_check.is_none());
        assert!(selector.status_json()["custom"].is_null());

        // 清单换成了另一个节点：换过去
        probed.lock().clear();
        let selector = custom_selector(custom_winner_state(), &[CUSTOM_B], recording(&probed));
        selector.start();
        wait_phase(&selector, Phase::Ready).await;
        assert!(!probed.lock().contains(&ip(CUSTOM_A)));
        assert_eq!(selector.winner_ip(), Some(ip(CUSTOM_B)));

        // 清单里添了一个节点（原来的还在）：先照常用着原来的，后台重新比一轮
        let selector = custom_selector(
            custom_winner_state(),
            &[CUSTOM_A, CUSTOM_B],
            Arc::new(|ip, _| match ip.to_string().as_str() {
                CUSTOM_A => outcome(ip, true, 60, None),
                CUSTOM_B => outcome(ip, true, 30, None),
                _ => outcome(ip, true, 10, None),
            }),
        );
        selector.start();
        assert_eq!(selector.phase(), Phase::Verifying);
        assert_eq!(selector.winner_ip(), Some(ip(CUSTOM_A)));
        wait_phase(&selector, Phase::Ready).await;
        wait_idle(&selector).await;
        assert_eq!(selector.winner_ip(), Some(ip(CUSTOM_B)));
    }

    #[tokio::test]
    async fn ip_family_change_reraces_among_custom_nodes() {
        // 自动模式下选了 IPv6 的自定义节点；改成 IPv4 优先后重启：后台在自定义节点里重挑
        const CUSTOM_V6: &str = "2606:4700::9";
        let mut state = state_with_key(1);
        state.winner = Some(Winner {
            ip: ip(CUSTOM_V6),
            latency_ms: 60,
            verified_at: 1,
            source: CandidateSource::Custom,
            ech_source: EchKeySource::Persisted,
        });
        state.network_sig = Some("wifi".to_string());
        state.custom_check = Some(CustomCheck {
            list: format!("auto|{},{}", CUSTOM_A, CUSTOM_V6),
            sig: Some("wifi".to_string()),
            at: now_unix(),
            ok: true,
            results: Vec::new(),
        });
        let selector = fake_selector_custom(
            SelectMode::LocalAtlas,
            FamilyPref::V4,
            state,
            by_family(80, 40),
            Arc::new(EdgePin::new(false)),
            Vec::new(),
            &[CUSTOM_A, CUSTOM_V6],
        );
        selector.set_local_family(DUAL_STACK);
        selector.start();
        assert_eq!(selector.winner_ip(), Some(ip(CUSTOM_V6)));
        wait_phase(&selector, Phase::Ready).await;
        wait_idle(&selector).await;
        assert_eq!(selector.winner_ip(), Some(ip(CUSTOM_A)));
        assert_eq!(winner_of(&selector).source, CandidateSource::Custom);
    }

    #[tokio::test]
    async fn custom_domain_is_resolved_and_preferred() {
        // 假 DoH 对任何域名都答这两个地址；其中一个在 Cloudflare 自家资产段
        let doh = fake_public_doh("fake", &["104.18.7.7", "104.16.5.5"]).await;
        let selector = fake_selector_custom(
            SelectMode::AtlasOnly,
            FamilyPref::V4,
            state_with_key(1),
            Arc::new(|ip, _| match ip.to_string().as_str() {
                "104.18.7.7" => outcome(ip, true, 120, None),
                "104.16.5.5" => outcome(ip, true, 70, None),
                _ => outcome(ip, true, 10, None),
            }),
            Arc::new(EdgePin::new(false)),
            vec![doh],
            &["cf.example.com", "nx.example.com:8443"],
        );
        selector.set_local_family(V4_ONLY);
        selector.start();
        wait_phase(&selector, Phase::Ready).await;
        // 「只用 atlas 池」模式下自定义节点照样参与；域名解析出的地址里挑最快的
        let winner = winner_of(&selector);
        assert_eq!(winner.ip, ip("104.16.5.5"));
        assert_eq!(winner.source, CandidateSource::Custom);
        let node = custom_node(&selector, 0);
        assert_eq!(node["entry"], "cf.example.com");
        assert_eq!(node["state"], "ok");
        assert_eq!(node["ip"], "104.16.5.5");
        assert_eq!(node["active"], true);
        assert_eq!(custom_node(&selector, 1)["state"], "invalid");
        // 赢家出自域名这一条：这一条还在，启动时照常校验
        let state = selector.inner.lock().state.clone();
        assert_eq!(state.custom_entry.as_deref(), Some("cf.example.com"));
        let restarted = fake_selector_custom(
            SelectMode::AtlasOnly,
            FamilyPref::V4,
            state,
            by_family(20, 20),
            Arc::new(EdgePin::new(false)),
            Vec::new(),
            &["cf.example.com", "nx.example.com:8443"],
        );
        restarted.set_local_family(V4_ONLY);
        restarted.start();
        assert_eq!(restarted.phase(), Phase::Verifying);
        assert_eq!(restarted.winner_ip(), Some(ip("104.16.5.5")));
        wait_phase(&restarted, Phase::Ready).await;
        wait_idle(&restarted).await;
        // 这个 selector 没有公共 DoH，域名解析不出来（DNS 一时没答上）：重新竞速时
        // 正用着的节点仍算这个域名的，不因此丢掉
        assert!(restarted.request_rerace(true));
        wait_idle(&restarted).await;
        wait_phase(&restarted, Phase::Ready).await;
        let winner = winner_of(&restarted);
        assert_eq!(winner.ip, ip("104.16.5.5"));
        assert_eq!(winner.source, CandidateSource::Custom);
        let node = custom_node(&restarted, 0);
        assert_eq!(node["state"], "ok");
        assert_eq!(node["active"], true);

        // 换成另一个域名（同样解析不出来）：原来的节点不是它的，不留
        let state = restarted.inner.lock().state.clone();
        let probed: Arc<Mutex<Vec<IpAddr>>> = Arc::new(Mutex::new(Vec::new()));
        let log = probed.clone();
        let swapped = fake_selector_custom(
            SelectMode::AtlasOnly,
            FamilyPref::V4,
            state,
            Arc::new(move |ip, _| {
                log.lock().push(ip);
                outcome(ip, true, 20, None)
            }),
            Arc::new(EdgePin::new(false)),
            Vec::new(),
            &["other.example.com"],
        );
        swapped.set_local_family(V4_ONLY);
        swapped.start();
        // 出处那一条不在清单里了：不校验、直接竞速；这个模式下又没有 atlas，没有候选
        assert_eq!(swapped.phase(), Phase::Racing);
        wait_phase(&swapped, Phase::Failed).await;
        assert!(probed.lock().is_empty());
        assert!(swapped.inner.lock().state.custom_entry.is_none());
        assert_eq!(custom_node(&swapped, 0)["state"], "pending");
    }

    #[tokio::test]
    async fn removing_the_literal_node_in_use_drops_it_even_with_domains_listed() {
        // 正用着字面 IP 那一条；把它从清单里拿掉，清单里还剩一个域名
        let mut state = state_with_key(1);
        state.winner = Some(Winner {
            ip: ip(CUSTOM_A),
            latency_ms: 60,
            verified_at: 1,
            source: CandidateSource::Custom,
            ech_source: EchKeySource::Persisted,
        });
        state.network_sig = Some("wifi".to_string());
        state.custom_entry = Some(CUSTOM_A.to_string());
        let probed: Arc<Mutex<Vec<IpAddr>>> = Arc::new(Mutex::new(Vec::new()));
        let log = probed.clone();
        let selector = custom_selector(
            state,
            &["cf.example.com"],
            Arc::new(move |ip, _| {
                log.lock().push(ip);
                outcome(ip, true, 20, None)
            }),
        );
        selector.start();
        assert_eq!(selector.phase(), Phase::Racing);
        wait_phase(&selector, Phase::Ready).await;
        // 域名这一轮没解析出来，也不把拿掉的节点算到它头上
        assert!(!probed.lock().contains(&ip(CUSTOM_A)));
        assert_ne!(winner_of(&selector).source, CandidateSource::Custom);
        assert!(selector.inner.lock().state.custom_entry.is_none());
        assert_eq!(custom_node(&selector, 0)["state"], "unresolved");
    }

    #[tokio::test]
    async fn unresolved_custom_domain_is_reported() {
        // 没有公共 DoH 可用：域名解析不出来，按平常的规则优选
        let selector = custom_selector(
            state_with_key(1),
            &["cf.example.com"],
            by_family(20, 20),
        );
        selector.start();
        wait_phase(&selector, Phase::Ready).await;
        assert_ne!(winner_of(&selector).source, CandidateSource::Custom);
        assert_eq!(custom_node(&selector, 0)["state"], "unresolved");
        assert!(!selector.inner.lock().state.custom_check.as_ref().unwrap().ok);
    }

    #[tokio::test]
    async fn custom_nodes_without_an_outcome_are_timeouts_only_when_the_race_ran_out() {
        let selector = custom_selector(
            state_with_key(1),
            &[CUSTOM_A, CUSTOM_B],
            custom_probe(&[CUSTOM_A], Some(60), 20),
        );
        // 收集候选时记下每条对应的地址
        let _ = selector.gather().await;
        let only_a = [outcome(ip(CUSTOM_A), true, 60, None)];
        // 提前收敛：B 只是没等它
        let early = selector.custom_results(&only_a, false);
        assert_eq!(early[0].state, CustomState::Ok);
        assert_eq!(early[1].state, CustomState::Pending);
        // 跑满总时限：B 到最后都没出结果，按超时算
        let late = selector.custom_results(&only_a, true);
        assert_eq!(late[0].state, CustomState::Ok);
        assert_eq!(late[1].state, CustomState::Failed);
        assert_eq!(late[1].detail.as_deref(), Some("timeout"));
        assert_eq!(late[1].ip, Some(ip(CUSTOM_B)));
    }

    #[test]
    fn custom_state_survives_the_state_json_roundtrip() {
        let mut state = state_with_key(1);
        state.custom_check = Some(CustomCheck {
            list: format!("v4|{}", CUSTOM_A),
            sig: Some("wifi".to_string()),
            at: 123,
            ok: true,
            results: vec![CustomResult {
                entry: CUSTOM_A.to_string(),
                state: CustomState::Ok,
                ip: Some(ip(CUSTOM_A)),
                latency_ms: Some(88),
                detail: None,
            }],
        });
        state.custom_demoted = vec![CustomDemotion { ip: ip(CUSTOM_B), at: 456 }];
        let json = serde_json::to_string(&state).unwrap();
        let back = SelectState::from_json(&json).unwrap();
        assert_eq!(back.custom_check, state.custom_check);
        assert_eq!(back.custom_demoted, state.custom_demoted);
        // 旧版落盘的状态没有这两项：照常读回
        let old = SelectState::from_json(r#"{"v":1,"ech_keys":[]}"#).unwrap();
        assert!(old.custom_check.is_none() && old.custom_demoted.is_empty());
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
            FamilyPref::Auto,
            Some("https://atlas.1molchuan.top/v1/routes"),
            None,
            Some("test"),
        );
        selector.run_race().await;
        println!("{}", selector.status_json());
        assert_eq!(selector.phase(), Phase::Ready);
    }
}
