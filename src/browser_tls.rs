//! 浏览器 TLS 指纹出口：上游握手按本机 WebView 的 ClientHello 复刻（BoringSSL，经 rama）。
//!
//! 移植自上游 Lingyan000/fluxdo（GPL-3.0）eac274bd 的 `core/net_core/src/browser_tls.rs`
//! 与 `mirror.rs` 的模板部分。上游用 rama 的 MITM 中继整条镜像 WebView 连接；这里入站 TLS
//! 仍由 rustls 终结，只在接受前窥探 WebView 发来的 ClientHello 存作模板，出站（Dart 网关道与
//! WebView 的 h2 MITM 道）都按模板回放。选址赛跑、地址族亲和、ECH 钥匙沿用原来的逻辑。
//!
//! - 套件默认逐个照抄参考握手；注入真 ECH 时改用 BoringSSL 标准接口，按参考握手的 TLS 1.2
//!   套件顺序写成标准套件名（内层由 BoringSSL 原版逻辑只写 TLS 1.3 套件，与真 Chrome 一致）。
//! - Chromium 系每条连接重新打乱扩展顺序、重新生成 GREASE；注入真 ECH 时请求 server padding。
//! - 证书按内置的 Mozilla 根证书校验，与原来的 rustls 路径一致（不依赖系统 / JNI）。
//! - 还没采到真实握手时按 UA 里 Chrome 大版本最接近的预置模板回放（见 `presets/`）。

use std::io::{self, Read, Write};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};
use rama_core::error::BoxError;
use rama_net::address::Host;
use rama_tls::client::{
    parse_client_hello_handshake, parse_client_hello_handshake_prefix, ClientHello,
    ClientHelloExtension, ClientHelloHandshakePrefix, ECHClientHello, TlsClientConfig,
};
use rama_tls::{is_grease_u16, CipherSuite, ExtensionId};
use rama_tls_boring::client::{
    BoringClientConfigExt as _, TlsClientSessionCache, TlsClientSessionDomain,
    TlsClientSessionStore, TlsConnectorContextBuilder, TlsConnectorData,
};
use rama_tls_boring::core::ssl::{HandshakeError, SslCipher, SslRef, UnknownValues};
use rama_tls_boring::core::tokio::{SslStream, SslStreamBuilder};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::{debug, info, warn};

use crate::fetch_shape::FetchShape;
use crate::upstream_pool::H2Profile;
use crate::BoxStream;

/// 握手后的上游连接
pub type BrowserStream = SslStream<BoxStream>;

/// ALPS 新旧两个码点，只有 Chromium 系发送
const ALPS_CODEPOINTS: [u16; 2] = [0x44cd, 0x4469];
/// Chrome 启用真 ECH 时一并请求服务端填充（server padding request）
const SERVER_PADDING_REQUEST: u16 = 0x12e0;
/// 模板写盘的最小间隔（首次齐全时立即写）
const PERSIST_INTERVAL: Duration = Duration::from_secs(60);
/// 窥探 ClientHello 时最多读多少字节（一个 TLS 记录的上限再加头）
const PEEK_LIMIT: usize = 16 * 1024 + 5;

// ---------------------------------------------------------------------------
// 模板
// ---------------------------------------------------------------------------

/// 模板从哪来：运行期采样 / 上次落盘 / 内置预置
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TemplateSource {
    #[default]
    Sampled,
    Cached,
    Builtin(&'static str),
}

impl TemplateSource {
    pub fn name(self) -> &'static str {
        match self {
            Self::Sampled => "sampled",
            Self::Cached => "cached",
            Self::Builtin(_) => "builtin",
        }
    }
}

/// 一份可回放的 WebView 指纹
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintTemplate {
    /// TLS ClientHello
    pub hello: ClientHello,
    /// HTTP/2 初始 SETTINGS 与连接窗口（采自 WebView 的 h2 连接前言，或预置）
    #[serde(default)]
    pub h2: Option<H2Profile>,
    /// WebView fetch 请求（`sec-fetch-mode: cors`）的头名顺序，小写：没有同一组头名的采样时
    /// 网关道的请求照这个排（最近一次采样，或预置）
    #[serde(default)]
    pub fetch_header_order: Vec<String>,
    /// 采到的 WebView fetch 头顺序，每组头名集合一份，新的在前（见 [`crate::fetch_shape`]）
    #[serde(default)]
    pub fetch_header_orders: Vec<Vec<String>>,
    /// WebView fetch 请求的 Accept-Encoding
    #[serde(default)]
    pub accept_encoding: Option<String>,
    /// 采样时 WebView 的 User-Agent（WebView 升级后 UA 变化，缓存随之作废）
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(skip)]
    pub source: TemplateSource,
    /// 模板版本：握手特征变化时递增，连接池据此淘汰旧指纹的连接
    #[serde(skip)]
    pub generation: u64,
}

/// 有没有要看这一条连接的扩展：padding（ClientHello 长度落在 256~511 字节才补）、
/// pre_shared_key 与 early_data（恢复会话才带）。这几个 BoringSSL 都是自己按连接写的
const PER_CONNECTION_EXTENSIONS: [u16; 3] = [21, 41, 42];

/// 连接身份只比较稳定的浏览器能力：SNI、ECH 密文、会话票据、key share 公钥和 GREASE 值
/// 每条连接都不一样，不代表浏览器升级（上游 mirror.rs 的 profile_hash）。按连接才有的扩展
/// 也不算：不然 WebView 的连接一会儿带 padding 一会儿不带，代数来回跳，池里的连接跟着作废
fn profile_hash(hello: &ClientHello) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut extensions: Vec<_> = hello
        .extensions()
        .iter()
        .filter_map(|ext| {
            if ext.id().is_grease() || PER_CONNECTION_EXTENSIONS.contains(&u16::from(ext.id())) {
                return None;
            }
            let mut ext = ext.clone();
            match &mut ext {
                ClientHelloExtension::ServerName(name) => *name = None,
                ClientHelloExtension::EncryptedClientHello(ech) => *ech = ECHClientHello::Inner,
                ClientHelloExtension::SupportedGroups(values) => values.retain(|v| !v.is_grease()),
                ClientHelloExtension::SupportedVersions(values) => {
                    values.retain(|v| !v.is_grease())
                }
                ClientHelloExtension::SignatureAlgorithms(values) => {
                    values.retain(|v| !v.is_grease())
                }
                ClientHelloExtension::Opaque { id, data } => match u16::from(*id) {
                    51 => {
                        // key_share：只留组别和公钥长度
                        let mut groups = Vec::new();
                        let mut offset = 2;
                        while offset + 4 <= data.len() {
                            let group = u16::from_be_bytes([data[offset], data[offset + 1]]);
                            let len =
                                u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
                            if offset + 4 + len > data.len() {
                                break;
                            }
                            if !is_grease_u16(group) {
                                groups.extend_from_slice(&data[offset..offset + 4]);
                            }
                            offset += 4 + len;
                        }
                        *data = groups;
                    }
                    21 | 35 | 41 | 44 => data.clear(),
                    _ => {}
                },
                _ => {}
            }
            Some(ext)
        })
        .collect();
    if is_chromium(hello) {
        // Chromium 本来就逐连接打乱扩展顺序，出口也开了同一策略
        extensions.sort_by_key(|ext| u16::from(ext.id()));
    }
    let profile = ClientHello::new(
        hello.protocol_version(),
        hello
            .cipher_suites()
            .iter()
            .filter(|v| !v.is_grease())
            .copied()
            .collect(),
        hello.compression_algorithms().to_vec(),
        extensions,
    );
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    profile.hash(&mut hasher);
    hasher.finish()
}

/// 预置：只留安卓两档，按 UA 里的 Chrome 大版本挑最接近的
struct Preset {
    id: &'static str,
    major: u16,
    json: &'static str,
}

static PRESETS: &[Preset] = &[
    Preset {
        id: "android-webview133",
        major: 133,
        json: include_str!("../presets/android-webview133.json"),
    },
    Preset {
        id: "android-chrome149",
        major: 149,
        json: include_str!("../presets/android-chrome149.json"),
    },
];

fn chrome_major(ua: &str) -> Option<u16> {
    ua.split_once("Chrome/")?
        .1
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

/// 上游预置的 JSON：hello + HTTP/2 早期帧（rama 的 EarlyFrameCapture 序列化）
fn parse_preset(preset: &Preset) -> Option<FingerprintTemplate> {
    let value: serde_json::Value = serde_json::from_str(preset.json).ok()?;
    let hello: ClientHello = serde_json::from_value(value.get("hello")?.clone()).ok()?;
    let h2 = value
        .get("early_frames")
        .and_then(|frames| frames.as_array())
        .map(|frames| h2_profile_from_early_frames(frames));
    let fetch_header_order = value
        .get("fetch_header_order")
        .and_then(|order| serde_json::from_value(order.clone()).ok())
        .unwrap_or_default();
    let accept_encoding = value
        .get("accept_encoding")
        .and_then(|value| value.as_str())
        .map(str::to_owned);
    Some(FingerprintTemplate {
        hello,
        h2,
        fetch_header_order,
        fetch_header_orders: Vec::new(),
        accept_encoding,
        user_agent: None,
        source: TemplateSource::Builtin(preset.id),
        generation: 0,
    })
}

fn h2_profile_from_early_frames(frames: &[serde_json::Value]) -> H2Profile {
    let mut profile = H2Profile::default();
    for frame in frames {
        if let Some(settings) = frame.get("Settings").and_then(|s| s.get("config")) {
            let order: Vec<u16> = settings
                .get("setting_order")
                .and_then(|o| o.as_array())
                .map(|o| o.iter().filter_map(|v| v.as_u64()).map(|v| v as u16).collect())
                .unwrap_or_default();
            let field = |name: &str| settings.get(name).and_then(|v| v.as_u64()).map(|v| v as u32);
            for id in order {
                let value = match id {
                    1 => field("header_table_size"),
                    2 => field("enable_push"),
                    3 => field("max_concurrent_streams"),
                    4 => field("initial_window_size"),
                    5 => field("max_frame_size"),
                    6 => field("max_header_list_size"),
                    8 => field("enable_connect_protocol"),
                    9 => field("no_rfc7540_priorities"),
                    _ => None,
                };
                if let Some(value) = value {
                    profile.settings.push((id, value));
                }
            }
        }
        if let Some(update) = frame.get("WindowUpdate") {
            if update.get("stream_id").and_then(|v| v.as_u64()) == Some(0) {
                profile.connection_window_increment = update
                    .get("size_increment")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32);
            }
        }
    }
    profile
}

fn select_preset(user_agent: Option<&str>) -> Option<FingerprintTemplate> {
    let major = user_agent.and_then(chrome_major);
    let selected = PRESETS.iter().min_by_key(|preset| {
        (
            major.map_or(0, |major| major.abs_diff(preset.major)),
            u16::MAX - preset.major,
        )
    })?;
    let template = parse_preset(selected)?;
    info!(
        "Fingerprint fallback preset {} (requested Chrome {:?})",
        selected.id, major
    );
    Some(template)
}

/// 最近一次 WebView 握手（与 HTTP/2 前言），作为上游回放的模板；配置了缓存路径时落盘
pub struct FingerprintTemplates {
    preset: Option<FingerprintTemplate>,
    source: RwLock<TemplateSource>,
    hello: RwLock<Option<ClientHello>>,
    h2: RwLock<Option<H2Profile>>,
    fetch_orders: RwLock<Vec<Vec<String>>>,
    accept_encoding: RwLock<Option<String>>,
    hello_hash: Mutex<Option<u64>>,
    generation: AtomicU64,
    cache_path: Option<PathBuf>,
    user_agent: Option<String>,
    last_persist: Mutex<Option<Instant>>,
    snapshot: RwLock<Option<Arc<FingerprintTemplate>>>,
    fetch_shape: RwLock<Option<Arc<FetchShape>>>,
}

impl FingerprintTemplates {
    /// `user_agent` 是 WebView 当前的 UA：缓存里的 UA 对不上（WebView 升级过）就不用缓存
    pub fn new(cache_path: Option<PathBuf>, user_agent: Option<String>) -> Self {
        let preset = select_preset(user_agent.as_deref());
        let templates = Self {
            preset,
            source: RwLock::new(TemplateSource::Sampled),
            hello: RwLock::new(None),
            h2: RwLock::new(None),
            fetch_orders: RwLock::new(Vec::new()),
            accept_encoding: RwLock::new(None),
            hello_hash: Mutex::new(None),
            generation: AtomicU64::new(0),
            cache_path,
            user_agent,
            last_persist: Mutex::new(None),
            snapshot: RwLock::new(None),
            fetch_shape: RwLock::new(None),
        };
        if let Some(cached) = templates.load_cache() {
            info!("Loaded fingerprint template from cache");
            *templates.source.write() = TemplateSource::Cached;
            *templates.hello_hash.lock() = Some(profile_hash(&cached.hello));
            *templates.hello.write() = Some(cached.hello);
            *templates.h2.write() = cached.h2;
            *templates.fetch_orders.write() = cached.fetch_header_orders;
            *templates.accept_encoding.write() = cached.accept_encoding;
            templates.generation.store(1, Ordering::Release);
        }
        templates.refresh_snapshot();
        templates
    }

    fn load_cache(&self) -> Option<FingerprintTemplate> {
        let path = self.cache_path.as_ref()?;
        if std::fs::metadata(path).ok()?.len() > 256 * 1024 {
            warn!("Ignore oversized fingerprint template cache");
            return None;
        }
        let text = std::fs::read_to_string(path).ok()?;
        match serde_json::from_str::<FingerprintTemplate>(&text) {
            Ok(template)
                if self.user_agent.is_none()
                    || template.user_agent.is_none()
                    || template.user_agent == self.user_agent =>
            {
                Some(template)
            }
            Ok(_) => {
                info!("Fingerprint cache was sampled with another WebView, using preset until a new sample arrives");
                None
            }
            Err(e) => {
                warn!("Ignore unreadable fingerprint template cache: {}", e);
                None
            }
        }
    }

    /// 记下 WebView 发来的 ClientHello（只认带 GREASE 的浏览器握手）
    pub fn record_hello(&self, hello: &ClientHello) {
        if !is_browser_like(hello) {
            debug!("Ignore non-browser ClientHello as fingerprint template");
            return;
        }
        let hash = profile_hash(hello);
        let changed = {
            let mut previous = self.hello_hash.lock();
            let old = previous.replace(hash);
            old != Some(hash)
        };
        // 同一浏览器：随机部分与按连接变的扩展不影响回放，留着已有的模板
        if !changed && self.hello.read().is_some() {
            let mut source = self.source.write();
            if *source != TemplateSource::Sampled {
                *source = TemplateSource::Sampled;
                drop(source);
                self.refresh_snapshot();
            }
            return;
        }
        if changed {
            let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
            info!(
                "Fingerprint template captured from WebView (generation {})",
                generation
            );
        }
        *self.source.write() = TemplateSource::Sampled;
        *self.hello.write() = Some(hello.clone());
        self.refresh_snapshot();
        if changed {
            self.maybe_persist(true);
        }
    }

    /// 记下 WebView 的 HTTP/2 初始 SETTINGS 与连接窗口
    pub fn record_h2(&self, profile: H2Profile) {
        let changed = {
            let mut current = self.h2.write();
            let changed = current.as_ref() != Some(&profile);
            *current = Some(profile);
            changed
        };
        if changed {
            let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
            info!("HTTP/2 profile captured from WebView (generation {})", generation);
            self.refresh_snapshot();
            self.maybe_persist(true);
        }
    }

    /// 记下 WebView 经 h2 MITM 发来的 fetch 请求（`sec-fetch-mode: cors`）的头名顺序与
    /// Accept-Encoding；只影响网关道的请求头怎么排，不改握手，所以不递增代数
    pub fn observe_fetch_request(&self, headers: &http::HeaderMap) {
        if headers
            .get("sec-fetch-mode")
            .is_none_or(|mode| mode.as_bytes() != b"cors")
        {
            return;
        }
        let order = crate::fetch_shape::header_names(headers);
        if order.is_empty() {
            return;
        }
        let mut changed = {
            let mut orders = self.fetch_orders.write();
            if orders.first() == Some(&order) {
                false
            } else {
                orders.retain(|known| !crate::fetch_shape::same_name_set(known, &order));
                orders.insert(0, order);
                orders.truncate(crate::fetch_shape::MAX_ORDERS);
                true
            }
        };
        if let Some(value) = headers
            .get(http::header::ACCEPT_ENCODING)
            .and_then(|value| value.to_str().ok())
        {
            let mut current = self.accept_encoding.write();
            if current.as_deref() != Some(value) {
                *current = Some(value.to_owned());
                changed = true;
            }
        }
        if changed {
            debug!("Fetch header order captured from WebView");
            self.refresh_snapshot();
            self.maybe_persist(false);
        }
    }

    /// 网关道请求的整形依据
    pub fn fetch_shape(&self) -> Option<Arc<FetchShape>> {
        self.fetch_shape.read().clone()
    }

    /// 当前模板：采样（或缓存）齐全就用它，否则用预置；H2 只采到 TLS 时借预置的
    pub fn snapshot(&self) -> Option<Arc<FingerprintTemplate>> {
        self.snapshot.read().clone()
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// 已经采到（或从缓存读到）WebView 的 HTTP/2 初始设置
    pub fn has_sampled_h2(&self) -> bool {
        self.h2.read().is_some()
    }

    fn refresh_snapshot(&self) {
        let generation = self.generation();
        let next = match self.hello.read().clone() {
            Some(hello) => Some(FingerprintTemplate {
                hello,
                h2: self
                    .h2
                    .read()
                    .clone()
                    .or_else(|| self.preset.as_ref().and_then(|p| p.h2.clone())),
                fetch_header_order: Vec::new(),
                fetch_header_orders: Vec::new(),
                accept_encoding: None,
                user_agent: self.user_agent.clone(),
                source: *self.source.read(),
                generation,
            }),
            None => self.preset.clone().map(|mut preset| {
                preset.generation = generation;
                preset
            }),
        };
        // 头顺序与 Accept-Encoding：采到的优先，没有就用预置的
        let next = next.map(|mut template| {
            let orders = self.fetch_orders.read().clone();
            let preset = self.preset.as_ref();
            template.fetch_header_order = orders.first().cloned().unwrap_or_else(|| {
                preset
                    .map(|p| p.fetch_header_order.clone())
                    .unwrap_or_default()
            });
            template.fetch_header_orders = orders;
            template.accept_encoding = self
                .accept_encoding
                .read()
                .clone()
                .or_else(|| preset.and_then(|p| p.accept_encoding.clone()));
            template
        });
        *self.fetch_shape.write() = next.as_ref().map(|template| {
            Arc::new(FetchShape::new(
                &template.fetch_header_orders,
                &template.fetch_header_order,
                template.accept_encoding.as_deref(),
            ))
        });
        *self.snapshot.write() = next.map(Arc::new);
    }

    /// 写盘：首次（或握手变了）立即写，其余节流
    fn maybe_persist(&self, force: bool) {
        let Some(path) = self.cache_path.as_ref() else {
            return;
        };
        let mut last = self.last_persist.lock();
        if !force && last.is_some_and(|at| at.elapsed() < PERSIST_INTERVAL) {
            return;
        }
        let Some(hello) = self.hello.read().clone() else {
            return;
        };
        let template = FingerprintTemplate {
            hello,
            h2: self.h2.read().clone(),
            fetch_header_order: Vec::new(),
            fetch_header_orders: self.fetch_orders.read().clone(),
            accept_encoding: self.accept_encoding.read().clone(),
            user_agent: self.user_agent.clone(),
            source: TemplateSource::Sampled,
            generation: 0,
        };
        let result = serde_json::to_vec(&template)
            .map_err(io::Error::other)
            .and_then(|bytes| {
                if let Some(dir) = path.parent() {
                    std::fs::create_dir_all(dir)?;
                }
                let tmp = path.with_extension("tmp");
                std::fs::write(&tmp, bytes)?;
                std::fs::rename(&tmp, path)
            });
        match result {
            Ok(()) => *last = Some(Instant::now()),
            Err(e) => warn!("Persist fingerprint template failed: {}", e),
        }
    }

    /// 给宿主看的状态
    pub fn status_json(&self) -> serde_json::Value {
        let snapshot = self.snapshot();
        serde_json::json!({
            "source": snapshot.as_ref().map(|t| t.source.name()),
            "preset": snapshot.as_ref().and_then(|t| match t.source {
                TemplateSource::Builtin(id) => Some(id),
                _ => None,
            }),
            "generation": self.generation(),
            "h2": snapshot.as_ref().map(|t| t.h2.is_some()),
            "fetch_orders": self.fetch_orders.read().len(),
        })
    }
}

// ---------------------------------------------------------------------------
// 握手
// ---------------------------------------------------------------------------

/// 握手是否来自浏览器（Chromium 与 WebKit 都在套件里放 GREASE；Dart IO、curl 等不放）。
/// 只有浏览器握手才能作为回放模板
pub fn is_browser_like(hello: &ClientHello) -> bool {
    hello
        .cipher_suites()
        .iter()
        .any(|suite| is_grease_u16(u16::from(*suite)))
}

/// 参考握手是否来自 Chromium 系（发送 GREASE ECH 或 ALPS）
pub fn is_chromium(hello: &ClientHello) -> bool {
    has_extension(hello, u16::from(ExtensionId::ENCRYPTED_CLIENT_HELLO))
        || ALPS_CODEPOINTS.iter().any(|id| has_extension(hello, *id))
}

fn has_extension(hello: &ClientHello, id: u16) -> bool {
    hello
        .extensions()
        .iter()
        .any(|ext| u16::from(ext.id()) == id)
}

/// 参考握手的 TLS 1.2 套件按原顺序写成 BoringSSL 标准套件名（`:` 分隔）。
/// TLS 1.3 套件与 GREASE 由 BoringSSL 自行生成；BoringSSL 不支持的套件跳过
fn standard_cipher_list(hello: &ClientHello) -> Option<String> {
    let names: Vec<&str> = without_grease(hello.cipher_suites())
        .into_iter()
        .filter(|value| value >> 8 != 0x13)
        .filter_map(|value| SslCipher::from_value(value).map(|cipher| cipher.name()))
        .collect();
    (!names.is_empty()).then(|| names.join(":"))
}

fn without_grease(suites: &[CipherSuite]) -> Vec<u16> {
    suites
        .iter()
        .map(|suite| u16::from(*suite))
        .filter(|value| !is_grease_u16(*value))
        .collect()
}

/// 握手失败的两种结局：ECH 被拒且服务端给了新钥匙（换钥匙重来），或别的错误
pub enum BrowserHandshakeError {
    EchRetry(Vec<u8>),
    Failed(String),
}

/// 按模板握手的出口；会话票据在同一实例的连接之间共享（与浏览器对同一站点恢复会话一致）
pub struct BrowserTls {
    templates: FingerprintTemplates,
    session_domain: TlsClientSessionDomain,
    session_store: Arc<dyn TlsClientSessionStore>,
}

impl BrowserTls {
    pub fn new(cache_path: Option<PathBuf>, user_agent: Option<String>) -> Self {
        Self {
            templates: FingerprintTemplates::new(cache_path, user_agent),
            session_domain: TlsClientSessionDomain::new(),
            // 每站点留几张：TLS 1.3 票据一次性，服务端通常一次发两张
            session_store: Arc::new(TlsClientSessionCache::new(
                NonZeroUsize::new(256).unwrap(),
                NonZeroUsize::new(4).unwrap(),
            )),
        }
    }

    pub fn templates(&self) -> &FingerprintTemplates {
        &self.templates
    }

    /// 按模板构造这一条连接的 BoringSSL 配置；返回（配置, 是否注入了真 ECH）
    pub fn connector_data(
        &self,
        template: &FingerprintTemplate,
        host: &str,
        ech_config_list: Option<&[u8]>,
    ) -> Result<(TlsConnectorData, bool), BoxError> {
        build(
            &template.hello,
            host.parse()?,
            ech_config_list,
            Some((self.session_domain, self.session_store.clone())),
        )
    }

    /// 在已连好的 TCP（或上游代理隧道）上按模板握手
    pub async fn handshake(
        &self,
        template: &FingerprintTemplate,
        host: &str,
        stream: BoxStream,
        ech_config_list: Option<&[u8]>,
    ) -> Result<BrowserStream, BrowserHandshakeError> {
        let (data, ech_applied) = self
            .connector_data(template, host, ech_config_list)
            .map_err(|e| BrowserHandshakeError::Failed(format!("Build browser TLS: {}", e)))?;
        let ssl = data
            .into_ssl()
            .map_err(|e| BrowserHandshakeError::Failed(format!("Prepare browser TLS: {}", e)))?;
        match SslStreamBuilder::new(ssl, stream).connect().await {
            Ok(stream) => {
                debug!(
                    "Browser TLS to {}: ech_applied={} ech_accepted={} resumed={} alpn={:?}",
                    host,
                    ech_applied,
                    stream.ssl().ech_accepted(),
                    stream.ssl().session_reused(),
                    stream
                        .ssl()
                        .selected_alpn_protocol()
                        .map(String::from_utf8_lossy)
                );
                Ok(stream)
            }
            Err(error) => {
                if let Some(configs) = error
                    .ssl()
                    .and_then(SslRef::get_ech_retry_configs)
                    .filter(|configs| !configs.is_empty())
                {
                    return Err(BrowserHandshakeError::EchRetry(configs.to_vec()));
                }
                Err(BrowserHandshakeError::Failed(describe_handshake_error(&error)))
            }
        }
    }
}

fn describe_handshake_error<S>(error: &rama_tls_boring::core::tokio::HandshakeError<S>) -> String {
    if let Some(io) = error.as_io_error() {
        return format!("TLS handshake I/O error: {}", io);
    }
    match error.as_ssl_error_stack() {
        Some(stack) => format!("TLS handshake failed: {}", stack),
        None => format!("TLS handshake failed: {}", error),
    }
}

/// 握手后是否谈成 h2
pub fn negotiated_h2(stream: &BrowserStream) -> bool {
    stream.ssl().selected_alpn_protocol() == Some(b"h2")
}

/// 按参考握手构造上游连接配置；`ech_config_list` 为该域名的 ECHConfigList
fn build(
    hello: &ClientHello,
    server_name: Host,
    ech_config_list: Option<&[u8]>,
    sessions: Option<(TlsClientSessionDomain, Arc<dyn TlsClientSessionStore>)>,
) -> Result<(TlsConnectorData, bool), BoxError> {
    let chromium = is_chromium(hello);
    let mut config =
        TlsClientConfig::new_from_client_hello(hello).with_unknown_values(UnknownValues::Drop);
    config.set_server_name(server_name);
    config.set_webpki_roots();
    if chromium {
        config.set_permute_extensions(true);
    }

    // 标准套件串为空（参考握手没有 BoringSSL 认识的 TLS 1.2 套件）时无法安全注入 ECH
    let ech = ech_config_list.and_then(|list| {
        let suites = standard_cipher_list(hello);
        if suites.is_none() {
            warn!("Reference ClientHello has no standard TLS 1.2 suites, not injecting ECH");
        }
        suites.map(|suites| (list, suites))
    });

    let mut data = match sessions {
        Some((domain, store)) => {
            config.insert(domain);
            TlsConnectorContextBuilder::try_from(&config)?
                .with_session_store(store)
                .build()
                .configure()?
        }
        None => TlsConnectorData::try_from(&config)?,
    };
    let ech_applied = match &ech {
        Some((list, suites)) => {
            data.config.set_strict_cipher_list(suites)?;
            if chromium && !has_extension(hello, SERVER_PADDING_REQUEST) {
                data.config.set_server_padding_request(0);
            }
            data.config.set_ech_config_list(list)?;
            true
        }
        None => false,
    };
    Ok((data, ech_applied))
}

// ---------------------------------------------------------------------------
// 入站窥探
// ---------------------------------------------------------------------------

/// 从入站连接读出 ClientHello（读到的字节原样返回，由调用方放回流前面再交给 TLS 接受方）。
/// 读不到完整的 ClientHello（不是 TLS、超时、太大）时返回 None，字节照样返回
pub async fn peek_client_hello<S>(stream: &mut S, timeout: Duration) -> (Vec<u8>, Option<ClientHello>)
where
    S: AsyncRead + Unpin,
{
    let mut buffer = Vec::with_capacity(2048);
    let read = async {
        let mut chunk = [0u8; 4096];
        loop {
            match parse_client_hello_handshake_prefix(&buffer) {
                ClientHelloHandshakePrefix::Complete(hello) => return Some(hello),
                ClientHelloHandshakePrefix::Invalid => return None,
                ClientHelloHandshakePrefix::Incomplete => {}
            }
            if buffer.len() >= PEEK_LIMIT {
                return None;
            }
            let room = (PEEK_LIMIT - buffer.len()).min(chunk.len());
            match stream.read(&mut chunk[..room]).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            }
        }
    };
    let hello = tokio::time::timeout(timeout, read).await.ok().flatten();
    (buffer, hello)
}

// ---------------------------------------------------------------------------
// HTTP/2 连接前言
// ---------------------------------------------------------------------------

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// 从 WebView 的 h2 连接前言里取初始 SETTINGS（按发送顺序）和连接级 WINDOW_UPDATE。
/// 字节不够或格式不对返回 None
pub fn parse_h2_preface(bytes: &[u8]) -> Option<H2Profile> {
    let rest = bytes.strip_prefix(H2_PREFACE)?;
    let mut profile = H2Profile::default();
    let mut offset = 0;
    let mut saw_settings = false;
    while offset + 9 <= rest.len() {
        let length = u32::from_be_bytes([0, rest[offset], rest[offset + 1], rest[offset + 2]]) as usize;
        let kind = rest[offset + 3];
        let flags = rest[offset + 4];
        let stream_id = u32::from_be_bytes([
            rest[offset + 5],
            rest[offset + 6],
            rest[offset + 7],
            rest[offset + 8],
        ]) & 0x7fff_ffff;
        let payload_start = offset + 9;
        if payload_start + length > rest.len() {
            break;
        }
        let payload = &rest[payload_start..payload_start + length];
        match kind {
            // SETTINGS（非 ACK）
            0x4 if flags & 0x1 == 0 && stream_id == 0 && !saw_settings => {
                if length % 6 != 0 {
                    return None;
                }
                for setting in payload.chunks_exact(6) {
                    let id = u16::from_be_bytes([setting[0], setting[1]]);
                    let value = u32::from_be_bytes([setting[2], setting[3], setting[4], setting[5]]);
                    profile.settings.push((id, value));
                }
                saw_settings = true;
            }
            // 连接级 WINDOW_UPDATE
            0x8 if stream_id == 0 && length == 4 => {
                profile.connection_window_increment = Some(
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7fff_ffff,
                );
            }
            _ => {}
        }
        offset = payload_start + length;
        // 只看前言紧跟的控制帧，碰到请求就停
        if kind == 0x1 {
            break;
        }
    }
    saw_settings.then_some(profile)
}

/// 从刚谈成 h2 的入站连接读出连接前言并记进模板；读到的字节原样返回（放回流前面再交给 hyper）。
/// Chromium 把前言、SETTINGS、WINDOW_UPDATE 和第一个请求一起发出，通常一次就读全；
/// SETTINGS 齐了而 WINDOW_UPDATE 还没到时只再等一小会
pub async fn read_h2_preface<S>(stream: &mut S, templates: &FingerprintTemplates) -> Vec<u8>
where
    S: AsyncRead + Unpin,
{
    const LIMIT: usize = 1024;
    let mut buffer = Vec::with_capacity(512);
    let read = async {
        let mut chunk = [0u8; 1024];
        loop {
            if let Some(profile) = parse_h2_preface(&buffer) {
                if profile.connection_window_increment.is_some() || buffer.len() >= LIMIT {
                    return Some(profile);
                }
                return match tokio::time::timeout(
                    Duration::from_millis(30),
                    stream.read(&mut chunk),
                )
                .await
                {
                    Ok(Ok(n)) if n > 0 => {
                        buffer.extend_from_slice(&chunk[..n]);
                        parse_h2_preface(&buffer).or(Some(profile))
                    }
                    _ => Some(profile),
                };
            }
            let seen = buffer.len().min(H2_PREFACE.len());
            if buffer.len() >= LIMIT || buffer[..seen] != H2_PREFACE[..seen] {
                return None;
            }
            let room = (LIMIT - buffer.len()).min(chunk.len());
            match stream.read(&mut chunk[..room]).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            }
        }
    };
    if let Ok(Some(profile)) = tokio::time::timeout(Duration::from_secs(3), read).await {
        templates.record_h2(profile);
    }
    buffer
}

// ---------------------------------------------------------------------------
// 测试用：不联网取出将要发出的 ClientHello
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct HelloSink(Vec<u8>);

impl Read for HelloSink {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::ErrorKind::WouldBlock.into())
    }
}

impl Write for HelloSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// 不联网取出连接配置将要发出的 ClientHello：对着只收不发的对端开始握手
pub fn emit_client_hello(data: TlsConnectorData) -> Result<ClientHello, BoxError> {
    let ssl = data.into_ssl()?;
    match ssl.connect(HelloSink::default()) {
        Err(HandshakeError::WouldBlock(stream)) => {
            Ok(parse_client_hello_handshake(&stream.get_ref().0)?)
        }
        _ => Err(BoxError::from("handshake did not stop waiting for the server")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // rama-tls-boring 测试用的服务端 ECHConfig（config id 1，public name ech.com）
    const ECH_CONFIG: &[u8] = &[
        0xfe, 0x0d, 0x00, 0x3a, 0x01, 0x00, 0x20, 0x00, 0x20, 0x7e, 0xfb, 0x5f, 0xee, 0xa2, 0xa2,
        0x74, 0xb3, 0xff, 0xfe, 0x69, 0x51, 0x9e, 0xfa, 0xe1, 0xfa, 0x49, 0x8c, 0x61, 0x2c, 0xfa,
        0xd0, 0x0f, 0x8c, 0x22, 0x87, 0x0e, 0xbc, 0xb0, 0x2d, 0x76, 0x25, 0x00, 0x08, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x03, 0x00, 0x07, 0x65, 0x63, 0x68, 0x2e, 0x63, 0x6f, 0x6d,
        0x00, 0x00,
    ];

    fn ech_config_list() -> Vec<u8> {
        let mut list = (ECH_CONFIG.len() as u16).to_be_bytes().to_vec();
        list.extend_from_slice(ECH_CONFIG);
        list
    }

    fn chrome156() -> ClientHello {
        serde_json::from_str(include_str!("../tests/fixtures/chrome156_linux_do_hello.json"))
            .expect("parse fixture")
    }

    fn webview133() -> ClientHello {
        parse_preset(&PRESETS[0]).unwrap().hello
    }

    fn ja4(hello: &ClientHello) -> String {
        rama_tls::fingerprint::Ja4::compute_from_client_hello(hello)
            .expect("ja4")
            .to_string()
    }

    fn extension_ids(hello: &ClientHello) -> Vec<u16> {
        let mut ids: Vec<u16> = hello
            .extensions()
            .iter()
            .map(|ext| u16::from(ext.id()))
            .filter(|id| !is_grease_u16(*id))
            .collect();
        ids.sort_unstable();
        ids
    }

    fn emitted(hello: &ClientHello, ech: Option<&[u8]>) -> ClientHello {
        let (data, _) = build(hello, Host::from_static("linux.do"), ech, None).unwrap();
        emit_client_hello(data).unwrap()
    }

    /// 不注入 ECH 时逐字复刻参考握手（JA4 相同）
    #[test]
    fn replay_reproduces_reference_ja4() {
        for hello in [chrome156(), webview133()] {
            assert_eq!(ja4(&emitted(&hello, None)), ja4(&hello));
        }
    }

    /// 注入真 ECH 时外层套件、扩展集合与 JA4 都与参考握手一致
    #[test]
    fn ech_outer_matches_reference() {
        let reference = chrome156();
        let outer = emitted(&reference, Some(&ech_config_list()));
        assert_eq!(
            without_grease(outer.cipher_suites()),
            without_grease(reference.cipher_suites())
        );
        assert_eq!(extension_ids(&outer), extension_ids(&reference));
        assert_eq!(ja4(&outer), ja4(&reference));
    }

    #[test]
    fn presets_parse_with_h2_profiles() {
        for preset in PRESETS {
            let template = parse_preset(preset).unwrap();
            let h2 = template.h2.unwrap();
            assert_eq!(
                h2.settings,
                vec![(1, 65536), (2, 0), (4, 6291456), (6, 262144)],
                "{}",
                preset.id
            );
            assert_eq!(h2.connection_window_increment, Some(15663105));
        }
    }

    #[test]
    fn preset_follows_the_nearest_chrome_major() {
        let pick = |ua: &str| match select_preset(Some(ua)).unwrap().source {
            TemplateSource::Builtin(id) => id,
            _ => unreachable!(),
        };
        assert_eq!(pick("Mozilla/5.0 (Linux; Android 15) Chrome/124.0.6367.219 Mobile"), "android-webview133");
        assert_eq!(pick("Chrome/146.0"), "android-chrome149");
        assert_eq!(chrome_major("no chrome here"), None);
    }

    #[test]
    fn only_browser_hellos_qualify_as_templates() {
        assert!(is_browser_like(&chrome156()));
        let plain = ClientHello::new(
            rama_tls::ProtocolVersion::TLSv1_2,
            without_grease(chrome156().cipher_suites())
                .into_iter()
                .map(CipherSuite::from)
                .collect(),
            Vec::new(),
            Vec::new(),
        );
        assert!(!is_browser_like(&plain));
    }

    /// 采到的握手顶替预置，代数递增；同一浏览器的随机部分（SNI、key share）不算变化
    #[test]
    fn sampled_hello_replaces_the_preset() {
        let templates = FingerprintTemplates::new(None, Some("Chrome/133.0".into()));
        let preset = templates.snapshot().unwrap();
        assert_eq!(preset.source, TemplateSource::Builtin("android-webview133"));
        templates.record_hello(&chrome156());
        let sampled = templates.snapshot().unwrap();
        assert_eq!(sampled.source, TemplateSource::Sampled);
        assert!(sampled.generation > preset.generation);
        // 只采到 TLS 时 H2 借预置的
        assert!(sampled.h2.is_some());
        let generation = templates.generation();
        templates.record_hello(&chrome156());
        assert_eq!(templates.generation(), generation);
    }

    /// 按连接才有的扩展（padding、恢复会话的 pre_shared_key）不算换了浏览器：代数不变，
    /// 模板留着先采到的那份
    #[test]
    fn per_connection_extensions_do_not_bump_the_generation() {
        let full = chrome156();
        let variant = |edit: &dyn Fn(&mut Vec<ClientHelloExtension>)| {
            let mut extensions = full.extensions().to_vec();
            edit(&mut extensions);
            ClientHello::new(
                full.protocol_version(),
                full.cipher_suites().to_vec(),
                full.compression_algorithms().to_vec(),
                extensions,
            )
        };
        let resumed = variant(&|extensions| {
            extensions.push(ClientHelloExtension::Opaque {
                id: ExtensionId::from(41u16),
                data: vec![0, 1, 2, 3],
            })
        });
        let padding_toggled = variant(&|extensions| {
            match extensions.iter().position(|ext| u16::from(ext.id()) == 21) {
                Some(index) => {
                    extensions.remove(index);
                }
                None => extensions.push(ClientHelloExtension::Opaque {
                    id: ExtensionId::from(21u16),
                    data: vec![0; 17],
                }),
            }
        });
        for other in [&resumed, &padding_toggled] {
            assert_eq!(profile_hash(&full), profile_hash(other));
        }
        let templates = FingerprintTemplates::new(None, Some("Chrome/156.0".into()));
        templates.record_hello(&full);
        let generation = templates.generation();
        templates.record_hello(&resumed);
        templates.record_hello(&padding_toggled);
        assert_eq!(templates.generation(), generation);
        assert!(!has_extension(&templates.snapshot().unwrap().hello, 41));
    }

    #[test]
    fn cache_round_trips_and_is_dropped_after_a_webview_upgrade() {
        let path = std::env::temp_dir().join(format!(
            "doh-proxy-fingerprint-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let ua = Some("Chrome/156.0".to_string());
        let first = FingerprintTemplates::new(Some(path.clone()), ua.clone());
        first.record_hello(&chrome156());
        assert!(path.exists());
        let reloaded = FingerprintTemplates::new(Some(path.clone()), ua);
        assert_eq!(reloaded.snapshot().unwrap().source, TemplateSource::Cached);
        let upgraded = FingerprintTemplates::new(Some(path.clone()), Some("Chrome/157.0".into()));
        assert!(matches!(
            upgraded.snapshot().unwrap().source,
            TemplateSource::Builtin(_)
        ));
        let _ = std::fs::remove_file(path);
    }

    /// WebView 的 fetch 头顺序按头名集合各记一份（同集合以新的为准），随模板落盘；
    /// 没采到之前用预置的顺序与 Accept-Encoding
    #[test]
    fn fetch_orders_are_kept_per_name_set_and_persisted() {
        let path = std::env::temp_dir().join(format!(
            "doh-proxy-fetch-orders-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let request = |names: &[&str]| {
            let mut headers = http::HeaderMap::new();
            for name in names {
                let value = match *name {
                    "sec-fetch-mode" => "cors",
                    "accept-encoding" => "gzip, deflate, br, zstd",
                    _ => "1",
                };
                headers.append(
                    http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                    http::HeaderValue::from_static(value),
                );
            }
            headers
        };
        let ua = Some("Chrome/156.0".to_string());
        let templates = FingerprintTemplates::new(Some(path.clone()), ua.clone());
        let preset = templates.snapshot().unwrap();
        assert!(!preset.fetch_header_order.is_empty());
        assert_eq!(preset.accept_encoding.as_deref(), Some("gzip, deflate, br, zstd"));
        templates.record_hello(&chrome156());
        // 导航请求（不是 fetch）不记
        templates.observe_fetch_request(&request(&["user-agent", "accept", "sec-fetch-mode"]).tap_mode("navigate"));
        assert!(templates.snapshot().unwrap().fetch_header_orders.is_empty());
        templates.observe_fetch_request(&request(&["user-agent", "accept", "sec-fetch-mode", "accept-encoding"]));
        templates.observe_fetch_request(&request(&["x-csrf-token", "accept", "sec-fetch-mode"]));
        // 与第一组同集合、顺序不同：替换掉旧的那份并排到最前
        templates.observe_fetch_request(&request(&["accept", "user-agent", "sec-fetch-mode", "accept-encoding"]));
        let snapshot = templates.snapshot().unwrap();
        assert_eq!(
            snapshot.fetch_header_orders,
            vec![
                vec!["accept", "user-agent", "sec-fetch-mode", "accept-encoding"],
                vec!["x-csrf-token", "accept", "sec-fetch-mode"],
            ]
        );
        assert_eq!(snapshot.fetch_header_order, snapshot.fetch_header_orders[0]);
        assert!(templates.fetch_shape().is_some());
        // 首次采到握手时立即写过盘；之后的头顺序按节流写，这里强制写一次再读回
        templates.maybe_persist(true);
        let reloaded = FingerprintTemplates::new(Some(path.clone()), ua);
        assert_eq!(
            reloaded.snapshot().unwrap().fetch_header_orders,
            snapshot.fetch_header_orders
        );
        let _ = std::fs::remove_file(path);
    }

    trait TapMode {
        fn tap_mode(self, mode: &'static str) -> Self;
    }

    impl TapMode for http::HeaderMap {
        fn tap_mode(mut self, mode: &'static str) -> Self {
            self.insert("sec-fetch-mode", http::HeaderValue::from_static(mode));
            self
        }
    }

    #[tokio::test]
    async fn peek_reads_a_complete_client_hello() {
        let (data, _) = build(&chrome156(), Host::from_static("linux.do"), None, None).unwrap();
        let ssl = data.into_ssl().unwrap();
        let bytes = match ssl.connect(HelloSink::default()) {
            Err(HandshakeError::WouldBlock(stream)) => stream.get_ref().0.clone(),
            _ => panic!("handshake did not stop"),
        };
        let mut wire = bytes.clone();
        wire.extend_from_slice(b"trailing");
        let mut reader = std::io::Cursor::new(wire.clone());
        let (consumed, hello) = peek_client_hello(&mut reader, Duration::from_secs(1)).await;
        assert!(hello.is_some());
        assert!(wire.starts_with(&consumed));
        // 不是 TLS：不当成 ClientHello，读到的字节照样返回
        let mut reader = std::io::Cursor::new(b"GET / HTTP/1.1\r\n\r\n".to_vec());
        let (consumed, hello) = peek_client_hello(&mut reader, Duration::from_secs(1)).await;
        assert!(hello.is_none());
        assert!(!consumed.is_empty());
    }

    #[test]
    fn h2_preface_settings_and_window_are_parsed() {
        let mut wire = H2_PREFACE.to_vec();
        // SETTINGS: 1=65536, 2=0, 4=6291456, 6=262144
        let settings: [(u16, u32); 4] = [(1, 65536), (2, 0), (4, 6291456), (6, 262144)];
        wire.extend_from_slice(&[0, 0, 24, 0x4, 0, 0, 0, 0, 0]);
        for (id, value) in settings {
            wire.extend_from_slice(&id.to_be_bytes());
            wire.extend_from_slice(&value.to_be_bytes());
        }
        // WINDOW_UPDATE 15663105
        wire.extend_from_slice(&[0, 0, 4, 0x8, 0, 0, 0, 0, 0]);
        wire.extend_from_slice(&15663105u32.to_be_bytes());
        let profile = parse_h2_preface(&wire).unwrap();
        assert_eq!(profile.settings, settings.to_vec());
        assert_eq!(profile.connection_window_increment, Some(15663105));
        assert!(parse_h2_preface(b"GET / HTTP/1.1\r\n").is_none());
    }
}
