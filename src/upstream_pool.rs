//! 上游连接池：所有本地回环连接共用一份，按（通道, 主机, 端口）复用上游连接。
//!
//! 以前每条回环连接各建各的上游连接：Dart 并发开几条回环连接就多几次 TCP + TLS + ECH 握手，
//! 回环连接空闲 15 s 被 Dart 关掉，上游连接跟着没了。现在：
//!
//! - h2 连接多路复用，所有回环连接共用；单连接在途流超过软上限才另开，每个 key 最多 3 条；
//! - 冷 key 的并发请求只建一条连接（单飞），建连任务独立于请求，请求取消不打断建连；
//! - h1 连接用完放回空闲列表（每个 key 最多 4 条）；
//! - h2 保活 PING（空闲也发），死连接 30 s 内被发现；空闲超时、进程冻结（设备休眠）后整体作废；
//! - 换网、地址族亲和切换、优选赢家变化时（[`EdgePin::epoch`] 递增）旧连接不再复用；
//!   复用前再核对对端地址族：cf_clearance 绑客户端出口，linux.do 各子域必须走同一地址族；
//! - 复用的连接上请求没发出去（连接刚关）就换新连接重发；GET / HEAD / OPTIONS 且无请求体时，
//!   响应头之前出错也换新连接重发一次。已发出的其他请求不盲目重发。
//!
//! Gateway（Dart）与 Mitm（WebView h2 MITM）分道，不共享连接：WebView 的畸形请求招来的
//! GOAWAY 不会连带 Dart 的请求。

use crate::edge_pin::{EdgePin, Pin};
use crate::stats::STATS;
use crate::BoxStream;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::client::conn::{http1, http2};
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin as StdPin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::watch;
use tracing::{debug, info};

pub type PoolBody = BoxBody<Bytes, hyper::Error>;

/// 每个 key 最多几条 h2 连接
const H2_MAX_CONNS_PER_KEY: usize = 3;
/// 单条 h2 连接在途流超过这个数就另开一条（CF 一般允许 256）
const H2_SOFT_STREAM_CAP: usize = 64;
/// 每个 key 最多留几条空闲 h1 连接
const H1_MAX_IDLE_PER_KEY: usize = 4;
/// 空闲多久的 h2 / h1 连接被回收
const H2_IDLE_TTL: Duration = Duration::from_secs(90);
const H1_IDLE_TTL: Duration = Duration::from_secs(30);
/// 回收器周期
const REAP_INTERVAL: Duration = Duration::from_secs(15);
/// 墙钟比上次回收晚了这么多 = 进程被冻结过（设备休眠 / 后台），连接多半已死
const SUSPEND_GAP: Duration = Duration::from_secs(45);
/// 池里最多保留多少个 key
const MAX_KEYS: usize = 64;
/// h2 保活
const H2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);
const H2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
/// h2 连接级接收窗口（默认 5 MiB 量级，大图 / 长帖多给点）
const H2_CONN_WINDOW: u32 = 16 * 1024 * 1024;

/// 连接分道
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Lane {
    /// Dart 经网关的请求
    Gateway,
    /// WebView 的 h2 MITM
    Mitm,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Key {
    lane: Lane,
    host: String,
    port: u16,
}

/// 建好的底层连接（TLS 已握手）
pub struct DialedIo {
    pub io: BoxStream,
    /// ALPN 协商出 h2
    pub h2: bool,
    /// 对端地址（经上游代理时不知道）
    pub peer: Option<SocketAddr>,
}

pub type DialFuture<'a> =
    StdPin<Box<dyn Future<Output = crate::error::Result<DialedIo>> + Send + 'a>>;

/// 池怎么建连、向谁问钉选状态。生产实现是 [`crate::ech::DohTlsConnector`]；测试连本地 h2c
pub trait Dialer: Send + Sync + 'static {
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> DialFuture<'a>;
    fn edge(&self) -> Option<&EdgePin>;
}

struct H2Conn {
    sender: http2::SendRequest<PoolBody>,
    epoch: u64,
    peer: Option<SocketAddr>,
    in_flight: AtomicUsize,
    last_used: Mutex<Instant>,
    dead: AtomicBool,
}

impl H2Conn {
    fn alive(&self) -> bool {
        !self.dead.load(Ordering::Acquire) && !self.sender.is_closed()
    }

    fn idle_for(&self) -> Option<Duration> {
        (self.in_flight.load(Ordering::Acquire) == 0).then(|| self.last_used.lock().elapsed())
    }
}

struct H1Idle {
    sender: http1::SendRequest<PoolBody>,
    epoch: u64,
    peer: Option<SocketAddr>,
    since: Instant,
}

#[derive(Clone)]
enum Dialed {
    H2(Arc<H2Conn>),
    /// 对端只给 h1：连接已放进空闲列表，等的人各自去取
    H1,
    Failed(String),
}

#[derive(Default)]
struct Entry {
    h2: Vec<Arc<H2Conn>>,
    h1: Vec<H1Idle>,
    /// 正在建的 h2 连接（单飞）
    dialing: Option<watch::Receiver<Option<Dialed>>>,
    /// 对端只会 h1：不再单飞，并发请求各建各的
    h1_only: bool,
    last_used: Option<Instant>,
}

enum Lease {
    H2(Arc<H2Conn>),
    H1 {
        sender: http1::SendRequest<PoolBody>,
        epoch: u64,
        peer: Option<SocketAddr>,
    },
}

/// 一次发送失败；`unsent` 是没发出去、原样拿回来的请求
struct SendFailure {
    error: hyper::Error,
    unsent: Option<Request<PoolBody>>,
}

pub struct UpstreamPool {
    dialer: Arc<dyn Dialer>,
    entries: Mutex<HashMap<Key, Entry>>,
    /// 池自己的代数：没有 EdgePin（或 FFI 换网通知时没有优选）也能整体作废
    local_epoch: AtomicU64,
    last_tick_wall: Mutex<SystemTime>,
    h2_builder: http2::Builder<TokioExecutor>,
    me: Weak<UpstreamPool>,
}

impl UpstreamPool {
    pub fn new(dialer: Arc<dyn Dialer>) -> Arc<Self> {
        let mut h2_builder = http2::Builder::new(TokioExecutor::new());
        h2_builder
            .timer(TokioTimer::new())
            .keep_alive_interval(H2_KEEPALIVE_INTERVAL)
            .keep_alive_timeout(H2_KEEPALIVE_TIMEOUT)
            .keep_alive_while_idle(true)
            .initial_connection_window_size(H2_CONN_WINDOW);
        Arc::new_cyclic(|me| Self {
            dialer,
            entries: Mutex::new(HashMap::new()),
            local_epoch: AtomicU64::new(0),
            last_tick_wall: Mutex::new(SystemTime::now()),
            h2_builder,
            me: me.clone(),
        })
    }

    /// 当前代数：EdgePin 的（换网 / 亲和切换 / 赢家变化）加上池自己的
    fn epoch(&self) -> u64 {
        self.dialer.edge().map(EdgePin::epoch).unwrap_or(0) + self.local_epoch.load(Ordering::Acquire)
    }

    /// 让现有连接全部不再复用（在途请求照常读完）
    pub fn bump_epoch(&self, reason: &str) {
        self.local_epoch.fetch_add(1, Ordering::AcqRel);
        info!("pool: epoch bumped ({})", reason);
    }

    /// 连接还能不能复用：代数没变；有地址族亲和时对端同族；覆盖域名钉住赢家时与赢家同族
    fn usable(&self, host: &str, epoch: u64, peer: Option<SocketAddr>) -> bool {
        if epoch != self.epoch() {
            STATS.pool_stale_dropped.inc();
            return false;
        }
        let (Some(peer), Some(edge)) = (peer, self.dialer.edge()) else {
            return true;
        };
        if edge.affinity().is_some_and(|v6| v6 != peer.is_ipv6()) {
            STATS.pool_stale_dropped.inc();
            return false;
        }
        if let Pin::Winner(winner) = edge.pin() {
            if EdgePin::is_covered(host) && winner.is_ipv6() != peer.is_ipv6() {
                STATS.pool_stale_dropped.inc();
                return false;
            }
        }
        true
    }

    /// 进程冻结过（墙钟跳了一大截）就让现有连接全部作废：休眠期间 NAT 映射多半已过期，
    /// 而 h2 保活计时用单调钟、休眠不走，死连接要等很久才被发现
    fn check_suspend(&self) {
        let now = SystemTime::now();
        let mut last = self.last_tick_wall.lock();
        let gap = now.duration_since(*last).unwrap_or_default();
        *last = now;
        if gap > SUSPEND_GAP {
            drop(last);
            STATS.pool_suspend_flush.inc();
            self.bump_epoch(&format!("process was frozen for {} s", gap.as_secs()));
        }
    }

    /// 转发一个请求。`replay` 有值表示请求可以安全重发（幂等且无请求体），给出重建的办法
    pub async fn forward(
        &self,
        lane: Lane,
        host: &str,
        port: u16,
        req: Request<PoolBody>,
        replay: Option<Replay>,
    ) -> Result<Response<PoolBody>, PoolError> {
        let key = Key {
            lane,
            host: host.to_string(),
            port,
        };
        self.check_suspend();
        let mut req = req;
        let mut fresh_only = false;
        loop {
            let (lease, reused) = match (!fresh_only).then(|| self.checkout(&key)).flatten() {
                Some(lease) => (lease, true),
                None => match self.dial_lease(&key).await {
                    Ok(lease) => (lease, false),
                    Err(message) => return Err(PoolError::Connect(message)),
                },
            };
            match self.send(&key, lease, req).await {
                Ok(response) => return Ok(response),
                // 复用的连接刚关、请求没发出去：原样换新连接再发
                Err(SendFailure {
                    unsent: Some(unsent),
                    error,
                }) if reused => {
                    STATS.pool_retry_unsent.inc();
                    debug!("pool: request to {} not sent ({}), retrying on a new connection", host, error);
                    req = unsent;
                }
                // 复用的连接上出错（响应头之前）：幂等且无请求体的重建后换新连接再发一次
                Err(SendFailure { error, .. }) if reused && replay.is_some() => {
                    STATS.pool_retry_idempotent.inc();
                    debug!("pool: idempotent request to {} failed on a reused connection ({}), retrying", host, error);
                    req = replay.as_ref().map(Replay::build).unwrap_or_else(|| unreachable!());
                }
                Err(SendFailure { error, .. }) => return Err(PoolError::Upstream(error)),
            }
            fresh_only = true;
        }
    }

    /// 只建连不发请求（启动预连）
    pub async fn preconnect(&self, lane: Lane, host: &str, port: u16) {
        let key = Key {
            lane,
            host: host.to_string(),
            port,
        };
        if self.checkout_h2(&key, false).is_some() {
            return;
        }
        match self.dial_lease(&key).await {
            Ok(Lease::H2(_)) => {
                STATS.pool_preconnect.inc();
                debug!("pool: preconnected {}:{}", host, port);
            }
            // h1 预连没意义：放回空闲列表即可
            Ok(Lease::H1 { sender, epoch, peer }) => self.put_idle_h1(&key, sender, epoch, peer),
            Err(message) => debug!("pool: preconnect {}:{} failed: {}", host, port, message),
        }
    }

    // ---------- 取连接 ----------

    fn checkout(&self, key: &Key) -> Option<Lease> {
        self.checkout_h2(key, true).or_else(|| self.checkout_h1(key))
    }

    /// 在途最少的可用 h2 连接。都满了（超软上限）且还能再开时返回 None，让调用方去建
    fn checkout_h2(&self, key: &Key, count: bool) -> Option<Lease> {
        let mut entries = self.entries.lock();
        let entry = entries.get_mut(key)?;
        entry.h2.retain(|conn| {
            conn.alive() && self.usable(&key.host, conn.epoch, conn.peer)
        });
        let best = entry
            .h2
            .iter()
            .min_by_key(|conn| conn.in_flight.load(Ordering::Acquire))?
            .clone();
        let saturated = best.in_flight.load(Ordering::Acquire) >= H2_SOFT_STREAM_CAP;
        if saturated && entry.h2.len() < H2_MAX_CONNS_PER_KEY {
            return None;
        }
        entry.last_used = Some(Instant::now());
        if count {
            STATS.gw_h2_reuse.inc();
        }
        Some(Lease::H2(best))
    }

    fn checkout_h1(&self, key: &Key) -> Option<Lease> {
        let mut entries = self.entries.lock();
        let entry = entries.get_mut(key)?;
        while let Some(idle) = entry.h1.pop() {
            if !idle.sender.is_closed()
                && idle.sender.is_ready()
                && self.usable(&key.host, idle.epoch, idle.peer)
            {
                entry.last_used = Some(Instant::now());
                STATS.gw_h1_reuse.inc();
                return Some(Lease::H1 {
                    sender: idle.sender,
                    epoch: idle.epoch,
                    peer: idle.peer,
                });
            }
        }
        None
    }

    /// 新建连接拿来用。h2 单飞：同 key 正在建就等它；建连在独立任务里跑，请求取消不打断
    async fn dial_lease(&self, key: &Key) -> Result<Lease, String> {
        enum Role {
            Lead(watch::Sender<Option<Dialed>>, watch::Receiver<Option<Dialed>>),
            Follow(watch::Receiver<Option<Dialed>>),
            Direct,
        }
        let role = {
            let mut entries = self.entries.lock();
            let entry = entries.entry(key.clone()).or_default();
            entry.last_used = Some(Instant::now());
            if entry.h1_only {
                Role::Direct
            } else if let Some(rx) = &entry.dialing {
                Role::Follow(rx.clone())
            } else {
                let (tx, rx) = watch::channel(None);
                entry.dialing = Some(rx.clone());
                Role::Lead(tx, rx)
            }
        };
        let mut rx = match role {
            Role::Direct => return self.dial_direct(key).await,
            Role::Follow(rx) => {
                STATS.pool_dial_joined.inc();
                rx
            }
            Role::Lead(tx, rx) => {
                let Some(pool) = self.me.upgrade() else {
                    return Err("pool is gone".to_string());
                };
                let key = key.clone();
                tokio::spawn(async move {
                    let dialed = match pool.dial(&key).await {
                        Ok(Lease::H2(conn)) => Dialed::H2(conn),
                        Ok(Lease::H1 { sender, epoch, peer }) => {
                            pool.put_idle_h1(&key, sender, epoch, peer);
                            Dialed::H1
                        }
                        Err(message) => Dialed::Failed(message),
                    };
                    {
                        let mut entries = pool.entries.lock();
                        if let Some(entry) = entries.get_mut(&key) {
                            entry.dialing = None;
                            if matches!(dialed, Dialed::H1) {
                                entry.h1_only = true;
                            }
                        }
                    }
                    let _ = tx.send(Some(dialed));
                });
                rx
            }
        };
        let dialed = match rx.wait_for(Option::is_some).await {
            Ok(dialed) => dialed.clone(),
            Err(_) => None,
        };
        match dialed {
            Some(Dialed::H2(conn)) => Ok(Lease::H2(conn)),
            Some(Dialed::H1) => match self.checkout_h1(key) {
                Some(lease) => Ok(lease),
                None => self.dial_direct(key).await,
            },
            Some(Dialed::Failed(message)) => Err(message),
            None => Err("connect task ended without result".to_string()),
        }
    }

    /// 不单飞直接建（h1 对端）；意外协商出 h2 也照样入池
    async fn dial_direct(&self, key: &Key) -> Result<Lease, String> {
        self.dial(key).await
    }

    async fn dial(&self, key: &Key) -> Result<Lease, String> {
        let epoch = self.epoch();
        let DialedIo { io, h2, peer } = self
            .dialer
            .dial(&key.host, key.port)
            .await
            .map_err(|e| format!("Connect failed: {}", e))?;
        let io = TokioIo::new(io);
        if h2 {
            let (sender, conn) = self
                .h2_builder
                .handshake::<_, PoolBody>(io)
                .await
                .map_err(|e| format!("H2 handshake failed: {}", e))?;
            let host = key.host.clone();
            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    debug!("pool: h2 connection to {} closed: {}", host, e);
                }
            });
            STATS.gw_h2_new.inc();
            let conn = Arc::new(H2Conn {
                sender,
                epoch,
                peer,
                in_flight: AtomicUsize::new(0),
                last_used: Mutex::new(Instant::now()),
                dead: AtomicBool::new(false),
            });
            // 建连期间代数变了（换网等）就只给这一次用，不入池
            if epoch == self.epoch() {
                let mut entries = self.entries.lock();
                let entry = entries.entry(key.clone()).or_default();
                entry.h2.push(conn.clone());
                if entry.h2.len() > H2_MAX_CONNS_PER_KEY {
                    // 挤掉在途最少的旧连接（不打断它的在途流）
                    if let Some(index) = entry
                        .h2
                        .iter()
                        .enumerate()
                        .filter(|(_, c)| !Arc::ptr_eq(c, &conn))
                        .min_by_key(|(_, c)| c.in_flight.load(Ordering::Acquire))
                        .map(|(i, _)| i)
                    {
                        entry.h2.remove(index);
                    }
                }
            }
            debug!("pool: new h2 connection to {}:{} via {:?}", key.host, key.port, peer);
            Ok(Lease::H2(conn))
        } else {
            let (sender, conn) = http1::handshake::<_, PoolBody>(io)
                .await
                .map_err(|e| format!("H1 handshake failed: {}", e))?;
            let host = key.host.clone();
            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    debug!("pool: h1 connection to {} closed: {}", host, e);
                }
            });
            STATS.gw_h1_new.inc();
            debug!("pool: new h1 connection to {}:{} via {:?}", key.host, key.port, peer);
            Ok(Lease::H1 {
                sender,
                epoch,
                peer,
            })
        }
    }

    fn put_idle_h1(
        &self,
        key: &Key,
        sender: http1::SendRequest<PoolBody>,
        epoch: u64,
        peer: Option<SocketAddr>,
    ) {
        if sender.is_closed() || epoch != self.epoch() {
            return;
        }
        let mut entries = self.entries.lock();
        let entry = entries.entry(key.clone()).or_default();
        if entry.h1.len() >= H1_MAX_IDLE_PER_KEY {
            entry.h1.remove(0);
        }
        entry.h1.push(H1Idle {
            sender,
            epoch,
            peer,
            since: Instant::now(),
        });
    }

    // ---------- 发送 ----------

    async fn send(
        &self,
        key: &Key,
        lease: Lease,
        req: Request<PoolBody>,
    ) -> Result<Response<PoolBody>, SendFailure> {
        match lease {
            Lease::H2(conn) => {
                conn.in_flight.fetch_add(1, Ordering::AcqRel);
                // 先拿到守卫：无论成功、失败还是被取消，在途计数都会扣回
                let guard = StreamGuard::H2(conn.clone());
                let mut sender = conn.sender.clone();
                match sender.try_send_request(req).await {
                    Ok(response) => Ok(response.map(|body| PooledBody::wrap(body, guard))),
                    Err(mut error) => {
                        conn.dead.store(true, Ordering::Release);
                        let unsent = error.take_message();
                        Err(SendFailure {
                            error: error.into_error(),
                            unsent,
                        })
                    }
                }
            }
            Lease::H1 {
                mut sender,
                epoch,
                peer,
            } => match sender.try_send_request(req).await {
                Ok(response) => {
                    // 响应体读完后连接回到空闲列表
                    let guard = StreamGuard::H1 {
                        pool: self.me.clone(),
                        key: key.clone(),
                        idle: Some((sender, epoch, peer)),
                    };
                    Ok(response.map(|body| PooledBody::wrap(body, guard)))
                }
                Err(mut error) => {
                    let unsent = error.take_message();
                    Err(SendFailure {
                        error: error.into_error(),
                        unsent,
                    })
                }
            },
        }
    }

    // ---------- 回收 ----------

    /// 定期回收：关掉的、代数过期的、空闲太久的连接出池；key 太多时挤掉最久没用的
    pub fn reap(&self) {
        self.check_suspend();
        let current = self.epoch();
        let mut reaped = 0usize;
        let mut entries = self.entries.lock();
        for entry in entries.values_mut() {
            let before = entry.h2.len() + entry.h1.len();
            entry.h2.retain(|conn| {
                conn.alive()
                    && conn.epoch == current
                    && conn.idle_for().is_none_or(|idle| idle < H2_IDLE_TTL)
            });
            entry.h1.retain(|idle| {
                !idle.sender.is_closed()
                    && idle.epoch == current
                    && idle.since.elapsed() < H1_IDLE_TTL
            });
            reaped += before - entry.h2.len() - entry.h1.len();
        }
        entries.retain(|_, entry| {
            !entry.h2.is_empty()
                || !entry.h1.is_empty()
                || entry.dialing.is_some()
                || entry
                    .last_used
                    .is_some_and(|at| at.elapsed() < Duration::from_secs(60))
        });
        while entries.len() > MAX_KEYS {
            let oldest = entries
                .iter()
                .filter(|(_, entry)| entry.dialing.is_none())
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone());
            match oldest {
                Some(key) => {
                    entries.remove(&key);
                }
                None => break,
            }
        }
        if reaped > 0 {
            for _ in 0..reaped {
                STATS.pool_reaped.inc();
            }
            debug!("pool: reaped {} connections, {} keys left", reaped, entries.len());
        }
    }

    /// 清空（代理停止时）
    pub fn clear(&self) {
        self.entries.lock().clear();
    }

    /// 起回收器：每 15 s 回收一次，收到停机信号退出
    pub fn spawn_reaper(self: &Arc<Self>, mut shutdown: tokio::sync::broadcast::Receiver<()>) {
        let pool = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(REAP_INTERVAL);
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let Some(pool) = pool.upgrade() else { break };
                        pool.reap();
                    }
                    _ = shutdown.recv() => break,
                }
            }
            if let Some(pool) = pool.upgrade() {
                pool.clear();
            }
        });
    }

    #[cfg(test)]
    fn h2_count(&self, lane: Lane, host: &str, port: u16) -> usize {
        self.entries
            .lock()
            .get(&Key {
                lane,
                host: host.to_string(),
                port,
            })
            .map(|entry| entry.h2.len())
            .unwrap_or(0)
    }
}

/// 可重发请求的模板（幂等方法且无请求体）
pub struct Replay {
    method: hyper::Method,
    uri: hyper::Uri,
    version: hyper::Version,
    headers: hyper::HeaderMap,
}

impl Replay {
    /// GET / HEAD / OPTIONS 且没有请求体时给出模板，其余返回 None
    pub fn capture<B: Body>(req: &Request<B>) -> Option<Self> {
        let idempotent = matches!(
            *req.method(),
            hyper::Method::GET | hyper::Method::HEAD | hyper::Method::OPTIONS
        );
        (idempotent && req.body().is_end_stream()).then(|| Self {
            method: req.method().clone(),
            uri: req.uri().clone(),
            version: req.version(),
            headers: req.headers().clone(),
        })
    }

    fn build(&self) -> Request<PoolBody> {
        let mut req = Request::new(Empty::new().map_err(|never| match never {}).boxed());
        *req.method_mut() = self.method.clone();
        *req.uri_mut() = self.uri.clone();
        *req.version_mut() = self.version;
        *req.headers_mut() = self.headers.clone();
        req
    }
}

/// 转发失败：建连（含 TLS / h2 握手）失败，或上游连接上出错
#[derive(Debug)]
pub enum PoolError {
    Connect(String),
    Upstream(hyper::Error),
}

impl std::fmt::Display for PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PoolError::Connect(message) => f.write_str(message),
            PoolError::Upstream(error) => write!(f, "Forward failed: {}", error),
        }
    }
}

/// 在途流守卫：响应体读完、被丢弃或发送失败时生效
enum StreamGuard {
    H2(Arc<H2Conn>),
    H1 {
        pool: Weak<UpstreamPool>,
        key: Key,
        idle: Option<(http1::SendRequest<PoolBody>, u64, Option<SocketAddr>)>,
    },
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        match self {
            StreamGuard::H2(conn) => {
                conn.in_flight.fetch_sub(1, Ordering::AcqRel);
                *conn.last_used.lock() = Instant::now();
            }
            StreamGuard::H1 { pool, key, idle } => {
                let (Some(pool), Some((mut sender, epoch, peer))) = (pool.upgrade(), idle.take())
                else {
                    return;
                };
                let Ok(handle) = tokio::runtime::Handle::try_current() else {
                    return;
                };
                let key = key.clone();
                // 上一个响应处理完连接才就绪；就绪了再放回空闲列表，关掉了就算了
                handle.spawn(async move {
                    if tokio::time::timeout(Duration::from_secs(5), sender.ready())
                        .await
                        .is_ok_and(|ready| ready.is_ok())
                    {
                        pool.put_idle_h1(&key, sender, epoch, peer);
                    }
                });
            }
        }
    }
}

/// 上游响应体：透传数据，读完（或被丢弃）时释放守卫
struct PooledBody {
    inner: Incoming,
    guard: Option<StreamGuard>,
}

impl PooledBody {
    fn wrap(inner: Incoming, guard: StreamGuard) -> PoolBody {
        let end = inner.is_end_stream();
        let mut body = Self {
            inner,
            guard: Some(guard),
        };
        if end {
            body.guard = None;
        }
        body.boxed()
    }
}

impl Body for PooledBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: StdPin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let polled = StdPin::new(&mut self.inner).poll_frame(cx);
        match &polled {
            Poll::Ready(None) | Poll::Ready(Some(Err(_))) => self.guard = None,
            Poll::Ready(Some(Ok(_))) if self.inner.is_end_stream() => self.guard = None,
            _ => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// 生产实现：经 ECH / 钉选建 TLS（ALPN h2 优先）
impl Dialer for crate::ech::DohTlsConnector {
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> DialFuture<'a> {
        Box::pin(async move {
            let (tls, peer) = self.connect_h2_with_peer(host, port).await?;
            let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
            Ok(DialedIo {
                io: Box::new(tls),
                h2,
                peer,
            })
        })
    }

    fn edge(&self) -> Option<&EdgePin> {
        self.dns_resolver().map(|resolver| resolver.edge_pin().as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge_pin::Outcome;
    use http_body_util::Full;
    use hyper::service::service_fn;
    use std::convert::Infallible;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::task::JoinHandle;

    /// 本地 h2c / h1 服务端：`/ok` 立即 200；`/slow` 300 ms 后 200；
    /// `/hang-first` 第一次永不响应、之后 200。
    /// 本机可能有别的进程探测新端口，所以只按「哪条连接处理了请求」认连接，不按 accept 顺序
    struct TestServer {
        addr: SocketAddr,
        conns: Arc<Mutex<HashMap<usize, JoinHandle<()>>>>,
        /// 处理过请求的连接序号（按请求顺序）
        served_by: Arc<Mutex<Vec<usize>>>,
    }

    impl TestServer {
        /// 处理过请求的不同连接数
        fn serving_conns(&self) -> usize {
            let mut seen = self.served_by.lock().clone();
            seen.sort_unstable();
            seen.dedup();
            seen.len()
        }

        /// 掐断处理第 `n` 个请求的那条连接
        fn abort_conn_of_request(&self, n: usize) {
            let index = self.served_by.lock()[n];
            if let Some(task) = self.conns.lock().get(&index) {
                task.abort();
            }
        }
    }

    async fn spawn_server(h2: bool) -> TestServer {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let conns: Arc<Mutex<HashMap<usize, JoinHandle<()>>>> = Arc::default();
        let served_by: Arc<Mutex<Vec<usize>>> = Arc::default();
        let hung = Arc::new(AtomicBool::new(false));
        {
            let conns = conns.clone();
            let served_by = served_by.clone();
            tokio::spawn(async move {
                let mut next_index = 0usize;
                while let Ok((stream, _)) = listener.accept().await {
                    let index = next_index;
                    next_index += 1;
                    let served_by = served_by.clone();
                    let hung = hung.clone();
                    let service = service_fn(move |req: Request<Incoming>| {
                        // 只记自己发的请求（别的进程探测端口时 Host 不是这个）
                        let ours = req.uri().host() == Some("example.test")
                            || req.headers().get(hyper::header::HOST).is_some_and(|h| h == "example.test");
                        if ours {
                            served_by.lock().push(index);
                        }
                        let hang = req.uri().path() == "/hang-first"
                            && !hung.swap(true, Ordering::SeqCst);
                        let slow = req.uri().path() == "/slow";
                        async move {
                            if hang {
                                std::future::pending::<()>().await;
                            }
                            if slow {
                                tokio::time::sleep(Duration::from_millis(300)).await;
                            }
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                        }
                    });
                    let io = TokioIo::new(stream);
                    let task = if h2 {
                        tokio::spawn(async move {
                            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                                .serve_connection(io, service)
                                .await;
                        })
                    } else {
                        tokio::spawn(async move {
                            let _ = hyper::server::conn::http1::Builder::new()
                                .serve_connection(io, service)
                                .await;
                        })
                    };
                    conns.lock().insert(index, task);
                }
            });
        }
        TestServer {
            addr,
            conns,
            served_by,
        }
    }

    struct TestDialer {
        addr: SocketAddr,
        h2: bool,
        dials: AtomicUsize,
        edge: Option<EdgePin>,
    }

    impl Dialer for TestDialer {
        fn dial<'a>(&'a self, _host: &'a str, _port: u16) -> DialFuture<'a> {
            Box::pin(async move {
                self.dials.fetch_add(1, Ordering::SeqCst);
                let tcp = TcpStream::connect(self.addr).await?;
                Ok(DialedIo {
                    io: Box::new(tcp),
                    h2: self.h2,
                    peer: Some(self.addr),
                })
            })
        }

        fn edge(&self) -> Option<&EdgePin> {
            self.edge.as_ref()
        }
    }

    fn pool_for(server: &TestServer, h2: bool, edge: Option<EdgePin>) -> (Arc<UpstreamPool>, Arc<TestDialer>) {
        let dialer = Arc::new(TestDialer {
            addr: server.addr,
            h2,
            dials: AtomicUsize::new(0),
            edge,
        });
        (UpstreamPool::new(dialer.clone()), dialer)
    }

    fn request(method: hyper::Method, path: &str, body: &'static [u8]) -> Request<PoolBody> {
        let body = if body.is_empty() {
            Empty::new().map_err(|never| match never {}).boxed()
        } else {
            Full::new(Bytes::from_static(body))
                .map_err(|never| match never {})
                .boxed()
        };
        let mut req = Request::new(body);
        *req.method_mut() = method;
        *req.uri_mut() = format!("https://example.test{}", path).parse().unwrap();
        req.headers_mut()
            .insert(hyper::header::HOST, "example.test".parse().unwrap());
        req
    }

    async fn get(pool: &UpstreamPool, path: &str) -> Result<u16, PoolError> {
        let req = request(hyper::Method::GET, path, b"");
        let replay = Replay::capture(&req);
        let response = pool
            .forward(Lane::Gateway, "example.test", 443, req, replay)
            .await?;
        let status = response.status().as_u16();
        let _ = response.into_body().collect().await;
        Ok(status)
    }

    #[tokio::test]
    async fn cold_key_concurrent_requests_share_one_connection() {
        let server = spawn_server(true).await;
        let (pool, dialer) = pool_for(&server, true, None);
        let tasks: Vec<_> = (0..6)
            .map(|_| {
                let pool = pool.clone();
                tokio::spawn(async move { get(&pool, "/slow").await })
            })
            .collect();
        for task in tasks {
            assert_eq!(task.await.unwrap().unwrap(), 200);
        }
        assert_eq!(dialer.dials.load(Ordering::SeqCst), 1);
        assert_eq!(server.serving_conns(), 1);
        // 之后的请求继续复用
        assert_eq!(get(&pool, "/ok").await.unwrap(), 200);
        assert_eq!(dialer.dials.load(Ordering::SeqCst), 1);
    }

    /// 代数递增后新请求走新连接，旧连接上的在途请求照常读完
    #[tokio::test]
    async fn epoch_bump_moves_new_requests_to_a_new_connection() {
        let server = spawn_server(true).await;
        let (pool, dialer) = pool_for(&server, true, None);
        assert_eq!(get(&pool, "/ok").await.unwrap(), 200);
        let slow = {
            let pool = pool.clone();
            tokio::spawn(async move { get(&pool, "/slow").await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        pool.bump_epoch("test");
        assert_eq!(get(&pool, "/ok").await.unwrap(), 200);
        assert_eq!(slow.await.unwrap().unwrap(), 200);
        assert_eq!(dialer.dials.load(Ordering::SeqCst), 2);
        assert_eq!(pool.h2_count(Lane::Gateway, "example.test", 443), 1);
    }

    /// 复用的连接在 GET 途中断掉：换新连接重发一次，调用方拿到正常响应
    #[tokio::test]
    async fn idempotent_get_is_retried_when_reused_connection_dies() {
        let server = spawn_server(true).await;
        let (pool, dialer) = pool_for(&server, true, None);
        assert_eq!(get(&pool, "/ok").await.unwrap(), 200);
        let hanging = {
            let pool = pool.clone();
            tokio::spawn(async move { get(&pool, "/hang-first").await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        server.abort_conn_of_request(1);
        let status = tokio::time::timeout(Duration::from_secs(5), hanging)
            .await
            .expect("retry should not hang")
            .unwrap()
            .unwrap();
        assert_eq!(status, 200);
        assert_eq!(dialer.dials.load(Ordering::SeqCst), 2);
    }

    /// 已发出的带请求体 POST 不盲目重发
    #[tokio::test]
    async fn sent_post_is_not_retried() {
        let server = spawn_server(true).await;
        let (pool, dialer) = pool_for(&server, true, None);
        assert_eq!(get(&pool, "/ok").await.unwrap(), 200);
        let posting = {
            let pool = pool.clone();
            tokio::spawn(async move {
                let req = request(hyper::Method::POST, "/hang-first", b"payload");
                assert!(Replay::capture(&req).is_none());
                pool.forward(Lane::Gateway, "example.test", 443, req, None)
                    .await
                    .map(|_| ())
            })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        server.abort_conn_of_request(1);
        let result = tokio::time::timeout(Duration::from_secs(5), posting)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, Err(PoolError::Upstream(_))));
        assert_eq!(dialer.dials.load(Ordering::SeqCst), 1);
    }

    /// h1 对端：响应体读完后连接回到空闲列表，下一个请求复用
    #[tokio::test]
    async fn h1_connection_is_reused_after_the_body_is_read() {
        let server = spawn_server(false).await;
        let (pool, dialer) = pool_for(&server, false, None);
        assert_eq!(get(&pool, "/ok").await.unwrap(), 200);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(get(&pool, "/ok").await.unwrap(), 200);
        assert_eq!(dialer.dials.load(Ordering::SeqCst), 1);
        assert_eq!(server.serving_conns(), 1);
    }

    /// 地址族亲和定下后，对端与亲和族不同的旧连接不再复用（cf_clearance 绑出口）
    #[tokio::test]
    async fn connection_outside_the_affinity_family_is_not_reused() {
        let server = spawn_server(true).await;
        let (pool, dialer) = pool_for(&server, true, Some(EdgePin::new(false)));
        assert_eq!(get(&pool, "/ok").await.unwrap(), 200);
        assert_eq!(get(&pool, "/ok").await.unwrap(), 200);
        assert_eq!(dialer.dials.load(Ordering::SeqCst), 1);
        // 亲和首次定为 IPv6（首次定下不递增代数），而现有连接的对端是 IPv4
        dialer.edge.as_ref().unwrap().report(
            "example.test",
            "::1".parse().unwrap(),
            Outcome::Connected {
                rtt: None,
                took_over: false,
            },
        );
        assert_eq!(get(&pool, "/ok").await.unwrap(), 200);
        assert_eq!(dialer.dials.load(Ordering::SeqCst), 2);
    }

    /// 回收器清掉服务端已关闭的连接
    #[tokio::test]
    async fn reaper_drops_closed_connections() {
        let server = spawn_server(true).await;
        let (pool, _dialer) = pool_for(&server, true, None);
        assert_eq!(get(&pool, "/ok").await.unwrap(), 200);
        assert_eq!(pool.h2_count(Lane::Gateway, "example.test", 443), 1);
        server.abort_conn_of_request(0);
        tokio::time::sleep(Duration::from_millis(100)).await;
        pool.reap();
        assert_eq!(pool.h2_count(Lane::Gateway, "example.test", 443), 0);
    }
}
