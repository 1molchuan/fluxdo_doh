//! 出站钉选（EdgePin）：覆盖域名连哪个边缘 IP、所有域名走哪个地址族，只在这里决定。
//!
//! CF 的 cf_clearance 绑定出口 IP，双栈网络下 v4 与 v6 是两个出口。linux.do 与其子域
//! （「覆盖域名」，见 [`EdgePin::is_covered`]）必须连同一个边缘 IP、走同一个地址族，
//! 否则 WebView 在 linux.do 过盾铸出的 clearance 到了别的子域就成了另一个 IP，稳定 403。
//!
//! 不变式：
//! 1. 本地优选有赢家时，覆盖域名一律先连赢家，不看各自的粘性 IP 和当前亲和；
//!    经赢家连通即把亲和强制定到赢家的地址族。
//! 2. 没有赢家时按地址族亲和：首次成功建连定下地址族，所有域名共用；只有亲和族整族
//!    连不上、由另一族接管时才切换。清缓存（网络切换）时重置。
//! 3. 候选一律先排首选族（钉住时是赢家的族，否则是亲和族，再否则配置偏好），族内按 RTT。
//! 4. 粘性 IP 只记实际连通过的地址；与亲和族不一致的读取时作废。
//! 5. 赢家在 60 s 内连败 3 次即解除钉住：所有覆盖域名一起离开它（指向它的粘性 IP 一并作废），
//!    交 Selector 降级重赛。
//!
//! 读写是单向的：Selector 只经 [`EdgePin::set_pin`] 交出赢家、经
//! [`EdgePin::effective_prefer_ipv6`] 读地址族；建连路径只问 [`EdgePin::route`]、
//! 只报 [`EdgePin::report`]。EdgePin 不认识 Selector，降级等事件经 [`PinListener`] 回调。
//!
//! 状态随所属 [`crate::dns::DnsResolver`] 存活（同一套 DoH 配置共用一份），resolver 只负责解析。

use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tracing::{debug, info, warn};

/// 粘性 IP 有效期
const STICKY_IP_TTL_SECS: u64 = 600;
/// 建连 RTT 记录有效期
const IP_RTT_TTL_SECS: u64 = 600;
/// 赢家连续失败阈值与窗口
pub const WINNER_FAIL_THRESHOLD: usize = 3;
pub const WINNER_FAIL_WINDOW_SECS: u64 = 60;
/// 粘性 / RTT 表超过这么多条时写入顺手清过期
const PRUNE_THRESHOLD: usize = 256;

/// 除 linux.do / *.linux.do 外也由优选覆盖的主机名（atlas、cfhub6）
static EXTRA_COVERED_HOSTS: OnceLock<RwLock<Vec<String>>> = OnceLock::new();

/// Selector 交给 EdgePin 的钉住状态
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Pin {
    /// 没有可用赢家（未启用 / 竞速失败 / 已停）：覆盖域名按亲和走，不等
    #[default]
    None,
    /// 正在竞速或校验：冷启动的解析可以等一会儿
    Pending,
    /// 覆盖域名钉到这个赢家
    Winner(IpAddr),
}

/// 一次建连的结果
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// 连上了。`rtt` 为建连耗时（不知道时为 None，不进 RTT 表）；
    /// `took_over` 表示首选族（亲和族）整族连不上、由另一族接管——只有这时才强制切换亲和
    Connected {
        rtt: Option<Duration>,
        took_over: bool,
    },
    /// TCP / TLS 阶段连不上
    Failed,
}

/// EdgePin 回调 Selector 的口子（EdgePin 不依赖 Selector 类型）
pub trait PinListener: Send + Sync {
    /// 赢家在窗口内连败达阈值，EdgePin 已解除钉住
    fn winner_failed(self: Arc<Self>, ip: IpAddr);
    /// 覆盖域名要建连，但当前没有赢家也没有在跑的竞速
    fn pin_missed(self: Arc<Self>);
}

/// 一次建连的地址计划（[`EdgePin::route`] 的结果）
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Route {
    /// 先单独试的地址：覆盖域名有赢家时是赢家，否则是该域名验证过的粘性 IP（已按亲和过滤）
    pub first: Option<IpAddr>,
    /// `first` 是优选赢家
    pub pinned: bool,
    /// 其余候选（解析结果）：首选族在前，族内按 RTT
    pub addrs: Vec<IpAddr>,
    /// 首选地址族是不是 IPv6：钉住时跟赢家，否则跟亲和，再否则按配置偏好
    pub primary_is_v6: bool,
    /// 地址族已定（钉住或有亲和）：首选族整族连不上才用另一族；未定时两族赛跑，赢家定亲和
    pub family_decided: bool,
}

impl Route {
    /// 按首选族拆成（首选族, 另一族），族内保持 `addrs` 的顺序
    pub fn split(&self) -> (Vec<IpAddr>, Vec<IpAddr>) {
        self.addrs
            .iter()
            .partition(|addr| addr.is_ipv6() == self.primary_is_v6)
    }

    /// 交给 App 引擎（rhttp）的地址表，按尝试顺序：`first` 在前（粘性 IP 须仍在解析结果里）。
    /// 钉住赢家时只给赢家同族的地址：rhttp 的 Happy Eyeballs 在首选族 300 ms 没连上时
    /// 会起跑另一族，给了就可能换出口
    pub fn app_addrs(&self) -> Vec<IpAddr> {
        let first = self
            .first
            .filter(|ip| self.pinned || self.addrs.contains(ip));
        let mut out: Vec<IpAddr> = first.into_iter().collect();
        for addr in &self.addrs {
            let family_ok = !self.pinned || addr.is_ipv6() == self.primary_is_v6;
            if family_ok && !out.contains(addr) {
                out.push(*addr);
            }
        }
        out
    }
}

struct Expiring<T> {
    value: T,
    expires_at: Instant,
}

#[derive(Default)]
struct State {
    pin: Pin,
    /// 钉住的赢家在窗口内的失败时刻
    winner_fails: Vec<Instant>,
    /// 出站地址族亲和（`Some(true)` = IPv6），未建连过为 None
    affinity: Option<bool>,
    /// 域名 -> 实际连通过的 IP
    sticky: HashMap<String, Expiring<IpAddr>>,
    /// IP -> 建连耗时（ms）
    rtt: HashMap<IpAddr, Expiring<u128>>,
    /// 亲和变化次数（测试用）
    #[cfg(test)]
    affinity_changes: usize,
}

pub struct EdgePin {
    /// 配置的地址族偏好，亲和未定时用
    prefer_ipv6: bool,
    state: RwLock<State>,
    /// 出站条件的代数：换网、亲和切换、钉住状态变化、清缓存时递增。
    /// 上游连接池据此判断旧连接还能不能复用（见 upstream_pool.rs）
    epoch: AtomicU64,
    /// 钉住状态变化时唤醒 [`EdgePin::settled_winner`]
    pin_changed: Notify,
    listener: RwLock<Option<Weak<dyn PinListener>>>,
}

impl EdgePin {
    pub fn new(prefer_ipv6: bool) -> Self {
        Self {
            prefer_ipv6,
            state: RwLock::new(State::default()),
            epoch: AtomicU64::new(0),
            pin_changed: Notify::new(),
            listener: RwLock::new(None),
        }
    }

    // ---------- 覆盖域名 ----------

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
    pub fn is_covered(host: &str) -> bool {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host == "linux.do" || host.ends_with(".linux.do") {
            return true;
        }
        EXTRA_COVERED_HOSTS
            .get()
            .is_some_and(|hosts| hosts.read().contains(&host))
    }

    // ---------- 建连方：问 ----------

    /// 覆盖域名在冷启动时最多等到 `deadline` 拿赢家（竞速 / 校验进行中才等）。
    /// 非覆盖域名、没有优选时立即返回 None；没有赢家时顺带告诉 Selector（可能按预算重试）
    pub async fn settled_winner(&self, host: &str, deadline: Instant) -> Option<IpAddr> {
        if !Self::is_covered(host) {
            return None;
        }
        loop {
            let notified = self.pin_changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let pin = self.state.read().pin;
            match pin {
                Pin::Winner(ip) => return Some(ip),
                Pin::None => {
                    if let Some(listener) = self.listener() {
                        listener.pin_missed();
                    }
                    return None;
                }
                Pin::Pending => {}
            }
            if tokio::time::timeout_at(deadline.into(), notified)
                .await
                .is_err()
            {
                return None;
            }
        }
    }

    /// 给 `host` 排连接顺序。`resolved` 是解析结果（表 / DoH / 系统 DNS），可以为空
    pub fn route(&self, host: &str, resolved: Vec<IpAddr>) -> Route {
        let winner = match self.state.read().pin {
            Pin::Winner(ip) if Self::is_covered(host) => Some(ip),
            _ => None,
        };
        // 优选有赢家：覆盖域名一律先连赢家，不看各自的粘性 IP 和当前地址族亲和
        let first = winner.or_else(|| self.sticky(host));
        let state = self.state.read();
        let affinity = state.affinity;
        // 钉住时首选族跟赢家走（经赢家连通后亲和也会被强制成这一族），兜底候选不换出口
        let primary_is_v6 = match winner {
            Some(ip) => ip.is_ipv6(),
            None => affinity.unwrap_or(self.prefer_ipv6),
        };
        let mut addrs = resolved;
        let now = Instant::now();
        addrs.sort_by_key(|addr| {
            let rtt = state
                .rtt
                .get(addr)
                .filter(|entry| entry.expires_at > now)
                .map(|entry| entry.value)
                .unwrap_or(u128::MAX);
            (addr.is_ipv6() != primary_is_v6, rtt)
        });
        Route {
            first,
            pinned: winner.is_some(),
            addrs,
            primary_is_v6,
            family_decided: winner.is_some() || affinity.is_some(),
        }
    }

    /// 该域名验证过的粘性 IP；与当前亲和族不一致（亲和切换前记下的）就作废
    pub fn sticky(&self, host: &str) -> Option<IpAddr> {
        let now = Instant::now();
        let (addr, affinity) = {
            let state = self.state.read();
            let addr = state
                .sticky
                .get(host)
                .filter(|entry| entry.expires_at > now)
                .map(|entry| entry.value)?;
            (addr, state.affinity)
        };
        if affinity.is_some_and(|prefer_ipv6| addr.is_ipv6() != prefer_ipv6) {
            debug!(
                "Dropping sticky IP {} for {}: address family differs from affinity",
                addr, host
            );
            self.forget_host(host);
            return None;
        }
        Some(addr)
    }

    // ---------- 建连方：报 ----------

    /// 回报一次到 `ip` 的建连结果
    pub fn report(&self, host: &str, ip: IpAddr, outcome: Outcome) {
        let covered = Self::is_covered(host);
        let mut demoted = None;
        {
            let mut state = self.state.write();
            let pinned = covered && state.pin == Pin::Winner(ip);
            let now = Instant::now();
            match outcome {
                Outcome::Connected { rtt, took_over } => {
                    if pinned {
                        state.winner_fails.clear();
                    }
                    Self::put_sticky(&mut state, host, ip, now);
                    if let Some(rtt) = rtt {
                        state.rtt.insert(
                            ip,
                            Expiring {
                                value: rtt.as_millis(),
                                expires_at: now + Duration::from_secs(IP_RTT_TTL_SECS),
                            },
                        );
                        if state.rtt.len() > PRUNE_THRESHOLD {
                            state.rtt.retain(|_, entry| entry.expires_at > now);
                        }
                    }
                    // 赢家连通即把亲和强制定到赢家的地址族，后续所有域名跟着走
                    if Self::record_family(&mut state, ip, pinned || took_over) {
                        self.bump_epoch();
                    }
                }
                Outcome::Failed => {
                    state.sticky.remove(host);
                    if pinned {
                        let window = Duration::from_secs(WINNER_FAIL_WINDOW_SECS);
                        state.winner_fails.push(now);
                        state
                            .winner_fails
                            .retain(|at| now.saturating_duration_since(*at) < window);
                        if state.winner_fails.len() >= WINNER_FAIL_THRESHOLD {
                            warn!(
                                "edge: winner {} failed {} times within {}s, unpinning",
                                ip,
                                state.winner_fails.len(),
                                WINNER_FAIL_WINDOW_SECS
                            );
                            state.pin = Pin::None;
                            state.winner_fails.clear();
                            // 所有覆盖域名一起离开它：降级到重赛出结果之间不能各自回到旧赢家
                            state.sticky.retain(|_, entry| entry.value != ip);
                            demoted = Some(ip);
                            self.bump_epoch();
                        }
                    }
                }
            }
        }
        if let Some(ip) = demoted {
            self.pin_changed.notify_waiters();
            if let Some(listener) = self.listener() {
                listener.winner_failed(ip);
            }
        }
    }

    /// 忘掉该域名的粘性 IP
    pub fn forget_host(&self, host: &str) {
        self.state.write().sticky.remove(host);
    }

    fn put_sticky(state: &mut State, host: &str, ip: IpAddr, now: Instant) {
        state.sticky.insert(
            host.to_string(),
            Expiring {
                value: ip,
                expires_at: now + Duration::from_secs(STICKY_IP_TTL_SECS),
            },
        );
        if state.sticky.len() > PRUNE_THRESHOLD {
            state.sticky.retain(|_, entry| entry.expires_at > now);
        }
    }

    /// 记录一次成功建连所用的地址族。`force` 为 false 时只在尚无亲和时写入；
    /// 为 true（经赢家连通 / 原亲和族整族连不上、由另一族接管）时强制切换。
    /// 返回是否从一族切到了另一族（首次定下不算）
    fn record_family(state: &mut State, addr: IpAddr, force: bool) -> bool {
        let is_ipv6 = addr.is_ipv6();
        let family = if is_ipv6 { "IPv6" } else { "IPv4" };
        let switched = match state.affinity {
            Some(current) if current == is_ipv6 => return false,
            Some(_) if !force => return false,
            Some(_) => {
                info!("Address family affinity switched to {}", family);
                true
            }
            None => {
                info!("Address family affinity set to {}", family);
                false
            }
        };
        state.affinity = Some(is_ipv6);
        #[cfg(test)]
        {
            state.affinity_changes += 1;
        }
        switched
    }

    // ---------- Selector ----------

    /// Selector 交出当前赢家状态。状态变了就清零赢家的失败窗口、唤醒等赢家的解析
    pub fn set_pin(&self, pin: Pin) {
        let changed = {
            let mut state = self.state.write();
            if state.pin == pin {
                false
            } else {
                state.pin = pin;
                state.winner_fails.clear();
                true
            }
        };
        if changed {
            debug!("edge: pin -> {:?}", pin);
            self.bump_epoch();
            self.pin_changed.notify_waiters();
        }
    }

    /// 当前钉住状态
    pub fn pin(&self) -> Pin {
        self.state.read().pin
    }

    /// 出站条件的代数（见字段说明）
    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    fn bump_epoch(&self) {
        self.epoch.fetch_add(1, Ordering::AcqRel);
    }

    /// 等钉住状态不再是待定（竞速 / 校验出结果）或到 `deadline`，返回那时的状态。
    /// 与 [`Self::settled_winner`] 不同：不回调 Selector，只用来决定什么时候预连
    pub async fn wait_settled(&self, deadline: Instant) -> Pin {
        loop {
            let notified = self.pin_changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let pin = self.pin();
            if pin != Pin::Pending {
                return pin;
            }
            if tokio::time::timeout_at(deadline.into(), notified)
                .await
                .is_err()
            {
                return self.pin();
            }
        }
    }

    /// 登记降级 / 缺赢家事件的接收方（新的覆盖旧的）
    pub fn attach(&self, listener: Weak<dyn PinListener>) {
        *self.listener.write() = Some(listener);
    }

    fn listener(&self) -> Option<Arc<dyn PinListener>> {
        self.listener.read().as_ref()?.upgrade()
    }

    /// 当前出站地址族亲和（`Some(true)` = IPv6），未建连过时为 `None`
    pub fn affinity(&self) -> Option<bool> {
        self.state.read().affinity
    }

    /// 本次应优先的地址族：有亲和用亲和，否则按配置的 prefer_ipv6
    pub fn effective_prefer_ipv6(&self) -> bool {
        self.affinity().unwrap_or(self.prefer_ipv6)
    }

    /// 钉住的赢家在窗口内已失败几次
    pub fn winner_fail_streak(&self) -> usize {
        let now = Instant::now();
        let window = Duration::from_secs(WINNER_FAIL_WINDOW_SECS);
        self.state
            .read()
            .winner_fails
            .iter()
            .filter(|at| now.saturating_duration_since(**at) < window)
            .count()
    }

    /// 网络变了：旧网络上的失败不再算到赢家头上，旧连接不再复用
    pub fn network_changed(&self) {
        self.state.write().winner_fails.clear();
        self.bump_epoch();
    }

    // ---------- 缓存 ----------

    /// 清掉粘性 IP、RTT 和亲和（网络切换后地址族可能变化，如 Wi-Fi 双栈 → 蜂窝 v4-only）。
    /// 赢家归 Selector 管，不动
    pub fn clear(&self) {
        let mut state = self.state.write();
        state.sticky.clear();
        state.rtt.clear();
        state.affinity = None;
        drop(state);
        self.bump_epoch();
    }

    /// 清过期条目
    pub(crate) fn prune(&self) {
        let now = Instant::now();
        let mut state = self.state.write();
        state.sticky.retain(|_, entry| entry.expires_at > now);
        state.rtt.retain(|_, entry| entry.expires_at > now);
    }

    /// 未过期的粘性 IP：(域名, IP, 过期时间)，供缓存统计 / 导出
    pub(crate) fn sticky_entries(&self) -> Vec<(String, IpAddr, Instant)> {
        let now = Instant::now();
        self.state
            .read()
            .sticky
            .iter()
            .filter(|(_, entry)| entry.expires_at > now)
            .map(|(host, entry)| (host.clone(), entry.value, entry.expires_at))
            .collect()
    }

    /// 未过期的 RTT 记录条数
    pub(crate) fn rtt_count(&self) -> usize {
        let now = Instant::now();
        self.state
            .read()
            .rtt
            .values()
            .filter(|entry| entry.expires_at > now)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn connected() -> Outcome {
        Outcome::Connected {
            rtt: None,
            took_over: false,
        }
    }

    /// 地址族亲和：首次成功建连定下地址族，之后另一族的粘性 IP 作废；
    /// 非强制记录不改亲和，强制记录（亲和族整族失败）才切换；清缓存重置
    #[test]
    fn family_affinity_pins_address_family_across_hosts() {
        let edge = EdgePin::new(false);
        let v4 = ip("198.51.100.10");
        let v6 = ip("2001:db8::10");

        assert_eq!(edge.affinity(), None);
        assert!(!edge.effective_prefer_ipv6());

        // 首次建连走了 v6（Happy Eyeballs 赛跑赢家）：亲和定为 v6
        edge.report("linux.do", v6, connected());
        assert_eq!(edge.affinity(), Some(true));
        assert!(edge.effective_prefer_ipv6());
        assert_eq!(edge.sticky("linux.do"), Some(v6));

        // 另一域名早先记下的 v4 粘性 IP 与亲和不一致：读取时作废
        edge.report("credit.linux.do", v4, connected());
        assert_eq!(edge.affinity(), Some(true));
        assert_eq!(edge.sticky("credit.linux.do"), None);
        assert_eq!(edge.sticky("credit.linux.do"), None);

        // 只有 A 记录的域名走 v4 成功，不是亲和族失败：亲和不变
        edge.report("a-only.example", v4, connected());
        assert_eq!(edge.affinity(), Some(true));

        // 亲和族整族失败、v4 接管：切换亲和，原 v6 粘性 IP 作废
        edge.report(
            "b.example",
            v4,
            Outcome::Connected {
                rtt: None,
                took_over: true,
            },
        );
        assert_eq!(edge.affinity(), Some(false));
        assert_eq!(edge.sticky("linux.do"), None);

        // 网络切换清缓存：亲和重置
        edge.clear();
        assert_eq!(edge.affinity(), None);
    }

    /// 代数只在出站条件真变了时递增：亲和首次定下、同一赢家重复交出都不算
    #[test]
    fn epoch_bumps_only_when_outbound_conditions_change() {
        let edge = EdgePin::new(false);
        let v4 = ip("198.51.100.10");
        let v6 = ip("2001:db8::10");
        let mut last = edge.epoch();
        let mut bumped = |edge: &EdgePin| {
            let now = edge.epoch();
            let changed = now != last;
            last = now;
            changed
        };

        edge.report("linux.do", v4, connected());
        assert!(!bumped(&edge), "first affinity is not a change");
        edge.report("linux.do", v4, connected());
        assert!(!bumped(&edge));
        edge.report(
            "linux.do",
            v6,
            Outcome::Connected {
                rtt: None,
                took_over: true,
            },
        );
        assert!(bumped(&edge), "affinity switch");

        edge.set_pin(Pin::Winner(v6));
        assert!(bumped(&edge), "pin change");
        edge.set_pin(Pin::Winner(v6));
        assert!(!bumped(&edge), "same pin again");

        for _ in 0..WINNER_FAIL_THRESHOLD {
            edge.report("linux.do", v6, Outcome::Failed);
        }
        assert_eq!(edge.pin(), Pin::None);
        assert!(bumped(&edge), "winner demoted");

        edge.network_changed();
        assert!(bumped(&edge), "network changed");
        edge.clear();
        assert!(bumped(&edge), "caches cleared");
    }

    const COVERED: [&str; 3] = ["linux.do", "connect.linux.do", "cdk.linux.do"];

    fn connected_in(ms: u64) -> Outcome {
        Outcome::Connected {
            rtt: Some(Duration::from_millis(ms)),
            took_over: false,
        }
    }

    /// 赢家是 v4，而表地址、各自的粘性 IP 和当前亲和都是 v6：linux.do、connect.linux.do、
    /// cdk.linux.do 一律先连赢家，兜底候选也先排赢家的族；经赢家连通把亲和强制改一次，之后不再变
    #[test]
    fn covered_hosts_pin_to_winner_and_its_family() {
        let edge = EdgePin::new(true);
        let winner = ip("104.21.0.1");
        let table_v4 = ip("172.67.0.1");
        let table_v6 = ip("2606:4700::6810:1");
        // 优选出结果前，cdk.linux.do 经 v6 表地址连通过：亲和 v6、粘性 v6
        edge.report("cdk.linux.do", table_v6, connected_in(30));
        assert_eq!(edge.affinity(), Some(true));
        assert_eq!(edge.state.read().affinity_changes, 1);

        edge.set_pin(Pin::Winner(winner));
        for host in COVERED {
            let route = edge.route(host, vec![table_v6, winner, table_v4]);
            assert_eq!(route.first, Some(winner), "{}", host);
            assert!(route.pinned);
            assert!(!route.primary_is_v6, "{} 的首选族要跟赢家", host);
            assert!(route.family_decided);
            assert_eq!(route.addrs, vec![winner, table_v4, table_v6]);
            // 交给 rhttp 的地址表只有赢家同族，避免 Happy Eyeballs 换出口
            assert_eq!(route.app_addrs(), vec![winner, table_v4]);
        }

        for host in COVERED {
            edge.report(host, winner, connected_in(50));
        }
        assert_eq!(edge.affinity(), Some(false));
        assert_eq!(edge.state.read().affinity_changes, 2, "只强制切换一次");
        assert_eq!(edge.sticky("cdk.linux.do"), Some(winner));

        // 非覆盖域名不钉赢家，按（已切到 v4 的）亲和排
        let route = edge.route("example.com", vec![table_v6, table_v4]);
        assert_eq!(route.first, None);
        assert!(!route.pinned);
        assert_eq!(route.addrs, vec![table_v4, table_v6]);
        // 只有 AAAA 的非覆盖域名连通，不是接管：亲和不动
        edge.report("v6-only.example", table_v6, connected_in(10));
        assert_eq!(edge.affinity(), Some(false));
        assert_eq!(edge.state.read().affinity_changes, 2);
    }

    /// 没有赢家：覆盖域名跟亲和族走（亲和族在前，另一族的粘性 IP 作废）；
    /// 非覆盖域名照旧先粘性 IP、族内按 RTT
    #[test]
    fn without_winner_covered_hosts_follow_affinity_others_keep_sticky_and_rtt() {
        let edge = EdgePin::new(false);
        let v4_fast = ip("198.51.100.1");
        let v4_slow = ip("198.51.100.2");
        let v6_fast = ip("2001:db8::1");
        let v6_slow = ip("2001:db8::2");
        // 首次建连走了 v6：亲和 v6（配置偏好是 v4）
        edge.report("linux.do", v6_slow, connected_in(80));
        edge.report("example.com", v6_fast, connected_in(20));
        edge.report("probe.example", v4_fast, connected_in(5));
        edge.report("cdk.linux.do", v4_slow, connected_in(90));
        assert_eq!(edge.affinity(), Some(true));
        // 等待中也不钉
        edge.set_pin(Pin::Pending);

        let resolved = vec![v4_fast, v6_slow, v4_slow, v6_fast];
        let route = edge.route("connect.linux.do", resolved.clone());
        assert_eq!(route.first, None);
        assert!(!route.pinned);
        assert!(route.primary_is_v6);
        assert!(route.family_decided);
        // v4_fast 最快也排在亲和族之后
        assert_eq!(route.addrs, vec![v6_fast, v6_slow, v4_fast, v4_slow]);
        assert_eq!(route.split().0, vec![v6_fast, v6_slow]);

        assert_eq!(
            edge.route("linux.do", resolved.clone()).first,
            Some(v6_slow)
        );
        // cdk.linux.do 的 v4 粘性 IP 与亲和不一致：作废
        assert_eq!(edge.route("cdk.linux.do", resolved.clone()).first, None);
        assert_eq!(edge.sticky("cdk.linux.do"), None);

        // 非覆盖域名：粘性 IP 先试，候选族内按 RTT
        let route = edge.route("example.com", resolved.clone());
        assert_eq!(route.first, Some(v6_fast));
        assert_eq!(route.addrs, vec![v6_fast, v6_slow, v4_fast, v4_slow]);
        // 没钉住时两族都给 rhttp（亲和族在前）；粘性 IP 不在这次解析结果里就不往前放
        let route = edge.route("linux.do", resolved);
        assert_eq!(route.app_addrs(), vec![v6_slow, v6_fast, v4_fast, v4_slow]);
        assert_eq!(
            edge.route("linux.do", vec![v6_fast]).app_addrs(),
            vec![v6_fast]
        );

        // 没有亲和时按配置偏好排，两族赛跑
        edge.clear();
        let route = edge.route("connect.linux.do", vec![v6_fast, v4_slow, v4_fast]);
        assert!(!route.family_decided);
        assert!(!route.primary_is_v6);
        assert_eq!(route.addrs, vec![v4_slow, v4_fast, v6_fast]);
    }

    /// 赢家连败：非覆盖域名、非赢家 IP 不计；窗口内第 3 次解除钉住，指向它的粘性 IP 一并作废，
    /// 冷启动等赢家的解析随之返回
    #[tokio::test]
    async fn pending_pin_wakes_waiters_and_fail_streak_unpins() {
        let edge = Arc::new(EdgePin::new(false));
        let winner = ip("104.21.0.1");
        edge.set_pin(Pin::Pending);
        let waiter = {
            let edge = edge.clone();
            tokio::spawn(async move {
                edge.settled_winner("linux.do", Instant::now() + Duration::from_secs(5))
                    .await
            })
        };
        tokio::task::yield_now().await;
        edge.set_pin(Pin::Winner(winner));
        assert_eq!(waiter.await.unwrap(), Some(winner));
        assert_eq!(
            edge.settled_winner("example.com", Instant::now()).await,
            None
        );

        edge.report("cdn.linux.do", winner, connected());
        edge.report("example.com", winner, Outcome::Failed);
        edge.report("linux.do", ip("104.21.0.9"), Outcome::Failed);
        edge.report("linux.do", winner, Outcome::Failed);
        edge.report("connect.linux.do", winner, Outcome::Failed);
        assert_eq!(edge.winner_fail_streak(), 2);
        edge.report("cdk.linux.do", winner, Outcome::Failed);
        assert_eq!(edge.winner_fail_streak(), 0);
        for host in [
            "linux.do",
            "connect.linux.do",
            "cdk.linux.do",
            "cdn.linux.do",
        ] {
            let route = edge.route(host, Vec::new());
            assert_eq!(route.first, None, "{} 不能再回到旧赢家", host);
        }
        assert_eq!(edge.settled_winner("linux.do", Instant::now()).await, None);
    }
}
