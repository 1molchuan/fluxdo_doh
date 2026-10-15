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
//! 3. 粘性 IP 只记实际连通过的地址；与亲和族不一致的读取时作废。
//! 4. 赢家在 60 s 内连败 3 次即解除钉住，交 Selector 降级重赛。
//!
//! 读写是单向的：Selector 只经 [`EdgePin::set_pin`] 交出赢家、经
//! [`EdgePin::effective_prefer_ipv6`] 读地址族；建连路径只问 [`EdgePin::route`]、
//! 只报 [`EdgePin::report`]。EdgePin 不认识 Selector，降级等事件经 [`PinListener`] 回调。
//!
//! 状态随所属 [`crate::dns::DnsResolver`] 存活（同一套 DoH 配置共用一份），resolver 只负责解析。

use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
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
    /// 其余候选（解析结果），按尝试顺序排好
    pub addrs: Vec<IpAddr>,
    /// 首选地址族是不是 IPv6
    pub primary_is_v6: bool,
    /// 地址族已定（有亲和）：首选族整族连不上才用另一族；未定时两族赛跑，赢家定亲和
    pub family_decided: bool,
}

impl Route {
    /// 按首选族拆成（首选族, 另一族），族内保持 `addrs` 的顺序
    pub fn split(&self) -> (Vec<IpAddr>, Vec<IpAddr>) {
        self.addrs
            .iter()
            .partition(|addr| addr.is_ipv6() == self.primary_is_v6)
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
    /// 钉住状态变化时唤醒 [`EdgePin::settled_winner`]
    pin_changed: Notify,
    listener: RwLock<Option<Weak<dyn PinListener>>>,
}

impl EdgePin {
    pub fn new(prefer_ipv6: bool) -> Self {
        Self {
            prefer_ipv6,
            state: RwLock::new(State::default()),
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
        let mut addrs = resolved;
        let now = Instant::now();
        addrs.sort_by_key(|addr| {
            let rtt = state
                .rtt
                .get(addr)
                .filter(|entry| entry.expires_at > now)
                .map(|entry| entry.value)
                .unwrap_or(u128::MAX);
            let family_bias = if addr.is_ipv6() == self.prefer_ipv6 {
                0
            } else {
                1
            };
            (rtt, family_bias)
        });
        Route {
            first,
            pinned: winner.is_some(),
            addrs,
            primary_is_v6: affinity.unwrap_or(self.prefer_ipv6),
            family_decided: affinity.is_some(),
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
                    Self::record_family(&mut state, ip, pinned || took_over);
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
                            demoted = Some(ip);
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

    /// App 引擎回报的成功：只记粘性 IP（见 FFI `doh_proxy_record_host_success`）
    pub(crate) fn remember_sticky(&self, host: &str, ip: IpAddr) {
        let mut state = self.state.write();
        Self::put_sticky(&mut state, host, ip, Instant::now());
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
    /// 为 true（经赢家连通 / 原亲和族整族连不上、由另一族接管）时强制切换
    fn record_family(state: &mut State, addr: IpAddr, force: bool) {
        let is_ipv6 = addr.is_ipv6();
        let family = if is_ipv6 { "IPv6" } else { "IPv4" };
        match state.affinity {
            Some(current) if current == is_ipv6 => return,
            Some(_) if !force => return,
            Some(_) => info!("Address family affinity switched to {}", family),
            None => info!("Address family affinity set to {}", family),
        }
        state.affinity = Some(is_ipv6);
        #[cfg(test)]
        {
            state.affinity_changes += 1;
        }
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
            self.pin_changed.notify_waiters();
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

    /// 网络变了：旧网络上的失败不再算到赢家头上
    pub fn network_changed(&self) {
        self.state.write().winner_fails.clear();
    }

    // ---------- 缓存 ----------

    /// 清掉粘性 IP、RTT 和亲和（网络切换后地址族可能变化，如 Wi-Fi 双栈 → 蜂窝 v4-only）。
    /// 赢家归 Selector 管，不动
    pub fn clear(&self) {
        let mut state = self.state.write();
        state.sticky.clear();
        state.rtt.clear();
        state.affinity = None;
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
        edge.remember_sticky("credit.linux.do", v4);
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
}
