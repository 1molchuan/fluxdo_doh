//! 网络引擎计数：建连、握手、网关转发、解析等待。全局原子量，只增不减，
//! FFI `doh_proxy_net_stats` 导出 JSON，代理运行时有变化每 60 s 打一行 info 汇总。
//! 计数只用来度量，不参与任何决策。

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Duration;

/// 单调计数
pub struct Counter(AtomicU64);

impl Counter {
    const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    pub fn inc(&self) {
        self.0.fetch_add(1, Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.0.load(Relaxed)
    }
}

/// 耗时：次数、总毫秒、最大毫秒
pub struct Timer {
    count: AtomicU64,
    total_ms: AtomicU64,
    max_ms: AtomicU64,
}

impl Timer {
    const fn new() -> Self {
        Self {
            count: AtomicU64::new(0),
            total_ms: AtomicU64::new(0),
            max_ms: AtomicU64::new(0),
        }
    }

    pub fn record(&self, elapsed: Duration) {
        let ms = elapsed.as_millis().min(u64::MAX as u128) as u64;
        self.count.fetch_add(1, Relaxed);
        self.total_ms.fetch_add(ms, Relaxed);
        self.max_ms.fetch_max(ms, Relaxed);
    }

    pub fn count(&self) -> u64 {
        self.count.load(Relaxed)
    }

    fn json(&self) -> serde_json::Value {
        let count = self.count();
        let total_ms = self.total_ms.load(Relaxed);
        serde_json::json!({
            "n": count,
            "total_ms": total_ms,
            "avg_ms": total_ms.checked_div(count).unwrap_or(0),
            "max_ms": self.max_ms.load(Relaxed),
        })
    }
}

macro_rules! net_stats {
    (
        counters { $($counter:ident: $counter_doc:literal,)* }
        timers { $($timer:ident: $timer_doc:literal,)* }
    ) => {
        pub struct NetStats {
            $(#[doc = $counter_doc] pub $counter: Counter,)*
            $(#[doc = $timer_doc] pub $timer: Timer,)*
        }

        pub static STATS: NetStats = NetStats {
            $($counter: Counter::new(),)*
            $($timer: Timer::new(),)*
        };

        impl NetStats {
            /// 全部字段的快照
            pub fn snapshot(&self) -> serde_json::Value {
                let mut map = serde_json::Map::new();
                $(map.insert(stringify!($counter).to_string(), self.$counter.get().into());)*
                $(map.insert(stringify!($timer).to_string(), self.$timer.json());)*
                serde_json::Value::Object(map)
            }

            /// 只含非零字段，日志用
            fn summary(&self) -> serde_json::Value {
                let mut map = serde_json::Map::new();
                $(if self.$counter.get() > 0 {
                    map.insert(stringify!($counter).to_string(), self.$counter.get().into());
                })*
                $(if self.$timer.count() > 0 {
                    map.insert(stringify!($timer).to_string(), self.$timer.json());
                })*
                serde_json::Value::Object(map)
            }

            /// 所有计数之和，判断有没有变化
            fn version(&self) -> u64 {
                0 $(+ self.$counter.get())* $(+ self.$timer.count())*
            }
        }
    };
}

net_stats! {
    counters {
        loopback_accepts: "本地回环入站连接（Dart / WebView 每开一条记一次）",
        connect_ok: "上游 TLS 建连成功（一次 connect / connect_h2 调用）",
        connect_fail: "上游 TLS 建连失败",
        tcp_fail: "单个地址的 TCP 连接失败或超时",
        tls_fail: "单个地址的 TLS 握手失败或超时",
        tls_full: "完整握手",
        tls_hrr: "完整握手且多一轮 HelloRetryRequest",
        tls_resumed: "会话恢复",
        ech_accepted: "ECH 被接受",
        ech_rejected: "ECH 被拒（之后按 retry_configs 处理）",
        ech_not_offered: "握手没带 ECH",
        ech_retry_adopted: "采纳服务端 retry_configs 的新钥匙",
        first_ok: "EdgePin 首选地址（赢家 / 粘性 IP）单独先试成功",
        first_fail: "EdgePin 首选地址单独先试失败",
        race_spawned: "赛跑排上的地址数",
        race_handshake_ok: "赛跑中完成 TLS 握手的地址数（含输家）",
        race_won: "赛跑出结果（赢家数）；race_handshake_ok - race_won = 白做的握手",
        race_aborted: "赛跑出结果时中止的在途尝试",
        tunnel_ok: "隧道（CONNECT 不做 MITM）上游 TCP 连通",
        tunnel_fail: "隧道上游 TCP 连不通",
        gw_requests: "网关转发的请求",
        gw_h2_reuse: "网关复用池里的 h2 连接",
        gw_h2_new: "网关新建 h2 连接",
        gw_h1_reuse: "网关复用池里的空闲 h1 连接",
        gw_h1_new: "网关新建 h1 连接",
        gw_502: "网关因建连 / 握手 / 转发失败回 502",
        pool_dial_joined: "冷 key 并发请求等同一次建连（单飞）",
        pool_preconnect: "启动预连成功",
        pool_stale_dropped: "取连接时因代数 / 地址族不符丢弃",
        pool_reaped: "回收器回收的连接（关闭 / 过期 / 空闲超时）",
        pool_suspend_flush: "进程冻结后整体作废连接",
        pool_retry_unsent: "复用连接上请求没发出去，换新连接重发",
        pool_retry_idempotent: "复用连接上幂等请求出错，换新连接重发",
        dns_inflight_timeout: "解析跟随者等满上限仍没等到领头查询",
    }
    timers {
        connect: "connect / connect_h2 成功的总耗时（含解析、等 pin、赛跑）",
        tcp_connect: "单个地址 TCP 连通耗时",
        tls_handshake: "单个地址 TLS 握手耗时",
        gw_ttfb: "网关从收到请求到拿到上游响应头",
        lookup_ip: "lookup_ip 总耗时（非 IP 字面量）",
        routes_wait: "lookup_ip 等路由表",
        pin_wait: "lookup_ip 等优选赢家确定",
        dns_follower_wait: "解析跟随者等领头查询（IP 与 ECH）",
    }
}

/// 当前快照（FFI / 基准用）
pub fn snapshot() -> serde_json::Value {
    STATS.snapshot()
}

/// 代理运行期间每 60 s 检查一次，有变化就打一行 info 汇总；收到停机信号即退出
pub(crate) fn spawn_reporter(mut shutdown: tokio::sync::broadcast::Receiver<()>) {
    tokio::spawn(async move {
        let mut last = STATS.version();
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.tick().await;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let version = STATS.version();
                    if version != last {
                        last = version;
                        tracing::info!("net_stats {}", STATS.summary());
                    }
                }
                _ = shutdown.recv() => break,
            }
        }
    });
}

/// 记一次成功握手的类型与 ECH 结果
pub(crate) fn record_handshake(conn: &rustls::ClientConnection, elapsed: Duration) {
    STATS.tls_handshake.record(elapsed);
    match conn.handshake_kind() {
        Some(rustls::HandshakeKind::Resumed) => STATS.tls_resumed.inc(),
        Some(rustls::HandshakeKind::FullWithHelloRetryRequest) => STATS.tls_hrr.inc(),
        _ => STATS.tls_full.inc(),
    }
    #[cfg(feature = "ech")]
    match conn.ech_status() {
        rustls::client::EchStatus::Accepted => STATS.ech_accepted.inc(),
        rustls::client::EchStatus::Rejected => STATS.ech_rejected.inc(),
        _ => STATS.ech_not_offered.inc(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timer_tracks_count_total_and_max() {
        let timer = Timer::new();
        timer.record(Duration::from_millis(30));
        timer.record(Duration::from_millis(10));
        let json = timer.json();
        assert_eq!(json["n"], 2);
        assert_eq!(json["total_ms"], 40);
        assert_eq!(json["avg_ms"], 20);
        assert_eq!(json["max_ms"], 30);
    }

    #[test]
    fn snapshot_lists_every_field() {
        let snapshot = snapshot();
        assert!(snapshot["gw_requests"].is_u64());
        assert!(snapshot["connect"]["n"].is_u64());
    }
}
