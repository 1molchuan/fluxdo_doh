//! 网关连接效率基准：进程内起 gateway 模式代理，照 Dart 的用法开回环连接发请求，
//! 测各场景的 TTFB 与上游握手次数（读 `doh_proxy::stats` 的前后差）。
//!
//! 用法：`cargo run --release --example gateway_bench --features ech -- [选项]`
//!
//! - `--select off|local_atlas`：本地优选模式（默认 local_atlas，与 App 一致）
//! - `--seed <file>`：启动种子（上次的优选状态 / 路由表 / 节点列表），跑完写回；相当于 App 的持久化
//! - `--sig <sig>`：启动时的网络签名（App 现在传 null）
//! - `--doh <url>`：DoH 服务器（默认 App 游客档的公共加速）
//! - `--host <host>` / `--path <path>`：请求目标（默认 linux.do /srv/status；无 cookie，403 质询不影响计时）
//! - `--idle <s>`：空闲场景等多久（默认 20，Dart 回环连接空闲 15 s 就关）
//! - `--preconnect`：启动后预连目标主机（App 传 `preconnect_hosts`）
//! - `--cold-delay <ms>`：代理就绪后过多久才发首个请求（App 里中间隔着 Flutter 初始化，默认 0）
//! - `--only cold,burst6,...`：只跑这些场景（cold burst6 serial20 idle netchange）
//! - `--json`：末尾输出一行 JSON 汇总

use bytes::Bytes;
use doh_proxy::{DohProxyServer, ProxyConfig};
use http_body_util::{BodyExt, Empty};
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

const PUBLIC_ACCEL: &str = "https://edge.1molchuan.top/linuxdo";
const PUBLIC_ACCEL_ROUTES: &str = "https://edge.1molchuan.top/v1/routes";
const PUBLIC_ACCEL_BOOTSTRAP: [&str; 4] = [
    "156.239.232.8",
    "156.239.232.72",
    "203.168.131.145",
    "103.199.103.204",
];
const ATLAS_ROUTES: &str = "https://atlas.1molchuan.top/v1/routes";
const UA: &str = "cfluxdo-gateway-bench";

/// 每个场景前后对比的计数
const COUNTERS: [&str; 20] = [
    "loopback_accepts",
    "connect_ok",
    "connect_fail",
    "tls_full",
    "tls_hrr",
    "tls_resumed",
    "ech_accepted",
    "first_ok",
    "first_fail",
    "race_spawned",
    "race_handshake_ok",
    "race_won",
    "gw_h2_new",
    "gw_h2_reuse",
    "gw_h1_new",
    "gw_502",
    "pool_dial_joined",
    "pool_preconnect",
    "pool_retry_unsent",
    "pool_retry_idempotent",
];
const TIMERS: [&str; 4] = ["pin_wait", "routes_wait", "dns_follower_wait", "connect"];

struct Sample {
    ttfb: Duration,
    status: u16,
}

/// 一条回环连接，相当于 Dart HttpClient 的一个 socket
struct Loopback {
    sender: SendRequest<Empty<Bytes>>,
}

impl Loopback {
    async fn open(port: u16) -> Result<Self, String> {
        let tcp = TcpStream::connect(("127.0.0.1", port))
            .await
            .map_err(|e| e.to_string())?;
        let _ = tcp.set_nodelay(true);
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
            .await
            .map_err(|e| e.to_string())?;
        tokio::spawn(conn);
        Ok(Self { sender })
    }

    async fn get(&mut self, host: &str, path: &str) -> Sample {
        let start = Instant::now();
        if let Err(error) = self.sender.ready().await {
            eprintln!("  loopback not ready: {}", error);
            return Sample { ttfb: start.elapsed(), status: 0 };
        }
        let request = hyper::Request::get(path)
            .header("host", host)
            .header("user-agent", UA)
            .header("accept", "*/*")
            .header("accept-encoding", "gzip")
            .body(Empty::new())
            .expect("request");
        match self.sender.send_request(request).await {
            Ok(response) => {
                let ttfb = start.elapsed();
                let status = response.status().as_u16();
                let _ = response.into_body().collect().await;
                Sample { ttfb, status }
            }
            Err(error) => {
                eprintln!("  request failed: {}", error);
                Sample { ttfb: start.elapsed(), status: 0 }
            }
        }
    }
}

/// 新开一条回环连接发一次请求
async fn one_shot(port: u16, host: &str, path: &str) -> Sample {
    match Loopback::open(port).await {
        Ok(mut lb) => lb.get(host, path).await,
        Err(error) => {
            eprintln!("  loopback connect failed: {}", error);
            Sample { ttfb: Duration::ZERO, status: 0 }
        }
    }
}

fn delta(before: &Value, after: &Value) -> Value {
    let mut out = serde_json::Map::new();
    for key in COUNTERS {
        let d = after[key].as_u64().unwrap_or(0) - before[key].as_u64().unwrap_or(0);
        out.insert(key.to_string(), d.into());
    }
    for key in TIMERS {
        let n = after[key]["n"].as_u64().unwrap_or(0) - before[key]["n"].as_u64().unwrap_or(0);
        let ms = after[key]["total_ms"].as_u64().unwrap_or(0)
            - before[key]["total_ms"].as_u64().unwrap_or(0);
        out.insert(key.to_string(), json!({ "n": n, "total_ms": ms }));
    }
    Value::Object(out)
}

fn report(name: &str, samples: &[Sample], d: &Value) -> Value {
    let mut ttfb: Vec<u128> = samples.iter().map(|s| s.ttfb.as_millis()).collect();
    ttfb.sort_unstable();
    let pick = |q: f64| ttfb.get(((ttfb.len() as f64 - 1.0) * q).round() as usize).copied().unwrap_or(0);
    let mut statuses = std::collections::BTreeMap::<u16, usize>::new();
    for s in samples {
        *statuses.entry(s.status).or_default() += 1;
    }
    let handshakes = d["tls_full"].as_u64().unwrap_or(0)
        + d["tls_hrr"].as_u64().unwrap_or(0)
        + d["tls_resumed"].as_u64().unwrap_or(0);
    println!(
        "{:<10} n={:<2} ttfb p50={:>5} p90={:>5} max={:>5} ms | 握手 {} (resumed {}) 赛跑 {}/{} 胜 {} | h2 新 {} 复用 {} 单飞 {} 预连 {} 重发 {} h1 {} 502 {} | 等pin {} ms 等表 {} ms | {}",
        name,
        samples.len(),
        pick(0.5),
        pick(0.9),
        ttfb.last().copied().unwrap_or(0),
        handshakes,
        d["tls_resumed"],
        d["race_handshake_ok"],
        d["race_spawned"],
        d["race_won"],
        d["gw_h2_new"],
        d["gw_h2_reuse"],
        d["pool_dial_joined"],
        d["pool_preconnect"],
        d["pool_retry_unsent"].as_u64().unwrap_or(0) + d["pool_retry_idempotent"].as_u64().unwrap_or(0),
        d["gw_h1_new"],
        d["gw_502"],
        d["pin_wait"]["total_ms"],
        d["routes_wait"]["total_ms"],
        statuses
            .iter()
            .map(|(status, count)| format!("{}×{}", status, count))
            .collect::<Vec<_>>()
            .join(" "),
    );
    json!({
        "scenario": name,
        "n": samples.len(),
        "ttfb_ms": ttfb,
        "p50": pick(0.5),
        "max": ttfb.last().copied().unwrap_or(0),
        "handshakes": handshakes,
        "delta": d,
        "statuses": statuses.iter().map(|(s, c)| (s.to_string(), json!(c))).collect::<serde_json::Map<_, _>>(),
    })
}

#[tokio::main]
async fn main() {
    let _ = tracing_subscriber::registry()
        .with(fmt::layer().with_ansi(false).with_writer(std::io::stderr))
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("doh_proxy=warn")))
        .try_init();

    let args: Vec<String> = std::env::args().collect();
    let arg = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let select_mode = arg("--select").unwrap_or_else(|| "local_atlas".to_string());
    let host = arg("--host").unwrap_or_else(|| "linux.do".to_string());
    let path = arg("--path").unwrap_or_else(|| "/srv/status".to_string());
    let idle_secs: u64 = arg("--idle").and_then(|v| v.parse().ok()).unwrap_or(20);
    let doh = arg("--doh").unwrap_or_else(|| PUBLIC_ACCEL.to_string());
    let seed_path = arg("--seed");
    let only: Option<Vec<String>> =
        arg("--only").map(|v| v.split(',').map(|s| s.trim().to_string()).collect());
    let want = |name: &str| only.as_ref().is_none_or(|list| list.iter().any(|s| s == name));
    let emit_json = args.iter().any(|a| a == "--json");
    let preconnect = args.iter().any(|a| a == "--preconnect");
    let cold_delay_ms: u64 = arg("--cold-delay").and_then(|v| v.parse().ok()).unwrap_or(0);

    let seed: Value = seed_path
        .as_deref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or(Value::Null);
    let seed_str = |key: &str| seed[key].as_str().map(str::to_string);

    let is_public_accel = doh == PUBLIC_ACCEL;
    let config = ProxyConfig {
        gateway_mode: true,
        enable_doh: true,
        doh_server: doh.clone(),
        doh_bootstrap_ips: if is_public_accel {
            PUBLIC_ACCEL_BOOTSTRAP.iter().map(|s| s.to_string()).collect()
        } else {
            Vec::new()
        },
        doh_routes_url: is_public_accel.then(|| PUBLIC_ACCEL_ROUTES.to_string()),
        doh_route_table_json: seed_str("route_table"),
        doh_node_list_json: seed.get("nodes_envelope").filter(|v| !v.is_null()).map(Value::to_string),
        select_mode: select_mode.clone(),
        select_state_json: seed_str("select_state"),
        atlas_routes_url: Some(ATLAS_ROUTES.to_string()),
        extra_covered_hosts: vec!["atlas.1molchuan.top".into(), "cfhub6.1molchuan.top".into()],
        app_version: Some("bench".to_string()),
        network_sig: arg("--sig"),
        preconnect_hosts: if preconnect { vec![host.clone()] } else { Vec::new() },
        ..Default::default()
    };
    println!(
        "gateway_bench select={} doh={} sig={} seed={} target={}{}",
        select_mode,
        doh,
        config.network_sig.as_deref().unwrap_or("-"),
        if seed.is_null() { "none" } else { "loaded" },
        host,
        path
    );

    let t0 = Instant::now();
    let server = Arc::new(DohProxyServer::new(config).await.expect("server"));
    let created = t0.elapsed();
    {
        let server = server.clone();
        tokio::spawn(async move { server.start().await });
    }
    let port = loop {
        if let Some(port) = server.port() {
            break port;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    };
    println!(
        "proxy ready: new {} ms, bound {} ms, port {}",
        created.as_millis(),
        t0.elapsed().as_millis(),
        port
    );

    let mut results = Vec::new();
    let mut run = |name: &'static str, samples: Vec<Sample>, before: Value| {
        let d = delta(&before, &doh_proxy::stats::snapshot());
        results.push(report(name, &samples, &d));
    };

    if want("cold") {
        tokio::time::sleep(Duration::from_millis(cold_delay_ms)).await;
        let before = doh_proxy::stats::snapshot();
        let sample = one_shot(port, &host, &path).await;
        run("cold", vec![sample], before);
    }

    if want("burst6") {
        let before = doh_proxy::stats::snapshot();
        let tasks: Vec<_> = (0..6)
            .map(|_| {
                let host = host.clone();
                let path = path.clone();
                tokio::spawn(async move { one_shot(port, &host, &path).await })
            })
            .collect();
        let mut samples = Vec::new();
        for task in tasks {
            if let Ok(sample) = task.await {
                samples.push(sample);
            }
        }
        run("burst6", samples, before);
    }

    if want("serial20") {
        let before = doh_proxy::stats::snapshot();
        let mut samples = Vec::new();
        match Loopback::open(port).await {
            Ok(mut lb) => {
                for _ in 0..20 {
                    samples.push(lb.get(&host, &path).await);
                }
            }
            Err(error) => eprintln!("  loopback connect failed: {}", error),
        }
        run("serial20", samples, before);
    }

    if want("idle") {
        tokio::time::sleep(Duration::from_secs(idle_secs)).await;
        let before = doh_proxy::stats::snapshot();
        let sample = one_shot(port, &host, &path).await;
        run("idle", vec![sample], before);
    }

    if want("netchange") {
        let before = doh_proxy::stats::snapshot();
        match doh_proxy::select::Selector::global() {
            Some(selector) => selector.on_network_changed("bench-net-2"),
            None => eprintln!("  netchange: no selector, nothing to notify"),
        }
        let tasks: Vec<_> = (0..3)
            .map(|_| {
                let host = host.clone();
                let path = path.clone();
                tokio::spawn(async move { one_shot(port, &host, &path).await })
            })
            .collect();
        let mut samples = Vec::new();
        for task in tasks {
            if let Ok(sample) = task.await {
                samples.push(sample);
            }
        }
        run("netchange", samples, before);
    }

    let selector = doh_proxy::select::Selector::global();
    if let Some(selector) = &selector {
        let status = selector.status_json();
        println!(
            "select: phase={} winner={}",
            status["phase"],
            status["winner"]["ip"]
        );
    }

    // 种子写回：相当于 App 落盘，下一轮带 --seed 就是热启动。先等优选出结果（最多 20 s）
    if let Some(path) = seed_path {
        if let Some(selector) = &selector {
            let deadline = Instant::now() + Duration::from_secs(20);
            while matches!(
                selector.phase(),
                doh_proxy::select::Phase::Racing | doh_proxy::select::Phase::Verifying
            ) && Instant::now() < deadline
            {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        let update = doh_proxy::dns::DnsResolver::take_accel_update().unwrap_or_default();
        let new_seed = json!({
            "select_state": selector.as_ref().map(|s| s.state_json()).or_else(|| seed_str("select_state")),
            "route_table": update.route_table.or_else(|| seed_str("route_table")),
            "nodes_envelope": update
                .nodes_envelope
                .map(|e| serde_json::to_value(e).unwrap_or(Value::Null))
                .unwrap_or_else(|| seed["nodes_envelope"].clone()),
        });
        if let Err(error) = std::fs::write(&path, new_seed.to_string()) {
            eprintln!("seed write failed: {}", error);
        }
    }

    if emit_json {
        println!(
            "{}",
            json!({
                "select": select_mode,
                "doh": doh,
                "proxy_ready_ms": t0.elapsed().as_millis() as u64,
                "results": results,
                "stats": doh_proxy::stats::snapshot(),
            })
        );
    }
    server.stop();
}
