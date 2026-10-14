//! 在 VPS / 开发机上跑一轮本地优选竞速，看候选、赢家与状态 JSON。
//!
//! 用法：`cargo run --example race --features ech -- [--mode local_atlas|atlas_only] [--atlas <url>] [--json]`

use doh_proxy::select::{Phase, SelectMode, Selector};
use std::time::{Duration, Instant};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[tokio::main]
async fn main() {
    let _ = tracing_subscriber::registry()
        .with(fmt::layer().with_ansi(false))
        .with(
            EnvFilter::from_default_env()
                .add_directive("doh_proxy=debug".parse().unwrap_or_default()),
        )
        .try_init();

    let args: Vec<String> = std::env::args().collect();
    let arg = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let mode = arg("--mode")
        .map(|m| SelectMode::parse(&m))
        .unwrap_or(SelectMode::LocalAtlas);
    let atlas = arg("--atlas").unwrap_or_else(|| "https://atlas.1molchuan.top/v1/routes".to_string());
    let json = args.iter().any(|a| a == "--json");

    let selector = Selector::standalone(mode, Some(&atlas), None, Some("cli"));
    // --probe <ip>：只探测这个 IP（钥匙照常从 atlas / HTTPS 记录拿）
    if let Some(ip) = arg("--probe").and_then(|v| v.parse::<std::net::IpAddr>().ok()) {
        // --via-proxy host:port：经 HTTP CONNECT 隧道探测（复现模拟器 / 特定出口的路径）
        let outcome = if let Some(proxy) = arg("--via-proxy") {
            let (host, port) = proxy.rsplit_once(':').expect("--via-proxy host:port");
            let proxy = doh_proxy::UpstreamProxyConfig {
                protocol: "http".to_string(),
                host: host.to_string(),
                port: port.parse().expect("port"),
                username: None,
                password: None,
                cipher: None,
            };
            match doh_proxy::upstream::connect_tunnel(&proxy, &ip.to_string(), 443).await {
                Ok(stream) => selector.diagnose_on_stream(ip, stream).await,
                Err(error) => {
                    println!("probe {} -> tunnel failed: {}", ip, error);
                    selector.shutdown();
                    return;
                }
            }
        } else {
            selector.diagnose_ip(ip).await
        };
        match outcome {
            Some(outcome) => println!(
                "probe {} -> ok={} latency={} ms ech_accepted={} failure={}",
                ip,
                outcome.ok,
                outcome.latency.as_millis(),
                outcome.ech_accepted,
                outcome.failure.map(|f| f.to_string()).unwrap_or_else(|| "-".into())
            ),
            None => println!("probe {} -> no ech key", ip),
        }
        selector.shutdown();
        return;
    }
    let start = Instant::now();
    assert!(selector.request_rerace(true), "race did not start");
    while selector.phase() == Phase::Racing && start.elapsed() < Duration::from_secs(20) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if json {
        println!("{}", selector.status_json());
    } else {
        println!(
            "phase={:?} elapsed={} ms\n{}",
            selector.phase(),
            start.elapsed().as_millis(),
            serde_json::to_string_pretty(&selector.status_json()).unwrap_or_default()
        );
    }
    selector.shutdown();
}
