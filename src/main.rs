//! DOH Proxy - Standalone executable

use doh_proxy::{DohProxyServer, ProxyConfig, UpstreamProxyConfig};
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env().add_directive("doh_proxy=info".parse()?))
        .init();

    info!("Starting DOH Proxy Server");

    // Parse command line args (simple version)
    let args: Vec<String> = std::env::args().collect();

    let port = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);

    let prefer_ipv6 = args.iter().any(|a| a == "--ipv6");
    let enable_doh = !args.iter().any(|a| a == "--no-doh");
    let gateway_mode = args.iter().any(|a| a == "--gateway");
    let h2_mitm = args.iter().any(|a| a == "--h2-mitm");

    // Parse --doh <url> argument
    let doh_server = args
        .iter()
        .position(|a| a == "--doh")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "cloudflare".to_string());

    let upstream_host = args
        .iter()
        .position(|a| a == "--upstream-host")
        .and_then(|i| args.get(i + 1))
        .cloned();
    let upstream_port = args
        .iter()
        .position(|a| a == "--upstream-port")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse::<u16>().ok());
    let upstream_protocol = args
        .iter()
        .position(|a| a == "--upstream-protocol")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "http".to_string());
    let upstream_username = args
        .iter()
        .position(|a| a == "--upstream-user")
        .and_then(|i| args.get(i + 1))
        .cloned();
    let upstream_cipher = args
        .iter()
        .position(|a| a == "--upstream-cipher")
        .and_then(|i| args.get(i + 1))
        .cloned();
    let upstream_password = args
        .iter()
        .position(|a| a == "--upstream-pass")
        .and_then(|i| args.get(i + 1))
        .cloned();

    // Parse --doh-server-ech <url> argument
    let doh_server_ech = args
        .iter()
        .position(|a| a == "--doh-server-ech")
        .and_then(|i| args.get(i + 1))
        .cloned();

    // Parse --doh-bootstrap-ips / --doh-ech-bootstrap-ips <ip,ip,...> arguments
    let parse_ip_list = |flag: &str| -> Vec<String> {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .map(|s| {
                s.split(',')
                    .map(str::trim)
                    .filter(|ip| !ip.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    let doh_bootstrap_ips = parse_ip_list("--doh-bootstrap-ips");
    let doh_ech_bootstrap_ips = parse_ip_list("--doh-ech-bootstrap-ips");

    // DoH 访问令牌走环境变量，不放命令行，避免出现在进程列表里
    let env_token = |name: &str| {
        std::env::var(name)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    };
    let doh_auth_token = env_token("DOH_PROXY_AUTH_TOKEN");
    let doh_ech_auth_token = env_token("DOH_PROXY_ECH_AUTH_TOKEN");

    // Parse --server-ip <ip> argument
    let server_ip = args
        .iter()
        .position(|a| a == "--server-ip")
        .and_then(|i| args.get(i + 1))
        .cloned();

    // Parse --doh-routes-url <url>：加速服务端的路由表接口，有值即查表模式
    let doh_routes_url = args
        .iter()
        .position(|a| a == "--doh-routes-url")
        .and_then(|i| args.get(i + 1))
        .cloned();

    // Parse --select-mode <off|local_atlas|atlas_only>：本地优选模式。桌面二进制默认关，
    // App 的测试环境会用进程模式拉起它，不该在测试里真跑竞速
    let select_mode = args
        .iter()
        .position(|a| a == "--select-mode")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "off".to_string());

    let upstream_proxy = match (upstream_host, upstream_port) {
        (Some(host), Some(port)) if !host.trim().is_empty() && port > 0 => {
            Some(UpstreamProxyConfig {
                protocol: upstream_protocol,
                host,
                port,
                username: upstream_username,
                password: upstream_password,
                cipher: upstream_cipher,
            })
        }
        _ => None,
    };

    let config = ProxyConfig {
        bind_port: port,
        enable_doh,
        gateway_mode,
        prefer_ipv6,
        doh_server,
        doh_server_ech,
        doh_bootstrap_ips,
        doh_ech_bootstrap_ips,
        doh_auth_token,
        doh_ech_auth_token,
        upstream_proxy,
        server_ip,
        h2_mitm,
        doh_routes_url,
        select_mode,
        ..Default::default()
    };

    let server_ip_str = config.server_ip.as_deref().unwrap_or("auto");
    let doh_ech_str = config.doh_server_ech.as_deref().unwrap_or("(same as dns)");
    if let Some(proxy) = config.upstream_proxy.as_ref() {
        info!(
            "Config: bind_port={}, enable_doh={}, prefer_ipv6={}, doh_server={}, doh_server_ech={}, server_ip={}, upstream={}://{}:{}",
            config.bind_port,
            config.enable_doh,
            config.prefer_ipv6,
            config.doh_server,
            doh_ech_str,
            server_ip_str,
            proxy.protocol(),
            proxy.host,
            proxy.port
        );
    } else {
        info!(
            "Config: bind_port={}, enable_doh={}, prefer_ipv6={}, doh_server={}, doh_server_ech={}, server_ip={}, upstream=disabled",
            config.bind_port, config.enable_doh, config.prefer_ipv6, config.doh_server, doh_ech_str, server_ip_str
        );
    }

    // Create and start server
    let server = DohProxyServer::new(config).await?;

    info!("Server starting...");

    // 进程模式没有 FFI，令牌被拒时在 stdout 打一行标记，由 App 读取后重新申请令牌；
    // 新拉到的路由表 / 节点列表也打一行单行 JSON，由 App 持久化
    tokio::spawn(async {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            if doh_proxy::dns::DnsResolver::take_auth_rejected() {
                println!("DOH_AUTH_REJECTED");
            }
            if let Some(update) = doh_proxy::dns::DnsResolver::take_accel_update() {
                let json = serde_json::json!({
                    "route_table": update.route_table,
                    "nodes": update.nodes,
                    "nodes_envelope": update.nodes_envelope,
                });
                println!("DOH_ACCEL_UPDATE {}", json);
            }
        }
    });

    // Handle Ctrl+C
    let server_handle = server;
    tokio::select! {
        result = server_handle.start() => {
            if let Err(e) = result {
                eprintln!("Server error: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received Ctrl+C, shutting down...");
            server_handle.stop();
        }
    }

    Ok(())
}
