//! FFI bindings for mobile platforms (Android/iOS)
//!
//! These functions are called from Dart via FFI.

use crate::{DohProxyServer, ProxyConfig};
use std::ffi::{c_char, c_int, CStr};
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::RwLock;

static RUNTIME: std::sync::OnceLock<Runtime> = std::sync::OnceLock::new();
static SERVER: std::sync::OnceLock<Arc<RwLock<Option<Arc<DohProxyServer>>>>> =
    std::sync::OnceLock::new();
static PORT: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create Tokio runtime")
    })
}

fn get_server_holder() -> &'static Arc<RwLock<Option<Arc<DohProxyServer>>>> {
    SERVER.get_or_init(|| Arc::new(RwLock::new(None)))
}

fn parse_required_string(
    ptr: *const c_char,
    field_name: &str,
) -> std::result::Result<String, String> {
    if ptr.is_null() {
        return Err(format!("{} is null", field_name));
    }

    match unsafe { CStr::from_ptr(ptr) }.to_str() {
        Ok(s) if !s.trim().is_empty() => Ok(s.to_string()),
        _ => Err(format!("invalid {}", field_name)),
    }
}

/// FFI 用的 resolver：代理在跑且参数就是它那套 DoH 配置时，用代理建连的那个（带上游代理、
/// 同一份 EdgePin）；否则按参数取共享 resolver（不带上游代理）
async fn ffi_resolver(
    doh_url: &str,
    doh_url_ech: Option<&str>,
    prefer_ipv6: bool,
) -> crate::error::Result<Arc<crate::dns::DnsResolver>> {
    let running = get_server_holder()
        .read()
        .await
        .as_ref()
        .and_then(|server| server.resolver_for(doh_url, doh_url_ech, prefer_ipv6));
    match running {
        Some(resolver) => Ok(resolver),
        None => crate::dns::DnsResolver::shared(doh_url, doh_url_ech, prefer_ipv6, None).await,
    }
}

fn parse_optional_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }

    match unsafe { CStr::from_ptr(ptr) }.to_str() {
        Ok(s) if !s.trim().is_empty() => Some(s.to_string()),
        _ => None,
    }
}

/// Start the DOH proxy server with DOH server URL
/// Returns the port number on success, or -1 on failure
///
/// # Arguments
/// * `port` - Port to bind (0 for auto-select)
/// * `prefer_ipv6` - Whether to prefer IPv6 addresses
/// * `doh_server` - DOH server URL (null-terminated C string, or null for default)
#[no_mangle]
pub extern "C" fn doh_proxy_start_with_server(
    port: c_int,
    prefer_ipv6: c_int,
    doh_server: *const c_char,
) -> c_int {
    // Initialize logging
    doh_proxy_init_logging();

    // Parse DOH server URL from C string
    let doh_url = if doh_server.is_null() {
        "cloudflare".to_string()
    } else {
        match unsafe { CStr::from_ptr(doh_server) }.to_str() {
            Ok(s) if !s.is_empty() => s.to_string(),
            _ => "cloudflare".to_string(),
        }
    };

    let config = ProxyConfig {
        bind_port: port as u16,
        prefer_ipv6: prefer_ipv6 != 0,
        doh_server: doh_url,
        ..Default::default()
    };

    start_server_with_config(config)
}

/// Start the DOH proxy server with a JSON configuration payload
/// Returns the port number on success, or -1 on failure
#[no_mangle]
pub extern "C" fn doh_proxy_start_with_config_json(config_json: *const c_char) -> c_int {
    doh_proxy_init_logging();

    if config_json.is_null() {
        tracing::error!("Config JSON pointer is null");
        return -1;
    }

    let config_str = match unsafe { CStr::from_ptr(config_json) }.to_str() {
        Ok(value) if !value.trim().is_empty() => value,
        _ => {
            tracing::error!("Invalid config JSON string");
            return -1;
        }
    };

    let config: ProxyConfig = match serde_json::from_str(config_str) {
        Ok(config) => config,
        Err(error) => {
            tracing::error!("Failed to parse config JSON: {}", error);
            return -1;
        }
    };

    start_server_with_config(config)
}

/// Start the DOH proxy server (legacy API, uses Cloudflare DOH)
/// Returns the port number on success, or -1 on failure
#[no_mangle]
pub extern "C" fn doh_proxy_start(port: c_int, prefer_ipv6: c_int) -> c_int {
    // Initialize logging
    doh_proxy_init_logging();

    let config = ProxyConfig {
        bind_port: port as u16,
        prefer_ipv6: prefer_ipv6 != 0,
        ..Default::default()
    };

    start_server_with_config(config)
}

fn start_server_with_config(config: ProxyConfig) -> c_int {
    let rt = get_runtime();

    // Create the server
    let server = match rt.block_on(async { DohProxyServer::new(config).await }) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::error!("Failed to create DOH proxy server: {}", e);
            return -1;
        }
    };

    // Store the server
    let server_holder = get_server_holder();
    let server_clone = server.clone();
    rt.block_on(async {
        let mut guard = server_holder.write().await;
        *guard = Some(server);
    });

    // Start server in background
    rt.spawn(async move {
        if let Err(e) = server_clone.start().await {
            tracing::error!("DOH proxy server error: {}", e);
        }
    });

    // Wait a bit for server to bind
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Get the actual port
    let actual_port = rt.block_on(async {
        let guard = server_holder.read().await;
        if let Some(ref server) = *guard {
            server.port().unwrap_or(0) as c_int
        } else {
            0
        }
    });

    if actual_port > 0 {
        PORT.store(actual_port, std::sync::atomic::Ordering::SeqCst);
        tracing::info!("DOH proxy started on port {}", actual_port);
        actual_port
    } else {
        tracing::error!("Failed to get DOH proxy port");
        -1
    }
}

/// Stop the DOH proxy server
#[no_mangle]
pub extern "C" fn doh_proxy_stop() {
    let rt = get_runtime();
    let server_holder = get_server_holder();

    rt.block_on(async {
        let mut guard = server_holder.write().await;
        if let Some(ref server) = *guard {
            server.stop();
            tracing::info!("DOH proxy stopped");
        }
        *guard = None;
    });

    PORT.store(0, std::sync::atomic::Ordering::SeqCst);
}

/// Check if the DOH proxy is running
/// Returns 1 if running, 0 if not
#[no_mangle]
pub extern "C" fn doh_proxy_is_running() -> c_int {
    if PORT.load(std::sync::atomic::Ordering::SeqCst) > 0 {
        1
    } else {
        0
    }
}

/// Get the DOH proxy port
/// Returns the port number, or 0 if not running
#[no_mangle]
pub extern "C" fn doh_proxy_get_port() -> c_int {
    PORT.load(std::sync::atomic::Ordering::SeqCst)
}

/// Lookup ECH config for a host via DOH DNS HTTPS record.
/// Returns a pointer to a JSON string: {"ok":true,"data":"<base64>"} or {"ok":false,"error":"..."}
/// The caller must free the returned string with doh_proxy_free_string.
#[no_mangle]
pub extern "C" fn doh_proxy_lookup_ech_config(
    host: *const c_char,
    doh_server: *const c_char,
) -> *mut c_char {
    use base64::Engine;

    doh_proxy_init_logging();

    let host_str = match parse_required_string(host, "host") {
        Ok(value) => value,
        Err(message) => return error_json(&message),
    };
    let doh_url = parse_optional_string(doh_server)
        .unwrap_or_else(|| "https://cloudflare-dns.com/dns-query".to_string());

    let rt = get_runtime();
    let result = rt.block_on(async {
        let resolver = ffi_resolver(&doh_url, Some(&doh_url), false).await?;
        resolver.lookup_ech_config(&host_str).await
    });

    match result {
        Ok(Some(ech_bytes)) => {
            let b64 = base64::engine::general_purpose::STANDARD.encode(ech_bytes.as_ref());
            let json = format!(r#"{{"ok":true,"data":"{}"}}"#, b64);
            match std::ffi::CString::new(json) {
                Ok(c) => c.into_raw(),
                Err(_) => error_json("CString conversion failed"),
            }
        }
        Ok(None) => error_json("no ECH config found"),
        Err(e) => error_json(&format!("{}", e)),
    }
}

/// Lookup IP addresses for a host via DOH A/AAAA records.
/// Returns a pointer to a JSON string:
/// {"ok":true,"data":["1.1.1.1","2606:4700:4700::1111"]} or {"ok":false,"error":"..."}
/// The caller must free the returned string with doh_proxy_free_string.
#[no_mangle]
pub extern "C" fn doh_proxy_lookup_ip(
    host: *const c_char,
    doh_server: *const c_char,
    prefer_ipv6: c_int,
) -> *mut c_char {
    doh_proxy_init_logging();

    let host_str = match parse_required_string(host, "host") {
        Ok(value) => value,
        Err(message) => return error_json(&message),
    };
    let doh_url = parse_optional_string(doh_server)
        .unwrap_or_else(|| "https://cloudflare-dns.com/dns-query".to_string());

    let rt = get_runtime();
    let result = rt.block_on(async {
        let resolver = ffi_resolver(&doh_url, Some(&doh_url), prefer_ipv6 != 0).await?;
        let addrs = resolver.lookup_ip(&host_str).await?;
        Ok::<_, crate::error::DohProxyError>(
            resolver.edge_pin().route(&host_str, addrs).app_addrs(),
        )
    });

    match result {
        Ok(addrs) => {
            let json = serde_json::json!({
                "ok": true,
                "data": addrs
                    .into_iter()
                    .map(|addr| addr.to_string())
                    .collect::<Vec<_>>(),
            })
            .to_string();
            match std::ffi::CString::new(json) {
                Ok(c) => c.into_raw(),
                Err(_) => error_json("CString conversion failed"),
            }
        }
        Err(e) => error_json(&format!("{}", e)),
    }
}

/// Lookup a host in one round-trip and return IPs, ECH config and TTL.
/// Returns:
/// {"ok":true,"ips":["1.1.1.1"],"ech":"<base64|null>","preferred_ip":"<ip|null>","pinned":false,"ttl_secs":300}
///
/// `pinned` 为 true 表示覆盖域名钉在优选赢家上：`ips` 是赢家及同族兜底，App 应原样使用，
/// 连接失败用 doh_proxy_report_host_failure 报回来，不要自己换 IP
#[no_mangle]
pub extern "C" fn doh_proxy_lookup_host(
    host: *const c_char,
    doh_server: *const c_char,
    doh_server_ech: *const c_char,
    prefer_ipv6: c_int,
    force_refresh: c_int,
) -> *mut c_char {
    use base64::Engine;

    doh_proxy_init_logging();

    let host_str = match parse_required_string(host, "host") {
        Ok(value) => value,
        Err(message) => return error_json(&message),
    };
    let doh_url = parse_optional_string(doh_server)
        .unwrap_or_else(|| "https://cloudflare-dns.com/dns-query".to_string());
    let doh_url_ech = parse_optional_string(doh_server_ech);

    let rt = get_runtime();
    let result = rt.block_on(async {
        let effective_doh_url_ech = doh_url_ech.as_deref().unwrap_or(doh_url.as_str());
        let resolver =
            ffi_resolver(&doh_url, Some(effective_doh_url_ech), prefer_ipv6 != 0).await?;
        resolver.lookup_host(&host_str, force_refresh != 0).await
    });

    match result {
        Ok(lookup) => {
            let ech = lookup
                .ech_config
                .as_ref()
                .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes.as_ref()));
            let json = serde_json::json!({
                "ok": true,
                "ips": lookup
                    .addrs
                    .into_iter()
                    .map(|addr| addr.to_string())
                    .collect::<Vec<_>>(),
                "ech": ech,
                "preferred_ip": lookup.preferred_ip.map(|addr| addr.to_string()),
                "pinned": lookup.pinned,
                "ttl_secs": lookup.ttl.as_secs(),
            })
            .to_string();
            match std::ffi::CString::new(json) {
                Ok(c) => c.into_raw(),
                Err(_) => error_json("CString conversion failed"),
            }
        }
        Err(e) => error_json(&format!("{}", e)),
    }
}

/// Record a successful host -> IP connection in the shared resolver's EdgePin
/// (sticky IP and address-family affinity; a pinned winner forces the affinity).
/// Returns 1 on success, 0 on failure.
#[no_mangle]
pub extern "C" fn doh_proxy_record_host_success(
    host: *const c_char,
    doh_server: *const c_char,
    doh_server_ech: *const c_char,
    prefer_ipv6: c_int,
    ip: *const c_char,
) -> c_int {
    doh_proxy_init_logging();

    let host_str = match parse_required_string(host, "host") {
        Ok(value) => value,
        Err(message) => {
            tracing::warn!("record_host_success: {}", message);
            return 0;
        }
    };
    let ip_str = match parse_required_string(ip, "ip") {
        Ok(value) => value,
        Err(message) => {
            tracing::warn!("record_host_success: {}", message);
            return 0;
        }
    };
    let ip_addr = match ip_str.parse::<std::net::IpAddr>() {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!("record_host_success: invalid ip '{}': {}", ip_str, error);
            return 0;
        }
    };

    let doh_url = parse_optional_string(doh_server)
        .unwrap_or_else(|| "https://cloudflare-dns.com/dns-query".to_string());
    let doh_url_ech = parse_optional_string(doh_server_ech);

    let rt = get_runtime();
    let result = rt.block_on(async {
        let effective_doh_url_ech = doh_url_ech.as_deref().unwrap_or(doh_url.as_str());
        let resolver =
            ffi_resolver(&doh_url, Some(effective_doh_url_ech), prefer_ipv6 != 0).await?;
        resolver.edge_pin().report(
            &host_str,
            ip_addr,
            crate::edge_pin::Outcome::Connected {
                rtt: None,
                took_over: false,
            },
        );
        Ok::<(), crate::error::DohProxyError>(())
    });

    if let Err(error) = result {
        tracing::warn!(
            "record_host_success failed for {} -> {}: {}",
            host_str,
            ip_str,
            error
        );
        0
    } else {
        1
    }
}

/// 报告 App 引擎连 host -> ip 失败：作废该域名的粘性 IP；ip 是钉住的赢家时计入它的连败
/// （60 s 内 3 次即解除钉住、重新优选）。参数同 doh_proxy_record_host_success。
/// Returns 1 on success, 0 on failure.
#[no_mangle]
pub extern "C" fn doh_proxy_report_host_failure(
    host: *const c_char,
    doh_server: *const c_char,
    doh_server_ech: *const c_char,
    prefer_ipv6: c_int,
    ip: *const c_char,
) -> c_int {
    doh_proxy_init_logging();

    let host_str = match parse_required_string(host, "host") {
        Ok(value) => value,
        Err(message) => {
            tracing::warn!("report_host_failure: {}", message);
            return 0;
        }
    };
    let ip_addr = match parse_required_string(ip, "ip")
        .and_then(|value| value.parse::<std::net::IpAddr>().map_err(|e| e.to_string()))
    {
        Ok(value) => value,
        Err(message) => {
            tracing::warn!("report_host_failure: invalid ip: {}", message);
            return 0;
        }
    };
    let doh_url = parse_optional_string(doh_server)
        .unwrap_or_else(|| "https://cloudflare-dns.com/dns-query".to_string());
    let doh_url_ech = parse_optional_string(doh_server_ech);

    let rt = get_runtime();
    let result = rt.block_on(async {
        let effective_doh_url_ech = doh_url_ech.as_deref().unwrap_or(doh_url.as_str());
        let resolver =
            ffi_resolver(&doh_url, Some(effective_doh_url_ech), prefer_ipv6 != 0).await?;
        resolver
            .edge_pin()
            .report(&host_str, ip_addr, crate::edge_pin::Outcome::Failed);
        Ok::<(), crate::error::DohProxyError>(())
    });

    if let Err(error) = result {
        tracing::warn!("report_host_failure failed for {}: {}", host_str, error);
        0
    } else {
        1
    }
}

/// Clear the shared preferred IP for a host.
/// Returns 1 on success, 0 on failure.
#[no_mangle]
pub extern "C" fn doh_proxy_clear_preferred_host_ip(
    host: *const c_char,
    doh_server: *const c_char,
    doh_server_ech: *const c_char,
    prefer_ipv6: c_int,
) -> c_int {
    doh_proxy_init_logging();

    let host_str = match parse_required_string(host, "host") {
        Ok(value) => value,
        Err(message) => {
            tracing::warn!("clear_preferred_host_ip: {}", message);
            return 0;
        }
    };
    let doh_url = parse_optional_string(doh_server)
        .unwrap_or_else(|| "https://cloudflare-dns.com/dns-query".to_string());
    let doh_url_ech = parse_optional_string(doh_server_ech);

    let rt = get_runtime();
    let result = rt.block_on(async {
        let effective_doh_url_ech = doh_url_ech.as_deref().unwrap_or(doh_url.as_str());
        let resolver =
            ffi_resolver(&doh_url, Some(effective_doh_url_ech), prefer_ipv6 != 0).await?;
        resolver.edge_pin().forget_host(&host_str);
        Ok::<(), crate::error::DohProxyError>(())
    });

    if let Err(error) = result {
        tracing::warn!("clear_preferred_host_ip failed for {}: {}", host_str, error);
        0
    } else {
        1
    }
}

#[no_mangle]
pub extern "C" fn doh_proxy_clear_dns_cache() -> c_int {
    doh_proxy_init_logging();

    let rt = get_runtime();
    rt.block_on(async {
        crate::dns::DnsResolver::clear_shared_caches().await;
    });
    1
}

/// 取出并清除「DoH 服务器拒绝了令牌」标记
/// Returns 1 if a token was rejected since the last call, 0 otherwise
#[no_mangle]
pub extern "C" fn doh_proxy_take_auth_rejected() -> c_int {
    if crate::dns::DnsResolver::take_auth_rejected() {
        1
    } else {
        0
    }
}

/// 取出并清空待 App 持久化的加速更新（新路由表原文 / 新节点列表）。
/// 返回 `{"ok":true,"route_table":<string|null>,"nodes":<string|null>,"nodes_envelope":{kid,payload,sig}|null}`；
/// 没有更新时三项都是 null。返回的字符串需要调用 doh_proxy_free_string 释放
#[no_mangle]
pub extern "C" fn doh_proxy_take_accel_update() -> *mut c_char {
    let update = crate::dns::DnsResolver::take_accel_update().unwrap_or_default();
    json_to_c_string(serde_json::json!({
        "ok": true,
        "route_table": update.route_table,
        "nodes": update.nodes,
        "nodes_envelope": update.nodes_envelope,
        "select_state": update.select_state,
        "report_auth_rejected": update.report_auth_rejected,
    }))
}

/// 网络变化通知（Dart 传连接类型集合的签名）。返回 1 受理、0 没有优选实例、-1 参数错
#[no_mangle]
pub extern "C" fn doh_proxy_network_changed(sig: *const c_char) -> c_int {
    let Some(sig) = parse_optional_string(sig) else {
        return -1;
    };
    match crate::select::Selector::global() {
        Some(selector) => {
            let _guard = get_runtime().enter();
            selector.on_network_changed(&sig);
            1
        }
        None => 0,
    }
}

/// 本地优选状态：`{"ok":true,"mode","phase","winner":{ip,latency_ms,verified_at,source,ech_source}|null,
/// "last_race_at","last_error","fail_streak","share"}`；没有实例时 `{"ok":false,"error":"no selector"}`。
/// 返回的字符串需要调用 doh_proxy_free_string 释放
#[no_mangle]
pub extern "C" fn doh_proxy_select_status() -> *mut c_char {
    match crate::select::Selector::global() {
        Some(selector) => json_to_c_string(selector.status_json()),
        None => error_json("no selector"),
    }
}

/// 手动重新优选。返回 1 已发车、0 冷却中 / 没有实例
#[no_mangle]
pub extern "C" fn doh_proxy_select_rerace() -> c_int {
    match crate::select::Selector::global() {
        Some(selector) => {
            let _guard = get_runtime().enter();
            if selector.request_rerace(true) {
                1
            } else {
                0
            }
        }
        None => 0,
    }
}

/// 开关「帮助优选」（把握手测量结果分享给 cfhub）。`bearer` 为 cfhub 令牌，关闭时可为 null。
/// 返回 1 已应用、0 没有实例。令牌不进日志
#[no_mangle]
pub extern "C" fn doh_proxy_set_share_measurements(enabled: c_int, bearer: *const c_char) -> c_int {
    match crate::select::Selector::global() {
        Some(selector) => {
            selector.set_share(enabled != 0, parse_optional_string(bearer).map(crate::Secret));
            1
        }
        None => 0,
    }
}

/// 经 DoH 同一套 HTTP 客户端发加速接口请求（令牌申请/续期等），让 Dart 侧不再有第二套 TLS 栈。
/// `headers_json` 为 `{"name":"value",...}` 或 null；`body` 为 UTF-8 字符串或 null。
/// 返回 `{"ok":true,"status":<u16>,"body":"<string>"}`，或 `{"ok":false,"error":"..."}`。
/// 返回的字符串需要调用 doh_proxy_free_string 释放
#[no_mangle]
pub extern "C" fn doh_proxy_accel_request(
    method: *const c_char,
    url: *const c_char,
    headers_json: *const c_char,
    body: *const c_char,
) -> *mut c_char {
    doh_proxy_init_logging();

    let method = match parse_required_string(method, "method") {
        Ok(value) => value,
        Err(message) => return error_json(&message),
    };
    let url = match parse_required_string(url, "url") {
        Ok(value) => value,
        Err(message) => return error_json(&message),
    };
    let headers: Vec<(String, String)> = match parse_optional_string(headers_json) {
        Some(raw) => match serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&raw)
        {
            Ok(map) => map
                .into_iter()
                .filter_map(|(name, value)| match value {
                    serde_json::Value::String(value) => Some((name, value)),
                    serde_json::Value::Null => None,
                    other => Some((name, other.to_string())),
                })
                .collect(),
            Err(e) => return error_json(&format!("Invalid headers JSON: {}", e)),
        },
        None => Vec::new(),
    };
    let body = parse_optional_string(body);

    let rt = get_runtime();
    let result = rt.block_on(crate::dns::DnsResolver::accel_request(
        &method,
        &url,
        &headers,
        body.as_deref().map(str::as_bytes),
    ));

    match result {
        Ok(response) => json_to_c_string(serde_json::json!({
            "ok": true,
            "status": response.status,
            "body": response.body,
        })),
        Err(e) => error_json(&format!("{}", e)),
    }
}

/// Return shared DNS resolver cache statistics.
/// The caller must free the returned string with doh_proxy_free_string.
#[no_mangle]
pub extern "C" fn doh_proxy_dns_cache_stats() -> *mut c_char {
    doh_proxy_init_logging();

    let rt = get_runtime();
    let stats = rt.block_on(async {
        let current_stats = {
            let server_holder = get_server_holder();
            let guard = server_holder.read().await;
            guard.as_ref().map(|server| server.dns_cache_stats())
        };
        if let Some(stats) = current_stats {
            stats
        } else {
            crate::dns::DnsResolver::shared_cache_stats().await
        }
    });
    let json = serde_json::json!({
        "ok": true,
        "resolver_count": stats.resolver_count,
        "host_count": stats.host_count,
        "ip_count": stats.ip_count,
        "ech_count": stats.ech_count,
        "ech_negative_count": stats.ech_negative_count,
        "ip_rtt_count": stats.ip_rtt_count,
        "preferred_ip_count": stats.preferred_ip_count,
        "total_entries": stats.total_entries(),
    })
    .to_string();

    match std::ffi::CString::new(json) {
        Ok(c) => c.into_raw(),
        Err(_) => error_json("CString conversion failed"),
    }
}

/// 当前代理为 `host` 签发（或将要签发）的 MITM 叶子证书 PEM。
/// 返回 JSON：{"ok":true,"pem":"..."} 或 {"ok":false,"error":"..."}；
/// Linux 的 WPE WebView 用它逐主机精确放行，代理重启后叶子会变，要重新取。
/// The caller must free the returned string with doh_proxy_free_string.
#[no_mangle]
pub extern "C" fn doh_proxy_mitm_leaf_pem(host: *const c_char) -> *mut c_char {
    if host.is_null() {
        return error_json("host is null");
    }
    let host = match unsafe { CStr::from_ptr(host) }.to_str() {
        Ok(h) if !h.trim().is_empty() => h.trim().to_ascii_lowercase(),
        _ => return error_json("invalid host"),
    };
    let rt = get_runtime();
    let cert_manager = rt.block_on(async {
        let guard = get_server_holder().read().await;
        guard.as_ref().and_then(|server| server.cert_manager().cloned())
    });
    let Some(cert_manager) = cert_manager else {
        return error_json("proxy not running or MITM disabled");
    };
    match cert_manager.leaf_cert_pem(&host) {
        Ok(pem) => json_to_c_string(serde_json::json!({ "ok": true, "pem": pem })),
        Err(e) => error_json(&format!("{}", e)),
    }
}

/// Return shared DNS resolver cache records.
/// The caller must free the returned string with doh_proxy_free_string.
#[no_mangle]
pub extern "C" fn doh_proxy_dns_cache_records() -> *mut c_char {
    doh_proxy_init_logging();

    let rt = get_runtime();
    let records = rt.block_on(async {
        let current_records = {
            let server_holder = get_server_holder();
            let guard = server_holder.read().await;
            guard.as_ref().map(|server| server.dns_cache_records())
        };
        if let Some(records) = current_records {
            records
        } else {
            crate::dns::DnsResolver::shared_cache_records().await
        }
    });
    let records_json: Vec<_> = records
        .into_iter()
        .map(|record| {
            serde_json::json!({
                "host": record.host,
                "kind": record.kind,
                "values": record.values,
                "ttl_ms": record.ttl_ms,
            })
        })
        .collect();
    let json = serde_json::json!({
        "ok": true,
        "records": records_json,
    })
    .to_string();

    match std::ffi::CString::new(json) {
        Ok(c) => c.into_raw(),
        Err(_) => error_json("CString conversion failed"),
    }
}

/// Generate a new CA certificate key pair.
/// Returns a pointer to a JSON string: {"ok":true,"cert_pem":"...","key_pem":"..."}
/// or {"ok":false,"error":"..."}
/// The caller must free the returned string with doh_proxy_free_string.
#[no_mangle]
pub extern "C" fn doh_proxy_generate_ca() -> *mut c_char {
    doh_proxy_init_logging();

    match crate::cert::CertManager::generate_ca_pem() {
        Ok((cert_pem, key_pem)) => {
            let json = serde_json::json!({
                "ok": true,
                "cert_pem": cert_pem,
                "key_pem": key_pem,
            })
            .to_string();
            match std::ffi::CString::new(json) {
                Ok(c) => c.into_raw(),
                Err(_) => error_json("CString conversion failed"),
            }
        }
        Err(e) => error_json(&format!("{}", e)),
    }
}

/// 获取编译时嵌入的 CA 证书 PEM
///
/// 返回的字符串需要调用 doh_proxy_free_string 释放
#[no_mangle]
pub extern "C" fn doh_proxy_get_embedded_ca_pem() -> *mut c_char {
    let pem = crate::cert::CertManager::get_embedded_ca_pem();
    match std::ffi::CString::new(pem) {
        Ok(c) => c.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free a string returned by doh_proxy_lookup_ech_config / doh_proxy_lookup_ip / doh_proxy_lookup_host
#[no_mangle]
pub extern "C" fn doh_proxy_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = std::ffi::CString::from_raw(ptr);
        }
    }
}

fn error_json(msg: &str) -> *mut c_char {
    json_to_c_string(serde_json::json!({ "ok": false, "error": msg }))
}

fn json_to_c_string(value: serde_json::Value) -> *mut c_char {
    match std::ffi::CString::new(value.to_string()) {
        Ok(c) => c.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Initialize logging (call once at startup)
#[no_mangle]
pub extern "C" fn doh_proxy_init_logging() {
    #[cfg(target_os = "android")]
    {
        use tracing_subscriber::prelude::*;
        use tracing_subscriber::EnvFilter;
        let filter = EnvFilter::from_default_env()
            .add_directive("doh_proxy=info".parse().unwrap())
            // 本地优选的逐 IP / 逐 DoH 结果开 debug：真机排障全靠这些行
            .add_directive("doh_proxy::select=debug".parse().unwrap())
            .add_directive("doh_proxy::probe=debug".parse().unwrap())
            .add_directive("rustls=warn".parse().unwrap())
            .add_directive("hickory_resolver=info".parse().unwrap())
            .add_directive("hickory_proto=warn".parse().unwrap())
            .add_directive("reqwest=warn".parse().unwrap());
        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(tracing_android::layer("DohProxy").unwrap())
            .try_init();
    }

    #[cfg(not(target_os = "android"))]
    {
        use tracing_subscriber::{fmt, prelude::*, EnvFilter};
        let _ = tracing_subscriber::registry()
            .with(fmt::layer().with_ansi(false))
            .with(
                EnvFilter::from_default_env()
                    .add_directive("doh_proxy=info".parse().unwrap_or_default()),
            )
            .try_init();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    /// 配了上游代理时，代理的 resolver key 带上游代理，FFI 按参数重建的 key 不带：以前 App 回报的
    /// 成功 / 失败记到了另一个 resolver 上，代理看不到。现在要落到运行中代理建连用的那份 EdgePin
    #[test]
    fn ffi_reports_reach_running_proxy_state_with_upstream() {
        // DoH 地址用 IP 字面量（不查系统 DNS），主机名别和其他测试的 127.0.0.1 撞上
        let doh = "https://127.0.0.2:9/dns-query";
        let config = CString::new(
            serde_json::json!({
                "bind_addr": "127.0.0.1",
                "bind_port": 0,
                "doh_server": doh,
                "prefer_ipv6": false,
                "timeout_secs": 5,
                "upstream_proxy": {"protocol": "http", "host": "127.0.0.1", "port": 9},
            })
            .to_string(),
        )
        .unwrap();
        assert!(doh_proxy_start_with_config_json(config.as_ptr()) > 0);
        let running = get_runtime()
            .block_on(async {
                get_server_holder()
                    .read()
                    .await
                    .as_ref()
                    .and_then(|server| server.resolver_for(doh, None, false))
            })
            .expect("running proxy resolver");

        // 参数和 Dart 一样：ECH 服务器没单独设时传 DNS 服务器本身
        let host = CString::new("cdk.linux.do").unwrap();
        let doh_c = CString::new(doh).unwrap();
        let ip = CString::new("104.21.0.5").unwrap();
        let record = doh_proxy_record_host_success(
            host.as_ptr(),
            doh_c.as_ptr(),
            doh_c.as_ptr(),
            0,
            ip.as_ptr(),
        );
        assert_eq!(record, 1);
        let edge = running.edge_pin();
        assert_eq!(edge.sticky("cdk.linux.do"), "104.21.0.5".parse().ok());
        assert_eq!(edge.affinity(), Some(false));

        // 按参数重建的那个（不带上游代理）是另一个 resolver，什么也没收到
        let keyed = get_runtime()
            .block_on(crate::dns::DnsResolver::shared(doh, Some(doh), false, None))
            .unwrap();
        assert!(!Arc::ptr_eq(&keyed, &running));
        assert_eq!(keyed.edge_pin().sticky("cdk.linux.do"), None);

        let failure = doh_proxy_report_host_failure(
            host.as_ptr(),
            doh_c.as_ptr(),
            doh_c.as_ptr(),
            0,
            ip.as_ptr(),
        );
        assert_eq!(failure, 1);
        assert_eq!(edge.sticky("cdk.linux.do"), None);

        // 地址族偏好不一致不是同一套配置：不碰运行中代理的状态
        let other = doh_proxy_record_host_success(
            host.as_ptr(),
            doh_c.as_ptr(),
            doh_c.as_ptr(),
            1,
            ip.as_ptr(),
        );
        assert_eq!(other, 1);
        assert_eq!(edge.sticky("cdk.linux.do"), None);

        doh_proxy_stop();
    }
}
