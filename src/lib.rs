//! DOH Proxy - DNS over HTTPS proxy with ECH support
//!
//! This library provides a local HTTP/HTTPS proxy that uses DOH for DNS
//! resolution and supports ECH to encrypt the SNI field in TLS handshakes.

use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

pub mod cert;
pub mod cfnet;
pub mod dns;
pub mod ech;
pub mod error;
pub mod ffi;
pub mod probe;
pub mod proxy;
pub mod select;
pub mod tls_crypto;
pub mod upstream;

pub use error::DohProxyError;
pub use proxy::DohProxyServer;

/// Upstream proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamProxyConfig {
    /// Upstream proxy protocol. Supports `http`, `socks5` and `shadowsocks`.
    #[serde(default = "default_upstream_protocol")]
    pub protocol: String,
    /// Upstream proxy host
    pub host: String,
    /// Upstream proxy port
    pub port: u16,
    /// Optional username
    #[serde(default)]
    pub username: Option<String>,
    /// Optional password
    #[serde(default)]
    pub password: Option<String>,
    /// Optional cipher for Shadowsocks
    #[serde(default)]
    pub cipher: Option<String>,
}

impl UpstreamProxyConfig {
    pub fn is_valid(&self) -> bool {
        if self.host.trim().is_empty() || self.port == 0 {
            return false;
        }

        if self.is_shadowsocks() {
            let cipher = self.cipher.as_deref().map(str::trim).unwrap_or_default();
            let password = self.password.as_deref().map(str::trim).unwrap_or_default();
            if cipher.is_empty() || password.is_empty() {
                return false;
            }

            if cipher.eq_ignore_ascii_case("2022-blake3-aes-256-gcm") {
                let normalized_password = normalize_base64_padding(password);
                let decoded = STANDARD
                    .decode(normalized_password.as_bytes())
                    .or_else(|_| URL_SAFE.decode(normalized_password.as_bytes()));
                let Ok(decoded) = decoded else {
                    return false;
                };
                return decoded.len() == 32;
            }

            return true;
        }

        true
    }

    pub fn protocol(&self) -> &str {
        let protocol = self.protocol.trim();
        if protocol.is_empty() {
            "http"
        } else {
            protocol
        }
    }

    pub fn is_http(&self) -> bool {
        self.protocol().eq_ignore_ascii_case("http")
    }

    pub fn is_socks5(&self) -> bool {
        matches!(
            self.protocol().to_ascii_lowercase().as_str(),
            "socks" | "socks5" | "socks5h"
        )
    }

    pub fn is_shadowsocks(&self) -> bool {
        matches!(
            self.protocol().to_ascii_lowercase().as_str(),
            "ss" | "shadowsocks"
        )
    }

    pub fn cache_key(&self) -> String {
        let username = self.username.as_deref().map(str::trim).unwrap_or_default();
        let password = self.password.as_deref().map(str::trim).unwrap_or_default();
        let cipher = self.cipher.as_deref().map(str::trim).unwrap_or_default();
        format!(
            "{}|{}|{}|{}|{}|{}",
            self.protocol().to_ascii_lowercase(),
            self.host.trim().to_ascii_lowercase(),
            self.port,
            username,
            password,
            cipher,
        )
    }
}


/// 不能进日志的字符串（令牌等）：Debug 固定打 "***"
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(pub String);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("***")
    }
}

/// 候选收集用的公共 DoH 服务器
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PublicDohServerConfig {
    pub url: String,
    #[serde(default)]
    pub bootstrap_ips: Vec<String>,
}

/// Proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Local address to bind (default: 127.0.0.1)
    pub bind_addr: String,
    /// Local port to bind (default: 0 for auto-select)
    pub bind_port: u16,
    /// Whether local gateway should use DoH/ECH MITM mode
    #[serde(default = "default_enable_doh")]
    pub enable_doh: bool,
    /// DOH server URL for DNS queries (A/AAAA records)
    pub doh_server: String,
    /// Optional separate DOH server URL for ECH config (HTTPS records)
    /// When None, uses the same server as doh_server
    #[serde(default)]
    pub doh_server_ech: Option<String>,
    /// doh_server 的备用节点 IP：系统 DNS 解析不出或连不上 DoH 域名时直连这些 IP（SNI 不变）
    #[serde(default)]
    pub doh_bootstrap_ips: Vec<String>,
    /// doh_server_ech 的备用节点 IP
    #[serde(default)]
    pub doh_ech_bootstrap_ips: Vec<String>,
    /// doh_server 的访问令牌，查询时放在 `Authorization: Bearer` 里
    #[serde(default)]
    pub doh_auth_token: Option<String>,
    /// doh_server_ech 的访问令牌
    #[serde(default)]
    pub doh_ech_auth_token: Option<String>,
    /// Whether to prefer IPv6
    pub prefer_ipv6: bool,
    /// Connection timeout in seconds
    pub timeout_secs: u64,
    /// Optional upstream proxy configuration
    #[serde(default)]
    pub upstream_proxy: Option<UpstreamProxyConfig>,
    /// Optional server IP address to connect directly, skipping DNS resolution
    #[serde(default)]
    pub server_ip: Option<String>,
    /// Gateway (reverse proxy) mode: accept plain HTTP, forward via TLS+ECH
    /// Eliminates double TLS overhead compared to MITM mode
    #[serde(default)]
    pub gateway_mode: bool,
    /// Whether CONNECT requests should use MITM (true) or plain tunnel (false).
    /// Plain tunnel mode: DOH resolution + raw TCP forwarding, client does end-to-end TLS.
    /// iOS requires plain tunnel because WKWebView's TLS challenge callback is too slow for MITM.
    #[serde(default = "default_true")]
    pub mitm_connect: bool,
    /// WebView MITM 是否启用 HTTP/2：client 协商 h2 时用 hyper 转发实现多路复用；
    /// 关闭则保持裸字节拷贝（锁 http/1.1）。默认关闭，需实测 CF 指纹后再开。
    #[serde(default)]
    pub h2_mitm: bool,
    /// Optional runtime CA certificate PEM (per-device CA for iOS)
    #[serde(default)]
    pub ca_cert_pem: Option<String>,
    /// Optional runtime CA private key PEM (per-device CA for iOS)
    #[serde(default)]
    pub ca_key_pem: Option<String>,
    /// 路由表接口地址（加速服务端 `GET /v1/routes`）。有值时进入查表模式：
    /// 表内域名直接用表里的 IP，不发 DoH；None 则和以前一样全部走 DoH
    #[serde(default)]
    pub doh_routes_url: Option<String>,
    /// App 持久化的上一份路由表原文（JSON），启动时先用它，后台再刷新
    #[serde(default)]
    pub doh_route_table_json: Option<String>,
    /// App 持久化的签名节点列表信封（JSON `{kid,payload,sig}`），启动时重新验签后生效
    #[serde(default)]
    pub doh_node_list_json: Option<String>,
    /// 本地优选模式："off" | "local_atlas"（默认）| "atlas_only"
    #[serde(default = "default_select_mode")]
    pub select_mode: String,
    /// App 持久化的优选状态 JSON，启动时回灌
    #[serde(default)]
    pub select_state_json: Option<String>,
    /// 是否把握手测量结果分享给 cfhub（默认关）
    #[serde(default)]
    pub share_measurements: bool,
    /// atlas 池地址（`GET /v1/routes`）；None 表示不拉 atlas
    #[serde(default)]
    pub atlas_routes_url: Option<String>,
    /// 候选收集用的国内公共 DoH；为空时用内置的 doh.pub / AliDNS
    #[serde(default)]
    pub public_doh: Vec<PublicDohServerConfig>,
    /// 上报地址（cfhub6 的 `/api/v1/probe/report`）
    #[serde(default)]
    pub report_url: Option<String>,
    /// 上报用的 cfhub 令牌；Debug 输出为 "***"
    #[serde(default)]
    pub report_bearer: Option<Secret>,
    /// 除 linux.do 外也走赢家 IP 的主机名（atlas、cfhub6）
    #[serde(default)]
    pub extra_covered_hosts: Vec<String>,
    /// App 版本，上报里的 version 为 "cfluxdo/<app_version>"
    #[serde(default)]
    pub app_version: Option<String>,
    /// 启动时的网络签名（Dart 的连接类型集合）
    #[serde(default)]
    pub network_sig: Option<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1".to_string(),
            bind_port: 0,
            enable_doh: true,
            doh_server: "https://cloudflare-dns.com/dns-query".to_string(),
            doh_server_ech: None,
            doh_bootstrap_ips: Vec::new(),
            doh_ech_bootstrap_ips: Vec::new(),
            doh_auth_token: None,
            doh_ech_auth_token: None,
            prefer_ipv6: false,
            timeout_secs: 30,
            upstream_proxy: None,
            server_ip: None,
            gateway_mode: false,
            mitm_connect: true,
            h2_mitm: false,
            ca_cert_pem: None,
            ca_key_pem: None,
            doh_routes_url: None,
            doh_route_table_json: None,
            doh_node_list_json: None,
            select_mode: default_select_mode(),
            select_state_json: None,
            share_measurements: false,
            atlas_routes_url: None,
            public_doh: Vec::new(),
            report_url: None,
            report_bearer: None,
            extra_covered_hosts: Vec::new(),
            app_version: None,
            network_sig: None,
        }
    }
}

fn default_upstream_protocol() -> String {
    "http".to_string()
}

fn default_enable_doh() -> bool {
    true
}

fn default_select_mode() -> String {
    "local_atlas".to_string()
}

fn default_true() -> bool {
    true
}

fn normalize_base64_padding(input: &str) -> String {
    let trimmed = input.trim();
    let remainder = trimmed.len() % 4;
    if remainder == 0 {
        return trimmed.to_string();
    }

    let mut normalized = String::with_capacity(trimmed.len() + (4 - remainder));
    normalized.push_str(trimmed);
    for _ in 0..(4 - remainder) {
        normalized.push('=');
    }
    normalized
}

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

pub type BoxStream = Box<dyn AsyncReadWrite>;
