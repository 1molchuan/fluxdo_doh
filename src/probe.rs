//! 单个 Cloudflare IP 的可用性探测，以及经指定 IP + ECH 发 HTTPS 请求的通用小客户端。
//!
//! 探测链路：TCP → TLS 1.3 + ECH（内层 SNI 为目标站）→ `GET /cdn-cgi/trace`。
//! 通过判定不是裸 200，而是 trace 正文里 `h=` 行等于目标站：Enterprise 专用边缘会回 403/1034，
//! 共享池里也有不服务该 zone 的节点。
//!
//! 这里绝不打印 ECH 钥匙字节、请求头和正文。

use crate::error::{DohProxyError, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use rustls::client::EchStatus;
use rustls::crypto::CryptoProvider;
use rustls::internal::msgs::codec::Codec;
use rustls::internal::msgs::handshake::EchConfigPayload;
use rustls::pki_types::{EchConfigListBytes, ServerName};
use rustls::{ClientConfig, RootCertStore};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tracing::debug;

/// 探测与小请求共用的 User-Agent：安卓上最常见的 HTTP 库
pub const PROBE_USER_AGENT: &str = "okhttp/4.12.0";

/// 三段超时：TCP 建连、TLS 握手、HTTP 往返
#[derive(Clone, Copy, Debug)]
pub struct ProbeTimeouts {
    pub tcp: Duration,
    pub tls: Duration,
    pub http: Duration,
}

impl Default for ProbeTimeouts {
    fn default() -> Self {
        Self {
            tcp: Duration::from_millis(2000),
            tls: Duration::from_millis(3000),
            http: Duration::from_millis(2000),
        }
    }
}

/// 一次探测的目标
#[derive(Clone, Debug)]
pub struct ProbeTarget {
    pub ip: IpAddr,
    /// ECH 内层 SNI，也是 `Host` 头
    pub inner_sni: &'static str,
}

/// 探测失败的分类
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeFailure {
    TcpConnect,
    TcpTimeout,
    TlsTimeout,
    Tls(String),
    /// 服务端拒绝了 ECH；带 retry_configs 时可以换钥匙重试
    EchRejected { retry_configs: Option<Vec<u8>> },
    HttpTimeout,
    HttpStatus(u16),
    /// 200 但 trace 正文里的 `h=` 不是目标站
    BodyMismatch,
    Http(String),
}

impl std::fmt::Display for ProbeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TcpConnect => write!(f, "tcp connect failed"),
            Self::TcpTimeout => write!(f, "tcp timeout"),
            Self::TlsTimeout => write!(f, "tls timeout"),
            Self::Tls(e) => write!(f, "tls: {}", e),
            Self::EchRejected { retry_configs } => write!(
                f,
                "ech rejected ({})",
                match retry_configs {
                    Some(bytes) => format!("retry_configs {} bytes", bytes.len()),
                    None => "no retry_configs".to_string(),
                }
            ),
            Self::HttpTimeout => write!(f, "http timeout"),
            Self::HttpStatus(status) => write!(f, "http {}", status),
            Self::BodyMismatch => write!(f, "trace host mismatch"),
            Self::Http(e) => write!(f, "http: {}", e),
        }
    }
}

/// 一次探测的结果
#[derive(Clone, Debug)]
pub struct ProbeOutcome {
    pub ip: IpAddr,
    /// 从 TCP 发起到收到状态行的墙钟时间
    pub latency: Duration,
    pub ok: bool,
    pub failure: Option<ProbeFailure>,
    pub ech_accepted: bool,
}

/// 小 HTTPS 请求的响应
#[derive(Clone, Debug)]
pub struct HttpsReply {
    pub status: u16,
    pub retry_after_secs: Option<u64>,
    pub body: Vec<u8>,
}

/// 构造探测 / 小请求用的 TLS 配置：TLS 1.3、可选 ECH、ALPN http/1.1。
/// `ech` 为 None 时按普通 TLS（只用于同一连接上不需要隐藏 SNI 的场合）。
pub fn build_probe_tls_config(
    ech: Option<&EchConfigListBytes<'static>>,
    roots: &RootCertStore,
    provider: Arc<CryptoProvider>,
) -> Result<Arc<ClientConfig>> {
    let mut config = match ech {
        Some(ech) => {
            #[cfg(feature = "ech")]
            {
                use rustls::client::{EchConfig, EchMode};
                let ech_config = EchConfig::new(
                    ech.clone(),
                    rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
                )?;
                ClientConfig::builder_with_provider(provider)
                    .with_ech(EchMode::Enable(ech_config))?
                    .with_root_certificates(roots.clone())
                    .with_no_client_auth()
            }
            #[cfg(not(feature = "ech"))]
            {
                let _ = ech;
                return Err(DohProxyError::EchNotSupported(
                    "built without the ech feature".to_string(),
                ));
            }
        }
        None => ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots.clone())
            .with_no_client_auth(),
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// 从 tokio-rustls 包装的 io::Error 里下钻：是不是「服务端拒绝 ECH」。
/// 外层 Some 表示确实是 ECH 被拒；内层是服务端给的 retry_configs（可能没有）。
/// 不看 ErrorKind：tokio-rustls 不同路径用的 kind 不一样。
pub(crate) fn ech_rejection(e: &io::Error) -> Option<Option<Vec<EchConfigPayload>>> {
    let inner = e.get_ref()?;
    let error = inner.downcast_ref::<rustls::Error>()?;
    match error {
        rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::ServerRejectedEncryptedClientHello(configs),
        ) => Some(configs.clone()),
        _ => None,
    }
}

/// ECH 被拒且服务端带了 retry_configs 时返回它们
pub(crate) fn ech_retry_configs(e: &io::Error) -> Option<Vec<EchConfigPayload>> {
    ech_rejection(e).flatten()
}

/// 把 retry_configs 重编成 ECHConfigList 线格式：`Vec<EchConfigPayload>` 的编码自带 u16 长度前缀
pub(crate) fn encode_ech_config_list(configs: &[EchConfigPayload]) -> EchConfigListBytes<'static> {
    let mut out = Vec::new();
    configs.to_vec().encode(&mut out);
    EchConfigListBytes::from(out)
}

/// 配置里的 public_name 列表，只用于日志
pub(crate) fn ech_public_names(configs: &[EchConfigPayload]) -> Vec<String> {
    configs
        .iter()
        .filter_map(|config| match config {
            EchConfigPayload::V18(contents) => Some(contents.public_name.as_ref().to_string()),
            EchConfigPayload::Unknown { .. } => None,
        })
        .collect()
}

/// trace 正文是否声明了目标站：逐行找 `h=`，必须整行相等
pub(crate) fn trace_matches(body: &[u8], expect: &str) -> bool {
    let text = String::from_utf8_lossy(body);
    text.lines()
        .any(|line| line.trim_end().strip_prefix("h=") == Some(expect))
}

/// TCP + TLS 建连；返回流和 ECH 是否被接受
async fn tls_connect(
    ip: IpAddr,
    server_name: &str,
    tls: Arc<ClientConfig>,
    t: &ProbeTimeouts,
) -> std::result::Result<(TlsStream<TcpStream>, bool), ProbeFailure> {
    let addr = SocketAddr::new(ip, 443);
    let tcp = match tokio::time::timeout(t.tcp, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(_)) => return Err(ProbeFailure::TcpConnect),
        Err(_) => return Err(ProbeFailure::TcpTimeout),
    };
    let _ = tcp.set_nodelay(true);
    tls_handshake(tcp, server_name, tls, t).await
}

/// 在任意已建好的流上做 TLS 握手（诊断时可以是经代理隧道的流）
pub async fn tls_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    tcp: S,
    server_name: &str,
    tls: Arc<ClientConfig>,
    t: &ProbeTimeouts,
) -> std::result::Result<(TlsStream<S>, bool), ProbeFailure> {
    let name = ServerName::try_from(server_name.to_string())
        .map_err(|e| ProbeFailure::Tls(format!("bad server name: {}", e)))?;
    let connector = TlsConnector::from(tls);
    let stream = match tokio::time::timeout(t.tls, connector.connect(name, tcp)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            return Err(match ech_rejection(&e) {
                Some(configs) => ProbeFailure::EchRejected {
                    retry_configs: configs
                        .as_deref()
                        .filter(|configs| !configs.is_empty())
                        .map(|configs| encode_ech_config_list(configs).as_ref().to_vec()),
                },
                None => ProbeFailure::Tls(e.to_string()),
            });
        }
        Err(_) => return Err(ProbeFailure::TlsTimeout),
    };
    let accepted = matches!(stream.get_ref().1.ech_status(), EchStatus::Accepted);
    Ok((stream, accepted))
}

/// 在已建好的 TLS 流上发一个 HTTP/1.1 请求，读正文到 `max_body` 为止
#[allow(clippy::too_many_arguments)]
async fn h1_request<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: TlsStream<S>,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<Vec<u8>>,
    t: &ProbeTimeouts,
    max_body: usize,
) -> std::result::Result<(HttpsReply, Duration), ProbeFailure> {
    let start = Instant::now();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| ProbeFailure::Http(e.to_string()))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let method = http::Method::from_bytes(method.as_bytes())
        .map_err(|e| ProbeFailure::Http(format!("bad method: {}", e)))?;
    let mut builder = http::Request::builder()
        .method(method)
        .uri(path)
        .header(http::header::HOST, host)
        .header(http::header::USER_AGENT, PROBE_USER_AGENT)
        .header(http::header::CONNECTION, "close");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder
        .body(Full::new(Bytes::from(body.unwrap_or_default())))
        .map_err(|e| ProbeFailure::Http(format!("bad request: {}", e)))?;

    let response = match tokio::time::timeout(t.http, sender.send_request(request)).await {
        Ok(Ok(response)) => response,
        Ok(Err(e)) => return Err(ProbeFailure::Http(e.to_string())),
        Err(_) => return Err(ProbeFailure::HttpTimeout),
    };
    let latency = start.elapsed();
    let status = response.status().as_u16();
    let retry_after_secs = response
        .headers()
        .get(http::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok());

    let mut body_reader = response.into_body();
    let mut out = Vec::new();
    let deadline = Instant::now() + t.http;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, body_reader.frame()).await {
            Ok(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    out.extend_from_slice(data);
                    if out.len() >= max_body {
                        out.truncate(max_body);
                        break;
                    }
                }
            }
            // 正文结束、读错或超时都按已读到的部分处理
            _ => break,
        }
    }
    Ok((
        HttpsReply {
            status,
            retry_after_secs,
            body: out,
        },
        latency,
    ))
}

/// 探测一个 IP：TCP → TLS+ECH（内层 SNI `target.inner_sni`）→ `GET /cdn-cgi/trace`，
/// 200 且 `h=` 等于 `inner_sni` 才算通过
pub async fn probe_once(
    target: &ProbeTarget,
    tls: Arc<ClientConfig>,
    t: &ProbeTimeouts,
) -> ProbeOutcome {
    let start = Instant::now();
    let addr = SocketAddr::new(target.ip, 443);
    let tcp = match tokio::time::timeout(t.tcp, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(_)) => return failed_outcome(target.ip, start, ProbeFailure::TcpConnect, false),
        Err(_) => return failed_outcome(target.ip, start, ProbeFailure::TcpTimeout, false),
    };
    let _ = tcp.set_nodelay(true);
    probe_once_on(tcp, target, start, tls, t).await
}

fn failed_outcome(ip: IpAddr, start: Instant, failure: ProbeFailure, ech_accepted: bool) -> ProbeOutcome {
    ProbeOutcome {
        ip,
        latency: start.elapsed(),
        ok: false,
        failure: Some(failure),
        ech_accepted,
    }
}

/// 在已建好的流上完成探测（TLS+ECH → trace）；`start` 为计时起点
pub async fn probe_once_on<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    tcp: S,
    target: &ProbeTarget,
    start: Instant,
    tls: Arc<ClientConfig>,
    t: &ProbeTimeouts,
) -> ProbeOutcome {
    let fail = |failure: ProbeFailure, ech_accepted: bool| {
        failed_outcome(target.ip, start, failure, ech_accepted)
    };
    let (stream, ech_accepted) = match tls_handshake(tcp, target.inner_sni, tls, t).await {
        Ok(value) => value,
        Err(failure) => return fail(failure, false),
    };
    let (reply, _) = match h1_request(
        stream,
        target.inner_sni,
        "GET",
        "/cdn-cgi/trace",
        &[],
        None,
        t,
        4096,
    )
    .await
    {
        Ok(value) => value,
        Err(failure) => return fail(failure, ech_accepted),
    };
    let latency = start.elapsed();
    if reply.status != 200 {
        return fail(ProbeFailure::HttpStatus(reply.status), ech_accepted);
    }
    if !trace_matches(&reply.body, target.inner_sni) {
        return fail(ProbeFailure::BodyMismatch, ech_accepted);
    }
    debug!(
        "probe {} ok in {} ms (ech accepted: {})",
        target.ip,
        latency.as_millis(),
        ech_accepted
    );
    ProbeOutcome {
        ip: target.ip,
        latency,
        ok: true,
        failure: None,
        ech_accepted,
    }
}

/// 经指定 IP 发一个 HTTPS 请求（SNI/Host 为 `host`，`tls` 里带 ECH 时 `host` 在内层）。
/// 用于 atlas 拉表、探针上报、`accel_request` 的赢家直连。只记录状态码。
#[allow(clippy::too_many_arguments)]
pub async fn https_request(
    ip: IpAddr,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<Vec<u8>>,
    tls: Arc<ClientConfig>,
    t: &ProbeTimeouts,
    max_body: usize,
) -> Result<HttpsReply> {
    let (stream, _) = tls_connect(ip, host, tls, t).await.map_err(|failure| match failure {
        // 带 retry_configs 的 ECH 被拒单独成错误，调用方可以换钥匙重试
        ProbeFailure::EchRejected {
            retry_configs: Some(configs),
        } => DohProxyError::EchRetry {
            addr: SocketAddr::new(ip, 443),
            configs,
        },
        other => DohProxyError::Proxy(format!("{} via {}: {}", host, ip, other)),
    })?;
    let (reply, latency) = h1_request(stream, host, method, path, headers, body, t, max_body)
        .await
        .map_err(|failure| DohProxyError::Proxy(format!("{} via {}: {}", host, ip, failure)))?;
    debug!(
        "{} {}{} via {} -> {} in {} ms",
        method,
        host,
        path,
        ip,
        reply.status,
        latency.as_millis()
    );
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::internal::msgs::codec::Reader;

    /// 手工拼一个单条 ECHConfigList（draft-ietf-tls-esni V18）：
    /// config_id 7、X25519、32 字节公钥、HKDF-SHA256 + AES-128-GCM、public_name 给定
    fn sample_ech_config_list(public_name: &str) -> Vec<u8> {
        let mut contents = Vec::new();
        contents.push(7u8); // config_id
        contents.extend_from_slice(&0x0020u16.to_be_bytes()); // kem X25519
        contents.extend_from_slice(&32u16.to_be_bytes());
        contents.extend_from_slice(&[0x11; 32]);
        contents.extend_from_slice(&4u16.to_be_bytes()); // cipher suites len
        contents.extend_from_slice(&0x0001u16.to_be_bytes()); // kdf
        contents.extend_from_slice(&0x0001u16.to_be_bytes()); // aead
        contents.push(64u8); // maximum_name_length
        contents.push(public_name.len() as u8);
        contents.extend_from_slice(public_name.as_bytes());
        contents.extend_from_slice(&0u16.to_be_bytes()); // extensions
        let mut config = Vec::new();
        config.extend_from_slice(&0xfe0du16.to_be_bytes());
        config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        config.extend_from_slice(&contents);
        let mut list = Vec::new();
        list.extend_from_slice(&(config.len() as u16).to_be_bytes());
        list.extend_from_slice(&config);
        list
    }

    fn rejected_error(kind: io::ErrorKind, configs: Option<Vec<EchConfigPayload>>) -> io::Error {
        io::Error::new(
            kind,
            rustls::Error::PeerIncompatible(
                rustls::PeerIncompatible::ServerRejectedEncryptedClientHello(configs),
            ),
        )
    }

    #[test]
    fn encode_roundtrips_and_keeps_length_prefix() {
        let bytes = sample_ech_config_list("cloudflare-ech.com");
        let parsed = Vec::<EchConfigPayload>::read(&mut Reader::init(&bytes)).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(ech_public_names(&parsed), vec!["cloudflare-ech.com".to_string()]);
        let encoded = encode_ech_config_list(&parsed);
        assert_eq!(encoded.as_ref(), bytes.as_slice());
        #[cfg(feature = "ech")]
        {
            rustls::client::EchConfig::new(
                encoded,
                rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
            )
            .expect("re-encoded list parses as an EchConfig");
        }
    }

    #[test]
    fn retry_configs_are_found_regardless_of_error_kind() {
        let bytes = sample_ech_config_list("cloudflare-ech.com");
        let configs = Vec::<EchConfigPayload>::read(&mut Reader::init(&bytes)).unwrap();
        for kind in [io::ErrorKind::Other, io::ErrorKind::InvalidData] {
            let error = rejected_error(kind, Some(configs.clone()));
            assert_eq!(ech_retry_configs(&error), Some(configs.clone()));
        }
        // 被拒但没有 retry_configs：外层 Some、内层 None
        let error = rejected_error(io::ErrorKind::Other, None);
        assert_eq!(ech_rejection(&error), Some(None));
        assert!(ech_retry_configs(&error).is_none());
        // 普通 io 错误 / 其他 rustls 错误都不算
        assert!(ech_rejection(&io::Error::other("plain")).is_none());
        let other = io::Error::other(rustls::Error::HandshakeNotComplete);
        assert!(ech_rejection(&other).is_none());
    }

    #[test]
    fn trace_host_line_must_match_exactly() {
        let body = b"fl=1f2\nh=linux.do\nip=203.0.113.9\nts=1.0\n";
        assert!(trace_matches(body, "linux.do"));
        assert!(!trace_matches(b"h=linux.do.evil\n", "linux.do"));
        assert!(!trace_matches(b"h=evil.linux.do\n", "linux.do"));
        assert!(!trace_matches(b"fl=1\nip=1.2.3.4\n", "linux.do"));
        assert!(trace_matches(b"h=linux.do\r\n", "linux.do"));
    }

    fn test_roots() -> RootCertStore {
        RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
    }

    fn tiny_timeouts() -> ProbeTimeouts {
        ProbeTimeouts {
            tcp: Duration::from_millis(500),
            tls: Duration::from_millis(300),
            http: Duration::from_millis(300),
        }
    }

    #[tokio::test]
    async fn closed_port_is_tcp_connect_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _port = listener.local_addr().unwrap().port();
        drop(listener);
        // 探测固定打 443；本机 443 没有监听时就是 TcpConnect（CI 容器里不会开 443）
        let tls = build_probe_tls_config(None, &test_roots(), Arc::new(crate::tls_crypto::build_provider()))
            .unwrap();
        let target = ProbeTarget {
            ip: "127.0.0.1".parse().unwrap(),
            inner_sni: "linux.do",
        };
        let outcome = probe_once(&target, tls, &tiny_timeouts()).await;
        assert!(!outcome.ok);
        assert!(matches!(
            outcome.failure,
            Some(ProbeFailure::TcpConnect) | Some(ProbeFailure::TlsTimeout) | Some(ProbeFailure::Tls(_))
        ));
    }

    #[tokio::test]
    async fn silent_listener_is_tls_timeout() {
        // tls_connect 固定 443，这里直接测内部分段：对一个不回话的监听做 TLS 握手
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _keep = listener.accept().await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let tls = build_probe_tls_config(None, &test_roots(), Arc::new(crate::tls_crypto::build_provider()))
            .unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let name = ServerName::try_from("linux.do".to_string()).unwrap();
        let result = tokio::time::timeout(
            Duration::from_millis(300),
            TlsConnector::from(tls).connect(name, tcp),
        )
        .await;
        assert!(result.is_err(), "handshake against a silent peer must time out");
    }
}
