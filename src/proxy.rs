//! MITM HTTP/HTTPS proxy server with ECH support
//!
//! This proxy supports two modes:
//! 1. DoH/ECH MITM mode: generates certificates locally and performs TLS interception
//! 2. Plain tunnel mode: only establishes upstream CONNECT/SOCKS5 tunnels and forwards bytes

use crate::cert::CertManager;
use crate::dns::DnsResolver;
use crate::ech::DohTlsConnector;
use crate::error::{DohProxyError, Result};
use crate::ProxyConfig;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1 as hyper_http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use parking_lot::RwLock;
use std::convert::Infallible;
use std::io::Cursor;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

/// Local proxy server
pub struct DohProxyServer {
    #[allow(dead_code)]
    config: ProxyConfig,
    doh_tls_connector: Arc<DohTlsConnector>,
    cert_manager: Option<Arc<CertManager>>,
    local_addr: Arc<RwLock<Option<SocketAddr>>>,
    shutdown_tx: broadcast::Sender<()>,
}

impl DohProxyServer {
    /// Create a new proxy server
    pub async fn new(config: ProxyConfig) -> Result<Self> {
        if config.gateway_mode && config.enable_doh {
            info!(
                "Creating local proxy in gateway (reverse proxy) mode with DoH server: {}",
                config.doh_server
            );
        } else if config.enable_doh {
            info!(
                "Creating local proxy in DoH/ECH MITM mode with DoH server: {}",
                config.doh_server
            );
        } else {
            info!("Creating local proxy in pure upstream tunnel mode");
        }

        let dns_resolver = if config.enable_doh {
            DnsResolver::set_bootstrap_ips(&config.doh_server, &config.doh_bootstrap_ips);
            DnsResolver::set_auth_token(&config.doh_server, config.doh_auth_token.as_deref());
            if let Some(ech_server) = config
                .doh_server_ech
                .as_deref()
                .filter(|ech_server| *ech_server != config.doh_server)
            {
                DnsResolver::set_bootstrap_ips(ech_server, &config.doh_ech_bootstrap_ips);
                DnsResolver::set_auth_token(ech_server, config.doh_ech_auth_token.as_deref());
            }
            // 节点列表先于 resolver 建立，首启解析 DoH 域名就能用下发的节点
            if let Some(raw) = config.doh_node_list_json.as_deref() {
                match DnsResolver::load_node_list_json(raw) {
                    Ok(true) => info!("Persisted node list loaded"),
                    Ok(false) => info!("Persisted node list is not newer than current"),
                    Err(error) => warn!("Persisted node list rejected: {}", error),
                }
            }
            // 查表模式：登记路由表接口；None 时取消登记（切回普通 DoH 服务器）
            if let Err(error) = DnsResolver::set_routes_url(
                &config.doh_server,
                config.doh_routes_url.as_deref(),
                config.upstream_proxy.as_ref(),
            ) {
                warn!("Route table URL rejected, staying in DoH-only mode: {}", error);
            } else if let Some(raw) = config
                .doh_route_table_json
                .as_deref()
                .filter(|_| config.doh_routes_url.is_some())
            {
                if let Err(error) = DnsResolver::load_route_table_json(&config.doh_server, raw) {
                    warn!("Persisted route table ignored: {}", error);
                }
            }
            Some(
                DnsResolver::shared(
                    &config.doh_server,
                    config.doh_server_ech.as_deref(),
                    config.prefer_ipv6,
                    config.upstream_proxy.clone(),
                )
                .await?,
            )
        } else {
            None
        };

        let dns_resolver_for_selector = dns_resolver.clone();
        let doh_tls_connector = Arc::new(DohTlsConnector::new(
            dns_resolver,
            config.enable_doh,
            Duration::from_secs(config.timeout_secs),
            config.upstream_proxy.clone(),
            config.server_ip.clone(),
        ));

        // 本地动态优选：一等链路。先卸载上一轮的实例（重启网关时）
        crate::dns::DnsResolver::set_extra_covered_hosts(&config.extra_covered_hosts);
        crate::select::Selector::uninstall();
        match crate::select::Selector::new(
            &config,
            doh_tls_connector.root_store().clone(),
            doh_tls_connector.crypto_provider(),
            dns_resolver_for_selector,
        ) {
            Some(selector) => {
                crate::select::Selector::install(selector.clone());
                selector.start();
            }
            None => info!("select: disabled (mode {})", config.select_mode),
        }

        // gateway 模式下仍需要 cert_manager：WebView 通过 CONNECT 走 MITM
        let cert_manager = if config.enable_doh {
            let cm = if let (Some(cert), Some(key)) = (&config.ca_cert_pem, &config.ca_key_pem) {
                CertManager::from_pem(cert, key, config.h2_mitm)? // 运行时 CA（per-device）
            } else {
                CertManager::new(config.h2_mitm)? // 编译时 CA
            };
            Some(Arc::new(cm))
        } else {
            None
        };
        let (shutdown_tx, _) = broadcast::channel(1);

        Ok(Self {
            config,
            doh_tls_connector,
            cert_manager,
            local_addr: Arc::new(RwLock::new(None)),
            shutdown_tx,
        })
    }

    /// Get the local address the server is bound to
    pub fn local_addr(&self) -> Option<SocketAddr> {
        *self.local_addr.read()
    }

    /// Get the local port
    pub fn port(&self) -> Option<u16> {
        self.local_addr().map(|a| a.port())
    }

    pub fn dns_cache_stats(&self) -> crate::dns::DnsCacheStats {
        self.doh_tls_connector.dns_cache_stats()
    }

    pub fn dns_cache_records(&self) -> Vec<crate::dns::DnsCacheRecord> {
        self.doh_tls_connector.dns_cache_records()
    }

    /// Start the proxy server
    pub async fn start(&self) -> Result<()> {
        let bind_addr = format!("{}:{}", self.config.bind_addr, self.config.bind_port);
        let listener = TcpListener::bind(&bind_addr).await?;

        let local_addr = listener.local_addr()?;
        *self.local_addr.write() = Some(local_addr);

        info!("Local proxy server listening on {}", local_addr);

        let mut shutdown_rx = self.shutdown_tx.subscribe();

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            debug!("New connection from {}", peer_addr);

                            let enable_doh = self.config.enable_doh;
                            let gateway_mode = self.config.gateway_mode;
                            let mitm_connect = self.config.mitm_connect;
                            let h2_mitm = self.config.h2_mitm;
                            let doh_tls_connector = self.doh_tls_connector.clone();
                            let cert_manager = self.cert_manager.clone();

                            tokio::spawn(async move {
                                if gateway_mode && enable_doh {
                                    // Gateway 模式：用 hyper server 统一处理
                                    // CONNECT → MITM 或 tunnel（取决于 mitm_connect）
                                    // 其他方法 → HTTP/2 反向代理 (Dio)
                                    if let Err(e) = handle_gateway_connection(
                                        stream,
                                        doh_tls_connector,
                                        cert_manager,
                                        mitm_connect,
                                        h2_mitm,
                                    ).await {
                                        debug!("Gateway connection error from {}: {}", peer_addr, e);
                                    }
                                } else if let Err(e) = handle_connection(
                                    stream,
                                    enable_doh,
                                    doh_tls_connector,
                                    cert_manager,
                                    h2_mitm,
                                ).await {
                                    warn!("Connection error from {}: {}", peer_addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Accept error: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Shutting down proxy server");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Stop the proxy server
    pub fn stop(&self) {
        crate::select::Selector::uninstall();
        let _ = self.shutdown_tx.send(());
    }
}

/// Handle a single connection
async fn handle_connection(
    client: TcpStream,
    enable_doh: bool,
    doh_tls_connector: Arc<DohTlsConnector>,
    cert_manager: Option<Arc<CertManager>>,
    h2_mitm: bool,
) -> Result<()> {
    let (read_half, write_half) = client.into_split();
    let mut reader = BufReader::new(read_half);
    let mut writer = write_half;

    let mut first_line = String::new();
    reader.read_line(&mut first_line).await?;

    let parts: Vec<&str> = first_line.trim().split_whitespace().collect();
    if parts.len() < 2 {
        return Err(DohProxyError::Parse("Invalid request".to_string()));
    }

    let method = parts[0];
    let target = parts[1].to_string();

    if method == "CONNECT" {
        // CF 验证域名（challenges.cloudflare.com）不做 MITM：改走隧道让 WebView
        // 与真 CF 端到端 TLS，否则 Turnstile 会识破中间人而拒绝人机验证。
        let (connect_host, _) = parse_host_port(&target).unwrap_or_default();
        let use_mitm = enable_doh && !is_cf_challenge_host(&connect_host);
        if use_mitm {
            let cert_manager = cert_manager.ok_or_else(|| {
                DohProxyError::Proxy("MITM mode requires certificate manager".to_string())
            })?;
            handle_connect_mitm(
                reader,
                writer,
                &target,
                doh_tls_connector,
                cert_manager,
                h2_mitm,
            )
            .await
        } else {
            handle_connect_tunnel(reader, writer, &target, doh_tls_connector).await
        }
    } else {
        writer
            .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\nOnly CONNECT method is supported\r\n")
            .await?;
        Ok(())
    }
}

/// Handle CONNECT request as a plain TCP tunnel.
async fn handle_connect_tunnel(
    mut reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    target: &str,
    doh_tls_connector: Arc<DohTlsConnector>,
) -> Result<()> {
    let (host, port) = parse_host_port(target)?;

    info!("Plain CONNECT {}:{}", host, port);

    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
    }

    let server_stream = match doh_tls_connector.connect_tcp(&host, port).await {
        Ok(stream) => stream,
        Err(e) => {
            warn!(
                "Failed to establish upstream tunnel for {}:{}: {}",
                host, port, e
            );
            let msg = format!("HTTP/1.1 502 Bad Gateway\r\n\r\n{}\r\n", e);
            writer.write_all(msg.as_bytes()).await?;
            return Err(e);
        }
    };

    writer
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    let buffered = reader.buffer().to_vec();
    let read_half = reader.into_inner();
    let client_stream = read_half
        .reunite(writer)
        .map_err(|_| DohProxyError::Proxy("Failed to reunite TCP stream halves".to_string()))?;
    let client_stream = PrefixedStream::new(client_stream, buffered);

    let (mut client_read, mut client_write) = tokio::io::split(client_stream);
    let (mut server_read, mut server_write) = tokio::io::split(server_stream);

    let client_to_server = tokio::io::copy(&mut client_read, &mut server_write);
    let server_to_client = tokio::io::copy(&mut server_read, &mut client_write);

    match tokio::try_join!(client_to_server, server_to_client) {
        Ok((to_server, to_client)) => {
            debug!(
                "Plain tunnel closed: {}:{} (sent: {}, received: {})",
                host, port, to_server, to_client
            );
        }
        Err(e) => {
            debug!("Plain tunnel error: {}:{} - {}", host, port, e);
        }
    }

    Ok(())
}

/// Handle CONNECT request with MITM
async fn handle_connect_mitm(
    mut reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    target: &str,
    doh_tls_connector: Arc<DohTlsConnector>,
    cert_manager: Arc<CertManager>,
    h2_mitm: bool,
) -> Result<()> {
    let (host, port) = parse_host_port(target)?;

    info!("MITM CONNECT {}:{}", host, port);

    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
    }

    // h2 MITM 路径：写 200 后用 hyper 自动协商 client h1/h2 并转发到上游（带 ECH）。
    // 上游连接由转发 service 内部按需建立、失败以 502 响应返回，故不在此预连。
    if h2_mitm {
        writer
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        let buffered = reader.buffer().to_vec();
        let read_half = reader.into_inner();
        let client_stream = read_half
            .reunite(writer)
            .map_err(|_| DohProxyError::Proxy("Failed to reunite TCP stream halves".to_string()))?;
        let client_stream = PrefixedStream::new(client_stream, buffered);

        let server_config = cert_manager.get_server_config(&host)?;
        let acceptor = TlsAcceptor::from(server_config);
        let client_tls = match acceptor.accept(client_stream).await {
            Ok(stream) => stream,
            Err(e) => {
                warn!("Client TLS handshake failed for {}: {}", host, e);
                return Err(DohProxyError::Io(e));
            }
        };
        info!("Client TLS handshake complete for {} (h2 MITM)", host);
        return mitm_serve(client_tls, host, port, doh_tls_connector).await;
    }

    let server_tls = match doh_tls_connector.connect(&host, port).await {
        Ok(stream) => stream,
        Err(e) => {
            warn!(
                "Failed to establish MITM upstream for {}:{}: {}",
                host, port, e
            );
            let msg = format!("HTTP/1.1 502 Bad Gateway\r\n\r\n{}\r\n", e);
            writer.write_all(msg.as_bytes()).await?;
            return Err(e);
        }
    };

    info!("Connected to {}:{} with ECH/TLS", host, port);

    writer
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    let buffered = reader.buffer().to_vec();
    let read_half = reader.into_inner();
    let client_stream = read_half
        .reunite(writer)
        .map_err(|_| DohProxyError::Proxy("Failed to reunite TCP stream halves".to_string()))?;
    let client_stream = PrefixedStream::new(client_stream, buffered);

    let server_config = cert_manager.get_server_config(&host)?;
    let acceptor = TlsAcceptor::from(server_config);

    let client_tls = match acceptor.accept(client_stream).await {
        Ok(stream) => stream,
        Err(e) => {
            warn!("Client TLS handshake failed for {}: {}", host, e);
            return Err(DohProxyError::Io(e));
        }
    };

    info!("Client TLS handshake complete for {}", host);

    let (mut client_read, mut client_write) = tokio::io::split(client_tls);
    let (mut server_read, mut server_write) = tokio::io::split(server_tls);

    let client_to_server = tokio::io::copy(&mut client_read, &mut server_write);
    let server_to_client = tokio::io::copy(&mut server_read, &mut client_write);

    match tokio::try_join!(client_to_server, server_to_client) {
        Ok((to_server, to_client)) => {
            debug!(
                "MITM tunnel closed: {}:{} (sent: {}, received: {})",
                host, port, to_server, to_client
            );
        }
        Err(e) => {
            debug!("MITM tunnel error: {}:{} - {}", host, port, e);
        }
    }

    Ok(())
}

/// Handle a gateway (reverse proxy) connection using hyper.
///
/// Uses hyper HTTP/1.1 server on the client side, hyper HTTP/2 (or HTTP/1.1)
/// client on the server side. Supports keep-alive with multi-host routing
/// and server-side connection pooling via HTTP/2 multiplexing.
async fn handle_gateway_connection(
    stream: TcpStream,
    connector: Arc<DohTlsConnector>,
    cert_manager: Option<Arc<CertManager>>,
    mitm_connect: bool,
    h2_mitm: bool,
) -> Result<()> {
    let io = TokioIo::new(stream);
    let pool: GatewayPool = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

    let service = service_fn(move |req: Request<Incoming>| {
        let connector = connector.clone();
        let cert_manager = cert_manager.clone();
        let pool = pool.clone();
        async move {
            if req.method() == hyper::Method::CONNECT {
                // CF 验证域名强制走隧道（端到端真 TLS），其余按 mitm_connect 配置。
                let is_cf = req
                    .uri()
                    .authority()
                    .map(|a| is_cf_challenge_host(a.host()))
                    .unwrap_or(false);
                if mitm_connect && !is_cf {
                    gateway_handle_connect(req, connector, cert_manager, h2_mitm).await
                } else {
                    gateway_handle_connect_tunnel(req, connector).await
                }
            } else {
                gateway_forward_request(req, connector, pool, None).await
            }
        }
    });

    hyper_http1::Builder::new()
        .keep_alive(true)
        .serve_connection(io, service)
        .with_upgrades()
        .await
        .map_err(|e| DohProxyError::Proxy(format!("Gateway hyper error: {}", e)))
}

type GatewayBody = BoxBody<Bytes, hyper::Error>;
type GatewayResponse = std::result::Result<Response<GatewayBody>, Infallible>;

/// 只缓存 HTTP/2 sender（可 clone 多路复用），HTTP/1.1 不缓存。
type GatewayPool = Arc<
    tokio::sync::Mutex<
        std::collections::HashMap<String, hyper::client::conn::http2::SendRequest<Incoming>>,
    >,
>;

enum GatewaySender {
    H2(hyper::client::conn::http2::SendRequest<Incoming>),
    H1(hyper::client::conn::http1::SendRequest<Incoming>),
}

fn gateway_error_response(status: u16, msg: &str) -> Response<GatewayBody> {
    let body = Full::new(Bytes::from(msg.to_owned()))
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(body)
        .unwrap()
}

/// Forward a plain HTTP request to the real server via TLS+ECH (HTTP/2 preferred).
async fn gateway_forward_request(
    req: Request<Incoming>,
    connector: Arc<DohTlsConnector>,
    pool: GatewayPool,
    forced_target: Option<(String, u16)>,
) -> GatewayResponse {
    // MITM 单 host 场景由 forced_target 指定目标；gateway 反代场景从 Host 头解析
    let (host, port) = match forced_target {
        Some(hp) => hp,
        None => {
            let host_header = req
                .headers()
                .get(hyper::header::HOST)
                .and_then(|h| h.to_str().ok())
                .unwrap_or_default()
                .to_string();

            if host_header.is_empty() {
                return Ok(gateway_error_response(400, "Missing Host header"));
            }

            match gateway_parse_host(&host_header) {
                Some(hp) => hp,
                None => return Ok(gateway_error_response(400, "Invalid Host header")),
            }
        }
    };
    let host_key = format!("{}:{}", host, port);

    debug!("Gateway {} {} -> {}", req.method(), req.uri(), host_key);

    // Try to get a pooled H2 sender (H1 is not pooled)
    let mut sender: Option<GatewaySender> = {
        let mut p = pool.lock().await;
        match p.get(&host_key) {
            Some(s) if s.is_ready() => Some(GatewaySender::H2(s.clone())),
            _ => {
                p.remove(&host_key);
                None
            }
        }
    };

    // Create new connection if needed
    if sender.is_none() {
        let tls = match connector.connect_h2(&host, port).await {
            Ok(s) => s,
            Err(e) => {
                warn!("Gateway connect failed for {}: {}", host_key, e);
                return Ok(gateway_error_response(
                    502,
                    &format!("Connect failed: {}", e),
                ));
            }
        };

        // Check negotiated ALPN
        let alpn = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());
        let is_h2 = alpn.as_deref() == Some(b"h2");
        let io = TokioIo::new(tls);

        if is_h2 {
            debug!("Gateway: HTTP/2 connection to {}", host_key);
            let (s, conn) = match hyper::client::conn::http2::handshake(
                hyper_util::rt::TokioExecutor::new(),
                io,
            )
            .await
            {
                Ok(pair) => pair,
                Err(e) => {
                    warn!("Gateway H2 handshake failed for {}: {}", host_key, e);
                    return Ok(gateway_error_response(
                        502,
                        &format!("H2 handshake failed: {}", e),
                    ));
                }
            };
            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    debug!("Gateway H2 conn closed: {}", e);
                }
            });
            let s_clone = s.clone();
            sender = Some(GatewaySender::H2(s));
            pool.lock().await.insert(host_key.clone(), s_clone);
        } else {
            debug!("Gateway: HTTP/1.1 connection to {}", host_key);
            let (s, conn) = match hyper::client::conn::http1::handshake(io).await {
                Ok(pair) => pair,
                Err(e) => {
                    warn!("Gateway H1 handshake failed for {}: {}", host_key, e);
                    return Ok(gateway_error_response(
                        502,
                        &format!("H1 handshake failed: {}", e),
                    ));
                }
            };
            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    debug!("Gateway H1 conn closed: {}", e);
                }
            });
            // H1 不能 clone/多路复用，不入池
            sender = Some(GatewaySender::H1(s));
        }
    }

    // Rewrite URI: 客户端发来的是相对路径 /path，HTTP/2 需要绝对 URI（:authority + :scheme）
    let mut req = req;
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let authority = if port == 443 {
        host.clone()
    } else {
        format!("{}:{}", host, port)
    };
    if let Ok(new_uri) = format!("https://{}{}", authority, path_and_query).parse() {
        *req.uri_mut() = new_uri;
    }

    // Forward the request
    let result = match sender.unwrap() {
        GatewaySender::H2(mut s) => s.send_request(req).await,
        GatewaySender::H1(mut s) => s.send_request(req).await,
    };

    match result {
        Ok(resp) => Ok(resp.map(|b| b.boxed())),
        Err(e) => {
            warn!("Gateway forward failed for {}: {}", host_key, e);
            // Remove broken connection from pool
            pool.lock().await.remove(&host_key);
            Ok(gateway_error_response(
                502,
                &format!("Forward failed: {}", e),
            ))
        }
    }
}

/// h2 MITM：在已建立的 client TLS 上用 hyper 自动协商 h1/h2，把每个请求转发到上游（带 ECH）。
/// CONNECT 已固定单 host，所有 h2 stream 复用同一条上游连接（h2 多路复用）。
async fn mitm_serve<I>(
    client_io: I,
    host: String,
    port: u16,
    connector: Arc<DohTlsConnector>,
) -> Result<()>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(client_io);
    // 单 host 连接池：h2 上游 sender 可 clone 多路复用
    let pool: GatewayPool = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    let service = service_fn(move |req: Request<Incoming>| {
        let connector = connector.clone();
        let pool = pool.clone();
        let target = (host.clone(), port);
        async move { gateway_forward_request(req, connector, pool, Some(target)).await }
    });

    hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
        .serve_connection_with_upgrades(io, service)
        .await
        .map_err(|e| DohProxyError::Proxy(format!("MITM h2 serve error: {}", e)))
}

/// Handle CONNECT in gateway mode as a plain tunnel (DOH resolution + raw TCP forwarding).
/// Client does end-to-end TLS with the target server — no MITM, no custom CA needed.
async fn gateway_handle_connect_tunnel(
    req: Request<Incoming>,
    connector: Arc<DohTlsConnector>,
) -> GatewayResponse {
    let target = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .unwrap_or_default();
    let (host, port) = match gateway_parse_host(&target) {
        Some(hp) => hp,
        None => return Ok(gateway_error_response(400, "Invalid CONNECT target")),
    };

    info!("Gateway CONNECT (tunnel) {}:{}", host, port);

    let connector_clone = connector.clone();
    let host_clone = host.clone();

    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let io = TokioIo::new(upgraded);
                // Connect to remote via DOH-resolved address
                match connector_clone.connect_tcp(&host_clone, port).await {
                    Ok(server_stream) => {
                        let (mut cr, mut cw) = tokio::io::split(io);
                        let (mut sr, mut sw) = tokio::io::split(server_stream);
                        let _ = tokio::try_join!(
                            tokio::io::copy(&mut cr, &mut sw),
                            tokio::io::copy(&mut sr, &mut cw),
                        );
                    }
                    Err(e) => {
                        warn!(
                            "Gateway tunnel connect failed {}:{}: {}",
                            host_clone, port, e
                        );
                    }
                }
            }
            Err(e) => warn!("Gateway CONNECT tunnel upgrade failed: {}", e),
        }
    });

    // Return 200 to initiate the upgrade
    let body = Full::new(Bytes::new())
        .map_err(|never| match never {})
        .boxed();
    Ok(Response::new(body))
}

/// Handle CONNECT in gateway mode (WebView MITM).
async fn gateway_handle_connect(
    req: Request<Incoming>,
    connector: Arc<DohTlsConnector>,
    cert_manager: Option<Arc<CertManager>>,
    h2_mitm: bool,
) -> GatewayResponse {
    let target = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .unwrap_or_default();
    let (host, port) = match gateway_parse_host(&target) {
        Some(hp) => hp,
        None => return Ok(gateway_error_response(400, "Invalid CONNECT target")),
    };

    info!("Gateway CONNECT (MITM) {}:{}", host, port);

    let cert_manager = match cert_manager {
        Some(cm) => cm,
        None => {
            return Ok(gateway_error_response(
                502,
                "Certificate manager not available",
            ))
        }
    };

    let connector_clone = connector.clone();
    let host_clone = host.clone();

    // Spawn MITM handling after upgrade
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let io = TokioIo::new(upgraded);
                if let Err(e) = gateway_mitm_upgraded(
                    io,
                    &host_clone,
                    port,
                    connector_clone,
                    cert_manager,
                    h2_mitm,
                )
                .await
                {
                    warn!("Gateway MITM error {}:{}: {}", host_clone, port, e);
                }
            }
            Err(e) => warn!("Gateway CONNECT upgrade failed: {}", e),
        }
    });

    // Return 200 to initiate the upgrade
    let body = Full::new(Bytes::new())
        .map_err(|never| match never {})
        .boxed();
    Ok(Response::new(body))
}

/// Run MITM on an upgraded CONNECT connection (WebView).
async fn gateway_mitm_upgraded<I>(
    client_io: I,
    host: &str,
    port: u16,
    connector: Arc<DohTlsConnector>,
    cert_manager: Arc<CertManager>,
    h2_mitm: bool,
) -> Result<()>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // h2 MITM：accept client TLS（ALPN 含 h2）后交给 hyper 转发，上游按需连（带 ECH）
    if h2_mitm {
        let server_config = cert_manager.get_server_config(host)?;
        let acceptor = TlsAcceptor::from(server_config);
        let client_tls = acceptor
            .accept(client_io)
            .await
            .map_err(DohProxyError::Io)?;
        return mitm_serve(client_tls, host.to_string(), port, connector).await;
    }

    // Connect to real server with TLS+ECH
    let server_tls = connector.connect(host, port).await?;

    // TLS handshake with client (MITM)
    let server_config = cert_manager.get_server_config(host)?;
    let acceptor = TlsAcceptor::from(server_config);
    let client_tls = acceptor
        .accept(client_io)
        .await
        .map_err(DohProxyError::Io)?;

    // Bidirectional copy
    let (mut cr, mut cw) = tokio::io::split(client_tls);
    let (mut sr, mut sw) = tokio::io::split(server_tls);
    let _ = tokio::try_join!(
        tokio::io::copy(&mut cr, &mut sw),
        tokio::io::copy(&mut sr, &mut cw),
    );

    Ok(())
}

fn gateway_parse_host(host_header: &str) -> Option<(String, u16)> {
    if host_header.starts_with('[') {
        // IPv6: [::1]:443
        let bracket_end = host_header.find(']')?;
        let host = &host_header[1..bracket_end];
        let port = host_header[bracket_end + 1..]
            .strip_prefix(':')
            .and_then(|s| s.parse().ok())
            .unwrap_or(443);
        Some((host.to_string(), port))
    } else if let Some(colon) = host_header.rfind(':') {
        let host = &host_header[..colon];
        let port = host_header[colon + 1..].parse().unwrap_or(443);
        Some((host.to_string(), port))
    } else {
        Some((host_header.to_string(), 443))
    }
}

/// 判断是否为 Cloudflare 验证（Turnstile）基础设施域名。
///
/// challenges.cloudflare.com 是 CF Turnstile 全球统一的固定域名（api.js 与
/// challenge-platform 都在此域），属协议级常量而非可变业务白名单。对它做 MITM
/// 会被 CF 挑战平台识破（TLS 指纹/证书不符）而拒绝人机验证，故这类连接必须以
/// 隧道方式端到端直连真 CF。
///
/// 挑战页还会向它的子域名（如 `brunhild.challenges.cloudflare.com`，只有 AAAA
/// 记录）发探测请求，这些子域同样属于挑战平台：被 MITM 后指纹不符，且 v4-only
/// 网络下代理这边直接报 `No addresses` 把连接掐断，WebView 记到
/// `ERR_CONNECTION_RESET`。所以整个 `*.challenges.cloudflare.com` 都走隧道，
/// 让浏览器自己和真 CF 握手，成功与否交给挑战平台按正常浏览器的行为判定。
fn is_cf_challenge_host(host: &str) -> bool {
    const CF_CHALLENGE_DOMAIN: &str = "challenges.cloudflare.com";
    let host = host.trim_end_matches('.');
    if host.eq_ignore_ascii_case(CF_CHALLENGE_DOMAIN) {
        return true;
    }
    host.len() > CF_CHALLENGE_DOMAIN.len() + 1
        && host.as_bytes()[host.len() - CF_CHALLENGE_DOMAIN.len() - 1] == b'.'
        && host[host.len() - CF_CHALLENGE_DOMAIN.len()..].eq_ignore_ascii_case(CF_CHALLENGE_DOMAIN)
}

/// Parse host:port from CONNECT target
fn parse_host_port(target: &str) -> Result<(String, u16)> {
    if target.starts_with('[') {
        if let Some(bracket_end) = target.find(']') {
            let host = &target[1..bracket_end];
            let port_str = &target[bracket_end + 1..];
            let port = if port_str.starts_with(':') {
                port_str[1..].parse().unwrap_or(443)
            } else {
                443
            };
            return Ok((host.to_string(), port));
        }
    }

    if let Some(colon) = target.rfind(':') {
        let host = &target[..colon];
        let port = target[colon + 1..].parse().unwrap_or(443);
        Ok((host.to_string(), port))
    } else {
        Ok((target.to_string(), 443))
    }
}

struct PrefixedStream<S> {
    prefix: Cursor<Vec<u8>>,
    inner: S,
}

impl<S> PrefixedStream<S> {
    fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            prefix: Cursor::new(prefix),
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let position = self.prefix.position() as usize;
        let prefix = self.prefix.get_ref();

        if position < prefix.len() {
            let remaining = &prefix[position..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.prefix.set_position((position + to_copy) as u64);
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::is_cf_challenge_host;

    /// 挑战平台的主域和所有子域都必须走隧道，其余域名（含同名前缀的伪装域）不算
    #[test]
    fn cf_challenge_host_covers_subdomains_only() {
        assert!(is_cf_challenge_host("challenges.cloudflare.com"));
        assert!(is_cf_challenge_host("CHALLENGES.cloudflare.com."));
        assert!(is_cf_challenge_host("brunhild.challenges.cloudflare.com"));
        assert!(is_cf_challenge_host("a.b.challenges.cloudflare.com"));
        assert!(!is_cf_challenge_host("cloudflare.com"));
        assert!(!is_cf_challenge_host("notchallenges.cloudflare.com"));
        assert!(!is_cf_challenge_host("challenges.cloudflare.com.evil.test"));
        assert!(!is_cf_challenge_host("linux.do"));
        assert!(!is_cf_challenge_host(""));
    }
}
