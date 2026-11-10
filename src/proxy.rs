//! MITM HTTP/HTTPS proxy server with ECH support
//!
//! This proxy supports two modes:
//! 1. DoH/ECH MITM mode: generates certificates locally and performs TLS interception
//! 2. Plain tunnel mode: only establishes upstream CONNECT/SOCKS5 tunnels and forwards bytes

use crate::cert::CertManager;
use crate::dns::DnsResolver;
use crate::ech::DohTlsConnector;
use crate::edge_pin::is_cf_challenge_host;
use crate::error::{DohProxyError, Result};
use crate::stats::STATS;
use crate::upstream_pool::{Lane, Replay, UpstreamPool};
use crate::ProxyConfig;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
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
    /// 本代理 DoH 配置的 key（不含上游代理），DoH 关闭时为 None
    doh_config_key: Option<String>,
    doh_tls_connector: Arc<DohTlsConnector>,
    cert_manager: Option<Arc<CertManager>>,
    local_addr: Arc<RwLock<Option<SocketAddr>>>,
    shutdown_tx: broadcast::Sender<()>,
    /// 所有回环连接共用的上游连接池
    pool: Arc<UpstreamPool>,
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
        } else if config.gateway_mode {
            info!("Creating local proxy in gateway mode without DoH (system DNS, no ECH)");
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
        let doh_tls_connector = DohTlsConnector::new(
            dns_resolver,
            config.enable_doh,
            Duration::from_secs(config.timeout_secs),
            config.upstream_proxy.clone(),
            config.server_ip.clone(),
        );
        // 浏览器指纹：网关道与 h2 MITM 道的上游握手照 WebView 的 ClientHello 复刻。
        // 不开 DoH 的网关（App 在 VPN 让路时只为指纹起网关）同样要：CF 对原生连接收紧的站点
        // 认握手不认 cf_clearance，换成非浏览器的握手，验证过了照样 403
        #[cfg(feature = "browser-tls")]
        let doh_tls_connector = if config.browser_tls && (config.enable_doh || config.gateway_mode)
        {
            info!("Browser TLS fingerprint enabled");
            doh_tls_connector.with_browser_tls(Arc::new(crate::browser_tls::BrowserTls::new(
                config
                    .fingerprint_cache_path
                    .as_deref()
                    .filter(|path| !path.is_empty())
                    .map(std::path::PathBuf::from),
                config.webview_user_agent.clone(),
            )))
        } else {
            doh_tls_connector
        };
        let doh_tls_connector = Arc::new(doh_tls_connector);

        // 本地动态优选：一等链路。先卸载上一轮的实例（重启网关时）
        crate::edge_pin::EdgePin::set_extra_covered_hosts(&config.extra_covered_hosts);
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
        let doh_config_key = config.enable_doh.then(|| {
            DnsResolver::doh_config_key(
                &config.doh_server,
                config.doh_server_ech.as_deref(),
                config.prefer_ipv6,
            )
        });

        let pool = UpstreamPool::new(doh_tls_connector.clone());
        pool.seed_network_signature(config.network_sig.as_deref());
        Ok(Self {
            config,
            doh_config_key,
            doh_tls_connector,
            cert_manager,
            local_addr: Arc::new(RwLock::new(None)),
            shutdown_tx,
            pool,
        })
    }

    /// MITM 证书管理器（DoH 关闭时为 None）。Linux 的 WebView 要按主机预先放行它签发的叶子证书
    pub fn cert_manager(&self) -> Option<&Arc<CertManager>> {
        self.cert_manager.as_ref()
    }

    /// 上游连接池（FFI 换网通知时作废旧连接）
    pub fn pool(&self) -> &Arc<UpstreamPool> {
        &self.pool
    }

    /// 浏览器指纹出口的状态（模板来源、代数）；没开时 `enabled: false`
    pub fn fingerprint_status(&self) -> serde_json::Value {
        #[cfg(feature = "browser-tls")]
        if let Some(browser) = self.doh_tls_connector.browser_tls() {
            let mut status = browser.templates().status_json();
            status["enabled"] = serde_json::Value::Bool(true);
            return status;
        }
        serde_json::json!({ "enabled": false })
    }

    /// Get the local address the server is bound to
    pub fn local_addr(&self) -> Option<SocketAddr> {
        *self.local_addr.read()
    }

    /// Get the local port
    pub fn port(&self) -> Option<u16> {
        self.local_addr().map(|a| a.port())
    }

    /// 参数与本代理的 DoH 配置一致时返回代理建连用的 resolver（连同它的 EdgePin）。
    /// FFI 要用它而不是按参数重建 key：key 里含上游代理，FFI 拿不到，重建出来的是另一个
    /// resolver，App 回报的粘性 IP / 亲和代理看不到，App 查到的也不是代理钉住的赢家
    pub fn resolver_for(
        &self,
        doh_url: &str,
        doh_url_ech: Option<&str>,
        prefer_ipv6: bool,
    ) -> Option<Arc<DnsResolver>> {
        let key = self.doh_config_key.as_ref()?;
        if *key != DnsResolver::doh_config_key(doh_url, doh_url_ech, prefer_ipv6) {
            return None;
        }
        self.doh_tls_connector.dns_resolver().cloned()
    }

    pub fn dns_cache_stats(&self) -> crate::dns::DnsCacheStats {
        self.doh_tls_connector.dns_cache_stats()
    }

    pub fn dns_cache_records(&self) -> Vec<crate::dns::DnsCacheRecord> {
        self.doh_tls_connector.dns_cache_records()
    }

    /// Start the proxy server
    pub async fn start(&self) -> Result<()> {
        let listener = self.bind().await?;
        self.serve(listener).await
    }

    /// 绑定监听端口，返回后 [`Self::port`] 即可用；接着交给 [`Self::serve`]
    pub async fn bind(&self) -> Result<TcpListener> {
        let bind_addr = format!("{}:{}", self.config.bind_addr, self.config.bind_port);
        let listener = TcpListener::bind(&bind_addr).await?;

        let local_addr = listener.local_addr()?;
        *self.local_addr.write() = Some(local_addr);

        info!("Local proxy server listening on {}", local_addr);
        Ok(listener)
    }

    /// 在已绑定的端口上接受连接，直到 [`Self::stop`]
    pub async fn serve(&self, listener: TcpListener) -> Result<()> {
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let mitm_scope: Arc<[String]> = self.config.mitm_hosts.clone().into();
        crate::stats::spawn_reporter(self.shutdown_tx.subscribe());
        self.pool.spawn_reaper(self.shutdown_tx.subscribe());
        self.spawn_preconnect();

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            debug!("New connection from {}", peer_addr);
                            crate::stats::STATS.loopback_accepts.inc();
                            let _ = stream.set_nodelay(true);

                            let enable_doh = self.config.enable_doh;
                            let gateway_mode = self.config.gateway_mode;
                            let mitm_connect = self.config.mitm_connect;
                            let h2_mitm = self.config.h2_mitm;
                            let mitm_scope = mitm_scope.clone();
                            let doh_tls_connector = self.doh_tls_connector.clone();
                            let pool = self.pool.clone();
                            let cert_manager = self.cert_manager.clone();

                            tokio::spawn(async move {
                                if gateway_mode {
                                    // Gateway 模式：用 hyper server 统一处理
                                    // CONNECT → MITM 或 tunnel（取决于 mitm_connect，没开 DoH 时
                                    // 没有证书管理器，一律 tunnel）
                                    // 其他方法 → HTTP/2 反向代理 (Dio)
                                    if let Err(e) = handle_gateway_connection(
                                        stream,
                                        doh_tls_connector,
                                        pool,
                                        cert_manager,
                                        mitm_connect,
                                        h2_mitm,
                                        mitm_scope,
                                    ).await {
                                        debug!("Gateway connection error from {}: {}", peer_addr, e);
                                    }
                                } else if let Err(e) = handle_connection(
                                    stream,
                                    enable_doh,
                                    doh_tls_connector,
                                    pool,
                                    cert_manager,
                                    h2_mitm,
                                    mitm_scope,
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
        self.pool.clear();
    }

    /// 启动预连：等优选出结果（不在待定期抢先定下地址族亲和），给 `preconnect_hosts`
    /// 各预建一条网关道的上游连接，首个请求不用再等握手
    fn spawn_preconnect(&self) {
        if !self.config.gateway_mode || self.config.preconnect_hosts.is_empty() {
            return;
        }
        let Some(edge) = self.doh_tls_connector.dns_resolver().map(|r| r.edge_pin().clone())
        else {
            return;
        };
        let hosts = self.config.preconnect_hosts.clone();
        let pool = Arc::downgrade(&self.pool);
        let mut shutdown = self.shutdown_tx.subscribe();
        tokio::spawn(async move {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            let pin = tokio::select! {
                pin = edge.wait_settled(deadline) => pin,
                _ = shutdown.recv() => return,
            };
            if pin == crate::edge_pin::Pin::Pending {
                return;
            }
            let Some(pool) = pool.upgrade() else { return };
            for host in hosts {
                let pool = pool.clone();
                tokio::spawn(async move { pool.preconnect(Lane::Gateway, &host, 443).await });
            }
        });
    }
}

/// Handle a single connection
async fn handle_connection(
    client: TcpStream,
    enable_doh: bool,
    doh_tls_connector: Arc<DohTlsConnector>,
    pool: Arc<UpstreamPool>,
    cert_manager: Option<Arc<CertManager>>,
    h2_mitm: bool,
    mitm_scope: Arc<[String]>,
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
        let use_mitm = enable_doh
            && !is_cf_challenge_host(&connect_host)
            && in_mitm_scope(&mitm_scope, &connect_host);
        if use_mitm {
            let cert_manager = cert_manager.ok_or_else(|| {
                DohProxyError::Proxy("MITM mode requires certificate manager".to_string())
            })?;
            handle_connect_mitm(
                reader,
                writer,
                &target,
                doh_tls_connector,
                pool,
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
    pool: Arc<UpstreamPool>,
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
        let client_stream = sniff_client_hello(client_stream, &doh_tls_connector).await;

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
        let client_tls = sniff_h2_preface(client_tls, &doh_tls_connector).await;
        return mitm_serve(client_tls, host, port, pool, doh_tls_connector).await;
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
    let client_stream = sniff_client_hello(client_stream, &doh_tls_connector).await;

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
    pool: Arc<UpstreamPool>,
    cert_manager: Option<Arc<CertManager>>,
    mitm_connect: bool,
    h2_mitm: bool,
    mitm_scope: Arc<[String]>,
) -> Result<()> {
    let io = TokioIo::new(stream);

    let service = service_fn(move |req: Request<Incoming>| {
        let connector = connector.clone();
        let cert_manager = cert_manager.clone();
        let pool = pool.clone();
        let mitm_scope = mitm_scope.clone();
        async move {
            if req.method() == hyper::Method::CONNECT {
                // CF 验证域名强制走隧道（端到端真 TLS），MITM 范围外的主机也走隧道，
                // 其余按 mitm_connect 配置。
                let use_mitm = req
                    .uri()
                    .authority()
                    .map(|a| !is_cf_challenge_host(a.host()) && in_mitm_scope(&mitm_scope, a.host()))
                    .unwrap_or(false);
                if mitm_connect && use_mitm && cert_manager.is_some() {
                    gateway_handle_connect(req, connector, pool, cert_manager, h2_mitm).await
                } else {
                    gateway_handle_connect_tunnel(req, connector).await
                }
            } else {
                gateway_forward_request(req, pool, Lane::Gateway, None).await
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

type GatewayBody = crate::fetch_shape::ClientBody;
type GatewayResponse = std::result::Result<Response<GatewayBody>, Infallible>;

/// 网关自己生成的错误响应带上这个头：调用方据此区分「网关连不上上游」与
/// 「源站真的回了 5xx」（Dart 侧把正文记进日志排查）
pub const GATEWAY_ERROR_HEADER: &str = "x-cfluxdo-gateway-error";

fn gateway_error_response(status: u16, msg: &str) -> Response<GatewayBody> {
    let body = Full::new(Bytes::from(msg.to_owned()))
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        // 头里也带原因：流式响应在 Dart 拦截器里读不到正文，只能看头
        .header(GATEWAY_ERROR_HEADER, gateway_error_header_value(msg))
        .body(body)
        .unwrap()
}

/// 原因压成头能放的样子：只留可打印 ASCII（其余换成 '?'），最多 200 字节；空的给 "1"
fn gateway_error_header_value(msg: &str) -> String {
    let value: String = msg
        .chars()
        .map(|c| if (' '..='~').contains(&c) { c } else { '?' })
        .take(200)
        .collect();
    let value = value.trim().to_owned();
    if value.is_empty() {
        "1".to_owned()
    } else {
        value
    }
}

/// 把明文请求经共用的上游连接池转发到真实服务端（TLS + ECH，h2 优先）
async fn gateway_forward_request(
    req: Request<Incoming>,
    pool: Arc<UpstreamPool>,
    lane: Lane,
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
                // 指向本机的请求（端口探测、误配）不转发：转回网关自己只会撞上一次 TLS 失败
                Some((host, _)) if is_loopback_host(&host) => {
                    return Ok(gateway_error_response(400, "Loopback host is not proxied"));
                }
                Some(hp) => hp,
                None => return Ok(gateway_error_response(400, "Invalid Host header")),
            }
        }
    };
    let host_key = format!("{}:{}", host, port);
    let started = std::time::Instant::now();
    STATS.gw_requests.inc();

    debug!("Gateway {} {} -> {}", req.method(), req.uri(), host_key);

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

    // Dart 的请求照 WebView 的 fetch 请求整形；WebView 的请求反过来记下它的头顺序
    let decode = match lane {
        Lane::Gateway => pool
            .fetch_shape()
            .is_some_and(|shape| shape.apply(req.headers_mut(), &host)),
        Lane::Mitm => {
            if req.version() == hyper::Version::HTTP_2 {
                pool.observe_webview_request(&host, req.headers());
            }
            false
        }
    };
    let replay = Replay::capture(&req);
    match pool
        .forward(lane, &host, port, req.map(|body| body.boxed()), replay)
        .await
    {
        Ok(resp) => {
            STATS.gw_ttfb.record(started.elapsed());
            Ok(if decode {
                crate::fetch_shape::decode_response(resp)
            } else {
                crate::fetch_shape::passthrough(resp)
            })
        }
        Err(e) => {
            warn!("Gateway forward failed for {}: {}", host_key, e);
            STATS.gw_502.inc();
            Ok(gateway_error_response(502, &e.to_string()))
        }
    }
}

/// h1 的协议升级请求（WebSocket）：`Connection` 里有 upgrade 且带 `Upgrade` 头
fn is_upgrade_request<B>(req: &Request<B>) -> bool {
    req.version() <= hyper::Version::HTTP_11
        && req.headers().contains_key(hyper::header::UPGRADE)
        && req
            .headers()
            .get_all(hyper::header::CONNECTION)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
}

/// 转发 WebSocket 等协议升级：另建一条 h1 上游连接，101 之后两侧原样对接
async fn gateway_forward_upgrade(
    mut req: Request<Incoming>,
    pool: Arc<UpstreamPool>,
    (host, port): (String, u16),
) -> GatewayResponse {
    let client = hyper::upgrade::on(&mut req);
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
    if let Ok(uri) = format!("https://{}{}", authority, path_and_query).parse() {
        *req.uri_mut() = uri;
    }
    info!("MITM upgrade {} -> {}:{}", req.uri().path(), host, port);
    match pool
        .forward_upgrade(&host, port, req.map(|body| body.boxed()), client)
        .await
    {
        Ok(response) => Ok(crate::fetch_shape::passthrough(response)),
        Err(e) => {
            warn!("MITM upgrade failed for {}:{}: {}", host, port, e);
            STATS.gw_502.inc();
            Ok(gateway_error_response(502, &e.to_string()))
        }
    }
}

/// h2 MITM：在已建立的 client TLS 上用 hyper 自动协商 h1/h2，把每个请求转发到上游（带 ECH）。
/// CONNECT 已固定单 host，所有 h2 stream 复用同一条上游连接（h2 多路复用）。
async fn mitm_serve<I>(
    client_io: I,
    host: String,
    port: u16,
    pool: Arc<UpstreamPool>,
    connector: Arc<DohTlsConnector>,
) -> Result<()>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(client_io);
    // 上游走共用池的 Mitm 道（与 Dart 的 Gateway 道分开）
    let service = service_fn(move |req: Request<Incoming>| {
        let pool = pool.clone();
        let target = (host.clone(), port);
        let _connector = connector.clone();
        async move {
            // WebView 主动采样头顺序：页面与采样请求由核心直接应答，不出本机
            #[cfg(feature = "browser-tls")]
            if let Some(browser) = _connector.browser_tls() {
                if let Some(response) = crate::fetch_probe::respond(&req, browser.templates()) {
                    return Ok(response);
                }
            }
            if is_upgrade_request(&req) {
                return gateway_forward_upgrade(req, pool, target).await;
            }
            gateway_forward_request(req, pool, Lane::Mitm, Some(target)).await
        }
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

    // 先连上游再回 200，连不上就给 CONNECT 回 502（与 MITM 的 CONNECT 一致）：以前先回 200
    // 再连，失败只能掐断，浏览器记成 TLS 握手失败。验证页的 Turnstile 走这条路
    let server_stream = match connector.connect_tcp(&host, port).await {
        Ok(stream) => stream,
        Err(e) => {
            warn!("Gateway tunnel connect failed {}:{}: {}", host, port, e);
            STATS.gw_502.inc();
            return Ok(gateway_error_response(502, &e.to_string()));
        }
    };

    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let io = TokioIo::new(upgraded);
                let (mut cr, mut cw) = tokio::io::split(io);
                let (mut sr, mut sw) = tokio::io::split(server_stream);
                let _ = tokio::try_join!(
                    tokio::io::copy(&mut cr, &mut sw),
                    tokio::io::copy(&mut sr, &mut cw),
                );
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
    pool: Arc<UpstreamPool>,
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

    // h1 MITM 要先连上游：连不上就直接给 CONNECT 回 502。以前先回 200、
    // 等浏览器发来 ClientHello 后才去连，上游一失败只能把连接掐掉，浏览器
    // 记成 TLS 握手失败（「此网站无法提供安全连接」，看着像证书问题），
    // 现在记成隧道连接失败，和真实原因一致。h2 MITM 的上游按请求从池里取，
    // 失败时在 TLS 里回 502，不受影响。
    let upstream = if h2_mitm {
        None
    } else {
        match connector.connect(&host, port).await {
            Ok(tls) => Some(tls),
            Err(e) => {
                warn!("Gateway MITM upstream connect failed {}:{}: {}", host, port, e);
                STATS.gw_502.inc();
                return Ok(gateway_error_response(502, &e.to_string()));
            }
        }
    };

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
                    upstream,
                    pool,
                    cert_manager,
                    connector,
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
///
/// [upstream] 是回 200 之前已连好的上游（h1 MITM）；None 表示 h2 MITM，
/// 上游按请求从池里取。
#[allow(clippy::too_many_arguments)]
async fn gateway_mitm_upgraded<I, S>(
    client_io: I,
    host: &str,
    port: u16,
    upstream: Option<S>,
    pool: Arc<UpstreamPool>,
    cert_manager: Arc<CertManager>,
    connector: Arc<DohTlsConnector>,
) -> Result<()>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let client_io = sniff_client_hello(client_io, &connector).await;
    // h2 MITM：accept client TLS（ALPN 含 h2）后交给 hyper 转发，上游按需连（带 ECH）
    let Some(server_tls) = upstream else {
        let server_config = cert_manager.get_server_config(host)?;
        let acceptor = TlsAcceptor::from(server_config);
        let client_tls = acceptor
            .accept(client_io)
            .await
            .map_err(DohProxyError::Io)?;
        let client_tls = sniff_h2_preface(client_tls, &connector).await;
        return mitm_serve(client_tls, host.to_string(), port, pool, connector).await;
    };

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

/// `localhost` 或回环地址字面量
fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
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
/// 主机是否在 MITM 范围内：范围为空表示不限；否则按后缀匹配（`linux.do` 覆盖 `a.linux.do`）
fn in_mitm_scope(scope: &[String], host: &str) -> bool {
    if scope.is_empty() {
        return true;
    }
    let host = host.trim_end_matches('.');
    scope.iter().any(|suffix| {
        let suffix = suffix.trim_start_matches('.');
        host.eq_ignore_ascii_case(suffix)
            || (host.len() > suffix.len() + 1
                && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
                && host[host.len() - suffix.len()..].eq_ignore_ascii_case(suffix))
    })
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

/// MITM 入站等 WebView 发来 ClientHello 的上限
#[cfg(feature = "browser-tls")]
const CLIENT_HELLO_PEEK_TIMEOUT: Duration = Duration::from_secs(10);

/// MITM 入站：接受 TLS 之前窥探 WebView 的 ClientHello，记作浏览器指纹模板；读到的字节
/// 原样放回流前面，再交给 rustls 接受
async fn sniff_client_hello<S>(stream: S, connector: &DohTlsConnector) -> PrefixedStream<S>
where
    S: AsyncRead + Unpin,
{
    #[cfg(feature = "browser-tls")]
    if let Some(browser) = connector.browser_tls() {
        let mut stream = stream;
        let (consumed, hello) =
            crate::browser_tls::peek_client_hello(&mut stream, CLIENT_HELLO_PEEK_TIMEOUT).await;
        if let Some(hello) = hello {
            browser.templates().record_hello(&hello);
        }
        return PrefixedStream::new(stream, consumed);
    }
    let _ = connector;
    PrefixedStream::new(stream, Vec::new())
}

/// h2 MITM 入站：TLS 谈成 h2 时读出 WebView 的 h2 连接前言（初始 SETTINGS、连接窗口），
/// 记进指纹模板；读到的字节放回流前面再交给 hyper。已经采到过就不再读
async fn sniff_h2_preface<S>(
    stream: tokio_rustls::server::TlsStream<S>,
    connector: &DohTlsConnector,
) -> PrefixedStream<tokio_rustls::server::TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    #[cfg(feature = "browser-tls")]
    if let Some(browser) = connector.browser_tls() {
        let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
        if h2 && !browser.templates().has_sampled_h2() {
            let mut stream = stream;
            let buffered =
                crate::browser_tls::read_h2_preface(&mut stream, browser.templates()).await;
            return PrefixedStream::new(stream, buffered);
        }
    }
    let _ = connector;
    PrefixedStream::new(stream, Vec::new())
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
    use super::{
        gateway_parse_host, in_mitm_scope, is_cf_challenge_host, is_loopback_host,
        is_upgrade_request,
    };

    /// WebSocket 握手才算升级请求；普通 keep-alive、h2 请求、只有 Upgrade 头的都不算
    #[test]
    fn upgrade_requests_are_recognised() {
        let build = |version, connection: Option<&str>, upgrade: bool| {
            let mut builder = hyper::Request::builder().version(version);
            if let Some(connection) = connection {
                builder = builder.header("connection", connection);
            }
            if upgrade {
                builder = builder.header("upgrade", "websocket");
            }
            builder.body(()).unwrap()
        };
        use hyper::Version;
        assert!(is_upgrade_request(&build(Version::HTTP_11, Some("Upgrade"), true)));
        assert!(is_upgrade_request(&build(Version::HTTP_11, Some("keep-alive, upgrade"), true)));
        assert!(!is_upgrade_request(&build(Version::HTTP_11, Some("keep-alive"), true)));
        assert!(!is_upgrade_request(&build(Version::HTTP_11, Some("upgrade"), false)));
        assert!(!is_upgrade_request(&build(Version::HTTP_2, Some("upgrade"), true)));
    }

    /// MITM 范围为空 = 不限；有值时按后缀匹配，同名前缀的伪装域不算
    #[test]
    fn mitm_scope_matches_suffix_only() {
        assert!(in_mitm_scope(&[], "example.com"));
        let scope = vec!["linux.do".to_string()];
        assert!(in_mitm_scope(&scope, "linux.do"));
        assert!(in_mitm_scope(&scope, "LINUX.DO."));
        assert!(in_mitm_scope(&scope, "cdn.linux.do"));
        assert!(in_mitm_scope(&scope, "x.cdn.linux.do"));
        assert!(!in_mitm_scope(&scope, "notlinux.do"));
        assert!(!in_mitm_scope(&scope, "linux.do.evil.test"));
        assert!(!in_mitm_scope(&scope, "github.com"));
        assert!(!in_mitm_scope(&scope, ""));
        let dotted = vec![".linux.do".to_string()];
        assert!(in_mitm_scope(&dotted, "linux.do"));
    }

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

    /// 网关不转发指向本机的 Host（端口探测会带 `Host: 127.0.0.1:<网关端口>`）
    #[test]
    fn loopback_hosts_are_recognised() {
        for host in ["localhost", "LOCALHOST.", "127.0.0.1", "127.8.9.10", "::1"] {
            assert!(is_loopback_host(host), "{}", host);
        }
        for host in ["linux.do", "localhost.linux.do", "10.0.0.1", "::2", ""] {
            assert!(!is_loopback_host(host), "{}", host);
        }
        assert_eq!(gateway_parse_host("[::1]:8080"), Some(("::1".to_string(), 8080)));
    }

    /// 不开 DoH 的网关（App 在 VPN 让路时只为指纹起的那种）照样按浏览器指纹握手；
    /// 没有证书管理器，内置网页的 CONNECT 一律走隧道
    #[cfg(feature = "browser-tls")]
    #[tokio::test]
    async fn gateway_without_doh_keeps_browser_fingerprint() {
        let server = super::DohProxyServer::new(crate::ProxyConfig {
            enable_doh: false,
            gateway_mode: true,
            browser_tls: true,
            select_mode: "off".to_string(),
            ..crate::ProxyConfig::default()
        })
        .await
        .unwrap();
        assert_eq!(server.fingerprint_status()["enabled"], true);
        assert!(server.cert_manager().is_none());

        let tunnel_only = super::DohProxyServer::new(crate::ProxyConfig {
            enable_doh: false,
            gateway_mode: false,
            browser_tls: true,
            select_mode: "off".to_string(),
            ..crate::ProxyConfig::default()
        })
        .await
        .unwrap();
        assert_eq!(tunnel_only.fingerprint_status()["enabled"], false);
    }
}
