//! 端到端看一眼浏览器指纹出口：经连接池（网关道）请求 tls.peet.ws，打印对方看到的
//! TLS / HTTP2 指纹。不带任何 Cookie。
//!
//! ```text
//! cargo run --example fingerprint_probe --features browser-tls -- [Chrome UA]
//! ```

use bytes::Bytes;
use doh_proxy::browser_tls::BrowserTls;
use doh_proxy::ech::DohTlsConnector;
use doh_proxy::upstream_pool::{Lane, UpstreamPool};
use http_body_util::{BodyExt, Empty};
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() {
    let ua = std::env::args().nth(1).unwrap_or_else(|| {
        "Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Mobile Safari/537.36".to_string()
    });
    let browser = Arc::new(BrowserTls::new(None, Some(ua.clone())));
    println!("template: {}", browser.templates().status_json());
    let connector = DohTlsConnector::new(None, false, Duration::from_secs(15), None, None)
        .with_browser_tls(browser);
    let pool = UpstreamPool::new(Arc::new(connector));
    for round in 0..2 {
        let req = hyper::Request::builder()
            .method("GET")
            .uri("https://tls.peet.ws/api/all")
            .header("host", "tls.peet.ws")
            .header("user-agent", &ua)
            .header("accept", "*/*")
            .body(Empty::<Bytes>::new().map_err(|never| match never {}).boxed())
            .unwrap();
        let response = pool
            .forward(Lane::Gateway, "tls.peet.ws", 443, req, None)
            .await
            .expect("forward");
        let body = response.into_body().collect().await.expect("body").to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        println!("--- round {}", round);
        println!("http_version {}", json["http_version"]);
        println!("ja4 {}", json["tls"]["ja4"]);
        println!("peetprint_hash {}", json["tls"]["peetprint_hash"]);
        println!("akamai {}", json["http2"]["akamai_fingerprint"]);
        if let Some(frames) = json["http2"]["sent_frames"].as_array() {
            for frame in frames.iter().take(4) {
                println!("frame {}", frame);
            }
        }
    }
}
