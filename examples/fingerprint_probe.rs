//! 端到端看一眼浏览器指纹出口：经连接池（网关道）请求 tls.peet.ws，打印对方看到的
//! TLS / HTTP2 指纹。不带任何 Cookie。
//!
//! ```text
//! cargo run --example fingerprint_probe --features browser-tls -- [Chrome UA]
//! ```

use bytes::Bytes;
use doh_proxy::browser_tls::BrowserTls;
use doh_proxy::ech::DohTlsConnector;
use doh_proxy::fetch_shape;
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
    // PROBE_URL=https://host/path：只看这个地址回来的压缩方式与解压结果
    if let Ok(url) = std::env::var("PROBE_URL") {
        let uri: hyper::Uri = url.parse().expect("url");
        let host = uri.host().expect("host").to_string();
        let mut req = hyper::Request::builder()
            .method("GET")
            .uri(uri)
            .header("host", &host)
            .header("user-agent", &ua)
            .header("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            .header("accept-encoding", "gzip")
            .body(Empty::<Bytes>::new().map_err(|never| match never {}).boxed())
            .unwrap();
        let decode = pool
            .fetch_shape()
            .is_some_and(|shape| shape.apply(req.headers_mut(), &host));
        let response = pool
            .forward(Lane::Gateway, &host, 443, req, None)
            .await
            .expect("forward");
        println!(
            "status {} content-encoding {:?} content-length {:?} (decode {})",
            response.status(),
            response.headers().get("content-encoding"),
            response.headers().get("content-length"),
            decode
        );
        let response = fetch_shape::decode_response(response);
        println!(
            "after decode: content-encoding {:?} content-length {:?}",
            response.headers().get("content-encoding"),
            response.headers().get("content-length")
        );
        let body = response.into_body().collect().await.expect("body").to_bytes();
        println!(
            "decoded {} bytes: {:?}",
            body.len(),
            String::from_utf8_lossy(&body[..body.len().min(80)])
        );
        return;
    }
    for round in 0..2 {
        // 照 Dart 拦截器的顺序与 dart:io 的默认 Accept-Encoding 发，经网关道同样的整形
        let mut req = hyper::Request::builder()
            .method("GET")
            .uri("https://tls.peet.ws/api/all")
            .header("host", "tls.peet.ws")
            .header("user-agent", &ua)
            .header("accept-language", "zh-CN,zh;q=0.9")
            .header("sec-ch-ua", "\"Chromium\";v=\"133\", \"Android WebView\";v=\"133\", \"Not-A.Brand\";v=\"99\"")
            .header("sec-ch-ua-mobile", "?1")
            .header("sec-ch-ua-platform", "\"Android\"")
            .header("referer", "https://tls.peet.ws/")
            .header("sec-fetch-dest", "empty")
            .header("sec-fetch-mode", "cors")
            .header("sec-fetch-site", "same-origin")
            .header("x-requested-with", "XMLHttpRequest")
            .header("accept", "application/json, text/javascript, */*; q=0.01")
            .header("accept-encoding", "gzip")
            .body(Empty::<Bytes>::new().map_err(|never| match never {}).boxed())
            .unwrap();
        let decode = pool
            .fetch_shape()
            .is_some_and(|shape| shape.apply(req.headers_mut(), "tls.peet.ws"));
        let response = pool
            .forward(Lane::Gateway, "tls.peet.ws", 443, req, None)
            .await
            .expect("forward");
        println!("--- round {}", round);
        println!(
            "content-encoding from server {:?} (decode {})",
            response.headers().get("content-encoding"),
            decode
        );
        let response = if decode {
            fetch_shape::decode_response(response)
        } else {
            fetch_shape::passthrough(response)
        };
        let body = response.into_body().collect().await.expect("body").to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
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
