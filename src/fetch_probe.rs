//! WebView 主动采样请求头顺序。
//!
//! Chromium 的请求头顺序随头名组合变化，网关道（Dart）的组合 WebView 平时未必发过，采样簿
//! 里对不上就只能近似排。宿主让隐藏 WebView 打开 `https://<论坛>/__cfluxdo_probe__/`：页面
//! 按网关道最近没对上的组合（[`FetchMisses`]）各发一个同源 fetch，自己要设的头照组合设上，
//! 其余由浏览器自己加。页面和这些请求都由核心在 h2 MITM 里直接应答，**不出本机**；fetch 请求
//! 经 [`FingerprintTemplates::observe_probe_fetch`] 记进采样簿，连同它带的 Client Hints。

use bytes::Bytes;
use http::header::{CACHE_CONTROL, CONTENT_TYPE};
use http::{Request, Response, StatusCode, Version};
use http_body_util::{BodyExt, Full};
use tracing::info;

use crate::browser_tls::FingerprintTemplates;
use crate::fetch_shape::{ClientBody, MissedSet, ProbeMethod};

/// 采样路径前缀（论坛自己不会用到）
pub const PROBE_PREFIX: &str = "/__cfluxdo_probe__/";
const PROBE_FETCH: &str = "/__cfluxdo_probe__/fetch";
/// 页面采完后把标题改成这个，宿主据此结束
pub const DONE_TITLE: &str = "cfluxdo-probe-done";

/// 浏览器自己加、页面设不了（或不该设）的头
fn browser_owned(name: &str) -> bool {
    name.starts_with("sec-")
        || matches!(
            name,
            "user-agent"
                | "referer"
                | "accept-encoding"
                | "accept-language"
                | "cookie"
                | "priority"
                | "origin"
                | "content-length"
                | "host"
        )
}

/// 页面要自己设的头与示例值（只看头名，值随便给个像样的）
fn page_headers(set: &MissedSet) -> serde_json::Map<String, serde_json::Value> {
    set.names
        .iter()
        .filter(|name| !browser_owned(name))
        .map(|name| {
            let value = match name.as_str() {
                "accept" => "application/json, text/javascript, */*; q=0.01",
                "x-requested-with" => "XMLHttpRequest",
                "content-type" => "application/x-www-form-urlencoded; charset=UTF-8",
                name if name.starts_with("discourse-") => "true",
                _ => "1",
            };
            (name.clone(), serde_json::Value::from(value))
        })
        .collect()
}

fn probe_page(sets: &[MissedSet]) -> String {
    let probes: Vec<serde_json::Value> = sets
        .iter()
        .map(|set| {
            serde_json::json!({
                "m": match set.method {
                    ProbeMethod::Get => "GET",
                    ProbeMethod::Post => "POST",
                },
                "h": page_headers(set),
            })
        })
        .collect();
    // 请求体用字节数组：浏览器不会因此自己加 content-type
    format!(
        "<!doctype html><meta charset=\"utf-8\"><title>cfluxdo-probe</title><script>\
(async()=>{{const p={};for(let i=0;i<p.length;i++){{try{{await fetch('{}?i='+i,\
{{method:p[i].m,headers:p[i].h,body:p[i].m==='POST'?new Uint8Array([49]):undefined,\
credentials:'same-origin',cache:'no-store'}});}}catch(e){{}}}}document.title='{}';}})();\
</script>",
        serde_json::Value::from(probes),
        PROBE_FETCH,
        DONE_TITLE
    )
}

fn respond_with(status: StatusCode, content_type: Option<&str>, body: String) -> Response<ClientBody> {
    let mut builder = Response::builder()
        .status(status)
        .header(CACHE_CONTROL, "no-store");
    if let Some(content_type) = content_type {
        builder = builder.header(CONTENT_TYPE, content_type);
    }
    builder
        .body(
            Full::new(Bytes::from(body))
                .map_err(|never| match never {})
                .boxed(),
        )
        .expect("static response")
}

/// MITM 道上发往采样路径的请求由核心直接应答：页面，或采样 fetch（记下头顺序后回 204）。
/// 别的路径返回 None，照常转发
pub fn respond<B>(req: &Request<B>, templates: &FingerprintTemplates) -> Option<Response<ClientBody>> {
    let path = req.uri().path();
    if !path.starts_with(PROBE_PREFIX) {
        return None;
    }
    let header = |name: &str| {
        req.headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
    };
    let host = req.uri().host().unwrap_or_default();
    if path == PROBE_PREFIX {
        let sets = templates.fetch_misses().take_for_probe();
        info!("Fetch order probe page with {} header sets", sets.len());
        return Some(respond_with(
            StatusCode::OK,
            Some("text/html; charset=utf-8"),
            probe_page(&sets),
        ));
    }
    if path == PROBE_FETCH {
        // 只认本页发出的同源 fetch：别的站点跨站打过来的不记。浏览器给它们带的 Client Hints
        // 若与之前记的不同（第一次采样多半如此），之前按旧一组记的组合作废，这一页的 fetch
        // 正好就是网关道之后照着带的样子
        if req.version() == Version::HTTP_2 && header("sec-fetch-site") == "same-origin" {
            templates.observe_probe_fetch(host, req.headers());
        }
        return Some(respond_with(StatusCode::NO_CONTENT, None, String::new()));
    }
    Some(respond_with(StatusCode::NOT_FOUND, None, String::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|name| name.to_string()).collect()
    }

    const DART_GET: &[&str] = &[
        "user-agent",
        "accept-language",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "x-csrf-token",
        "referer",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "discourse-present",
        "x-requested-with",
        "discourse-logged-in",
        "accept",
        "cookie",
        "accept-encoding",
        "priority",
    ];

    fn request(path: &str, version: Version, headers: &[(&str, &str)]) -> Request<()> {
        let mut builder = Request::builder()
            .uri(format!("https://linux.do{}", path))
            .version(version);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).unwrap()
    }

    #[tokio::test]
    async fn page_lists_missed_sets_with_only_page_settable_headers() {
        let templates = FingerprintTemplates::new(None, Some("Chrome/124.0".into()));
        templates.fetch_misses().note(names(DART_GET));
        // 图片请求（没有 sec-fetch-*）WebView 发不出同一组头，不记
        templates
            .fetch_misses()
            .note(names(&["user-agent", "accept", "cookie", "accept-encoding"]));
        assert_eq!(templates.fetch_misses().pending(), 1);

        let response = respond(&request(PROBE_PREFIX, Version::HTTP_2, &[]), &templates).unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let page = String::from_utf8(body.to_vec()).unwrap();
        for name in ["x-csrf-token", "discourse-present", "discourse-logged-in", "x-requested-with", "accept"] {
            assert!(page.contains(&format!("\"{}\"", name)), "{name} missing");
        }
        for name in ["user-agent", "cookie", "sec-fetch-mode", "priority", "referer"] {
            assert!(!page.contains(&format!("\"{}\"", name)), "{name} must be left to the browser");
        }
        assert!(page.contains(DONE_TITLE));
    }

    #[test]
    fn sets_are_retried_at_most_twice() {
        let templates = FingerprintTemplates::new(None, None);
        templates.fetch_misses().note(names(DART_GET));
        for _ in 0..2 {
            assert_eq!(templates.fetch_misses().take_for_probe().len(), 1);
        }
        assert!(templates.fetch_misses().take_for_probe().is_empty());
        assert_eq!(templates.fetch_misses().pending(), 0);
    }

    #[test]
    fn same_origin_probe_fetch_fills_the_missed_set() {
        let templates = FingerprintTemplates::new(None, Some("Chrome/124.0".into()));
        templates.fetch_misses().note(names(DART_GET));
        // WebView 发来的同一组头（顺序是它自己的）
        let mut headers: Vec<(&str, &str)> = DART_GET.iter().rev().map(|name| (*name, "1")).collect();
        for header in headers.iter_mut() {
            match header.0 {
                "sec-fetch-mode" => header.1 = "cors",
                "sec-fetch-site" => header.1 = "same-origin",
                _ => {}
            }
        }
        // 跨站打过来的不记
        let cross: Vec<(&str, &str)> = headers
            .iter()
            .map(|(name, value)| if *name == "sec-fetch-site" { (*name, "cross-site") } else { (*name, *value) })
            .collect();
        let response = respond(&request(PROBE_FETCH, Version::HTTP_2, &cross), &templates).unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(templates.fetch_misses().pending(), 1);

        respond(&request(PROBE_FETCH, Version::HTTP_2, &headers), &templates).unwrap();
        assert_eq!(templates.fetch_misses().pending(), 0);
        let orders = templates.snapshot().unwrap().fetch_header_orders.clone();
        let reversed: Vec<String> = DART_GET.iter().rev().map(|name| name.to_string()).collect();
        assert_eq!(orders.first(), Some(&reversed));
    }

    #[test]
    fn other_paths_are_forwarded() {
        let templates = FingerprintTemplates::new(None, None);
        assert!(respond(&request("/latest.json", Version::HTTP_2, &[]), &templates).is_none());
        let unknown = respond(&request("/__cfluxdo_probe__/nope", Version::HTTP_2, &[]), &templates).unwrap();
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    }
}
