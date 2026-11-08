//! 网关道（Dart）的请求照 WebView 的 fetch 请求整形，与浏览器指纹握手配套：
//!
//! - 头顺序：Chromium 渲染进程用哈希表存请求头，JS 设的头与 UA、client hints 交错，顺序随
//!   头名集合变化；网络栈再在后面接 sec-fetch-*、referer、accept-encoding、accept-language、
//!   cookie、priority。采到过同一组头名的 WebView 请求就照它排；没采到的照最近一次采样
//!   （或预置）排，模板里没有的头插在网络栈那几个之前；
//! - Accept-Encoding：dart:io 只发 `gzip`，Chrome 发 `gzip, deflate, br, zstd`。换成浏览器的值，
//!   回来的 br / zstd / deflate 由 [`decode_response`] 解开再交给 Dart（gzip 仍由 Dart 自己解）；
//! - `priority`：Chrome 给 fetch 请求带 `priority: u=1, i`（RFC 9218），Dart 的没有就补上；
//! - Client Hints：站点（CF 验证页）用 Accept-CH 要过高熵提示后，真页面里的 fetch 都带
//!   `sec-ch-ua-arch`、`sec-ch-ua-model` 等，Dart 只有低熵三件套。网关道发给同一主机的 fetch 请求
//!   照 WebView 采样页里的 fetch 带的那组 `sec-ch-*`（名字和值）带。
//!
//! 采样簿里没有同集合的头名组合记进 [`FetchMisses`]，由 WebView 主动采样补上（见 `fetch_probe`）。

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use parking_lot::Mutex;

use bytes::Bytes;
use http::header::{HeaderMap, HeaderName, HeaderValue, ACCEPT_ENCODING, HOST, RANGE};
use http_body_util::{combinators::BoxBody, BodyExt};
use hyper::Response;

use crate::upstream_pool::PoolBody;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
/// 交给 Dart / WebView 的响应体
pub type ClientBody = BoxBody<Bytes, BoxError>;

/// Chromium 网络栈接在渲染进程的头后面的那几个
const NETWORK_TAIL: &[&str] = &[
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-user",
    "sec-fetch-dest",
    "sec-fetch-storage-access",
    "referer",
    "accept-encoding",
    "accept-language",
    "cookie",
    "priority",
];
/// 上游预置里标记「页面自定义头」位置的占位名
const CUSTOM_MARKER: &str = "x-rama-custom-header-marker";
/// 逐跳头：h2 上游由 hyper 剥掉，不参与排序比较
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
    "te",
];
/// 最多记几组头名集合各自的顺序
pub const MAX_ORDERS: usize = 48;

/// 排序与比较时跳过的头：Host（h2 上游不发，h1 放最前）与逐跳头
fn skipped(name: &HeaderName) -> bool {
    name == HOST || HOP_BY_HOP.contains(&name.as_str())
}

/// 一组请求头名（小写、按出现顺序、不重复），跳过 Host 与逐跳头
pub fn header_names(headers: &HeaderMap) -> Vec<String> {
    headers
        .keys()
        .filter(|name| !skipped(name))
        .map(|name| name.as_str().to_owned())
        .collect()
}

/// 两组头名是不是同一个集合
pub fn same_name_set(a: &[String], b: &[String]) -> bool {
    a.len() == b.len() && {
        let set: HashSet<&String> = a.iter().collect();
        b.iter().all(|name| set.contains(name))
    }
}

/// WebView 的 fetch 一定会带、Dart 请求也带齐了才值得让 WebView 去采的头。WebView 的请求
/// 一律带 X-Requested-With（页面没设就是包名），所以 Dart 那边没有它的组合采不到
const PROBE_REQUIRED: &[&str] = &[
    "user-agent",
    "accept",
    "x-requested-with",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-dest",
    "referer",
    "accept-encoding",
    "accept-language",
];
/// 最多记几组没对上的头名组合
const MAX_MISSES: usize = 32;
/// 一组头名最多让 WebView 采几次（采回来的集合对不上就不再试）
const MAX_PROBE_ATTEMPTS: u8 = 2;
/// 一页最多采几组
pub const MAX_PROBES_PER_PAGE: usize = 8;

/// 采样请求用的方法：GET 或带请求体的 POST（浏览器给 POST 加 origin 与 content-length）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeMethod {
    Get,
    Post,
}

#[derive(Debug, Clone)]
pub struct MissedSet {
    /// 头名（小写，Dart 发出时的顺序）
    pub names: Vec<String>,
    pub method: ProbeMethod,
    pub count: u32,
    pub attempts: u8,
}

/// 网关道请求的头名组合在采样簿里找不到时记一笔，等 WebView 主动采样
#[derive(Debug, Default)]
pub struct FetchMisses {
    entries: Mutex<Vec<MissedSet>>,
}

impl FetchMisses {
    /// WebView 能不能发出同一组头名：浏览器自己加的头 Dart 也得带齐；带请求体的只认 POST
    fn probe_method(names: &[String]) -> Option<ProbeMethod> {
        let has = |name: &str| names.iter().any(|n| n == name);
        if !PROBE_REQUIRED.iter().all(|name| has(name)) {
            return None;
        }
        match (has("content-length"), has("origin")) {
            (true, true) => Some(ProbeMethod::Post),
            (false, false) => Some(ProbeMethod::Get),
            _ => None,
        }
    }

    pub fn note(&self, names: Vec<String>) {
        let Some(method) = Self::probe_method(&names) else {
            return;
        };
        let mut entries = self.entries.lock();
        if let Some(entry) = entries
            .iter_mut()
            .find(|entry| same_name_set(&entry.names, &names))
        {
            entry.count = entry.count.saturating_add(1);
            return;
        }
        if entries.len() >= MAX_MISSES {
            if let Some(index) = entries
                .iter()
                .enumerate()
                .min_by_key(|(_, entry)| entry.count)
                .map(|(index, _)| index)
            {
                entries.remove(index);
            }
        }
        entries.push(MissedSet {
            names,
            method,
            count: 1,
            attempts: 0,
        });
    }

    /// 网关道的头名组合整体变了（换了一组 Client Hints），之前记的都不作数
    pub fn clear(&self) {
        self.entries.lock().clear();
    }

    /// WebView 采到了这组头名：不再缺
    pub fn resolve(&self, names: &[String]) -> bool {
        let mut entries = self.entries.lock();
        let before = entries.len();
        entries.retain(|entry| !same_name_set(&entry.names, names));
        entries.len() != before
    }

    /// 还值得采的组数
    pub fn pending(&self) -> usize {
        self.entries
            .lock()
            .iter()
            .filter(|entry| entry.attempts < MAX_PROBE_ATTEMPTS)
            .count()
    }

    /// 取出这一页要采的组（出现最多的在前），并记一次尝试
    pub fn take_for_probe(&self) -> Vec<MissedSet> {
        let mut entries = self.entries.lock();
        let mut picked: Vec<&mut MissedSet> = entries
            .iter_mut()
            .filter(|entry| entry.attempts < MAX_PROBE_ATTEMPTS)
            .collect();
        picked.sort_by(|a, b| b.count.cmp(&a.count));
        picked
            .into_iter()
            .take(MAX_PROBES_PER_PAGE)
            .map(|entry| {
                entry.attempts += 1;
                entry.clone()
            })
            .collect()
    }
}

#[derive(Debug, Clone, Default)]
pub struct FetchShape {
    /// 采到的 WebView fetch 头顺序，每组头名集合一份，新的在前
    orders: Vec<Vec<HeaderName>>,
    /// 没有同集合的采样时照这个排（最近一次采样，或预置）
    fallback: Vec<HeaderName>,
    accept_encoding: Option<HeaderValue>,
    /// 模板里有 priority 头（Chrome 124 起才发）
    send_priority: bool,
    /// WebView 采样页的 fetch 发给各主机时带的 `sec-ch-*`
    client_hints: HashMap<String, Vec<(HeaderName, HeaderValue)>>,
    /// 没对上的头名组合记到这里（与模板仓库共用一份）
    misses: Option<Arc<FetchMisses>>,
}

fn parse_names(names: &[String]) -> Vec<HeaderName> {
    names
        .iter()
        .filter_map(|name| HeaderName::from_bytes(name.as_bytes()).ok())
        .collect()
}

impl FetchShape {
    pub fn new(
        orders: &[Vec<String>],
        fallback: &[String],
        accept_encoding: Option<&str>,
        client_hints: &BTreeMap<String, Vec<(String, String)>>,
        misses: Option<Arc<FetchMisses>>,
    ) -> Self {
        let orders: Vec<Vec<HeaderName>> = orders
            .iter()
            .take(MAX_ORDERS)
            .map(|order| parse_names(order))
            .collect();
        let fallback = parse_names(fallback);
        let send_priority = fallback
            .iter()
            .chain(orders.iter().flatten())
            .any(|name| name.as_str() == "priority");
        Self {
            orders,
            fallback,
            accept_encoding: accept_encoding.and_then(|value| HeaderValue::from_str(value).ok()),
            send_priority,
            client_hints: client_hints
                .iter()
                .map(|(host, hints)| {
                    let hints = hints
                        .iter()
                        .filter_map(|(name, value)| {
                            Some((
                                HeaderName::from_bytes(name.as_bytes()).ok()?,
                                HeaderValue::from_str(value).ok()?,
                            ))
                        })
                        .collect();
                    (host.clone(), hints)
                })
                .collect(),
            misses,
        }
    }

    /// 整形发往 `host` 的请求；返回 true 表示 Accept-Encoding 换成了浏览器的值，响应要交给
    /// [`decode_response`]
    pub fn apply(&self, headers: &mut HeaderMap, host: &str) -> bool {
        // 冒充浏览器 fetch 的请求（带 sec-fetch-*）才照 WebView 带 Client Hints
        if headers.contains_key("sec-fetch-mode") {
            if let Some(hints) = self.client_hints.get(&host.to_ascii_lowercase()) {
                let dart_hints: Vec<HeaderName> = headers
                    .keys()
                    .filter(|name| name.as_str().starts_with("sec-ch-"))
                    .cloned()
                    .collect();
                for name in dart_hints {
                    headers.remove(name);
                }
                for (name, value) in hints {
                    headers.append(name.clone(), value.clone());
                }
            }
        }
        let is_fetch = headers
            .get("sec-fetch-mode")
            .is_some_and(|mode| mode.as_bytes() == b"cors");
        if is_fetch && self.send_priority && !headers.contains_key("priority") {
            headers.insert(
                HeaderName::from_static("priority"),
                HeaderValue::from_static("u=1, i"),
            );
        }
        let mut rewrote = false;
        if let Some(value) = &self.accept_encoding {
            // 只换 dart:io 的默认值；调用方自己指定的（identity 等）与分段请求不动
            let mut values = headers.get_all(ACCEPT_ENCODING).iter();
            let dart_default = values
                .next()
                .is_some_and(|first| first.as_bytes().eq_ignore_ascii_case(b"gzip"))
                && values.next().is_none();
            if dart_default && !headers.contains_key(RANGE) {
                headers.insert(ACCEPT_ENCODING, value.clone());
                rewrote = true;
            }
        }
        let order = self.order_for(headers);
        *headers = reorder(std::mem::take(headers), &order);
        rewrote
    }

    fn order_for(&self, headers: &HeaderMap) -> Vec<HeaderName> {
        let names: Vec<&HeaderName> = headers.keys().filter(|name| !skipped(name)).collect();
        let present: HashSet<&HeaderName> = names.iter().copied().collect();
        if let Some(order) = self
            .orders
            .iter()
            .find(|order| order.len() == present.len() && order.iter().all(|n| present.contains(n)))
        {
            crate::stats::STATS.gw_order_exact.inc();
            return order.clone();
        }
        crate::stats::STATS.gw_order_fallback.inc();
        if let Some(misses) = &self.misses {
            misses.note(names.iter().map(|name| name.as_str().to_owned()).collect());
        }
        let base = if self.fallback.is_empty() {
            self.orders.first().map(Vec::as_slice).unwrap_or_default()
        } else {
            self.fallback.as_slice()
        };
        let known: HashSet<&HeaderName> = base.iter().collect();
        let unknown: Vec<HeaderName> = names
            .iter()
            .filter(|name| !known.contains(**name))
            .map(|name| (*name).clone())
            .collect();
        let mut order = Vec::with_capacity(names.len());
        let mut inserted = unknown.is_empty();
        for name in base {
            if name.as_str() == CUSTOM_MARKER || (!inserted && NETWORK_TAIL.contains(&name.as_str()) && present.contains(name)) {
                if !inserted {
                    order.extend(unknown.iter().cloned());
                    inserted = true;
                }
                if name.as_str() == CUSTOM_MARKER {
                    continue;
                }
            }
            if present.contains(name) {
                order.push(name.clone());
            }
        }
        if !inserted {
            order.extend(unknown);
        }
        order
    }
}

/// 按给定顺序重排：Host 在最前，`order` 里的依次排，其余（逐跳头等）原序在后。只改顺序
fn reorder(mut headers: HeaderMap, order: &[HeaderName]) -> HeaderMap {
    let mut out = HeaderMap::with_capacity(headers.len());
    let take = |name: &HeaderName, headers: &mut HeaderMap, out: &mut HeaderMap| {
        if let http::header::Entry::Occupied(entry) = headers.entry(name) {
            let (name, values) = entry.remove_entry_mult();
            for value in values {
                out.append(name.clone(), value);
            }
        }
    };
    take(&HOST, &mut headers, &mut out);
    for name in order {
        take(name, &mut headers, &mut out);
    }
    let mut last: Option<HeaderName> = None;
    for (name, value) in headers {
        if let Some(name) = name {
            last = Some(name);
        }
        if let Some(name) = &last {
            out.append(name.clone(), value);
        }
    }
    out
}

/// 不解压，只换响应体的错误类型
pub fn passthrough(response: Response<PoolBody>) -> Response<ClientBody> {
    response.map(|body| body.map_err(BoxError::from).boxed())
}

/// 解开 Accept-Encoding 换过之后回来的 br / zstd / deflate；gzip 与未压缩的原样交给 Dart
#[cfg(feature = "browser-tls")]
pub fn decode_response(response: Response<PoolBody>) -> Response<ClientBody> {
    use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE};

    let coding = response
        .headers()
        .get(CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_ascii_lowercase());
    let status = response.status();
    let bodiless = status.is_informational()
        || status == http::StatusCode::NO_CONTENT
        || status == http::StatusCode::NOT_MODIFIED
        || response.headers().contains_key(CONTENT_RANGE);
    let decoder = match coding.as_deref() {
        _ if bodiless => None,
        Some("br") => Some(decode::Decoder::brotli()),
        Some("zstd") => decode::Decoder::zstd().ok(),
        Some("deflate") => Some(decode::Decoder::deflate()),
        _ => None,
    };
    let Some(decoder) = decoder else {
        return passthrough(response);
    };
    let (mut parts, body) = response.into_parts();
    parts.headers.remove(CONTENT_ENCODING);
    parts.headers.remove(CONTENT_LENGTH);
    Response::from_parts(parts, decode::DecodedBody::new(body, decoder).boxed())
}

#[cfg(not(feature = "browser-tls"))]
pub fn decode_response(response: Response<PoolBody>) -> Response<ClientBody> {
    passthrough(response)
}

#[cfg(feature = "browser-tls")]
mod decode {
    use std::io::{self, Write};
    use std::pin::Pin;
    use std::task::{ready, Context, Poll};

    use bytes::Bytes;
    use hyper::body::{Body, Frame};

    use super::BoxError;
    use crate::upstream_pool::PoolBody;

    pub enum Decoder {
        Brotli(Box<brotli::DecompressorWriter<Vec<u8>>>),
        Zstd(Box<zstd::stream::write::Decoder<'static, Vec<u8>>>),
        Zlib(Box<flate2::write::ZlibDecoder<Vec<u8>>>),
        RawDeflate(Box<flate2::write::DeflateDecoder<Vec<u8>>>),
        /// deflate 还没收到头两个字节，分不清有没有 zlib 包装（两种服务端都有）
        Deflate(Vec<u8>),
    }

    impl Decoder {
        pub fn brotli() -> Self {
            Self::Brotli(Box::new(brotli::DecompressorWriter::new(Vec::new(), 16 * 1024)))
        }

        pub fn zstd() -> io::Result<Self> {
            Ok(Self::Zstd(Box::new(zstd::stream::write::Decoder::new(Vec::new())?)))
        }

        pub fn deflate() -> Self {
            Self::Deflate(Vec::new())
        }

        /// 喂一段压缩数据，取出已解出的部分
        pub fn feed(&mut self, data: &[u8]) -> io::Result<Bytes> {
            if let Self::Deflate(head) = self {
                head.extend_from_slice(data);
                if head.len() < 2 {
                    return Ok(Bytes::new());
                }
                let head = std::mem::take(head);
                // zlib 头：CM = 8，且头两字节按大端是 31 的倍数
                let zlib = head[0] & 0x0f == 8 && u16::from_be_bytes([head[0], head[1]]) % 31 == 0;
                *self = if zlib {
                    Self::Zlib(Box::new(flate2::write::ZlibDecoder::new(Vec::new())))
                } else {
                    Self::RawDeflate(Box::new(flate2::write::DeflateDecoder::new(Vec::new())))
                };
                return self.feed(&head);
            }
            match self {
                Self::Brotli(decoder) => {
                    decoder.write_all(data)?;
                    Ok(Bytes::from(std::mem::take(decoder.get_mut())))
                }
                Self::Zstd(decoder) => {
                    decoder.write_all(data)?;
                    decoder.flush()?;
                    Ok(Bytes::from(std::mem::take(decoder.get_mut())))
                }
                Self::Zlib(decoder) => {
                    decoder.write_all(data)?;
                    decoder.flush()?;
                    Ok(Bytes::from(std::mem::take(decoder.get_mut())))
                }
                Self::RawDeflate(decoder) => {
                    decoder.write_all(data)?;
                    decoder.flush()?;
                    Ok(Bytes::from(std::mem::take(decoder.get_mut())))
                }
                Self::Deflate(_) => unreachable!(),
            }
        }

        /// 数据收完：取出剩下的，流不完整时报错
        pub fn finish(&mut self) -> io::Result<Bytes> {
            match self {
                Self::Brotli(decoder) => {
                    decoder.close()?;
                    Ok(Bytes::from(std::mem::take(decoder.get_mut())))
                }
                Self::Zstd(decoder) => {
                    decoder.flush()?;
                    Ok(Bytes::from(std::mem::take(decoder.get_mut())))
                }
                Self::Zlib(decoder) => {
                    decoder.try_finish()?;
                    Ok(Bytes::from(std::mem::take(decoder.get_mut())))
                }
                Self::RawDeflate(decoder) => {
                    decoder.try_finish()?;
                    Ok(Bytes::from(std::mem::take(decoder.get_mut())))
                }
                Self::Deflate(head) if head.is_empty() => Ok(Bytes::new()),
                Self::Deflate(_) => Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated deflate stream",
                )),
            }
        }
    }

    /// 边收边解的响应体
    pub struct DecodedBody {
        inner: PoolBody,
        decoder: Decoder,
        /// 收到过数据（HEAD 等空响应收完时不必收尾）
        fed: bool,
        done: bool,
        /// 解完剩余数据后再交出的尾部帧（trailers）
        pending: Option<Frame<Bytes>>,
    }

    impl DecodedBody {
        pub fn new(inner: PoolBody, decoder: Decoder) -> Self {
            Self {
                inner,
                decoder,
                fed: false,
                done: false,
                pending: None,
            }
        }

        fn finish(&mut self) -> io::Result<Bytes> {
            self.done = true;
            if self.fed {
                self.decoder.finish()
            } else {
                Ok(Bytes::new())
            }
        }
    }

    impl Body for DecodedBody {
        type Data = Bytes;
        type Error = BoxError;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
            let this = &mut *self;
            loop {
                if let Some(frame) = this.pending.take() {
                    return Poll::Ready(Some(Ok(frame)));
                }
                if this.done {
                    return Poll::Ready(None);
                }
                match ready!(Pin::new(&mut this.inner).poll_frame(cx)) {
                    Some(Ok(frame)) => match frame.into_data() {
                        Ok(data) => {
                            this.fed |= !data.is_empty();
                            let out = this.decoder.feed(&data)?;
                            if !out.is_empty() {
                                return Poll::Ready(Some(Ok(Frame::data(out))));
                            }
                        }
                        Err(trailers) => {
                            let out = this.finish()?;
                            if out.is_empty() {
                                return Poll::Ready(Some(Ok(trailers)));
                            }
                            this.pending = Some(trailers);
                            return Poll::Ready(Some(Ok(Frame::data(out))));
                        }
                    },
                    Some(Err(error)) => return Poll::Ready(Some(Err(error.into()))),
                    None => {
                        let out = this.finish()?;
                        if !out.is_empty() {
                            return Poll::Ready(Some(Ok(Frame::data(out))));
                        }
                    }
                }
            }
        }

        fn is_end_stream(&self) -> bool {
            self.done && self.pending.is_none()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|name| name.to_string()).collect()
    }

    fn headers(list: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in list {
            map.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    fn order_of(map: &HeaderMap) -> Vec<&str> {
        map.keys().map(HeaderName::as_str).collect()
    }

    /// Chrome 124 实测的 fetch 顺序（带 Discourse 的自定义头）
    const CHROME_FETCH: &[&str] = &[
        "sec-ch-ua",
        "discourse-present",
        "x-csrf-token",
        "sec-ch-ua-mobile",
        "user-agent",
        "discourse-logged-in",
        "accept",
        "x-requested-with",
        "sec-ch-ua-platform",
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-dest",
        "referer",
        "accept-encoding",
        "accept-language",
        "cookie",
        "priority",
    ];

    fn dart_request() -> HeaderMap {
        headers(&[
            ("host", "linux.do"),
            ("user-agent", "UA"),
            ("accept-language", "zh-CN"),
            ("sec-ch-ua", "x"),
            ("sec-ch-ua-mobile", "?1"),
            ("sec-ch-ua-platform", "\"Android\""),
            ("x-csrf-token", "t"),
            ("referer", "https://linux.do/"),
            ("sec-fetch-dest", "empty"),
            ("sec-fetch-mode", "cors"),
            ("sec-fetch-site", "same-origin"),
            ("discourse-present", "true"),
            ("x-requested-with", "XMLHttpRequest"),
            ("discourse-logged-in", "true"),
            ("accept", "application/json"),
            ("cookie", "a=b"),
            ("accept-encoding", "gzip"),
            ("connection", "keep-alive"),
        ])
    }

    #[test]
    fn same_name_set_follows_the_sampled_order_exactly() {
        let shape = FetchShape::new(&[names(CHROME_FETCH)], &[], Some("gzip, deflate, br, zstd"), &BTreeMap::new(), None);
        let mut map = dart_request();
        assert!(shape.apply(&mut map, "linux.do"));
        let mut expected = vec!["host"];
        expected.extend_from_slice(CHROME_FETCH);
        expected.push("connection");
        assert_eq!(order_of(&map), expected);
        assert_eq!(map["accept-encoding"], "gzip, deflate, br, zstd");
        assert_eq!(map["priority"], "u=1, i");
    }

    #[test]
    fn unknown_headers_go_before_the_network_tail() {
        let preset = names(&[
            "content-length",
            "sec-ch-ua-platform",
            "user-agent",
            "sec-ch-ua",
            "content-type",
            "sec-ch-ua-mobile",
            "accept",
            "origin",
            "x-requested-with",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-dest",
            "referer",
            "accept-encoding",
            "accept-language",
            "cookie",
            "priority",
        ]);
        let shape = FetchShape::new(&[], &preset, Some("gzip, deflate, br, zstd"), &BTreeMap::new(), None);
        let mut map = dart_request();
        shape.apply(&mut map, "linux.do");
        assert_eq!(
            order_of(&map),
            vec![
                "host",
                "sec-ch-ua-platform",
                "user-agent",
                "sec-ch-ua",
                "sec-ch-ua-mobile",
                "accept",
                "x-requested-with",
                // 模板里没有的，原序插在 sec-fetch-* 之前
                "x-csrf-token",
                "discourse-present",
                "discourse-logged-in",
                "sec-fetch-site",
                "sec-fetch-mode",
                "sec-fetch-dest",
                "referer",
                "accept-encoding",
                "accept-language",
                "cookie",
                "priority",
                "connection",
            ]
        );
    }

    #[test]
    fn custom_marker_places_unknown_headers() {
        let shape = FetchShape::new(
            &[],
            &names(&["sec-ch-ua", "x-rama-custom-header-marker", "user-agent", "sec-fetch-mode"]),
            None,
            &BTreeMap::new(),
            None,
        );
        let mut map = headers(&[
            ("sec-fetch-mode", "cors"),
            ("x-custom", "1"),
            ("user-agent", "UA"),
            ("sec-ch-ua", "x"),
        ]);
        assert!(!shape.apply(&mut map, "linux.do"));
        assert_eq!(
            order_of(&map),
            vec!["sec-ch-ua", "x-custom", "user-agent", "sec-fetch-mode"]
        );
        // 模板里没有 priority（老版本 Chrome）就不补
        assert!(!map.contains_key("priority"));
    }

    #[test]
    fn explicit_encodings_and_ranges_are_left_alone() {
        let shape = FetchShape::new(&[], &names(CHROME_FETCH), Some("gzip, deflate, br, zstd"), &BTreeMap::new(), None);
        let mut identity = headers(&[("accept-encoding", "identity")]);
        assert!(!shape.apply(&mut identity, "linux.do"));
        assert_eq!(identity["accept-encoding"], "identity");
        let mut range = headers(&[("accept-encoding", "gzip"), ("range", "bytes=0-")]);
        assert!(!shape.apply(&mut range, "linux.do"));
        assert_eq!(range["accept-encoding"], "gzip");
    }

    /// 冒充 fetch 的请求照 WebView 发给同一主机的那组 Client Hints 带（名字和值都换成它的）
    #[test]
    fn client_hints_follow_the_webview_for_the_same_host() {
        let mut hints = BTreeMap::new();
        hints.insert(
            "linux.do".to_string(),
            vec![
                ("sec-ch-ua".to_string(), "\"Android WebView\";v=\"124\"".to_string()),
                ("sec-ch-ua-mobile".to_string(), "?1".to_string()),
                ("sec-ch-ua-model".to_string(), "\"Pixel\"".to_string()),
                ("sec-ch-ua-arch".to_string(), "\"\"".to_string()),
            ],
        );
        let shape = FetchShape::new(&[], &names(CHROME_FETCH), None, &hints, None);
        let mut fetch = headers(&[
            ("sec-ch-ua", "dart"),
            ("sec-ch-ua-mobile", "?1"),
            ("sec-ch-ua-platform", "\"Android\""),
            ("sec-fetch-mode", "cors"),
        ]);
        shape.apply(&mut fetch, "LINUX.DO");
        assert_eq!(fetch["sec-ch-ua"], "\"Android WebView\";v=\"124\"");
        assert_eq!(fetch["sec-ch-ua-model"], "\"Pixel\"");
        assert!(fetch.contains_key("sec-ch-ua-arch"));
        // WebView 这一组里没有的就不带
        assert!(!fetch.contains_key("sec-ch-ua-platform"));

        let mut other_host = headers(&[("sec-ch-ua", "dart"), ("sec-fetch-mode", "cors")]);
        shape.apply(&mut other_host, "tls.peet.ws");
        assert_eq!(other_host["sec-ch-ua"], "dart");
        let mut image = headers(&[("sec-ch-ua", "dart"), ("accept", "image/webp")]);
        shape.apply(&mut image, "linux.do");
        assert_eq!(image["sec-ch-ua"], "dart");
        assert!(!image.contains_key("sec-ch-ua-model"));
    }

    #[test]
    fn repeated_values_keep_their_order() {
        let shape = FetchShape::new(&[], &names(&["accept", "cookie"]), None, &BTreeMap::new(), None);
        let mut map = headers(&[("cookie", "a=1"), ("accept", "*/*"), ("cookie", "b=2")]);
        shape.apply(&mut map, "linux.do");
        let cookies: Vec<_> = map.get_all("cookie").iter().collect();
        assert_eq!(cookies, vec!["a=1", "b=2"]);
        assert_eq!(order_of(&map), vec!["accept", "cookie"]);
    }

    #[cfg(feature = "browser-tls")]
    mod decoding {
        use super::super::*;
        use http_body_util::{BodyExt, Full};
        use hyper::body::{Body, Frame};
        use std::collections::VecDeque;
        use std::io::Write;
        use std::pin::Pin;
        use std::task::{Context, Poll};

        const TEXT: &[u8] = b"{\"topic_list\":{\"topics\":[1,2,3]},\"users\":[]} repeated repeated repeated";

        /// 一帧一帧交出的响应体
        struct Chunks(VecDeque<Bytes>);

        impl Body for Chunks {
            type Data = Bytes;
            type Error = hyper::Error;

            fn poll_frame(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
                Poll::Ready(self.0.pop_front().map(|chunk| Ok(Frame::data(chunk))))
            }
        }

        fn chunked_response(encoding: &str, body: Vec<u8>) -> Response<PoolBody> {
            // 拆成 3 字节一帧，模拟分片到达
            let body = Chunks(body.chunks(3).map(Bytes::copy_from_slice).collect()).boxed();
            Response::builder()
                .header("content-encoding", encoding)
                .header("content-length", "999")
                .body(body)
                .unwrap()
        }

        async fn decoded(response: Response<PoolBody>) -> (HeaderMap, Vec<u8>) {
            let response = decode_response(response);
            let headers = response.headers().clone();
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            (headers, bytes.to_vec())
        }

        #[tokio::test]
        async fn brotli_zstd_and_deflate_are_decoded() {
            let mut br = Vec::new();
            {
                let mut writer = brotli::CompressorWriter::new(&mut br, 4096, 5, 22);
                writer.write_all(TEXT).unwrap();
            }
            let zstd = zstd::encode_all(TEXT, 3).unwrap();
            let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            zlib.write_all(TEXT).unwrap();
            let zlib = zlib.finish().unwrap();
            let mut raw = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            raw.write_all(TEXT).unwrap();
            let raw = raw.finish().unwrap();
            for (encoding, body) in [("br", br), ("zstd", zstd), ("deflate", zlib), ("deflate", raw)] {
                let (headers, bytes) = decoded(chunked_response(encoding, body)).await;
                assert_eq!(bytes, TEXT, "{encoding}");
                assert!(!headers.contains_key("content-encoding"));
                assert!(!headers.contains_key("content-length"));
            }
        }

        #[tokio::test]
        async fn gzip_passes_through_for_dart() {
            let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            gz.write_all(TEXT).unwrap();
            let gz = gz.finish().unwrap();
            let (headers, bytes) = decoded(chunked_response("gzip", gz.clone())).await;
            assert_eq!(bytes, gz);
            assert_eq!(headers["content-encoding"], "gzip");
        }

        #[tokio::test]
        async fn truncated_brotli_is_an_error() {
            let mut br = Vec::new();
            {
                let mut writer = brotli::CompressorWriter::new(&mut br, 4096, 5, 22);
                writer.write_all(TEXT).unwrap();
            }
            br.truncate(br.len() / 2);
            let response = decode_response(chunked_response("br", br));
            assert!(response.into_body().collect().await.is_err());
        }

        #[tokio::test]
        async fn empty_bodies_are_not_finished() {
            let body = Full::new(Bytes::new()).map_err(|never| match never {}).boxed();
            let response = Response::builder()
                .header("content-encoding", "br")
                .body(body)
                .unwrap();
            let (_, bytes) = decoded(response).await;
            assert!(bytes.is_empty());
        }
    }
}
