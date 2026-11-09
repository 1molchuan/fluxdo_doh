# h2 0.4.13 的 cfluxdo 补丁

原样复制自 crates.io 的 h2 0.4.13（MIT），删掉了 benches / examples，经根目录 `Cargo.toml`
的 `[patch.crates-io]` 替换。改动都只在请求带 `ext::RequestPriority` 时生效（网关只给按浏览器
指纹握手的连接带），其余连接与原版逐字节一致：

- `src/ext.rs`：新增 `RequestPriority` 请求扩展。
- `src/proto/streams/streams.rs` 的 `send_request`（及 `stream.rs` 记下的权重）：带
  `RequestPriority` 的请求在 HEADERS 帧里按 Chromium 的写法带优先级（独占依赖最近一个还开着、
  权重不低于自己的流），并打开下面的伪头顺序。
- `src/frame/headers.rs`、`src/frame/priority.rs`：`Headers::set_stream_dep` 与优先级字段的编码；
  `Pseudo::chromium_order` 打开时 `Iter::next` 按 Chromium 的顺序编码请求伪头
  （`:method, :authority, :scheme, :path`），否则保持原版的 `:method, :scheme, :authority, :path`。
  网关按浏览器指纹握手后，HTTP/2 层的伪头顺序也要和 WebView 一致（Akamai 指纹的最后一段）。
  rustls 握手的连接（桌面端、关掉浏览器指纹的安卓）不能跟着改：2026-11-09 实测 Windows 版经国内
  出口时，rustls 连接用 Chromium 伪头顺序、又不带 Host（网关那边的改动），验证页过了以后原生请求
  仍被 Cloudflare 拦下（403）；两样都恢复原版发法后正常。
  响应只有 `:status`，服务端方向不受影响。

升级 h2 时重新复制新版本、重打这些补丁，并单独跑一遍它自己的用例（h2 不是 workspace 成员，
根目录的 `cargo test` 不会跑到；跑完删掉生成的 `vendor/h2/Cargo.lock`）：

```
CARGO_TARGET_DIR=/tmp/h2-test cargo test --manifest-path vendor/h2/Cargo.toml --lib pseudo
```
