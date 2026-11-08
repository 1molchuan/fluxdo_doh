# h2 0.4.13 的 cfluxdo 补丁

原样复制自 crates.io 的 h2 0.4.13（MIT），删掉了 benches / examples，经根目录 `Cargo.toml`
的 `[patch.crates-io]` 替换。只改了一处：

- `src/frame/headers.rs` 的 `Iter::next`：请求伪头按 Chromium 的顺序编码
  （`:method, :authority, :scheme, :path`），原版是 `:method, :scheme, :authority, :path`。
  网关按浏览器指纹握手后，HTTP/2 层的伪头顺序也要和 WebView 一致（Akamai 指纹的最后一段）。
  响应只有 `:status`，服务端方向不受影响。

升级 h2 时重新复制新版本、重打这一处补丁，并跑 `cargo test` 里的伪头顺序用例。
