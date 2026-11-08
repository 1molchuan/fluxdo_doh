# 浏览器指纹预置模板

取自上游 Lingyan000/fluxdo（GPL-3.0）eac274bd 的 `core/net_core/presets/`，只留安卓两档：

- `android-webview133`：上游在安卓模拟器上对 WebView 133 的实际探针；
- `android-chrome149`：rama 23d59722 的 rama-ua 样本（同内核浏览器，不是 WebView 149 采样）。

用途：网关还没采到本机 WebView 的 ClientHello 之前（首次启动、WebView 升级后），上游握手先按
UA 里 Chrome 大版本最接近的一档回放；采到真实握手后改用采样，并落盘供下次冷启动直接用。
SNI、ECH 密文、会话票据、key share 公钥都已清除/置零，握手时由 BoringSSL 重新生成。

来源与 SHA256 见 `manifest.json`；rama 的许可证（MIT / Apache-2.0）随目录保留。
