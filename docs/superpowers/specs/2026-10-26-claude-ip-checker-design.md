# Claude AI IP 风险检测 Mac 本地客户端设计文档

## 1. 项目目标与范围

构建一个独立运行的 macOS 原生客户端（`Claude IP 检测.app`），专门复刻并增强 `https://ip.net.coffee/claude/` 的 **Claude AI IP 风险检测** 功能。剔除原网页顶部无关导航菜单与底部资讯文章，内置独立的多源网络分流与风控情报检测引擎，支持自动跟随系统代理/TUN 环境以及手动指定本地代理端口（如 `127.0.0.1:7890`）进行对比检测。

## 2. 架构设计（方案 A：Swift 原生宿主 + 内置 UI 引擎）

系统由以下三层组成：

1. **macOS 原生窗口与系统桥接层（`Sources/AppMain.swift`）**：
   - 基于 `AppKit` + `WebKit`（`WKWebView`）构建轻量级原生 `.app` 宿主，无需外部运行时依赖，打包体积约 1 MB。
   - 实现 `WKScriptMessageHandler` 原生通信桥（`nativeBridge`），支持前端触发异步网络检测并流式接收各卡片模块的检测结果。
   - 支持读取 macOS 系统当前代理状态（`scutil --proxy`），并提供标准 macOS 菜单栏与快捷键（`Cmd+R` 重新检测、`Cmd+Q` 退出、`Cmd+W` 关闭、`Cmd+C/V` 拷贝粘贴）。

2. **多路网络分流与风控情报引擎（`Sources/NetworkDetector.swift`）**：
   - 采用 Swift 并发任务 + `/usr/bin/curl` 多参数控制，精准支持三种代理模式：
     - `system`（默认跟随系统代理与 TUN 分流规则）
     - `custom`（手动指定本地代理地址，如 `http://127.0.0.1:7890` 或 `socks5://127.0.0.1:7890`）
     - `direct`（强制使用 `--noproxy '*'` 直连测试）
   - **三路出口 IP 检测**：
     - **中国出口 IPv4**：强制绕过代理（`--noproxy '*'`）请求国内 IP 接口（主：`myip.ipip.net/json`，备：`4.ipw.cn` + 国内地理位置查询），获取真实国内出口 IP 与运营商。
     - **Cloudflare 出口 IP**：通过 `cloudflare.com/cdn-cgi/trace` 及 `1.1.1.1/cdn-cgi/trace` 获取 Cloudflare 路由出口 IP，并补充地理与 ASN 信息。
     - **Claude AI 出口 IP 与风控属性**：模拟访问 Claude 路由环境，聚合多源公共情报接口（`ipwho.is`、`ip-api.com`、`ipapi.co`），提取国家、城市、ASN、ISP、IP 类型（住宅/机房/移动网络）及安全风险标签（VPN/Proxy/Tor/Crawler/Abuse）。
   - **Claude 信任评分算法（0-100）**：
     - 满分 100 分；纯净机房 IP（Hosting）扣 11 分（得 89 分「纯净」，对齐原站评分模型）；命中代理（Proxy）扣 25 分；命中 VPN 扣 15 分；命中 Tor 扣 45 分；命中机器人/滥用记录扣 20~30 分；非 Claude 官方支持国家/地区额外提示风险。
   - **Claude 可用性测速与 DNS 泄露检测**：
     - 真实测量 `claude.ai` 与 `api.anthropic.com` 的 HTTPS 握手延迟（毫秒）与状态码。
     - 通过 `edns.ip-api.com/json` 与系统 DNS 配置检测 DNS 出口 IP 是否存在国内 DNS 泄露。

3. **1:1 像素级复刻前端与设备指纹检测层（`Resources/index.html`）**：
   - 1:1 还原截图中的卡片网格、国旗展示、信任评分渐变进度条与游标、胶囊状态徽章、隐藏 IP 打码开关、深浅色主题切换。
   - 利用 WebKit 原生 `RTCPeerConnection` 检测 WebRTC UDP 泄露情况。
   - 采集本地时区、系统语言、WebGL 渲染器、Canvas 指纹，并自动比对「系统时区」与「Claude 出口 IP 所在时区」是否一致。
   - 使用 `localStorage` 本地存储历史检测记录，支持一键清除。
