# Claude AI IP 风险检测 (macOS Native Client)

专为 macOS 打造的轻量级 **Claude AI IP 纯净度与风险检测** 原生客户端（体积仅 ~1.2 MB），1:1 复刻并增强在线版 Claude IP 风险检测面板，内置多路网络分流与风控情报引擎。

## 功能特性

- **三路出口 IP 分流对比**：
  - **中国出口 IPv4**：强制绕过代理（`--noproxy`）直连探测国内宽带真实出口 IP 与运营商。
  - **Cloudflare 出口 IP**：通过 Cloudflare Trace 接口检测 CDN 出口 IP 与归属地。
  - **Claude AI 出口 IP**：通过 `claude.ai/cdn-cgi/trace` 与多路情报源探测针对 Claude 分流规则下的真实出口 IP。
- **Claude 信任评分与风控属性诊断**：
  - **0–100 信任评分 (Trust Score)**：综合评估 IP 纯净度、机房/住宅属性与黑名单记录。
  - **Claude 支持地区校验**：自动比对 Anthropic 官方支持国家/地区白名单。
  - **IP 属性识别**：自动区分 `住宅IP (Residential)`、`机房IP (Hosting)` 与 `移动网络 (Mobile)`。
  - **5 项安全检测**：`VPN`、`代理 (Proxy)`、`Tor`、`机器人 (Crawler)`、`滥用记录 (Abuse)`。
- **连通性、泄露与设备环境自查**：
  - **Claude 可用性测速**：真实测量 `claude.ai` 与 `anthropic.com` 的 HTTPS 握手延迟（ms）。
  - **DNS 泄露检测**：探测递归 DNS 出口 IP，识别是否存在国内 DNS 泄露。
  - **WebRTC UDP 泄露检测**：基于本地 STUN 探测是否暴露真实公网 UDP IP。
  - **设备指纹与时区一致性校验**：采集系统时区、语言、WebGL 渲染器、Canvas 指纹，并自动校验本地时区与 Claude 出口 IP 时区是否一致。
- **多代理模式切换**：
  - 支持 **跟随系统代理/TUN（默认）**、**手动指定代理端口（如 `127.0.0.1:7890`）** 与 **强制直连** 三种模式。
  - 支持 **隐藏 IP（打码截图模式）**、**深色/浅色主题切换** 与 **本地历史记录保存**。

## 快速构建与安装

环境要求：macOS 14.0+ 及 Xcode Command Line Tools (`swiftc`)。

```bash
# 1. 编译并打包生成 macOS .app 应用
./build.sh

# 2. 安装到 macOS「应用程序」目录
cp -Rf "build/Claude IP 检测.app" /Applications/

# 3. 启动客户端
open "/Applications/Claude IP 检测.app"
```

## 目录结构

```text
claude-ip-checker/
├── Sources/
│   ├── AppMain.swift          # macOS 原生窗口宿主、菜单栏与 WKWebView 桥接
│   ├── NetworkDetector.swift  # 多路网络分流、代理控制与风控评分核心引擎
│   └── IconGenerator.swift    # CoreGraphics 高清应用图标生成器
├── Resources/
│   └── index.html             # 1:1 复刻级前端界面、WebRTC 探测与设备指纹采集
└── build.sh                   # 一键编译、图标制作与 .app 签名打包脚本
```
