# Claude AI IP 风险检测 Mac 客户端实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 构建并打包独立运行的 macOS 原生应用 `Claude IP 检测.app`，1:1 复刻 `ip.net.coffee/claude/` 的界面与全部检测能力，支持系统代理与手动指定代理端口。

**Architecture:** 采用 Swift (`AppKit` + `WebKit`) 作为原生窗口宿主与底层网络探测引擎，前端使用内置单文件 `Resources/index.html` 实现 1:1 视觉复刻、WebRTC UDP 泄露探测、Canvas/WebGL 设备指纹采集与本地历史存储，通过 `WKScriptMessageHandler` 实现双向异步桥接。

**Tech Stack:** Swift 5+ (`swiftc`), macOS AppKit, WebKit (`WKWebView`), `/usr/bin/curl` 多路代理/直连控制, HTML5/CSS3/Vanilla JS, `iconutil`/`sips` 应用图标打包工具。

## Global Constraints

- 必须编译为标准 macOS `.app` 应用包（`build/Claude IP 检测.app`），双击可直接启动，无需安装 Electron 或额外依赖。
- 仅包含 Claude AI IP 风险检测专属功能，不包含原网页顶部其他工具导航栏与底部资讯文章。
- 支持三种代理检测模式：跟随系统代理/TUN（默认）、手动指定代理地址（如 `127.0.0.1:7890`）、强制直连。

---

### Task 1: 实现底层多路网络分流与风控情报检测引擎 (`Sources/NetworkDetector.swift`)

**Files:**
- Create: `/Users/tiantian/.gemini/antigravity/scratch/claude-ip-checker/Sources/NetworkDetector.swift`

- [x] **Step 1: 实现系统代理读取、curl 多路代理封装与三路 IP/风控/可用性/DNS 检测逻辑**
- [x] **Step 2: 验证 Swift 文件语法与类型定义无误**

### Task 2: 实现 1:1 像素级复刻前端界面与浏览器级指纹/WebRTC 检测 (`Resources/index.html`)

**Files:**
- Create: `/Users/tiantian/.gemini/antigravity/scratch/claude-ip-checker/Resources/index.html`

- [x] **Step 1: 编写 1:1 复刻的卡片布局、渐变信任评分条、隐藏 IP 开关、深浅色切换及代理配置栏**
- [x] **Step 2: 实现与 Swift 原生层的异步消息通信、WebRTC UDP 泄露检测、设备指纹与本地历史记录管理**

### Task 3: 实现 macOS 原生窗口宿主与 WKWebView 桥接 (`Sources/AppMain.swift`)

**Files:**
- Create: `/Users/tiantian/.gemini/antigravity/scratch/claude-ip-checker/Sources/AppMain.swift`

- [x] **Step 1: 实现 NSApplicationDelegate、自适应窗口、标准 macOS 菜单栏与 WKScriptMessageHandler 桥接分发**

### Task 4: 编写应用图标生成器与一键编译打包脚本 (`build.sh`) 并执行验证

**Files:**
- Create: `/Users/tiantian/.gemini/antigravity/scratch/claude-ip-checker/build.sh`

- [x] **Step 1: 生成高清 `.icns` 图标与 `Info.plist`，调用 `swiftc` 编译生成 `build/Claude IP 检测.app`**
- [x] **Step 2: 运行单元测试/命令行自检与启动 `.app` 验证全流程无报错**
