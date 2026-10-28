# Claude AI IP 风险检测 · v1.1.1

轻量级桌面网络诊断工具：macOS 使用 Swift/Cocoa/WKWebView，Windows 使用 Go 本地宿主与 Edge/Chrome 应用窗口。

> 参考分是启发式网络诊断，不是封号概率、官方信誉分或账户可用性保证。缺少数据会显示“未知/未取得情报”，而不是正常。本地 v1.1.1 构建尚未发布到 GitHub。

## 本版改进

- 出口卡片保留实际探测来源；通用 IP 回退明确标注“未确认 Claude 域名出口”。基础 IPv4 仅停用显式代理，仍可能经过系统 TUN。
- VPN、Proxy、Tor、Crawler、Abuse 使用四态：来源命中、来源未标记、未取得字段、查询失败。机房品牌不覆盖代理阳性，Tor 不自动等于滥用，缺失机房字段不推断住宅。
- 旧版信任分替换为五项安全情报覆盖率；各项参考权重可见。地区支持规则链接官方页面核对。
- 区分 HTTP 2xx、重定向、401/403、429、5xx、网络错误。首页连通不等于登录、API、注册或支付验证。
- DNS 失败保留未知，地区差异仅标注差异。WebRTC 比较全部公网候选；无候选或收集不完整保留未知。浏览器 WebRTC 路径可能不同于原生 HTTP 代理路径。
- 时区按当前 UTC 偏移计算；Shanghai/Taipei 同偏移不加分，IPv6 本身不加分。
- 增加批次隔离、65 秒前端截止时间、取消与重试。取消保留已完成项，后台原生请求按各自超时结束。
- 历史有 ISO 日期、模式、来源与验证标记。仅最近 24 小时同模式的已验证记录参与地区变化参考；旧版无日期记录仅展示。
- 隐藏 IP 覆盖出口、DNS、WebRTC、来源说明、归因和历史；JSON 导出总是隐藏 IP、代理凭据及指纹字段。
- HTTPS 外链校验；macOS 原生桥限定内置主文档；Windows 本地 API 校验 Host、Origin 与 Fetch Metadata。
- 深浅色、窄窗口、键盘焦点和国别代码标记；修复隐藏开关零尺寸点击目标。

## 隐私与边界

检测会向 IP 查询、地理情报、Claude/Anthropic 首页、Cloudflare Trace、DNS 探测及 STUN 服务发送请求；第三方自然可看到请求来源。`ip-api.com` 免费情报和 EDNS 探测目前使用 **HTTP**，来源在证据中注明，结果仅作参考。本工具没有登录、账户、密钥或支付操作。

历史 IP 明文保存在本机 WebView/浏览器 localStorage，最多 100 条；“隐藏 IP”是屏幕遮罩，不是存储加密。“清除”会删除两代历史键。脱敏报告仍可能包含地区、ASN、ISP、时间等元数据，分享前请复核。

免费接口的字段、配额及可达性会变化。DNS 地区比对不是全系统泄露测试；地区名称未识别时不做差异推断。客户端不替代官方地区政策，也不预测账户处理结果。

## 构建与测试

要求：Apple Silicon Mac、macOS 14+、Xcode Command Line Tools、Go（见 go.mod）、Node.js（测试）。无额外 Go/JS 运行依赖。

```sh
./test.sh       # Node 回归、Go test/vet、Swift 离线断言和类型检查
./build.sh      # macOS arm64 .app、Windows amd64 .exe 及 ZIP
```

产物在 build/：
- Claude-IP-Checker-macOS-v1.1.1.zip
- Claude-IP-Checker-Windows-x64-v1.1.1.zip

macOS 使用本地 ad-hoc 签名，未做 Developer ID 公证；按系统提示处理经你确认来源的应用，保留旧版副本。Windows 是交叉编译产物，实际 Windows 环境需另行验收。本地构建不等于已上传 [GitHub Releases](https://github.com/245678000000/claude-ip-checker/releases)。

可选离线浏览器 UI 回归，使用已有 Playwright 和 Chrome/Chromium：

```sh
PLAYWRIGHT_MODULE=/absolute/path/to/playwright \
CHROME_EXECUTABLE=/absolute/path/to/chrome \
QA_OUTPUT=/absolute/path/to/qa-output node Tests/ui.e2e.cjs
```

Tests/ui-fixture.js 阻断外网并提供显式样例，不打包进应用。此测试验证共享 UI，不替代 WKWebView 原生桥或 Windows 真机验收。直接浏览 HTML 会显示“未连接桌面检测宿主”，不会生成检测数据。

## 代码入口

| 内容 | 文件 |
|---|---|
| 页面结构与样式 | Resources/index.html |
| 前端状态、批次、历史、导出 | Resources/app.js |
| 参考规则、IP/时区/候选比较、脱敏 | Resources/diagnostics.js |
| macOS 探测与解析 | Sources/NetworkDetector.swift |
| macOS 窗口与桥接 | Sources/AppMain.swift |
| Windows 宿主与探测 | main.go |
| Go 解析与本地 API 边界 | diagnostics.go |
| 版本、构建、回归 | VERSION、build.sh、test.sh、Tests/、main_test.go |
