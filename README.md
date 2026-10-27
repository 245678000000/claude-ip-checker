# Claude AI IP 风险检测 (macOS & Windows Native Client)

专为 **macOS** 与 **Windows** 打造的轻量级 **Claude AI IP 纯净度与封号风险检测** 原生桌面客户端，1:1 复刻并增强在线版 Claude IP 风险检测面板，内置多路网络分流、**6 维 Claude 封号概率预测模型** 与自动检查更新功能。

## 下载直接可用版本 (Releases)

前往 [**GitHub Releases (Latest)**](https://github.com/245678000000/claude-ip-checker/releases/latest) 直接下载对应系统版本：

- **macOS (Apple Silicon / macOS 14.0+)**：`Claude-IP-Checker-macOS-v1.1.0.zip`（解压后将 `Claude IP 检测.app` 拖入「应用程序」即可，体积仅 ~1 MB）
- **Windows (Windows 10 / 11 64-bit)**：`Claude-IP-Checker-Windows-x64.exe` 或 `Claude-IP-Checker-Windows-x64-v1.1.0.zip`（绿色单文件免安装，双击直接启动独立窗口）

## 核心功能特性

- **Claude 账号 6 维封号概率预测 (Ban Risk Prediction)**：
  - 综合 **地区支持白名单**、**IP 属性（住宅 ISP vs 大厂云机房 vs 廉价 VPS）**、**黑名单/公开代理特征**、**本机时区与节点时区偏移差**、**DNS/WebRTC/IPv6 协议泄露**、**历史节点跨国跳变频率** 6 大维度实时预测封号概率百分比（`3%–98%`）。
  - 针对 **Claude.ai 网页对话**、**Claude Code (CLI/API)**、**新号注册 / Pro 绑卡支付** 三大核心使用场景分别给出安全评级与防封建议。
- **三路出口 IP 分流对比**：
  - **中国出口 IPv4**：强制绕过系统代理直连探测国内宽带真实出口 IP 与运营商。
  - **Cloudflare 出口 IP**：通过 Cloudflare Trace 接口检测 CDN 出口 IP 与归属地。
  - **Claude AI 出口 IP**：通过 `claude.ai/cdn-cgi/trace` 与多路情报源探测针对 Claude 分流规则下的真实出口 IP。
- **Claude 信任评分与风控属性诊断**：
  - **0–100 信任评分 (Trust Score)**、**Claude 支持地区校验**、**IP 属性识别** 与 **5 项安全检测（VPN/Proxy/Tor/Crawler/Abuse）**。
- **连通性、泄露与设备环境自查**：
  - **Claude 可用性测速**（`claude.ai` / `anthropic.com` 毫秒级延迟）、**DNS 泄露检测**、**WebRTC UDP 泄露检测**、**设备指纹与时区一致性校验**。
- **在线检查更新与多代理模式切换**：
  - 内置 GitHub Releases 在线版本检查（快捷键 `Cmd + U` 或点击顶部 `检查更新` 按钮）。
  - 支持 **跟随系统代理/TUN（默认）**、**手动指定代理端口（如 `127.0.0.1:7890`）** 与 **强制直连** 三种模式。

## 从源码构建

```bash
# 同时构建 macOS .app 与交叉编译 Windows .exe
./build.sh
```
