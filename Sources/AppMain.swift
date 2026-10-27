import Cocoa
import WebKit

/// 原生 WebView 消息处理器与主窗口控制器
class MainWindowController: NSObject, NSWindowDelegate, WKScriptMessageHandler, WKNavigationDelegate {
    var window: NSWindow!
    var webView: WKWebView!
    private var lastClaudeCountryCode: String = ""

    override init() {
        super.init()
        setupWindow()
    }

    private func setupWindow() {
        let contentRect = NSRect(x: 0, y: 0, width: 1160, height: 860)
        let styleMask: NSWindow.StyleMask = [.titled, .closable, .miniaturizable, .resizable]

        window = NSWindow(
            contentRect: contentRect,
            styleMask: styleMask,
            backing: .buffered,
            defer: false
        )
        window.title = "Claude AI IP 风险检测"
        window.minSize = NSSize(width: 820, height: 640)
        window.center()
        window.delegate = self
        window.isReleasedWhenClosed = false

        // 配置 WKWebView 与 JS 通信桥
        let userContentController = WKUserContentController()
        userContentController.add(self, name: "nativeBridge")

        let config = WKWebViewConfiguration()
        config.userContentController = userContentController
        config.preferences.setValue(true, forKey: "developerExtrasEnabled")

        webView = WKWebView(frame: contentRect, configuration: config)
        webView.navigationDelegate = self
        webView.autoresizingMask = [.width, .height]

        window.contentView = webView
        loadLocalHTML()
    }

    /// 加载内置的 Resources/index.html
    private func loadLocalHTML() {
        if let htmlURL = Bundle.main.url(forResource: "index", withExtension: "html") {
            webView.loadFileURL(htmlURL, allowingReadAccessTo: htmlURL.deletingLastPathComponent())
            return
        }

        // 开发调试回退路径
        let fallbackPath = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent("Resources/index.html")
        if FileManager.default.fileExists(atPath: fallbackPath.path) {
            webView.loadFileURL(fallbackPath, allowingReadAccessTo: fallbackPath.deletingLastPathComponent())
        }
    }

    /// 接收来自前端页面的异步指令
    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard message.name == "nativeBridge",
              let body = message.body as? [String: Any],
              let action = body["action"] as? String else {
            return
        }

        let proxyMode = (body["proxyMode"] as? String) ?? "system"
        let customProxy = (body["customProxy"] as? String) ?? ""

        switch action {
        case "runFullCheck":
            runFullCheckAsync(proxyMode: proxyMode, customProxy: customProxy)
        case "checkAvailability":
            runAvailabilityAsync(proxyMode: proxyMode, customProxy: customProxy)
        case "checkDNS":
            runDNSCheckAsync(proxyMode: proxyMode, customProxy: customProxy)
        case "checkUpdate":
            let curVer = (body["currentVersion"] as? String) ?? "1.1.0"
            runUpdateCheckAsync(currentVersion: curVer, proxyMode: proxyMode, customProxy: customProxy)
        case "openExternalURL":
            if let urlStr = body["url"] as? String, let url = URL(string: urlStr) {
                NSWorkspace.shared.open(url)
            }
        default:
            break
        }
    }

    func runUpdateCheckAsync(currentVersion: String, proxyMode: String, customProxy: String) {
        DispatchQueue.global(qos: .userInitiated).async {
            let res = NetworkDetector.shared.checkAppUpdate(
                currentVersion: currentVersion,
                proxyMode: proxyMode,
                customProxy: customProxy
            )
            self.sendJSONToJS(funcName: "window.onNativeUpdateResult", payload: res)
        }
    }

    /// 并发执行全量检测并流式回调前端
    func runFullCheckAsync(proxyMode: String, customProxy: String) {
        // 1. 立即刷新系统代理状态
        DispatchQueue.global(qos: .userInitiated).async {
            let sysInfo = NetworkDetector.shared.getSystemProxyInfo()
            self.sendJSONToJS(funcName: "window.onNativeSystemProxy", payload: sysInfo)
        }

        // 2. 并发检测：中国出口 IPv4
        DispatchQueue.global(qos: .userInitiated).async {
            let cnData = NetworkDetector.shared.detectChinaIPv4()
            self.sendJSONToJS(funcName: "window.onNativeChinaIP", payload: cnData)
        }

        // 3. 并发检测：Cloudflare 出口 IP
        DispatchQueue.global(qos: .userInitiated).async {
            let cfData = NetworkDetector.shared.detectCloudflareIP(proxyMode: proxyMode, customProxy: customProxy)
            self.sendJSONToJS(funcName: "window.onNativeCloudflareIP", payload: cfData)
        }

        // 4. 并发检测：Claude AI 出口 IP、风控属性与信任评分，完成后联动 DNS 泄露判断
        DispatchQueue.global(qos: .userInitiated).async {
            let claudeData = NetworkDetector.shared.detectClaudeIPAndRisk(proxyMode: proxyMode, customProxy: customProxy)
            self.lastClaudeCountryCode = claudeData.countryCode
            self.sendJSONToJS(funcName: "window.onNativeClaudeRisk", payload: claudeData)

            let dnsData = NetworkDetector.shared.detectDNSLeak(
                proxyMode: proxyMode,
                customProxy: customProxy,
                claudeCountryCode: claudeData.countryCode
            )
            self.sendJSONToJS(funcName: "window.onNativeDNSLeak", payload: dnsData)
        }

        // 5. 并发检测：Claude 可用性与延迟测速
        runAvailabilityAsync(proxyMode: proxyMode, customProxy: customProxy)
    }

    func runAvailabilityAsync(proxyMode: String, customProxy: String) {
        DispatchQueue.global(qos: .userInitiated).async {
            let list = NetworkDetector.shared.detectClaudeAvailability(proxyMode: proxyMode, customProxy: customProxy)
            self.sendJSONToJS(funcName: "window.onNativeAvailability", payload: list)
        }
    }

    func runDNSCheckAsync(proxyMode: String, customProxy: String) {
        let cc = self.lastClaudeCountryCode
        DispatchQueue.global(qos: .userInitiated).async {
            let dnsData = NetworkDetector.shared.detectDNSLeak(
                proxyMode: proxyMode,
                customProxy: customProxy,
                claudeCountryCode: cc
            )
            self.sendJSONToJS(funcName: "window.onNativeDNSLeak", payload: dnsData)
        }
    }

    /// 将 Codable 结构体序列化为 JSON 并在主线程调用前端 JS 函数
    private func sendJSONToJS<T: Encodable>(funcName: String, payload: T) {
        let encoder = JSONEncoder()
        guard let data = try? encoder.encode(payload),
              let jsonStr = String(data: data, encoding: .utf8) else {
            return
        }
        DispatchQueue.main.async {
            let js = "\(funcName)(\(jsonStr));"
            self.webView.evaluateJavaScript(js, completionHandler: nil)
        }
    }
}

/// 应用生命周期代理
class AppDelegate: NSObject, NSApplicationDelegate {
    var mainController: MainWindowController?

    func applicationDidFinishLaunching(_ notification: Notification) {
        setupMainMenu()
        mainController = MainWindowController()
        mainController?.window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return true
    }

    @objc func refreshCheckAction(_ sender: Any?) {
        mainController?.webView.evaluateJavaScript("triggerFullCheck();", completionHandler: nil)
    }

    @objc func checkUpdateMenuAction(_ sender: Any?) {
        mainController?.webView.evaluateJavaScript("triggerUpdateCheck(true);", completionHandler: nil)
    }

    /// 构建标准 macOS 菜单栏（支持 Cmd+Q, Cmd+R, Cmd+W, Cmd+C/V/A）
    private func setupMainMenu() {
        let mainMenu = NSMenu()

        // 1. 应用菜单
        let appMenuItem = NSMenuItem()
        mainMenu.addItem(appMenuItem)
        let appMenu = NSMenu()
        appMenuItem.submenu = appMenu
        appMenu.addItem(withTitle: "关于 Claude AI IP 风险检测", action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        appMenu.addItem(withTitle: "检查更新...", action: #selector(checkUpdateMenuAction(_:)), keyEquivalent: "u")
        appMenu.addItem(NSMenuItem.separator())
        appMenu.addItem(withTitle: "重新检测网络风险", action: #selector(refreshCheckAction(_:)), keyEquivalent: "r")
        appMenu.addItem(NSMenuItem.separator())
        appMenu.addItem(withTitle: "隐藏窗口", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        appMenu.addItem(withTitle: "退出 Claude IP 检测", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")

        // 2. 编辑菜单（支持输入框复制粘贴）
        let editMenuItem = NSMenuItem()
        mainMenu.addItem(editMenuItem)
        let editMenu = NSMenu(title: "编辑")
        editMenuItem.submenu = editMenu
        editMenu.addItem(withTitle: "撤销", action: Selector(("undo:")), keyEquivalent: "z")
        editMenu.addItem(withTitle: "重做", action: Selector(("redo:")), keyEquivalent: "Z")
        editMenu.addItem(NSMenuItem.separator())
        editMenu.addItem(withTitle: "剪切", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        editMenu.addItem(withTitle: "拷贝", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        editMenu.addItem(withTitle: "粘贴", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        editMenu.addItem(withTitle: "全选", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")

        // 3. 窗口菜单
        let winMenuItem = NSMenuItem()
        mainMenu.addItem(winMenuItem)
        let winMenu = NSMenu(title: "窗口")
        winMenuItem.submenu = winMenu
        winMenu.addItem(withTitle: "最小化", action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m")
        winMenu.addItem(withTitle: "关闭窗口", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")

        NSApp.mainMenu = mainMenu
    }
}

// MARK: - 程序入口
@main
struct ClaudeIPApp {
    static func main() {
        let args = CommandLine.arguments
        if args.contains("--self-test") {
            let sysProxy = NetworkDetector.shared.getSystemProxyInfo()
            let flagTW = NetworkDetector.shared.countryCodeToFlag("TW")
            let encoder = JSONEncoder()
            encoder.outputFormatting = .prettyPrinted
            if let data = try? encoder.encode(sysProxy),
               let json = String(data: data, encoding: .utf8) {
                print("SELF_TEST_OK flag=\(flagTW)")
                print(json)
                exit(0)
            }
            exit(1)
        }

        let app = NSApplication.shared
        app.setActivationPolicy(.regular)
        let delegate = AppDelegate()
        app.delegate = delegate
        app.run()
    }
}
