import Cocoa
import WebKit
import UniformTypeIdentifiers

struct NativeExportResult: Encodable {
    var success: Bool
    var error: String
}

/// 原生 WebView 消息处理器与主窗口控制器
class MainWindowController: NSObject, NSWindowDelegate, WKScriptMessageHandler, WKNavigationDelegate {
    var window: NSWindow!
    var webView: WKWebView!
    private var batch = NativeBatchState()
    private var trustedHTMLURL: URL?

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
            trustedHTMLURL = htmlURL
            webView.loadFileURL(htmlURL, allowingReadAccessTo: htmlURL.deletingLastPathComponent())
            return
        }

        // 开发调试回退路径
        let fallbackPath = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent("Resources/index.html")
        if FileManager.default.fileExists(atPath: fallbackPath.path) {
            trustedHTMLURL = fallbackPath
            webView.loadFileURL(fallbackPath, allowingReadAccessTo: fallbackPath.deletingLastPathComponent())
        }
    }

    /// Only the bundled main document may issue native commands.
    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard message.name == "nativeBridge", message.webView === webView, message.frameInfo.isMainFrame,
              NativeBridgePolicy.trustedDocument(message.frameInfo.request.url, expected: trustedHTMLURL),
              NativeBridgePolicy.trustedDocument(webView.url, expected: trustedHTMLURL),
              let body = message.body as? [String: Any], let action = body["action"] as? String else { return }
        let proxyMode = body["proxyMode"] as? String ?? "system"
        let customProxy = body["customProxy"] as? String ?? ""
        switch action {
        case "runFullCheck":
            guard let runID = NativeBridgePolicy.runID(body["runId"]), batch.begin(runID) else { return }
            runFullCheckAsync(proxyMode: proxyMode, customProxy: customProxy, runID: runID)
        case "cancelCheck":
            guard let runID = NativeBridgePolicy.runID(body["runId"]) else { return }
            _ = batch.begin(runID)
        case "checkAvailability", "checkDNS":
            guard let runID = NativeBridgePolicy.runID(body["runId"]) else { return }
            if batch.currentRunID == nil { _ = batch.begin(runID) }
            guard batch.isCurrent(runID) else { return }
            if action == "checkAvailability" {
                runAvailabilityAsync(proxyMode: proxyMode, customProxy: customProxy, runID: runID)
            } else { runDNSCheckAsync(proxyMode: proxyMode, customProxy: customProxy, runID: runID) }
        case "checkUpdate":
            let version = body["currentVersion"] as? String
                ?? Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "1.1.1"
            runUpdateCheckAsync(currentVersion: version, proxyMode: proxyMode, customProxy: customProxy)
        case "openExternalURL":
            if let text = body["url"] as? String, let url = NativeBridgePolicy.externalURL(text) {
                NSWorkspace.shared.open(url)
            }
        case "exportReport":
            let text = body["text"] as? String ?? (body["payload"] as? [String: Any])?["text"] as? String ?? ""
            exportReport(text)
        default: break
        }
    }

    /// Never give a remote page or a second local document the native bridge.
    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        if NativeBridgePolicy.trustedDocument(navigationAction.request.url, expected: trustedHTMLURL),
           navigationAction.targetFrame?.isMainFrame != false {
            decisionHandler(.allow)
        } else {
            decisionHandler(.cancel)
            if navigationAction.navigationType == .linkActivated,
               let text = navigationAction.request.url?.absoluteString,
               let url = NativeBridgePolicy.externalURL(text) { NSWorkspace.shared.open(url) }
        }
    }

    private func exportReport(_ text: String) {
        guard NativeBridgePolicy.validReport(text) else {
            sendJSONToJS(funcName: "window.onNativeExportResult", payload: NativeExportResult(success: false, error: "报告须为 1 MiB 以内的 JSON"))
            return
        }
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.json]
        panel.nameFieldStringValue = "claude-ip-diagnostics.json"
        panel.canCreateDirectories = true
        panel.beginSheetModal(for: window) { response in
            guard response == .OK, let url = panel.url else {
                self.sendJSONToJS(funcName: "window.onNativeExportResult", payload: NativeExportResult(success: false, error: "已取消保存"))
                return
            }
            do {
                try text.write(to: url, atomically: true, encoding: .utf8)
                self.sendJSONToJS(funcName: "window.onNativeExportResult", payload: NativeExportResult(success: true, error: ""))
            } catch {
                self.sendJSONToJS(funcName: "window.onNativeExportResult", payload: NativeExportResult(success: false, error: "保存失败，请重试"))
            }
        }
    }

    func runUpdateCheckAsync(currentVersion: String, proxyMode: String, customProxy: String) {
        DispatchQueue.global(qos: .userInitiated).async {
            let result = NetworkDetector.shared.checkAppUpdate(currentVersion: currentVersion, proxyMode: proxyMode, customProxy: customProxy)
            self.sendJSONToJS(funcName: "window.onNativeUpdateResult", payload: result)
        }
    }

    func runFullCheckAsync(proxyMode: String, customProxy: String, runID: Int) {
        DispatchQueue.global(qos: .userInitiated).async {
            self.sendJSONToJS(funcName: "window.onNativeSystemProxy", payload: NetworkDetector.shared.getSystemProxyInfo(), runID: runID)
        }
        DispatchQueue.global(qos: .userInitiated).async {
            self.sendJSONToJS(funcName: "window.onNativeChinaIP", payload: NetworkDetector.shared.detectChinaIPv4(), runID: runID)
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let result = NetworkDetector.shared.detectCloudflareIP(proxyMode: proxyMode, customProxy: customProxy)
            self.sendJSONToJS(funcName: "window.onNativeCloudflareIP", payload: result, runID: runID)
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let result = NetworkDetector.shared.detectClaudeIPAndRisk(proxyMode: proxyMode, customProxy: customProxy)
            DispatchQueue.main.async {
                guard self.batch.isCurrent(runID) else { return }
                self.batch.setCountry(result.countryCode, runID: runID)
                self.sendJSONToJS(funcName: "window.onNativeClaudeRisk", payload: result, runID: runID)
                self.runDNSCheckAsync(proxyMode: proxyMode, customProxy: customProxy, runID: runID)
            }
        }
        runAvailabilityAsync(proxyMode: proxyMode, customProxy: customProxy, runID: runID)
    }

    func runAvailabilityAsync(proxyMode: String, customProxy: String, runID: Int) {
        DispatchQueue.global(qos: .userInitiated).async {
            let result = NetworkDetector.shared.detectClaudeAvailability(proxyMode: proxyMode, customProxy: customProxy)
            self.sendJSONToJS(funcName: "window.onNativeAvailability", payload: result, runID: runID)
        }
    }

    func runDNSCheckAsync(proxyMode: String, customProxy: String, runID: Int) {
        guard batch.isCurrent(runID) else { return }
        let countryCode = batch.countryCode
        DispatchQueue.global(qos: .userInitiated).async {
            let result = NetworkDetector.shared.detectDNSLeak(proxyMode: proxyMode, customProxy: customProxy, claudeCountryCode: countryCode)
            self.sendJSONToJS(funcName: "window.onNativeDNSLeak", payload: result, runID: runID)
        }
    }

    /// Queue and validate on the main thread, including the moment the JS callback runs.
    private func sendJSONToJS<T: Encodable>(funcName: String, payload: T, runID: Int? = nil) {
        guard let data = try? JSONEncoder().encode(payload), let json = String(data: data, encoding: .utf8) else { return }
        DispatchQueue.main.async {
            guard NativeBridgePolicy.trustedDocument(self.webView.url, expected: self.trustedHTMLURL) else { return }
            if let runID, !self.batch.isCurrent(runID) { return }
            let args = runID.map { "\(json), \($0)" } ?? json
            self.webView.evaluateJavaScript("\(funcName)(\(args));", completionHandler: nil)
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
