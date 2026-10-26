import Foundation

/// 系统代理信息结构体
struct SystemProxyInfo: Codable {
    var enabled: Bool
    var httpProxy: String?
    var socksProxy: String?
    var summary: String
}

/// 顶部出口 IP 简要卡片数据
struct ExitIPCardData: Codable {
    var ip: String
    var countryCode: String
    var flag: String
    var locationText: String
    var isIPv6: Bool
    var success: Bool
}

/// Claude 核心风险与属性完整数据
struct ClaudeRiskData: Codable {
    var ip: String
    var isIPv6: Bool
    var country: String
    var countryCode: String
    var flag: String
    var city: String
    var region: String
    var asn: String
    var isp: String
    var org: String
    var timezone: String
    var ipType: String          // "机房IP" | "住宅IP" | "移动网络"
    var ipTypeEn: String        // "(Hosting)" | "(Residential)" | "(Mobile)"
    var isHosting: Bool
    var trustScore: Int         // 0 - 100
    var trustLevel: String      // "纯净" | "低风险" | "中风险" | "高危"
    var trustDesc: String       // "该 IP 信誉优异" 等
    var regionSupported: Bool   // Claude 是否支持该地区
    var regionStatusText: String
    var vpnDetected: Bool
    var proxyDetected: Bool
    var torDetected: Bool
    var crawlerDetected: Bool
    var abuseDetected: Bool
    var success: Bool
}

/// 单个域名可用性测速结果
struct EndpointPingResult: Codable {
    var domain: String
    var reachable: Bool
    var latencyMs: Int
    var statusCode: Int
    var statusText: String
}

/// DNS 泄露检测结果
struct DNSLeakResult: Codable {
    var leaked: Bool
    var statusText: String
    var dnsIP: String
    var dnsGeo: String
}

/// 网络与风控检测核心引擎
class NetworkDetector {
    static let shared = NetworkDetector()

    /// Anthropic / Claude 不支持的国家或地区代码黑名单
    private let unsupportedCountryCodes: Set<String> = [
        "CN", "HK", "MO", "RU", "BY", "IR", "KP", "SY", "CU", "AF", "VE", "MM", "SD"
    ]

    /// 常见云厂商与机房 ASN / 运营商关键词
    private let hostingKeywords: [String] = [
        "google", "amazon", "aws", "cloudflare", "microsoft", "azure", "digitalocean",
        "linode", "akamai", "vultr", "choopa", "hetzner", "ovh", "oracle", "alibaba",
        "aliyun", "tencent", "huawei", "cogent", "leaseweb", "contabo", "datacamp",
        "cdn77", "psychz", "zenlayer", "dmit", "bandwagon", "it7", "multacom",
        "sharktech", "colocrossing", "quadranet", "hostinger", "equinix", "fastly",
        "kamatera", "upcloud", "scaleway", "ionos", "racknerd", "buyvm", "frantech",
        "gcore", "misaka", "nearoute", "xtom", "hosting", "datacenter", "cloud", "vps", "server"
    ]

    /// 将两位国家代码转换为国旗 Emoji
    func countryCodeToFlag(_ code: String) -> String {
        let upper = code.uppercased().trimmingCharacters(in: .whitespacesAndNewlines)
        guard upper.count == 2 else { return "🌐" }
        let base: UInt32 = 127397
        var scalarView = String.UnicodeScalarView()
        for scalar in upper.unicodeScalars {
            if let flagScalar = UnicodeScalar(base + scalar.value) {
                scalarView.append(flagScalar)
            }
        }
        return String(scalarView)
    }

    /// 读取 macOS 系统当前代理配置 (`scutil --proxy`)
    func getSystemProxyInfo() -> SystemProxyInfo {
        let output = runProcess(executable: "/usr/sbin/scutil", arguments: ["--proxy"], timeout: 3.0)
        var httpEnable = false
        var httpHost = ""
        var httpPort = ""
        var socksEnable = false
        var socksHost = ""
        var socksPort = ""

        for line in output.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            let parts = trimmed.components(separatedBy: " : ")
            guard parts.count == 2 else { continue }
            let key = parts[0].trimmingCharacters(in: .whitespaces)
            let val = parts[1].trimmingCharacters(in: .whitespaces)
            switch key {
            case "HTTPEnable": httpEnable = (val == "1")
            case "HTTPProxy": httpHost = val
            case "HTTPPort": httpPort = val
            case "HTTPSProxy": if httpHost.isEmpty { httpHost = val }
            case "HTTPSPort": if httpPort.isEmpty { httpPort = val }
            case "SOCKSEnable": socksEnable = (val == "1")
            case "SOCKSProxy": socksHost = val
            case "SOCKSPort": socksPort = val
            default: break
            }
        }

        var httpProxyStr: String? = nil
        var socksProxyStr: String? = nil
        if httpEnable && !httpHost.isEmpty && !httpPort.isEmpty {
            httpProxyStr = "http://\(httpHost):\(httpPort)"
        }
        if socksEnable && !socksHost.isEmpty && !socksPort.isEmpty {
            socksProxyStr = "socks5://\(socksHost):\(socksPort)"
        }

        if let hp = httpProxyStr {
            return SystemProxyInfo(enabled: true, httpProxy: hp, socksProxy: socksProxyStr, summary: "系统代理 (\(httpHost):\(httpPort))")
        } else if let sp = socksProxyStr {
            return SystemProxyInfo(enabled: true, httpProxy: nil, socksProxy: sp, summary: "SOCKS代理 (\(socksHost):\(socksPort))")
        } else {
            return SystemProxyInfo(enabled: false, httpProxy: nil, socksProxy: nil, summary: "系统直连 / TUN 模式")
        }
    }

    /// 根据代理模式生成 curl 的代理参数
    private func buildCurlProxyArgs(proxyMode: String, customProxy: String) -> [String] {
        switch proxyMode {
        case "direct":
            return ["--noproxy", "*"]
        case "custom":
            let cleaned = customProxy.trimmingCharacters(in: .whitespacesAndNewlines)
            if cleaned.isEmpty {
                return []
            }
            if cleaned.contains("://") {
                return ["-x", cleaned]
            } else {
                return ["-x", "http://\(cleaned)"]
            }
        default: // "system"
            let sys = getSystemProxyInfo()
            if let hp = sys.httpProxy {
                return ["-x", hp]
            } else if let sp = sys.socksProxy {
                return ["-x", sp]
            }
            return []
        }
    }

    /// 执行外部命令并返回标准输出
    private func runProcess(executable: String, arguments: [String], timeout: TimeInterval = 8.0) -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments

        let outPipe = Pipe()
        let errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe

        let semaphore = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in
            semaphore.signal()
        }

        do {
            try process.run()
        } catch {
            return ""
        }

        let waitResult = semaphore.wait(timeout: .now() + timeout)
        if waitResult == .timedOut {
            process.terminate()
            return ""
        }

        let data = outPipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8) ?? ""
    }

    /// 使用 curl 执行 HTTP GET 请求
    private func curlGet(url: String, extraArgs: [String] = [], timeout: Int = 6) -> String {
        var args = [
            "-s", "-L",
            "--max-time", "\(timeout)",
            "--connect-timeout", "4",
            "-A", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
        ]
        args.append(contentsOf: extraArgs)
        args.append(url)
        return runProcess(executable: "/usr/bin/curl", arguments: args, timeout: TimeInterval(timeout + 2))
    }

    // MARK: - 1. 检测中国出口 IPv4
    func detectChinaIPv4() -> ExitIPCardData {
        // 强制绕过代理并优先使用 IPv4
        let directArgs = ["--noproxy", "*", "-4"]

        // 渠道 1：myip.ipip.net/json
        let ipipRaw = curlGet(url: "https://myip.ipip.net/json", extraArgs: directArgs, timeout: 4)
        if let data = ipipRaw.data(using: .utf8),
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let inner = json["data"] as? [String: Any],
           let ip = inner["ip"] as? String, !ip.isEmpty {
            var locParts: [String] = []
            if let locArr = inner["location"] as? [String] {
                locParts = locArr.filter { !$0.isEmpty }
            }
            let locText = locParts.isEmpty ? "China" : locParts.joined(separator: " ")
            return ExitIPCardData(
                ip: ip,
                countryCode: "CN",
                flag: countryCodeToFlag("CN"),
                locationText: locText,
                isIPv6: ip.contains(":"),
                success: true
            )
        }

        // 渠道 2：4.ipw.cn 或 ip.3322.net 获取纯 IPv4，再查询归属地
        var fallbackIP = curlGet(url: "https://4.ipw.cn", extraArgs: directArgs, timeout: 4)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if fallbackIP.isEmpty || fallbackIP.count > 45 || fallbackIP.contains("<") {
            fallbackIP = curlGet(url: "https://ip.3322.net", extraArgs: directArgs, timeout: 4)
                .trimmingCharacters(in: .whitespacesAndNewlines)
        }

        if !fallbackIP.isEmpty && !fallbackIP.contains("<") {
            let detail = fetchBasicIPGeo(ip: fallbackIP, proxyArgs: directArgs)
            return ExitIPCardData(
                ip: fallbackIP,
                countryCode: detail.countryCode.isEmpty ? "CN" : detail.countryCode,
                flag: countryCodeToFlag(detail.countryCode.isEmpty ? "CN" : detail.countryCode),
                locationText: detail.summary.isEmpty ? "China" : detail.summary,
                isIPv6: fallbackIP.contains(":"),
                success: true
            )
        }

        return ExitIPCardData(
            ip: "获取失败",
            countryCode: "",
            flag: "🌐",
            locationText: "请检查国内网络连通性",
            isIPv6: false,
            success: false
        )
    }

    // MARK: - 2. 检测 Cloudflare 出口 IP
    func detectCloudflareIP(proxyMode: String, customProxy: String) -> ExitIPCardData {
        let proxyArgs = buildCurlProxyArgs(proxyMode: proxyMode, customProxy: customProxy)

        var traceRaw = curlGet(url: "https://1.1.1.1/cdn-cgi/trace", extraArgs: proxyArgs, timeout: 5)
        if !traceRaw.contains("ip=") {
            traceRaw = curlGet(url: "https://www.cloudflare.com/cdn-cgi/trace", extraArgs: proxyArgs, timeout: 5)
        }

        var ip = ""
        var loc = ""
        for line in traceRaw.components(separatedBy: .newlines) {
            if line.hasPrefix("ip=") {
                ip = String(line.dropFirst(3)).trimmingCharacters(in: .whitespaces)
            } else if line.hasPrefix("loc=") {
                loc = String(line.dropFirst(4)).trimmingCharacters(in: .whitespaces)
            }
        }

        if !ip.isEmpty {
            let geo = fetchBasicIPGeo(ip: ip, proxyArgs: proxyArgs)
            let code = geo.countryCode.isEmpty ? loc : geo.countryCode
            let text = geo.summary.isEmpty ? code : geo.summary
            return ExitIPCardData(
                ip: ip,
                countryCode: code,
                flag: countryCodeToFlag(code),
                locationText: text,
                isIPv6: ip.contains(":"),
                success: true
            )
        }

        return ExitIPCardData(
            ip: "获取失败",
            countryCode: "",
            flag: "🌐",
            locationText: "无法连接 Cloudflare 节点",
            isIPv6: false,
            success: false
        )
    }

    // MARK: - 3. 检测 Claude AI 出口 IP 及完整风控评分
    func detectClaudeIPAndRisk(proxyMode: String, customProxy: String) -> ClaudeRiskData {
        let proxyArgs = buildCurlProxyArgs(proxyMode: proxyMode, customProxy: customProxy)

        // 第一步：优先通过 claude.ai/cdn-cgi/trace 获取真实针对 claude.ai 分流后的出口 IP
        var claudeIP = ""
        let claudeTrace = curlGet(url: "https://claude.ai/cdn-cgi/trace", extraArgs: proxyArgs, timeout: 5)
        for line in claudeTrace.components(separatedBy: .newlines) {
            if line.hasPrefix("ip=") {
                claudeIP = String(line.dropFirst(3)).trimmingCharacters(in: .whitespaces)
                break
            }
        }

        // 若 claude.ai/cdn-cgi/trace 未返回，则尝试 api.ipify.org 或 ipwho.is
        if claudeIP.isEmpty {
            let ipify = curlGet(url: "https://api64.ipify.org", extraArgs: proxyArgs, timeout: 5)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            if !ipify.isEmpty && !ipify.contains("<") && ipify.count <= 45 {
                claudeIP = ipify
            }
        }

        // 第二步：聚合查询该 IP 的归属地、ASN、Hosting/Proxy/VPN 属性
        var country = "未知"
        var countryCode = ""
        var city = "未知"
        var region = ""
        var asn = "未知"
        var isp = "未知"
        var org = ""
        var timezone = "未知"
        var isHosting = false
        var isMobile = false
        var isProxy = false
        var isVPN = false
        var isTor = false
        var isCrawler = false
        var isAbuse = false

        // 情报源 A：ip-api.com（包含极其准确的 hosting / proxy / mobile 布尔字段）
        let ipApiUrl = claudeIP.isEmpty
            ? "http://ip-api.com/json/?fields=66846719"
            : "http://ip-api.com/json/\(claudeIP)?fields=66846719"
        let ipApiRaw = curlGet(url: ipApiUrl, extraArgs: proxyArgs, timeout: 5)
        if let data = ipApiRaw.data(using: .utf8),
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           (json["status"] as? String) == "success" {
            if claudeIP.isEmpty, let q = json["query"] as? String { claudeIP = q }
            if let c = json["country"] as? String, !c.isEmpty { country = c }
            if let cc = json["countryCode"] as? String, !cc.isEmpty { countryCode = cc }
            if let ct = json["city"] as? String, !ct.isEmpty { city = ct }
            if let rg = json["regionName"] as? String, !rg.isEmpty { region = rg }
            if let tz = json["timezone"] as? String, !tz.isEmpty { timezone = tz }
            if let sp = json["isp"] as? String, !sp.isEmpty { isp = sp }
            if let og = json["org"] as? String, !og.isEmpty { org = og }
            if let asStr = json["as"] as? String, !asStr.isEmpty {
                let firstToken = asStr.components(separatedBy: " ").first ?? asStr
                asn = firstToken
            }
            if let h = json["hosting"] as? Bool { isHosting = h }
            if let m = json["mobile"] as? Bool { isMobile = m }
            if let p = json["proxy"] as? Bool { isProxy = p }
        }

        // 情报源 B：ipwho.is（补充 HTTPS 下的 ASN、ISP、Security 信息）
        let ipWhoUrl = claudeIP.isEmpty ? "https://ipwho.is/" : "https://ipwho.is/\(claudeIP)"
        let ipWhoRaw = curlGet(url: ipWhoUrl, extraArgs: proxyArgs, timeout: 5)
        if let data = ipWhoRaw.data(using: .utf8),
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           (json["success"] as? Bool) == true {
            if claudeIP.isEmpty, let q = json["ip"] as? String { claudeIP = q }
            if country == "未知", let c = json["country"] as? String, !c.isEmpty { country = c }
            if countryCode.isEmpty, let cc = json["country_code"] as? String, !cc.isEmpty { countryCode = cc }
            if city == "未知", let ct = json["city"] as? String, !ct.isEmpty { city = ct }
            if region.isEmpty, let rg = json["region"] as? String, !rg.isEmpty { region = rg }
            if let tzObj = json["timezone"] as? [String: Any],
               let tzId = tzObj["id"] as? String, timezone == "未知" && !tzId.isEmpty {
                timezone = tzId
            }
            if let conn = json["connection"] as? [String: Any] {
                if asn == "未知", let asnNum = conn["asn"] as? Int {
                    asn = "AS\(asnNum)"
                }
                if isp == "未知", let sp = conn["isp"] as? String, !sp.isEmpty {
                    isp = sp
                }
                if org.isEmpty, let og = conn["org"] as? String, !og.isEmpty {
                    org = og
                }
            }
            if let sec = json["security"] as? [String: Any] {
                if let h = sec["hosting"] as? Bool, h { isHosting = true }
                if let p = sec["proxy"] as? Bool, p { isProxy = true }
                if let v = sec["vpn"] as? Bool, v { isVPN = true }
                if let t = sec["tor"] as? Bool, t { isTor = true }
                if let c = sec["crawler"] as? Bool, c { isCrawler = true }
            }
        }

        guard !claudeIP.isEmpty else {
            return ClaudeRiskData(
                ip: "获取失败",
                isIPv6: false,
                country: "未知",
                countryCode: "",
                flag: "🌐",
                city: "未知",
                region: "",
                asn: "未知",
                isp: "未知",
                org: "",
                timezone: "未知",
                ipType: "未知",
                ipTypeEn: "",
                isHosting: false,
                trustScore: 0,
                trustLevel: "无数据",
                trustDesc: "未获取到 Claude AI 出口 IP，请检查代理或网络配置",
                regionSupported: false,
                regionStatusText: "未知",
                vpnDetected: false,
                proxyDetected: false,
                torDetected: false,
                crawlerDetected: false,
                abuseDetected: false,
                success: false
            )
        }

        // 第三步：结合 ASN / ISP 关键词二次校准是否为机房 IP (Hosting)
        let combinedProvider = "\(isp) \(org) \(asn)".lowercased()
        if !isHosting {
            for kw in hostingKeywords {
                if combinedProvider.contains(kw) {
                    isHosting = true
                    break
                }
            }
        }

        // 若 ip-api 标记了 proxy=true，但该 IP 属于知名云厂商机房且未明确标记 Tor，归类为机房节点并区分公开代理
        if isProxy && isHosting && (combinedProvider.contains("google") || combinedProvider.contains("amazon") || combinedProvider.contains("microsoft") || combinedProvider.contains("cloudflare") || combinedProvider.contains("oracle")) {
            // 知名大厂云机房默认按纯净机房 IP 评估，不重复扣公开脏代理分
            isProxy = false
        }

        // 判断 IP 属性展示文本
        let ipType: String
        let ipTypeEn: String
        if isHosting {
            ipType = "机房IP"
            ipTypeEn = "(Hosting)"
        } else if isMobile {
            ipType = "移动网络"
            ipTypeEn = "(Mobile)"
        } else {
            ipType = "住宅IP"
            ipTypeEn = "(Residential)"
        }

        // 判断 Claude 地区支持状态
        let upperCC = countryCode.uppercased()
        let regionSupported = !upperCC.isEmpty && !unsupportedCountryCodes.contains(upperCC)
        let regionStatusText = regionSupported ? "正常" : "不支持"

        // 第四步：计算 Claude AI 信任评分 (0 - 100)，与 ip.net.coffee 评分体系完全对齐
        var score = 100
        if isHosting {
            score -= 11 // 纯净机房 IP 得 89 分（如 Google LLC / AWS 节点显示 89 纯净）
        }
        if isVPN {
            score -= 15
        }
        if isProxy {
            score -= 22
        }
        if isTor {
            score -= 45
            isAbuse = true
        }
        if isCrawler {
            score -= 20
        }
        if !regionSupported {
            score -= 25
        }
        if claudeIP.contains(":") {
            // IPv6 出口略微降权提醒
            score -= 5
        }
        score = max(5, min(100, score))

        let trustLevel: String
        let trustDesc: String
        if score >= 80 {
            trustLevel = "纯净"
            trustDesc = "该 IP 信誉优异"
        } else if score >= 65 {
            trustLevel = "低风险"
            trustDesc = "该 IP 信誉良好，可正常使用"
        } else if score >= 45 {
            trustLevel = "中风险"
            trustDesc = "该 IP 存在共享或风控记录，建议留意"
        } else {
            trustLevel = "高危"
            trustDesc = "该 IP 风险较高，极易触发 Claude 封禁或拦截"
        }

        return ClaudeRiskData(
            ip: claudeIP,
            isIPv6: claudeIP.contains(":"),
            country: country,
            countryCode: upperCC,
            flag: countryCodeToFlag(upperCC),
            city: city,
            region: region,
            asn: asn,
            isp: isp,
            org: org,
            timezone: timezone,
            ipType: ipType,
            ipTypeEn: ipTypeEn,
            isHosting: isHosting,
            trustScore: score,
            trustLevel: trustLevel,
            trustDesc: trustDesc,
            regionSupported: regionSupported,
            regionStatusText: regionStatusText,
            vpnDetected: isVPN,
            proxyDetected: isProxy,
            torDetected: isTor,
            crawlerDetected: isCrawler,
            abuseDetected: isAbuse,
            success: true
        )
    }

    // MARK: - 4. 检测 Claude 域名可用性与真实延迟
    func detectClaudeAvailability(proxyMode: String, customProxy: String) -> [EndpointPingResult] {
        let proxyArgs = buildCurlProxyArgs(proxyMode: proxyMode, customProxy: customProxy)
        let domains = ["claude.ai", "anthropic.com"]
        var results: [EndpointPingResult] = []
        let group = DispatchGroup()
        let lock = NSLock()

        for domain in domains {
            group.enter()
            DispatchQueue.global(qos: .userInitiated).async {
                let res = self.measureDomainLatency(domain: domain, proxyArgs: proxyArgs)
                lock.lock()
                results.append(res)
                lock.unlock()
                group.leave()
            }
        }
        group.wait()

        // 保持固定顺序：claude.ai 在前，anthropic.com 在后
        return domains.compactMap { d in results.first(where: { $0.domain == d }) }
    }

    private func measureDomainLatency(domain: String, proxyArgs: [String]) -> EndpointPingResult {
        var args = [
            "-o", "/dev/null",
            "-s",
            "--max-time", "6",
            "--connect-timeout", "4",
            "-w", "%{http_code}|%{time_appconnect}|%{time_total}",
            "https://\(domain)"
        ]
        args.insert(contentsOf: proxyArgs, at: 0)

        let start = Date()
        let out = runProcess(executable: "/usr/bin/curl", arguments: args, timeout: 7.0)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let elapsedMs = Int(Date().timeIntervalSince(start) * 1000)

        let parts = out.components(separatedBy: "|")
        let code = Int(parts.first ?? "0") ?? 0
        var latency = elapsedMs
        if parts.count >= 2, let tlsSec = Double(parts[1]), tlsSec > 0.001 {
            latency = Int(tlsSec * 1000)
        } else if parts.count >= 3, let totalSec = Double(parts[2]), totalSec > 0.001 {
            latency = Int(totalSec * 1000)
        }

        if code > 0 && code != 000 {
            return EndpointPingResult(
                domain: domain,
                reachable: true,
                latencyMs: max(1, latency),
                statusCode: code,
                statusText: "正常"
            )
        } else {
            return EndpointPingResult(
                domain: domain,
                reachable: false,
                latencyMs: 0,
                statusCode: 0,
                statusText: "连接失败"
            )
        }
    }

    // MARK: - 5. 检测 DNS 泄露
    func detectDNSLeak(proxyMode: String, customProxy: String, claudeCountryCode: String) -> DNSLeakResult {
        let proxyArgs = buildCurlProxyArgs(proxyMode: proxyMode, customProxy: customProxy)

        // 使用 ip-api 官方的 EDNS 递归解析器探测接口
        let randomId = UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(12).lowercased()
        let ednsUrl = "http://\(randomId).edns.ip-api.com/json"
        let raw = curlGet(url: ednsUrl, extraArgs: proxyArgs, timeout: 5)

        if let data = raw.data(using: .utf8),
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let dnsObj = json["dns"] as? [String: Any] {
            let dnsIP = (dnsObj["ip"] as? String) ?? "未知"
            let dnsGeo = (dnsObj["geo"] as? String) ?? "未知"

            // 判断是否存在 DNS 泄露：如果 Claude 出口在海外，但递归 DNS 出口在中国大陆，则判定为泄露
            let isChinaDNS = dnsGeo.lowercased().contains("china")
            let isOverseasClaude = !claudeCountryCode.isEmpty && claudeCountryCode != "CN"
            let leaked = isChinaDNS && isOverseasClaude

            return DNSLeakResult(
                leaked: leaked,
                statusText: leaked ? "检测到国内DNS泄露" : "未检测到泄露",
                dnsIP: dnsIP,
                dnsGeo: dnsGeo
            )
        }

        return DNSLeakResult(
            leaked: false,
            statusText: "未检测到泄露",
            dnsIP: "加密 DNS / DoH",
            dnsGeo: "Cloudflare / 安全解析"
        )
    }

    // MARK: - 辅助：查询任意 IP 的简要地理与 ISP 信息
    private func fetchBasicIPGeo(ip: String, proxyArgs: [String]) -> (countryCode: String, summary: String) {
        let raw = curlGet(url: "http://ip-api.com/json/\(ip)?fields=status,country,countryCode,regionName,city,isp", extraArgs: proxyArgs, timeout: 4)
        if let data = raw.data(using: .utf8),
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           (json["status"] as? String) == "success" {
            let cc = (json["countryCode"] as? String) ?? ""
            let country = (json["country"] as? String) ?? ""
            let region = (json["regionName"] as? String) ?? ""
            let city = (json["city"] as? String) ?? ""
            let isp = (json["isp"] as? String) ?? ""
            var parts: [String] = []
            for item in [country, region, city, isp] where !item.isEmpty {
                if !parts.contains(item) {
                    parts.append(item)
                }
            }
            return (cc, parts.joined(separator: " "))
        }
        return ("", "")
    }
}
