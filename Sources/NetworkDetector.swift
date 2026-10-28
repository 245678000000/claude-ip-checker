import Foundation
import CoreFoundation
import Darwin

struct NativeHTTPResponse {
    var body: String = ""
    var statusCode: Int = 0
    var latencyMs: Int = 0
    var error: String = ""
    var effectiveURL: String = ""

    var succeeded: Bool { error.isEmpty && (200..<300).contains(statusCode) }
}

typealias NativeHTTPRequest = (String, [String], Int, Bool) -> NativeHTTPResponse

struct SystemProxyInfo: Codable {
    var enabled: Bool
    var httpProxy: String?
    var socksProxy: String?
    var summary: String
    var status: String = "observed"
}

struct ExitIPCardData: Codable {
    var ip: String
    var countryCode: String
    var flag: String
    var locationText: String
    var isIPv6: Bool
    var success: Bool
    var source: String = ""
    var observedAt: String = ""
}

struct EvidenceSignal: Codable, Equatable {
    var status: String
    var source: String
}

struct ClaudeRiskData: Codable {
    var ip: String = "获取失败"
    var isIPv6: Bool = false
    var country: String = "未知"
    var countryCode: String = ""
    var flag: String = "🌐"
    var city: String = "未知"
    var region: String = ""
    var asn: String = "未知"
    var isp: String = "未知"
    var org: String = ""
    var timezone: String = "未知"
    var ipType: String = "未知"
    var ipTypeEn: String = ""
    // Legacy booleans describe detected values only; read signals for unknown/error.
    var isHosting: Bool = false
    var trustScore: Int = 0
    var trustLevel: String = "未评级"
    var trustDesc: String = "未执行账号信誉检测；仅展示本次证据"
    var regionSupported: Bool = false
    var regionStatusText: String = "待官方核对"
    var vpnDetected: Bool = false
    var proxyDetected: Bool = false
    var torDetected: Bool = false
    var crawlerDetected: Bool = false
    var abuseDetected: Bool = false
    var success: Bool = false
    var signals: [String: EvidenceSignal] = [:]
    var exitSource: String = ""
    var exitVerified: Bool = false
    var observedAt: String = ""
}

struct EndpointPingResult: Codable {
    var domain: String
    var reachable: Bool
    var latencyMs: Int
    var statusCode: Int
    var statusText: String
    var status: String
}

struct DNSLeakResult: Codable {
    var leaked: Bool = false // Geography mismatch alone does not establish a leak.
    var statusText: String = "解析器结果未知"
    var dnsIP: String = "未知"
    var dnsGeo: String = "未知"
    var status: String = "unknown"
    var source: String = ""
    var error: String = ""
}

struct UpdateCheckResult: Codable {
    var currentVersion: String
    var latestVersion: String
    var hasUpdate: Bool
    var releaseURL: String
    var downloadURL: String
    var releaseNotes: String
    var errorMsg: String
}

/// Deterministic parser seams shared by live requests and offline fixtures.
enum NativeDiagnostics {
    static let signalNames = ["vpn", "proxy", "tor", "crawler", "abuse", "hosting", "mobile"]
    static let hostingKeywords = ["google", "amazon", "aws", "cloudflare", "microsoft", "azure",
        "digitalocean", "linode", "akamai", "vultr", "choopa", "hetzner", "ovh", "oracle",
        "alibaba", "aliyun", "tencent", "huawei", "leaseweb", "contabo", "datacamp", "cdn77",
        "psychz", "zenlayer", "dmit", "bandwagon", "it7", "multacom", "sharktech", "colocrossing",
        "quadranet", "hostinger", "equinix", "fastly", "kamatera", "upcloud", "scaleway", "ionos",
        "racknerd", "buyvm", "frantech", "gcore", "misaka", "nearoute", "xtom", "hosting", "datacenter", "cloud", "vps"]

    static func timestamp() -> String { ISO8601DateFormatter().string(from: Date()) }

    static func normalizedIP(_ text: String) -> String? {
        let value = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty, value.utf8.count <= 45, !value.contains("%"), !value.contains("\0") else { return nil }
        // Darwin's inet_pton accepts some leading-zero forms; reject ambiguous IPv4 spelling.
        if value.contains(".") || !value.contains(":") {
            let tail = value.split(separator: ":", omittingEmptySubsequences: false).last.map(String.init) ?? value
            let octets = tail.split(separator: ".", omittingEmptySubsequences: false)
            guard octets.count == 4, octets.allSatisfy({ part in
                !part.isEmpty && part.utf8.allSatisfy { (48...57).contains($0) }
                    && (part.count == 1 || part.first != "0") && (Int(part) ?? 256) <= 255
            }) else { return nil }
        }
        var address4 = in_addr()
        if value.withCString({ inet_pton(AF_INET, $0, &address4) }) == 1 {
            var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            guard inet_ntop(AF_INET, &address4, &buffer, socklen_t(buffer.count)) != nil else { return nil }
            return String(cString: buffer)
        }
        var address6 = in6_addr()
        if value.withCString({ inet_pton(AF_INET6, $0, &address6) }) == 1 {
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            guard inet_ntop(AF_INET6, &address6, &buffer, socklen_t(buffer.count)) != nil else { return nil }
            return String(cString: buffer)
        }
        return nil
    }

    static func countryCode(_ text: String) -> String {
        let code = text.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        return code.utf8.count == 2 && code.utf8.allSatisfy { (65...90).contains($0) } ? code : ""
    }

    static func countryFlag(_ text: String) -> String {
        let code = countryCode(text)
        guard !code.isEmpty else { return "🌐" }
        return String(String.UnicodeScalarView(code.unicodeScalars.compactMap { UnicodeScalar(127397 + $0.value) }))
    }

    static func json(_ response: NativeHTTPResponse) -> [String: Any]? {
        guard response.succeeded, let data = response.body.data(using: .utf8) else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }

    // Foundation can bridge numeric 0/1 as Bool; only JSON true/false are evidence.
    static func strictBool(_ value: Any?) -> Bool? {
        guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { return nil }
        return number.boolValue
    }

    static func trace(_ response: NativeHTTPResponse) -> (ip: String, countryCode: String)? {
        guard response.succeeded else { return nil }
        var entries: [String: String] = [:]
        for line in response.body.components(separatedBy: .newlines) {
            let parts = line.split(separator: "=", maxSplits: 1).map(String.init)
            if parts.count == 2 { entries[parts[0]] = parts[1] }
        }
        guard let ip = normalizedIP(entries["ip"] ?? "") else { return nil }
        return (ip, countryCode(entries["loc"] ?? ""))
    }

    static func httpStatus(_ code: Int, error: String = "") -> String {
        guard error.isEmpty, (100...599).contains(code) else { return "error" }
        switch code {
        case 200..<300: return "ok"
        case 300..<400: return "redirect"
        case 401, 403: return "blocked"
        case 429: return "rate_limited"
        case 500..<600: return "server_error"
        default: return "http_error"
        }
    }

    static func endpoint(domain: String, response: NativeHTTPResponse) -> EndpointPingResult {
        let status = httpStatus(response.statusCode, error: response.error)
        let text = ["ok": "HTTP 响应成功（未验证账号功能）", "redirect": "HTTP 重定向",
                    "blocked": "HTTP 访问受限", "rate_limited": "HTTP 请求限流",
                    "server_error": "HTTP 服务端错误", "http_error": "HTTP 非成功响应", "error": "请求失败"]
        return EndpointPingResult(domain: domain, reachable: (100...599).contains(response.statusCode),
                                  latencyMs: max(0, response.latencyMs), statusCode: response.statusCode,
                                  statusText: text[status] ?? "请求失败", status: status)
    }

    static func resolverCountry(_ dns: [String: Any]) -> String {
        for key in ["countryCode", "country_code"] {
            let code = countryCode(dns[key] as? String ?? "")
            if !code.isEmpty { return code }
        }
        let geography = (dns["country"] as? String) ?? (dns["geo"] as? String) ?? ""
        let head = geography.components(separatedBy: CharacterSet(charactersIn: ",-")).first?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let code = countryCode(head)
        if !code.isEmpty { return code }
        let aliases = ["china": "CN", "mainland china": "CN", "china mainland": "CN",
                       "united states": "US", "united states of america": "US", "united kingdom": "GB",
                       "hong kong": "HK", "taiwan": "TW"]
        if let alias = aliases[head.lowercased()] { return alias }
        let locale = Locale(identifier: "en_US")
        return Locale.Region.isoRegions.first { locale.localizedString(forRegionCode: $0.identifier)?.caseInsensitiveCompare(head) == .orderedSame }?.identifier ?? ""
    }

    static func dns(response: NativeHTTPResponse, source: String, exitCountry: String) -> DNSLeakResult {
        var result = DNSLeakResult(source: source)
        guard response.succeeded else {
            result.status = "error"
            result.statusText = "DNS 检测失败 / 结果未知"
            result.error = response.error.isEmpty ? "HTTP \(response.statusCode)" : response.error
            return result
        }
        guard let data = json(response) else {
            result.status = "error"; result.error = "invalid_json"; result.statusText = "DNS 响应解析失败"
            return result
        }
        guard let dns = data["dns"] as? [String: Any], let ip = normalizedIP(dns["ip"] as? String ?? "") else {
            result.error = "resolver_not_returned"
            return result
        }
        result.dnsIP = ip
        result.dnsGeo = (dns["geo"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? "未知"
        let resolverCC = resolverCountry(dns)
        let exitCC = countryCode(exitCountry)
        let differs = !resolverCC.isEmpty && !exitCC.isEmpty && resolverCC != exitCC
        result.status = differs ? "mismatch" : "observed"
        result.statusText = differs ? "解析器与出口地区不同（不等同泄露）" : "已观测解析器（仅当前请求路径）"
        return result
    }

    static func risk(ip: String, source: String, verified: Bool,
                     ipAPI: NativeHTTPResponse, ipWho: NativeHTTPResponse,
                     observedAt: String = timestamp()) -> ClaudeRiskData {
        var result = ClaudeRiskData(observedAt: observedAt)
        result.signals = Dictionary(uniqueKeysWithValues: signalNames.map { ($0, EvidenceSignal(status: "unknown", source: "未取得字段")) })
        guard let validIP = normalizedIP(ip) else { return result }
        result.ip = validIP; result.isIPv6 = validIP.contains(":"); result.success = true
        result.exitSource = source; result.exitVerified = verified

        func merge(_ field: String, _ value: Any?, _ source: String) {
            guard let value = strictBool(value) else { return }
            // Preserve positive provider observations instead of brand-based overrides.
            if result.signals[field]?.status != "detected" {
                result.signals[field] = EvidenceSignal(status: value ? "detected" : "not_detected", source: source)
            }
        }
        func markFailure(_ fields: [String], _ source: String) {
            for field in fields where result.signals[field]?.status == "unknown" {
                result.signals[field] = EvidenceSignal(status: "error", source: source)
            }
        }
        func value(_ object: [String: Any], _ name: String, default fallback: String = "") -> String {
            guard let text = object[name] as? String, !text.isEmpty else { return fallback }
            return text
        }

        if let a = json(ipAPI), a["status"] as? String == "success",
           normalizedIP(value(a, "query")) == validIP {
            result.country = value(a, "country", default: result.country)
            result.countryCode = countryCode(value(a, "countryCode"))
            result.city = value(a, "city", default: result.city)
            result.region = value(a, "regionName")
            result.asn = value(a, "as", default: result.asn).components(separatedBy: " ").first ?? "未知"
            result.isp = value(a, "isp", default: result.isp); result.org = value(a, "org")
            result.timezone = value(a, "timezone", default: result.timezone)
            for field in ["hosting", "proxy", "mobile"] { merge(field, a[field], "ip-api.com (HTTP): \(field)") }
        } else { markFailure(["hosting", "proxy", "mobile"], "ip-api.com: 请求或响应无效") }

        if let b = json(ipWho), strictBool(b["success"]) == true,
           normalizedIP(value(b, "ip")) == validIP {
            if result.country == "未知" { result.country = value(b, "country", default: result.country) }
            if result.countryCode.isEmpty { result.countryCode = countryCode(value(b, "country_code")) }
            if result.city == "未知" { result.city = value(b, "city", default: result.city) }
            if result.region.isEmpty { result.region = value(b, "region") }
            if let tz = b["timezone"] as? [String: Any], result.timezone == "未知" { result.timezone = value(tz, "id", default: result.timezone) }
            if let connection = b["connection"] as? [String: Any] {
                if result.asn == "未知", let asn = connection["asn"] as? Int, asn > 0 { result.asn = "AS\(asn)" }
                if result.isp == "未知" { result.isp = value(connection, "isp", default: result.isp) }
                if result.org.isEmpty { result.org = value(connection, "org") }
            }
            let security = b["security"] as? [String: Any] ?? [:]
            for field in signalNames {
                merge(field, security[field], "ipwho.is: security.\(field)")
                if result.signals[field]?.status == "unknown" {
                    result.signals[field]?.source = "ipwho.is: security.\(field) 未返回"
                }
            }
        } else { markFailure(["vpn", "proxy", "tor", "crawler", "hosting", "mobile"], "ipwho.is: 请求或响应无效") }

        let provider = "\(result.isp) \(result.org) \(result.asn)".lowercased()
        if ["unknown", "error"].contains(result.signals["hosting"]?.status ?? ""),
           hostingKeywords.contains(where: { provider.contains($0) }) {
            result.signals["hosting"] = EvidenceSignal(status: "detected", source: "ASN/ISP heuristic")
        }
        result.isHosting = result.signals["hosting"]?.status == "detected"
        if result.isHosting { result.ipType = "机房IP"; result.ipTypeEn = "(Hosting)" }
        else if result.signals["mobile"]?.status == "detected" { result.ipType = "移动网络"; result.ipTypeEn = "(Mobile)" }
        result.vpnDetected = result.signals["vpn"]?.status == "detected"
        result.proxyDetected = result.signals["proxy"]?.status == "detected"
        result.torDetected = result.signals["tor"]?.status == "detected"
        result.crawlerDetected = result.signals["crawler"]?.status == "detected"
        result.abuseDetected = result.signals["abuse"]?.status == "detected"
        result.flag = countryFlag(result.countryCode)
        return result
    }
}

/// These decisions are pure so the bridge boundary and batching can be tested offline.
enum NativeBridgePolicy {
    static func runID(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
        let value = number.doubleValue
        guard value.isFinite, value >= 0, value <= 9_007_199_254_740_991, value.rounded(.towardZero) == value else { return nil }
        return Int(value)
    }
    static func externalURL(_ text: String) -> URL? {
        guard let url = URL(string: text), url.scheme?.lowercased() == "https",
              let host = url.host, !host.isEmpty, url.user == nil, url.password == nil else { return nil }
        return url
    }
    static func trustedDocument(_ url: URL?, expected: URL?) -> Bool {
        guard let url, let expected, url.isFileURL, expected.isFileURL,
              url.host == nil || url.host == "" || url.host == "localhost" else { return false }
        return url.standardizedFileURL.resolvingSymlinksInPath().path == expected.standardizedFileURL.resolvingSymlinksInPath().path
    }
    static func validReport(_ text: String) -> Bool {
        guard let data = text.data(using: .utf8), data.count <= 1_048_576,
              (try? JSONSerialization.jsonObject(with: data)) != nil else { return false }
        return true
    }
}

struct NativeBatchState {
    private(set) var currentRunID: Int?
    private(set) var countryCode = ""
    mutating func begin(_ runID: Int) -> Bool {
        guard currentRunID == nil || runID > currentRunID! else { return false }
        currentRunID = runID; countryCode = ""
        return true
    }
    func isCurrent(_ runID: Int) -> Bool { currentRunID == runID }
    mutating func setCountry(_ value: String, runID: Int) {
        if isCurrent(runID) { countryCode = value }
    }
}

class NetworkDetector {
    static let shared = NetworkDetector()
    private let injectedRequest: NativeHTTPRequest?
    init(request: NativeHTTPRequest? = nil) { injectedRequest = request }
    func countryCodeToFlag(_ code: String) -> String { NativeDiagnostics.countryFlag(code) }

    /// 读取 macOS 系统当前代理配置 (`scutil --proxy`)
    func getSystemProxyInfo() -> SystemProxyInfo {
        let output = runProcess(executable: "/usr/sbin/scutil", arguments: ["--proxy"], timeout: 3.0)
        guard !output.isEmpty else {
            return SystemProxyInfo(enabled: false, httpProxy: nil, socksProxy: nil,
                                   summary: "系统代理配置读取失败（状态未知）", status: "error")
        }
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
            case "HTTPEnable", "HTTPSEnable": httpEnable = httpEnable || (val == "1")
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
            return SystemProxyInfo(enabled: false, httpProxy: nil, socksProxy: nil, summary: "未发现显式系统代理（仍可能受 TUN 影响）")
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

    /// File-backed output avoids a full stdout pipe deadlocking while the process runs.
    private func execute(executable: String, arguments: [String], timeout: TimeInterval) -> (output: String, error: String) {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("claude-probe-\(UUID().uuidString)")
        guard FileManager.default.createFile(atPath: file.path, contents: nil, attributes: [.posixPermissions: 0o600]),
              let output = try? FileHandle(forWritingTo: file) else { return ("", "output_file_failed") }
        defer { try? output.close(); try? FileManager.default.removeItem(at: file) }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable); process.arguments = arguments
        process.standardOutput = output; process.standardError = FileHandle.nullDevice
        let completed = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in completed.signal() }
        do { try process.run() } catch { return ("", "process_start_failed") }
        if completed.wait(timeout: .now() + timeout) == .timedOut {
            if process.isRunning { process.terminate() }
            if completed.wait(timeout: .now() + 1) == .timedOut, process.isRunning { kill(process.processIdentifier, SIGKILL) }
            return ("", "timeout")
        }
        let data = (try? Data(contentsOf: file)) ?? Data()
        return (String(data: data, encoding: .utf8) ?? "", process.terminationStatus == 0 ? "" : "process_exit_\(process.terminationStatus)")
    }

    private func runProcess(executable: String, arguments: [String], timeout: TimeInterval = 8) -> String {
        let result = execute(executable: executable, arguments: arguments, timeout: timeout)
        return result.error.isEmpty ? result.output : ""
    }

    private func request(_ url: String, proxyArgs: [String], timeout: Int = 6, followRedirects: Bool = true) -> NativeHTTPResponse {
        if let injectedRequest { return injectedRequest(url, proxyArgs, timeout, followRedirects) }
        let marker = "\n__CLAUDE_HTTP_\(UUID().uuidString)__"
        var args = ["-s", "--max-time", "\(timeout)", "--connect-timeout", "4", "--max-filesize", "4194304",
                    "--proto", "=http,https", "--proto-redir", "=https", "--max-redirs", "5",
                    "-A", "Claude-IP-Checker", "-w", marker + "%{http_code}|%{time_total}|%{url_effective}"]
        if followRedirects { args.append("-L") }
        args += proxyArgs; args.append(url)
        let result = execute(executable: "/usr/bin/curl", arguments: args, timeout: TimeInterval(timeout + 2))
        guard let range = result.output.range(of: marker, options: .backwards) else {
            return NativeHTTPResponse(error: result.error.isEmpty ? "invalid_transport_response" : result.error)
        }
        let fields = result.output[range.upperBound...].components(separatedBy: "|")
        let seconds = fields.count > 1 ? (Double(fields[1]) ?? 0) : 0
        return NativeHTTPResponse(body: String(result.output[..<range.lowerBound]),
                                  statusCode: Int(fields.first ?? "") ?? 0,
                                  latencyMs: seconds.isFinite ? Int(max(0, min(seconds, 86_400)) * 1000) : 0,
                                  error: result.error, effectiveURL: fields.count > 2 ? fields[2] : "")
    }

    private func card(ip: String, countryCode: String, location: String, source: String) -> ExitIPCardData {
        ExitIPCardData(ip: ip, countryCode: countryCode, flag: NativeDiagnostics.countryFlag(countryCode),
                       locationText: location.isEmpty ? "地区未知" : location, isIPv6: ip.contains(":"), success: true,
                       source: source, observedAt: NativeDiagnostics.timestamp())
    }

    private func failedCard(_ source: String) -> ExitIPCardData {
        ExitIPCardData(ip: "获取失败", countryCode: "", flag: "🌐", locationText: "未取得出口证据",
                       isIPv6: false, success: false, source: source, observedAt: NativeDiagnostics.timestamp())
    }

    func detectChinaIPv4() -> ExitIPCardData {
        // This bypasses explicit curl proxies, not an OS-level TUN route.
        let args = ["--noproxy", "*", "-4"]
        let ipipURL = "https://myip.ipip.net/json"
        let response = request(ipipURL, proxyArgs: args, timeout: 4)
        if let json = NativeDiagnostics.json(response), let data = json["data"] as? [String: Any],
           let ip = NativeDiagnostics.normalizedIP(data["ip"] as? String ?? ""), !ip.contains(":") {
            let geo = fetchBasicIPGeo(ip: ip, proxyArgs: args)
            let location = (data["location"] as? [String] ?? []).filter { !$0.isEmpty }.joined(separator: " ")
            return card(ip: ip, countryCode: geo.countryCode, location: geo.summary.isEmpty ? location : geo.summary,
                        source: response.effectiveURL.isEmpty ? ipipURL : response.effectiveURL)
        }
        for url in ["https://4.ipw.cn", "https://ip.3322.net"] {
            let response = request(url, proxyArgs: args, timeout: 4)
            if response.succeeded, let ip = NativeDiagnostics.normalizedIP(response.body), !ip.contains(":") {
                let geo = fetchBasicIPGeo(ip: ip, proxyArgs: args)
                return card(ip: ip, countryCode: geo.countryCode, location: geo.summary, source: response.effectiveURL.isEmpty ? url : response.effectiveURL)
            }
        }
        return failedCard("未使用显式代理的 IPv4 请求")
    }

    func detectCloudflareIP(proxyMode: String, customProxy: String) -> ExitIPCardData {
        let args = buildCurlProxyArgs(proxyMode: proxyMode, customProxy: customProxy)
        for url in ["https://1.1.1.1/cdn-cgi/trace", "https://www.cloudflare.com/cdn-cgi/trace"] {
            let response = request(url, proxyArgs: args, timeout: 5)
            if let trace = NativeDiagnostics.trace(response) {
                let geo = fetchBasicIPGeo(ip: trace.ip, proxyArgs: args)
                let cc = geo.countryCode.isEmpty ? trace.countryCode : geo.countryCode
                return card(ip: trace.ip, countryCode: cc, location: geo.summary.isEmpty ? cc : geo.summary,
                            source: response.effectiveURL.isEmpty ? url : response.effectiveURL)
            }
        }
        return failedCard("https://www.cloudflare.com/cdn-cgi/trace")
    }

    func detectClaudeIPAndRisk(proxyMode: String, customProxy: String) -> ClaudeRiskData {
        let args = buildCurlProxyArgs(proxyMode: proxyMode, customProxy: customProxy)
        let traceURL = "https://claude.ai/cdn-cgi/trace"
        let traceResponse = request(traceURL, proxyArgs: args, timeout: 5)
        var ip = "", source = "", verified = false
        if let trace = NativeDiagnostics.trace(traceResponse) {
            ip = trace.ip
            source = traceResponse.effectiveURL.isEmpty ? traceURL : traceResponse.effectiveURL
            // A cross-host redirect proves the redirect destination's route, not claude.ai's.
            let endpoint = URL(string: source)
            verified = endpoint?.scheme?.lowercased() == "https" && endpoint?.host?.lowercased() == "claude.ai"
                && endpoint?.path == "/cdn-cgi/trace"
        }
        if ip.isEmpty {
            let url = "https://api64.ipify.org"
            let response = request(url, proxyArgs: args, timeout: 5)
            if response.succeeded, let candidate = NativeDiagnostics.normalizedIP(response.body) {
                ip = candidate; source = response.effectiveURL.isEmpty ? url : response.effectiveURL
            }
        }
        var whoResponse: NativeHTTPResponse?
        if ip.isEmpty {
            let url = "https://ipwho.is/"
            let response = request(url, proxyArgs: args, timeout: 5)
            if let json = NativeDiagnostics.json(response), NativeDiagnostics.strictBool(json["success"]) == true,
               let candidate = NativeDiagnostics.normalizedIP(json["ip"] as? String ?? "") {
                ip = candidate; source = response.effectiveURL.isEmpty ? url : response.effectiveURL; whoResponse = response
            }
        }
        guard !ip.isEmpty else {
            return NativeDiagnostics.risk(ip: "", source: "", verified: false, ipAPI: NativeHTTPResponse(), ipWho: NativeHTTPResponse())
        }
        let api = request("http://ip-api.com/json/\(ip)?fields=status,query,country,countryCode,regionName,city,as,isp,org,timezone,hosting,proxy,mobile", proxyArgs: args, timeout: 5)
        let who = whoResponse ?? request("https://ipwho.is/\(ip)", proxyArgs: args, timeout: 5)
        return NativeDiagnostics.risk(ip: ip, source: source, verified: verified, ipAPI: api, ipWho: who)
    }

    func detectClaudeAvailability(proxyMode: String, customProxy: String) -> [EndpointPingResult] {
        let args = buildCurlProxyArgs(proxyMode: proxyMode, customProxy: customProxy)
        return ["claude.ai", "anthropic.com"].map { domain in
            // Do not follow redirects: preserve the endpoint's measured HTTP response.
            NativeDiagnostics.endpoint(domain: domain, response: request("https://\(domain)", proxyArgs: args, timeout: 6, followRedirects: false))
        }
    }

    func detectDNSLeak(proxyMode: String, customProxy: String, claudeCountryCode: String) -> DNSLeakResult {
        let args = buildCurlProxyArgs(proxyMode: proxyMode, customProxy: customProxy)
        let id = UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(12).lowercased()
        let url = "http://\(id).edns.ip-api.com/json"
        let response = request(url, proxyArgs: args, timeout: 5)
        return NativeDiagnostics.dns(response: response, source: response.effectiveURL.isEmpty ? url : response.effectiveURL,
                                     exitCountry: claudeCountryCode)
    }

    private func fetchBasicIPGeo(ip: String, proxyArgs: [String]) -> (countryCode: String, summary: String) {
        guard let valid = NativeDiagnostics.normalizedIP(ip) else { return ("", "") }
        let response = request("https://ipwho.is/\(valid)", proxyArgs: proxyArgs, timeout: 4)
        guard let json = NativeDiagnostics.json(response), NativeDiagnostics.strictBool(json["success"]) == true,
              NativeDiagnostics.normalizedIP(json["ip"] as? String ?? "") == valid else { return ("", "") }
        let cc = NativeDiagnostics.countryCode(json["country_code"] as? String ?? "")
        var parts: [String] = []
        for key in ["country", "region", "city"] {
            if let text = json[key] as? String, !text.isEmpty, !parts.contains(text) { parts.append(text) }
        }
        return (cc, parts.joined(separator: " "))
    }

    func checkAppUpdate(currentVersion: String, proxyMode: String, customProxy: String) -> UpdateCheckResult {
        let args = buildCurlProxyArgs(proxyMode: proxyMode, customProxy: customProxy)
        let apiURL = "https://api.github.com/repos/245678000000/claude-ip-checker/releases/latest"
        let releases = "https://github.com/245678000000/claude-ip-checker/releases"
        var response = request(apiURL, proxyArgs: args, timeout: 6)
        if NativeDiagnostics.json(response)?["tag_name"] == nil { response = request(apiURL, proxyArgs: ["--noproxy", "*"], timeout: 5) }
        guard let json = NativeDiagnostics.json(response), let tag = json["tag_name"] as? String,
              let latest = versionParts(tag), let current = versionParts(currentVersion) else {
            return UpdateCheckResult(currentVersion: currentVersion, latestVersion: currentVersion, hasUpdate: false,
                                     releaseURL: releases, downloadURL: "", releaseNotes: "", errorMsg: "版本检查失败，请稍后重试")
        }
        let newer = current.lexicographicallyPrecedes(latest)
        let page = NativeBridgePolicy.externalURL(json["html_url"] as? String ?? "")?.absoluteString ?? releases
        var download = page
        for asset in json["assets"] as? [[String: Any]] ?? [] {
            if (asset["name"] as? String ?? "").lowercased().contains("macos"),
               let url = NativeBridgePolicy.externalURL(asset["browser_download_url"] as? String ?? "") {
                download = url.absoluteString; break
            }
        }
        return UpdateCheckResult(currentVersion: currentVersion, latestVersion: tag, hasUpdate: newer,
                                 releaseURL: page, downloadURL: download, releaseNotes: json["body"] as? String ?? "", errorMsg: "")
    }

    private func versionParts(_ version: String) -> [Int]? {
        var text = version.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.hasPrefix("v") || text.hasPrefix("V") { text.removeFirst() }
        let pieces = text.split(separator: ".", omittingEmptySubsequences: false)
        guard pieces.count == 3 else { return nil }
        let values = pieces.compactMap { Int($0) }
        guard values.count == 3, values.allSatisfy({ $0 >= 0 }) else { return nil }
        return values
    }
}
