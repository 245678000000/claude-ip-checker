import Foundation

@main
struct NativeDiagnosticsTests {
    static func main() throws {
        var failures: [String] = []
        var count = 0
        func expect(_ value: @autoclosure () -> Bool, _ message: String) {
            count += 1
            if !value() { failures.append(message) }
        }
        func json<T: Encodable>(_ value: T) throws -> [String: Any] {
            try JSONSerialization.jsonObject(with: JSONEncoder().encode(value)) as! [String: Any]
        }
        func response(_ body: String, _ status: Int = 200) -> NativeHTTPResponse {
            NativeHTTPResponse(body: body, statusCode: status)
        }
        let baseAPI = response(#"{"status":"success","query":"203.0.113.7","countryCode":"US"}"#)
        let baseWho = response(#"{"success":true,"ip":"203.0.113.7"}"#)
        func risk(api: NativeHTTPResponse? = nil, who: NativeHTTPResponse? = nil) -> ClaudeRiskData {
            NativeDiagnostics.risk(ip: "203.0.113.7", source: "https://claude.ai/cdn-cgi/trace", verified: true,
                                   ipAPI: api ?? baseAPI, ipWho: who ?? baseWho, observedAt: "2026-10-28T06:00:00Z")
        }

        // Request injection guarantees these regression tests never access the network.
        let failed = NetworkDetector(request: { _, _, _, _ in NativeHTTPResponse(error: "timeout") })
        let failedDNS = failed.detectDNSLeak(proxyMode: "direct", customProxy: "", claudeCountryCode: "US")
        expect(failedDNS.status == "error", "failed DNS must be error, not successful DoH")
        expect(failedDNS.dnsIP == "未知" && failedDNS.dnsGeo == "未知", "failed DNS must keep resolver unknown")
        expect(failedDNS.error == "timeout" && !failedDNS.source.isEmpty, "failed DNS retains error and attempted source")
        let emptyDNS = NativeDiagnostics.dns(response: response("{}"), source: "fixture", exitCountry: "US")
        expect(emptyDNS.status == "unknown" && emptyDNS.dnsIP == "未知", "empty DNS stays unknown")
        expect(NativeDiagnostics.dns(response: response(""), source: "fixture", exitCountry: "US").status == "error", "empty body is parse error")
        expect(NativeDiagnostics.dns(response: response("<html>403</html>", 403), source: "fixture", exitCountry: "US").status == "error", "HTTP failure stays DNS error")
        expect(NativeDiagnostics.dns(response: response(#"{"dns":{"ip":"html"}}"#), source: "fixture", exitCountry: "US").status == "unknown", "invalid resolver IP stays unknown")
        let observed = NativeDiagnostics.dns(response: response(#"{"dns":{"ip":"198.51.100.1","geo":"United States - Dallas"}}"#), source: "fixture", exitCountry: "US")
        expect(observed.status == "observed" && !observed.leaked, "matching resolver is observed, not universal no-leak")
        let mismatch = NativeDiagnostics.dns(response: response(#"{"dns":{"ip":"198.51.100.2","geo":"China - Beijing"}}"#), source: "fixture", exitCountry: "US")
        expect(mismatch.status == "mismatch" && !mismatch.leaked, "geographic mismatch does not prove a leak")
        let japanMismatch = NativeDiagnostics.dns(response: response(#"{"dns":{"ip":"2001:db8::1","countryCode":"JP","geo":"Japan"}}"#), source: "fixture", exitCountry: "US")
        expect(japanMismatch.status == "mismatch", "mismatch is not restricted to CN")
        let noCountry = NativeDiagnostics.dns(response: response(#"{"dns":{"ip":"198.51.100.1"}}"#), source: "fixture", exitCountry: "US")
        expect(noCountry.status == "observed" && noCountry.dnsGeo == "未知", "valid resolver with unknown geography remains observed")

        for (code, status) in [(200, "ok"), (204, "ok"), (301, "redirect"), (307, "redirect"),
                               (401, "blocked"), (403, "blocked"), (429, "rate_limited"),
                               (500, "server_error"), (503, "server_error"), (404, "http_error"), (0, "error")] {
            let result = NativeDiagnostics.endpoint(domain: "fixture", response: response("", code))
            expect(result.status == status, "HTTP \(code) must be \(status)")
            expect(result.reachable == (code > 0), "HTTP \(code) transport evidence kept separate")
        }
        let partialTransport = NativeDiagnostics.endpoint(domain: "fixture", response: NativeHTTPResponse(statusCode: 200, error: "timeout"))
        expect(partialTransport.status == "error" && partialTransport.reachable, "incomplete HTTP body is error with transport evidence")
        var followedRedirects = false
        let statusDetector = NetworkDetector(request: { _, _, _, follow in
            if follow { followedRedirects = true }
            return NativeHTTPResponse(statusCode: 403, latencyMs: 25)
        })
        expect(statusDetector.detectClaudeAvailability(proxyMode: "direct", customProxy: "").allSatisfy { $0.status == "blocked" && $0.latencyMs == 25 }, "availability uses status classification")
        expect(!followedRedirects, "availability preserves redirect response rather than following it")

        let absent = risk()
        expect(absent.signals.count == 7 && absent.signals.values.allSatisfy { $0.status == "unknown" }, "absent security fields all stay unknown")
        expect(absent.ipType == "未知", "missing hosting must not imply residential")
        expect(absent.regionStatusText == "待官方核对" && !absent.regionSupported, "region requires official manual check")
        expect(absent.trustScore == 0 && absent.trustLevel == "未评级", "legacy score does not claim measured reputation")
        expect(absent.observedAt == "2026-10-28T06:00:00Z", "observation time is retained")
        let securityFalse = risk(who: response(#"{"success":true,"ip":"203.0.113.7","security":{"vpn":false,"proxy":false,"tor":false,"crawler":false,"abuse":false,"hosting":false,"mobile":false}}"#))
        expect(securityFalse.signals.values.allSatisfy { $0.status == "not_detected" }, "explicit false is not_detected")
        expect(securityFalse.ipType == "未知", "not detected hosting does not prove residential")
        let numericFalse = risk(who: response(#"{"success":true,"ip":"203.0.113.7","security":{"vpn":0,"proxy":1,"tor":"false","crawler":null}}"#))
        expect(["vpn", "proxy", "tor", "crawler"].allSatisfy { numericFalse.signals[$0]?.status == "unknown" }, "numeric/string/null is not Boolean evidence")
        let cloudProxy = risk(api: response(#"{"status":"success","query":"203.0.113.7","hosting":true,"proxy":true,"isp":"Google Cloud"}"#),
                              who: response(#"{"success":true,"ip":"203.0.113.7","security":{"proxy":false,"tor":true}}"#))
        expect(cloudProxy.proxyDetected && cloudProxy.signals["proxy"]?.status == "detected", "cloud brand never clears proxy=true")
        expect(cloudProxy.torDetected && !cloudProxy.abuseDetected && cloudProxy.signals["abuse"]?.status == "unknown", "Tor does not imply Abuse")
        let heuristic = risk(api: response(#"{"status":"success","query":"203.0.113.7","isp":"Amazon AWS"}"#))
        expect(heuristic.isHosting && heuristic.signals["hosting"]?.source == "ASN/ISP heuristic", "ASN heuristic is identified as heuristic")
        let explicitHostingFalse = risk(api: response(#"{"status":"success","query":"203.0.113.7","isp":"Amazon AWS","hosting":false}"#))
        expect(!explicitHostingFalse.isHosting, "heuristic does not override explicit negative provider observation")
        let failedSources = risk(api: NativeHTTPResponse(error: "timeout"), who: NativeHTTPResponse(error: "timeout"))
        expect(failedSources.signals["vpn"]?.status == "error", "provider request failure differs from absent field")
        expect(failedSources.signals["abuse"]?.status == "unknown", "no independent Abuse source stays unknown")
        let wrongSubject = risk(api: response(#"{"status":"success","query":"203.0.113.8","proxy":true,"countryCode":"CN"}"#))
        expect(wrongSubject.signals["proxy"]?.status == "error" && wrongSubject.countryCode.isEmpty, "provider data for a different IP is rejected")
        let invalidRisk = NativeDiagnostics.risk(ip: "error", source: "fixture", verified: true, ipAPI: baseAPI, ipWho: baseWho)
        expect(!invalidRisk.success && !invalidRisk.exitVerified, "invalid IP never becomes successful evidence")

        for invalid in ["", "<html>error</html>", "error", "1.2.3.999", "1.2.3", "01.2.3.4", "1.2.3.4:80", ":::", "fe80::1%en0", "1.2.3.4\u{0}evil"] {
            expect(NativeDiagnostics.normalizedIP(invalid) == nil, "invalid IP \(invalid.debugDescription) rejected")
        }
        expect(NativeDiagnostics.normalizedIP(" 203.0.113.7\n") == "203.0.113.7", "valid IPv4 whitespace trimmed")
        expect(NativeDiagnostics.normalizedIP("2001:0DB8:0:0:0:0:0:1") == "2001:db8::1", "IPv6 canonicalized")
        expect(NativeDiagnostics.trace(response("ip=not-an-ip\nloc=CN")) == nil, "invalid trace rejected")
        expect(NativeDiagnostics.trace(response("ip=203.0.113.7", 403)) == nil, "error status trace rejected")
        expect(NativeDiagnostics.countryFlag("12") == "🌐", "invalid country flag falls back")

        let fallbackDetector = NetworkDetector(request: { url, _, _, _ in
            if url.contains("cdn-cgi") { return response("<html>blocked</html>", 403) }
            if url.contains("ipify") { return response("203.0.113.7") }
            if url.contains("ip-api.com") { return baseAPI }
            return baseWho
        })
        let fallback = fallbackDetector.detectClaudeIPAndRisk(proxyMode: "direct", customProxy: "")
        expect(fallback.success && !fallback.exitVerified && fallback.exitSource == "https://api64.ipify.org", "generic exit fallback preserves unverified actual source")
        let verifiedDetector = NetworkDetector(request: { url, _, _, _ in
            if url.contains("cdn-cgi") { return response("ip=203.0.113.7\nloc=US") }
            if url.contains("ip-api.com") { return baseAPI }
            return baseWho
        })
        expect(verifiedDetector.detectClaudeIPAndRisk(proxyMode: "direct", customProxy: "").exitVerified, "Claude trace confirms endpoint-specific exit")
        let crossHost = NetworkDetector(request: { url, _, _, _ in
            if url.contains("cdn-cgi") { return NativeHTTPResponse(body: "ip=203.0.113.7", statusCode: 200, effectiveURL: "https://example.com/cdn-cgi/trace") }
            if url.contains("ip-api.com") { return baseAPI }
            return baseWho
        }).detectClaudeIPAndRisk(proxyMode: "direct", customProxy: "")
        expect(!crossHost.exitVerified && crossHost.exitSource.contains("example.com"), "redirect source is not asserted to be Claude")
        expect(!failed.detectClaudeIPAndRisk(proxyMode: "direct", customProxy: "").success, "all request failures yield no exit")
        let directDetector = NetworkDetector(request: { url, args, _, _ in
            expect(args.contains("--noproxy") && args.contains("-4"), "direct IPv4 path explicitly disables proxy")
            if url.contains("ipip") { return response(#"{"data":{"ip":"203.0.113.7","location":["United States"]}}"#) }
            return response("{}")
        })
        let direct = directDetector.detectChinaIPv4()
        expect(direct.success && direct.countryCode.isEmpty && !direct.locationText.contains("China"), "direct lookup never invents CN")

        let document = URL(fileURLWithPath: "/tmp/app/Resources/index.html")
        expect(NativeBridgePolicy.trustedDocument(document, expected: document), "exact main document is trusted")
        expect(!NativeBridgePolicy.trustedDocument(URL(string: "https://example.com/index.html"), expected: document), "remote document rejected")
        expect(!NativeBridgePolicy.trustedDocument(URL(fileURLWithPath: "/tmp/app/Resources/other.html"), expected: document), "unrelated local file rejected")
        expect(!NativeBridgePolicy.trustedDocument(nil, expected: document), "missing document rejected")
        expect(NativeBridgePolicy.externalURL("https://example.com/path") != nil, "HTTPS link allowed")
        for url in ["http://example.com", "file:///tmp/a", "javascript:alert(1)", "https:", "https://u:p@example.com", "data:text/plain,a"] {
            expect(NativeBridgePolicy.externalURL(url) == nil, "non-HTTPS/credentialed external URL rejected")
        }
        expect(NativeBridgePolicy.runID(NSNumber(value: 12)) == 12, "integer batch accepted")
        for value: Any in [true, "12", -1, 1.5, Double.nan, Double.infinity, 9_007_199_254_740_992.0] {
            expect(NativeBridgePolicy.runID(value) == nil, "invalid batch value rejected")
        }
        var batch = NativeBatchState()
        expect(batch.begin(1), "first batch starts")
        batch.setCountry("US", runID: 1)
        expect(batch.countryCode == "US" && batch.isCurrent(1), "current batch result accepted")
        expect(batch.begin(2) && batch.countryCode.isEmpty, "new batch clears old geography")
        batch.setCountry("CN", runID: 1)
        expect(!batch.isCurrent(1) && batch.countryCode.isEmpty, "old result cannot mutate new batch")
        expect(!batch.begin(1) && !batch.begin(2), "older and duplicate full requests are rejected")
        expect(batch.begin(3) && !batch.isCurrent(2), "cancel generation invalidates in-flight callbacks")
        batch.setCountry("JP", runID: 2)
        expect(batch.countryCode.isEmpty, "canceled run does not seed later DNS geography")
        expect(NativeBridgePolicy.validReport(#"{"ip":"203.0.113.*"}"#), "JSON report accepted")
        expect(!NativeBridgePolicy.validReport("not JSON"), "non-JSON report rejected")
        expect(!NativeBridgePolicy.validReport("{\"data\":\"" + String(repeating: "a", count: 1_048_576) + "\"}"), "oversize report rejected")
        let encoded = try json(fallback)
        expect(encoded["signals"] is [String: Any] && encoded["exitVerified"] as? Bool == false, "public JSON contract includes signals and provenance")

        if !failures.isEmpty {
            failures.forEach { print("FAIL: \($0)") }
            print("\(failures.count) failures in \(count) assertions")
            exit(1)
        }
        print("Native diagnostics fixtures passed: \(count) assertions (offline)")
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        print("DNS_JSON=" + String(data: try encoder.encode(mismatch), encoding: .utf8)!)
        print("RISK_JSON=" + String(data: try encoder.encode(fallback), encoding: .utf8)!)
    }
}
