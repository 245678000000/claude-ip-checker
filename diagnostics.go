package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type EvidenceSignal struct {
	Status string `json:"status"`
	Source string `json:"source"`
}

func validIP(s string) string {
	p := net.ParseIP(strings.TrimSpace(s))
	if p == nil {
		return ""
	}
	return p.String()
}
func classifyHTTP(code int) (string, string) {
	switch {
	case code < 100 || code > 599:
		return "error", "连接失败"
	case code >= 200 && code < 300:
		return "ok", "HTTP 响应正常"
	case code >= 300 && code < 400:
		return "redirect", "重定向响应"
	case code == 401 || code == 403:
		return "blocked", fmt.Sprintf("访问受限 (%d)", code)
	case code == 429:
		return "rate_limited", "请求受限 (429)"
	case code >= 500:
		return "server_error", "服务端错误"
	default:
		return "http_error", "HTTP 异常响应"
	}
}
func validCountryCode(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if len(s) != 2 || s[0] < 'A' || s[0] > 'Z' || s[1] < 'A' || s[1] > 'Z' {
		return ""
	}
	return s
}

var resolverCountryNames = map[string]string{
	"china": "CN", "mainland china": "CN", "china mainland": "CN", "taiwan": "TW", "hong kong": "HK",
	"united states": "US", "united states of america": "US", "united kingdom": "GB", "japan": "JP", "singapore": "SG",
	"germany": "DE", "france": "FR", "canada": "CA", "australia": "AU", "netherlands": "NL", "south korea": "KR", "south africa": "ZA",
	"india": "IN", "indonesia": "ID", "malaysia": "MY", "thailand": "TH", "vietnam": "VN", "philippines": "PH",
	"brazil": "BR", "mexico": "MX", "italy": "IT", "spain": "ES", "switzerland": "CH", "sweden": "SE", "russia": "RU",
}

func proxyDisplay(raw string) string {
	clean := raw
	if !strings.Contains(clean, "://") {
		clean = "http://" + clean
	}
	u, err := url.Parse(clean)
	if err != nil || u.Hostname() == "" {
		return "地址已配置"
	}
	return u.Host
}
func parseDNS(raw, cc string) DNSLeakResult {
	r := DNSLeakResult{Status: "error", StatusText: "检测失败 / 结果未知", DNSIP: "未知", DNSGeo: "未知", Source: "edns.ip-api.com (HTTP)", Error: "未取得有效解析器响应"}
	var m struct {
		DNS struct {
			IP          string `json:"ip"`
			Geo         string `json:"geo"`
			CountryCode string `json:"countryCode"`
			Code        string `json:"country_code"`
			Country     string `json:"country"`
		} `json:"dns"`
	}
	if json.Unmarshal([]byte(raw), &m) != nil {
		return r
	}
	if validIP(m.DNS.IP) == "" {
		r.Status = "unknown"
		r.StatusText = "解析器结果未知"
		return r
	}
	r.DNSIP = validIP(m.DNS.IP)
	r.DNSGeo = m.DNS.Geo
	r.Error = ""
	r.Status = "observed"
	r.StatusText = "已观测解析器"
	resolverCC := validCountryCode(m.DNS.CountryCode)
	if resolverCC == "" {
		resolverCC = validCountryCode(m.DNS.Code)
	}
	if resolverCC == "" {
		geo := m.DNS.Country
		if geo == "" {
			geo = m.DNS.Geo
		}
		head := strings.TrimSpace(strings.SplitN(strings.SplitN(geo, ",", 2)[0], " - ", 2)[0])
		resolverCC = validCountryCode(head)
		if resolverCC == "" {
			resolverCC = resolverCountryNames[strings.ToLower(head)]
		}
	}
	if resolverCC != "" && validCountryCode(cc) != "" && resolverCC != validCountryCode(cc) {
		r.Status = "mismatch"
		r.StatusText = "解析器与出口地区不同（不等同泄露）"
	}
	return r
}
func parseRisk(ip string, verified bool, source, aRaw, bRaw string) ClaudeRiskData {
	r := ClaudeRiskData{IP: validIP(ip), Country: "未知", City: "未知", ASN: "未知", ISP: "未知", Timezone: "未知", IPType: "未知", TrustLevel: "未评级", TrustDesc: "未执行账号信誉检测；仅展示本次证据", RegionStatusText: "待官方核对", Signals: map[string]EvidenceSignal{}, ExitSource: source, ExitVerified: verified, ObservedAt: time.Now().UTC().Format(time.RFC3339)}
	for _, k := range []string{"vpn", "proxy", "tor", "crawler", "abuse", "hosting", "mobile"} {
		r.Signals[k] = EvidenceSignal{"unknown", "未取得有效情报"}
	}
	var a, b map[string]any
	_ = json.Unmarshal([]byte(aRaw), &a)
	_ = json.Unmarshal([]byte(bRaw), &b)
	aIP, _ := a["query"].(string)
	bIP, _ := b["ip"].(string)
	aOK := a["status"] == "success" && r.IP != "" && validIP(aIP) == r.IP
	bOK := b["success"] == true && r.IP != "" && validIP(bIP) == r.IP
	assign := func(dst *string, v any) {
		if s, ok := v.(string); ok && s != "" && (*dst == "" || *dst == "未知") {
			*dst = s
		}
	}
	merge := func(k string, v any, src string) {
		if flag, ok := v.(bool); ok {
			if r.Signals[k].Status == "detected" && !flag {
				return
			}
			status := "not_detected"
			if flag {
				status = "detected"
			}
			r.Signals[k] = EvidenceSignal{status, src}
		}
	}
	if aOK {
		assign(&r.Country, a["country"])
		assign(&r.CountryCode, a["countryCode"])
		assign(&r.City, a["city"])
		assign(&r.Region, a["regionName"])
		assign(&r.ISP, a["isp"])
		assign(&r.Org, a["org"])
		assign(&r.Timezone, a["timezone"])
		if as, ok := a["as"].(string); ok {
			if fields := strings.Fields(as); len(fields) > 0 {
				r.ASN = fields[0]
			}
		}
		for _, k := range []string{"proxy", "hosting", "mobile"} {
			merge(k, a[k], "ip-api.com (HTTP) / "+k)
		}
	}
	if bOK {
		assign(&r.Country, b["country"])
		assign(&r.CountryCode, b["country_code"])
		assign(&r.City, b["city"])
		assign(&r.Region, b["region"])
		if z, ok := b["timezone"].(map[string]any); ok {
			assign(&r.Timezone, z["id"])
		}
		if c, ok := b["connection"].(map[string]any); ok {
			assign(&r.ISP, c["isp"])
			assign(&r.Org, c["org"])
			if n, ok := c["asn"].(float64); ok && r.ASN == "未知" {
				r.ASN = fmt.Sprintf("AS%.0f", n)
			}
		}
		if sec, ok := b["security"].(map[string]any); ok {
			for k := range r.Signals {
				merge(k, sec[k], "ipwho.is security."+k)
			}
		}
	}
	markError := func(keys []string, source string) {
		for _, k := range keys {
			if r.Signals[k].Status == "unknown" {
				r.Signals[k] = EvidenceSignal{"error", source}
			}
		}
	}
	if !aOK {
		markError([]string{"proxy", "hosting", "mobile"}, "ip-api.com: 请求或响应无效")
	}
	if !bOK {
		markError([]string{"vpn", "proxy", "tor", "crawler", "hosting", "mobile"}, "ipwho.is: 请求或响应无效")
	}

	combined := strings.ToLower(r.ISP + " " + r.Org + " " + r.ASN)
	if r.Signals["hosting"].Status == "unknown" || r.Signals["hosting"].Status == "error" {
		for _, k := range hostingKeywords {
			if strings.Contains(combined, k) {
				r.Signals["hosting"] = EvidenceSignal{"detected", "ASN/ISP heuristic"}
				break
			}
		}
	}
	r.IsHosting = r.Signals["hosting"].Status == "detected"
	if r.IsHosting {
		r.IPType = "机房特征"
		r.IPTypeEn = "(Hosting)"
	} else if r.Signals["mobile"].Status == "detected" {
		r.IPType = "移动网络"
		r.IPTypeEn = "(Mobile)"
	}
	r.VPNDetected = r.Signals["vpn"].Status == "detected"
	r.ProxyDetected = r.Signals["proxy"].Status == "detected"
	r.TorDetected = r.Signals["tor"].Status == "detected"
	r.CrawlerDetected = r.Signals["crawler"].Status == "detected"
	r.AbuseDetected = r.Signals["abuse"].Status == "detected"
	r.CountryCode = strings.ToUpper(r.CountryCode)
	if len(r.CountryCode) != 2 || strings.IndexFunc(r.CountryCode, func(c rune) bool { return c < 'A' || c > 'Z' }) >= 0 {
		r.CountryCode = ""
	}
	r.Flag = countryCodeToFlag(r.CountryCode)
	r.Success = r.IP != ""
	r.IsIPv6 = strings.Contains(r.IP, ":")
	if !r.Success {
		r.IP = "获取失败"
		r.ExitVerified = false
	}
	return r
}
func validExternalURL(raw string) bool {
	u, e := url.Parse(raw)
	return e == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && !strings.ContainsAny(raw, "\r\n\x00")
}
func localOnly(host string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Host != host {
			http.Error(w, "Forbidden host", 403)
			return
		}
		origin := "http://" + host
		if o := r.Header.Get("Origin"); o != "" && o != origin {
			http.Error(w, "Forbidden origin", 403)
			return
		}
		if s := r.Header.Get("Sec-Fetch-Site"); s == "cross-site" || s == "same-site" {
			http.Error(w, "Forbidden site", 403)
			return
		}
		switch r.URL.Path {
		case "/api/open-url", "/api/quit", "/api/heartbeat":
			if r.Method != "POST" {
				http.Error(w, "POST required", 405)
				return
			}
			if r.Header.Get("Origin") == "" {
				ref, e := url.Parse(r.Referer())
				if e != nil || ref.Scheme+"://"+ref.Host != origin {
					http.Error(w, "Same origin required", 403)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}
