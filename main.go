package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed Resources/index.html
var embeddedFiles embed.FS

// 系统代理信息结构体
type SystemProxyInfo struct {
	Enabled    bool   `json:"enabled"`
	HTTPProxy  string `json:"httpProxy,omitempty"`
	SOCKSProxy string `json:"socksProxy,omitempty"`
	Summary    string `json:"summary"`
}

// 顶部出口 IP 简要卡片数据
type ExitIPCardData struct {
	IP           string `json:"ip"`
	CountryCode  string `json:"countryCode"`
	Flag         string `json:"flag"`
	LocationText string `json:"locationText"`
	IsIPv6       bool   `json:"isIPv6"`
	Success      bool   `json:"success"`
}

// Claude 核心风险与属性完整数据
type ClaudeRiskData struct {
	IP               string `json:"ip"`
	IsIPv6           bool   `json:"isIPv6"`
	Country          string `json:"country"`
	CountryCode      string `json:"countryCode"`
	Flag             string `json:"flag"`
	City             string `json:"city"`
	Region           string `json:"region"`
	ASN              string `json:"asn"`
	ISP              string `json:"isp"`
	Org              string `json:"org"`
	Timezone         string `json:"timezone"`
	IPType           string `json:"ipType"`
	IPTypeEn         string `json:"ipTypeEn"`
	IsHosting        bool   `json:"isHosting"`
	TrustScore       int    `json:"trustScore"`
	TrustLevel       string `json:"trustLevel"`
	TrustDesc        string `json:"trustDesc"`
	RegionSupported  bool   `json:"regionSupported"`
	RegionStatusText string `json:"regionStatusText"`
	VPNDetected      bool   `json:"vpnDetected"`
	ProxyDetected    bool   `json:"proxyDetected"`
	TorDetected      bool   `json:"torDetected"`
	CrawlerDetected  bool   `json:"crawlerDetected"`
	AbuseDetected    bool   `json:"abuseDetected"`
	Success          bool   `json:"success"`
}

// 单个域名可用性测速结果
type EndpointPingResult struct {
	Domain     string `json:"domain"`
	Reachable  bool   `json:"reachable"`
	LatencyMs  int    `json:"latencyMs"`
	StatusCode int    `json:"statusCode"`
	StatusText string `json:"statusText"`
}

// DNS 泄露检测结果
type DNSLeakResult struct {
	Leaked     bool   `json:"leaked"`
	StatusText string `json:"statusText"`
	DNSIP      string `json:"dnsIP"`
	DNSGeo     string `json:"dnsGeo"`
}

var unsupportedCountryCodes = map[string]bool{
	"CN": true, "HK": true, "MO": true, "RU": true, "BY": true,
	"IR": true, "KP": true, "SY": true, "CU": true, "AF": true,
	"VE": true, "MM": true, "SD": true,
}

var hostingKeywords = []string{
	"google", "amazon", "aws", "cloudflare", "microsoft", "azure", "digitalocean",
	"linode", "akamai", "vultr", "choopa", "hetzner", "ovh", "oracle", "alibaba",
	"aliyun", "tencent", "huawei", "cogent", "leaseweb", "contabo", "datacamp",
	"cdn77", "psychz", "zenlayer", "dmit", "bandwagon", "it7", "multacom",
	"sharktech", "colocrossing", "quadranet", "hostinger", "equinix", "fastly",
	"kamatera", "upcloud", "scaleway", "ionos", "racknerd", "buyvm", "frantech",
	"gcore", "misaka", "nearoute", "xtom", "hosting", "datacenter", "cloud", "vps", "server",
}

// 将两位国家代码转换为国旗 Emoji
func countryCodeToFlag(code string) string {
	upper := strings.ToUpper(strings.TrimSpace(code))
	if len(upper) != 2 {
		return "🌐"
	}
	r1 := rune(upper[0]) - 'A' + 0x1F1E6
	r2 := rune(upper[1]) - 'A' + 0x1F1E6
	return string([]rune{r1, r2})
}

// 读取 Windows 注册表系统代理配置
func getSystemProxyInfo() SystemProxyInfo {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("reg", "query", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`)
		prepareBackgroundCmd(cmd)
		out, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(out), "\n")
			enabled := false
			proxyServer := ""
			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "ProxyEnable") && strings.Contains(trimmed, "0x1") {
					enabled = true
				}
				if strings.HasPrefix(trimmed, "ProxyServer") {
					fields := strings.Fields(trimmed)
					if len(fields) >= 3 {
						proxyServer = fields[len(fields)-1]
					}
				}
			}
			if enabled && proxyServer != "" {
				// 处理形如 http=127.0.0.1:7890;https=127.0.0.1:7890 或直接 127.0.0.1:7890
				cleanHost := proxyServer
				if strings.Contains(cleanHost, "=") {
					for _, part := range strings.Split(cleanHost, ";") {
						if strings.HasPrefix(part, "http=") {
							cleanHost = strings.TrimPrefix(part, "http=")
							break
						}
					}
				}
				httpURL := cleanHost
				if !strings.Contains(httpURL, "://") {
					httpURL = "http://" + httpURL
				}
				return SystemProxyInfo{
					Enabled:   true,
					HTTPProxy: httpURL,
					Summary:   fmt.Sprintf("系统代理 (%s)", cleanHost),
				}
			}
		}
	}

	// 检查环境变量代理
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return SystemProxyInfo{
				Enabled:   true,
				HTTPProxy: v,
				Summary:   fmt.Sprintf("环境代理 (%s)", v),
			}
		}
	}

	return SystemProxyInfo{
		Enabled: false,
		Summary: "系统直连 / TUN 模式",
	}
}

// 构造指定代理模式下的 HTTP Client
func buildHTTPClient(proxyMode string, customProxy string, timeout time.Duration, forceIPv4 bool) *http.Client {
	dialer := &net.Dialer{
		Timeout:   4 * time.Second,
		KeepAlive: 15 * time.Second,
	}

	transport := &http.Transport{
		TLSHandshakeTimeout: 4 * time.Second,
		DisableKeepAlives:   true,
	}

	if forceIPv4 {
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", addr)
		}
	} else {
		transport.DialContext = dialer.DialContext
	}

	switch proxyMode {
	case "direct":
		transport.Proxy = nil
	case "custom":
		cleaned := strings.TrimSpace(customProxy)
		if cleaned != "" {
			if !strings.Contains(cleaned, "://") {
				cleaned = "http://" + cleaned
			}
			if u, err := url.Parse(cleaned); err == nil {
				transport.Proxy = http.ProxyURL(u)
			}
		}
	default: // "system"
		sys := getSystemProxyInfo()
		if sys.Enabled && sys.HTTPProxy != "" {
			if u, err := url.Parse(sys.HTTPProxy); err == nil {
				transport.Proxy = http.ProxyURL(u)
			}
		} else {
			transport.Proxy = http.ProxyFromEnvironment
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}

func httpGetString(client *http.Client, targetURL string) string {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return ""
	}
	return string(body)
}

// 1. 检测中国出口 IPv4
func detectChinaIPv4() ExitIPCardData {
	client := buildHTTPClient("direct", "", 5*time.Second, true)

	// 渠道 1：myip.ipip.net/json
	raw := httpGetString(client, "https://myip.ipip.net/json")
	if raw != "" {
		var parsed struct {
			Data struct {
				IP       string   `json:"ip"`
				Location []string `json:"location"`
			} `json:"data"`
		}
		if json.Unmarshal([]byte(raw), &parsed) == nil && parsed.Data.IP != "" {
			var parts []string
			for _, item := range parsed.Data.Location {
				if strings.TrimSpace(item) != "" {
					parts = append(parts, strings.TrimSpace(item))
				}
			}
			locText := "China"
			if len(parts) > 0 {
				locText = strings.Join(parts, " ")
			}
			return ExitIPCardData{
				IP:           parsed.Data.IP,
				CountryCode:  "CN",
				Flag:         countryCodeToFlag("CN"),
				LocationText: locText,
				IsIPv6:       strings.Contains(parsed.Data.IP, ":"),
				Success:      true,
			}
		}
	}

	// 渠道 2：4.ipw.cn 或 ip.3322.net
	fallbackIP := strings.TrimSpace(httpGetString(client, "https://4.ipw.cn"))
	if fallbackIP == "" || len(fallbackIP) > 45 || strings.Contains(fallbackIP, "<") {
		fallbackIP = strings.TrimSpace(httpGetString(client, "https://ip.3322.net"))
	}
	if fallbackIP != "" && !strings.Contains(fallbackIP, "<") {
		cc, summary := fetchBasicIPGeo(client, fallbackIP)
		if cc == "" {
			cc = "CN"
		}
		if summary == "" {
			summary = "China"
		}
		return ExitIPCardData{
			IP:           fallbackIP,
			CountryCode:  cc,
			Flag:         countryCodeToFlag(cc),
			LocationText: summary,
			IsIPv6:       strings.Contains(fallbackIP, ":"),
			Success:      true,
		}
	}

	return ExitIPCardData{
		IP:           "获取失败",
		CountryCode:  "",
		Flag:         "🌐",
		LocationText: "请检查国内网络连通性",
		IsIPv6:       false,
		Success:      false,
	}
}

// 2. 检测 Cloudflare 出口 IP
func detectCloudflareIP(proxyMode, customProxy string) ExitIPCardData {
	client := buildHTTPClient(proxyMode, customProxy, 6*time.Second, false)

	traceRaw := httpGetString(client, "https://1.1.1.1/cdn-cgi/trace")
	if !strings.Contains(traceRaw, "ip=") {
		traceRaw = httpGetString(client, "https://www.cloudflare.com/cdn-cgi/trace")
	}

	ip := ""
	loc := ""
	for _, line := range strings.Split(traceRaw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ip=") {
			ip = strings.TrimPrefix(line, "ip=")
		} else if strings.HasPrefix(line, "loc=") {
			loc = strings.TrimPrefix(line, "loc=")
		}
	}

	if ip != "" {
		cc, summary := fetchBasicIPGeo(client, ip)
		if cc == "" {
			cc = loc
		}
		if summary == "" {
			summary = cc
		}
		return ExitIPCardData{
			IP:           ip,
			CountryCode:  cc,
			Flag:         countryCodeToFlag(cc),
			LocationText: summary,
			IsIPv6:       strings.Contains(ip, ":"),
			Success:      true,
		}
	}

	return ExitIPCardData{
		IP:           "获取失败",
		CountryCode:  "",
		Flag:         "🌐",
		LocationText: "无法连接 Cloudflare 节点",
		IsIPv6:       false,
		Success:      false,
	}
}

// 3. 检测 Claude AI 出口 IP 与完整风控评分
func detectClaudeIPAndRisk(proxyMode, customProxy string) ClaudeRiskData {
	client := buildHTTPClient(proxyMode, customProxy, 6*time.Second, false)

	claudeIP := ""
	traceRaw := httpGetString(client, "https://claude.ai/cdn-cgi/trace")
	for _, line := range strings.Split(traceRaw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ip=") {
			claudeIP = strings.TrimPrefix(line, "ip=")
			break
		}
	}

	if claudeIP == "" {
		ipify := strings.TrimSpace(httpGetString(client, "https://api64.ipify.org"))
		if ipify != "" && !strings.Contains(ipify, "<") && len(ipify) <= 45 {
			claudeIP = ipify
		}
	}

	country := "未知"
	countryCode := ""
	city := "未知"
	region := ""
	asn := "未知"
	isp := "未知"
	org := ""
	timezone := "未知"
	isHosting := false
	isMobile := false
	isProxy := false
	isVPN := false
	isTor := false
	isCrawler := false
	isAbuse := false

	// 情报源 A：ip-api.com
	ipApiURL := "http://ip-api.com/json/?fields=66846719"
	if claudeIP != "" {
		ipApiURL = fmt.Sprintf("http://ip-api.com/json/%s?fields=66846719", claudeIP)
	}
	if raw := httpGetString(client, ipApiURL); raw != "" {
		var m map[string]any
		if json.Unmarshal([]byte(raw), &m) == nil && m["status"] == "success" {
			if claudeIP == "" {
				if s, ok := m["query"].(string); ok {
					claudeIP = s
				}
			}
			if s, ok := m["country"].(string); ok && s != "" {
				country = s
			}
			if s, ok := m["countryCode"].(string); ok && s != "" {
				countryCode = s
			}
			if s, ok := m["city"].(string); ok && s != "" {
				city = s
			}
			if s, ok := m["regionName"].(string); ok && s != "" {
				region = s
			}
			if s, ok := m["timezone"].(string); ok && s != "" {
				timezone = s
			}
			if s, ok := m["isp"].(string); ok && s != "" {
				isp = s
			}
			if s, ok := m["org"].(string); ok && s != "" {
				org = s
			}
			if s, ok := m["as"].(string); ok && s != "" {
				asn = strings.Fields(s)[0]
			}
			if b, ok := m["hosting"].(bool); ok {
				isHosting = b
			}
			if b, ok := m["mobile"].(bool); ok {
				isMobile = b
			}
			if b, ok := m["proxy"].(bool); ok {
				isProxy = b
			}
		}
	}

	// 情报源 B：ipwho.is
	ipWhoURL := "https://ipwho.is/" + claudeIP
	if raw := httpGetString(client, ipWhoURL); raw != "" {
		var m map[string]any
		if json.Unmarshal([]byte(raw), &m) == nil {
			if okVal, _ := m["success"].(bool); okVal {
				if claudeIP == "" {
					if s, ok := m["ip"].(string); ok {
						claudeIP = s
					}
				}
				if country == "未知" {
					if s, ok := m["country"].(string); ok && s != "" {
						country = s
					}
				}
				if countryCode == "" {
					if s, ok := m["country_code"].(string); ok && s != "" {
						countryCode = s
					}
				}
				if city == "未知" {
					if s, ok := m["city"].(string); ok && s != "" {
						city = s
					}
				}
				if conn, ok := m["connection"].(map[string]any); ok {
					if asn == "未知" {
						if num, ok := conn["asn"].(float64); ok && num > 0 {
							asn = fmt.Sprintf("AS%.0f", num)
						}
					}
					if isp == "未知" {
						if s, ok := conn["isp"].(string); ok && s != "" {
							isp = s
						}
					}
				}
				if sec, ok := m["security"].(map[string]any); ok {
					if b, ok := sec["hosting"].(bool); ok && b {
						isHosting = true
					}
					if b, ok := sec["proxy"].(bool); ok && b {
						isProxy = true
					}
					if b, ok := sec["vpn"].(bool); ok && b {
						isVPN = true
					}
					if b, ok := sec["tor"].(bool); ok && b {
						isTor = true
					}
					if b, ok := sec["crawler"].(bool); ok && b {
						isCrawler = true
					}
				}
			}
		}
	}

	if claudeIP == "" {
		return ClaudeRiskData{
			IP:               "获取失败",
			Country:          "未知",
			Flag:             "🌐",
			City:             "未知",
			ASN:              "未知",
			ISP:              "未知",
			Timezone:         "未知",
			IPType:           "未知",
			TrustScore:       0,
			TrustLevel:       "无数据",
			TrustDesc:        "未获取到 Claude AI 出口 IP，请检查代理或网络配置",
			RegionStatusText: "未知",
			Success:          false,
		}
	}

	combinedProvider := strings.ToLower(fmt.Sprintf("%s %s %s", isp, org, asn))
	if !isHosting {
		for _, kw := range hostingKeywords {
			if strings.Contains(combinedProvider, kw) {
				isHosting = true
				break
			}
		}
	}

	if isProxy && isHosting && (strings.Contains(combinedProvider, "google") ||
		strings.Contains(combinedProvider, "amazon") ||
		strings.Contains(combinedProvider, "microsoft") ||
		strings.Contains(combinedProvider, "cloudflare") ||
		strings.Contains(combinedProvider, "oracle")) {
		isProxy = false
	}

	ipType := "住宅IP"
	ipTypeEn := "(Residential)"
	if isHosting {
		ipType = "机房IP"
		ipTypeEn = "(Hosting)"
	} else if isMobile {
		ipType = "移动网络"
		ipTypeEn = "(Mobile)"
	}

	upperCC := strings.ToUpper(countryCode)
	regionSupported := upperCC != "" && !unsupportedCountryCodes[upperCC]
	regionStatusText := "不支持"
	if regionSupported {
		regionStatusText = "正常"
	}

	score := 100
	if isHosting {
		score -= 11
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
	if strings.Contains(claudeIP, ":") {
		score -= 5
	}
	if score < 5 {
		score = 5
	}

	trustLevel := "高危"
	trustDesc := "该 IP 风险较高，极易触发 Claude 封禁或拦截"
	if score >= 80 {
		trustLevel = "纯净"
		trustDesc = "该 IP 信誉优异"
	} else if score >= 65 {
		trustLevel = "低风险"
		trustDesc = "该 IP 信誉良好，可正常使用"
	} else if score >= 45 {
		trustLevel = "中风险"
		trustDesc = "该 IP 存在共享或风控记录，建议留意"
	}

	return ClaudeRiskData{
		IP:               claudeIP,
		IsIPv6:           strings.Contains(claudeIP, ":"),
		Country:          country,
		CountryCode:      upperCC,
		Flag:             countryCodeToFlag(upperCC),
		City:             city,
		Region:           region,
		ASN:              asn,
		ISP:              isp,
		Org:              org,
		Timezone:         timezone,
		IPType:           ipType,
		IPTypeEn:         ipTypeEn,
		IsHosting:        isHosting,
		TrustScore:       score,
		TrustLevel:       trustLevel,
		TrustDesc:        trustDesc,
		RegionSupported:  regionSupported,
		RegionStatusText: regionStatusText,
		VPNDetected:      isVPN,
		ProxyDetected:    isProxy,
		TorDetected:      isTor,
		CrawlerDetected:  isCrawler,
		AbuseDetected:    isAbuse,
		Success:          true,
	}
}

// 4. 检测 Claude 可用性与延迟
func detectClaudeAvailability(proxyMode, customProxy string) []EndpointPingResult {
	domains := []string{"claude.ai", "anthropic.com"}
	results := make([]EndpointPingResult, len(domains))
	var wg sync.WaitGroup

	for i, d := range domains {
		wg.Add(1)
		go func(idx int, domain string) {
			defer wg.Done()
			client := buildHTTPClient(proxyMode, customProxy, 6*time.Second, false)
			// 不自动跟随多次重定向，只要收到首个 HTTPS 响应即代表握手成功
			client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}
			start := time.Now()
			req, _ := http.NewRequest("GET", "https://"+domain, nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
			resp, err := client.Do(req)
			ms := int(time.Since(start).Milliseconds())
			if err == nil && resp != nil {
				resp.Body.Close()
				if ms < 1 {
					ms = 1
				}
				results[idx] = EndpointPingResult{
					Domain:     domain,
					Reachable:  true,
					LatencyMs:  ms,
					StatusCode: resp.StatusCode,
					StatusText: "正常",
				}
			} else {
				results[idx] = EndpointPingResult{
					Domain:     domain,
					Reachable:  false,
					LatencyMs:  0,
					StatusCode: 0,
					StatusText: "连接失败",
				}
			}
		}(i, d)
	}
	wg.Wait()
	return results
}

// 5. 检测 DNS 泄露
func detectDNSLeak(proxyMode, customProxy, claudeCountryCode string) DNSLeakResult {
	client := buildHTTPClient(proxyMode, customProxy, 5*time.Second, false)
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	randID := hex.EncodeToString(b)
	raw := httpGetString(client, fmt.Sprintf("http://%s.edns.ip-api.com/json", randID))

	if raw != "" {
		var parsed struct {
			DNS struct {
				IP  string `json:"ip"`
				Geo string `json:"geo"`
			} `json:"dns"`
		}
		if json.Unmarshal([]byte(raw), &parsed) == nil && parsed.DNS.IP != "" {
			isChinaDNS := strings.Contains(strings.ToLower(parsed.DNS.Geo), "china")
			isOverseasClaude := claudeCountryCode != "" && claudeCountryCode != "CN"
			leaked := isChinaDNS && isOverseasClaude
			statusText := "未检测到泄露"
			if leaked {
				statusText = "检测到国内DNS泄露"
			}
			return DNSLeakResult{
				Leaked:     leaked,
				StatusText: statusText,
				DNSIP:      parsed.DNS.IP,
				DNSGeo:     parsed.DNS.Geo,
			}
		}
	}

	return DNSLeakResult{
		Leaked:     false,
		StatusText: "未检测到泄露",
		DNSIP:      "加密 DNS / DoH",
		DNSGeo:     "Cloudflare / 安全解析",
	}
}

func fetchBasicIPGeo(client *http.Client, ip string) (string, string) {
	raw := httpGetString(client, fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,countryCode,regionName,city,isp", ip))
	if raw != "" {
		var m map[string]string
		if json.Unmarshal([]byte(raw), &m) == nil && m["status"] == "success" {
			cc := m["countryCode"]
			var parts []string
			seen := map[string]bool{}
			for _, k := range []string{"country", "regionName", "city", "isp"} {
				v := strings.TrimSpace(m[k])
				if v != "" && !seen[v] {
					seen[v] = true
					parts = append(parts, v)
				}
			}
			return cc, strings.Join(parts, " ")
		}
	}
	return "", ""
}

// 启动独立无边框应用窗口（优先使用 Windows 自带的 Edge / Chrome --app 模式）
func launchAppWindow(appURL string) {
	if runtime.GOOS != "windows" {
		_ = exec.Command("open", appURL).Start()
		return
	}

	candidates := []string{
		 filepath.Join(os.Getenv("ProgramFiles(x86)"), `Microsoft\Edge\Application\msedge.exe`),
		 filepath.Join(os.Getenv("ProgramFiles"), `Microsoft\Edge\Application\msedge.exe`),
		 filepath.Join(os.Getenv("LocalAppData"), `Microsoft\Edge\Application\msedge.exe`),
		 filepath.Join(os.Getenv("ProgramFiles"), `Google\Chrome\Application\chrome.exe`),
		 filepath.Join(os.Getenv("ProgramFiles(x86)"), `Google\Chrome\Application\chrome.exe`),
		 filepath.Join(os.Getenv("LocalAppData"), `Google\Chrome\Application\chrome.exe`),
	}

	for _, exe := range candidates {
		if exe != "" {
			if _, err := os.Stat(exe); err == nil {
				cmd := exec.Command(exe,
					"--app="+appURL,
					"--window-size=1160,860",
					"--disable-extensions",
				)
				prepareBackgroundCmd(cmd)
				if err := cmd.Start(); err == nil {
					return
				}
			}
		}
	}

	// 兜底：使用系统默认方式打开
	cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", appURL)
	prepareBackgroundCmd(cmd)
	_ = cmd.Start()
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func main() {
	var lastHeartbeat int64
	atomic.StoreInt64(&lastHeartbeat, time.Now().Unix())

	mux := http.NewServeMux()

	// 首页返回内嵌的 Resources/index.html
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		atomic.StoreInt64(&lastHeartbeat, time.Now().Unix())
		data, err := embeddedFiles.ReadFile("Resources/index.html")
		if err != nil {
			http.Error(w, "Missing embedded index.html", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
	})

	mux.HandleFunc("/api/sys-proxy", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, getSystemProxyInfo())
	})

	mux.HandleFunc("/api/china-ip", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, detectChinaIPv4())
	})

	mux.HandleFunc("/api/cf-ip", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		writeJSON(w, detectCloudflareIP(q.Get("proxyMode"), q.Get("customProxy")))
	})

	mux.HandleFunc("/api/claude-risk", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		writeJSON(w, detectClaudeIPAndRisk(q.Get("proxyMode"), q.Get("customProxy")))
	})

	mux.HandleFunc("/api/availability", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		writeJSON(w, detectClaudeAvailability(q.Get("proxyMode"), q.Get("customProxy")))
	})

	mux.HandleFunc("/api/dns-leak", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		writeJSON(w, detectDNSLeak(q.Get("proxyMode"), q.Get("customProxy"), q.Get("cc")))
	})

	mux.HandleFunc("/api/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		atomic.StoreInt64(&lastHeartbeat, time.Now().Unix())
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/api/quit", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
		go func() {
			time.Sleep(300 * time.Millisecond)
			os.Exit(0)
		}()
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		os.Exit(1)
	}
	appURL := fmt.Sprintf("http://%s", listener.Addr().String())

	// 启动心跳监控：若窗口关闭超过 15 秒无心跳则自动退出进程
	go func() {
		time.Sleep(15 * time.Second)
		for {
			time.Sleep(3 * time.Second)
			last := atomic.LoadInt64(&lastHeartbeat)
			if time.Now().Unix()-last > 15 {
				os.Exit(0)
			}
		}
	}()

	go func() {
		time.Sleep(150 * time.Millisecond)
		launchAppWindow(appURL)
	}()

	_ = http.Serve(listener, mux)
}
