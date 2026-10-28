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

//go:embed Resources/* VERSION
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
	Source       string `json:"source"`
	ObservedAt   string `json:"observedAt"`
	IP           string `json:"ip"`
	CountryCode  string `json:"countryCode"`
	Flag         string `json:"flag"`
	LocationText string `json:"locationText"`
	IsIPv6       bool   `json:"isIPv6"`
	Success      bool   `json:"success"`
}

// Claude 核心风险与属性完整数据
type ClaudeRiskData struct {
	Signals          map[string]EvidenceSignal `json:"signals"`
	ExitSource       string                    `json:"exitSource"`
	ExitVerified     bool                      `json:"exitVerified"`
	ObservedAt       string                    `json:"observedAt"`
	IP               string                    `json:"ip"`
	IsIPv6           bool                      `json:"isIPv6"`
	Country          string                    `json:"country"`
	CountryCode      string                    `json:"countryCode"`
	Flag             string                    `json:"flag"`
	City             string                    `json:"city"`
	Region           string                    `json:"region"`
	ASN              string                    `json:"asn"`
	ISP              string                    `json:"isp"`
	Org              string                    `json:"org"`
	Timezone         string                    `json:"timezone"`
	IPType           string                    `json:"ipType"`
	IPTypeEn         string                    `json:"ipTypeEn"`
	IsHosting        bool                      `json:"isHosting"`
	TrustScore       int                       `json:"trustScore"`
	TrustLevel       string                    `json:"trustLevel"`
	TrustDesc        string                    `json:"trustDesc"`
	RegionSupported  bool                      `json:"regionSupported"`
	RegionStatusText string                    `json:"regionStatusText"`
	VPNDetected      bool                      `json:"vpnDetected"`
	ProxyDetected    bool                      `json:"proxyDetected"`
	TorDetected      bool                      `json:"torDetected"`
	CrawlerDetected  bool                      `json:"crawlerDetected"`
	AbuseDetected    bool                      `json:"abuseDetected"`
	Success          bool                      `json:"success"`
}

// 单个域名可用性测速结果
type EndpointPingResult struct {
	Status     string `json:"status"`
	Domain     string `json:"domain"`
	Reachable  bool   `json:"reachable"`
	LatencyMs  int    `json:"latencyMs"`
	StatusCode int    `json:"statusCode"`
	StatusText string `json:"statusText"`
}

// DNS 泄露检测结果
type DNSLeakResult struct {
	Status     string `json:"status"`
	Source     string `json:"source"`
	Error      string `json:"error"`
	Leaked     bool   `json:"leaked"`
	StatusText string `json:"statusText"`
	DNSIP      string `json:"dnsIP"`
	DNSGeo     string `json:"dnsGeo"`
}

// 客户端版本更新检查结果
type UpdateCheckResult struct {
	CurrentVersion string `json:"currentVersion"`
	LatestVersion  string `json:"latestVersion"`
	HasUpdate      bool   `json:"hasUpdate"`
	ReleaseURL     string `json:"releaseURL"`
	DownloadURL    string `json:"downloadURL"`
	ReleaseNotes   string `json:"releaseNotes"`
	ErrorMsg       string `json:"errorMsg"`
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
	if validCountryCode(upper) == "" {
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
					Summary:   fmt.Sprintf("系统代理 (%s)", proxyDisplay(httpURL)),
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
				Summary:   fmt.Sprintf("环境代理 (%s)", proxyDisplay(v)),
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
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return ""
	}
	return string(body)
}

// 1. 不使用显式代理的 IPv4 探测；系统 TUN 路由仍可能生效
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
		if json.Unmarshal([]byte(raw), &parsed) == nil && validIP(parsed.Data.IP) != "" {
			var parts []string
			for _, item := range parsed.Data.Location {
				if strings.TrimSpace(item) != "" {
					parts = append(parts, strings.TrimSpace(item))
				}
			}
			locText := "归属地未知"
			if len(parts) > 0 {
				locText = strings.Join(parts, " ")
			}
			return ExitIPCardData{
				IP:     parsed.Data.IP,
				Source: "https://myip.ipip.net/json", ObservedAt: time.Now().UTC().Format(time.RFC3339),
				CountryCode:  "",
				Flag:         countryCodeToFlag(""),
				LocationText: locText,
				IsIPv6:       strings.Contains(parsed.Data.IP, ":"),
				Success:      true,
			}
		}
	}

	// 渠道 2：4.ipw.cn 或 ip.3322.net
	source := "https://4.ipw.cn"
	fallbackIP := validIP(httpGetString(client, source))
	if fallbackIP == "" {
		source = "https://ip.3322.net"
		fallbackIP = validIP(httpGetString(client, source))
	}
	if validIP(fallbackIP) != "" {
		cc, summary := fetchBasicIPGeo(client, fallbackIP)
		if summary == "" {
			summary = "归属地未知"
		}
		return ExitIPCardData{
			IP:     fallbackIP,
			Source: source, ObservedAt: time.Now().UTC().Format(time.RFC3339),
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

	source := "https://1.1.1.1/cdn-cgi/trace"
	traceRaw := httpGetString(client, source)
	if !strings.Contains(traceRaw, "ip=") {
		source = "https://www.cloudflare.com/cdn-cgi/trace"
		traceRaw = httpGetString(client, source)
	}

	ip := ""
	loc := ""
	for _, line := range strings.Split(traceRaw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ip=") {
			ip = validIP(strings.TrimPrefix(line, "ip="))
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
			IP:     ip,
			Source: source, ObservedAt: time.Now().UTC().Format(time.RFC3339),
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
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	ip := ""
	source := "claude.ai/cdn-cgi/trace"
	verified := false
	for _, line := range strings.Split(httpGetString(client, "https://claude.ai/cdn-cgi/trace"), "\n") {
		if strings.HasPrefix(line, "ip=") {
			ip = validIP(strings.TrimPrefix(line, "ip="))
			verified = ip != ""
			break
		}
	}
	if ip == "" {
		ip = validIP(httpGetString(client, "https://api64.ipify.org"))
		source = "api64.ipify.org (generic fallback)"
	}
	if ip == "" {
		raw := httpGetString(client, "https://ipwho.is/")
		var m map[string]any
		_ = json.Unmarshal([]byte(raw), &m)
		if m["success"] == true {
			if candidate, ok := m["ip"].(string); ok {
				ip = validIP(candidate)
				source = "https://ipwho.is/ (generic fallback)"
			}
		}
	}
	if ip == "" {
		return parseRisk("", false, "", "", "")
	}
	a := httpGetString(client, "http://ip-api.com/json/"+ip+"?fields=status,query,country,countryCode,regionName,city,as,isp,org,timezone,hosting,proxy,mobile")
	b := httpGetString(client, "https://ipwho.is/"+ip)
	return parseRisk(ip, verified, source, a, b)
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
				status, statusText := classifyHTTP(resp.StatusCode)
				results[idx] = EndpointPingResult{
					Domain:     domain,
					Reachable:  true,
					LatencyMs:  ms,
					StatusCode: resp.StatusCode,
					StatusText: statusText,
					Status:     status,
				}
			} else {
				results[idx] = EndpointPingResult{
					Domain:     domain,
					Reachable:  false,
					LatencyMs:  0,
					StatusCode: 0,
					StatusText: "连接失败",
					Status:     "error",
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
	raw := httpGetString(client, fmt.Sprintf("http://%s.edns.ip-api.com/json", hex.EncodeToString(b)))
	return parseDNS(raw, claudeCountryCode)
}

func fetchBasicIPGeo(client *http.Client, ip string) (string, string) {
	raw := httpGetString(client, "https://ipwho.is/"+ip)
	var m map[string]any
	_ = json.Unmarshal([]byte(raw), &m)
	subject, _ := m["ip"].(string)
	if m["success"] != true || validIP(subject) != validIP(ip) {
		return "", ""
	}
	cc, _ := m["country_code"].(string)
	parts := []string{}
	for _, key := range []string{"country", "region", "city"} {
		if s, ok := m[key].(string); ok && s != "" {
			parts = append(parts, s)
		}
	}
	if conn, ok := m["connection"].(map[string]any); ok {
		if s, ok := conn["isp"].(string); ok && s != "" {
			parts = append(parts, s)
		}
	}
	return cc, strings.Join(parts, " ")
}

// 6. 检查 GitHub Release 最新版本
func checkAppUpdate(currentVersion, proxyMode, customProxy string) UpdateCheckResult {
	client := buildHTTPClient(proxyMode, customProxy, 6*time.Second, false)
	apiURL := "https://api.github.com/repos/245678000000/claude-ip-checker/releases/latest"
	raw := httpGetString(client, apiURL)
	if !strings.Contains(raw, "tag_name") {
		directClient := buildHTTPClient("direct", "", 5*time.Second, false)
		raw = httpGetString(directClient, apiURL)
	}

	var parsed struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
		Body    string `json:"body"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}

	if raw == "" || json.Unmarshal([]byte(raw), &parsed) != nil || parsed.TagName == "" {
		return UpdateCheckResult{
			CurrentVersion: currentVersion,
			LatestVersion:  currentVersion,
			HasUpdate:      false,
			ReleaseURL:     "https://github.com/245678000000/claude-ip-checker/releases",
			ErrorMsg:       "无法连接 GitHub 检查更新，请检查网络或代理设置",
		}
	}

	cleanCur := strings.TrimLeft(strings.TrimSpace(currentVersion), "vV")
	cleanLatest := strings.TrimLeft(strings.TrimSpace(parsed.TagName), "vV")
	hasUpdate := compareSemver(cleanLatest, cleanCur)

	dlURL := parsed.HTMLURL
	for _, a := range parsed.Assets {
		lower := strings.ToLower(a.Name)
		if strings.Contains(lower, "windows") && strings.HasSuffix(lower, ".exe") {
			dlURL = a.BrowserDownloadURL
			break
		}
	}

	return UpdateCheckResult{
		CurrentVersion: "v" + cleanCur,
		LatestVersion:  "v" + cleanLatest,
		HasUpdate:      hasUpdate,
		ReleaseURL:     parsed.HTMLURL,
		DownloadURL:    dlURL,
		ReleaseNotes:   parsed.Body,
	}
}

func compareSemver(v1, v2 string) bool {
	p1 := strings.Split(v1, ".")
	p2 := strings.Split(v2, ".")
	maxLen := len(p1)
	if len(p2) > maxLen {
		maxLen = len(p2)
	}
	for i := 0; i < maxLen; i++ {
		var n1, n2 int
		if i < len(p1) {
			_, _ = fmt.Sscanf(p1[i], "%d", &n1)
		}
		if i < len(p2) {
			_, _ = fmt.Sscanf(p2[i], "%d", &n2)
		}
		if n1 != n2 {
			return n1 > n2
		}
	}
	return false
}

func openExternalBrowser(targetURL string) {
	if !validExternalURL(targetURL) {
		return
	}
	if runtime.GOOS == "windows" {
		cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", targetURL)
		prepareBackgroundCmd(cmd)
		_ = cmd.Start()
	} else {
		_ = exec.Command("open", targetURL).Start()
	}
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
		path := r.URL.Path
		if path == "/" {
			path = "/index.html"
		}
		mime := map[string]string{"/index.html": "text/html; charset=utf-8", "/app.js": "text/javascript; charset=utf-8", "/diagnostics.js": "text/javascript; charset=utf-8"}
		kind, ok := mime[path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		data, err := embeddedFiles.ReadFile("Resources" + path)
		if err != nil {
			http.Error(w, "Missing resource", 500)
			return
		}
		w.Header().Set("Content-Type", kind)
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

	mux.HandleFunc("/api/check-update", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		curVer := q.Get("currentVersion")
		if curVer == "" {
			curVer = appVersion()
		}
		writeJSON(w, checkAppUpdate(curVer, q.Get("proxyMode"), q.Get("customProxy")))
	})

	mux.HandleFunc("/api/open-url", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		if !validExternalURL(target) {
			http.Error(w, "HTTPS URL required", 400)
			return
		}
		openExternalBrowser(target)
		w.WriteHeader(http.StatusNoContent)
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

	_ = http.Serve(listener, localOnly(listener.Addr().String(), mux))
}

func appVersion() string {
	b, e := embeddedFiles.ReadFile("VERSION")
	if e != nil {
		return "1.1.1"
	}
	return strings.TrimSpace(string(b))
}
