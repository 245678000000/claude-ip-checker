package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDNSFailuresAreNotSuccess(t *testing.T) {
	for _, raw := range []string{"", `{}`, `{"dns":{"ip":"invalid","geo":"China"}}`} {
		d := parseDNS(raw, "US")
		if (d.Status != "error" && d.Status != "unknown") || d.DNSIP != "未知" || d.Leaked {
			t.Fatalf("invalid evidence: %+v", d)
		}
	}
}
func TestHTTPStatuses(t *testing.T) {
	for code, want := range map[int]string{0: "error", 200: "ok", 302: "redirect", 403: "blocked", 429: "rate_limited", 500: "server_error"} {
		got, _ := classifyHTTP(code)
		if got != want {
			t.Fatalf("%d: %s", code, got)
		}
	}
}
func TestMissingSecurityAndCloudProxy(t *testing.T) {
	r := parseRisk("8.8.8.8", true, "fixture", `{"status":"success","query":"8.8.8.8","isp":"Google LLC","proxy":true,"hosting":true}`, `{"success":true,"ip":"8.8.8.8"}`)
	if r.Signals["proxy"].Status != "detected" || r.Signals["vpn"].Status != "unknown" || r.Signals["abuse"].Status != "unknown" {
		t.Fatalf("%+v", r.Signals)
	}
}
func TestNegativeAndInvalidEvidence(t *testing.T) {
	r := parseRisk("8.8.8.8", false, "fallback", `{"status":"success","query":"8.8.8.8","proxy":false}`, `{"success":true,"ip":"8.8.8.8","security":{"vpn":false,"tor":true}}`)
	if r.Signals["vpn"].Status != "not_detected" || r.Signals["abuse"].Status != "unknown" || r.ExitVerified {
		t.Fatalf("%+v", r)
	}
	if parseRisk("bad", false, "", `{}`, `{}`).Success {
		t.Fatal("invalid IP")
	}
}
func TestHTTPSOnly(t *testing.T) {
	for _, u := range []string{"file:///tmp/x", "javascript:alert(1)", "http://example.com", "https://user:pw@example.com"} {
		if validExternalURL(u) {
			t.Fatal(u)
		}
	}
	if !validExternalURL("https://example.com/path") {
		t.Fatal("https")
	}
}
func TestLocalOriginGuard(t *testing.T) {
	h := localOnly("127.0.0.1:1234", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	for _, tc := range []struct {
		host, origin, method, path string
		want                       int
	}{{"127.0.0.1:1234", "", "GET", "/", 204}, {"evil.test:1234", "", "GET", "/", 403}, {"127.0.0.1:1234", "https://evil.test", "POST", "/api/quit", 403}, {"127.0.0.1:1234", "", "GET", "/api/quit", 405}, {"127.0.0.1:1234", "http://127.0.0.1:1234", "POST", "/api/quit", 204}} {
		r := httptest.NewRequest(tc.method, "http://"+tc.host+tc.path, strings.NewReader(""))
		r.Header.Set("Origin", tc.origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("%+v got %d", tc, w.Code)
		}
	}
}

func TestDNSCountryEvidence(t *testing.T) {
	for _, tc := range []struct{ raw, cc, want string }{
		{`{"dns":{"ip":"8.8.8.8","geo":"United States - Dallas"}}`, "US", "observed"},
		{`{"dns":{"ip":"8.8.8.8","geo":"Japan - Tokyo"}}`, "US", "mismatch"},
		{`{"dns":{"ip":"8.8.8.8","countryCode":"DE"}}`, "JP", "mismatch"},
		{`{"dns":{"ip":"8.8.8.8","geo":"unknown"}}`, "US", "observed"},
	} {
		if r := parseDNS(tc.raw, tc.cc); r.Status != tc.want || r.Leaked {
			t.Fatalf("%+v: %+v", tc, r)
		}
	}
}
func TestHTTP401Text(t *testing.T) {
	_, text := classifyHTTP(401)
	if strings.Contains(text, "403") {
		t.Fatal(text)
	}
}
func TestProxySummaryHidesCredentials(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://alice:secret@proxy.example:7890")
	if r := getSystemProxyInfo(); strings.Contains(r.Summary, "secret") || strings.Contains(r.Summary, "alice") {
		t.Fatal("credentials in display summary")
	}
}
func TestWrongIPSubjectAndBooleanTypes(t *testing.T) {
	r := parseRisk("8.8.8.8", true, "fixture", `{"status":"success","query":"9.9.9.9","proxy":true}`, `{"success":true,"ip":"8.8.8.8","security":{"vpn":0,"tor":"false"}}`)
	if r.Signals["proxy"].Status != "error" || r.Signals["vpn"].Status != "unknown" || r.Signals["tor"].Status != "unknown" {
		t.Fatalf("%+v", r.Signals)
	}
}
