package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLimiterBurstThenRefuse(t *testing.T) {
	l := newLimiter(1, 3) // 1/min refill, burst 3
	for i := 0; i < 3; i++ {
		if !l.allow("1.2.3.4") {
			t.Fatalf("attempt %d denied within burst", i+1)
		}
	}
	if l.allow("1.2.3.4") {
		t.Fatal("4th immediate attempt should be refused")
	}
	// Another IP is unaffected.
	if !l.allow("5.6.7.8") {
		t.Fatal("independent IP should not be limited")
	}
}

func TestLimiterRefills(t *testing.T) {
	l := newLimiter(60, 1) // 1/s refill, burst 1
	if !l.allow("9.9.9.9") {
		t.Fatal("first attempt should pass")
	}
	if l.allow("9.9.9.9") {
		t.Fatal("second immediate attempt should be refused")
	}
	l.mu.Lock()
	b := l.m["9.9.9.9"]
	b.last = b.last.Add(-1500 * time.Millisecond) // pretend 1.5s passed
	l.mu.Unlock()
	if !l.allow("9.9.9.9") {
		t.Fatal("refill should grant a token after ~1.5s")
	}
}

func TestProxyAuthAcceptsAndRejects(t *testing.T) {
	hash := proxyAuthHash("alice", "s3cret")
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	gate := requireProxyAuth(ok, hash, newLimiter(100, 100))

	reqCase := func(authz string, want int) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/x", nil)
		if authz != "" {
			req.Header.Set("Proxy-Authorization", authz)
			req.RemoteAddr = "10.1.1.1:55555"
		}
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("authz=%q status=%d want=%d", authz, rec.Code, want)
		}
	}

	// Correct credentials: base64("alice:s3cret") = YWxpY2U6czNjcmV0
	reqCase("Basic YWxpY2U6czNjcmV0", http.StatusOK)
	reqCase("", http.StatusProxyAuthRequired)
	reqCase("Basic aW52YWxpZDppbnZhbGlk", http.StatusProxyAuthRequired) // invalid:invalid
	reqCase("Bearer nonsense", http.StatusProxyAuthRequired)
	reqCase("Basic!!!notbase64", http.StatusProxyAuthRequired)
}

func TestBlocksLoopbackTarget(t *testing.T) {
	for hostPort, want := range map[string]bool{
		"127.0.0.1:8000":  true,
		"[::1]:9999":      true,
		"localhost:80":    true,
		"LOCALHOST:80":    true,
		"example.com:443": false,
		"10.0.0.1:80":     false,
	} {
		if _, got := blocksLoopbackTarget(hostPort); got != want {
			t.Errorf("blocksLoopbackTarget(%q) = %v, want %v", hostPort, got, want)
		}
	}
}

func TestIsControlPath(t *testing.T) {
	for p, want := range map[string]bool{
		rotatePath:   true,
		adminPath:    true,
		"/admin":     true,
		"/":          true,
		"/example":   false,
		"/other.com": false,
	} {
		if got := isControlPath(p); got != want {
			t.Errorf("isControlPath(%q) = %v, want %v", p, got, want)
		}
	}
}

// The documented leak: a client proxies THROUGH sock2http to 127.0.0.1:<laddr>.
// The request then arrives from loopback, where the control endpoints'
// loopback-only check would pass. Public-mode protection is the deny rule in
// dial(); this test proves the helper catches the shape.
func TestLoopbackTargetDenyShapes(t *testing.T) {
	// All forms an attacker may use to sparkle their way to the admin port.
	for _, target := range []string{
		"127.0.0.1:8000",
		"[::1]:8000",
		"localhost:8000",
		"127.8.8.8:8000",
		"0.0.0.0:8000", // unspecified, but not example.com
	} {
		_, blocked := blocksLoopbackTarget(target)
		direct := target != "0.0.0.0:8000" && target != "example.com:443"
		if blocked != direct {
			t.Errorf("target %q blocked=%v want=%v", target, blocked, direct)
		}
	}
}

func TestMaskSecret(t *testing.T) {
	for _, s := range []string{"", "short", "12345678", "abcdefgh12345678"} {
		masked := maskSecret(s)
		if strings.Contains(masked, s) && len(s) > 8 {
			t.Fatalf("maskSecret leaked full secret %q", s)
		}
	}
}
