package main

import (
	"crypto/sha256"
	"encoding/base64"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// limiter is a per-IP token bucket for failed auth attempts. Successes are
// never limited, so proxy throughput is untouched; brute force is what gets
// slowed down.
type limiter struct {
	mu    sync.Mutex
	m     map[string]*bucket
	rate  float64 // tokens per second
	burst float64
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(perMinute, burst float64) *limiter {
	return &limiter{
		m:     make(map[string]*bucket),
		rate:  perMinute / 60,
		burst: burst,
	}
}

func (l *limiter) allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	// Bound memory: a flood of source IPs must not grow the map unboundedly.
	if len(l.m) > 4096 {
		for k, b := range l.m {
			if now.Sub(b.last) > 10*time.Minute {
				delete(l.m, k)
			}
		}
	}

	b, ok := l.m[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.m[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// proxyAuthHash digests the expected user:pass once, so request headers are
// compared hash-to-hash in constant time, never as raw secrets.
func proxyAuthHash(user, pass string) string {
	h := sha256.Sum256([]byte(user + ":" + pass))
	return base64.RawStdEncoding.EncodeToString(h[:])
}

// requireProxyAuth wraps next with Proxy-Authorization enforcement, returning
// 407 when credentials are missing or wrong. Applied only when listening
// publicly; loopback use stays friction-free.
func requireProxyAuth(next http.Handler, expectedHash string, failures *limiter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got string
		if pa := r.Header.Get("Proxy-Authorization"); strings.HasPrefix(pa, "Basic ") {
			if raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(pa, "Basic ")); err == nil {
				got = proxyAuthHashRaw(string(raw))
			}
		}
		if !constTimeEq(got, expectedHash) {
			if !failures.allow(remoteIP(r)) {
				http.Error(w, "too many failed proxy authentications", http.StatusTooManyRequests)
				return
			}
			w.Header().Set("Proxy-Authenticate", `Basic realm="sock2http"`)
			http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func proxyAuthHashRaw(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return base64.RawStdEncoding.EncodeToString(h[:])
}

func constTimeEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// isControlPath reports whether a path belongs to the admin/control surface.
func isControlPath(p string) bool {
	return p == rotatePath || p == adminPath || p == "/admin" || p == "/"
}

// blocksLoopbackTarget reports whether a proxy destination is the machine's own
// loopback, which a public proxy must deny: proxying to 127.0.0.1 would let
// remote clients reach local-only services — including this proxy's own admin
// endpoints, whose loopback check they would then pass.
func blocksLoopbackTarget(hostPort string) (string, bool) {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return host, true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return host, true
	}
	return host, false
}
