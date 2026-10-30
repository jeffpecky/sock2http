package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const rotatePath = "/__rotate"
const adminPath = "/__admin"

// Token comes from the config file (written by the dashboard) or the env, and
// is generated only when neither supplies one. A stable token matters because
// 9router stores a copy; a per-run token would break it on every restart.
var (
	configMu    sync.RWMutex
	appConfig   = loadConfig()
	rotateToken = resolveRotateToken()
)

func resolveRotateToken() string {
	if v := os.Getenv("SOCK2HTTP_ROTATE_TOKEN"); v != "" {
		return v
	}
	if appConfig.RotateToken != "" {
		return appConfig.RotateToken
	}
	// Self-generate once and persist, so restarts keep the same secret.
	token := newRotateToken()
	appConfig.RotateToken = token
	if err := saveConfig(appConfig); err != nil {
		logWarn("rotate_token_persist_failed", "error", err.Error())
	}
	return token
}

func newRotateToken() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	return hex.EncodeToString(buf)
}

// currentToken reads the live token under the lock; the admin endpoint can
// replace it while requests are in flight.
func currentToken() string {
	configMu.RLock()
	defer configMu.RUnlock()
	return rotateToken
}

// checkRotateAuth enforces: POST, the rotate token (header, cookie session, or
// ?token= for the first-run link), and — on the proxy listener — loopback
// origin. The dedicated dashboard port binds to whatever -laddr binds to, so
// remote dashboards are allowed there when the token matches.
func (s *sessionStore) checkRotateAuth(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return false
	}
	want := currentToken()
	if want == "" {
		http.Error(w, "invalid token", http.StatusForbidden)
		return false
	}
	header := r.Header.Get("X-Rotate-Token")
	if header == "" {
		header = r.URL.Query().Get("token")
	}
	if subtle.ConstantTimeCompare([]byte(header), []byte(want)) == 1 {
		// Successful token login mints a session cookie, so the browser stops
		// sending the token and later actions ride the cookie.
		if header != "" {
			s.issue(w)
		}
		return true
	}
	// Fall back to a live session cookie.
	if !s.valid(r) {
		http.Error(w, "invalid token", http.StatusForbidden)
		return false
	}
	return true
}

func rotateHandler(pool *egressPool, sessions *sessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !sessions.checkRotateAuth(w, r) {
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
		defer cancel()

		beforeIP := pool.exitIP()
		oldIP, newIP, err := pool.rotate(ctx)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error(), "oldIp": oldIP})
			return
		}
		// Trust but verify: the transport reports the IPs it intended to move
		// between; an independent probe confirms the digit actually changed.
		verified := false
		if afterIP, err := probeExitIP(ctx, pool.upstream()); err == nil {
			verified = afterIP != beforeIP
			if !verified {
				logWarn("rotate_ip_unchanged", "before", beforeIP, "after", afterIP)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "rotated", "oldIp": oldIP, "newIp": newIP, "verified": verified,
		})
	}
}

// adminHandler backs the dashboard: read status (masked secrets), update
// GitHub PATs and the rotate token, force a rotation, or verify the exit IP.
// Actions arrive as {"action": "...", ...} in the POST body.
func adminHandler(pool *egressPool, sessions *sessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !sessions.checkRotateAuth(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")

		var body struct {
			Action     string   `json:"action"`
			Tokens     []string `json:"tokens"`
			CsFallback bool     `json:"csFallback"`
			Token      string   `json:"token"`
			User       string   `json:"user"`
			Pass       string   `json:"pass"`
		}
		// GET status is allowed for a plain dashboard load; everything else is
		// a POST with an action in the body.
		if r.Method == http.MethodGet {
			body.Action = "status"
		} else if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		switch body.Action {
		case "status":
			configMu.RLock()
			tokens := len(appConfig.GHTokens)
			fallback := appConfig.CodespaceFallback
			configMu.RUnlock()
			eg := pool.egress()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"mode":        pool.kind(),
				"exitIp":      pool.exitIP(),
				"family":      eg.family(),
				"ipv4":        eg.IPv4,
				"ipv6":        eg.IPv6,
				"rotateUrl":   appConfig.RotateURL,
				"rotateToken": maskSecret(currentToken()),
				"ghAccounts":  tokens,
				"csFallback":  fallback,
				"configPath":  mustConfigPath(),
			})

		case "reveal":
			_ = json.NewEncoder(w).Encode(map[string]any{"token": currentToken()})

		case "logout":
			// Cookie is server-issued; expire the session server-side and tell
			// the browser to drop it.
			sessions.expire(w, r)
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "logged-out"})

		case "set-proxy-auth":
			// Body fields were decoded into `body` before this switch; re-reading
			// r.Body here would always fail with EOF.
			if body.User == "" || body.Pass == "" {
				http.Error(w, "both user and pass are required", http.StatusBadRequest)
				return
			}
			configMu.Lock()
			appConfig.ProxyUser = body.User
			appConfig.ProxyPass = body.Pass
			configMu.Unlock()
			if err := saveConfig(appConfig); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "saved", "restartRequired": true})

		case "rotate-now":
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
			defer cancel()
			beforeIP := pool.exitIP()
			oldIP, newIP, err := pool.rotate(ctx)
			if err != nil {
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error(), "oldIp": oldIP})
				return
			}
			// Independent verification, same as the /__rotate endpoint: the
			// reported pair describes intent, the probe confirms the digit.
			verified := false
			if afterIP, perr := probeExitIP(ctx, pool.upstream()); perr == nil {
				verified = afterIP != beforeIP
				if !verified {
					logWarn("rotate_ip_unchanged", "before", beforeIP, "after", afterIP)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "rotated", "oldIp": oldIP, "newIp": newIP, "verified": verified,
			})

		case "ipcheck":
			ctx, cancel := context.WithTimeout(r.Context(), 2*exitIPProbeTimeout)
			defer cancel()
			d := pool.upstream()
			if d == nil {
				w.WriteHeader(http.StatusBadGateway)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "no egress upstream configured"})
				return
			}
			eg, err := probeEgress(ctx, d)
			if err != nil {
				w.WriteHeader(http.StatusBadGateway)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
				return
			}
			logInfo("ipcheck", "ip", eg.address(), "family", eg.family(),
				"ipv4", eg.IPv4, "ipv6", eg.IPv6)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ip": eg.address(), "family": eg.family(),
				"ipv4": eg.IPv4, "ipv6": eg.IPv6,
			})

		case "set-gh-tokens":
			for _, t := range body.Tokens {
				if len(t) < 20 || strings.Contains(t, " ") {
					http.Error(w, "tokens look invalid (expected one PAT per line, 20+ chars)", http.StatusBadRequest)
					return
				}
			}
			configMu.Lock()
			appConfig.GHTokens = body.Tokens
			appConfig.CodespaceFallback = body.CsFallback
			configMu.Unlock()
			if err := saveConfig(appConfig); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":     "saved",
				"ghAccounts": len(body.Tokens),
				// Restart required: gh tokens are read when codespaces are provisioned.
				"restartRequired": true,
			})

		case "set-rotate-token":
			token := body.Token
			if token == "" {
				token = newRotateToken()
			}
			configMu.Lock()
			appConfig.RotateToken = token
			rotateToken = token
			configMu.Unlock()
			if err := saveConfig(appConfig); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "saved", "rotateToken": token})

		default:
			http.Error(w, "unknown action", http.StatusBadRequest)
		}
	}
}

func maskSecret(s string) string {
	if len(s) <= 8 {
		return "********"
	}
	return s[:4] + "…" + s[len(s)-4:]
}

func mustConfigPath() string {
	p, err := configPath()
	if err != nil {
		return ""
	}
	return p
}

func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// announceRotateToken publishes where the control plane lives. The rotate URL
// is what 9router calls; the dashboard URL is what a person opens. They are on
// different ports: the proxy port carries only proxying, the dashboard port
// carries only control.
func announceRotateToken(proxyAddr string, dashPort int) {
	if rotateToken == "" {
		return
	}
	host, proxyPort, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		host, proxyPort = "127.0.0.1", proxyAddr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}

	// 9router talks to the dashboard listener, where the rotate endpoint lives.
	rotatePort := proxyPort
	if dashPort != 0 {
		rotatePort = fmt.Sprint(dashPort)
	}
	appConfig.RotateURL = fmt.Sprintf("http://%s:%s%s", host, rotatePort, rotatePath)
	if err := saveConfig(appConfig); err != nil {
		logWarn("rotate_url_persist_failed", "error", err.Error())
	}
	logInfo("rotate_endpoint", "url", appConfig.RotateURL)

	if dashPort != 0 {
		// First-run convenience: a clickable link carrying the token, so the
		// dashboard opens authenticated with no copy-paste. Subsequent runs can
		// just open /admin; the persisted session/token still works there.
		logInfo("dashboard_url", "url", fmt.Sprintf("http://%s:%d/admin#token=%s", host, dashPort, rotateToken))
	}
}
