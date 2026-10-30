package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

type fakeDialer struct{}

func (fakeDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return nil, errors.New("fake dialer")
}

// A rotation must not run while a hijacked CONNECT tunnel is still open.
func TestSwapDialerCountsInFlight(t *testing.T) {
	s := &swapDialer{cur: connDialer{}}
	if !s.idle() {
		t.Fatal("fresh swapDialer should be idle")
	}

	// trackedConn.Close runs the release hook exactly once, however often the
	// hijacked tunnel closes it.
	tc := &trackedConn{Conn: stubConn{}, done: func() { s.active.Add(-1) }}
	s.active.Add(1)
	if s.idle() {
		t.Fatal("swapDialer should not be idle with a connection in flight")
	}
	tc.Close()
	tc.Close()
	if !s.idle() {
		t.Fatal("swapDialer should return to idle after the connection closes")
	}
}

type connDialer struct{}

func (connDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return stubConn{}, nil
}

type stubConn struct {
	net.Conn
}

func (stubConn) Close() error { return nil }

func TestSwapDialerSwapReplacesUpstream(t *testing.T) {
	s := &swapDialer{}
	if _, err := s.DialContext(context.Background(), "tcp", "example.com:443"); err == nil {
		t.Fatal("DialContext succeeded with no upstream")
	}
	s.swap(fakeDialer{})
	if s.cur == nil {
		t.Fatal("swap did not install the dialer")
	}
}

func TestRotateRefusesDuringCooldown(t *testing.T) {
	p := &egressPool{}
	p.lastRotate = time.Now()
	if _, _, err := p.rotate(context.Background()); !errors.Is(err, errRotationBusy) {
		t.Fatalf("rotate() error = %v, want errRotationBusy", err)
	}
	if p.rotating {
		t.Fatal("a refused rotation must not mark the pool as rotating")
	}
}

// A long-lived upstream socket must not veto rotation forever: the policy is
// drain briefly, then proceed. The codespace-less pool therefore surfaces its
// own error rather than errRotationBusy, proving the in-flight gate did not
// block it.
func TestRotateProceedsDespiteTrafficInFlight(t *testing.T) {
	cs := &codespaceManager{dialer: &swapDialer{}}
	p := &egressPool{cs: cs}
	p.lastRotate = time.Now().Add(-time.Hour)
	cs.dialer.active.Add(1)
	defer cs.dialer.active.Add(-1)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _, err := p.rotate(ctx)
	if errors.Is(err, errRotationBusy) {
		t.Fatalf("rotate() still refuses on in-flight traffic: %v", err)
	}
	if p.rotating {
		t.Fatal("rotation flag must be cleared after the attempt")
	}
}

func TestRotateEndpointRejectsNonLoopbackAndBadToken(t *testing.T) {
	h := rotateHandler(&egressPool{cs: &codespaceManager{dialer: &swapDialer{}}}, newSessionStore())
	oldToken := rotateToken
	rotateToken = "secret"
	defer func() { rotateToken = oldToken }()

	cases := []struct {
		name   string
		remote string
		method string
		token  string
		want   int
	}{
		// Origin is no longer restricted — the rotate token is the sole
		// credential, by design for remote dashboards. A valid token gets
		// past auth and hits the (expected) no-upstream business error.
		{"non-loopback", "10.0.0.5:1234", http.MethodPost, "secret", http.StatusConflict},
		{"no token", "127.0.0.1:1234", http.MethodPost, "", http.StatusForbidden},
		{"wrong token", "127.0.0.1:1234", http.MethodPost, "nope", http.StatusForbidden},
		{"wrong method", "127.0.0.1:1234", http.MethodGet, "secret", http.StatusMethodNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, rotatePath, nil)
			req.RemoteAddr = tc.remote
			if tc.token != "" {
				req.Header.Set("X-Rotate-Token", tc.token)
			}
			rec := httptest.NewRecorder()
			h(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

func TestRotateEndpointReportsBusyAsConflict(t *testing.T) {
	oldToken := rotateToken
	rotateToken = "secret"
	defer func() { rotateToken = oldToken }()

	// Cooldown is active, so rotate defers before any gh/network work.
	p := &egressPool{cs: &codespaceManager{dialer: &swapDialer{}}}
	p.lastRotate = time.Now()
	req := httptest.NewRequest(http.MethodPost, rotatePath, nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Rotate-Token", "secret")
	rec := httptest.NewRecorder()
	rotateHandler(p, newSessionStore())(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusConflict)
	}
	if !strings.Contains(rec.Body.String(), "rotation deferred") {
		t.Fatalf("body = %q, want a deferred-rotation error", rec.Body.String())
	}
}

func TestIsLoopback(t *testing.T) {
	for host, want := range map[string]bool{
		"127.0.0.1": true,
		"::1":       true,
		"10.0.0.5":  false,
		"0.0.0.0":   false,
		"":          false,
	} {
		if got := isLoopback(host); got != want {
			t.Errorf("isLoopback(%q) = %v, want %v", host, got, want)
		}
	}
}

// guard against the probe helpers silently changing contract
var _ = io.EOF
var _ proxy.ContextDialer = fakeDialer{}
