package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

const (
	codespaceDefaultRepo    = "github/codespaces-blank"
	codespaceDefaultMachine = "basicLinux32gb"
	codespaceReadyTimeout   = 180 * time.Second
	codespaceTunnelTimeout  = 60 * time.Second
	codespaceRotateCooldown = 60 * time.Second
	exitIPProbeURL          = "https://api4.ipify.org"
	exitIPv6ProbeURL        = "https://api6.ipify.org"
	exitIPProbeTimeout      = 20 * time.Second
)

// swapDialer holds the live upstream and counts in-flight connections so a
// rotation never yanks the tunnel out from under a request in flight.
type swapDialer struct {
	mu     sync.RWMutex
	cur    proxy.ContextDialer
	active atomic.Int64
	// exit holds the families the current egress advertises, so per-connection
	// family reporting knows what the tunnel can actually reach.
	exitFn func() egressInfo
}

func (s *swapDialer) exit() egressInfo {
	if s.exitFn == nil {
		return egressInfo{}
	}
	return s.exitFn()
}

func (s *swapDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	s.mu.RLock()
	d := s.cur
	s.mu.RUnlock()
	if d == nil {
		return nil, errors.New("no upstream tunnel established")
	}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	s.active.Add(1)
	// Which family carried this request is decided by two things: what the
	// target resolves to, and what the exit can reach. conn.RemoteAddr() is the
	// local SOCKS hop, so it proves nothing — compute the answer instead.
	logInfo("dial", "target", addr, "network", network,
		"family", s.carriedFamily(addr))
	return &trackedConn{Conn: conn, done: func() { s.active.Add(-1) }}, nil
}

// carriedFamily reports the address family that must have been used for this
// target, given the exit's advertised families and the target's resolution.
//
// Rules, most specific first:
//   - target is a literal v6 → ipv6; literal v4 → ipv4
//   - target resolves to both, exit has only v4 → ipv4 (v4 is preferred by
//     happy-eyeballs ordering and by our own resolvers)
//   - target resolves to v6 only and exit has no v6 → the dial should have
//     failed; report "unreachable" rather than guessing
func (s *swapDialer) carriedFamily(target string) string {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	host = strings.Trim(host, "[]")

	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			return "ipv4"
		}
		return "ipv6"
	}

	exit := s.exit()
	has4, has6 := exit.IPv4 != "", exit.IPv6 != ""

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		return exit.family()
	}

	var v4, v6 bool
	for _, a := range addrs {
		if a.IP.To4() != nil {
			v4 = true
		} else {
			v6 = true
		}
	}
	switch {
	case v4 && has4:
		return "ipv4"
	case v6 && has6:
		return "ipv6"
	case v4 && !has4 && v6 && has6:
		return "ipv6"
	}
	return "unreachable"
}

// familyOf reports the IP family of a resolved connection address.
func familyOf(a net.Addr) string {
	var host string
	switch v := a.(type) {
	case *net.TCPAddr:
		if v.IP.To4() != nil {
			return "ipv4"
		}
		return "ipv6"
	default:
		host, _, _ = net.SplitHostPort(a.String())
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return "unknown"
	}
	if ip.To4() != nil {
		return "ipv4"
	}
	return "ipv6"
}

func (s *swapDialer) swap(d proxy.ContextDialer) {
	s.mu.Lock()
	s.cur = d
	s.mu.Unlock()
}

func (s *swapDialer) idle() bool { return s.active.Load() == 0 }

// trackedConn releases the in-flight slot however the connection ends, so a
// hijacked CONNECT tunnel is still counted until both sides close.
type trackedConn struct {
	net.Conn
	once sync.Once
	done func()
}

func (c *trackedConn) Close() error {
	c.once.Do(c.done)
	return c.Conn.Close()
}

// codespaceTunnel is one codespace plus the `gh codespace ssh -D` process that
// exposes it as a local SOCKS5 listener.
type codespaceTunnel struct {
	name   string
	port   string
	ip     string
	egress egressInfo
	cmd    *exec.Cmd
	done   chan error
}

func (t *codespaceTunnel) address() string { return t.egress.address() }

func (t *codespaceTunnel) stop() {
	if t.cmd == nil || t.cmd.Process == nil {
		return
	}
	_ = t.cmd.Process.Kill()
	select {
	case <-t.done:
	case <-time.After(5 * time.Second):
	}
}

// codespaceManager owns the codespace lifecycle and rotates it on demand.
type egressUpstream interface {
	kind() string
	upstream() *swapDialer
	rotate(ctx context.Context) (string, string, error)
	stop()
}

// codespaceManager owns codespaces across one or more GitHub accounts and
// rotates between them. Each account is a GH_TOKEN; gh reads the first
// non-empty of GH_TOKEN/GITHUB_TOKEN, so handing a token per exec switches the
// account for that call.
type codespaceManager struct {
	repo    string
	machine string
	dialer  *swapDialer
	tokens  []string

	mu         sync.Mutex
	current    *codespaceTunnel
	account    int
	lastRotate time.Time
	rotating   bool
}

// token returns the GH_TOKEN in force for the current account.
func (m *codespaceManager) token() string {
	if len(m.tokens) == 0 {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tokens[m.account%len(m.tokens)]
}

// nextAccount switches to the next GitHub account, if any, and reports whether
// one was available. Used when the current account runs out of quota.
func (m *codespaceManager) nextAccount() bool {
	if len(m.tokens) < 2 {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.account = (m.account + 1) % len(m.tokens)
	logInfo("gh_account_switch", "account", m.account+1, "of", len(m.tokens))
	return true
}

func (m *codespaceManager) kind() string { return "codespace" }

func (m *codespaceManager) upstream() *swapDialer { return m.dialer }

func (m *codespaceManager) stop() {
	m.mu.Lock()
	cur := m.current
	m.current = nil
	m.mu.Unlock()
	if cur != nil {
		cur.stop()
	}
}

// isQuotaError reports whether a gh failure means the account cannot create
// more codespaces. GitHub has no dedicated exit code for this, so the message
// is the only signal.
func isQuotaError(msg string) bool {
	lower := strings.ToLower(msg)
	for _, needle := range []string{
		"quota", "billing", "payment", "spending limit", "insufficient",
		"usage limit", "402",
	} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

// parseTokens splits a comma-separated token list, dropping blanks. An empty
// list means "use whatever `gh auth login` stored" (or GH_TOKEN in the env).
//
// ponytail: tokens arrive on the command line, so they are visible in process
// listings. Failing over to a file/env source is the upgrade path if that
// matters on this host.
func parseTokens(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if t := strings.TrimSpace(part); t != "" {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		if t := strings.TrimSpace(os.Getenv("GH_TOKEN")); t != "" {
			return []string{t}
		}
		if t := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); t != "" {
			return []string{t}
		}
	}
	return out
}

func startCodespace(ctx context.Context, repo, machine string, tokens []string) (*codespaceManager, error) {
	if err := checkGH(); err != nil {
		return nil, err
	}
	if repo == "" {
		repo = codespaceDefaultRepo
	}
	if machine == "" {
		machine = codespaceDefaultMachine
	}

	m := &codespaceManager{repo: repo, machine: machine, dialer: &swapDialer{}, tokens: tokens}
	// Per-connection family reporting needs to know which families the current
	// codespace egress can reach.
	m.dialer.exitFn = func() egressInfo {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.current != nil {
			return m.current.egress
		}
		return egressInfo{}
	}

	tunnel, err := m.provision(ctx, "")
	if err != nil {
		return nil, err
	}
	m.current = tunnel

	d, err := newSOCKSDialer(tunnel.port, nil)
	if err != nil {
		tunnel.stop()
		return nil, fmt.Errorf("create codespace SOCKS5 dialer: %w", err)
	}
	m.dialer.swap(d)
	m.lastRotate = time.Now()

	return m, nil
}

func checkGH() error {
	if _, err := exec.LookPath("gh"); err != nil {
		return fmt.Errorf("the -codespace mode requires the GitHub CLI (gh) on PATH: %w", err)
	}
	if os.Getenv("GH_TOKEN") == "" && os.Getenv("GITHUB_TOKEN") == "" {
		// gh can also use its stored login; only warn, don't fail.
		fmt.Fprintln(os.Stderr, "note: neither GH_TOKEN nor GITHUB_TOKEN is set; relying on `gh auth login` credentials")
	}
	return nil
}

// provision creates a codespace (optionally reusing one) and brings up its
// SOCKS5 tunnel, verifying that it actually carries traffic.
//
// Tunnel ownership is the process lifetime, not the caller's: rotation calls
// this from inside an HTTP handler whose context dies the moment the rotate
// response is written, and exec.CommandContext would kill the fresh
// `gh codespace ssh` right after it — dead proxy until a manual restart.
// The gh API calls below may still use the caller's context (they are one
// shots), but the long-lived ssh child gets the detached owner context.
func (m *codespaceManager) provision(ctx context.Context, exclude string) (*codespaceTunnel, error) {
	owner := context.WithoutCancel(ctx)
	name, err := m.pickOrCreate(ctx, exclude)
	if err != nil {
		return nil, err
	}
	if err := m.ensureAvailable(ctx, name); err != nil {
		return nil, err
	}

	port, err := reserveLocalAddress()
	if err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(owner, "gh", "codespace", "ssh", "--codespace", name, "--",
		"-D", port,
		"-N",
		"-o", "ServerAliveInterval=30",
		"-o", "ServerAliveCountMax=3",
		"-o", "TCPKeepAlive=yes",
		"-o", "ExitOnForwardFailure=yes",
		"-o", "ControlMaster=no",
		"-o", "ControlPath=none",
	)
	cmd.Env = ghEnv(m.token())
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start codespace SSH tunnel: %w", err)
	}
	go func() { done <- cmd.Wait() }()

	t := &codespaceTunnel{name: name, port: port, cmd: cmd, done: done}

	if err := waitForPort(owner, port, done, codespaceTunnelTimeout); err != nil {
		t.stop()
		return nil, fmt.Errorf("codespace %s: %w", name, err)
	}

	d, err := newSOCKSDialer(port, nil)
	if err != nil {
		t.stop()
		return nil, err
	}
	// Probe under the owner context too: a cancelled request context aborting
	// the verification would stop() a healthy tunnel mid-handshake.
	eg, err := probeEgress(owner, d)
	if err != nil {
		t.stop()
		return nil, fmt.Errorf("verify codespace %s egress: %w", name, err)
	}
	t.egress = eg
	t.ip = eg.address()
	logInfo("codespace_ready", "codespace", name, "socksAddr", port,
		"exitIp", eg.address(), "family", eg.family(),
		"ipv4", eg.IPv4, "ipv6", eg.IPv6)

	return t, nil
}

func (m *codespaceManager) pickOrCreate(ctx context.Context, exclude string) (string, error) {
	list, err := listCodespaces(ctx, m.token())
	if err == nil {
		for _, cs := range list {
			if cs.Name != exclude && cs.State == "Available" {
				logInfo("codespace_reuse", "codespace", cs.Name)
				return cs.Name, nil
			}
		}
	}

	// Creating is the step that hits quota; try each account before giving up
	// so a single exhausted account does not take egress down.
	attempts := max(len(m.tokens), 1)
	var lastErr error
	for i := 0; i < attempts; i++ {
		name, err := createCodespace(ctx, m.repo, m.machine, m.token())
		if err == nil {
			return name, nil
		}
		lastErr = err
		if !isQuotaError(err.Error()) || !m.nextAccount() {
			break
		}
	}
	return "", lastErr
}

type codespaceInfo struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

func listCodespaces(ctx context.Context, token string) ([]codespaceInfo, error) {
	out, err := ghOutput(ctx, token, "codespace", "list", "--json", "name,state", "--limit", "30")
	if err != nil {
		return nil, err
	}
	var list []codespaceInfo
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		return nil, fmt.Errorf("parse codespace list: %w", err)
	}
	return list, nil
}

func createCodespace(ctx context.Context, repo, machine, token string) (string, error) {
	logInfo("codespace_create", "repo", repo, "machine", machine)
	out, err := ghOutput(ctx, token, "codespace", "create", "-R", repo, "-m", machine)
	if err != nil {
		return "", fmt.Errorf("create codespace: %w", err)
	}
	// `gh codespace create` has no --json; the name is the last stdout line.
	name := ""
	for _, line := range strings.Split(out, "\n") {
		if s := strings.TrimSpace(line); s != "" {
			name = s
		}
	}
	if name == "" {
		return "", errors.New("gh codespace create returned no codespace name")
	}
	logInfo("codespace_created", "codespace", name)
	return name, nil
}

func (m *codespaceManager) ensureAvailable(ctx context.Context, name string) error {
	deadline := time.Now().Add(codespaceReadyTimeout)
	started := false
	for {
		list, err := listCodespaces(ctx, m.token())
		if err == nil {
			for _, cs := range list {
				if cs.Name != name {
					continue
				}
				switch cs.State {
				case "Available":
					return nil
				case "Shutdown":
					if !started {
						logInfo("codespace_start", "codespace", name)
						_, _ = ghOutput(ctx, m.token(), "api", "-X", "POST", "/user/codespaces/"+name+"/start")
						started = true
					}
				}
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("codespace did not become available within %s", codespaceReadyTimeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

func deleteCodespace(ctx context.Context, name, token string) error {
	_, err := ghOutput(ctx, token, "codespace", "delete", "--codespace", name, "--force")
	return err
}

// ghEnv builds the child environment for gh. A token overrides whatever
// `gh auth login` stored, which is how account switching works. The token is
// passed via the environment, never argv, so it stays out of process listings.
func ghEnv(token string) []string {
	env := os.Environ()
	if token == "" {
		return env
	}
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if strings.HasPrefix(kv, "GH_TOKEN=") || strings.HasPrefix(kv, "GITHUB_TOKEN=") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "GH_TOKEN="+token)
}

func ghOutput(ctx context.Context, token string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "gh", args...)
	cmd.Env = ghEnv(token)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", errors.New(msg)
	}
	return string(out), nil
}

func waitForPort(ctx context.Context, addr string, processDone chan error, timeout time.Duration) error {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		select {
		case processErr := <-processDone:
			processDone <- processErr
			return fmt.Errorf("SSH tunnel exited before opening its SOCKS5 listener: %w", processErr)
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("SOCKS5 listener did not open at %s within %s", addr, timeout)
		case <-ticker.C:
		}
	}
}

// egressInfo is what the exit actually looks like from outside: the address
// and, explicitly, which IP family it is. Family is derived from the parsed
// address rather than assumed from the probe used, so a v6 address arriving on
// a v4-labelled probe is reported as v6.
type egressInfo struct {
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
}

// family returns the address family traffic egresses on. Dual-stack exits are
// reported by which probe succeeded; IPv4 wins when both answer because that is
// what a v4-first resolver picks.
func (e egressInfo) family() string {
	switch {
	case e.IPv4 != "":
		return "ipv4"
	case e.IPv6 != "":
		return "ipv6"
	default:
		return "unknown"
	}
}

func (e egressInfo) address() string {
	if e.IPv4 != "" {
		return e.IPv4
	}
	return e.IPv6
}

// probeEgress probes both families. A v6 probe failing is normal (most exits
// are v4-only), so it is not an error; only losing both is.
func probeEgress(ctx context.Context, dialer proxy.ContextDialer) (egressInfo, error) {
	var out egressInfo

	v4ctx, cancel4 := context.WithTimeout(ctx, exitIPProbeTimeout)
	defer cancel4()
	if ip, err := probeExitIPFamily(v4ctx, dialer, 4); err == nil {
		out.IPv4 = ip
	} else {
		logWarn("probe_family_failed", "family", "ipv4", "error", err.Error())
	}

	v6ctx, cancel6 := context.WithTimeout(ctx, exitIPProbeTimeout)
	defer cancel6()
	if ip, err := probeExitIPFamily(v6ctx, dialer, 6); err == nil {
		out.IPv6 = ip
	} else {
		// Expected on v4-only exits; debug-level noise, not a warning.
		logInfo("probe_family_unavailable", "family", "ipv6", "error", err.Error())
	}

	if out.IPv4 == "" && out.IPv6 == "" {
		return out, fmt.Errorf("egress probe failed on both IPv4 and IPv6")
	}
	return out, nil
}

func probeExitIP(ctx context.Context, dialer proxy.ContextDialer) (string, error) {
	e, err := probeEgress(ctx, dialer)
	if err != nil {
		return "", err
	}
	return e.address(), nil
}

func probeExitIPFamily(ctx context.Context, dialer proxy.ContextDialer, family int) (string, error) {
	switch family {
	case 4:
		return probeExitIPAt(ctx, dialer, exitIPProbeURL, 4)
	case 6:
		return probeExitIPAt(ctx, dialer, exitIPv6ProbeURL, 6)
	default:
		return "", fmt.Errorf("unsupported IP family: %d", family)
	}
}

func probeExitIPAt(ctx context.Context, dialer proxy.ContextDialer, url string, family int) (string, error) {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, addr)
			},
		},
		Timeout: exitIPProbeTimeout,
	}
	defer client.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("exit IP probe failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("exit IP probe returned HTTP %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(body))
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", fmt.Errorf("exit IP probe returned a non-address: %q", ip)
	}
	if family == 4 && parsed.To4() == nil {
		return "", fmt.Errorf("IPv4 exit IP probe returned a non-IPv4 address: %q", ip)
	}
	if family == 6 && (parsed.To4() != nil || !strings.Contains(ip, ":")) {
		return "", fmt.Errorf("IPv6 exit IP probe returned a non-IPv6 address: %q", ip)
	}
	return ip, nil
}

// errRotationBusy means a rotation was requested while one was already running
// or while traffic was in flight; the caller should retry later.
var errRotationBusy = errors.New("rotation deferred: tunnel busy or cooldown active")

// rotate replaces the current codespace with a freshly created one, keeping the
// old tunnel serving until the replacement is verified. Busy/cooldown gating
// lives in egressPool, which arbitrates every upstream kind.
func (m *codespaceManager) rotate(ctx context.Context) (string, string, error) {
	m.mu.Lock()
	old := m.current
	m.mu.Unlock()
	if old == nil {
		return "", "", fmt.Errorf("no codespace is running")
	}

	// Create the replacement before touching the old tunnel: a failed create
	// must leave the current egress working.
	next, err := m.provision(ctx, old.name)
	if err != nil {
		return "", "", err
	}

	nextDialer, err := newSOCKSDialer(next.port, nil)
	if err != nil {
		next.stop()
		return "", "", err
	}
	m.dialer.swap(nextDialer)

	m.mu.Lock()
	m.current = next
	m.lastRotate = time.Now()
	m.mu.Unlock()

	oldIP := old.ip
	old.stop()
	if err := deleteCodespace(ctx, old.name, m.token()); err != nil {
		logWarn("codespace_delete_failed", "codespace", old.name, "error", err.Error())
	}
	logInfo("codespace_rotated",
		"from", old.name, "oldIp", old.ip, "oldFamily", old.egress.family(),
		"to", next.name, "newIp", next.ip, "newFamily", next.egress.family(),
		"ipv4", next.egress.IPv4, "ipv6", next.egress.IPv6)

	return oldIP, next.ip, nil
}
