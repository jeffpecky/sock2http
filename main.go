package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/proxy"
)

var (
	laddr           = flag.String("laddr", "127.0.0.1:8000", "Address to listen on")
	dashPort        = flag.Int("dashboard-port", 2121, "Dashboard port (bound to the same interface as -laddr); 0 disables the dashboard")
	raddr           = flag.String("raddr", "127.0.0.1:1080", "SOCKS5 proxy address")
	user            = flag.String("u", "", "SOCKS5 username")
	pass            = flag.String("p", "", "SOCKS5 password")
	warp            = flag.Bool("warp", false, "Use a Cloudflare WARP tunnel managed by sock2http")
	promptWarpTerms = flag.Bool("prompt-warp-terms", false, "Require confirmation before first-time WARP account registration")
	codespace       = flag.Bool("codespace", false, "Use a GitHub Codespace as the upstream, with a rotate endpoint")
	csRepo          = flag.String("cs-repo", codespaceDefaultRepo, "Repository to create codespaces from (-codespace)")
	csMachine       = flag.String("cs-machine", codespaceDefaultMachine, "Codespace machine type (-codespace)")
	csTokens        = flag.String("cs-tokens", "", "Comma-separated GitHub PATs, one per account (-codespace); falls back to GH_TOKEN/GITHUB_TOKEN when empty")
	csFallback      = flag.Bool("cs-fallback", false, "Fall back to WARP when codespace quota is exhausted; also settable in the dashboard config")
	svcFlag         = flag.String("service", "", "Manage the Windows service: \"install\" (records the rest of the command line as the service's flags) or \"uninstall\"")
	svcRun          = flag.Bool("svc", false, "Started by the Windows service manager; not for console use")
)

var hopByHop = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func removeHopHeaders(h http.Header) {
	for _, c := range strings.Split(h.Get("Connection"), ",") {
		if c = strings.TrimSpace(c); c != "" {
			h.Del(c)
		}
	}
	for _, k := range hopByHop {
		h.Del(k)
	}
}

func main() {
	// Collect the raw argv BEFORE parsing: `-service install` is a flag value,
	// not a separator — `-service install -warp -laddr 0.0.0.0:8001` must bake
	// the same flags into the service's command line, and flag.Args() would be
	// empty because the Go flag package stops at args it knows and calls only
	// the leftovers "arguments". Everything after the literal "install" token
	// is the service definition, verbatim.
	installFlags := []string{}
	if idx := slices.Index(os.Args, "-service"); idx >= 0 &&
		idx+1 < len(os.Args) && os.Args[idx+1] == "install" {
		installFlags = os.Args[idx+2:]
	}

	flag.Parse()

	if *svcRun {
		if err := runService(); err != nil {
			log.Fatal(err)
		}
		return
	}

	switch *svcFlag {
	case "":
	case "install":
		if err := installService(installFlags); err != nil {
			log.Fatal(err)
		}
		return
	case "uninstall":
		if err := uninstallService(); err != nil {
			log.Fatal(err)
		}
		return
	default:
		log.Fatalf("-service must be \"install\" or \"uninstall\", got %q", *svcFlag)
	}

	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if *svcFlag != "" {
		// install/uninstall were returned from already; fallthrough here would
		// start a proxy as a side effect of a management command.
		return nil
	}
	ctx, stop := context.WithCancel(context.Background())
	// Ctrl+C (console) or service Stop (svcOnce in scv_windows.go) both land on
	// this cancellation, so shutdown handling is written once.
	stopOnSignal(stop)
	defer stop()
	applyConfigDefaults()
	if *promptWarpTerms && !*warp {
		return fmt.Errorf("-prompt-warp-terms requires -warp")
	}
	if *warp && *codespace {
		return fmt.Errorf("-warp and -codespace are mutually exclusive")
	}

	proxyListener, err := net.Listen("tcp", *laddr)
	if err != nil {
		if reclaimErr := reclaimAppPort(*laddr); reclaimErr != nil {
			return fmt.Errorf("HTTP proxy server: listen on %s: %w (port recovery failed: %v)", *laddr, err, reclaimErr)
		}
		proxyListener, err = net.Listen("tcp", *laddr)
		if err != nil {
			return fmt.Errorf("HTTP proxy server: listen on %s after port recovery: %w", *laddr, err)
		}
	}
	defer proxyListener.Close()

	username, password := *user, *pass
	usernameSet, passwordSet := false, false
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "u":
			usernameSet = true
		case "p":
			passwordSet = true
		}
	})

	var cd proxy.ContextDialer
	var pool *egressPool
	switch {
	case *warp:
		wm, werr := startWarpManager(ctx, *promptWarpTerms)
		if werr != nil {
			return werr
		}
		pool = &egressPool{warp: wm}
		cd = wm.upstream()
		defer wm.stop()
	case *codespace:
		tokens := parseTokens(*csTokens)
		cs, cerr := startCodespace(ctx, *csRepo, *csMachine, tokens)
		if cerr != nil {
			return cerr
		}
		pool = &egressPool{cs: cs, token: tokens, csFallback: *csFallback}
		cd = cs.upstream()
		defer cs.stop()
	default:
		if usernameSet != passwordSet {
			return fmt.Errorf("SOCKS5 username and password flags (-u and -p) must be used together")
		}
		if !usernameSet {
			username, usernameSet = os.LookupEnv("SOCKS5_USERNAME")
			password, passwordSet = os.LookupEnv("SOCKS5_PASSWORD")
		}
		if usernameSet != passwordSet {
			return fmt.Errorf("SOCKS5_USERNAME and SOCKS5_PASSWORD must be set together")
		}

		var auth *proxy.Auth
		if usernameSet {
			if username == "" || password == "" {
				return fmt.Errorf("SOCKS5 username and password must not be empty")
			}
			auth = &proxy.Auth{User: username, Password: password}
		}

		cd, err = newSOCKSDialer(*raddr, auth)
		if err != nil {
			return fmt.Errorf("create SOCKS5 dialer: %w", err)
		}
	}

	// Public listen (anything not loopback) changes the rules: the proxy
	// requires listener credentials (-u/-p in codespace/warp mode, where there
	// is no upstream SOCKS for them to mean anything else), control endpoints
	// demand the rotate token from remote callers, and proxying to loopback
	// targets is denied — otherwise a remote client could proxy to
	// 127.0.0.1:<laddr> and reach the admin surface from "loopback".
	listenHost, _, _ := net.SplitHostPort(*laddr)
	publicListen := !(listenHost == "" || isLoopback(listenHost))
	if publicListen && !(*warp || *codespace) && (usernameSet || passwordSet) {
		return fmt.Errorf("-u and -p authenticate the upstream SOCKS5; listener credentials for a public listen are set with proxyUser/proxyPass in the config")
	}
	// In codespace/warp mode -u/-p are never upstream auth: on a public listen
	// they are the listener credentials (validated together below); on a
	// loopback listen there is no listener auth to configure, so passing them
	// is a mistake we refuse instead of silently ignoring.
	publicModeTunnel := *warp || *codespace
	if publicModeTunnel {
		if usernameSet != passwordSet {
			return fmt.Errorf("listener credentials: -u and -p must be used together")
		}
		if (usernameSet || passwordSet) && !publicListen {
			return fmt.Errorf("-u and -p authenticate a PUBLIC proxy listen; this listen is loopback, so a tunnel mode has no listener credentials to set — drop them")
		}
	}

	// Resolved per request, not captured: a codespace→WARP fallback swaps the
	// upstream out from under this handler and must take effect immediately.
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if publicListen {
			if _, blocked := blocksLoopbackTarget(addr); blocked {
				return nil, fmt.Errorf("proxying to loopback is denied while listening publicly")
			}
		}
		if pool != nil {
			if d := pool.upstream(); d != nil {
				return d.DialContext(ctx, network, addr)
			}
		}
		return cd.DialContext(ctx, network, addr)
	}

	transport := &http.Transport{
		DialContext: dial,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Listener credentials for a public listen: flag first (codespace/warp
	// mode), then env, then dashboard config. Refusing to start wide open is
	// deliberate — an unauthenticated open proxy on a VPS gets found and
	// abused within hours.
	var proxyAuthHashVal string
	if publicListen {
		user, pass := os.Getenv("SOCK2HTTP_PROXY_USER"), os.Getenv("SOCK2HTTP_PROXY_PASS")
		configMu.RLock()
		if user == "" {
			user = appConfig.ProxyUser
		}
		if pass == "" {
			pass = appConfig.ProxyPass
		}
		configMu.RUnlock()
		if publicModeTunnel && usernameSet {
			user, pass = username, password
		}
		if user == "" || pass == "" {
			return fmt.Errorf("public listening on %s requires proxy credentials: -u/-p, or SOCK2HTTP_PROXY_USER/_PASS, or proxyUser/proxyPass in the config file", *laddr)
		}
		proxyAuthHashVal = proxyAuthHash(user, pass)
	}
	publicAuth := newLimiter(10, 6) // failed-auth buckets, per source IP
	sessions := newSessionStore()

	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// The proxy listener is a pure forward proxy: no control endpoints, so
		// a browser that lands here never gets admin responses, and there is no
		// second admin surface to guard. Everything admin lives on the
		// dedicated dashboard port below.
		//
		// Browsers auto-request these; answer locally instead of trying to
		// resolve them as hostnames (which surfaced as 502s).
		switch req.URL.Path {
		case "/favicon.ico":
			w.WriteHeader(http.StatusNoContent)
			return
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("User-agent: *\nDisallow: /\n"))
			return
		}
		if req.Method == http.MethodConnect {
			dst, err := dial(req.Context(), "tcp", req.Host)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			hj, ok := w.(http.Hijacker)
			if !ok {
				dst.Close()
				http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
				return
			}
			conn, brw, err := hj.Hijack()
			if err != nil {
				dst.Close()
				return
			}
			if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
				conn.Close()
				dst.Close()
				return
			}

			go func() {
				defer conn.Close()
				defer dst.Close()
				io.Copy(dst, brw) // brw.Reader may hold already-buffered bytes
			}()
			go func() {
				defer conn.Close()
				defer dst.Close()
				io.Copy(conn, dst)
			}()
			return
		}

		req.RequestURI = ""
		removeHopHeaders(req.Header)
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		removeHopHeaders(resp.Header)
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	})

	var handler http.Handler = baseHandler
	if publicListen {
		// Every request on a public listen needs proxy credentials, CONNECT or
		// not. No control paths exist here to exempt.
		handler = requireProxyAuth(baseHandler, proxyAuthHashVal, publicAuth)
	}

	server := &http.Server{Handler: handler}
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Serve(proxyListener)
	}()
	logInfo("proxy_listening", "addr", *laddr, "public", publicListen)
	if pool != nil {
		logInfo("egress_upstream", "kind", pool.kind())
	}

	// Dedicated dashboard listener. Separate port keeps admin traffic off the
	// proxy path and lets a VPS firewall rule close it entirely.
	//
	// Available in every mode: default mode shows status/config but rotation
	// answers "no egress upstream configured", which is honest and useful.
	// The listener always binds loopback unless -laddr is explicitly public —
	// an admin console has no business being reachable by default.
	var dashServer *http.Server
	var dashErr chan error
	if *dashPort != 0 {
		dashHost := "127.0.0.1"
		if publicListen {
			dashHost = listenHost
		}
		dashAddr := net.JoinHostPort(dashHost, fmt.Sprint(*dashPort))
		dashMux := http.NewServeMux()
		dashMux.HandleFunc("/admin", func(w http.ResponseWriter, req *http.Request) {
			if req.Method == http.MethodGet {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Write([]byte(dashboardHTML))
				return
			}
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
		})
		dashMux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		dashMux.HandleFunc(adminPath, adminHandler(pool, sessions))
		dashMux.HandleFunc(rotatePath, rotateHandler(pool, sessions))
		dashServer = &http.Server{Addr: dashAddr, Handler: dashMux, ReadHeaderTimeout: 10 * time.Second}
		dashListener, err := net.Listen("tcp", dashAddr)
		if err != nil {
			if reclaimErr := reclaimAppPort(dashAddr); reclaimErr != nil {
				return fmt.Errorf("dashboard server: listen on %s: %w (port recovery failed: %v)", dashAddr, err, reclaimErr)
			}
			dashListener, err = net.Listen("tcp", dashAddr)
			if err != nil {
				return fmt.Errorf("dashboard server: listen on %s after port recovery: %w", dashAddr, err)
			}
		}
		dashErr = make(chan error, 1)
		go func() {
			dashErr <- dashServer.Serve(dashListener)
		}()
		logInfo("dashboard_listening", "addr", dashAddr)
		announceRotateToken(*laddr, *dashPort)
	}

	select {
	case err := <-serverErr:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("HTTP proxy server: %w", err)
		}
		return nil
	case err := <-dashErr:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("dashboard server: %w", err)
		}
		return nil
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if dashServer != nil {
			_ = dashServer.Shutdown(shutdownCtx)
		}
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shut down HTTP proxy server: %w", err)
		}
		if err := <-serverErr; err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("HTTP proxy server: %w", err)
		}
		return nil
	}
}

// stopOnSignal cancels stop on Ctrl+C (console) or service stop; the service
// path closes svcStop itself, so in service mode only the signal hook runs.
func stopOnSignal(stop context.CancelFunc) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	// systemd and most supervisors stop services with SIGTERM; console Ctrl+C
	// arrives as os.Interrupt — both land on the same cancellation.
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sigCh:
			stop()
		case <-svcStopClosed():
			stop()
		}
	}()
}

// svcStopClosed yields a channel that closes when the service wants shutdown,
// or a never-closed channel in console mode so the select only watches signals.
func svcStopClosed() <-chan struct{} {
	if *svcRun {
		return svcStop
	}
	never := make(chan struct{})
	return never
}

func newSOCKSDialer(addr string, auth *proxy.Auth) (proxy.ContextDialer, error) {
	dialer, err := proxy.SOCKS5("tcp", addr, auth, proxy.Direct)
	if err != nil {
		return nil, err
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("SOCKS5 dialer does not support context-aware connections")
	}
	return contextDialer, nil
}
