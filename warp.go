package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

const (
	wgcfVersion             = "2.3.1"
	wgcfSHA256              = "e222fd9443d7cb3264d825a3e86967797fc9c938507c5d93e3cc21e4aed11dcc"
	wireproxyVersion        = "1.1.3"
	wireproxyArchiveSHA256  = "bce041ea9fe0f8a3351301dcbe29cdf6a523bb25cf9c62f17ebb5699a8051d0f"
	wireproxyBinarySHA256   = "b176b561fd8bf15d828fcab484cfd5b4fb941cb9f61807901ca64b955af27e1f"
	maxDownloadSize         = 50 << 20
	maxBinarySize           = 100 << 20
	warpStartupTimeout      = 30 * time.Second
	warpTraceRequestTimeout = 20 * time.Second
)

func warpConfigDir() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("find user config directory: %w", err)
	}
	configDir = filepath.Join(configDir, "sock2http", "warp")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return "", fmt.Errorf("create WARP config directory: %w", err)
	}
	return configDir, nil
}

func startWarp(ctx context.Context, promptForTerms bool) (proxy.ContextDialer, func(), error) {
	if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
		return nil, nil, fmt.Errorf("the -warp mode currently supports Windows amd64 only")
	}

	configDir, err := warpConfigDir()
	if err != nil {
		return nil, nil, err
	}

	wgcfPath := filepath.Join(configDir, "wgcf.exe")
	wireproxyPath := filepath.Join(configDir, "wireproxy.exe")
	if err := ensureWGCF(wgcfPath); err != nil {
		return nil, nil, err
	}
	if err := ensureWireproxy(wireproxyPath); err != nil {
		return nil, nil, err
	}

	profilePath := filepath.Join(configDir, "wgcf-profile.conf")
	if _, err := os.Stat(profilePath); errors.Is(err, os.ErrNotExist) {
		accountPath := filepath.Join(configDir, "wgcf-account.toml")
		if _, accountErr := os.Stat(accountPath); errors.Is(accountErr, os.ErrNotExist) {
			if promptForTerms {
				accepted, err := confirmWARPRegistration()
				if err != nil {
					return nil, nil, err
				}
				if !accepted {
					return nil, nil, fmt.Errorf("WARP account registration was not confirmed")
				}
			}
			if err := runWGCF(ctx, configDir, wgcfPath, "--config", accountPath, "register", "--accept-tos"); err != nil {
				return nil, nil, fmt.Errorf("register WARP account: %w", err)
			}
		} else if accountErr != nil {
			return nil, nil, fmt.Errorf("check WARP account file: %w", accountErr)
		}

		if err := runWGCF(ctx, configDir, wgcfPath, "--config", accountPath, "generate", "--profile", profilePath); err != nil {
			return nil, nil, fmt.Errorf("generate WARP WireGuard profile: %w", err)
		}
	}

	profileInfo, err := os.Stat(profilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("read WARP profile: %w", err)
	}
	if !profileInfo.Mode().IsRegular() || profileInfo.Size() == 0 {
		return nil, nil, fmt.Errorf("WARP profile is not a non-empty regular file: %s", profilePath)
	}

	proxyAddr, err := reserveLocalAddress()
	if err != nil {
		return nil, nil, err
	}
	wireproxyConfig := fmt.Sprintf("WGConfig = %s\n\n[Socks5]\nBindAddress = %s\n", profilePath, proxyAddr)
	configPath := filepath.Join(configDir, "wireproxy.conf")
	if err := os.WriteFile(configPath, []byte(wireproxyConfig), 0600); err != nil {
		return nil, nil, fmt.Errorf("write wireproxy config: %w", err)
	}

	proxyCtx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(proxyCtx, wireproxyPath, "-c", configPath)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, nil, fmt.Errorf("start wireproxy: %w", err)
	}

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()
	cleanup := func() {
		cancel()
		select {
		case <-waitCh:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-waitCh
		}
	}

	if err := waitForListener(ctx, proxyAddr, waitCh); err != nil {
		cleanup()
		return nil, nil, err
	}

	dialer, err := newSOCKSDialer(proxyAddr, nil)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("create WARP SOCKS5 dialer: %w", err)
	}
	if err := verifyWARP(ctx, dialer); err != nil {
		cleanup()
		return nil, nil, err
	}

	return dialer, cleanup, nil
}

// warpManager owns a WARP tunnel that can be rebuilt to change its exit IP.
//
// Observed in practice: restarting wireproxy on the same enrolled device is
// usually enough, because Cloudflare reassigns the tunnel's egress on
// reconnect. Tier 2 (delete account + profile, enroll a new device) is the
// fallback for when a restart comes back on the same address. rotate() always
// verifies the IP actually changed rather than assuming either tier works.
type warpManager struct {
	promptForTerms bool
	cleanup        func()
	dialer         *swapDialer
	ip             string
	egress         egressInfo
}

func (w *warpManager) address() string { return w.egress.address() }

func startWarpManager(ctx context.Context, promptForTerms bool) (*warpManager, error) {
	d, cleanup, err := startWarp(ctx, promptForTerms)
	if err != nil {
		return nil, err
	}
	s := &swapDialer{cur: d}
	eg, _ := probeEgress(ctx, d)
	wm := &warpManager{promptForTerms: promptForTerms, cleanup: cleanup, dialer: s,
		ip: eg.address(), egress: eg}
	s.exitFn = func() egressInfo { return wm.egress }
	logInfo("warp_ready", "exitIp", eg.address(), "family", eg.family(),
		"ipv4", eg.IPv4, "ipv6", eg.IPv6)

	return wm, nil
}

func (w *warpManager) kind() string { return "warp" }

func (w *warpManager) upstream() *swapDialer { return w.dialer }

func (w *warpManager) stop() {
	if w.cleanup != nil {
		w.cleanup()
		w.cleanup = nil
	}
}

// rotate replaces the WARP tunnel by restarting wireproxy.
//
// Re-enrollment (delete account + profile, register a fresh device) was tried
// as a second tier and removed: measured live, three successive re-enrollments
// returned the identical IPv4 (104.28.219.97) — the address belongs to the
// Cloudflare NAT pool the account lands in, not to the device, so escalating
// only wasted ~30s per attempt and burned a registration. A restart is still
// kept because recreating the tunnel resets the Cloudflare-side session state,
// which is what actually clears provider 429s (not the IP, which does not
// change).
func (w *warpManager) rotate(ctx context.Context) (string, string, error) {
	oldIP := w.ip
	dialer := w.dialer
	oldCleanup := w.cleanup

	// Start the replacement before retiring the current tunnel, so a failed
	// restart does not leave us without any egress.
	d, newCleanup, err := startWarp(ctx, false)
	if err != nil {
		return oldIP, "", fmt.Errorf("WARP restart failed: %w", err)
	}
	eg, probeErr := probeEgress(ctx, d)
	if probeErr != nil {
		newCleanup()
		return oldIP, "", fmt.Errorf("WARP restart probe failed: %v", probeErr)
	}
	oldCleanup()
	dialer.swap(d)
	w.cleanup = newCleanup
	w.ip, w.egress = eg.address(), eg
	if eg.address() != oldIP {
		logInfo("warp_rotated", "method", "restart",
			"oldIp", oldIP, "newIp", eg.address(),
			"family", eg.family(), "ipv4", eg.IPv4, "ipv6", eg.IPv6)
	} else {
		// WARP IPv4 is pinned per account; what changes is the tunnel
		// (and the v6 suffix), not the address.
		logWarn("warp_ip_unchanged", "ip", eg.address(), "family", eg.family(),
			"ipv6", eg.IPv6, "note", "warp ipv4 is pinned; restart resets session state only")
	}
	return oldIP, eg.address(), nil
}

func ensureWGCF(path string) error {
	url := "https://github.com/ViRb3/wgcf/releases/download/v" + wgcfVersion +
		"/wgcf_" + wgcfVersion + "_windows_amd64.exe"
	return installVerifiedBinary(path, url, wgcfSHA256)
}

func ensureWireproxy(path string) error {
	url := "https://github.com/windtf/wireproxy/releases/download/v" + wireproxyVersion +
		"/wireproxy_windows_amd64.tar.gz"
	if _, err := os.Stat(path); err == nil {
		return verifyFileSHA256(path, wireproxyBinarySHA256)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("check wireproxy binary: %w", err)
	}

	archive, err := downloadVerified(url, wireproxyArchiveSHA256, maxDownloadSize)
	if err != nil {
		return fmt.Errorf("download wireproxy v%s: %w", wireproxyVersion, err)
	}
	binary, err := extractWireproxyBinary(archive)
	if err != nil {
		return err
	}
	if err := verifyBytesSHA256(binary, wireproxyBinarySHA256); err != nil {
		return fmt.Errorf("verify wireproxy binary from archive: %w", err)
	}
	if err := writeExecutable(path, binary); err != nil {
		return fmt.Errorf("install wireproxy: %w", err)
	}
	return nil
}

func installVerifiedBinary(path, url, expectedSHA256 string) error {
	if _, err := os.Stat(path); err == nil {
		return verifyFileSHA256(path, expectedSHA256)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("check binary %s: %w", filepath.Base(path), err)
	}

	binary, err := downloadVerified(url, expectedSHA256, maxBinarySize)
	if err != nil {
		return fmt.Errorf("download %s: %w", filepath.Base(path), err)
	}
	if err := writeExecutable(path, binary); err != nil {
		return fmt.Errorf("install %s: %w", filepath.Base(path), err)
	}
	return nil
}

func downloadVerified(url, expectedSHA256 string, maxSize int64) ([]byte, error) {
	client := &http.Client{Timeout: 2 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("request release asset: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("release download returned HTTP %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("read release asset: %w", err)
	}
	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("release asset exceeds %d bytes", maxSize)
	}
	if err := verifyBytesSHA256(data, expectedSHA256); err != nil {
		return nil, err
	}
	return data, nil
}

func extractWireproxyBinary(archive []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("open wireproxy archive: %w", err)
	}
	defer gz.Close()

	reader := tar.NewReader(gz)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read wireproxy archive: %w", err)
		}
		if strings.EqualFold(filepath.Base(strings.ReplaceAll(header.Name, "\\", "/")), "wireproxy.exe") &&
			header.Typeflag == tar.TypeReg {
			if header.Size <= 0 || header.Size > maxBinarySize {
				return nil, fmt.Errorf("wireproxy executable has invalid size %d", header.Size)
			}
			binary, err := io.ReadAll(io.LimitReader(reader, maxBinarySize+1))
			if err != nil {
				return nil, fmt.Errorf("extract wireproxy executable: %w", err)
			}
			if int64(len(binary)) != header.Size {
				return nil, fmt.Errorf("wireproxy executable size mismatch")
			}
			return binary, nil
		}
	}
	return nil, fmt.Errorf("wireproxy.exe not found in release archive")
}

func writeExecutable(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "download-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if err := tmp.Chmod(0700); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func verifyFileSHA256(path, expected string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", filepath.Base(path), err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, maxBinarySize+1)); err != nil {
		return fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), expected) {
		return fmt.Errorf("SHA-256 mismatch for %s; remove it and retry to download a verified copy", filepath.Base(path))
	}
	return nil
}

func verifyBytesSHA256(data []byte, expected string) error {
	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), expected) {
		return fmt.Errorf("SHA-256 checksum mismatch")
	}
	return nil
}

func confirmWARPRegistration() (bool, error) {
	fmt.Fprintln(os.Stderr, "This will register a WARP device with Cloudflare and accept the WARP Terms of Service.")
	fmt.Fprintln(os.Stderr, "Terms: https://www.cloudflare.com/terms/")
	fmt.Fprint(os.Stderr, "Type YES to continue: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("read WARP registration confirmation: %w", err)
	}
	return strings.TrimSpace(line) == "YES", nil
}

func runWGCF(ctx context.Context, dir, executable string, args ...string) error {
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func reserveLocalAddress() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("reserve local WARP SOCKS5 port: %w", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		return "", fmt.Errorf("release local WARP SOCKS5 port: %w", err)
	}
	return addr, nil
}

func waitForListener(ctx context.Context, addr string, processDone chan error) error {
	deadline := time.NewTimer(warpStartupTimeout)
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
			return fmt.Errorf("wireproxy exited before opening its SOCKS5 listener: %w", processErr)
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("wireproxy did not open its SOCKS5 listener at %s within %s", addr, warpStartupTimeout)
		case <-ticker.C:
		}
	}
}

func verifyWARP(ctx context.Context, dialer proxy.ContextDialer) error {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, addr)
			},
		},
		Timeout: warpTraceRequestTimeout,
	}
	defer client.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.cloudflare.com/cdn-cgi/trace", nil)
	if err != nil {
		return fmt.Errorf("create WARP status request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("check WARP connection through Cloudflare trace: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Cloudflare trace returned HTTP %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return fmt.Errorf("read Cloudflare trace response: %w", err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		switch strings.TrimSpace(line) {
		case "warp=on", "warp=plus":
			fmt.Fprintln(os.Stderr, "WARP connection established:", strings.TrimSpace(line))
			return nil
		}
	}
	return fmt.Errorf("Cloudflare trace did not report WARP as enabled")
}
