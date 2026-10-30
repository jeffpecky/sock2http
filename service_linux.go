//go:build linux

package main

// Linux service support via systemd, chosen because it ships with every distro
// this targets; no extra daemon (nssm, supervisord) to make the user install.
//
// `socks2http -service install -warp …` writes a unit with those flags baked
// into ExecStart, ready for `systemctl restart sock2http` — restart without a
// terminal, restart-on-failure for crashes, and Stop delivers SIGTERM to the
// cgroup, so child wireproxy/codespace tunnels do not survive the stop.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	serviceName = "sock2http"
	unitPath    = "/etc/systemd/system/sock2http.service"
)

// svcStop: systemd shuts the service down by signalling the process (SIGTERM
// via the cgroup), which stopOnSignal already handles — no in-process stop
// channel is needed, so this is a never-closed placeholder like console mode.
var svcStop = make(chan struct{})

// runService exists for symmetry with the Windows build; -svc is not part of
// the systemd story, and arriving here means a flag was misused.
func runService() error {
	logWarn("svc_without_scm", "note", "-svc is a Windows-service flag; on Linux use -service install (systemd)")
	return run()
}

func installService(flags []string) error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("-service install needs systemd (systemctl not on PATH); run the binary directly or use another supervisor")
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return err
	}

	parts := make([]string, 0, len(flags)+1)
	for _, f := range flags {
		parts = append(parts, shellQuote(f))
	}
	// User= set so the config paths are the calling user's ~/.config, matching
	// console runs — a service running as root would look at /root/.config and
	// silently see none of the dashboard's saved tokens.
	user := os.Getenv("SUDO_USER")
	userLine := ""
	if user != "" {
		userLine = fmt.Sprintf("User=%s\n", user)
	}

	unit := fmt.Sprintf(`[Unit]
Description=sock2http HTTP proxy with rotatable egress
After=network-online.target
Wants=network-online.target

[Service]
%sExecStart=%s %s
Restart=on-failure
RestartSec=5
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
`, userLine, shellQuote(exe), strings.Join(parts, " "))

	if err := os.WriteFile(unitPath, []byte(unit), 0644); err != nil {
		return fmt.Errorf("write %s (re-run with sudo): %w", unitPath, err)
	}
	for _, args := range [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", "--now", serviceName},
	} {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	fmt.Fprintf(os.Stderr,
		"service %s installed and started. Restart without Ctrl+C: `sudo systemctl restart %s`,\n"+
			"or `journalctl -u %s -f` to watch the log.\n", serviceName, serviceName, serviceName)
	return nil
}

func uninstallService() error {
	_ = exec.Command("systemctl", "disable", "--now", serviceName).Run()
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s (re-run with sudo): %w", unitPath, err)
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()
	fmt.Fprintf(os.Stderr, "service %s uninstalled\n", serviceName)
	return nil
}

// shellQuote single-quotes for a systemd ExecStart line, which parses like a
// shell command line for a single executable.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
