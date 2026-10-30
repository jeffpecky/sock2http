//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Windows-service mode so the proxy lives in services.msc and restarts without
// a terminal; SCM Stop does the same clean shutdown as Ctrl+C.
//
// `socks2http.exe -service install -warp …` bakes those flags into the service
// command line (SCM runs `socks2http.exe -svc`), across reboots too;
// `-service uninstall` stops and removes it. Running without -svc behaves
// exactly as before, so console use is unaffected.

const serviceName = "sock2http"

func serviceMgr() (*mgr.Mgr, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, fmt.Errorf("connect service manager (run from an elevated terminal): %w", err)
	}
	return m, nil
}

func installService(flags []string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return err
	}
	if base := filepath.Base(exe); !strings.EqualFold(base, "socks2http.exe") {
		// SCM shows this name; a different binary name is confusing to manage.
		logWarn("service_binary_name", "binary", base, "expected", "socks2http.exe")
	}

	m, err := serviceMgr()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("service %q already exists; run -service uninstall first", serviceName)
	}

	// mgr.CreateService passes args through syscall.EscapeArg, so flags with
	// spaces or quotes survive the round-trip into ImagePath.
	cfg, err := m.CreateService(serviceName, exe, mgr.Config{StartType: mgr.StartAutomatic},
		append([]string{"-svc"}, flags...)...)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer cfg.Close()

	// Auto-restart on crash; the reset period is short so a genuine crash loop
	// still surfaces in Event Viewer instead of hiding behind restarts.
	if err := cfg.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
	}, 60); err != nil {
		logWarn("service_recovery_not_set", "error", err.Error())
	}

	if err := cfg.Start(); err != nil {
		// Installed-but-not-started is still a success state; say so.
		logWarn("service_start_failed", "error", err.Error())
		fmt.Fprintln(os.Stderr, "service installed but not started; start it in services.msc")
		return nil
	}
	fmt.Fprintf(os.Stderr,
		"service %s installed and started. Restart without Ctrl+C: Restart in services.msc,\n"+
			"or `sc stop %s` then `sc start %s`, or POST /__rotate for egress rotation.\n",
		serviceName, serviceName, serviceName)
	return nil
}

func uninstallService() error {
	m, err := serviceMgr()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %q is not installed", serviceName)
	}
	defer s.Close()

	// Stop first so tunnels and listeners close cleanly before the service is
	// deleted; already-stopped is fine.
	if st, _ := s.Query(); st.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err != nil {
			logWarn("service_stop_on_uninstall", "error", err.Error())
		}
		waitSvcStopped(s, 15*time.Second)
	}
	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}
	fmt.Fprintf(os.Stderr, "service %s uninstalled\n", serviceName)
	return nil
}

func waitSvcStopped(s *mgr.Service, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if st, err := s.Query(); err != nil || st.State == svc.Stopped {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
}
