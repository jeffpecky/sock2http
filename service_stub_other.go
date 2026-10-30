//go:build !windows && !linux

package main

import "fmt"

// Platforms with neither a Windows SCM nor Linux systemd: -service install
// refuses rather than half-working, and -svc is a no-op alias for console mode
// (there is no service manager here to run the wrapper anyway).

// svcStop is Windows-only plumbing; elsewhere a service manager signals the
// process itself (SIGTERM), which the run() signal hook already handles.
var svcStop = make(chan struct{})

func runService() error {
	logWarn("svc_without_scm", "note", "-svc outside the service manager; running in console mode")
	return run()
}

func installService(flags []string) error {
	return fmt.Errorf("-service install is not supported on this platform; run the binary directly under a supervisor")
}

func uninstallService() error {
	return fmt.Errorf("-service uninstall is not supported on this platform")
}
