//go:build windows

// Service entry point. SCM runs `socks2http.exe -svc`; every child process we
// spawn (wireproxy, gh codespace ssh) dies with this process, so a service Stop
// leaves no half-torn-down tunnels behind.

package main

import (
	"sync"

	"golang.org/x/sys/windows/svc"
)

// svcStop is closed when the service is being told to shut down (SCM Stop or
// run() finishing); runDone is closed when run() has actually returned.
var (
	svcStop = make(chan struct{})
	svcOnce sync.Once
	svcDone = make(chan struct{})
)

func runService() error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !isService {
		// Launched with -svc outside the SCM: console mode instead, so `-svc`
		// alone never silently strands the user out of a foreground process.
		logWarn("svc_without_scm", "note", "-svc outside the service manager; running in console mode (install with -service install)")
		return run()
	}
	return svc.Run(serviceName, &serviceHandler{})
}

type serviceHandler struct{}

func (h *serviceHandler) Execute(args []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	s <- svc.Status{State: svc.StartPending}

	// run() in its own goroutine; its error is logged, not returned to the SCM,
	// because by the time run() fails at startup the SCM has already seen us
	// report Running. Closing svcStop cancels run()'s context exactly like
	// Ctrl+C would.
	go func() {
		defer close(svcDone)
		defer svcOnce.Do(func() { close(svcStop) })
		if err := run(); err != nil {
			logErr("service_run_failed", "error", err.Error())
		}
	}()
	s <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for req := range r {
		switch req.Cmd {
		case svc.Interrogate:
			s <- req.CurrentStatus
		case svc.Stop, svc.Shutdown:
			s <- svc.Status{State: svc.StopPending}
			svcOnce.Do(func() { close(svcStop) })
			// run() tears down listeners and child tunnels (wireproxy, codespace
			// ssh die with the process anyway); wait so a service Restart never
			// races the old process still holding the ports.
			<-svcDone
			s <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}
	return false, 0
}
