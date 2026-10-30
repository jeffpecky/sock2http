package main

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// egressPool owns the active upstream and decides when to fall back.
//
// Order of preference: a codespace (rotates cheaply, dedicated egress IP) and,
// once every GitHub account is out of quota, WARP. The fallback is one-way for
// the life of the process: a codespace exhausted its accounts, so retrying it
// on every rotation would just spend another failed create.
type egressPool struct {
	mu sync.Mutex

	cs         *codespaceManager
	warp       *warpManager
	token      []string
	csFallback bool

	lastRotate time.Time
	rotating   bool
}

const egressCooldown = 60 * time.Second

// egressDrainTimeout is how long rotate() waits for live connections to end
// before proceeding anyway. Short enough that a request-triggered rotation is
// still useful, long enough that an idle-pool socket usually closes first.
const egressDrainTimeout = 10 * time.Second

// drainDialer waits for the dialer to report idle, returning false on timeout
// or cancellation.
func drainDialer(ctx context.Context, d *swapDialer, timeout time.Duration) bool {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		if d.idle() {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-deadline.C:
			return d.idle()
		case <-ticker.C:
		}
	}
}

func (p *egressPool) kind() string {
	if p == nil {
		return "none"
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cs != nil {
		return p.cs.kind()
	}
	if p.warp != nil {
		return p.warp.kind()
	}
	return "none"
}

func (p *egressPool) exitIP() string {
	if p == nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cs != nil && p.cs.current != nil {
		return p.cs.current.address()
	}
	if p.warp != nil {
		return p.warp.address()
	}
	return ""
}

// egress returns the full v4/v6 picture for status reporting.
func (p *egressPool) egress() egressInfo {
	if p == nil {
		return egressInfo{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cs != nil && p.cs.current != nil {
		return p.cs.current.egress
	}
	if p.warp != nil {
		return p.warp.egress
	}
	return egressInfo{}
}

func (p *egressPool) upstream() *swapDialer {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cs != nil {
		return p.cs.upstream()
	}
	if p.warp != nil {
		return p.warp.upstream()
	}
	return nil
}

func (p *egressPool) stop() {
	if p == nil {
		return
	}
	p.mu.Lock()
	cs, w := p.cs, p.warp
	p.cs, p.warp = nil, nil
	p.mu.Unlock()
	if cs != nil {
		cs.stop()
	}
	if w != nil {
		w.stop()
	}
}

// rotate swaps the exit IP, falling back to WARP when codespaces are unusable.
func (p *egressPool) rotate(ctx context.Context) (string, string, error) {
	if p == nil {
		return "", "", fmt.Errorf("no egress upstream configured")
	}
	p.mu.Lock()
	if p.rotating {
		p.mu.Unlock()
		return "", "", errRotationBusy
	}
	// A long-lived client (opencode holds upstream sockets open indefinitely)
	// would block rotation forever under a hard "must be idle" rule — and then
	// the rotation that clears a 429 can never run. So drain briefly, then
	// proceed regardless: the cost is that the in-flight request fails and the
	// client retries on the new egress, which is exactly what a rotation is for.
	if d := p.currentDialerLocked(); d != nil && !d.idle() {
		before := d.active.Load()
		p.mu.Unlock()
		if !drainDialer(ctx, d, egressDrainTimeout) {
			logWarn("rotate_with_live_connections",
				"inFlight", d.active.Load(), "waitedSeconds", int(egressDrainTimeout.Seconds()))
		} else {
			logInfo("rotated_after_drain", "previouslyInFlight", before)
		}
		p.mu.Lock()
	}
	if wait := egressCooldown - time.Since(p.lastRotate); wait > 0 {
		p.mu.Unlock()
		return "", "", fmt.Errorf("%w (cooldown %s remaining)", errRotationBusy, wait.Round(time.Second))
	}
	p.rotating = true
	cs, csFallback, w := p.cs, p.csFallback, p.warp
	p.mu.Unlock()

	defer func() {
		p.mu.Lock()
		p.rotating = false
		p.lastRotate = time.Now()
		p.mu.Unlock()
	}()

	// Already on WARP: rotate it in place.
	if cs == nil && w != nil {
		return w.rotate(ctx)
	}
	if cs == nil {
		return "", "", fmt.Errorf("no egress upstream configured")
	}

	oldIP, newIP, err := cs.rotate(ctx)
	if err == nil {
		return oldIP, newIP, nil
	}
	if !csFallback || !isQuotaError(err.Error()) {
		return oldIP, newIP, err
	}

	// Every GitHub account is out of quota: fall back to WARP for the rest of
	// the process lifetime.
	logWarn("codespace_quota_exhausted", "error", err.Error(), "fallingBackTo", "warp")
	cs.stop()

	wm, werr := startWarpManager(ctx, false)
	if werr != nil {
		return oldIP, "", fmt.Errorf("codespace quota exhausted (%v) and WARP unavailable (%v)", err, werr)
	}

	p.mu.Lock()
	p.cs = nil
	p.warp = wm
	p.mu.Unlock()

	// WARP starts on its own egress already; no rotation needed yet.
	return oldIP, wm.ip, nil
}

func (p *egressPool) currentDialerLocked() *swapDialer {
	if p.cs != nil {
		return p.cs.upstream()
	}
	if p.warp != nil {
		return p.warp.upstream()
	}
	return nil
}
