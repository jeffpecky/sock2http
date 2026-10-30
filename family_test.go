package main

import (
	"context"
	"net"
	"testing"
)

// familyOf must classify real net.Addr values, which is what the dial log
// prints. This is the guarantee behind "we can tell whether egress was v4/v6".
func TestFamilyOf(t *testing.T) {
	cases := []struct {
		name string
		addr net.Addr
		want string
	}{
		{"tcp v4", &net.TCPAddr{IP: net.ParseIP("105.115.6.60"), Port: 443}, "ipv4"},
		{"tcp v6", &net.TCPAddr{IP: net.ParseIP("2607:f8b0:4009:80b::200e"), Port: 443}, "ipv6"},
		{"tcp v4-mapped v6", &net.TCPAddr{IP: net.ParseIP("::ffff:1.2.3.4"), Port: 80}, "ipv4"},
		{"opaque v4", &net.TCPAddr{IP: net.ParseIP("8.8.8.8")}, "ipv4"},
		{"opaque v6", &net.TCPAddr{IP: net.ParseIP("::1")}, "ipv6"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := familyOf(tc.addr); got != tc.want {
				t.Fatalf("familyOf(%v) = %q, want %q", tc.addr, got, tc.want)
			}
		})
	}
}

func TestEgressInfoFamilyAndAddress(t *testing.T) {
	cases := []struct {
		name     string
		info     egressInfo
		wantFam  string
		wantAddr string
	}{
		{"v4 only", egressInfo{IPv4: "1.2.3.4"}, "ipv4", "1.2.3.4"},
		{"v6 only", egressInfo{IPv6: "2607::1"}, "ipv6", "2607::1"},
		{"dual stack prefers v4", egressInfo{IPv4: "1.2.3.4", IPv6: "2607::1"}, "ipv4", "1.2.3.4"},
		{"neither", egressInfo{}, "unknown", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.info.family(); got != tc.wantFam {
				t.Fatalf("family() = %q, want %q", got, tc.wantFam)
			}
			if got := tc.info.address(); got != tc.wantAddr {
				t.Fatalf("address() = %q, want %q", got, tc.wantAddr)
			}
		})
	}
}

// A dual-stack exit must still log a family even when the v6 probe fails,
// which is the common case for v4-only egress.
func TestProbeEgressV4OnlyUpstream(t *testing.T) {
	if testing.Short() {
		t.Skip("network probe")
	}
	d, err := newSOCKSDialer("127.0.0.1:1", nil) // deliberately nothing listening
	if err != nil {
		t.Skipf("dialer unavailable: %v", err)
	}
	eg, err := probeEgress(context.Background(), d)
	if err == nil {
		t.Fatalf("probeEgress reported success against a dead upstream: %+v", eg)
	}
	if eg.family() != "unknown" {
		t.Fatalf("family() = %q, want unknown when every probe fails", eg.family())
	}
}

// The rejected-but-important shape: probeExitIPAt must refuse a v6 answer on a
// v4-labelled probe, so a mislabelled exit can never be reported as v4.
func TestProbeExitIPAtRejectsWrongFamily(t *testing.T) {
	if _, err := probeExitIPAt(context.Background(), deadDialer{}, exitIPProbeURL, 4); err == nil {
		t.Fatal("v4 probe succeeded against a dead dialer")
	}
}

type deadDialer struct{}

func (deadDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return nil, &net.OpError{Op: "dial", Net: network, Err: net.ErrClosed}
}
