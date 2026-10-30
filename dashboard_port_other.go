//go:build !windows

package main

import "fmt"

func reclaimAppPort(addr string) error {
	return fmt.Errorf("automatic port recovery is only supported on Windows")
}
