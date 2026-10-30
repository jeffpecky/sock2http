//go:build windows

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var (
	iphlpapiDLL               = syscall.NewLazyDLL("iphlpapi.dll")
	getExtendedTcpTableProc   = iphlpapiDLL.NewProc("GetExtendedTcpTable")
	kernel32DLL               = syscall.NewLazyDLL("kernel32.dll")
	openProcessProc           = kernel32DLL.NewProc("OpenProcess")
	queryFullProcessImageProc = kernel32DLL.NewProc("QueryFullProcessImageNameW")
	closeHandleProc           = kernel32DLL.NewProc("CloseHandle")
)

const (
	tcpTableOwnerPIDListener = 3
	afInet                   = 2
	afInet6                  = 23
	tcpStateListen           = 2
	processQueryLimitedInfo  = 0x1000
)

type tcpRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	PID        uint32
}

type tcp6RowOwnerPID struct {
	LocalAddr     [16]byte
	LocalScopeID  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeID uint32
	RemotePort    uint32
	State         uint32
	PID           uint32
}

func reclaimAppPort(addr string) error {
	_, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("parse listening address: %w", err)
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil {
		return fmt.Errorf("parse listening port: %w", err)
	}

	pids, err := dashboardListenerPIDs(uint16(port))
	if err != nil {
		return fmt.Errorf("inspect port %s: %w", addr, err)
	}
	if len(pids) == 0 {
		return nil
	}

	currentPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find current executable: %w", err)
	}
	currentPath, err = filepath.Abs(currentPath)
	if err != nil {
		return fmt.Errorf("resolve current executable path: %w", err)
	}

	for _, pid := range pids {
		if pid == uint32(os.Getpid()) {
			return fmt.Errorf("port %s is already held by this process", addr)
		}
		path, err := processImagePath(pid)
		if err != nil {
			return fmt.Errorf("identify process %d using port %s: %w", pid, addr, err)
		}
		if !strings.EqualFold(filepath.Clean(path), filepath.Clean(currentPath)) {
			return fmt.Errorf("port %s is used by another application (PID %d, %s); refusing to stop it", addr, pid, path)
		}
	}

	for _, pid := range pids {
		output, err := exec.Command("taskkill.exe", "/PID", fmt.Sprint(pid), "/T", "/F").CombinedOutput()
		if err != nil {
			return fmt.Errorf("stop previous sock2http process %d: %w: %s", pid, err, strings.TrimSpace(string(output)))
		}
		logWarn("previous_instance_stopped", "pid", pid, "addr", addr)
	}
	return nil
}

func dashboardListenerPIDs(port uint16) ([]uint32, error) {
	var pids []uint32
	for _, family := range []uint32{afInet, afInet6} {
		data, err := tcpOwnerPIDTable(family)
		if err != nil {
			return nil, fmt.Errorf("list TCP port owners: %w", err)
		}
		if len(data) < 4 {
			return nil, fmt.Errorf("read TCP owner table: truncated response")
		}
		count := *(*uint32)(unsafe.Pointer(&data[0]))
		offset := uintptr(4)
		for i := uint32(0); i < count; i++ {
			if family == afInet {
				rowSize := unsafe.Sizeof(tcpRowOwnerPID{})
				if uintptr(len(data)) < offset+rowSize {
					return nil, fmt.Errorf("read IPv4 TCP owner table: truncated response")
				}
				row := (*tcpRowOwnerPID)(unsafe.Pointer(&data[offset]))
				if row.State == tcpStateListen && decodeTCPPort(row.LocalPort) == port {
					pids = appendUniquePID(pids, row.PID)
				}
				offset += rowSize
			} else {
				rowSize := unsafe.Sizeof(tcp6RowOwnerPID{})
				if uintptr(len(data)) < offset+rowSize {
					return nil, fmt.Errorf("read IPv6 TCP owner table: truncated response")
				}
				row := (*tcp6RowOwnerPID)(unsafe.Pointer(&data[offset]))
				if row.State == tcpStateListen && decodeTCPPort(row.LocalPort) == port {
					pids = appendUniquePID(pids, row.PID)
				}
				offset += rowSize
			}
		}
	}
	return pids, nil
}

func tcpOwnerPIDTable(family uint32) ([]byte, error) {
	var size uint32
	result, _, _ := getExtendedTcpTableProc.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(family), tcpTableOwnerPIDListener, 0)
	if result != uintptr(syscall.ERROR_INSUFFICIENT_BUFFER) && result != 0 {
		return nil, syscall.Errno(result)
	}
	if size == 0 {
		return []byte{}, nil
	}
	data := make([]byte, size)
	result, _, _ = getExtendedTcpTableProc.Call(uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(family), tcpTableOwnerPIDListener, 0)
	if result != 0 {
		return nil, syscall.Errno(result)
	}
	return data[:size], nil
}

func decodeTCPPort(port uint32) uint16 {
	value := uint16(port)
	return value>>8 | value<<8
}

func appendUniquePID(pids []uint32, pid uint32) []uint32 {
	for _, existing := range pids {
		if existing == pid {
			return pids
		}
	}
	return append(pids, pid)
}

func processImagePath(pid uint32) (string, error) {
	handle, _, callErr := openProcessProc.Call(processQueryLimitedInfo, 0, uintptr(pid))
	if handle == 0 {
		return "", callErr
	}
	defer closeHandleProc.Call(handle)

	buffer := make([]uint16, 1024)
	size := uint32(len(buffer))
	ok, _, callErr := queryFullProcessImageProc.Call(handle, 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)))
	if ok == 0 {
		return "", callErr
	}
	return syscall.UTF16ToString(buffer[:size]), nil
}
