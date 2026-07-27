package server

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// peerCred returns the kernel's view of who is on the other end of a unix
// socket. Unlike anything in the request body, these values cannot be forged by
// the caller.
func peerCred(conn *net.UnixConn) (*syscall.Ucred, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("obtaining raw conn: %w", err)
	}

	var (
		cred    *syscall.Ucred
		credErr error
	)
	ctrlErr := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if ctrlErr != nil {
		return nil, fmt.Errorf("control: %w", ctrlErr)
	}
	if credErr != nil {
		return nil, fmt.Errorf("SO_PEERCRED: %w", credErr)
	}
	return cred, nil
}

// processStartTime reads field 22 of /proc/<pid>/stat, the process start time in
// clock ticks since boot.
//
// A PID alone is not a stable identifier: the caller could exit between the
// SO_PEERCRED read and the point where we mark the PID protected, and the kernel
// could hand that number to an unrelated process. Pairing the PID with its start
// time detects that recycling.
func processStartTime(pid uint32) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}

	// Field 2 is the executable name in parentheses and may itself contain
	// spaces or parentheses, so parse from after the final ')'.
	idx := bytes.LastIndexByte(data, ')')
	if idx < 0 || idx+2 >= len(data) {
		return 0, fmt.Errorf("malformed /proc/%d/stat", pid)
	}

	fields := strings.Fields(string(data[idx+2:]))

	// fields[0] is field 3 (state), so field N sits at index N-3.
	const startTimeIndex = 22 - 3
	if len(fields) <= startTimeIndex {
		return 0, fmt.Errorf("/proc/%d/stat has %d fields after comm, need %d",
			pid, len(fields), startTimeIndex+1)
	}

	return strconv.ParseUint(fields[startTimeIndex], 10, 64)
}

// processExe resolves a process's executable path, for audit logging only.
func processExe(pid uint32) string {
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "unknown"
	}
	return target
}

// processCgroup returns a process's cgroup path, for audit logging only.
func processCgroup(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "unknown"
	}

	// Prefer the unified (v2) entry, which is prefixed "0::".
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.HasPrefix(line, "0::") {
			return strings.TrimPrefix(line, "0::")
		}
	}

	// Fall back to the first entry's path component.
	first := strings.SplitN(strings.TrimSpace(string(data)), "\n", 2)[0]
	if parts := strings.SplitN(first, ":", 3); len(parts) == 3 {
		return parts[2]
	}
	return "unknown"
}

// describePeer renders the kernel-verified identity of a caller for audit logs.
func describePeer(cred *syscall.Ucred) string {
	pid := uint32(cred.Pid)
	return fmt.Sprintf("pid=%d uid=%d gid=%d exe=%s cgroup=%s",
		pid, cred.Uid, cred.Gid, processExe(pid), processCgroup(pid))
}
