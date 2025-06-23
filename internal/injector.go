package internal

import "log"

func InjectSecrets(pid int) {
	// TODO: use /proc/$pid/mem or remote mmap w/ pwrite
	log.Printf("🧪 [X00] Would inject secrets into PID %d\n", pid)
}
