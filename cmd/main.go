package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"x00/internal"
)

func main() {
	log.Println("🚀 Starting X00 Sidecar...")

	internal.ApplyFileProtectionPolicy()

	go internal.LoadAndAttachExecHook()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	log.Println("🛑 Shutting down X00")
}
