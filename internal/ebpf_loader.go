package internal

import (
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func LoadAndAttachExecHook() {
	spec, err := ebpf.LoadCollectionSpec("bpf/exec_monitor.bpf.o")
	if err != nil {
		log.Fatalf("failed to load eBPF spec: %v", err)
	}

	objs := struct {
		HandleExecve *ebpf.Program `ebpf:"handle_execve"`
	}{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("failed to assign programs: %v", err)
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecve, nil)
	if err != nil {
		log.Fatalf("failed to attach tracepoint: %v", err)
	}

	log.Println("✅ eBPF execve hook attached.")
	defer tp.Close()
	select {}
}
