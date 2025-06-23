#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Minimal execve hook - just logs PID (replace with perf events later)
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    bpf_printk("X00: execve() called by pid %d\n", bpf_get_current_pid_tgid() >> 32);
    return 0;
}
