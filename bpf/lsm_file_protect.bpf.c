// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// KernelSeal BPF-LSM: Protect /proc/$pid/{environ,mem,maps} from unauthorized reads
//
// Event and policy layouts come from kernelseal_common.h so this program and the
// Go user-space side cannot drift apart. Do not redeclare them here.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "kernelseal_common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define EPERM 1

// Longest name we classify is "environ" (7 chars + NUL)
#define MAX_PROC_FILE_LEN 16

// Ring buffer for audit events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB ring buffer
} events SEC(".maps");

// PIDs of KernelSeal processes, which must retain access to protected files
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);   // PID
    __type(value, __u8);  // 1 = allowed
} ks_allowed_pids SEC(".maps");

// Protected PIDs (processes that have received secrets)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);   // PID
    __type(value, __u8);  // 1 = protected
} protected_pids SEC(".maps");

// Policy configuration, written from user space
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ks_policy_config);
} policy_config SEC(".maps");

// Classify a /proc file name into a ks_access_type.
// Returns -1 when the name is not one of the files we guard.
static __always_inline int classify_proc_file(const char *f) {
    if (f[0] == 'e' && f[1] == 'n' && f[2] == 'v' && f[3] == 'i' &&
        f[4] == 'r' && f[5] == 'o' && f[6] == 'n' && f[7] == '\0')
        return KS_ACCESS_ENVIRON;

    if (f[0] == 'm' && f[1] == 'e' && f[2] == 'm' && f[3] == '\0')
        return KS_ACCESS_MEM;

    if (f[0] == 'm' && f[1] == 'a' && f[2] == 'p' && f[3] == 's' && f[4] == '\0')
        return KS_ACCESS_MAPS;

    return -1;
}

// Extract the PID from the parent directory of a /proc/<pid>/<file> dentry.
// Returns 0 when the parent is not purely numeric, which also rejects paths
// such as /proc/self/environ.
static __always_inline __u32 get_proc_dir_pid(struct dentry *dentry) {
    struct dentry *parent;
    bpf_core_read(&parent, sizeof(parent), &dentry->d_parent);
    if (!parent)
        return 0;

    struct qstr parent_name;
    bpf_core_read(&parent_name, sizeof(parent_name), &parent->d_name);

    const unsigned char *pname;
    bpf_core_read(&pname, sizeof(pname), &parent_name.name);
    if (!pname)
        return 0;

    char pid_str[16] = {};
    long len = bpf_probe_read_kernel_str(pid_str, sizeof(pid_str), pname);
    if (len <= 1) // len counts the NUL, so <= 1 means empty
        return 0;

    __u32 pid = 0;
    #pragma unroll
    for (int i = 0; i < 15; i++) {
        char c = pid_str[i];
        if (c == '\0')
            break;
        if (c < '0' || c > '9')
            return 0; // not a numeric directory
        pid = pid * 10 + (__u32)(c - '0');
    }

    return pid;
}

// Send an audit event to user space
static __always_inline void send_audit_event(
    __u32 pid, __u32 tid, __u32 uid, __u32 target_pid,
    __u8 event_type, __u8 access_type, const char *path)
{
    struct ks_lsm_event *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return;

    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = tid;
    event->uid = uid;
    event->target_pid = target_pid;
    event->event_type = event_type;
    event->access_type = access_type;
    event->reserved[0] = 0;
    event->reserved[1] = 0;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_probe_read_kernel_str(event->path, sizeof(event->path), path);

    bpf_ringbuf_submit(event, 0);
}

// LSM hook: file_open - block reads of a protected process's /proc files
SEC("lsm/file_open")
int BPF_PROG(ks_file_open, struct file *file) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;  // thread group leader == userspace PID
    __u32 tid = (__u32)pid_tgid; // kernel thread id
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    __u32 key = 0;
    struct ks_policy_config *policy = bpf_map_lookup_elem(&policy_config, &key);
    if (!policy || policy->enforce_mode == KS_MODE_DISABLED)
        return 0;

    // KernelSeal itself must keep access so it can resolve target processes
    __u8 *allowed = bpf_map_lookup_elem(&ks_allowed_pids, &pid);
    if (allowed && *allowed == 1)
        return 0;

    struct dentry *dentry;
    bpf_core_read(&dentry, sizeof(dentry), &file->f_path.dentry);
    if (!dentry)
        return 0;

    struct qstr d_name;
    bpf_core_read(&d_name, sizeof(d_name), &dentry->d_name);

    const unsigned char *name;
    bpf_core_read(&name, sizeof(name), &d_name.name);
    if (!name)
        return 0;

    // Zero-initialized so classify_proc_file never reads uninitialized stack
    char filename[MAX_PROC_FILE_LEN] = {};
    if (bpf_probe_read_kernel_str(filename, sizeof(filename), name) < 0)
        return 0;

    int access_type = classify_proc_file(filename);
    if (access_type < 0)
        return 0;

    __u8 guarded = 0;
    if (access_type == KS_ACCESS_ENVIRON)
        guarded = policy->block_environ;
    else if (access_type == KS_ACCESS_MEM)
        guarded = policy->block_mem;
    else if (access_type == KS_ACCESS_MAPS)
        guarded = policy->block_maps;

    __u32 target_pid = get_proc_dir_pid(dentry);
    if (target_pid == 0)
        return 0;

    __u8 *is_protected = bpf_map_lookup_elem(&protected_pids, &target_pid);
    if (!is_protected || *is_protected != 1)
        return 0;

    // A protected process may inspect itself when configured to
    int self_read = policy->allow_self_read && pid == target_pid;

    if (guarded && !self_read) {
        if (policy->enforce_mode == KS_MODE_ENFORCE) {
            send_audit_event(pid, tid, uid, target_pid,
                             KS_EVENT_BLOCKED, access_type, filename);
            return -EPERM;
        }

        // Audit mode: record what enforce mode would have blocked, but allow it
        send_audit_event(pid, tid, uid, target_pid,
                         KS_EVENT_AUDIT, access_type, filename);
        return 0;
    }

    if (policy->audit_all)
        send_audit_event(pid, tid, uid, target_pid,
                         KS_EVENT_AUDIT, access_type, filename);

    return 0;
}

// LSM hook: ptrace_access_check - block debuggers attaching to protected processes
SEC("lsm/ptrace_access_check")
int BPF_PROG(ks_ptrace_access_check, struct task_struct *child, unsigned int mode) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    __u32 key = 0;
    struct ks_policy_config *policy = bpf_map_lookup_elem(&policy_config, &key);
    if (!policy || policy->enforce_mode == KS_MODE_DISABLED || !policy->block_ptrace)
        return 0;

    __u8 *allowed = bpf_map_lookup_elem(&ks_allowed_pids, &pid);
    if (allowed && *allowed == 1)
        return 0;

    // protected_pids is keyed by userspace PID, so compare against the target's
    // thread group leader. Reading child->pid would miss attaches aimed at a
    // non-leader thread of a protected process.
    __u32 child_pid;
    bpf_core_read(&child_pid, sizeof(child_pid), &child->tgid);

    __u8 *is_protected = bpf_map_lookup_elem(&protected_pids, &child_pid);
    if (!is_protected || *is_protected != 1)
        return 0;

    if (policy->allow_self_read && pid == child_pid)
        return 0;

    if (policy->enforce_mode == KS_MODE_ENFORCE) {
        send_audit_event(pid, tid, uid, child_pid,
                         KS_EVENT_BLOCKED, KS_ACCESS_PTRACE, "ptrace");
        return -EPERM;
    }

    send_audit_event(pid, tid, uid, child_pid,
                     KS_EVENT_AUDIT, KS_ACCESS_PTRACE, "ptrace");
    return 0;
}
