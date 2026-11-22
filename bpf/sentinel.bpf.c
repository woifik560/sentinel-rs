// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 Sentinel-RS Authors */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "sentinel_types.h"

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

#ifndef bpf_ntohs
#define bpf_ntohs(x) __builtin_bswap16(x)
#endif

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/* =========================================================================
 * BPF MAPS DEFINITIONS
 * ========================================================================= */

/// RingBuffer for streaming real-time events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/// Dynamic Flow Context: mark -> flow_context (Zero-Race synchronous lookup)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct flow_context);
} flow_mark_ctx SEC(".maps");

/// Allowed TGIDs (Fast-path clean process bypass)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} allowed_tgids SEC(".maps");

/// Monotonic flow sequence generator
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} flow_seq SEC(".maps");

/* =========================================================================
 * HELPER FUNCTIONS
 * ========================================================================= */

static __always_inline void init_header(struct raw_ebpf_header *hdr, __u32 event_type) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    hdr->event_type = event_type;
    hdr->cpu_id = bpf_get_smp_processor_id();
    hdr->timestamp_ns = bpf_ktime_get_ns();
    hdr->pid = (__u32)pid_tgid;
    hdr->tgid = (__u32)(pid_tgid >> 32);
    hdr->uid = (__u32)bpf_get_current_uid_gid();
}

static __always_inline __u32 next_flow_mark(bool reval) {
    __u32 key = 0;
    __u32 *seq = bpf_map_lookup_elem(&flow_seq, &key);
    __u32 val = 1;
    if (seq) {
        val = __sync_fetch_and_add(seq, 1);
    }
    val &= 0x007FFFFF; // 23-bit flow ID
    __u32 mark = 0x5E000000 | val;
    if (reval) {
        mark |= 0x00800000;
    }
    return mark;
}

/* =========================================================================
 * LSM HOOK: file_open
 * ========================================================================= */
SEC("lsm/file_open")
int BPF_PROG(sentinel_file_open, struct file *file) {
    if (!file)
        return 0;

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);

    struct raw_file_open_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    init_header(&evt->hdr, EVENT_TYPE_FILE_OPEN);
    evt->tgid = tgid;
    evt->uid = (__u32)bpf_get_current_uid_gid();
    evt->flags = BPF_CORE_READ(file, f_flags);
    evt->ino = BPF_CORE_READ(inode, i_ino);

    struct super_block *sb = BPF_CORE_READ(inode, i_sb);
    if (sb) {
        evt->dev = BPF_CORE_READ(sb, s_dev);
    } else {
        evt->dev = 0;
    }

    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (dentry) {
        const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
        if (name) {
            bpf_probe_read_kernel_str(evt->path, sizeof(evt->path), name);
        }
    }
    evt->path_len = sizeof(evt->path);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* =========================================================================
 * LSM HOOK: file_permission
 * ========================================================================= */
SEC("lsm/file_permission")
int BPF_PROG(sentinel_file_permission, struct file *file, int mask) {
    if (!file)
        return 0;

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;

    umode_t mode = BPF_CORE_READ(inode, i_mode);
    bool is_pipe = (mode & 0010000) != 0; // S_ISFIFO
    bool is_fifo = is_pipe;

    struct raw_file_perm_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    init_header(&evt->hdr, EVENT_TYPE_FILE_PERMISSION);
    evt->tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    evt->uid = (__u32)bpf_get_current_uid_gid();
    evt->mask = (__u32)mask;
    evt->ino = BPF_CORE_READ(inode, i_ino);
    evt->is_pipe = is_pipe ? 1 : 0;
    evt->is_fifo = is_fifo ? 1 : 0;

    struct super_block *sb = BPF_CORE_READ(inode, i_sb);
    evt->dev = sb ? BPF_CORE_READ(sb, s_dev) : 0;

    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (dentry) {
        const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
        if (name) {
            bpf_probe_read_kernel_str(evt->path, sizeof(evt->path), name);
        }
    }
    evt->path_len = sizeof(evt->path);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* =========================================================================
 * LSM HOOK: bprm_check_security
 * ========================================================================= */
SEC("lsm/bprm_check_security")
int BPF_PROG(sentinel_bprm_check_security, struct linux_binprm *bprm) {
    if (!bprm || !bprm->file)
        return 0;

    struct inode *inode = BPF_CORE_READ(bprm->file, f_inode);
    if (!inode)
        return 0;

    struct raw_bprm_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    init_header(&evt->hdr, EVENT_TYPE_BPRM_CHECK);
    evt->tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    evt->uid = (__u32)bpf_get_current_uid_gid();
    evt->ino = BPF_CORE_READ(inode, i_ino);

    struct super_block *sb = BPF_CORE_READ(inode, i_sb);
    evt->dev = sb ? BPF_CORE_READ(sb, s_dev) : 0;

    // Detect memfd execution
    const char *interp = BPF_CORE_READ(bprm, filename);
    if (interp) {
        bpf_probe_read_kernel_str(evt->exe_path, sizeof(evt->exe_path), interp);
    }
    evt->exe_path_len = sizeof(evt->exe_path);

    // Simple memfd signature check
    evt->is_memfd = (evt->exe_path[0] == 'm' && evt->exe_path[1] == 'e' &&
                     evt->exe_path[2] == 'm' && evt->exe_path[3] == 'f' &&
                     evt->exe_path[4] == 'd') ? 1 : 0;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* =========================================================================
 * LSM HOOK: socket_connect
 * ========================================================================= */
SEC("lsm/socket_connect")
int BPF_PROG(sentinel_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
    if (!sock || !address || addrlen < sizeof(struct sockaddr_in))
        return 0;

    __u16 family = BPF_CORE_READ(address, sa_family);
    if (family != AF_INET && family != AF_INET6)
        return 0;

    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);

    // Check if whitelisted in allowed_tgids map (Fast-Path gigabit throughput)
    __u8 *allowed = bpf_map_lookup_elem(&allowed_tgids, &tgid);
    if (allowed && *allowed == 1) {
        return 0;
    }

    // Allocate dynamic flow mark with reval flag
    __u32 mark = next_flow_mark(false);

    // Synchronously write FlowContext into flow_mark_ctx map
    struct flow_context fctx = {};
    fctx.mark = mark;
    fctx.tgid = tgid;
    fctx.pid = (__u32)bpf_get_current_pid_tgid();
    fctx.uid = (__u32)bpf_get_current_uid_gid();
    bpf_map_update_elem(&flow_mark_ctx, &mark, &fctx, BPF_ANY);

    // Set mark on socket
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (sk) {
        sk->sk_mark = mark;
    }

    struct raw_connect_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    init_header(&evt->hdr, EVENT_TYPE_SOCKET_CONNECT);
    evt->tgid = tgid;
    evt->addr_family = family;
    evt->so_mark = mark;

    if (family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)address;
        evt->dst_ipv4 = BPF_CORE_READ(sin, sin_addr.s_addr);
        evt->dst_port = bpf_ntohs(BPF_CORE_READ(sin, sin_port));
        evt->protocol = 6; // TCP
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* =========================================================================
 * LSM HOOK: socket_sendmsg
 * ========================================================================= */
SEC("lsm/socket_sendmsg")
int BPF_PROG(sentinel_socket_sendmsg, struct socket *sock, struct msghdr *msg, size_t size) {
    if (!sock)
        return 0;

    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        return 0;

    __u32 existing_mark = BPF_CORE_READ(sk, sk_mark);
    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);

    struct raw_sendmsg_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    init_header(&evt->hdr, EVENT_TYPE_SOCKET_SENDMSG);
    evt->tgid = tgid;
    evt->so_mark = existing_mark;
    evt->is_preopened = (existing_mark == 0) ? 1 : 0;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* =========================================================================
 * LSM HOOK: ptrace_access_check
 * ========================================================================= */
SEC("lsm/ptrace_access_check")
int BPF_PROG(sentinel_ptrace_access_check, struct task_struct *child, unsigned int mode) {
    if (!child)
        return 0;

    __u32 tracer_tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u32 tracee_tgid = BPF_CORE_READ(child, tgid);

    struct raw_ptrace_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    init_header(&evt->hdr, EVENT_TYPE_PTRACE_CHECK);
    evt->tracer_tgid = tracer_tgid;
    evt->tracee_tgid = tracee_tgid;
    evt->mode = mode;
    evt->is_blocked = 0;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* =========================================================================
 * LSM HOOK: mmap_file
 * ========================================================================= */
SEC("lsm/mmap_file")
int BPF_PROG(sentinel_mmap_file, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags) {
    if (!file)
        return 0;

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;

    struct raw_mmap_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    init_header(&evt->hdr, EVENT_TYPE_MMAP_FILE);
    evt->tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    evt->uid = (__u32)bpf_get_current_uid_gid();
    evt->prot = (__u32)prot;
    evt->flags = (__u32)flags;
    evt->ino = BPF_CORE_READ(inode, i_ino);

    struct super_block *sb = BPF_CORE_READ(inode, i_sb);
    evt->dev = sb ? BPF_CORE_READ(sb, s_dev) : 0;

    evt->is_exec = (prot & 0x4) ? 1 : 0; // PROT_EXEC
    evt->is_write_shared = ((prot & 0x2) && (flags & 0x1)) ? 1 : 0; // PROT_WRITE | MAP_SHARED

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* =========================================================================
 * LSM HOOK: unix_may_send
 * ========================================================================= */
SEC("lsm/unix_may_send")
int BPF_PROG(sentinel_unix_may_send, struct socket *sock, struct socket *other) {
    if (!sock || !other)
        return 0;

    __u32 sender_tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);

    struct raw_unix_send_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    init_header(&evt->hdr, EVENT_TYPE_UNIX_MAY_SEND);
    evt->sender_tgid = sender_tgid;
    evt->receiver_tgid = 0;
    evt->is_blocked = 0;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* =========================================================================
 * TRACEPOINTS: sched_process_fork & sched_process_exec
 * ========================================================================= */
SEC("tp/sched/sched_process_fork")
int sentinel_trace_fork(struct trace_event_raw_sched_process_fork *ctx) {
    struct raw_fork_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    init_header(&evt->hdr, EVENT_TYPE_PROCESS_FORK);
    evt->parent_tgid = ctx->parent_pid;
    evt->child_tgid = ctx->child_pid;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("tp/sched/sched_process_exec")
int sentinel_trace_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct raw_exec_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    init_header(&evt->hdr, EVENT_TYPE_PROCESS_EXEC);
    evt->tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}
