#ifndef __SENTINEL_TYPES_H__
#define __SENTINEL_TYPES_H__

#define MAX_PATH_LEN 256
#define MAX_CMDLINE_ARGS 16

#define EVENT_TYPE_FILE_OPEN 1
#define EVENT_TYPE_FILE_PERMISSION 2
#define EVENT_TYPE_BPRM_CHECK 3
#define EVENT_TYPE_PROCESS_FORK 4
#define EVENT_TYPE_PROCESS_EXEC 5
#define EVENT_TYPE_SOCKET_CONNECT 6
#define EVENT_TYPE_SOCKET_SENDMSG 7
#define EVENT_TYPE_UNIX_MAY_SEND 8
#define EVENT_TYPE_PTRACE_CHECK 9
#define EVENT_TYPE_MMAP_FILE 10
#define EVENT_TYPE_FILE_RECEIVE 11

struct raw_ebpf_header {
    __u32 event_type;
    __u32 cpu_id;
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
};

struct task_storage_entry {
    __u32 tgid;
    __u32 group_leader_tgid;
    __u32 tid;
    __u64 taint_flags;
    __u32 baseline_profile;
    __u8 is_leaf;
    __u8 is_verified_gui;
    __u8 is_sealed;
    __u8 _pad;
    __u32 parent_tgid;
};

struct inode_storage_entry {
    __u64 taint_flags;
    __u32 source_tgid;
    __u32 _pad;
    __u64 dev;
    __u64 ino;
    __u8 is_pipe;
    __u8 is_fifo;
    __u8 is_trusted_system_pkg;
    __u8 _pad2[5];
    __u64 inode_version;
};

struct flow_context {
    __u32 mark;
    __u32 tgid;
    __u32 pid;
    __u32 uid;
    __u64 cgroup_id;
    __u64 sock_cookie;
    __u64 taint_flags;
    __u64 exe_inode;
    __u64 exec_id;
};

struct raw_file_open_event {
    struct raw_ebpf_header hdr;
    __u32 tgid;
    __u32 uid;
    __u8 path[MAX_PATH_LEN];
    __u32 path_len;
    __u64 dev;
    __u64 ino;
    __u32 flags;
    __u32 _pad;
};

struct raw_file_perm_event {
    struct raw_ebpf_header hdr;
    __u32 tgid;
    __u32 uid;
    __u8 path[MAX_PATH_LEN];
    __u32 path_len;
    __u64 dev;
    __u64 ino;
    __u32 mask;
    __u8 is_pipe;
    __u8 is_fifo;
    __u8 _pad[6];
};

struct raw_bprm_event {
    struct raw_ebpf_header hdr;
    __u32 tgid;
    __u32 uid;
    __u8 exe_path[MAX_PATH_LEN];
    __u32 exe_path_len;
    __u64 dev;
    __u64 ino;
    __u8 is_memfd;
    __u8 _pad[7];
};

struct raw_fork_event {
    struct raw_ebpf_header hdr;
    __u32 parent_tgid;
    __u32 child_tgid;
};

struct raw_exec_event {
    struct raw_ebpf_header hdr;
    __u32 tgid;
    __u8 exe_path[MAX_PATH_LEN];
    __u32 exe_path_len;
    __u8 cmdline[MAX_CMDLINE_ARGS][MAX_PATH_LEN];
    __u32 cmdline_lens[MAX_CMDLINE_ARGS];
    __u32 cmdline_count;
};

struct raw_connect_event {
    struct raw_ebpf_header hdr;
    __u32 tgid;
    __u16 addr_family;
    __u32 dst_ipv4;
    __u8 dst_ipv6[16];
    __u16 dst_port;
    __u8 protocol;
    __u8 _pad;
    __u32 so_mark;
};

struct raw_sendmsg_event {
    struct raw_ebpf_header hdr;
    __u32 tgid;
    __u16 addr_family;
    __u32 dst_ipv4;
    __u8 dst_ipv6[16];
    __u16 dst_port;
    __u8 _pad;
    __u8 is_preopened;
    __u32 so_mark;
};

struct raw_ptrace_event {
    struct raw_ebpf_header hdr;
    __u32 tracer_tgid;
    __u32 tracee_tgid;
    __u32 mode;
    __u8 is_blocked;
    __u8 _pad[3];
};

struct raw_mmap_event {
    struct raw_ebpf_header hdr;
    __u32 tgid;
    __u32 uid;
    __u8 path[MAX_PATH_LEN];
    __u32 path_len;
    __u64 dev;
    __u64 ino;
    __u32 prot;
    __u32 flags;
    __u8 is_secret;
    __u8 is_write_shared;
    __u8 is_exec;
    __u8 _pad[5];
};

struct raw_unix_send_event {
    struct raw_ebpf_header hdr;
    __u32 sender_tgid;
    __u32 receiver_tgid;
    __u8 sock_path[MAX_PATH_LEN];
    __u32 sock_path_len;
    __u8 is_blocked;
    __u8 _pad[3];
};

#endif
