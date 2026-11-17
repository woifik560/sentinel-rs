# Sentinel-RS eBPF Compatibility & Kernel Requirements

## 1. Supported Linux Kernel Matrix

Sentinel-RS uses BPF LSM (Linux Security Modules) and modern eBPF tracepoints.

| Kernel Family | Status | Capabilities & Notes |
| :--- | :--- | :--- |
| **Linux 6.1+** (Modern LTS) | **Fully Supported** (Recommended) | Full BPF LSM, BTF, BPF Ring Buffer, Task/Socket local storage (`bpf_task_storage`, `bpf_sk_storage`). Zero kernel patches required. |
| **Linux 5.15 - 6.0** | **Fully Supported** | Requires `lsm=...,bpf` enabled in boot parameters. Full LSM and tracepoint functionality. |
| **Linux 5.10 - 5.14** | **Supported** | Minimum supported kernel. BPF RingBuffer supported. Kernel must be built with `CONFIG_BPF_LSM=y` and `CONFIG_DEBUG_INFO_BTF=y`. |
| **Linux < 5.10** | **Unsupported** | Missing RingBuffer API and local storage hooks. Daemon enters degraded observer state if forced. |

---

## 2. Kernel Features & Configuration Flags

Verify the following flags in `/boot/config-$(uname -r)` or `/proc/config.gz`:

```ini
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_BPF_LSM=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_BPF_EVENTS=y
CONFIG_NETFILTER=y
CONFIG_NF_TABLES=y
CONFIG_NETFILTER_NETLINK_QUEUE=y
```

### 2.1 Enabling BPF LSM on Boot
Many distributions (e.g., Ubuntu, Debian) ship with `CONFIG_BPF_LSM=y` compiled in, but BPF LSM may not be active in the kernel LSM list.
To activate, check current LSMs:
```bash
cat /sys/kernel/security/lsm
```
If `bpf` is not in the output, update `/etc/default/grub`:
```ini
GRUB_CMDLINE_LINUX="lsm=landlock,lockdown,yama,integrity,apparmor,bpf"
```
Then update the bootloader:
```bash
sudo update-grub
sudo reboot
```

---

## 3. BPF Maps and Memory Footprint

Kernel-side maps are sized conservatively to ensure the total kernel memory overhead remains $< 4\text{MB}$:

| Map Name | Map Type | Max Entries | Key/Value Size | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| `events_ringbuf` | `BPF_MAP_TYPE_RINGBUF` | 256 KB | Event Struct | Asynchronous kernel-to-userspace event delivery |
| `taint_tasks` | `BPF_MAP_TYPE_HASH` | 16,384 | `u32` $\rightarrow$ `u8` | Process taint tracking |
| `flow_mark_ctx` | `BPF_MAP_TYPE_HASH` | 8,192 | `u32` $\rightarrow$ Context | Netfilter mark to socket context correlation |
| `watchdog_map` | `BPF_MAP_TYPE_ARRAY` | 4 | `u32` $\rightarrow$ `u64` | In-kernel heartbeat timestamp array |

---

## 4. Capability Detection & Degraded State Fallbacks

During initialization (`sentineld/src/preflight.rs`), Sentinel-RS checks for:
1. Availability of `/sys/kernel/btf/vmlinux`
2. Presence of `bpf` in `/sys/kernel/security/lsm`
3. Netfilter NFQUEUE availability via `nft list tables`

If BPF LSM is disabled or unsupported on the running kernel:
- The daemon does **not** crash or panic.
- It enters **Degraded LSM Fallback Mode**:
  - Execution prevention shifts to user-space response actions (`SIGSTOP` + anti-PID-reuse termination).
  - Telemetry falls back to tracepoints (`sched_process_exec`, `sched_process_fork`).
  - Network enforcement relies entirely on `nftables` connection rules.
  - An alert is logged and reflected in `sntctl doctor` and `sntctl health`.
