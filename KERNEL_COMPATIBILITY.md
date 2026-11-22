# Sentinel-RS: Kernel Compatibility & Prerequisites

## 1. Supported Linux Kernel Matrix

Sentinel-RS leverages modern Linux kernel facilities including BPF LSM (Linux Security Modules), eBPF RingBuffer, BTF (BPF Type Format), Task/Socket Local Storage, and Netfilter NFQUEUE.

| Kernel Family | Compatibility Tier | Status | Required Boot Flags | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Linux 6.12+** | Tier 1 (Current Stable) | **Fully Supported** | None | Tested on Debian 13 (Trixie). BPF LSM enabled out of the box in `/sys/kernel/security/lsm`. |
| **Linux 6.6 LTS** | Tier 1 (Primary LTS) | **Fully Supported** | None | Full BPF LSM, local storage, RingBuffer, `pidfd_send_signal`, `nftables` transactional API. Tested in WSL2 (6.6.87.2) & native Linux. |
| **Linux 6.1 LTS** | Tier 1 (Enterprise LTS) | **Fully Supported** | `lsm=...,bpf` (if not enabled by default) | Standard Debian 12 / Ubuntu 22.04 LTS kernel. Zero patches required. |
| **Linux 5.15 LTS** | Tier 2 (Long Term Support) | **Fully Supported** | `lsm=landlock,lockdown,yama,integrity,apparmor,bpf` | Ubuntu 20.04.4+ LTS / RHEL 9 kernel. BPF LSM requires explicit boot parameter activation. |
| **Linux 5.10 LTS** | Tier 3 (Minimum Supported) | **Supported** | `lsm=...,bpf` | Minimum kernel with BPF RingBuffer and `pidfd_open`. Requires `CONFIG_DEBUG_INFO_BTF=y`. |
| **Linux < 5.10** | Legacy / Incompatible | **Unsupported** | N/A | Missing in-kernel BPF RingBuffer API and LSM hooks. Daemon safely refuses initialization or enters fallback observer mode. |

---

## 2. Kernel Features & Configuration Flags

Check kernel configuration via `/boot/config-$(uname -r)` or `/proc/config.gz`:

```ini
# Core eBPF & JIT Compiler
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_BPF_EVENTS=y

# BPF LSM & Modern BTF Metadata
CONFIG_BPF_LSM=y
CONFIG_DEBUG_INFO_BTF=y

# Local Storage Hooks
CONFIG_BPF_STORAGE=y

# Netfilter & NFQUEUE Subsystems
CONFIG_NETFILTER=y
CONFIG_NF_TABLES=y
CONFIG_NF_TABLES_INET=y
CONFIG_NETFILTER_NETLINK_QUEUE=y

# Process Management
CONFIG_PID_IN_FD=y
```

---

## 3. How to Enable BPF LSM on Boot

To verify whether BPF LSM is active:
```bash
cat /sys/kernel/security/lsm
```
*Expected output*: `lockdown,capability,landlock,yama,apparmor,bpf`

If `bpf` is missing:
1. Edit `/etc/default/grub`:
   ```ini
   GRUB_CMDLINE_LINUX="lsm=landlock,lockdown,yama,integrity,apparmor,bpf"
   ```
2. Update GRUB and reboot:
   ```bash
   sudo update-grub
   sudo reboot
   ```
