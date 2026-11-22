# Sentinel-RS Supported Linux Kernels & eBPF Compatibility Matrix

## 1. Supported Linux Kernel Matrix

Sentinel-RS leverages modern Linux kernel facilities including BPF LSM (Linux Security Modules), eBPF RingBuffer, BTF (BPF Type Format), Task/Socket Local Storage, and Netfilter NFQUEUE.

| Kernel Family | Compatibility Tier | Status | Required Boot Flags | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Linux 6.6+** | Tier 1 (Primary Target) | **Fully Supported** | None (BPF LSM default on most modern distros) | Full BPF LSM, local storage, RingBuffer, `pidfd_send_signal`, `nftables` transactional API. Tested in WSL2 (6.6.87.2) & native Linux. |
| **Linux 6.1 LTS** | Tier 1 (Enterprise LTS) | **Fully Supported** | `lsm=...,bpf` (if not enabled by default) | Standard Debian 12 / Ubuntu 22.04 LTS kernel. Zero patches required. |
| **Linux 5.15 LTS** | Tier 2 (Long Term Support) | **Fully Supported** | `lsm=landlock,lockdown,yama,integrity,apparmor,bpf` | Ubuntu 20.04.4+ LTS / RHEL 9 kernel. BPF LSM requires explicit boot parameter activation. |
| **Linux 5.10 LTS** | Tier 3 (Minimum Supported) | **Supported** | `lsm=...,bpf` | Minimum kernel with BPF RingBuffer and `pidfd_open`. Requires `CONFIG_DEBUG_INFO_BTF=y`. |
| **Linux < 5.10** | Legacy / Incompatible | **Unsupported** | N/A | Missing in-kernel BPF RingBuffer API and LSM hooks. Daemon safely refuses initialization or enters fallback observer mode. |

---

## 2. eBPF Mechanism States

To prevent ambiguous states and avoid reporting false security guarantees, Sentinel-RS categorizes every kernel subsystem into one of six distinct states (`MechanismState` enum):

```
                     +---------------+
                     |  Unsupported  |  (Kernel < 5.10 or missing BTF)
                     +---------------+
                             ^
                             |
+---------------+     +---------------+     +---------------+
|  Unavailable  | --> |    Loading    | --> |    Active     |
+---------------+     +---------------+     +---------------+
(Disabled in boot            |                      |
 or ELF missing)             v                      v
                      +---------------+     +---------------+
                      |    Failed     |     |   Degraded    |
                      +---------------+     +---------------+
```

- **`Unsupported`**: The running kernel lacks required subsystems (e.g. missing `CONFIG_DEBUG_INFO_BTF` or kernel < 5.10).
- **`Unavailable`**: Subsystem is supported by the kernel, but currently disabled (e.g. `bpf` omitted from `/sys/kernel/security/lsm`) or the compiled eBPF ELF binary is not installed in `/usr/lib/sentinel/`.
- **`Loading`**: Programs are being validated and loaded into kernel memory via Aya.
- **`Active`**: Programs are verified, attached to LSM and tracepoint hooks, and actively forwarding events through the RingBuffer.
- **`Degraded`**: Partial functionality (e.g. tracepoints and Netfilter NFQUEUE are active, but BPF LSM is unavailable; responses fall back to userspace `pidfd` termination).
- **`Failed`**: Critical kernel probe failure or unrecoverable verifier error during attach.

> **Integrity Guarantee**: `sentineld` never reports `bpf_lsm_active: true` or `Healthy` unless the BPF LSM hooks are physically attached to the kernel.

---

## 3. Mandatory Kernel Configuration Flags

Verify your kernel configuration in `/boot/config-$(uname -r)` or `/proc/config.gz`:

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

## 4. How to Enable BPF LSM on Boot

Most modern Linux distributions compile the kernel with `CONFIG_BPF_LSM=y`, but do not include `bpf` in the default active LSM sequence.

### Check Current Active LSMs:
```bash
cat /sys/kernel/security/lsm
```
*Expected output*: `lockdown,capability,landlock,yama,apparmor,bpf`

If `bpf` is missing from the list:

### Debian / Ubuntu:
1. Edit `/etc/default/grub`:
   ```ini
   GRUB_CMDLINE_LINUX="lsm=landlock,lockdown,yama,integrity,apparmor,bpf"
   ```
2. Update GRUB and reboot:
   ```bash
   sudo update-grub
   sudo reboot
   ```

### Arch Linux / systemd-boot:
1. Append `lsm=landlock,lockdown,yama,integrity,bpf` to your kernel boot entries in `/boot/loader/entries/*.conf`.
2. Reboot the system.

---

## 5. Verification Commands

After reboot, verify readiness using `sntctl` or standard Linux tools:

```bash
# 1. Check BTF availability
ls -l /sys/kernel/btf/vmlinux

# 2. Check active LSM list
cat /sys/kernel/security/lsm | grep bpf

# 3. Check loaded BPF programs via bpftool
sudo bpftool prog list

# 4. Check active nftables ruleset
sudo nft list ruleset

# 5. Run Sentinel Diagnostics
sntctl doctor
```
