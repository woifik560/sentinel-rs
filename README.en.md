# Sentinel-RS

**eBPF Desktop Anti-Stealer & Deterministic Context-Aware Firewall for Linux**

[![Language: Rust](https://img.shields.io/badge/Language-Rust_2021-orange.svg?logo=rust)](https://www.rust-lang.org/)
[![Kernel: eBPF LSM](https://img.shields.io/badge/Kernel-eBPF_LSM_(Linux_6.x%2B)-blue.svg?logo=linux)](https://ebpf.io/)
[![GUI: Slint](https://img.shields.io/badge/GUI-Slint_UI-blueviolet.svg)](https://slint.dev/)
[![Engine: Deterministic Risk](https://img.shields.io/badge/Engine-Causal_Lineage_%26_Risk-brightgreen.svg)](https://github.com/woifik560/sentinel-rs)
[![Memory: < 30 MB](https://img.shields.io/badge/RAM-%3C_30_MB-success.svg)](#key-features)
[![Platform: Debian 13](https://img.shields.io/badge/Platform-Debian_13_Trixie-red.svg?logo=debian)](https://www.debian.org/)

**English** | [Русский](README.md)

---

## About the Project (Version 2.0)

**Sentinel-RS** is an ultra-lightweight host firewall and integrity monitor for Linux Desktop specifically engineered to prevent **Infostealers** and unauthorized credential exfiltration.

Unlike traditional packet filters (`iptables`, `nftables`, `ufw`) that lack data provenance context, or bloated endpoint agents with opaque heuristics or nondeterministic LLMs, Sentinel-RS combines:
1. **eBPF In-Kernel Object Storage**:
   - Replaces legacy PID/TGID maps with `BPF_MAP_TYPE_TASK_STORAGE`, `BPF_MAP_TYPE_INODE_STORAGE`, and `BPF_MAP_TYPE_SK_STORAGE`. This eliminates memory leaks and PID reuse race conditions.
   - **Cross-Thread Taint Propagation (`task->group_leader`)**: Taint state is anchored to the thread group leader, ensuring that if Thread A reads a secret, network sockets across all sibling threads (Go goroutines, Tokio, Python, Node.js) are immediately blocked.
2. **End-to-End Data Flow Taint Tracking & Anti-Bypass Hooks**:
   - `lsm/file_permission`: Tracks secret leakage across pipes (`cat ~/.ssh/id_rsa | curl ...`), FIFOs, and temporary files (`/tmp`).
   - `lsm/file_receive`: Tracks file descriptor passing between processes via `SCM_RIGHTS` over AF_UNIX domain sockets.
   - `lsm/mmap_file`: Tracks memory mappings of protected files and blocks execution (`PROT_EXEC`) on anonymous or tainted memory.
   - `lsm/unix_may_send`: Prevents taint laundering across AF_UNIX sockets, isolating core desktop brokers (`dbus-daemon`, `systemd`, `pipewire`) from contaminating the entire desktop.
   - `lsm/ptrace_access_check` & Kernel Self-Defense: Blocks `ptrace`, `process_vm_readv/writev`, and `/proc/<pid>/mem` access against both `sentineld` and `sentinel-gui` from any process running under the same user UID.
3. **Fast-Path & Slow-Path Separation via NFQUEUE**:
   - *Fast-Path in eBPF*: **Sub-microsecond in-kernel fast-path** on clean regular files with zero allocations or locks, eliminating I/O regressions during large project builds.
   - *Synchronous Dynamic Mark Correlation*: Eliminates race conditions between NFQUEUE and RingBuffer. The kernel encodes a dynamic `mark = 0x5E170000 | flow_id` and records context in the `flow_mark_ctx` BPF map synchronously prior to packet departure.
   - *Closing the Established Socket (`ct state established`) & UDP/QUIC Bypass*: If a process attempts exfiltration over a pre-opened socket, `lsm/socket_sendmsg` and `cgroup_skb/egress` tag the packet with revalidation mark `0x40000000 | flow_id`. In Netfilter, this mark check is evaluated **above** `ct state established accept`.
4. **LoLBin Hardening & TOFU**:
   - Package trust discount (`-35`) is invalidated whenever a secret is accessed (`SECRET_NON_OWNER`) or when run via piped stdin or inline arguments.
   - Cryptographic integrity verification via SHA-256 with symlink canonicalization, root-ownership verification, and cache invalidation on write (`MAY_WRITE`) and rename/unlink.
   - **Trust On First Use (TOFU)** for external tools (`~/.cargo/bin`, Flatpak, AppImage, local user builds).
   - Contextual policies ("who + what secret + where to connect").
5. **Dual-Socket Architecture & Strict GUI Peer Verification (P0)**:
   - **Dual Unix Domain Sockets**:
     - `/run/sentinel/sentinel-ro.sock` (0666): Public read-only socket for monitoring, status queries, and forensic exports (`sntctl monitor`, `sntctl status`, `sntctl export`).
     - `/run/sentinel/sentinel.sock` (0750, root:root): Privileged management socket accepting verdicts **only** from `root` (UID 0) or cryptographically verified `sentinel-gui`.
   - **Strict Peer Verification**: Validates `SO_PEERCRED`, checks `/proc/<pid>/exe`, verifies binary is owned by root and unwriteable by user, verifies `(dev, ino)` and SHA-256, and ensures environment variables (`LD_PRELOAD`, `LD_AUDIT`) have not been tampered with.
   - **X11 Anti-Clickjacking Defense**: Detects X11 sessions and mandates entering an ephemeral 4-digit PIN for sensitive prompt actions.
6. **Never-Freeze Allowlist & DoS Defense**:
   - Hardcoded protection list (PID 1, `systemd*`, `dbus*`, `gnome-shell`, `kwin*`, `sway`, `hyprland`, `pipewire`, `NetworkManager`, `sntctl`).
   - Anti-Spoofing: Validation strictly based on `(dev, inode)` and canonical binary path. Spoofing `comm` via `prctl(PR_SET_NAME)` is ignored.
   - NFQUEUE queue saturation defense (`pending_queue_size = 512`, duplicate SYN retransmit aggregation, `AllowForDuration` temporary approval).
   - **Kernel Requirements & CVE-2026-64192**: Checking for `bpf` presence in `/sys/kernel/security/lsm` on kernels 6.1.184+ provides verified protection against CVE-2026-64192, as the kernel patch secures `map_type_inode_storage` operations.

> **V2.0 Architectural Rule:** 100% Pure Rust. Zero C/Python runtime dependencies, zero LLMs in the security critical loop! Deterministic scoring in **< 1 millisecond**, memory footprint **< 25–30 MB RAM**.

---

## Kernel Setup & GRUB Configuration

Sentinel-RS requires BPF LSM hooks to be enabled at kernel boot.

### Ubuntu / Debian Setup:
1. Open `/etc/default/grub` with root privileges:
   ```bash
   sudo nano /etc/default/grub
   ```
2. Ensure `bpf` is included in the `lsm` boot parameter under `GRUB_CMDLINE_LINUX`:
   ```bash
   GRUB_CMDLINE_LINUX="lsm=landlock,lockdown,yama,apparmor,bpf"
   ```
3. Update GRUB and reboot:
   ```bash
   sudo update-grub
   sudo reboot
   ```
4. Verify BPF LSM activation:
   ```bash
   cat /sys/kernel/security/lsm
   # 'bpf' must be present in the output
   ```

---

## Architecture Diagram

```mermaid
flowchart TD
    subgraph Kernel["LINUX KERNEL (eBPF LSM, Tracepoints & Netfilter)"]
        LSM_BPRM["lsm/bprm_check_security<br/>(Early profiling & memfd/anon exec detection)"]
        LSM_FILE["lsm/file_open & file_permission<br/>(Sub-microsecond fast-path & pipe taint)"]
        LSM_MMAP["lsm/mmap_file<br/>(Blocks PROT_EXEC on anon/tainted memory)"]
        LSM_RECV["lsm/file_receive<br/>(Intercepts SCM_RIGHTS FD transfers in AF_UNIX)"]
        LSM_UNIX["lsm/unix_may_send<br/>(D-Bus & systemd broker isolation)"]
        LSM_PTRACE["lsm/ptrace_access_check<br/>(Protects GUI & daemon from same-UID ptrace/mem snooping)"]
        
        DYNAMIC_MARK["Synchronous eBPF Map:<br/>flow_mark_ctx (mark -> FlowContext)"]
        NFQUEUE_HOOK["Netfilter / nftables<br/>1. meta mark & 0x40000000 (Reval Pre-Opened)<br/>2. ct state established accept<br/>3. meta mark & 0x5E170000 (NFQUEUE SYN Hold)"]
        
        LSM_BPRM --> DYNAMIC_MARK
        LSM_FILE --> DYNAMIC_MARK
        LSM_MMAP --> DYNAMIC_MARK
        DYNAMIC_MARK --> NFQUEUE_HOOK
    end

    subgraph Daemon["BACKGROUND DAEMON (sentineld, root, < 30 MB RAM)"]
        MAP_READER["Synchronous reading of flow_mark_ctx by mark<br/>(Zero race condition against RingBuffer)"]
        
        subgraph Engine["Deterministic Security Engine"]
            LINEAGE["Lineage Tracker (LRU graph 8192 nodes)"]
            DPKG["Dpkg Checker & SHA-256 Cache<br/>(Verified against /var/lib/dpkg/info/*.md5sums & SHA-256)"]
            RISK["Risk Engine (0..100 in < 1 ms)<br/>(LoLBin Hardening: Disallows trust discount upon Taint)"]
            ROUTER{"Verdict Router"}
        end

        NF_MGR["NFQUEUE Aggregator & Orchestrator<br/>(SYN retransmit collapse, AllowForDuration)"]
        SAFETY["Never-Freeze Allowlist<br/>(Protects PID 1, systemd, dbus, wayland, sntctl)"]
        
        subgraph Sockets["Dual Sockets with Privilege Separation"]
            RO_SOCK["/run/sentinel/sentinel-ro.sock (0666)<br/>Read-Only: Status, monitoring, exports"]
            MGMT_SOCK["/run/sentinel/sentinel.sock (0750)<br/>Privileged: GUI verification, SO_PEERCRED, PIN"]
        end

        MAP_READER --> LINEAGE
        LINEAGE --> RISK
        DPKG --> RISK
        RISK --> ROUTER
        
        ROUTER -->|0..39: LOW| ALLOW["Accept & Audit Log"]
        ROUTER -->|40..74: GREY| NF_MGR
        ROUTER -->|75..100: HIGH| BLOCK["NF_DROP / TCP RST + Optional SIGKILL"]
        
        NF_MGR <--> SAFETY
        NF_MGR <--> MGMT_SOCK
    end

    subgraph Clients["USER SPACE CLIENTS"]
        CLI["Terminal CLI: sntctl<br/>(watch, monitor, status, export)"]
        GUI["Native Slint GUI: sentinel-gui<br/>(Alerts, Breadcrumbs, X11 PIN protection)"]
    end

    Kernel -->|NFQUEUE Packets| NF_MGR
    NF_MGR -->|Verdicts NF_ACCEPT / NF_DROP| Kernel
    RO_SOCK -->|Event Monitoring| CLI
    MGMT_SOCK <-->|Interactive Verdicts| GUI
    MGMT_SOCK <-->|watch / unfreeze| CLI
```

---

## Risk Scoring Weights

| Rule | Weight | Description |
|---|:---:|---|
| `FILELESS_MEMFD` | **+50** | Anonymous memory execution (`memfd_create`) |
| `FILELESS_ANON_EXEC` | **+35** | Memory execution via `mmap` with `PROT_EXEC` on deleted/tmpfs file |
| `SECRET_NON_OWNER` | **+40** | Unauthorized secret access or taint inherited via pipe/file/SCM_RIGHTS |
| `UNTRUSTED_BINARY_ORIGIN` | **+25** | Executable launched from `/tmp`, `/dev/shm`, `~/Downloads`, or unverified in `dpkg` |
| `SUSPICIOUS_SCRIPT_EXECUTION` | **+25** | Script execution from anonymous sources, stdin, or suspicious flags |
| `SUSPICIOUS_INTERPRETER` | **+20** | Interpreter launched with inline code (`-c`, `-e`), eval, base64, or pipe |
| `FIRST_SEEN_DESTINATION` | **+15** | First connection to external public IP outside RFC1918 / loopback |
| `FAST_EXFIL_BURST` | **+15** | Network connection initiated within <= 5s of secret access |
| `RAW_IP_CONNECT` | **+10** | Direct IP connection without preceding DNS query |
| `TRUSTED_PACKAGE_CONTEXT` | **-35** | Binary verified in `dpkg` by SHA-256 (**Disallowed upon Taint or pipe!**) |

---

## CLI Usage (`sntctl`)

Renamed from `sentinelctl` to `sntctl` to prevent namespace collision with SentinelOne:

```bash
# Real-time interactive triage (for servers and SSH) [Requires Root]
sudo sntctl watch

# Live firewall event monitor [Read-Only, no root needed]
sntctl monitor

# Check daemon health and statistics [Read-Only, no root needed]
sntctl status

# Unfreeze process [Requires Root]
sudo sntctl unfreeze <TGID>

# Export forensic incident report as JSON [Read-Only]
sntctl export <INCIDENT_ID> --format json

# Manage application whitelist
sntctl whitelist list
sudo sntctl whitelist add /usr/bin/curl
```
