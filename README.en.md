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
1. **eBPF In-Kernel Object Storage**: Replaces legacy PID/TGID maps with `BPF_MAP_TYPE_TASK_STORAGE`, `BPF_MAP_TYPE_INODE_STORAGE`, and `BPF_MAP_TYPE_SK_STORAGE`. This completely eliminates memory leaks and PID reuse race conditions.
2. **End-to-End Data Flow Taint Tracking**: Uses `lsm/file_permission` to track secret leakage across pipes (`cat ~/.ssh/id_rsa | curl ...`), FIFOs, and temporary files (`/tmp`).
3. **Fast-Path & Slow-Path Separation via NFQUEUE**:
   - *Fast-Path*: Clean, trusted binaries pass kernel network checks in nanoseconds with zero daemon roundtrips.
   - *Slow-Path*: Tainted or suspicious processes have their sockets marked with `SO_MARK` (`0x5E170001`), freezing the first SYN packet in Netfilter `NFQUEUE` without breaking connections and without risky `SIGSTOP`.
4. **LoLBin (Living off the Land) Hardening**:
   - Package trust discount (`-35`) is invalidated whenever a secret is accessed (`SECRET_NON_OWNER`). System binaries like `curl`, `git`, or `python3` cannot bypass inspection.
   - Cryptographic integrity verification via `/var/lib/dpkg/info/*.md5sums`.
5. **Never-Freeze Allowlist Protection**:
   - Hardcoded protection list (PID 1, `systemd*`, `dbus*`, `gnome-shell`, `kwin*`, `sway`, `hyprland`, `pipewire`, `NetworkManager`, terminal emulators). These are never subject to `SIGSTOP`.

> **V2.0 Architectural Rule:** Zero LLMs in the security critical loop! Deterministic scoring in **< 1 millisecond**, memory footprint **< 25–30 MB RAM**, no AVX2 requirements.

---

## Key Features

- **eBPF Object Storage & Taint Tracking**:
  - `TASK_STORAGE`: Stores task taint status and baseline trust profile, automatically reclaimed on process exit.
  - `INODE_STORAGE`: Tracks taint flow across pipes, FIFOs, and temporary files.
  - `SK_STORAGE`: Holds kernel `SO_MARK` socket tag.
  - `lsm/file_permission`: Propagates taint from writing tasks to inodes and from tainted inodes to reading tasks.
- **Taint Hygiene**:
  - Excludes pseudo-terminals (`/dev/pts/*`), `/dev/null`, system logs, and Wayland/X11 sockets to prevent OS over-tainting.
  - Strictly filters private credentials (`~/.ssh/id_*`), ignoring `.pub`, `known_hosts`, and `config`.
- **Causal Lineage Graph**:
  - In-memory ring LRU DAG holding 4096–8192 process nodes with ancestor reconstruction.
  - Interactive shell isolation: developer shells (`bash`, `zsh`) do not become permanently tainted.
- **Deep Execution Context Inspection**:
  - `lsm/bprm_check_security`: Early detection of fileless execution (`memfd_create`) before `execve` completes.
  - Script analyzer for interpreters (`python3`, `bash`, `node`, `perl`).
- **Deterministic Risk Engine (0..100) in < 1 ms**:
  - Transparent rule weights. Thresholds: **LOW** (0..39), **GREY** (40..74), **HIGH** (75..100).
- **Safe "Freeze & Inspect" via NFQUEUE**:
  - Holds initial network packets in Netfilter queue without freezing GUI processes or desktop compositors.
  - **Fail-Closed**: 30-second timeout automatically drops held packets.
- **IPC Security via `SO_PEERCRED`**:
  - Commands accepted only from root or active desktop session UID.
- **Extreme Lightweight Efficiency**:
  - Background daemon: **< 25–30 MB RAM**
  - Native Slint GUI: **< 30 MB RAM**
  - Pure Rust. Zero Python, Electron, or C++ dependencies.

---

## Risk Scoring Weights

| Rule | Weight | Description |
|---|:---:|---|
| `FILELESS_MEMFD` | **+50** | Anonymous memory execution (`memfd_create`) |
| `SECRET_NON_OWNER` | **+40** | Non-owner secret access or inherited taint via pipe/file |
| `UNTRUSTED_BINARY_ORIGIN` | **+25** | Executable from `/tmp`, `/dev/shm`, `~/Downloads`, or unverified in `dpkg` |
| `SUSPICIOUS_INTERPRETER` | **+20** | Interpreter launched with inline code (`-c`, `-e`), eval, base64, or pipe |
| `FIRST_SEEN_DESTINATION` | **+15** | First-ever connection to a public destination IP outside RFC1918 / loopback |
| `FAST_EXFIL_BURST` | **+15** | Outbound network connection within <= 5s of secret access |
| `RAW_IP_CONNECT` | **+10** | Direct IP connection without preceding DNS query |
| `TRUSTED_PACKAGE_CONTEXT` | **-35** | Binary verified in `dpkg` with MD5 check (**Disallowed if Tainted!**) |

---

## Never-Freeze Allowlist

To eliminate the danger of locking up the user's desktop, Sentinel-RS enforces an immutable protection list:
- `PID 1` (init / systemd)
- Core services: `systemd*`, `dbus-daemon`, `dbus-broker`, `NetworkManager`, `wpa_supplicant`
- Desktop compositors & display servers: `gnome-shell`, `kwin_x11`, `kwin_wayland`, `sway`, `hyprland`, `mutter`, `Xwayland`, `Xorg`
- Audio stack: `pipewire`, `pipewire-pulse`, `wireplumber`
- Sentinel tools: `sentinel-gui`, `sentinelctl`
- Terminal emulators: `gnome-terminal`, `kitty`, `alacritty`, `konsole`, `foot`, `wezterm`, `xterm`

Processes in this list are **never subject to `SIGSTOP`**.

---

## 4-Milestone Engineering Plan

- [x] **Milestone 1 — "Silent Observer" (Soak / Audit Mode) + Red-Team Test Suite**:
  - Kernel storages `TASK_STORAGE` + `INODE_STORAGE` + `lsm/file_permission`.
  - Pipe & FIFO taint propagation (`cat secret | curl`).
  - Red-Team integration test suite (`tests/red_team.rs`).
  - `--audit-only` soak mode flag.
- [x] **Milestone 2 — Deterministic App Scoping + LoLBin Hardening**:
  - Hierarchical risk floors and Debian package MD5 checksum verification.
  - Interactive shell isolation for bash/zsh.
- [x] **Milestone 3 — Interactive Enforce via SO_MARK + NFQUEUE**:
  - Zero-drop packet holding via Netfilter queue with `SO_MARK` `0x5E170001`.
  - Console and background arbitration with Fail-Closed timeout.
- [x] **Milestone 4 — Slint Desktop UI & Forensics**:
  - Visual alert window with breadcrumb DAG and risk scoring breakdown.

---

## CLI Usage (`sentinelctl`)

```bash
# Real-time interactive triage
sentinelctl watch

# Live event stream
sentinelctl monitor

# Unfreeze process
sentinelctl unfreeze <TGID>

# Export forensic incident report (JSON)
sentinelctl export <INCIDENT_ID> --format json

# Manage whitelist
sentinelctl whitelist list
sentinelctl whitelist add /usr/bin/curl
```
