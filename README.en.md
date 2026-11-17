# Sentinel-RS

**Autonomous Headless Linux HIPS / EDR Agent Powered by eBPF LSM and Rust**

[![Language: Rust](https://img.shields.io/badge/Language-Rust_2021-orange.svg?logo=rust)](https://www.rust-lang.org/)
[![Kernel: eBPF LSM](https://img.shields.io/badge/Kernel-eBPF_LSM_(Linux_5.10%2B)-blue.svg?logo=linux)](https://ebpf.io/)
[![Architecture: Headless HIPS/EDR](https://img.shields.io/badge/Architecture-Headless_EDR-green.svg)](#architecture)
[![Engine: Deterministic Risk](https://img.shields.io/badge/Engine-Causal_Lineage_%26_Risk-brightgreen.svg)](docs/ARCHITECTURE.md)
[![Memory: < 25-30 MB](https://img.shields.io/badge/RAM-%3C_25--30_MB-success.svg)](docs/PERFORMANCE.md)
[![Tests: 95 Passing](https://img.shields.io/badge/Tests-95_Passed-brightgreen.svg)](docs/TESTING.md)

**English** | [Русский](README.md)

---

## About the Project (Version 0.2.1)

**Sentinel-RS** is an ultra-lightweight, high-performance, fully autonomous **Headless Host Intrusion Prevention System (HIPS)** and **Endpoint Detection and Response (EDR)** security agent for Linux systems (supporting both Linux Server and Linux Desktop platforms).

The agent operates as a background `systemd` daemon service (`sentineld`) managed via the `sntctl` command-line utility. The project has **zero graphical dependencies** (no X11, Wayland, Slint, GUI authentications, or interactive popup prompts). All threat prevention, detection, and containment decisions are evaluated **deterministically and autonomously** without requiring human intervention.

---

## Core Capabilities

1. **Kernel-Space Enforcement (eBPF & BPF LSM)**:
   - Early interception via BPF LSM hooks (`bprm_check_security`, `file_open`, `file_permission`, `mmap_file`, `ptrace_access_check`, `unix_may_send`, `socket_connect`).
   - Kernel object storages (`task_storage`, `sk_storage`) and high-throughput BPF RingBuffer.
   - Fileless execution detection (`memfd_create`, anonymous `PROT_EXEC`) and cross-process memory snooping prevention (`ptrace`, `/proc/<pid>/mem`, `process_vm_readv`).

2. **Causal Data-Flow Taint Tracking**:
   - Automatically marks tasks as Tainted upon touching credentials (`/etc/shadow`, `~/.ssh/id_*`, cloud metadata, password stores).
   - Propagates taint across `fork`/`clone`, anonymous pipes, FIFOs, `SCM_RIGHTS` descriptors, and AF_UNIX domain sockets.
   - Prevents taint laundering through intermediate background brokers.

3. **Causal Process Lineage DAG**:
   - Maintains an in-memory directed acyclic graph of all processes in userspace.
   - Tracks full ancestor chains (`ancestor_chain`) up to PID 1.
   - Anti-PID-reuse guarantee using process start timestamps from `/proc/<pid>/stat`.

4. **Deterministic Risk Engine**:
   - Calculates normalized risk scores ($0 \le S \le 100$).
   - Rolling window evidence deduplication.
   - Exponential risk decay with a 5-minute half-life ($T_{1/2} = 300\text{s}$).
   - Multi-stage attack compounding multipliers (up to $1.6\times$ for full MITRE ATT&CK progression).

5. **Six-Stage Autonomous Policy Engine**:
   1. *Stage 1 (Safety Invariant)*: Absolute immunity for PID 1, PID 2, and the `sentineld` daemon.
   2. *Stage 2 (Protected Resources)*: Kernel and core system path integrity protection.
   3. *Stage 3 (Admin Deny)*: Explicit administrator blacklists.
   4. *Stage 4 (Admin Allow)*: Explicit administrator whitelists.
   5. *Stage 5 (Behavior Detection)*: High-confidence behavioral detection matches.
   6. *Stage 6 (Operating Mode Defaults)*: Default action matrices for `AUDIT`, `BALANCED`, `STRICT`, and `CUSTOM` modes.

6. **Automated Response Engine**:
   - Two-phase safe process termination (`SIGSTOP` $\rightarrow$ verify `/proc/<pid>/stat` $\rightarrow$ `SIGTERM` $\rightarrow$ `SIGKILL`).
   - Process suspension for forensic live-memory triage.
   - Dynamic netfilter IP blocking and emergency host network isolation via `nftables` (preserving local loopback and management IPC).

7. **Secure Management CLI & IPC**:
   - Headless administration exclusively via `sntctl`.
   - Kernel-enforced peer credential authentication (`SO_PEERCRED`) over `/run/sentinel/sentinel.sock` (RBAC: `RootAdmin`, `Operator`, `ReadOnly`).

8. **Ultra-Low Resource Footprint**:
   - 100% pure Rust (Zero C/Python runtimes, Zero LLM in security hotpath).
   - Resident Memory: **$< 25\text{--}30\text{ MB}$ RSS**.
   - Evaluation Latency: **$< 1\text{ ms}$**.

---

## Workspace Architecture

```
crates/
├── sentinel-common/    # Shared data types, events, IPC messages, policy enums
├── sentinel-ebpf/      # Kernel eBPF programs, BPF LSM hooks, maps, RingBuffer
├── sentineld/          # Privileged host security daemon (HIPS/EDR Engine)
│   ├── src/collector/  # Kernel event ingestion and normalization
│   ├── src/lineage/    # Process lineage graph (DAG) and anti-PID-reuse
│   ├── src/behavior/   # Behavioral detection rules
│   ├── src/risk/       # Deterministic risk engine and half-life decay
│   ├── src/policy/     # 6-stage autonomous policy engine
│   ├── src/response/   # Response orchestrator (Kill, Suspend, NetBlock)
│   ├── src/incidents/  # Incident lifecycle management and correlation
│   ├── src/storage/    # Async SQLite storage in WAL mode
│   ├── src/health/     # Subsystem health monitoring and sd_notify watchdog
│   └── src/ipc/        # SO_PEERCRED RBAC IPC server
└── sntctl/             # CLI management client
```

---

## Quick Start

### System Requirements
- Linux kernel $\ge 5.10$ (recommended $\ge 6.1$) with BPF LSM enabled (`lsm=...,bpf`).
- Required packages: `libelf`, `nftables`, `sqlite3`.

### Building from Source
```bash
git clone https://github.com/woifik560/sentinel-rs.git
cd sentinel-rs

# Build release binaries
cargo build --release
```

### System Installation & Service Launch
```bash
# Install binaries and default configs
sudo install -m 0755 target/release/sentineld /usr/local/bin/
sudo install -m 0755 target/release/sntctl /usr/local/bin/
sudo mkdir -p /etc/sentinel /var/lib/sentinel /run/sentinel
sudo cp config/config.toml /etc/sentinel/
sudo cp config/rules.toml /etc/sentinel/
sudo cp config/sentineld.service /etc/systemd/system/

# Enable and start daemon
sudo systemctl daemon-reload
sudo systemctl enable --now sentineld.service
```

### Verification
```bash
# Run environment diagnostics
sudo sntctl doctor

# Check daemon status
sntctl status

# Check subsystem health metrics
sntctl health
```

---

## CLI Usage Examples (`sntctl`)

```bash
# Query protection status
sntctl protection status

# Stream live audit events
sntctl events tail

# List detected incidents
sntctl incidents list

# View detailed incident forensics
sntctl incidents show <INCIDENT_ID>

# Inspect process lineage DAG
sntctl process inspect <PID>
sntctl process lineage <PID>

# Hot-reload policy rules
sudo sntctl policy reload

# Emergency host containment
sudo sntctl network isolate

# Restore network connectivity
sudo sntctl network unisolate
```

---

## Technical Documentation

Comprehensive documentation is available in [`docs/`](docs/):
- [Architecture Specification](docs/ARCHITECTURE.md)
- [Security Model & RBAC](docs/SECURITY_MODEL.md)
- [Threat Model & MITRE Mapping](docs/THREAT_MODEL.md)
- [Installation Guide](docs/INSTALLATION.md)
- [Configuration Reference](docs/CONFIGURATION.md)
- [IPC Protocol Specification](docs/IPC_PROTOCOL.md)
- [eBPF & Kernel Compatibility](docs/EBPF_COMPATIBILITY.md)
- [Policy Engine Precedence](docs/POLICY_ENGINE.md)
- [Incident Response & Forensics](docs/INCIDENT_RESPONSE.md)
- [Troubleshooting & Diagnostics](docs/TROUBLESHOOTING.md)
- [Testing & Verification Methodology](docs/TESTING.md)
- [Performance & Resource Budgets](docs/PERFORMANCE.md)

---

## License

Licensed under the MIT License.
