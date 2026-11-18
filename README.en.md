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

## 🚀 Quick Start: Step-by-Step Setup from Scratch

Follow these steps in order. All commands can be copied directly into your Linux terminal.

### Step 1. Install System Dependencies and Rust Toolchain

Building the project requires C build tools, `libssl`, `nftables`, and a modern version of the **Rust (Cargo)** toolchain.

#### For Debian / Ubuntu / Kali / Astra Linux:
```bash
# 1. Install build tools, SSL libraries, and nftables
sudo apt update && sudo apt install -y curl build-essential pkg-config libssl-dev nftables git

# 2. Install official Rust toolchain via rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# 3. Activate Cargo environment in your current shell
source "$HOME/.cargo/env"
```

#### For RHEL / CentOS / Rocky Linux / Fedora:
```bash
sudo dnf install -y gcc gcc-c++ make pkgconfig openssl-devel nftables git curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

#### For Arch Linux / Manjaro:
```bash
sudo pacman -Syu --noconfirm base-devel git rustup nftables
rustup default stable
```

> [!TIP]
> Verify that the Rust toolchain is available:
> `cargo --version && rustc --version`

---

### Step 2. Clone Repository and Compile Binaries

```bash
# Clone source repository
git clone https://github.com/woifik560/sentinel-rs.git
cd sentinel-rs

# Build optimized release binaries
cargo build --release
```

After compilation finishes, two core binaries will be located in `target/release/`:
* `target/release/sentineld` — Root security daemon (HIPS/EDR Engine).
* `target/release/sntctl` — CLI management and triage utility.

---

### Step 3. Launch the Security Agent

Choose the launch method that fits your environment:

#### Option A: Run as a background systemd service (Recommended for production servers and workstations)

```bash
# 1. Install binaries into system path
sudo install -m 0755 target/release/sentineld /usr/local/bin/
sudo install -m 0755 target/release/sntctl /usr/local/bin/

# 2. Create runtime, state, and configuration directories
sudo mkdir -p /etc/sentinel /var/lib/sentinel /run/sentinel

# 3. Copy default configuration files and systemd service unit
sudo cp config/config.toml /etc/sentinel/
sudo cp config/rules.toml /etc/sentinel/
sudo cp config/sentineld.service /etc/systemd/system/

# 4. Reload systemd and start service
sudo systemctl daemon-reload
sudo systemctl enable --now sentineld.service
```

#### Option B: Run directly in terminal (For testing, debugging, or WSL/Docker)

In the first terminal window, start the daemon with root privileges:
```bash
sudo ./target/release/sentineld --config config/config.toml --rules config/rules.toml
```

In a second terminal window (or tab), interact with the agent using `sntctl`:
```bash
./target/release/sntctl status
```

---

### Step 4. Operational Verification

Verify that all subsystems are running properly:

```bash
# 1. Run system and kernel preflight diagnostics
sntctl doctor

# 2. Query agent status (role, tracked processes, frozen processes)
sntctl status

# 3. Inspect health metrics of internal subsystems
sntctl health

# 4. Check systemd unit status (if launched via Option A)
systemctl status sentineld.service
```

---

### Step 5. Run Live End-to-End Test Suite

An automated live testing suite is bundled to verify all security layers in your Linux environment:
```bash
cd ~/sentinel-rs
sudo ./tests/run_live_vm_tests.sh
```

This test exercises 8 live scenarios:
1. `sntctl doctor` and kernel capability inspection.
2. Daemon launch and Netfilter (`inet sentinel`) rule insertion.
3. Access control verification (`SO_PEERCRED` RBAC: root `RootAdmin` vs unprivileged `ReadOnly`).
4. Causal Lineage DAG ancestry reconstruction up to PID 1.
5. Process suspension (`SIGSTOP`), resumption (`SIGCONT`), and termination with Anti-PID-Reuse verification.
6. Stage 1 Safety Invariants (refusal to terminate PID 1 or the daemon itself).
7. Emergency host network containment (`network isolate`) preserving local loopback (`127.0.0.1`).
8. Synthetic credential touch modeling and clean teardown.

---

## 📋 Common CLI Operations (`sntctl`)

```bash
# -------------------------------------------------------------
# 1. Monitoring & Diagnostics
# -------------------------------------------------------------
sntctl status                      # Agent status summary
sntctl health                      # Internal health diagnostics
sntctl doctor                      # Kernel and BPF LSM preflight checks
sntctl monitor                     # Live streaming of security events

# -------------------------------------------------------------
# 2. Protection & Policy Controls
# -------------------------------------------------------------
sntctl protection status           # Protection subsystem status
sudo sntctl protection enable      # Enable active enforcement (blocking mode)
sudo sntctl protection disable     # Set to audit-only mode (logging only)
sudo sntctl policy reload          # Hot-reload rules.toml without restarting daemon

# -------------------------------------------------------------
# 3. Process Triage & Forensics
# -------------------------------------------------------------
sntctl process inspect <PID>       # Process metadata, executable SHA-256, and secret history
sntctl process lineage <PID>       # Reconstruct causal ancestor lineage DAG to PID 1
sudo sntctl process suspend <PID>  # Freeze suspicious process immediately (SIGSTOP)
sudo sntctl unfreeze <PID>         # Resume suspended process (SIGCONT)
sudo sntctl process kill <PID>     # Safely terminate process with anti-PID-reuse verification

# -------------------------------------------------------------
# 4. Incident Management
# -------------------------------------------------------------
sntctl incidents list              # List recorded security incidents
sntctl incidents show <ID>         # Show detailed forensic report with computed risk score

# -------------------------------------------------------------
# 5. Network Containment
# -------------------------------------------------------------
sntctl network status              # Netfilter and NFQUEUE holding status
sudo sntctl network isolate        # Emergency host network containment (drops outbound except loopback)
sudo sntctl network unisolate      # Release containment and restore regular traffic
```

---

## 🧠 Architecture Overview

Sentinel-RS is implemented as a 100% Rust workspace with zero external runtimes (Zero C/Python/LLM):

```
crates/
├── sentinel-common/    # Shared data types, IPC protocol, events, policy structures
├── sentinel-ebpf/      # Kernel eBPF programs, BPF LSM hooks, maps, and RingBuffer
├── sentineld/          # Autonomous background root security daemon (HIPS/EDR Engine)
│   ├── src/collector/  # Kernel event collection and normalization
│   ├── src/lineage/    # Process Causal Lineage DAG
│   ├── src/behavior/   # Behavioral detection heuristics
│   ├── src/risk/       # Deterministic risk engine with exponential decay
│   ├── src/policy/     # 6-stage autonomous policy evaluation engine
│   ├── src/response/   # Autonomous response (Kill, Suspend, NetBlock, Containment)
│   ├── src/incidents/  # Incident lifecycle management and correlation
│   ├── src/storage/    # Asynchronous SQLite WAL persistence
│   ├── src/health/     # Subsystem health monitors and systemd watchdog
│   └── src/ipc/        # SO_PEERCRED RBAC IPC server
└── sntctl/             # Terminal management CLI client
```

### Core Security Highlights

1. **Kernel BPF LSM**: Early-stage interception before syscall execution (`bprm_check_security`, `file_open`, `socket_connect`) and memory snooping protection (`ptrace`, `/proc/<pid>/mem`).
2. **Causal Taint Tracking**: Marks processes that access sensitive credentials and propagates taint across `fork`, pipes, AF_UNIX domain sockets, and `SCM_RIGHTS` file descriptors.
3. **Causal Lineage DAG**: In-memory process dependency graph with start-time verification to prevent race conditions from PID recycling.
4. **Deterministic Risk Engine**: Rolling-window deduplication, exponential risk decay ($T_{1/2} = 300\text{s}$), and MITRE ATT&CK multi-stage compounding multipliers.
5. **6-Stage Policy Precedence**: Strict deterministic hierarchy preventing conflicting verdicts.
6. **Autonomous Response**: Anti-PID-reuse termination, process freezing, and dynamic Netfilter holding with fail-safe bypass.
7. **Ultra-Low Footprint**: Consumes $< 25\text{--}30\text{ MB}$ RAM RSS, sub-millisecond evaluation latency.

---

## 📚 Technical Documentation

Full documentation is available in the [`docs/`](docs/) directory:
* [Architecture Specification](docs/ARCHITECTURE.md)
* [Security Model & RBAC](docs/SECURITY_MODEL.md)
* [Threat Model & Attack Analysis](docs/THREAT_MODEL.md)
* [Deployment & Installation Guide](docs/INSTALLATION.md)
* [Configuration & Rule Syntax](docs/CONFIGURATION.md)
* [IPC Protocol Specification](docs/IPC_PROTOCOL.md)
* [eBPF Kernel Compatibility](docs/EBPF_COMPATIBILITY.md)
* [Autonomous Policy Engine](docs/POLICY_ENGINE.md)
* [Incident Response & Investigation](docs/INCIDENT_RESPONSE.md)
* [Troubleshooting Guide](docs/TROUBLESHOOTING.md)
* [Testing & Verification Methodology](docs/TESTING.md)
* [Performance Budgets & Benchmarks](docs/PERFORMANCE.md)

---

## ⚖️ License

Dual-licensed under either **MIT** or **GPL-2.0-only**.
