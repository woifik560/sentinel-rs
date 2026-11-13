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

## Overview (Version 2.0)

**Sentinel-RS** is an ultra-lightweight host firewall and data integrity system for Linux Desktop environments, engineered specifically to prevent **infostealers** and unauthorized credential exfiltration.

Unlike traditional packet filters (`iptables`, `nftables`, `ufw`), which lack awareness of data origin, and bulky endpoint protection agents with unpredictable LLMs or opaque heuristics, Sentinel-RS combines:
1. **Linux Kernel Rigor (eBPF LSM)** with in-kernel **Taint Tracking**.
2. **Deterministic In-Memory Causal Lineage Tracking** of process hierarchies.
3. **Context-Aware Interactive Prompts ("Freeze & Inspect")** for ambiguous actions, preventing false positives.

> **Architectural Principle V2.0:** No embedded Large Language Models (LLMs) in the security core! The daemon eliminates hallucinations, runs without AVX2 instruction requirements, makes decisions in **< 1 millisecond**, and consumes **under 25–30 MB of RAM**.

---

## Key Features

- **eBPF LSM Taint Tracking & App Scoping**:
  - Access to sensitive credentials (Telegram `tdata`, browser cookies/logins, SSH/GPG keys, crypto wallets) is strictly guarded by application origin.
  - Unauthorized reads mark the entire process group (`TGID`) as `TAINTED`.
- **Causal Lineage Graph (In-Memory Process DAG)**:
  - Tracks process ancestry (`sched_process_fork` / `exec`) inside a ring LRU graph (4096–8192 nodes).
  - Ancestry is preserved even after intermediate parents (e.g., `sh -c` or npm build scripts) terminate.
- **Deep Execution Context Inspection**:
  - Script interpreter inspection (`python3`, `bash`, `node`, `perl`): trustworthiness is judged by the script and arguments, not the system binary hash.
  - Detection of fileless execution from RAM (`memfd_create`).
- **Deterministic Sub-millisecond Risk Engine (0..100)**:
  - Completely transparent, human-auditable rule weights (no black-box models).
  - Categorization into **LOW** (0..39), **GREY** (40..74), and **HIGH** (75..100).
- **Interactive "Freeze & Inspect" Prompts**:
  - For ambiguous events (GREY): immediate socket rejection (`-EPERM`) + `SIGSTOP`, surfacing an interactive dialog in Slint GUI or CLI.
  - Phase 2: zero-drop packet retention via `NFQUEUE` without breaking active user workflows.
  - **Fail-Closed Principle**: unhandled prompts time out in 30 seconds, automatically dropping the connection.
- **IPC Security via `SO_PEERCRED`**:
  - Unix Domain Socket commands are only accepted from `root` or the UID of the active desktop user session.
- **Extreme Lightweight Footprint**:
  - Daemon memory: **< 25–30 MB RAM**
  - Slint GUI: **< 30 MB RAM**
  - **No Python, Electron, or C++ dependencies!** Pure Rust stack.
  - Broad hardware compatibility: fully functional on legacy x86_64 CPUs (e.g. Intel Sandy Bridge without AVX2).

---

## System Architecture

```mermaid
flowchart TD
    subgraph Kernel["LINUX KERNEL (eBPF LSM & Tracepoints)"]
        LSM_FILE["lsm/file_open<br/>(App Scoping & Flag TAINTED)"]
        SCHED_FORK["sched_process_fork & exec<br/>(TGID Lineage & cmdline)"]
        LSM_NET["lsm/socket_connect & sendmsg<br/>(Socket Drop: Return -EPERM)"]
        MAPS[("eBPF Maps & RingBuffer<br/>(TGID Taint Flags & Events)")]
        
        LSM_FILE --> MAPS
        SCHED_FORK --> MAPS
        MAPS --> LSM_NET
    end

    subgraph Daemon["BACKGROUND DAEMON (sentineld, root, < 30 MB RAM)"]
        RING_BUF["RingBuffer Consumer"]
        
        subgraph Engine["Deterministic Security Engine"]
            LINEAGE["Lineage Tracker<br/>(LRU Process DAG, memfd, script args)"]
            RISK["Risk Engine (0..100 in < 1 ms)<br/>(Transparent rule weights)"]
            ROUTER{"Verdict Router"}
        end

        IPC_SOCK["IPC Server (Unix Socket)<br/>(/run/sentinel/sentinel.sock + SO_PEERCRED)"]

        RING_BUF --> LINEAGE
        LINEAGE --> RISK
        RISK --> ROUTER
        
        ROUTER -->|0..39: LOW| ALLOW["Allow & Audit Log"]
        ROUTER -->|40..74: GREY| PROMPT_MGR["Freeze & Inspect Manager<br/>(-EPERM / SIGSTOP / NFQUEUE)"]
        ROUTER -->|75..100: HIGH| BLOCK["Instant Drop / SIGKILL"]

        PROMPT_MGR <--> IPC_SOCK
    end

    subgraph Clients["USER SPACE INTERFACES"]
        CLI["Terminal: sentinelctl<br/>(watch, monitor, export JSON)"]
        GUI["Native GUI: sentinel-gui (Slint)<br/>(Interactive Prompt, Breadcrumb, Risk Gauge)"]
    end

    Kernel -->|RingBuffer Events| Daemon
    Daemon <-->|Secure JSON-RPC / IPC| Clients
```

---

## Transparent Risk Scoring

Every event is evaluated against a deterministic scoring table (`clamp(0, 100)`):

| Rule ID | Weight | Reason |
|---|:---:|---|
| `FILELESS_MEMFD` | **+50** | Execution directly from anonymous memory (`memfd_create`) |
| `SECRET_NON_OWNER` | **+40** | Secret access by an application not authorized in App Scope |
| `UNTRUSTED_BINARY_ORIGIN` | **+25** | Executable/script located in `/tmp`, `/dev/shm`, `~/Downloads`, or unmanaged by `dpkg` |
| `SUSPICIOUS_INTERPRETER` | **+20** | Interpreter executed with inline code (`-c`), `base64`, `eval`, or piped from web |
| `FAST_EXFIL_BURST` | **+15** | Outbound network connection attempted within <= 5s of reading a secret |
| `RAW_IP_CONNECT` | **+10** | Direct connection to raw IP without preceding DNS query |
| `TRUSTED_PACKAGE_CONTEXT` | **-35** | Binary integrity verified against system package manager database |

### Verdict Thresholds:
* **0..39 (LOW):** Allowed and recorded in audit log.
* **40..74 (GREY):** Interactive user prompt in GUI or `sentinelctl watch`. Defaults to **Fail-Closed (Blocked)** after a 30s timeout.
* **75..100 (HIGH):** Immediate kernel drop (`-EPERM`), optional process freeze, and priority alert.

---

## CLI Usage (`sentinelctl`)

```bash
# Real-time interactive terminal prompt mode (ideal for SSH/servers)
sentinelctl watch

# TUI monitor streaming process accesses and network sockets
sentinelctl monitor

# Unfreeze a mistakenly flagged process
sentinelctl unfreeze <TGID>

# Export forensic incident report in JSON format (BYO-AI / SIEM analysis)
sentinelctl export <INCIDENT_ID> --format json

# Manage whitelist
sentinelctl whitelist list
sentinelctl whitelist add /usr/bin/curl
```

---

## Project Structure (Cargo Workspace)

The project is structured as a modular Rust workspace with clean separation of concerns across kernel, daemon, and client layers:

```text
sentinel-rs/
├── crates/
│   ├── sentinel-common/            # Shared types, protocol, and risk models
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs              # Library entry point
│   │       ├── events.rs           # eBPF kernel events (file_open, fork, exec, socket_connect)
│   │       ├── process.rs          # ProcessNode, script interpreter inspection (python3, bash, node)
│   │       ├── risk.rs             # Deterministic Risk Engine (0..100) and rule weights
│   │       ├── ipc.rs              # Unix IPC message protocol (PromptRequest, Verdict)
│   │       ├── incident.rs         # Forensic report formatters (Human / JSON)
│   │       └── config.rs           # Configuration deserialization for config.toml and rules.toml
│   │
│   ├── sentinel-ebpf/              # Linux kernel programs (Aya eBPF, LSM hooks, maps)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs              # Exported eBPF structures and constants
│   │       ├── maps.rs             # TaintMapManager, RingBuffer, pending_verdicts
│   │       ├── loader.rs           # eBPF LSM and tracepoint loader
│   │       └── programs/
│   │           ├── mod.rs          # Kernel program modules
│   │           ├── file_open.rs    # LSM hook file_open: App Scoping and TAINTED tagging
│   │           ├── process_fork.rs # sched fork tracepoint: lineage and taint inheritance
│   │           ├── process_exec.rs # sched exec tracepoint: cmdline and memfd_create inspection
│   │           ├── socket_connect.rs # LSM socket_connect: TCP SYN blocking (-EPERM)
│   │           └── socket_sendmsg.rs # LSM socket_sendmsg: UDP/RAW transfer mediation
│   │
│   ├── sentineld/                  # Root security daemon (Root, RAM < 30 MB)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs             # Entry point, runtime initialization, and event loop
│   │       ├── lineage.rs          # Causal Lineage Tracker (ring LRU DAG with 8192 nodes)
│   │       ├── risk_engine.rs      # Sub-millisecond risk evaluation across 7 transparent rules
│   │       ├── verdict.rs          # Verdict router (LOW: Allow, GREY: Prompt, HIGH: Kill)
│   │       ├── freeze.rs           # Freeze & Inspect Orchestrator (SIGSTOP, Fail-Closed 30s)
│   │       ├── ipc_server.rs       # Unix IPC server (/run/sentinel.sock + SO_PEERCRED)
│   │       ├── sha_cache.rs        # In-memory SHA-256 binary hash cache
│   │       └── pkg_check.rs        # Binary origin verification via dpkg-query
│   │
│   ├── sentinelctl/                # Terminal management utility (CLI Triage)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── main.rs             # Commands: watch, monitor, unfreeze, status, export, whitelist
│   │
│   └── sentinel-gui/               # Native desktop alert UI (Slint, RAM < 30 MB)
│       ├── Cargo.toml
│       └── src/
│           └── main.rs             # Slint DSL incident dialog, Fail-Closed timer, and IPC client
│
├── config/
│   ├── config.toml                 # Protected secret paths, app whitelist, IPC settings
│   └── rules.toml                  # Deterministic rule weights and risk category thresholds
│
├── systemd/
│   └── sentineld.service           # systemd service unit file for automated daemon startup
│
├── Cargo.toml                      # Root Cargo Workspace configuration
├── Cargo.lock                      # Locked dependency versions
├── README.md                       # Documentation & User Guide (Russian)
├── README.en.md                    # Documentation & User Guide (English)
└── ТЗ.txt                          # Full technical specification (v2.0)
```

---

## Roadmap (V2.0)

- [x] **Milestone 1: V2.0 Architecture & Design Specifications**
  - Removal of LLM dependencies, strict RAM budget < 30 MB.
  - Causal Lineage DAG & Deterministic Risk Engine design.
- [x] **Milestone 2: Shared Types (`sentinel-common`)**
  - eBPF events, `ProcessNode`, configuration parsing, and IPC serialization formats.
- [x] **Milestone 3: Kernel eBPF Module (`sentinel-ebpf`)**
  - LSM hooks (`file_open`, `socket_connect`, `socket_sendmsg`, `sched_process_fork/exec`), RingBuffer, and TaintMap.
- [x] **Milestone 4: Daemon Engine (`sentineld`)**
  - In-memory process LRU graph (8192 nodes), `memfd` detection, interpreter inspection, sub-millisecond risk scoring.
- [x] **Milestone 5: IPC & CLI (`sentinelctl watch`)**
  - `SO_PEERCRED` validation, terminal interactive triage (`watch`, `monitor`, `unfreeze`, `status`, `export`).
- [x] **Milestone 6: Native Slint GUI (`sentinel-gui`)**
  - Incident prompt dialog with breadcrumbs, risk gauge, fail-closed countdown, zero GPU/AVX2 requirements.
- [ ] **Milestone 7: Zero-Drop NFQUEUE Integration (Phase 2 Prompt)**
- [ ] **Milestone 8: Test Harness & Debian Package Packaging**
