# Sentinel-RS

Autonomous headless Linux HIPS / EDR agent and host firewall powered by eBPF LSM and Rust.

Implemented capabilities:
* Kernel execution, file operations, and socket activity collection via eBPF.
* Process causal relationship graph (Lineage DAG) with `pidfd`-based anti-PID-reuse verification.
* Sensitive credential tracking (Taint Tracking: SSH keys, shadow, cloud tokens) propagated across forks, pipes, and sockets.
* Deterministic Risk Engine using heuristic weights and MITRE ATT&CK risk thresholds.
* Network control and emergency host containment (`nftables` table `inet sentinel`) with an Anti-Lockout safety timer.
* Two-phase threat response (safe `kill`, process `suspend`, and `unfreeze`).
* Local IPC server with `SO_PEERCRED` role-based access control (root/privileged vs read-only).
* Local event and incident persistence backed by SQLite in WAL mode.

---

## Build & Installation

### 1. System Dependencies

* **Debian / Ubuntu / Kali / Astra Linux:**
  ```bash
  sudo apt update && sudo apt install -y curl build-essential pkg-config libssl-dev nftables git
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  source "$HOME/.cargo/env"
  ```

* **RHEL / CentOS / Rocky Linux / Fedora:**
  ```bash
  sudo dnf install -y gcc gcc-c++ make pkgconfig openssl-devel nftables git curl
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  source "$HOME/.cargo/env"
  ```

* **Arch Linux / Manjaro:**
  ```bash
  sudo pacman -Syu --noconfirm base-devel git rustup nftables
  rustup default stable
  ```

### 2. Compilation

```bash
git clone https://github.com/woifik560/sentinel-rs.git
cd sentinel-rs
cargo build --release
```

Compiled binaries:
* `target/release/sentineld` — Core security daemon.
* `target/release/sntctl` — CLI management and triage utility.

### 3. Automatic BPF LSM Kernel Configuration (If Needed)

If BPF LSM is not yet enabled in the running kernel, configure the bootloader automatically (GRUB / systemd-boot):
```bash
sudo ./target/release/sntctl setup-kernel
```
*(Requires a system reboot if bootloader parameters are updated).*

---

## Running the Agent

### Option 1: systemd Service

```bash
# Install binaries to system path
sudo install -m 0755 target/release/sentineld /usr/local/bin/
sudo install -m 0755 target/release/sntctl /usr/local/bin/

# Create runtime and configuration directories
sudo mkdir -p /etc/sentinel /var/lib/sentinel /run/sentinel

# Copy configuration files and service unit
sudo cp config/config.toml /etc/sentinel/
sudo cp config/rules.toml /etc/sentinel/
sudo cp config/sentineld.service /etc/systemd/system/

# Reload systemd and start service
sudo systemctl daemon-reload
sudo systemctl enable --now sentineld.service
```

### Option 2: Direct Execution in Terminal

```bash
sudo ./target/release/sentineld --config config/config.toml --rules config/rules.toml
```

`sentineld` CLI options:
* `-c, --config <PATH>` — Path to configuration file (default: `/etc/sentinel/config.toml`).
* `-r, --rules <PATH>` — Path to rules file (default: `/etc/sentinel/rules.toml`).
* `--audit-only` — Run in audit mode (logging only, no blocking).
* `-v, --verbose` — Enable verbose output (DEBUG level).

---

## Management via CLI (`sntctl`)

### Global Options

* `--json` — Output machine-readable JSON.
* `-s, --socket <PATH>` — Explicit Unix socket path (`/run/sentinel/sentinel.sock` for root, `/run/sentinel/sentinel-ro.sock` for read-only).

---

### Monitoring & Diagnostics

```bash
sntctl status
# Overview: daemon status, tracked process count, and protection state

sntctl health
# Health metrics of subsystems (Lineage, Storage, Network, Watchdog)

sntctl doctor
# Environment diagnostics: kernel version, permissions, BPF LSM, and hooks

sntctl diagnostics
# Deep internal telemetry and performance statistics

sntctl monitor
# Live stream of security events and alerts (press Ctrl+C to quit)
```

---

### Protection Controls

```bash
sntctl protection status
# Display current protection state

sudo sntctl protection enable
# Enable active defense (threat blocking)

sudo sntctl protection disable
# Disable active defense (switch to audit mode)
```

---

### Process Inspection & Forensics

```bash
sntctl process inspect <PID>
# Process attributes: executable hash, permissions, secrets, taint status

sntctl process lineage <PID>
# Render ancestor lineage tree (DAG) to PID 1 with anti-PID-reuse protection

sudo sntctl process suspend <PID>
# Suspend process execution (SIGSTOP via pidfd)

sudo sntctl unfreeze <PID>
# Resume a suspended process (SIGCONT)

sudo sntctl process kill <PID> [--reason "reason text"]
# Safely terminate process with identity verification via pidfd
```

---

### Network Control & Containment

```bash
sntctl network status
# Netfilter state, NFQUEUE status, and inet sentinel table rules

sntctl network blocked
# List currently blocked or isolated destinations and processes

sudo sntctl network isolate [--tier full|restricted|selective] [--timeout <secs>] [--trusted-ssh-ip <IP>]
# Emergency host containment (default tier: full, timeout: 300s)
# Anti-Lockout timer will automatically roll back isolation if connectivity is lost

sudo sntctl network confirm-isolation
# Confirm isolation and disarm Anti-Lockout auto-rollback timer

sudo sntctl network unisolate
# Release network isolation and restore standard connectivity

sudo nft flush table inet sentinel
# Emergency kernel-level reset of all Sentinel network rules
```

---

### Incident Management

```bash
sntctl incidents list [--limit <N>]
# List recorded security incidents (default: 20)

sntctl incidents show <INCIDENT_ID>
# Detailed forensic report with risk score and trigger breakdown

sntctl incidents export <INCIDENT_ID>
# Export incident report to JSON

sudo sntctl incidents clear
# Purge incident database
```

---

### Security Events

```bash
sntctl events list [--limit <N>]
# List recently captured security events (default: 50)

sntctl events show <EVENT_ID>
# View details for a specific event by ID

sntctl events export [--limit <N>]
# Export events to JSON (default: up to 1000)
```

---

### Policies, Rules & Configuration Validation

```bash
sntctl policy list
# List loaded security policies

sntctl policy validate [--file <PATH>]
# Validate rules syntax (default: /etc/sentinel/rules.toml)

sudo sntctl policy reload
# Hot-reload rules.toml without restarting the daemon

sntctl rules list
# List active heuristic detection rules and weights

sntctl rules show <RULE_ID>
# View rule details

sntctl config validate [--file <PATH>]
# Validate main configuration syntax (default: /etc/sentinel/config.toml)
```

---

### Service Management (systemd)

```bash
sudo systemctl status sentineld     # Check service status
sudo systemctl stop sentineld       # Stop service
sudo systemctl start sentineld      # Start service
sudo systemctl restart sentineld    # Restart service
journalctl -u sentineld -f          # Stream system logs in real time
```

---

## Configuration

* **`config/config.toml` (`/etc/sentinel/config.toml`)** — Daemon parameters:
  * `general.mode` — Operating mode (`balanced`, `strict`, `learning`).
  * `general.audit_only` — Audit mode (no blocking).
  * `socket.path` & `socket.readonly_path` — IPC socket paths.
  * `targets` — Protection toggles for Telegram, browsers, SSH keys, cryptocurrency wallets.
  * `whitelist.binaries` — Trusted system binaries list.
  * `context_rules` — Contextual network/secret access rules (e.g. SSH/Git).

* **`config/rules.toml` (`/etc/sentinel/rules.toml`)** — Risk Engine weights and thresholds:
  * `thresholds`: `low_max` (0–39 audit), `grey_max` (40–74 hold & inspect), `high_min` (75–100 block).
  * Heuristic rules: in-memory execution (`memfd_create`), non-owner secret access, suspicious interpreters, anomalous network destinations, and burst exfiltration.

---

## Testing

```bash
# Run unit and integration tests
cargo test

# Run end-to-end test suite in live Linux environment (eBPF, netfilter, RBAC, DAG, kill/suspend, isolation)
sudo ./tests/run_live_vm_tests.sh
```
