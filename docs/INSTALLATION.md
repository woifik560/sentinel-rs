# Sentinel-RS Installation Guide

## 1. Prerequisites and Requirements

### 1.1 Operating System and Architecture
- **Supported Architectures**: `x86_64`, `aarch64`
- **Supported Linux Distributions**:
  - Ubuntu 22.04 LTS / 24.04 LTS
  - Debian 12 (Bookworm)
  - Fedora 39 / 40
  - Red Hat Enterprise Linux (RHEL) / Rocky Linux 9+
  - Arch Linux

### 1.2 Kernel Configuration Requirements
Sentinel-RS requires a modern Linux kernel ($\ge 5.10$, recommended $\ge 6.1$) with:
1. **BPF LSM Support**: `CONFIG_BPF_LSM=y`
   - Verify kernel command line includes `lsm=...,bpf` in `/etc/default/grub` or `/boot/cmdline.txt`.
2. **BPF Ring Buffer & BTF**:
   - `CONFIG_BPF=y`
   - `CONFIG_BPF_SYSCALL=y`
   - `CONFIG_DEBUG_INFO_BTF=y` (inspect via `/sys/kernel/btf/vmlinux`)
3. **Netfilter / Nftables**:
   - `CONFIG_NF_TABLES=y`
   - `CONFIG_NETFILTER_NETLINK_QUEUE=y` (for packet holding capabilities)

### 1.3 Build-time Dependencies
To build Sentinel-RS from source, the following tools are required:
```bash
# Debian / Ubuntu:
sudo apt-get update && sudo apt-get install -y \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    libsqlite3-dev \
    pkg-config \
    nftables

# Fedora / RHEL:
sudo dnf install -y \
    gcc \
    clang \
    llvm \
    elfutils-libelf-devel \
    sqlite-devel \
    pkgconf-pkg-config \
    nftables
```

Rust toolchain:
- Rust $\ge 1.75$ (MSRV)
- Installed via `rustup`: `rustup default stable`

---

## 2. Building Sentinel-RS

Clone the repository and build the workspace:
```bash
git clone https://github.com/woifik560/sentinel-rs.git
cd sentinel-rs

# Compile release binaries
cargo build --release
```

The build artifacts will be placed in `target/release/`:
- `sentineld`: Root security daemon.
- `sntctl`: Management CLI utility.

---

## 3. System Installation

### 3.1 Install Binaries and Directories
```bash
# 1. Install binaries to system execution path
sudo install -m 0755 target/release/sentineld /usr/local/bin/sentineld
sudo install -m 0755 target/release/sntctl /usr/local/bin/sntctl

# 2. Create runtime, state, and configuration directories
sudo mkdir -p /etc/sentinel
sudo mkdir -p /var/lib/sentinel
sudo mkdir -p /run/sentinel

# 3. Set secure permissions (restrict access to root)
sudo chmod 0750 /etc/sentinel /var/lib/sentinel
sudo chmod 0755 /run/sentinel

# 4. Install configuration templates
sudo cp config/config.toml /etc/sentinel/config.toml
sudo cp config/rules.toml /etc/sentinel/rules.toml
sudo chmod 0640 /etc/sentinel/config.toml /etc/sentinel/rules.toml
```

### 3.2 Linux Capabilities (Non-Root Execution Option)
While `sentineld` is typically managed by systemd as `root`, it only requires a strictly minimized set of kernel capabilities rather than unrestricted root. Notably, `CAP_SYS_ADMIN` and `CAP_SYS_PTRACE` have been completely removed from the service bounding set:
```bash
# Set minimal required capabilities (CAP_SYS_ADMIN and CAP_SYS_PTRACE are strictly excluded):
sudo setcap 'cap_bpf,cap_perfmon,cap_net_admin,cap_kill,cap_dac_read_search=ep' /usr/local/bin/sentineld
```

### 3.3 Privilege Separation
Sentinel-RS employs privilege separation between `sentineld` (the unprivileged analysis core) and `sentinel-privileged` (a dedicated helper for eBPF loading, atomic nftables batch execution, and pidfd-based process control). The privileged helper runs in an isolated context communicating via Unix domain sockets, enforcing least privilege for the detection daemon.

---

## 4. Systemd Service Setup

Install the hardened systemd unit file:
```bash
sudo cp config/sentineld.service /etc/systemd/system/sentineld.service
sudo systemctl daemon-reload
```

### 4.1 Enable and Start Daemon
```bash
sudo systemctl enable sentineld.service
sudo systemctl start sentineld.service
```

### 4.2 Verify Service Status
```bash
sudo systemctl status sentineld.service
```

Expected output:
```text
● sentineld.service - Sentinel-RS Headless HIPS/EDR Security Daemon
     Loaded: loaded (/etc/systemd/system/sentineld.service; enabled; preset: enabled)
     Active: active (running) since ...
       Docs: https://github.com/woifik560/sentinel-rs
   Main PID: 1234 (sentineld)
     Status: "Operational - Monitoring 128 processes"
      Tasks: 6 (limit: 4915)
     Memory: 18.4M (limit: 50.0M)
        CPU: 120ms
     CGroup: /system.slice/sentineld.service
             └─1234 /usr/local/bin/sentineld --config /etc/sentinel/config.toml
```

---

## 5. Post-Installation Verification

Run the built-in diagnostic suite:
```bash
sudo sntctl doctor
```

Verify that all checks return `PASS`:
- Kernel version $\ge 5.10$
- BPF LSM enabled
- BTF available at `/sys/kernel/btf/vmlinux`
- Netfilter and nftables active
- Socket `/run/sentinel/sentinel.sock` accessible
- SQLite database `/var/lib/sentinel/sentinel.db` initialized in WAL mode
