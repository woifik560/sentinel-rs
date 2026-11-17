# Sentinel-RS Configuration Guide

## 1. Overview

Sentinel-RS uses TOML configuration files located by default in `/etc/sentinel/`:
- **`config.toml`**: Agent core daemon settings, storage paths, watchdog parameters, and network timeouts.
- **`rules.toml`**: Security policies, detection rules, admin whitelists/blacklists, and operating mode.

Both files support live hot-reloading via:
```bash
sudo sntctl policy reload
```
or by sending `SIGHUP` to the `sentineld` process.

---

## 2. Core Configuration (`config.toml`)

```toml
[general]
# Operating Mode: "AUDIT", "BALANCED", "STRICT", or "CUSTOM"
operating_mode = "BALANCED"

# BPF Ring Buffer capacity in bytes (must be power of 2, default 256KB)
ring_buffer_size = 262144

# Minimum required Linux kernel version
min_kernel_version = "5.10.0"

# Event collection pending queue bounds (prevents OOM under flood)
pending_queue_size = 50000

# Aggregation window in milliseconds for repeated network flows
aggregate_window_ms = 500

# Maximum duration in seconds for held network packets before drop
prompt_timeout_secs = 10

# Audit-only mode flag (logs all security events without blocking)
audit_only = false

[socket]
# Privileged administrative Unix domain socket
path = "/run/sentinel/sentinel.sock"

# Read-only public telemetry Unix domain socket
readonly_path = "/run/sentinel/sentinel-ro.sock"

[storage]
# SQLite database path for persistent events, incidents, and audit trail
db_path = "/var/lib/sentinel/sentinel.db"

# Storage queue maximum capacity before dropping lowest priority telemetry
queue_size = 10000

# Telemetry data retention period in days
retention_days = 30

[watchdog]
# Systemd sd_notify watchdog keepalive interval in seconds
watchdog_interval_secs = 4

# Maximum acceptable latency for subsystem health checks before degraded state
health_check_timeout_ms = 1000

[tofu]
# Trust-On-First-Use SQLite tracking database for non-packaged binaries
db_path = "/var/lib/sentinel/tofu.db"
```

---

## 3. Rules Configuration (`rules.toml`)

`rules.toml` defines the behavioral risk parameters, custom policy rules, and context rules.

### 3.1 Operating Modes
- **`AUDIT`**: Observer mode. Evaluates behavior and calculates risk scores. Emits audit logs and records incidents, but never terminates processes or drops packets.
- **`BALANCED`** (Default): Autonomous protection. Automatically terminates Critical risk threats ($S \ge 85$), drops/isolates High risk network threats ($60 \le S \le 84$), and monitors Medium/Low risks.
- **`STRICT`**: High-security server environment. Automatically terminates both High and Critical threats ($S \ge 60$) and blocks all unapproved egress connections.
- **`CUSTOM`**: Custom user-defined thresholds mapped in `[policy.custom_thresholds]`.

### 3.2 Administrative Rules Syntax
```toml
# Explicit Administrative Deny (Stage 3 Precedence)
[[policy.admin_deny]]
id = "block-malicious-tools"
description = "Block known offending binaries in temporary directories"
condition_type = "PathPrefix" # "ExactPath", "PathPrefix", "Sha256", "CidrBlock"
value = "/tmp/miner"
action = "TerminateProcess" # "TerminateProcess", "DenyNetwork", "Audit"

# Explicit Administrative Allow (Stage 4 Precedence)
[[policy.admin_allow]]
id = "allow-developer-scripts"
description = "Allow custom python build scripts"
condition_type = "ExactPath"
value = "/opt/ci/build_runner"
action = "Allow"
```

### 3.3 Context Policy Rules (Exfiltration Pre-Approval)
Pre-approves specific applications to connect to specific destinations after touching specific assets:
```toml
[[context_rules]]
id = "git-ssh-push"
binary_path = "/usr/bin/ssh"
secret_category = "SshKey"
dest_ip = "140.82.121.4"
dest_port = 22
dest_domain = "github.com"
action = "Allow"
```

---

## 4. Policy Syntax Validation

Always validate rules syntax prior to reloading in production:
```bash
sntctl policy test /etc/sentinel/rules.toml
```
