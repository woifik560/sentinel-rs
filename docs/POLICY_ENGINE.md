# Sentinel-RS Policy Engine Specification

## 1. Six-Stage Precedence Hierarchy

The Autonomous Policy Engine evaluates process, file, and network operations through an immutable 6-stage precedence hierarchy. The first matching stage dictates the policy decision; subsequent stages are never evaluated.

```
       +---------------------------------------------+
       |   Stage 1: Safety Invariant (Never-Freeze)  |
       |  (PID 1, PID 2, sentineld, PPID == 0)       |
       +---------------------------------------------+
                              |
                     No match |
                              v
       +---------------------------------------------+
       |   Stage 2: Protected System Resources       |
       |  (/boot/vmlinuz, /lib/modules, core system) |
       +---------------------------------------------+
                              |
                     No match |
                              v
       +---------------------------------------------+
       |   Stage 3: Explicit Administrative Deny     |
       |  (PathPrefix, ExactPath, Sha256, CidrBlock) |
       +---------------------------------------------+
                              |
                     No match |
                              v
       +---------------------------------------------+
       |   Stage 4: Explicit Administrative Allow    |
       |  (PathPrefix, ExactPath, Sha256, CidrBlock) |
       +---------------------------------------------+
                              |
                     No match |
                              v
       +---------------------------------------------+
       |   Stage 5: Behavior Detection Rule Matches  |
       |  (Confirmed Reverse Shells, Credential Dump)|
       +---------------------------------------------+
                              |
                     No match |
                              v
       +---------------------------------------------+
       |   Stage 6: Operating Mode Defaults          |
       |  (AUDIT, BALANCED, STRICT, CUSTOM)          |
       +---------------------------------------------+
```

---

## 2. Precedence Stages Detailed

### Stage 1: Safety Rules (`Never-Freeze`)
- **Action**: Always `PolicyAction::Allow`
- **Protected Entities**:
  - `PID 1` (`systemd`, init)
  - `PID 2` (`kthreadd`)
  - Any kernel thread (`PPID == 0`)
  - Sentinel-RS daemon processes (`sentineld`)
- **Invariant**: Absolute immunity. Cannot be overridden by any administrative rule or risk score.

### Stage 2: Protected Resources
- **Action**: `PolicyAction::Deny` or `PolicyAction::Audit`
- **Protected Paths**: `/boot/*`, `/lib/modules/*`, `/etc/ld.so.preload`
- Enforces system integrity invariants against rootkit insertion or boot modification.

### Stage 3: Administrative Deny Rules
- **Action**: `PolicyAction::Deny`, `PolicyAction::TerminateProcess`, or `PolicyAction::DenyNetwork`
- Explicit administrator blacklists configured in `rules.toml` under `[[policy.admin_deny]]`.
- Precedes any administrative allow or behavioral rule.

### Stage 4: Administrative Allow Rules
- **Action**: `PolicyAction::Allow`
- Explicit administrator whitelists configured in `rules.toml` under `[[policy.admin_allow]]`.
- Allows legitimate developer tools, CI/CD runners, or custom in-house software to execute unhindered.

### Stage 5: Behavior Detection Rule Matches
- **Action**: Dynamically determined by triggered high-confidence behavioral detection rules (e.g. `ReverseShellDetected` $\rightarrow$ `TerminateProcess`).

### Stage 6: Operating Mode Defaults
Determined by the risk score ($S \in [0, 100]$) and active `OperatingMode`:

| Operating Mode | Low (0-29) | Medium (30-59) | High (60-84) | Critical (85-100) |
| :--- | :--- | :--- | :--- | :--- |
| **`AUDIT`** | `Allow` | `Monitor` | `Monitor` | `Monitor` |
| **`BALANCED`** | `Allow` | `Monitor` | `DenyNetwork` | `TerminateProcess` |
| **`STRICT`** | `Allow` | `DenyNetwork` | `TerminateProcess` | `TerminateProcess` |
| **`CUSTOM`** | User mapped | User mapped | User mapped | User mapped |

---

## 3. Policy Rule Definition Syntax

Policy rules are expressed in `rules.toml`:

```toml
[[policy.admin_deny]]
id = "block-unauthorized-nc"
description = "Block untrusted netcat binaries in /tmp"
condition_type = "PathPrefix"
value = "/tmp/nc"
action = "TerminateProcess"

[[policy.admin_allow]]
id = "allow-apt-package-manager"
description = "Allow official package manager operations"
condition_type = "ExactPath"
value = "/usr/bin/apt-get"
action = "Allow"
```
