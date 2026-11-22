# Sentinel-RS Threat Detection & Coverage Matrix

**Document Version:** 1.0.0  
**Audit Date:** 2026-11-22  
**Auditor:** Senior Linux Security Engineer & Detection Engineer  
**Workspace:** `firewall_linux`  

---

## 1. Overview of Detection Architecture

Sentinel-RS employs a multi-layered telemetry and risk evaluation pipeline consisting of:
1. **eBPF/LSM Telemetry Capture:** Ingests low-level kernel lifecycle events (`bprm_check_security`, `file_open`, `socket_connect`) via high-speed BPF RingBuffer (with graceful tracepoint fallback if BTF/LSM is missing).
2. **Process Lineage DAG:** Tracks exact execution context, parent-child provenance, session ID, cgroup identity, and start time ticks to neutralize PID reuse.
3. **Behavioral Risk Engine:** Continuously calculates dynamic risk scores [0..100] with exponential time decay, evaluating LOLBins, execution paths, anomalous network egress, and binary hash changes (TOFU).
4. **Three-Tier Verdict Evaluation:**
   - **Green (Low Risk: 0..39):** Normal execution, direct kernel fast-path bypass.
   - **Yellow / Grey (Medium Risk: 40..69):** Suspicious context; intercepted and placed into NFQUEUE holding pending contextual correlation.
   - **Red / High (Critical Risk: 70..100):** Threat confirmed; triggers immediate process termination and network isolation.

---

## 2. Rule Catalog & MITRE ATT&CK Mapping

| Rule ID | Rule Identifier | MITRE ATT&CK ID | ATT&CK Technique Name | Target Telemetry / Event | Scoring Impact | Default Action | Verification Test |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **RULE-001** | `CredentialAccess` | **T1003** | OS Credential Dumping | Access to `/etc/shadow`, `/etc/gshadow`, `/proc/*/mem`, or LSASS/keyring | +50 to +80 | High / Block & Terminate | `test_infostealer_detection` |
| **RULE-002** | `DataExfiltration` | **T1048.003** | Exfil Over Unencrypted Protocol | High-volume egress to unapproved external endpoints, DNS tunneling | +40 to +60 | Grey / NFQUEUE Hold | `test_lolbin_curl_exfiltration_retains_grey_verdict` |
| **RULE-003** | `MaliciousExecution`| **T1204.002** | Malicious File Execution | Execution from `/tmp`, `/dev/shm`, `/var/tmp`, or unlinked file descriptors | +45 to +75 | High / Block & Terminate | `test_spoofed_sshd_in_tmp_is_not_protected` |
| **RULE-004** | `ReflectiveLoading` | **T1620** | Reflective Code Loading | `memfd_create` followed by `fexecve`, anonymous executable mappings | +70 to +90 | High / Block & Terminate | `test_is_memfd` |
| **RULE-005** | `SuspiciousShell` | **T1059** | Command & Scripting Interpreter | Interactive shell (`sh`, `bash`) spawned by webserver (`nginx`, `apache`, `node`) | +55 to +75 | High / Block & Terminate | `test_interactive_shell_detection` |
| **RULE-006** | `AnomalousC2Egress` | **T1071** | Application Layer Protocol | Unknown protocol traffic over standard ports (e.g. non-TLS on port 443) | +35 to +55 | Grey / NFQUEUE Hold | `test_context_rule_matching_ssh_github` |
| **RULE-007** | `BinaryTampering` | **T1554** | Compromise Host Software Binary | Hash mismatch between binary at runtime and TOFU (Trust On First Use) baseline | +60 to +85 | High / Block & Terminate | `test_tofu_tampered_binary_detection` |
| **RULE-008** | `ProcessInjection` | **T1055.008** | Process Injection: Ptrace | `PTRACE_POKETEXT`, `PTRACE_SEIZE` on foreign process without parent relationship | +75 to +95 | High / Block & Terminate | `test_ptrace_access_check_protection` |

---

## 3. Detailed Detection Scenarios & Evidence

### 3.1. RULE-001: OS Credential Dumping (T1003)
- **Attack Vector:** An attacker gains unprivileged access, attempts to read password hashes from `/etc/shadow`, or accesses `/proc/<pid>/mem` of a credential-bearing daemon.
- **Sentinel-RS Detection Logic:**
  - LSM hook `file_open` intercepts the read attempt.
  - Path normalization checks target against critical secret paths.
  - Risk engine verifies caller's lineage. If caller is an unprivileged or interactive user process rather than `login`/`sshd`/`passwd`, risk score immediately surges to >= 80.
- **MITRE Mitigation:** M1027 (Password Policies), M1042 (Disable or Remove Feature).

### 3.2. RULE-003: User Execution from Temp Directories (T1204.002)
- **Attack Vector:** Dropper writes ELF payload into `/tmp` or `/dev/shm` and attempts to execute it disguised as a legitimate daemon (e.g. `/tmp/sshd`).
- **Sentinel-RS Detection Logic:**
  - eBPF `bprm_check_security` captures real canonical path of executable binary.
  - `protection.rs` validates path against protected prefixes (`/usr/bin/`, `/usr/sbin/`). Spoofed binary names located in world-writable mount points are flagged.
  - High risk verdict emitted; process execution aborted before entering userspace.
- **Test Proof:** `crates/sentineld/src/protection.rs::test_spoofed_sshd_in_tmp_is_not_protected` successfully confirms `/tmp/sshd` is rejected and flagged as hostile.

### 3.3. RULE-004: Reflective Code Loading via memfd (T1620)
- **Attack Vector:** Stealthy in-memory malware allocates anonymous memory file via `memfd_create("payload", MFD_CLOEXEC)`, writes shellcode, and executes with `fexecve`.
- **Sentinel-RS Detection Logic:**
  - eBPF inspects inode flags and backing filesystem. An anonymous file with `memfd:` prefix lacking a disk vnode triggers `test_is_memfd`.
  - Taint flag `TAINT_MEMFD_EXEC` is attached to task struct.
  - Subsequent network socket requests by this process are automatically routed to NFQUEUE holding and rejected.
- **Test Proof:** `crates/sentinel-ebpf/src/programs/process_exec.rs::test_is_memfd`.

### 3.4. RULE-007: TOFU Binary Hash Integrity (T1554)
- **Attack Vector:** Local attacker overwrites or patches an existing system utility with a backdoored version.
- **Sentinel-RS Detection Logic:**
  - Upon initial execution, Sentinel records the SHA-256 digest of the binary into the local database (Trust-On-First-Use).
  - On subsequent executions, `tofu.rs` hashes the executable and compares against stored record.
  - If the hash differs and no official package manager update transaction was registered, `RULE-007` fires with high severity.
- **Test Proof:** `crates/sentineld/src/risk/engine.rs::test_tofu_tampered_binary_detection`.

---

## 4. Threat Coverage Gap Analysis & Production Guidance

| Threat Scenario | Coverage Level | Enforced By | Gaps & Mitigations |
| :--- | :--- | :--- | :--- |
| **Kernel Rootkits (Ring 0)** | Partial | Preflight verification | BPF LSM runs in kernel space, but a pre-existing rootkit can hide from BPF. Require Secure Boot + `lockdown=integrity`. |
| **Direct Hardware DMA Attacks** | Out of Scope | None (Hardware level) | Requires IOMMU hardware virtualization enabled in BIOS. |
| **Subverted Kernel Modules** | Covered | Kernel lockdown | Sentinel preflight checks module signing policy (`sys/module`). |
| **Network Egress Tunneling** | Covered | nftables + NFQUEUE holding | Outbound SYN packets from tainted processes are held in userspace queue until lineage is evaluated. |
| **Anti-Lockout During Attack** | Covered | nftables IP pin | Critical SSH administration sessions remain open even during total isolation. |

---
**Verification Signature:**  
*Sentinel-RS Threat Research & Detection Engineering*
