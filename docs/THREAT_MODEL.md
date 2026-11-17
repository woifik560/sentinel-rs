# Sentinel-RS Threat Model

## 1. Scope and Threat Landscape

Sentinel-RS is designed to defend Linux endpoints (both Desktop workstations and headless cloud/enterprise servers) against advanced post-exploitation, credential harvesting, memory injection, evasion, and living-off-the-land techniques.

### 1.1 In-Scope Threats
- **Fileless Execution**: In-memory binary execution using `memfd_create`, `/dev/shm`, anonymous executable mappings (`PROT_EXEC` via `mmap`).
- **Credential Access & Memory Snooping**: Reading `/etc/shadow`, `~/.ssh/id_*`, GNOME Keyring, browser credential databases, cloud IAM metadata; process memory dumping via `ptrace`, `/proc/<pid>/mem`, `/proc/<pid>/environ`, and `process_vm_readv`.
- **Living-off-the-Land Binaries (LoLBins)**: Abuse of legitimate system tools (`curl`, `wget`, `nc`, `python`, `bash`, `perl`, `socat`) for command-and-control (C2) or exfiltration following credential touches.
- **Taint Laundering**: Multi-step evasion where tainted processes pass secrets or file descriptors through intermediate IPC channels (AF_UNIX sockets, pipes, FIFOs, `SCM_RIGHTS`) to untainted worker processes.
- **Reverse Shells and Covert C2**: Direct TCP/UDP socket connections back to external adversary-controlled IPs from interactive shells, scripts, or compromised worker daemons.
- **Persistence and Privilege Escalation**: Tampering with system services, cron jobs, `/etc/sudoers`, or injecting into shared libraries.

### 1.2 Out-of-Scope Threats
- **Hardware & Microarchitectural Attacks**: Rowhammer, Spectre, Meltdown (mitigated by CPU microcode and kernel page table isolation).
- **Compromised Ring 0 / Rootkits**: Direct kernel memory tampering via malicious kernel modules (`LKM`) or direct DMA attacks. Sentinel-RS relies on the integrity of the Linux kernel and eBPF subsystem.
- **Antivirus Mass-Scanning**: Traditional static filesystem signature scanning, heuristic scanning of inert files at rest, and cloud malware multi-engine lookups. Sentinel-RS focuses strictly on runtime behavioral prevention and telemetry.

---

## 2. Adversary Techniques Mapped to MITRE ATT&CK

| MITRE ATT&CK ID | Technique Name | Sentinel-RS Detection & Prevention Mechanism |
| :--- | :--- | :--- |
| **T1059.004** | Unix Shell | Process Lineage DAG tracks shell execution from non-interactive parent processes. |
| **T1055.008** | Ptrace System Calls | BPF LSM `ptrace_access_check` denies `PTRACE_ATTACH` and `process_vm_readv` by tainted or untrusted processes. |
| **T1003.008** | /etc/passwd and /etc/shadow | BPF LSM `file_open` & `file_permission` detects credential touches; taints task; raises risk score. |
| **T1552.001** | Credentials In Files | Monitored paths include `~/.ssh`, `~/.aws/credentials`, cloud service tokens, and browser profiles. |
| **T1036.005** | Masquerading: Space after Filename / LoLBin | Causal DAG compares executable name against package database (`dpkg` / TOFU) and canonical binary hash. |
| **T1620** | Reflective Code Loading (memfd) | BPF LSM `bprm_check_security` flags execution from `memfd:`, `/dev/shm`, or deleted inodes. |
| **T1071.001** | Web Protocols (Exfiltration) | Netfilter holding + BPF `socket_connect` correlates outbound HTTP/S flows with recent secret touches. |
| **T1048** | Exfiltration Over Alternative Protocol | Network Protection Manager blocks unauthorized raw sockets and covert port usage. |
| **T1021.004** | SSH Hijacking | Monitors access to active SSH agent sockets (`SSH_AUTH_SOCK`) and taints consumers. |

---

## 3. Taint Laundering Threat Analysis

Adversaries frequently attempt to evade endpoint detection by separating the credential stealer from the exfiltrator:

```
[ Stage 1: Stealer ]             [ Stage 2: IPC Broker ]            [ Stage 3: Exfiltrator ]
Reads /etc/shadow        -->      Sends over AF_UNIX     -->        Calls curl / socket
(Tainted Task A)                  (Laundering Attempt)              (Inherits Taint Task C)
```

### Sentinel-RS Mitigation
1. **LSM `unix_may_send`**: When Task A sends a datagram or establishes a stream to Task B over AF_UNIX, `sentinel-ebpf` evaluates the sender's taint state in `task_storage`. If Task A is tainted, Task B is marked tainted immediately.
2. **File Descriptor Propagation (`SCM_RIGHTS`)**: Passing open file descriptors via `sendmsg` is intercepted by `lsm/file_receive`. The receiver inherits taint if the underlying inode represents a sensitive asset.
3. **Pipe and FIFO Tracking**: Reading from an anonymous or named pipe written to by a tainted process propagates the taint bit to the reader.

---

## 4. Risk Compounding and Temporal Decay

Single security events (such as reading an SSH configuration) may be benign developer activity. However, multiple stages of the attack lifecycle occurring in close temporal proximity indicate a high-confidence threat.

### 4.1 Multi-Stage Multipliers
The Risk Engine categorizes events into MITRE stages:
- Initial Access
- Execution
- Persistence / Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Lateral Movement
- Collection / Exfiltration
- Command & Control

If an entity engages in actions across multiple stages within a rolling window:
$$\text{Compounded Score} = \min\left(100, \text{Base Score} \times \text{Multiplier}\right)$$
Where the multiplier scales from $1.0\times$ (1 stage) up to $1.6\times$ (5+ stages).

### 4.2 Half-Life Decay Formula
Isolated, unrepeated risk signals decay exponentially over time:
$$S(t) = S_0 \cdot 2^{-\frac{\Delta t}{T_{1/2}}}$$
With $T_{1/2} = 300\text{ seconds}$ (5 minutes). This prevents stale low-level anomalies from triggering false positive responses hours later.
