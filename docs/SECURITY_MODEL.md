# Sentinel-RS Security Model

## 1. Security Architecture Principles

Sentinel-RS operates under a strict Zero-Trust Host Security paradigm:
1. **Zero Graphical Dependencies**: Removal of all X11, Wayland, and Slint components eliminates GUI-based privilege escalations, synthetic input hijacking, window injection, and graphical IPC snooping.
2. **Autonomous Determinism**: Prevention, detection, and response decisions occur autonomously via deterministic rules and mathematical risk compounding without requiring interactive user prompts.
3. **Fail-Closed Default**: In the presence of ambiguous kernel events, saturated queues, or malformed IPC messages, the agent enforces a fail-closed posture for critical threats.
4. **Kernel-Authenticated Trust Boundaries**: All administrative IPC interactions are authenticated directly by the Linux kernel using `SO_PEERCRED`. No tokens, passwords, or shared secrets are transmitted.
5. **Anti-PID-Reuse & Safe Signal Delivery Guarantee**: Process identity incorporates start timestamps from `/proc/<pid>/stat`, canonical executable path, and inode to eliminate Time-of-Check to Time-of-Use (TOCTOU) races. Process control relies on Linux `pidfd` (`pidfd_open`, `pidfd_send_signal`), ensuring signals are delivered exclusively to the verified process instance.

---

## 2. Authentication and Access Control (RBAC)

Sentinel-RS exposes two Unix Domain Sockets located within `/run/sentinel/`:
- **Management Socket**: `/run/sentinel/sentinel.sock` (Permissions: `0660`, owner: `root:root`).
- **Read-Only Telemetry Socket**: `/run/sentinel/sentinel-ro.sock` (Permissions: `0666`, owner: `root:root`).

### 2.1 Kernel-Level Peer Credential Validation (`SO_PEERCRED`)
When a client connects to either socket, `sentineld` queries `SO_PEERCRED` via `nix::sys::socket::getsockopt`:

```rust
let creds = getsockopt(stream, PeerCredentials)?;
let peer_uid = creds.uid();
let peer_gid = creds.gid();
let peer_pid = creds.pid();
```

Because `SO_PEERCRED` is populated directly by the kernel networking stack based on the connecting process's real credentials, it cannot be spoofed by unprivileged userspace processes.

### 2.2 Role-Based Access Control (RBAC) Hierarchy

| Role | Required Credential | Permitted Operations |
| :--- | :--- | :--- |
| **`RootAdmin`** | Effective UID `0` | - Enable / disable global protection<br>- Reload and update security policies (`rules.toml`)<br>- Manual process termination, suspension, and unfreeze<br>- Emergency host network isolation / un-isolation<br>- Manual IP block/unblock<br>- Full diagnostic report export |
| **`Operator`** | Effective GID `0` (or `sentinel` group) | - Query agent status, health metrics, and daemon statistics<br>- Inspect process lineage DAG<br>- List and view incident reports<br>- Stream real-time security events<br>- Run environment diagnostics (`sntctl doctor`) |
| **`ReadOnly`** | UID $\ge 1000$ (on `sentinel-ro.sock`) | - Stream non-sensitive audit events<br>- Query basic daemon uptime and version |

Any unprivileged client attempting to invoke administrative commands on `/run/sentinel/sentinel.sock` receives an immediate `EACCES` response and triggers an audit violation log.

---

## 3. Defense-in-Depth & Causal Taint Tracking

Sentinel-RS uses BPF LSM to implement continuous multi-vector taint tracking across the entire OS lifecycle:

```
[ Sensitive Asset ]
(/etc/shadow, ~/.ssh)
       |
       | lsm/file_open / lsm/file_permission
       v
+--------------+   AF_UNIX / Pipe / FIFO   +--------------+
| Tainted Task | ------------------------> | Tainted Task |
+--------------+                           +--------------+
       |                                          |
       | lsm/socket_connect                       | lsm/bprm_check_security
       v                                          v
[ Block / Isolate ]                        [ Prevent Execution ]
```

### 3.1 Taint Origins
A process is marked **Tainted** upon:
- Accessing credential stores: `/etc/shadow`, `/etc/gshadow`, `~/.ssh/id_*`, `/etc/ssl/private`, GNOME Keyrings, cloud metadata endpoints (`169.254.169.254`).
- Accessing another process's environment variables or virtual memory (`/proc/<pid>/environ`, `/proc/<pid>/mem`).
- Anonymous memory execution (`memfd_create` or `mmap` with `PROT_EXEC`).

### 3.2 Taint Propagation
Taint propagates across:
- **`fork` / `clone`**: Child processes automatically inherit the parent process's taint state.
- **AF_UNIX IPC**: If a tainted process writes to an AF_UNIX socket, the receiving process is tainted.
- **Pipes and FIFOs**: Taint transfers through anonymous and named pipes when data is read.
- **`SCM_RIGHTS`**: File descriptor passing over domain sockets propagates taint to the recipient.

### 3.3 Taint Enforcement
When a tainted process attempts:
- **Network Egress**: Evaluated against the strict Context Policy. Untrusted outbound connections trigger immediate netfilter dropping or process freezing.
- **Debugging / Memory Access (`ptrace`)**: Blocked unconditionally if attempting to trace untainted processes.
- **Execution of Shells**: Flagged as high-severity credential harvesting and exfiltration attempts.

---

## 4. Immutable Safety Constraints & Process Protection Policy

### 4.1 The Never-Freeze / Never-Kill Invariant
To prevent denial-of-service, kernel panics, or agent self-bricking, Sentinel-RS enforces an immutable Stage 1 Safety Filter via `ProcessProtectionPolicy`:

1. **System Critical Processes**:
   - `PID 1` (`systemd` / init)
   - `PID 2` (`kthreadd`)
   - Any process with `PPID == 0` (kernel worker threads)
   - Core operating system binaries in trusted paths: `/usr/lib/systemd/*`, `/usr/sbin/sshd`, `/usr/bin/login`, `/usr/bin/sudo`
2. **Sentinel-RS Processes**:
   - The `sentineld` daemon itself (`std::process::id()`)
   - The `sentinel-privileged` helper
   - Sub-threads and spawned verification helpers of `sentineld`

### 4.2 Multi-Attribute Anti-Spoofing Verification
To prevent malware from evading response by masquerading as a protected process (e.g., executing `/tmp/sshd` or naming argv[0] `systemd`), `ProcessProtectionPolicy` validates:
- Process binary canonical path (`/proc/<pid>/exe`);
- Filesystem device and inode numbers (`dev_ino`), ensuring binary resides on a trusted read-only/system mount;
- Package manager provenance (DPKG/RPM database status);
- Real binary identity vs. self-identity (PID/TGID match).

When a legitimate protected binary is suspected of exploitation, termination is blocked and the response is safely downgraded to `Alert` accompanied by network socket containment.

---

## 5. Anti-PID-Reuse & pidfd Verification Protocol

In Linux systems under high process churn, PIDs are recycled rapidly. A naive `kill(pid, SIGKILL)` introduces a severe race condition where the malicious process exits and a legitimate service receives the recycled PID before the signal arrives.

Sentinel-RS solves this using Linux `pidfd` (`pidfd_open`, `pidfd_send_signal`) combined with two-phase process identity verification:

```
[ 1. Obtain pidfd & Query Identity ]
       |
       +---> pidfd = pidfd_open(pid, 0)
       +---> Read /proc/<pid>/stat (extract start_time_ns)
       +---> Readlink /proc/<pid>/exe (extract canonical executable path)
       |
[ 2. Verify Against ProcessKey ]
       |
       +---> If start_time != expected_start_time: ABORT (Err: PidReuseDetected)
       +---> If exe_path != expected_exe: ABORT (Binary Mismatch)
       |
[ 3. Atomic Signal Sequence via pidfd ]
       |
       +---> pidfd_send_signal(pidfd, SIGSTOP, NULL, 0) (freeze process)
       +---> Re-verify /proc/<pid>/stat start_time under freeze
       +---> If verified: pidfd_send_signal(pidfd, SIGTERM, NULL, 0)
       +---> (50ms grace period)
       +---> pidfd_send_signal(pidfd, SIGKILL, NULL, 0)
```

If the kernel lacks `pidfd_open` support (Linux < 5.3), Sentinel-RS falls back to verifying `/proc/<pid>/stat` *before* issuing any signal, and immediately aborts if identity divergence is detected without sending any signal to the reused PID.

---

## 6. Privilege Separation and Sandboxing

To uphold least privilege, Sentinel-RS segregates functionality into two distinct tiers:

1. **`sentineld` (Detection & Analysis Core)**:
   - Evaluates process lineage, behavior rules, risk scoring, and policy decisions.
   - Operates with minimal capabilities, incapable of directly loading kernel modules or modifying raw firewall chains.
2. **`sentinel-privileged` (Privileged Execution Helper)**:
   - Performs eBPF map attachment and program loading.
   - Executes atomic nftables transactions exclusively within table `inet sentinel`.
   - Sends signals via Linux `pidfd`.
   - Stripped of dangerous broad capabilities: `CAP_SYS_ADMIN` and `CAP_SYS_PTRACE` are dropped.
   - Restricts capabilities strictly to: `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN`, `CAP_KILL`, `CAP_DAC_READ_SEARCH`.
