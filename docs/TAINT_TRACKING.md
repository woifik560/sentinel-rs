# Sentinel-RS: Taint Tracking & Data Flow Graph

## 1. Overview

Sentinel-RS implements a **hybrid kernel/userspace Taint Tracking and Causation Engine** designed to detect and prevent data exfiltration (infostealers, credential theft, and unauthorized egress).

Traditional EDRs rely on single-event rules (e.g. "curl connects to an external IP"), resulting in false positives for normal developer activities or failing to connect the read of `~/.ssh/id_rsa` with subsequent egress via a piped process. Sentinel-RS connects these events across inter-process boundaries using a **Two-Tier Process & Data Flow Graph**.

---

## 2. Two-Tier Graph Architecture

```
  +-------------------------------------------------------------------------+
  | TIER 1: Process Graph (Ancestry Lifecycle)                              |
  |                                                                         |
  |     [bash (PID 50)] ---Fork---> [cat (PID 100)]                         |
  |            \                                                            |
  |             +------------Fork---> [curl (PID 101)]                      |
  +-------------------------------------------------------------------------+
                                         |
                                         v
  +-------------------------------------------------------------------------+
  | TIER 2: Data Flow Graph (Object Causation)                              |
  |                                                                         |
  | [~/.ssh/id_rsa] ---Read---> [cat (PID 100)] ---Write---> [Pipe 9988]    |
  |                                                              |          |
  |                                                            Read         |
  |                                                              v          |
  |                                                      [curl (PID 101)]   |
  |                                                              |          |
  |                                                         SocketConnect   |
  |                                                              v          |
  |                                                      [93.184.216.34:443]|
  +-------------------------------------------------------------------------+
```

### 2.1 Tier 1: Process Graph
- Tracks fork, exec, and exit relationships using `ProcessKey`.
- Pinned to `(tgid, start_time_ns, exe_path, inode)` to prevent PID reuse confusion.

### 2.2 Tier 2: Data Flow Graph
- Tracks interactions between processes and `FlowObject` instances:
  - `SecretFile(PathBuf)`: SSH keys, browser databases, shadow, cryptocurrency wallets, Telegram session tokens.
  - `Pipe { dev, ino }`: Anonymous pipes (`cat secret | curl`).
  - `Fifo { path }`: Named pipes (`mkfifo /tmp/p`).
  - `UnixSocket { sun_path }`: Local Unix domain sockets.
  - `NetworkSocket { dest_ip, dest_port }`: Outbound egress endpoints.
  - `FileDescriptor(i32)`: Descriptors transferred via `SCM_RIGHTS`.

---

## 3. Taint Propagation Rules

1. **Direct File Read**: When a process reads a registered secret file, its `ProcessNode` records a `SecretAccess` event and the kernel LSM marks its `task_storage` with the corresponding taint bit.
2. **IPC Pipe & FIFO Transfer**: When a tainted process writes to a pipe, the pipe is registered as carrying tainted data. When an untainted process reads from this pipe, its taint bit is set.
3. **Unix Domain Sockets (`unix_may_send`)**: If a tainted process attempts to transfer messages to another process via AF_UNIX, the recipient process inherits the taint.
4. **Descriptor Passing (`file_receive`)**: If an open descriptor to a secret file or pipe is transferred across processes via `SCM_RIGHTS`, the recipient is immediately tainted upon receipt.
5. **Memory Snooping (`ptrace_access_check`, `/proc/*/mem`)**: If a process attempts to inspect the memory of a tainted process, the action is blocked or taint is propagated.

---

## 4. Graph Traversal & Causation Querying

The method `LineageGraph::find_data_flow_path(secret_path, recipient_pid)` conducts causal analysis:
- Identifies initial read edges matching the secret.
- Traces subsequent write actions to intermediate IPC objects (pipes, sockets, FIFOs) with non-decreasing timestamps (`timestamp_ns >= reader.timestamp_ns`).
- Finds the recipient's read edge on the corresponding object.
- Returns the exact 3-step or direct edge chain connecting the confidential file to the network egress event.

---

## 5. Memory Management & Dead Process Retention

To prevent unbounded memory growth while preserving evidence for delayed incident correlation:
- **Clean terminated processes** (`secret_accesses.is_empty()`) are pruned immediately once `/proc/<pid>` disappears.
- **Tainted terminated processes** are retained for a 1-hour window (3600 seconds) after their last secret access to allow correlation with lingering network connections or forensic audits.
- Older entries beyond the retention window are reclaimed during `prune_dead()`.
