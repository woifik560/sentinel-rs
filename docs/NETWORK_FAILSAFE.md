# Sentinel-RS: Network Fail-Safe & Crash-Resilient Anti-Lockout

## 1. The Host Bricking Problem in Automated Security Systems

A major vulnerability in automated Endpoint Detection & Response (EDR) platforms is **host lockout**:
If an automated system or administrator isolates a remote server's network interfaces (e.g. during ransomware containment or active incident response), and the security daemon subsequently crashes, panics, or hangs, the server becomes permanently unreachable. Restoring access often requires out-of-band IPMI/KVM access, cloud console reboots, or on-site physical intervention.

Sentinel-RS solves this problem through an **independent, crash-resilient Anti-Lockout subsystem**.

---

## 2. Multi-Layered Anti-Lockout Architecture

```
                                  [ Operator: sntctl network isolate --tier Full --timeout 60 ]
                                                                |
                                                                v
                                              +-----------------------------------+
                                              |        sentineld daemon           |
                                              +-----------------------------------+
                                                                |
                                              Privileged IPC: Firewall(ArmAntiLockout)
                                                                v
                                              +-----------------------------------+
                                              |       sentinel-privileged         |
                                              +-----------------------------------+
                                                    /                       \
                                     Persist state /                         \ Spawn background thread
                                                  v                           v
                      [/run/sentinel/isolation_lockout.state]          [ Watchdog Timer (sleep) ]
                                                                                      |
          +---------------------------------------------------------------------------+
          | Scenarios:
          | 1. Operator runs `sntctl network confirm` before timeout:
          |    -> State file deleted, watchdog disarmed. Isolation remains in effect.
          |
          | 2. Operator loses SSH / connection dies / timeout expires:
          |    -> Watchdog triggers automatically, deletes state file, applies IsolationTier::None.
          |
          | 3. `sentineld` is killed (kill -9 sentineld):
          |    -> `sentinel-privileged` watchdog continues running independently!
          |    -> Automatically rolls back network isolation when timer expires!
          |
          | 4. System / Daemon rebooted while isolated:
          |    -> On startup, helper inspects `/run/sentinel/isolation_lockout.state`:
          |       * If `now >= expires_at`: immediate rollback.
          |       * If `now < expires_at`: resumes timer for remaining duration.
          +---------------------------------------------------------------------------
```

---

## 3. Persistent State Format

The Anti-Lockout watchdog state is written to `/run/sentinel/isolation_lockout.state` (or `/tmp/sentinel_isolation_lockout.state` in non-root test environments) as structured JSON:

```json
{
  "expires_at": 1774321200,
  "trusted_ssh_ips": ["192.168.1.50", "2001:db8::1"]
}
```

- **`expires_at`**: Unix timestamp (seconds) when the safety window lapses.
- **`trusted_ssh_ips`**: Validated IP addresses allowed to communicate with the host via TCP port 22 even during emergency isolation tiers.

---

## 4. Fail-Open vs Fail-Closed Semantics

Sentinel-RS employs carefully calibrated fail-open and fail-closed behaviors:

### 4.1 Packet Triage (NFQUEUE) -> Fail-Open with Bypass
- The Netfilter diversion rules for SO_MARK packets (`0x5e800000` and `0x5e000000`) include the `bypass` flag:
  ```text
  add rule inet sentinel output meta mark & 0xff800000 == 0x5e800000 counter queue num 100 bypass
  ```
- **Rationale**: If the `sentineld` process terminates or the userspace NFQUEUE buffer saturates during a high-throughput network flood, the kernel bypasses the queue and routes packets instead of dropping entire production network traffic.

### 4.2 Network Isolation Tiers -> Fail-Safe Auto-Rollback
- When isolation is applied (`Restricted` or `FullIsolation`), traffic is dropped according to strict table rules.
- If unconfirmed within the specified `--timeout` (default: 60 seconds), the isolation is automatically released to `IsolationTier::None`.

### 4.3 Input Validation -> Fail-Closed
- Malformed IP strings, unrecognized isolation tiers, or syntax-corrupting characters are rejected before touching the Netfilter engine (`EINVAL`), leaving existing firewall rules unmodified.

---

## 5. Verification & Testing

The Anti-Lockout subsystem is rigorously verified in the test suite:
- `test_anti_lockout_arm_and_confirm`: Validates state file generation, timer arming, and confirmation disarm.
- `test_network_anti_lockout_confirm_state`: Confirms IPC handling and status reporting.
- `test_sec_007_daemon_crash_recovery_integrity`: Validates state recovery and rollback logic after unexpected daemon crashes.
