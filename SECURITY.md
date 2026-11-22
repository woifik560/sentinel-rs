# Sentinel-RS: Security Policy & Vulnerability Disclosure

## 1. Security Invariants

Sentinel-RS adheres to strict security design invariants:
1. **Zero Unauthenticated Access**: All IPC interfaces authenticate callers via Linux kernel `SO_PEERCRED`. No cleartext tokens or shared secrets are stored or transmitted.
2. **Fail-Closed by Default**: When process identity, verification timestamps, or kernel probes fail or time out, operations fail closed rather than assuming safety.
3. **Immutable Safety Constraints**: `PID 1` (`systemd`), `PID 2` (`kthreadd`), kernel workers, and `sentineld` itself can never be suspended or terminated by the agent.
4. **Physical Privilege Separation**: Critical system changes (nftables atomic transactions, process signals) are isolated within `sentinel-privileged`.
5. **Anti-PID-Reuse Guarantee**: Process identity incorporates start timestamps from `/proc/<pid>/stat`, canonical executable path, and inode to eliminate Time-of-Check to Time-of-Use (TOCTOU) races. Process control relies on Linux `pidfd`.

---

## 2. Reporting Vulnerabilities

If you discover a security vulnerability in Sentinel-RS:
1. Please **do not** open a public issue on GitHub.
2. Email the vulnerability report directly to: `security@sentinel-rs.local` or the maintainer `antonputin732@gmail.com`.
3. Provide reproduction steps, kernel version (`uname -r`), and affected component.
4. The security team will acknowledge receipt within 48 hours and work on a coordinated disclosure timeline.
