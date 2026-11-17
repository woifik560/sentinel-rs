# Sentinel-RS Incident Response & Forensic Preservation

## 1. Incident Lifecycle

Sentinel-RS manages security threats as structured incidents with deterministic state machines:

```
                  +---------------+
                  |   DETECTED    |
                  +---------------+
                          |
             Autonomous   |
             Containment  v
                  +---------------+
                  |  CONTAINED    |
                  +---------------+
                          |
             Analyst      |
             Review       v
                  +---------------+
                  | INVESTIGATING |
                  +---------------+
                     /         \
         Remediated /           \ False Positive
                   v             v
          +------------+     +----------------+
          |  RESOLVED  |     | FALSE_POSITIVE |
          +------------+     +----------------+
```

### Incident States:
- **`DETECTED`**: Initial threat identification via behavior rules or compound risk threshold.
- **`CONTAINED`**: Immediate autonomous mitigations applied (process terminated or suspended, IP blocked, or host quarantined).
- **`INVESTIGATING`**: Under active forensic review by a security engineer via `sntctl`.
- **`RESOLVED`**: Root cause remediated, exceptions added if appropriate, incident closed.
- **`FALSE_POSITIVE`**: Incident flagged as benign; feedback fed into policy rules.

---

## 2. Temporal Correlation Engine

Threat events occurring on a host are not evaluated in isolation. The Correlator (`sentineld/src/incidents/correlator.rs`) maintains an active correlation window ($T_{\text{window}} = 300\text{ seconds}$):
- Events sharing the same process lineage DAG or origin TGID are automatically linked to the same active incident.
- Secondary child processes spawned by a compromised parent inherit the incident ID.
- Network flows originating from a tainted process are aggregated into the incident evidence bundle.

---

## 3. Forensic Evidence Preservation

When an incident is created:
1. **Process Snapshot**: Captures command-line arguments, environment variables, working directory, executable binary hash (SHA-256), UID, GID, and process start timestamp.
2. **Lineage Ancestry**: Records the full ancestor chain up to `PID 1`.
3. **Network Context**: Records destination IP, remote port, protocol, and socket creation timestamp.
4. **Persistent Storage**: Serialized to the SQLite database (`incidents` and `incident_events` tables in WAL mode).

---

## 4. Emergency Host Network Containment

Under Critical multi-stage attacks, Sentinel-RS can place the host into emergency isolation:
```bash
sudo sntctl network isolate
```

### Isolation Behavior:
- All inbound and outbound IPv4/IPv6 traffic is dropped at the netfilter PREROUTING and OUTPUT hooks via dynamic nftables sets.
- **Loopback Traffic (`127.0.0.1`, `::1`) is Preserved**: Ensures local services, local databases, and IPC continue operating normally.
- **Management Unix Sockets Remain Active**: Allows local administrators to investigate and remediate via `sntctl`.

To restore connectivity after threat eradication:
```bash
sudo sntctl network unisolate
```
