# Sentinel-RS IPC Protocol Specification

## 1. Transport & Framing

Communication between the management CLI (`sntctl`) and the daemon (`sentineld`) occurs via Unix Domain Sockets:
- **Privileged**: `/run/sentinel/sentinel.sock` (mode: `0660`, owner: `root:root`)
- **Read-Only**: `/run/sentinel/sentinel-ro.sock` (mode: `0666`, owner: `root:root`)

Framing uses **JSON Lines (JSONL)**:
- Each message is a complete UTF-8 JSON object terminated by a single newline character (`\n`).
- Commands are processed sequentially per connection.
- Streaming connections (`events tail`) receive continuous JSON Lines until closed.

---

## 2. Authentication & Handshake

When a client establishes a connection:
1. The kernel populates `SO_PEERCRED` on the socket.
2. `sentineld` calls `getsockopt(fd, SOL_SOCKET, SO_PEERCRED, ...)` to retrieve the peer's UID, GID, and PID.
3. Access is mapped to one of three roles:
   - `RootAdmin` (UID `0`): full read/write management.
   - `Operator` (GID `0` or `sentinel` group): diagnostic, status, inspection.
   - `ReadOnly` (UID $\ge 1000$ on `sentinel-ro.sock`): streaming public telemetry.
4. If an unauthorized client attempts an unpermitted command, an immediate `EACCES` error is returned.

---

## 3. Command & Response Specification

### 3.1 Status & Health
#### Command: `Status`
Request:
```json
{"Status": null}
```
Response:
```json
{
  "Ok": {
    "tracked_processes": 142,
    "frozen_processes": 0,
    "role": "RootAdmin"
  }
}
```

#### Command: `Health`
Request:
```json
{"Health": null}
```
Response:
```json
{
  "Health": {
    "uptime_secs": 18452,
    "subsystems": [
      {"id": "Ebpf", "status": "Healthy", "details": "RingBuffer active"},
      {"id": "Lineage", "status": "Healthy", "details": "142 nodes tracked"},
      {"id": "Storage", "status": "Healthy", "details": "WAL checkpoint ok"},
      {"id": "Policy", "status": "Healthy", "details": "Mode: BALANCED"}
    ]
  }
}
```

---

### 3.2 Protection Management
#### Command: `ProtectionEnable` / `ProtectionDisable`
Request:
```json
{"ProtectionEnable": null}
```
Response:
```json
{
  "Ok": {"enabled": true}
}
```

---

### 3.3 Incidents & Events
#### Command: `IncidentsList`
Request:
```json
{"IncidentsList": {"limit": 10, "offset": 0}}
```
Response:
```json
{
  "Ok": {
    "incidents": ["3f9b2d88-18e4-4a57-9d7c-87d2a843b123"]
  }
}
```

#### Command: `IncidentsShow`
Request:
```json
{"IncidentsShow": {"incident_id": "3f9b2d88-18e4-4a57-9d7c-87d2a843b123"}}
```
Response:
```json
{
  "Ok": {
    "incident_id": "3f9b2d88-18e4-4a57-9d7c-87d2a843b123",
    "risk_score": 88,
    "severity": "Critical",
    "primary_threat": "ShadowCredentialAccess",
    "process_key": "1842:1731859200",
    "status": "CONTAINED",
    "response_actions": ["ProcessTermination"]
  }
}
```

---

### 3.4 Process Control
#### Command: `ProcessKill`
Request:
```json
{"ProcessKill": {"tgid": 1842, "reason": "Admin investigation"}}
```
Response:
```json
{
  "Ok": {"terminated_tgid": 1842, "status": "Terminated"}
}
```

#### Command: `Unfreeze`
Request:
```json
{"Unfreeze": {"tgid": 1842}}
```
Response:
```json
{
  "Ok": {"unfrozen_tgid": 1842}
}
```

---

### 3.5 Error Responses
If a request fails or is denied:
```json
{
  "Error": {
    "code": "EACCES",
    "message": "Root administrator permission required for policy operations"
  }
}
```
Standard error codes:
- `EACCES`: Insufficient role permissions.
- `ENOENT`: Incident or entity not found.
- `ESRCH`: Process ID not found or already exited.
- `EINVAL`: Invalid command arguments or malformed payload.
