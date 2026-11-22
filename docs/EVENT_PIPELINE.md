# Sentinel-RS: Unified Event Pipeline Specification

## 1. Pipeline Architecture Overview

The Sentinel-RS Event Pipeline is a deterministic, multi-stage processing pipeline that converts raw kernel events and telemetry into actionable, correlated security incidents.

```
 [ Linux Kernel ]
 (RingBuffer / Tracepoints / fanotify)
        │
        ▼ (Stage 1: Ingestion & Validation)
 ┌─────────────────────────────────────────┐
 │        Raw Kernel Event Parser          │
 │  - Magic number check (0x534E544C)      │
 │  - Schema & CRC verification            │
 └────────────────────┬────────────────────┘
                      │
                      ▼ (Stage 2: Normalization)
 ┌─────────────────────────────────────────┐
 │          Event Normalizer               │
 │  - Monotonic & Realtime timestamping    │
 │  - Canonical path resolution            │
 │  - Provenance identity linking          │
 └────────────────────┬────────────────────┘
                      │
                      ▼ (Stage 3: Deduplication & Throttling)
 ┌─────────────────────────────────────────┐
 │        Deduplication Filter             │
 │  - Burst suppression (rapid connect)    │
 │  - In-flight loop detection             │
 └────────────────────┬────────────────────┘
                      │
                      ▼ (Stage 4: Lineage & Taint Tracking)
 ┌─────────────────────────────────────────┐
 │        Lineage DAG & Taint Tracker      │
 │  - Parent-child relationship linking    │
 │  - Causal credential taint propagation  │
 └────────────────────┬────────────────────┘
                      │
                      ▼ (Stage 5: Risk Engine & Correlator)
 ┌─────────────────────────────────────────┐
 │        Deterministic Risk Engine        │
 │  - Multi-vector MITRE evidence scoring  │
 │  - Autonomous Verdict (Low/Med/High)    │
 └────────────────────┬────────────────────┘
                      │
                      ▼ (Stage 6: Dispatch & Storage)
 ┌─────────────────────────────────────────┐
 │       Dispatcher & Storage Worker       │
 │  - SQLite WAL batch commits             │
 │  - Response Orchestrator triggering     │
 └─────────────────────────────────────────┘
```

---

## 2. Canonical Security Event Schema

Every security event processed by `sentineld` implements the standard `SecurityEvent` envelope:

| Field | Type | Description |
| :--- | :--- | :--- |
| `event_id` | `Uuid` | Globally unique identifier (UUIDv4) for telemetry deduplication. |
| `timestamp_mono_ns` | `u64` | Monotonic timestamp from `CLOCK_MONOTONIC_RAW` (immune to NTP steps). |
| `timestamp_utc` | `DateTime<Utc>` | Wall-clock UTC timestamp for correlation and SIEM logging. |
| `source` | `EventSource` | Origin: `EbpfRingBuf`, `KernelTracepoint`, `Fanotify`, `Netfilter`. |
| `event_type` | `EventType` | Event category: `ProcessExec`, `FileAccess`, `SocketConnect`, etc. |
| `process_key` | `ProcessKey` | Canonical identity: PID, TGID, start timestamp (ticks), binary path, inode. |
| `parent_key` | `Option<ProcessKey>` | Lineage parent identity for DAG tracing. |
| `target_object` | `TargetObject` | Affected resource: File path, IPv4/IPv6 socket, Unix domain socket, signal target. |
| `operation` | `Operation` | Syscall / Action: `Open`, `Read`, `Write`, `Connect`, `Exec`, `Fork`, `Kill`. |
| `metadata` | `EventMetadata` | Command line arguments, environment flags, network ports, return code. |
| `confidence` | `f32` | Source reliability score ($0.0 \dots 1.0$). eBPF = 1.0, ftrace = 0.8. |
| `collection_status`| `CollectionStatus` | Ingestion status: `Delivered`, `Approximated`, `DecodedWithLoss`. |

---

## 3. Reliability & Operational Guarantees

### 3.1 Deduplication & Burst Throttling
Rapid repeated events (e.g. loops calling `connect()` to port 4444) are deduplicated within a sliding 500 ms window:
- The first event triggers immediate lineage lookup and risk scoring.
- Subsequent identical events increment an atomic counter on the active event record, preventing event-loop DoS.

### 3.2 Backpressure & Queue Monitoring
The pipeline enforces bounded queues between userspace workers:
- **RingBuffer Capacity**: 8192 records default.
- **Internal Worker Channels**: Bounded Tokio channels with `try_send` capacity checks.
- **Overflow Policy**: When queues reach 90% saturation, low-priority passive telemetry is dropped while high-severity credential and execution events take strict precedence.

### 3.3 Graceful Pipeline Teardown
On daemon shutdown (`SIGINT`, `SIGTERM`):
1. Ingestion loops stop receiving new kernel events.
2. The internal queue drains all in-flight events to the SQLite WAL database.
3. An explicit database checkpoint (`PRAGMA wal_checkpoint(TRUNCATE)`) flushes pending writes to disk before process exit.
