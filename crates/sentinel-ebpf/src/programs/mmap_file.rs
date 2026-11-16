//! eBPF LSM hook: `lsm/mmap_file` (`security_mmap_file`)
//!
//! # Kernel Logic & Memory Isolation:
//! Intercepts memory mappings (`mmap(MAP_SHARED)`, `mmap(MAP_PRIVATE)`) before page table
//! allocation to prevent stealthy data theft and taint laundering:
//!
//! 1. **Secret Read via mmap**:
//!    - If a process maps a sensitive file (e.g. `~/.ssh/id_rsa`), immediately sets the
//!      `TAINTED` bitflag in `BPF_MAP_TYPE_TASK_STORAGE` for `task->group_leader`.
//! 2. **Shared Memory Exfiltration (`MAP_SHARED | PROT_WRITE`)**:
//!    - If a tainted process maps a file or `/dev/shm` with `PROT_WRITE | MAP_SHARED`,
//!      immediately marks the file's inode in `BPF_MAP_TYPE_INODE_STORAGE` as tainted!
//! 3. **Anonymous / Fileless Executable Mappings (`PROT_EXEC`)**:
//!    - Intercepts executable mappings on unlinked files (`i_nlink == 0`), anonymous tmpfs,
//!      or memfd loaders, raising the `FILELESS_ANON_EXEC` risk flag.
//! 4. Emits `RawMmapFileEvent` to the RingBuffer.

use std::path::Path;
use sentinel_common::events::{RawMmapFileEvent, MAX_PATH_LEN};
use crate::maps::{MmapVerdict, TaintMapManager};

/// Evaluates a `mmap_file` LSM hook invocation.
pub fn evaluate_mmap_file(
    manager: &TaintMapManager,
    id: u32,
    dev: u64,
    ino: u64,
    path: &Path,
    prot: u32,
    flags: u32,
) -> MmapVerdict {
    manager.handle_mmap_file(id, dev, ino, path, prot, flags)
}

/// Convenience evaluation for tests and userspace simulation.
pub fn handle_mmap_file<P: AsRef<Path>>(
    manager: &TaintMapManager,
    id: u32,
    path: P,
    prot: u32,
    flags: u32,
) -> MmapVerdict {
    manager.handle_mmap_file(id, 0, 0, path.as_ref(), prot, flags)
}

/// Convenience evaluation with explicit inode attributes.
pub fn handle_mmap_file_attrs<P: AsRef<Path>>(
    manager: &TaintMapManager,
    id: u32,
    path: P,
    prot: u32,
    flags: u32,
    inode_uid: u32,
    inode_mode: u32,
) -> MmapVerdict {
    manager.handle_mmap_file_attrs(id, 0, 0, path.as_ref(), prot, flags, inode_uid, inode_mode)
}

/// Convenience evaluation for `lsm/file_mprotect` hook.
pub fn handle_file_mprotect<P: AsRef<Path>>(
    manager: &TaintMapManager,
    id: u32,
    path: Option<P>,
    reqprot: u32,
    prot: u32,
    inode_uid: u32,
    inode_mode: u32,
) -> MmapVerdict {
    let path_ref = path.as_ref().map(|p| p.as_ref());
    manager.handle_file_mprotect(id, path_ref, reqprot, prot, inode_uid, inode_mode)
}

/// Helper to create a raw event for testing and RingBuffer simulation.
pub fn create_raw_mmap_event(
    tgid: u32,
    uid: u32,
    path_str: &str,
    dev: u64,
    ino: u64,
    prot: u32,
    flags: u32,
    is_secret: bool,
    is_write_shared: bool,
    is_exec: bool,
) -> RawMmapFileEvent {
    let mut path_buf = [0u8; MAX_PATH_LEN];
    let bytes = path_str.as_bytes();
    let len = bytes.len().min(MAX_PATH_LEN);
    path_buf[..len].copy_from_slice(&bytes[..len]);

    RawMmapFileEvent {
        tgid,
        uid,
        path: path_buf,
        path_len: len as u32,
        dev,
        ino,
        prot,
        flags,
        is_secret: if is_secret { 1 } else { 0 },
        is_write_shared: if is_write_shared { 1 } else { 0 },
        is_exec: if is_exec { 1 } else { 0 },
        _pad: [0; 5],
    }
}
