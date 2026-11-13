//! Tracepoint hook: `sched/sched_process_exec`
//!
//! # Kernel Logic:
//! 1. Captures `current->tgid`, the newly executed binary path (`filename`),
//!    and the command line arguments from user space.
//! 2. Detects anonymous memory execution (`memfd_create`):
//!    - Checks if the filename begins with `/memfd:` or `/proc/self/fd/`.
//! 3. Submits `RawProcessExecEvent` to the eBPF RingBuffer.
//! 4. `sentineld` receives this event, updates the node in the Lineage DAG,
//!    checks package origin (`dpkg`), hashes the binary, and inspects script arguments.

/// Check if a binary path corresponds to anonymous memfd execution.
pub fn is_memfd_path(path: &str) -> bool {
    path.starts_with("/memfd:")
        || path.starts_with("memfd:")
        || path.contains("/memfd:")
        || (path.starts_with("/proc/") && path.contains("/fd/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_memfd() {
        assert!(is_memfd_path("/memfd:stealer (deleted)"));
        assert!(is_memfd_path("memfd:malware"));
        assert!(is_memfd_path("/proc/self/fd/3"));
        assert!(!is_memfd_path("/usr/bin/python3"));
        assert!(!is_memfd_path("/tmp/test.sh"));
    }
}
