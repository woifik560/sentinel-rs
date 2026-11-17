# Sentinel-RS Troubleshooting & Operational Diagnostics

## 1. Automated Health Diagnostics (`sntctl doctor`)

The fastest way to troubleshoot issues is running the environment doctor:
```bash
sudo sntctl doctor
```

The doctor verifies 8 critical operating parameters:
1. **Kernel Version**: Must be $\ge 5.10.0$.
2. **BPF LSM State**: Verifies `/sys/kernel/security/lsm` contains `bpf`.
3. **BTF Availability**: Verifies `/sys/kernel/btf/vmlinux` exists and is readable.
4. **Cgroups v2 Unified Hierarchy**: Checks `/sys/fs/cgroup/cgroup.controllers`.
5. **Netfilter / Nftables**: Ensures `nft` binary exists and netfilter tables can be queried.
6. **Daemon Socket**: Probes connectivity to `/run/sentinel/sentinel.sock`.
7. **Storage Database**: Checks SQLite database accessibility and WAL mode journal.
8. **Memory Budget**: Verifies resident set size is under the 50MB safety limit.

---

## 2. Common Operational Issues

### 2.1 BPF LSM Not Enabled
**Symptom**: `sntctl doctor` reports `FAIL: BPF LSM is not enabled in the current kernel`.
**Resolution**:
1. Check `/etc/default/grub`.
2. Ensure `GRUB_CMDLINE_LINUX` includes `lsm=landlock,lockdown,yama,integrity,apparmor,bpf`.
3. Run `sudo update-grub` and reboot the machine.

### 2.2 Socket Connection Refused (`ENOENT` / `ECONNREFUSED`)
**Symptom**: `sntctl` outputs `Failed to connect to /run/sentinel/sentinel.sock`.
**Resolution**:
1. Check if `sentineld` is running:
   ```bash
   sudo systemctl status sentineld.service
   ```
2. If service failed, inspect logs:
   ```bash
   sudo journalctl -u sentineld.service -e --no-pager
   ```
3. Verify permissions on `/run/sentinel/`:
   ```bash
   ls -ld /run/sentinel
   # Should be: drwxr-xr-x root root
   ```

### 2.3 Degraded RingBuffer State
**Symptom**: `sntctl health` reports `Subsystem Ebpf: Degraded (Dropped events > 0)`.
**Resolution**:
1. The kernel event generation rate exceeded the ring buffer consumption rate.
2. Increase `ring_buffer_size` in `/etc/sentinel/config.toml` (e.g. from `262144` to `524288` or `1048576`).
3. Reload daemon: `sudo systemctl restart sentineld.service`.

### 2.4 Unfreezing a Mistakenly Suspended Process
**Symptom**: A developer application was paused (`SIGSTOP`) due to heuristic grey score.
**Resolution**:
```bash
# 1. Identify TGID
sntctl status

# 2. Issue authorized administrative unfreeze
sudo sntctl process unfreeze <TGID>

# 3. Add exception to /etc/sentinel/rules.toml if benign
sudo sntctl policy reload
```
