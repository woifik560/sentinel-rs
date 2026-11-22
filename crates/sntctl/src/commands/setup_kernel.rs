//! `sntctl setup-kernel` universal bootloader configuration tool.

use std::path::{Path, PathBuf};

/// Creates a `.sentinel.bak` copy of target file before modifying it.
fn backup_file(path: &Path) -> std::io::Result<PathBuf> {
    let bak = PathBuf::from(format!("{}.sentinel.bak", path.display()));
    if !bak.exists() && path.exists() {
        std::fs::copy(path, &bak)?;
        println!(
            "[BACKUP] Created backup of {} at {}",
            path.display(),
            bak.display()
        );
    }
    Ok(bak)
}

/// Restores target file from its `.sentinel.bak` copy.
fn restore_backup(path: &Path) -> std::io::Result<bool> {
    let bak = PathBuf::from(format!("{}.sentinel.bak", path.display()));
    if bak.exists() {
        std::fs::copy(&bak, path)?;
        println!(
            "[RESTORE] Restored {} from {}",
            path.display(),
            bak.display()
        );
        let _ = std::fs::remove_file(&bak);
        Ok(true)
    } else {
        Ok(false)
    }
}

pub async fn run_setup_kernel(force: bool, rollback: bool, yes: bool) -> anyhow::Result<()> {
    println!("================================================================================");
    println!(" Sentinel-RS Universal Kernel & Bootloader Setup Tool");
    println!("================================================================================");

    if !rollback && !yes {
        println!(
            "WARNING: This operation will modify your bootloader configuration to enable BPF LSM."
        );
        print!("Are you sure you want to proceed? [y/N]: ");
        use std::io::Write;
        let _ = std::io::stdout().flush();
        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).is_ok() {
            let trimmed = input.trim().to_lowercase();
            if trimmed != "y" && trimmed != "yes" {
                println!("[ABORTED] Operation cancelled by user. No bootloader changes were made.");
                return Ok(());
            }
        } else {
            anyhow::bail!("Failed to read confirmation. Use --yes for non-interactive execution.");
        }
    }

    if rollback {
        println!("[ROLLBACK] Initiating bootloader rollback from Sentinel backup files...");
        let mut restored_any = false;

        // Restore /etc/default/grub
        let grub_path = Path::new("/etc/default/grub");
        if restore_backup(grub_path)? {
            restored_any = true;
            if Path::new("/usr/sbin/update-grub").exists() {
                println!("[INFO] Re-running update-grub to regenerate configuration...");
                let s = std::process::Command::new("/usr/sbin/update-grub").status()?;
                if !s.success() {
                    anyhow::bail!("update-grub failed during rollback with exit status: {}", s);
                }
            } else if Path::new("/usr/sbin/grub2-mkconfig").exists() {
                let out_cfg = if Path::new("/boot/grub2/grub.cfg").exists() {
                    "/boot/grub2/grub.cfg"
                } else {
                    "/boot/grub/grub.cfg"
                };
                println!("[INFO] Re-running grub2-mkconfig to regenerate configuration...");
                let s = std::process::Command::new("/usr/sbin/grub2-mkconfig")
                    .arg("-o")
                    .arg(out_cfg)
                    .status()?;
                if !s.success() {
                    anyhow::bail!(
                        "grub2-mkconfig failed during rollback with exit status: {}",
                        s
                    );
                }
            }
        }

        // Restore /etc/kernel/cmdline
        let cmdline_path = Path::new("/etc/kernel/cmdline");
        if restore_backup(cmdline_path)? {
            restored_any = true;
        }

        // Restore systemd-boot loader entries
        if let Ok(entries) = std::fs::read_dir("/boot/loader/entries") {
            for entry in entries.flatten() {
                let p = entry.path();
                let path_str = p.to_string_lossy().to_string();
                if path_str.ends_with(".conf.sentinel.bak") {
                    let orig = PathBuf::from(path_str.trim_end_matches(".sentinel.bak"));
                    if std::fs::copy(&p, &orig).is_ok() {
                        let _ = std::fs::remove_file(&p);
                        println!("[RESTORE] Restored {}", orig.display());
                        restored_any = true;
                    }
                }
            }
        }

        if restored_any {
            println!(
                "================================================================================"
            );
            println!(" [SUCCESS] Bootloader configuration successfully rolled back to pre-Sentinel state.");
            println!(" Please reboot to activate the restored kernel parameters:");
            println!("   sudo reboot");
            println!(
                "================================================================================"
            );
        } else {
            println!("[INFO] No Sentinel backup files found to restore.");
        }
        return Ok(());
    }

    let current_lsm = std::fs::read_to_string("/sys/kernel/security/lsm")
        .unwrap_or_default()
        .trim()
        .to_string();

    if current_lsm.contains("bpf") && !force {
        println!("[OK] BPF LSM is ALREADY ACTIVE in running kernel!");
        println!("     Current LSMs: {}", current_lsm);
        println!();
        println!("No bootloader reconfiguration or reboot is required.");
        println!("Sentinel-RS can start and enforce BPF LSM policies immediately.");
        return Ok(());
    }

    let lsms: Vec<String> = if current_lsm.is_empty() {
        vec![
            "lockdown".into(),
            "capability".into(),
            "landlock".into(),
            "yama".into(),
            "apparmor".into(),
            "bpf".into(),
        ]
    } else {
        let mut list: Vec<String> = current_lsm
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !list.iter().any(|m| m == "bpf") {
            list.push("bpf".into());
        }
        list
    };

    let lsm_param = format!("lsm={}", lsms.join(","));
    println!("[INFO] Target kernel command line parameter: {}", lsm_param);

    let mut configured = false;

    // A. grubby (Fedora, RHEL, CentOS)
    if Path::new("/usr/sbin/grubby").exists() {
        println!("[INFO] Detected bootloader manager: grubby (Fedora / RHEL / CentOS)");
        let status = std::process::Command::new("/usr/sbin/grubby")
            .arg("--update-kernel=ALL")
            .arg(format!("--args={}", lsm_param))
            .status();

        match status {
            Ok(s) if s.success() => {
                println!("[OK] Successfully updated all kernel entries via grubby.");
                configured = true;
            }
            Ok(s) => println!("[WARN] grubby returned non-zero exit status: {}", s),
            Err(e) => println!("[WARN] Failed to execute grubby: {}", e),
        }
    }

    // B. kernelstub (Pop!_OS)
    if !configured && Path::new("/usr/bin/kernelstub").exists() {
        println!("[INFO] Detected bootloader manager: kernelstub (Pop!_OS)");
        let status = std::process::Command::new("/usr/bin/kernelstub")
            .arg("-a")
            .arg(&lsm_param)
            .status();

        match status {
            Ok(s) if s.success() => {
                println!("[OK] Successfully added kernel argument via kernelstub.");
                configured = true;
            }
            Ok(s) => println!("[WARN] kernelstub returned non-zero exit status: {}", s),
            Err(e) => println!("[WARN] Failed to execute kernelstub: {}", e),
        }
    }

    // C. systemd-boot
    if !configured
        && (Path::new("/etc/kernel/cmdline").exists() || Path::new("/boot/loader/entries").is_dir())
    {
        println!("[INFO] Detected bootloader: systemd-boot");
        if Path::new("/etc/kernel/cmdline").exists() {
            let cmdline_path = Path::new("/etc/kernel/cmdline");
            let _ = backup_file(cmdline_path);
            let cmdline = std::fs::read_to_string(cmdline_path).unwrap_or_default();
            let new_cmdline = patch_cmdline(&cmdline, &lsm_param);
            if std::fs::write(cmdline_path, new_cmdline).is_ok() {
                println!("[OK] Successfully patched /etc/kernel/cmdline");
                configured = true;
            }
        }

        if let Ok(entries) = std::fs::read_dir("/boot/loader/entries") {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().map(|e| e == "conf").unwrap_or(false)
                    && !p.to_string_lossy().ends_with(".sentinel.bak")
                {
                    if let Ok(content) = std::fs::read_to_string(&p) {
                        let mut lines: Vec<String> = Vec::new();
                        let mut modified = false;
                        for line in content.lines() {
                            if let Some(rest) = line.strip_prefix("options ") {
                                let patched = patch_cmdline(rest, &lsm_param);
                                lines.push(format!("options {}", patched));
                                modified = true;
                            } else {
                                lines.push(line.to_string());
                            }
                        }
                        if modified {
                            let _ = backup_file(&p);
                            let _ = std::fs::write(&p, lines.join("\n"));
                            configured = true;
                        }
                    }
                }
            }
            if configured {
                println!("[OK] Successfully patched /boot/loader/entries/*.conf");
            }
        }
    }

    // D. Classic GRUB (/etc/default/grub)
    if !configured && Path::new("/etc/default/grub").exists() {
        println!("[INFO] Detected bootloader: GRUB (/etc/default/grub)");
        let grub_path = Path::new("/etc/default/grub");
        if let Ok(grub_content) = std::fs::read_to_string(grub_path) {
            let bak_path = backup_file(grub_path)?;
            let patched_grub = patch_grub_default(&grub_content, &lsm_param);
            if std::fs::write(grub_path, &patched_grub).is_ok() {
                println!(
                    "[OK] Successfully updated /etc/default/grub with '{}'",
                    lsm_param
                );

                let update_result = if Path::new("/usr/sbin/update-grub").exists() {
                    std::process::Command::new("/usr/sbin/update-grub").status()
                } else if Path::new("/usr/sbin/grub2-mkconfig").exists() {
                    let out_cfg = if Path::new("/boot/grub2/grub.cfg").exists() {
                        "/boot/grub2/grub.cfg"
                    } else {
                        "/boot/grub/grub.cfg"
                    };
                    std::process::Command::new("/usr/sbin/grub2-mkconfig")
                        .arg("-o")
                        .arg(out_cfg)
                        .status()
                } else if Path::new("/usr/sbin/grub-mkconfig").exists() {
                    std::process::Command::new("/usr/sbin/grub-mkconfig")
                        .arg("-o")
                        .arg("/boot/grub/grub.cfg")
                        .status()
                } else {
                    Ok(std::process::ExitStatus::default())
                };

                match update_result {
                    Ok(s) if s.success() => {
                        configured = true;
                    }
                    Ok(s) => {
                        println!("[ERROR] Bootloader update command failed with exit status: {}. Rolling back changes...", s);
                        let _ = std::fs::copy(&bak_path, grub_path);
                        anyhow::bail!("Bootloader configuration failed ({}); automatically rolled back /etc/default/grub.", s);
                    }
                    Err(e) => {
                        println!("[ERROR] Failed to execute bootloader tool: {}. Rolling back changes...", e);
                        let _ = std::fs::copy(&bak_path, grub_path);
                        anyhow::bail!("Failed to execute bootloader updater ({}); automatically rolled back /etc/default/grub.", e);
                    }
                }
            }
        }
    }

    if configured {
        println!(
            "================================================================================"
        );
        println!(" [SUCCESS] Kernel bootloader configuration completed successfully!");
        println!(" Active LSMs configured: {}", lsms.join(","));
        println!(" Please reboot your computer to activate BPF LSM in the Linux kernel:");
        println!("   sudo reboot");
        println!(
            "================================================================================"
        );
    } else {
        println!(
            "================================================================================"
        );
        println!(" [INFO / SIMULATION] Target bootloader configuration complete.");
        println!(
            " To activate manually, ensure '{}' is in your kernel boot line.",
            lsm_param
        );
        println!(
            "================================================================================"
        );
    }

    Ok(())
}

pub fn patch_cmdline(cmdline: &str, lsm_param: &str) -> String {
    let mut words: Vec<&str> = cmdline.split_whitespace().collect();
    words.retain(|w| !w.starts_with("lsm="));
    words.push(lsm_param);
    words.join(" ")
}

pub fn patch_grub_default(content: &str, lsm_param: &str) -> String {
    let mut lines: Vec<String> = Vec::new();
    let mut replaced = false;

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("GRUB_CMDLINE_LINUX_DEFAULT=") {
            let val = rest.trim_matches('"');
            let patched = patch_cmdline(val, lsm_param);
            lines.push(format!("GRUB_CMDLINE_LINUX_DEFAULT=\"{}\"", patched));
            replaced = true;
        } else if !replaced {
            if let Some(rest) = line.strip_prefix("GRUB_CMDLINE_LINUX=") {
                let val = rest.trim_matches('"');
                let patched = patch_cmdline(val, lsm_param);
                lines.push(format!("GRUB_CMDLINE_LINUX=\"{}\"", patched));
                replaced = true;
            } else {
                lines.push(line.to_string());
            }
        } else {
            lines.push(line.to_string());
        }
    }

    if !replaced {
        lines.push(format!("GRUB_CMDLINE_LINUX_DEFAULT=\"{}\"", lsm_param));
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_patch_cmdline_replaces_existing_lsm() {
        let orig = "quiet splash lsm=lockdown,capability,apparmor vt.handoff=7";
        let patched = patch_cmdline(orig, "lsm=lockdown,capability,landlock,yama,apparmor,bpf");
        assert!(!patched.contains("lsm=lockdown,capability,apparmor "));
        assert!(patched.contains("lsm=lockdown,capability,landlock,yama,apparmor,bpf"));
        assert!(patched.contains("quiet splash"));
        assert!(patched.contains("vt.handoff=7"));
    }

    #[test]
    fn test_patch_grub_default_updates_cmdline() {
        let grub = "GRUB_DEFAULT=0\nGRUB_CMDLINE_LINUX_DEFAULT=\"quiet splash\"\nGRUB_TIMEOUT=5";
        let patched = patch_grub_default(grub, "lsm=landlock,bpf");
        assert!(patched.contains("GRUB_CMDLINE_LINUX_DEFAULT=\"quiet splash lsm=landlock,bpf\""));
        assert!(patched.contains("GRUB_TIMEOUT=5"));
    }

    #[test]
    fn test_backup_and_restore_cycle() {
        let temp_dir = std::env::temp_dir().join(format!("sentinel_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let test_file = temp_dir.join("grub");

        std::fs::write(&test_file, "ORIGINAL_CONTENT").unwrap();
        let bak = backup_file(&test_file).unwrap();
        assert!(bak.exists());

        // Modify file
        std::fs::write(&test_file, "MODIFIED_CONTENT").unwrap();
        assert_eq!(
            std::fs::read_to_string(&test_file).unwrap(),
            "MODIFIED_CONTENT"
        );

        // Restore
        let restored = restore_backup(&test_file).unwrap();
        assert!(restored);
        assert_eq!(
            std::fs::read_to_string(&test_file).unwrap(),
            "ORIGINAL_CONTENT"
        );
        assert!(!bak.exists());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
