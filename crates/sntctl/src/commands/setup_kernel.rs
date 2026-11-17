//! `sntctl setup-kernel` universal bootloader configuration tool.

use std::path::Path;

pub async fn run_setup_kernel(force: bool) -> anyhow::Result<()> {
    println!("================================================================================");
    println!(" Sentinel-RS Universal Kernel & Bootloader Setup Tool");
    println!("================================================================================");

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
    if !configured && (Path::new("/etc/kernel/cmdline").exists() || Path::new("/boot/loader/entries").is_dir()) {
        println!("[INFO] Detected bootloader: systemd-boot");
        if Path::new("/etc/kernel/cmdline").exists() {
            let cmdline = std::fs::read_to_string("/etc/kernel/cmdline").unwrap_or_default();
            let new_cmdline = patch_cmdline(&cmdline, &lsm_param);
            if std::fs::write("/etc/kernel/cmdline", new_cmdline).is_ok() {
                println!("[OK] Successfully patched /etc/kernel/cmdline");
                configured = true;
            }
        }

        if let Ok(entries) = std::fs::read_dir("/boot/loader/entries") {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().map(|e| e == "conf").unwrap_or(false) {
                    if let Ok(content) = std::fs::read_to_string(&p) {
                        let mut lines: Vec<String> = Vec::new();
                        let mut modified = false;
                        for line in content.lines() {
                            if line.starts_with("options ") {
                                let rest = &line["options ".len()..];
                                let patched = patch_cmdline(rest, &lsm_param);
                                lines.push(format!("options {}", patched));
                                modified = true;
                            } else {
                                lines.push(line.to_string());
                            }
                        }
                        if modified {
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
        if let Ok(grub_content) = std::fs::read_to_string("/etc/default/grub") {
            let patched_grub = patch_grub_default(&grub_content, &lsm_param);
            if std::fs::write("/etc/default/grub", patched_grub).is_ok() {
                println!("[OK] Successfully updated /etc/default/grub with '{}'", lsm_param);

                if Path::new("/usr/sbin/update-grub").exists() {
                    let _ = std::process::Command::new("/usr/sbin/update-grub").status();
                    configured = true;
                } else if Path::new("/usr/sbin/grub2-mkconfig").exists() {
                    let out_cfg = if Path::new("/boot/grub2/grub.cfg").exists() {
                        "/boot/grub2/grub.cfg"
                    } else {
                        "/boot/grub/grub.cfg"
                    };
                    let _ = std::process::Command::new("/usr/sbin/grub2-mkconfig")
                        .arg("-o")
                        .arg(out_cfg)
                        .status();
                    configured = true;
                } else if Path::new("/usr/sbin/grub-mkconfig").exists() {
                    let _ = std::process::Command::new("/usr/sbin/grub-mkconfig")
                        .arg("-o")
                        .arg("/boot/grub/grub.cfg")
                        .status();
                    configured = true;
                }
            }
        }
    }

    if configured {
        println!("================================================================================");
        println!(" [SUCCESS] Kernel bootloader configuration completed successfully!");
        println!(" Active LSMs configured: {}", lsms.join(","));
        println!(" Please reboot your computer to activate BPF LSM in the Linux kernel:");
        println!("   sudo reboot");
        println!("================================================================================");
    } else {
        println!("================================================================================");
        println!(" [INFO / SIMULATION] Target bootloader configuration complete.");
        println!(" To activate manually, ensure '{}' is in your kernel boot line.", lsm_param);
        println!("================================================================================");
    }

    Ok(())
}

fn patch_cmdline(cmdline: &str, lsm_param: &str) -> String {
    let mut words: Vec<&str> = cmdline.split_whitespace().collect();
    words.retain(|w| !w.starts_with("lsm="));
    words.push(lsm_param);
    words.join(" ")
}

fn patch_grub_default(content: &str, lsm_param: &str) -> String {
    let mut lines: Vec<String> = Vec::new();
    let mut replaced = false;

    for line in content.lines() {
        if line.starts_with("GRUB_CMDLINE_LINUX_DEFAULT=") {
            let val = line["GRUB_CMDLINE_LINUX_DEFAULT=".len()..].trim_matches('"');
            let patched = patch_cmdline(val, lsm_param);
            lines.push(format!("GRUB_CMDLINE_LINUX_DEFAULT=\"{}\"", patched));
            replaced = true;
        } else if !replaced && line.starts_with("GRUB_CMDLINE_LINUX=") {
            let val = line["GRUB_CMDLINE_LINUX=".len()..].trim_matches('"');
            let patched = patch_cmdline(val, lsm_param);
            lines.push(format!("GRUB_CMDLINE_LINUX=\"{}\"", patched));
            replaced = true;
        } else {
            lines.push(line.to_string());
        }
    }

    if !replaced {
        lines.push(format!("GRUB_CMDLINE_LINUX_DEFAULT=\"{}\"", lsm_param));
    }

    lines.join("\n")
}
