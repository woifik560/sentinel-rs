//! Contextual Policy Engine for legitimate toolchains ("who + which secret + where to connect").
//!
//! Evaluates fine-grained contextual exceptions:
//! e.g. `/usr/bin/ssh` with `~/.ssh/id_ed25519` can connect to `github.com:22` or `gitlab.com:22`
//! without prompting the user, but triggers an interactive alert if connecting to an arbitrary IP or port.

use std::path::Path;
use sentinel_common::config::ContextRule;
use sentinel_common::process::SecretCategory;

#[derive(Clone, Default)]
pub struct ContextPolicyEngine {
    rules: Vec<ContextRule>,
}

impl ContextPolicyEngine {
    pub fn new(rules: Vec<ContextRule>) -> Self {
        Self { rules }
    }

    /// Add default built-in contextual rules for standard developer tools if not specified in config.
    pub fn with_default_rules(mut self) -> Self {
        if self.rules.is_empty() {
            self.rules = Self::builtin_developer_rules();
        }
        self
    }

    /// Evaluates if a connection attempt is pre-approved by a contextual policy rule.
    pub fn is_allowed(
        &self,
        exe_path: &Path,
        exe_sha256: Option<&str>,
        secret_category: Option<&SecretCategory>,
        dest_ip: Option<&str>,
        dest_port: u16,
        dest_domain: Option<&str>,
    ) -> Option<&ContextRule> {
        let exe_str = exe_path.to_string_lossy();
        let exe_name = exe_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();

        for rule in &self.rules {
            // 1. Binary path or name check
            if let Some(ref path) = rule.binary_path {
                let rule_str = path.to_string_lossy();
                if rule_str != exe_str && rule_str != exe_name {
                    continue;
                }
            }

            // 2. Binary SHA-256 integrity check (if specified)
            if let Some(ref expected_sha) = rule.binary_sha256 {
                if let Some(actual_sha) = exe_sha256 {
                    if !expected_sha.eq_ignore_ascii_case(actual_sha) {
                        continue;
                    }
                } else {
                    continue;
                }
            }

            // 3. Secret category check
            if let Some(ref cat_str) = rule.secret_category {
                if let Some(actual_cat) = secret_category {
                    let cat_matches = match actual_cat {
                        SecretCategory::SshKey => cat_str.eq_ignore_ascii_case("ssh"),
                        SecretCategory::GpgKey => cat_str.eq_ignore_ascii_case("gpg"),
                        SecretCategory::BrowserCookies => cat_str.eq_ignore_ascii_case("browser"),
                        SecretCategory::TelegramData => cat_str.eq_ignore_ascii_case("telegram"),
                        SecretCategory::CryptoWallet => cat_str.eq_ignore_ascii_case("crypto"),
                        SecretCategory::Other(s) => s.contains(cat_str),
                    };
                    if !cat_matches {
                        continue;
                    }
                }
            }

            // 4. Destination port check
            if !rule.allowed_ports.is_empty() && !rule.allowed_ports.contains(&dest_port) {
                continue;
            }

            // 5. Destination target check (domain or IP matching)
            let mut dest_matched = rule.allowed_destinations.is_empty();
            for allowed in &rule.allowed_destinations {
                if let Some(domain) = dest_domain {
                    if domain == allowed
                        || domain.ends_with(&format!(".{}", allowed))
                        || allowed == "*"
                    {
                        dest_matched = true;
                        break;
                    }
                }
                if let Some(ip) = dest_ip {
                    if ip == allowed || allowed == "*" {
                        dest_matched = true;
                        break;
                    }
                }
            }

            if dest_matched {
                return Some(rule);
            }
        }

        None
    }

    /// Standard baseline rules for Git, SSH, GitHub CLI, and Package Managers.
    pub fn builtin_developer_rules() -> Vec<ContextRule> {
        vec![
            ContextRule {
                id: "DEV_SSH_GITHUB".into(),
                binary_path: Some(Path::new("/usr/bin/ssh").to_path_buf()),
                binary_sha256: None,
                secret_category: Some("ssh".into()),
                allowed_destinations: vec![
                    "github.com".into(),
                    "gitlab.com".into(),
                    "bitbucket.org".into(),
                    "140.82.112.3".into(),
                    "140.82.112.4".into(),
                ],
                allowed_ports: vec![22, 443],
                description: "Pre-approved SSH access to GitHub/GitLab repository remotes".into(),
            },
            ContextRule {
                id: "DEV_GIT_REMOTES".into(),
                binary_path: Some(Path::new("/usr/bin/git").to_path_buf()),
                binary_sha256: None,
                secret_category: Some("ssh".into()),
                allowed_destinations: vec![
                    "github.com".into(),
                    "gitlab.com".into(),
                    "bitbucket.org".into(),
                ],
                allowed_ports: vec![22, 443, 9418],
                description: "Pre-approved Git sync to recognized development forges".into(),
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_rule_matching_ssh_github() {
        let engine = ContextPolicyEngine::default().with_default_rules();

        // 1. /usr/bin/ssh connecting to github.com on port 22 with SshKey -> ALLOWED!
        let rule = engine.is_allowed(
            Path::new("/usr/bin/ssh"),
            None,
            Some(&SecretCategory::SshKey),
            Some("140.82.112.3"),
            22,
            Some("github.com"),
        );
        assert!(rule.is_some());
        assert_eq!(rule.unwrap().id, "DEV_SSH_GITHUB");

        // 2. Same /usr/bin/ssh connecting to an unknown rogue IP on port 4444 -> BLOCKED / NOT MATCHED!
        let rogue = engine.is_allowed(
            Path::new("/usr/bin/ssh"),
            None,
            Some(&SecretCategory::SshKey),
            Some("185.220.101.5"),
            4444,
            None,
        );
        assert!(rogue.is_none());
    }
}
