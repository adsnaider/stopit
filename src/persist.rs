//! Persisting interactive approvals (`[p]`) to `.stopit.toml` (DESIGN.md §4.2).
//!
//! When the user answers `[p] allow and persist` on the `stopit server`
//! terminal, stopit updates `.stopit.toml` in the workspace:
//!
//! * **Clipboard writes (`ClipboardWrite`):** sets
//!   `[terminal] clipboard_write = "allow"`.
//! * **`stopit-grant` requests (`Grant`):** adds the requested `fs.ro`,
//!   `fs.rw`, and `network` (`mode` / `allow_domains`) grants to a `config`
//!   provider named `"approvals-<profile>"`.
//! * **Brokered shim commands (`Shim`):** writes the shim into the
//!   `"approvals-<profile>"` `config` provider for the caller profile with the
//!   matched rule (or `default`) changed to `decision = "allow"`.

use crate::config::{ConfigLayer, ProfileRef, ProviderEntry, ProviderKind};
use crate::manifest::{
    Domain, Manifest, PathPattern, ShimAction, ShimKind, ShimName, ShimRule, ShimSpec,
};
use crate::policy::{Decision, NetworkMode};
use crate::resolve::approvals_provider_name;

/// Marker comment separating hand-written `.stopit.toml` content from the
/// `[[provider]]` entries managed by `[p] allow and persist`.
pub const PERSIST_HEADER: &str = "# --- stopit persisted approvals ---";

/// What `[p] allow and persist` writes to `.stopit.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistTarget {
    /// Set `[terminal] clipboard_write = "allow"`.
    ClipboardWrite,
    /// Allow the matched rule of `shim` in `caller_profile`.
    Shim {
        /// Profile that invoked the shim.
        caller_profile: ProfileRef,
        /// Name of the shim.
        shim: ShimName,
        /// Matched rule pattern (`"default"` or a [`SubcommandPattern`]).
        matched_rule: String,
        /// Target profile the command runs in.
        target_profile: ProfileRef,
        /// Current effective [`ShimSpec`] of `shim` in `caller_profile`.
        spec: ShimSpec,
    },
    /// Add `stopit-grant` capabilities to `caller_profile`.
    Grant {
        /// Profile that invoked `stopit-grant`.
        caller_profile: ProfileRef,
        /// `+ro:<path>` patterns.
        ro: Vec<String>,
        /// `+rw:<path>` patterns.
        rw: Vec<String>,
        /// `+net:<domain>` entries.
        net_domains: Vec<Domain>,
        /// Whether `+net:full` was requested.
        net_full: bool,
    },
}

/// Applies `target` to the `.stopit.toml` document `existing` and returns the
/// updated TOML text, validated with [`ConfigLayer::from_toml_str`].
pub fn update_config_toml(existing: &str, target: &PersistTarget) -> Result<String, String> {
    ConfigLayer::from_toml_str(existing).map_err(|e| e.to_string())?;
    let (user_part, persisted_part) = split_persisted_section(existing);

    match target {
        PersistTarget::ClipboardWrite => {
            let updated_user = set_clipboard_write_allow(user_part)?;
            let out = join_raw_sections(&updated_user, persisted_part);
            ConfigLayer::from_toml_str(&out).map_err(|e| e.to_string())?;
            Ok(out)
        }
        PersistTarget::Grant {
            caller_profile,
            ro,
            rw,
            net_domains,
            net_full,
        } => {
            let user_layer = ConfigLayer::from_toml_str(user_part).map_err(|e| e.to_string())?;
            let mut managed_layer = match persisted_part {
                Some(p) => ConfigLayer::from_toml_str(p).map_err(|e| e.to_string())?,
                None => ConfigLayer::default(),
            };
            let sandbox =
                ensure_approvals_manifest(&user_layer, &mut managed_layer, caller_profile)?;
            for raw in ro {
                let pat: PathPattern = raw.parse().map_err(|e| format!("{e}"))?;
                sandbox.grants.fs.masked.retain(|p| p != &pat);
                sandbox.grants.fs.protected.retain(|p| p != &pat);
                if !sandbox.grants.fs.ro.contains(&pat) && !sandbox.grants.fs.rw.contains(&pat) {
                    sandbox.grants.fs.ro.push(pat);
                }
            }
            for raw in rw {
                let pat: PathPattern = raw.parse().map_err(|e| format!("{e}"))?;
                sandbox.grants.fs.ro.retain(|p| p != &pat);
                sandbox.grants.fs.masked.retain(|p| p != &pat);
                sandbox.grants.fs.protected.retain(|p| p != &pat);
                if !sandbox.grants.fs.rw.contains(&pat) {
                    sandbox.grants.fs.rw.push(pat);
                }
            }
            for domain in net_domains {
                if !sandbox.grants.network.allow_domains.contains(domain) {
                    sandbox.grants.network.allow_domains.push(domain.clone());
                }
                if sandbox.grants.network.mode != Some(NetworkMode::Full) {
                    sandbox.grants.network.mode = Some(NetworkMode::Proxy);
                }
            }
            if *net_full {
                sandbox.grants.network.mode = Some(NetworkMode::Full);
            }
            let out = join_sections(user_part, &managed_layer.providers)?;
            ConfigLayer::from_toml_str(&out).map_err(|e| e.to_string())?;
            Ok(out)
        }
        PersistTarget::Shim {
            caller_profile,
            shim,
            matched_rule,
            target_profile,
            spec,
        } => {
            let user_layer = ConfigLayer::from_toml_str(user_part).map_err(|e| e.to_string())?;
            let mut managed_layer = match persisted_part {
                Some(p) => ConfigLayer::from_toml_str(p).map_err(|e| e.to_string())?,
                None => ConfigLayer::default(),
            };
            let sandbox =
                ensure_approvals_manifest(&user_layer, &mut managed_layer, caller_profile)?;
            let mut updated_spec = sandbox
                .grants
                .shims
                .get(shim)
                .cloned()
                .unwrap_or_else(|| spec.clone());
            allow_shim_rule(&mut updated_spec, matched_rule, target_profile)?;
            sandbox.grants.shims.insert(shim.clone(), updated_spec);

            let out = join_sections(user_part, &managed_layer.providers)?;
            ConfigLayer::from_toml_str(&out).map_err(|e| e.to_string())?;
            Ok(out)
        }
    }
}

/// Splits `existing` into the user-managed prefix before [`PERSIST_HEADER`] and
/// the managed suffix starting at [`PERSIST_HEADER`].
fn split_persisted_section(existing: &str) -> (&str, Option<&str>) {
    if let Some(idx) = existing.find(PERSIST_HEADER)
        && (idx == 0 || existing.as_bytes()[idx - 1] == b'\n')
    {
        return (&existing[..idx], Some(&existing[idx..]));
    }
    (existing, None)
}

/// Returns a mutable reference to the `[provider.sandbox]` manifest of the
/// approvals `config` provider for `caller_profile` in `managed_layer` (after
/// [`PERSIST_HEADER`]), creating the provider entry if absent and refusing to
/// clobber a hand-written entry of the same name in `user_layer`.
fn ensure_approvals_manifest<'a>(
    user_layer: &ConfigLayer,
    managed_layer: &'a mut ConfigLayer,
    caller_profile: &ProfileRef,
) -> Result<&'a mut Manifest, String> {
    let name = approvals_provider_name(caller_profile);
    if user_layer.providers.iter().any(|p| p.name == name) {
        return Err(format!(
            "provider {:?} is already defined above {PERSIST_HEADER:?} in .stopit.toml; \
             rename or remove that hand-written entry to persist approvals for profile {:?}",
            name.as_str(),
            caller_profile.as_str()
        ));
    }
    let idx = match managed_layer.providers.iter().position(|p| p.name == name) {
        Some(idx) => idx,
        None => {
            managed_layer.providers.push(ProviderEntry {
                name: name.clone(),
                enabled: true,
                kind: ProviderKind::Config {
                    profile: caller_profile.clone(),
                    sandbox: Box::new(Manifest::default()),
                },
            });
            managed_layer.providers.len() - 1
        }
    };
    if !managed_layer.providers[idx].enabled {
        return Err(format!(
            "provider {:?} in .stopit.toml is disabled (`enabled = false`); \
             re-enable or remove it to persist approvals for profile {:?}",
            name.as_str(),
            caller_profile.as_str()
        ));
    }
    match &managed_layer.providers[idx].kind {
        ProviderKind::Config { profile, .. } if profile == caller_profile => {}
        ProviderKind::Config { profile, .. } => {
            return Err(format!(
                "provider {:?} in .stopit.toml targets profile {:?}, not {:?}",
                name.as_str(),
                profile.as_str(),
                caller_profile.as_str()
            ));
        }
        other => {
            return Err(format!(
                "provider {:?} in .stopit.toml has type {:?}, not \"config\"",
                name.as_str(),
                other.type_name()
            ));
        }
    }
    let ProviderKind::Config { sandbox, .. } = &mut managed_layer.providers[idx].kind else {
        return Err(format!(
            "provider {:?} in .stopit.toml is not a config provider",
            name.as_str()
        ));
    };
    Ok(sandbox)
}

/// Updates `spec` so `matched_rule` (`"default"` or a [`ShimMatcher::key`])
/// has `decision = "allow"` in `target_profile`.
pub fn allow_shim_rule(
    spec: &mut ShimSpec,
    matched_rule: &str,
    target_profile: &ProfileRef,
) -> Result<(), String> {
    let ShimKind::Declarative { default, rules, .. } = &mut spec.kind else {
        return Err(
            "proxy shims decide dynamically and cannot be persisted as declarative rules"
                .to_owned(),
        );
    };
    if matched_rule == "default" {
        *default = ShimAction {
            decision: Decision::Allow,
            profile: Some(target_profile.clone()),
        };
        return Ok(());
    }
    let mut matched_any = false;
    for rule in rules.iter_mut() {
        if rule.matcher.key() == matched_rule {
            matched_any = true;
            rule.decision = Decision::Allow;
            rule.profile = Some(target_profile.clone());
        }
    }
    if !matched_any {
        return Err(format!(
            "cannot find rule {matched_rule:?} in shim to mark as allowed"
        ));
    }
    Ok(())
}

/// Sets `[terminal] clipboard_write = "allow"` in `user_part`, preserving
/// existing comments and formatting whenever possible.
fn set_clipboard_write_allow(user_part: &str) -> Result<String, String> {
    let mut root: toml::Table = toml::from_str(user_part).map_err(|e| e.to_string())?;
    if !root.contains_key("terminal") {
        let mut out = user_part.trim_end().to_owned();
        if !out.is_empty() {
            out.push_str("\n\n");
        }
        out.push_str("[terminal]\nclipboard_write = \"allow\"\n");
        return Ok(out);
    }
    if let Some(edited) = try_edit_clipboard_in_place(user_part)
        && ConfigLayer::from_toml_str(&edited)
            .is_ok_and(|l| l.terminal_clipboard_write == Some(crate::config::ClipboardWrite::Allow))
    {
        return Ok(edited);
    }
    let terminal = root
        .get_mut("terminal")
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| "`terminal` in .stopit.toml is not a table".to_owned())?;
    terminal.insert(
        "clipboard_write".to_owned(),
        toml::Value::String("allow".to_owned()),
    );
    toml::to_string_pretty(&root).map_err(|e| e.to_string())
}

/// Attempts an in-place line edit of `clipboard_write` under `[terminal]` (or
/// `terminal.clipboard_write` at top level) so comments and formatting in
/// `user_part` stay untouched.
fn try_edit_clipboard_in_place(user_part: &str) -> Option<String> {
    let mut lines: Vec<String> = user_part.lines().map(str::to_owned).collect();
    let mut in_terminal = false;
    let mut terminal_header_idx = None;
    let mut replaced = false;

    for (idx, line) in lines.iter_mut().enumerate() {
        let code = line.split('#').next().unwrap_or("").trim();
        if code.starts_with('[') {
            in_terminal = code == "[terminal]";
            if in_terminal {
                terminal_header_idx = Some(idx);
            }
            continue;
        }
        if let Some((key, _)) = code.split_once('=') {
            let key = key.trim();
            let comment = line.find('#').map(|i| &line[i..]).unwrap_or("");
            let suffix = if comment.is_empty() {
                String::new()
            } else {
                format!(" {comment}")
            };
            if in_terminal && key == "clipboard_write" {
                *line = format!("clipboard_write = \"allow\"{suffix}");
                replaced = true;
                break;
            } else if !in_terminal && key == "terminal.clipboard_write" {
                *line = format!("terminal.clipboard_write = \"allow\"{suffix}");
                replaced = true;
                break;
            }
        }
    }

    if !replaced {
        let idx = terminal_header_idx?;
        lines.insert(idx + 1, "clipboard_write = \"allow\"".to_owned());
    }

    let mut out = lines.join("\n");
    out.push('\n');
    Some(out)
}

/// Joins `updated_user` and an untouched `persisted_part` (starting at
/// [`PERSIST_HEADER`]).
fn join_raw_sections(updated_user: &str, persisted_part: Option<&str>) -> String {
    let mut out = updated_user.trim_end().to_owned();
    match persisted_part {
        None => {
            if !out.is_empty() {
                out.push('\n');
            }
            out
        }
        Some(persisted) => {
            if !out.is_empty() {
                out.push_str("\n\n");
            }
            out.push_str(persisted.trim_end());
            out.push('\n');
            out
        }
    }
}

/// Joins `user_part` and the rendered managed `approvals` providers with
/// [`PERSIST_HEADER`].
fn join_sections(user_part: &str, approvals: &[ProviderEntry]) -> Result<String, String> {
    let mut out = user_part.trim_end().to_owned();
    if approvals.is_empty() {
        if !out.is_empty() {
            out.push('\n');
        }
        return Ok(out);
    }
    if !out.is_empty() {
        out.push_str("\n\n");
    }
    out.push_str(PERSIST_HEADER);
    out.push('\n');
    for (i, entry) in approvals.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&render_approvals_provider(entry)?);
    }
    Ok(out)
}

/// Renders an approvals `config` provider entry as clean TOML without panicking
/// if the section below [`PERSIST_HEADER`] was hand-edited to hold a disabled
/// or non-`config` entry.
fn render_approvals_provider(entry: &ProviderEntry) -> Result<String, String> {
    if !entry.enabled {
        return Err(format!(
            "provider {:?} under {PERSIST_HEADER:?} has `enabled = false`",
            entry.name.as_str()
        ));
    }
    let ProviderKind::Config { profile, sandbox } = &entry.kind else {
        return Err(format!(
            "provider {:?} under {PERSIST_HEADER:?} has type {:?}, not \"config\"",
            entry.name.as_str(),
            entry.kind.type_name()
        ));
    };
    let mut out = String::new();
    out.push_str("[[provider]]\n");
    out.push_str(&format!("name = {}\n", toml_str(entry.name.as_str())));
    out.push_str("type = \"config\"\n");
    out.push_str(&format!("profile = {}\n", toml_str(profile.as_str())));
    let fs = &sandbox.grants.fs;
    if !fs.ro.is_empty()
        || !fs.rw.is_empty()
        || !fs.masked.is_empty()
        || !fs.protected.is_empty()
        || !fs.ephemeral.is_empty()
    {
        out.push_str("\n[provider.sandbox.fs]\n");
        if !fs.ro.is_empty() {
            out.push_str(&format!(
                "ro = {}\n",
                toml_str_array(fs.ro.iter().map(PathPattern::as_str))
            ));
        }
        if !fs.rw.is_empty() {
            out.push_str(&format!(
                "rw = {}\n",
                toml_str_array(fs.rw.iter().map(PathPattern::as_str))
            ));
        }
        if !fs.masked.is_empty() {
            out.push_str(&format!(
                "masked = {}\n",
                toml_str_array(fs.masked.iter().map(PathPattern::as_str))
            ));
        }
        if !fs.protected.is_empty() {
            out.push_str(&format!(
                "protected = {}\n",
                toml_str_array(fs.protected.iter().map(PathPattern::as_str))
            ));
        }
        if !fs.ephemeral.is_empty() {
            out.push_str(&format!(
                "ephemeral = {}\n",
                toml_str_array(fs.ephemeral.iter().map(PathPattern::as_str))
            ));
        }
    }
    let net = &sandbox.grants.network;
    if net.mode.is_some() || !net.allow_domains.is_empty() {
        out.push_str("\n[provider.sandbox.network]\n");
        if let Some(mode) = net.mode {
            out.push_str(&format!("mode = {}\n", toml_str(mode.as_str())));
        }
        if !net.allow_domains.is_empty() {
            out.push_str(&format!(
                "allow_domains = {}\n",
                toml_str_array(net.allow_domains.iter().map(Domain::as_str))
            ));
        }
    }
    for (shim_name, spec) in &sandbox.grants.shims {
        out.push_str(&format!(
            "\n[provider.sandbox.shims.{}]\n",
            toml_key(shim_name.as_str())
        ));
        match &spec.kind {
            ShimKind::Declarative {
                cmd,
                default,
                rules,
            } => {
                if cmd.args.is_empty() {
                    out.push_str(&format!("cmd = {}\n", toml_str(cmd.binary.as_str())));
                } else {
                    let all_args = std::iter::once(cmd.binary.as_str())
                        .chain(cmd.args.iter().map(|a| a.as_str()));
                    out.push_str(&format!("cmd = {}\n", toml_str_array(all_args)));
                }
                if spec.tty {
                    out.push_str("tty = true\n");
                }
                out.push_str(&format!("default = {}\n", render_action(default)));
                if !rules.is_empty() {
                    out.push_str("rules = [\n");
                    for rule in rules {
                        out.push_str(&format!("  {},\n", render_rule(rule)));
                    }
                    out.push_str("]\n");
                }
            }
            ShimKind::Proxy { proxy, protect, .. } => {
                out.push_str(&format!("proxy = {}\n", toml_str(proxy.as_str())));
                if !*protect {
                    out.push_str("protect = false\n");
                }
                if spec.tty {
                    out.push_str("tty = true\n");
                }
            }
            ShimKind::Disabled => {
                out.push_str("enabled = false\n");
            }
        }
    }
    Ok(out)
}

fn render_action(action: &ShimAction) -> String {
    match &action.profile {
        Some(profile) => format!(
            "{{ decision = {}, profile = {} }}",
            toml_str(action.decision.as_str()),
            toml_str(profile.as_str())
        ),
        None => format!("{{ decision = {} }}", toml_str(action.decision.as_str())),
    }
}

fn render_rule(rule: &ShimRule) -> String {
    let matcher_part = match &rule.matcher {
        crate::manifest::ShimMatcher::Literal(s) => format!("literal = {}", toml_str(s)),
        crate::manifest::ShimMatcher::Prefix(s) => format!("prefix = {}", toml_str(s)),
        crate::manifest::ShimMatcher::Regex(r) => format!("regex = {}", toml_str(r.as_str())),
        crate::manifest::ShimMatcher::Flags(f) => {
            format!(
                "flags = {}",
                toml_str_array(f.flags().iter().map(String::as_str))
            )
        }
    };
    let mut parts = vec![
        matcher_part,
        format!("decision = {}", toml_str(rule.decision.as_str())),
    ];
    if let Some(profile) = &rule.profile {
        parts.push(format!("profile = {}", toml_str(profile.as_str())));
    }
    format!("{{ {} }}", parts.join(", "))
}

fn toml_str(s: &str) -> String {
    toml::Value::String(s.to_owned()).to_string()
}

fn toml_str_array<'a>(items: impl IntoIterator<Item = &'a str>) -> String {
    let rendered: Vec<String> = items.into_iter().map(toml_str).collect();
    format!("[{}]", rendered.join(", "))
}

fn toml_key(key: &str) -> String {
    if key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        key.to_owned()
    } else {
        toml_str(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persist_grant_into_empty_and_existing_config_preserves_comments() {
        let initial = "# Project comment\n[workspace]\nmount = \"host\"\n";
        let target = PersistTarget::Grant {
            caller_profile: "main".parse().unwrap(),
            ro: vec!["/opt/sdk".to_owned()],
            rw: vec!["~/data".to_owned()],
            net_domains: vec!["example.com".parse().unwrap()],
            net_full: false,
        };
        let step1 = update_config_toml(initial, &target).unwrap();
        assert!(step1.starts_with(initial), "{step1}");
        assert!(step1.contains(PERSIST_HEADER), "{step1}");
        assert!(step1.contains("ro = [\"/opt/sdk\"]"), "{step1}");
        assert!(step1.contains("rw = [\"~/data\"]"), "{step1}");
        assert!(step1.contains("mode = \"proxy\""), "{step1}");
        assert!(
            step1.contains("allow_domains = [\"example.com\"]"),
            "{step1}"
        );

        // A second grant merges into the same `approvals` provider and upgrades
        // `/opt/sdk` from ro to rw when requested as rw.
        let target2 = PersistTarget::Grant {
            caller_profile: "main".parse().unwrap(),
            ro: Vec::new(),
            rw: vec!["/opt/sdk".to_owned()],
            net_domains: Vec::new(),
            net_full: true,
        };
        let step2 = update_config_toml(&step1, &target2).unwrap();
        assert!(step2.starts_with(initial), "{step2}");
        assert_eq!(step2.matches("[[provider]]").count(), 1, "{step2}");
        let parsed = ConfigLayer::from_toml_str(&step2).unwrap();
        assert_eq!(parsed.providers.len(), 1);
        let ProviderKind::Config { sandbox, .. } = &parsed.providers[0].kind else {
            panic!("expected config provider");
        };
        assert!(sandbox.grants.fs.ro.is_empty());
        assert_eq!(
            sandbox
                .grants
                .fs
                .rw
                .iter()
                .map(PathPattern::as_str)
                .collect::<Vec<_>>(),
            ["~/data", "/opt/sdk"]
        );
        assert_eq!(sandbox.grants.network.mode, Some(NetworkMode::Full));
    }

    #[test]
    fn persist_shim_updates_only_the_approved_rule() {
        let jj_spec: ShimSpec = toml::from_str(
            r#"
            cmd = ["jj", "--no-pager", "-R", "{workspace}"]
            default = { decision = "ask", profile = "vcs.local" }
            rules = [
              { regex = '(^|\s)(-R|--repository)(\s|=|$)', decision = "deny" },
              { prefix = "status", decision = "allow", profile = "vcs.local" },
              { prefix = "squash", decision = "ask", profile = "vcs.local" },
              { prefix = "abandon", decision = "ask", profile = "vcs.local" },
              { prefix = "git push", decision = "deny" },
            ]
            "#,
        )
        .unwrap();
        let target = PersistTarget::Shim {
            caller_profile: "main".parse().unwrap(),
            shim: "jj".parse().unwrap(),
            matched_rule: "prefix = \"squash\"".to_owned(),
            target_profile: "vcs.local".parse().unwrap(),
            spec: jj_spec,
        };
        let out = update_config_toml("", &target).unwrap();
        let layer = ConfigLayer::from_toml_str(&out).unwrap();
        let ProviderKind::Config { sandbox, .. } = &layer.providers[0].kind else {
            panic!("expected config provider");
        };
        let persisted_jj = &sandbox.grants.shims[&"jj".parse::<ShimName>().unwrap()];
        let (squash_outcome, _) = crate::broker::decide(persisted_jj, &[b"squash".to_vec()]);
        assert_eq!(
            squash_outcome,
            crate::broker::Outcome::Allow("vcs.local".parse().unwrap())
        );
        let (abandon_outcome, _) = crate::broker::decide(persisted_jj, &[b"abandon".to_vec()]);
        assert_eq!(
            abandon_outcome,
            crate::broker::Outcome::Ask("vcs.local".parse().unwrap())
        );
    }

    #[test]
    fn persist_clipboard_write_sets_terminal_allow() {
        let out = update_config_toml("# header\n", &PersistTarget::ClipboardWrite).unwrap();
        assert!(out.starts_with("# header\n"), "{out}");
        let layer = ConfigLayer::from_toml_str(&out).unwrap();
        assert_eq!(
            layer.terminal_clipboard_write,
            Some(crate::config::ClipboardWrite::Allow)
        );

        let with_ask = "# keep comment\n[terminal]\nclipboard_write = \"ask\" # inline note\n";
        let out2 = update_config_toml(with_ask, &PersistTarget::ClipboardWrite).unwrap();
        assert!(out2.contains("# keep comment\n"), "{out2}");
        assert!(out2.contains("# inline note\n"), "{out2}");
        let layer2 = ConfigLayer::from_toml_str(&out2).unwrap();
        assert_eq!(
            layer2.terminal_clipboard_write,
            Some(crate::config::ClipboardWrite::Allow)
        );
    }

    #[test]
    fn persist_injective_profile_names_and_non_config_or_disabled_entries_never_panic() {
        let initial = concat!(
            "[[provider]]\nname = \"approvals-helper\"\ntype = \"nix\"\nprofile = \"main\"\n\n",
            "[[provider]]\nname = \"approvals-disabled\"\nenabled = false\n",
        );

        // 1. `ClipboardWrite` preserves non-`config` and disabled `approvals-*`
        // providers in `user_part` without duplicating, re-enabling, or panicking.
        let after_clip = update_config_toml(initial, &PersistTarget::ClipboardWrite).unwrap();
        let clip_layer = ConfigLayer::from_toml_str(&after_clip).unwrap();
        assert_eq!(clip_layer.providers.len(), 2, "{after_clip}");
        assert!(matches!(
            clip_layer.providers[0].kind,
            ProviderKind::Nix { .. }
        ));
        assert!(!clip_layer.providers[1].enabled);

        // 2. `dev.shell`, `dev-shell`, and `dev_shell` persist into distinct
        // managed providers without colliding or disturbing `user_part`.
        let mut doc = after_clip.clone();
        for prof in ["dev.shell", "dev-shell", "dev_shell"] {
            doc = update_config_toml(
                &doc,
                &PersistTarget::Grant {
                    caller_profile: prof.parse().unwrap(),
                    ro: vec![format!("/opt/{}", prof.replace('.', "-"))],
                    rw: Vec::new(),
                    net_domains: Vec::new(),
                    net_full: false,
                },
            )
            .unwrap();
        }
        let parsed = ConfigLayer::from_toml_str(&doc).unwrap();
        let names: Vec<&str> = parsed.providers.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "approvals-helper",
                "approvals-disabled",
                "approvals-dev_0shell",
                "approvals-dev-shell",
                "approvals-dev__shell",
            ]
        );

        // 3. Another `ClipboardWrite` with existing managed approvals keeps both
        // sections intact without duplicating any provider.
        let clip_again = update_config_toml(&doc, &PersistTarget::ClipboardWrite).unwrap();
        let parsed_again = ConfigLayer::from_toml_str(&clip_again).unwrap();
        assert_eq!(parsed_again.providers.len(), 5, "{clip_again}");

        // 4. Attempting to persist for profile `"disabled"` when `user_part`
        // explicitly defined `name = "approvals-disabled"` with `enabled = false`
        // fails cleanly without panicking or losing `enabled = false`.
        let err = update_config_toml(
            &doc,
            &PersistTarget::Grant {
                caller_profile: "disabled".parse().unwrap(),
                ro: vec!["/opt/x".to_owned()],
                rw: Vec::new(),
                net_domains: Vec::new(),
                net_full: false,
            },
        )
        .unwrap_err();
        assert!(err.contains("approvals-disabled"), "{err}");
    }
}
