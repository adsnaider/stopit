//! Persisting interactive approvals (`[p]`) to `.stopit.toml` (DESIGN.md §4.2).
//!
//! When the user answers `[p] allow and persist` on the `stopit server`
//! terminal, stopit updates `.stopit.toml` in the workspace:
//!
//! * **Clipboard writes (`ClipboardWrite`):** sets
//!   `[terminal] clipboard_write = "allow"`.
//! * **`stopit-grant` requests (`Grant`):** adds the requested `fs.ro`,
//!   `fs.rw`, and `network` (`mode` / `allow_domains`) grants to a `config`
//!   provider named `"approvals"` (or `"approvals-<profile>"` for a non-`main`
//!   caller profile).
//! * **Brokered shim commands (`Shim`):** writes the shim into the `"approvals"`
//!   `config` provider for the caller profile with the matched rule (or
//!   `default`) changed to `decision = "allow"`.

use crate::config::{ConfigLayer, ProfileRef, ProviderEntry, ProviderKind};
use crate::manifest::{
    Domain, Flag, Manifest, PathPattern, ShimAction, ShimName, ShimRule, ShimSpec,
    SubcommandPattern,
};
use crate::policy::{Decision, NetworkMode};
use crate::resolve::{approvals_provider_name, is_approvals_provider};

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
    let mut layer = ConfigLayer::from_toml_str(existing).map_err(|e| e.to_string())?;
    let (user_part, _) = split_persisted_section(existing);

    match target {
        PersistTarget::ClipboardWrite => {
            let updated_user = set_clipboard_write_allow(user_part)?;
            let approvals: Vec<&ProviderEntry> = layer
                .providers
                .iter()
                .filter(|p| is_approvals_provider(&p.name))
                .collect();
            let out = join_sections(&updated_user, &approvals);
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
            let sandbox = ensure_approvals_manifest(&mut layer, caller_profile)?;
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
            let cleaned_user = strip_approvals_from_user_part(user_part)?;
            let approvals: Vec<&ProviderEntry> = layer
                .providers
                .iter()
                .filter(|p| is_approvals_provider(&p.name))
                .collect();
            let out = join_sections(&cleaned_user, &approvals);
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
            let sandbox = ensure_approvals_manifest(&mut layer, caller_profile)?;
            let mut updated_spec = sandbox
                .grants
                .shims
                .get(shim)
                .cloned()
                .unwrap_or_else(|| spec.clone());
            allow_shim_rule(&mut updated_spec, matched_rule, target_profile)?;
            sandbox.grants.shims.insert(shim.clone(), updated_spec);

            let cleaned_user = strip_approvals_from_user_part(user_part)?;
            let approvals: Vec<&ProviderEntry> = layer
                .providers
                .iter()
                .filter(|p| is_approvals_provider(&p.name))
                .collect();
            let out = join_sections(&cleaned_user, &approvals);
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
/// approvals `config` provider for `caller_profile` in `layer`, creating the
/// provider entry if absent.
fn ensure_approvals_manifest<'a>(
    layer: &'a mut ConfigLayer,
    caller_profile: &ProfileRef,
) -> Result<&'a mut Manifest, String> {
    let name = approvals_provider_name(caller_profile);
    let idx = match layer.providers.iter().position(|p| p.name == name) {
        Some(idx) => idx,
        None => {
            layer.providers.push(ProviderEntry {
                name: name.clone(),
                kind: ProviderKind::Config {
                    profile: caller_profile.clone(),
                    sandbox: Box::new(Manifest::default()),
                },
            });
            layer.providers.len() - 1
        }
    };
    match &layer.providers[idx].kind {
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
    let ProviderKind::Config { sandbox, .. } = &mut layer.providers[idx].kind else {
        unreachable!("checked above");
    };
    Ok(sandbox)
}

/// Updates `spec` so `matched_rule` (`"default"` or a subcommand pattern) has
/// `decision = "allow"` in `target_profile`.
pub fn allow_shim_rule(
    spec: &mut ShimSpec,
    matched_rule: &str,
    target_profile: &ProfileRef,
) -> Result<(), String> {
    if matched_rule == "default" {
        spec.default = ShimAction {
            decision: Decision::Allow,
            profile: Some(target_profile.clone()),
        };
        return Ok(());
    }
    let pat: SubcommandPattern = matched_rule.parse().map_err(|e| format!("{e}"))?;
    let mut new_rules = Vec::with_capacity(spec.rules.len() + 1);
    let mut matched_any = false;
    for mut rule in spec.rules.drain(..) {
        if let Some(pos) = rule.subcommand.iter().position(|p| p == &pat) {
            matched_any = true;
            if rule.decision == Decision::Allow && rule.profile.as_ref() == Some(target_profile) {
                new_rules.push(rule);
            } else if rule.subcommand.len() == 1 {
                rule.decision = Decision::Allow;
                rule.profile = Some(target_profile.clone());
                new_rules.push(rule);
            } else {
                rule.subcommand.remove(pos);
                let flags: Vec<Flag> = rule.deny_flags.clone();
                new_rules.push(ShimRule {
                    subcommand: vec![pat.clone()],
                    decision: Decision::Allow,
                    profile: Some(target_profile.clone()),
                    deny_flags: flags,
                });
                new_rules.push(rule);
            }
        } else {
            new_rules.push(rule);
        }
    }
    if !matched_any {
        new_rules.push(ShimRule {
            subcommand: vec![pat],
            decision: Decision::Allow,
            profile: Some(target_profile.clone()),
            deny_flags: Vec::new(),
        });
    }
    spec.rules = new_rules;
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

/// If `user_part` manually defined a `[[provider]]` with an approvals name
/// before [`PERSIST_HEADER`], removes that entry from `user_part` so it is not
/// duplicated when the managed approvals section is appended. Otherwise returns
/// `user_part` unchanged.
fn strip_approvals_from_user_part(user_part: &str) -> Result<String, String> {
    let user_layer = ConfigLayer::from_toml_str(user_part).map_err(|e| e.to_string())?;
    if !user_layer
        .providers
        .iter()
        .any(|p| is_approvals_provider(&p.name))
    {
        return Ok(user_part.to_owned());
    }
    let mut root: toml::Table = toml::from_str(user_part).map_err(|e| e.to_string())?;
    if let Some(toml::Value::Array(providers)) = root.get_mut("provider") {
        providers.retain(|v| {
            let name = v
                .as_table()
                .and_then(|t| t.get("name"))
                .and_then(toml::Value::as_str);
            !name.is_some_and(|n| n == "approvals" || n.starts_with("approvals-"))
        });
        if providers.is_empty() {
            root.remove("provider");
        }
    }
    toml::to_string_pretty(&root).map_err(|e| e.to_string())
}

/// Joins `user_part` and the rendered `approvals` providers with
/// [`PERSIST_HEADER`].
fn join_sections(user_part: &str, approvals: &[&ProviderEntry]) -> String {
    let mut out = user_part.trim_end().to_owned();
    if approvals.is_empty() {
        if !out.is_empty() {
            out.push('\n');
        }
        return out;
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
        out.push_str(&render_approvals_provider(entry));
    }
    out
}

/// Renders an approvals `config` provider entry as clean TOML.
fn render_approvals_provider(entry: &ProviderEntry) -> String {
    let ProviderKind::Config { profile, sandbox } = &entry.kind else {
        unreachable!("approvals provider is always a config provider");
    };
    let mut out = String::new();
    out.push_str("[[provider]]\n");
    out.push_str(&format!("name = {}\n", toml_str(entry.name.as_str())));
    out.push_str("type = \"config\"\n");
    if *profile != ProfileRef::main() {
        out.push_str(&format!("profile = {}\n", toml_str(profile.as_str())));
    }
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
        out.push_str(&format!("binary = {}\n", toml_str(spec.binary.as_str())));
        if !spec.args.is_empty() {
            out.push_str(&format!(
                "args = {}\n",
                toml_str_array(spec.args.iter().map(|a| a.as_str()))
            ));
        }
        if spec.tty {
            out.push_str("tty = true\n");
        }
        if !spec.deny_flags.is_empty() {
            out.push_str(&format!(
                "deny_flags = {}\n",
                toml_str_array(spec.deny_flags.iter().map(Flag::as_str))
            ));
        }
        out.push_str(&format!("default = {}\n", render_action(&spec.default)));
        if !spec.rules.is_empty() {
            out.push_str("rules = [\n");
            for rule in &spec.rules {
                out.push_str(&format!("  {},\n", render_rule(rule)));
            }
            out.push_str("]\n");
        }
    }
    out
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
    let mut parts = vec![
        format!(
            "subcommand = {}",
            toml_str_array(rule.subcommand.iter().map(SubcommandPattern::as_str))
        ),
        format!("decision = {}", toml_str(rule.decision.as_str())),
    ];
    if let Some(profile) = &rule.profile {
        parts.push(format!("profile = {}", toml_str(profile.as_str())));
    }
    if !rule.deny_flags.is_empty() {
        parts.push(format!(
            "deny_flags = {}",
            toml_str_array(rule.deny_flags.iter().map(Flag::as_str))
        ));
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
            caller_profile: ProfileRef::main(),
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
        assert!(step1.contains("allow_domains = [\"example.com\"]"), "{step1}");

        // A second grant merges into the same `approvals` provider and upgrades
        // `/opt/sdk` from ro to rw when requested as rw.
        let target2 = PersistTarget::Grant {
            caller_profile: ProfileRef::main(),
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
    fn persist_shim_splits_only_the_approved_subcommand_pattern() {
        let jj_spec: ShimSpec = toml::from_str(
            r#"
            binary = "jj"
            args = ["--no-pager", "-R", "{workspace}"]
            deny_flags = ["-R", "--repository"]
            default = { decision = "ask", profile = "vcs.local" }
            rules = [
              { subcommand = ["status", "st", "diff"], decision = "allow", profile = "vcs.local" },
              { subcommand = ["squash", "rebase", "abandon"], decision = "ask", profile = "vcs.local" },
              { subcommand = ["git push"], decision = "deny" },
            ]
            "#,
        )
        .unwrap();
        let target = PersistTarget::Shim {
            caller_profile: ProfileRef::main(),
            shim: "jj".parse().unwrap(),
            matched_rule: "squash".to_owned(),
            target_profile: "vcs.local".parse().unwrap(),
            spec: jj_spec,
        };
        let out = update_config_toml("", &target).unwrap();
        let layer = ConfigLayer::from_toml_str(&out).unwrap();
        let ProviderKind::Config { sandbox, .. } = &layer.providers[0].kind else {
            panic!("expected config provider");
        };
        let persisted_jj = &sandbox.grants.shims[&"jj".parse::<ShimName>().unwrap()];
        let (squash_outcome, _) =
            crate::broker::decide(persisted_jj, &[b"squash".to_vec()]);
        assert_eq!(
            squash_outcome,
            crate::broker::Outcome::Allow("vcs.local".parse().unwrap())
        );
        let (abandon_outcome, _) =
            crate::broker::decide(persisted_jj, &[b"abandon".to_vec()]);
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
}
