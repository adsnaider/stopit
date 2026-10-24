//! Providers: the single source of grants (DESIGN.md §3.6).
//!
//! A provider turns its configuration entry into a [`ProviderOutput`] at
//! session start. Merging the outputs of all providers happens elsewhere.

mod config;

use std::path::PathBuf;

use thiserror::Error;

use crate::config::{ProfileRef, ProviderEntry, ProviderKind, ProviderName, WorkspaceMount};
use crate::manifest::Manifest;

pub use config::ConfigProvider;

/// What every provider receives at session start.
#[derive(Debug, Clone)]
pub struct ProviderContext {
    /// Host workspace directory.
    pub workspace: PathBuf,
    /// Where the workspace appears inside the sandbox.
    pub workspace_mount: WorkspaceMount,
    /// Host `$HOME`.
    pub home: PathBuf,
    /// The session runtime directory.
    pub session_dir: PathBuf,
}

/// The result of running a provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderOutput {
    /// The profile the manifest's top-level grants apply to: the `profile`
    /// of a `config` provider, `main` for every other type.
    pub profile: ProfileRef,
    /// The manifest. Contributed profiles stay in `manifest.profiles`,
    /// unprefixed; the provider-name prefix is added during resolution.
    pub manifest: Manifest,
}

/// Error produced while running a provider.
#[derive(Debug, Error)]
pub enum ProviderError {
    /// The provider type exists in the configuration schema but has no
    /// implementation yet.
    #[error("provider type {kind:?} (entry {name:?}) is not implemented yet")]
    Unsupported {
        /// Effective name of the entry.
        name: ProviderName,
        /// The `type` of the entry.
        kind: &'static str,
    },
}

/// A source of grants.
///
/// Broker handlers (`handlers`) will be added to this trait with the broker.
pub trait Provider: Send + Sync {
    /// The effective name of this provider.
    fn name(&self) -> &ProviderName;

    /// Computes the manifest, once, at session start.
    fn manifest(&self, ctx: &ProviderContext) -> Result<ProviderOutput, ProviderError>;
}

/// Builds the provider for a configuration entry.
pub fn from_entry(entry: &ProviderEntry) -> Result<Box<dyn Provider>, ProviderError> {
    match &entry.kind {
        ProviderKind::Config { profile, sandbox } => Ok(Box::new(ConfigProvider::new(
            entry.name.clone(),
            profile.clone(),
            (**sandbox).clone(),
        ))),
        kind @ (ProviderKind::Script { .. } | ProviderKind::Vcs { .. }) => {
            Err(ProviderError::Unsupported {
                name: entry.name.clone(),
                kind: kind.type_name(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn entries(src: &str) -> Vec<ProviderEntry> {
        Config::from_toml_str(src).unwrap().providers
    }

    fn ctx(tag: &str) -> ProviderContext {
        ProviderContext {
            workspace: PathBuf::from(format!("/w/{tag}")),
            workspace_mount: "/workspace".parse().unwrap(),
            home: PathBuf::from(format!("/home/{tag}")),
            session_dir: PathBuf::from(format!("/run/{tag}")),
        }
    }

    fn output(src: &str) -> (ProviderName, ProviderOutput) {
        let e = &entries(src)[0];
        let p = from_entry(e).unwrap();
        (p.name().clone(), p.manifest(&ctx("a")).unwrap())
    }

    const SANDBOX: &str = "[provider.sandbox]\nfs.ro = [\"/etc/ssl/certs\"]\nnetwork = { mode = \"loopback\" }\n[provider.sandbox.profiles.local]\nfs.rw = [\"/x\"]\n";

    fn inline_sandbox(src: &str) -> Manifest {
        match &entries(src)[0].kind {
            ProviderKind::Config { sandbox, .. } => (**sandbox).clone(),
            k => panic!("{k:?}"),
        }
    }

    #[test]
    fn config_entry_builds_a_provider() {
        let (name, out) = output("[[provider]]\ntype = \"config\"");
        assert_eq!(name.as_str(), "config");
        assert_eq!(out.profile, ProfileRef::main());
        assert_eq!(out.manifest, Manifest::default());
    }

    #[test]
    fn config_provider_returns_its_sandbox_and_profile_unchanged() {
        let src = format!("[[provider]]\ntype = \"config\"\n{SANDBOX}");
        let (_, out) = output(&src);
        assert_eq!(out.profile, ProfileRef::main());
        assert_eq!(out.manifest, inline_sandbox(&src));
        assert_eq!(out.manifest.grants.fs.ro.len(), 1);
        // Contributed profiles stay inside the manifest, unprefixed.
        assert_eq!(out.manifest.profiles.len(), 1);
        assert!(out.manifest.profiles.keys().any(|k| k.as_str() == "local"));

        let src = format!("[[provider]]\ntype = \"config\"\nprofile = \"harness\"\n{SANDBOX}");
        let (_, out) = output(&src);
        assert_eq!(out.profile.as_str(), "harness");
        assert_eq!(out.manifest, inline_sandbox(&src));
    }

    #[test]
    fn from_entry_over_a_mixed_config_in_order() {
        let es = entries(
            "[[provider]]\ntype = \"config\"\n\
             [[provider]]\ntype = \"config\"\nname = \"approvals\"\n\
             [[provider]]\ntype = \"vcs\"",
        );
        assert_eq!(es.len(), 3);
        let mut built = Vec::new();
        let mut failure = None;
        for e in &es {
            match from_entry(e) {
                Ok(p) => built.push(p.name().as_str().to_owned()),
                Err(err) => {
                    failure = Some(err.to_string());
                    break;
                }
            }
        }
        // Effective names: the default (type) and an explicit one.
        assert_eq!(built, ["config", "approvals"]);
        let msg = failure.expect("the vcs entry is unsupported");
        assert!(msg.contains("\"vcs\""), "{msg}");
        assert!(msg.contains("not implemented"), "{msg}");
    }

    #[test]
    fn context_is_ignored() {
        let src = format!("[[provider]]\ntype = \"config\"\n{SANDBOX}");
        let p = from_entry(&entries(&src)[0]).unwrap();
        let a = p.manifest(&ctx("a")).unwrap();
        let b = p.manifest(&ctx("b")).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn script_and_vcs_are_unsupported() {
        for (src, kind, name) in [
            (
                "[[provider]]\ntype = \"script\"\nsource = \"x.sh\"",
                "script",
                "script",
            ),
            (
                "[[provider]]\ntype = \"script\"\nsource = \"x.sh\"\nname = \"env\"",
                "script",
                "env",
            ),
            ("[[provider]]\ntype = \"vcs\"", "vcs", "vcs"),
        ] {
            let Err(e) = from_entry(&entries(src)[0]) else {
                panic!("{src:?} should be unsupported");
            };
            let msg = e.to_string();
            assert!(msg.contains(&format!("{kind:?}")), "{msg}");
            assert!(msg.contains(&format!("{name:?}")), "{msg}");
            assert!(msg.contains("not implemented"), "{msg}");
        }
    }
}
