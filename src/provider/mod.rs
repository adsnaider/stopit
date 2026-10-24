//! Providers: the single source of grants (DESIGN.md §3.6).
//!
//! A provider turns its configuration entry into a [`ProviderOutput`] at
//! session start. Merging the outputs of all providers happens elsewhere.

mod config;
mod script;

use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::string::FromUtf8Error;

use thiserror::Error;

use crate::config::{ProfileRef, ProviderEntry, ProviderKind, ProviderName, WorkspaceMount};
use crate::manifest::{Manifest, ManifestError};

pub use config::ConfigProvider;
pub use script::{STDERR_LIMIT, STDOUT_LIMIT, ScriptProvider};

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

    /// A script provider's path could not be canonicalized (e.g. it does not
    /// exist).
    #[error("cannot resolve script provider {:?} ({}): {error}", .name.as_str(), .script.display())]
    Resolve {
        /// Effective name of the entry.
        name: ProviderName,
        /// The script path as declared, joined to the base directory.
        script: PathBuf,
        /// The underlying error.
        #[source]
        error: io::Error,
    },

    /// The directory of the configuration file that declared a script
    /// provider (its working directory) is missing or not a directory.
    #[error(
        "cannot run script provider {:?} ({}): its directory {} is not accessible: {error}",
        .name.as_str(),
        .script.display(),
        .dir.display()
    )]
    BaseDir {
        /// Effective name of the entry.
        name: ProviderName,
        /// The script path as declared, joined to the base directory.
        script: PathBuf,
        /// The directory.
        dir: PathBuf,
        /// The underlying error.
        #[source]
        error: io::Error,
    },

    /// A script provider could not be started (e.g. not executable).
    #[error("failed to start script provider {:?} ({}): {error}", .name.as_str(), .script.display())]
    Spawn {
        /// Effective name of the entry.
        name: ProviderName,
        /// The resolved script path.
        script: PathBuf,
        /// The underlying error.
        #[source]
        error: io::Error,
    },

    /// Reading from, writing to or waiting for a script provider failed.
    #[error("i/o error while running script provider {:?} ({}): {error}", .name.as_str(), .script.display())]
    Io {
        /// Effective name of the entry.
        name: ProviderName,
        /// The resolved script path.
        script: PathBuf,
        /// The underlying error.
        #[source]
        error: io::Error,
    },

    /// A script provider exited unsuccessfully.
    #[error(
        "script provider {:?} ({}) {}{}",
        .name.as_str(),
        .script.display(),
        script::describe_status(.status),
        script::describe_stderr(.stderr)
    )]
    Failed {
        /// Effective name of the entry.
        name: ProviderName,
        /// The resolved script path.
        script: PathBuf,
        /// How it exited.
        status: ExitStatus,
        /// The beginning of its stderr (lossily decoded, trimmed), with a
        /// marker when it was truncated.
        stderr: String,
    },

    /// A script provider printed more than the stdout limit.
    #[error(
        "script provider {:?} ({}) printed more than {limit} bytes on stdout",
        .name.as_str(),
        .script.display()
    )]
    StdoutTooLarge {
        /// Effective name of the entry.
        name: ProviderName,
        /// The resolved script path.
        script: PathBuf,
        /// The limit, in bytes.
        limit: usize,
    },

    /// A script provider's stdout is not valid UTF-8.
    #[error("script provider {:?} ({}) printed invalid UTF-8 on stdout: {error}", .name.as_str(), .script.display())]
    StdoutNotUtf8 {
        /// Effective name of the entry.
        name: ProviderName,
        /// The resolved script path.
        script: PathBuf,
        /// The decoding error.
        #[source]
        error: FromUtf8Error,
    },

    /// A script provider printed something that is not a valid manifest.
    #[error("script provider {:?} ({}) printed an {error}", .name.as_str(), .script.display())]
    InvalidManifest {
        /// Effective name of the entry.
        name: ProviderName,
        /// The resolved script path.
        script: PathBuf,
        /// The parse or validation error.
        #[source]
        error: ManifestError,
    },

    /// A context path cannot be passed to a script provider as JSON.
    #[error(
        "cannot run script provider {:?} ({}): context path {field} {path:?} is not valid UTF-8",
        .name.as_str(),
        .script.display()
    )]
    NonUtf8Path {
        /// Effective name of the entry.
        name: ProviderName,
        /// The resolved script path.
        script: PathBuf,
        /// The context field.
        field: &'static str,
        /// The offending path.
        path: PathBuf,
    },

    /// A `[provider.config]` value has no JSON representation.
    #[error(
        "cannot run script provider {:?} ({}): config value {key:?} cannot be converted to JSON: {reason}",
        .name.as_str(),
        .script.display()
    )]
    ConfigNotJson {
        /// Effective name of the entry.
        name: ProviderName,
        /// The resolved script path.
        script: PathBuf,
        /// Key path of the value, e.g. `a.b[1]`.
        key: String,
        /// Why it cannot be converted.
        reason: &'static str,
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

    /// Host paths this provider asks to be `protected`, because they hold
    /// code that runs on the host (a script provider's `source`). None by
    /// default.
    fn protected_paths(&self) -> Result<Vec<PathBuf>, ProviderError> {
        Ok(Vec::new())
    }
}

/// Builds the provider for a configuration entry.
///
/// `base_dir` is the directory of the configuration file that declared the
/// entry: a relative script `source` is resolved against it, and it is the
/// script's current directory. `config` entries ignore it.
pub fn from_entry(
    entry: &ProviderEntry,
    base_dir: &Path,
) -> Result<Box<dyn Provider>, ProviderError> {
    match &entry.kind {
        ProviderKind::Config { profile, sandbox } => Ok(Box::new(ConfigProvider::new(
            entry.name.clone(),
            profile.clone(),
            (**sandbox).clone(),
        ))),
        ProviderKind::Script {
            source,
            protect,
            config,
        } => Ok(Box::new(ScriptProvider::new(
            entry.name.clone(),
            source,
            base_dir,
            *protect,
            config.clone(),
        ))),
        kind @ ProviderKind::Vcs { .. } => Err(ProviderError::Unsupported {
            name: entry.name.clone(),
            kind: kind.type_name(),
        }),
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
        let p = from_entry(e, Path::new("/cfg")).unwrap();
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
             [[provider]]\ntype = \"script\"\nsource = \"x.sh\"\n\
             [[provider]]\ntype = \"vcs\"",
        );
        assert_eq!(es.len(), 4);
        let mut built = Vec::new();
        let mut failure = None;
        for e in &es {
            match from_entry(e, Path::new("/cfg")) {
                Ok(p) => built.push(p.name().as_str().to_owned()),
                Err(err) => {
                    failure = Some(err.to_string());
                    break;
                }
            }
        }
        // Effective names: the default (type) and an explicit one.
        assert_eq!(built, ["config", "approvals", "script"]);
        let msg = failure.expect("the vcs entry is unsupported");
        assert!(msg.contains("\"vcs\""), "{msg}");
        assert!(msg.contains("not implemented"), "{msg}");
    }

    #[test]
    fn context_is_ignored() {
        let src = format!("[[provider]]\ntype = \"config\"\n{SANDBOX}");
        let p = from_entry(&entries(&src)[0], Path::new("/cfg")).unwrap();
        let a = p.manifest(&ctx("a")).unwrap();
        let b = p.manifest(&ctx("b")).unwrap();
        assert_eq!(a, b);
        // So is the base directory.
        let q = from_entry(&entries(&src)[0], Path::new("/elsewhere")).unwrap();
        assert_eq!(q.manifest(&ctx("a")).unwrap(), a);
    }

    #[test]
    fn script_entries_build_a_provider() {
        for (src, name) in [
            (
                "[[provider]]\ntype = \"script\"\nsource = \"x.sh\"",
                "script",
            ),
            (
                "[[provider]]\ntype = \"script\"\nsource = \"x.sh\"\nname = \"env\"",
                "env",
            ),
        ] {
            let p = from_entry(&entries(src)[0], Path::new("/cfg")).unwrap();
            assert_eq!(p.name().as_str(), name);
        }
    }

    #[test]
    fn missing_script_fails_when_run_not_when_built() {
        let p = from_entry(
            &entries("[[provider]]\ntype = \"script\"\nsource = \"x.sh\"")[0],
            Path::new("/nonexistent-stopit-dir"),
        )
        .unwrap();
        // The missing directory is blamed, not the script. Nothing is
        // spawned: resolving the script path already fails.
        for e in [
            p.manifest(&ctx("a")).unwrap_err(),
            p.protected_paths().unwrap_err(),
        ] {
            let ProviderError::BaseDir { dir, error, .. } = &e else {
                panic!("{e:?}");
            };
            assert_eq!(dir, Path::new("/nonexistent-stopit-dir"));
            assert_eq!(error.kind(), io::ErrorKind::NotFound);
            let msg = e.to_string();
            assert!(
                msg.contains("its directory /nonexistent-stopit-dir is not accessible"),
                "{msg}"
            );
            assert!(msg.contains("\"script\""), "{msg}");
        }
    }

    #[test]
    fn config_providers_protect_nothing() {
        let p = from_entry(
            &entries("[[provider]]\ntype = \"config\"")[0],
            Path::new("/cfg"),
        )
        .unwrap();
        assert!(p.protected_paths().unwrap().is_empty());
    }

    #[test]
    fn vcs_is_unsupported() {
        let Err(e) = from_entry(
            &entries("[[provider]]\ntype = \"vcs\"")[0],
            Path::new("/cfg"),
        ) else {
            panic!("vcs should be unsupported");
        };
        let msg = e.to_string();
        assert!(msg.contains("\"vcs\""), "{msg}");
        assert!(msg.contains("not implemented"), "{msg}");
    }
}
