//! Providers: the single source of grants (DESIGN.md §3.6).
//!
//! A provider turns its configuration entry into a [`ProviderOutput`] at
//! session start. Merging the outputs of all providers happens elsewhere.

mod base;
mod config;
mod script;
mod vcs;

use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::string::FromUtf8Error;

use thiserror::Error;

use crate::config::{
    LayeredProviderEntry, ProfileRef, ProviderEntry, ProviderKind, ProviderName, ProviderOrigin,
    WorkspaceMount,
};
use crate::manifest::{Manifest, ManifestError};
use crate::spec::UntrustedRoot;

pub use base::{
    BASE_PROVIDER_NAME, SUPERVISOR_PROVIDER_NAME, default_base_manifest, layered_session_providers,
    session_providers,
};
pub use config::ConfigProvider;
pub use script::{STDERR_LIMIT, STDOUT_LIMIT, ScriptProvider};
pub use vcs::{Layout as VcsLayout, VCS_PROVIDER_NAME, VcsProvider, discover as discover_vcs};

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
    /// The host directories the `config` providers grant `rw`, known
    /// before any script runs
    /// ([`static_rw_roots`](crate::spec::static_rw_roots)): with the workspace,
    /// the roots a script provider's path must not run through a symlink
    /// inside (DESIGN.md §3.6).
    pub rw_grants: Vec<UntrustedRoot>,
}

impl ProviderContext {
    /// Where the workspace appears inside the sandbox, resolved against
    /// [`Self::workspace`].
    pub fn resolved_workspace_mount(&self) -> &Path {
        self.workspace_mount.resolve(&self.workspace)
    }
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
    /// Layer that declared this provider.
    pub origin: ProviderOrigin,
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

    /// A user provider is named like the built-in provider of the default
    /// base.
    #[error(
        "provider name {:?} is reserved by the built-in provider of `base = \"default\"`: \
         choose a different name, or set `base = \"none\"`",
        .name.as_str()
    )]
    ReservedName {
        /// The offending name.
        name: ProviderName,
    },

    /// A user provider is named like the supervisor's own rules
    /// ([`SUPERVISOR_PROVIDER_NAME`]).
    #[error(
        "provider name {:?} is reserved for stopit's own rules (such as protecting the \
         configuration file): choose a different name",
        .name.as_str()
    )]
    ReservedForSupervisor {
        /// The offending name.
        name: ProviderName,
    },

    /// A script provider's source is a regular file with more than one
    /// hard link: the sandbox could rewrite it through another name, which
    /// protecting this one cannot prevent, so it is not run (DESIGN.md
    /// §3.6).
    #[error(
        "refusing to run script provider {:?} ({}): {path:?} has {links} hard links, so a sandbox \
         could have rewritten it through another name that no protection covers; give it a \
         single link (copy it, then replace the original with the copy)",
        .name.as_str(),
        .script.display()
    )]
    SourceHardLinked {
        /// Effective name of the entry.
        name: ProviderName,
        /// The script path as declared, joined to the base directory.
        script: PathBuf,
        /// The canonical script path.
        path: PathBuf,
        /// Its number of hard links.
        links: u64,
    },

    /// The built-in provider of the default base is invalid (its name or
    /// embedded manifest). A bug in `stopit`, prevented by a unit test.
    #[error("internal error: the built-in default base is invalid: {0}")]
    BuiltinBase(String),

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

    /// A caught signal interrupted a running script provider and killed its
    /// process group.
    #[error(
        "script provider {:?} at {} interrupted by signal {signal}",
        .name.as_str(),
        .script.display()
    )]
    Interrupted {
        /// Effective name of the entry.
        name: ProviderName,
        /// The script path as declared, joined to the base directory.
        script: PathBuf,
        /// Signal number.
        signal: i32,
    },

    /// A script provider's path runs through a symlink inside the host
    /// workspace or a directory a `config` provider grants `rw`, which a
    /// sandbox can write: it may have planted the link to have its own code
    /// run on the host (DESIGN.md §3.6).
    #[error(
        "refusing to run script provider {:?} ({}): its path runs through the symlink {} inside \
         {root}; a sandbox can write there, so it could have planted the link to run its own \
         code on the host: point `source` at a path without links inside it",
        .name.as_str(),
        .script.display(),
        .link.display()
    )]
    SourceLink {
        /// Effective name of the entry.
        name: ProviderName,
        /// The script path as declared, joined to the base directory.
        script: PathBuf,
        /// The first such symlink on the way, named below its canonical
        /// parent directory.
        link: PathBuf,
        /// The innermost writable directory containing it.
        root: Box<UntrustedRoot>,
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

    /// The `vcs` provider cannot express the repository's layout.
    #[error("provider {name:?}: {reason}")]
    Vcs {
        /// Its name.
        name: ProviderName,
        /// Why.
        reason: String,
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
    /// code that runs on the host (a script provider's `source`): canonical
    /// paths, files or directories. None by default.
    ///
    /// The supervisor protects them in every profile of the session,
    /// whatever the providers grant (see [`protected_sources`]).
    fn protected_paths(&self) -> Result<Vec<PathBuf>, ProviderError> {
        Ok(Vec::new())
    }

    /// The output, if it is known without running anything on the host and
    /// without a context (a `config` provider's inline manifest). None by
    /// default.
    ///
    /// The supervisor reads these outputs' `rw` grants before any script
    /// runs (see [`static_outputs`]).
    fn static_output(&self) -> Option<ProviderOutput> {
        None
    }
}

/// The outputs of `providers` known before any of them runs
/// ([`Provider::static_output`]), with their providers, in provider order.
///
/// Their `rw` grants ([`static_rw_roots`](crate::spec::static_rw_roots)) are the directories, besides the
/// workspace, that a script provider's path must not run through a symlink
/// inside (DESIGN.md §3.6).
pub fn static_outputs(providers: &[Box<dyn Provider>]) -> Vec<(ProviderName, ProviderOutput)> {
    providers
        .iter()
        .filter_map(|p| Some((p.name().clone(), p.static_output()?)))
        .collect()
}

/// A canonical host path a provider asks to be `protected`
/// ([`Provider::protected_paths`]), with that provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedSource {
    /// The provider asking.
    pub provider: ProviderName,
    /// The canonical host path.
    pub path: PathBuf,
}

/// Every path `providers` ask to be protected, in provider order.
///
/// These are the supervisor's rule, not grants: the session compiler
/// protects them wherever a profile would let the sandbox write them, which
/// no provider's grant can lift (DESIGN.md §3.6).
pub fn protected_sources(
    providers: &[Box<dyn Provider>],
) -> Result<Vec<ProtectedSource>, ProviderError> {
    let mut out = Vec::new();
    for p in providers {
        for path in p.protected_paths()? {
            out.push(ProtectedSource {
                provider: p.name().clone(),
                path,
            });
        }
    }
    Ok(out)
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
    from_entry_with_origin(entry, base_dir, ProviderOrigin::Workspace)
}

/// Builds the provider for a configuration entry tagged with `origin`.
pub fn from_entry_with_origin(
    entry: &ProviderEntry,
    base_dir: &Path,
    origin: ProviderOrigin,
) -> Result<Box<dyn Provider>, ProviderError> {
    match &entry.kind {
        ProviderKind::Config { profile, sandbox } => Ok(Box::new(ConfigProvider::with_origin(
            entry.name.clone(),
            profile.clone(),
            (**sandbox).clone(),
            origin,
        ))),
        ProviderKind::Script {
            source,
            protect,
            config,
        } => Ok(Box::new(ScriptProvider::with_origin(
            entry.name.clone(),
            source,
            base_dir,
            *protect,
            config.clone(),
            origin,
        ))),
        ProviderKind::Vcs {
            view,
            tools,
            fetch,
            push,
            signing,
        } => Ok(Box::new(
            VcsProvider::new(
                entry.name.clone(),
                *view,
                tools.clone(),
                *fetch,
                *push,
                origin,
            )
            .with_signing(*signing),
        )),
    }
}

/// Builds the provider for a [`LayeredProviderEntry`].
pub fn from_layered_entry(
    entry: &LayeredProviderEntry,
) -> Result<Box<dyn Provider>, ProviderError> {
    from_entry_with_origin(&entry.entry, &entry.base_dir, entry.origin)
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
            rw_grants: Vec::new(),
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
        assert_eq!(built, ["config", "approvals", "script", "vcs"]);
        assert_eq!(failure, None);
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
    fn protected_sources_name_their_provider_in_order() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        for f in ["a.sh", "b.sh"] {
            std::fs::write(root.join(f), "").unwrap();
        }
        let es = entries(
            "[[provider]]\ntype = \"script\"\nname = \"a\"\nsource = \"a.sh\"\n\
             [[provider]]\ntype = \"config\"\n\
             [[provider]]\ntype = \"script\"\nname = \"off\"\nsource = \"a.sh\"\nprotect = false\n\
             [[provider]]\ntype = \"script\"\nname = \"b\"\nsource = \"b.sh\"",
        );
        let ps: Vec<_> = es.iter().map(|e| from_entry(e, &root).unwrap()).collect();
        assert_eq!(
            protected_sources(&ps).unwrap(),
            [
                ProtectedSource {
                    provider: "a".parse().unwrap(),
                    path: root.join("a.sh"),
                },
                ProtectedSource {
                    provider: "b".parse().unwrap(),
                    path: root.join("b.sh"),
                },
            ]
        );
        // A source that cannot be resolved is an error naming its provider.
        let es = entries("[[provider]]\ntype = \"script\"\nname = \"gone\"\nsource = \"c.sh\"");
        let ps = [from_entry(&es[0], &root).unwrap()];
        let e = protected_sources(&ps).unwrap_err();
        assert!(matches!(e, ProviderError::Resolve { .. }), "{e:?}");
        assert!(e.to_string().contains("\"gone\""), "{e}");
    }

    #[test]
    fn a_vcs_entry_builds_the_vcs_provider() {
        let p = from_entry(
            &entries("[[provider]]\ntype = \"vcs\"")[0],
            Path::new("/cfg"),
        )
        .unwrap();
        assert_eq!(p.name().as_str(), "vcs");
        // A workspace without a repository gets nothing from it.
        let ws = tempfile::TempDir::new().unwrap();
        let mut c = ctx("x");
        c.workspace = ws.path().to_owned();
        assert_eq!(p.manifest(&c).unwrap().manifest, Manifest::default());
    }
}
