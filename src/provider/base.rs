//! The built-in providers of a base (DESIGN.md §3.2, §3.5).

use std::path::Path;

use super::{ConfigProvider, Provider, ProviderError, from_layered_entry};
use crate::config::{Base, Config, LayeredProviderEntry, ProfileRef, ProviderName, ProviderOrigin};
use crate::manifest::Manifest;

/// The name of the built-in `config` provider of `base = "default"`. User
/// providers cannot use it under that base.
pub const BASE_PROVIDER_NAME: &str = "base";

/// The name the supervisor's own rules are attributed to (the protection of
/// the loaded configuration file, DESIGN.md §3). User providers cannot use
/// it under any base, so that a message naming it is never about theirs.
pub const SUPERVISOR_PROVIDER_NAME: &str = "stopit";

/// The default base's sandbox manifest (Appendix A), as data.
const DEFAULT_MANIFEST_TOML: &str = include_str!("base_default.toml");

/// Parses the embedded default-base manifest with the manifest parser that
/// user `[provider.sandbox]` tables use.
///
/// Fails only if the embedded file is broken, which a unit test rules out.
pub fn default_base_manifest() -> Result<Manifest, ProviderError> {
    toml::from_str(DEFAULT_MANIFEST_TOML).map_err(|e| ProviderError::BuiltinBase(e.to_string()))
}

/// The ordered providers of a single-layer session: the base's built-in
/// providers first, then `config.providers` in file order resolved against
/// `base_dir`.
pub fn session_providers(
    config: &Config,
    base_dir: &Path,
) -> Result<Vec<Box<dyn Provider>>, ProviderError> {
    let entries: Vec<LayeredProviderEntry> = config
        .providers
        .iter()
        .cloned()
        .map(|entry| LayeredProviderEntry {
            origin: ProviderOrigin::Workspace,
            base_dir: base_dir.to_path_buf(),
            entry,
        })
        .collect();
    layered_session_providers(config.base, &entries)
}

/// Builds the ordered providers of a layered session with built-in base
/// providers first, followed by `entries` in merge order using each entry's
/// own declaring directory and [`ProviderOrigin`].
pub fn layered_session_providers(
    base: Base,
    entries: &[LayeredProviderEntry],
) -> Result<Vec<Box<dyn Provider>>, ProviderError> {
    if let Some(entry) = entries
        .iter()
        .find(|e| e.entry.name.as_str() == SUPERVISOR_PROVIDER_NAME)
    {
        return Err(ProviderError::ReservedForSupervisor {
            name: entry.entry.name.clone(),
        });
    }
    let mut providers: Vec<Box<dyn Provider>> = Vec::new();
    match base {
        Base::None => {}
        Base::Default => {
            if let Some(entry) = entries
                .iter()
                .find(|e| e.entry.name.as_str() == BASE_PROVIDER_NAME)
            {
                return Err(ProviderError::ReservedName {
                    name: entry.entry.name.clone(),
                });
            }
            let name = BASE_PROVIDER_NAME
                .parse::<ProviderName>()
                .map_err(|e| ProviderError::BuiltinBase(e.to_string()))?;
            providers.push(Box::new(ConfigProvider::with_origin(
                name,
                ProfileRef::main(),
                default_base_manifest()?,
                ProviderOrigin::Builtin,
            )));
            // The default `vcs` provider, unless the configuration declares
            // one of its own, which then takes its place.
            if !entries
                .iter()
                .any(|e| matches!(e.entry.kind, crate::config::ProviderKind::Vcs { .. }))
            {
                if let Some(entry) = entries
                    .iter()
                    .find(|e| e.entry.name.as_str() == super::VCS_PROVIDER_NAME)
                {
                    return Err(ProviderError::ReservedName {
                        name: entry.entry.name.clone(),
                    });
                }
                providers.push(Box::new(super::VcsProvider::builtin()));
            }
        }
    }
    for entry in entries {
        providers.push(from_layered_entry(entry)?);
    }
    Ok(providers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::DevMode;
    use crate::policy::NetworkMode;
    use crate::provider::ProviderContext;
    use std::path::PathBuf;

    fn cfg(src: &str) -> Config {
        Config::from_toml_str(src).unwrap()
    }

    fn names(config: &Config) -> Vec<String> {
        session_providers(config, Path::new("/cfg"))
            .unwrap()
            .iter()
            .map(|p| p.name().as_str().to_owned())
            .collect()
    }

    fn ctx() -> ProviderContext {
        ProviderContext {
            workspace: PathBuf::from("/w"),
            workspace_mount: "/workspace".parse().unwrap(),
            home: PathBuf::from("/home/h"),
            session_dir: PathBuf::from("/run/s"),
            rw_grants: Vec::new(),
        }
    }

    fn strs<T>(items: &[T], f: impl Fn(&T) -> &str) -> Vec<String> {
        items.iter().map(|i| f(i).to_owned()).collect()
    }

    #[test]
    fn embedded_manifest_parses_with_the_expected_rules() {
        let m = default_base_manifest().unwrap();
        assert!(m.profiles.is_empty());
        assert!(m.grants.shims.is_empty());
        let g = &m.grants;
        assert_eq!(g.network.mode, Some(NetworkMode::Loopback));
        assert_eq!(g.system.proc, Some(true));
        assert_eq!(g.system.dev, Some(DevMode::Minimal));
        // HOME's location is not a grant: the spec defaults it, so users can
        // set `system.home` without a merge conflict.
        assert_eq!(g.system.home, None);
        assert_eq!(
            strs(&g.system.etc, |e| e.as_str()),
            ["passwd", "group", "hosts", "nsswitch.conf"]
        );
        assert_eq!(strs(&g.fs.rw, |p| p.as_str()), ["{workspace}"]);
        assert_eq!(g.fs.masked.len(), 13);
        let masked = strs(&g.fs.masked, |p| p.as_str());
        for want in [
            "{workspace}/**/.env",
            "{workspace}/**/.pypirc",
            "{workspace}/**/.netrc",
            "{workspace}/**/*.p12",
            "{workspace}/**/*.pfx",
            "{workspace}/**/*credentials*.json",
            "{workspace}/**/id_rsa",
            "{workspace}/**/id_ed25519",
            "{workspace}/**/.terraformrc",
        ] {
            assert!(masked.contains(&want.to_owned()), "{want}");
        }
        assert_eq!(g.fs.mask_sockets, Some(true));
        assert_eq!(g.fs.protected.len(), 21);
        let protected = strs(&g.fs.protected, |p| p.as_str());
        for want in [
            "{workspace}/.stopit.toml",
            "{workspace}/**/.stopit.toml",
            "{workspace}/.github/workflows",
            "{workspace}/.gitmodules",
            "{workspace}/.cargo/config.toml",
            "{workspace}/.cargo/config",
            "{workspace}/.bazelrc",
            "{workspace}/.claude",
            "{workspace}/.gemini",
            "{workspace}/.cursor",
            "{workspace}/.mcp.json",
            "{workspace}/.zed",
            "{workspace}/**/.nvim.lua",
            "{workspace}/**/.exrc",
            "{workspace}/.gdbinit",
            "{workspace}/.lldbinit",
        ] {
            assert!(protected.contains(&want.to_owned()), "{want}");
        }
        assert_eq!(strs(&g.fs.ephemeral, |p| p.as_str()), ["/tmp", "~"]);
        assert!(g.fs.ro.is_empty() && g.fs.bind.is_empty());
        assert_eq!(
            strs(&g.env.pass, |p| p.as_str()),
            ["TERM", "LANG", "COLORTERM"]
        );
        assert_eq!(g.env.deny.len(), 8);
        let deny = strs(&g.env.deny, |p| p.as_str());
        assert!(deny.contains(&"SSH_AUTH_SOCK".to_owned()));
        assert!(deny.contains(&"*_TOKEN".to_owned()));
    }

    #[test]
    fn base_none_has_only_user_providers() {
        assert!(names(&cfg("base = \"none\"")).is_empty());
        let c = cfg(
            "base = \"none\"\n[[provider]]\ntype = \"config\"\nname = \"b\"\n\
             [[provider]]\ntype = \"config\"\nname = \"a\"",
        );
        assert_eq!(names(&c), ["b", "a"]);
    }

    #[test]
    fn base_default_comes_first_then_user_providers_in_order() {
        assert_eq!(names(&cfg("")), ["base", "vcs"]);
        let c = cfg("[[provider]]\ntype = \"config\"\nname = \"z\"\n\
             [[provider]]\ntype = \"script\"\nsource = \"x.sh\"\n\
             [[provider]]\ntype = \"config\"\nname = \"a\"");
        assert_eq!(names(&c), ["base", "vcs", "z", "script", "a"]);
    }

    #[test]
    fn user_provider_named_base_is_reserved_under_default_only() {
        let src = "[[provider]]\ntype = \"config\"\nname = \"base\"";
        let Err(e) = session_providers(&cfg(src), Path::new("/cfg")) else {
            panic!("the name is reserved");
        };
        assert!(matches!(e, ProviderError::ReservedName { .. }), "{e:?}");
        let msg = e.to_string();
        assert!(msg.contains("\"base\""), "{msg}");
        assert!(msg.contains("base = \"none\""), "{msg}");
        assert!(msg.contains("different name"), "{msg}");

        let c = cfg(&format!("base = \"none\"\n{src}"));
        assert_eq!(names(&c), ["base"]);
    }

    #[test]
    fn user_provider_named_stopit_is_reserved_under_every_base() {
        let src = "[[provider]]\ntype = \"config\"\nname = \"stopit\"";
        for base in ["", "base = \"none\"\n"] {
            let Err(e) = session_providers(&cfg(&format!("{base}{src}")), Path::new("/cfg")) else {
                panic!("{base:?}: the name is reserved");
            };
            assert!(
                matches!(e, ProviderError::ReservedForSupervisor { .. }),
                "{e:?}"
            );
            let msg = e.to_string();
            assert!(msg.contains("\"stopit\""), "{msg}");
            assert!(msg.contains("reserved"), "{msg}");
            assert!(msg.contains("different name"), "{msg}");
        }
    }

    #[test]
    fn a_vcs_provider_of_the_users_replaces_the_default_one() {
        let c = cfg("[[provider]]\ntype = \"vcs\"\nname = \"mine\"\nview = \"ro\"");
        assert_eq!(names(&c), ["base", "mine"]);
        // Another type may not take the default one's name.
        let c = cfg("[[provider]]\ntype = \"config\"\nname = \"vcs\"");
        let Err(e) = session_providers(&c, Path::new("/cfg")) else {
            panic!("the name is reserved");
        };
        assert!(matches!(e, ProviderError::ReservedName { .. }), "{e:?}");
        // Without the default base, there is no default one.
        assert!(names(&cfg("base = \"none\"")).is_empty());
    }

    #[test]
    fn base_provider_targets_main_with_the_parsed_manifest() {
        let ps = session_providers(&cfg(""), Path::new("/cfg")).unwrap();
        let out = ps[0].manifest(&ctx()).unwrap();
        assert_eq!(out.profile, ProfileRef::main());
        assert_eq!(out.manifest, default_base_manifest().unwrap());
        assert!(ps[0].protected_paths().unwrap().is_empty());
    }
}
