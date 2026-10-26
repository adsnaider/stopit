//! The built-in providers of a base (DESIGN.md §3.2, §3.5).

use std::path::Path;

use super::{ConfigProvider, Provider, ProviderError, from_entry};
use crate::config::{Base, Config, ProfileRef, ProviderName};
use crate::manifest::Manifest;

/// The name of the built-in `config` provider of `base = "default"`. User
/// providers cannot use it under that base.
pub const BASE_PROVIDER_NAME: &str = "base";

/// The default base's sandbox manifest (Appendix A), as data.
const DEFAULT_MANIFEST_TOML: &str = include_str!("base_default.toml");

/// Parses the embedded default-base manifest with the manifest parser that
/// user `[provider.sandbox]` tables use.
///
/// Fails only if the embedded file is broken, which a unit test rules out.
pub fn default_base_manifest() -> Result<Manifest, ProviderError> {
    toml::from_str(DEFAULT_MANIFEST_TOML).map_err(|e| ProviderError::BuiltinBase(e.to_string()))
}

/// The ordered providers of a session: the base's built-in providers first,
/// then the user's `[[provider]]` entries in file order (§3.5).
///
/// `base_dir` is the directory of the configuration file, as for
/// [`from_entry`].
///
/// TODO: a single `base_dir` is used because only one configuration file is
/// loaded today. When user-global layering lands, each entry must carry the
/// directory of the file that declared it (DESIGN.md §3.6).
pub fn session_providers(
    config: &Config,
    base_dir: &Path,
) -> Result<Vec<Box<dyn Provider>>, ProviderError> {
    let mut providers: Vec<Box<dyn Provider>> = Vec::new();
    match config.base {
        Base::None => {}
        Base::Default => {
            if let Some(entry) = config
                .providers
                .iter()
                .find(|e| e.name.as_str() == BASE_PROVIDER_NAME)
            {
                return Err(ProviderError::ReservedName {
                    name: entry.name.clone(),
                });
            }
            // The `vcs` provider joins the default base in Phase 3.
            let name = BASE_PROVIDER_NAME
                .parse::<ProviderName>()
                .map_err(|e| ProviderError::BuiltinBase(e.to_string()))?;
            providers.push(Box::new(ConfigProvider::new(
                name,
                ProfileRef::main(),
                default_base_manifest()?,
            )));
        }
    }
    for entry in &config.providers {
        providers.push(from_entry(entry, base_dir)?);
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
        assert_eq!(g.fs.masked.len(), 6);
        let masked = strs(&g.fs.masked, |p| p.as_str());
        assert!(masked.contains(&"{workspace}/**/.env".to_owned()));
        assert!(masked.contains(&"{workspace}/**/.pypirc".to_owned()));
        assert_eq!(g.fs.mask_sockets, Some(true));
        assert_eq!(g.fs.protected.len(), 7);
        let protected = strs(&g.fs.protected, |p| p.as_str());
        assert!(protected.contains(&"{workspace}/.stopit.toml".to_owned()));
        assert!(protected.contains(&"{workspace}/.github/workflows".to_owned()));
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
        assert_eq!(names(&cfg("")), ["base"]);
        let c = cfg("[[provider]]\ntype = \"config\"\nname = \"z\"\n\
             [[provider]]\ntype = \"script\"\nsource = \"x.sh\"\n\
             [[provider]]\ntype = \"config\"\nname = \"a\"");
        assert_eq!(names(&c), ["base", "z", "script", "a"]);
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
    fn user_provider_errors_propagate() {
        // `from_entry` has no other failure today (a script provider only
        // fails when run), so use the unimplemented vcs type. Replace this
        // trigger when the vcs provider lands in Phase 3.
        let c = cfg("[[provider]]\ntype = \"vcs\"");
        let Err(e) = session_providers(&c, Path::new("/cfg")) else {
            panic!("vcs is unsupported");
        };
        assert!(matches!(e, ProviderError::Unsupported { .. }), "{e:?}");
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
