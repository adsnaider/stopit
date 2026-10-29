//! The target's environment (DESIGN.md §9): the sandbox's identity
//! (`HOME`, `USER`, `LOGNAME`), the host's variables filtered by `pass` and
//! `deny`, then the explicit `set` variables, then `PATH`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;

use crate::etc::SANDBOX_USER;
use crate::manifest::SandboxHome;
use crate::resolve::EffectiveEnv;
use crate::spec::SandboxSpec;

/// The name of the search path variable, built from `path_prepend`.
const PATH: &str = "PATH";

/// The variables stopit sets itself, to the sandbox's identity: its home
/// directory, and the user the synthesized `/etc/passwd` defines.
const HOME: &str = "HOME";
const USER: &str = "USER";
const LOGNAME: &str = "LOGNAME";

impl EffectiveEnv {
    /// The environment the target gets in a sandbox whose home is `home`,
    /// built from the `host` variables.
    ///
    /// * stopit sets the sandbox's identity: `HOME` is `home`, and `USER`
    ///   and `LOGNAME` are the user of the synthesized `/etc/passwd`
    ///   ([`SANDBOX_USER`]). These are never taken from the host, whatever
    ///   `pass` says, so these variables never reveal the host home path or
    ///   user name. `set` may override them.
    /// * A host variable is passed only if its name matches a `pass` pattern
    ///   and no `deny` pattern: `deny` always wins. Matching is by name,
    ///   byte for byte, so non-UTF-8 names and values are matched and passed
    ///   intact; `pass` is case-sensitive, but `deny` ignores ASCII case,
    ///   being the safety net (`*_TOKEN` drops `github_token`). `PATH` is
    ///   never taken from the
    ///   host either: its entries are host paths that mostly do not exist in
    ///   the sandbox. A host variable that could not be in an environment
    ///   (an empty name, a `=` or NUL byte in the name, a NUL in the value)
    ///   is dropped; a real environment has none. If a name repeats, the
    ///   first occurrence is used, as `getenv` does.
    /// * Every `set` variable is then added, overriding a passed or identity
    ///   variable of the same name. `set` is explicit and not subject to the
    ///   host filter, so `deny` does not remove it.
    /// * `PATH` is the `path_prepend` entries joined with `:`, in order
    ///   (earlier entries first). With no entries there is no `PATH` at all:
    ///   a bare command is then not found (`__init` has no default search
    ///   path).
    ///
    /// Nothing else is added, not even `PWD`. The result is sorted by name
    /// and has no repeated name, so it is ready for
    /// [`init::encode_env`](crate::init::encode_env). An empty policy (such
    /// as `base = "none"`) gives just the identity.
    pub fn apply(
        &self,
        home: &SandboxHome,
        host: impl IntoIterator<Item = (OsString, OsString)>,
    ) -> Vec<(OsString, OsString)> {
        self.apply_with(home, host, &[])
    }

    /// [`apply`](Self::apply), with `defaults` added after the identity
    /// variables and before `set`. They override passed host variables, and
    /// `set` overrides them.
    pub fn apply_with(
        &self,
        home: &SandboxHome,
        host: impl IntoIterator<Item = (OsString, OsString)>,
        defaults: &[(&str, String)],
    ) -> Vec<(OsString, OsString)> {
        let mut env: BTreeMap<OsString, OsString> = BTreeMap::new();
        for (name, value) in host {
            let key = name.as_bytes();
            let well_formed = !key.is_empty()
                && !key.contains(&b'=')
                && !key.contains(&0)
                && !value.as_bytes().contains(&0);
            let ours = [PATH, HOME, USER, LOGNAME]
                .iter()
                .any(|reserved| key == reserved.as_bytes());
            if !well_formed
                || ours
                || !self.pass.iter().any(|p| p.matches(key))
                || self.deny.iter().any(|p| p.matches_ignore_ascii_case(key))
            {
                continue;
            }
            env.entry(name).or_insert(value);
        }
        env.insert(HOME.into(), home.as_str().into());
        env.insert(USER.into(), SANDBOX_USER.into());
        env.insert(LOGNAME.into(), SANDBOX_USER.into());
        for (name, value) in defaults {
            env.insert(name.into(), value.into());
        }
        for (name, value) in &self.set {
            env.insert(name.as_str().into(), value.as_str().into());
        }
        if !self.path_prepend.is_empty() {
            let entries: Vec<&str> = self.path_prepend.iter().map(|e| e.as_str()).collect();
            env.insert(PATH.into(), entries.join(":").into());
        }
        env.into_iter().collect()
    }
}

impl SandboxSpec {
    /// The environment the target gets in this sandbox, built from the
    /// `host` environment (typically [`std::env::vars_os`]). See
    /// [`EffectiveEnv::apply`]. With a network proxy
    /// ([`SandboxSpec::proxy_domains`]), the proxy variables point at the
    /// bridge ([`crate::proxy::proxy_env`]), whatever the host's say.
    pub fn target_env(
        &self,
        host: impl IntoIterator<Item = (OsString, OsString)>,
    ) -> Vec<(OsString, OsString)> {
        let defaults = if self.proxy_domains().is_some() {
            crate::proxy::proxy_env()
        } else {
            Vec::new()
        };
        let mut env = self.env.apply_with(&self.system.home, host, &defaults);
        // The profile's shims come first in `PATH`, once.
        if !self.installed_shims().is_empty() {
            let bin = OsString::from(crate::shim::SANDBOX_BIN);
            match env.iter_mut().find(|(k, _)| k == PATH) {
                Some((_, path)) => {
                    let mut joined = bin.clone();
                    // An empty entry would mean the current directory, so
                    // none is added.
                    for entry in path
                        .as_bytes()
                        .split(|&b| b == b':')
                        .filter(|e| !e.is_empty() && *e != bin.as_bytes())
                    {
                        joined.push(":");
                        joined.push(std::ffi::OsStr::from_bytes(entry));
                    }
                    *path = joined;
                }
                None => {
                    env.push((PATH.into(), bin));
                    env.sort();
                }
            }
        }
        env
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStringExt;

    use super::*;
    use crate::manifest::{EnvName, EnvPattern, EnvValue, SearchPathEntry};

    fn pats(v: &[&str]) -> Vec<EnvPattern> {
        v.iter().map(|s| s.parse().unwrap()).collect()
    }

    fn policy(pass: &[&str], deny: &[&str], set: &[(&str, &str)], path: &[&str]) -> EffectiveEnv {
        EffectiveEnv {
            pass: pats(pass),
            deny: pats(deny),
            set: set
                .iter()
                .map(|(k, v)| {
                    (
                        k.parse::<EnvName>().unwrap(),
                        v.parse::<EnvValue>().unwrap(),
                    )
                })
                .collect(),
            path_prepend: path
                .iter()
                .map(|p| p.parse::<SearchPathEntry>().unwrap())
                .collect(),
        }
    }

    fn vars(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        pairs.iter().map(|&(k, v)| (k.into(), v.into())).collect()
    }

    /// `env` applied to `host` in a sandbox with the default home.
    fn run(env: &EffectiveEnv, host: Vec<(OsString, OsString)>) -> Vec<(OsString, OsString)> {
        env.apply(&SandboxHome::default(), host)
    }

    /// `pairs` plus the default identity (unless `pairs` overrides it),
    /// sorted by name.
    fn with_identity(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        let mut all: BTreeMap<&str, &str> = BTreeMap::from([
            ("HOME", "/home/user"),
            ("USER", "user"),
            ("LOGNAME", "user"),
        ]);
        all.extend(pairs.iter().copied());
        all.into_iter().map(|(k, v)| (k.into(), v.into())).collect()
    }

    #[test]
    fn identity_is_always_present() {
        let out = run(&EffectiveEnv::default(), vars(&[]));
        assert_eq!(
            out,
            vars(&[
                ("HOME", "/home/user"),
                ("LOGNAME", SANDBOX_USER),
                ("USER", SANDBOX_USER)
            ])
        );
        assert_eq!(SANDBOX_USER, "user");
        // Also with a policy that passes and sets other things.
        let env = policy(&["A"], &[], &[("B", "2")], &["/bin"]);
        let out = run(&env, vars(&[("A", "1")]));
        assert_eq!(
            out,
            with_identity(&[("A", "1"), ("B", "2"), ("PATH", "/bin")])
        );
    }

    #[test]
    fn identity_is_never_taken_from_the_host() {
        let host = vars(&[
            ("HOME", "/home/adam"),
            ("USER", "adam"),
            ("LOGNAME", "adam"),
            ("A", "1"),
        ]);
        for pass in [
            &["*"][..],
            &["HOME", "USER", "LOGNAME", "A"],
            &["*ME", "U*", "A"],
        ] {
            let env = policy(pass, &[], &[], &[]);
            assert_eq!(run(&env, host.clone()), with_identity(&[("A", "1")]));
        }
    }

    #[test]
    fn set_overrides_the_identity() {
        let env = policy(
            &["*"],
            &["HOME", "*"],
            &[("HOME", "/srv/agent"), ("USER", "agent")],
            &[],
        );
        let host = vars(&[("HOME", "/home/adam"), ("LOGNAME", "adam")]);
        assert_eq!(
            run(&env, host),
            with_identity(&[("HOME", "/srv/agent"), ("USER", "agent")])
        );
    }

    #[test]
    fn home_is_the_sandbox_home() {
        let home: SandboxHome = "/srv/agent home".parse().unwrap();
        let out = EffectiveEnv::default().apply(&home, vars(&[("HOME", "/home/adam")]));
        let home_of = |out: &[(OsString, OsString)]| {
            let found = out.iter().find(|(k, _)| k == "HOME");
            found.map(|(_, v)| v.clone())
        };
        assert_eq!(home_of(&out), Some("/srv/agent home".into()));
        // Through a spec, from `system.home`.
        let mut spec = SandboxSpec::default();
        spec.system.home = home;
        let out = spec.target_env(vars(&[]));
        assert_eq!(home_of(&out), Some("/srv/agent home".into()));
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn only_passed_variables_reach_the_target() {
        let env = policy(&["TERM", "RUST_*"], &[], &[], &[]);
        let host = vars(&[
            ("OTHER", "/home/me"),
            ("RUST_LOG", "debug"),
            ("TERM", "xterm"),
            ("term", "lower"),
            ("TERMINAL", "x"),
        ]);
        assert_eq!(
            run(&env, host),
            with_identity(&[("RUST_LOG", "debug"), ("TERM", "xterm")])
        );
    }

    #[test]
    fn nothing_is_passed_without_a_pass_pattern() {
        let env = policy(&[], &["X"], &[], &[]);
        assert_eq!(
            run(&env, vars(&[("A", "1"), ("X", "2")])),
            with_identity(&[])
        );
    }

    #[test]
    fn deny_always_wins_over_pass() {
        // §9: `CARGO_REGISTRY_TOKEN` matches `CARGO_*` and `*_TOKEN`.
        let env = policy(&["CARGO_*", "TERM"], &["*_TOKEN", "TERM"], &[], &[]);
        let host = vars(&[
            ("CARGO_REGISTRY_TOKEN", "secret"),
            ("CARGO_HOME", "/c"),
            ("TERM", "xterm"),
        ]);
        assert_eq!(run(&env, host), with_identity(&[("CARGO_HOME", "/c")]));
        let env = policy(&["*"], &["*"], &[], &[]);
        assert_eq!(run(&env, vars(&[("A", "1")])), with_identity(&[]));
    }

    #[test]
    fn set_overrides_a_passed_value() {
        let env = policy(&["EDITOR", "LANG"], &[], &[("EDITOR", "nvim")], &[]);
        let host = vars(&[("EDITOR", "emacs"), ("LANG", "C")]);
        assert_eq!(
            run(&env, host),
            with_identity(&[("EDITOR", "nvim"), ("LANG", "C")])
        );
    }

    #[test]
    fn set_is_not_subject_to_the_host_filter() {
        // Neither missing from `pass` nor matched by `deny` removes it.
        let env = policy(
            &[],
            &["*_TOKEN", "EDITOR"],
            &[("EDITOR", "nvim"), ("MY_TOKEN", "explicit"), ("EMPTY", "")],
            &[],
        );
        assert_eq!(
            run(&env, vars(&[("MY_TOKEN", "host"), ("EDITOR", "host")])),
            with_identity(&[("EDITOR", "nvim"), ("EMPTY", ""), ("MY_TOKEN", "explicit")])
        );
    }

    #[test]
    fn path_is_built_from_path_prepend_in_order() {
        let env = policy(&[], &[], &[], &["/nix/store/a/bin", "/b", "/usr/bin"]);
        assert_eq!(
            run(&env, vars(&[])),
            with_identity(&[("PATH", "/nix/store/a/bin:/b:/usr/bin")])
        );
        let env = policy(&[], &[], &[], &["/only"]);
        assert_eq!(run(&env, vars(&[])), with_identity(&[("PATH", "/only")]));
    }

    #[test]
    fn no_path_without_path_prepend() {
        let env = policy(&["*"], &[], &[("A", "1")], &[]);
        let out = run(&env, vars(&[("B", "2")]));
        assert_eq!(out, with_identity(&[("A", "1"), ("B", "2")]));
        assert!(out.iter().all(|(k, _)| k != "PATH"));
    }

    #[test]
    fn host_path_never_leaks() {
        let host = vars(&[("PATH", "/home/me/bin:/usr/bin"), ("A", "1")]);
        // Even when `pass` names it or matches everything.
        for pass in [&["PATH", "A"][..], &["*"], &["PA*"]] {
            let env = policy(pass, &[], &[], &[]);
            let out = run(&env, host.clone());
            assert!(out.iter().all(|(k, _)| k != "PATH"), "{pass:?}: {out:?}");
            let env = policy(pass, &[], &[], &["/sandbox/bin"]);
            let out = run(&env, host.clone());
            assert!(
                out.contains(&("PATH".into(), "/sandbox/bin".into())),
                "{pass:?}: {out:?}"
            );
        }
    }

    #[test]
    fn empty_policy_gives_only_the_identity() {
        // What `base = "none"` with no providers merges to.
        let env = EffectiveEnv::default();
        assert_eq!(
            run(
                &env,
                vars(&[("HOME", "/h"), ("PATH", "/bin"), ("TERM", "x")])
            ),
            with_identity(&[])
        );
        assert_eq!(
            SandboxSpec::default().target_env(vars(&[("A", "1")])),
            with_identity(&[])
        );
    }

    #[test]
    fn non_utf8_values_and_names_pass_through_intact() {
        let bytes = |b: &[u8]| OsString::from_vec(b.to_vec());
        let env = policy(&["BIN", "*_BLOB", "NOPE_*"], &["NOPE_*"], &[], &[]);
        let host = vec![
            (OsString::from("BIN"), bytes(b"a\xff\xfeb")),
            (bytes(b"x\xffy_BLOB"), bytes(b"\x80\x81")),
            (bytes(b"NOPE_\xff"), bytes(b"1")),
        ];
        let mut want = with_identity(&[]);
        want.push((OsString::from("BIN"), bytes(b"a\xff\xfeb")));
        want.push((bytes(b"x\xffy_BLOB"), bytes(b"\x80\x81")));
        want.sort();
        assert_eq!(run(&env, host), want);
        // `deny` matches such names too.
        let env = policy(&["*"], &["*_BLOB"], &[], &[]);
        assert_eq!(
            run(&env, vec![(bytes(b"x\xff_BLOB"), bytes(b"v"))]),
            with_identity(&[])
        );
    }

    #[test]
    fn host_entries_that_cannot_be_in_an_environment_are_dropped() {
        let env = policy(&["*"], &[], &[], &[]);
        let host = vec![
            (OsString::from(""), OsString::from("v")),
            (OsString::from("A=B"), OsString::from("v")),
            (OsString::from("A\0B"), OsString::from("v")),
            (OsString::from("NUL"), OsString::from("a\0b")),
            (OsString::from("GOOD"), OsString::from("v")),
        ];
        assert_eq!(run(&env, host), with_identity(&[("GOOD", "v")]));
    }

    #[test]
    fn repeated_host_names_use_the_first_occurrence() {
        let env = policy(&["A"], &[], &[], &[]);
        let host = vars(&[("A", "first"), ("A", "second")]);
        assert_eq!(run(&env, host), with_identity(&[("A", "first")]));
    }

    #[test]
    fn output_is_sorted_by_name_whatever_the_input_order() {
        let env = policy(&["*"], &[], &[("M", "m")], &["/bin"]);
        let host = vars(&[("Z", "z"), ("a", "a"), ("B", "b"), ("_u", "u")]);
        let mut reversed = host.clone();
        reversed.reverse();
        let out = run(&env, host);
        assert_eq!(out, run(&env, reversed));
        let names: Vec<_> = out.iter().map(|(k, _)| k.to_str().unwrap()).collect();
        assert_eq!(
            names,
            ["B", "HOME", "LOGNAME", "M", "PATH", "USER", "Z", "_u", "a"]
        );
    }

    #[test]
    fn output_is_accepted_by_the_init_encoder() {
        let env = policy(&["*"], &[], &[("A", "")], &["/bin"]);
        let out = run(&env, vars(&[("B", "x=y"), ("PATH", "/h")]));
        assert_eq!(
            crate::init::encode_env(out.iter().map(|(k, v)| (k, v))).unwrap(),
            b"A=\0B=x=y\0HOME=/home/user\0LOGNAME=user\0PATH=/bin\0USER=user\0"
        );
    }

    #[test]
    fn proxy_mode_points_the_proxy_variables_at_the_bridge() {
        use crate::spec::{NetworkSpec, SandboxSpec};
        let mut spec = SandboxSpec {
            env: policy(&["*_PROXY", "*_proxy"], &[], &[("NO_PROXY", "mine")], &[]),
            network: NetworkSpec::Proxy {
                allow_domains: Default::default(),
            },
            ..SandboxSpec::default()
        };
        let host = vars(&[
            ("HTTPS_PROXY", "http://corp:3128"),
            ("FTP_PROXY", "ftp://corp"),
        ]);
        let env: BTreeMap<OsString, OsString> = spec.target_env(host.clone()).into_iter().collect();
        let get = |k: &str| {
            env.get(OsStr::new(k))
                .map(|v| v.to_str().unwrap().to_owned())
        };
        // The host's proxy is no use in the sandbox; ours wins over it.
        assert_eq!(get("HTTPS_PROXY").as_deref(), Some("http://127.0.0.1:1080"));
        assert_eq!(get("https_proxy").as_deref(), Some("http://127.0.0.1:1080"));
        assert_eq!(
            get("ALL_PROXY").as_deref(),
            Some("socks5h://127.0.0.1:1080")
        );
        assert_eq!(get("NODE_USE_ENV_PROXY").as_deref(), Some("1"));
        assert_eq!(get("no_proxy").as_deref(), Some("localhost,127.0.0.1,::1"));
        // `env.set` wins over ours, and a passed host variable we do not
        // set stays.
        assert_eq!(get("NO_PROXY").as_deref(), Some("mine"));
        assert_eq!(get("FTP_PROXY").as_deref(), Some("ftp://corp"));
        // Other modes, and a shared network namespace, set nothing.
        for network in [NetworkSpec::None, NetworkSpec::Loopback, NetworkSpec::Full] {
            spec.network = network;
            let env: BTreeMap<_, _> = spec.target_env(host.clone()).into_iter().collect();
            assert_eq!(
                env.get(OsStr::new("HTTPS_PROXY"))
                    .map(|v| v.to_str().unwrap()),
                Some("http://corp:3128")
            );
            assert!(!env.contains_key(OsStr::new("ALL_PROXY")));
        }
        spec.network = NetworkSpec::Proxy {
            allow_domains: Default::default(),
        };
        spec.namespaces.shared = [crate::manifest::ShareableNamespace::Net].into();
        let env: BTreeMap<_, _> = spec.target_env(host).into_iter().collect();
        assert!(!env.contains_key(OsStr::new("ALL_PROXY")));
    }

    #[test]
    fn deny_ignores_ascii_case_but_pass_does_not() {
        let env = policy(&["*"], &["*_TOKEN", "aws_*"], &[], &[]);
        let host = vars(&[
            ("github_token", "1"),
            ("GitHub_Token", "2"),
            ("GITHUB_TOKEN", "3"),
            ("AWS_REGION", "4"),
            ("npm_config__authToken", "5"),
            ("OK", "6"),
        ]);
        assert_eq!(
            run(&env, host),
            with_identity(&[("OK", "6"), ("npm_config__authToken", "5")])
        );
        let env = policy(&["RUST_*"], &[], &[], &[]);
        let host = vars(&[("RUST_LOG", "a"), ("rust_log", "b"), ("Rust_Log", "c")]);
        assert_eq!(run(&env, host), with_identity(&[("RUST_LOG", "a")]));
    }
}
