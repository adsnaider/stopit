//! The command line of `stopit` (DESIGN.md §5): `stopit run`, `stopit
//! shell`, the trust store's `stopit allow`, `revoke` and `allowed` (§3),
//! and `--version`.
//!
//! The internal `stopit __init` (§6.3) is not part of it: `main` dispatches
//! it before this parser runs, so its argv contract (`__init --env-fd N --
//! <cmd…>`) never goes through clap and none of the options here can
//! change it.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// `stopit`'s arguments.
#[derive(Debug, Parser)]
#[command(
    name = "stopit",
    version,
    about = "Run a command in a sandbox",
    disable_help_subcommand = true
)]
pub struct Cli {
    /// What to do.
    #[command(subcommand)]
    pub command: CliCommand,
}

/// A subcommand.
#[derive(Debug, PartialEq, Eq, Subcommand)]
pub enum CliCommand {
    /// Run a command in the sandbox.
    Run {
        /// The session's options.
        #[command(flatten)]
        session: SessionArgs,
        /// The command and its arguments, passed on unchanged. Everything
        /// from the command on is its own, flags included (`stopit run ls
        /// -la`); a command that starts with `-` goes after `--`.
        //
        // `trailing_var_arg` alone, without `allow_hyphen_values`: a
        // mistyped stopit option before the command (`--profle x`) is a
        // usage error instead of a command to run.
        #[arg(required = true, trailing_var_arg = true, value_name = "CMD")]
        command: Vec<OsString>,
    },
    /// Run the host's `$SHELL` in the sandbox (the sandbox must grant it).
    Shell {
        /// The session's options.
        #[command(flatten)]
        session: SessionArgs,
    },
    /// Allow the workspace's `.stopit.toml` as it is now. Review it first:
    /// it decides what the sandbox may do and which scripts run on the host.
    Allow {
        /// Which workspace.
        #[command(flatten)]
        workspace: WorkspaceArg,
    },
    /// Stop allowing the workspace's `.stopit.toml`, or the configuration
    /// file PATH.
    Revoke {
        /// Which workspace.
        #[command(flatten)]
        workspace: WorkspaceArg,
        /// The configuration file to stop allowing, as `stopit allowed`
        /// lists it, without looking for a workspace: it may be gone.
        #[arg(value_name = "PATH", conflicts_with = "workspace")]
        config: Option<PathBuf>,
    },
    /// List the configurations you allowed.
    Allowed,
}

/// The options `run` and `shell` share.
#[derive(Debug, Clone, Default, PartialEq, Eq, Args)]
pub struct SessionArgs {
    /// The workspace directory [default: the nearest directory, from the
    /// current one up, containing `.stopit.toml`, else the current
    /// directory].
    #[arg(long, value_name = "DIR")]
    pub workspace: Option<PathBuf>,
    /// The profile to run in [default: main].
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,
    /// Do not print the startup summary of what the sandbox is granted
    /// (warnings and errors are still printed). Must come before the
    /// command: after it, `-q` is the command's own.
    #[arg(short, long)]
    pub quiet: bool,
}

/// The workspace option of `allow` and `revoke`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Args)]
pub struct WorkspaceArg {
    /// The workspace directory [default: the nearest directory, from the
    /// current one up, containing `.stopit.toml`, else the current
    /// directory], found as `run` finds it.
    #[arg(long, value_name = "DIR")]
    pub workspace: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use std::os::unix::ffi::OsStringExt;

    use clap::error::ErrorKind;

    use super::*;

    fn parse(args: &[&str]) -> Result<CliCommand, clap::Error> {
        Cli::try_parse_from(std::iter::once("stopit").chain(args.iter().copied()))
            .map(|cli| cli.command)
    }

    fn run(workspace: Option<&str>, profile: Option<&str>, command: &[&str]) -> CliCommand {
        CliCommand::Run {
            session: SessionArgs {
                workspace: workspace.map(PathBuf::from),
                profile: profile.map(str::to_owned),
                quiet: false,
            },
            command: command.iter().map(OsString::from).collect(),
        }
    }

    #[test]
    fn the_command_and_everything_after_it_is_passed_on() {
        assert_eq!(parse(&["run", "ls"]).unwrap(), run(None, None, &["ls"]));
        // Flags after the command are the command's, even stopit's own.
        assert_eq!(
            parse(&["run", "ls", "-la", "--profile", "x", "--", "--help"]).unwrap(),
            run(None, None, &["ls", "-la", "--profile", "x", "--", "--help"])
        );
        assert_eq!(
            parse(&[
                "run",
                "--profile",
                "p",
                "--workspace",
                "/w",
                "cargo",
                "test",
                "--",
                "-q"
            ])
            .unwrap(),
            run(Some("/w"), Some("p"), &["cargo", "test", "--", "-q"])
        );
    }

    #[test]
    fn double_dash_ends_stopits_options() {
        assert_eq!(
            parse(&["run", "--", "-weird", "--version"]).unwrap(),
            run(None, None, &["-weird", "--version"])
        );
        assert_eq!(
            parse(&["run", "--profile=p", "--", "ls"]).unwrap(),
            run(None, Some("p"), &["ls"])
        );
        // Only the first `--` is stopit's.
        assert_eq!(
            parse(&["run", "--", "--", "x"]).unwrap(),
            run(None, None, &["--", "x"])
        );
    }

    #[test]
    fn a_mistyped_option_before_the_command_is_an_error() {
        let e = parse(&["run", "--profle", "p", "ls"]).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::UnknownArgument);
        assert_eq!(e.exit_code(), 2);
    }

    #[test]
    fn run_needs_a_command() {
        for args in [&["run"][..], &["run", "--profile", "p"], &["run", "--"]] {
            let e = parse(args).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::MissingRequiredArgument, "{args:?}");
        }
    }

    #[test]
    fn option_values_are_required() {
        for args in [&["run", "--profile"][..], &["shell", "--workspace"]] {
            assert!(parse(args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn shell_takes_only_the_session_options() {
        assert_eq!(
            parse(&["shell"]).unwrap(),
            CliCommand::Shell {
                session: SessionArgs::default()
            }
        );
        assert_eq!(
            parse(&["shell", "--workspace", "w", "--profile", "p"]).unwrap(),
            CliCommand::Shell {
                session: SessionArgs {
                    workspace: Some("w".into()),
                    profile: Some("p".into()),
                    quiet: false,
                }
            }
        );
        let e = parse(&["shell", "ls"]).unwrap_err();
        assert_eq!(e.exit_code(), 2);
    }

    #[test]
    fn quiet_is_a_session_option_before_the_command() {
        let quiet = |command: &[&str]| CliCommand::Run {
            session: SessionArgs {
                quiet: true,
                ..SessionArgs::default()
            },
            command: command.iter().map(OsString::from).collect(),
        };
        assert_eq!(parse(&["run", "-q", "ls"]).unwrap(), quiet(&["ls"]));
        assert_eq!(parse(&["run", "--quiet", "ls"]).unwrap(), quiet(&["ls"]));
        // After the command it is the command's own.
        assert_eq!(
            parse(&["run", "ls", "-q"]).unwrap(),
            run(None, None, &["ls", "-q"])
        );
        assert_eq!(
            parse(&["shell", "--quiet"]).unwrap(),
            CliCommand::Shell {
                session: SessionArgs {
                    quiet: true,
                    ..SessionArgs::default()
                }
            }
        );
    }

    #[test]
    fn non_utf8_commands_and_workspaces_pass() {
        let odd = OsString::from_vec(b"\xff\xfe".to_vec());
        let args: Vec<OsString> = ["stopit", "run", "--workspace"]
            .into_iter()
            .map(OsString::from)
            .chain([odd.clone(), odd.clone(), odd.clone()])
            .collect();
        let cli = Cli::try_parse_from(args).unwrap();
        assert_eq!(
            cli.command,
            CliCommand::Run {
                session: SessionArgs {
                    workspace: Some(PathBuf::from(&odd)),
                    profile: None,
                    quiet: false,
                },
                command: vec![odd.clone(), odd],
            }
        );
    }

    #[test]
    fn revoke_takes_the_workspace_or_a_configuration_path() {
        let revoke = |dir: Option<&str>, config: Option<&str>| CliCommand::Revoke {
            workspace: WorkspaceArg {
                workspace: dir.map(PathBuf::from),
            },
            config: config.map(PathBuf::from),
        };
        assert_eq!(parse(&["revoke"]).unwrap(), revoke(None, None));
        assert_eq!(
            parse(&["revoke", "/gone/.stopit.toml"]).unwrap(),
            revoke(None, Some("/gone/.stopit.toml"))
        );
        // A path that looks like an option goes after `--`.
        assert_eq!(
            parse(&["revoke", "--", "--x"]).unwrap(),
            revoke(None, Some("--x"))
        );
        for args in [
            &["revoke", "--workspace", "w", "p"][..],
            &["revoke", "p", "--workspace", "w"],
        ] {
            let e = parse(args).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::ArgumentConflict, "{args:?}");
            assert_eq!(e.exit_code(), 2, "{args:?}");
        }
        assert_eq!(parse(&["revoke", "a", "b"]).unwrap_err().exit_code(), 2);
    }

    #[test]
    fn allow_takes_only_the_workspace_and_revoke_takes_it_too() {
        let ws = |dir: Option<&str>| WorkspaceArg {
            workspace: dir.map(PathBuf::from),
        };
        assert_eq!(
            parse(&["allow"]).unwrap(),
            CliCommand::Allow {
                workspace: ws(None)
            }
        );
        assert_eq!(
            parse(&["allow", "--workspace", "w"]).unwrap(),
            CliCommand::Allow {
                workspace: ws(Some("w"))
            }
        );
        assert_eq!(
            parse(&["revoke", "--workspace=w"]).unwrap(),
            CliCommand::Revoke {
                workspace: ws(Some("w")),
                config: None,
            }
        );
        assert_eq!(parse(&["allowed"]).unwrap(), CliCommand::Allowed);
        for args in [
            &["allow", "x"][..],
            &["allow", "--profile", "p"],
            &["revoke", "--workspace"],
            &["allowed", "--workspace", "w"],
        ] {
            assert_eq!(parse(args).unwrap_err().exit_code(), 2, "{args:?}");
        }
    }

    #[test]
    fn version_and_help_are_not_errors() {
        for (args, kind) in [
            (&["--version"][..], ErrorKind::DisplayVersion),
            (&["--help"], ErrorKind::DisplayHelp),
            (&["run", "--help"], ErrorKind::DisplayHelp),
        ] {
            let e = parse(args).unwrap_err();
            assert_eq!(e.kind(), kind, "{args:?}");
            assert_eq!(e.exit_code(), 0, "{args:?}");
        }
    }

    #[test]
    fn init_is_not_a_subcommand() {
        // `main` runs it before parsing; the parser knows no such thing.
        let e = parse(&["__init", "--env-fd", "3", "--", "x"]).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidSubcommand);
    }

    #[test]
    fn the_cli_is_consistent() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
