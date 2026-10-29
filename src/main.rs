use std::ffi::OsString;
use std::process::ExitCode;

use clap::Parser;
use stopit::cli::{Cli, CliCommand};
use stopit::supervisor::{self, Invocation};

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().collect();
    // The init helper, run by bwrap inside every sandbox (DESIGN.md §6.3).
    // Dispatched before the command-line parser, so its argv contract never
    // depends on it. Returns only on failure.
    if let [_, subcommand, rest @ ..] = args.as_slice() {
        if subcommand == stopit::init::SUBCOMMAND {
            return ExitCode::from(stopit::init::run(rest));
        }
    }
    let cli = match Cli::try_parse_from(&args) {
        Ok(cli) => cli,
        // Usage errors exit with 2; `--help` and `--version` print to
        // stdout and exit with 0.
        Err(e) => {
            let _ = e.print();
            return ExitCode::from(u8::try_from(e.exit_code()).unwrap_or(2));
        }
    };
    let invocation = match cli.command {
        CliCommand::Run { session, command } => Invocation {
            workspace: session.workspace,
            profile: session.profile,
            quiet: session.quiet,
            command,
            server: session.server,
            standalone: session.standalone,
        },
        CliCommand::Shell { session } => {
            match supervisor::shell_command(std::env::var_os("SHELL")) {
                Ok(command) => Invocation {
                    workspace: session.workspace,
                    profile: session.profile,
                    quiet: session.quiet,
                    command,
                    server: session.server,
                    standalone: session.standalone,
                },
                Err(e) => {
                    supervisor::print_error(&e.to_string());
                    return ExitCode::from(supervisor::EXIT_SUPERVISOR_FAILED);
                }
            }
        }
        CliCommand::Allow { workspace } => return supervisor::allow(workspace.workspace),
        CliCommand::Revoke { workspace, config } => {
            return supervisor::revoke(workspace.workspace, config);
        }
        CliCommand::Allowed => return supervisor::allowed(),
        CliCommand::Server { workspace, quiet } => {
            return stopit::server::serve(workspace.workspace, quiet);
        }
    };
    supervisor::run(invocation)
}
