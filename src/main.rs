use std::ffi::OsString;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match args.as_slice() {
        [arg] if arg == "--version" => {
            println!("stopit {}", stopit::VERSION);
            ExitCode::SUCCESS
        }
        // The init helper, run by bwrap inside every sandbox (DESIGN.md
        // §6.3). Returns only on failure.
        [subcommand, rest @ ..] if subcommand == stopit::init::SUBCOMMAND => {
            ExitCode::from(stopit::init::run(rest))
        }
        _ => {
            eprintln!("usage: stopit --version");
            ExitCode::from(2)
        }
    }
}
