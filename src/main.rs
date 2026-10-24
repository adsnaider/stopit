use std::ffi::OsString;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match args.as_slice() {
        [arg] if arg == "--version" => {
            println!("stopit {}", stopit::VERSION);
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("usage: stopit --version");
            ExitCode::from(2)
        }
    }
}
