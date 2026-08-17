mod cli;
mod client;
mod server;
mod util;

use std::process::ExitCode;

fn main() -> ExitCode {
    if let Err(e) = cli::Cli::run() {
        eprintln!("{e}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
