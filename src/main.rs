//! CLI-утилита для управления серверами и клиентами AmneziaWG.
#![deny(missing_docs)]

mod cli;
mod client;
mod commands;
mod errors;
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
// TODO: table pre_* post_* awg wireguard-conf
// Добавить в list время?
// Переписать комментарии
