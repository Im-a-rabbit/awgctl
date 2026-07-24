mod cli;
mod server;
use cli::Cli;

use crate::server::Result;

fn main() -> Result<()> {
    Cli::run()?;
    Ok(())
}
