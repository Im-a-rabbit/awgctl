use crate::server::{Result, Server};
use clap::builder::styling::{AnsiColor, Effects, Styles};
use clap::{Args, Parser, Subcommand};
use wireguard_conf::ipnet::IpNet;

#[derive(Parser)]
#[command(
    styles = Styles::styled()
    .header(AnsiColor::Green.on_default() | Effects::BOLD)
    .usage(AnsiColor::Green.on_default() | Effects::BOLD)
    .literal(AnsiColor::Cyan.on_default())
    .placeholder(AnsiColor::Yellow.on_default()),
    version,
    about,
    long_about = None,
)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

impl Cli {
    pub fn run() -> Result<()> {
        match Self::parse().command {
            Commands::New(args) => Server::new(args)?.save(),
            Commands::Print(args) => {
                let server = Server::new(args)?;
                println!("{}", server.name);
                println!("{}", toml::to_string_pretty(&server)?);
                Ok(())
            }
        }
    }
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create a new AmneziaWG server.
    New(NewArgs),
    Print(NewArgs),
}

#[derive(Args)]
pub struct NewArgs {
    /// Interface name.
    pub name: Option<String>,

    /// Interface description.
    #[arg(short, long)]
    pub desc: Option<String>,

    /// Interface address.
    #[arg(short, long)]
    pub address: Option<Vec<IpNet>>,

    /// Listen port.
    #[arg(short, long)]
    pub listen_port: Option<u16>,

    /// DNS servers.
    #[arg(short, long)]
    pub dns: Option<Vec<String>>,

    /// Public endpoint.
    #[arg(long)]
    pub endpoint: Option<String>,

    /// Interface MTU.
    #[arg(long)]
    pub mtu: Option<usize>,
}
