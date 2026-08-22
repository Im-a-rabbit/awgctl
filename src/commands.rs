use clap::{Args, Subcommand};
use clap_complete::Shell;
use std::path::PathBuf;
use wireguard_conf::ipnet::IpNet;

/// Доступные подкоманды.
#[derive(Subcommand)]
pub enum Commands {
    /// Create a new AmneziaWG server.
    New(NewArgs),

    /// Add a new peer.
    Add(AddArgs),

    /// Remove a server or client.
    Rm(RmArgs),

    /// Export a client's WireGuard configuration.
    Export(ExportArgs),

    /// List servers or clients.
    List(ListArgs),

    /// Generate shell completions.
    Completions(CompletionsArgs),
}

/// Аргументы команды [`Commands::New`].
#[derive(Args)]
pub struct NewArgs {
    /// Interface name.
    pub name: Option<String>,

    /// Interface address.
    #[arg(short, long)]
    pub address: Vec<IpNet>,

    /// Listen port.
    #[arg(short = 'p', long = "port")]
    pub listen_port: Option<u16>,

    /// Public endpoint.
    #[arg(short, long)]
    pub endpoint: Option<String>,

    /// DNS servers.
    #[arg(long)]
    pub dns: Vec<String>,

    /// Interface MTU.
    #[arg(long)]
    pub mtu: Option<usize>,
}

/// Аргументы команды [`Commands::Add`].
#[derive(Args)]
pub struct AddArgs {
    /// Server name.
    pub server: String,

    /// Client name.
    pub client: String,

    /// Client addresses.
    #[arg(short, long)]
    pub address: Vec<IpNet>,

    /// Use the VPN as the default gateway.
    #[arg(short, long)]
    pub default_gateway: bool,

    /// DNS servers.
    #[arg(long)]
    pub dns: Option<Vec<String>>,

    /// Don't inherit DNS from the server.
    #[arg(long)]
    pub no_dns: bool,

    /// Persistent keepalive.
    #[arg(short, long)]
    pub keepalive: Option<u16>,
}

/// Аргументы команды [`Commands::Rm`].
#[derive(Args)]
pub struct RmArgs {
    /// Server name.
    pub server: String,
    /// Client name. If provided, removes client instead of server.
    pub client: Option<String>,
}

/// Аргументы команды [`Commands::Export`].
#[derive(Args)]
pub struct ExportArgs {
    /// Server name.
    pub server: String,

    /// Client name.
    pub client: String,

    /// Output file path.
    /// With -q: saves QR code as SVG.
    /// Without -q: saves config as text.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Output QR code instead of text config.
    #[arg(short, long)]
    pub qr: bool,
}

/// Аргументы команды [`Commands::List`].
#[derive(Args)]
pub struct ListArgs {
    /// Server name. If specified, lists clients for this server.
    pub server: Option<String>,

    /// Show extended output.
    #[arg(short, long)]
    pub verbose: bool,
}

/// Аргументы команды [`Commands::Completions`].
#[derive(Args)]
pub struct CompletionsArgs {
    /// Shell to generate completions for.
    pub shell: Shell,
}
