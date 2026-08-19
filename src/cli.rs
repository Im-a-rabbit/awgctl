use crate::{
    client::Client,
    server::Server,
    util::{Listable, Result, print_table, secure_write},
};
use clap::{
    Args, CommandFactory, Parser, Subcommand,
    builder::styling::{AnsiColor, Effects, Styles},
};
use clap_complete::Shell;
use qrcode::{
    QrCode,
    render::{svg, unicode},
};
use std::{io, io::Write, path::PathBuf};
use wireguard_conf::ipnet::IpNet;

/// Корневая CLI-структура.
///
/// Разбирает аргументы командной строки и делегирует выполнение
/// соответствующим [`Server`] или [`Client`] функциям.
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
    /// Эскалирует привилегии через [`sudo2`] и выполняет подкоманду.
    pub fn run() -> Result<()> {
        sudo2::escalate_if_needed()?;
        match Self::parse().command {
            Commands::New(args) => Server::new(args)?.save(),
            Commands::Add(args) => {
                let mut server = Server::load(&args.server)?;
                Client::new(args, &mut server)?.save()?;
                server.save()
            }
            Commands::Rm(args) => match args.client {
                Some(client) => Client::rm(&args.server, &client),
                None => Server::rm(&args.server),
            },
            Commands::Export(args) => {
                let client = Client::load(&args.server, &args.client)?;
                let config = client.into_interface()?.to_string();

                match (args.output, args.qr) {
                    (Some(path), true) => {
                        let code = QrCode::new(config.as_bytes())?
                            .render()
                            .min_dimensions(200, 200)
                            .dark_color(svg::Color("#000000"))
                            .light_color(svg::Color("#ffffff"))
                            .build();
                        secure_write(&path, &code)
                    }
                    (None, true) => {
                        let code = QrCode::new(config.as_bytes())?
                            .render::<unicode::Dense1x2>()
                            .dark_color(unicode::Dense1x2::Light)
                            .light_color(unicode::Dense1x2::Dark)
                            .build();
                        println!("{code}");
                        Ok(())
                    }
                    (Some(path), false) => secure_write(&path, &config),
                    (None, false) => {
                        println!("{config}");
                        Ok(())
                    }
                }
            }
            Commands::List(args) => {
                match args.server {
                    Some(server_name) => {
                        let server = Server::load(&server_name)?;
                        let lhs = Server::headers(true);
                        let label_width = lhs.iter().map(|h| h.len()).max().unwrap_or(0);

                        let mut out = io::stdout().lock();
                        lhs.iter().zip(server.row(true)).for_each(|(key, value)| {
                            writeln!(out, "{:<label_width$}  {}", key, value).ok();
                        });
                        writeln!(out).ok();

                        print_table(&Client::list(&server_name)?, args.verbose, "no clients");
                    }
                    None => {
                        print_table(&Server::list()?, args.verbose, "no servers");
                    }
                }
                Ok(())
            }
            Commands::Completions(args) => {
                let mut cmd = Self::command();
                clap_complete::generate(args.shell, &mut cmd, "awgctl", &mut io::stdout());
                Ok(())
            }
        }
    }
}

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
    pub address: Option<Vec<IpNet>>,

    /// Listen port.
    #[arg(short = 'p', long = "port")]
    pub listen_port: Option<u16>,

    /// DNS servers.
    #[arg(long)]
    pub dns: Option<Vec<String>>,

    /// Public endpoint.
    #[arg(long)]
    pub endpoint: Option<String>,

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
    pub address: Option<Vec<IpNet>>,

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
