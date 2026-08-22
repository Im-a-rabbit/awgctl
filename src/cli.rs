use crate::{
    client::Client,
    commands::Commands,
    errors::Result,
    server::Server,
    util::{Listable, print_table, secure_write},
};
use clap::{
    CommandFactory, Parser,
    builder::styling::{AnsiColor, Effects, Styles},
};
use qrcode::{
    QrCode,
    render::{svg, unicode},
};
use std::{io, io::Write};

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
        let args = Self::parse();
        if !matches!(args.command, Commands::Completions(_)) {
            sudo2::escalate_if_needed()?;
        }
        match args.command {
            Commands::New(args) => Server::new(args)?.save(),
            Commands::Add(args) => {
                // TODO: подумать над порядком операций
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
                        let label_width = lhs
                            .iter()
                            .map(|h| h.len())
                            .max()
                            .expect("headers must not be empty");

                        let mut out = io::stdout().lock();
                        lhs.iter().zip(server.row(true)).for_each(|(key, value)| {
                            writeln!(out, "{:<label_width$}  {}", key, value).ok();
                        });
                        writeln!(out).ok();

                        print_table(&Client::list(&server_name)?, args.verbose, "No clients");
                    }
                    None => {
                        print_table(&Server::list()?, args.verbose, "No servers");
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
