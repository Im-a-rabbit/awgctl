use crate::{
    cli::AddArgs,
    server::Server,
    util::{AwgctlError, CLIENT_CAPACITY, CONF_DIR, Result, secure_write, validate_name},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, ffi::OsStr, fs, net::IpAddr, path::Path};
use time::OffsetDateTime;
use wireguard_conf::{ipnet::IpNet, prelude::*};

/// Клиент AmneziaWG — peer в конфигурации сервера.
///
/// Хранит метаданные (имя, дату создания), DNS-настройки и конфигурацию
/// [`Peer`]. Сериализуется в TOML-файл в `CONF_DIR/<server>/<client>.toml`.
#[derive(Debug, Serialize, Deserialize)]
pub struct Client {
    /// Client name.
    #[serde(skip)]
    pub name: String,

    /// Server name.
    #[serde(skip)]
    pub server: String,

    /// Client creation date.
    pub created_at: OffsetDateTime,

    /// DNS servers for this client. Overrides the server's DNS at export time.
    /// `None` inherits the server's DNS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<Vec<String>>,

    /// Use the VPN as the default gateway.
    pub default_gateway: bool,

    /// WireGuard peer configuration.
    pub peer: Peer,
}

impl Client {
    /// Loads a client configuration by name from the server's client directory.
    pub fn load(server_name: &str, client_name: &str) -> Result<Self> {
        let path = Path::new(CONF_DIR)
            .join(server_name)
            .join(client_name)
            .with_extension("toml");
        if path.exists() {
            Self::open(&path, server_name)
        } else {
            Err(AwgctlError::ClientNotFound(client_name.into()))
        }
    }

    /// Creates a new client peer configuration for the given server.
    pub fn new(args: AddArgs, server: &mut Server) -> Result<Self> {
        let clients = Self::scan(&args.server)?;

        let mut builder = Peer::builder();
        builder.allowed_ips(Self::resolve_ip(
            args.address,
            clients
                .iter()
                .flat_map(|c| c.peer.allowed_ips.iter().cloned()),
            &server.interface.address,
        )?);

        if let Some(keepalive) = args.keepalive {
            builder.persistent_keepalive(keepalive);
        }

        let peer = builder.build();
        server.interface.peers.push(peer.clone());

        Ok(Self {
            name: validate_name(args.client, clients.iter().map(|c| &c.name))?,
            created_at: OffsetDateTime::now_utc(),
            server: args.server,
            default_gateway: args.default_gateway,
            dns: if args.no_dns { Some(vec![]) } else { args.dns },
            peer,
        })
    }

    /// Saves the client configuration to a `.toml` file.
    pub fn save(&self) -> Result<()> {
        let path = Path::new(CONF_DIR)
            .join(&self.server)
            .join(&self.name)
            .with_extension("toml");
        secure_write(&path, &toml::to_string_pretty(self)?)?;
        Ok(())
    }

    /// Removes a client and its peer from the server.
    ///
    /// Saves the server before deleting the client file to avoid
    /// data loss on error.
    pub fn rm(server_name: &str, client_name: &str) -> Result<()> {
        let client = Self::load(server_name, client_name)?;
        let mut server = Server::load(server_name)?;
        server.interface.peers.retain(|p| p.key != client.peer.key);
        server.save()?;
        let path = Path::new(CONF_DIR)
            .join(server_name)
            .join(client_name)
            .with_extension("toml");
        fs::remove_file(path)?;
        Ok(())
    }

    /// Generate [`Interface`] from client's [`Peer`] and server's [`Interface`].
    pub fn into_interface(self) -> Result<Interface> {
        let server = Server::load(&self.server)?;
        let mut interface = self.peer.to_interface(
            &server.interface,
            ToInterfaceOptions::new()
                .default_gateway(self.default_gateway)
                .persistent_keepalive(self.peer.persistent_keepalive)
                .strip_server_data(true),
        )?;
        if let Some(dns) = self.dns {
            interface.dns = dns;
        }
        Ok(interface)
    }
}

impl Client {
    /// Loads a client configuration from a TOML file.
    ///
    /// The client name is derived from the file stem (filename without extension).
    fn open(path: &Path, server: &str) -> Result<Self> {
        let mut client: Self = toml::from_str(&fs::read_to_string(path)?)?;
        client.name = path
            .file_stem()
            .and_then(OsStr::to_str)
            .expect("path must have a file name")
            .to_string();
        client.server = server.to_string();
        Ok(client)
    }

    /// Scans the server's client directory for existing client configurations.
    fn scan(server_name: &str) -> Result<Vec<Self>> {
        let dir = Path::new(CONF_DIR).join(server_name);
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let mut clients = Vec::with_capacity(CLIENT_CAPACITY);

        for entry in fs::read_dir(&dir)? {
            let path = match entry {
                Ok(entry) => entry.path(),
                Err(e) => {
                    eprintln!("warning: skipping unreadable entry: {e}");
                    continue;
                }
            };

            if let Some("toml") = path.extension().and_then(OsStr::to_str) {
                match Self::open(&path, server_name) {
                    Ok(client) => clients.push(client),
                    Err(e) => eprintln!("warning: skipping {}: {e}", path.display()),
                }
            }
        }
        Ok(clients)
    }

    /// Resolves client IP addresses: validates user-provided addresses against
    /// existing client and server addresses, or auto-assigns from the server's subnet.
    fn resolve_ip(
        ips: Option<Vec<IpNet>>,
        existing: impl Iterator<Item = IpNet>,
        server_ips: &[IpNet],
    ) -> Result<Vec<IpNet>> {
        let existing: HashSet<IpAddr> = existing
            .map(|n| n.addr())
            .chain(server_ips.iter().map(|n| n.addr()))
            .collect();

        match ips {
            Some(ips) => {
                if let Some(&overlap) = ips.iter().find(|ua| existing.contains(&ua.addr())) {
                    Err(AwgctlError::AddressAlreadyExists(overlap))
                } else {
                    Ok(ips)
                }
            }
            None => {
                let primary = server_ips.first().ok_or(AwgctlError::NoServerAddresses)?;
                primary
                    .hosts()
                    .find(|h| !existing.contains(h))
                    .map(|ip| vec![IpNet::new(ip, primary.prefix_len()).expect("valid IpNet")])
                    .ok_or(AwgctlError::NoAvailableAddress(*primary))
            }
        }
    }
}
