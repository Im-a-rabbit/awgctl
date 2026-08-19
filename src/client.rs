use crate::{
    cli::AddArgs,
    server::Server,
    util::{AwgctlError, CLIENT_CAPACITY, CONF_DIR, Listable, Result, secure_write, validate_name},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, ffi::OsStr, fs, net::IpAddr, path::Path};
use time::OffsetDateTime;
use wireguard_conf::{ipnet::IpNet, prelude::*};

/// Клиент AmneziaWG — peer в конфигурации сервера.
///
/// Хранит метаданные (имя, дату создания), DNS-настройки и конфигурацию
/// [`Peer`]. Сериализуется в TOML-файл в [`CONF_DIR`]/<server>/<client>.toml.
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
    /// Загружает конфигурацию клиента по имени из директории клиентов сервера.
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

    /// Создаёт новую конфигурацию peer-клиента для указанного сервера.
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

    /// Сохраняет конфигурацию клиента в TOML-файл.
    pub fn save(&self) -> Result<()> {
        let path = Path::new(CONF_DIR)
            .join(&self.server)
            .join(&self.name)
            .with_extension("toml");
        secure_write(&path, &toml::to_string_pretty(self)?)?;
        Ok(())
    }

    /// Удаляет клиента и его peer из сервера.
    ///
    /// Сохраняет сервер перед удалением файла клиента, чтобы избежать
    /// потери данных при ошибке.
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

    /// Генерирует [`Interface`] из [`Peer`] клиента и [`Interface`] сервера.
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

    /// Возвращает всех клиентов для указанного сервера.
    pub fn list(server_name: &str) -> Result<Vec<Self>> {
        let mut entries = Self::scan(server_name)?;
        entries.sort_by_key(|e| e.created_at);
        Ok(entries)
    }
}

impl Listable for Client {
    fn headers(verbose: bool) -> &'static [&'static str] {
        if verbose {
            &["Name", "Address", "DNS", "Gateway", "Keepalive"]
        } else {
            &["Name", "Address", "DNS", "Gateway"]
        }
    }
    fn row(&self, verbose: bool) -> Vec<String> {
        let mut row = vec![
            self.name.clone(),
            self.peer.allowed_ips.iter().map(|a| a.to_string()).fold(
                String::new(),
                |mut acc, s| {
                    if !acc.is_empty() {
                        acc.push_str(", ");
                    }
                    acc.push_str(&s);
                    acc
                },
            ),
            match &self.dns {
                Some(dns) if !dns.is_empty() => dns.join(", "),
                Some(_) => "—".into(),
                None => "Inherit".into(),
            },
            if self.default_gateway { "yes" } else { "no" }.into(),
        ];
        if verbose {
            row.push(if self.peer.persistent_keepalive == 0 {
                "no".into()
            } else {
                self.peer.persistent_keepalive.to_string()
            });
        }
        row
    }
}

impl Client {
    /// Загружает конфигурацию клиента из TOML-файла.
    ///
    /// Имя клиента определяется из имени файла без расширения.
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

    /// Сканирует директорию клиентов сервера на наличие существующих конфигураций.
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

    /// Определяет IP-адреса клиента: проверяет указанные пользователем адреса
    /// на пересечение с существующими адресами клиентов и сервера
    /// на вхождение в подсеть сервера,
    /// или автоматически назначает из подсети сервера.
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
                } else if let Some(&bad) = ips
                    .iter()
                    .find(|&ua| !server_ips.iter().any(|n| n.contains(ua)))
                {
                    Err(AwgctlError::AddressOutsideSubnet(bad))
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
