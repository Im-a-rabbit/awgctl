use crate::{
    commands::AddArgs,
    errors::{AwgctlError, Result},
    server::Server,
    util::{
        CLIENT_CAPACITY, CONF_DIR, Listable, client_validate_ip, is_valid_dns_entry, secure_write,
        validate_dns, validate_name,
    },
};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, ffi::OsStr, fs, io, net::IpAddr, path::Path};
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
    /// Создаёт новую конфигурацию peer-клиента для указанного сервера.
    pub fn new(args: AddArgs, server: &mut Server) -> Result<Self> {
        let clients = Self::scan(&args.server)?;

        let name = validate_name(args.client, clients.iter().map(|c| &c.name))?;
        let dns = if args.no_dns {
            Some(vec![])
        } else {
            args.dns.map(validate_dns).transpose()?
        };

        let mut peer = Peer::builder()
            .allowed_ips(Self::resolve_ip(
                args.address,
                clients.iter().flat_map(|c| &c.peer.allowed_ips),
                &server.interface.address,
            )?)
            .build();
        peer.persistent_keepalive = args.keepalive.unwrap_or(0);

        server.interface.peers.push(peer.clone());

        Ok(Self {
            name,
            created_at: OffsetDateTime::now_utc(),
            server: args.server,
            default_gateway: args.default_gateway,
            dns,
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

    /// Загружает конфигурацию клиента по имени из директории клиентов сервера.
    pub fn load(server_name: &str, client_name: &str) -> Result<Self> {
        let path = Path::new(CONF_DIR)
            .join(server_name)
            .join(client_name)
            .with_extension("toml");
        match Self::open(&path, server_name) {
            Ok(c) => Ok(c),
            Err(AwgctlError::Io(e)) if e.kind() == io::ErrorKind::NotFound => {
                Err(AwgctlError::ClientNotFound(client_name.into()))
            }
            Err(e) => Err(e),
        }
    }

    /// Удаляет клиента и его peer из сервера.
    // TODO: подумать над порядком операций
    pub fn rm(server_name: &str, client_name: &str) -> Result<()> {
        let client = Self::load(server_name, client_name)?;

        let path = Path::new(CONF_DIR)
            .join(server_name)
            .join(client_name)
            .with_extension("toml");
        fs::remove_file(path)?;

        let mut server = Server::load(server_name)?;
        server.interface.peers.retain(|p| p.key != client.peer.key);
        server.save()?;

        Ok(())
    }

    /// Генерирует [`Interface`] из [`Peer`] клиента и [`Interface`] сервера.
    pub fn into_interface(self) -> Result<Interface> {
        let server = Server::load(&self.server)?;

        if let Some(&bad) = self
            .peer
            .allowed_ips
            .iter()
            .find(|&ip| !server.interface.address.iter().any(|n| n.contains(ip)))
        {
            return Err(AwgctlError::AddressOutsideSubnet(bad));
        }

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
            self.peer
                .allowed_ips
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            match &self.dns {
                Some(dns) if !dns.is_empty() => dns.join(", "),
                Some(_) => "—".into(),
                None => "Inherit".into(),
            },
            if self.default_gateway { "Yes" } else { "No" }.into(),
        ];
        if verbose {
            row.push(if self.peer.persistent_keepalive == 0 {
                "No".into()
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

        if client.peer.allowed_ips.is_empty() {
            return Err(AwgctlError::ClientInvalid("no allowed ips"));
        }
        if let Some(dns) = &client.dns
            && let Some(bad) = dns.iter().find(|d| !is_valid_dns_entry(d))
        {
            return Err(AwgctlError::InvalidDnsEntry(bad.into()));
        }

        Ok(client)
    }

    /// Сканирует директорию клиентов сервера на наличие существующих конфигураций.
    fn scan(server_name: &str) -> Result<Vec<Self>> {
        let dir = Path::new(CONF_DIR).join(server_name);
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };

        let mut clients = Vec::with_capacity(CLIENT_CAPACITY);

        for entry in entries {
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
    fn resolve_ip<'a>(
        ips: Vec<IpNet>,
        existing: impl Iterator<Item = &'a IpNet>,
        server_ips: &'a [IpNet],
    ) -> Result<Vec<IpNet>> {
        let existing: HashSet<IpAddr> = existing.chain(server_ips).map(|n| n.addr()).collect();

        if !ips.is_empty() {
            client_validate_ip(ips, existing, server_ips)
        } else {
            let primary = server_ips.first().expect("server address");
            primary
                .hosts()
                .find(|h| !existing.contains(h))
                .map(|ip| vec![IpNet::new(ip, primary.prefix_len()).expect("valid IpNet")])
                .ok_or(AwgctlError::NoAvailableAddress(*primary))
        }
    }
}
