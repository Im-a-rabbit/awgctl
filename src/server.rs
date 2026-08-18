use crate::{cli::NewArgs, util::*};
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    ffi::OsStr,
    fs,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, TcpStream, ToSocketAddrs},
    path::Path,
    time::Duration,
};
use time::OffsetDateTime;
use wireguard_conf::{ipnet::IpNet, prelude::*};

#[derive(Debug, Serialize, Deserialize)]
pub struct Server {
    /// Server name.
    #[serde(skip)]
    pub name: String,

    /// Server creation date.
    pub created_at: OffsetDateTime,

    /// Interface configuration.
    pub interface: Interface,
}

impl Server {
    /// Loads a server configuration from a TOML file.
    ///
    /// The server name is derived from the file stem (filename without extension).
    fn open(path: &Path) -> Result<Self> {
        let mut server: Self = toml::from_str(&fs::read_to_string(path)?)?;
        server.name = path
            .file_stem()
            .and_then(OsStr::to_str)
            .expect("path must have a file name")
            .to_string();
        Ok(server)
    }

    /// Scans the configuration directory for servers and their names.
    ///
    /// Returns a list of loaded servers and a set of all known names
    /// (from both `.toml` and `.conf` files). Invalid `.toml` files are
    /// skipped with a warning on stderr.
    fn scan() -> Result<(Vec<Self>, HashSet<String>)> {
        let mut servers = Vec::with_capacity(SERVER_CAPACITY);
        let mut names = HashSet::with_capacity(SERVER_CAPACITY);

        let conf_dir = Path::new(CONF_DIR);
        let wg_dir = Path::new(WG_CONF_DIR);
        if conf_dir.exists() && wg_dir.exists() {
            for entry in fs::read_dir(conf_dir)?.chain(fs::read_dir(wg_dir)?) {
                let path = match entry {
                    Ok(entry) => entry.path(),
                    Err(e) => {
                        eprintln!("warning: skipping unreadable entry: {e}");
                        continue;
                    }
                };

                match path.extension().and_then(OsStr::to_str) {
                    Some("toml") => match Self::open(&path) {
                        Ok(server) => {
                            names.insert(server.name.clone());
                            servers.push(server);
                        }
                        Err(e) => eprintln!("warning: skipping {}: {e}", path.display()),
                    },
                    Some("conf") => {
                        if let Some(stem) = path.file_stem().and_then(OsStr::to_str) {
                            names.insert(stem.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok((servers, names))
    }

    /// Resolves a server name: validates user-provided name or auto-generates
    /// the next available `awgN` name.
    fn resolve_name(name: Option<String>, existing: HashSet<String>) -> Result<String> {
        match name {
            Some(name) => validate_name(name, existing),
            None => {
                let next = existing
                    .iter()
                    .filter_map(|name| name.strip_prefix("awg")?.parse::<u32>().ok())
                    .max()
                    .map_or(0, |n| n + 1);
                Ok(format!("awg{next}"))
            }
        }
    }

    /// Resolves server IP addresses: validates user-provided subnets against
    /// system and existing server addresses,
    /// or auto-assigns from `{SUBNET_BASE.0}.{SUBNET_BASE.1}.X.0/{SUBNET_PREFIX}`.
    fn resolve_ip(
        ips: Option<Vec<IpNet>>,
        existing: impl Iterator<Item = IpNet>,
        sys_used: &[Addr],
    ) -> Result<Vec<IpNet>> {
        let existing: Vec<IpNet> = sys_used
            .iter()
            .filter_map(|addr| {
                if let Some(IpAddr::V4(ipv4)) = addr.netmask() {
                    let prefix = u32::from(ipv4).count_ones() as u8;
                    IpNet::new(addr.ip(), prefix).ok()
                } else {
                    None
                }
            })
            .chain(existing)
            .collect();

        match ips {
            Some(ips) => {
                if let Some(&overlap) = ips
                    .iter()
                    .find(|&ua| existing.iter().any(|ea| net_overlaps(ua, ea)))
                {
                    Err(AwgctlError::SubnetAlreadyExists(overlap))
                } else {
                    Ok(ips)
                }
            }
            None => {
                for subnet in 0..=255u8 {
                    let candidate = IpNet::new(
                        Ipv4Addr::new(SUBNET_BASE.0, SUBNET_BASE.1, subnet, 1).into(),
                        SUBNET_PREFIX,
                    )
                    .expect("valid subnet");

                    if existing.iter().all(|net| !net_overlaps(&candidate, net)) {
                        return Ok(vec![candidate]);
                    }
                }
                Err(AwgctlError::NoAvailableSubnet)
            }
        }
    }

    /// Resolves a listen port: validates user-provided port or finds the first
    /// available port in `PORT_RANGE`. Checks both configuration and system availability.
    fn resolve_port(port: Option<u16>, existing: HashSet<u16>) -> Result<u16> {
        match port {
            Some(port) => {
                if !existing.contains(&port) && std::net::UdpSocket::bind(("0.0.0.0", port)).is_ok()
                {
                    Ok(port)
                } else if existing.contains(&port) {
                    Err(AwgctlError::PortAlreadyConfigured(port))
                } else {
                    Err(AwgctlError::PortInUse(port))
                }
            }
            None => PORT_RANGE
                .into_iter()
                .find(|port| {
                    !existing.contains(port)
                    // TODO: избавиться от bind.
                        && std::net::UdpSocket::bind(("0.0.0.0", *port)).is_ok()
                })
                .ok_or(AwgctlError::NoAvailablePort),
        }
    }

    // TODO: Возможно переписать

    /// Resolves the public endpoint: uses user-provided value or auto-detects
    /// via `checkip.amazonaws.com`. Verifies the result matches a local interface.
    fn resolve_endpoint(endpoint: Option<String>, sys_addrs: &[Addr]) -> Result<String> {
        match endpoint {
            Some(endpoint) => Ok(endpoint),
            None => {
                let addr = ("checkip.amazonaws.com", 80)
                    .to_socket_addrs()?
                    .next()
                    .ok_or(AwgctlError::EndpointResolutionFailed)?;
                let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
                stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                stream.write_all(
                    b"GET / HTTP/1.1\r\nHost: checkip.amazonaws.com\r\nConnection: close\r\n\r\n",
                )?;
                let mut response = String::with_capacity(256);
                stream.read_to_string(&mut response)?;
                let external_ip = response
                    .split_once("\r\n\r\n")
                    .map(|(_, body)| body.trim().to_string())
                    .filter(|ip| !ip.is_empty())
                    .ok_or(AwgctlError::EndpointResolutionFailed)?;
                let parsed_ip: IpAddr = external_ip
                    .parse()
                    .map_err(|_| AwgctlError::EndpointResolutionFailed)?;
                if sys_addrs.iter().any(|addr| addr.ip() == parsed_ip) {
                    Ok(external_ip)
                } else {
                    Err(AwgctlError::EndpointResolutionFailed)
                }
            }
        }
    }
}

impl Server {
    /// Loads a server configuration by name from `CONF_DIR`.
    pub fn load(name: &str) -> Result<Self> {
        let server_path = Path::new(CONF_DIR).join(name).with_extension("toml");
        if server_path.exists() {
            Self::open(&server_path)
        } else {
            Err(AwgctlError::ServerNotFound(name.into()))
        }
    }

    /// Creates a new server with auto-resolved or user-provided configuration.
    pub fn new(args: NewArgs) -> Result<Self> {
        let (servers, used_names) = Self::scan()?;
        let used_addresses = servers
            .iter()
            .flat_map(|s| s.interface.address.iter().cloned());
        let sys_addrs: Vec<Addr> = NetworkInterface::show()?
            .into_iter()
            .flat_map(|i| i.addr.clone())
            .collect();
        let used_ports: HashSet<u16> = servers
            .iter()
            .filter_map(|s| s.interface.listen_port)
            .collect();

        let mut builder = Interface::builder();
        builder
            .address(Self::resolve_ip(args.address, used_addresses, &sys_addrs)?)
            .listen_port(Self::resolve_port(args.listen_port, used_ports)?)
            .endpoint(Self::resolve_endpoint(args.endpoint, &sys_addrs)?)
            // TODO: Возможно добавить обработку awgs из new. Либо через set.
            .amnezia_settings(AmneziaWG::random_v2());

        if let Some(dns) = args.dns {
            builder.dns(dns);
        }
        if let Some(mtu) = args.mtu {
            builder.mtu(mtu);
        }

        Ok(Self {
            name: Self::resolve_name(args.name, used_names)?,
            created_at: OffsetDateTime::now_utc(),
            interface: builder.build(),
        })
    }

    /// Saves the server configuration to `.toml` and `.conf` files atomically.
    pub fn save(&self) -> Result<()> {
        let toml_path = Path::new(CONF_DIR).join(&self.name).with_extension("toml");
        let conf_path = Path::new(WG_CONF_DIR)
            .join(&self.name)
            .with_extension("conf");
        secure_write(&toml_path, &toml::to_string_pretty(self)?)?;
        secure_write(&conf_path, &self.interface.to_string())?;
        Ok(())
    }

    /// Removes a server and its configuration files.
    ///
    /// Deletes the `.toml` metadata, `.conf` WireGuard config,
    /// and the client directory if it exists.
    pub fn rm(name: &str) -> Result<()> {
        let toml_path = Path::new(CONF_DIR).join(name).with_extension("toml");
        if toml_path.exists() {
            fs::remove_file(toml_path)?;
            let conf_path = Path::new(WG_CONF_DIR).join(name).with_extension("conf");
            let _ = fs::remove_file(conf_path);
            let client_dir = Path::new(CONF_DIR).join(name);
            if client_dir.is_dir() {
                fs::remove_dir_all(client_dir)?;
            }
            Ok(())
        } else {
            Err(AwgctlError::ServerNotFound(name.into()))
        }
    }
}
