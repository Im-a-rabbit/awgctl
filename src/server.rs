use crate::{
    cli::NewArgs,
    util::{
        AwgctlError, CONF_DIR, Listable, PORT_RANGE, Result, SERVER_CAPACITY, SUBNET_BASE,
        WG_CONF_DIR, get_system_addrs, secure_write, validate_ip, validate_name,
    },
};
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

/// AmneziaWG-сервер.
///
/// Хранит метаданные (имя, дату создания) и конфигурацию интерфейса.
/// Сериализуется в TOML-файл в [`CONF_DIR`] и в `.conf` в [`WG_CONF_DIR`].
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
    /// Загружает конфигурацию сервера по имени из [`CONF_DIR`].
    pub fn load(name: &str) -> Result<Self> {
        let server_path = Path::new(CONF_DIR).join(name).with_extension("toml");
        if server_path.exists() {
            Self::open(&server_path)
        } else {
            Err(AwgctlError::ServerNotFound(name.into()))
        }
    }

    /// Создаёт новый сервер с автоматически определённой или указанной пользователем конфигурацией.
    pub fn new(args: NewArgs) -> Result<Self> {
        let (servers, used_names) = Self::scan()?;
        let sys_addrs: Vec<IpNet> = get_system_addrs()?;
        let used_addrs = servers
            .iter()
            .flat_map(|s| s.interface.address.iter().copied())
            .chain(sys_addrs.iter().copied());
        let used_ports: HashSet<u16> = servers
            .iter()
            .filter_map(|s| s.interface.listen_port)
            .collect();

        let mut builder = Interface::builder();
        builder
            .address(Self::resolve_ip(args.address, used_addrs)?)
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

    /// Атомарно сохраняет конфигурацию сервера в файлы `.toml` и `.conf`.
    pub fn save(&self) -> Result<()> {
        let toml_path = Path::new(CONF_DIR).join(&self.name).with_extension("toml");
        let conf_path = Path::new(WG_CONF_DIR)
            .join(&self.name)
            .with_extension("conf");
        secure_write(&toml_path, &toml::to_string_pretty(self)?)?;
        secure_write(&conf_path, &self.interface.to_string())?;
        Ok(())
    }

    /// Удаляет сервер и его конфигурационные файлы.
    ///
    /// Удаляет метаданные `.toml`, конфигурацию WireGuard `.conf`
    /// и директорию клиентов, если она существует.
    pub fn rm(name: &str) -> Result<()> {
        let base = Path::new(CONF_DIR).join(name);
        let toml_path = base.with_extension("toml");
        if toml_path.exists() {
            fs::remove_file(toml_path)?;
            let conf_path = Path::new(WG_CONF_DIR).join(name).with_extension("conf");
            let _ = fs::remove_file(conf_path);
            if base.is_dir() {
                fs::remove_dir_all(base)?;
            }
            Ok(())
        } else {
            Err(AwgctlError::ServerNotFound(name.into()))
        }
    }

    /// Возвращает все серверы, найденные в [`CONF_DIR`].
    pub fn list() -> Result<Vec<Self>> {
        let mut entries = Self::scan()?.0;
        entries.sort_by_key(|e| e.created_at);
        Ok(entries)
    }
}

impl Listable for Server {
    fn headers(verbose: bool) -> &'static [&'static str] {
        if verbose {
            &["Name", "Address", "Endpoint", "DNS", "MTU"]
        } else {
            &["Name", "Address", "DNS"]
        }
    }

    fn row(&self, verbose: bool) -> Vec<String> {
        let address = self.interface.address.iter().map(|a| a.to_string()).fold(
            String::new(),
            |mut acc, s| {
                if !acc.is_empty() {
                    acc.push_str(", ");
                }
                acc.push_str(&s);
                acc
            },
        );
        let dns = if self.interface.dns.is_empty() {
            "—".into()
        } else {
            self.interface.dns.join(", ")
        };
        if verbose {
            vec![
                self.name.clone(),
                address,
                self.interface.endpoint.as_deref().unwrap_or("—").into(),
                dns,
                self.interface.mtu.map_or("—".into(), |m| m.to_string()),
            ]
        } else {
            vec![self.name.clone(), address, dns]
        }
    }
}

impl Server {
    /// Загружает конфигурацию сервера из TOML-файла.
    ///
    /// Имя сервера определяется из имени файла без расширения.
    fn open(path: &Path) -> Result<Self> {
        let mut server: Self = toml::from_str(&fs::read_to_string(path)?)?;
        server.name = path
            .file_stem()
            .and_then(OsStr::to_str)
            .expect("path must have a file name")
            .to_string();
        Ok(server)
    }

    /// Сканирует директорию конфигураций на наличие серверов и их имён.
    ///
    /// Возвращает список загруженных серверов и множество всех известных имён
    /// (из файлов `.toml` и `.conf`). Некорректные `.toml`-файлы
    /// пропускаются с предупреждением в stderr.
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

    /// Определяет имя сервера: проверяет указанное пользователем имя или
    /// автоматически генерирует следующее доступное имя `awgN`.
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

    /// Определяет IP-адреса сервера: проверяет указанные пользователем подсети
    /// на пересечение с системными и существующими адресами серверов
    /// или автоматически назначает из диапазона, определяемого
    /// [`SUBNET_BASE`] (по умолчанию `10.0.X.0/24`).
    fn resolve_ip(
        ips: Option<Vec<IpNet>>,
        existing: impl Iterator<Item = IpNet>,
    ) -> Result<Vec<IpNet>> {
        /// Длина префикса для автоматически назначаемых подсетей серверов.
        ///
        /// ВАЖНО: жёстко зафиксирован на /24. Логика `resolve_ip`
        /// завязана на это значение (один кандидат = один третий октет
        /// SUBNET_BASE.0.SUBNET_BASE.1.X.0/24).
        const SUBNET_PREFIX: u8 = 24;

        match ips {
            Some(ips) => validate_ip(ips, existing),
            None => {
                let pool_start: u32 = Ipv4Addr::new(SUBNET_BASE.0, SUBNET_BASE.1, 0, 0).into();
                let pool_end: u32 = Ipv4Addr::new(SUBNET_BASE.0, SUBNET_BASE.1, 255, 255).into();

                let mut blocked = [false; 256];
                for net in existing {
                    let IpNet::V4(v4) = net else { continue };
                    let net_start: u32 = v4.network().into();
                    let net_end: u32 = v4.broadcast().into();

                    if net_end < pool_start || net_start > pool_end {
                        continue;
                    }

                    let lo = net_start.max(pool_start);
                    let hi = net_end.min(pool_end);
                    let first = ((lo - pool_start) >> 8) as u8;
                    let last = ((hi - pool_start) >> 8) as u8;

                    for subnet in first..=last {
                        blocked[subnet as usize] = true;
                    }
                }

                blocked
                    .iter()
                    .position(|is_blocked| !is_blocked)
                    .map(|subnet| {
                        IpNet::new(
                            Ipv4Addr::new(SUBNET_BASE.0, SUBNET_BASE.1, subnet as u8, 1).into(),
                            SUBNET_PREFIX,
                        )
                        .expect("valid subnet")
                    })
                    .map(|net| vec![net])
                    .ok_or(AwgctlError::NoAvailableSubnet)
            }
        }
    }

    /// Определяет порт прослушивания: проверяет указанный пользователем порт или
    /// находит первый доступный порт в [`PORT_RANGE`]. Проверяет как конфигурацию, так и системную доступность.
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

    /// Определяет публичный эндпоинт: использует указанное значение или
    /// определяет автоматически через `checkip.amazonaws.com`. Проверяет, что результат совпадает с локальным интерфейсом.
    // TODO: Возможно переписать
    fn resolve_endpoint(endpoint: Option<String>, sys_addrs: &[IpNet]) -> Result<String> {
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
                if sys_addrs.iter().any(|addr| addr.addr() == parsed_ip) {
                    Ok(external_ip)
                } else {
                    Err(AwgctlError::EndpointResolutionFailed)
                }
            }
        }
    }
}
