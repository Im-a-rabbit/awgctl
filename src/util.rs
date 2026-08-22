use crate::errors::{AwgctlError, Result};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use std::{
    collections::HashSet,
    fs,
    io::{self, Write},
    net::IpAddr,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use wireguard_conf::ipnet::IpNet;

/// Директория для хранения метаданных awgctl (файлы `.toml`).
pub const CONF_DIR: &str = match option_env!("AWGCTL_CONF_DIR") {
    Some(dir) => dir,
    None => "/etc/awgctl",
};

/// Директория для хранения конфигурационных файлов AmneziaWG.
pub const WG_CONF_DIR: &str = match option_env!("AWG_CONF_DIR") {
    Some(dir) => dir,
    None => "/etc/amnezia/amneziawg",
};

/// Предварительно выделенная ёмкость для списка серверов.
pub const SERVER_CAPACITY: usize = 4;

/// Предварительно выделенная ёмкость для списка клиентов на сервер.
pub const CLIENT_CAPACITY: usize = 8;

/// Первые октет автоматически назначаемых подсетей серверов (10.0.X.0/24).
pub const FIRST_OCT: u8 = 10;
/// Второй октет автоматически назначаемых подсетей серверов (10.0.X.0/24).
pub const SECOND_OCT: u8 = 0;

/// Диапазон портов для попытки автоматического назначения порта прослушивания.
pub const PORT_RANGE: std::ops::RangeInclusive<u16> = 51820..=51900;

pub fn is_valid_dns_entry(entry: &str) -> bool {
    if entry.parse::<IpAddr>().is_ok() {
        return true;
    }
    // упрощённая проверка доменного имени: непустые метки из alphanumeric/дефисов,
    // разделённые точками, не начинающиеся/заканчивающиеся дефисом
    !entry.is_empty()
        && entry.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

pub fn validate_dns(dns: Vec<String>) -> Result<Vec<String>> {
    if let Some(bad) = dns.iter().find(|d| !is_valid_dns_entry(d)) {
        Err(AwgctlError::InvalidDnsEntry(bad.into()))
    } else {
        Ok(dns)
    }
}

/// Проверяет, что имя непустое, ASCII-алфавитно-цифровое (с `-` и `_`),
/// и не используется.
pub fn validate_name<I>(name: String, existing: I) -> Result<String>
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    if name.is_empty()
        || name
            .bytes()
            .any(|c| !c.is_ascii_alphanumeric() && c != b'-' && c != b'_')
    {
        Err(AwgctlError::InvalidName(name))
    } else if existing.into_iter().any(|n| n.as_ref() == name) {
        Err(AwgctlError::NameAlreadyExists(name))
    } else {
        Ok(name)
    }
}

pub fn get_system_addrs() -> Result<Vec<IpNet>> {
    Ok(NetworkInterface::show()?
        .into_iter()
        .flat_map(|i| i.addr)
        .filter_map(|addr| {
            if let Some(IpAddr::V4(ipv4)) = addr.netmask() {
                let prefix = u32::from(ipv4).count_ones() as u8;
                IpNet::new(addr.ip(), prefix).ok()
            } else {
                None
            }
        })
        .collect())
}

pub fn server_validate_ip(
    ips: Vec<IpNet>,
    existing: impl Iterator<Item = IpNet>,
    sys_addrs: &[IpNet],
) -> Result<Vec<IpNet>> {
    let existing: Vec<IpNet> = existing.collect();
    for ua in &ips {
        if let Some(&overlap) = existing
            .iter()
            .find(|&ea| ua.contains(ea) || ea.contains(ua))
        {
            return Err(AwgctlError::SubnetConfigured(overlap));
        }
        if let Some(&overlap) = sys_addrs
            .iter()
            .find(|&ea| ua.contains(ea) || ea.contains(ua))
        {
            return Err(AwgctlError::SubnetInUse(overlap));
        }
    }
    Ok(ips)
}

// PERF: Переписать без bind.
pub fn server_validate_port(port: u16, existing: HashSet<u16>) -> Result<u16> {
    if !existing.contains(&port) && std::net::UdpSocket::bind(("0.0.0.0", port)).is_ok() {
        Ok(port)
    } else if existing.contains(&port) {
        Err(AwgctlError::PortAlreadyConfigured(port))
    } else {
        Err(AwgctlError::PortInUse(port))
    }
}

pub fn client_validate_ip(
    ips: Vec<IpNet>,
    existing: HashSet<IpAddr>,
    server_ips: &[IpNet],
) -> Result<Vec<IpNet>> {
    for ua in &ips {
        if existing.contains(&ua.addr()) {
            return Err(AwgctlError::AddressAlreadyExists(*ua));
        }
        if !server_ips.iter().any(|n| n.contains(ua)) {
            return Err(AwgctlError::AddressOutsideSubnet(*ua));
        }
    }
    Ok(ips)
}

/// Атомарно записывает `contents` в `path` с правами `0600`.
///
/// Создаёт родительские директории с правами `0700` при необходимости.
/// Сначала пишет во временный файл, затем атомарно переименовывает.
/// Удаляет временный файл при ошибке.
pub fn secure_write(path: &Path, contents: &str) -> Result<()> {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() && !parent.exists() => {
            fs::create_dir_all(parent)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
        _ => {}
    }

    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);

    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(tmp);
        return Err(e);
    }

    fs::rename(tmp, path)?;
    Ok(())
}

/// Тип, отображаемый как строка в таблице.
///
/// Реализуется для [`Server`](crate::server::Server) и
/// [`Client`](crate::client::Client).
pub trait Listable {
    /// Заголовки столбцов, зависящие от уровня детализации.
    fn headers(verbose: bool) -> &'static [&'static str];

    /// Значения ячеек для этой строки, зависящие от уровня детализации.
    fn row(&self, verbose: bool) -> Vec<String>;
}

/// Выводит форматированную таблицу с автоматическим расчётом ширины столбцов.
pub fn print_table<I: Listable>(entries: &[I], verbose: bool, msg: &str) {
    if entries.is_empty() {
        println!("{}", msg);
    } else {
        let headers: &[&str] = I::headers(verbose);
        let rows: Vec<Vec<String>> = entries.iter().map(|e| e.row(verbose)).collect();
        let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
        for row in &rows {
            for (w, cell) in widths.iter_mut().zip(row) {
                *w = (*w).max(cell.len());
            }
        }
        let mut out = io::stdout().lock();
        for (h, w) in headers.iter().zip(&widths) {
            write!(out, "{h:<w$}  ").ok();
        }
        writeln!(out).ok();
        for row in &rows {
            for (c, w) in row.iter().zip(&widths) {
                write!(out, "{c:<w$}  ").ok();
            }
            writeln!(out).ok();
        }
    }
}
