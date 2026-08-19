use qrcode::types::QrError;
use std::{
    fs, io,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use thiserror::Error;
use wireguard_conf::{
    ipnet::{self, IpNet},
    prelude::*,
};

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

/// Первые два октета автоматически назначаемых подсетей серверов (10.0.X.0/24).
pub const SUBNET_BASE: (u8, u8) = (10, 0);

/// Длина префикса для автоматически назначаемых подсетей серверов.
pub const SUBNET_PREFIX: u8 = 24;

/// Диапазон портов для попытки автоматического назначения порта прослушивания.
pub const PORT_RANGE: std::ops::RangeInclusive<u16> = 51820..=51900;

/// Ошибки, которые могут возникнуть при управлении серверами и клиентами AmneziaWG.
#[derive(Debug, Error)]
pub enum AwgctlError {
    // Ошибки домена
    #[error("Invalid name '{0}': only alphanumeric, '-' and '_' allowed")]
    InvalidName(String),

    #[error("Name '{0}' already exists")]
    NameAlreadyExists(String),

    #[error("Subnet '{0}' already exists")]
    SubnetAlreadyExists(IpNet),

    #[error("No available subnet (10.0.X.0/24)")]
    NoAvailableSubnet,

    #[error("Address '{0}' already exists")]
    AddressAlreadyExists(IpNet),

    #[error("Address '{0}' is outside the server's subnet")]
    AddressOutsideSubnet(IpNet),

    #[error("Server has no configured addresses")]
    NoServerAddresses,

    #[error("No available address in subnet '{0}'")]
    NoAvailableAddress(IpNet),

    #[error("Port '{0}' already configured")]
    PortAlreadyConfigured(u16),

    #[error("Port '{0}' is already in use by another service")]
    PortInUse(u16),

    #[error("No available port ({}..={})", PORT_RANGE.start(), PORT_RANGE.end())]
    NoAvailablePort,

    #[error("Could not auto-detect a public endpoint, pass --endpoint explicitly")]
    EndpointResolutionFailed,

    #[error("Server '{0}' not found")]
    ServerNotFound(String),

    #[error("Client '{0}' not found")]
    ClientNotFound(String),

    // Обёртки внешних ошибок
    #[error(transparent)]
    Sudo(#[from] Box<dyn std::error::Error>),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    TomlDe(#[from] toml::de::Error),

    #[error(transparent)]
    TomlSer(#[from] toml::ser::Error),

    #[error(transparent)]
    Wireguard(#[from] WireguardError),

    #[error(transparent)]
    NetworkInterface(#[from] network_interface::Error),

    #[error(transparent)]
    IpNet(#[from] ipnet::PrefixLenError),

    #[error(transparent)]
    Qr(#[from] QrError),
}

/// Удобный псевдоним для `Result<T, AwgctlError>`.
pub type Result<T> = std::result::Result<T, AwgctlError>;

/// Проверяет, что имя непустое, ASCII-алфавитно-цифровое (с `-` и `_`),
/// и не используется.
pub fn validate_name<I>(name: String, existing: I) -> Result<String>
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    if !name.is_empty()
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        if existing.into_iter().any(|n| n.as_ref() == name) {
            Err(AwgctlError::NameAlreadyExists(name))
        } else {
            Ok(name)
        }
    } else {
        Err(AwgctlError::InvalidName(name))
    }
}

/// Проверяет, пересекаются ли две сети: одна содержит другую.
pub fn net_overlaps(a: &IpNet, b: &IpNet) -> bool {
    a.contains(b) || b.contains(a)
}

/// Атомарно записывает `contents` в `path` с правами `0600`.
///
/// Создаёт родительские директории с правами `0700` при необходимости.
/// Сначала пишет во временный файл, затем атомарно переименовывает.
/// Удаляет временный файл при ошибке.
pub fn secure_write(path: &Path, contents: &str) -> Result<()> {
    let path = match path.parent() {
        Some(p) if p == Path::new("") => &Path::new(".").join(path),
        Some(parent) => {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            }
            path
        }
        None => path,
    };

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
        let mut out = io::stdout().lock();
        let headers: &[&str] = I::headers(verbose);
        let rows: Vec<Vec<String>> = entries.iter().map(|e| e.row(verbose)).collect();
        let widths: Vec<usize> = (0..headers.len())
            .map(|i| {
                headers[i]
                    .len()
                    .max(rows.iter().map(|r| r[i].len()).max().unwrap_or(0))
            })
            .collect();
        for (i, h) in headers.iter().enumerate() {
            write!(out, "{:<width$}  ", h, width = widths[i]).ok();
        }
        writeln!(out).ok();
        for row in &rows {
            for (i, cell) in row.iter().enumerate() {
                write!(out, "{:<width$}  ", cell, width = widths[i]).ok();
            }
            writeln!(out).ok();
        }
    }
}
