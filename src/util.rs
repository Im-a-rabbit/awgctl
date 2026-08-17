use qrcode::types::QrError;
use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use thiserror::Error;
use wireguard_conf::{
    ipnet::{self, IpNet},
    prelude::*,
};

/// Directory where awgctl metadata files (`.toml`) are stored.
pub const CONF_DIR: &str = match option_env!("AWGCTL_CONF_DIR") {
    Some(dir) => dir,
    None => "/etc/awgctl",
};

/// Directory where AmneziaWG configuration files are stored.
pub const WG_CONF_DIR: &str = match option_env!("AWG_CONF_DIR") {
    Some(dir) => dir,
    None => "/etc/amnezia/amneziawg",
};

/// Pre-allocated capacity for the server list.
pub const SERVER_CAPACITY: usize = 4;

/// Pre-allocated capacity for the client list per server.
pub const CLIENT_CAPACITY: usize = 8;

/// First two octets of auto-assigned server subnets (10.0.X.0/24).
pub const SUBNET_BASE: (u8, u8) = (10, 0);

/// Prefix length for auto-assigned server subnets.
pub const SUBNET_PREFIX: u8 = 24;

/// Range of ports to try when auto-assigning a listen port.
pub const PORT_RANGE: std::ops::RangeInclusive<u16> = 51820..=51900;

/// Errors that can occur when managing AmneziaWG servers and clients.
#[derive(Debug, Error)]
pub enum AwgctlError {
    // Domain errors
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

    // External error wrappers
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

/// Convenience alias for `Result<T, AwgctlError>`.
pub type Result<T> = std::result::Result<T, AwgctlError>;

/// Validates that a name is non-empty, ASCII alphanumeric (with `-` and `_`),
/// and not already in use.
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

/// Checks if two networks overlap: one contains the other.
pub fn net_overlaps(a: &IpNet, b: &IpNet) -> bool {
    a.contains(b) || b.contains(a)
}

/// Writes `contents` to `path` atomically with `0600` permissions.
///
/// Creates parent directories with `0700` permissions if needed.
/// Writes to a temporary file first, then renames atomically.
/// Cleans up the temporary file on error.
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
