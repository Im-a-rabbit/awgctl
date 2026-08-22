use crate::util::{FIRST_OCT, PORT_RANGE, SECOND_OCT};
use qrcode::types::QrError;
use thiserror::Error;
use wireguard_conf::{
    WireguardError,
    ipnet::{IpNet, PrefixLenError},
};

/// Удобный псевдоним для `Result<T, AwgctlError>`.
pub type Result<T> = std::result::Result<T, AwgctlError>;

/// Ошибки, которые могут возникнуть при управлении серверами и клиентами AmneziaWG.
#[derive(Debug, Error)]
pub enum AwgctlError {
    #[error("Invalid name '{0}': only alphanumeric, '-' and '_' allowed")]
    InvalidName(String),
    #[error("Name '{0}' already exists")]
    NameAlreadyExists(String),

    #[error("DNS entry '{0}' is invalid")]
    InvalidDnsEntry(String),

    // Ошибки [`Server`](crate::server::Server)
    #[error("Server is invalid: {0}")]
    ServerInvalid(&'static str),

    #[error("No available subnet ({FIRST_OCT}.{SECOND_OCT}.X.0/24)")]
    NoAvailableSubnet,
    #[error("Subnet '{0}' used by other awg-conf")]
    SubnetConfigured(IpNet),
    #[error("Subnet '{0}' in system use")]
    SubnetInUse(IpNet),

    #[error("No available port ({}..={})", PORT_RANGE.start(), PORT_RANGE.end())]
    NoAvailablePort,
    #[error("Port '{0}' used by other awg-conf")]
    PortAlreadyConfigured(u16),
    #[error("Port '{0}' in system use")]
    PortInUse(u16),

    #[error("Could not auto-detect a public endpoint, pass --endpoint explicitly")]
    EndpointResolutionFailed,
    #[error("Empty endpoint")]
    EmptyEndpoint,

    #[error("Server '{0}' not found")]
    ServerNotFound(String),

    // Ошибки [`Client`](crate::client::Client)
    #[error("Client is invalid: {0}")]
    ClientInvalid(&'static str),

    #[error("No available address in subnet '{0}'")]
    NoAvailableAddress(IpNet),
    #[error("Address '{0}' already exists")]
    AddressAlreadyExists(IpNet),
    #[error("Address '{0}' is outside the server's subnet")]
    AddressOutsideSubnet(IpNet),

    #[error("Client '{0}' not found")]
    ClientNotFound(String),

    // Обёртки внешних ошибок
    #[error(transparent)]
    // FIX: слишком широкое определение
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
    IpNet(#[from] PrefixLenError),
    #[error(transparent)]
    Qr(#[from] QrError),
}
