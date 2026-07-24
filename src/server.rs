use crate::cli::NewArgs;
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsStr,
    fs,
    net::{IpAddr, Ipv4Addr},
    path::Path,
};
use thiserror::Error;
use time::{OffsetDateTime, UtcOffset};
use wireguard_conf::{
    ipnet::{self, IpNet},
    prelude::*,
};

const CONF_DIR: &str = "/etc/amnezia/amneziawg/";

#[derive(Debug, Error)]
pub enum AwgctlError {
    #[error("Server '{0}' already exists")]
    ServerAlreadyExists(String),

    #[error(transparent)]
    Sudo(#[from] Box<dyn std::error::Error>),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    NetworkInterface(#[from] network_interface::Error),

    #[error("No available subnet (10.0.X.0/24)")]
    NoAvailableSubnet,

    #[error("Subnet '{0}' already exists")]
    SubnetAlreadyExists(String),

    #[error(transparent)]
    IpNet(#[from] ipnet::PrefixLenError),

    #[error(transparent)]
    TomlDe(#[from] toml::de::Error),

    #[error(transparent)]
    TomlSer(#[from] toml::ser::Error),

    #[error(transparent)]
    Wireguard(#[from] WireguardError),
}

pub type Result<T> = std::result::Result<T, AwgctlError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Server {
    /// Server name.
    #[serde(skip_serializing)]
    pub name: String,

    /// Optional server description.
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,

    /// Server creation date.
    created_at: OffsetDateTime,

    /// Interface configuration.
    pub interface: Interface,
}

impl Server {
    pub fn new(args: NewArgs) -> Result<Self> {
        macro_rules! apply_options {
            ($builder:ident, $args:ident, $($field:ident),+ $(,)?) => {
                $(
                    if let Some(value) = $args.$field {
                        $builder.$field(value);
                    }
                )+
            };
        }
        let mut builder = Interface::builder();
        builder
            .address(Self::resolve_ip(args.address)?)
            .amnezia_settings(AmneziaSettings::random());
        apply_options!(builder, args, listen_port, dns, endpoint, mtu);
        let interface = builder.build();
        let offset = UtcOffset::current_local_offset().expect("failed to get local offset");
        Ok(Self {
            name: Self::resolve_name(args.name)?,
            description: args.desc,
            created_at: OffsetDateTime::now_utc().to_offset(offset),
            interface,
        })
    }

    fn load(path: &Path) -> Result<Self> {
        sudo2::escalate_if_needed()?;
        Ok(toml::from_str(&fs::read_to_string(path)?)?)
    }

    pub fn save(&self) -> Result<()> {
        sudo2::escalate_if_needed()?;
        let conf_path = Path::new(CONF_DIR).join(format!("{}.conf", self.name));
        let toml_path = Path::new(CONF_DIR).join(format!("{}.toml", self.name));
        fs::write(conf_path, self.interface.to_string())?;
        fs::write(toml_path, toml::to_string_pretty(&self)?)?;
        Ok(())
    }

    pub fn resolve_name(name: Option<String>) -> Result<String> {
        sudo2::escalate_if_needed()?;
        match name {
            Some(name) => {
                let path = Path::new(CONF_DIR);
                if path.join(format!("{name}.conf")).exists()
                    || path.join(format!("{name}.toml")).exists()
                {
                    Err(AwgctlError::ServerAlreadyExists(name))
                } else {
                    Ok(name)
                }
            }
            None => Ok(format!(
                "awg{}",
                fs::read_dir(CONF_DIR)?.try_fold(0, |acc, entry| {
                    let path = entry?.path();
                    let num = if matches!(
                        path.extension().and_then(|e| e.to_str()),
                        Some("conf" | "toml")
                    ) {
                        path.file_stem()
                            .and_then(|s| s.to_str())
                            .and_then(|s| s.strip_prefix("awg"))
                            .and_then(|s| s.parse::<u32>().ok())
                    } else {
                        None
                    };
                    Ok::<_, AwgctlError>(num.map_or(acc, |num| acc.max(num + 1)))
                })?
            )),
        }
    }

    pub fn resolve_ip(user_addresses: Option<Vec<IpNet>>) -> Result<Vec<IpNet>> {
        let mut addresses: Vec<IpNet> = NetworkInterface::show()?
            .into_iter()
            .flat_map(|i| i.addr)
            .filter_map(|addr| {
                if let Some(IpAddr::V4(ipv4)) = addr.netmask() {
                    let ip = addr.ip();
                    let bits = u32::from(ipv4);
                    let prefix = bits.count_ones() as u8;
                    IpNet::new(ip, prefix).ok()
                } else {
                    None
                }
            })
            .collect();

        for entry in fs::read_dir(CONF_DIR)? {
            let path = entry?.path();
            if path.extension() == Some(OsStr::new("toml")) {
                let cfg = Self::load(&path)?;
                addresses.extend(cfg.interface.address);
            }
        }

        match user_addresses {
            Some(user_addresses) => {
                if let Some(overlap) = user_addresses
                    .iter()
                    .find(|ua| addresses.iter().any(|ia| Self::overlaps(ua, ia)))
                {
                    Err(AwgctlError::SubnetAlreadyExists(overlap.to_string()))
                } else {
                    Ok(user_addresses)
                }
            }
            None => {
                for subnet in 0..=255 {
                    let candidate = IpNet::new(Ipv4Addr::new(10, 0, subnet, 1).into(), 24)?;
                    if addresses.iter().all(|net| !Self::overlaps(&candidate, net)) {
                        return Ok(vec![candidate]);
                    }
                }
                Err(AwgctlError::NoAvailableSubnet)
            }
        }
    }

    fn overlaps(a: &IpNet, b: &IpNet) -> bool {
        a.contains(b) || b.contains(a)
    }
}
