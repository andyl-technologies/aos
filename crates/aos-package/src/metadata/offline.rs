//! Offline-channel [`PlatformFetcher`] implementations.
//!
//! Every offline channel resolves to a mounted directory under
//! `/run/aos-metadata` produced by `detect`'s config-drive mount helper (or
//! the qemu `fw_cfg` sysfs tree). The fetcher reads files from that directory
//! with `std::fs` — no network — so each is unit-testable against a fixture
//! directory with no root.
//!
//! Channels:
//!
//! - [`AosMetadataFetcher`] — the AOS-native `aos-metadata` ISO:
//!   `provisioning.json` or literal `host.nix`, optional `provisioning.sig`,
//!   and optional pre-baked `facts.json`.
//! - [`NoCloudFetcher`] — NoCloud `cidata`: `user-data` is the literal
//!   `host.nix`; `meta-data` (YAML) + `network-config` (netplan) feed facts.
//! - [`ConfigDriveFetcher`] — OpenStack `config-2`:
//!   `openstack/latest/user_data` + `meta_data.json` + `network_data.json`.
//! - [`QemuFwCfgFetcher`] — qemu `fw_cfg`: reads the provisioning blob from
//!   `/sys/firmware/qemu_fw_cfg/by_name/<name>/raw`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

use super::fetcher::{Facts, PlatformFetcher, UserData};
use super::http::MetadataHttp;
use super::staticnet;

/// Read a file to bytes, mapping "not found" to `None` and other errors to
/// `Err`.
fn read_opt(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Read a file to a UTF-8 string, trimming trailing whitespace, mapping "not
/// found" to `None`.
fn read_opt_string(path: &Path) -> Result<Option<String>> {
    Ok(read_opt(path)?.and_then(|b| String::from_utf8(b).ok().map(|s| s.trim().to_string())))
}

// ---------------------------------------------------------------------------
// aos-metadata ISO
// ---------------------------------------------------------------------------

/// The AOS-native `aos-metadata` ISO channel.
pub struct AosMetadataFetcher {
    dir: PathBuf,
}

impl AosMetadataFetcher {
    /// Read from the mounted `aos-metadata` directory (`METADATA_DIR`).
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }
}

#[async_trait::async_trait]
impl PlatformFetcher for AosMetadataFetcher {
    fn platform_id(&self) -> &'static str {
        "aos-metadata"
    }

    async fn fetch_user_data(&self, _http: &dyn MetadataHttp) -> Result<Option<UserData>> {
        let payload = match read_opt(&self.dir.join("provisioning.json"))? {
            Some(bytes) => bytes,
            None => {
                let Some(bytes) = read_opt(&self.dir.join("host.nix"))? else {
                    return Ok(None);
                };
                bytes
            }
        };
        let sig = read_opt_string(&self.dir.join("provisioning.sig"))?;
        Ok(Some(UserData::Inline { payload, sig }))
    }

    async fn fetch_facts(&self, _http: &dyn MetadataHttp) -> Result<Facts> {
        match read_opt(&self.dir.join("facts.json"))? {
            Some(bytes) => serde_json::from_slice(&bytes).context("parsing pre-baked facts.json"),
            None => Ok(Facts::default()),
        }
    }
}

// ---------------------------------------------------------------------------
// NoCloud cidata
// ---------------------------------------------------------------------------

/// The NoCloud `cidata` channel (ISO9660 or vfat).
pub struct NoCloudFetcher {
    dir: PathBuf,
}

impl NoCloudFetcher {
    /// Read from the mounted `cidata` directory.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }
}

/// NoCloud `meta-data` (a small YAML map).
#[derive(Debug, Deserialize)]
struct NoCloudMeta {
    #[serde(default, rename = "local-hostname")]
    local_hostname: Option<String>,
    #[serde(default, rename = "instance-id")]
    instance_id: Option<String>,
}

#[async_trait::async_trait]
impl PlatformFetcher for NoCloudFetcher {
    fn platform_id(&self) -> &'static str {
        "nocloud"
    }

    async fn fetch_user_data(&self, _http: &dyn MetadataHttp) -> Result<Option<UserData>> {
        // AOS treats the NoCloud `user-data` body as the literal host.nix; a
        // leading `#cloud-config`/`#!` is NOT interpreted.
        let Some(host_nix) = read_opt(&self.dir.join("user-data"))? else {
            return Ok(None);
        };
        let sig = read_opt_string(&self.dir.join("user-data.sig"))?;
        Ok(Some(UserData::Inline {
            payload: host_nix,
            sig,
        }))
    }

    async fn fetch_facts(&self, _http: &dyn MetadataHttp) -> Result<Facts> {
        let mut facts = Facts::default();
        if let Some(bytes) = read_opt(&self.dir.join("meta-data"))? {
            let meta: NoCloudMeta =
                serde_yaml::from_slice(&bytes).context("parsing NoCloud meta-data")?;
            facts.hostname = meta.local_hostname;
            facts.instance_id = meta.instance_id;
        }
        if let Some(bytes) = read_opt(&self.dir.join("network-config"))? {
            let net = staticnet::parse_netplan_network_config(&bytes)?;
            if net.is_seedable() {
                facts.network = Some(net);
            }
        }
        Ok(facts)
    }
}

// ---------------------------------------------------------------------------
// OpenStack config-2
// ---------------------------------------------------------------------------

/// The OpenStack `config-2` config-drive channel.
pub struct ConfigDriveFetcher {
    dir: PathBuf,
}

impl ConfigDriveFetcher {
    /// Read from the mounted `config-2` directory.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn openstack_dir(&self) -> PathBuf {
        self.dir.join("openstack").join("latest")
    }
}

/// OpenStack `meta_data.json`.
#[derive(Debug, Deserialize)]
struct OpenStackMeta {
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    uuid: Option<String>,
    #[serde(default)]
    public_keys: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    keys: Vec<OpenStackKey>,
    #[serde(default)]
    devices: Vec<OpenStackDevice>,
}

#[derive(Debug, Deserialize)]
struct OpenStackKey {
    #[serde(default)]
    data: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpenStackDevice {
    #[serde(default)]
    serial: Option<String>,
    #[serde(default)]
    wwn: Option<String>,
}

#[async_trait::async_trait]
impl PlatformFetcher for ConfigDriveFetcher {
    fn platform_id(&self) -> &'static str {
        "config-drive"
    }

    async fn fetch_user_data(&self, _http: &dyn MetadataHttp) -> Result<Option<UserData>> {
        let os = self.openstack_dir();
        let Some(host_nix) = read_opt(&os.join("user_data"))? else {
            return Ok(None);
        };
        let sig = read_opt_string(&os.join("user_data.sig"))?;
        Ok(Some(UserData::Inline {
            payload: host_nix,
            sig,
        }))
    }

    async fn fetch_facts(&self, _http: &dyn MetadataHttp) -> Result<Facts> {
        let os = self.openstack_dir();
        let mut facts = Facts::default();
        if let Some(bytes) = read_opt(&os.join("meta_data.json"))? {
            let meta: OpenStackMeta =
                serde_json::from_slice(&bytes).context("parsing OpenStack meta_data.json")?;
            facts.hostname = meta.hostname;
            facts.instance_id = meta.uuid;
            // public_keys map values + keys[].data.
            for v in meta.public_keys.into_values() {
                facts.ssh_authorized_keys.push(v);
            }
            for k in meta.keys {
                if let Some(d) = k.data {
                    facts.ssh_authorized_keys.push(d);
                }
            }
            for d in meta.devices {
                if let Some(s) = d.serial.or(d.wwn) {
                    facts.disk_ids.push(s);
                }
            }
        }
        if let Some(bytes) = read_opt(&os.join("network_data.json"))? {
            let net = staticnet::parse_openstack_network_data(&bytes)?;
            if net.is_seedable() {
                facts.network = Some(net);
            }
        }
        Ok(facts)
    }
}

// ---------------------------------------------------------------------------
// QEMU fw_cfg
// ---------------------------------------------------------------------------

/// Default `fw_cfg` sysfs root (overridable for tests).
pub const FW_CFG_ROOT: &str = "/sys/firmware/qemu_fw_cfg/by_name";

/// AOS `fw_cfg` blob name for the provisioning payload.
pub const FW_CFG_PROVISIONING: &str = "opt/org.andyl/provisioning";
/// AOS `fw_cfg` blob name for the detached signature.
pub const FW_CFG_PROVISIONING_SIG: &str = "opt/org.andyl/provisioning.sig";

/// The qemu `fw_cfg` channel.
pub struct QemuFwCfgFetcher {
    root: PathBuf,
}

impl Default for QemuFwCfgFetcher {
    fn default() -> Self {
        Self {
            root: PathBuf::from(FW_CFG_ROOT),
        }
    }
}

impl QemuFwCfgFetcher {
    /// Read `fw_cfg` blobs from `root/<name>/raw` (default [`FW_CFG_ROOT`]).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn raw(&self, name: &str) -> PathBuf {
        self.root.join(name).join("raw")
    }
}

#[async_trait::async_trait]
impl PlatformFetcher for QemuFwCfgFetcher {
    fn platform_id(&self) -> &'static str {
        "qemu"
    }

    async fn fetch_user_data(&self, _http: &dyn MetadataHttp) -> Result<Option<UserData>> {
        let Some(payload) = read_opt(&self.raw(FW_CFG_PROVISIONING))? else {
            return Ok(None);
        };
        let sig = read_opt_string(&self.raw(FW_CFG_PROVISIONING_SIG))?;
        Ok(Some(UserData::Inline { payload, sig }))
    }

    async fn fetch_facts(&self, _http: &dyn MetadataHttp) -> Result<Facts> {
        // fw_cfg carries no standard facts document.
        Ok(Facts::default())
    }
}
