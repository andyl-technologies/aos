//! Offline-channel [`PlatformFetcher`] implementations.
//!
//! Every offline channel resolves to a mounted directory under
//! the provider's private transaction scratch produced by its config-drive mount helper (or
//! the qemu `fw_cfg` sysfs tree). The fetcher reads files from that directory
//! with `std::fs` — no network — so each is unit-testable against a fixture
//! directory with no root.
//!
//! Channels:
//!
//! - [`AosMetadataFetcher`] — the AOS-native `aos-metadata` ISO: literal
//!   `host.nix`, optional `host.nix.sig`, and optional pre-baked `facts.json`.
//! - [`NoCloudFetcher`] — NoCloud `cidata`: `user-data` is the literal
//!   `host.nix`; `meta-data` (YAML) + `network-config` (netplan) feed facts.
//! - [`ConfigDriveFetcher`] — OpenStack `config-2`:
//!   `openstack/latest/user_data` + `meta_data.json` + `network_data.json`.
//! - [`QemuFwCfgFetcher`] — qemu `fw_cfg`: reads the provisioning blob from
//!   `/sys/firmware/qemu_fw_cfg/by_name/<name>/raw`.

use std::fs::OpenOptions;
use std::io::Read as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;

use super::fetcher::{Facts, PlatformFetcher, UserData};
use super::http::MetadataHttp;
use super::staticnet;

use super::http::{
    MAX_ACQUISITION_BYTES, MAX_FACT_DOCUMENT_BYTES, MAX_SIGNATURE_BYTES, MAX_USER_DATA_BYTES,
};

#[derive(Default)]
struct ReadBudget {
    used: AtomicU64,
}

impl ReadBudget {
    fn charge(&self, bytes: u64) -> Result<()> {
        self.used
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(bytes)
                    .filter(|next| *next <= MAX_ACQUISITION_BYTES)
            })
            .map_err(|_| anyhow::anyhow!("offline metadata exceeds aggregate byte limit"))?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum FilePolicy {
    Regular,
    // fw_cfg sysfs attributes do not follow ordinary on-disk size and file
    // semantics, but still use no-follow, nonblocking, bounded reads.
    FwCfgSysfs,
}

/// Read a file to bytes, mapping "not found" to `None` and other errors to
/// `Err`.
fn read_opt(
    path: &Path,
    maximum_bytes: u64,
    budget: &ReadBudget,
    policy: FilePolicy,
) -> Result<Option<Vec<u8>>> {
    let path_metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("inspecting {}", path.display())),
    };
    if matches!(policy, FilePolicy::Regular) && !path_metadata.file_type().is_file() {
        bail!("offline metadata is not a regular file: {}", path.display());
    }
    if path_metadata.len() > maximum_bytes && matches!(policy, FilePolicy::Regular) {
        bail!(
            "offline metadata {} exceeds {maximum_bytes} byte limit",
            path.display()
        );
    }

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    let opened_metadata = file
        .metadata()
        .with_context(|| format!("inspecting opened {}", path.display()))?;
    if matches!(policy, FilePolicy::Regular) && !opened_metadata.file_type().is_file() {
        bail!("offline metadata is not a regular file: {}", path.display());
    }

    let read_limit = maximum_bytes
        .checked_add(1)
        .context("offline metadata byte limit overflow")?;
    let mut bytes = Vec::new();
    let reserve = usize::try_from(opened_metadata.len().min(maximum_bytes))
        .context("offline metadata size does not fit memory")?;
    bytes
        .try_reserve(reserve)
        .context("reserving offline metadata storage")?;
    file.by_ref()
        .take(read_limit)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    ensure!(
        bytes.len() as u64 <= maximum_bytes,
        "offline metadata {} exceeds {maximum_bytes} byte limit",
        path.display()
    );
    budget.charge(bytes.len() as u64)?;
    Ok(Some(bytes))
}

/// Read a file to a UTF-8 string, trimming trailing whitespace, mapping "not
/// found" to `None`.
fn read_opt_string(
    path: &Path,
    maximum_bytes: u64,
    budget: &ReadBudget,
    policy: FilePolicy,
) -> Result<Option<String>> {
    Ok(read_opt(path, maximum_bytes, budget, policy)?
        .and_then(|b| String::from_utf8(b).ok().map(|s| s.trim().to_string())))
}

// ---------------------------------------------------------------------------
// aos-metadata ISO
// ---------------------------------------------------------------------------

/// The AOS-native `aos-metadata` ISO channel.
pub struct AosMetadataFetcher {
    dir: PathBuf,
    budget: ReadBudget,
}

impl AosMetadataFetcher {
    /// Reads from the invocation-private mounted `aos-metadata` directory.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            budget: ReadBudget::default(),
        }
    }
}

#[async_trait::async_trait]
impl PlatformFetcher for AosMetadataFetcher {
    fn platform_id(&self) -> &'static str {
        "aos-metadata"
    }

    async fn fetch_user_data(&self, _http: &dyn MetadataHttp) -> Result<Option<UserData>> {
        let Some(payload) = read_opt(
            &self.dir.join("host.nix"),
            MAX_USER_DATA_BYTES,
            &self.budget,
            FilePolicy::Regular,
        )?
        else {
            return Ok(None);
        };
        let sig = read_opt_string(
            &self.dir.join("host.nix.sig"),
            MAX_SIGNATURE_BYTES,
            &self.budget,
            FilePolicy::Regular,
        )?;
        Ok(Some(UserData::Inline { payload, sig }))
    }

    async fn fetch_facts(&self, _http: &dyn MetadataHttp) -> Result<Facts> {
        match read_opt(
            &self.dir.join("facts.json"),
            MAX_FACT_DOCUMENT_BYTES,
            &self.budget,
            FilePolicy::Regular,
        )? {
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
    budget: ReadBudget,
}

impl NoCloudFetcher {
    /// Read from the mounted `cidata` directory.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            budget: ReadBudget::default(),
        }
    }
}

#[async_trait::async_trait]
impl PlatformFetcher for NoCloudFetcher {
    fn platform_id(&self) -> &'static str {
        "nocloud"
    }

    async fn fetch_user_data(&self, _http: &dyn MetadataHttp) -> Result<Option<UserData>> {
        // AOS treats the NoCloud `user-data` body as the literal host.nix; a
        // leading `#cloud-config`/`#!` is NOT interpreted.
        let Some(host_nix) = read_opt(
            &self.dir.join("user-data"),
            MAX_USER_DATA_BYTES,
            &self.budget,
            FilePolicy::Regular,
        )?
        else {
            return Ok(None);
        };
        let sig = read_opt_string(
            &self.dir.join("user-data.sig"),
            MAX_SIGNATURE_BYTES,
            &self.budget,
            FilePolicy::Regular,
        )?;
        Ok(Some(UserData::Inline {
            payload: host_nix,
            sig,
        }))
    }

    async fn fetch_facts(&self, _http: &dyn MetadataHttp) -> Result<Facts> {
        let mut facts = Facts::default();
        if let Some(bytes) = read_opt(
            &self.dir.join("meta-data"),
            MAX_FACT_DOCUMENT_BYTES,
            &self.budget,
            FilePolicy::Regular,
        )? {
            let meta = super::yaml::parse_metadata(&bytes).context("parsing NoCloud meta-data")?;
            facts.hostname = meta.hostname;
            facts.instance_id = meta.instance_id;
        }
        if let Some(bytes) = read_opt(
            &self.dir.join("network-config"),
            MAX_FACT_DOCUMENT_BYTES,
            &self.budget,
            FilePolicy::Regular,
        )? {
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
    budget: ReadBudget,
}

impl ConfigDriveFetcher {
    /// Read from the mounted `config-2` directory.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            budget: ReadBudget::default(),
        }
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
        let Some(host_nix) = read_opt(
            &os.join("user_data"),
            MAX_USER_DATA_BYTES,
            &self.budget,
            FilePolicy::Regular,
        )?
        else {
            return Ok(None);
        };
        let sig = read_opt_string(
            &os.join("user_data.sig"),
            MAX_SIGNATURE_BYTES,
            &self.budget,
            FilePolicy::Regular,
        )?;
        Ok(Some(UserData::Inline {
            payload: host_nix,
            sig,
        }))
    }

    async fn fetch_facts(&self, _http: &dyn MetadataHttp) -> Result<Facts> {
        let os = self.openstack_dir();
        let mut facts = Facts::default();
        if let Some(bytes) = read_opt(
            &os.join("meta_data.json"),
            MAX_FACT_DOCUMENT_BYTES,
            &self.budget,
            FilePolicy::Regular,
        )? {
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
        if let Some(bytes) = read_opt(
            &os.join("network_data.json"),
            MAX_FACT_DOCUMENT_BYTES,
            &self.budget,
            FilePolicy::Regular,
        )? {
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

/// AOS `fw_cfg` blob name for literal `host.nix`.
pub const FW_CFG_HOST_NIX: &str = "opt/org.andyl/host-nix";
/// AOS `fw_cfg` blob name for the detached host signature.
pub const FW_CFG_HOST_NIX_SIG: &str = "opt/org.andyl/host-nix.sig";

/// The qemu `fw_cfg` channel.
pub struct QemuFwCfgFetcher {
    root: PathBuf,
    budget: ReadBudget,
}

impl Default for QemuFwCfgFetcher {
    fn default() -> Self {
        Self {
            root: PathBuf::from(FW_CFG_ROOT),
            budget: ReadBudget::default(),
        }
    }
}

impl QemuFwCfgFetcher {
    /// Read `fw_cfg` blobs from `root/<name>/raw` (default [`FW_CFG_ROOT`]).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            budget: ReadBudget::default(),
        }
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
        let Some(payload) = read_opt(
            &self.raw(FW_CFG_HOST_NIX),
            MAX_USER_DATA_BYTES,
            &self.budget,
            FilePolicy::FwCfgSysfs,
        )?
        else {
            return Ok(None);
        };
        let sig = read_opt_string(
            &self.raw(FW_CFG_HOST_NIX_SIG),
            MAX_SIGNATURE_BYTES,
            &self.budget,
            FilePolicy::FwCfgSysfs,
        )?;
        Ok(Some(UserData::Inline { payload, sig }))
    }

    async fn fetch_facts(&self, _http: &dyn MetadataHttp) -> Result<Facts> {
        // fw_cfg carries no standard facts document.
        Ok(Facts::default())
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;

    use super::*;

    #[test]
    fn regular_file_reads_enforce_exact_limit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("metadata");
        std::fs::write(&path, b"abcd").unwrap();

        assert_eq!(
            read_opt(&path, 4, &ReadBudget::default(), FilePolicy::Regular)
                .unwrap()
                .unwrap(),
            b"abcd"
        );
        let error = read_opt(&path, 3, &ReadBudget::default(), FilePolicy::Regular).unwrap_err();
        assert!(error.to_string().contains("3 byte limit"), "{error:#}");
    }

    #[test]
    fn regular_file_reads_reject_symlinks_and_special_files() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let link = directory.path().join("link");
        let socket = directory.path().join("socket");
        std::fs::write(&target, b"bytes").unwrap();
        symlink(&target, &link).unwrap();
        let _listener = UnixListener::bind(&socket).unwrap();

        for path in [&link, &socket] {
            let error =
                read_opt(path, 64, &ReadBudget::default(), FilePolicy::Regular).unwrap_err();
            assert!(
                error.to_string().contains("not a regular file"),
                "{error:#}"
            );
        }
    }

    #[test]
    fn fw_cfg_policy_still_applies_streaming_limit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("raw");
        std::fs::write(&path, b"abcd").unwrap();

        let error = read_opt(&path, 3, &ReadBudget::default(), FilePolicy::FwCfgSysfs).unwrap_err();

        assert!(error.to_string().contains("3 byte limit"), "{error:#}");
    }

    #[test]
    fn offline_budget_accepts_exact_limit_and_rejects_more() {
        let budget = ReadBudget::default();

        budget.charge(MAX_ACQUISITION_BYTES).unwrap();

        assert!(budget.charge(1).is_err());
    }
}
