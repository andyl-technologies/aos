//! Owns host administrative project provisioning and protected quota broker input.
//!
//! Configuration and ledger are host-owned TOML outside the content layout.
//! ```toml
//! socket = "/run/terrane-host/quota.sock"
//! epoch = "00000000000000000000000000000001"
//! tier_charge_budget_bytes = 1073741824
//! # Each [[owners]] lists all seven [[owners.roots]] allocation classes.
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use terrane_fs::host_quota::{
    ConfiguredOwner, ConfiguredRoot, HostQuotaBroker, NativeProject, NativeQuota, ROOT_LABELS,
    filesystem_uuid, open_host_path, provision_project,
};

/// Carries the protected host quota partition configuration.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostConfig {
    /// Protected query socket pathname.
    pub socket: PathBuf,
    /// Explicit administrator-selected 16-byte epoch in lowercase hexadecimal.
    pub epoch: String,
    /// Finite sum ceiling for all configured project limits.
    pub tier_charge_budget_bytes: u64,
    /// Complete project partition.
    pub owners: Vec<OwnerConfig>,
}

/// Configures one stable domain charge owner.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerConfig {
    /// Stable host-assigned identifier.
    pub owner_id: String,
    /// Canonical disclosure domain.
    pub domain: String,
    /// Nonzero native project identifier.
    pub project_id: u32,
    /// Finite 1024-byte-aligned hard limit.
    pub hard_limit_bytes: u64,
    /// Kernel identities authorized for read-only queries.
    pub allowed_client_uids: BTreeSet<u32>,
    /// Complete set of compatible allocation roots.
    pub roots: Vec<RootConfig>,
}

/// Configures one allocation-class root.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootConfig {
    /// Registered allocation-class label.
    pub role_directory: String,
    /// Absolute administrator-selected root path.
    pub path: PathBuf,
}

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Binding {
    owner_id: String,
    domain: String,
    filesystem_uuid: [u8; 16],
    project_id: u32,
    role_directory: String,
    path: PathBuf,
    device: u64,
    inode: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    version: u32,
    epoch: String,
    bindings: Vec<Binding>,
}

fn protected_text(path: &Path) -> io::Result<String> {
    let mut file = open_host_path(path, false)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.len() > 1024 * 1024
    {
        return Err(io::Error::other(
            "host file lacks protected custody or exceeds size bound",
        ));
    }
    let mut text = String::new();
    Read::by_ref(&mut file)
        .take(1024 * 1024 + 1)
        .read_to_string(&mut text)?;
    if text.len() > 1024 * 1024 {
        return Err(io::Error::other("host file size limit"));
    }
    Ok(text)
}

fn parse_error(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn epoch(value: &str) -> io::Result<[u8; 16]> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(io::Error::other(
            "epoch must contain 32 lowercase hexadecimal digits",
        ));
    }
    let mut result = [0u8; 16];
    for (destination, pair) in result.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let digit = |byte: u8| {
            if byte <= b'9' {
                byte - b'0'
            } else {
                byte - b'a' + 10
            }
        };
        *destination = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(result)
}

fn load(path: &Path) -> io::Result<HostConfig> {
    let config: HostConfig = toml::from_str(&protected_text(path)?).map_err(parse_error)?;
    epoch(&config.epoch)?;
    let mut identities = BTreeSet::new();
    let mut projects = BTreeSet::new();
    let mut domains = BTreeSet::new();
    let mut sum = 0u64;
    if config.owners.is_empty() || config.owners.len() > 256 {
        return Err(io::Error::other("invalid partition size"));
    }
    for owner in &config.owners {
        terrane_fs::host_quota::validate_domain_label(&owner.domain)?;
        if owner.owner_id.is_empty()
            || owner.owner_id.len() > 256
            || owner.domain.is_empty()
            || owner.domain.len() > 256
            || owner.project_id == 0
            || owner.hard_limit_bytes == 0
            || owner.hard_limit_bytes % 1024 != 0
            || owner.allowed_client_uids.is_empty()
            || !identities.insert((&owner.owner_id, &owner.domain))
            || !projects.insert(owner.project_id)
            || !domains.insert(&owner.domain)
        {
            return Err(io::Error::other("invalid or duplicate project owner"));
        }
        let labels: BTreeSet<_> = owner
            .roots
            .iter()
            .map(|root| root.role_directory.as_str())
            .collect();
        if labels.len() != owner.roots.len()
            || !ROOT_LABELS.iter().all(|label| labels.contains(label))
            || labels
                .iter()
                .any(|label| !ROOT_LABELS.contains(label) && *label != "administrative-root")
        {
            return Err(io::Error::other(
                "owner must cover all allocation classes exactly once",
            ));
        }
        let layout = owner
            .roots
            .iter()
            .find(|root| root.role_directory == "layout-root")
            .ok_or_else(|| io::Error::other("missing explicit layout root"))?;
        for root in &owner.roots {
            if root.role_directory == "administrative-root" {
                if owner.domain != "public" || root.path.starts_with(&layout.path) {
                    return Err(io::Error::other(
                        "administrative scaffold requires a separate explicit public-owner root",
                    ));
                }
            } else if root.role_directory != "layout-root"
                && root.path != layout.path.join(&root.role_directory)
            {
                return Err(io::Error::other(
                    "allocation classes must belong to their explicit domain layout",
                ));
            }
        }
        sum = sum
            .checked_add(owner.hard_limit_bytes)
            .ok_or_else(|| io::Error::other("partition limit overflow"))?;
    }
    let layouts: Vec<_> = config
        .owners
        .iter()
        .flat_map(|owner| &owner.roots)
        .filter(|root| root.role_directory == "layout-root")
        .collect();
    for (index, layout) in layouts.iter().enumerate() {
        if layouts.iter().skip(index + 1).any(|other| {
            layout.path.starts_with(&other.path) || other.path.starts_with(&layout.path)
        }) {
            return Err(io::Error::other(
                "disclosure domain layouts must be physically disjoint",
            ));
        }
    }
    if sum > config.tier_charge_budget_bytes {
        return Err(io::Error::other("partition exceeds tier budget"));
    }
    Ok(config)
}

fn retain(config: &HostConfig) -> io::Result<(Vec<ConfiguredOwner>, Vec<Binding>)> {
    let mut owners = Vec::new();
    let mut bindings = Vec::new();
    let mut root_identities = BTreeSet::new();
    for owner in &config.owners {
        let mut roots = Vec::new();
        let mut owner_uuid = None;
        for root in &owner.roots {
            let directory = open_host_path(&root.path, true)?;
            let actual = NativeProject::inspect(&directory)?;
            let uuid = filesystem_uuid(&directory)?;
            if owner_uuid.is_some_and(|previous| previous != uuid)
                || !root_identities.insert((actual.device, actual.inode))
            {
                return Err(io::Error::other(
                    "owner roots cross filesystems or duplicate native inode",
                ));
            }
            owner_uuid = Some(uuid);
            bindings.push(Binding {
                owner_id: owner.owner_id.clone(),
                domain: owner.domain.clone(),
                filesystem_uuid: uuid,
                project_id: owner.project_id,
                role_directory: root.role_directory.clone(),
                path: root.path.clone(),
                device: actual.device,
                inode: actual.inode,
            });
            roots.push(ConfiguredRoot {
                role_directory: root.role_directory.clone(),
                directory,
                device: actual.device,
                inode: actual.inode,
            });
        }
        owners.push(ConfiguredOwner {
            owner_id: owner.owner_id.clone(),
            domain: owner.domain.clone(),
            filesystem_uuid: owner_uuid.ok_or_else(|| io::Error::other("owner has no roots"))?,
            project_id: owner.project_id,
            hard_limit_bytes: owner.hard_limit_bytes,
            allowed_client_uids: owner.allowed_client_uids.clone(),
            roots,
        });
    }
    Ok((owners, bindings))
}

fn validate_initial_skeleton(config: &HostConfig) -> io::Result<()> {
    let paths: BTreeSet<_> = config
        .owners
        .iter()
        .flat_map(|owner| &owner.roots)
        .map(|root| root.path.as_path())
        .collect();
    for path in &paths {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() || !paths.contains(entry.path().as_path()) {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "initial provisioning permits only the exact configured directory skeleton",
                ));
            }
        }
    }
    Ok(())
}

fn verify_ledger(path: &Path, config: &HostConfig, bindings: &[Binding]) -> io::Result<()> {
    let ledger: Ledger = toml::from_str(&protected_text(path)?).map_err(parse_error)?;
    if ledger.version != 1 || ledger.epoch != config.epoch || ledger.bindings != bindings {
        return Err(io::Error::other("host provisioning ledger mismatch"));
    }
    Ok(())
}

/// Provisions only the explicit administrator-selected partition.
///
/// A new ledger is synchronized before native mutations, preserving ownership
/// even across interrupted provisioning. Existing bindings cannot be reassigned.
///
/// # Errors
/// Returns configuration, ledger-conflict, privilege or filesystem errors.
pub fn provision(config_path: &Path, ledger_path: &Path) -> io::Result<()> {
    let config = load(config_path)?;
    let (owners, bindings) = retain(&config)?;
    let mut provisioning_guards = Vec::new();
    for owner in &owners {
        let layout = owner
            .roots
            .iter()
            .find(|root| root.role_directory == "layout-root")
            .ok_or_else(|| io::Error::other("missing explicit layout root"))?;
        provisioning_guards.push(terrane_fs::host_quota::DomainProvisioningGuard::exclusive(
            &layout.directory,
        )?);
    }
    if config
        .owners
        .iter()
        .flat_map(|owner| &owner.roots)
        .any(|root| ledger_path.starts_with(&root.path))
    {
        return Err(io::Error::other("ledger must be outside content roots"));
    }
    match fs::symlink_metadata(ledger_path) {
        Ok(_) => verify_ledger(ledger_path, &config, &bindings)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // A lost ledger cannot turn an existing native project into a new
            // domain. Initial provisioning only adopts genuinely empty roots.
            for owner in &owners {
                for root in &owner.roots {
                    if NativeProject::inspect(&root.directory)?.project_id != 0 {
                        return Err(io::Error::other(
                            "missing ledger for already assigned project root",
                        ));
                    }
                }
            }
            validate_initial_skeleton(&config)?;
            let parent = ledger_path
                .parent()
                .ok_or_else(|| io::Error::other("ledger has no parent"))?;
            let directory = open_host_path(parent, true)?;
            let metadata = directory.metadata()?;
            if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(io::Error::other("unsafe ledger parent"));
            }
            if config
                .owners
                .iter()
                .flat_map(|owner| &owner.roots)
                .any(|root| ledger_path.starts_with(&root.path))
            {
                return Err(io::Error::other("ledger must be outside content roots"));
            }
            let serialized = toml::to_string(&Ledger {
                version: 1,
                epoch: config.epoch.clone(),
                bindings,
            })
            .map_err(parse_error)?;
            if serialized.len() > 1024 * 1024 {
                return Err(io::Error::other(
                    "provisioning ledger exceeds protected read bound",
                ));
            }
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(ledger_path)?;
            output.write_all(serialized.as_bytes())?;
            output.sync_all()?;
            directory.sync_all()?;
        }
        Err(error) => return Err(error),
    }
    for owner in &owners {
        for root in &owner.roots {
            if NativeProject::inspect(&root.directory)?.project_id == 0 {
                validate_initial_skeleton(&config)?;
            }
            provision_project(&root.directory, owner.project_id, owner.hard_limit_bytes)?;
        }
        NativeQuota::query(&owner.roots[0].directory, owner.project_id)?;
    }
    Ok(())
}

/// Runs the read-only quota broker using the immutable host ledger.
///
/// # Errors
/// Returns configuration, native verification or socket setup errors.
pub fn serve(config_path: &Path, ledger_path: &Path) -> io::Result<()> {
    let config = load(config_path)?;
    let (owners, bindings) = retain(&config)?;
    verify_ledger(ledger_path, &config, &bindings)?;
    let parent = config
        .socket
        .parent()
        .ok_or_else(|| io::Error::other("socket has no parent"))?;
    let directory = open_host_path(parent, true)?;
    let metadata = directory.metadata()?;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::other("unsafe quota socket parent"));
    }
    let broker = std::sync::Arc::new(HostQuotaBroker::bind(
        &config.socket,
        epoch(&config.epoch)?,
        config.tier_charge_budget_bytes,
        owners,
    )?);
    fs::set_permissions(&config.socket, fs::Permissions::from_mode(0o666))?;
    let mut workers = Vec::new();
    for _ in 0..16 {
        let broker = std::sync::Arc::clone(&broker);
        workers.push(std::thread::spawn(move || -> () {
            loop {
                // A malformed or disconnected client loses only its own connection.
                let _ = broker.serve_connection();
            }
        }));
    }
    for worker in workers {
        worker
            .join()
            .map_err(|_| io::Error::other("quota worker terminated"))?;
    }
    Err(io::Error::other("quota workers stopped"))
}

/// Queries a configured owner through the authenticated read-only helper.
///
/// This diagnostic path performs no direct privileged quota syscall and is
/// suitable for running as an unprivileged Terrane role.
///
/// # Errors
/// Returns protected configuration, authentication or live observation errors.
pub fn query(
    config_path: &Path,
    owner_id: &str,
    domain: &str,
) -> io::Result<terrane_fs::host_quota::VerifiedQuotaObservation> {
    let config = load(config_path)?;
    if !config
        .owners
        .iter()
        .any(|owner| owner.owner_id == owner_id && owner.domain == domain)
    {
        return Err(io::Error::other(
            "owner is not in the protected host configuration",
        ));
    }
    let mut client =
        terrane_fs::host_quota::HostQuotaClient::connect(&config.socket, 0, epoch(&config.epoch)?)?;
    client.query(owner_id, domain)
}
