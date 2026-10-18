//! Owns host administrative project provisioning and protected quota broker input.
//!
//! Configuration and ledger are host-owned TOML outside the content layout.
//! ```toml
//! socket = "/run/terrane-host/quota.sock"
//! epoch = "00000000000000000000000000000001"
//! tier_charge_budget_bytes = 1073741824
//! # Each [[owners]] lists layout-root and the seven allocation classes.
//! ```
//!
//! The host ledger stores an explicit transition and original inode custody:
//! ```toml
//! version = 2
//! epoch = "00000000000000000000000000000001"
//! phase = "provisioning" # Becomes "ready" only after verified restoration.
//! bindings = [] # Each binding records UUID, inode, domain, project and uid/gid/mode.
//! [registry]
//! device = 1
//! inode = 2
//! ```

/// Consumes genuine fresh-bucket evidence for first administrative enrollment.
pub mod initial_enrollment;

mod claims;

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
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

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
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
    hard_limit_bytes: u64,
    original_uid: u32,
    original_gid: u32,
    original_mode: u32,
}

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum ProvisioningPhase {
    Provisioning,
    Ready,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    version: u32,
    epoch: String,
    registry: claims::RegistryIdentity,
    phase: ProvisioningPhase,
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

fn retain(config: &HostConfig) -> io::Result<Vec<ConfiguredOwner>> {
    let mut owners = Vec::new();
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
            scaffolding: Vec::new(),
            claim: None,
        });
    }
    Ok(owners)
}

fn owner_for_path<'a>(config: &'a HostConfig, path: &Path) -> io::Result<&'a OwnerConfig> {
    config
        .owners
        .iter()
        .flat_map(|owner| {
            owner
                .roots
                .iter()
                .filter(|root| {
                    root.role_directory == "layout-root"
                        || root.role_directory == "administrative-root"
                })
                .map(move |root| (owner, root))
        })
        .filter(|(_, root)| path.starts_with(&root.path))
        .max_by_key(|(_, root)| root.path.components().count())
        .map(|(owner, _)| owner)
        .ok_or_else(|| io::Error::other("ledger path is outside explicit configured roots"))
}

fn binding_for(config: &HostConfig, path: PathBuf, directory: &File) -> io::Result<Binding> {
    let owner = owner_for_path(config, &path)?;
    let metadata = directory.metadata()?;
    let role = owner
        .roots
        .iter()
        .find(|root| root.path == path)
        .map(|root| root.role_directory.as_str())
        .unwrap_or("scaffold");
    Ok(Binding {
        owner_id: owner.owner_id.clone(),
        domain: owner.domain.clone(),
        filesystem_uuid: filesystem_uuid(directory)?,
        project_id: owner.project_id,
        role_directory: role.into(),
        path,
        device: metadata.dev(),
        inode: metadata.ino(),
        hard_limit_bytes: owner.hard_limit_bytes,
        original_uid: metadata.uid(),
        original_gid: metadata.gid(),
        original_mode: metadata.mode() & 0o7777,
    })
}

fn snapshot_skeleton(
    config: &HostConfig,
    owners: &[ConfiguredOwner],
) -> io::Result<Vec<(Binding, File)>> {
    let mut discovered: BTreeMap<PathBuf, (Binding, File)> = BTreeMap::new();
    let mut stack = Vec::new();
    for owner in owners {
        for root in &owner.roots {
            if root.role_directory == "layout-root" || root.role_directory == "administrative-root"
            {
                let path = config
                    .owners
                    .iter()
                    .find(|item| item.owner_id == owner.owner_id && item.domain == owner.domain)
                    .and_then(|item| {
                        item.roots
                            .iter()
                            .find(|item| item.role_directory == root.role_directory)
                    })
                    .ok_or_else(|| io::Error::other("missing configured root"))?
                    .path
                    .clone();
                stack.push((path, root.directory.try_clone()?, 0usize));
            }
        }
    }
    while let Some((path, directory, depth)) = stack.pop() {
        if let Some((previous, _)) = discovered.get(&path) {
            let actual = directory.metadata()?;
            let previous: &Binding = previous;
            if previous.device != actual.dev() || previous.inode != actual.ino() {
                return Err(io::Error::other(
                    "directory incarnation changed during skeleton walk",
                ));
            }
            continue;
        }
        if depth > 32 || discovered.len() >= 1024 {
            return Err(io::Error::other("directory skeleton bound exceeded"));
        }
        for child in terrane_fs::host_quota::directory_children(&directory)? {
            if discovered.len() + stack.len() >= 1024 {
                return Err(io::Error::other(
                    "pending directory skeleton bound exceeded",
                ));
            }
            stack.push((path.join(child.name), child.directory, depth + 1));
        }
        discovered.insert(
            path.clone(),
            (binding_for(config, path, &directory)?, directory),
        );
    }
    let mut identities = BTreeSet::new();
    for (binding, _) in discovered.values() {
        if !identities.insert((binding.device, binding.inode)) {
            return Err(io::Error::other("aliased directory skeleton"));
        }
    }
    Ok(discovered.into_values().collect())
}

fn stable_binding(left: &Binding, right: &Binding) -> bool {
    left.owner_id == right.owner_id
        && left.domain == right.domain
        && left.filesystem_uuid == right.filesystem_uuid
        && left.project_id == right.project_id
        && left.role_directory == right.role_directory
        && left.path == right.path
        && left.device == right.device
        && left.inode == right.inode
        && left.hard_limit_bytes == right.hard_limit_bytes
}

fn read_ledger(path: &Path, config: &HostConfig) -> io::Result<Ledger> {
    let ledger: Ledger = toml::from_str(&protected_text(path)?).map_err(parse_error)?;
    if ledger.version != 2
        || ledger.epoch != config.epoch
        || ledger.bindings.len() > 1024
        || !ledger
            .bindings
            .windows(2)
            .all(|pair| pair[0].path < pair[1].path)
    {
        return Err(io::Error::other(
            "host provisioning ledger version, epoch or bound mismatch",
        ));
    }
    Ok(ledger)
}

fn open_binding(
    config: &HostConfig,
    owners: &[ConfiguredOwner],
    binding: &Binding,
) -> io::Result<File> {
    let owner = owner_for_path(config, &binding.path)?;
    let configured = owner
        .roots
        .iter()
        .filter(|root| binding.path.starts_with(&root.path))
        .max_by_key(|root| root.path.components().count())
        .ok_or_else(|| io::Error::other("unbound ledger path"))?;
    let retained = owners
        .iter()
        .find(|item| item.owner_id == owner.owner_id && item.domain == owner.domain)
        .and_then(|item| {
            item.roots
                .iter()
                .find(|item| item.role_directory == configured.role_directory)
        })
        .ok_or_else(|| io::Error::other("missing retained ledger root"))?;
    let mut directory = retained.directory.try_clone()?;
    for component in binding
        .path
        .strip_prefix(&configured.path)
        .map_err(parse_error)?
        .components()
    {
        let std::path::Component::Normal(name) = component else {
            return Err(io::Error::other("invalid ledger component"));
        };
        directory = terrane_fs::host_quota::open_directory_child(&directory, name)?;
    }
    Ok(directory)
}

fn bind_ledger(
    config: &HostConfig,
    owners: &mut [ConfiguredOwner],
    ledger: &Ledger,
) -> io::Result<Vec<File>> {
    let mut directories = Vec::new();
    let mut parents: BTreeMap<PathBuf, File> = BTreeMap::new();
    let mut paths = BTreeSet::new();
    let mut identities = BTreeSet::new();
    for binding in &ledger.bindings {
        let directory = open_binding(config, owners, binding)?;
        let actual = binding_for(config, binding.path.clone(), &directory)?;
        if !stable_binding(binding, &actual)
            || !paths.insert(binding.path.clone())
            || !identities.insert((binding.device, binding.inode))
        {
            return Err(io::Error::other("host ledger immutable binding mismatch"));
        }
        let original = actual.original_uid == binding.original_uid
            && actual.original_gid == binding.original_gid;
        let custody = actual.original_uid == 0 && actual.original_gid == 0;
        let known_mode =
            actual.original_mode == binding.original_mode || actual.original_mode == 0o700;
        if ledger.phase == ProvisioningPhase::Ready {
            if !original || actual.original_mode != binding.original_mode {
                return Err(io::Error::other("ready directory ownership mismatch"));
            }
        } else if !(original || custody) || !known_mode {
            return Err(io::Error::other(
                "unrecognized interrupted provisioning ownership",
            ));
        }
        if binding.role_directory == "scaffold" {
            let owner = owners
                .iter_mut()
                .find(|owner| owner.owner_id == binding.owner_id && owner.domain == binding.domain)
                .ok_or_else(|| io::Error::other("unknown scaffold owner"))?;
            owner
                .scaffolding
                .push(terrane_fs::host_quota::ConfiguredScaffold {
                    directory: directory.try_clone()?,
                    parent: parents
                        .get(
                            binding
                                .path
                                .parent()
                                .ok_or_else(|| io::Error::other("scaffold has no parent"))?,
                        )
                        .ok_or_else(|| io::Error::other("scaffold parent missing from ledger"))?
                        .try_clone()?,
                    name: binding
                        .path
                        .file_name()
                        .ok_or_else(|| io::Error::other("scaffold has no name"))?
                        .to_os_string(),
                    device: binding.device,
                    inode: binding.inode,
                });
        }
        parents.insert(binding.path.clone(), directory.try_clone()?);
        directories.push(directory);
    }
    for binding in &ledger.bindings {
        if let Some(parent) = binding.path.parent() {
            if owner_for_path(config, parent).is_ok() && !paths.contains(parent) {
                return Err(io::Error::other(
                    "ledger omits an internal directory ancestor",
                ));
            }
        }
    }
    for owner in &config.owners {
        for root in &owner.roots {
            if !paths.contains(&root.path) {
                return Err(io::Error::other("configured root missing from host ledger"));
            }
        }
    }
    Ok(directories)
}

fn persist_ledger(path: &Path, ledger: &Ledger) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("ledger has no parent"))?;
    let parent_fd = open_host_path(parent, true)?;
    let metadata = parent_fd.metadata()?;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::other("unsafe ledger parent"));
    }
    let serialized = toml::to_string(ledger).map_err(parse_error)?;
    if serialized.len() > 1024 * 1024 {
        return Err(io::Error::other("provisioning ledger exceeds read bound"));
    }
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let temporary = parent.join(format!(".terrane-ledger-{}-{sequence}", std::process::id()));
    let mut created = false;
    let result = (|| {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        created = true;
        output.write_all(serialized.as_bytes())?;
        output.sync_all()?;
        fs::rename(&temporary, path)?;
        parent_fd.sync_all()
    })();
    if result.is_err() && created {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn verify_live(owners: &[ConfiguredOwner]) -> io::Result<()> {
    for owner in owners {
        owner
            .claim
            .as_ref()
            .ok_or_else(|| io::Error::other("owner has no durable project claim"))?
            .verify(&owner.filesystem_uuid, owner.project_id)?;
        for scaffold in &owner.scaffolding {
            let named =
                terrane_fs::host_quota::open_directory_child(&scaffold.parent, &scaffold.name)?
                    .metadata()?;
            if named.dev() != scaffold.device || named.ino() != scaffold.inode {
                return Err(io::Error::other("scaffold pathname incarnation changed"));
            }
        }
        for (directory, device, inode) in owner
            .roots
            .iter()
            .map(|root| (&root.directory, root.device, root.inode))
            .chain(
                owner
                    .scaffolding
                    .iter()
                    .map(|root| (&root.directory, root.device, root.inode)),
            )
        {
            let actual = NativeProject::inspect(directory)?;
            if actual.project_id != owner.project_id
                || !actual.inherit
                || actual.device != device
                || actual.inode != inode
                || filesystem_uuid(directory)? != owner.filesystem_uuid
            {
                return Err(io::Error::other("native ledger project binding mismatch"));
            }
        }
        if NativeQuota::query(&owner.roots[0].directory, owner.project_id)?.hard_limit_bytes
            != owner.hard_limit_bytes
        {
            return Err(io::Error::other("native hard limit mismatch"));
        }
    }
    Ok(())
}

/// Provisions an explicit quiescent domain partition with durable ownership custody.
///
/// Initial provisioning records every directory-only scaffold inode before taking
/// root ownership. Interrupted attempts retain that original record and remain
/// unavailable until an explicit retry restores it. Ready ledgers are verified
/// read-only; this entry point never silently changes an existing hard limit.
///
/// # Errors
/// Returns configuration, active-factory, ledger, privilege or filesystem errors.
pub fn provision(config_path: &Path, ledger_path: &Path) -> io::Result<()> {
    let config = load(config_path)?;
    let mut owners = retain(&config)?;
    let mut guards = Vec::new();
    for owner in &owners {
        let layout = owner
            .roots
            .iter()
            .find(|root| root.role_directory == "layout-root")
            .ok_or_else(|| io::Error::other("missing explicit layout root"))?;
        guards.push(terrane_fs::host_quota::DomainProvisioningGuard::exclusive(
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
    let ledger_parent = ledger_path
        .parent()
        .ok_or_else(|| io::Error::other("ledger has no parent"))?;
    let ledger_directory = open_host_path(ledger_parent, true)?;
    let metadata = ledger_directory.metadata()?;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::other("unsafe ledger parent"));
    }
    // Serialize host administrators sharing a ledger directory as well as
    // native factories sharing domain roots. This lock never assigns its parent
    // to a quota project; the directory is outside the content layout.
    let _ledger_guard =
        terrane_fs::host_quota::DomainProvisioningGuard::exclusive(&ledger_directory)?;
    let initial_enrollment = match fs::symlink_metadata(ledger_path) {
        Ok(_) => false,
        Err(error) if error.kind() == io::ErrorKind::NotFound => true,
        Err(error) => return Err(error),
    };
    let registry = claims::Registry::open(&config, ledger_path, initial_enrollment)?;
    let _registry_guard =
        terrane_fs::host_quota::DomainProvisioningGuard::exclusive(registry.directory())?;
    let mut ledger = match fs::symlink_metadata(ledger_path) {
        Ok(_) => read_ledger(ledger_path, &config)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let snapshot = snapshot_skeleton(&config, &owners)?;
            for (_, directory) in &snapshot {
                if NativeProject::inspect(directory)?.project_id != 0 {
                    return Err(io::Error::other(
                        "missing ledger for assigned project inode",
                    ));
                }
            }
            for owner in &owners {
                terrane_fs::host_quota::require_unused_project(
                    &owner.roots[0].directory,
                    owner.project_id,
                )?;
            }
            let ledger = Ledger {
                version: 2,
                epoch: config.epoch.clone(),
                registry: registry.identity(),
                phase: ProvisioningPhase::Provisioning,
                bindings: snapshot.into_iter().map(|(binding, _)| binding).collect(),
            };
            registry.ensure(&ledger, &owners)?;
            persist_ledger(ledger_path, &ledger)?;
            #[cfg(test)]
            provisioning_test_checkpoint("ledger-durable")?;
            ledger
        }
        Err(error) => return Err(error),
    };
    registry.bind(&ledger, &mut owners)?;
    let directories = bind_ledger(&config, &mut owners, &ledger)?;
    if ledger.phase == ProvisioningPhase::Ready {
        return verify_live(&owners);
    }
    for directory in &directories {
        terrane_fs::host_quota::set_directory_custody(directory, 0, 0, 0o700)?;
    }
    #[cfg(test)]
    provisioning_test_checkpoint("custody-taken")?;
    // Re-enumeration under root custody closes creation and rename races from
    // the initial snapshot, including creation through old directory FDs.
    // Existing open file custody is excluded by quiescent native factory guards;
    // changing directory ownership never revokes an already-open body FD.
    let current = snapshot_skeleton(&config, &owners)?;
    if current.len() != ledger.bindings.len()
        || !current
            .iter()
            .zip(&ledger.bindings)
            .all(|((actual, _), saved)| stable_binding(actual, saved))
    {
        return Err(io::Error::other(
            "directory skeleton changed before exclusive ownership custody",
        ));
    }
    for (binding, directory) in ledger.bindings.iter().zip(&directories) {
        provision_project(directory, binding.project_id, binding.hard_limit_bytes)?;
        #[cfg(test)]
        provisioning_test_checkpoint("project-mutated")?;
    }
    for (binding, directory) in ledger.bindings.iter().zip(&directories) {
        terrane_fs::host_quota::set_directory_custody(
            directory,
            binding.original_uid,
            binding.original_gid,
            binding.original_mode,
        )?;
    }
    verify_live(&owners)?;
    ledger.phase = ProvisioningPhase::Ready;
    persist_ledger(ledger_path, &ledger)
}

/// Runs the read-only quota broker using the immutable host ledger.
///
/// # Errors
/// Returns configuration, native verification or socket setup errors.
pub fn serve(config_path: &Path, ledger_path: &Path) -> io::Result<()> {
    let config = load(config_path)?;
    let mut owners = retain(&config)?;
    let ledger = read_ledger(ledger_path, &config)?;
    if ledger.phase != ProvisioningPhase::Ready {
        return Err(io::Error::other("host provisioning remains incomplete"));
    }
    let registry = claims::Registry::open(&config, ledger_path, false)?;
    registry.bind(&ledger, &mut owners)?;
    bind_ledger(&config, &mut owners, &ledger)?;
    verify_live(&owners)?;
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

// The production binary contains no fault-injection environment surface. The
// explicit VM unit-test executable alone can pause at durable transitions so
// its supervising test can kill the real provisioning process.
#[cfg(test)]
fn provisioning_test_checkpoint(stage: &str) -> io::Result<()> {
    if std::env::var("TERRANE_QUOTA_TEST_STOP").as_deref() != Ok(stage) {
        return Ok(());
    }
    let marker = PathBuf::from(
        std::env::var_os("TERRANE_QUOTA_TEST_MARKER")
            .ok_or_else(|| io::Error::other("test checkpoint lacks marker"))?,
    );
    let temporary = marker.with_extension("marker-partial");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(stage.as_bytes())?;
    file.sync_all()?;
    // Publish only the completed marker. Its pathname must never signal a
    // checkpoint while the stage bytes are still being written or synced.
    fs::hard_link(&temporary, &marker)?;
    fs::remove_file(&temporary)?;
    loop {
        std::thread::park();
    }
}
