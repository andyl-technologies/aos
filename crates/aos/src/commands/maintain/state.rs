//! Repository-bound durable state and rebuildable local projections.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use aos_contract::{Sha256Digest, canonical};
use aos_maintain::discovery::DiscoverySnapshotV1;
use aos_maintain::envelope::InventoryEnvelopeV1;
use aos_maintain::plan::PackageUpdatePlanV1;
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::inventory::RepositoryCoordinates;

const MAX_STATE_DOCUMENT_BYTES: u64 = 32 * 1024 * 1024;

/// Resolves and owns one local repository's protected maintenance paths.
pub(super) struct StateStore {
    root: PathBuf,
    repository: PathBuf,
}

impl StateStore {
    /// Opens the repository namespace and creates protected directories.
    pub(super) fn open(
        override_root: Option<&Path>,
        coordinates: &RepositoryCoordinates,
    ) -> Result<Self> {
        Self::open_identity(
            override_root,
            &coordinates.canonical_remote,
            &coordinates.common_dir,
            false,
        )
    }

    /// Opens the namespace already bound by a validated inventory envelope.
    pub(super) fn open_for_envelope(
        override_root: Option<&Path>,
        envelope: &InventoryEnvelopeV1,
    ) -> Result<Self> {
        Self::open_identity(
            override_root,
            &envelope.canonical_remote,
            Path::new(&envelope.git_common_dir),
            true,
        )
    }

    fn open_identity(
        override_root: Option<&Path>,
        canonical_remote: &str,
        common_dir: &Path,
        create: bool,
    ) -> Result<Self> {
        let root = state_root(override_root)?;
        if create {
            secure_directory(&root)?;
        }
        let repositories = root.join("repositories");
        if create {
            secure_directory(&repositories)?;
        }

        let identity = Sha256Digest::separated(
            "aos.maintain.repository/v1",
            format!("{}\0{}", canonical_remote, common_dir.display()),
        );
        let repository = repositories.join(identity.hex());
        if create {
            secure_directory(&repository)?;
        }
        Ok(Self { root, repository })
    }

    /// Writes the latest repository-bound inventory projection atomically.
    pub(super) fn write_inventory(&self, inventory: &InventoryEnvelopeV1) -> Result<()> {
        atomic_write(&self.repository, "inventory.json", inventory)
    }

    /// Reads and validates the latest repository-bound inventory projection.
    pub(super) fn read_inventory(&self) -> Result<Option<InventoryEnvelopeV1>> {
        let Some(value) = read_optional(&self.repository.join("inventory.json"), "inventory")?
        else {
            return Ok(None);
        };
        let inventory: InventoryEnvelopeV1 = value;
        inventory.validate()?;
        Ok(Some(inventory))
    }

    /// Writes an immutable content-addressed discovery snapshot and latest pointer.
    pub(super) fn write_discovery(&self, snapshot: &DiscoverySnapshotV1) -> Result<Sha256Digest> {
        snapshot.validate()?;
        let digest = Sha256Digest::of_canonical(aos_maintain::DISCOVERY_SNAPSHOT_V1, snapshot)?;
        let snapshots = self.repository.join("discovery");
        secure_directory(&snapshots)?;
        let name = format!("{}.json", digest.hex());
        write_immutable(&snapshots, &name, snapshot)?;
        atomic_write(&self.repository, "discovery-latest.json", snapshot)?;
        Ok(digest)
    }

    /// Reads and validates the latest discovery projection, when present.
    pub(super) fn read_discovery(&self) -> Result<Option<DiscoverySnapshotV1>> {
        let Some(value) = read_optional(
            &self.repository.join("discovery-latest.json"),
            "discovery snapshot",
        )?
        else {
            return Ok(None);
        };
        let snapshot: DiscoverySnapshotV1 = value;
        snapshot.validate()?;
        Ok(Some(snapshot))
    }

    /// Stores one immutable plan beneath its deterministic plan identity.
    pub(super) fn write_plan(&self, plan: &PackageUpdatePlanV1) -> Result<Sha256Digest> {
        plan.validate()?;
        let plans = self.repository.join("plans");
        secure_directory(&plans)?;
        let name = format!("{}.json", plan.plan_id);
        write_immutable(&plans, &name, plan)?;
        Sha256Digest::of_canonical(aos_maintain::PACKAGE_UPDATE_PLAN_V1, plan)
    }

    /// Reads an exact immutable plan identity.
    pub(super) fn read_plan(&self, plan_id: &str) -> Result<Option<PackageUpdatePlanV1>> {
        if plan_id.is_empty()
            || plan_id.len() > 96
            || !plan_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+' | b':')
            })
        {
            bail!("plan identity is invalid");
        }
        let Some(plan) = read_optional(
            &self
                .repository
                .join("plans")
                .join(format!("{plan_id}.json")),
            "package update plan",
        )?
        else {
            return Ok(None);
        };
        let plan: PackageUpdatePlanV1 = plan;
        plan.validate()?;
        Ok(Some(plan))
    }

    /// Records an immutable provider identity's earliest observed time.
    pub(super) fn record_first_observed(&self, identity: &str, observed_at: u64) -> Result<u64> {
        if identity.is_empty()
            || identity.len() > 4096
            || identity.bytes().any(|byte| byte.is_ascii_control())
        {
            bail!("provider first-observed identity is invalid");
        }
        self.with_provider_lock(|| {
            let path = self.root.join("provider-first-observed.json");
            let mut values: BTreeMap<String, u64> =
                read_optional(&path, "provider first-observed index")?.unwrap_or_default();
            let value = *values.entry(identity.to_string()).or_insert(observed_at);
            atomic_write(&self.root, "provider-first-observed.json", &values)?;
            Ok(value)
        })
    }

    /// Claims one Repology request under the host-wide spacing and daily budget.
    pub(super) fn claim_repology_request(&self, now_unix: u64) -> Result<()> {
        self.with_provider_lock(|| {
            let path = self.root.join("repology-budget.json");
            let mut budget: RepologyBudget =
                read_optional(&path, "Repology request budget")?.unwrap_or_default();
            let day = now_unix / 86_400;
            if budget.day != day {
                budget = RepologyBudget {
                    day,
                    ..RepologyBudget::default()
                };
            }
            if now_unix < budget.retry_after_unix {
                bail!("Repology retry deadline has not elapsed");
            }
            if budget.requests >= 1_000 {
                bail!("Repology daily request budget is exhausted");
            }
            if now_unix < budget.last_request_unix.saturating_add(1) {
                bail!("Repology one-request-per-second lease is unavailable");
            }
            budget.requests += 1;
            budget.last_request_unix = now_unix;
            atomic_write(&self.root, "repology-budget.json", &budget)
        })
    }

    /// Stores exact bounded public provider bytes by their content identity.
    pub(super) fn store_provider_response(&self, bytes: &[u8]) -> Result<Sha256Digest> {
        if bytes.len() as u64 > MAX_STATE_DOCUMENT_BYTES {
            bail!("provider response exceeds cache size limit");
        }
        let digest = Sha256Digest::separated("aos.maintain.provider-response/v1", bytes);
        let cache = cache_root()?.join("observations");
        secure_directory(&cache)?;
        let destination = cache.join(digest.hex());
        match destination.symlink_metadata() {
            Ok(metadata) => {
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    bail!("provider response cache entry is not a regular file");
                }
                if fs::read(&destination)? != bytes {
                    bail!("provider response cache digest collision");
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                atomic_write_bytes(&cache, &digest.hex(), bytes)?;
            }
            Err(error) => return Err(error).context("inspecting provider response cache"),
        }
        Ok(digest)
    }

    /// Returns the protected state root for diagnostics.
    pub(super) fn root(&self) -> &Path {
        &self.root
    }

    fn with_provider_lock<T>(&self, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        let lock_path = self.root.join("provider-state.lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&lock_path)
            .context("opening provider-state lock")?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive)
            .context("locking provider state")?;
        operation()
    }
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RepologyBudget {
    day: u64,
    requests: u64,
    last_request_unix: u64,
    retry_after_unix: u64,
}

/// Returns wall-clock Unix seconds for observational metadata only.
pub(super) fn now_unix() -> Result<u64> {
    std::time::UNIX_EPOCH
        .elapsed()
        .context("system clock is before the Unix epoch")
        .map(|duration| duration.as_secs())
}

fn state_root(override_root: Option<&Path>) -> Result<PathBuf> {
    let root = if let Some(root) = override_root {
        root.to_path_buf()
    } else if let Some(root) = absolute_environment_path("XDG_STATE_HOME")? {
        root.join("aos/maintain")
    } else {
        let home = absolute_environment_path("HOME")?
            .ok_or_else(|| anyhow::anyhow!("HOME is required when XDG_STATE_HOME is unset"))?;
        home.join(".local/state/aos/maintain")
    };
    if !root.is_absolute() {
        bail!("maintenance state root must be absolute");
    }
    Ok(root)
}

fn cache_root() -> Result<PathBuf> {
    if let Some(root) = absolute_environment_path("XDG_CACHE_HOME")? {
        return Ok(root.join("aos/maintain"));
    }
    let home = absolute_environment_path("HOME")?
        .ok_or_else(|| anyhow::anyhow!("HOME is required when XDG_CACHE_HOME is unset"))?;
    Ok(home.join(".cache/aos/maintain"))
}

fn absolute_environment_path(name: &str) -> Result<Option<PathBuf>> {
    let Some(value) = std::env::var_os(name) else {
        return Ok(None);
    };
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        bail!("{name} must contain an absolute path");
    }
    Ok(Some(path))
}

fn secure_directory(path: &Path) -> Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            bail!(
                "maintenance state path is not a real directory: {}",
                path.display()
            );
        }
    } else {
        fs::create_dir_all(path)
            .with_context(|| format!("creating maintenance state directory {}", path.display()))?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("protecting maintenance state directory {}", path.display()))?;
    Ok(())
}

fn atomic_write<T>(directory: &Path, name: &str, value: &T) -> Result<()>
where
    T: Serialize,
{
    let bytes = canonical::to_vec(value)?;
    if bytes.len() as u64 > MAX_STATE_DOCUMENT_BYTES {
        bail!("maintenance state document exceeds size limit");
    }
    atomic_write_bytes(directory, name, &bytes)
}

fn atomic_write_bytes(directory: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let mut temporary = tempfile::NamedTempFile::new_in(directory)
        .context("creating temporary maintenance state document")?;
    temporary
        .as_file_mut()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    temporary.write_all(bytes)?;
    temporary.as_file_mut().sync_all()?;
    temporary
        .persist(directory.join(name))
        .map_err(|error| error.error)
        .context("publishing maintenance state document")?;
    File::open(directory)?.sync_all()?;
    Ok(())
}

fn write_immutable<T>(directory: &Path, name: &str, value: &T) -> Result<()>
where
    T: Serialize + DeserializeOwned,
{
    let destination = directory.join(name);
    if let Ok(metadata) = destination.symlink_metadata() {
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            bail!("immutable maintenance object is not a regular file");
        }
        let existing: T = read_required(&destination, "immutable maintenance object")?;
        let expected = canonical::to_vec(value)?;
        let actual = canonical::to_vec(&existing)?;
        if actual != expected {
            bail!("immutable maintenance object digest collision");
        }
        return Ok(());
    }
    atomic_write(directory, name, value)
}

fn read_optional<T>(path: &Path, label: &str) -> Result<Option<T>>
where
    T: DeserializeOwned,
{
    match path.symlink_metadata() {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                bail!("{label} path is not a regular file");
            }
            Ok(Some(read_required(path, label)?))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("inspecting {label}")),
    }
}

fn read_required<T>(path: &Path, label: &str) -> Result<T>
where
    T: DeserializeOwned,
{
    let file = File::open(path).with_context(|| format!("opening {label}"))?;
    let length = file.metadata()?.len();
    if length > MAX_STATE_DOCUMENT_BYTES {
        bail!("{label} exceeds size limit");
    }
    let capacity = usize::try_from(length).context("state document length does not fit memory")?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(MAX_STATE_DOCUMENT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STATE_DOCUMENT_BYTES {
        bail!("{label} exceeds size limit");
    }
    canonical::from_slice(&bytes, label)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn atomic_documents_are_canonical_and_round_trip() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let values = BTreeMap::from([("answer".to_string(), 42_u64)]);
        atomic_write(temporary.path(), "value.json", &values)?;

        let bytes = fs::read(temporary.path().join("value.json"))?;
        assert_eq!(bytes, br#"{"answer":42}"#);
        let loaded: BTreeMap<String, u64> =
            read_required(&temporary.path().join("value.json"), "fixture")?;
        assert_eq!(loaded, values);
        Ok(())
    }

    #[test]
    fn state_directories_reject_symlinks() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let target = temporary.path().join("target");
        fs::create_dir(&target)?;
        let link = temporary.path().join("link");
        symlink(&target, &link)?;

        assert!(secure_directory(&link).is_err());
        Ok(())
    }

    #[test]
    fn repology_budget_is_host_wide_and_day_bounded() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let repository = temporary.path().join("repository");
        secure_directory(&repository)?;
        let store = StateStore {
            root: temporary.path().to_path_buf(),
            repository,
        };

        store.claim_repology_request(100_000)?;
        assert!(store.claim_repology_request(100_000).is_err());
        store.claim_repology_request(100_001)?;
        Ok(())
    }
}
