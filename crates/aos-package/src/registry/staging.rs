//! Durable local storage for exact registry candidate revisions.
//!
//! Immutable candidate records and content-addressed bytes live under
//! `.git/apr/stages`. Capture binds a revision to its real destination snapshot;
//! publication preserves its public HEAD and channel frontiers. Authoring
//! branches and worktrees remain independent of finalized release tags.
//!
//! The [`capture`] adapter gathers inventories, [`publication`] performs exact
//! transfers and pointer effects, and [`retention`] owns active and grace roots.

mod capture;
pub mod gc;
pub mod hub;
mod publication;
mod retention;

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub use aos_registry_surface::staging::{
    STAGE_SCHEMA, StageContainerGraph, StageObject, StagePointer, StageRecord, StageRevision,
    StageState, inventory_digest, validate_stage_id,
};

/// Stores immutable candidate bytes and compare-and-swap stage records locally.
#[derive(Clone, Debug)]
pub struct LocalStageStore {
    registry: PathBuf,
    root: PathBuf,
}

/// Binds an immutable revision to its required publication destinations.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StageTargets {
    destinations: Vec<String>,
}

impl LocalStageStore {
    /// Opens a stage store and creates its private storage directories.
    ///
    /// During a dry run this opens the read-only view without creating storage.
    ///
    /// # Errors
    ///
    /// Returns an error when the repository cannot be opened or storage cannot
    /// be created.
    pub fn open(registry: &Path) -> Result<Self> {
        let store = Self::open_read_only(registry)?;
        if !crate::dry_run::active() {
            store.ensure_storage()?;
        }
        Ok(store)
    }

    /// Opens an existing repository's candidate catalog without writing files.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry repository cannot be opened.
    pub fn open_read_only(registry: &Path) -> Result<Self> {
        let git_dir = super::objectstore::repo_git_dir(registry)?;
        Ok(Self {
            registry: registry.to_path_buf(),
            root: git_dir.join("apr/stages"),
        })
    }

    /// Returns the private content-addressed candidate object directory.
    pub fn objects_path(&self) -> PathBuf {
        self.root.join("objects")
    }

    /// Returns the durable workspace path for a candidate preparation.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe identifier or zero revision.
    pub fn workspace(&self, id: &str, revision: u64) -> Result<PathBuf> {
        validate_stage_id(id)?;
        if revision == 0 {
            bail!("stage revision must begin at one");
        }
        Ok(self
            .root
            .join("workspaces")
            .join(id)
            .join(revision.to_string()))
    }

    /// Returns the generated cache directory belonging to an exact preparation.
    ///
    /// The cache is separate from the maintainer workspace so its generated
    /// bytes can be collected after the candidate retirement grace period.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe identifier or zero revision.
    pub fn cache_path(&self, id: &str, revision: u64) -> Result<PathBuf> {
        validate_stage_id(id)?;
        if revision == 0 {
            bail!("stage revision must begin at one");
        }
        Ok(self.root.join("caches").join(id).join(revision.to_string()))
    }

    /// Lists current candidate records in identifier order.
    ///
    /// # Errors
    ///
    /// Returns an error when a stored record is invalid or unreadable.
    pub fn list(&self) -> Result<Vec<StageRecord>> {
        let entries = match fs::read_dir(self.root.join("records")) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut records = Vec::new();
        for entry in entries {
            let path = entry?.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                let id = path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .context("candidate record has an invalid filename")?;
                records.push(self.show(id)?);
            }
        }
        records.sort_by(|left, right| left.revision.id.cmp(&right.revision.id));
        Ok(records)
    }

    /// Loads a stage's exact current revision and lifecycle state.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identifiers, absent stages, or corrupt records.
    pub fn show(&self, id: &str) -> Result<StageRecord> {
        self.optional_record(id)?
            .context("registry stage does not exist")
    }

    /// Finds a current candidate without treating absence as an error.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe identifiers or corrupt stored records.
    pub fn find(&self, id: &str) -> Result<Option<StageRecord>> {
        self.optional_record(id)
    }

    /// Verifies every immutable byte in a selected current revision.
    ///
    /// # Errors
    ///
    /// Returns an error for stale revisions, missing bytes, or identity mismatches.
    pub fn verify_inventory(&self, id: &str, revision: u64) -> Result<StageRevision> {
        let record = self.show(id)?;
        self.require_revision(&record, revision)?;
        for object in &record.revision.inventory {
            if hash_file(&self.object_path(&object.sha256)?)?
                != (object.byte_size, object.sha256.clone())
            {
                bail!("staged object identity changed: {}", object.path);
            }
        }
        if let Some(graph) = &record.revision.container {
            crate::registry::container_stage::verify_container_stage_objects(
                graph,
                &self.objects_path(),
            )?;
        }
        Ok(record.revision)
    }

    /// Discards a mutable stage while retaining its roots through the grace period.
    ///
    /// # Errors
    ///
    /// Returns an error for stale, frozen, or released stages.
    pub fn discard(&self, id: &str, revision: u64) -> Result<StageRecord> {
        crate::dry_run::refuse_mutation("discard a registry candidate")?;
        let _lock = self.lock()?;
        let mut record = self.show(id)?;
        self.require_revision(&record, revision)?;
        if !matches!(
            record.state,
            StageState::Draft | StageState::Ready | StageState::Discarded
        ) {
            bail!("invalid registry stage state transition");
        }
        if record.state != StageState::Discarded {
            self.retire_revision_roots(id, revision)?;
        }
        record.state = StageState::Discarded;
        record.released_version = None;
        self.write_record(&record)?;
        Ok(record)
    }

    /// Returns the local immutable bytes for an inventory digest.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed digest.
    pub fn object_path(&self, digest: &str) -> Result<PathBuf> {
        let hash = digest
            .strip_prefix("sha256:")
            .context("stage object lacks SHA-256 prefix")?;
        if hash.len() != 64
            || !hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            bail!("invalid stage object digest");
        }
        Ok(self.objects_path().join(hash))
    }

    /// Requires an ordinary maintainer branch for candidate authoring.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe names, the public default, or channel branches.
    pub fn require_authoring_branch(&self, branch: &str) -> Result<()> {
        crate::types::validate_branch_name(branch)?;
        let repository = git2::Repository::open(&self.registry)?;
        let default = repository
            .find_reference("refs/remotes/origin/HEAD")
            .ok()
            .and_then(|reference| {
                reference
                    .symbolic_target()
                    .ok()
                    .flatten()
                    .map(str::to_string)
            })
            .and_then(|target| {
                target
                    .strip_prefix("refs/remotes/origin/")
                    .map(str::to_string)
            });
        let git_dir = super::objectstore::repo_git_dir(&self.registry)?;
        if matches!(branch, "main" | "master" | "stable" | "candidate" | "edge")
            || default.as_deref() == Some(branch)
            || git_dir.join("channels").join(branch).exists()
        {
            bail!(
                "stages must be authored on a maintainer branch, not a default or channel branch"
            );
        }
        Ok(())
    }

    fn ensure_storage(&self) -> Result<()> {
        crate::dry_run::refuse_mutation("create candidate storage")?;
        for directory in ["objects", "records", "revisions", "retention"] {
            fs::create_dir_all(self.root.join(directory))?;
        }
        Ok(())
    }

    fn optional_record(&self, id: &str) -> Result<Option<StageRecord>> {
        validate_stage_id(id)?;
        let path = self.root.join("records").join(format!("{id}.json"));
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let record: StageRecord = serde_json::from_slice(&bytes)?;
        record.revision.validate()?;
        if record.revision.id != id
            || (record.state == StageState::Released) != record.released_version.is_some()
            || record
                .released_version
                .as_ref()
                .is_some_and(|version| version != &record.revision.release_id)
        {
            bail!("candidate record identity or release state is inconsistent");
        }
        let frozen = fs::read(self.revision_path(id, record.revision.revision))?;
        if serde_json::from_slice::<StageRevision>(&frozen)? != record.revision {
            bail!("mutable stage record differs from immutable revision");
        }
        Ok(Some(record))
    }

    fn require_revision(&self, record: &StageRecord, revision: u64) -> Result<()> {
        if record.revision.revision != revision {
            bail!("stage revision changed; refusing stale candidate operation");
        }
        Ok(())
    }

    fn revision_path(&self, id: &str, revision: u64) -> PathBuf {
        self.root
            .join("revisions")
            .join(id)
            .join(format!("{revision}.json"))
    }

    fn targets_path(&self, id: &str, revision: u64) -> PathBuf {
        self.root
            .join("revisions")
            .join(id)
            .join(format!("{revision}.targets.json"))
    }

    fn require_targets(&self, id: &str, revision: u64, destinations: &[String]) -> Result<()> {
        let expected: StageTargets =
            serde_json::from_slice(&fs::read(self.targets_path(id, revision))?)?;
        if normalized_targets(destinations)? != expected.destinations {
            bail!("candidate destinations differ from the frozen revision; capture a new revision");
        }
        Ok(())
    }

    fn write_record(&self, record: &StageRecord) -> Result<()> {
        self.write_replace(
            &self
                .root
                .join("records")
                .join(format!("{}.json", record.revision.id)),
            &serde_json::to_vec(record)?,
        )
    }

    fn write_replace(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        crate::dry_run::refuse_mutation("persist candidate state")?;
        let parent = path.parent().context("candidate path lacks a parent")?;
        fs::create_dir_all(parent)?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        temporary.write_all(bytes)?;
        temporary.as_file().sync_all()?;
        temporary.persist(path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    }

    fn write_new(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        crate::dry_run::refuse_mutation("persist immutable candidate bytes")?;
        if path.exists() {
            if fs::read(path)? == bytes {
                return Ok(());
            }
            bail!("immutable stage revision already exists with different bytes");
        }
        let parent = path.parent().context("candidate path lacks a parent")?;
        fs::create_dir_all(parent)?;
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.write_all(bytes)?;
        file.as_file().sync_all()?;
        file.persist_noclobber(path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    }

    fn lock(&self) -> Result<StageLock> {
        self.ensure_storage()?;
        let path = self.root.join("lock");
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .context("another local stage operation is running")?;
        file.set_len(0)?;
        writeln!(file, "pid={}", std::process::id())?;
        Ok(StageLock { file })
    }
}

struct StageLock {
    file: File,
}

impl Drop for StageLock {
    fn drop(&mut self) {
        // A concurrently forked child can retain this open-file description
        // until exec. Release ownership when the stage operation completes.
        let _ = rustix::fs::flock(&self.file, rustix::fs::FlockOperation::Unlock);
    }
}

fn normalized_targets(destinations: &[String]) -> Result<Vec<String>> {
    if destinations.is_empty() {
        bail!("candidate operations require at least one publication destination");
    }
    let mut targets = BTreeSet::new();
    for destination in destinations {
        let parsed = url::Url::parse(destination).ok();
        let mut url = match parsed {
            Some(url) if url.scheme() == "file" => {
                let path = url
                    .to_file_path()
                    .map_err(|_| anyhow::anyhow!("invalid file destination"))?;
                url::Url::from_directory_path(fs::canonicalize(path)?)
                    .map_err(|_| anyhow::anyhow!("invalid file destination path"))?
            }
            Some(url) => url,
            None => url::Url::from_directory_path(fs::canonicalize(destination)?)
                .map_err(|_| anyhow::anyhow!("invalid local destination path"))?,
        };
        if url.query().is_some() || url.fragment().is_some() {
            bail!("candidate destination must not contain a query or fragment");
        }
        let path = format!("{}/", url.path().trim_end_matches('/'));
        url.set_path(&path);
        targets.insert(url.to_string());
    }
    Ok(targets.into_iter().collect())
}

fn hash_file(path: &Path) -> Result<(u64, String)> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
        size = size
            .checked_add(count as u64)
            .context("stage object size overflow")?;
    }
    Ok((size, format!("sha256:{}", hex::encode(digest.finalize()))))
}

#[cfg(test)]
mod tests;
