//! Collects private candidate bytes and aged cache pairs under one stage lock.
//!
//! Active and released candidates keep their exact inventory indefinitely.
//! Retired revisions retain bytes for the catalog's 24-hour grace period; this
//! collector adds the same minimum age for unreferenced object-store files.
//! Revision records, history, preparation workspaces, and worktrees are retained.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context as _, Result};

use super::retention::RETIRED_ROOT_GRACE_SECONDS as OBJECT_GRACE_SECONDS;
use super::{LocalStageStore, StageRevision, validate_stage_id};
use crate::registry::nixcache::{self, StaticCacheGcReport};

/// Reports the cache and private candidate object portions of one cleanup.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StageCacheGcReport {
    /// Reports the existing age-based narinfo/NAR pair cleanup.
    pub cache: StaticCacheGcReport,
    /// Reports exact private objects unreferenced beyond the grace period.
    pub objects: StageObjectGcReport,
    /// Reports generated publication surfaces whose revision roots expired.
    pub generated: StageGeneratedGcReport,
}

/// Reports private content-addressed candidate object cleanup.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StageObjectGcReport {
    /// Counts unreferenced object files older than 24 hours.
    pub candidates: usize,
    /// Counts object files actually removed; zero during a preview.
    pub deleted_files: usize,
    /// Counts bytes actually removed; zero during a preview.
    pub deleted_bytes: u64,
    /// Lists candidate SHA-256 digests for review during a preview.
    pub digests: Vec<String>,
}

/// Reports generated private publication and cache directory cleanup.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StageGeneratedGcReport {
    /// Counts generated revision directories with expired retention roots.
    pub candidates: usize,
    /// Counts revision directories actually removed; zero during a preview.
    pub deleted_revisions: usize,
    /// Counts generated file links actually removed; zero during a preview.
    pub deleted_files: usize,
    /// Counts logical file bytes removed; shared hardlinks may retain storage.
    pub deleted_bytes: u64,
    /// Lists generated roots and revisions as `root/stage-id/revision`.
    pub revisions: Vec<String>,
}

impl LocalStageStore {
    /// Collects aged cache pairs and unreferenced private candidate objects.
    ///
    /// The stage lock protects retention discovery through deletion, so a
    /// concurrent capture cannot acquire bytes being removed. A dry run opens
    /// an existing lock without changing it and never creates stage storage.
    ///
    /// # Errors
    ///
    /// Returns an error if another stage operation holds the lock, retention
    /// metadata is invalid, or a cache or object file cannot be read or removed.
    pub fn gc_cache(
        &self,
        cache_dir: &Path,
        max_age_days: u64,
        dry_run: bool,
    ) -> Result<StageCacheGcReport> {
        self.gc_cache_at(cache_dir, max_age_days, dry_run, SystemTime::now())
    }

    fn gc_cache_at(
        &self,
        cache_dir: &Path,
        max_age_days: u64,
        dry_run: bool,
        now: SystemTime,
    ) -> Result<StageCacheGcReport> {
        let dry_run = dry_run || aos_registry_client::dry_run::active();
        let _write_lock;
        let _preview_lock;
        if dry_run {
            _write_lock = None;
            _preview_lock = match File::open(self.root.join("lock")) {
                Ok(file) => {
                    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
                        .context("another local stage operation is running")?;
                    Some(file)
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(error.into()),
            };
        } else {
            _write_lock = Some(self.lock()?);
            _preview_lock = None;
        }

        let timestamp = now.duration_since(SystemTime::UNIX_EPOCH)?.as_secs();
        let revisions = self.retained_revisions_at(timestamp)?;
        let mut retained_paths = BTreeSet::new();
        let mut retained_digests = BTreeSet::new();
        let mut retained_revisions = BTreeSet::new();
        for revision in revisions {
            retained_revisions.insert((revision.id.clone(), revision.revision));
            for object in revision.inventory {
                retained_paths.insert(object.path);
                retained_digests.insert(object.sha256);
            }
            for root in revision.store_roots {
                retained_paths.insert(format!("{}.narinfo", aos_nar::info::store_hash(&root)));
            }
            for pointer in revision.publication {
                if pointer.path.ends_with(".narinfo") {
                    retained_paths.insert(pointer.path);
                }
            }
        }

        let cache = nixcache::gc_static_cache_retaining_paths(
            cache_dir,
            max_age_days,
            dry_run,
            &retained_paths,
        )?;
        let objects = self.collect_objects(&retained_digests, dry_run, now)?;
        let generated = self.collect_generated(&retained_revisions, dry_run)?;
        Ok(StageCacheGcReport {
            cache,
            objects,
            generated,
        })
    }

    fn collect_generated(
        &self,
        retained: &BTreeSet<(String, u64)>,
        dry_run: bool,
    ) -> Result<StageGeneratedGcReport> {
        let mut candidates = Vec::new();
        for root_name in ["surfaces", "caches"] {
            candidates.extend(self.generated_candidates(root_name, retained)?);
        }
        candidates.sort_by(|left, right| left.0.cmp(&right.0));
        let mut report = StageGeneratedGcReport {
            candidates: candidates.len(),
            revisions: candidates
                .iter()
                .map(|(revision, _, _, _)| revision.clone())
                .collect(),
            ..StageGeneratedGcReport::default()
        };
        if !dry_run {
            for (_, path, files, bytes) in candidates {
                fs::remove_dir_all(&path)
                    .with_context(|| format!("removing generated surface {}", path.display()))?;
                report.deleted_revisions += 1;
                report.deleted_files += files;
                report.deleted_bytes += bytes;
            }
        }
        Ok(report)
    }

    fn generated_candidates(
        &self,
        root_name: &str,
        retained: &BTreeSet<(String, u64)>,
    ) -> Result<Vec<(String, PathBuf, usize, u64)>> {
        let root = self.root.join(root_name);
        let metadata = match fs::symlink_metadata(&root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Vec::new());
            }
            Err(error) => return Err(error.into()),
        };
        anyhow::ensure!(
            metadata.is_dir(),
            "candidate surface root must be a regular directory"
        );
        let mut candidates = Vec::new();
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(id) = name.to_str() else { continue };
            if validate_stage_id(id).is_err() || !entry.file_type()?.is_dir() {
                continue;
            }
            for revision_entry in fs::read_dir(entry.path())? {
                let revision_entry = revision_entry?;
                let name = revision_entry.file_name();
                let Some(number) = name.to_str() else {
                    continue;
                };
                let Ok(revision) = number.parse::<u64>() else {
                    continue;
                };
                if revision == 0
                    || number != revision.to_string()
                    || !revision_entry.file_type()?.is_dir()
                    || retained.contains(&(id.to_string(), revision))
                {
                    continue;
                }
                let bytes = match fs::read(self.revision_path(id, revision)) {
                    Ok(bytes) => bytes,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error.into()),
                };
                let candidate: StageRevision = serde_json::from_slice(&bytes)?;
                candidate.validate()?;
                anyhow::ensure!(
                    candidate.id == id && candidate.revision == revision,
                    "generated surface revision differs from its frozen metadata"
                );
                if let Some((files, bytes)) =
                    surface_file_totals(&revision_entry.path(), &candidate)?
                {
                    candidates.push((
                        format!("{root_name}/{id}/{revision}"),
                        revision_entry.path(),
                        files,
                        bytes,
                    ));
                }
            }
        }
        Ok(candidates)
    }

    fn collect_objects(
        &self,
        retained: &BTreeSet<String>,
        dry_run: bool,
        now: SystemTime,
    ) -> Result<StageObjectGcReport> {
        let directory = self.objects_path();
        let metadata = match fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(StageObjectGcReport::default());
            }
            Err(error) => return Err(error.into()),
        };
        anyhow::ensure!(
            metadata.is_dir(),
            "candidate object directory must be a regular directory"
        );
        let cutoff = now
            .checked_sub(Duration::from_secs(OBJECT_GRACE_SECONDS))
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let mut candidates = Vec::new();
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(hash) = name.to_str() else { continue };
            if hash.len() != 64
                || !hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                continue;
            }
            let digest = format!("sha256:{hash}");
            let metadata = fs::symlink_metadata(entry.path())?;
            if retained.contains(&digest) || !metadata.is_file() || metadata.modified()? >= cutoff {
                continue;
            }
            candidates.push((digest, entry.path(), metadata.len()));
        }
        candidates.sort_by(|left, right| left.0.cmp(&right.0));
        let mut report = StageObjectGcReport {
            candidates: candidates.len(),
            digests: candidates
                .iter()
                .map(|(digest, _, _)| digest.clone())
                .collect(),
            ..StageObjectGcReport::default()
        };
        if !dry_run {
            for (_, path, bytes) in candidates {
                fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
                report.deleted_files += 1;
                report.deleted_bytes += bytes;
            }
        }
        Ok(report)
    }
}

/// Recognizes only generated files and their parent directories from the frozen
/// revision. Unexpected files or links preserve the entire surface for review.
fn surface_file_totals(root: &Path, revision: &StageRevision) -> Result<Option<(usize, u64)>> {
    let paths = revision
        .inventory
        .iter()
        .map(|object| PathBuf::from(&object.path))
        .chain(
            revision
                .publication
                .iter()
                .map(|pointer| PathBuf::from(&pointer.path)),
        )
        .collect::<BTreeSet<_>>();
    let directories = paths
        .iter()
        .flat_map(|path| path.ancestors().skip(1).map(Path::to_path_buf))
        .collect::<BTreeSet<_>>();
    let mut pending = vec![root.to_path_buf()];
    let mut files = 0;
    let mut bytes = 0_u64;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let relative = path.strip_prefix(root)?;
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.is_dir() && directories.contains(relative) {
                pending.push(path);
            } else if metadata.is_file() && paths.contains(relative) {
                files += 1;
                bytes = bytes
                    .checked_add(metadata.len())
                    .context("generated surface byte count overflow")?;
            } else {
                return Ok(None);
            }
        }
    }
    Ok(Some((files, bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::staging::{
        STAGE_SCHEMA, StageObject, StagePointer, StageRecord, StageRevision, StageState,
        inventory_digest,
    };
    use sha2::{Digest as _, Sha256};

    fn store() -> (tempfile::TempDir, LocalStageStore) {
        let temporary = tempfile::TempDir::new().unwrap();
        git2::Repository::init_bare(temporary.path()).unwrap();
        let store = LocalStageStore::open(temporary.path()).unwrap();
        (temporary, store)
    }

    fn install(store: &LocalStageStore, id: &str, bytes: &[u8], state: StageState) -> StageObject {
        let object = StageObject {
            path: format!("nar/{id}.nar"),
            sha256: format!("sha256:{}", hex::encode(Sha256::digest(bytes))),
            byte_size: bytes.len() as u64,
            kind: "package".into(),
            media_type: "application/octet-stream".into(),
        };
        let inventory = vec![object.clone()];
        let revision = StageRevision {
            schema: STAGE_SCHEMA.into(),
            id: id.into(),
            registry: "example/main".into(),
            revision: 1,
            release_id: "1.0.0".into(),
            source_branch: "dplecki/release-1.0.0".into(),
            commit: "a".repeat(40),
            inventory_digest: inventory_digest(&inventory).unwrap(),
            inventory,
            container: None,
            publication: vec![StagePointer {
                path: format!("{id}.narinfo"),
                bytes: b"prepared narinfo".to_vec(),
                expected_sha256: None,
            }],
            store_roots: Vec::new(),
        };
        revision.validate().unwrap();
        let path = store.revision_path(id, 1);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, serde_json::to_vec(&revision).unwrap()).unwrap();
        fs::write(store.object_path(&object.sha256).unwrap(), bytes).unwrap();
        store
            .write_record(&StageRecord {
                revision,
                state,
                released_version: None,
            })
            .unwrap();
        object
    }

    fn retire_at(store: &LocalStageStore, id: &str, retired_at: u64) {
        let directory = store.root.join("retention").join(id);
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("1.json"),
            serde_json::to_vec(&serde_json::json!({
                "retired_at": retired_at,
            }))
            .unwrap(),
        )
        .unwrap();
    }

    fn age(path: &Path, modified: SystemTime) {
        File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(modified))
            .unwrap();
    }

    fn cache_pair(cache: &Path, hash: &str, object: &StageObject, now: SystemTime) {
        fs::create_dir_all(cache.join("nar")).unwrap();
        fs::write(cache.join(&object.path), vec![0; object.byte_size as usize]).unwrap();
        let narinfo = cache.join(format!("{hash}.narinfo"));
        fs::write(&narinfo, format!(
            "StorePath: /nix/store/{hash}-package\nURL: {}\nCompression: none\nFileHash: {}\nFileSize: {}\nNarHash: {}\nNarSize: {}\nReferences: \n",
            object.path, object.sha256, object.byte_size, object.sha256, object.byte_size,
        )).unwrap();
        for path in [&narinfo, &cache.join(&object.path)] {
            age(path, now - Duration::from_secs(3 * OBJECT_GRACE_SECONDS));
        }
    }

    #[test]
    fn collects_retired_bytes_after_grace_but_preserves_shared_active_bytes_and_history() {
        let (_temporary, store) = store();
        let now = SystemTime::now();
        let timestamp = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let shared = install(&store, "active", b"shared", StageState::Draft);
        install(&store, "discarded-shared", b"shared", StageState::Discarded);
        let retired = install(&store, "discarded-only", b"retired", StageState::Discarded);
        retire_at(
            &store,
            "discarded-shared",
            timestamp - OBJECT_GRACE_SECONDS - 1,
        );
        retire_at(
            &store,
            "discarded-only",
            timestamp - OBJECT_GRACE_SECONDS + 1,
        );
        for object in [&shared, &retired] {
            age(
                &store.object_path(&object.sha256).unwrap(),
                now - Duration::from_secs(3 * OBJECT_GRACE_SECONDS),
            );
        }
        let active_surface = store.materialize_surface("active", 1).unwrap();
        let shared_surface = store.materialize_surface("discarded-shared", 1).unwrap();
        let retired_surface = store.materialize_surface("discarded-only", 1).unwrap();
        let active_cache = store.cache_path("active", 1).unwrap();
        let retired_cache = store.cache_path("discarded-only", 1).unwrap();
        for (root, object) in [(&active_cache, &shared), (&retired_cache, &retired)] {
            fs::create_dir_all(root.join("nar")).unwrap();
            fs::hard_link(
                store.object_path(&object.sha256).unwrap(),
                root.join(&object.path),
            )
            .unwrap();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            assert_eq!(
                fs::metadata(active_surface.join(&shared.path))
                    .unwrap()
                    .ino(),
                fs::metadata(shared_surface.join("nar/discarded-shared.nar"))
                    .unwrap()
                    .ino(),
            );
        }
        let workspace = store.workspace("discarded-only", 1).unwrap();
        fs::create_dir_all(&workspace).unwrap();
        fs::write(workspace.join("preparation"), b"keep").unwrap();
        let cache = store.registry.join("cache");
        cache_pair(&cache, "abc123", &shared, now);
        cache_pair(&cache, "def456", &retired, now);
        let closure = StageObject {
            path: "nar/held-closure.nar".into(),
            ..shared.clone()
        };
        cache_pair(&cache, "active", &closure, now);

        let before = store.gc_cache_at(&cache, 1, false, now).unwrap();
        assert_eq!(before.objects.candidates, 0);
        assert_eq!(before.cache.candidates, 0);
        assert_eq!(
            before.generated.revisions,
            vec!["surfaces/discarded-shared/1"]
        );
        assert!(!shared_surface.exists());
        assert!(retired_surface.exists());
        let preview = store
            .gc_cache_at(&cache, 1, true, now + Duration::from_secs(1))
            .unwrap();
        assert_eq!(preview.objects.digests, vec![retired.sha256.clone()]);
        assert_eq!(preview.objects.deleted_files, 0);
        assert_eq!(preview.cache.hashes, vec!["def456"]);
        assert_eq!(
            preview.generated.revisions,
            vec!["caches/discarded-only/1", "surfaces/discarded-only/1"]
        );
        assert_eq!(preview.generated.deleted_files, 0);
        assert!(retired_surface.exists());
        assert!(retired_cache.exists());
        assert!(store.object_path(&retired.sha256).unwrap().exists());

        let removed = store
            .gc_cache_at(&cache, 1, false, now + Duration::from_secs(1))
            .unwrap();
        assert_eq!(removed.objects.deleted_files, 1);
        assert_eq!(removed.generated.deleted_revisions, 2);
        assert!(!retired_surface.exists());
        assert!(!retired_cache.exists());
        assert_eq!(
            fs::read(active_surface.join(&shared.path)).unwrap(),
            b"shared"
        );
        assert_eq!(
            fs::read(active_cache.join(&shared.path)).unwrap(),
            b"shared"
        );
        assert_eq!(removed.cache.deleted_files, 2);
        assert!(cache.join("abc123.narinfo").exists());
        assert!(cache.join(&shared.path).exists());
        assert!(cache.join("active.narinfo").exists());
        assert!(cache.join(&closure.path).exists());
        assert_eq!(removed.objects.deleted_bytes, b"retired".len() as u64);
        assert!(store.object_path(&shared.sha256).unwrap().exists());
        assert!(!store.object_path(&retired.sha256).unwrap().exists());
        assert!(store.show("discarded-only").is_ok());
        assert!(store.revision_path("discarded-only", 1).exists());
        assert!(workspace.join("preparation").exists());
    }

    #[test]
    fn previews_without_initializing_storage_and_refuses_a_concurrent_stage_operation() {
        let temporary = tempfile::TempDir::new().unwrap();
        git2::Repository::init_bare(temporary.path()).unwrap();
        let store = LocalStageStore::open_read_only(temporary.path()).unwrap();

        assert_eq!(
            store
                .gc_cache(&temporary.path().join("cache"), 0, true)
                .unwrap(),
            StageCacheGcReport::default()
        );
        assert!(!store.root.exists());

        let _lock = store.lock().unwrap();
        let lock_bytes = fs::read(store.root.join("lock")).unwrap();
        assert!(
            store
                .gc_cache(&temporary.path().join("cache"), 0, true)
                .is_err()
        );
        assert!(
            store
                .gc_cache(&temporary.path().join("cache"), 0, false)
                .is_err()
        );
        assert_eq!(fs::read(store.root.join("lock")).unwrap(), lock_bytes);
    }

    #[test]
    fn collects_only_old_canonical_object_files() {
        let (_temporary, store) = store();
        let now = SystemTime::now();
        let old = store
            .object_path(&format!("sha256:{}", "b".repeat(64)))
            .unwrap();
        let recent = store
            .object_path(&format!("sha256:{}", "c".repeat(64)))
            .unwrap();
        fs::write(&old, b"old").unwrap();
        fs::write(&recent, b"recent").unwrap();
        age(&old, now - Duration::from_secs(OBJECT_GRACE_SECONDS + 1));
        fs::write(store.objects_path().join("preparing.tmp"), b"keep").unwrap();
        fs::create_dir(store.objects_path().join("a".repeat(64))).unwrap();
        let unknown_surface = store.root.join("surfaces/unknown/1");
        fs::create_dir_all(&unknown_surface).unwrap();
        fs::write(unknown_surface.join("preparation"), b"keep").unwrap();

        let report = store
            .gc_cache_at(&store.registry.join("cache"), 0, false, now)
            .unwrap();

        assert_eq!(report.objects.deleted_files, 1);
        assert!(!old.exists());
        assert!(recent.exists());
        assert!(store.objects_path().join("preparing.tmp").exists());
        assert!(store.objects_path().join("a".repeat(64)).is_dir());
        assert!(unknown_surface.join("preparation").exists());
    }
}
