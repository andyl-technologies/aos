//! Hub-private immutable storage for signed system-image bytes.
//!
//! Files are addressed by their lowercase SHA-256 digest below a retained,
//! owner-private directory descriptor. Publication copies an already-open
//! origin descriptor into a create-new temporary file, validates the bytes,
//! fsyncs and makes the inode read-only, then links it into place without
//! replacing an existing winner.

use std::fs;
use std::io::{Read as _, Seek as _, Write as _};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;

use anyhow::{Context as _, Result};
use sha2::{Digest as _, Sha256};

/// A retained descriptor for the Hub-private image snapshot directory.
pub struct ImageSnapshotStore {
    directory: OwnedFd,
    path: std::path::PathBuf,
    retained: Mutex<std::collections::HashMap<String, Arc<fs::File>>>,
    lifecycle: Arc<tokio::sync::Mutex<()>>,
}

/// Opens a surface-relative regular file without following any symlink component.
///
/// # Errors
///
/// Returns an error for an unsafe component, symlink, non-regular file, or I/O failure.
pub fn open_surface_file(root: &Path, path: &str) -> Result<Option<fs::File>> {
    let flags =
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW;
    let mut directory = match rustix::fs::openat(
        rustix::fs::CWD,
        root,
        flags | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut components = path.split('/').peekable();
    while let Some(component) = components.next() {
        anyhow::ensure!(
            !component.is_empty() && component != "." && component != "..",
            "invalid image surface path component"
        );
        let component_flags = if components.peek().is_some() {
            flags | rustix::fs::OFlags::DIRECTORY
        } else {
            flags
        };
        directory = match rustix::fs::openat(
            &directory,
            component,
            component_flags,
            rustix::fs::Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
    }
    let metadata = rustix::fs::fstat(&directory)?;
    anyhow::ensure!(
        rustix::fs::FileType::from_raw_mode(metadata.st_mode) == rustix::fs::FileType::RegularFile,
        "image publication source must be a regular file"
    );
    Ok(Some(fs::File::from(directory)))
}

impl ImageSnapshotStore {
    /// Creates or opens `<hub-root>/image-snapshots/sha256` securely.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory cannot be created, is linked,
    /// is not owner-private, or is not owned by the effective user.
    pub fn open(hub_root: &Path) -> Result<Arc<Self>> {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

        let root = hub_root.join("image-snapshots");
        let sha256 = root.join("sha256");
        for directory in [&root, &sha256] {
            if fs::symlink_metadata(directory)
                .is_ok_and(|metadata| metadata.file_type().is_symlink())
            {
                anyhow::bail!("image snapshot directory must not be a symlink");
            }
            if !directory.exists() {
                let mut builder = fs::DirBuilder::new();
                builder.mode(0o700).create(directory).with_context(|| {
                    format!("creating private image directory {}", directory.display())
                })?;
            }
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        fs::File::open(hub_root)?.sync_all()?;
        fs::File::open(&root)?.sync_all()?;
        fs::File::open(&sha256)?.sync_all()?;
        let directory = rustix::fs::openat(
            rustix::fs::CWD,
            &sha256,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )?;
        let metadata = rustix::fs::fstat(&directory)?;
        anyhow::ensure!(
            rustix::fs::FileType::from_raw_mode(metadata.st_mode)
                == rustix::fs::FileType::Directory
                && metadata.st_uid == rustix::process::geteuid().as_raw()
                && metadata.st_mode & 0o077 == 0,
            "image snapshot directory must be owner-private and owned by the effective user"
        );
        Ok(Arc::new(Self {
            directory,
            path: sha256,
            retained: Mutex::new(std::collections::HashMap::new()),
            lifecycle: Arc::new(tokio::sync::Mutex::new(())),
        }))
    }

    fn validate_digest(digest: &str) -> Result<()> {
        anyhow::ensure!(
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "invalid image snapshot SHA-256"
        );
        Ok(())
    }

    fn open_digest(&self, digest: &str) -> Result<fs::File> {
        Self::validate_digest(digest)?;
        let fd = rustix::fs::openat(
            &self.directory,
            digest,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )?;
        let metadata = rustix::fs::fstat(&fd)?;
        anyhow::ensure!(
            rustix::fs::FileType::from_raw_mode(metadata.st_mode)
                == rustix::fs::FileType::RegularFile
                && metadata.st_uid == rustix::process::geteuid().as_raw()
                && metadata.st_mode & 0o7777 == 0o400
                && metadata.st_nlink == 1,
            "image snapshot is not an owner-read-only regular inode"
        );
        Ok(fs::File::from(fd))
    }

    fn validate_winner(&self, digest: &str, expected_size: u64) -> Result<fs::File> {
        let mut file = self.open_digest(digest)?;
        let mut hasher = Sha256::new();
        let mut observed = 0_u64;
        let mut buffer = [0_u8; 128 * 1024];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            observed = observed
                .checked_add(count as u64)
                .context("snapshot size overflow")?;
            hasher.update(&buffer[..count]);
        }
        anyhow::ensure!(observed == expected_size, "existing snapshot size mismatch");
        anyhow::ensure!(
            hex::encode(hasher.finalize()) == digest,
            "existing snapshot digest mismatch"
        );
        file.rewind()?;
        Ok(file)
    }

    /// Validates an already-open placement source against its path-bound digest.
    pub(crate) fn validate_source(&self, mut source: fs::File, digest: &str) -> Result<u64> {
        Self::validate_digest(digest)?;
        let mut hasher = Sha256::new();
        let mut size = 0_u64;
        let mut buffer = [0_u8; 128 * 1024];
        loop {
            let count = source.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            size = size
                .checked_add(count as u64)
                .context("snapshot source size overflow")?;
            hasher.update(&buffer[..count]);
        }
        anyhow::ensure!(
            hex::encode(hasher.finalize()) == digest,
            "image placement source digest mismatch"
        );
        Ok(size)
    }

    /// Publishes one open origin descriptor and returns an open immutable snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid digest, changed input, unsafe winner, or I/O failure.
    pub fn publish(&self, mut source: fs::File, digest: &str) -> Result<(fs::File, u64)> {
        Self::validate_digest(digest)?;
        if let Some(file) = self.open_retained(digest)? {
            let size = file.metadata()?.len();
            return Ok((file, size));
        }
        let temporary = format!(".{digest}.{}.tmp", uuid::Uuid::new_v4());
        let result = (|| -> Result<(fs::File, u64)> {
            let fd = rustix::fs::openat(
                &self.directory,
                temporary.as_str(),
                rustix::fs::OFlags::WRONLY
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::EXCL
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            )?;
            let mut target = fs::File::from(fd);
            let mut hasher = Sha256::new();
            let mut size = 0_u64;
            let mut buffer = [0_u8; 128 * 1024];
            loop {
                let count = source.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                size = size
                    .checked_add(count as u64)
                    .context("snapshot size overflow")?;
                hasher.update(&buffer[..count]);
                target.write_all(&buffer[..count])?;
            }
            anyhow::ensure!(
                hex::encode(hasher.finalize()) == digest,
                "image source digest mismatch"
            );
            target.sync_all()?;
            rustix::fs::fchmod(&target, rustix::fs::Mode::RUSR)?;
            target.sync_all()?;
            drop(target);
            match rustix::fs::linkat(
                &self.directory,
                temporary.as_str(),
                &self.directory,
                digest,
                rustix::fs::AtFlags::empty(),
            ) {
                Ok(()) => {
                    rustix::fs::unlinkat(
                        &self.directory,
                        temporary.as_str(),
                        rustix::fs::AtFlags::empty(),
                    )?;
                    rustix::fs::fsync(&self.directory)?;
                    Ok((self.open_digest(digest)?, size))
                }
                Err(rustix::io::Errno::EXIST) => {
                    let mut last_error = None;
                    for _ in 0..100 {
                        match self.validate_winner(digest, size) {
                            Ok(winner) => return Ok((winner, size)),
                            Err(error) => {
                                last_error = Some(error);
                                std::thread::yield_now();
                            }
                        }
                    }
                    let error = last_error.context("snapshot winner never stabilized")?;
                    Err(error)
                }
                Err(error) => Err(error.into()),
            }
        })();
        let _ = rustix::fs::unlinkat(
            &self.directory,
            temporary.as_str(),
            rustix::fs::AtFlags::empty(),
        );
        let (file, size) = result?;
        self.retained
            .lock()
            .map_err(|_| anyhow::anyhow!("image snapshot cache lock poisoned"))?
            .insert(digest.to_string(), Arc::new(file.try_clone()?));
        Ok((file, size))
    }

    /// Publishes while serialized against snapshot collection.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input, publication failure, or task failure.
    pub async fn publish_async(
        self: &Arc<Self>,
        source: fs::File,
        digest: String,
    ) -> Result<(fs::File, u64)> {
        let guard = Arc::clone(&self.lifecycle).lock_owned().await;
        let store = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            store.publish(source, &digest)
        })
        .await
        .context("joining image snapshot publication")?
    }

    /// Opens or publishes a snapshot and leases it before collection can run.
    ///
    /// Successful indexing replaces this transient protection with durable
    /// registry-placement references. Expiration makes an interrupted request
    /// or crashed process self-cleaning.
    ///
    /// # Errors
    ///
    /// Returns an error for an absent origin, invalid bytes, database failure,
    /// or task failure.
    pub async fn open_or_publish_leased(
        self: &Arc<Self>,
        source: Option<fs::File>,
        digest: String,
        db: &aos_hub_core::db::Database,
        require_lease: bool,
    ) -> Result<(fs::File, u64, Option<String>)> {
        const LEASE_SECONDS: i64 = 24 * 60 * 60;

        let _guard = Arc::clone(&self.lifecycle).lock_owned().await;
        let store = Arc::clone(self);
        let digest_for_open = digest.clone();
        let opened = tokio::task::spawn_blocking(move || {
            if require_lease {
                let source = source
                    .context("image placement source disappeared before snapshot verification")?;
                if let Some(file) = store.open_retained(&digest_for_open)? {
                    let source_size = store.validate_source(source, &digest_for_open)?;
                    anyhow::ensure!(
                        file.metadata()?.len() == source_size,
                        "image placement source size differs from retained snapshot"
                    );
                    Ok((file, source_size))
                } else {
                    store.publish(source, &digest_for_open)
                }
            } else if let Some(file) = store.open_retained(&digest_for_open)? {
                let size = file.metadata()?.len();
                Ok((file, size))
            } else {
                let source =
                    source.context("image origin disappeared before snapshot publication")?;
                store.publish(source, &digest_for_open)
            }
        })
        .await
        .context("joining leased image snapshot publication")??;
        let byte_size = i64::try_from(opened.1).context("image snapshot exceeds database range")?;
        let expires_at = aos_hub_core::clock::now_unix_secs()
            .checked_add(LEASE_SECONDS)
            .context("image snapshot lease expiry overflow")?;
        // A committed registry-placement reference is already durable GC
        // protection. Only first publication and concurrent pre-commit index
        // reads need a transient lease; ordinary downloads must not create one
        // durable row per request.
        let lease_id = if require_lease || !db.image_snapshot_has_references(&digest).await? {
            let lease_id = uuid::Uuid::new_v4().simple().to_string();
            db.lease_image_snapshot(&lease_id, &digest, byte_size, expires_at)
                .await?;
            Some(lease_id)
        } else {
            None
        };
        Ok((opened.0, opened.1, lease_id))
    }

    /// Opens one immutable snapshot without following links.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid digest, absent file, or unsafe inode.
    pub fn open_readonly(&self, digest: &str) -> Result<fs::File> {
        self.open_digest(digest)
    }

    /// Opens a snapshot when present.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid digest or unsafe inode.
    pub fn open_optional(&self, digest: &str) -> Result<Option<fs::File>> {
        match self.open_digest(digest) {
            Ok(file) => Ok(Some(file)),
            Err(error)
                if error
                    .downcast_ref::<rustix::io::Errno>()
                    .is_some_and(|errno| *errno == rustix::io::Errno::NOENT) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    /// Opens only an inode retained and verified by this Hub process.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid digest or poisoned store state.
    pub fn open_retained(&self, digest: &str) -> Result<Option<fs::File>> {
        Self::validate_digest(digest)?;
        let retained = self
            .retained
            .lock()
            .map_err(|_| anyhow::anyhow!("image snapshot cache lock poisoned"))?
            .get(digest)
            .cloned();
        let Some(retained) = retained else {
            return Ok(None);
        };

        // Duplicating a descriptor shares its open-file offset, so concurrent
        // streams could consume one another. Linux procfs opens the retained
        // descriptor as a new file description while remaining bound to the
        // verified inode even if its digest pathname is replaced.
        #[cfg(target_os = "linux")]
        {
            let descriptor = format!("/proc/self/fd/{}", retained.as_raw_fd());
            let reopened = fs::File::open(descriptor)?;
            let retained_metadata = retained.metadata()?;
            let reopened_metadata = reopened.metadata()?;
            use std::os::unix::fs::MetadataExt as _;
            anyhow::ensure!(
                retained_metadata.dev() == reopened_metadata.dev()
                    && retained_metadata.ino() == reopened_metadata.ino(),
                "retained image snapshot inode changed while reopening"
            );
            Ok(Some(reopened))
        }

        #[cfg(not(target_os = "linux"))]
        {
            // Native Hub serving is Linux-only. Keep other targets buildable
            // for development without claiming independent stream offsets.
            Ok(Some(retained.try_clone()?))
        }
    }

    /// Validates and retains every snapshot tracked by durable state.
    ///
    /// # Errors
    ///
    /// Returns an error when database state or any snapshot is invalid.
    pub async fn load_tracked(&self, db: &aos_hub_core::db::Database) -> Result<()> {
        for (digest, size) in db.known_image_snapshots().await? {
            let size = u64::try_from(size).context("snapshot size is negative")?;
            let file = self.validate_winner(&digest, size)?;
            self.retained
                .lock()
                .map_err(|_| anyhow::anyhow!("image snapshot cache lock poisoned"))?
                .insert(digest, Arc::new(file));
        }
        Ok(())
    }

    /// Removes one unreferenced snapshot by digest.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid digest, unsafe inode, or unlink failure.
    pub fn remove(&self, digest: &str) -> Result<()> {
        Self::validate_digest(digest)?;
        let retained = match if let Some(file) = self.open_retained(digest)? {
            Some(file)
        } else {
            self.open_optional(digest)?
        } {
            Some(file) => file,
            None => return Ok(()),
        };
        match rustix::fs::unlinkat(&self.directory, digest, rustix::fs::AtFlags::empty()) {
            Ok(()) => {
                rustix::fs::fsync(&self.directory)?;
                drop(retained);
                self.retained
                    .lock()
                    .map_err(|_| anyhow::anyhow!("image snapshot cache lock poisoned"))?
                    .remove(digest);
                Ok(())
            }
            Err(rustix::io::Errno::NOENT) => {
                self.retained
                    .lock()
                    .map_err(|_| anyhow::anyhow!("image snapshot cache lock poisoned"))?
                    .remove(digest);
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Collects snapshots whose durable reference count reached zero.
    ///
    /// # Errors
    ///
    /// Returns an error for database, directory, validation, or unlink failure.
    pub async fn collect(&self, db: &aos_hub_core::db::Database, limit: i64) -> Result<usize> {
        db.prune_expired_image_snapshot_leases().await?;
        let mut removed = 0_usize;
        for (digest, _) in db.collectible_image_snapshots(limit).await? {
            let _guard = Arc::clone(&self.lifecycle).lock_owned().await;
            // Lease acquisition uses this same lifecycle lock. The conditional
            // delete therefore observes either the lease or a fully completed
            // prior collection, never the gap between verified bytes and their
            // durable in-flight protection.
            if db.forget_collectible_image_snapshot(&digest).await? {
                self.remove(&digest)?;
                removed += 1;
            }
        }
        let _guard = Arc::clone(&self.lifecycle).lock_owned().await;
        let known = db.known_image_snapshot_digests().await?;
        for entry in fs::read_dir(&self.path)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let old_enough = entry
                .metadata()?
                .modified()?
                .elapsed()
                .is_ok_and(|age| age >= std::time::Duration::from_secs(3600));
            let orphan = old_enough
                && ((name.starts_with('.') && name.ends_with(".tmp"))
                    || (Self::validate_digest(name).is_ok() && !known.contains(name)));
            if orphan {
                match rustix::fs::unlinkat(&self.directory, name, rustix::fs::AtFlags::empty()) {
                    Ok(()) | Err(rustix::io::Errno::NOENT) => {
                        self.retained
                            .lock()
                            .map_err(|_| anyhow::anyhow!("image snapshot cache lock poisoned"))?
                            .remove(name);
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
        rustix::fs::fsync(&self.directory)?;
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(bytes: &[u8]) -> fs::File {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(bytes).unwrap();
        file.rewind().unwrap();
        file
    }

    #[test]
    fn publication_is_private_read_only_and_concurrent_create_once() {
        use std::os::unix::fs::PermissionsExt as _;

        let hub = tempfile::tempdir().unwrap();
        let store = ImageSnapshotStore::open(hub.path()).unwrap();
        let bytes = b"immutable-image";
        let digest = hex::encode(Sha256::digest(bytes));
        let mut threads = Vec::new();
        for _ in 0..4 {
            let store = Arc::clone(&store);
            let digest = digest.clone();
            threads.push(std::thread::spawn(move || {
                store.publish(source(bytes), &digest).unwrap().1
            }));
        }
        for thread in threads {
            assert_eq!(thread.join().unwrap(), bytes.len() as u64);
        }
        let path = hub.path().join("image-snapshots/sha256").join(&digest);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o400
        );
        assert_eq!(fs::read(&path).unwrap(), bytes);
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"replacement----").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        let mut retained = store.open_retained(&digest).unwrap().unwrap();
        let mut retained_bytes = Vec::new();
        retained.read_to_end(&mut retained_bytes).unwrap();
        assert_eq!(retained_bytes, bytes);
    }

    #[test]
    fn preseed_symlink_wrong_winner_and_failed_temp_are_rejected_and_cleaned() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let hub = tempfile::tempdir().unwrap();
        let store = ImageSnapshotStore::open(hub.path()).unwrap();
        let directory = hub.path().join("image-snapshots/sha256");
        let bytes = b"expected";
        let digest = hex::encode(Sha256::digest(bytes));
        let outside = hub.path().join("outside");
        fs::write(&outside, bytes).unwrap();
        symlink(&outside, directory.join(&digest)).unwrap();
        assert!(store.publish(source(bytes), &digest).is_err());
        fs::remove_file(directory.join(&digest)).unwrap();

        fs::write(directory.join(&digest), b"wrong---").unwrap();
        fs::set_permissions(directory.join(&digest), fs::Permissions::from_mode(0o400)).unwrap();
        assert!(store.publish(source(bytes), &digest).is_err());
        fs::remove_file(directory.join(&digest)).unwrap();
        assert!(store.publish(source(b"wrong"), &digest).is_err());
        assert!(fs::read_dir(directory).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")));
    }

    #[tokio::test]
    async fn orphan_collection_evicts_the_retained_descriptor() {
        let hub = tempfile::tempdir().unwrap();
        let store = ImageSnapshotStore::open(hub.path()).unwrap();
        let bytes = b"unleased-image";
        let digest = hex::encode(Sha256::digest(bytes));
        store.publish(source(bytes), &digest).unwrap();
        let path = hub.path().join("image-snapshots/sha256").join(&digest);
        let file = fs::File::open(&path).unwrap();
        file.set_times(fs::FileTimes::new().set_modified(std::time::SystemTime::UNIX_EPOCH))
            .unwrap();

        let db = aos_hub_core::db::Database::open_in_memory().await.unwrap();
        store.collect(&db, 100).await.unwrap();
        assert!(!path.exists());
        assert!(store.open_retained(&digest).unwrap().is_none());
    }

    #[tokio::test]
    async fn empty_index_transition_never_deletes_placement_bytes() {
        use aos_hub_core::db::{IndexSnapshot, NewSurfacePlacementSpec, SurfaceTarget};

        let root = tempfile::tempdir().unwrap();
        let primary_root = root.path().join("primary");
        let replica_root = root.path().join("replica");
        fs::create_dir_all(&primary_root).unwrap();
        fs::create_dir_all(&replica_root).unwrap();
        let primary_bytes = primary_root.join("published.img");
        let replica_bytes = replica_root.join("published.img");
        fs::write(&primary_bytes, b"primary-image").unwrap();
        fs::write(&replica_bytes, b"replica-image").unwrap();

        let db = aos_hub_core::db::Database::open_in_memory().await.unwrap();
        let registry_id = db
            .register_registry("physical-empty", &[], false)
            .await
            .unwrap();
        let binding = db
            .ensure_instance_default_binding("local_fs", Some(root.path().to_str().unwrap()), None)
            .await
            .unwrap();
        let placement = |name: &str, read_order: i64| NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(registry_id),
            name: name.into(),
            storage_binding_id: binding.id,
            prefix: name.into(),
            kind: "complete".into(),
            desired_state: "active".into(),
            hash_range: None,
            desired_read_enabled: true,
            read_order,
            requires_conditional_writes: false,
        };
        let primary = db
            .create_surface_placement(&placement("primary", 0))
            .await
            .unwrap();
        let primary = db
            .observe_surface_placement(primary.id, "ready", "complete", 1)
            .await
            .unwrap();
        let replica = db
            .create_surface_placement(&placement("replica", 10))
            .await
            .unwrap();
        db.observe_surface_placement(replica.id, "ready", "complete", 1)
            .await
            .unwrap();
        db.apply_snapshot_from_placement(
            registry_id,
            &IndexSnapshot {
                commit: "c".repeat(64),
                name: "Physical bytes".into(),
                refs_digest: Some("d".repeat(64)),
                ..Default::default()
            },
            Some(primary.id),
        )
        .await
        .unwrap();

        db.mark_index_empty_from_placement(registry_id, primary.id)
            .await
            .unwrap();
        assert_eq!(fs::read(primary_bytes).unwrap(), b"primary-image");
        assert_eq!(fs::read(replica_bytes).unwrap(), b"replica-image");
    }
}
