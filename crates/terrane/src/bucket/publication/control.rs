//! Checks protected native control paths and durable create-once installation.
//!
//! ```text
//! <external-control>/backend-registration.cbor
//! <external-control>/publication/commits/<revision>
//! <external-control>/publication/transactions/<operation-id>
//! ```

use super::receipts::RecordRead;
use super::{corrupt, unsupported};
use crate::bucket::held::HeldIdentity;
use crate::bucket::{BucketBinding, FileBucket, FileBucketPublicationConfig, files};
use crate::store::{Clock, ContentValidator, LocalFs, NativeProtectedRead, StoreFailure};
use std::path::{Path, PathBuf};
use terrane_core::bucket::BucketKey;
use terrane_core::gc::publication::BackendBinding;

/// Pins the actual protected owner and physical namespace under caller exclusion.
pub(super) struct Control {
    /// The independently configured protected external control directory.
    pub path: PathBuf,
    /// The verified actual root and stable coordination identities.
    pub binding: BackendBinding,
    owner: u32,
    identity: (u64, u64),
    root: PathBuf,
    coordination: PathBuf,
}

/// Borrows an actual excluded namespace throughout a read-only control batch.
pub(super) struct HeldReads<'scope, F> {
    control: &'scope Control,
    fs: &'scope F,
    _held: &'scope HeldIdentity<'scope>,
}

impl<F: LocalFs + BucketBinding> HeldReads<'_, F> {
    /// Reads exact protected record bytes while retaining the actual exclusion.
    ///
    /// # Errors
    /// Rejects invalid keys, unsafe record parents, modes, links or inode changes.
    pub(super) async fn read(&self, key: &str) -> Result<Option<Vec<u8>>, StoreFailure> {
        self.control.read_record(self.fs, key).await
    }

    /// Retains one exact protected read under the live batch exclusion.
    ///
    /// # Errors
    /// Rejects malformed keys, unsafe or replaced parents and leaves, and
    /// propagates unavailable exact reads.
    pub(super) async fn read_observed(&self, key: &str) -> Result<RecordRead, StoreFailure> {
        self.control.read_record_observed(self.fs, key).await
    }

    /// Rechecks all physical bindings and ancestry after the complete batch.
    ///
    /// # Errors
    /// Rejects physical replacement or changed ownership and permissions.
    pub(super) async fn finish(self) -> Result<(), StoreFailure> {
        self.control.recheck(self.fs).await
    }
}

#[cfg(unix)]
fn identity(metadata: &std::fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (metadata.dev(), metadata.ino())
}

impl Control {
    fn location(
        root: &Path,
        config: &FileBucketPublicationConfig,
    ) -> Result<(u32, PathBuf), StoreFailure> {
        super::configured_location(root, config)
    }

    /// Validates configured namespace admission before root or lock creation.
    ///
    /// # Errors
    /// Refuses unsafe ancestry, unregistered existing roots, stale external
    /// control for absent roots, and unavailable exact metadata or reads.
    pub(super) async fn preflight<
        F: LocalFs + BucketBinding,
        C: Clock + BucketBinding,
        V: ContentValidator + BucketBinding,
    >(
        bucket: &FileBucket<F, C, V>,
    ) -> Result<(), StoreFailure> {
        let config = bucket
            .inner
            .config
            .publication_control
            .as_ref()
            .ok_or_else(unsupported)?;
        let (owner, path) = Self::location(bucket.root(), config)?;
        #[cfg(not(unix))]
        {
            let _ = (owner, path);
            Err(unsupported())
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            ancestry(
                &bucket.inner.fs,
                bucket.root().parent().ok_or_else(unsupported)?,
                owner,
            )
            .await?;
            ancestry(
                &bucket.inner.fs,
                path.parent().ok_or_else(unsupported)?,
                owner,
            )
            .await?;
            let root = match bucket.inner.fs.symlink_metadata(bucket.root()).await {
                Ok(metadata) => Some(metadata),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(files::io_failure(error)),
            };
            let exists = match bucket.inner.fs.symlink_metadata(&path).await {
                Ok(_) => {
                    protected_directory(&bucket.inner.fs, &path, owner).await?;
                    true
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => return Err(files::io_failure(error)),
            };
            let registration = match bucket
                .inner
                .fs
                .symlink_metadata(&path.join("backend-registration.cbor"))
                .await
            {
                Ok(metadata) => {
                    protected_record(&metadata, owner)?;
                    true
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => return Err(files::io_failure(error)),
            };
            match root {
                Some(metadata)
                    if metadata.is_dir()
                        && !metadata.file_type().is_symlink()
                        && metadata.uid() == owner
                        && metadata.mode() & 0o022 == 0
                        && registration =>
                {
                    Ok(())
                }
                Some(_) => Err(unsupported()),
                None if exists => Err(unsupported()),
                None => Ok(()),
            }
        }
    }

    /// Opens or exclusively creates independently configured protected control.
    ///
    /// # Errors
    /// Rejects unconfigured ownership, noncanonical paths, unsafe ancestry,
    /// aliases, replaced nodes, unsupported primitives, and unavailable I/O.
    pub(super) async fn open<
        F: LocalFs + BucketBinding,
        C: Clock + BucketBinding,
        V: ContentValidator + BucketBinding,
    >(
        bucket: &FileBucket<F, C, V>,
        create: bool,
    ) -> Result<Self, StoreFailure> {
        let config = bucket
            .inner
            .config
            .publication_control
            .as_ref()
            .ok_or_else(unsupported)?;
        Self::open_config(&bucket.inner.fs, bucket.root(), config, create).await
    }

    /// Pins configured existing identities without constructing a writable bucket.
    ///
    /// # Errors
    /// Rejects unsafe configured paths, owners, nodes, aliases or unavailable I/O.
    pub(super) async fn open_existing_config<F: LocalFs + BucketBinding>(
        fs: &F,
        root: &Path,
        config: &FileBucketPublicationConfig,
    ) -> Result<Self, StoreFailure> {
        Self::open_config(fs, root, config, false).await
    }

    async fn open_config<F: LocalFs + BucketBinding>(
        fs: &F,
        root: &Path,
        config: &FileBucketPublicationConfig,
        create: bool,
    ) -> Result<Self, StoreFailure> {
        #[cfg(not(unix))]
        {
            let _ = (fs, root, config, create);
            Err(unsupported())
        }
        #[cfg(unix)]
        {
            use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};

            let (_, path) = Self::location(root, config)?;

            ancestry(fs, root, config.operator_uid).await?;
            ancestry(
                fs,
                path.parent().ok_or_else(unsupported)?,
                config.operator_uid,
            )
            .await?;
            let root_metadata = fs.symlink_metadata(root).await.map_err(files::io_failure)?;
            let lock_key = BucketKey::parse("CAPABILITIES").map_err(|_| corrupt())?;
            let coordination = root.join(lock_key.lock_name());
            ancestry(
                fs,
                coordination.parent().ok_or_else(unsupported)?,
                config.operator_uid,
            )
            .await?;
            let lock = fs
                .symlink_metadata(&coordination)
                .await
                .map_err(files::io_failure)?;
            if root_metadata.uid() != config.operator_uid
                || root_metadata.mode() & 0o022 != 0
                || !lock.is_file()
                || lock.file_type().is_symlink()
                || lock.uid() != config.operator_uid
                || lock.nlink() != 1
                || lock.mode() & 0o022 != 0
            {
                return Err(unsupported());
            }

            if create {
                fs.create_dir_new(&path).await.map_err(files::io_failure)?;
                fs.sync_directory(path.parent().ok_or_else(unsupported)?)
                    .await
                    .map_err(files::io_failure)?;
            }
            let metadata = protected_directory(fs, &path, config.operator_uid).await?;
            if identity(&metadata) == identity(&root_metadata) {
                return Err(unsupported());
            }
            Ok(Self {
                path,
                binding: BackendBinding::Local {
                    root: root.as_os_str().as_bytes().to_vec(),
                    root_device: root_metadata.dev(),
                    root_inode: root_metadata.ino(),
                    coordination_device: lock.dev(),
                    coordination_inode: lock.ino(),
                },
                owner: config.operator_uid,
                identity: identity(&metadata),
                root: root.to_path_buf(),
                coordination,
            })
        }
    }

    /// Holds the already-existing stable inode without creating coordination state.
    ///
    /// # Errors
    /// Refuses unavailable existing-only exclusion or any replaced physical binding.
    pub(super) async fn lock_existing<F: LocalFs + BucketBinding>(
        &self,
        fs: &F,
    ) -> Result<F::Lock, StoreFailure> {
        self.recheck(fs).await?;
        let held = fs
            .lock_existing_exclusive(&self.coordination)
            .await
            .map_err(files::io_failure)?;
        self.recheck(fs).await?;
        Ok(held)
    }

    /// Revalidates protected ancestry and every actual physical identity.
    ///
    /// # Errors
    /// Rejects changed roots, coordination inodes, owners, modes, or control
    /// directories and preserves unavailable metadata as a storage failure.
    pub(super) async fn recheck<F: LocalFs + BucketBinding>(
        &self,
        fs: &F,
    ) -> Result<(), StoreFailure> {
        #[cfg(not(unix))]
        {
            let _ = fs;
            Err(unsupported())
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            ancestries(
                fs,
                &[
                    &self.root,
                    self.path.parent().ok_or_else(unsupported)?,
                    self.coordination.parent().ok_or_else(unsupported)?,
                ],
                self.owner,
            )
            .await?;
            let root = fs
                .symlink_metadata(&self.root)
                .await
                .map_err(files::io_failure)?;
            let coordination = fs
                .symlink_metadata(&self.coordination)
                .await
                .map_err(files::io_failure)?;
            let BackendBinding::Local {
                root_device,
                root_inode,
                coordination_device,
                coordination_inode,
                ..
            } = &self.binding
            else {
                return Err(corrupt());
            };
            if !root.is_dir()
                || root.file_type().is_symlink()
                || root.uid() != self.owner
                || root.mode() & 0o022 != 0
                || identity(&root) != (*root_device, *root_inode)
                || !coordination.is_file()
                || coordination.file_type().is_symlink()
                || coordination.uid() != self.owner
                || coordination.nlink() != 1
                || coordination.mode() & 0o022 != 0
                || identity(&coordination) != (*coordination_device, *coordination_inode)
            {
                return Err(corrupt());
            }
            if identity(&protected_directory(fs, &self.path, self.owner).await?) != self.identity {
                return Err(corrupt());
            }
            Ok(())
        }
    }

    async fn parents<F: LocalFs + BucketBinding>(
        &self,
        fs: &F,
        key: &str,
        create: bool,
    ) -> Result<PathBuf, StoreFailure> {
        self.recheck(fs).await?;
        if !registered(key) {
            return Err(corrupt());
        }
        let mut path = self.path.clone();
        for part in Path::new(key).parent().ok_or_else(corrupt)?.components() {
            path.push(part);
            match fs.symlink_metadata(&path).await {
                Ok(_) => {}
                Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
                    fs.create_dir_new(&path).await.map_err(files::io_failure)?;
                    fs.sync_directory(path.parent().ok_or_else(corrupt)?)
                        .await
                        .map_err(files::io_failure)?;
                }
                Err(error) => return Err(files::io_failure(error)),
            }
            protected_directory(fs, &path, self.owner).await?;
        }
        Ok(path)
    }

    /// Reads one protected regular record through nofollow and rechecks its inode.
    ///
    /// # Errors
    /// Rejects unsafe or changed nodes and preserves unavailable reads as errors.
    /// Only exact `NotFound` returns absence.
    pub(super) async fn read<F: LocalFs + BucketBinding>(
        &self,
        fs: &F,
        key: &str,
    ) -> Result<Option<Vec<u8>>, StoreFailure> {
        self.recheck(fs).await?;
        let bytes = self.read_record(fs, key).await?;
        if bytes.is_some() {
            self.recheck(fs).await?;
        }
        Ok(bytes)
    }

    /// Returns the actual protected control incarnation checked on opening.
    pub(super) fn physical_identity(&self) -> (u64, u64) {
        self.identity
    }

    /// Retains exact protected bytes and metadata under complete physical checks.
    ///
    /// # Errors
    /// Rejects changed bindings or ancestry, malformed keys, unsafe or replaced
    /// record nodes, and unavailable exact reads.
    pub(super) async fn read_observed<F: LocalFs + BucketBinding>(
        &self,
        fs: &F,
        key: &str,
    ) -> Result<RecordRead, StoreFailure> {
        self.recheck(fs).await?;
        let read = self.read_record_observed(fs, key).await?;
        if read.bytes().is_some() {
            self.recheck(fs).await?;
        }
        Ok(read)
    }

    /// Starts read-only batching under a borrowed actual namespace exclusion.
    ///
    /// # Errors
    /// Rejects a different held namespace and changed physical or ancestry evidence.
    pub(super) async fn held_reads<'scope, F: LocalFs + BucketBinding>(
        &'scope self,
        fs: &'scope F,
        held: &'scope HeldIdentity<'scope>,
    ) -> Result<HeldReads<'scope, F>, StoreFailure> {
        let BackendBinding::Local {
            root_device,
            root_inode,
            coordination_device,
            coordination_inode,
            ..
        } = self.binding
        else {
            return Err(corrupt());
        };
        if held.root() != self.root
            || held.physical_identity()
                != (
                    (root_device, root_inode),
                    (coordination_device, coordination_inode),
                )
        {
            return Err(corrupt());
        }
        self.recheck(fs).await?;
        Ok(HeldReads {
            control: self,
            fs,
            _held: held,
        })
    }

    async fn read_record<F: LocalFs + BucketBinding>(
        &self,
        fs: &F,
        key: &str,
    ) -> Result<Option<Vec<u8>>, StoreFailure> {
        Ok(self.read_record_observed(fs, key).await?.into_bytes())
    }

    // Each record retains all protected-parent and inode checks. A held batch
    // checks the common physical ancestry before and after the whole resolution.
    async fn read_record_observed<F: LocalFs + BucketBinding>(
        &self,
        fs: &F,
        key: &str,
    ) -> Result<RecordRead, StoreFailure> {
        if !registered(key) {
            return Err(corrupt());
        }
        let path = self.path.join(key);
        let recipe = NativeProtectedRead::for_record(&self.path, key, self.owner);
        if let Some(record) = fs.read_protected_record(recipe).await? {
            let (bytes, metadata) = record.into_parts();
            return Ok(RecordRead::observed(path, bytes, metadata));
        }

        let mut parent = self.path.clone();
        let mut parents = Vec::new();
        for part in Path::new(key).parent().ok_or_else(corrupt)?.components() {
            parent.push(part);
            // The existence read and protected-directory read remain distinct
            // ordered observations, including their different missing results.
            parents.push(parent.clone());
            parents.push(parent.clone());
        }
        let observations = fs
            .symlink_metadata_batch(&parents)
            .await
            .map_err(files::io_failure)?;
        if observations.len() != parents.len() {
            return Err(corrupt());
        }
        let mut observations = observations.into_iter();
        while let Some(existence) = observations.next() {
            match existence {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(RecordRead::observed(path, None, None));
                }
                Err(error) => return Err(files::io_failure(error)),
                Ok(_) => {
                    let metadata = observations
                        .next()
                        .ok_or_else(corrupt)?
                        .map_err(files::io_failure)?;
                    check_protected_directory(&metadata, self.owner)?;
                }
            }
        }
        let before = match fs.symlink_metadata(&path).await {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(RecordRead::observed(path, None, None));
            }
            Err(error) => return Err(files::io_failure(error)),
            Ok(metadata) => metadata,
        };
        protected_record(&before, self.owner)?;
        let bytes = fs.read_nofollow(&path).await.map_err(files::io_failure)?;
        let after = fs
            .symlink_metadata(&path)
            .await
            .map_err(files::io_failure)?;
        protected_record(&after, self.owner)?;
        #[cfg(unix)]
        if identity(&before) != identity(&after) {
            return Err(corrupt());
        }
        Ok(RecordRead::observed(path, Some(bytes), Some(after)))
    }

    /// Durably installs one protected record without replacing immutable evidence.
    ///
    /// # Errors
    /// Rejects unsafe keys and nodes, and propagates durability failures. An error
    /// after installation is indeterminate and never converted into a lost CAS.
    pub(super) async fn install<F: LocalFs + BucketBinding>(
        &self,
        fs: &F,
        key: &str,
        bytes: &[u8],
        replace_registration: bool,
    ) -> Result<bool, StoreFailure> {
        self.install_record(fs, key, bytes, replace_registration)
            .await
    }

    async fn install_record<F: LocalFs + BucketBinding>(
        &self,
        fs: &F,
        key: &str,
        bytes: &[u8],
        replace_registration: bool,
    ) -> Result<bool, StoreFailure> {
        if replace_registration && key != "backend-registration.cbor" {
            return Err(corrupt());
        }
        let parent = self.parents(fs, key, true).await?;
        let entropy = fs.random_bytes(16).await.map_err(files::io_failure)?;
        if entropy.len() != 16 {
            return Err(unsupported());
        }
        let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
        let temporary = parent.join(format!(".terrane-tmp:{suffix}"));
        fs.write_new(&temporary, bytes)
            .await
            .map_err(files::io_failure)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs.set_permissions_and_sync(&temporary, std::fs::Permissions::from_mode(0o600))
                .await
                .map_err(files::io_failure)?;
        }
        #[cfg(not(unix))]
        return Err(unsupported());
        let metadata = fs
            .symlink_metadata(&temporary)
            .await
            .map_err(files::io_failure)?;
        protected_record(&metadata, self.owner)?;
        let result = if replace_registration {
            fs.rename(&temporary, &self.path.join(key)).await
        } else {
            fs.rename_no_replace(&temporary, &self.path.join(key)).await
        };
        match result {
            Ok(()) => {
                fs.sync_directory(&parent)
                    .await
                    .map_err(files::io_failure)?;
                self.recheck(fs).await?;
                Ok(true)
            }
            Err(error)
                if !replace_registration && error.kind() == std::io::ErrorKind::AlreadyExists =>
            {
                fs.remove_file(&temporary)
                    .await
                    .map_err(files::io_failure)?;
                fs.sync_directory(&parent)
                    .await
                    .map_err(files::io_failure)?;
                Ok(false)
            }
            Err(error) => Err(files::io_failure(error)),
        }
    }
}

fn registered(key: &str) -> bool {
    if matches!(key, "backend-registration.cbor" | "publication/ACTIVATION") {
        return true;
    }
    if let Some(value) = key.strip_prefix("publication/commits/") {
        return value
            .parse::<u64>()
            .is_ok_and(|revision| revision.to_string() == value);
    }
    [
        "publication/transactions/",
        "publication/lineage/",
        "publication/guards/",
    ]
    .iter()
    .any(|prefix| {
        key.strip_prefix(prefix).is_some_and(|suffix| {
            suffix.len() == 64
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    })
}

#[cfg(unix)]
async fn ancestry<F: LocalFs + BucketBinding>(
    fs: &F,
    path: &Path,
    owner: u32,
) -> Result<(), StoreFailure> {
    ancestries(fs, &[path], owner).await
}

/// Retains every ordered path and duplicate from consecutive physical walks.
#[cfg(unix)]
async fn ancestries<F: LocalFs + BucketBinding>(
    fs: &F,
    walks: &[&Path],
    owner: u32,
) -> Result<(), StoreFailure> {
    use std::os::unix::fs::MetadataExt;
    let mut paths = Vec::new();
    for walk in walks {
        let mut current = PathBuf::new();
        for part in walk.components() {
            current.push(part);
            paths.push(current.clone());
        }
    }
    let observations = fs
        .symlink_metadata_batch(&paths)
        .await
        .map_err(files::io_failure)?;
    if observations.len() != paths.len() {
        return Err(corrupt());
    }

    // Every path and duplicate retains its original result position. An earlier
    // unsafe ancestor must be rejected before a later path's metadata failure.
    for observation in observations {
        let metadata = observation.map_err(files::io_failure)?;
        let protected_sticky = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || !matches!(metadata.uid(), 0) && metadata.uid() != owner
            || metadata.mode() & 0o022 != 0 && !protected_sticky
        {
            return Err(unsupported());
        }
    }
    Ok(())
}

async fn protected_directory<F: LocalFs + BucketBinding>(
    fs: &F,
    path: &Path,
    owner: u32,
) -> Result<std::fs::Metadata, StoreFailure> {
    let metadata = fs.symlink_metadata(path).await.map_err(files::io_failure)?;
    check_protected_directory(&metadata, owner)?;
    Ok(metadata)
}

fn check_protected_directory(metadata: &std::fs::Metadata, owner: u32) -> Result<(), StoreFailure> {
    crate::store::protected_read::check_directory(metadata, owner)
}

fn protected_record(metadata: &std::fs::Metadata, owner: u32) -> Result<(), StoreFailure> {
    crate::store::protected_read::check_record(metadata, owner)
}

#[cfg(all(test, feature = "tokio", unix))]
mod tests;
