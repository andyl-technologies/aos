//! Retains protected administrative exclusion beneath an already held backend.
//!
//! This synchronization witness grants no repository authority. Native original
//! verification and selected publication use its actual path and inode checks.
//! Shared read exclusion and exclusive writer exclusion are chosen before
//! nonblocking acquisition. The lock remains owned until the complete checked
//! operation has finished, including every retained native duplicate.

use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use crate::bucket::BucketBinding;
use crate::store::{LocalFs, StoreFailure};

use super::{invalid, io_failure, protected_file};

/// Owns duplicates and exact records captured under genuine administrative exclusion.
///
/// This physical receipt establishes no actor or publication authority. Only the
/// checked producer combines it with actual selected state and request evidence.
/// Cloning retains the same acquired native exclusions and original observations;
/// it neither acquires a new lock nor refreshes physical or semantic authority.
#[derive(Clone)]
pub(crate) struct RetainedControls {
    exclusions: std::sync::Arc<[crate::store::NativeExclusion]>,
    directory: PathBuf,
    owner: u32,
    directory_identity: (u64, u64),
    lock_identity: (u64, u64),
    ancestors: Vec<RetainedControlAncestor>,
    records: Vec<RetainedControlRecord>,
}

/// Preserves the checked incarnation and protection of a control ancestor.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RetainedControlAncestor {
    path: PathBuf,
    identity: (u64, u64),
    owner: u32,
    mode: u32,
}

impl RetainedControlAncestor {
    /// Returns the actual ancestor name traversed under exclusion.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the captured ancestor incarnation.
    pub(crate) fn identity(&self) -> (u64, u64) {
        self.identity
    }

    /// Returns the actual ancestor owner and permission bits.
    pub(crate) fn protection(&self) -> (u32, u32) {
        (self.owner, self.mode)
    }
}

/// Preserves one exact canonical control read and its checked named incarnation.
#[derive(Clone)]
pub(crate) struct RetainedControlRecord {
    path: PathBuf,
    identity: (u64, u64),
    bytes: Vec<u8>,
}

impl RetainedControlRecord {
    /// Returns the exact protected record name observed under exclusion.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the checked device and inode of the named canonical record.
    pub(crate) fn identity(&self) -> (u64, u64) {
        self.identity
    }

    /// Returns the complete canonical bytes consumed by the genuine resolver.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl RetainedControls {
    /// Rechecks every exact consumed control under its already retained exclusion.
    ///
    /// # Errors
    /// Rejects unavailable retention, replaced or unsafe ancestors/directory/lock,
    /// changed record identities or bytes and underlying nofollow read failures.
    pub(crate) async fn revalidate<F: LocalFs + BucketBinding>(
        &self,
        fs: &F,
    ) -> Result<(), StoreFailure> {
        let mut controls =
            OriginalControls::retained(fs, &self.directory, self.owner, self).await?;
        for record in &self.records {
            let selector = record
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(invalid)?;
            controls.read_record(selector).await?;
        }
        controls.revalidate().await
    }

    /// Retains the actual already duplicated exclusion in the submitted worker.
    pub(crate) fn exclusions(&self) -> std::sync::Arc<[crate::store::NativeExclusion]> {
        std::sync::Arc::clone(&self.exclusions)
    }

    /// Returns the actual protected configuration directory.
    pub(crate) fn directory(&self) -> &Path {
        &self.directory
    }

    /// Returns the independently configured operator checked for these controls.
    pub(crate) fn owner(&self) -> u32 {
        self.owner
    }

    /// Returns the checked directory and coordination incarnations.
    pub(crate) fn identities(&self) -> ((u64, u64), (u64, u64)) {
        (self.directory_identity, self.lock_identity)
    }

    /// Returns every exact canonical record consumed under this control exclusion.
    pub(crate) fn records(&self) -> &[RetainedControlRecord] {
        &self.records
    }

    /// Returns every protected ancestor traversed by the actual control receipt.
    pub(crate) fn ancestors(&self) -> &[RetainedControlAncestor] {
        &self.ancestors
    }
}

/// Selects administrative access before acquiring the stable control inode.
#[derive(Clone, Copy)]
pub(super) enum ControlAccess {
    /// Preserves exact records for verification without admitting a writer.
    Read,
    /// Excludes every reader and writer before installing protected records.
    Write,
}

/// Holds one protected control directory and its stable coordination inode.
pub(crate) struct ControlExclusion<'a, F: LocalFs> {
    fs: &'a F,
    directory: PathBuf,
    owner: u32,
    directory_identity: (u64, u64),
    lock_identity: (u64, u64),
    _lock: F::Lock,
    #[cfg(test)]
    _trace: crate::ref_advance::NativeTrace,
}

impl<'a, F: LocalFs + BucketBinding> ControlExclusion<'a, F> {
    /// Retains actual exclusion and canonical pins from the finished local resolver.
    ///
    /// # Errors
    /// Refuses unsupported descriptor retention, changed canonical record bytes,
    /// replaced identities or unsafe control metadata and ancestors.
    pub(crate) async fn retain_used(
        &mut self,
        pins: &[terrane_format::gc::publication::evidence::RequiredControlPin],
    ) -> Result<RetainedControls, StoreFailure> {
        let mut expected = Vec::with_capacity(pins.len());
        for pin in pins {
            let bytes = self.read_record(&pin.key).await?;
            pin.check_record(&bytes).map_err(|_| invalid())?;
            expected.push((pin.key.clone(), bytes));
        }
        self.retain_named(&expected).await
    }

    /// Retains exact checked administrative records without assigning a pin kind.
    ///
    /// Dedicated disclosure-role configuration has no registered control-pin
    /// variant. Its checked producer supplies exact canonical bytes here solely
    /// to retain physical exclusion and detect replacement in the native worker.
    /// This receipt establishes no role, actor or repository authority.
    ///
    /// # Errors
    /// Rejects duplicate names, differing bytes, replaced records or ancestors,
    /// unsafe protection and unsupported native descriptor retention.
    pub(crate) async fn retain_named(
        &mut self,
        expected: &[(String, Vec<u8>)],
    ) -> Result<RetainedControls, StoreFailure> {
        self.revalidate().await?;
        let ancestors = self.capture_ancestors().await?;
        let exclusion = self
            .fs
            .retain_native_exclusion(&self._lock)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::Unsupported {
                    crate::store::StoreFailure::with_source(
                        crate::store::StoreErrorKind::Unsupported,
                        error,
                    )
                } else {
                    io_failure(error)
                }
            })?;

        let mut names = std::collections::BTreeSet::new();
        let mut records = Vec::with_capacity(expected.len());
        for (key, expected_bytes) in expected {
            if !names.insert(key) {
                return Err(invalid());
            }
            let path = self.record_path(key)?;
            let identity = protected_file(self.fs, &path, self.owner).await?;
            let bytes = self.read_record(key).await?;
            if bytes != *expected_bytes {
                return Err(invalid());
            }
            if protected_file(self.fs, &path, self.owner).await? != identity {
                return Err(invalid());
            }
            records.push(RetainedControlRecord {
                path,
                identity,
                bytes,
            });
        }
        self.revalidate().await?;
        if self.capture_ancestors().await? != ancestors {
            return Err(invalid());
        }
        Ok(RetainedControls {
            exclusions: vec![exclusion].into(),
            directory: self.directory.clone(),
            owner: self.owner,
            directory_identity: self.directory_identity,
            lock_identity: self.lock_identity,
            ancestors,
            records,
        })
    }

    async fn capture_ancestors(&mut self) -> Result<Vec<RetainedControlAncestor>, StoreFailure> {
        let mut path = PathBuf::new();
        let mut paths = Vec::new();
        for part in self.directory.components() {
            path.push(part);
            paths.push(path.clone());
        }
        let observations = self
            .fs
            .symlink_metadata_batch(&paths)
            .await
            .map_err(io_failure)?;
        if observations.len() != paths.len() {
            return Err(invalid());
        }
        paths
            .into_iter()
            .zip(observations)
            .map(|(path, metadata)| {
                let metadata = metadata.map_err(io_failure)?;
                let sticky_root = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
                if !metadata.is_dir()
                    || metadata.file_type().is_symlink()
                    || metadata.uid() != 0 && metadata.uid() != self.owner
                    || metadata.mode() & 0o022 != 0 && !sticky_root
                {
                    return Err(invalid());
                }
                Ok(RetainedControlAncestor {
                    path,
                    identity: (metadata.dev(), metadata.ino()),
                    owner: metadata.uid(),
                    mode: metadata.mode() & 0o7777,
                })
            })
            .collect()
    }

    /// Acquires actual administrative exclusion after backend exclusion.
    ///
    /// Access is chosen before acquisition. Contention returns immediately so
    /// callers release backend exclusion instead of waiting on retained controls.
    ///
    /// # Errors
    /// Rejects unprotected paths, replaced coordination or directory inodes,
    /// owner or mode changes, unsupported acquisition, busy controls and unavailable
    /// filesystem observations.
    pub(super) async fn acquire(
        fs: &'a F,
        directory: &Path,
        owner: u32,
        access: ControlAccess,
    ) -> Result<Self, StoreFailure> {
        let mut ancestor = PathBuf::new();
        for part in directory.components() {
            ancestor.push(part);
            let metadata = fs.symlink_metadata(&ancestor).await.map_err(io_failure)?;
            let protected_sticky = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != 0 && metadata.uid() != owner
                || metadata.mode() & 0o022 != 0 && !protected_sticky
            {
                return Err(invalid());
            }
        }

        let metadata = fs.symlink_metadata(directory).await.map_err(io_failure)?;
        if metadata.uid() != owner || metadata.mode() & 0o777 != 0o700 {
            return Err(invalid());
        }

        let directory_identity = (metadata.dev(), metadata.ino());
        let lock_path = directory.join("retention.lock");
        let lock_identity = protected_file(fs, &lock_path, owner).await?;
        #[cfg(test)]
        let trace = crate::ref_advance::NativeTrace::new(&lock_path, "original-control-acquire");
        let lock = match access {
            ControlAccess::Read => fs.try_lock_existing_shared(&lock_path).await,
            ControlAccess::Write => fs.try_lock_existing_exclusive(&lock_path).await,
        }
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::Unsupported {
                StoreFailure::with_source(crate::store::StoreErrorKind::Unsupported, error)
            } else {
                io_failure(error)
            }
        })?;

        #[cfg(test)]
        trace.mark("actual-control-lock-acquired");
        let mut held = Self {
            fs,
            directory: directory.to_path_buf(),
            owner,
            directory_identity,
            lock_identity,
            _lock: lock,
            #[cfg(test)]
            _trace: trace,
        };
        held.revalidate().await?;
        Ok(held)
    }

    /// Reads one exact protected administrative record without releasing exclusion.
    ///
    /// # Errors
    /// Rejects non-leaf selectors, unsafe file metadata, replaced records or
    /// control paths, and unavailable no-follow reads.
    pub(crate) async fn read_record(&mut self, selector: &str) -> Result<Vec<u8>, StoreFailure> {
        let path = self.record_path(selector)?;

        self.revalidate().await?;
        let identity = protected_file(self.fs, &path, self.owner).await?;
        let bytes = self.fs.read_nofollow(&path).await.map_err(io_failure)?;
        if protected_file(self.fs, &path, self.owner).await? != identity {
            return Err(invalid());
        }

        self.revalidate().await?;
        Ok(bytes)
    }

    fn record_path(&self, selector: &str) -> Result<PathBuf, StoreFailure> {
        let mut components = Path::new(selector).components();
        if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
            return Err(invalid());
        }
        Ok(self.directory.join(selector))
    }

    /// Rechecks the actual protected paths while retaining their exclusion.
    ///
    /// # Errors
    /// Rejects directory replacement, symlink ancestors, owner or mode changes,
    /// replaced coordination, and unavailable filesystem observations.
    pub(crate) async fn revalidate(&mut self) -> Result<(), StoreFailure> {
        // Keep every fresh ancestor observation in its original path order;
        // batching avoids a separate filesystem dispatch for each ancestor.
        self.capture_ancestors().await?;

        let metadata = self
            .fs
            .symlink_metadata(&self.directory)
            .await
            .map_err(io_failure)?;
        if metadata.uid() != self.owner
            || metadata.mode() & 0o777 != 0o700
            || (metadata.dev(), metadata.ino()) != self.directory_identity
            || protected_file(self.fs, &self.directory.join("retention.lock"), self.owner).await?
                != self.lock_identity
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Reads exact Original controls under either acquired or genuine retained exclusion.
/// Neither branch creates semantic authority; the native binder checks configured
/// owner/backend/registration independently before consuming these reads.
pub(super) enum OriginalControls<'a, F: LocalFs> {
    /// Owns the ordinary freshly acquired administrative exclusion.
    Acquired(ControlExclusion<'a, F>),
    /// Borrows the genuine retained administrative exclusion and captured records.
    Retained {
        /// Actual binding used for fresh nofollow physical observations.
        fs: &'a F,
        /// Same acquired exclusion with original record and incarnation evidence.
        receipt: &'a RetainedControls,
    },
}

impl<'a, F: LocalFs + BucketBinding> OriginalControls<'a, F> {
    /// Acquires ordinary protected exclusion for callers without a retained receipt.
    ///
    /// # Errors
    /// Preserves unsafe paths, replaced identities and acquisition failures.
    pub(super) async fn acquire(
        fs: &'a F,
        directory: &Path,
        owner: u32,
    ) -> Result<Self, StoreFailure> {
        Ok(Self::Acquired(
            ControlExclusion::acquire(fs, directory, owner, ControlAccess::Read).await?,
        ))
    }

    /// Reuses real same-directory exclusion with independently configured ownership.
    ///
    /// # Errors
    /// Refuses another directory/owner, empty exclusions and changed physical controls.
    pub(super) async fn retained(
        fs: &'a F,
        directory: &Path,
        owner: u32,
        receipt: &'a RetainedControls,
    ) -> Result<Self, StoreFailure> {
        if receipt.directory != directory || receipt.owner != owner || receipt.exclusions.is_empty()
        {
            return Err(invalid());
        }
        let mut result = Self::Retained { fs, receipt };
        result.revalidate().await?;
        Ok(result)
    }

    /// Rechecks actual retained physical paths without acquiring another lock.
    ///
    /// # Errors
    /// Refuses replaced ancestors, directory/lock identities or unsafe protection.
    pub(super) async fn revalidate(&mut self) -> Result<(), StoreFailure> {
        match self {
            Self::Acquired(acquired) => acquired.revalidate().await,
            Self::Retained { fs, receipt } => {
                for ancestor in &receipt.ancestors {
                    let metadata = fs
                        .symlink_metadata(&ancestor.path)
                        .await
                        .map_err(io_failure)?;
                    if !metadata.is_dir()
                        || metadata.file_type().is_symlink()
                        || (metadata.dev(), metadata.ino()) != ancestor.identity
                        || metadata.uid() != ancestor.owner
                        || metadata.mode() & 0o7777 != ancestor.mode
                    {
                        return Err(invalid());
                    }
                }
                let metadata = fs
                    .symlink_metadata(&receipt.directory)
                    .await
                    .map_err(io_failure)?;
                if !metadata.is_dir()
                    || metadata.file_type().is_symlink()
                    || metadata.uid() != receipt.owner
                    || metadata.mode() & 0o777 != 0o700
                    || (metadata.dev(), metadata.ino()) != receipt.directory_identity
                    || protected_file(
                        *fs,
                        &receipt.directory.join("retention.lock"),
                        receipt.owner,
                    )
                    .await?
                        != receipt.lock_identity
                {
                    return Err(invalid());
                }
                Ok(())
            }
        }
    }

    /// Reads the actual exact protected record covered by the retained receipt.
    ///
    /// # Errors
    /// Refuses missing captured records, unsafe selectors, changed bytes or incarnations.
    pub(super) async fn read_record(&mut self, selector: &str) -> Result<Vec<u8>, StoreFailure> {
        self.revalidate().await?;
        let bytes = match self {
            Self::Acquired(acquired) => acquired.read_record(selector).await?,
            Self::Retained { fs, receipt } => {
                let mut components = Path::new(selector).components();
                if !matches!(components.next(), Some(Component::Normal(_)))
                    || components.next().is_some()
                {
                    return Err(invalid());
                }
                let path = receipt.directory.join(selector);
                let record = receipt
                    .records
                    .iter()
                    .find(|record| record.path == path)
                    .ok_or_else(invalid)?;
                if protected_file(*fs, &path, receipt.owner).await? != record.identity {
                    return Err(invalid());
                }
                let bytes = fs.read_nofollow(&path).await.map_err(io_failure)?;
                if bytes != record.bytes
                    || protected_file(*fs, &path, receipt.owner).await? != record.identity
                {
                    return Err(invalid());
                }
                bytes
            }
        };
        self.revalidate().await?;
        Ok(bytes)
    }
}

#[cfg(all(test, feature = "tokio"))]
mod lock_mode_tests;
