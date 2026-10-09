//! Provides stable exclusion and durable conditional filesystem installation.

use super::publication::receipts::RecordRead;
use super::{BucketBinding, FileBucket};
use crate::store::{
    Clock, ContentValidator, CorruptSubject, InvalidReason, LocalFs, StoreErrorKind, StoreFailure,
};
use std::path::{Path, PathBuf};
use terrane_core::bucket::{BucketKey, Mutability};

pub(super) fn io_failure(error: std::io::Error) -> StoreFailure {
    let kind = match error.kind() {
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ReadOnlyFilesystem => {
            StoreErrorKind::ReadOnly
        }
        std::io::ErrorKind::StorageFull => StoreErrorKind::Capacity,
        std::io::ErrorKind::Unsupported => StoreErrorKind::Unsupported,
        _ => StoreErrorKind::Unavailable { retry_after: None },
    };
    StoreFailure::with_source(kind, error)
}

pub(super) fn malformed() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Invalid(InvalidReason::MalformedRequest))
}

pub(super) fn layout_corrupt() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Corrupt(CorruptSubject::RefName(
        "CAPABILITIES".into(),
    )))
}

impl<F: LocalFs + BucketBinding, C: Clock + BucketBinding, V: ContentValidator + BucketBinding>
    FileBucket<F, C, V>
{
    /// Requires an existing real directory rather than a symlink or other node.
    ///
    /// # Errors
    /// Returns corruption for an incompatible node and propagates metadata failures.
    pub(super) async fn check_directory(&self, path: &Path) -> Result<(), StoreFailure> {
        let metadata = self
            .inner
            .fs
            .symlink_metadata(path)
            .await
            .map_err(io_failure)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(layout_corrupt());
        }
        Ok(())
    }

    /// Checks physical cache nodes without using their bytes as selected values.
    ///
    /// # Errors
    /// Rejects symlinked ancestors and nonregular present payload nodes while
    /// preserving exact absence and unavailable metadata as distinct outcomes.
    /// Rejects incomplete metadata batches before observing a payload leaf.
    ///
    /// # Panics
    /// Test builds can panic if enabled phase diagnostics cannot write to stderr.
    pub(super) async fn check_payload_namespace(
        &self,
        key: &BucketKey,
    ) -> Result<(), StoreFailure> {
        #[cfg(test)]
        let mut trace = crate::ref_advance::PhaseTrace::new(
            &self.inner.clock,
            key.as_str(),
            None,
            None,
            "payload-namespace-start",
        );
        let mut path = self.inner.config.root.clone();
        self.check_directory(&path).await?;
        #[cfg(test)]
        trace.mark("payload-namespace-root-checked");
        let relative = Path::new(key.as_str()).parent().ok_or_else(malformed)?;
        let mut parents = Vec::new();
        for part in relative.components() {
            path.push(part);
            parents.push(path.clone());
        }

        if !parents.is_empty() {
            #[cfg(test)]
            trace.mark("payload-namespace-ancestor-batch-submitted");
            let observations = self
                .inner
                .fs
                .symlink_metadata_batch(&parents)
                .await
                .map_err(io_failure)?;
            #[cfg(test)]
            trace.mark("payload-namespace-ancestor-batch-returned");
            if observations.len() != parents.len() {
                return Err(layout_corrupt());
            }
            // Batch dispatch is not an atomic observation. Classify every
            // ancestor in order before asking for any payload leaf metadata.
            for observation in observations {
                match observation {
                    Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
                    Ok(_) => return Err(layout_corrupt()),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                    Err(error) => return Err(io_failure(error)),
                }
            }
        }

        #[cfg(test)]
        trace.mark("payload-namespace-ancestors-classified");
        #[cfg(test)]
        trace.mark("payload-namespace-leaf-metadata-submitted");
        let observation = self.inner.fs.symlink_metadata(&self.path(key)).await;
        #[cfg(test)]
        trace.mark("payload-namespace-leaf-metadata-returned");
        match observation {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(()),
            Ok(_) => Err(layout_corrupt()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io_failure(error)),
        }
    }

    async fn parents(&self, key: &BucketKey) -> Result<PathBuf, StoreFailure> {
        let mut path = self.inner.config.root.clone();
        self.check_directory(&path).await?;
        let relative = Path::new(key.as_str()).parent().ok_or_else(malformed)?;
        for part in relative.components() {
            path.push(part);
            match self.inner.fs.symlink_metadata(&path).await {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
                Ok(_) => return Err(layout_corrupt()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    self.inner
                        .fs
                        .create_dir_all(&path)
                        .await
                        .map_err(io_failure)?;
                    self.check_directory(&path).await?;
                    let parent = path.parent().ok_or_else(malformed)?;
                    self.inner
                        .fs
                        .sync_directory(parent)
                        .await
                        .map_err(io_failure)?;
                }
                Err(error) => return Err(io_failure(error)),
            }
        }
        Ok(path)
    }

    /// Acquires the stable exclusion inode shared by all bucket mutations.
    ///
    /// # Errors
    /// Rejects unsafe coordination paths and propagates unavailable lock or
    /// synchronization primitives. The inode is never unlinked or replaced.
    pub(super) async fn exclusive(&self) -> Result<F::Lock, StoreFailure> {
        if self.inner.access.read_only() {
            return Err(StoreFailure::new(StoreErrorKind::ReadOnly));
        }
        let locks = self.inner.config.root.join(".terrane-locks");
        match self.inner.fs.create_dir_new(&locks).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(io_failure(error)),
        }
        self.check_directory(&locks).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            let operator = self
                .publication_operator_uid()
                .ok_or_else(|| StoreFailure::new(StoreErrorKind::Unsupported))?;
            let metadata = self
                .inner
                .fs
                .symlink_metadata(&locks)
                .await
                .map_err(io_failure)?;
            if metadata.uid() != operator || metadata.mode() & 0o022 != 0 {
                return Err(StoreFailure::new(StoreErrorKind::Unsupported));
            }
        }
        let key = BucketKey::parse("CAPABILITIES").map_err(|_| malformed())?;
        let path = self.inner.config.root.join(key.lock_name());
        match self.inner.fs.symlink_metadata(&path).await {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Err(layout_corrupt()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_failure(error)),
        }
        // Never unlink or replace this inode, including after crashes. Every
        // process must lock the same inode before observing the condition.
        let guard = self
            .inner
            .fs
            .lock_exclusive(&path)
            .await
            .map_err(io_failure)?;
        self.inner
            .fs
            .sync_directory(&self.inner.config.root)
            .await
            .map_err(io_failure)?;
        self.inner
            .fs
            .sync_directory(&locks)
            .await
            .map_err(io_failure)?;
        Ok(guard)
    }

    /// Holds an already registered namespace without creating or syncing nodes.
    ///
    /// # Errors
    /// Refuses missing existing-only locking, unsafe configured ownership or
    /// coordination directories, and changed protected namespace admission.
    pub(super) async fn existing_exclusive(&self) -> Result<F::Lock, StoreFailure> {
        if self.inner.access.read_only() {
            return Err(StoreFailure::new(StoreErrorKind::ReadOnly));
        }
        self.preflight_publication_namespace().await?;
        let locks = self.inner.config.root.join(".terrane-locks");
        self.check_directory(&locks).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            let operator = self
                .publication_operator_uid()
                .ok_or_else(|| StoreFailure::new(StoreErrorKind::Unsupported))?;
            let metadata = self
                .inner
                .fs
                .symlink_metadata(&locks)
                .await
                .map_err(io_failure)?;
            if metadata.uid() != operator || metadata.mode() & 0o022 != 0 {
                return Err(StoreFailure::new(StoreErrorKind::Unsupported));
            }
        }
        let key = BucketKey::parse("CAPABILITIES").map_err(|_| malformed())?;
        let guard = self
            .inner
            .fs
            .lock_existing_exclusive(&self.inner.config.root.join(key.lock_name()))
            .await
            .map_err(io_failure)?;
        self.preflight_publication_namespace().await?;
        Ok(guard)
    }

    /// Returns exact registered bytes without retaining read data beyond the call.
    ///
    /// # Errors
    /// Preserves all parent, leaf, incarnation and binding read failures.
    pub(super) async fn read_optional(
        &self,
        key: &BucketKey,
    ) -> Result<Option<Vec<u8>>, StoreFailure> {
        Ok(self.read_optional_observed(key).await?.into_bytes())
    }

    /// Retains original physical ancestry before consuming a payload value.
    ///
    /// # Errors
    /// Refuses unsafe or unavailable original ancestors, payload observations
    /// and any change found by the complete closing physical check.
    pub(super) async fn read_optional_retained(
        &self,
        key: &BucketKey,
    ) -> Result<RecordRead, StoreFailure> {
        let capture = crate::store::native_publication_effects::PayloadReadCapture::capture(
            &self.inner.fs,
            &self.path(key),
            self.publication_operator_uid().ok_or_else(layout_corrupt)?,
        )
        .await?;
        let observed = self.read_optional_observed(key).await?;
        let retained = capture.finish(&observed)?;
        retained.revalidate(&self.inner.fs).await?;
        Ok(observed.with_retained_payload(retained))
    }

    /// Reads a registered regular file while rejecting symlinked layout nodes.
    ///
    /// # Errors
    /// Returns corruption for incompatible nodes and propagates read failures;
    /// a missing registered key returns `None`.
    ///
    /// # Panics
    /// Test builds can panic if enabled phase diagnostics cannot write to stderr.
    pub(super) async fn read_optional_observed(
        &self,
        key: &BucketKey,
    ) -> Result<RecordRead, StoreFailure> {
        #[cfg(test)]
        let mut trace = crate::ref_advance::PhaseTrace::new(
            &self.inner.clock,
            key.as_str(),
            None,
            None,
            "ordinary-record-start",
        );
        let path = self.path(key);
        let mut parent = self.inner.config.root.clone();
        let relative = Path::new(key.as_str()).parent().ok_or_else(malformed)?;
        let mut parents = Vec::new();
        for part in relative.components() {
            parent.push(part);
            parents.push(parent.clone());
        }
        #[cfg(test)]
        trace.mark("ordinary-record-ancestor-batch-submitted");
        let observations = self
            .inner
            .fs
            .symlink_metadata_batch(&parents)
            .await
            .map_err(io_failure)?;
        #[cfg(test)]
        trace.mark("ordinary-record-ancestor-batch-returned");
        if observations.len() != parents.len() {
            return Err(layout_corrupt());
        }
        for observation in observations {
            match observation {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
                Ok(_) => return Err(layout_corrupt()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(RecordRead::observed(path, None, None));
                }
                Err(error) => return Err(io_failure(error)),
            }
        }
        #[cfg(test)]
        trace.mark("ordinary-record-ancestors-classified");
        #[cfg(test)]
        trace.mark("ordinary-record-native-leaf-submitted");
        let record = self
            .inner
            .fs
            .read_ordinary_record(crate::store::NativeOrdinaryRead::for_leaf(&path))
            .await
            .map_err(io_failure)?;
        #[cfg(test)]
        trace.mark("ordinary-record-native-leaf-returned");
        if let Some(record) = record {
            match record.into_outcome() {
                #[cfg(all(feature = "tokio", unix))]
                crate::store::OrdinaryReadOutcome::ProjectionChecked => {
                    return Err(StoreFailure::new(StoreErrorKind::Unsupported));
                }
                #[cfg(all(feature = "tokio", unix))]
                crate::store::OrdinaryReadOutcome::Absent => {
                    return Ok(RecordRead::observed(path, None, None));
                }
                #[cfg(all(feature = "tokio", unix))]
                crate::store::OrdinaryReadOutcome::Present(bytes, metadata) => {
                    return Ok(RecordRead::observed(path, Some(bytes), Some(metadata)));
                }
                #[cfg(all(feature = "tokio", unix))]
                crate::store::OrdinaryReadOutcome::InvalidLayout => return Err(layout_corrupt()),
            }
        }
        let before = match self.inner.fs.symlink_metadata(&path).await {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => metadata,
            Ok(_) => return Err(layout_corrupt()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(RecordRead::observed(path, None, None));
            }
            Err(error) => return Err(io_failure(error)),
        };
        match self.inner.fs.read_nofollow(&path).await {
            Ok(bytes) => {
                let after = self
                    .inner
                    .fs
                    .symlink_metadata(&path)
                    .await
                    .map_err(io_failure)?;
                if !after.is_file() || after.file_type().is_symlink() {
                    return Err(layout_corrupt());
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
                        return Err(layout_corrupt());
                    }
                }
                #[cfg(not(unix))]
                let _ = before;
                Ok(RecordRead::observed(path, Some(bytes), Some(after)))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(RecordRead::observed(path, None, None))
            }
            Err(error) => Err(io_failure(error)),
        }
    }

    /// Syncs a private sibling and atomically installs it before syncing the directory.
    ///
    /// # Errors
    /// Rejects replacement of non-CAS keys and unsupported entropy bindings, and
    /// propagates filesystem failures. A failure after rename can leave the new
    /// bytes visible, so callers must not infer a rejected conditional outcome.
    pub(super) async fn install(
        &self,
        key: &BucketKey,
        bytes: &[u8],
        replace: bool,
    ) -> Result<bool, StoreFailure> {
        if replace && key.mutability() != Mutability::CompareAndSwap {
            return Err(malformed());
        }
        let parent = self.parents(key).await?;
        let entropy = self.inner.fs.random_bytes(16).await.map_err(io_failure)?;
        if entropy.len() != 16 {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
        let temporary = parent.join(format!(".terrane-tmp:{suffix}"));
        self.inner
            .fs
            .write_new(&temporary, bytes)
            .await
            .map_err(io_failure)?;
        self.inner
            .fs
            .sync_file(&temporary)
            .await
            .map_err(io_failure)?;
        let destination = self.path(key);
        let installed = if replace {
            self.inner.fs.rename(&temporary, &destination).await
        } else {
            self.inner
                .fs
                .rename_no_replace(&temporary, &destination)
                .await
        };
        match installed {
            Ok(()) => {
                self.inner
                    .fs
                    .sync_directory(&parent)
                    .await
                    .map_err(io_failure)?;
                Ok(true)
            }
            Err(error) if !replace && error.kind() == std::io::ErrorKind::AlreadyExists => {
                self.inner
                    .fs
                    .remove_file(&temporary)
                    .await
                    .map_err(io_failure)?;
                self.inner
                    .fs
                    .sync_directory(&parent)
                    .await
                    .map_err(io_failure)?;
                Ok(false)
            }
            Err(error) => Err(io_failure(error)),
        }
    }

    // The caller owns the exclusion guard across this comparison and the
    // installation's directory sync. Conditions compare bytes, never hashes
    // or interpretations of provider version tokens.
    /// Compares complete opaque bytes and installs a conditional replacement.
    ///
    /// # Errors
    /// Propagates invalid layout and filesystem failures. Callers hold stable
    /// exclusion across this method and its final directory synchronization.
    pub(super) async fn replace_conditionally(
        &self,
        key: &BucketKey,
        expected: Option<&[u8]>,
        new: &[u8],
    ) -> Result<bool, StoreFailure> {
        if key.mutability() != Mutability::CompareAndSwap {
            return Err(malformed());
        }
        let current = self.read_optional(key).await?;
        if current.as_deref() != expected {
            return Ok(false);
        }
        self.install(key, new, current.is_some()).await
    }
}

#[cfg(all(test, feature = "tokio", unix))]
mod payload_namespace_tests;
