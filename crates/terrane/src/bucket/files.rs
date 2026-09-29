//! Provides stable exclusion and durable conditional filesystem installation.

use super::{BucketBinding, FileBucket};
use crate::store::{
    Clock, ContentValidator, CorruptSubject, InvalidReason, LocalFs, StoreErrorKind, StoreFailure,
};
use std::path::{Path, PathBuf};
use terrane_core::bucket::{BucketKey, Mutability};

pub(super) fn io_failure(error: std::io::Error) -> StoreFailure {
    let kind = match error.kind() {
        std::io::ErrorKind::PermissionDenied => StoreErrorKind::ReadOnly,
        std::io::ErrorKind::StorageFull => StoreErrorKind::Capacity,
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

    pub(super) async fn exclusive(&self) -> Result<F::Lock, StoreFailure> {
        let locks = self.inner.config.root.join(".terrane-locks");
        self.inner
            .fs
            .create_dir_all(&locks)
            .await
            .map_err(io_failure)?;
        self.check_directory(&locks).await?;
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

    pub(super) async fn read_optional(
        &self,
        key: &BucketKey,
    ) -> Result<Option<Vec<u8>>, StoreFailure> {
        let path = self.path(key);
        let mut parent = self.inner.config.root.clone();
        let relative = Path::new(key.as_str()).parent().ok_or_else(malformed)?;
        for part in relative.components() {
            parent.push(part);
            match self.inner.fs.symlink_metadata(&parent).await {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
                Ok(_) => return Err(layout_corrupt()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(io_failure(error)),
            }
        }
        match self.inner.fs.symlink_metadata(&path).await {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Err(layout_corrupt()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_failure(error)),
        }
        match self.inner.fs.read(&path).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(io_failure(error)),
        }
    }

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
