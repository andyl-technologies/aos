//! Routes initializer I/O through immediate worker reads or retained effects.
//!
//! These private bindings reject scalar mutations. The native creator runs all
//! immediate futures on its submitted worker; later activation preserves the
//! configured binding's read and fault interception while retaining the original
//! opened-directory receipts inside every submitted physical command.

#[cfg(all(test, feature = "tokio", unix))]
#[path = "initializer_faults.rs"]
pub(super) mod initializer_faults;

use super::super::super::super::{
    NativeEffectFailure, NativeExclusion, NativeFsEffect, NativeOpenedDirectory, Plan, open_native,
};
use crate::bucket::BucketBinding;
use crate::store::{ByteRange, LocalFs};
use std::io::{self, Read, Seek};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Retains the original opened directories for the whole initializer program.
pub(super) type Directories = Arc<Mutex<Arc<[NativeOpenedDirectory]>>>;

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "initializer requires retained effects",
    )
}

fn retain(
    mut effect: NativeFsEffect,
    directories: &Directories,
) -> Result<NativeFsEffect, NativeEffectFailure> {
    if matches!(effect.plan, Plan::RetainedDirectories { .. }) {
        return Err(denied().into());
    }
    let directories = Arc::clone(
        &*directories
            .lock()
            .map_err(|_| io::Error::other("directory receipt poisoned"))?,
    );
    effect.plan = Plan::RetainedDirectories {
        directories,
        operation: Box::new(effect.plan),
    };
    Ok(effect)
}

/// Performs only immediate native operations inside the creator's owned worker.
pub(super) struct WorkerFs {
    /// The original retained directory receipts shared by every physical effect.
    pub(super) directories: Directories,
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl LocalFs for WorkerFs {
    type Lock = NativeExclusion;

    async fn lock_exclusive(&self, _path: &Path) -> io::Result<Self::Lock> {
        Err(denied())
    }

    async fn write_new(&self, _path: &Path, _bytes: &[u8]) -> io::Result<()> {
        Err(denied())
    }

    async fn create_dir_all(&self, _path: &Path) -> io::Result<()> {
        Err(denied())
    }

    async fn read_dir(&self, _path: &Path) -> io::Result<Vec<PathBuf>> {
        Err(denied())
    }

    async fn remove_file(&self, _path: &Path) -> io::Result<()> {
        Err(denied())
    }

    async fn rename(&self, _from: &Path, _to: &Path) -> io::Result<()> {
        Err(denied())
    }

    async fn rename_no_replace(&self, _from: &Path, _to: &Path) -> io::Result<()> {
        Err(denied())
    }

    async fn sync_file(&self, _path: &Path) -> io::Result<()> {
        Err(denied())
    }

    async fn sync_directory(&self, _path: &Path) -> io::Result<()> {
        Err(denied())
    }

    async fn execute_retained_effect(
        &self,
        effect: NativeFsEffect,
    ) -> Result<(), NativeEffectFailure> {
        let effect = retain(effect, &self.directories)?;
        #[cfg(all(test, feature = "tokio", unix))]
        let effect = initializer_faults::intercept(effect)?;
        effect.execute_inline()
    }

    async fn random_bytes(&self, length: usize) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(io::Error::other)?;
        bytes.resize(length, 0);
        std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    async fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        self.read_nofollow(path).await
    }

    async fn read_nofollow(&self, path: &Path) -> io::Result<Vec<u8>> {
        let mut file = open_native(path, false)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        super::super::super::super::check_opened_name(&file, path, false)?;
        Ok(bytes)
    }

    async fn read_range(&self, path: &Path, range: ByteRange) -> io::Result<Vec<u8>> {
        let mut file = open_native(path, false)?;
        let mut bytes = vec![0; usize::try_from(range.length).map_err(io::Error::other)?];
        file.seek(std::io::SeekFrom::Start(range.start))?;
        file.read_exact(&mut bytes)?;
        super::super::super::super::check_opened_name(&file, path, false)?;
        Ok(bytes)
    }

    async fn metadata(&self, path: &Path) -> io::Result<std::fs::Metadata> {
        std::fs::symlink_metadata(path)
    }

    async fn symlink_metadata(&self, path: &Path) -> io::Result<std::fs::Metadata> {
        std::fs::symlink_metadata(path)
    }

    async fn symlink_metadata_batch(
        &self,
        paths: &[PathBuf],
    ) -> io::Result<Vec<io::Result<std::fs::Metadata>>> {
        Ok(paths.iter().map(std::fs::symlink_metadata).collect())
    }
}

/// Preserves configured reads while binding all effects to genuine directory receipts.
pub(super) struct RetainedFs<'a, F> {
    /// The actual configured filesystem binding and its fault interception.
    pub(super) inner: &'a F,
    /// The original retained directory receipts shared by every physical effect.
    pub(super) directories: Directories,
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<F: LocalFs + BucketBinding> LocalFs for RetainedFs<'_, F> {
    type Lock = F::Lock;

    async fn lock_exclusive(&self, _path: &Path) -> io::Result<Self::Lock> {
        Err(denied())
    }

    async fn write_new(&self, _path: &Path, _bytes: &[u8]) -> io::Result<()> {
        Err(denied())
    }

    async fn create_dir_all(&self, _path: &Path) -> io::Result<()> {
        Err(denied())
    }

    async fn read_dir(&self, _path: &Path) -> io::Result<Vec<PathBuf>> {
        Err(denied())
    }

    async fn remove_file(&self, _path: &Path) -> io::Result<()> {
        Err(denied())
    }

    async fn rename(&self, _from: &Path, _to: &Path) -> io::Result<()> {
        Err(denied())
    }

    async fn rename_no_replace(&self, _from: &Path, _to: &Path) -> io::Result<()> {
        Err(denied())
    }

    async fn sync_file(&self, _path: &Path) -> io::Result<()> {
        Err(denied())
    }

    async fn sync_directory(&self, _path: &Path) -> io::Result<()> {
        Err(denied())
    }

    async fn execute_retained_effect(
        &self,
        effect: NativeFsEffect,
    ) -> Result<(), NativeEffectFailure> {
        self.inner
            .execute_retained_effect(retain(effect, &self.directories)?)
            .await
    }

    async fn random_bytes(&self, length: usize) -> io::Result<Vec<u8>> {
        self.inner.random_bytes(length).await
    }

    async fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        self.inner.read(path).await
    }

    async fn read_nofollow(&self, path: &Path) -> io::Result<Vec<u8>> {
        self.inner.read_nofollow(path).await
    }

    async fn read_range(&self, path: &Path, range: ByteRange) -> io::Result<Vec<u8>> {
        self.inner.read_range(path, range).await
    }

    async fn metadata(&self, path: &Path) -> io::Result<std::fs::Metadata> {
        self.inner.metadata(path).await
    }

    async fn symlink_metadata(&self, path: &Path) -> io::Result<std::fs::Metadata> {
        self.inner.symlink_metadata(path).await
    }

    async fn symlink_metadata_batch(
        &self,
        paths: &[PathBuf],
    ) -> io::Result<Vec<io::Result<std::fs::Metadata>>> {
        self.inner.symlink_metadata_batch(paths).await
    }
}
