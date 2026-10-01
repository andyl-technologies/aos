//! Implements a local native test binding with real exclusion and inline effects.

/// Exposes the actual test binding through its owning native descendant.
pub(crate) use crate::store::native_clock::gc_test_clock::TestClock;

use crate::store::{ByteRange, LocalFs, NativeEffectFailure, NativeExclusion, NativeFsEffect};
use std::cell::Cell;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::rc::Rc;

/// Preserves genuine filesystem effects without requiring Send or a runtime.
#[derive(Clone, Default)]
pub(crate) struct TestFs {
    effects: Rc<Cell<usize>>,
}

impl TestFs {
    /// Observes actual native dispatches after fixture setup.
    pub(crate) fn effects(&self) -> usize {
        self.effects.get()
    }

    /// Resets the qualified zero-effect refusal count.
    pub(crate) fn reset(&self) {
        self.effects.set(0);
    }
}

fn open(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

fn lock(path: &Path, create: bool) -> std::io::Result<File> {
    let held = OpenOptions::new()
        .read(true)
        .write(true)
        .create(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let before = held.metadata()?;
    if !before.is_file() || before.nlink() != 1 {
        return Err(std::io::Error::other("unsafe native test coordination"));
    }
    held.lock()?;
    let named = std::fs::symlink_metadata(path)?;
    if (named.dev(), named.ino()) != (before.dev(), before.ino()) {
        return Err(std::io::Error::other("changed native test coordination"));
    }
    Ok(held)
}

#[async_trait::async_trait(?Send)]
impl LocalFs for TestFs {
    type Lock = File;

    async fn initialize_publication(
        &self,
        request: crate::store::NativePublicationInitialization,
    ) -> Result<crate::store::NativePublicationInitializationOutcome, crate::store::StoreFailure>
    {
        request.execute_inline()
    }

    fn retain_native_exclusion(&self, held: &Self::Lock) -> std::io::Result<NativeExclusion> {
        Ok(NativeExclusion {
            file: held.try_clone()?,
        })
    }

    async fn execute_retained_effect(
        &self,
        effect: NativeFsEffect,
    ) -> Result<(), NativeEffectFailure> {
        self.effects.set(self.effects.get() + 1);
        effect.execute_inline()
    }

    async fn random_bytes(&self, length: usize) -> std::io::Result<Vec<u8>> {
        let mut bytes = vec![0; length];
        File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    async fn lock_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        lock(path, true)
    }

    async fn lock_existing_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        lock(path, false)
    }

    async fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        std::fs::read(path)
    }

    async fn read_nofollow(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        open(path)?.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    async fn read_range(&self, path: &Path, range: ByteRange) -> std::io::Result<Vec<u8>> {
        let mut file = open(path)?;
        file.seek(std::io::SeekFrom::Start(range.start))?;
        let length = usize::try_from(range.length).map_err(std::io::Error::other)?;
        let mut bytes = vec![0; length];
        file.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    async fn write_new(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        self.effects.set(self.effects.get() + 1);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        file.write_all(bytes)?;
        file.sync_all()
    }

    async fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
        self.effects.set(self.effects.get() + 1);
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
    }

    async fn create_dir_new(&self, path: &Path) -> std::io::Result<()> {
        self.effects.set(self.effects.get() + 1);
        std::fs::DirBuilder::new().mode(0o700).create(path)
    }

    async fn read_dir(&self, path: &Path) -> std::io::Result<Vec<PathBuf>> {
        std::fs::read_dir(path)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect()
    }

    async fn metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        std::fs::metadata(path)
    }

    async fn symlink_metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        std::fs::symlink_metadata(path)
    }

    async fn remove_file(&self, path: &Path) -> std::io::Result<()> {
        self.effects.set(self.effects.get() + 1);
        std::fs::remove_file(path)
    }

    async fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.effects.set(self.effects.get() + 1);
        std::fs::rename(from, to)
    }

    async fn rename_no_replace(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.effects.set(self.effects.get() + 1);
        std::fs::hard_link(from, to)?;
        std::fs::remove_file(from)
    }

    async fn sync_file(&self, path: &Path) -> std::io::Result<()> {
        open(path)?.sync_all()
    }

    async fn sync_directory(&self, path: &Path) -> std::io::Result<()> {
        open(path)?.sync_all()
    }

    async fn set_permissions_and_sync(
        &self,
        path: &Path,
        permissions: std::fs::Permissions,
    ) -> std::io::Result<()> {
        self.effects.set(self.effects.get() + 1);
        let file = open(path)?;
        file.set_permissions(permissions)?;
        file.sync_all()
    }
}
