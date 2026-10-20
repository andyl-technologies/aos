//! Intercepts actual pack-body I/O while forwarding the genuine native binding.

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use crate::store::{ByteRange, LocalFs, TokioFileLock, TokioLocalFs};

#[path = "fs/requalification.rs"]
mod requalification;

pub(super) use requalification::SourceMutation;

/// Observes real pack I/O and native effects while forwarding the actual filesystem.
#[derive(Clone, Default)]
pub(super) struct CountingFs {
    /// Arms refusal of actual pack-body I/O for no-read witnesses.
    pub(super) reject_packs: Arc<AtomicBool>,
    /// Counts actual intercepted pack-body operations.
    pub(super) pack_io: Arc<AtomicUsize>,
    /// Counts actual submitted filesystem effects.
    pub(super) effects: Arc<AtomicUsize>,
    lose_original_after_retention: Arc<Mutex<Option<PathBuf>>>,
    acknowledged: Arc<Mutex<Vec<terrane_format::gc::publication::PublicationTransaction>>>,
    lose_original_at_guard_lineage: Arc<Mutex<Option<GuardLineageLoss>>>,
    requalification: Arc<requalification::RequalificationHooks>,
}

struct GuardLineageLoss {
    directory: PathBuf,
    original: PathBuf,
}

impl CountingFs {
    /// Clears ordinary observations before the separately measured operation.
    ///
    /// # Panics
    /// Panics when fixture observation synchronization is poisoned.
    pub(super) fn reset_acknowledged(&self) {
        required(self.acknowledged.lock()).clear();
    }

    /// Copies actual transactions whose sealed native executor returned success.
    ///
    /// # Panics
    /// Panics when fixture observation synchronization is poisoned.
    pub(super) fn acknowledged(
        &self,
    ) -> Vec<terrane_format::gc::publication::PublicationTransaction> {
        required(self.acknowledged.lock()).clone()
    }

    /// Arms real Original loss at an actual carried-lineage installation effect.
    ///
    /// The fixture obtains both paths from its real selected lineage receipt and
    /// independently checked source Original context. This changes no sealed
    /// effect or permission and is inactive unless this fixture explicitly arms it.
    ///
    /// # Errors
    /// Rejects duplicate arming or poisoned fixture synchronization.
    pub(super) fn lose_original_at_guard_lineage(
        &self,
        directory: PathBuf,
        original: PathBuf,
    ) -> std::io::Result<()> {
        let mut pending = self
            .lose_original_at_guard_lineage
            .lock()
            .map_err(|_| std::io::Error::other("fixture hook lock poisoned"))?;
        if pending.is_some() {
            return Err(std::io::Error::other("guard lineage loss already armed"));
        }
        *pending = Some(GuardLineageLoss {
            directory,
            original,
        });
        Ok(())
    }

    fn take_guard_lineage_loss(
        &self,
        effect: &crate::store::NativeFsEffect,
    ) -> std::io::Result<Option<PathBuf>> {
        let mut pending = self
            .lose_original_at_guard_lineage
            .lock()
            .map_err(|_| std::io::Error::other("fixture hook lock poisoned"))?;
        let Some(expected) = pending.as_ref() else {
            return Ok(None);
        };
        let selected = match effect.fault_probe() {
            crate::store::EffectFaultProbe::WriteNew(path)
            | crate::store::EffectFaultProbe::RenameNoReplace(path) => {
                path.parent() == Some(expected.directory.as_path())
            }
            _ => false,
        };
        Ok(if selected {
            pending.take().map(|loss| loss.original)
        } else {
            None
        })
    }

    /// Schedules actual source Original loss after genuine candidate retention.
    ///
    /// # Errors
    /// Rejects a poisoned fixture hook lock.
    pub(super) fn lose_original_after_retention(&self, original: PathBuf) -> std::io::Result<()> {
        *self
            .lose_original_after_retention
            .lock()
            .map_err(|_| std::io::Error::other("fixture hook lock poisoned"))? = Some(original);

        Ok(())
    }

    fn take_original_loss(&self, retained: &Path) -> std::io::Result<Option<PathBuf>> {
        let mut selected = self
            .lose_original_after_retention
            .lock()
            .map_err(|_| std::io::Error::other("fixture hook lock poisoned"))?;
        let Some(original) = selected.as_ref() else {
            return Ok(None);
        };

        let candidate_association = retained != original
            && retained.parent() == original.parent()
            && retained
                .file_name()
                .is_some_and(|name| name.as_encoded_bytes().starts_with(b"commit-"));
        if candidate_association {
            Ok(selected.take())
        } else {
            Ok(None)
        }
    }

    fn check_pack(&self, path: &Path) -> std::io::Result<()> {
        if path
            .extension()
            .is_some_and(|extension| extension == "pack")
        {
            self.pack_io.fetch_add(1, Ordering::SeqCst);
            if self.reject_packs.load(Ordering::SeqCst) {
                return Err(std::io::Error::other(
                    "ordinary pack-body I/O is forbidden during cold qualification",
                ));
            }
        }
        Ok(())
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl LocalFs for CountingFs {
    type Lock = TokioFileLock;

    fn retain_native_exclusion(
        &self,
        held: &Self::Lock,
    ) -> std::io::Result<crate::store::NativeExclusion> {
        TokioLocalFs.retain_native_exclusion(held)
    }

    async fn initialize_publication(
        &self,
        request: crate::store::NativePublicationInitialization,
    ) -> Result<crate::store::NativePublicationInitializationOutcome, crate::store::StoreFailure>
    {
        TokioLocalFs.initialize_publication(request).await
    }

    async fn execute_retained_effect(
        &self,
        effect: crate::store::NativeFsEffect,
    ) -> Result<(), crate::store::NativeEffectFailure> {
        self.effects.fetch_add(1, Ordering::SeqCst);
        let mutation = match effect.fault_probe() {
            crate::store::EffectFaultProbe::SealMutationPublication(path) => Some(path.to_owned()),
            _ => None,
        };
        if let Some(original) = self.take_guard_lineage_loss(&effect)? {
            TokioLocalFs.remove_file(&original).await?;
        }
        self.execute_requalification_effect(effect).await?;
        if let Some(path) = mutation {
            // The real sealed executor has acknowledged its final directory sync.
            // Decode and bind the actual durable slot; observations grant no permit.
            let slot = required(terrane_format::gc::publication::PublicationCommit::decode(
                &required(std::fs::read(&path)),
            ));
            let control = match path.ancestors().nth(3) {
                Some(control) => control,
                None => panic!("actual publication slot has no control ancestor"),
            };
            let bytes = required(std::fs::read(control.join(&slot.transaction_key)));
            required(
                slot.check_transaction(&format!("publication/commits/{}", slot.revision), &bytes),
            );
            required(self.acknowledged.lock()).push(required(
                terrane_format::gc::publication::PublicationTransaction::decode(&bytes),
            ));
        }
        Ok(())
    }

    async fn random_bytes(&self, length: usize) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.random_bytes(length).await
    }

    async fn lock_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        TokioLocalFs.lock_exclusive(path).await
    }

    async fn lock_existing_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        TokioLocalFs.lock_existing_exclusive(path).await
    }

    async fn try_lock_existing_shared(&self, path: &Path) -> std::io::Result<Self::Lock> {
        TokioLocalFs.try_lock_existing_shared(path).await
    }

    async fn try_lock_existing_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        TokioLocalFs.try_lock_existing_exclusive(path).await
    }

    async fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        self.check_pack(path)?;
        self.observe_requalification_pack(path)?;
        TokioLocalFs.read(path).await
    }

    async fn read_nofollow(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        self.check_pack(path)?;
        self.observe_requalification_pack(path)?;
        TokioLocalFs.read_nofollow(path).await
    }

    async fn read_ordinary_record(
        &self,
        read: crate::store::NativeOrdinaryRead,
    ) -> std::io::Result<Option<crate::store::NativeOrdinaryRecord>> {
        // Leaf reads keep the scalar pack counters and armed refusal hooks.
        // Closing projections have no scalar fallback and must execute the
        // unchanged native recipe before held history can be completed.
        if read.path_for_test().is_some() {
            return Ok(None);
        }

        TokioLocalFs.read_ordinary_record(read).await
    }

    async fn read_payload_ranges(
        &self,
        request: crate::store::NativePayloadRangeRead,
    ) -> std::io::Result<Option<crate::store::NativePayloadRangeRecord>> {
        // Native reads and closing replays encounter the same pack-body traps
        // as scalar reads. Capability probes and capture consume no body bytes.
        if let Some((path, _)) = request.read_data_range() {
            self.check_pack(path)?;
            self.observe_requalification_pack(path)?;
        }
        if let Some(ranges) = request.closing_data_ranges_for_test() {
            for (path, _) in ranges {
                self.check_pack(path)?;
                self.observe_requalification_pack(path)?;
            }
        }

        TokioLocalFs.read_payload_ranges(request).await
    }

    async fn read_range(&self, path: &Path, range: ByteRange) -> std::io::Result<Vec<u8>> {
        self.check_pack(path)?;
        self.observe_requalification_pack(path)?;
        TokioLocalFs.read_range(path, range).await
    }

    async fn write_new(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        self.check_pack(path)?;
        TokioLocalFs.write_new(path, bytes).await?;
        if let Some(original) = self.take_original_loss(path)? {
            TokioLocalFs.remove_file(&original).await?;
        }
        Ok(())
    }

    async fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.create_dir_all(path).await
    }

    async fn create_dir_new(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.create_dir_new(path).await
    }

    async fn read_dir(&self, path: &Path) -> std::io::Result<Vec<PathBuf>> {
        TokioLocalFs.read_dir(path).await
    }

    async fn metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        TokioLocalFs.metadata(path).await
    }

    async fn symlink_metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        TokioLocalFs.symlink_metadata(path).await
    }

    async fn symlink_metadata_batch(
        &self,
        paths: &[PathBuf],
    ) -> std::io::Result<Vec<std::io::Result<std::fs::Metadata>>> {
        TokioLocalFs.symlink_metadata_batch(paths).await
    }

    async fn remove_file(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.remove_file(path).await
    }

    async fn remove_dir(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.remove_dir(path).await
    }

    async fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        TokioLocalFs.rename(from, to).await
    }

    async fn rename_no_replace(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        TokioLocalFs.rename_no_replace(from, to).await
    }

    async fn sync_file(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.sync_file(path).await
    }

    async fn sync_file_nofollow(
        &self,
        path: &Path,
        expected: &std::fs::Metadata,
    ) -> std::io::Result<std::fs::Metadata> {
        TokioLocalFs.sync_file_nofollow(path, expected).await
    }

    async fn sync_directory(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.sync_directory(path).await
    }

    async fn set_permissions(
        &self,
        path: &Path,
        permissions: std::fs::Permissions,
    ) -> std::io::Result<()> {
        TokioLocalFs.set_permissions(path, permissions).await
    }

    async fn set_permissions_and_sync(
        &self,
        path: &Path,
        permissions: std::fs::Permissions,
    ) -> std::io::Result<()> {
        TokioLocalFs
            .set_permissions_and_sync(path, permissions)
            .await
    }

    async fn read_link(&self, path: &Path) -> std::io::Result<PathBuf> {
        TokioLocalFs.read_link(path).await
    }

    async fn list_xattrs(&self, path: &Path) -> std::io::Result<Vec<std::ffi::OsString>> {
        TokioLocalFs.list_xattrs(path).await
    }

    async fn get_xattr(
        &self,
        path: &Path,
        name: &std::ffi::OsStr,
    ) -> std::io::Result<Option<Vec<u8>>> {
        TokioLocalFs.get_xattr(path, name).await
    }
}

// A fixture invariant failure must stop the owning witness rather than produce observations.
fn required<T>(value: Result<T, impl std::fmt::Debug>) -> T {
    match value {
        Ok(value) => value,
        Err(error) => panic!("owning fixture invariant failed: {error:?}"),
    }
}
