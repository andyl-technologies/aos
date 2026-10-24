//! Fails one actual audit Candidate slot before its retained native rename.
//!
//! All authority, reads, exclusions and effects remain production operations.
//! The selector observes canonical staged records; it supplies no checked proof.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use terrane_format::bucket::BucketKey;
use terrane_format::gc::publication::{
    PublicationCommit, PublicationProof, PublicationTransaction,
};

use crate::store::{
    ByteRange, EffectFault, EffectFaultProbe, LocalFs, NativeEffectFailure, NativeExclusion,
    NativeFsEffect, NativeOrdinaryRead, NativeOrdinaryRecord, NativePayloadRangeRead,
    NativePayloadRangeRecord, NativeProtectedRead, NativeProtectedRecord,
    NativePublicationInitialization, NativePublicationInitializationOutcome, StoreFailure,
    TokioFileLock, TokioLocalFs,
};

#[derive(Clone, Default)]
pub(super) struct AuditFaultFs {
    pending: Arc<Mutex<Option<Selector>>>,
    rejected_slot: Arc<Mutex<Option<PathBuf>>>,
}

struct Selector {
    control: PathBuf,
    reference: BucketKey,
}

impl AuditFaultFs {
    /// Arms only the configured audit ref's actual Candidate publication.
    pub(super) fn arm(&self, control: PathBuf, reference: &str) {
        let mut pending = self.pending.lock().unwrap();
        assert!(pending.is_none());
        *pending = Some(Selector {
            control,
            reference: BucketKey::ref_record(reference).unwrap(),
        });
    }

    /// Requires consumption by the exact publication effect and names its slot.
    pub(super) fn rejected_slot(&self) -> PathBuf {
        assert!(self.pending.lock().unwrap().is_none());
        self.rejected_slot.lock().unwrap().clone().unwrap()
    }

    async fn selects_audit_candidate(&self, source: &Path, target: &Path) -> std::io::Result<bool> {
        let selected = {
            let pending = self.pending.lock().unwrap();
            pending.as_ref().and_then(|selector| {
                (target.parent() == Some(selector.control.join("publication/commits").as_path()))
                    .then(|| (selector.control.clone(), selector.reference.clone()))
            })
        };
        let Some((control, reference)) = selected else {
            return Ok(false);
        };

        let slot = PublicationCommit::decode(&TokioLocalFs.read_nofollow(source).await?)
            .map_err(std::io::Error::other)?;
        let transaction_bytes = TokioLocalFs
            .read_nofollow(&control.join(&slot.transaction_key))
            .await?;
        let slot_key = target
            .strip_prefix(&control)
            .map_err(std::io::Error::other)?
            .to_str()
            .ok_or_else(|| std::io::Error::other("noncanonical audit slot path"))?;
        slot.check_transaction(slot_key, &transaction_bytes)
            .map_err(std::io::Error::other)?;
        let transaction =
            PublicationTransaction::decode(&transaction_bytes).map_err(std::io::Error::other)?;
        if !matches!(transaction.proof, PublicationProof::Candidate(_))
            || !transaction
                .changes
                .iter()
                .any(|change| change.key == reference.as_str())
        {
            return Ok(false);
        }

        assert!(self.pending.lock().unwrap().take().is_some());
        *self.rejected_slot.lock().unwrap() = Some(target.to_owned());
        Ok(true)
    }
}

#[async_trait::async_trait]
impl LocalFs for AuditFaultFs {
    type Lock = TokioFileLock;

    async fn initialize_publication(
        &self,
        request: NativePublicationInitialization,
    ) -> Result<NativePublicationInitializationOutcome, StoreFailure> {
        TokioLocalFs.initialize_publication(request).await
    }

    fn retain_native_exclusion(&self, held: &Self::Lock) -> std::io::Result<NativeExclusion> {
        TokioLocalFs.retain_native_exclusion(held)
    }

    async fn execute_retained_effect(
        &self,
        effect: NativeFsEffect,
    ) -> Result<(), NativeEffectFailure> {
        let names = match (effect.rename_noreplace_source(), effect.fault_probe()) {
            (Some(source), EffectFaultProbe::RenameNoReplace(target)) => {
                Some((source.to_owned(), target.to_owned()))
            }
            _ => None,
        };
        let selected = match names {
            Some((source, target)) => self.selects_audit_candidate(&source, &target).await?,
            None => false,
        };
        let effect = if selected {
            // Fail the genuine selected-slot syscall; never acknowledge a
            // substitute effect or intercept unrelated preparatory Raw slots.
            effect.inject_test_faults(vec![EffectFault::BeforeRename])
        } else {
            effect
        };
        let result = TokioLocalFs.execute_retained_effect(effect).await;
        if selected {
            assert!(
                matches!(
                    &result,
                    Err(NativeEffectFailure::Io(error))
                        if error.to_string() == "injected retained rename failure"
                ),
                "the actual native rename must reach the armed failure: {result:?}"
            );
        }
        result
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
        TokioLocalFs.read(path).await
    }

    async fn read_range(&self, path: &Path, range: ByteRange) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.read_range(path, range).await
    }

    async fn read_nofollow(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.read_nofollow(path).await
    }

    async fn read_protected_record(
        &self,
        read: NativeProtectedRead,
    ) -> Result<Option<NativeProtectedRecord>, StoreFailure> {
        TokioLocalFs.read_protected_record(read).await
    }

    async fn read_ordinary_record(
        &self,
        read: NativeOrdinaryRead,
    ) -> std::io::Result<Option<NativeOrdinaryRecord>> {
        TokioLocalFs.read_ordinary_record(read).await
    }

    async fn read_payload_ranges(
        &self,
        read: NativePayloadRangeRead,
    ) -> std::io::Result<Option<NativePayloadRangeRecord>> {
        TokioLocalFs.read_payload_ranges(read).await
    }

    async fn write_new(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        TokioLocalFs.write_new(path, bytes).await
    }

    async fn create_dir_new(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.create_dir_new(path).await
    }

    async fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.create_dir_all(path).await
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
}
