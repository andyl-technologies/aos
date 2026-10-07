//! Observes actual submitted native effects and forwards the sealed executor.
//!
//! Physical hooks are finite, unarmed by default and activated only after actual
//! cold preparation reaches immutable staging. No successful ACK is inferred
//! from selection visibility or unit success supplied by a replacement binding.

use super::support::required;
#[cfg(feature = "send")]
use crate::store::EffectFault;
use crate::store::{
    ByteRange, EffectFaultProbe, LocalFs, NativeEffectFailure, NativeFsEffect,
    NativePublicationInitialization, NativePublicationInitializationOutcome, StoreFailure,
    TokioFileLock, TokioLocalFs,
};
use std::{
    io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use terrane_core::gc::publication::{PublicationCommit, PublicationProof, PublicationTransaction};

pub(super) enum Hook {
    /// Removes an exact prior Original after real cold qualification, before staging.
    Remove(PathBuf),
    /// Replaces an exact selected control with identical bytes and a new incarnation.
    Replace(PathBuf),
    /// Injects the existing native worker's real final directory synchronization fault.
    #[cfg(feature = "send")]
    FinalSync,
    /// Advances the same originally injected clock after qualification.
    #[cfg(feature = "send")]
    Expire(crate::store::TestClock),
}

#[derive(Clone, Debug)]
pub(super) struct Mutation {
    pub(super) path: PathBuf,
    pub(super) transaction: PublicationTransaction,
    /// Retains exact bytes observed from the actual submitted publication slot.
    pub(super) slot_bytes: Vec<u8>,
    /// Retains exact bytes observed from the referenced immutable transaction.
    pub(super) transaction_bytes: Vec<u8>,
    pub(super) acknowledged: bool,
}

#[derive(Default)]
struct State {
    hook: Option<Hook>,
    reached: bool,
    staging_reached: bool,
    effects: Vec<(String, Option<PathBuf>)>,
    mutations: Vec<Mutation>,
}

#[derive(Clone, Default)]
pub(super) struct ProbeFs(Arc<Mutex<State>>);

impl ProbeFs {
    pub(super) fn reset(&self) {
        let mut state = required(self.0.lock());
        assert!(state.hook.is_none(), "unconsumed finite native hook");
        *state = State::default();
    }

    pub(super) fn arm(&self, hook: Hook) {
        let mut state = required(self.0.lock());
        assert!(state.hook.is_none(), "already armed native hook");
        state.hook = Some(hook);
    }

    pub(super) fn reached(&self) -> bool {
        required(self.0.lock()).reached
    }

    pub(super) fn staging_reached(&self) -> bool {
        required(self.0.lock()).staging_reached
    }

    pub(super) fn mutations(&self) -> Vec<Mutation> {
        required(self.0.lock()).mutations.clone()
    }

    pub(super) fn effects(&self) -> Vec<(String, Option<PathBuf>)> {
        required(self.0.lock()).effects.clone()
    }

    pub(super) fn successful_ref_ack(&self, reference: &str) -> usize {
        let key = format!("{reference}:record");
        self.mutations()
            .iter()
            .filter(|row| {
                row.acknowledged
                    && matches!(row.transaction.proof, PublicationProof::Candidate(_))
                    && row
                        .transaction
                        .changes
                        .iter()
                        .any(|change| change.key == key && change.new.is_some())
            })
            .count()
    }

    pub(super) fn successful_requalification_ack(&self, reference: &str) -> usize {
        self.mutations()
            .iter()
            .filter(|row| {
                row.acknowledged
                    && matches!(row.transaction.proof, PublicationProof::Candidate(_))
                    && row.transaction.changes.is_empty()
                    && row.transaction.old.as_ref().is_some_and(|old| {
                        old.branches == row.transaction.new.branches
                            && old.sources.iter().find(|source| source.name == reference)
                                != row
                                    .transaction
                                    .new
                                    .sources
                                    .iter()
                                    .find(|source| source.name == reference)
                    })
            })
            .count()
    }
}

fn mutation(path: &Path) -> Mutation {
    let slot_bytes = required(std::fs::read(path));
    let slot = required(PublicationCommit::decode(&slot_bytes));
    let control = required(path.ancestors().nth(3).ok_or("actual publication control"));
    let body = required(std::fs::read(control.join(&slot.transaction_key)));
    required(slot.check_transaction(&format!("publication/commits/{}", slot.revision), &body));
    Mutation {
        path: path.to_owned(),
        transaction: required(PublicationTransaction::decode(&body)),
        slot_bytes,
        transaction_bytes: body,
        acknowledged: false,
    }
}

pub(super) fn replace(path: &Path) -> io::Result<()> {
    let original = std::fs::symlink_metadata(path)?;
    let body = std::fs::read(path)?;
    let next = path.with_extension("cold-replacement");
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&next)?;
    std::fs::set_permissions(
        &next,
        std::fs::Permissions::from_mode(original.mode() & 0o777),
    )?;
    drop(file);
    std::fs::write(&next, &body)?;
    std::fs::rename(&next, path)?;
    let current = std::fs::symlink_metadata(path)?;
    assert_ne!(
        (original.dev(), original.ino()),
        (current.dev(), current.ino())
    );
    assert_eq!(std::fs::read(path)?, body);
    Ok(())
}

#[async_trait::async_trait]
impl LocalFs for ProbeFs {
    type Lock = TokioFileLock;

    async fn initialize_publication(
        &self,
        request: NativePublicationInitialization,
    ) -> Result<NativePublicationInitializationOutcome, StoreFailure> {
        TokioLocalFs.initialize_publication(request).await
    }

    fn retain_native_exclusion(
        &self,
        held: &Self::Lock,
    ) -> io::Result<crate::store::NativeExclusion> {
        TokioLocalFs.retain_native_exclusion(held)
    }

    async fn execute_retained_effect(
        &self,
        effect: NativeFsEffect,
    ) -> Result<(), NativeEffectFailure> {
        let (name, path, staging, final_slot) = match effect.fault_probe() {
            EffectFaultProbe::SealPendingCreation(path) => {
                ("SealPendingCreation", Some(path.to_owned()), true, false)
            }
            EffectFaultProbe::SealArtifact(path) => {
                ("SealArtifact", Some(path.to_owned()), false, false)
            }
            EffectFaultProbe::CommitCreation(path) => {
                ("CommitCreation", Some(path.to_owned()), false, false)
            }
            EffectFaultProbe::SealRawPublication(path) => {
                ("SealRawPublication", Some(path.to_owned()), false, false)
            }
            EffectFaultProbe::SealMutationPublication(path) => (
                "SealMutationPublication",
                Some(path.to_owned()),
                false,
                true,
            ),
            EffectFaultProbe::SealLeasePublication(path) => {
                ("SealLeasePublication", Some(path.to_owned()), false, false)
            }
            EffectFaultProbe::WriteNew(path) => ("WriteNew", Some(path.to_owned()), false, false),
            EffectFaultProbe::DirectorySync(path) => {
                ("DirectorySync", Some(path.to_owned()), false, false)
            }
            EffectFaultProbe::RenameNoReplace(path) => {
                ("RenameNoReplace", Some(path.to_owned()), false, false)
            }
            EffectFaultProbe::Rename(path) => ("Rename", Some(path.to_owned()), false, false),
            EffectFaultProbe::FileSync => ("FileSync", None, false, false),
            EffectFaultProbe::Other => ("Other", None, false, false),
        };
        let observed = if final_slot || name == "SealRawPublication" {
            Some(mutation(required(
                path.as_deref().ok_or("actual mutation path"),
            )))
        } else {
            None
        };
        let (hook, ordinal) = {
            let mut state = required(self.0.lock());
            state.effects.push((name.into(), path));
            state.staging_reached |= staging;
            let ordinal = observed.map(|row| {
                let ordinal = state.mutations.len();
                state.mutations.push(row);
                ordinal
            });
            let should_fire = state.hook.as_ref().is_some_and(|hook| {
                #[cfg(feature = "send")]
                {
                    if matches!(hook, Hook::FinalSync) {
                        final_slot
                    } else {
                        staging
                    }
                }
                #[cfg(not(feature = "send"))]
                {
                    let _ = hook;
                    staging
                }
            });
            let hook = if should_fire {
                state.reached = true;
                state.hook.take()
            } else {
                None
            };
            (hook, ordinal)
        };
        let effect = match hook {
            Some(Hook::Remove(path)) => {
                required(std::fs::remove_file(path));
                effect
            }
            Some(Hook::Replace(path)) => {
                required(replace(&path));
                effect
            }
            #[cfg(feature = "send")]
            Some(Hook::FinalSync) => {
                effect.inject_test_faults(vec![EffectFault::BeforeDirectorySync])
            }
            #[cfg(feature = "send")]
            Some(Hook::Expire(clock)) => {
                clock.set(2_000_000_031, 31);
                effect
            }
            None => effect,
        };
        TokioLocalFs.execute_retained_effect(effect).await?;
        if let Some(ordinal) = ordinal {
            required(self.0.lock()).mutations[ordinal].acknowledged = true;
        }
        Ok(())
    }

    async fn random_bytes(&self, length: usize) -> io::Result<Vec<u8>> {
        TokioLocalFs.random_bytes(length).await
    }

    async fn read_nofollow(&self, path: &Path) -> io::Result<Vec<u8>> {
        TokioLocalFs.read_nofollow(path).await
    }

    async fn lock_existing_exclusive(&self, path: &Path) -> io::Result<Self::Lock> {
        TokioLocalFs.lock_existing_exclusive(path).await
    }

    async fn lock_exclusive(&self, path: &Path) -> io::Result<Self::Lock> {
        TokioLocalFs.lock_exclusive(path).await
    }

    async fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        TokioLocalFs.read(path).await
    }

    async fn read_range(&self, path: &Path, range: ByteRange) -> io::Result<Vec<u8>> {
        TokioLocalFs.read_range(path, range).await
    }

    async fn set_permissions_and_sync(
        &self,
        path: &Path,
        permissions: std::fs::Permissions,
    ) -> io::Result<()> {
        TokioLocalFs
            .set_permissions_and_sync(path, permissions)
            .await
    }

    async fn write_new(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        TokioLocalFs.write_new(path, bytes).await
    }

    async fn create_dir_new(&self, path: &Path) -> io::Result<()> {
        TokioLocalFs.create_dir_new(path).await
    }

    async fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        TokioLocalFs.create_dir_all(path).await
    }

    async fn metadata(&self, path: &Path) -> io::Result<std::fs::Metadata> {
        TokioLocalFs.metadata(path).await
    }

    async fn symlink_metadata(&self, path: &Path) -> io::Result<std::fs::Metadata> {
        TokioLocalFs.symlink_metadata(path).await
    }

    async fn remove_file(&self, path: &Path) -> io::Result<()> {
        TokioLocalFs.remove_file(path).await
    }

    async fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        TokioLocalFs.rename(from, to).await
    }

    async fn rename_no_replace(&self, from: &Path, to: &Path) -> io::Result<()> {
        TokioLocalFs.rename_no_replace(from, to).await
    }

    async fn sync_directory(&self, path: &Path) -> io::Result<()> {
        TokioLocalFs.sync_directory(path).await
    }

    async fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        TokioLocalFs.read_dir(path).await
    }

    async fn sync_file(&self, path: &Path) -> io::Result<()> {
        TokioLocalFs.sync_file(path).await
    }
}
