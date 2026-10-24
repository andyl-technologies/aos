//! Observes the actual Raw preslot boundary through a forwarding native adapter.

use super::super::*;
use crate::store::{
    ByteRange, EffectFaultProbe, NativeExclusion, NativeFsEffect, NativePublicationInitialization,
    NativePublicationInitializationOutcome, TokioFileLock,
};
use std::{
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

struct Intervention {
    root: PathBuf,
    target: PathBuf,
    slot: PathBuf,
    tamper: bool,
    cohort_completed: bool,
    barrier_seen: bool,
    raw_ack_seen: bool,
}

#[derive(Clone, Default)]
struct ProbeFs(Arc<Mutex<Option<Intervention>>>);

impl ProbeFs {
    fn state(&self) -> io::Result<std::sync::MutexGuard<'_, Option<Intervention>>> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("preslot fixture mutex poisoned"))
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl crate::store::LocalFs for ProbeFs {
    type Lock = TokioFileLock;

    async fn initialize_publication(
        &self,
        request: NativePublicationInitialization,
    ) -> Result<NativePublicationInitializationOutcome, StoreFailure> {
        TokioLocalFs.initialize_publication(request).await
    }

    fn retain_native_exclusion(&self, held: &Self::Lock) -> io::Result<NativeExclusion> {
        TokioLocalFs.retain_native_exclusion(held)
    }

    async fn execute_retained_effect(
        &self,
        effect: NativeFsEffect,
    ) -> Result<(), NativeEffectFailure> {
        let targets = effect.immutable_catalog_cohort_targets();
        {
            let mut state = self.state()?;
            if let Some(intervention) = state.as_mut() {
                match effect.fault_probe() {
                    EffectFaultProbe::DirectorySync(path)
                        if path == intervention.root
                            && intervention.cohort_completed
                            && !intervention.barrier_seen =>
                    {
                        // This is the added root durability barrier, after real
                        // cohort completion and before any selecting slot exists.
                        assert!(!intervention.slot.exists());
                        intervention.barrier_seen = true;
                        if intervention.tamper {
                            std::fs::write(&intervention.target, b"changed before selection")?;
                        }
                    }
                    EffectFaultProbe::SealRawPublication(_) => intervention.raw_ack_seen = true,
                    _ => {}
                }
            }
        }

        // Only genuine retained execution can produce a creation receipt.
        TokioLocalFs.execute_retained_effect(effect).await?;
        let mut state = self.state()?;
        if let Some(intervention) = state.as_mut()
            && targets
                .as_ref()
                .is_some_and(|paths| paths.contains(&intervention.target))
        {
            intervention.cohort_completed = true;
        }
        Ok(())
    }

    async fn random_bytes(&self, length: usize) -> io::Result<Vec<u8>> {
        TokioLocalFs.random_bytes(length).await
    }

    async fn lock_exclusive(&self, path: &Path) -> io::Result<Self::Lock> {
        TokioLocalFs.lock_exclusive(path).await
    }

    async fn lock_existing_exclusive(&self, path: &Path) -> io::Result<Self::Lock> {
        TokioLocalFs.lock_existing_exclusive(path).await
    }

    async fn try_lock_existing_shared(&self, path: &Path) -> io::Result<Self::Lock> {
        TokioLocalFs.try_lock_existing_shared(path).await
    }

    async fn try_lock_existing_exclusive(&self, path: &Path) -> io::Result<Self::Lock> {
        TokioLocalFs.try_lock_existing_exclusive(path).await
    }

    async fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        TokioLocalFs.read(path).await
    }

    async fn read_nofollow(&self, path: &Path) -> io::Result<Vec<u8>> {
        TokioLocalFs.read_nofollow(path).await
    }

    async fn read_range(&self, path: &Path, range: ByteRange) -> io::Result<Vec<u8>> {
        TokioLocalFs.read_range(path, range).await
    }

    async fn metadata(&self, path: &Path) -> io::Result<std::fs::Metadata> {
        TokioLocalFs.metadata(path).await
    }

    async fn symlink_metadata(&self, path: &Path) -> io::Result<std::fs::Metadata> {
        TokioLocalFs.symlink_metadata(path).await
    }

    async fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        TokioLocalFs.read_dir(path).await
    }

    async fn write_new(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        TokioLocalFs.write_new(path, bytes).await
    }

    async fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        TokioLocalFs.create_dir_all(path).await
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

    async fn sync_file(&self, path: &Path) -> io::Result<()> {
        TokioLocalFs.sync_file(path).await
    }

    async fn sync_directory(&self, path: &Path) -> io::Result<()> {
        TokioLocalFs.sync_directory(path).await
    }
}

#[tokio::test]
async fn raw_preslot_barrier_rejects_persistent_output_tamper_before_selection() {
    for tamper in [false, true] {
        let entropy = required(TokioLocalFs.random_bytes(16).await);
        let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
        let root = std::env::temp_dir().join(format!("terrane-install-preslot-{suffix}"));
        let control = root.with_file_name(format!(".terrane-install-preslot-control:{suffix}"));
        let owner_probe = root.with_file_name(format!(".terrane-install-owner:{suffix}"));
        required(std::fs::DirBuilder::new().mode(0o700).create(&owner_probe));
        let operator_uid = required(std::fs::symlink_metadata(&owner_probe)).uid();
        required(std::fs::remove_dir(&owner_probe));
        let fs = ProbeFs::default();
        let config = FileBucketConfig {
            root: root.clone(),
            publication_control: Some(FileBucketPublicationConfig {
                operator_uid,
                control: Some(control.clone()),
            }),
            chunk_profile_name: "cdc-1m".into(),
            chunk_profile: ChunkProfile::cdc_1m([0; 32]),
            locality: Locality::default(),
        };
        let bucket = required(FileBucket::open(config, fs.clone(), TokioClock, Validator).await);
        let holder = required(SingleHeld::acquire(&bucket).await);
        let held = holder.destination();
        let observed = required(held.observe_publication().await);
        let prior = observed.stamp();
        let slot = control.join(format!("publication/commits/{}", prior.0 + 1));
        let key = "objects/index/904/1.idx";
        let bytes = required(crate::pack::MergedShard::rebuild(
            1,
            904,
            &[],
            &std::collections::BTreeSet::new(),
            None,
            &std::collections::BTreeSet::new(),
        ))
        .encode();
        *required(fs.state()) = Some(Intervention {
            root: root.clone(),
            target: root.join(key),
            slot: slot.clone(),
            tamper,
            cohort_completed: false,
            barrier_seen: false,
            raw_ack_seen: false,
        });

        // The positive control proves this exact canonical mutation is admitted;
        // the negative uses the same producer and intervenes only after creation.
        let result = held
            .publish_raw(
                &observed,
                vec![terrane_format::gc::publication::LogicalChange {
                    key: key.into(),
                    expected: None,
                    new: Some(bytes.clone()),
                }],
            )
            .await;
        {
            let state = required(fs.state());
            let intervention = present(state.as_ref());
            assert!(intervention.cohort_completed);
            assert!(intervention.barrier_seen);
            assert_eq!(intervention.raw_ack_seen, !tamper);
        }
        if tamper {
            let Err(error) = result else {
                panic!("tampered Raw publication unexpectedly selected a successor");
            };
            assert_eq!(
                error.kind(),
                &StoreErrorKind::Unavailable { retry_after: None }
            );
            assert!(!slot.exists());
            required(observed.revalidate().await);
            assert_eq!(required(held.observe_publication().await).stamp(), prior);
        } else {
            let receipt = required(result);
            assert_eq!(receipt.stamp.0, prior.0 + 1);
            assert!(slot.exists());
            let selected = required(held.observe_publication().await);
            assert_eq!(selected.logical().get(key), Some(&Some(bytes)));
        }
        drop(observed);
        drop(holder);
        drop(bucket);
        required(std::fs::remove_dir_all(root));
        required(std::fs::remove_dir_all(control));
    }
}
