//! Forwards genuine native deletion and observes final cold publication ACKs.
//!
//! The finite replacement hook runs only at actual immutable staging after
//! cold qualification. Every effect still reaches the existing native worker.

use crate::store::native_publication_effects::collection::test_fs::TestFs;
use crate::store::native_publication_effects::collection_local_deletion::DeletionFs;
use crate::store::{
    ByteRange, EffectFaultProbe, LocalFs, NativeEffectFailure, NativeFsEffect,
    NativePublicationInitialization, NativePublicationInitializationOutcome, StoreFailure,
};
use std::{
    io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use terrane_format::gc::publication::{
    PublicationCommit, PublicationProof, PublicationTransaction,
};

#[derive(Default)]
struct State {
    replacement: Option<PathBuf>,
    reached: bool,
    acknowledgments: Vec<PublicationTransaction>,
}

/// Retains the existing native deletion executor and a finite cold-stage hook.
#[derive(Clone)]
pub(super) struct ProbeFs {
    inner: DeletionFs,
    state: Arc<Mutex<State>>,
}

impl ProbeFs {
    /// Wraps the same genuine filesystem state used by the source producer.
    pub(super) fn new(inner: TestFs) -> Self {
        Self {
            inner: DeletionFs::new(inner),
            state: Arc::new(Mutex::new(State::default())),
        }
    }

    /// Arms one actual consumed control replacement after cold qualification.
    ///
    /// # Panics
    /// Panics on poisoned observation or an already armed hook.
    pub(super) fn arm(&self, path: PathBuf) {
        assert!(
            self.state
                .lock()
                .unwrap()
                .replacement
                .replace(path)
                .is_none()
        );
    }

    /// Reports whether the native cold staging boundary consumed the hook.
    ///
    /// # Panics
    /// Panics on poisoned observation.
    pub(super) fn reached(&self) -> bool {
        self.state.lock().unwrap().reached
    }

    /// Counts actual successful candidate ACKs affecting this canonical ref key.
    ///
    /// # Panics
    /// Panics on poisoned observation or an invalid test ref name.
    pub(super) fn successful_ref_ack(&self, name: &str) -> usize {
        let key = terrane_format::bucket::BucketKey::ref_record(name).unwrap();
        self.state
            .lock()
            .unwrap()
            .acknowledgments
            .iter()
            .filter(|tx| {
                matches!(tx.proof, PublicationProof::Candidate(_))
                    && tx
                        .changes
                        .iter()
                        .any(|change| change.key == key.as_str() && change.new.is_some())
            })
            .count()
    }

    /// Requires a real native Done return, independent of the operation cache.
    ///
    /// # Panics
    /// Panics if no actual native Done effect completed.
    pub(super) fn assert_done_effect(&self) {
        assert!(
            self.inner
                .completed()
                .contains(&terrane_format::gc::DeletePhase::Done)
        );
    }
}

fn replacement(path: &Path) -> io::Result<()> {
    let old = std::fs::symlink_metadata(path)?;
    let bytes = std::fs::read(path)?;
    let next = path.with_extension("post-done-replacement");
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&next)?;
    std::fs::set_permissions(&next, std::fs::Permissions::from_mode(old.mode() & 0o777))?;
    std::io::Write::write_all(&mut file, &bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&next, path)?;
    std::fs::File::open(
        path.parent()
            .ok_or_else(|| io::Error::other("control parent"))?,
    )?
    .sync_all()?;
    let new = std::fs::symlink_metadata(path)?;
    assert_ne!((old.dev(), old.ino()), (new.dev(), new.ino()));
    assert_eq!(std::fs::read(path)?, bytes);
    Ok(())
}

fn transaction(path: &Path) -> PublicationTransaction {
    let slot = PublicationCommit::decode(&std::fs::read(path).unwrap()).unwrap();
    let control = path.ancestors().nth(3).unwrap();
    let bytes = std::fs::read(control.join(&slot.transaction_key)).unwrap();
    slot.check_transaction(&format!("publication/commits/{}", slot.revision), &bytes)
        .unwrap();
    PublicationTransaction::decode(&bytes).unwrap()
}

#[async_trait::async_trait]
impl LocalFs for ProbeFs {
    type Lock = <DeletionFs as LocalFs>::Lock;

    async fn initialize_publication(
        &self,
        request: NativePublicationInitialization,
    ) -> Result<NativePublicationInitializationOutcome, StoreFailure> {
        self.inner.initialize_publication(request).await
    }

    fn retain_native_exclusion(
        &self,
        held: &Self::Lock,
    ) -> io::Result<crate::store::NativeExclusion> {
        self.inner.retain_native_exclusion(held)
    }

    async fn execute_retained_effect(
        &self,
        effect: NativeFsEffect,
    ) -> Result<(), NativeEffectFailure> {
        let candidate = match effect.fault_probe() {
            EffectFaultProbe::SealMutationPublication(path) => Some(transaction(path)),
            _ => None,
        };
        let hook = if matches!(
            effect.fault_probe(),
            EffectFaultProbe::SealPendingCreation(_)
        ) {
            let mut state = self.state.lock().unwrap();
            let hook = state.replacement.take();
            state.reached |= hook.is_some();
            hook
        } else {
            None
        };
        if let Some(path) = hook {
            replacement(&path).unwrap();
        }
        self.inner.execute_retained_effect(effect).await?;
        if let Some(candidate) = candidate {
            self.state.lock().unwrap().acknowledgments.push(candidate);
        }
        Ok(())
    }

    async fn random_bytes(&self, length: usize) -> io::Result<Vec<u8>> {
        self.inner.random_bytes(length).await
    }

    async fn read_nofollow(&self, path: &Path) -> io::Result<Vec<u8>> {
        self.inner.read_nofollow(path).await
    }

    async fn lock_existing_exclusive(&self, path: &Path) -> io::Result<Self::Lock> {
        self.inner.lock_existing_exclusive(path).await
    }

    async fn try_lock_existing_shared(&self, path: &Path) -> io::Result<Self::Lock> {
        self.inner.try_lock_existing_shared(path).await
    }

    async fn try_lock_existing_exclusive(&self, path: &Path) -> io::Result<Self::Lock> {
        self.inner.try_lock_existing_exclusive(path).await
    }

    async fn lock_exclusive(&self, path: &Path) -> io::Result<Self::Lock> {
        self.inner.lock_exclusive(path).await
    }

    async fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        self.inner.read(path).await
    }

    async fn read_range(&self, path: &Path, range: ByteRange) -> io::Result<Vec<u8>> {
        self.inner.read_range(path, range).await
    }

    async fn set_permissions_and_sync(
        &self,
        path: &Path,
        permissions: std::fs::Permissions,
    ) -> io::Result<()> {
        self.inner.set_permissions_and_sync(path, permissions).await
    }

    async fn write_new(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        self.inner.write_new(path, bytes).await
    }

    async fn create_dir_new(&self, path: &Path) -> io::Result<()> {
        self.inner.create_dir_new(path).await
    }

    async fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        self.inner.create_dir_all(path).await
    }

    async fn metadata(&self, path: &Path) -> io::Result<std::fs::Metadata> {
        self.inner.metadata(path).await
    }

    async fn symlink_metadata(&self, path: &Path) -> io::Result<std::fs::Metadata> {
        self.inner.symlink_metadata(path).await
    }

    async fn remove_file(&self, path: &Path) -> io::Result<()> {
        self.inner.remove_file(path).await
    }

    async fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.inner.rename(from, to).await
    }

    async fn rename_no_replace(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.inner.rename_no_replace(from, to).await
    }

    async fn sync_directory(&self, path: &Path) -> io::Result<()> {
        self.inner.sync_directory(path).await
    }

    async fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        self.inner.read_dir(path).await
    }

    async fn sync_file(&self, path: &Path) -> io::Result<()> {
        self.inner.sync_file(path).await
    }
}
