//! Injects failures into actual durable pack, log and authority filesystem operations.

#![allow(clippy::unwrap_used)]

use super::AdvanceError;
use super::native_fixture::NativeFixture;
use super::tests::{Validator, config, configured_with_fs, request, request_file_acl, token};
use crate::bucket::FileBucket;
use crate::store::{
    ByteRange, ContentStore, LocalFs, RefStore, StoreErrorKind, TokioClock, TokioLocalFs,
};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use terrane_core::bucket::BucketKey;

mod candidate_slot;

#[cfg(unix)]
mod mutation_ack;

use candidate_slot::{CandidateSlotBarrier, CandidateSlotPause};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Failure {
    Pack,
    Index,
    Log,
    RefDirectory,
    RefInstall,
    Entropy,
}

#[derive(Clone, Default)]
pub(super) struct FaultFs {
    #[cfg(unix)]
    mutation: mutation_ack::Hooks,
    failure: Arc<Mutex<Option<Failure>>>,
    ref_read_failure: Arc<Mutex<Option<usize>>>,
    lock_calls: Arc<AtomicUsize>,
    metadata_calls: Arc<AtomicUsize>,
    metadata_batches: Arc<AtomicUsize>,
    protected_read_calls: Arc<AtomicUsize>,
    retained_effect_calls: Arc<AtomicUsize>,
    ref_install_profile: Arc<Mutex<Option<std::time::Instant>>>,
    ref_install_barrier: Arc<Mutex<Option<Arc<RefInstallBarrier>>>>,
    candidate_slot_pause: Arc<Mutex<Option<CandidateSlotPause>>>,
    #[cfg(unix)]
    control_change: Arc<Mutex<Option<PathBuf>>>,
    #[cfg(unix)]
    registration_change_at_slot: Arc<Mutex<Option<PathBuf>>>,
    #[cfg(unix)]
    registration_dispatch: Arc<Mutex<Option<RegistrationDispatch>>>,
}

#[cfg(unix)]
#[derive(Clone)]
struct RegistrationDispatch {
    target: PathBuf,
    predecessor: (u64, [u8; 32]),
    staged_digest: [u8; 32],
    staged_proof: terrane_core::gc::publication::PublicationProof,
    staged_transaction: String,
    slots: Vec<ObservedSlot>,
}

#[cfg(unix)]
#[derive(Clone)]
struct ObservedSlot {
    stamp: (u64, [u8; 32]),
    proof: terrane_core::gc::publication::PublicationProof,
    keys: Vec<String>,
}

struct RefInstallBarrier {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl FaultFs {
    /// Pauses one exact genuine candidate slot before its retained native checks.
    ///
    /// The selector confers no authority and never changes the submitted effect.
    /// Unrelated roots, references and non-candidate slots leave it armed.
    ///
    /// # Errors
    /// Rejects malformed reference keys, poisoned synchronization or an already
    /// armed selector. The control path must be the actual destination factory's.
    pub(super) fn pause_candidate_slot(
        &self,
        control: PathBuf,
        reference: &str,
    ) -> std::io::Result<Arc<CandidateSlotBarrier>> {
        let reference = BucketKey::ref_record(reference).map_err(std::io::Error::other)?;
        let mut pending = self
            .candidate_slot_pause
            .lock()
            .map_err(|_| std::io::Error::other("candidate slot synchronization poisoned"))?;
        if pending.is_some() {
            return Err(std::io::Error::other("candidate slot pause already armed"));
        }
        let (selector, barrier) = CandidateSlotPause::new(control, reference);
        *pending = Some(selector);
        Ok(barrier)
    }

    #[cfg(unix)]
    pub(super) fn change_registration_during_slot_staging(&self, registration: PathBuf) {
        *self.registration_change_at_slot.lock().unwrap() = Some(registration);
    }

    #[cfg(unix)]
    pub(super) fn registration_slot_change_consumed(&self) -> bool {
        self.registration_change_at_slot.lock().unwrap().is_none()
    }

    /// Checks the complete dispatch predecessor and absent rejected slot.
    ///
    /// # Errors
    /// Returns a filesystem error if the rejected target cannot be inspected.
    #[cfg(unix)]
    pub(super) async fn assert_registration_slot_refused(
        &self,
        stamp: (u64, [u8; 32]),
    ) -> std::io::Result<()> {
        let dispatch = self.registration_dispatch.lock().unwrap().clone().unwrap();
        assert_eq!(stamp, dispatch.predecessor);
        assert_eq!(
            TokioLocalFs
                .symlink_metadata(&dispatch.target)
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::NotFound,
            "the rejected Guard slot must remain absent before reopen"
        );
        Ok(())
    }

    /// Reports the exact selected proof after a genuine registration fault.
    ///
    /// # Errors
    /// Rejects missing records or a mismatch in the actual selected digest.
    #[cfg(unix)]
    pub(super) async fn report_selected_registration_fault(
        &self,
        stamp: (u64, [u8; 32]),
    ) -> std::io::Result<()> {
        use terrane_core::gc::publication::{PublicationCommit, PublicationTransaction};

        let dispatch = self.registration_dispatch.lock().unwrap().clone().unwrap();
        let selected = dispatch.target.parent().unwrap().join(stamp.0.to_string());
        let bytes = TokioLocalFs.read_nofollow(&selected).await?;
        if blake3::hash(&bytes).as_bytes() != &stamp.1 {
            return Err(std::io::Error::other("selected diagnostic digest mismatch"));
        }
        let slot = PublicationCommit::decode(&bytes).map_err(std::io::Error::other)?;
        let control = selected.ancestors().nth(3).unwrap();
        let transaction_bytes = TokioLocalFs
            .read_nofollow(&control.join(&slot.transaction_key))
            .await?;
        let key = format!("publication/commits/{}", stamp.0);
        slot.check_transaction(&key, &transaction_bytes)
            .map_err(std::io::Error::other)?;
        let transaction =
            PublicationTransaction::decode(&transaction_bytes).map_err(std::io::Error::other)?;
        assert!(transaction.new.guard.is_none());
        if stamp != dispatch.predecessor {
            assert_eq!(stamp.0, dispatch.predecessor.0 + 1);
            assert_eq!(slot.predecessor, Some(dispatch.predecessor.1));
            assert_eq!(
                transaction.proof,
                terrane_core::gc::publication::PublicationProof::Raw
            );
            assert_eq!(transaction.changes.len(), 1);
            assert_eq!(transaction.changes[0].key, "CAPABILITIES");
            assert_eq!(
                transaction.new.branches,
                transaction.old.as_ref().unwrap().branches
            );
            assert_eq!(
                transaction.new.sources,
                transaction.old.as_ref().unwrap().sources
            );
            assert_ne!(stamp.1, dispatch.staged_digest);
            assert_ne!(slot.transaction_key, dispatch.staged_transaction);
        }
        eprintln!(
            "actual post-fault selected {:?}, transaction {}, proof {:?}, guard {:?}, keys {:?}; injected target {:?}, predecessor {:?}, staged digest {:?}, transaction {}, proof {:?}",
            stamp,
            slot.transaction_key,
            transaction.proof,
            transaction.new.guard,
            transaction
                .changes
                .iter()
                .map(|change| &change.key)
                .collect::<Vec<_>>(),
            dispatch.target,
            dispatch.predecessor,
            dispatch.staged_digest,
            dispatch.staged_transaction,
            dispatch.staged_proof,
        );
        Ok(())
    }

    #[cfg(unix)]
    async fn replace_registration_before_slot_effect(
        &self,
        source: &Path,
        target: &Path,
    ) -> std::io::Result<()> {
        use terrane_core::gc::publication::evidence::LocalOriginalRegistration;

        let registration = self.registration_change_at_slot.lock().unwrap().clone();
        if let Some(registration) = registration {
            let dispatch = Self::observe_slot_predecessor(source, target).await?;
            let mut record = LocalOriginalRegistration::decode(
                &TokioLocalFs.read_nofollow(&registration).await?,
            )
            .map_err(std::io::Error::other)?;
            record.original_id[0] ^= 1;
            let replacement =
                registration.with_file_name("staged-registration-replacement.fixture");
            TokioLocalFs
                .write_new(
                    &replacement,
                    &record.encode().map_err(std::io::Error::other)?,
                )
                .await?;
            TokioLocalFs
                .set_permissions_and_sync(
                    &replacement,
                    std::os::unix::fs::PermissionsExt::from_mode(0o600),
                )
                .await?;
            TokioLocalFs.rename(&replacement, &registration).await?;
            TokioLocalFs
                .sync_directory(registration.parent().unwrap())
                .await?;
            eprintln!(
                "registration fault target {:?}, exact predecessor {:?}",
                dispatch.target, dispatch.predecessor
            );
            for slot in &dispatch.slots {
                eprintln!(
                    "verified predecessor slot {} proof {:?}: {:?}",
                    slot.stamp.0, slot.proof, slot.keys
                );
            }
            *self.registration_dispatch.lock().unwrap() = Some(dispatch);
            *self.registration_change_at_slot.lock().unwrap() = None;
        }
        Ok(())
    }

    #[cfg(unix)]
    async fn observe_slot_predecessor(
        source: &Path,
        target: &Path,
    ) -> std::io::Result<RegistrationDispatch> {
        use terrane_core::gc::publication::{PublicationCommit, PublicationTransaction};

        let revision = target
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| std::io::Error::other("noncanonical slot target"))?
            .parse::<u64>()
            .map_err(std::io::Error::other)?;
        if target.file_name().unwrap() != revision.to_string().as_str() || revision == 0 {
            return Err(std::io::Error::other("missing canonical predecessor"));
        }
        let control = target
            .ancestors()
            .nth(3)
            .ok_or_else(|| std::io::Error::other("missing actual slot control"))?;
        let mut slots = Vec::new();
        let mut previous = None;
        let mut state = None;
        for current in 0..revision {
            let key = format!("publication/commits/{current}");
            let bytes = TokioLocalFs.read_nofollow(&control.join(&key)).await?;
            let slot = PublicationCommit::decode(&bytes).map_err(std::io::Error::other)?;
            let digest = *blake3::hash(&bytes).as_bytes();
            let transaction_bytes = TokioLocalFs
                .read_nofollow(&control.join(&slot.transaction_key))
                .await?;
            slot.check_transaction(&key, &transaction_bytes)
                .map_err(std::io::Error::other)?;
            let transaction = PublicationTransaction::decode(&transaction_bytes)
                .map_err(std::io::Error::other)?;
            if slot.revision != current
                || slot.predecessor != previous.as_ref().map(|value: &(u64, [u8; 32])| value.1)
                || transaction.old != state
                || transaction
                    .predecessor
                    .as_ref()
                    .map(|value| (value.revision, value.digest))
                    != previous
            {
                return Err(std::io::Error::other("mismatched actual selected chain"));
            }
            previous = Some((current, digest));
            state = Some(transaction.new);
            slots.push(ObservedSlot {
                stamp: (current, digest),
                proof: transaction.proof,
                keys: transaction
                    .changes
                    .into_iter()
                    .map(|change| change.key)
                    .collect(),
            });
        }
        let staged_bytes = TokioLocalFs.read_nofollow(source).await?;
        let staged = PublicationCommit::decode(&staged_bytes).map_err(std::io::Error::other)?;
        let transaction_bytes = TokioLocalFs
            .read_nofollow(&control.join(&staged.transaction_key))
            .await?;
        staged
            .check_transaction(
                &format!("publication/commits/{revision}"),
                &transaction_bytes,
            )
            .map_err(std::io::Error::other)?;
        let transaction =
            PublicationTransaction::decode(&transaction_bytes).map_err(std::io::Error::other)?;
        if staged.revision != revision
            || staged.predecessor != previous.map(|value| value.1)
            || transaction.old != state
        {
            return Err(std::io::Error::other("mismatched staged slot predecessor"));
        }
        Ok(RegistrationDispatch {
            staged_digest: *blake3::hash(&staged_bytes).as_bytes(),
            staged_proof: transaction.proof,
            staged_transaction: staged.transaction_key,
            target: target.to_owned(),
            predecessor: previous.ok_or_else(|| std::io::Error::other("absent predecessor"))?,
            slots,
        })
    }

    async fn staged_slot_transaction(
        from: &Path,
        to: &Path,
    ) -> std::io::Result<Option<terrane_core::gc::publication::PublicationTransaction>> {
        use terrane_core::gc::publication::{PublicationCommit, PublicationTransaction};

        if !to
            .parent()
            .is_some_and(|parent| parent.ends_with("publication/commits"))
        {
            return Ok(None);
        }
        let slot = PublicationCommit::decode(&TokioLocalFs.read_nofollow(from).await?)
            .map_err(std::io::Error::other)?;
        let control = to
            .ancestors()
            .nth(3)
            .ok_or_else(|| std::io::Error::other("missing slot control"))?;
        let bytes = TokioLocalFs
            .read_nofollow(&control.join(&slot.transaction_key))
            .await?;
        if blake3::hash(&bytes).as_bytes() != &slot.transaction_digest {
            return Err(std::io::Error::other("mismatched staged transaction"));
        }
        let transaction = PublicationTransaction::decode(&bytes).map_err(std::io::Error::other)?;
        Ok(Some(transaction))
    }

    async fn is_ref_slot(from: &Path, to: &Path) -> std::io::Result<bool> {
        let reference = BucketKey::ref_record("refs/heads/_/main").unwrap();
        Ok(Self::staged_slot_transaction(from, to)
            .await?
            .is_some_and(|transaction| {
                transaction
                    .changes
                    .iter()
                    .any(|change| change.key == reference.as_str())
            }))
    }

    fn before_authoritative_read(&self, path: &Path) -> std::io::Result<()> {
        if !path
            .parent()
            .is_some_and(|parent| parent.ends_with("publication/transactions"))
        {
            return Ok(());
        }
        let mut pending = self.ref_read_failure.lock().unwrap();
        match *pending {
            Some(0) => {
                *pending = None;
                Err(std::io::Error::other(
                    "injected current policy read failure",
                ))
            }
            Some(remaining) => {
                *pending = Some(remaining - 1);
                Ok(())
            }
            None => Ok(()),
        }
    }

    pub(super) fn lock_calls(&self) -> usize {
        self.lock_calls.load(Ordering::SeqCst)
    }

    #[cfg(unix)]
    pub(super) fn change_control_after_registration(&self, control: PathBuf) {
        *self.control_change.lock().unwrap() = Some(control);
    }

    #[cfg(unix)]
    pub(super) fn control_change_consumed(&self) -> bool {
        self.control_change.lock().unwrap().is_none()
    }

    async fn after_read(&self, path: &Path) -> std::io::Result<()> {
        #[cfg(unix)]
        if path
            .file_name()
            .is_some_and(|name| name == "registration.cbor")
        {
            use std::os::unix::fs::PermissionsExt;

            let control = self.control_change.lock().unwrap().take();
            if let Some(control) = control {
                TokioLocalFs
                    .set_permissions(&control, std::fs::Permissions::from_mode(0o755))
                    .await?;
            }
        }

        Ok(())
    }

    #[allow(
        clippy::disallowed_methods,
        reason = "Native test diagnostics measure preparation only; host time never enters authored or Crucible state."
    )]
    fn pause_ref_install(&self) -> Arc<RefInstallBarrier> {
        let barrier = Arc::new(RefInstallBarrier {
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        *self.ref_install_barrier.lock().unwrap() = Some(barrier.clone());
        self.metadata_calls.store(0, Ordering::SeqCst);
        self.metadata_batches.store(0, Ordering::SeqCst);
        self.protected_read_calls.store(0, Ordering::SeqCst);
        self.retained_effect_calls.store(0, Ordering::SeqCst);
        *self.ref_install_profile.lock().unwrap() = Some(std::time::Instant::now());
        barrier
    }

    fn fail(&self, failure: Failure) {
        *self.failure.lock().unwrap() = Some(failure);
    }

    fn fail_ref_read_after(&self, successful_reads: usize) {
        *self.ref_read_failure.lock().unwrap() = Some(successful_reads);
    }

    fn check(&self, failure: Failure) -> std::io::Result<()> {
        let mut pending = self.failure.lock().unwrap();
        if *pending == Some(failure) {
            *pending = None;
            return Err(std::io::Error::other("injected publication failure"));
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl LocalFs for FaultFs {
    type Lock = crate::store::TokioFileLock;

    async fn initialize_publication(
        &self,
        request: crate::store::NativePublicationInitialization,
    ) -> Result<crate::store::NativePublicationInitializationOutcome, crate::store::StoreFailure>
    {
        TokioLocalFs.initialize_publication(request).await
    }

    fn retain_native_exclusion(
        &self,
        held: &Self::Lock,
    ) -> std::io::Result<crate::store::NativeExclusion> {
        TokioLocalFs.retain_native_exclusion(held)
    }

    #[allow(
        clippy::disallowed_methods,
        reason = "Native test diagnostics report elapsed preparation only; effect authorization uses the actual retained clock."
    )]
    async fn execute_retained_effect(
        &self,
        effect: crate::store::NativeFsEffect,
    ) -> Result<(), crate::store::NativeEffectFailure> {
        let count = self.retained_effect_calls.fetch_add(1, Ordering::SeqCst) + 1;
        if let Some(started) = *self.ref_install_profile.lock().unwrap() {
            let phase = match effect.fault_probe() {
                crate::store::EffectFaultProbe::SealPendingCreation(_) => "Pending journal sync",
                crate::store::EffectFaultProbe::SealArtifact(_) => "artifact descriptor sync",
                crate::store::EffectFaultProbe::CommitCreation(_) => "creation journal commitment",
                crate::store::EffectFaultProbe::FileSync => "file sync",
                crate::store::EffectFaultProbe::WriteNew(_) => "create-new write",
                crate::store::EffectFaultProbe::DirectorySync(_) => "directory sync",
                crate::store::EffectFaultProbe::RenameNoReplace(_) => "create-once rename",
                crate::store::EffectFaultProbe::Rename(_) => "replacing rename",
                crate::store::EffectFaultProbe::SealMutationPublication(_) => {
                    "checked mutation publication"
                }
                crate::store::EffectFaultProbe::SealLeasePublication(path) => {
                    eprintln!("lease publication slot {}", path.display());
                    "lease publication"
                }
                crate::store::EffectFaultProbe::Other => "other effect",
            };
            eprintln!(
                "actual preparation {:?}: effect {count} ({phase}), {} metadata paths in {} ordered batches, {} protected reads",
                started.elapsed(),
                self.metadata_calls.load(Ordering::SeqCst),
                self.metadata_batches.load(Ordering::SeqCst),
                self.protected_read_calls.load(Ordering::SeqCst),
            );
        }
        #[cfg(unix)]
        if matches!(
            effect.fault_probe(),
            crate::store::EffectFaultProbe::SealMutationPublication(_)
        ) {
            return mutation_ack::execute(self, effect).await;
        }
        let mut effect = effect;
        let content_failure = match effect.fault_probe() {
            crate::store::EffectFaultProbe::RenameNoReplace(target) => {
                match target.extension().and_then(|extension| extension.to_str()) {
                    Some("pack") => Some(Failure::Pack),
                    Some("idx") => Some(Failure::Index),
                    _ => None,
                }
            }
            _ => None,
        };
        if let Some(content_failure) = content_failure {
            let mut pending = self.failure.lock().unwrap();
            if *pending == Some(content_failure) {
                *pending = None;
                // Fail the genuine fixed content rename before it takes effect.
                effect = effect.inject_test_faults(vec![crate::store::EffectFault::BeforeRename]);
            }
        }
        let candidate_log = matches!(
            effect.fault_probe(),
            crate::store::EffectFaultProbe::RenameNoReplace(target)
                if target.components().any(|component| component.as_os_str() == "logs")
        );
        if candidate_log {
            let inject = {
                let mut pending = self.failure.lock().unwrap();
                if *pending == Some(Failure::Log) {
                    *pending = None;
                    true
                } else {
                    false
                }
            };
            if inject {
                // The candidate log's own fixed rename completes before its
                // durability failure; the checked branch slot must never follow.
                effect =
                    effect.inject_test_faults(vec![crate::store::EffectFault::BeforeDirectorySync]);
            }
        }
        let staged_transaction = match (effect.rename_noreplace_source(), effect.fault_probe()) {
            (Some(source), crate::store::EffectFaultProbe::RenameNoReplace(target)) => {
                Self::staged_slot_transaction(source, target)
                    .await
                    .map_err(crate::store::NativeEffectFailure::Io)?
            }
            _ => None,
        };
        let reference = BucketKey::ref_record("refs/heads/_/main").unwrap();
        let branch_slot = staged_transaction.as_ref().is_some_and(|transaction| {
            transaction
                .changes
                .iter()
                .any(|change| change.key == reference.as_str())
        });
        if branch_slot {
            let injected = {
                let mut pending = self.failure.lock().unwrap();
                match *pending {
                    Some(Failure::RefInstall) => {
                        *pending = None;
                        Some(crate::store::EffectFault::BeforeRename)
                    }
                    Some(Failure::RefDirectory) => {
                        *pending = None;
                        Some(crate::store::EffectFault::BeforeDirectorySync)
                    }
                    _ => None,
                }
            };
            if let Some(injected) = injected {
                effect = effect.inject_test_faults(vec![injected]);
            }
            let barrier = self.ref_install_barrier.lock().unwrap().take();
            if let Some(barrier) = barrier {
                barrier.entered.notify_one();
                barrier.release.notified().await;
            }
        }

        #[cfg(unix)]
        {
            let selected_slot = match effect.fault_probe() {
                crate::store::EffectFaultProbe::RenameNoReplace(path)
                    if path
                        .parent()
                        .is_some_and(|parent| parent.ends_with("publication/commits")) =>
                {
                    Some(path.to_owned())
                }
                _ => None,
            };
            let checked_actor_slot = staged_transaction.as_ref().is_some_and(|transaction| {
                matches!(
                    transaction.proof,
                    terrane_core::gc::publication::PublicationProof::Guard(_)
                        | terrane_core::gc::publication::PublicationProof::Candidate(_)
                )
            });
            if let Some(selected_slot) = selected_slot.filter(|_| checked_actor_slot) {
                // Staging has finished. The genuine worker must reject this
                // changed consumed record before its fixed selected-slot rename.
                let staged_source = effect.rename_noreplace_source().unwrap().to_owned();
                self.replace_registration_before_slot_effect(&staged_source, &selected_slot)
                    .await
                    .map_err(crate::store::NativeEffectFailure::Io)?;
            }
        }
        let candidate_barrier = {
            let mut pending = self.candidate_slot_pause.lock().map_err(|_| {
                crate::store::NativeEffectFailure::Io(std::io::Error::other(
                    "candidate slot synchronization poisoned",
                ))
            })?;
            let matched = match effect.fault_probe() {
                crate::store::EffectFaultProbe::RenameNoReplace(target) => pending
                    .as_ref()
                    .is_some_and(|pause| pause.matches(target, staged_transaction.as_ref())),
                _ => false,
            };
            if matched {
                pending.take().map(CandidateSlotPause::into_barrier)
            } else {
                None
            }
        };
        if let Some(barrier) = candidate_barrier {
            // The worker's actual final check runs after this pause. No mutex
            // guard survives the wait and the genuine effect remains intact.
            barrier.pause().await;
        }
        TokioLocalFs.execute_retained_effect(effect).await
    }

    #[cfg(unix)]
    async fn before_candidate_projection_for_tests(&self, root: &Path) -> std::io::Result<()> {
        self.mutation.before_candidate_projection(root)
    }

    async fn random_bytes(&self, length: usize) -> std::io::Result<Vec<u8>> {
        self.check(Failure::Entropy)?;
        TokioLocalFs.random_bytes(length).await
    }

    async fn lock_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        self.lock_calls.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.lock_exclusive(path).await
    }

    async fn lock_existing_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        self.lock_calls.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.lock_existing_exclusive(path).await
    }

    async fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        self.before_authoritative_read(path)?;
        let bytes = TokioLocalFs.read(path).await?;
        self.after_read(path).await?;
        Ok(bytes)
    }

    async fn read_range(&self, path: &Path, range: ByteRange) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.read_range(path, range).await
    }

    async fn read_nofollow(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        self.protected_read_calls.fetch_add(1, Ordering::SeqCst);
        self.before_authoritative_read(path)?;
        let bytes = TokioLocalFs.read_nofollow(path).await?;
        self.after_read(path).await?;
        Ok(bytes)
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
        self.metadata_calls.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.symlink_metadata(path).await
    }

    async fn symlink_metadata_batch(
        &self,
        paths: &[PathBuf],
    ) -> std::io::Result<Vec<std::io::Result<std::fs::Metadata>>> {
        self.metadata_calls.fetch_add(paths.len(), Ordering::SeqCst);
        self.metadata_batches.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.symlink_metadata_batch(paths).await
    }

    async fn remove_file(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.remove_file(path).await
    }

    async fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        TokioLocalFs.rename(from, to).await
    }

    async fn rename_no_replace(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        if Self::is_ref_slot(from, to).await? {
            self.check(Failure::RefInstall)?;
            let barrier = self.ref_install_barrier.lock().unwrap().take();
            if let Some(barrier) = barrier {
                barrier.entered.notify_one();
                barrier.release.notified().await;
            }
        }
        if to.extension().is_some_and(|extension| extension == "pack") {
            self.check(Failure::Pack)?;
        }
        if to.extension().is_some_and(|extension| extension == "idx") {
            self.check(Failure::Index)?;
        }
        if to
            .components()
            .any(|component| component.as_os_str() == "logs")
        {
            self.check(Failure::Log)?;
        }
        TokioLocalFs.rename_no_replace(from, to).await
    }

    async fn sync_file(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.sync_file(path).await
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

    async fn sync_directory(&self, path: &Path) -> std::io::Result<()> {
        if path.ends_with("refs/heads/_")
            && !path
                .components()
                .any(|component| component.as_os_str() == "logs")
        {
            self.check(Failure::RefDirectory)?;
        }
        TokioLocalFs.sync_directory(path).await
    }
}

async fn fixture(fs: FaultFs) -> FileBucket<FaultFs, TokioClock, Validator> {
    let entropy = TokioLocalFs.random_bytes(16).await.unwrap();
    let suffix = entropy
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let root = std::env::temp_dir().join(format!("terrane-ref-fault-{suffix}"));
    FileBucket::open(config(root).await, fs, TokioClock, Validator)
        .await
        .unwrap()
}

#[cfg(unix)]
#[tokio::test]
async fn ordinary_advance_rechecks_used_registration_before_retained_slot_dispatch() {
    use crate::bucket::held::SingleHeld;

    let fs = FaultFs::default();
    let coordinator =
        NativeFixture::initialize(configured_with_fs(fixture(fs.clone()).await, fs.clone())).await;
    let reference = "refs/heads/_/main";
    let mut session = coordinator.begin(reference, &token(), "sdk").await.unwrap();
    let first = coordinator
        .advance(&mut session, request(Vec::new()))
        .await
        .unwrap();
    let original = coordinator.guard().original_commit(&first.commit).unwrap();
    let registration = original
        .baseline()
        .authority()
        .control()
        .join("registration.cbor");
    let before = {
        let held = SingleHeld::acquire(coordinator.store()).await.unwrap();
        let destination = held.destination();
        destination.observe_publication().await.unwrap().stamp()
    };

    fs.change_registration_during_slot_staging(registration);
    let attempted = coordinator
        .advance(
            &mut session,
            super::tests::request_file(vec![first.commit], b"unselected candidate"),
        )
        .await;

    assert!(fs.registration_slot_change_consumed());
    assert!(attempted.is_err());
    assert_eq!(
        coordinator.store().ref_get(reference).await.unwrap(),
        Some(first)
    );
    let dispatch = fs.registration_dispatch.lock().unwrap().clone().unwrap();
    assert_eq!(dispatch.slots[before.0 as usize].stamp, before);
    assert!(dispatch.predecessor.0 > before.0);

    // Pack and index preparation may select Raw slots before the checked branch
    // dispatch. The rejected dispatch must preserve that exact chained predecessor.
    for slot in dispatch.slots.iter().filter(|slot| slot.stamp.0 > before.0) {
        assert_eq!(
            slot.proof,
            terrane_core::gc::publication::PublicationProof::Raw
        );
        eprintln!(
            "preparatory selected slot {}: {:?}",
            slot.stamp.0, slot.keys
        );
    }
    let held = SingleHeld::acquire(coordinator.store()).await.unwrap();
    let destination = held.destination();
    assert_eq!(
        destination.observe_publication().await.unwrap().stamp(),
        dispatch.predecessor,
        "changed used registration must not select an ordinary branch advance"
    );
    assert_eq!(
        TokioLocalFs
            .symlink_metadata(&dispatch.target)
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotFound,
        "the rejected checked slot must remain absent"
    );
}

#[tokio::test]
async fn captured_admin_request_preserves_unavailable_current_policy() {
    use terrane_core::identity::{IdentityKind, TERRANE_V1};

    let fs = FaultFs::default();
    let coordinator =
        NativeFixture::initialize(configured_with_fs(fixture(fs.clone()).await, fs.clone())).await;
    let reference = "refs/heads/_/main";
    let mut session = coordinator.begin(reference, &token(), "sdk").await.unwrap();
    let first = coordinator
        .advance(&mut session, request(Vec::new()))
        .await
        .unwrap();
    let candidate = request_file_acl(vec![first.commit], b"unpublished after policy failure", 15);
    let node = TERRANE_V1
        .from_digest(IdentityKind::Node, &candidate.commit.tree)
        .unwrap();
    let chunk = TERRANE_V1
        .calculate(IdentityKind::Chunk, b"unpublished after policy failure")
        .unwrap();
    let admitted = coordinator
        .guard()
        .admit(reference, session.epoch(), candidate)
        .await
        .unwrap();
    let failure = {
        let namespace = crate::bucket::held::SingleHeld::acquire(coordinator.store())
            .await
            .unwrap();
        let destination = namespace.destination();
        let proof = destination.identity_proof();
        let guard = coordinator
            .guard()
            .held_guard(namespace.destination(), TokioClock)
            .unwrap();
        let history = crate::guard::HistoryObservation::held(&proof);
        let current = guard
            .capture_admission_authorizations_observed(&admitted, history)
            .await
            .unwrap();
        assert!(
            current
                .iter()
                .any(|request| request.verb() == terrane_core::auth::Verb::Admin)
        );

        fs.fail_ref_read_after(2);
        guard
            .capture_admission_authorizations_observed(&admitted, history)
            .await
            .unwrap_err()
    };
    assert!(matches!(failure.kind(), StoreErrorKind::Unavailable { .. }));
    assert!(fs.ref_read_failure.lock().unwrap().is_none());
    assert_eq!(
        coordinator.store().ref_get(reference).await.unwrap(),
        Some(first)
    );
    assert_eq!(
        coordinator.store().has(&[node, chunk]).await.unwrap(),
        [false, false]
    );

    tokio::fs::remove_dir_all(coordinator.store().root())
        .await
        .unwrap();
}

#[tokio::test]
async fn unavailable_admin_policy_read_never_falls_back_or_publishes_objects() {
    use terrane_core::identity::{IdentityKind, TERRANE_V1};

    let fs = FaultFs::default();
    let coordinator =
        NativeFixture::initialize(configured_with_fs(fixture(fs.clone()).await, fs.clone())).await;
    let reference = "refs/heads/_/main";
    let mut session = coordinator.begin(reference, &token(), "sdk").await.unwrap();
    let first = coordinator
        .advance(&mut session, request(Vec::new()))
        .await
        .unwrap();
    let plaintext = b"unpublished ACL-changing coordinator request";
    let candidate = request_file_acl(vec![first.commit], plaintext, 15);
    let node = TERRANE_V1
        .from_digest(IdentityKind::Node, &candidate.commit.tree)
        .unwrap();
    let chunk = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .unwrap();
    let admitted = coordinator
        .guard()
        .admit(
            reference,
            session.epoch(),
            request_file_acl(vec![first.commit], plaintext, 15),
        )
        .await
        .unwrap();
    let commit = TERRANE_V1
        .from_digest(IdentityKind::Commit, &admitted.commit.identity())
        .unwrap();
    let before = {
        let namespace = crate::bucket::held::SingleHeld::acquire(coordinator.store())
            .await
            .unwrap();
        let destination = namespace.destination();
        destination.observe_publication().await.unwrap().stamp()
    };

    fs.fail_ref_read_after(2);
    let failure = coordinator
        .advance(&mut session, candidate)
        .await
        .unwrap_err();
    assert!(
        matches!(failure, AdvanceError::Store(error) if matches!(error.kind(), StoreErrorKind::Unavailable { .. }))
    );
    assert!(fs.ref_read_failure.lock().unwrap().is_none());
    assert_eq!(
        coordinator.store().ref_get(reference).await.unwrap(),
        Some(first)
    );
    assert_eq!(
        coordinator
            .store()
            .has(&[node, chunk, commit])
            .await
            .unwrap(),
        [false, false, false]
    );
    let namespace = crate::bucket::held::SingleHeld::acquire(coordinator.store())
        .await
        .unwrap();
    let destination = namespace.destination();
    let after = destination.observe_publication().await.unwrap();
    assert_eq!(after.stamp(), before, "failed advance must select no slot");
}

#[tokio::test]
async fn ref_advance_ordering_pack_index_or_log_failure_never_publishes_head() {
    for failure in [Failure::Pack, Failure::Index, Failure::Log] {
        let fs = FaultFs::default();
        let coordinator =
            NativeFixture::initialize(configured_with_fs(fixture(fs.clone()).await, fs.clone()))
                .await;
        let mut session = coordinator
            .begin("refs/heads/_/main", &token(), "sdk")
            .await
            .unwrap();
        fs.fail(failure);

        assert!(
            coordinator
                .advance(&mut session, request(Vec::new()))
                .await
                .is_err(),
            "{failure:?}"
        );
        assert!(
            fs.failure.lock().unwrap().is_none(),
            "fault was not reached: {failure:?}"
        );
        let root = coordinator.store().root().to_owned();
        let reopened = FileBucket::open(
            config(root.clone()).await,
            TokioLocalFs,
            TokioClock,
            Validator,
        )
        .await
        .unwrap();
        assert!(
            reopened
                .ref_get(session.reference())
                .await
                .unwrap()
                .is_none()
        );
        tokio::fs::remove_dir_all(root).await.unwrap();
    }
}

#[tokio::test]
async fn final_cas_directory_failure_is_indeterminate_and_fences_the_writer() {
    let fs = FaultFs::default();
    let coordinator =
        NativeFixture::initialize(configured_with_fs(fixture(fs.clone()).await, fs.clone())).await;
    let mut session = coordinator
        .begin("refs/heads/_/main", &token(), "sdk")
        .await
        .unwrap();
    let first = coordinator
        .advance(&mut session, request(Vec::new()))
        .await
        .unwrap();
    fs.fail(Failure::RefDirectory);

    let observed = match coordinator
        .advance(&mut session, request(vec![first.commit]))
        .await
    {
        Err(AdvanceError::Indeterminate {
            observed: Ok(Some(record)),
            ..
        }) => record,
        other => panic!("expected indeterminate applied CAS, got {other:?}"),
    };
    assert_eq!(observed.seq, 2);
    assert!(matches!(
        coordinator
            .advance(&mut session, request(vec![observed.commit]))
            .await,
        Err(AdvanceError::Fenced { .. })
    ));
    let root = coordinator.store().root().to_owned();
    let reopened = FileBucket::open(
        config(root.clone()).await,
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    assert_eq!(
        reopened.ref_get(session.reference()).await.unwrap(),
        Some(*observed)
    );
    tokio::fs::remove_dir_all(root).await.unwrap();
}

#[tokio::test]
async fn abandoned_durable_candidate_does_not_block_a_reopened_writer() {
    let fs = FaultFs::default();
    let coordinator =
        NativeFixture::initialize(configured_with_fs(fixture(fs.clone()).await, fs.clone())).await;
    let mut session = coordinator
        .begin("refs/heads/_/main", &token(), "sdk")
        .await
        .unwrap();
    let first = coordinator
        .advance(&mut session, request(Vec::new()))
        .await
        .unwrap();
    fs.fail(Failure::RefInstall);
    assert!(
        matches!(coordinator.advance(&mut session, request(vec![first.commit])).await,
        Err(AdvanceError::Indeterminate { observed: Ok(Some(ref observed)), .. }) if **observed == first)
    );
    assert!(fs.failure.lock().unwrap().is_none());
    let root = coordinator.store().root().to_owned();
    let candidates = TokioLocalFs
        .read_dir(&root.join("logs/refs/heads/_/main"))
        .await
        .unwrap();
    assert_eq!(
        candidates.len(),
        2,
        "the rejected head install left its durable proposal"
    );
    let reopened = FileBucket::open(
        config(root.clone()).await,
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    assert_eq!(
        reopened
            .ref_log_read(session.reference(), 1)
            .await
            .unwrap()
            .len(),
        1
    );
    let renewed = NativeFixture::reopen(configured_with_fs(reopened, TokioLocalFs)).await;
    let mut writer = renewed
        .begin(session.reference(), &token(), "sdk")
        .await
        .unwrap();
    let second = renewed
        .advance(&mut writer, request(vec![first.commit]))
        .await
        .unwrap();
    assert_eq!(second.seq, 2);
    assert!(second.writer_epoch > first.writer_epoch);
    let all = TokioLocalFs
        .read_dir(&root.join("logs/refs/heads/_/main"))
        .await
        .unwrap();
    assert_eq!(
        all.len(),
        3,
        "the fresh selector preserves the abandoned proposal"
    );
    let selected = renewed
        .store()
        .ref_log_read(session.reference(), 1)
        .await
        .unwrap();
    assert_eq!(selected.len(), 2);
    assert_eq!(selected[1].record, second);
    assert_eq!(selected[1].expected_previous, Some(Some(first)));
    tokio::fs::remove_dir_all(root).await.unwrap();
}

#[tokio::test]
async fn missing_secure_entropy_never_publishes_a_candidate_or_head() {
    let fs = FaultFs::default();
    let coordinator =
        NativeFixture::initialize(configured_with_fs(fixture(fs.clone()).await, fs.clone())).await;
    let mut session = coordinator
        .begin("refs/heads/_/main", &token(), "sdk")
        .await
        .unwrap();
    fs.fail(Failure::Entropy);
    assert!(matches!(
        coordinator.advance(&mut session, request(Vec::new())).await,
        Err(AdvanceError::Store(_))
    ));
    assert!(fs.failure.lock().unwrap().is_none());
    assert!(
        coordinator
            .store()
            .ref_get(session.reference())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        coordinator
            .store()
            .ref_log_read(session.reference(), 1)
            .await
            .unwrap()
            .is_empty()
    );
    tokio::fs::remove_dir_all(coordinator.store().root())
        .await
        .unwrap();
}

#[tokio::test]
async fn ref_advance_ordering_cancelled_held_publication_releases_independent_writer() {
    use std::time::Duration;

    let fs = FaultFs::default();
    let coordinator =
        NativeFixture::initialize(configured_with_fs(fixture(fs.clone()).await, fs.clone())).await;
    let reference = "refs/heads/_/main";
    let mut session = coordinator.begin(reference, &token(), "sdk").await.unwrap();
    let first = coordinator
        .advance(&mut session, request(Vec::new()))
        .await
        .unwrap();
    let root = coordinator.store().root().to_owned();
    let independent_bucket = FileBucket::open(
        config(root.clone()).await,
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    let independent =
        NativeFixture::reopen(configured_with_fs(independent_bucket, TokioLocalFs)).await;

    let barrier = fs.pause_ref_install();
    let publication = tokio::spawn(async move {
        coordinator
            .advance(&mut session, request(vec![first.commit]))
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), barrier.entered.notified())
        .await
        .unwrap();
    let mut competitor = tokio::spawn(async move {
        let session = independent.begin(reference, &token(), "sdk").await.unwrap();
        (independent, session)
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut competitor)
            .await
            .is_err(),
        "an independently opened writer must remain blocked by final publication exclusion"
    );

    publication.abort();
    assert!(publication.await.unwrap_err().is_cancelled());
    let (independent, mut session) = tokio::time::timeout(Duration::from_secs(2), competitor)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.record(), Some(&first));
    let second = independent
        .advance(&mut session, request(vec![first.commit]))
        .await
        .unwrap();
    assert_eq!(second.seq, first.seq + 1);
    assert!(second.writer_epoch > first.writer_epoch);
    let selected = independent
        .store()
        .ref_log_read(reference, 1)
        .await
        .unwrap();
    assert_eq!(selected.len(), 2);
    assert_eq!(selected[1].record, second);
    assert_eq!(selected[1].expected_previous, Some(Some(first)));
    let proposals = TokioLocalFs
        .read_dir(&root.join("logs/refs/heads/_/main"))
        .await
        .unwrap();
    assert_eq!(
        proposals.len(),
        3,
        "the cancelled durable proposal remains unselected"
    );

    tokio::fs::remove_dir_all(root).await.unwrap();
}
