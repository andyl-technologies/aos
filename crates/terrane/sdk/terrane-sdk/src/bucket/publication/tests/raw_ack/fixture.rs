//! Supplies native Raw publication fixtures and exact final-worker interventions.
//!
//! The adapter forwards initialization and every ordinary operation. Only an
//! already sealed Raw acknowledgment can be skipped, faulted or held; no test
//! constructs its request, receiver, projection or native exclusion.

use crate::bucket::{FileBucket, FileBucketConfig, held::SingleHeld};
use crate::store::{
    ByteRange, EffectFault, EffectFaultProbe, LocalFs, NativeEffectFailure, NativeExclusion,
    NativeFsEffect, NativePublicationInitialization, NativePublicationInitializationOutcome,
    RefStore, StoreFailure, TokioClock, TokioFileLock, TokioLocalFs,
};
use std::{
    error::Error,
    io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, mpsc},
    time::Duration,
};
use terrane_format::gc::publication::{
    PortableCurrent, PortableSnapshot, PublicationCommit, PublicationProof, PublicationState,
    PublicationTransaction,
};
use terrane_format::refs::{Locality, RefRecord};

/// Preserves real fixture, producer and executor failures.
pub(super) type Failure = Box<dyn Error + Send + Sync>;

/// Names the genuine native-backed bucket with boundary observation.
pub(super) type Bucket = FileBucket<ProbeFs, TokioClock, crate::bucket::tests::Validator>;

/// Names the backend-only tag used by every independently initialized fixture.
pub(super) const NAME: &str = "refs/tags/_/raw-ack";

/// Fixes a negative intervention at the actual closed Raw worker dispatch.
pub(super) enum Action {
    /// Returns unit without executing the request; its private channel stays empty.
    Noop,
    /// Executes a real sync fault, preserving its failure.
    Fault(EffectFault),
    /// Executes and records a real sync failure before deliberately swallowing it.
    Swallow(EffectFault),
    /// Holds the native worker at its actual directory syscall handoff.
    Handoff {
        /// Reports the actual before-directory-sync boundary.
        before: mpsc::Sender<()>,
        /// Releases the retained native worker.
        release: mpsc::Receiver<()>,
        /// Reports the actual after-directory-sync boundary.
        after: mpsc::Sender<()>,
    },
}

struct Hook {
    slot: PathBuf,
    action: Action,
}

/// Records an actual Raw acknowledgment failure before the caller's store mapping.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct NativeError {
    /// The real I/O kind, absent for a rejected owning check.
    pub(super) io_kind: Option<io::ErrorKind>,
    /// The unchanged real executor diagnostic.
    pub(super) message: String,
}

#[derive(Default)]
struct State {
    hook: Mutex<Option<Hook>>,
    slots: Mutex<Vec<PathBuf>>,
    errors: Mutex<Vec<NativeError>>,
}

/// Forwards real native execution with one exact Raw boundary intervention.
#[derive(Clone, Default)]
pub(super) struct ProbeFs(Arc<State>);

fn lock<T>(mutex: &Mutex<T>) -> io::Result<MutexGuard<'_, T>> {
    mutex
        .lock()
        .map_err(|_| io::Error::other("Raw fixture mutex poisoned"))
}

impl ProbeFs {
    /// Arms only the exact selecting slot in a genuinely produced Raw request.
    ///
    /// # Errors
    /// Refuses poisoned synchronization or an already armed intervention.
    pub(super) fn arm(&self, slot: PathBuf, action: Action) -> io::Result<()> {
        let mut pending = lock(&self.0.hook)?;
        if pending.is_some() {
            return Err(io::Error::other("Raw fixture already armed"));
        }
        *pending = Some(Hook { slot, action });
        Ok(())
    }

    /// Returns the real closed Raw dispatches, preserving their order.
    ///
    /// # Errors
    /// Refuses poisoned synchronization.
    pub(super) fn slots(&self) -> io::Result<Vec<PathBuf>> {
        Ok(lock(&self.0.slots)?.clone())
    }

    /// Takes genuine Raw executor errors recorded before any deliberate swallowing.
    ///
    /// # Errors
    /// Refuses poisoned synchronization.
    pub(super) fn errors(&self) -> io::Result<Vec<NativeError>> {
        Ok(std::mem::take(&mut *lock(&self.0.errors)?))
    }

    /// Checks that the selected actual effect consumed the entire intervention.
    ///
    /// # Errors
    /// Refuses poisoned synchronization or an unmatched intervention.
    pub(super) fn consumed(&self) -> io::Result<()> {
        if lock(&self.0.hook)?.is_some() {
            return Err(io::Error::other("Raw fixture intervention not consumed"));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl LocalFs for ProbeFs {
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
        mut effect: NativeFsEffect,
    ) -> Result<(), NativeEffectFailure> {
        let is_raw_acknowledgment = matches!(
            effect.fault_probe(),
            EffectFaultProbe::SealRawPublication(_)
        );

        let action = if let EffectFaultProbe::SealRawPublication(slot) = effect.fault_probe() {
            lock(&self.0.slots)?.push(slot.to_owned());
            let mut pending = lock(&self.0.hook)?;
            if pending.as_ref().is_some_and(|hook| hook.slot == slot) {
                pending.take().map(|hook| hook.action)
            } else {
                None
            }
        } else {
            None
        };

        let swallow = match action {
            Some(Action::Noop) => return Ok(()),
            Some(Action::Fault(fault)) => {
                effect = effect.inject_test_faults(vec![fault]);
                false
            }
            Some(Action::Swallow(fault)) => {
                effect = effect.inject_test_faults(vec![fault]);
                true
            }
            Some(Action::Handoff {
                before,
                release,
                after,
            }) => {
                effect = effect.test_directory_sync_handoff(before, release, after);
                false
            }
            None => false,
        };

        let result = TokioLocalFs.execute_retained_effect(effect).await;
        if is_raw_acknowledgment && let Err(error) = &result {
            let io_kind = match error {
                NativeEffectFailure::Io(error) => Some(error.kind()),
                NativeEffectFailure::Rejected(_) => None,
            };
            lock(&self.0.errors)?.push(NativeError {
                io_kind,
                message: error.to_string(),
            });
        }
        if swallow {
            if result.is_ok() {
                return Err(io::Error::other("Raw fixture swallowed no actual failure").into());
            }
            Ok(())
        } else {
            result
        }
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

/// Owns a genuinely initialized namespace and independently configured backend.
pub(super) struct Fixture {
    /// The actual writable native bucket.
    pub(super) bucket: Bucket,
    /// The same configuration used for native reopening.
    pub(super) config: FileBucketConfig,
    /// The actual backend observer, shared by bucket clones.
    pub(super) fs: ProbeFs,
    /// The actual external protected publication control directory.
    pub(super) control: PathBuf,
}

/// Initializes the real native root without constructing backend authority.
///
/// # Errors
/// Preserves entropy, initialization and filesystem failures.
///
/// # Panics
/// Panics if the existing operator-configuration fixture fails its owner probe
/// or native initialization unexpectedly dispatches a Raw acknowledgment.
pub(super) async fn fixture() -> Result<Fixture, Failure> {
    let entropy = TokioLocalFs.random_bytes(16).await?;
    let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
    let root = std::env::temp_dir().join(format!("terrane-raw-ack-{suffix}"));
    let config = crate::bucket::tests::config(root);
    let control = crate::bucket::tests::control_path(&config.root);
    let fs = ProbeFs::default();
    let bucket = FileBucket::open(
        config.clone(),
        fs.clone(),
        TokioClock,
        crate::bucket::tests::Validator,
    )
    .await?;
    assert!(fs.slots()?.is_empty());
    Ok(Fixture {
        bucket,
        config,
        fs,
        control,
    })
}

impl Fixture {
    /// Returns the independent expected first selecting slot.
    pub(super) fn slot(&self) -> PathBuf {
        self.control.join("publication/commits/1")
    }

    /// Reopens through the ordinary native factory and reads the selected tag.
    ///
    /// # Errors
    /// Preserves reopening, selected-chain, artifact decode and native read failures.
    ///
    /// # Panics
    /// Panics if the published tag or exact predecessor differs, or reopening
    /// selects any successor beyond its single capability timestamp update.
    pub(super) async fn reopen(&self) -> Result<(), Failure> {
        let prior = before(&self.bucket).await?;
        assert_eq!(prior.state.revision, 1);

        let reopened = FileBucket::open(
            self.config.clone(),
            self.fs.clone(),
            TokioClock,
            crate::bucket::tests::Validator,
        )
        .await?;
        let holder = SingleHeld::acquire(&reopened).await?;
        let held = holder.destination();
        let observed = held.observe_publication().await?;
        if observed.stamp() == prior.stamp {
            assert_eq!(observed.state(), &prior.state);
            assert_eq!(observed.snapshot(), &prior.snapshot);
        } else {
            // Native open may refresh probed_at in a fresh Raw transition. Check
            // the exact journal; an arbitrary later revision is never accepted.
            self.check_probe_successor(&prior, &observed).await?;
        }
        assert_eq!(held.ref_get(NAME).await?, Some(record()));
        Ok(())
    }

    // Independently checks the one capability-only transition that native open
    // can publish, including its complete installed slot/snapshot association.
    async fn check_probe_successor(
        &self,
        prior: &Before,
        observed: &crate::bucket::publication::SelectedObservation<'_>,
    ) -> Result<(), Failure> {
        let mut expected_state = prior.state.clone();
        expected_state.revision = 2;
        assert_eq!(observed.state(), &expected_state);

        let slot_bytes = TokioLocalFs
            .read_nofollow(&self.control.join("publication/commits/2"))
            .await?;
        let slot = PublicationCommit::decode(&slot_bytes).map_err(io::Error::other)?;
        assert_eq!(slot.encode().map_err(io::Error::other)?, slot_bytes);
        assert_eq!(observed.stamp(), (2, *blake3::hash(&slot_bytes).as_bytes()));
        assert_eq!(slot.revision, 2);
        assert_eq!(slot.predecessor, Some(prior.stamp.1));

        let transaction_bytes = TokioLocalFs
            .read_nofollow(&self.control.join(&slot.transaction_key))
            .await?;
        let transaction =
            PublicationTransaction::decode(&transaction_bytes).map_err(io::Error::other)?;
        assert_eq!(
            transaction.encode().map_err(io::Error::other)?,
            transaction_bytes
        );
        transaction
            .check_key(&slot.transaction_key)
            .map_err(io::Error::other)?;
        assert_eq!(
            slot.transaction_digest,
            *blake3::hash(&transaction_bytes).as_bytes()
        );
        assert_eq!(transaction.old, Some(prior.state.clone()));
        assert_eq!(transaction.new, expected_state);
        assert_eq!(transaction.proof, PublicationProof::Raw);
        assert_eq!(
            transaction
                .predecessor
                .as_ref()
                .map(|slot| (slot.revision, slot.digest)),
            Some(prior.stamp)
        );

        let capabilities = observed
            .logical()
            .get("CAPABILITIES")
            .and_then(Option::as_deref)
            .ok_or_else(|| io::Error::other("reopened capability bytes absent"))?;
        let current = terrane_format::bucket::BucketCapabilities::decode(capabilities)
            .map_err(io::Error::other)?;
        let mut expected = terrane_format::bucket::BucketCapabilities::decode(&prior.capabilities)
            .map_err(io::Error::other)?;
        assert_ne!(expected.probed_at, current.probed_at);
        expected.probed_at = current.probed_at;
        assert_eq!(expected.encode().map_err(io::Error::other)?, capabilities);
        assert_eq!(transaction.changes.len(), 1);
        assert_eq!(transaction.changes[0].key, "CAPABILITIES");
        assert_eq!(
            transaction.changes[0].expected.as_deref(),
            Some(prior.capabilities.as_slice())
        );
        assert_eq!(transaction.changes[0].new.as_deref(), Some(capabilities));
        assert_eq!(
            observed
                .logical()
                .get("publication/SELECTED-HISTORY")
                .and_then(Option::as_deref),
            Some(prior.history.as_slice())
        );
        assert_eq!(
            TokioLocalFs
                .read_nofollow(&self.bucket.root().join("CAPABILITIES"))
                .await?,
            capabilities
        );

        let pointer_bytes = TokioLocalFs
            .read_nofollow(&self.bucket.root().join("publication/PORTABLE"))
            .await?;
        let pointer = PortableCurrent::decode(&pointer_bytes).map_err(io::Error::other)?;
        assert_eq!(pointer.encode().map_err(io::Error::other)?, pointer_bytes);
        assert_eq!(&pointer, observed.snapshot());
        assert_eq!(pointer, transaction.snapshot);
        let snapshot_bytes = TokioLocalFs
            .read_nofollow(&self.bucket.root().join(&pointer.key))
            .await?;
        transaction
            .check_snapshot(&snapshot_bytes)
            .map_err(io::Error::other)?;
        let snapshot = PortableSnapshot::decode(&snapshot_bytes).map_err(io::Error::other)?;
        assert_eq!(snapshot.encode().map_err(io::Error::other)?, snapshot_bytes);
        assert_eq!(snapshot.predecessor, Some(prior.snapshot.clone()));
        assert_eq!(snapshot.projection.len(), 1);
        assert_eq!(snapshot.projection[0].key, "CAPABILITIES");
        assert_eq!(snapshot.projection[0].value.as_deref(), Some(capabilities));
        Ok(())
    }

    /// Removes only this fixture's native namespace and external control.
    ///
    /// # Errors
    /// Preserves actual cleanup failure.
    pub(super) async fn cleanup(self) -> Result<(), Failure> {
        tokio::fs::remove_dir_all(self.bucket.root()).await?;
        tokio::fs::remove_dir_all(self.control).await?;
        Ok(())
    }
}

/// Supplies ordinary tag data, with no branch or actor authorization claim.
pub(super) fn record() -> RefRecord {
    RefRecord {
        commit: [42; 32],
        seq: 1,
        writer_epoch: 0,
        home: Locality::default(),
        policy: None,
        candidate_id: None,
    }
}

/// Captures genuine selected predecessor data for independent artifact assertions.
pub(super) struct Before {
    /// Whole genuine selected state before publication.
    pub(super) state: PublicationState,
    /// Exact selecting predecessor revision and digest.
    pub(super) stamp: (u64, [u8; 32]),
    /// Actual immutable portable predecessor pointer.
    pub(super) snapshot: PortableCurrent,
    /// Exact selected capability bytes before the new name is introduced.
    pub(super) capabilities: Vec<u8>,
    /// Exact unchanged branch-history payload retained through Raw publication.
    pub(super) history: Vec<u8>,
}

/// Reads the actual native predecessor without creating a checked producer.
///
/// # Errors
/// Preserves native holder and complete selected-chain failures.
pub(super) async fn before(bucket: &Bucket) -> Result<Before, StoreFailure> {
    let holder = SingleHeld::acquire(bucket).await?;
    let held = holder.destination();
    let observed = held.observe_publication().await?;
    Ok(Before {
        state: observed.state().clone(),
        stamp: observed.stamp(),
        snapshot: observed.snapshot().clone(),
        capabilities: observed
            .logical()
            .get("CAPABILITIES")
            .and_then(Option::as_ref)
            .cloned()
            .ok_or_else(|| StoreFailure::new(crate::store::StoreErrorKind::Unsupported))?,
        history: observed
            .logical()
            .get("publication/SELECTED-HISTORY")
            .and_then(Option::as_ref)
            .cloned()
            .ok_or_else(|| StoreFailure::new(crate::store::StoreErrorKind::Unsupported))?,
    })
}

/// Publishes the whole tag transition through the actual held Raw producer.
///
/// # Errors
/// Preserves preparation, whole-preimage, native effect and closed ACK refusal.
pub(super) async fn publish(
    bucket: &Bucket,
) -> Result<crate::bucket::publication::SelectedReceipt, StoreFailure> {
    let holder = SingleHeld::acquire(bucket).await?;
    let held = holder.destination();
    let observed = held.observe_publication().await?;
    let (_, changes) = observed.ref_transition(NAME, &record())?;
    held.publish_raw(&observed, changes).await
}

/// Checks exact canonical slot, transaction, snapshot, pointer and selected tag bytes.
///
/// This independently reads real installed artifacts; no captured producer
/// inventory defines which artifacts the assertions require.
///
/// # Errors
/// Preserves artifact I/O and ordinary canonical decode errors.
///
/// # Panics
/// Panics on incorrect selected association, raw proof, preimage or payload bytes.
pub(super) async fn artifacts(
    fixture: &Fixture,
    prior: &Before,
) -> Result<(u64, [u8; 32]), Failure> {
    let slot_bytes = TokioLocalFs.read_nofollow(&fixture.slot()).await?;
    let slot = PublicationCommit::decode(&slot_bytes).map_err(io::Error::other)?;
    assert_eq!(slot.revision, prior.stamp.0 + 1);
    assert_eq!(slot.predecessor, Some(prior.stamp.1));
    assert_eq!(slot.encode().map_err(io::Error::other)?, slot_bytes);
    let transaction_bytes = TokioLocalFs
        .read_nofollow(&fixture.control.join(&slot.transaction_key))
        .await?;
    let transaction =
        PublicationTransaction::decode(&transaction_bytes).map_err(io::Error::other)?;
    assert_eq!(
        transaction.encode().map_err(io::Error::other)?,
        transaction_bytes
    );
    assert_eq!(
        slot.transaction_digest,
        *blake3::hash(&transaction_bytes).as_bytes()
    );
    assert_eq!(transaction.old, Some(prior.state.clone()));
    assert_eq!(transaction.proof, PublicationProof::Raw);
    assert_eq!(transaction.new.revision, slot.revision);
    assert_eq!(transaction.new.binding, prior.state.binding);
    assert_eq!(transaction.new.guard, prior.state.guard);
    assert_eq!(transaction.new.loss_generation, prior.state.loss_generation);
    assert_eq!(transaction.new.sources, prior.state.sources);
    assert_eq!(transaction.new.branches, prior.state.branches);
    assert_eq!(
        transaction
            .predecessor
            .as_ref()
            .map(|previous| (previous.revision, previous.digest)),
        Some(prior.stamp)
    );
    transaction
        .check_key(&slot.transaction_key)
        .map_err(io::Error::other)?;

    let pointer_bytes = TokioLocalFs
        .read_nofollow(&fixture.bucket.root().join("publication/PORTABLE"))
        .await?;
    let pointer = PortableCurrent::decode(&pointer_bytes).map_err(io::Error::other)?;
    assert_eq!(pointer, transaction.snapshot);
    assert_eq!(pointer.encode().map_err(io::Error::other)?, pointer_bytes);
    let snapshot_bytes = TokioLocalFs
        .read_nofollow(&fixture.bucket.root().join(&pointer.key))
        .await?;
    assert_eq!(pointer.digest, *blake3::hash(&snapshot_bytes).as_bytes());
    transaction
        .check_snapshot(&snapshot_bytes)
        .map_err(io::Error::other)?;
    let snapshot = PortableSnapshot::decode(&snapshot_bytes).map_err(io::Error::other)?;
    assert_eq!(snapshot.encode().map_err(io::Error::other)?, snapshot_bytes);
    assert_eq!(snapshot.predecessor, Some(prior.snapshot.clone()));
    let record_bytes = record().encode().map_err(io::Error::other)?;
    // The new tag requires a capability row as well as its independently
    // spelled ref payload. Predict both ordinary values from the predecessor.
    let mut capabilities = terrane_format::bucket::BucketCapabilities::decode(&prior.capabilities)
        .map_err(io::Error::other)?;
    let names = capabilities
        .ref_names
        .as_mut()
        .ok_or_else(|| io::Error::other("initial ref inventory absent"))?;
    assert!(!names.iter().any(|name| name == NAME));
    names.push(NAME.into());
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    let capabilities_bytes = capabilities.encode().map_err(io::Error::other)?;
    let ref_key = format!("{NAME}:record");
    assert_eq!(transaction.changes.len(), 3);
    assert_eq!(transaction.changes[0].key, "CAPABILITIES");
    assert_eq!(
        transaction.changes[0].expected.as_deref(),
        Some(prior.capabilities.as_slice())
    );
    assert_eq!(
        transaction.changes[0].new.as_deref(),
        Some(capabilities_bytes.as_slice())
    );
    assert_eq!(transaction.changes[1].key, "publication/SELECTED-HISTORY");
    assert_eq!(
        transaction.changes[1].expected.as_deref(),
        Some(prior.history.as_slice())
    );
    assert_eq!(
        transaction.changes[1].new.as_deref(),
        Some(prior.history.as_slice())
    );
    assert_eq!(transaction.changes[2].key, ref_key);
    assert_eq!(transaction.changes[2].expected, None);
    assert_eq!(
        transaction.changes[2].new.as_deref(),
        Some(record_bytes.as_slice())
    );
    assert_eq!(snapshot.projection.len(), 3);
    assert_eq!(snapshot.projection[0].key, "CAPABILITIES");
    assert_eq!(
        snapshot.projection[0].value.as_deref(),
        Some(capabilities_bytes.as_slice())
    );
    assert_eq!(snapshot.projection[1].key, "publication/SELECTED-HISTORY");
    assert_eq!(
        snapshot.projection[1].value.as_deref(),
        Some(prior.history.as_slice())
    );
    assert_eq!(snapshot.projection[2].key, ref_key);
    assert_eq!(
        snapshot.projection[2].value.as_deref(),
        Some(record_bytes.as_slice())
    );
    assert_eq!(
        TokioLocalFs
            .read_nofollow(&fixture.bucket.root().join("CAPABILITIES"))
            .await?,
        capabilities_bytes
    );
    assert_eq!(
        TokioLocalFs
            .read_nofollow(&fixture.bucket.root().join(&ref_key))
            .await?,
        record_bytes
    );
    Ok((slot.revision, *blake3::hash(&slot_bytes).as_bytes()))
}

/// Waits for the real native handoff using the existing bounded fixture timeout.
///
/// # Errors
/// Preserves worker, channel and timeout failures.
pub(super) async fn signal(receiver: mpsc::Receiver<()>) -> Result<(), Failure> {
    tokio::task::spawn_blocking(move || receiver.recv_timeout(Duration::from_secs(30))).await??;
    Ok(())
}

/// Replaces one actual queued input with byte-identical but distinct native data.
///
/// # Errors
/// Preserves native metadata, body, replacement and durability failures.
///
/// # Panics
/// Panics if replacement fails to change the inode or preserve bytes, mode or owner.
pub(super) fn replace_same_bytes(path: &Path) -> io::Result<()> {
    let before = std::fs::symlink_metadata(path)?;
    let bytes = std::fs::read(path)?;
    let replacement = path.with_extension("raw-ack-replacement");
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&replacement)?;
    use std::io::Write;
    (&file).write_all(&bytes)?;
    file.set_permissions(std::fs::Permissions::from_mode(before.mode() & 0o7777))?;
    file.sync_all()?;
    assert_ne!((before.dev(), before.ino()), {
        let after = file.metadata()?;
        (after.dev(), after.ino())
    });
    std::fs::rename(&replacement, path)?;
    std::fs::File::open(
        path.parent()
            .ok_or_else(|| io::Error::other("replacement parent absent"))?,
    )?
    .sync_all()?;
    let after = std::fs::symlink_metadata(path)?;
    assert_eq!(std::fs::read(path)?, bytes);
    assert_eq!(after.uid(), before.uid());
    assert_eq!(after.mode(), before.mode());
    assert_ne!((before.dev(), before.ino()), (after.dev(), after.ino()));
    Ok(())
}
