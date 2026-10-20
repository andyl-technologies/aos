//! Observes real selected ownership and physical fault targets independently.

use crate::bucket::held::SingleHeld;
use crate::gc::runner::copied_retirement_tests::fs::CopiedFs;
use crate::gc::runner::copied_retirement_tests::support::CopiedFixture;
use crate::gc::runner::permanent_local::Recovery;
use crate::repository::MetadataValidator;
use crate::store::native_publication_effects::collection::test_fs::PermanentPhase;
use crate::store::{Clock, NativeEffectClock};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, UNIX_EPOCH};
use terrane_format::bucket::{BucketCapabilities, GenerationManifest};
use terrane_format::gc::publication::{
    PublicationCommit, PublicationProof, PublicationState, PublicationTransaction,
};
use terrane_format::gc::retirement::{
    CopiedRetirementPreparation, ObservationState, ObservedArtifact, OwnershipSlot,
    PermanentDeleteAuthorization, PermanentDeleteOperation, PermanentDeletePass, PreparationPhase,
};
use terrane_format::gc::{GcLease, Windows};

/// Names the real recovery coordinator using the fixture's native executor and clock.
pub(super) type NativeRecovery<'a> =
    Recovery<'a, CopiedFs, NativeEffectClock, MetadataValidator, NativeEffectClock>;

/// Retains independently observed selected semantics without granting native permission.
pub(super) struct Selected {
    /// Whole selected publication state, including permanent owner associations.
    pub(super) state: PublicationState,
    /// Actual selecting revision and raw digest of its immutable commit bytes.
    pub(super) stamp: (u64, [u8; 32]),
    /// Canonical permanent operation resolved from the selected projection.
    pub(super) operation: PermanentDeleteOperation,
    /// Current selected immutable progress event, when progress has been selected.
    pub(super) pass: Option<PermanentDeletePass>,
    /// Progress events bound to actual selected transactions, excluding orphan proposals.
    pub(super) history: Vec<PermanentDeletePass>,
    /// Current selected whole lease used to establish genuine fixture takeover.
    pub(super) lease: GcLease,
    /// Current selected inventory and permanent burn visibility.
    pub(super) manifest: GenerationManifest,
}

/// Constructs and checks the canonical candidate key for the operation's authorization.
///
/// # Panics
/// Panics if the genuine fixture authorization does not validate its own key.
pub(super) fn owner_key(operation: &PermanentDeleteOperation) -> String {
    let authorization = &operation.authorization;
    let nonce: String = authorization
        .nonce()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let pack = crate::pack::PackId::from_random_bytes(authorization.exclusion().pack);
    let key = format!(
        "gc/{}/delete/{pack}/{nonce}",
        authorization.exclusion().cycle
    );
    authorization.check_key(&key).unwrap();
    key
}

/// Returns the destination control path independently configured by the fixture.
pub(super) fn control(fixture: &CopiedFixture) -> PathBuf {
    fixture.source.parent.join("copied-publication")
}

/// Resolves actual selected operation and event history beneath real namespace exclusion.
///
/// # Panics
/// Panics if held observation, canonical decoding, immutable record reads or
/// event-to-selection association assertions fail.
pub(super) async fn selected(fixture: &CopiedFixture, key: &str) -> Selected {
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let operation =
        PermanentDeleteOperation::decode(observed.logical()[key].as_deref().unwrap()).unwrap();
    let pass = operation.pass.as_ref().map(|pointer| {
        let bytes = std::fs::read(control(fixture).join(&pointer.key)).unwrap();
        assert_eq!(*blake3::hash(&bytes).as_bytes(), pointer.digest);
        operation.check_pass(&bytes, key).unwrap();
        PermanentDeletePass::decode(&bytes).unwrap()
    });
    let capabilities =
        BucketCapabilities::decode(observed.logical()["CAPABILITIES"].as_deref().unwrap()).unwrap();
    let manifest = GenerationManifest::decode(
        observed.logical()[&format!(
            "objects/index/{}/MANIFEST",
            capabilities.generation.unwrap()
        )]
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    let mut history = Vec::new();
    for revision in 0..=observed.stamp().0 {
        let slot_key = format!("publication/commits/{revision}");
        let slot_bytes = std::fs::read(control(fixture).join(&slot_key)).unwrap();
        let slot = PublicationCommit::decode(&slot_bytes).unwrap();
        let transaction_bytes =
            std::fs::read(control(fixture).join(&slot.transaction_key)).unwrap();
        slot.check_transaction(&slot_key, &transaction_bytes)
            .unwrap();
        let transaction = PublicationTransaction::decode(&transaction_bytes).unwrap();
        let Some(bytes) = transaction
            .changes
            .iter()
            .find(|change| change.key == key)
            .and_then(|change| change.new.as_deref())
        else {
            continue;
        };
        if let Ok(preparation) = CopiedRetirementPreparation::decode(bytes) {
            // The transaction decoder already checks the closed preparation /
            // operation union, including its whole key, binding and proof.
            // A genuine selected preparation precedes promotion at this key;
            // it carries no permanent pass to include in the event history.
            assert_eq!(preparation.phase, PreparationPhase::Preparing);
            assert!(matches!(transaction.proof, PublicationProof::Raw));
            preparation.plan.check_key(key).unwrap();
            assert_eq!(preparation.plan.backend, transaction.new.binding);
            let PermanentDeleteAuthorization::Copied(authorization) = &operation.authorization
            else {
                panic!("selected preparation lacks copied permanent authorization");
            };
            authorization
                .check_preparation(
                    &preparation,
                    &OwnershipSlot {
                        revision: slot.revision,
                        digest: *blake3::hash(&slot_bytes).as_bytes(),
                    },
                )
                .unwrap();
            continue;
        }
        let selected_operation = PermanentDeleteOperation::decode(bytes).unwrap();
        let Some(pointer) = &selected_operation.pass else {
            continue;
        };
        let bytes = std::fs::read(control(fixture).join(&pointer.key)).unwrap();
        selected_operation.check_pass(&bytes, key).unwrap();
        let pass = PermanentDeletePass::decode(&bytes).unwrap();
        assert_eq!(
            pass.predecessor.revision.checked_add(1).unwrap(),
            slot.revision
        );
        assert_eq!(Some(pass.predecessor.digest), slot.predecessor);
        assert_eq!(Some(&pass.state), transaction.old.as_ref());
        assert_eq!(pass.nonce, transaction.nonce);
        history.push(pass);
    }
    Selected {
        state: observed.state().clone(),
        stamp: observed.stamp(),
        operation,
        pass,
        history,
        lease: GcLease::decode(observed.logical()["gc/lease"].as_deref().unwrap()).unwrap(),
        manifest,
    }
}

/// Takes over the genuinely expired current lease through the native recovery factory.
///
/// Only the live lease clock advances. First ownership has already observed
/// full real G/D; immutable authorization and artifact age stay fixed.
///
/// # Panics
/// Panics if selected lease observation, clock advancement or independently
/// configured native recovery acquisition fails.
pub(super) async fn recovery<'a>(fixture: &'a CopiedFixture, key: &str) -> NativeRecovery<'a> {
    let current = selected(fixture, key).await;
    expire(fixture, current.lease.expiry);
    Recovery::start(
        fixture.guard(),
        &fixture.authority,
        "permanent-fault-recovery".into(),
        90,
        fixture.repository.coordinator(),
        Windows::new(30, 60, 60, 90).unwrap(),
    )
    .await
    .unwrap()
}

/// Advances both actual configured clock readings beyond the supplied live lease expiry.
///
/// # Panics
/// Panics if configured wall time precedes the Unix epoch or checked clock
/// arithmetic exhausts the fixture's representable bounds.
pub(super) fn expire(fixture: &CopiedFixture, expiry: u64) {
    let wall = fixture
        .source
        .clock
        .now()
        .duration_since(UNIX_EPOCH)
        .unwrap();
    let next = expiry.checked_add(1).unwrap().max(wall.as_secs() + 1);
    let delta = next.checked_sub(wall.as_secs()).unwrap();
    let ticks = fixture
        .source
        .clock
        .monotonic()
        .as_secs()
        .checked_add(delta)
        .unwrap();
    fixture.source.clock.set(next, ticks);
}

/// Verifies that recovery preserves permanent ownership and independent selected semantics.
///
/// # Panics
/// Panics if authorization, owner, burn, Guard, backend, branches or loss
/// generation change, or the selected manifest lacks the permanent burn.
pub(super) fn assert_owner(before: &Selected, after: &Selected, pack: &[u8; 16]) {
    assert_eq!(
        after.operation.authorization,
        before.operation.authorization
    );
    assert_eq!(after.state.burn_owners, before.state.burn_owners);
    assert_eq!(after.state.binding, before.state.binding);
    assert_eq!(after.state.guard, before.state.guard);
    assert_eq!(after.state.loss_generation, before.state.loss_generation);
    assert_eq!(after.state.branches, before.state.branches);
    assert!(after.manifest.burns.as_ref().unwrap().contains(pack));
    if let Some(owner) = &before.operation.owner {
        assert_eq!(after.operation.owner.as_ref(), Some(owner));
    }
}

/// Requires the actual selected current event to retain an unresolved target duty.
///
/// # Panics
/// Panics if selected progress is absent or lacks the exact Planned artifact.
pub(super) fn assert_planned(selected: &Selected, artifact: ObservedArtifact) {
    let pass = selected.pass.as_ref().unwrap();
    assert!(
        pass.observations
            .iter()
            .any(|row| { row.artifact == artifact && row.state == ObservationState::Planned })
    );
}

/// Waits for the actual native worker to reach its registered handoff.
///
/// # Panics
/// Panics if the worker does not arrive within the fixture bound or the
/// observation task/channel fails.
pub(super) async fn arrival(receiver: mpsc::Receiver<()>) {
    tokio::time::timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || receiver.recv()),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
}

/// Replaces equal physical bytes with a genuinely different synchronized inode.
///
/// # Panics
/// Panics on native I/O failure or if the replacement retains the old inode.
pub(super) fn replace(path: &Path) -> Vec<u8> {
    let bytes = std::fs::read(path).unwrap();
    let old = std::fs::symlink_metadata(path).unwrap();
    let temporary = path.with_extension("permanent-fault-replacement");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(old.mode() & 0o777)
        .open(&temporary)
        .unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
    std::fs::rename(&temporary, path).unwrap();
    std::fs::File::open(path.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
    assert_ne!(std::fs::symlink_metadata(path).unwrap().ino(), old.ino());
    bytes
}

/// Requires actual no-follow absence of the exact physical target.
///
/// # Panics
/// Panics if the target exists or metadata access fails for any other reason.
pub(super) fn assert_absent(path: &Path) {
    assert_eq!(
        std::fs::symlink_metadata(path).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
}

/// Removes fixture storage after every submitted permanent worker has actually returned.
///
/// Callers first drop all recovery coordinators and complete each native waiter
/// or cancellation handoff. Terminal recording independently rules out removing
/// storage beneath a submitted permanent worker that still owns its Frame.
///
/// # Panics
/// Panics if a native worker does not terminate within the fixture bound, a
/// hook remains unconsumed or removal of this fixture's private storage fails.
pub(super) async fn cleanup(fixture: CopiedFixture) {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let finished = [
                PermanentPhase::Observation,
                PermanentPhase::Reclaim,
                PermanentPhase::Progress,
            ]
            .into_iter()
            .all(|phase| {
                fixture.source.fs.permanent_submitted_paths(phase).len()
                    == fixture.source.fs.permanent_completed(phase).len()
            });
            if finished {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    fixture.source.fs.assert_permanent_hooks_consumed();
    drop(fixture.repository);
    fixture.source.cleanup();
}
