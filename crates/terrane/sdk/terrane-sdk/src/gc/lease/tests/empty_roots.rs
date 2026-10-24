//! Qualifies native collection and reopened checkpoints from a known-empty inventory.

use super::super::fixture::ConcreteGuard;
use super::Fixture;
use crate::bucket::held::SingleHeld;
use crate::gc::runner::Collection;
use terrane_format::bucket::{BucketCapabilities, GenerationManifest};
use terrane_format::gc::publication::{
    PortableCurrent, PortableSnapshot, PublicationCommit, PublicationTransaction,
};
use terrane_format::gc::{GcLease, GcRoots, GcState, Phase, Windows};

#[tokio::test]
async fn native_gc_known_empty_inventory_completes_empty_root_collection() {
    let fixture = Fixture::new().await;
    let cycle = 1;
    let windows = Windows::new(30, 60, 60, 90).unwrap();

    // Complete genesis evidence distinguishes an empty inventory from unknown
    // legacy state before the collector can publish any lease or checkpoint.
    let before_revision = {
        let holder = SingleHeld::acquire(fixture.guard.store()).await.unwrap();
        let held = holder.destination();
        let observed = held.observe_publication_unrepaired().await.unwrap();
        let capabilities =
            BucketCapabilities::decode(observed.logical()["CAPABILITIES"].as_deref().unwrap())
                .unwrap();
        assert_eq!(capabilities.ref_names, Some(Vec::new()));

        let generation = capabilities.generation.unwrap();
        let manifest = GenerationManifest::decode(
            observed.logical()[&format!("objects/index/{generation}/MANIFEST")]
                .as_deref()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(manifest.generation, generation);
        assert_eq!(manifest.inventory, Some(Vec::new()));
        assert_eq!(manifest.exclusions, Some(Vec::new()));
        assert_eq!(manifest.burns, Some(Vec::new()));
        assert!(observed.state().sources.is_empty());
        assert!(observed.state().branches.is_empty());
        assert_eq!(observed.state().burn_owners, Some(Vec::new()));
        assert!(
            observed
                .logical()
                .keys()
                .all(|key| !key.starts_with("refs/") && !key.starts_with("logs/refs/"))
        );
        assert_eq!(observed.logical()["gc/lease"], None);
        assert!(
            !observed
                .logical()
                .contains_key(&format!("gc/{cycle}/roots"))
        );
        assert!(
            !observed
                .logical()
                .contains_key(&format!("gc/{cycle}/state"))
        );
        observed.revalidate().await.unwrap();
        observed.state().revision
    };
    assert!(!fixture.config.root.join(format!("gc/{cycle}")).exists());

    let mut collection = Collection::start(
        fixture.guard.as_ref(),
        &fixture.authority,
        "collector".into(),
        1_000,
        cycle,
        windows,
    )
    .await
    .unwrap();

    assert_eq!(collection.roots().cycle, cycle);
    assert_eq!(collection.roots().epoch, collection.lease().epoch);
    assert_eq!(collection.roots().timestamp, 100);
    assert!(collection.roots().roots.is_empty());
    assert_eq!(collection.state().phase, Phase::Mark);
    assert_empty_progress(collection.state());
    let roots = collection.roots().clone();
    let initial_state = collection.state().clone();
    let initial_revision = assert_selected_checkpoint(
        &fixture,
        fixture.guard.as_ref(),
        &roots,
        &initial_state,
        collection.lease(),
    )
    .await;
    assert_eq!(initial_revision, before_revision + 2);

    collection.finish_mark().await.unwrap();

    let completed = collection.state().clone();
    assert_eq!(collection.roots(), &roots);
    let mut expected = initial_state;
    expected.phase = Phase::Sweep;
    assert_eq!(completed, expected);
    assert_empty_progress(&completed);
    let completed_revision = assert_selected_checkpoint(
        &fixture,
        fixture.guard.as_ref(),
        &roots,
        &completed,
        collection.lease(),
    )
    .await;
    assert_eq!(completed_revision, initial_revision + 2);
    let lease = collection.lease().clone();
    drop(collection);

    let reopened_guard = fixture.reopen().await;
    let reopened = Collection::resume(
        reopened_guard.as_ref(),
        &fixture.authority,
        lease,
        1_000,
        cycle,
        windows,
    )
    .await
    .unwrap();

    assert_eq!(reopened.roots(), &roots);
    assert_eq!(reopened.state(), &completed);
    let reopened_revision = assert_selected_checkpoint(
        &fixture,
        reopened_guard.as_ref(),
        reopened.roots(),
        reopened.state(),
        reopened.lease(),
    )
    .await;
    assert_eq!(reopened_revision, completed_revision + 1);
}

fn assert_empty_progress(state: &GcState) {
    assert!(state.pending.is_empty());
    assert!(state.checkpoints.is_empty());
    assert!(state.expanded.is_empty());
    assert!(state.objects.is_empty());
    assert!(state.progress.is_empty());
}

// Decoder comparisons are an oracle for bytes selected by the real holder;
// they are never supplied to a private authority or checkpoint constructor.
async fn assert_selected_checkpoint(
    fixture: &Fixture,
    guard: &ConcreteGuard,
    roots: &GcRoots,
    state: &GcState,
    lease: &GcLease,
) -> u64 {
    let holder = SingleHeld::acquire(guard.store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let root_key = format!("gc/{}/roots", roots.cycle);
    let state_key = format!("gc/{}/state", roots.cycle);
    let root_bytes = roots.encode();
    let state_bytes = state.encode().unwrap();
    assert_eq!(
        observed.logical()[&root_key].as_deref(),
        Some(root_bytes.as_slice())
    );
    assert_eq!(
        observed.logical()[&state_key].as_deref(),
        Some(state_bytes.as_slice())
    );
    assert_eq!(
        std::fs::read(fixture.config.root.join(&root_key)).unwrap(),
        root_bytes
    );
    assert_eq!(
        std::fs::read(fixture.config.root.join(&state_key)).unwrap(),
        state_bytes
    );
    assert_eq!(GcRoots::decode(&root_bytes).unwrap(), *roots);
    assert_eq!(GcState::decode(&state_bytes).unwrap(), *state);
    assert_eq!(state.cycle, roots.cycle);
    assert_eq!(state.epoch, roots.epoch);
    assert_eq!(state.snapshot_at, roots.timestamp);
    assert_eq!(
        GcLease::decode(observed.logical()["gc/lease"].as_deref().unwrap()).unwrap(),
        *lease
    );
    assert!(
        !fixture
            .config
            .root
            .join(format!("gc/{}/mark", roots.cycle))
            .exists()
    );

    let pointer_bytes = std::fs::read(fixture.config.root.join("publication/PORTABLE")).unwrap();
    let pointer = PortableCurrent::decode(&pointer_bytes).unwrap();
    assert_eq!(pointer.encode().unwrap(), pointer_bytes);
    assert_eq!(&pointer, observed.snapshot());
    let snapshot_bytes = std::fs::read(fixture.config.root.join(&pointer.key)).unwrap();
    pointer.check_snapshot(&snapshot_bytes).unwrap();
    let snapshot = PortableSnapshot::decode(&snapshot_bytes).unwrap();
    assert_eq!(snapshot.encode().unwrap(), snapshot_bytes);
    assert_eq!(snapshot.revision, observed.state().revision);

    let slot_bytes = std::fs::read(fixture.slot(snapshot.revision)).unwrap();
    let slot = PublicationCommit::decode(&slot_bytes).unwrap();
    assert_eq!(
        observed.stamp(),
        (snapshot.revision, *blake3::hash(&slot_bytes).as_bytes())
    );
    let transaction_bytes = std::fs::read(
        fixture
            .parent
            .join("publication")
            .join(&slot.transaction_key),
    )
    .unwrap();
    slot.check_transaction(
        &format!("publication/commits/{}", snapshot.revision),
        &transaction_bytes,
    )
    .unwrap();
    let transaction = PublicationTransaction::decode(&transaction_bytes).unwrap();
    assert_eq!(&transaction.new, observed.state());
    assert_eq!(transaction.snapshot, pointer);
    observed.revalidate().await.unwrap();
    snapshot.revision
}
