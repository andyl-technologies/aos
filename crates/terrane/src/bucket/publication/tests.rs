//! Exercises actual selected-chain recovery and protected native registration.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture assertions intentionally panic."
)]

use super::control::Control;
use super::*;
use crate::bucket::held::SingleHeld;
use crate::bucket::tests::{
    PreparedCas, Selected as SelectedRecord, Validator, config, control_path, fixture, log,
};
use crate::store::{RefCasOutcome, RefStore, TokioClock, TokioLocalFs};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use terrane_core::gc::publication::{Activation, BackendRegistration, LogicalChange};
use terrane_core::refs::RefRecord;

const NAME: &str = "refs/heads/_/selected";

#[tokio::test]
async fn advisory_transition_data_preserves_history_and_rejects_other_mutations() {
    let bucket = fixture().await;
    let head = RefRecord::first([1; 32], 3, Default::default()).selected();
    bucket.prepared_cas(NAME, None, &head).await.unwrap();
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let adapter = holder.destination();
    let tag = "refs/tags/_/selected";
    let notes = "refs/notes/memos/_/selected";
    let first = RefRecord::first([2; 32], 3, Default::default());

    for name in [tag, notes] {
        let observed = adapter.observe_publication().await.unwrap();
        let (next, changes) = observed.ref_transition(name, &first).unwrap();
        super::checked::verify_advisory_change(&observed, &next, &changes).unwrap();
        assert_eq!(next.branches, observed.state().branches);
        assert_eq!(next.sources, observed.state().sources);
        assert!(
            changes
                .iter()
                .all(|row| row.key != "publication/SELECTED-HISTORY")
        );

        let mut changed_guard = next.clone();
        changed_guard.guard = Some([7; 32]);
        assert!(
            super::checked::verify_advisory_change(&observed, &changed_guard, &changes).is_err()
        );

        let mut changed_history = next.clone();
        changed_history.branches.clear();
        assert!(
            super::checked::verify_advisory_change(&observed, &changed_history, &changes).is_err()
        );

        let mut changed_lineage = next.clone();
        changed_lineage
            .sources
            .push(terrane_core::gc::publication::SourceLineage {
                name: NAME.into(),
                digest: [8; 32],
            });
        assert!(
            super::checked::verify_advisory_change(&observed, &changed_lineage, &changes).is_err()
        );

        let mut extra_change = changes.clone();
        extra_change.push(LogicalChange {
            key: "gc/lease".into(),
            expected: None,
            new: None,
        });
        assert!(super::checked::verify_advisory_change(&observed, &next, &extra_change).is_err());

        // Raw storage exercises the data path without constructing checked
        // authority. Advisory admission requires the separate private producer.
        adapter.publish_raw(&observed, changes).await.unwrap();
    }

    let observed = adapter.observe_publication().await.unwrap();
    let second = first.advance([3; 32], 4).unwrap();
    assert!(observed.ref_transition(tag, &second).is_err());

    let mut candidate_notes = second.clone();
    candidate_notes.candidate_id = Some([4; 32]);
    assert!(observed.ref_transition(notes, &candidate_notes).is_err());

    let (next, changes) = observed.ref_transition(notes, &second).unwrap();
    super::checked::verify_advisory_change(&observed, &next, &changes).unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].expected, Some(first.encode().unwrap()));

    let next_head = head.advance([5; 32], 4).unwrap().selected();
    let (next, changes) = observed.ref_transition(NAME, &next_head).unwrap();
    assert!(super::checked::verify_advisory_change(&observed, &next, &changes).is_err());
    drop(observed);
    drop(holder);
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
    tokio::fs::remove_dir_all(control_path(bucket.root()))
        .await
        .unwrap();
}

#[tokio::test]
async fn coordination_directory_is_private_and_unsafe_existing_modes_are_refused() {
    let bucket = fixture().await;
    let locks = bucket.root().join(".terrane-locks");
    assert_eq!(
        tokio::fs::symlink_metadata(&locks).await.unwrap().mode() & 0o777,
        0o700
    );
    tokio::fs::set_permissions(&locks, std::fs::Permissions::from_mode(0o775))
        .await
        .unwrap();

    assert!(bucket.ref_get(NAME).await.is_err());
    assert_eq!(
        tokio::fs::symlink_metadata(&locks).await.unwrap().mode() & 0o777,
        0o775
    );
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
    tokio::fs::remove_dir_all(control_path(bucket.root()))
        .await
        .unwrap();
}

#[tokio::test]
async fn selected_chain_ignores_cache_bytes_hints_and_slots_after_a_gap() {
    let bucket = fixture().await;
    let first = RefRecord::first([1; 32], 1, Default::default()).selected();
    bucket.prepared_cas(NAME, None, &first).await.unwrap();
    let before = bucket.selected_publication_locked().await.unwrap();
    let control = control_path(bucket.root());

    tokio::fs::write(
        bucket.root().join("CAPABILITIES"),
        b"stale capability cache",
    )
    .await
    .unwrap();
    tokio::fs::write(
        bucket.root().join(format!("{NAME}:record")),
        b"stale head cache",
    )
    .await
    .unwrap();
    tokio::fs::write(control.join("publication/CURRENT"), b"untrusted hint")
        .await
        .unwrap();
    tokio::fs::write(
        control.join(format!(
            "publication/commits/{}",
            before.state.revision + 1000
        )),
        b"invalid later slot",
    )
    .await
    .unwrap();

    assert_eq!(bucket.ref_get(NAME).await.unwrap(), Some(first.clone()));
    let reopened = FileBucket::open(
        config(bucket.root().to_owned()),
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    assert_eq!(reopened.ref_get(NAME).await.unwrap(), Some(first.clone()));
    assert_eq!(
        tokio::fs::read(bucket.root().join(format!("{NAME}:record")))
            .await
            .unwrap(),
        first.encode().unwrap()
    );
    assert_eq!(
        reopened
            .selected_publication_locked()
            .await
            .unwrap()
            .state
            .branches,
        before.state.branches
    );

    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
    tokio::fs::remove_dir_all(control).await.unwrap();
}

#[tokio::test]
async fn absent_history_retains_sequence_and_recreation_replays_the_exact_chain() {
    let bucket = fixture().await;
    let first = RefRecord::first([1; 32], 3, Default::default()).selected();
    bucket.prepared_cas(NAME, None, &first).await.unwrap();
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let adapter = holder.destination();
    let observed = adapter.observe_publication().await.unwrap();
    let old_stamp = observed.stamp();
    assert_eq!(
        observed
            .logical()
            .get(&format!("{NAME}:record"))
            .cloned()
            .flatten(),
        Some(first.encode().unwrap())
    );
    assert!(
        adapter
            .selected_guard_snapshot(&observed)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        adapter
            .selected_lineage(&observed, NAME)
            .await
            .unwrap()
            .is_none()
    );

    let receipt = adapter
        .publish_raw(
            &observed,
            vec![LogicalChange {
                key: format!("{NAME}:record"),
                expected: Some(first.encode().unwrap()),
                new: None,
            }],
        )
        .await
        .unwrap();
    assert_eq!(receipt.stamp.0, old_stamp.0 + 1);
    assert_eq!(receipt.state.branches, observed.state().branches);
    assert!(adapter.publish_raw(&observed, Vec::new()).await.is_err());
    drop(observed);

    let absent = adapter.observe_publication().await.unwrap();
    let same_session = first
        .advance([2; 32], first.writer_epoch)
        .unwrap()
        .selected();
    let (next, changes) = absent.ref_transition(NAME, &same_session).unwrap();
    assert_eq!(
        next.branches[0].selection,
        terrane_core::gc::publication::CommittedSelection::Selected(same_session.clone().into())
    );
    assert!(
        changes
            .iter()
            .any(|change| change.key == format!("{NAME}:record") && change.expected.is_none())
    );
    let mut wrong_home = same_session;
    wrong_home.home.region = Some("elsewhere".into());
    assert!(absent.ref_transition(NAME, &wrong_home).is_err());
    drop(absent);
    // The adapter retains a duplicate exclusion descriptor until it is dropped.
    drop(adapter);
    drop(holder);

    assert_eq!(bucket.ref_get(NAME).await.unwrap(), None);
    assert_eq!(
        bucket.ref_log_read(NAME, 1).await.unwrap(),
        vec![log(first.clone(), None)]
    );
    let reset = RefRecord::first([2; 32], 4, Default::default()).selected();
    assert!(bucket.prepared_cas(NAME, None, &reset).await.is_err());

    let second = first.advance([2; 32], 4).unwrap().selected();
    let mut candidate = log(second.clone(), None);
    candidate.previous_commit = Some(first.commit);
    candidate.committed_previous = Some(first.clone());
    bucket
        .ref_log_append(NAME, second.seq, &candidate)
        .await
        .unwrap();
    assert!(matches!(
        bucket.ref_cas(NAME, None, &second).await.unwrap(),
        RefCasOutcome::Applied
    ));
    assert_eq!(
        bucket.ref_log_read(NAME, 1).await.unwrap(),
        vec![log(first, None), candidate]
    );

    let reopened = FileBucket::open(
        config(bucket.root().to_owned()),
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    assert_eq!(reopened.ref_get(NAME).await.unwrap(), Some(second));
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
    tokio::fs::remove_dir_all(control_path(bucket.root()))
        .await
        .unwrap();
}

#[tokio::test]
async fn raw_transaction_cannot_select_decoded_guard_proof() {
    use terrane_core::gc::publication::{
        PortableCurrent, PortableSnapshot, PredecessorSlot, PublicationProof,
        PublicationTransaction,
    };

    let bucket = fixture().await;
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let before = bucket.selected_publication_locked().await.unwrap();
    let control = Control::open(&bucket, false).await.unwrap();
    let mut next = before.state.clone();
    next.revision += 1;
    next.guard = Some([7; 32]);
    next.sources.clear();
    let snapshot = PortableSnapshot {
        revision: next.revision,
        origin: next.binding.clone(),
        projection: Vec::new(),
        predecessor: Some(before.snapshot.clone()),
    };
    let snapshot_bytes = snapshot.encode().unwrap();
    let nonce = [9; 32];
    let operation: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
    let transaction = PublicationTransaction {
        nonce,
        old: Some(before.state.clone()),
        new: next,
        changes: Vec::new(),
        proof: PublicationProof::Guard([7; 32]),
        predecessor: Some(PredecessorSlot {
            revision: before.state.revision,
            digest: before.digest,
        }),
        snapshot: PortableCurrent {
            key: format!("publication/snapshots/{}:{operation}", snapshot.revision),
            digest: digest(&snapshot_bytes),
        },
    };
    let encoded = transaction.encode().unwrap();
    assert_eq!(
        PublicationTransaction::decode(&encoded).unwrap(),
        transaction
    );
    transaction.check_snapshot(&snapshot_bytes).unwrap();
    bucket
        .stage_snapshot_locked(&transaction.snapshot, &snapshot_bytes)
        .await
        .unwrap();

    assert!(
        bucket
            .commit_publication_locked(&control, transaction)
            .await
            .is_err()
    );
    let after = bucket.selected_publication_locked().await.unwrap();
    assert_eq!(after.digest, before.digest);
    assert_eq!(after.state, before.state);
    drop(holder);

    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
    tokio::fs::remove_dir_all(control_path(bucket.root()))
        .await
        .unwrap();
}

#[tokio::test]
async fn configured_owner_and_protected_single_link_records_are_required() {
    let bucket = fixture().await;
    let control = control_path(bucket.root());
    let registration = control.join("backend-registration.cbor");
    assert_eq!(
        tokio::fs::symlink_metadata(&control).await.unwrap().mode() & 0o777,
        0o700
    );
    assert_eq!(
        tokio::fs::symlink_metadata(&registration)
            .await
            .unwrap()
            .mode()
            & 0o777,
        0o600
    );

    let mut wrong_owner = config(bucket.root().to_owned());
    let configured = wrong_owner.publication_control.as_mut().unwrap();
    configured.operator_uid = configured.operator_uid.checked_add(1).unwrap();
    assert!(
        FileBucket::open(wrong_owner, TokioLocalFs, TokioClock, Validator)
            .await
            .is_err()
    );

    let alias = control.join("registration-hardlink");
    tokio::fs::hard_link(&registration, &alias).await.unwrap();
    assert!(bucket.ref_get(NAME).await.is_err());
    tokio::fs::remove_file(alias).await.unwrap();
    tokio::fs::set_permissions(&registration, std::fs::Permissions::from_mode(0o644))
        .await
        .unwrap();
    assert!(bucket.ref_get(NAME).await.is_err());

    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
    tokio::fs::remove_dir_all(control).await.unwrap();
}

#[tokio::test]
async fn pending_same_binding_recovers_existing_genesis_and_missing_genesis_refuses() {
    let bucket = fixture().await;
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let control = Control::open(&bucket, false).await.unwrap();
    let bytes = control
        .read(&bucket.inner.fs, "backend-registration.cbor")
        .await
        .unwrap()
        .unwrap();
    let mut pending = BackendRegistration::decode(&bytes).unwrap();
    pending.activation = Activation::Pending;
    control
        .install(
            &bucket.inner.fs,
            "backend-registration.cbor",
            &pending.encode().unwrap(),
            true,
        )
        .await
        .unwrap();
    drop(holder);

    let reopened = FileBucket::open(
        config(bucket.root().to_owned()),
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    let current = Control::open(&reopened, false).await.unwrap();
    let active = BackendRegistration::decode(
        &current
            .read(&bucket.inner.fs, "backend-registration.cbor")
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(active.activation, Activation::Active);
    assert_eq!(active.genesis, pending.genesis);

    let holder = SingleHeld::acquire(&reopened).await.unwrap();
    current
        .install(
            &bucket.inner.fs,
            "backend-registration.cbor",
            &pending.encode().unwrap(),
            true,
        )
        .await
        .unwrap();
    tokio::fs::remove_file(current.path.join("publication/commits/0"))
        .await
        .unwrap();
    tokio::fs::remove_file(bucket.root().join("publication/PORTABLE"))
        .await
        .unwrap();
    drop(holder);
    assert!(
        FileBucket::open(
            config(bucket.root().to_owned()),
            TokioLocalFs,
            TokioClock,
            Validator
        )
        .await
        .is_err()
    );

    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
    tokio::fs::remove_dir_all(control_path(bucket.root()))
        .await
        .unwrap();
}

#[tokio::test]
async fn raw_backend_worker_retains_actual_namespace_after_waiter_cancellation() {
    let bucket = fixture().await;
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let adapter = holder.destination();
    let observed = adapter.observe_publication().await.unwrap();
    let (arrived, arrival) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    let effect = crate::store::native_publication_effects::backend_sync_for_test(
        &TokioLocalFs,
        &observed,
        arrived,
        released,
    )
    .await
    .unwrap();
    let task = tokio::spawn(async move { TokioLocalFs.execute_retained_effect(effect).await });
    tokio::task::spawn_blocking(move || arrival.recv_timeout(std::time::Duration::from_secs(30)))
        .await
        .unwrap()
        .unwrap();

    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    drop(observed);
    drop(adapter);
    drop(holder);
    let reopened_bucket = bucket.clone();
    let mut next = tokio::spawn(async move {
        let _held = SingleHeld::acquire(&reopened_bucket).await.unwrap();
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut next)
            .await
            .is_err()
    );

    release.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(30), next)
        .await
        .unwrap()
        .unwrap();
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
    tokio::fs::remove_dir_all(control_path(bucket.root()))
        .await
        .unwrap();
}

#[tokio::test]
async fn raw_changes_refuse_collector_keys_without_publication_effects() {
    let bucket = fixture().await;
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let adapter = holder.destination();
    let before = adapter.observe_publication().await.unwrap();
    let control = Control::open(&bucket, false).await.unwrap();
    let next_slot = format!("publication/commits/{}", before.stamp().0 + 1);
    let deletion = format!("gc/1/delete/{}/{}", "11".repeat(16), "22".repeat(32));
    let trash = format!("trash/1/{}", "11".repeat(16));
    for key in [
        "gc/lease",
        "gc/1/state",
        "gc/cycle/1",
        "gc/1/roots",
        "gc/1/mark/0/0",
        deletion.as_str(),
        trash.as_str(),
        "publication/SELECTED-HISTORY",
    ] {
        terrane_core::bucket::BucketKey::parse(key).unwrap();
        let value = before.logical().get(key).cloned().flatten();
        let error = match adapter
            .publish_raw(
                &before,
                vec![LogicalChange {
                    key: key.into(),
                    expected: value.clone(),
                    new: value,
                }],
            )
            .await
        {
            Ok(_) => panic!("raw collector key unexpectedly published"),
            Err(error) => error,
        };
        assert!(matches!(
            error.kind(),
            crate::store::StoreErrorKind::Unsupported
        ));
        assert!(
            control
                .read(&bucket.inner.fs, &next_slot)
                .await
                .unwrap()
                .is_none()
        );
        before.revalidate().await.unwrap();
    }
    drop(before);
    drop(holder);
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
    tokio::fs::remove_dir_all(control_path(bucket.root()))
        .await
        .unwrap();
}

#[tokio::test]
async fn raw_catalog_cannot_change_selected_retirement_associations() {
    use terrane_core::bucket::{BucketCapabilities, GenerationManifest, PackExclusion};
    let bucket = fixture().await;
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let adapter = holder.destination();
    let before = adapter.observe_publication().await.unwrap();
    let capability_bytes = before
        .logical()
        .get("CAPABILITIES")
        .unwrap()
        .as_ref()
        .unwrap();
    let mut capabilities = BucketCapabilities::decode(capability_bytes).unwrap();
    let generation = capabilities.generation.unwrap();
    let next_generation = generation + 1;
    let manifest = GenerationManifest::decode(
        before
            .logical()
            .get(&format!("objects/index/{generation}/MANIFEST"))
            .unwrap()
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(manifest.exclusions, Some(Vec::new()));
    capabilities.generation = Some(next_generation);
    let mut changes = vec![LogicalChange {
        key: "CAPABILITIES".into(),
        expected: Some(capability_bytes.clone()),
        new: Some(capabilities.encode().unwrap()),
    }];
    for shard in &manifest.shards {
        let bytes = before
            .logical()
            .get(&format!("objects/index/{generation}/{}.idx", shard.shard))
            .unwrap()
            .as_ref()
            .unwrap()
            .clone();
        changes.push(LogicalChange {
            key: format!("objects/index/{next_generation}/{}.idx", shard.shard),
            expected: None,
            new: Some(bytes),
        });
    }
    let mut changed_manifest = manifest;
    changed_manifest.generation = next_generation;
    changed_manifest.exclusions = Some(vec![PackExclusion {
        pack_id: [1; 16],
        cycle: 1,
        epoch: 1,
    }]);
    changes.push(LogicalChange {
        key: format!("objects/index/{next_generation}/MANIFEST"),
        expected: None,
        new: Some(changed_manifest.encode().unwrap()),
    });
    let mut logical = before.logical().clone();
    for change in &changes {
        logical.insert(change.key.clone(), change.new.clone());
    }
    let mut state = before.state().clone();
    state.revision += 1;
    projection::validate(&bucket, &state, &logical).unwrap();
    projection::validate_successor(before.logical(), &logical).unwrap();

    let error = match adapter.publish_raw(&before, changes).await {
        Ok(_) => panic!("raw retirement association change unexpectedly published"),
        Err(error) => error,
    };
    assert!(matches!(
        error.kind(),
        crate::store::StoreErrorKind::Unsupported
    ));
    before.revalidate().await.unwrap();
    let control = Control::open(&bucket, false).await.unwrap();
    assert!(
        control
            .read(
                &bucket.inner.fs,
                &format!("publication/commits/{}", before.stamp().0 + 1)
            )
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        TokioLocalFs
            .symlink_metadata(
                &bucket
                    .root()
                    .join(format!("objects/index/{next_generation}/MANIFEST"))
            )
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotFound
    );
    drop(before);
    drop(holder);
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
    tokio::fs::remove_dir_all(control_path(bucket.root()))
        .await
        .unwrap();
}
