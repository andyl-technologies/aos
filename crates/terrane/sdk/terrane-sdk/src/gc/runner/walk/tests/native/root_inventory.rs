//! Checks exhaustive native root selection and selected snapshot continuity.
//!
//! Every positive history originates in ordinary signed publication. Read-only
//! snapshots come from the opaque factory bound to a real selected whole lease;
//! expected rows describe the published ref values and registered retention rules.

use super::*;
use crate::store::{CorruptSubject, RefLogAppendOutcome, RefStore};
use terrane_format::bucket::{BucketCapabilities, BucketKey};
use terrane_format::gc::publication::{CommittedSelection, LogicalChange};
use terrane_format::gc::{GcRoots, ParentCutoff, RootReason};
use terrane_format::refs::{Lease, RefClass, RefLogReason, RefLogRecord, RefName, RefRecord};

type NativeCollection<'configuration> =
    Collection<'configuration, TestFs, NativeEffectClock, MetadataValidator, NativeEffectClock>;

/// Publishes actual ordinary history with explicit root retention and signed lease.
async fn publish(
    fixture: &Fixture,
    repository: &RepositoryWithIndexes,
    name: &str,
    plaintext: &[u8],
    retention: Option<&[u8]>,
    lease: Option<Lease>,
) -> RefRecord {
    let mut properties = vec![
        Property {
            name: "acl",
            value: b"\x81\x82\x66writer\x18\x1f",
        },
        Property {
            name: "domain",
            value: b"\x66public",
        },
    ];
    if let Some(retention) = retention {
        properties.push(Property {
            name: "reflog_retain",
            value: retention,
        });
    }
    if lease.is_some() {
        properties.push(Property {
            name: "retain",
            value: b"\x65lease",
        });
    }
    let tree = Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: entry(plaintext),
        }],
        Some(properties),
        262144,
        TreeUse::Ordinary,
    )
    .assert_success();
    let current = repository
        .coordinator()
        .guard()
        .store()
        .ref_get(name)
        .await
        .assert_success();
    let mut request = proposal(fixture, &tree, None, &[plaintext]).await;
    request.commit.parents = current.map(|record| record.commit).into_iter().collect();
    request.commit.profile_pair.lease = lease;
    let mut writer = repository
        .begin(name, &token(fixture), "sdk")
        .await
        .assert_success();
    repository
        .commit_request(&mut writer, request)
        .await
        .assert_success()
}

/// Derives both root sets from actual held selection and completed signed histories.
async fn snapshots(
    fixture: &Fixture,
    repository: &RepositoryWithIndexes,
    collection: &NativeCollection<'_>,
) -> (GcRoots, GcRoots) {
    let guard = repository.coordinator().guard();
    let holder = SingleHeld::acquire(guard.store()).await.assert_success();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.assert_success();
    let history = crate::guard::collection_authority::historical_guard(
        guard,
        &held,
        &observed,
        &collection.session,
        collection.session.clock().assert_success(),
    )
    .assert_success();
    let consumed = ConsumedResolver::new(guard, &fixture.authority).assert_success();
    let cycle = crate::selected_bridge::native_collection_roots::cycle(
        &history,
        &consumed,
        &held,
        &observed,
        &collection.session,
        collection.roots().cycle,
    )
    .await
    .assert_success();
    let current = crate::selected_bridge::native_collection_roots::current(
        &history,
        &consumed,
        &held,
        &observed,
        &collection.session,
        (collection.roots().cycle, windows()),
    )
    .await
    .assert_success();
    for qualified in [&cycle, &current] {
        for root in &qualified.snapshot().roots {
            let retained = qualified
                .history(&root.commit)
                .assert_success()
                .assert_success();
            assert_eq!(retained.tree().commit.identity(), root.commit);
        }
    }
    observed.revalidate().await.assert_success();
    (cycle.snapshot().clone(), current.snapshot().clone())
}

fn rows(roots: &GcRoots, name: &str) -> Vec<(Digest, RootReason, ParentCutoff)> {
    roots
        .roots
        .iter()
        .filter(|root| root.reference.as_str() == name)
        .map(|root| (root.commit, root.reason, root.parent_cutoff))
        .collect()
}

/// Checks all registered commit-bearing classes and actual lease expiration.
///
/// # Panics
/// Panics if signed publication, exhaustive qualification or an expected row fails.
pub(super) async fn current_inventory_keeps_all_commit_classes_and_live_jobs() {
    let fixture = Fixture::new().await;
    let repository = production_repository(&fixture).await;
    let derived_name = "refs/derived/_/collection";
    let conflict_name = "refs/conflicts/_/main/00000000000000000001";
    let job_name = "refs/jobs/_/work";
    let tag_name = "refs/tags/_/retained";
    for (name, class) in [
        (derived_name, RefClass::Derived),
        (conflict_name, RefClass::Conflicts),
        (job_name, RefClass::Jobs),
        (tag_name, RefClass::Tags),
    ] {
        assert_eq!(RefName::parse(name).assert_success().class(), class);
        BucketKey::ref_record(name).assert_success();
    }
    let derived = publish(&fixture, &repository, derived_name, b"derived", None, None).await;
    let conflict = publish(
        &fixture,
        &repository,
        conflict_name,
        b"conflict",
        None,
        None,
    )
    .await;
    let job = publish(
        &fixture,
        &repository,
        job_name,
        b"job",
        None,
        Some(Lease {
            owner: "writer".into(),
            expiry: 105,
        }),
    )
    .await;
    let tag = repository
        .coordinator()
        .annotated_tag(
            "refs/heads/_/main",
            tag_name,
            &token(&fixture),
            "sdk",
            &crate::ref_advance::TagAnnotation {
                attestation: vec![0xa0],
                terminal_secret: terminal_seed(),
            },
        )
        .await
        .assert_success();
    assert_eq!(tag.commit, fixture.head.commit);
    let collection = Collection::start(
        repository.coordinator().guard(),
        &fixture.authority,
        "roots-collector".into(),
        1_000,
        51,
        windows(),
    )
    .await
    .assert_success();
    let (cycle, current) = snapshots(&fixture, &repository, &collection).await;
    assert_eq!(cycle, *collection.roots());
    assert_eq!(current.roots, cycle.roots);
    assert_eq!(current.timestamp, 100);
    assert_eq!(current.roots.len(), 9);
    for (name, commit) in [
        ("refs/heads/_/main", fixture.head.commit),
        (derived_name, derived.commit),
        (conflict_name, conflict.commit),
    ] {
        assert_eq!(
            rows(&current, name),
            vec![
                (commit, RootReason::Current, ParentCutoff::Since(0)),
                (commit, RootReason::ReflogGc, ParentCutoff::Since(0)),
            ]
        );
    }
    assert_eq!(
        rows(&current, tag_name),
        vec![(tag.commit, RootReason::Tag, ParentCutoff::Since(0))]
    );
    assert_eq!(
        rows(&current, job_name),
        vec![
            (job.commit, RootReason::Job, ParentCutoff::Unbounded),
            (job.commit, RootReason::Lease, ParentCutoff::Unbounded),
        ]
    );

    fixture.clock.set(105, 5);
    let (unchanged_cycle, expired) = snapshots(&fixture, &repository, &collection).await;
    assert_eq!(unchanged_cycle, cycle);
    assert_eq!(expired.timestamp, 105);
    assert_eq!(
        rows(&expired, job_name),
        vec![
            (
                job.commit,
                RootReason::RetentionWitness,
                ParentCutoff::Unbounded
            );
            2
        ]
    );
    assert!(
        expired
            .roots
            .iter()
            .all(|root| root.reason != RootReason::Job)
    );
    drop(collection);
    drop(repository);
    fixture.cleanup();
}

/// Checks selected sequence-count and duration roots across genuine ref absence.
///
/// # Panics
/// Panics if selected history, proposal exclusion or the independent rows disagree.
pub(super) async fn retained_selection_keeps_absent_history_and_excludes_proposals() {
    let fixture = Fixture::new().await;
    let repository = production_repository(&fixture).await;
    let count_name = "refs/heads/_/count";
    let duration_name = "refs/heads/_/duration";
    let count = b"\x82\x65count\x02";
    let first = publish(
        &fixture,
        &repository,
        count_name,
        b"count first",
        Some(count),
        None,
    )
    .await;
    let duration_first = publish(
        &fixture,
        &repository,
        duration_name,
        b"duration first",
        Some(b"\x0a"),
        None,
    )
    .await;
    fixture.clock.set(101, 1);
    let second = publish(
        &fixture,
        &repository,
        count_name,
        b"count second",
        Some(count),
        None,
    )
    .await;
    fixture.clock.set(102, 2);
    let third = publish(
        &fixture,
        &repository,
        count_name,
        b"count third",
        Some(count),
        None,
    )
    .await;
    let duration_second = publish(
        &fixture,
        &repository,
        duration_name,
        b"duration second",
        Some(b"\x0a"),
        None,
    )
    .await;
    let mut unselected = third
        .advance(fixture.head.commit, third.writer_epoch + 1)
        .assert_success();
    unselected.candidate_id = Some(
        fixture
            .fs
            .random_bytes(32)
            .await
            .assert_success()
            .try_into()
            .assert_success(),
    );
    let proposal = RefLogRecord {
        record: unselected,
        previous_commit: Some(third.commit),
        principal: "writer".into(),
        reason: RefLogReason::Commit,
        timestamp: 102,
        expected_previous: Some(Some(third.clone())),
        committed_previous: None,
    };
    assert_eq!(
        repository
            .coordinator()
            .guard()
            .store()
            .ref_log_append(count_name, proposal.record.seq, &proposal)
            .await
            .assert_success(),
        RefLogAppendOutcome::Appended
    );
    let holder = SingleHeld::acquire(repository.coordinator().guard().store())
        .await
        .assert_success();
    let held = holder.destination();
    let before = held.observe_publication_unrepaired().await.assert_success();
    let key = BucketKey::ref_record(count_name)
        .assert_success()
        .as_str()
        .to_owned();
    held.publish_raw(
        &before,
        vec![LogicalChange {
            expected: Some(third.encode().assert_success()),
            key: key.clone(),
            new: None,
        }],
    )
    .await
    .assert_success();
    let after = held.observe_publication_unrepaired().await.assert_success();
    assert_eq!(after.logical().get(&key), Some(&None));
    assert_eq!(
        after
            .state()
            .branches
            .iter()
            .find(|row| row.name == count_name)
            .assert_success()
            .selection,
        CommittedSelection::Selected(Box::new(third.clone()))
    );
    drop(after);
    drop(before);
    drop(held);
    drop(holder);

    fixture.clock.set(120, 20);
    let collection = Collection::start(
        repository.coordinator().guard(),
        &fixture.authority,
        "roots-collector".into(),
        1_000,
        52,
        windows(),
    )
    .await
    .assert_success();
    let (cycle, current) = snapshots(&fixture, &repository, &collection).await;
    assert_eq!(cycle.roots, current.roots);
    assert_eq!(
        rows(&current, count_name),
        vec![
            (
                third.commit,
                RootReason::ReflogCount,
                ParentCutoff::RootsOnly
            ),
            (
                second.commit,
                RootReason::RetentionWitness,
                ParentCutoff::RootsOnly
            ),
            (
                second.commit,
                RootReason::ReflogCount,
                ParentCutoff::RootsOnly
            ),
            (
                first.commit,
                RootReason::RetentionWitness,
                ParentCutoff::RootsOnly
            ),
            (
                first.commit,
                RootReason::RetentionWitness,
                ParentCutoff::RootsOnly
            ),
        ]
    );
    assert_eq!(
        rows(&current, duration_name),
        vec![
            (
                duration_second.commit,
                RootReason::Current,
                ParentCutoff::Since(110)
            ),
            (
                duration_second.commit,
                RootReason::RetentionWitness,
                ParentCutoff::Since(110)
            ),
            (
                duration_first.commit,
                RootReason::RetentionWitness,
                ParentCutoff::RootsOnly
            ),
            (
                duration_first.commit,
                RootReason::RetentionWitness,
                ParentCutoff::Since(110)
            ),
        ]
    );
    assert!(
        rows(&current, count_name)
            .iter()
            .all(|row| row.0 != proposal.record.commit)
    );
    assert_eq!(
        repository
            .coordinator()
            .guard()
            .store()
            .ref_log_read(count_name, 1)
            .await
            .assert_success()
            .iter()
            .map(|row| row.record.seq)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    drop(collection);
    drop(repository);
    fixture.cleanup();
}

/// Reopens genuine selected progress while fresh current roots advance separately.
///
/// # Panics
/// Panics if persisted root bytes, resumed progress or fresh selected roots differ.
pub(super) async fn snapshot_resume_preserves_roots_after_current_ref_moves() {
    let fixture = Fixture::new().await;
    let repository = production_repository(&fixture).await;
    let mut collection = Collection::start(
        repository.coordinator().guard(),
        &fixture.authority,
        "roots-collector".into(),
        1_000,
        53,
        windows(),
    )
    .await
    .assert_success();
    let selected_roots = collection.roots().clone();
    let roots_path = fixture.config.root.join("gc/53/roots");
    let roots_bytes = std::fs::read(&roots_path).assert_success();
    assert_eq!(
        GcRoots::decode(&roots_bytes).assert_success(),
        selected_roots
    );
    collection.mark_batch(1).await.assert_success();
    let selected_state = collection.state().clone();
    let moved = publish(
        &fixture,
        &repository,
        "refs/heads/_/main",
        b"after snapshot",
        Some(b"\x82\x65count\x00"),
        None,
    )
    .await;
    let (cycle, fresh) = snapshots(&fixture, &repository, &collection).await;
    assert_eq!(cycle, selected_roots);
    assert!(
        fresh
            .roots
            .iter()
            .any(|root| root.commit == moved.commit && root.reason == RootReason::Current)
    );
    assert!(cycle.roots.iter().all(|root| root.commit != moved.commit));
    assert_eq!(std::fs::read(&roots_path).assert_success(), roots_bytes);
    let lease = collection.lease().clone();
    drop(collection);
    drop(repository);
    let reopened = production_repository(&fixture).await;
    let resumed = Collection::resume(
        reopened.coordinator().guard(),
        &fixture.authority,
        lease,
        1_000,
        53,
        windows(),
    )
    .await
    .assert_success();
    assert_eq!(resumed.roots(), &selected_roots);
    assert_eq!(resumed.state(), &selected_state);
    let (cycle, fresh) = snapshots(&fixture, &reopened, &resumed).await;
    assert_eq!(cycle, selected_roots);
    assert!(
        fresh
            .roots
            .iter()
            .any(|root| root.commit == moved.commit && root.reason == RootReason::Current)
    );
    assert_eq!(std::fs::read(&roots_path).assert_success(), roots_bytes);
    drop(resumed);
    drop(reopened);
    fixture.cleanup();
}

/// Refuses unknown or partial successor inventories before they gain selection.
///
/// # Panics
/// Panics if incomplete data is selected, alters physical effects or changes roots.
pub(super) async fn incomplete_inventory_cannot_replace_selected_authority() {
    let fixture = Fixture::new().await;
    let repository = production_repository(&fixture).await;
    let collection = Collection::start(
        repository.coordinator().guard(),
        &fixture.authority,
        "roots-collector".into(),
        1_000,
        54,
        windows(),
    )
    .await
    .assert_success();
    let holder = SingleHeld::acquire(repository.coordinator().guard().store())
        .await
        .assert_success();
    let held = holder.destination();
    let before = held.observe_publication_unrepaired().await.assert_success();
    let bytes = before
        .logical()
        .get("CAPABILITIES")
        .assert_success()
        .as_ref()
        .assert_success();
    let complete = BucketCapabilities::decode(bytes).assert_success();
    assert!(
        complete
            .ref_names
            .as_ref()
            .assert_success()
            .iter()
            .any(|name| name == "refs/heads/_/main")
    );
    for names in [None, Some(Vec::new())] {
        let mut incomplete = complete.clone();
        incomplete.ref_names = names;
        fixture.fs.reset();
        let result = held
            .publish_raw(
                &before,
                vec![LogicalChange {
                    key: "CAPABILITIES".into(),
                    expected: Some(bytes.clone()),
                    new: Some(incomplete.encode().assert_success()),
                }],
            )
            .await;
        let error = match result {
            Ok(_) => panic!("incomplete inventory acquired native selection"),
            Err(error) => error,
        };
        assert_eq!(
            error.kind(),
            &StoreErrorKind::Corrupt(CorruptSubject::RefName("publication".into()))
        );
        assert!(std::error::Error::source(&error).is_none());
        assert_eq!(fixture.fs.effects(), 0);
        let after = held.observe_publication_unrepaired().await.assert_success();
        assert_eq!(after.stamp(), before.stamp());
        assert_eq!(after.state(), before.state());
        assert_eq!(after.logical(), before.logical());
    }
    drop(before);
    drop(held);
    drop(holder);
    let (cycle, current) = snapshots(&fixture, &repository, &collection).await;
    assert_eq!(cycle.roots, current.roots);
    assert_eq!(rows(&current, "refs/heads/_/main").len(), 2);
    drop(collection);
    drop(repository);
    fixture.cleanup();
}
