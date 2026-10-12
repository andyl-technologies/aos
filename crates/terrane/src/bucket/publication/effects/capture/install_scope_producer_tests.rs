//! Exercises early roles through actual factory-held installation and recapture.

use super::*;
use std::collections::BTreeSet;

#[tokio::test]
async fn early_install_scope_preserves_consumed_present_and_absent_roles() {
    let bucket = fixture().await;
    let holder = required(SingleHeld::acquire(&bucket).await);
    let held = holder.destination();
    let observed = required(held.observe_publication().await);
    let (mut frame, _) =
        required(super::super::backend_with_control(&TokioLocalFs, &observed).await);
    let root = bucket.root();
    let keys = [
        "objects/index/901/1.idx",
        "objects/index/901/2.idx",
        "objects/index/901/3.idx",
    ];
    required(
        frame
            .install_immutable_cohort_tracked(&TokioLocalFs, root, &[(keys[0], b"body")], None)
            .await,
    );
    let owner = frame.owner;
    assert!(
        required(
            frame
                .actual_read(
                    &TokioLocalFs,
                    &root.join(keys[1]),
                    FencePolicy::Payload { owner }
                )
                .await
        )
        .is_none()
    );
    let consumed = frame.reads.iter().map(|read| read.path.clone()).collect();
    let rows: &[(&str, &[u8])] = &[(keys[0], b"body"), (keys[1], b"body"), (keys[2], b"body")];
    let candidates = required(super::super::super::raw::early_install_candidates(
        root, owner, rows, &consumed,
    ));
    let created = required(
        frame
            .install_immutable_cohort_tracked(&TokioLocalFs, root, rows, Some(candidates))
            .await,
    );
    assert_eq!(
        created,
        BTreeSet::from([root.join(keys[1]), root.join(keys[2])])
    );

    let candidates = required(super::super::super::raw::early_install_candidates(
        root, owner, rows, &consumed,
    ));
    let mut scope = candidates.cohort(&created);
    let effect = required(frame.effect(Plan::SyncDirectory {
        path: root.to_owned(),
    }));
    scope.prepare(&effect.preimages);
    for (index, key) in keys.iter().enumerate() {
        let read = present(
            effect
                .preimages
                .iter()
                .find(|read| read.path == root.join(key)),
        );
        assert_eq!(scope.defers(read), index == 2);
    }
}

#[tokio::test]
async fn early_install_scope_excludes_container_mutable_create_once_and_existing_equal() {
    let bucket = fixture().await;
    let holder = required(SingleHeld::acquire(&bucket).await);
    let held = holder.destination();
    let observed = required(held.observe_publication().await);
    let (mut frame, _) =
        required(super::super::backend_with_control(&TokioLocalFs, &observed).await);
    let root = bucket.root();
    let owner = frame.owner;
    let key = "objects/index/902/1.idx";
    required(
        frame
            .install_immutable_cohort_tracked(&TokioLocalFs, root, &[(key, b"body")], None)
            .await,
    );
    let rows: &[(&str, &[u8])] = &[(key, b"body")];
    let candidates = required(super::super::super::raw::early_install_candidates(
        root,
        owner,
        rows,
        &BTreeSet::new(),
    ));
    assert!(
        required(
            frame
                .install_immutable_cohort_tracked(&TokioLocalFs, root, rows, Some(candidates))
                .await
        )
        .is_empty()
    );

    let pack = "objects/pack/00/00000000000000000000000000000000.pack".to_owned();
    let snapshot = format!("publication/snapshots/1:{}", "00".repeat(32));
    let excluded: &[(&str, &[u8])] = &[
        ("CAPABILITIES", b"body"),
        (&snapshot, b"body"),
        (&pack, b"body"),
    ];
    let candidates = required(super::super::super::raw::early_install_candidates(
        root,
        owner,
        excluded,
        &BTreeSet::new(),
    ));
    for (excluded_key, _) in excluded {
        assert!(!candidates.contains(&root.join(excluded_key)));
    }
    let mut scope = candidates.cohort(&BTreeSet::from([root.join(key)]));
    let effect = required(frame.effect(Plan::SyncDirectory {
        path: root.to_owned(),
    }));
    let read = present(
        effect
            .preimages
            .iter()
            .find(|read| read.path == root.join(key)),
    );
    scope.prepare(&effect.preimages);
    assert!(!scope.defers(read));
}

#[tokio::test]
async fn complete_preslot_barrier_refuses_changed_scoped_body_without_selection() {
    let bucket = fixture().await;
    let holder = required(SingleHeld::acquire(&bucket).await);
    let held = holder.destination();
    let observed = required(held.observe_publication().await);
    let (mut frame, _) =
        required(super::super::backend_with_control(&TokioLocalFs, &observed).await);
    let root = bucket.root();
    let owner = frame.owner;
    let key = "objects/index/903/1.idx";
    let rows: &[(&str, &[u8])] = &[(key, b"canonical")];
    let consumed = frame.reads.iter().map(|read| read.path.clone()).collect();
    let candidates = required(super::super::super::raw::early_install_candidates(
        root, owner, rows, &consumed,
    ));
    required(
        frame
            .install_immutable_cohort_tracked(&TokioLocalFs, root, rows, Some(candidates))
            .await,
    );

    required(std::fs::write(
        root.join(key),
        b"changed before selecting slot",
    ));
    assert!(
        frame
            .verify_staged_payloads(&TokioLocalFs, root)
            .await
            .is_err()
    );
    // The exact production preslot barrier has no selecting effect on failure.
    required(observed.revalidate().await);
    assert_eq!(
        required(held.observe_publication().await).stamp(),
        observed.stamp()
    );
}

#[path = "install_scope_preslot.rs"]
mod preslot;
