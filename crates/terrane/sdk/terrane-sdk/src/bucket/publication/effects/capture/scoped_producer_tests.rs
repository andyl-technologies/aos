//! Exercises immutable durability provenance through genuine native capture.

use super::*;
use std::collections::BTreeSet;

#[tokio::test]
async fn consumed_present_and_absent_immutable_paths_keep_input_roles() {
    let bucket = fixture().await;
    let holder = required(SingleHeld::acquire(&bucket).await);
    let held = holder.destination();
    let observed = required(held.observe_publication().await);
    let (mut frame, _) =
        required(super::super::backend_with_control(&TokioLocalFs, &observed).await);
    let root = bucket.root();
    let present_key = "objects/index/900/1.idx";
    let absent_key = "objects/index/900/2.idx";
    required(
        frame
            .install_immutable_cohort_tracked(
                &TokioLocalFs,
                root,
                &[(present_key, b"present input")],
                None,
            )
            .await,
    );
    let owner = frame.owner;
    assert!(
        required(
            frame
                .actual_read(
                    &TokioLocalFs,
                    &root.join(absent_key),
                    FencePolicy::Payload { owner }
                )
                .await
        )
        .is_none()
    );
    let inputs: BTreeSet<_> = frame.reads.iter().map(|read| read.path.clone()).collect();
    let rows: &[(&str, &[u8])] = &[(present_key, b"present input"), (absent_key, b"new output")];

    let created = required(
        frame
            .install_immutable_cohort_tracked(&TokioLocalFs, root, rows, None)
            .await,
    );
    assert_eq!(created, BTreeSet::from([root.join(absent_key)]));
    assert_eq!(
        required(TokioLocalFs.read(&root.join(absent_key)).await),
        b"new output"
    );
    // Actual recapture after creation cannot retroactively erase consumed absence.
    let scope = required(super::super::fresh_immutable_outputs(
        root, rows, &inputs, &created,
    ));
    assert!(scope.is_empty());
}

#[tokio::test]
async fn genuinely_new_immutable_output_requires_actual_creation_receipt() {
    let bucket = fixture().await;
    let holder = required(SingleHeld::acquire(&bucket).await);
    let held = holder.destination();
    let observed = required(held.observe_publication().await);
    let (mut frame, _) =
        required(super::super::backend_with_control(&TokioLocalFs, &observed).await);
    frame.writes = Some(super::super::super::CompletedWrites {
        records: BTreeMap::new(),
    });
    let root = bucket.root();
    let key = "objects/index/901/1.idx";
    let inputs: BTreeSet<_> = frame.reads.iter().map(|read| read.path.clone()).collect();
    let rows: &[(&str, &[u8])] = &[(key, b"genuine new output")];

    let created = required(
        frame
            .install_immutable_cohort_tracked(&TokioLocalFs, root, rows, None)
            .await,
    );
    let scope = required(super::super::fresh_immutable_outputs(
        root, rows, &inputs, &created,
    ));
    assert_eq!(scope, BTreeSet::from([root.join(key)]));
    let writes = present(frame.writes.as_ref());
    let (_, write) = present(writes.records().find(|(path, _)| **path == root.join(key)));
    assert_eq!(write.expected(), Some(b"genuine new output".as_slice()));
    assert_eq!(write.root(), root);
}

#[tokio::test]
async fn preexisting_equal_immutable_output_is_not_new_durability_scope() {
    let bucket = fixture().await;
    let holder = required(SingleHeld::acquire(&bucket).await);
    let held = holder.destination();
    let observed = required(held.observe_publication().await);
    let (mut frame, _) =
        required(super::super::backend_with_control(&TokioLocalFs, &observed).await);
    let root = bucket.root();
    let key = "objects/index/902/1.idx";
    let rows: &[(&str, &[u8])] = &[(key, b"already present")];
    required(
        frame
            .install_immutable_cohort_tracked(&TokioLocalFs, root, rows, None)
            .await,
    );

    let created = required(
        frame
            .install_immutable_cohort_tracked(&TokioLocalFs, root, rows, None)
            .await,
    );
    assert!(created.is_empty());
    let scope = required(super::super::fresh_immutable_outputs(
        root,
        rows,
        &BTreeSet::new(),
        &created,
    ));
    assert!(scope.is_empty());
}

#[tokio::test]
async fn registered_mutable_create_once_and_container_outputs_never_enter_scope() {
    let bucket = fixture().await;
    let holder = required(SingleHeld::acquire(&bucket).await);
    let held = holder.destination();
    let observed = required(held.observe_publication().await);
    let (mut frame, _) =
        required(super::super::backend_with_control(&TokioLocalFs, &observed).await);
    let root = bucket.root();
    let pack_key = "objects/pack/00/00000000000000000000000000000000.pack";
    let rows: &[(&str, &[u8])] = &[
        ("objects/index/903/1.idx", b"metadata output"),
        (pack_key, b"container bytes confer no creator seal"),
    ];
    let created = required(
        frame
            .install_immutable_cohort_tracked(&TokioLocalFs, root, rows, None)
            .await,
    );
    let snapshot = format!("publication/snapshots/1:{}", "0".repeat(64));
    assert!(created.contains(&root.join(pack_key)));
    assert!(
        frame
            .install_immutable_cohort_tracked(
                &TokioLocalFs,
                root,
                &[("CAPABILITIES", b"mutable")],
                None
            )
            .await
            .is_err()
    );
    assert!(
        frame
            .install_immutable_cohort_tracked(
                &TokioLocalFs,
                root,
                &[(&snapshot, b"create once")],
                None
            )
            .await
            .is_err()
    );

    let scope = required(super::super::fresh_immutable_outputs(
        root,
        &[
            ("CAPABILITIES", b"mutable"),
            (&snapshot, b"create once"),
            (
                "objects/pack/00/00000000000000000000000000000000.pack",
                b"container",
            ),
        ],
        &BTreeSet::new(),
        &created,
    ));
    assert!(scope.is_empty());
}
