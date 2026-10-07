//! Exercises predicate coalescing through genuine held capture and native effects.
//!
//! These witnesses inspect submitted physical predicates. A successful root
//! sync grants no selected publication, actor, collector or creator authority.

use super::*;
use crate::bucket::{FileBucket, held::SingleHeld};
use crate::store::{
    ContentValidator, EffectFault, MetaUpload, NativeEffectFailure, TokioClock, TokioLocalFs,
};
use std::{fmt::Debug, sync::Arc};
use terrane_core::identity::IdentityKind;

struct Validator;

impl ContentValidator for Validator {
    fn validate_meta(&self, upload: &MetaUpload<'_>) -> Result<(), StoreFailure> {
        if upload.kind() != IdentityKind::Node {
            return Err(corrupt());
        }
        terrane_core::tree_format::decode_node(upload.bytes(), true, 262144)
            .map(|_| ())
            .map_err(|_| corrupt())
    }
}

type Bucket = FileBucket<TokioLocalFs, TokioClock, Validator>;

// Assertions preserve the original typed failure rather than treating it as
// successful capture or native execution.
fn required<T, E: Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("required native fixture step failed: {error:?}"),
    }
}

fn present<T>(value: Option<T>) -> T {
    match value {
        Some(value) => value,
        None => panic!("required actual native observation is absent"),
    }
}

// Initialization uses the ordinary factory and its independently configured
// operator owner; tests never assemble a Frame or a native exclusion receipt.
async fn fixture() -> Bucket {
    let entropy = required(TokioLocalFs.random_bytes(16).await);
    let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
    let root = std::env::temp_dir().join(format!("terrane-receipt-coalescing-{suffix}"));
    required(
        FileBucket::open(
            crate::bucket::tests::config(root),
            TokioLocalFs,
            TokioClock,
            Validator,
        )
        .await,
    )
}

fn rejected(error: NativeEffectFailure, message: &str) {
    match error {
        NativeEffectFailure::Io(error) => {
            assert_eq!(error.kind(), std::io::ErrorKind::Other);
            assert_eq!(error.to_string(), message);
        }
        NativeEffectFailure::Rejected(error) => {
            panic!("unexpected producer refusal instead of physical failure: {error:?}");
        }
    }
}

#[tokio::test]
async fn native_frame_coalesces_repeated_actual_observations_before_execution() {
    let bucket = fixture().await;
    let holder = required(SingleHeld::acquire(&bucket).await);
    let held = holder.destination();
    let observed = required(held.observe_publication().await);
    let (mut frame, _) =
        required(super::super::raw::backend_with_control(&TokioLocalFs, &observed).await);
    let path = bucket.root().join("CAPABILITIES");
    let original = present(required(
        frame
            .actual_read(
                &TokioLocalFs,
                &path,
                FencePolicy::Payload { owner: frame.owner },
            )
            .await,
    ));

    for _ in 0..4 {
        assert_eq!(
            required(
                frame
                    .actual_read(
                        &TokioLocalFs,
                        &path,
                        FencePolicy::Payload { owner: frame.owner },
                    )
                    .await,
            ),
            Some(original.clone()),
        );
        required(
            frame
                .directory(
                    &TokioLocalFs,
                    bucket.root(),
                    FencePolicy::NamespaceDirectory { owner: frame.owner },
                )
                .await,
        );
    }
    assert!(frame.reads.iter().filter(|read| read.path == path).count() >= 5);
    assert!(
        frame
            .names
            .iter()
            .filter(|name| name.path == bucket.root())
            .count()
            >= 5
    );

    let effect = required(frame.effect(Plan::SyncDirectory {
        path: bucket.root().to_owned(),
    }));
    assert_eq!(
        effect
            .preimages
            .iter()
            .filter(|read| read.path == path)
            .count(),
        1
    );
    assert_eq!(
        effect
            .names
            .iter()
            .filter(|name| {
                name.path == bucket.root()
                    && matches!(name.policy, FencePolicy::NamespaceDirectory { .. })
            })
            .count(),
        1,
    );
    assert!(Arc::ptr_eq(&effect.exclusions, &frame.exclusions));
    required(TokioLocalFs.execute_retained_effect(effect).await);
    required(observed.revalidate().await);
    assert_eq!(required(TokioLocalFs.read_nofollow(&path).await), original);
}

#[tokio::test]
async fn native_frame_preserves_actual_distinct_policy_and_descriptor_predicates() {
    let bucket = fixture().await;
    let holder = required(SingleHeld::acquire(&bucket).await);
    let held = holder.destination();
    let observed = required(held.observe_publication().await);
    let (mut frame, _) =
        required(super::super::raw::backend_with_control(&TokioLocalFs, &observed).await);
    let path = bucket.root().join("CAPABILITIES");
    for policy in [
        FencePolicy::Payload { owner: frame.owner },
        FencePolicy::ProtectedRecord { owner: frame.owner },
    ] {
        present(required(
            frame.actual_read(&TokioLocalFs, &path, policy).await,
        ));
    }
    let key = required(BucketKey::parse("CAPABILITIES"));
    let lock = bucket.root().join(key.lock_name());
    let identity = observed.identity().physical_identity().1;
    for descriptor in [None, Some(0)] {
        required(
            frame
                .name(
                    &TokioLocalFs,
                    lock.clone(),
                    identity,
                    FencePolicy::NamespaceCoordination { owner: frame.owner },
                    descriptor,
                )
                .await,
        );
    }

    let effect = required(frame.effect(Plan::SyncDirectory {
        path: bucket.root().to_owned(),
    }));
    assert_eq!(
        effect
            .preimages
            .iter()
            .filter(|read| read.path == path)
            .count(),
        2
    );
    assert_eq!(
        effect.names.iter().filter(|name| name.path == lock).count(),
        2
    );
    required(TokioLocalFs.execute_retained_effect(effect).await);
    required(observed.revalidate().await);
}

#[tokio::test]
async fn native_frame_preserves_changed_actual_body_and_refuses_execution() {
    let bucket = fixture().await;
    let holder = required(SingleHeld::acquire(&bucket).await);
    let held = holder.destination();
    let observed = required(held.observe_publication().await);
    let (mut frame, _) =
        required(super::super::raw::backend_with_control(&TokioLocalFs, &observed).await);
    let path = bucket.root().join("CAPABILITIES");
    let original = present(required(
        frame
            .actual_read(
                &TokioLocalFs,
                &path,
                FencePolicy::Payload { owner: frame.owner },
            )
            .await,
    ));
    let mut changed = original.clone();
    changed.push(0);
    // A recorded physical fault changes bytes without replacing the inode.
    required(tokio::fs::write(&path, &changed).await);
    assert_eq!(
        required(
            frame
                .actual_read(
                    &TokioLocalFs,
                    &path,
                    FencePolicy::Payload { owner: frame.owner }
                )
                .await
        ),
        Some(changed),
    );

    let effect = required(frame.effect(Plan::SyncDirectory {
        path: bucket.root().to_owned(),
    }));
    let reads: Vec<_> = effect
        .preimages
        .iter()
        .filter(|read| read.path == path)
        .collect();
    assert_eq!(reads.len(), 2);
    assert_eq!(reads[0].identity, reads[1].identity);
    assert_ne!(reads[0].expected, reads[1].expected);
    // The physical refusal must precede even the real sync failure boundary.
    let effect = effect.inject_test_faults(vec![EffectFault::BeforeDirectorySync]);
    match TokioLocalFs.execute_retained_effect(effect).await {
        Err(error) => rejected(error, "whole preimage changed"),
        Ok(()) => panic!("changed original bytes were accepted by native execution"),
    }
}

#[tokio::test]
async fn native_frame_preserves_changed_actual_incarnation_and_refuses_execution() {
    let bucket = fixture().await;
    let holder = required(SingleHeld::acquire(&bucket).await);
    let held = holder.destination();
    let observed = required(held.observe_publication().await);
    let (mut frame, _) =
        required(super::super::raw::backend_with_control(&TokioLocalFs, &observed).await);
    let path = bucket.root().join("CAPABILITIES");
    let original = present(required(
        frame
            .actual_read(
                &TokioLocalFs,
                &path,
                FencePolicy::Payload { owner: frame.owner },
            )
            .await,
    ));
    let replacement = bucket.root().join(".receipt-test-replacement");
    let permissions = required(TokioLocalFs.symlink_metadata(&path).await).permissions();
    required(TokioLocalFs.write_new(&replacement, &original).await);
    required(tokio::fs::set_permissions(&replacement, permissions).await);
    required(TokioLocalFs.rename(&replacement, &path).await);
    assert_eq!(
        required(
            frame
                .actual_read(
                    &TokioLocalFs,
                    &path,
                    FencePolicy::Payload { owner: frame.owner }
                )
                .await
        ),
        Some(original),
    );

    let effect = required(frame.effect(Plan::SyncDirectory {
        path: bucket.root().to_owned(),
    }));
    let reads: Vec<_> = effect
        .preimages
        .iter()
        .filter(|read| read.path == path)
        .collect();
    assert_eq!(reads.len(), 2);
    assert_eq!(reads[0].expected, reads[1].expected);
    assert_ne!(reads[0].identity, reads[1].identity);
    // The physical refusal must precede even the real sync failure boundary.
    let effect = effect.inject_test_faults(vec![EffectFault::BeforeDirectorySync]);
    match TokioLocalFs.execute_retained_effect(effect).await {
        Err(error) => rejected(error, "exact read metadata changed"),
        Ok(()) => panic!("replaced original inode was accepted by native execution"),
    }
}
