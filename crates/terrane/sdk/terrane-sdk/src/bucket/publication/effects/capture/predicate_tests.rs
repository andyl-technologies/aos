//! Exercises original input predicates across real directory and leaf changes.
//!
//! Captures come from the actual held backend. Native root synchronization is
//! ordinary fixture work and establishes no publication or selected authority.

use super::*;
use crate::bucket::{FileBucket, FileBucketConfig, FileBucketPublicationConfig, held::SingleHeld};
use crate::store::{ContentValidator, EffectFault, MetaUpload, TokioClock, TokioLocalFs};
use std::{
    fmt::Debug,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
};
use terrane_format::{chunking::ChunkProfile, identity::IdentityKind, refs::Locality};

struct Validator;

impl ContentValidator for Validator {
    fn validate_meta(&self, upload: &MetaUpload<'_>) -> Result<(), StoreFailure> {
        if upload.kind() != IdentityKind::Node {
            return Err(corrupt());
        }
        terrane_format::tree_format::decode_node(upload.bytes(), true, 262144)
            .map(|_| ())
            .map_err(|_| corrupt())
    }
}

fn required<T, E: Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| panic!("actual native fixture failed: {error:?}"))
}

fn present<T>(value: Option<T>, message: &str) -> T {
    match value {
        Some(value) => value,
        None => panic!("{message}"),
    }
}

fn refused<T>(result: std::io::Result<T>, message: &str) -> std::io::Error {
    match result {
        Err(error) => error,
        Ok(_) => panic!("{message}"),
    }
}

async fn fixture() -> FileBucket<TokioLocalFs, TokioClock, Validator> {
    let entropy = required(TokioLocalFs.random_bytes(16).await);
    let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
    let root = std::env::temp_dir().join(format!("terrane-input-predicates-{suffix}"));
    let owner_probe = root.with_file_name(format!(".terrane-input-owner-{suffix}"));
    directory(&owner_probe);
    let operator_uid = required(std::fs::symlink_metadata(&owner_probe)).uid();
    required(std::fs::remove_dir(&owner_probe));

    required(
        FileBucket::open(
            FileBucketConfig {
                root,
                publication_control: Some(FileBucketPublicationConfig {
                    operator_uid,
                    control: None,
                }),
                chunk_profile_name: "cdc-1m".into(),
                chunk_profile: ChunkProfile::cdc_1m([0; 32]),
                locality: Locality::default(),
            },
            TokioLocalFs,
            TokioClock,
            Validator,
        )
        .await,
    )
}

fn directory(path: &Path) {
    required(std::fs::DirBuilder::new().mode(0o700).create(path));
}

fn write(path: &Path, body: &[u8]) {
    required(std::fs::write(path, body));
    required(std::fs::set_permissions(
        path,
        std::fs::Permissions::from_mode(0o600),
    ));
}

async fn capture(frame: &mut Frame, path: &Path, policy: FencePolicy) {
    required(frame.actual_read(&TokioLocalFs, path, policy).await);
}

fn input<'a>(reads: &'a [ExactRead], path: &Path) -> &'a ExactRead {
    reads
        .iter()
        .find(|read| read.path == path)
        .unwrap_or_else(|| panic!("actual input recipe missing: {path:?}"))
}

/// Models the actual continuity constraints as ordinary immutable tuple data.
fn stamp_constraints(stamp: MetadataStamp) -> ((u64, u64), u32, u32, Option<u64>) {
    let regular_links = (stamp.mode & libc::S_IFMT == libc::S_IFREG).then_some(stamp.links);
    (stamp.identity, stamp.owner, stamp.mode, regular_links)
}

fn assert_constraint_matrix(reads: &[&ExactRead]) {
    let constraints: Vec<_> = reads
        .iter()
        .map(|read| {
            (
                &read.path,
                &read.expected,
                read.identity,
                read.metadata.map(stamp_constraints),
                read.policy,
                read.owner,
                read.parents
                    .iter()
                    .map(|parent| (&parent.path, stamp_constraints(parent.stamp)))
                    .collect::<Vec<_>>(),
            )
        })
        .collect();
    for (left_index, left) in reads.iter().enumerate() {
        for (right_index, right) in reads.iter().enumerate() {
            assert_eq!(
                same_read_predicate(left, right),
                constraints[left_index] == constraints[right_index],
                "actual constraint pair {left_index}/{right_index}",
            );
        }
    }
}

/// Compares static physical refusals without promising transient sample order.
async fn refuses_original_and_packaged(frame: &Frame, root: &Path, path: &Path) {
    let original = input(&frame.reads, path);
    let (_, packaged) = required(frame.physical_inputs());
    let retained = input(&packaged, path);
    assert!(retained == original, "first actual recipe was rewritten");
    let before = refused(original.check(), "original input must refuse");
    let after = refused(retained.check(), "packaged input must refuse");
    assert_eq!(before.kind(), after.kind());
    assert_eq!(before.to_string(), after.to_string());

    let effect = required(frame.effect(Plan::SyncDirectory {
        path: root.to_owned(),
    }))
    .inject_test_faults(vec![EffectFault::BeforeDirectorySync]);
    match TokioLocalFs.execute_retained_effect(effect).await {
        Err(NativeEffectFailure::Io(error)) => {
            assert_eq!(error.kind(), std::io::ErrorKind::Other);
            assert!(
                !error.to_string().contains("injected"),
                "physical refusal must precede the sync fault: {error}"
            );
        }
        outcome => panic!("actual native input refusal required: {outcome:?}"),
    }
}

#[tokio::test]
async fn directory_link_growth_keeps_original_input_recipe_and_fresh_refusals() {
    let bucket = fixture().await;
    let holder = required(SingleHeld::acquire(&bucket).await);
    let held = holder.destination();
    let observed = required(held.observe_publication().await);
    let (mut frame, _) =
        required(super::super::raw::backend_with_control(&TokioLocalFs, &observed).await);
    let parent = bucket.root().join("predicate-inputs");
    directory(&parent);
    let path = parent.join("input");
    write(&path, b"original body");
    let policy = FencePolicy::Payload { owner: frame.owner };
    let directory_policy = FencePolicy::NamespaceDirectory { owner: frame.owner };
    capture(&mut frame, &path, policy).await;
    required(
        frame
            .directory(&TokioLocalFs, &parent, directory_policy)
            .await,
    );
    let first_name = frame.names.len() - 1;
    let before = required(std::fs::symlink_metadata(&parent));

    directory(&parent.join("unrelated-child"));
    let after = required(std::fs::symlink_metadata(&parent));
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    assert_eq!(after.nlink(), before.nlink() + 1);
    capture(&mut frame, &path, policy).await;
    required(
        frame
            .directory(&TokioLocalFs, &parent, directory_policy)
            .await,
    );

    let originals: Vec<_> = frame
        .reads
        .iter()
        .filter(|read| read.path == path)
        .collect();
    assert_eq!(originals.len(), 2);
    assert_constraint_matrix(&originals);
    assert!(originals[0] != originals[1]);
    assert!(same_read_predicate(originals[0], originals[1]));
    let original_parent = present(
        originals[0]
            .parents
            .iter()
            .find(|fence| fence.path == parent),
        "actual original parent recipe",
    );
    assert_eq!(original_parent.stamp.links, before.nlink());
    let second_name = present(frame.names.last(), "second actual name");
    assert!(frame.names[first_name] != *second_name);
    assert!(same_name_predicate(&frame.names[first_name], second_name));

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
    assert!(input(&effect.preimages, &path) == originals[0]);
    let names: Vec<_> = effect
        .names
        .iter()
        .filter(|name| name.path == parent && name.policy == directory_policy)
        .collect();
    assert_eq!(names.len(), 1);
    assert!(*names[0] == frame.names[first_name]);
    assert_eq!(names[0].stamp.links, before.nlink());
    assert!(Arc::ptr_eq(&effect.exclusions, &frame.exclusions));
    required(TokioLocalFs.execute_retained_effect(effect).await);

    // Every mutation happens after genuine capture and successful fixture sync.
    write(&path, b"changed body");
    refuses_original_and_packaged(&frame, bucket.root(), &path).await;
    write(&path, b"original body");

    required(std::fs::set_permissions(
        &path,
        std::fs::Permissions::from_mode(0o640),
    ));
    refuses_original_and_packaged(&frame, bucket.root(), &path).await;
    required(std::fs::set_permissions(
        &path,
        std::fs::Permissions::from_mode(0o600),
    ));

    let alias = parent.join("hardlink");
    required(std::fs::hard_link(&path, &alias));
    assert_eq!(required(std::fs::symlink_metadata(&path)).nlink(), 2);
    refuses_original_and_packaged(&frame, bucket.root(), &path).await;
    required(std::fs::remove_file(&alias));

    required(std::fs::set_permissions(
        &parent,
        std::fs::Permissions::from_mode(0o720),
    ));
    refuses_original_and_packaged(&frame, bucket.root(), &path).await;
    required(std::fs::set_permissions(
        &parent,
        std::fs::Permissions::from_mode(0o700),
    ));

    let saved = parent.join("saved-input");
    required(std::fs::rename(&path, &saved));
    write(&path, b"original body");
    let replacement = required(std::fs::symlink_metadata(&path));
    assert_ne!(
        (replacement.dev(), replacement.ino()),
        (
            required(std::fs::symlink_metadata(&saved)).dev(),
            required(std::fs::symlink_metadata(&saved)).ino()
        ),
    );
    assert_eq!(
        required(std::fs::read(&path)),
        required(std::fs::read(&saved))
    );
    refuses_original_and_packaged(&frame, bucket.root(), &path).await;
    required(std::fs::remove_file(&path));
    required(std::fs::rename(&saved, &path));

    let saved_parent = bucket.root().join("saved-predicate-inputs");
    required(std::fs::rename(&parent, &saved_parent));
    directory(&parent);
    write(&path, b"original body");
    let replacement = required(std::fs::symlink_metadata(&parent));
    assert_ne!(
        (before.dev(), before.ino()),
        (replacement.dev(), replacement.ino())
    );
    assert_eq!(
        required(std::fs::read(&path)),
        required(std::fs::read(saved_parent.join("input")))
    );
    refuses_original_and_packaged(&frame, bucket.root(), &path).await;
}

#[tokio::test]
async fn differing_original_input_constraints_remain_distinct_and_fail_closed() {
    let bucket = fixture().await;
    let holder = required(SingleHeld::acquire(&bucket).await);
    let held = holder.destination();
    let observed = required(held.observe_publication().await);
    let (mut frame, _) =
        required(super::super::raw::backend_with_control(&TokioLocalFs, &observed).await);
    let ancestor = bucket.root().join("distinct-original-parent");
    directory(&ancestor);
    let ancestry_input = ancestor.join("input");
    write(&ancestry_input, b"unchanged ancestry input");
    let path = bucket.root().join("predicate-distinct-input");
    write(&path, b"A");
    let payload = FencePolicy::Payload { owner: frame.owner };
    let protected = FencePolicy::ProtectedRecord { owner: frame.owner };
    capture(&mut frame, &ancestry_input, payload).await;
    capture(&mut frame, &path, payload).await;
    capture(&mut frame, &path, protected).await;
    capture(&mut frame, &path, payload).await;
    write(&path, b"B");
    capture(&mut frame, &path, payload).await;
    write(&path, b"A");
    capture(&mut frame, &path, payload).await;
    required(std::fs::set_permissions(
        &path,
        std::fs::Permissions::from_mode(0o640),
    ));
    capture(&mut frame, &path, payload).await;
    required(std::fs::set_permissions(
        &path,
        std::fs::Permissions::from_mode(0o600),
    ));
    capture(&mut frame, &path, payload).await;

    let key = required(BucketKey::parse("CAPABILITIES"));
    let lock = bucket.root().join(key.lock_name());
    let identity = observed.identity().physical_identity().1;
    for descriptor in [None, Some(0), None] {
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

    let (packaged_names, packaged) = required(frame.physical_inputs());
    let original: Vec<_> = frame
        .reads
        .iter()
        .filter(|read| read.path == path)
        .collect();
    assert_constraint_matrix(&original);
    let retained: Vec<_> = packaged.iter().filter(|read| read.path == path).collect();
    assert_eq!(retained.len(), 4);
    for (actual, expected) in retained.iter().zip([0, 1, 3, 5]) {
        assert!(**actual == *original[expected]);
    }
    assert_eq!(retained[0].expected.as_deref(), Some(b"A".as_slice()));
    assert_eq!(retained[2].expected.as_deref(), Some(b"B".as_slice()));
    assert!(retained[0].policy != retained[1].policy);
    assert_ne!(
        present(retained[0].metadata, "actual metadata").mode,
        present(retained[3].metadata, "actual metadata").mode
    );

    let effect = required(frame.effect(Plan::SyncDirectory {
        path: bucket.root().to_owned(),
    }));
    let names: Vec<_> = packaged_names
        .iter()
        .filter(|name| name.path == lock)
        .collect();
    assert_eq!(names.len(), 2);
    assert_eq!(names[0].descriptor, Some(0));
    assert_eq!(names[1].descriptor, None);
    match TokioLocalFs.execute_retained_effect(effect).await {
        Err(NativeEffectFailure::Io(error)) => {
            assert_eq!(error.to_string(), "whole preimage changed")
        }
        outcome => panic!("distinct original B must refuse current A: {outcome:?}"),
    }

    let saved = bucket.root().join("saved-distinct-input");
    required(std::fs::rename(&path, &saved));
    write(&path, b"A");
    capture(&mut frame, &path, payload).await;
    let (_, packaged) = required(frame.physical_inputs());
    let retained: Vec<_> = packaged.iter().filter(|read| read.path == path).collect();
    assert_eq!(retained.len(), 5);
    assert_ne!(retained[0].identity, retained[4].identity);
    refuses_original_and_packaged(&frame, bucket.root(), &path).await;

    // Independently capture the new ancestry under the same genuine held scope.
    // Moving the original leaf preserves its inode and body, isolating the
    // changed parent constraints without updating the first original recipe.
    let old_ancestor = required(std::fs::symlink_metadata(&ancestor));
    let saved_ancestor = bucket.root().join("saved-distinct-parent");
    required(std::fs::rename(&ancestor, &saved_ancestor));
    directory(&ancestor);
    required(std::fs::rename(
        saved_ancestor.join("input"),
        &ancestry_input,
    ));
    let new_ancestor = required(std::fs::symlink_metadata(&ancestor));
    assert_ne!(
        (old_ancestor.dev(), old_ancestor.ino()),
        (new_ancestor.dev(), new_ancestor.ino()),
    );
    for mode in [0o700, 0o750] {
        required(std::fs::set_permissions(
            &ancestor,
            std::fs::Permissions::from_mode(mode),
        ));
        let (mut fresh, _) =
            required(super::super::raw::backend_with_control(&TokioLocalFs, &observed).await);
        capture(&mut fresh, &ancestry_input, payload).await;
        frame.reads.extend(
            fresh
                .reads
                .into_iter()
                .filter(|read| read.path == ancestry_input),
        );
    }
    let (_, packaged) = required(frame.physical_inputs());
    let originals: Vec<_> = frame
        .reads
        .iter()
        .filter(|read| read.path == ancestry_input)
        .collect();
    assert_constraint_matrix(&originals);
    let retained: Vec<_> = packaged
        .iter()
        .filter(|read| read.path == ancestry_input)
        .collect();
    assert_eq!(retained.len(), 3);
    for (actual, original) in retained.iter().zip(&originals) {
        assert!(**actual == **original);
        assert_eq!(actual.identity, retained[0].identity);
        assert_eq!(actual.expected, retained[0].expected);
    }
    refuses_original_and_packaged(&frame, bucket.root(), &ancestry_input).await;

    // An equal-byte coordination reincarnation cannot match the held descriptor.
    for name in &names {
        required(name.check(&frame.exclusions));
    }
    let lock_bytes = required(std::fs::read(&lock));
    let old_lock = bucket.root().join("saved-actual-lock");
    required(std::fs::rename(&lock, &old_lock));
    write(&lock, &lock_bytes);
    let old = required(std::fs::symlink_metadata(&old_lock));
    let new = required(std::fs::symlink_metadata(&lock));
    assert_ne!((old.dev(), old.ino()), (new.dev(), new.ino()));
    for name in names {
        let original = present(
            frame
                .names
                .iter()
                .find(|original| original.path == lock && original.descriptor == name.descriptor),
            "first original coordination predicate",
        );
        assert!(name == original);
        let original_error = refused(
            original.check(&frame.exclusions),
            "original lock replacement",
        );
        let packaged_error = refused(name.check(&frame.exclusions), "packaged lock replacement");
        assert_eq!(original_error.kind(), packaged_error.kind());
        assert_eq!(original_error.to_string(), packaged_error.to_string());
    }
    let effect = required(frame.effect(Plan::SyncDirectory {
        path: bucket.root().to_owned(),
    }));
    assert!(matches!(
        TokioLocalFs.execute_retained_effect(effect).await,
        Err(NativeEffectFailure::Io(_))
    ));
}

#[tokio::test]
async fn missing_input_stays_absent_after_predicate_coalescence() {
    let bucket = fixture().await;
    let holder = required(SingleHeld::acquire(&bucket).await);
    let held = holder.destination();
    let observed = required(held.observe_publication().await);
    let (mut frame, _) =
        required(super::super::raw::backend_with_control(&TokioLocalFs, &observed).await);
    let parent = bucket.root().join("predicate-missing-inputs");
    directory(&parent);
    let path = parent.join("absent");
    let policy = FencePolicy::Payload { owner: frame.owner };
    capture(&mut frame, &path, policy).await;
    let before = required(std::fs::symlink_metadata(&parent));
    directory(&parent.join("unrelated-child"));
    let after = required(std::fs::symlink_metadata(&parent));
    assert_eq!(after.nlink(), before.nlink() + 1);
    capture(&mut frame, &path, policy).await;
    let (_, packaged) = required(frame.physical_inputs());
    assert_eq!(packaged.iter().filter(|read| read.path == path).count(), 1);
    assert!(input(&packaged, &path) == input(&frame.reads, &path));
    assert!(input(&packaged, &path).expected.is_none());
    required(input(&packaged, &path).check());

    write(&path, b"appeared");
    refuses_original_and_packaged(&frame, bucket.root(), &path).await;
    capture(&mut frame, &path, policy).await;
    required(std::fs::remove_file(&path));
    capture(&mut frame, &path, policy).await;
    let (_, packaged) = required(frame.physical_inputs());
    let retained: Vec<_> = packaged.iter().filter(|read| read.path == path).collect();
    assert_eq!(retained.len(), 2);
    assert!(retained[0].expected.is_none());
    assert_eq!(
        retained[1].expected.as_deref(),
        Some(b"appeared".as_slice())
    );
    let effect = required(frame.effect(Plan::SyncDirectory {
        path: bucket.root().to_owned(),
    }));
    assert!(matches!(
        TokioLocalFs.execute_retained_effect(effect).await,
        Err(NativeEffectFailure::Io(_))
    ));

    let (mut frame, _) =
        required(super::super::raw::backend_with_control(&TokioLocalFs, &observed).await);
    let missing_parent = bucket.root().join("originally-missing-parent");
    capture(&mut frame, &missing_parent.join("leaf"), policy).await;
    capture(&mut frame, &missing_parent.join("leaf"), policy).await;
    let (_, packaged) = required(frame.physical_inputs());
    assert_eq!(
        packaged
            .iter()
            .filter(|read| read.path == missing_parent)
            .count(),
        1
    );
    assert!(input(&packaged, &missing_parent) == input(&frame.reads, &missing_parent));
    directory(&missing_parent);
    write(&missing_parent.join("leaf"), b"appeared descendant");
    refuses_original_and_packaged(&frame, bucket.root(), &missing_parent).await;
}
