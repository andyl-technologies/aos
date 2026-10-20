//! Exercises explicit native copy admission and exact destination activation.

#![allow(clippy::unwrap_used)]

mod closure;
mod recovery;
mod support;

use super::{
    FileBucket,
    held::SingleHeld,
    tests::{PreparedCas, Selected, log},
};
use crate::pack::{MergedShard, PackId};
use crate::ref_advance::tests::Validator;
use crate::store::{
    ContentStore, LocalFs, RefCasOutcome, RefStore, StoreErrorKind, TokioClock, TokioLocalFs,
};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use support::*;
use terrane_format::bucket::{BucketCapabilities, BucketKey, GenerationManifest};
use terrane_format::gc::publication::{
    Activation, BackendRegistration, CommittedSelection, PermanentOwnerSelection, PortableCurrent,
    PortableSnapshot, ProjectionEntry, SelectedHistory,
};
use terrane_format::identity::{IdentityKind, TERRANE_V1};

use crate::store::native_publication_effects::initialization::copy_tests::{
    self as boundaries, CopyBoundary,
};

#[tokio::test]
async fn portable_copy_resolves_exact_projection_and_selected_log_closure() {
    closure::run().await;
}

#[tokio::test]
async fn portable_copy_preserves_absent_ref_history_and_recreation() {
    let (native, first) = source().await;
    {
        let held = SingleHeld::acquire(native.store()).await.unwrap();
        let destination = held.destination();
        let observed = destination.observe_publication().await.unwrap();
        destination
            .publish_raw(
                &observed,
                vec![terrane_format::gc::publication::LogicalChange {
                    key: format!("{NAME}:record"),
                    expected: Some(first.encode().unwrap()),
                    new: None,
                }],
            )
            .await
            .unwrap();
    }
    let configuration = destination(native.store()).await;
    let copied = initialize(configuration.clone()).await.unwrap();
    assert_eq!(copied.ref_get(NAME).await.unwrap(), None);
    let logs = copied.ref_log_read(NAME, 1).await.unwrap();
    assert_eq!(logs.last().unwrap().record, first);
    let selected = copied.selected_publication_locked().await.unwrap();
    assert_eq!(
        selected.state.branches[0].selection,
        CommittedSelection::Selected(first.clone().into())
    );
    let reset = terrane_format::refs::RefRecord::first(
        first.commit,
        first.writer_epoch,
        first.home.clone(),
    )
    .selected();
    assert!(copied.prepared_cas(NAME, None, &reset).await.is_err());
    let second = first
        .advance(first.commit, first.writer_epoch)
        .unwrap()
        .selected();
    let mut candidate = log(second.clone(), None);
    candidate.previous_commit = Some(first.commit);
    candidate.committed_previous = Some(first.clone());
    copied
        .ref_log_append(NAME, second.seq, &candidate)
        .await
        .unwrap();
    assert!(matches!(
        copied.ref_cas(NAME, None, &second).await.unwrap(),
        RefCasOutcome::Applied
    ));
    let logs = copied.ref_log_read(NAME, 1).await.unwrap();
    assert_eq!(logs.len(), 2);
    assert_eq!(logs[0].record, first);
    assert_eq!(logs[1], candidate);
    drop(copied);
    assert_eq!(
        reopen(configuration.clone())
            .await
            .unwrap()
            .ref_get(NAME)
            .await
            .unwrap(),
        Some(second)
    );
    remove(&configuration).await;
}

#[tokio::test]
async fn portable_copy_requires_genuine_destination_registration() {
    let (native, _) = source().await;
    let configuration = destination(native.store()).await;
    assert!(
        matches!(reopen(configuration.clone()).await, Err(error) if matches!(error.kind(), StoreErrorKind::Unsupported))
    );
    assert!(!control(&configuration).exists());
    let fs = ReadFs::default();
    fs.deny_retention();
    assert!(
        FileBucket::initialize_portable_copy(
            configuration.clone(),
            fs.clone(),
            TokioClock,
            Validator
        )
        .await
        .is_err()
    );
    assert_eq!(fs.effects(), 0);
    assert!(!control(&configuration).exists());
    initialize(configuration.clone()).await.unwrap();
    let before = tokio::fs::read(control(&configuration).join("backend-registration.cbor"))
        .await
        .unwrap();
    assert!(initialize(configuration.clone()).await.is_err());
    assert_eq!(
        tokio::fs::read(control(&configuration).join("backend-registration.cbor"))
            .await
            .unwrap(),
        before
    );
    remove(&configuration).await;

    for case in [
        "same root stamp",
        "wrong operator",
        "existing control",
        "symlink root",
        "hardlinked lock",
        "unsafe root",
    ] {
        let mut configuration = destination(native.store()).await;
        match case {
            "same root stamp" => {
                let mut projection = portable(native.store()).await;
                let mut stamp = origin(&projection);
                if let terrane_format::gc::publication::BackendBinding::Local { root, .. } =
                    &mut stamp
                {
                    use std::os::unix::ffi::OsStrExt;
                    *root = configuration.root.as_os_str().as_bytes().to_vec();
                }
                let mut history = SelectedHistory::decode(
                    projection["publication/SELECTED-HISTORY"]
                        .as_deref()
                        .unwrap(),
                )
                .unwrap();
                history.origin = stamp.clone();
                projection.insert(
                    "publication/SELECTED-HISTORY".into(),
                    Some(history.encode().unwrap()),
                );
                checkpoint(&configuration.root, &projection, stamp, 0).await;
            }
            "wrong operator" => {
                configuration
                    .publication_control
                    .as_mut()
                    .unwrap()
                    .operator_uid = rustix::process::geteuid().as_raw().checked_add(1).unwrap()
            }
            "existing control" => {
                TokioLocalFs
                    .create_dir_new(&control(&configuration))
                    .await
                    .unwrap();
            }
            "symlink root" => {
                let moved = configuration.root.with_extension("real");
                tokio::fs::rename(&configuration.root, &moved)
                    .await
                    .unwrap();
                std::os::unix::fs::symlink(&moved, &configuration.root).unwrap();
            }
            "hardlinked lock" => {
                let key = BucketKey::parse("CAPABILITIES").unwrap().lock_name();
                tokio::fs::remove_file(configuration.root.join(&key))
                    .await
                    .unwrap();
                tokio::fs::hard_link(
                    native.store().root().join(&key),
                    configuration.root.join(&key),
                )
                .await
                .unwrap();
            }
            "unsafe root" => {
                tokio::fs::set_permissions(
                    &configuration.root,
                    std::fs::Permissions::from_mode(0o777),
                )
                .await
                .unwrap();
            }
            _ => unreachable!(),
        }
        assert!(initialize(configuration.clone()).await.is_err(), "{case}");
        if case != "existing control" {
            assert!(!control(&configuration).exists(), "{case}");
        }
        if case == "symlink root" {
            tokio::fs::remove_file(&configuration.root).await.unwrap();
            tokio::fs::remove_dir_all(configuration.root.with_extension("real"))
                .await
                .unwrap();
        } else {
            remove(&configuration).await;
        }
    }
}

#[tokio::test]
async fn portable_copy_recovers_exact_pending_activation_at_every_boundary() {
    recovery::run().await;
}

#[tokio::test]
async fn portable_copy_after_interrupted_source_projection_uses_selected_pointer() {
    for (key, after, new_pointer) in [
        ("publication/PORTABLE", false, false),
        ("publication/PORTABLE", true, true),
        ("refs/heads/tenant/main:record", false, true),
    ] {
        let (native, head) = source().await;
        let fs = ReadFs::default();
        let source_bucket = FileBucket::open(
            native.store().inner.config.clone(),
            fs.clone(),
            TokioClock,
            Validator,
        )
        .await
        .unwrap();
        let second = head
            .advance(head.commit, head.writer_epoch)
            .unwrap()
            .selected();
        source_bucket
            .ref_log_append(NAME, second.seq, &log(second.clone(), Some(head.clone())))
            .await
            .unwrap();
        fs.fault(source_bucket.root().join(key), after);
        assert!(
            source_bucket
                .ref_cas(NAME, Some(&head), &second)
                .await
                .is_err(),
            "{key}, after={after}"
        );
        let configuration = destination(native.store()).await;
        let copied = initialize(configuration.clone()).await.unwrap();
        let expected = if new_pointer { second } else { head };
        assert_eq!(
            copied.ref_get(NAME).await.unwrap(),
            Some(expected.clone()),
            "{key}, after={after}"
        );
        assert_eq!(
            copied
                .ref_log_read(NAME, 1)
                .await
                .unwrap()
                .last()
                .unwrap()
                .record,
            expected
        );
        assert_eq!(
            copied
                .selected_publication_locked()
                .await
                .unwrap()
                .state
                .branches[0]
                .selection,
            CommittedSelection::Selected(expected.into())
        );
        remove(&configuration).await;
    }
}

#[tokio::test]
async fn portable_copy_cancellation_keeps_actual_activation_exclusion() {
    use std::os::unix::fs::OpenOptionsExt;
    use std::time::Duration;
    let (native, head) = source().await;
    for cancel in [false, true] {
        let configuration = destination(native.store()).await;
        let control = control(&configuration);
        let (arrived, arrivals) = std::sync::mpsc::channel();
        let (release, releases) = std::sync::mpsc::channel();
        let observations = boundaries::gate(
            control.clone(),
            configuration.root.clone(),
            CopyBoundary::Pending,
            arrived,
            releases,
        );
        let first_config = configuration.clone();
        let creator = tokio::spawn(async move { initialize(first_config).await });
        tokio::time::timeout(
            Duration::from_secs(30),
            tokio::task::spawn_blocking(move || arrivals.recv().unwrap()),
        )
        .await
        .unwrap()
        .unwrap();
        let retained = observations.recv().unwrap();
        assert!(retained.retained());
        let path = configuration
            .root
            .join(BucketKey::parse("CAPABILITIES").unwrap().lock_name());
        let contender = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
            .unwrap();
        let named = std::fs::symlink_metadata(&path).unwrap();
        let opened = contender.metadata().unwrap();
        assert_eq!((named.dev(), named.ino()), (opened.dev(), opened.ino()));
        if cancel {
            creator.abort();
        }
        assert!(retained.retained());
        assert!(matches!(
            contender.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        drop(contender);
        let second_config = configuration.clone();
        let second = if cancel {
            None
        } else {
            Some(tokio::spawn(async move { initialize(second_config).await }))
        };
        release.send(()).unwrap();
        if cancel {
            assert!(creator.await.err().unwrap().is_cancelled());
            let held = tokio::time::timeout(
                Duration::from_secs(30),
                TokioLocalFs.lock_existing_exclusive(&path),
            )
            .await
            .unwrap()
            .unwrap();
            let pending = BackendRegistration::decode(
                &tokio::fs::read(control.join("backend-registration.cbor"))
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(pending.activation, Activation::Pending);
            assert!(!control.join("publication/commits/0").exists());
            drop(held);
        } else {
            creator.await.unwrap().unwrap();
            assert!(second.unwrap().await.unwrap().is_err());
        }
        assert!(!retained.retained());
        let copied = reopen(configuration.clone()).await.unwrap();
        assert_eq!(copied.ref_get(NAME).await.unwrap(), Some(head.clone()));
        let activation = tokio::fs::read(control.join("publication/ACTIVATION"))
            .await
            .unwrap();
        assert_eq!(
            tokio::fs::read(control.join("publication/commits/0"))
                .await
                .unwrap(),
            activation
        );
        remove(&configuration).await;
    }
}

#[tokio::test]
async fn portable_copy_preserves_burn_visibility_without_old_artifacts() {
    use crate::pack::{EntryKind, PackClass, PackWriter};
    use crate::store::{ContentUpload, MetaUpload};
    let (native, head) = source().await;
    let old = PackId::generate(&TokioLocalFs).await.unwrap();
    let mut writer = PackWriter::new(old, PackClass::Data, false);
    writer
        .append_raw(EntryKind::Chunk, b"burned old body")
        .unwrap();
    let sealed = writer.seal().unwrap();
    let old_index = sealed.index_object().to_vec();
    let old_entry = super::containers::inventory_entry(old, sealed.bytes(), &old_index).unwrap();
    let old_pack_identity = TERRANE_V1
        .from_digest(IdentityKind::Pack, &old_entry.pack_hash)
        .unwrap();
    let old_index_identity = TERRANE_V1
        .from_digest(IdentityKind::Index, &old_entry.index_hash)
        .unwrap();
    // A configured pure Index validator admits this exact opaque alias. The
    // bucket still delegates Node/Commit semantics to the native fixture.
    let source_bucket = FileBucket::open(
        native.store().inner.config.clone(),
        TokioLocalFs,
        TokioClock,
        IndexValidator,
    )
    .await
    .unwrap();
    assert_eq!(
        source_bucket
            .put(ContentUpload::Meta(
                MetaUpload::new(IdentityKind::Index, &old_index).unwrap()
            ))
            .await
            .unwrap(),
        old_index_identity
    );
    let original = source_bucket
        .selected_publication_locked()
        .await
        .unwrap()
        .logical;
    let cap = BucketCapabilities::decode(original["CAPABILITIES"].as_deref().unwrap()).unwrap();
    let generation = cap.generation.unwrap();
    let manifest_key = format!("objects/index/{generation}/MANIFEST");
    for retained_inventory in [false, true] {
        let configuration = destination(native.store()).await;
        let mut projection = original.clone();
        projection.insert("gc/lease".into(), None);
        let mut manifest =
            GenerationManifest::decode(projection[&manifest_key].as_deref().unwrap()).unwrap();
        if retained_inventory {
            let inventory = manifest.inventory.as_mut().unwrap();
            inventory.push(old_entry.clone());
            inventory.sort_by_key(|row| row.pack_id);
        }
        manifest.burns = Some(vec![*old.as_bytes()]);
        manifest.exclusions = Some(vec![terrane_format::bucket::PackExclusion {
            pack_id: *old.as_bytes(),
            cycle: 7,
            epoch: 3,
        }]);
        projection.insert(manifest_key.clone(), Some(manifest.encode().unwrap()));
        tokio::fs::write(
            configuration.root.join(&manifest_key),
            projection[&manifest_key].as_ref().unwrap(),
        )
        .await
        .unwrap();
        checkpoint(&configuration.root, &projection, origin(&projection), 0).await;
        assert!(!configuration.root.join(old.pack_key()).exists());
        assert!(!configuration.root.join(old.index_key()).exists());
        let copied = FileBucket::initialize_portable_copy(
            configuration.clone(),
            TokioLocalFs,
            TokioClock,
            IndexValidator,
        )
        .await
        .unwrap();
        assert_eq!(copied.ref_get(NAME).await.unwrap(), Some(head.clone()));
        for identity in [&old_pack_identity, &old_index_identity] {
            assert!(
                matches!(copied.get(identity, None).await, Err(error) if matches!(error.kind(), StoreErrorKind::Absent(_)))
            );
        }
        let chunk = TERRANE_V1.calculate(IdentityKind::Chunk, BODY).unwrap();
        assert_eq!(
            copied.get(&chunk, None).await.unwrap(),
            super::content_tests::raw(BODY)
        );
        let state = copied.selected_publication_locked().await.unwrap().state;
        let selected = copied.selected_publication_locked().await.unwrap();
        assert!(
            selected
                .logical
                .keys()
                .filter(|key| key.starts_with("objects/index/"))
                .all(|key| key.starts_with(&format!("objects/index/{generation}/")))
        );
        for key in original.keys().filter(|key| {
            key.starts_with("objects/index/")
                && !key.starts_with(&format!("objects/index/{generation}/"))
        }) {
            assert!(
                configuration.root.join(key).exists(),
                "obsolete physical catalog {key}"
            );
        }
        let owner = &state.burn_owners.as_ref().unwrap()[0];
        assert_eq!(owner.pack, *old.as_bytes());
        assert_eq!(owner.selection, PermanentOwnerSelection::CopiedVisibility);
        let fresh = copied
            .catalog()
            .await
            .unwrap()
            .inventory
            .unwrap()
            .into_iter()
            .find(|row| row.pack_id != *old.as_bytes())
            .unwrap();
        let identity = TERRANE_V1
            .from_digest(IdentityKind::Index, &fresh.index_hash)
            .unwrap();
        let fresh_bytes = TokioLocalFs
            .read_nofollow(
                &configuration
                    .root
                    .join(PackId::from_random_bytes(fresh.pack_id).index_key()),
            )
            .await
            .unwrap();
        assert_eq!(copied.get(&identity, None).await.unwrap(), fresh_bytes);
        assert_eq!(
            copied
                .put(ContentUpload::Meta(
                    MetaUpload::new(IdentityKind::Index, &fresh_bytes).unwrap()
                ))
                .await
                .unwrap(),
            identity
        );
        assert!(
            copied
                .put(ContentUpload::Meta(
                    MetaUpload::new(IdentityKind::Index, &old_index).unwrap()
                ))
                .await
                .is_err()
        );
        assert!(
            copied
                .selected_publication_locked()
                .await
                .unwrap()
                .state
                .burn_owners
                .as_ref()
                .unwrap()
                .contains(owner)
        );
        drop(copied);
        let copied = FileBucket::open(
            configuration.clone(),
            TokioLocalFs,
            TokioClock,
            IndexValidator,
        )
        .await
        .unwrap();
        assert!(
            matches!(copied.get(&old_index_identity, None).await, Err(error) if matches!(error.kind(), StoreErrorKind::Absent(_)))
        );
        remove(&configuration).await;
    }
    unknown_burn_completeness(native.store(), &old_index).await;
}

/// Keeps Unknown legacy visibility distinct from a complete known-empty set.
async fn unknown_burn_completeness(source: &Bucket, index: &[u8]) {
    let mut empty_config = source.inner.config.clone();
    empty_config.root = source.root().with_extension("empty-copy-source");
    empty_config.publication_control.as_mut().unwrap().control = None;
    let empty = reopen(empty_config.clone()).await.unwrap();
    for known in [false, true] {
        let configuration = destination(&empty).await;
        let mut projection = portable(&empty).await;
        let generation = BucketCapabilities::decode(projection["CAPABILITIES"].as_deref().unwrap())
            .unwrap()
            .generation
            .unwrap();
        let key = format!("objects/index/{generation}/MANIFEST");
        let mut manifest =
            GenerationManifest::decode(projection[&key].as_deref().unwrap()).unwrap();
        manifest.burns = known.then(Vec::new);
        projection.insert(key.clone(), Some(manifest.encode().unwrap()));
        tokio::fs::write(
            configuration.root.join(&key),
            projection[&key].as_ref().unwrap(),
        )
        .await
        .unwrap();
        checkpoint(&configuration.root, &projection, origin(&projection), 0).await;

        let copied = FileBucket::initialize_portable_copy(
            configuration.clone(),
            TokioLocalFs,
            TokioClock,
            IndexValidator,
        )
        .await
        .unwrap();
        let selected = copied.selected_publication_locked().await.unwrap();
        assert_eq!(selected.state.burn_owners, known.then(Vec::new));
        assert_eq!(copied.catalog().await.unwrap().burns, known.then(Vec::new));
        let upload = crate::store::MetaUpload::new(IdentityKind::Index, index).unwrap();
        crate::store::ContentValidator::validate_meta(&IndexValidator, &upload).unwrap();
        let identity = TERRANE_V1.calculate(IdentityKind::Index, index).unwrap();
        if !known {
            assert!(
                matches!(copied.put(crate::store::ContentUpload::Meta(upload)).await, Err(error) if matches!(error.kind(), StoreErrorKind::Unsupported))
            );
            assert!(
                matches!(copied.get(&identity, None).await, Err(error) if matches!(error.kind(), StoreErrorKind::Unsupported))
            );
        } else {
            assert_eq!(
                copied
                    .put(crate::store::ContentUpload::Meta(upload))
                    .await
                    .unwrap(),
                identity
            );
            assert_eq!(copied.get(&identity, None).await.unwrap(), index);
        }
        drop(copied);
        assert_eq!(
            FileBucket::open(
                configuration.clone(),
                TokioLocalFs,
                TokioClock,
                IndexValidator
            )
            .await
            .unwrap()
            .selected_publication_locked()
            .await
            .unwrap()
            .state
            .burn_owners,
            known.then(Vec::new)
        );
        remove(&configuration).await;
    }
    remove(&empty_config).await;
}

struct IndexValidator;

impl crate::store::ContentValidator for IndexValidator {
    fn validate_meta(
        &self,
        upload: &crate::store::MetaUpload<'_>,
    ) -> Result<(), crate::store::StoreFailure> {
        if upload.kind() == IdentityKind::Index
            && crate::pack::PackIndexSnapshot::decode(upload.bytes(), 1).is_ok()
        {
            return Ok(());
        }
        crate::store::ContentValidator::validate_meta(&Validator, upload)
    }
}
