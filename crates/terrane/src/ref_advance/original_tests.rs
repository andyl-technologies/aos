//! Exercises protected physical authority against actual opened FileBucket bindings.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::PublicationStep;
use super::fault_tests::FaultFs;
use super::tests::{
    Validator, config, configured, configured_with_fs, raw_fixture as fixture, request_file, token,
};
use crate::bucket::FileBucket;
use crate::bucket::held::HeldBuckets;
use crate::domain::DomainNamespace;
use crate::guard::{AssociationView, BootstrapView, RegistrationView};
use crate::store::{ContentStore, LocalFs, RefStore, StoreErrorKind, TokioClock, TokioLocalFs};
use std::os::unix::{
    ffi::OsStrExt,
    fs::{MetadataExt, PermissionsExt},
};
use terrane_core::{
    bucket::{BucketCapabilities, BucketKey},
    cbor,
};

#[tokio::test]
async fn original_authority_requires_exact_protected_registration_and_actual_backend() {
    let coordinator = fixture().await;
    let bucket = coordinator.guard().store();
    let root = bucket.root().to_path_buf();
    let administrative = root.with_file_name(format!(
        "{}-authority-administration",
        root.file_name().unwrap().to_string_lossy()
    ));
    TokioLocalFs.create_dir_new(&administrative).await.unwrap();
    TokioLocalFs
        .set_permissions_and_sync(&administrative, std::fs::Permissions::from_mode(0o700))
        .await
        .unwrap();
    let control = administrative.join("control");
    TokioLocalFs.create_dir_new(&control).await.unwrap();
    TokioLocalFs
        .set_permissions(&control, std::fs::Permissions::from_mode(0o700))
        .await
        .unwrap();

    let coordination = root.join(BucketKey::parse("CAPABILITIES").unwrap().lock_name());
    let root_metadata = TokioLocalFs.symlink_metadata(&root).await.unwrap();
    let lock_metadata = TokioLocalFs.symlink_metadata(&coordination).await.unwrap();
    let root_identity = (root_metadata.dev(), root_metadata.ino());
    let coordination_identity = (lock_metadata.dev(), lock_metadata.ino());
    let id = [53; 32];
    let mut bytes = Vec::new();
    cbor::write_array(&mut bytes, 9);
    cbor::write_uint(&mut bytes, 1);
    cbor::write_bytes(&mut bytes, &id);
    cbor::write_bytes(&mut bytes, root.as_os_str().as_bytes());
    cbor::write_text(&mut bytes, "public");
    for value in [
        root_identity.0,
        root_identity.1,
        coordination_identity.0,
        coordination_identity.1,
    ] {
        cbor::write_uint(&mut bytes, value);
    }
    cbor::write_bytes(&mut bytes, control.as_os_str().as_bytes());
    for (name, data) in [
        ("retention.lock", &[][..]),
        ("registration.cbor", bytes.as_slice()),
    ] {
        let path = control.join(name);
        TokioLocalFs.write_new(&path, data).await.unwrap();
        TokioLocalFs
            .set_permissions_and_sync(&path, std::fs::Permissions::from_mode(0o600))
            .await
            .unwrap();
    }
    TokioLocalFs.sync_directory(&control).await.unwrap();
    let namespace = DomainNamespace {
        root: root.clone(),
        domain: "public".into(),
    };
    let view = || RegistrationView {
        id: &id,
        root: &root,
        domain: "public",
        root_identity,
        coordination_identity,
        control: &control,
    };

    let authority = coordinator
        .guard()
        .bind_original_authority(&namespace, &control, view())
        .await
        .unwrap();
    assert_eq!(authority.id(), &id);
    assert_eq!(
        authority.physical_identity(),
        (root_identity, coordination_identity)
    );
    TokioLocalFs
        .set_permissions_and_sync(&administrative, std::fs::Permissions::from_mode(0o777))
        .await
        .unwrap();
    let unsafe_ancestor = coordinator
        .guard()
        .bind_original_authority(&namespace, &control, view())
        .await
        .unwrap_err();
    assert!(matches!(unsafe_ancestor.kind(), StoreErrorKind::Invalid(_)));
    assert_eq!(
        TokioLocalFs
            .symlink_metadata(&administrative)
            .await
            .unwrap()
            .mode()
            & 0o777,
        0o777
    );
    assert_eq!(
        coordinator
            .store()
            .ref_get("refs/heads/_/main")
            .await
            .unwrap(),
        None
    );
    TokioLocalFs
        .set_permissions_and_sync(&administrative, std::fs::Permissions::from_mode(0o700))
        .await
        .unwrap();

    let reopened = configured(
        FileBucket::open(
            config(root.clone()).await,
            TokioLocalFs,
            TokioClock,
            Validator,
        )
        .await
        .unwrap(),
    );
    assert_eq!(
        reopened
            .guard()
            .bind_original_authority(&namespace, &control, view())
            .await
            .unwrap()
            .id(),
        &id
    );

    let reference = "refs/heads/_/main";
    let acl = vec![("writer".to_owned(), 16)];
    let baseline_view = || BootstrapView {
        id: &id,
        reference,
        epoch: 1,
        acl: &acl,
    };
    assert!(
        reopened
            .guard()
            .bind_original_bootstrap(&authority, baseline_view())
            .await
            .is_err()
    );
    let mut baseline_bytes = Vec::new();
    cbor::write_array(&mut baseline_bytes, 5);
    cbor::write_uint(&mut baseline_bytes, 1);
    cbor::write_bytes(&mut baseline_bytes, &id);
    cbor::write_text(&mut baseline_bytes, reference);
    cbor::write_uint(&mut baseline_bytes, 1);
    cbor::write_array(&mut baseline_bytes, 1);
    cbor::write_array(&mut baseline_bytes, 2);
    cbor::write_text(&mut baseline_bytes, "writer");
    cbor::write_uint(&mut baseline_bytes, 16);
    let id_hex = id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let baseline_path = control.join(format!(
        "bootstrap-{id_hex}-{}-1.cbor",
        blake3::hash(reference.as_bytes()).to_hex()
    ));
    TokioLocalFs
        .write_new(&baseline_path, &baseline_bytes)
        .await
        .unwrap();
    TokioLocalFs
        .set_permissions_and_sync(&baseline_path, std::fs::Permissions::from_mode(0o600))
        .await
        .unwrap();
    let baseline = reopened
        .guard()
        .bind_original_bootstrap(&authority, baseline_view())
        .await
        .unwrap();
    assert_eq!(baseline.acl(), &acl);
    let wrong_acl = vec![("writer".to_owned(), 31)];
    assert!(
        reopened
            .guard()
            .bind_original_bootstrap(
                &authority,
                BootstrapView {
                    acl: &wrong_acl,
                    ..baseline_view()
                }
            )
            .await
            .is_err()
    );

    let commit = [61; 32];
    let association = || AssociationView {
        commit: &commit,
        id: &id,
        reference,
        epoch: 1,
    };
    assert!(
        reopened
            .guard()
            .bind_original_commit(&baseline, association())
            .await
            .is_err()
    );
    let mut association_bytes = Vec::new();
    cbor::write_array(&mut association_bytes, 5);
    cbor::write_uint(&mut association_bytes, 1);
    cbor::write_bytes(&mut association_bytes, &commit);
    cbor::write_bytes(&mut association_bytes, &id);
    cbor::write_text(&mut association_bytes, reference);
    cbor::write_uint(&mut association_bytes, 1);
    let commit_hex = commit
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let association_path = control.join(format!("commit-{commit_hex}.cbor"));
    TokioLocalFs
        .write_new(&association_path, &association_bytes)
        .await
        .unwrap();
    TokioLocalFs
        .set_permissions_and_sync(&association_path, std::fs::Permissions::from_mode(0o600))
        .await
        .unwrap();
    let context = reopened
        .guard()
        .bind_original_commit(&baseline, association())
        .await
        .unwrap();
    assert_eq!(context.commit(), &commit);
    assert_eq!(context.baseline().acl(), &acl);
    reopened
        .guard()
        .install_original_bootstrap(baseline.clone())
        .await
        .unwrap();
    reopened
        .guard()
        .install_original_bootstrap(baseline.clone())
        .await
        .unwrap();
    reopened
        .guard()
        .install_original_commit(context.clone())
        .await
        .unwrap();
    reopened
        .guard()
        .install_original_commit(context.clone())
        .await
        .unwrap();
    assert!(
        reopened
            .guard()
            .check_original_bootstrap(baseline_view())
            .await
            .is_err()
    );
    reopened
        .guard()
        .install_original_verifier(&authority)
        .await
        .unwrap();
    let checked = reopened
        .guard()
        .check_original_bootstrap(baseline_view())
        .await
        .unwrap();
    assert_eq!(checked, baseline);
    assert_eq!(
        reopened
            .guard()
            .check_original_commit(&checked, association())
            .await
            .unwrap(),
        context
    );

    // Retention precedes effects for a genuine signed candidate. The stored
    // history must then authenticate canonical scope before resolving either
    // its content introduction or the independent inline attribute producer.
    let mut writer = reopened.begin(reference, &token(), "sdk").await.unwrap();
    let prepared = reopened
        .prepare_advance(
            &mut writer,
            request_file(Vec::new(), b"retained original bytes"),
        )
        .await
        .unwrap();
    let authored = prepared.commit();
    let mut authored_bytes = Vec::new();
    cbor::write_array(&mut authored_bytes, 5);
    cbor::write_uint(&mut authored_bytes, 1);
    cbor::write_bytes(&mut authored_bytes, &authored);
    cbor::write_bytes(&mut authored_bytes, &id);
    cbor::write_text(&mut authored_bytes, reference);
    cbor::write_uint(&mut authored_bytes, writer.epoch());
    let authored_hex = authored
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let authored_path = control.join(format!("commit-{authored_hex}.cbor"));
    TokioLocalFs
        .write_new(&authored_path, &authored_bytes)
        .await
        .unwrap();
    TokioLocalFs
        .set_permissions_and_sync(&authored_path, std::fs::Permissions::from_mode(0o600))
        .await
        .unwrap();
    TokioLocalFs.sync_directory(&control).await.unwrap();
    let authored_context = reopened
        .guard()
        .check_original_commit(
            prepared.baseline(),
            AssociationView {
                commit: &authored,
                id: &id,
                reference,
                epoch: writer.epoch(),
            },
        )
        .await
        .unwrap();
    let PublicationStep::Published(outcome) = reopened
        .publish_prepared(&mut writer, prepared, authored_context)
        .await
        .unwrap()
    else {
        panic!("an uncontended initial candidate must publish once");
    };
    assert_eq!(outcome.record.commit, authored);
    assert!(outcome.excluded.is_empty());
    let verified = reopened.guard().verified_tree(authored).await.unwrap();
    let history = reopened.guard().verified_history(authored).await.unwrap();
    let location = terrane_core::provenance::EntryLocation {
        commit: authored,
        root: verified.commit.commit().tree,
        path: b"file".to_vec(),
    };
    assert_eq!(history.introducing_commit(&location).unwrap(), authored);
    assert_eq!(
        history.attribute_producer(&location, "note").unwrap(),
        authored
    );

    let restricted = terrane_core::auth::Token::decode(&token())
        .unwrap()
        .attenuate(
            terrane_core::auth::Attenuation {
                grants: Some(vec![
                    terrane_core::auth::Grant::new(
                        reference.into(),
                        terrane_core::auth::Verbs::new(8).unwrap(),
                    )
                    .unwrap(),
                ]),
                ..Default::default()
            },
            &super::tests::secret(),
            terrane_core::auth::public_key_from_secret(&super::tests::secret()),
        )
        .unwrap()
        .encode();
    assert!(reopened.begin(reference, &restricted, "sdk").await.is_err());
    let tagged = reopened
        .annotated_tag(
            reference,
            "refs/tags/_/retained",
            &restricted,
            "sdk",
            &super::TagAnnotation {
                attestation: vec![0xa0],
                terminal_secret: super::tests::secret(),
            },
        )
        .await
        .unwrap();
    assert_eq!(tagged.commit, authored);
    assert_eq!(tagged.writer_epoch, writer.epoch());
    assert!(tagged.policy.as_ref().unwrap().snapshot.is_some());
    assert!(
        reopened
            .annotated_tag(
                reference,
                "refs/tags/_/retained",
                &restricted,
                "sdk",
                &super::TagAnnotation {
                    attestation: vec![0xa0],
                    terminal_secret: super::tests::secret()
                },
            )
            .await
            .is_err()
    );

    let admitted_target = "refs/tags/_/admitted-annotation";
    let other_target = "refs/tags/_/retargeted-annotation";
    let mut retargeted = reopened
        .guard()
        .admit_tag(reference, admitted_target, &restricted, "sdk")
        .await
        .unwrap();
    reopened
        .guard()
        .annotate_tag(
            reference,
            &restricted,
            "sdk",
            &mut retargeted,
            &super::TagAnnotation {
                attestation: vec![0xa0],
                terminal_secret: super::tests::secret(),
            },
        )
        .unwrap();
    let denied = reopened
        .guard()
        .publish_tag_native(
            super::NativeTagRequest {
                source: reference.into(),
                target: other_target.into(),
                token: restricted.clone(),
                surface: "sdk".into(),
                publication: retargeted,
                started: crate::store::Clock::monotonic(&TokioClock),
                timing: super::CommitTiming::new(
                    std::time::Duration::from_secs(30),
                    std::time::Duration::from_secs(60),
                    std::time::Duration::from_secs(10),
                )
                .unwrap(),
            },
            &TokioClock,
        )
        .await
        .unwrap_err();
    assert!(matches!(denied, super::AdvanceError::Store(ref failure)
        if matches!(failure.kind(), StoreErrorKind::Denied { .. })));
    for name in [admitted_target, other_target] {
        assert!(reopened.store().ref_get(name).await.unwrap().is_none());
    }
    assert_eq!(
        reopened.store().ref_get(reference).await.unwrap(),
        Some(outcome.record)
    );

    let stale_target = "refs/tags/_/stale-source";
    let publication = reopened
        .guard()
        .admit_tag(reference, stale_target, &restricted, "sdk")
        .await
        .unwrap();
    let changed_source = reopened
        .set_policy(
            reference,
            Some(terrane_core::refs::RefPolicy {
                multi_writer: Some(false),
                ..Default::default()
            }),
            &token(),
            "sdk",
        )
        .await
        .unwrap();
    let stale = reopened
        .guard()
        .publish_tag_native(
            super::NativeTagRequest {
                source: reference.into(),
                target: stale_target.into(),
                token: restricted,
                surface: "sdk".into(),
                publication,
                started: crate::store::Clock::monotonic(&TokioClock),
                timing: super::CommitTiming::new(
                    std::time::Duration::from_secs(30),
                    std::time::Duration::from_secs(60),
                    std::time::Duration::from_secs(10),
                )
                .unwrap(),
            },
            &TokioClock,
        )
        .await
        .unwrap_err();
    assert!(matches!(stale, super::AdvanceError::Store(ref failure)
        if matches!(failure.kind(), StoreErrorKind::Denied { .. })));
    assert!(
        reopened
            .store()
            .ref_get(stale_target)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        reopened.store().ref_get(reference).await.unwrap(),
        Some(changed_source)
    );

    TokioLocalFs
        .set_permissions(&authored_path, std::fs::Permissions::from_mode(0o644))
        .await
        .unwrap();
    assert!(reopened.guard().verified_tree(authored).await.is_err());
    TokioLocalFs
        .set_permissions(&authored_path, std::fs::Permissions::from_mode(0o600))
        .await
        .unwrap();

    // A cached context cannot substitute for protected bytes read by the
    // captured actual backend, even after the initial check succeeded.
    TokioLocalFs
        .set_permissions(&association_path, std::fs::Permissions::from_mode(0o644))
        .await
        .unwrap();
    assert!(
        reopened
            .guard()
            .check_original_commit(&checked, association())
            .await
            .is_err()
    );
    TokioLocalFs
        .set_permissions(&association_path, std::fs::Permissions::from_mode(0o600))
        .await
        .unwrap();

    let unrelated = fixture().await;
    {
        let pair = HeldBuckets::acquire(unrelated.store(), reopened.store())
            .await
            .unwrap();
        let destination = pair.destination();
        let proof = destination.identity_proof();
        let original = reopened.guard().original_commit(&authored).unwrap();
        let checked = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            reopened.guard().check_original_commit_held(
                original.baseline(),
                AssociationView {
                    commit: &authored,
                    id: &id,
                    reference,
                    epoch: writer.epoch(),
                },
                &proof,
            ),
        )
        .await
        .expect("held validation must not reacquire the backend lock")
        .unwrap();
        assert_eq!(checked, original);

        let held_guard = reopened
            .guard()
            .held_guard(pair.destination(), TokioClock)
            .unwrap();
        let observation = crate::guard::HistoryObservation::held(&proof);
        let authorization = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            held_guard.authorize_observed(
                reference,
                &token(),
                terrane_core::auth::Verb::Commit,
                &[],
                "sdk",
                observation,
            ),
        )
        .await
        .expect("current policy and ordinary history must use the held backend")
        .unwrap();
        assert_eq!(authorization.record().unwrap().commit, authored);
        let history = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            held_guard.verified_history_observed(authored, observation),
        )
        .await
        .expect("historical associations must not reacquire the backend")
        .unwrap();
        assert_eq!(history.introducing_commit(&location).unwrap(), authored);

        let source = pair.source();
        let readonly = source.identity_proof();
        let denied = reopened
            .guard()
            .check_original_commit_held(
                original.baseline(),
                AssociationView {
                    commit: &authored,
                    id: &id,
                    reference,
                    epoch: writer.epoch(),
                },
                &readonly,
            )
            .await
            .unwrap_err();
        assert!(matches!(denied.kind(), StoreErrorKind::ReadOnly));
    }
    {
        let pair = HeldBuckets::acquire(reopened.store(), unrelated.store())
            .await
            .unwrap();
        let destination = pair.destination();
        let other = destination.identity_proof();
        let original = reopened.guard().original_commit(&authored).unwrap();
        let denied = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            reopened.guard().check_original_commit_held(
                original.baseline(),
                AssociationView {
                    commit: &authored,
                    id: &id,
                    reference,
                    epoch: writer.epoch(),
                },
                &other,
            ),
        )
        .await
        .expect("a mismatched proof must reject without acquiring another backend")
        .unwrap_err();
        assert!(matches!(denied.kind(), StoreErrorKind::Invalid(_)));
    }

    assert!(
        unrelated
            .guard()
            .install_original_bootstrap(baseline.clone())
            .await
            .is_err()
    );
    assert!(
        unrelated
            .guard()
            .install_original_commit(context.clone())
            .await
            .is_err()
    );
    assert!(
        reopened
            .guard()
            .bind_original_commit(
                &baseline,
                AssociationView {
                    epoch: 2,
                    ..association()
                }
            )
            .await
            .is_err()
    );

    let fault_fs = FaultFs::default();
    let faulted = configured_with_fs(
        FileBucket::open(
            config(root.clone()).await,
            fault_fs.clone(),
            TokioClock,
            Validator,
        )
        .await
        .unwrap(),
        fault_fs.clone(),
    );
    fault_fs.change_control_after_registration(control.clone());
    assert!(
        faulted
            .guard()
            .bind_original_authority(&namespace, &control, view())
            .await
            .is_err()
    );
    assert!(fault_fs.control_change_consumed());
    assert_eq!(
        TokioLocalFs
            .symlink_metadata(&control)
            .await
            .unwrap()
            .mode()
            & 0o777,
        0o755
    );
    TokioLocalFs
        .set_permissions(&control, std::fs::Permissions::from_mode(0o700))
        .await
        .unwrap();

    let wrong_id = [54; 32];
    let mut wrong = view();
    wrong.id = &wrong_id;
    assert!(
        reopened
            .guard()
            .bind_original_authority(&namespace, &control, wrong)
            .await
            .is_err()
    );
    let mut wrong = view();
    wrong.root_identity.1 += 1;
    assert!(
        reopened
            .guard()
            .bind_original_authority(&namespace, &control, wrong)
            .await
            .is_err()
    );

    TokioLocalFs
        .set_permissions(
            &control.join("registration.cbor"),
            std::fs::Permissions::from_mode(0o644),
        )
        .await
        .unwrap();
    assert!(
        reopened
            .guard()
            .bind_original_authority(&namespace, &control, view())
            .await
            .is_err()
    );
    TokioLocalFs
        .set_permissions(
            &control.join("registration.cbor"),
            std::fs::Permissions::from_mode(0o600),
        )
        .await
        .unwrap();
    TokioLocalFs
        .remove_file(&control.join("registration.cbor"))
        .await
        .unwrap();
    assert!(
        reopened
            .guard()
            .bind_original_authority(&namespace, &control, view())
            .await
            .is_err()
    );
    let cap_path = root.join("CAPABILITIES");
    let mut capabilities =
        BucketCapabilities::decode(&TokioLocalFs.read(&cap_path).await.unwrap()).unwrap();
    capabilities.layout_version = 1;
    capabilities.ref_names = None;
    capabilities.publication_protocol = None;
    let replacement = root.join("legacy-capability.fixture");
    TokioLocalFs
        .write_new(&replacement, &capabilities.encode().unwrap())
        .await
        .unwrap();
    TokioLocalFs.sync_file(&replacement).await.unwrap();
    TokioLocalFs.rename(&replacement, &cap_path).await.unwrap();
    TokioLocalFs.sync_directory(&root).await.unwrap();
    let legacy_fs = FaultFs::default();
    let legacy = configured_with_fs(
        FileBucket::open_legacy_read_only(
            config(root.clone()).await,
            legacy_fs.clone(),
            TokioClock,
            Validator,
        )
        .await
        .unwrap(),
        legacy_fs.clone(),
    );
    let denied = legacy
        .guard()
        .bind_original_authority(&namespace, &control, view())
        .await
        .unwrap_err();
    assert!(matches!(denied.kind(), StoreErrorKind::ReadOnly));
    let resolver_denied = legacy
        .guard()
        .install_original_verifier(&authority)
        .await
        .unwrap_err();
    assert!(matches!(resolver_denied.kind(), StoreErrorKind::ReadOnly));
    assert_eq!(legacy_fs.lock_calls(), 0);
    assert!(
        TokioLocalFs
            .symlink_metadata(&control.join("registration.cbor"))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn unretained_coordinator_authoring_has_no_immutable_effects() {
    let coordinator = fixture().await;
    let reference = "refs/heads/_/main";
    let mut session = coordinator.begin(reference, &token(), "sdk").await.unwrap();
    let request = request_file(Vec::new(), b"unretained plaintext");
    let identities = request
        .uploads
        .iter()
        .map(|upload| match upload {
            crate::guard::StagedUpload::Meta { kind, bytes } => terrane_core::identity::TERRANE_V1
                .calculate(*kind, bytes)
                .unwrap(),
            crate::guard::StagedUpload::Chunk { identity, .. } => identity.clone(),
        })
        .collect::<Vec<_>>();

    let rejected = coordinator
        .advance(&mut session, request)
        .await
        .unwrap_err();

    assert!(matches!(rejected, super::AdvanceError::Store(_)));
    assert!(
        coordinator
            .store()
            .ref_get(reference)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        coordinator
            .store()
            .ref_log_read(reference, 1)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        coordinator.store().has(&identities).await.unwrap(),
        vec![false; identities.len()]
    );
    assert!(session.record().is_none());
}
