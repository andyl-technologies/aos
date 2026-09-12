//! Coordinator and protocol coverage for missing-initial workspace-pin repair.

#![allow(clippy::unwrap_used)]

use super::*;

use std::rc::Rc;

#[test]
fn missing_initial_repair_admits_ordinal_one_then_existing_attempt_ordinal_two_and_reopens() {
    let directory = TempDir::new().unwrap();
    let fixture = Fixture::new();
    let (mut broker, creation) = committed_workspace_without_pin(&directory, &fixture);
    let workspace_handle = creation.storage_handle().unwrap();
    let repair_manifest = assignment_manifest_at(&sandbox_spec(72), 6);
    let request = repair_request(80, 81, workspace_handle, 6, repair_manifest.digest());
    let artifacts = fixture.repair_artifacts(&request);
    let contract = ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap();
    let host_scope = WorkspacePinHostScopeV1::new([50; 16], 51, 52).unwrap();

    let dispatch = broker
        .plan_workspace_pin_repair_admission_observation(
            &request,
            &artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            peer_policy(),
            &clock(),
            &contract,
            host_scope,
        )
        .unwrap();
    assert!(matches!(
        dispatch.predecessor,
        WorkspacePinRepairPredecessorV1::MissingInitial {
            creation: ref exact,
            ..
        }
            if exact.as_ref() == &creation
    ));
    let result = crate::workspace_repair_admission::WorkspacePinRepairAdmissionResultV1::new(
        dispatch.probe().digest(),
        crate::pin_worker::WorkspacePinWorkerResultV1::new(
            dispatch.probe().latest_attempt_id(),
            crate::workspace_pin::WorkspaceDatasetObservationV1::Exact {
                name: "tank/aos/project/work".to_owned(),
                guid: 11,
            },
            crate::workspace_pin::WorkspacePinObservationV1::Absent,
            ObjectDigest::from_bytes([91; 32]),
        ),
    );
    let validated =
        crate::workspace_repair_admission::ValidatedWorkspacePinRepairAdmissionObservationV1::from_result(
            dispatch.probe(),
            result,
        )
        .unwrap();
    let fresh = FreshWorkspacePinRepairObservationV1::new_for_test(validated);
    let AuthorizedWorkspacePinRepairAttemptV1::Dispatch(admitted) = broker
        .begin_workspace_pin_repair(
            dispatch,
            fresh,
            &request,
            &artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            peer_policy(),
            &contract,
            &mut || Ok(clock()),
        )
        .unwrap()
    else {
        panic!("missing-initial repair did not dispatch")
    };
    assert_eq!(admitted.attempt().attempt_ordinal(), 1);
    assert_eq!(
        admitted.attempt().creation_operation_id(),
        creation.operation_id()
    );
    let intent = broker
        .transactions
        .workspace_pin_repair_intent([81; 16])
        .unwrap()
        .unwrap();
    assert!(matches!(
        intent.predecessor(),
        crate::workspace_repair::WorkspacePinRepairIntentPredecessorV1::MissingInitial { .. }
    ));
    let first_attempt = admitted.attempt().clone();

    let successor_manifest = assignment_manifest_at(&sandbox_spec(72), 7);
    let successor_request =
        repair_request(82, 83, workspace_handle, 7, successor_manifest.digest());
    let successor_artifacts = fixture.repair_artifacts(&successor_request);
    let successor_dispatch = broker
        .plan_workspace_pin_repair_admission_observation(
            &successor_request,
            &successor_artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            peer_policy(),
            &clock(),
            &contract,
            host_scope,
        )
        .unwrap();
    assert!(matches!(
        successor_dispatch.predecessor,
        WorkspacePinRepairPredecessorV1::ExistingAttempt(ref attempt)
            if attempt.as_ref() == &first_attempt
    ));
    let successor_result =
        crate::workspace_repair_admission::WorkspacePinRepairAdmissionResultV1::new(
            successor_dispatch.probe().digest(),
            crate::pin_worker::WorkspacePinWorkerResultV1::new(
                successor_dispatch.probe().latest_attempt_id(),
                crate::workspace_pin::WorkspaceDatasetObservationV1::Exact {
                    name: "tank/aos/project/work".to_owned(),
                    guid: 11,
                },
                crate::workspace_pin::WorkspacePinObservationV1::Absent,
                ObjectDigest::from_bytes([92; 32]),
            ),
        );
    let successor_validated =
        crate::workspace_repair_admission::ValidatedWorkspacePinRepairAdmissionObservationV1::from_result(
            successor_dispatch.probe(),
            successor_result,
        )
        .unwrap();
    let AuthorizedWorkspacePinRepairAttemptV1::Dispatch(successor) = broker
        .begin_workspace_pin_repair(
            successor_dispatch,
            FreshWorkspacePinRepairObservationV1::new_for_test(successor_validated),
            &successor_request,
            &successor_artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            peer_policy(),
            &contract,
            &mut || Ok(clock()),
        )
        .unwrap()
    else {
        panic!("successor repair did not dispatch")
    };
    assert_eq!(successor.attempt().attempt_ordinal(), 2);
    drop(broker);

    let reopened = coordinator(&directory, &fixture);
    reopened.authenticate_workspace_pin_attempts().unwrap();
    let attempts = reopened.transactions.workspace_pin_attempts().unwrap();
    assert_eq!(attempts.len(), 2);
    assert_eq!(
        attempts
            .iter()
            .map(WorkspacePinAttemptV1::attempt_ordinal)
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from([1, 2])
    );
    assert!(
        reopened
            .workspace_pin_repair_replay(
                &successor_request,
                &successor_artifacts,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap()
    );
    assert_eq!(
        reopened.transactions.workspace_pin_attempts().unwrap(),
        attempts
    );
}

#[test]
fn existing_attempt_repair_keeps_ordinal_two_and_legacy_v1_reopens() {
    let directory = TempDir::new().unwrap();
    let fixture = Fixture::new();
    let (mut broker, initial, creation) = workspace_pin_ensure_dispatch(&directory, &fixture);
    let workspace_handle = creation.storage_handle().unwrap();
    let repair_manifest = assignment_manifest_at(&sandbox_spec(72), 6);
    let request = repair_request(80, 81, workspace_handle, 6, repair_manifest.digest());
    let artifacts = fixture.repair_artifacts(&request);
    let contract = ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap();
    let host_scope = WorkspacePinHostScopeV1::new([50; 16], 51, 52).unwrap();
    let dispatch = broker
        .plan_workspace_pin_repair_admission_observation(
            &request,
            &artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            peer_policy(),
            &clock(),
            &contract,
            host_scope,
        )
        .unwrap();
    assert!(matches!(
        dispatch.predecessor,
        WorkspacePinRepairPredecessorV1::ExistingAttempt(ref attempt)
            if attempt.as_ref() == initial.attempt()
    ));
    let result = crate::workspace_repair_admission::WorkspacePinRepairAdmissionResultV1::new(
        dispatch.probe().digest(),
        crate::pin_worker::WorkspacePinWorkerResultV1::new(
            dispatch.probe().latest_attempt_id(),
            crate::workspace_pin::WorkspaceDatasetObservationV1::Exact {
                name: "tank/aos/project/work".to_owned(),
                guid: 11,
            },
            crate::workspace_pin::WorkspacePinObservationV1::Absent,
            ObjectDigest::from_bytes([91; 32]),
        ),
    );
    let validated =
        crate::workspace_repair_admission::ValidatedWorkspacePinRepairAdmissionObservationV1::from_result(
            dispatch.probe(),
            result,
        )
        .unwrap();
    let AuthorizedWorkspacePinRepairAttemptV1::Dispatch(admitted) = broker
        .begin_workspace_pin_repair(
            dispatch,
            FreshWorkspacePinRepairObservationV1::new_for_test(validated),
            &request,
            &artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            peer_policy(),
            &contract,
            &mut || Ok(clock()),
        )
        .unwrap()
    else {
        panic!("existing-attempt repair did not dispatch")
    };
    assert_eq!(admitted.attempt().attempt_ordinal(), 2);

    let intent = broker
        .transactions
        .workspace_pin_repair_intent([81; 16])
        .unwrap()
        .unwrap();
    assert!(matches!(
        intent.predecessor(),
        crate::workspace_repair::WorkspacePinRepairIntentPredecessorV1::ExistingAttempt {
            attempt_id,
            ..
        } if attempt_id == initial.attempt().attempt_id()
    ));
    let legacy =
        crate::workspace_repair::encode_legacy_intent_for_test(&intent, [51; 16], &[52; 32])
            .unwrap();
    broker
        .transactions
        .put_authority_record_with_transaction_for_test(
            [98; 16],
            RecordNamespace::StorageWorkspacePinRepairIntent,
            &[81; 16],
            legacy,
        );
    drop(broker);

    let reopened = coordinator(&directory, &fixture);
    reopened.authenticate_workspace_pin_attempts().unwrap();
    assert_eq!(
        reopened
            .transactions
            .workspace_pin_repair_intent([81; 16])
            .unwrap()
            .unwrap(),
        intent
    );
}

#[test]
fn missing_initial_repair_then_remove_attempt_reopens_with_contiguous_history() {
    let directory = TempDir::new().unwrap();
    let fixture = Fixture::new();
    let (mut broker, creation) = committed_workspace_without_pin(&directory, &fixture);
    let workspace_handle = creation.storage_handle().unwrap();
    let repair_manifest = assignment_manifest_at(&sandbox_spec(72), 6);
    let repair = repair_request(80, 81, workspace_handle, 6, repair_manifest.digest());
    let repair_artifacts = fixture.repair_artifacts(&repair);
    let contract = ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap();
    let host_scope = WorkspacePinHostScopeV1::new([50; 16], 51, 52).unwrap();
    let dispatch = broker
        .plan_workspace_pin_repair_admission_observation(
            &repair,
            &repair_artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            peer_policy(),
            &clock(),
            &contract,
            host_scope,
        )
        .unwrap();
    let observation = crate::workspace_repair_admission::WorkspacePinRepairAdmissionResultV1::new(
        dispatch.probe().digest(),
        crate::pin_worker::WorkspacePinWorkerResultV1::new(
            dispatch.probe().latest_attempt_id(),
            crate::workspace_pin::WorkspaceDatasetObservationV1::Exact {
                name: "tank/aos/project/work".to_owned(),
                guid: 11,
            },
            crate::workspace_pin::WorkspacePinObservationV1::Absent,
            ObjectDigest::from_bytes([91; 32]),
        ),
    );
    let validated =
        crate::workspace_repair_admission::ValidatedWorkspacePinRepairAdmissionObservationV1::from_result(
            dispatch.probe(),
            observation,
        )
        .unwrap();
    let AuthorizedWorkspacePinRepairAttemptV1::Dispatch(repair_dispatch) = broker
        .begin_workspace_pin_repair(
            dispatch,
            FreshWorkspacePinRepairObservationV1::new_for_test(validated),
            &repair,
            &repair_artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            peer_policy(),
            &contract,
            &mut || Ok(clock()),
        )
        .unwrap()
    else {
        panic!("missing-initial repair did not dispatch")
    };
    let proof = workspace_pin_proof(workspace_handle, "tank/aos/project/work", 11);
    broker
        .complete_workspace_pin_repair_execution(
            repair_dispatch.attempt(),
            &crate::pin_worker::WorkspacePinWorkerResultV1::new(
                repair_dispatch.attempt().attempt_id(),
                crate::workspace_pin::WorkspaceDatasetObservationV1::Exact {
                    name: "tank/aos/project/work".to_owned(),
                    guid: 11,
                },
                crate::workspace_pin::WorkspacePinObservationV1::Present(proof.clone()),
                ObjectDigest::from_bytes([93; 32]),
            ),
        )
        .unwrap();

    let destroy_manifest = assignment_manifest_at(&sandbox_spec(72), 7);
    let destroy = destroy_request_at_generation(82, workspace_handle, 7, destroy_manifest.digest());
    let destroy_catalog = destroy_catalog(workspace_handle, 11);
    let expected_head = broker.transactions.catalog_head_binding().unwrap();
    let destroy_artifacts =
        fixture.artifacts_at_head(&destroy, &destroy_catalog, expected_head, 300);
    prepare_for_apply(
        &mut broker,
        &destroy,
        &destroy_artifacts,
        &destroy_catalog,
        &clock(),
    );
    let StorageAdmissionOutcome::Prepared { .. } = broker
        .admit_apply_intent(
            &destroy,
            &destroy_artifacts,
            &destroy_catalog,
            ProtocolVersion::new(1, 0),
            peer(),
            peer_policy(),
            &clock(),
        )
        .unwrap()
    else {
        panic!("destroy was not prepared")
    };
    let mut helper = StorageMutationHelper::new(
        contract,
        CountingBackend {
            executions: Rc::new(Cell::new(0)),
        },
    );
    let prepared = helper.preobserve(&broker.transactions, [82; 16]).unwrap();
    let AuthorizedWorkspaceRemoveAttemptV1::Dispatch(remove) = broker
        .begin_workspace_pin_remove_and_destroy(prepared, host_scope, proof, &mut || Ok(clock()))
        .unwrap()
    else {
        panic!("remove attempt did not dispatch")
    };
    assert_eq!(remove.attempt().attempt_ordinal(), 2);
    drop(broker);

    let reopened = coordinator(&directory, &fixture);
    reopened.authenticate_workspace_pin_attempts().unwrap();
    let attempts = reopened.transactions.workspace_pin_attempts().unwrap();
    assert_eq!(attempts.len(), 2);
    assert_eq!(
        attempts
            .iter()
            .map(WorkspacePinAttemptV1::attempt_ordinal)
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from([1, 2])
    );
    assert!(
        attempts
            .iter()
            .any(|attempt| attempt.action() == WorkspacePinActionV1::RemoveAndDestroy)
    );
}

#[test]
fn missing_initial_repair_ignores_committed_same_handle_quota_history() {
    let directory = TempDir::new().unwrap();
    let fixture = Fixture::new();
    let (mut broker, creation) = committed_workspace_without_pin(&directory, &fixture);
    let workspace_handle = creation.storage_handle().unwrap();
    let quota = catalog(8, 11);
    let BeginStorageTransaction::Prepared { mutation_digest } = broker
        .transactions
        .begin([90; 16], ObjectDigest::from_bytes([91; 32]), &quota)
        .unwrap()
    else {
        panic!("same-handle quota history was not prepared")
    };
    broker
        .transactions
        .mark_mutation_ambiguous([90; 16], mutation_digest)
        .unwrap();
    broker
        .transactions
        .commit_observed(
            [90; 16],
            mutation_digest,
            &quota,
            &quota.plan().postcondition(),
            Some(11),
            ObjectDigest::from_bytes([92; 32]),
        )
        .unwrap();
    assert_eq!(
        broker
            .transactions
            .workspace_creation_for_pin_repair(workspace_handle)
            .unwrap(),
        creation
    );

    let repair_manifest = assignment_manifest_at(&sandbox_spec(72), 6);
    let repair = repair_request(80, 81, workspace_handle, 6, repair_manifest.digest());
    let repair_artifacts = fixture.repair_artifacts(&repair);
    let contract = ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap();
    let dispatch = broker
        .plan_workspace_pin_repair_admission_observation(
            &repair,
            &repair_artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            peer_policy(),
            &clock(),
            &contract,
            WorkspacePinHostScopeV1::new([50; 16], 51, 52).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        dispatch.predecessor,
        WorkspacePinRepairPredecessorV1::MissingInitial { .. }
    ));
    assert_eq!(dispatch.request.catalog_for_test(), &create_catalog(9));
}

#[test]
fn missing_initial_clone_repair_binds_source_policy_and_ordinal_one() {
    let directory = TempDir::new().unwrap();
    let fixture = Fixture::new();
    let (mut broker, creation) = committed_clone_without_pin(&directory, &fixture);
    let workspace_handle = creation.storage_handle().unwrap();
    let repair_manifest = assignment_manifest_at(&sandbox_spec(72), 6);
    let request = repair_request(80, 81, workspace_handle, 6, repair_manifest.digest());
    let artifacts = fixture.repair_artifacts(&request);
    let contract = ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap();
    let host_scope = WorkspacePinHostScopeV1::new([50; 16], 51, 52).unwrap();
    let dispatch = broker
        .plan_workspace_pin_repair_admission_observation(
            &request,
            &artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            peer_policy(),
            &clock(),
            &contract,
            host_scope,
        )
        .unwrap();
    assert_eq!(dispatch.request.catalog_for_test(), &clone_catalog(9));
    assert_ne!(
        dispatch.probe().root_policy(),
        WorkspaceRootPolicyV1::create_initialize()
    );
    let expected_root_policy = dispatch.probe().root_policy();
    let CatalogPlanV1::Clone {
        source,
        origin_hold,
        ..
    } = dispatch.request.catalog_for_test().plan()
    else {
        panic!("clone repair did not retain its exact source catalog")
    };
    assert_eq!(source.guid(), 12);
    assert_eq!(source.version_handle(), [32; 32]);
    assert_eq!(origin_hold.snapshot_guid(), source.guid());
    assert_eq!(origin_hold.hold_id().as_bytes(), [33; 16]);
    assert_eq!(expected_root_policy.source_snapshot_guid(), Some(12));
    assert!(expected_root_policy.source_metadata_commitment().is_some());

    let mut substituted_source = broker
        .plan_workspace_pin_repair_admission_observation(
            &request,
            &artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            peer_policy(),
            &clock(),
            &contract,
            host_scope,
        )
        .unwrap();
    substituted_source
        .request
        .replace_catalog_for_test(clone_catalog_with_source_version(9, [34; 32]));
    assert!(
        crate::workspace_repair_admission::authenticate_request(
            &StorageStateKey::new([51; 16], [52; 32]).unwrap(),
            &contract,
            substituted_source.request,
            host_scope,
        )
        .is_err()
    );

    let result = crate::workspace_repair_admission::WorkspacePinRepairAdmissionResultV1::new(
        dispatch.probe().digest(),
        crate::pin_worker::WorkspacePinWorkerResultV1::new(
            dispatch.probe().latest_attempt_id(),
            crate::workspace_pin::WorkspaceDatasetObservationV1::Exact {
                name: "tank/aos/project/clone".to_owned(),
                guid: 13,
            },
            crate::workspace_pin::WorkspacePinObservationV1::Absent,
            ObjectDigest::from_bytes([91; 32]),
        ),
    );
    let validated =
        crate::workspace_repair_admission::ValidatedWorkspacePinRepairAdmissionObservationV1::from_result(
            dispatch.probe(),
            result,
        )
        .unwrap();
    let fresh = FreshWorkspacePinRepairObservationV1::new_for_test(validated);
    let AuthorizedWorkspacePinRepairAttemptV1::Dispatch(admitted) = broker
        .begin_workspace_pin_repair(
            dispatch,
            fresh,
            &request,
            &artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            peer_policy(),
            &contract,
            &mut || Ok(clock()),
        )
        .unwrap()
    else {
        panic!("missing-initial clone repair did not dispatch")
    };
    assert_eq!(admitted.attempt().attempt_ordinal(), 1);
    assert_eq!(admitted.attempt().root_policy(), expected_root_policy);

    let encoded_worker = admitted.worker_request_bytes().unwrap();
    let authenticated_worker = crate::workspace_repair_worker::authenticate_request(
        &fixture.authority(),
        &StorageStateKey::new([51; 16], [52; 32]).unwrap(),
        &contract,
        crate::workspace_repair_worker::decode_request(&encoded_worker).unwrap(),
    )
    .unwrap();
    assert_eq!(authenticated_worker.attempt(), admitted.attempt());
    assert_eq!(authenticated_worker.catalog(), &clone_catalog(9));
    let CatalogPlanV1::Clone { source, .. } = authenticated_worker.catalog().plan() else {
        panic!("authenticated worker lost its Clone source")
    };
    assert_eq!(source.version_handle(), [32; 32]);

    let mut substituted_worker =
        crate::workspace_repair_worker::decode_request(&encoded_worker).unwrap();
    substituted_worker.replace_catalog_for_test(clone_catalog_with_source_version(9, [34; 32]));
    let substituted_worker =
        crate::workspace_repair_worker::encode_request(&substituted_worker).unwrap();
    assert!(
        crate::workspace_repair_worker::authenticate_request(
            &fixture.authority(),
            &StorageStateKey::new([51; 16], [52; 32]).unwrap(),
            &contract,
            crate::workspace_repair_worker::decode_request(&substituted_worker).unwrap(),
        )
        .is_err()
    );
}

#[test]
fn missing_initial_repair_requires_exact_absence_before_journal_mutation() {
    let directory = TempDir::new().unwrap();
    let fixture = Fixture::new();
    let (broker, creation) = committed_workspace_without_pin(&directory, &fixture);
    let workspace_handle = creation.storage_handle().unwrap();
    let repair_manifest = assignment_manifest_at(&sandbox_spec(72), 6);
    let request = repair_request(80, 81, workspace_handle, 6, repair_manifest.digest());
    let artifacts = fixture.repair_artifacts(&request);
    let contract = ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap();
    let host_scope = WorkspacePinHostScopeV1::new([50; 16], 51, 52).unwrap();
    let dispatch = broker
        .plan_workspace_pin_repair_admission_observation(
            &request,
            &artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            peer_policy(),
            &clock(),
            &contract,
            host_scope,
        )
        .unwrap();
    let sequence = broker.transactions.journal_sequence_for_test();
    let proof = workspace_pin_proof(workspace_handle, "tank/aos/project/work", 11);
    for (dataset, pin) in [
        (
            crate::workspace_pin::WorkspaceDatasetObservationV1::Exact {
                name: "tank/aos/project/work".to_owned(),
                guid: 11,
            },
            crate::workspace_pin::WorkspacePinObservationV1::Present(proof),
        ),
        (
            crate::workspace_pin::WorkspaceDatasetObservationV1::Exact {
                name: "tank/aos/project/work".to_owned(),
                guid: 11,
            },
            crate::workspace_pin::WorkspacePinObservationV1::Mismatch,
        ),
        (
            crate::workspace_pin::WorkspaceDatasetObservationV1::Mismatch,
            crate::workspace_pin::WorkspacePinObservationV1::Absent,
        ),
    ] {
        let result = crate::workspace_repair_admission::WorkspacePinRepairAdmissionResultV1::new(
            dispatch.probe().digest(),
            crate::pin_worker::WorkspacePinWorkerResultV1::new(
                dispatch.probe().latest_attempt_id(),
                dataset,
                pin,
                ObjectDigest::from_bytes([91; 32]),
            ),
        );
        assert!(crate::workspace_repair_admission::ValidatedWorkspacePinRepairAdmissionObservationV1::from_result(
            dispatch.probe(),
            result,
        )
        .is_err());
    }
    assert_eq!(broker.transactions.journal_sequence_for_test(), sequence);
    assert!(
        broker
            .transactions
            .workspace_pin_attempts()
            .unwrap()
            .is_empty()
    );
    assert!(
        broker
            .transactions
            .workspace_pin_repair_intent([81; 16])
            .unwrap()
            .is_none()
    );
}

#[test]
fn uncertain_missing_initial_admission_poisons_until_exact_reopen() {
    let directory = TempDir::new().unwrap();
    let fixture = Fixture::new();
    let (mut broker, creation) = committed_workspace_without_pin(&directory, &fixture);
    let workspace_handle = creation.storage_handle().unwrap();
    let repair_manifest = assignment_manifest_at(&sandbox_spec(72), 6);
    let request = repair_request(80, 81, workspace_handle, 6, repair_manifest.digest());
    let artifacts = fixture.repair_artifacts(&request);
    let contract = ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap();
    let host_scope = WorkspacePinHostScopeV1::new([50; 16], 51, 52).unwrap();
    let dispatch = broker
        .plan_workspace_pin_repair_admission_observation(
            &request,
            &artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            peer_policy(),
            &clock(),
            &contract,
            host_scope,
        )
        .unwrap();
    let result = crate::workspace_repair_admission::WorkspacePinRepairAdmissionResultV1::new(
        dispatch.probe().digest(),
        crate::pin_worker::WorkspacePinWorkerResultV1::new(
            dispatch.probe().latest_attempt_id(),
            crate::workspace_pin::WorkspaceDatasetObservationV1::Exact {
                name: "tank/aos/project/work".to_owned(),
                guid: 11,
            },
            crate::workspace_pin::WorkspacePinObservationV1::Absent,
            ObjectDigest::from_bytes([91; 32]),
        ),
    );
    let validated =
        crate::workspace_repair_admission::ValidatedWorkspacePinRepairAdmissionObservationV1::from_result(
            dispatch.probe(),
            result,
        )
        .unwrap();
    broker.fail_after_next_journal_commit_for_test();
    assert!(
        broker
            .begin_workspace_pin_repair(
                dispatch,
                FreshWorkspacePinRepairObservationV1::new_for_test(validated),
                &request,
                &artifacts,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &contract,
                &mut || Ok(clock()),
            )
            .is_err()
    );
    assert!(broker.transactions.workspace_pin_attempts().is_err());
    drop(broker);

    let reopened = coordinator(&directory, &fixture);
    reopened.authenticate_workspace_pin_attempts().unwrap();
    let attempts = reopened.transactions.workspace_pin_attempts().unwrap();
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].attempt_ordinal(), 1);
    assert!(matches!(
        reopened
            .transactions
            .workspace_pin_repair_intent([81; 16])
            .unwrap()
            .unwrap()
            .predecessor(),
        crate::workspace_repair::WorkspacePinRepairIntentPredecessorV1::MissingInitial { .. }
    ));
}

#[test]
fn missing_initial_repair_rejects_substituted_physical_head_before_clock_or_mutation() {
    let directory = TempDir::new().unwrap();
    let fixture = Fixture::new();
    let (mut broker, creation) = committed_workspace_without_pin(&directory, &fixture);
    let workspace_handle = creation.storage_handle().unwrap();
    let repair_manifest = assignment_manifest_at(&sandbox_spec(72), 6);
    let request = repair_request(80, 81, workspace_handle, 6, repair_manifest.digest());
    let artifacts = fixture.repair_artifacts(&request);
    let contract = ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap();
    let host_scope = WorkspacePinHostScopeV1::new([50; 16], 51, 52).unwrap();
    let mut dispatch = broker
        .plan_workspace_pin_repair_admission_observation(
            &request,
            &artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            peer_policy(),
            &clock(),
            &contract,
            host_scope,
        )
        .unwrap();
    let result = crate::workspace_repair_admission::WorkspacePinRepairAdmissionResultV1::new(
        dispatch.probe().digest(),
        crate::pin_worker::WorkspacePinWorkerResultV1::new(
            dispatch.probe().latest_attempt_id(),
            crate::workspace_pin::WorkspaceDatasetObservationV1::Exact {
                name: "tank/aos/project/work".to_owned(),
                guid: 11,
            },
            crate::workspace_pin::WorkspacePinObservationV1::Absent,
            ObjectDigest::from_bytes([91; 32]),
        ),
    );
    let validated =
        crate::workspace_repair_admission::ValidatedWorkspacePinRepairAdmissionObservationV1::from_result(
            dispatch.probe(),
            result,
        )
        .unwrap();
    dispatch.request.replace_physical_catalog_head_for_test(
        crate::CatalogBindingV1::from_publisher(99, ObjectDigest::from_bytes([99; 32])).unwrap(),
    );
    let sequence = broker.transactions.journal_sequence_for_test();
    let clock_samples = std::cell::Cell::new(0_u8);
    assert!(
        broker
            .begin_workspace_pin_repair(
                dispatch,
                FreshWorkspacePinRepairObservationV1::new_for_test(validated),
                &request,
                &artifacts,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &contract,
                &mut || {
                    clock_samples.set(clock_samples.get() + 1);
                    Ok(clock())
                },
            )
            .is_err()
    );
    assert_eq!(clock_samples.get(), 0);
    assert_eq!(broker.transactions.journal_sequence_for_test(), sequence);
    assert!(
        broker
            .transactions
            .workspace_pin_attempts()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn missing_initial_observer_rejects_tampered_publication_and_creation_catalog() {
    let directory = TempDir::new().unwrap();
    let fixture = Fixture::new();
    let (broker, creation) = committed_workspace_without_pin(&directory, &fixture);
    let workspace_handle = creation.storage_handle().unwrap();
    let repair_manifest = assignment_manifest_at(&sandbox_spec(72), 6);
    let request = repair_request(80, 81, workspace_handle, 6, repair_manifest.digest());
    let artifacts = fixture.repair_artifacts(&request);
    let contract = ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap();
    let host_scope = WorkspacePinHostScopeV1::new([50; 16], 51, 52).unwrap();
    let state_key = StorageStateKey::new([51; 16], [52; 32]).unwrap();

    let mut tampered_publication = broker
        .plan_workspace_pin_repair_admission_observation(
            &request,
            &artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            peer_policy(),
            &clock(),
            &contract,
            host_scope,
        )
        .unwrap();
    tampered_publication
        .request
        .corrupt_publication_record_for_test();
    assert!(
        crate::workspace_repair_admission::authenticate_request(
            &state_key,
            &contract,
            tampered_publication.request,
            host_scope,
        )
        .is_err()
    );

    let mut substituted_catalog = broker
        .plan_workspace_pin_repair_admission_observation(
            &request,
            &artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            peer_policy(),
            &clock(),
            &contract,
            host_scope,
        )
        .unwrap();
    substituted_catalog
        .request
        .replace_catalog_for_test(clone_catalog(9));
    assert!(
        crate::workspace_repair_admission::authenticate_request(
            &state_key,
            &contract,
            substituted_catalog.request,
            host_scope,
        )
        .is_err()
    );
    assert!(
        broker
            .transactions
            .workspace_pin_attempts()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn missing_initial_repair_rejects_tampered_committed_creation_record() {
    let directory = TempDir::new().unwrap();
    let fixture = Fixture::new();
    let (mut broker, creation) = committed_workspace_without_pin(&directory, &fixture);
    let workspace_handle = creation.storage_handle().unwrap();
    let mut creation_record = broker
        .transactions
        .workspace_creation_record(creation)
        .unwrap();
    *creation_record.last_mut().unwrap() ^= 1;
    broker
        .transactions
        .put_authority_record_with_transaction_for_test(
            [97; 16],
            RecordNamespace::Operation,
            &creation.operation_id(),
            creation_record,
        );
    let repair_manifest = assignment_manifest_at(&sandbox_spec(72), 6);
    let request = repair_request(80, 81, workspace_handle, 6, repair_manifest.digest());
    let artifacts = fixture.repair_artifacts(&request);
    let contract = ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap();
    let host_scope = WorkspacePinHostScopeV1::new([50; 16], 51, 52).unwrap();

    assert!(
        broker
            .plan_workspace_pin_repair_admission_observation(
                &request,
                &artifacts,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
                &contract,
                host_scope,
            )
            .is_err()
    );
    assert!(
        broker
            .transactions
            .workspace_pin_attempts()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn missing_initial_repair_rejects_stale_wrong_target_and_tampered_authority_before_probe() {
    let directory = TempDir::new().unwrap();
    let fixture = Fixture::new();
    let (broker, creation) = committed_workspace_without_pin(&directory, &fixture);
    let workspace_handle = creation.storage_handle().unwrap();
    let contract = ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap();
    let host_scope = WorkspacePinHostScopeV1::new([50; 16], 51, 52).unwrap();
    let sequence = broker.transactions.journal_sequence_for_test();

    let stale_manifest = assignment_manifest_at(&sandbox_spec(72), 4);
    let stale_request = repair_request(80, 81, workspace_handle, 4, stale_manifest.digest());
    let stale_artifacts = fixture.repair_artifacts(&stale_request);
    assert!(
        broker
            .plan_workspace_pin_repair_admission_observation(
                &stale_request,
                &stale_artifacts,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
                &contract,
                host_scope,
            )
            .is_err()
    );

    let current_manifest = assignment_manifest_at(&sandbox_spec(72), 6);
    let wrong_target = repair_request(82, 83, [0x83; 32], 6, current_manifest.digest());
    let wrong_target_artifacts = fixture.repair_artifacts(&wrong_target);
    assert!(
        broker
            .plan_workspace_pin_repair_admission_observation(
                &wrong_target,
                &wrong_target_artifacts,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
                &contract,
                host_scope,
            )
            .is_err()
    );

    let valid = repair_request(84, 85, workspace_handle, 6, current_manifest.digest());
    let valid_artifacts = fixture.repair_artifacts(&valid);
    let mut tampered = valid.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(
        broker
            .plan_workspace_pin_repair_admission_observation(
                &tampered,
                &valid_artifacts,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
                &contract,
                host_scope,
            )
            .is_err()
    );

    assert_eq!(broker.transactions.journal_sequence_for_test(), sequence);
    assert!(
        broker
            .transactions
            .workspace_pin_attempts()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn missing_initial_repair_rejects_nonterminal_and_non_creation_sources() {
    let fixture = Fixture::new();
    let operation_request = request(7, 8);
    let operation_catalog = catalog(8, 9);
    let operation_artifacts = fixture.artifacts(
        &operation_request,
        &operation_catalog,
        300,
        BrokerAudience::Storage,
        ProtocolId::StorageBroker,
    );
    let repair_manifest = assignment_manifest_at(&sandbox_spec(72), 6);
    let repair = repair_request(80, 81, [8; 32], 6, repair_manifest.digest());
    let repair_artifacts = fixture.repair_artifacts(&repair);
    let contract = ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap();
    let host_scope = WorkspacePinHostScopeV1::new([50; 16], 51, 52).unwrap();

    let nonterminal_directory = TempDir::new().unwrap();
    let mut nonterminal =
        initialized_coordinator(&nonterminal_directory, &fixture, &operation_catalog);
    prepare_for_apply(
        &mut nonterminal,
        &operation_request,
        &operation_artifacts,
        &operation_catalog,
        &clock(),
    );
    nonterminal
        .admit_apply_intent(
            &operation_request,
            &operation_artifacts,
            &operation_catalog,
            ProtocolVersion::new(1, 0),
            peer(),
            peer_policy(),
            &clock(),
        )
        .unwrap();
    assert!(
        nonterminal
            .plan_workspace_pin_repair_admission_observation(
                &repair,
                &repair_artifacts,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
                &contract,
                host_scope,
            )
            .is_err()
    );

    let wrong_kind_directory = TempDir::new().unwrap();
    let mut wrong_kind =
        initialized_coordinator(&wrong_kind_directory, &fixture, &operation_catalog);
    prepare_for_apply(
        &mut wrong_kind,
        &operation_request,
        &operation_artifacts,
        &operation_catalog,
        &clock(),
    );
    let StorageAdmissionOutcome::Prepared { mutation_digest } = wrong_kind
        .admit_apply_intent(
            &operation_request,
            &operation_artifacts,
            &operation_catalog,
            ProtocolVersion::new(1, 0),
            peer(),
            peer_policy(),
            &clock(),
        )
        .unwrap()
    else {
        panic!("non-creation source was not prepared")
    };
    wrong_kind
        .transactions
        .mark_mutation_ambiguous([7; 16], mutation_digest)
        .unwrap();
    wrong_kind
        .transactions
        .commit_observed(
            [7; 16],
            mutation_digest,
            &operation_catalog,
            &operation_catalog.plan().postcondition(),
            Some(11),
            ObjectDigest::from_bytes([99; 32]),
        )
        .unwrap();
    assert!(
        wrong_kind
            .plan_workspace_pin_repair_admission_observation(
                &repair,
                &repair_artifacts,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
                &contract,
                host_scope,
            )
            .is_err()
    );
    assert!(
        wrong_kind
            .transactions
            .workspace_pin_attempts()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn missing_initial_repair_rejects_every_authority_substitution_before_provider_action() {
    let directory = TempDir::new().unwrap();
    let fixture = Fixture::new();
    let (mut broker, creation) = committed_workspace_without_pin(&directory, &fixture);
    let workspace_handle = creation.storage_handle().unwrap();
    let current_manifest = assignment_manifest_at(&sandbox_spec(72), 6);
    let valid = repair_request(80, 81, workspace_handle, 6, current_manifest.digest());
    let contract = ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap();
    let host_scope = WorkspacePinHostScopeV1::new([50; 16], 51, 52).unwrap();
    let sequence = broker.transactions.journal_sequence_for_test();

    let substitutions = [
        ("sandbox", with_repair_sandbox(&valid, [91; 16])),
        ("incarnation", with_repair_incarnation(&valid, [92; 16])),
        ("epoch", with_repair_epoch(&valid, 5)),
        ("desired generation", with_repair_generation(&valid, 4)),
        (
            "equal-generation assignment",
            with_repair_assignment(
                &with_repair_generation(&valid, 5),
                ObjectDigest::from_bytes([93; 32]),
            ),
        ),
        ("repair operation", {
            let mut request = RepairStorageWorkspacePinRequest::decode_from_slice(&valid).unwrap();
            request.operation_id = creation.operation_id().to_vec();
            request.encode_to_vec()
        }),
    ];
    for (name, candidate) in substitutions {
        let artifacts = fixture.repair_artifacts(&candidate);
        assert!(
            broker
                .plan_workspace_pin_repair_admission_observation(
                    &candidate,
                    &artifacts,
                    ProtocolVersion::new(1, 0),
                    peer(),
                    peer_policy(),
                    &clock(),
                    &contract,
                    host_scope,
                )
                .is_err(),
            "{name} substitution reached the observation provider"
        );
    }

    let mismatched_ownership = fixture.repair_artifacts(&with_repair_assignment(
        &valid,
        ObjectDigest::from_bytes([94; 32]),
    ));
    assert!(
        broker
            .plan_workspace_pin_repair_admission_observation(
                &valid,
                &mismatched_ownership,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
                &contract,
                host_scope,
            )
            .is_err(),
        "ownership assignment substitution reached the provider"
    );

    let wrong_plan = fixture.repair_artifacts_without_plan_grant(&valid);
    assert!(
        broker
            .plan_workspace_pin_repair_admission_observation(
                &valid,
                &wrong_plan,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
                &contract,
                host_scope,
            )
            .is_err(),
        "unauthorized plan reached the provider"
    );

    let expired_lease = fixture.repair_artifacts_between(&valid, 100, 300, 140);
    assert!(
        broker
            .plan_workspace_pin_repair_admission_observation(
                &valid,
                &expired_lease,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
                &contract,
                host_scope,
            )
            .is_err(),
        "expired lease reached the provider"
    );

    let signed = fixture.repair_artifacts(&valid);
    let mut tampered_plan_signature = signed.broker_plan_signature().to_vec();
    *tampered_plan_signature.last_mut().unwrap() ^= 1;
    let tampered_signature = validated(
        BrokerAuthorizationArtifactsV1 {
            broker_plan: signed.broker_plan().to_vec(),
            broker_plan_signature: tampered_plan_signature,
            ownership_lease: signed.ownership_lease().to_vec(),
            ownership_lease_signature: signed.ownership_lease_signature().to_vec(),
            ..Default::default()
        },
        ProtocolId::StorageBroker,
    );
    assert!(
        broker
            .plan_workspace_pin_repair_admission_observation(
                &valid,
                &tampered_signature,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
                &contract,
                host_scope,
            )
            .is_err(),
        "repair plan signature substitution reached the provider"
    );

    broker.authority = fixture.authority_at_node(NodeId::from_bytes([96; 16]));
    let artifacts = fixture.repair_artifacts(&valid);
    assert!(
        broker
            .plan_workspace_pin_repair_admission_observation(
                &valid,
                &artifacts,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
                &contract,
                host_scope,
            )
            .is_err(),
        "wrong node ownership reached the provider"
    );

    assert_eq!(broker.transactions.journal_sequence_for_test(), sequence);
    assert!(
        broker
            .transactions
            .workspace_pin_attempts()
            .unwrap()
            .is_empty()
    );
}
