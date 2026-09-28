//! Protected original-Effect join and capacity-transfer fixtures.
//!
//! These exercise canonical retained admission identity and real journal cuts.
//! Historical publisher inputs are synthetic and do not establish production
//! Source genesis, fixed installed Controller custody, or positive Root authority.

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use aos_proto::aos::sandbox::v1::{
    DesiredLifecycle, Sandbox, SandboxDesiredState, SandboxObservedState, SandboxPhase, Timestamp,
};
use aos_sandbox_core::{OperationId, RevocationScopeId};

use super::*;
use crate::controller_service::public_projection::PublicProjectionPlanV1;
use crate::policy_compiler::HistoricalCreateProjectSourceHeadsV1;
use crate::reconciler::effect::EffectState;

struct Fixture {
    directory: tempfile::TempDir,
    source_directory: tempfile::TempDir,
    journal: Journal,
    source: Journal,
    uid: u32,
    operation: OperationId,
    scope: ControllerRequestScopeV1,
    plan: EffectPlan,
}

impl Fixture {
    fn prepared() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let source_directory = tempfile::tempdir().unwrap();
        for path in [directory.path(), source_directory.path()] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let journal = Journal::open_protected_at_uid(
            directory.path(),
            "controller.journal",
            crate::controller_service::journal::production_journal_limits(),
            uid,
        )
        .unwrap()
        .0;
        let source = Journal::open_protected_at_uid(
            source_directory.path(),
            "source-domains-v1.journal",
            crate::lifecycle::protected_journal_join::source_domain_journal_limits(),
            uid,
        )
        .unwrap()
        .0;
        let admission = crate::reconciler::tests::live_create_sandbox_plan(0xd1);
        let operation = admission.operation_id();
        let plan = admission.effects[0].clone();
        let scope = ControllerRequestScopeV1::new(ObjectDigest::from_bytes([0xe1; 32])).unwrap();
        let mut reconciler = crate::reconciler::Reconciler::new(
            journal,
            crate::reconciler::tests::Executor::default(),
        );
        reconciler.accept(&admission).unwrap();
        let mut journal = reconciler.journal;
        let context = plan.public_mutation_context().unwrap().unwrap();
        let crate::cli_model::DormantSandboxRequestKindV1::Create(request) =
            context.validated_request().unwrap()
        else {
            panic!("Create fixture");
        };
        let sandbox = SandboxId::from_bytes([0xc4; 16]);
        let policy = request.requested_policy.as_option().unwrap().clone();
        let timestamp = Timestamp {
            seconds: 100,
            ..Default::default()
        };
        let projection = PublicProjectionPlanV1::new(
            context.project(),
            operation,
            PublicProjectionResourceV1::Sandbox(Sandbox {
                sandbox_id: sandbox.as_bytes().to_vec(),
                project_id: context.project().as_bytes().to_vec(),
                resource_version:
                    crate::production_operation_compiler::admitted_public_resource_version_v1(
                        operation,
                        crate::controller_query::PublicOperationMethodV1::CreateSandbox,
                        1,
                        admission.request_digest(),
                    ),
                desired: Some(SandboxDesiredState {
                    specification: request.specification.clone(),
                    requested_policy: Some(policy.clone()).into(),
                    lifecycle: DesiredLifecycle::DESIRED_LIFECYCLE_STOPPED.into(),
                    generation: 1,
                    ..Default::default()
                })
                .into(),
                observed: Some(SandboxObservedState {
                    phase: SandboxPhase::SANDBOX_PHASE_REQUESTED.into(),
                    desired_generation: 1,
                    observation_sequence: 1,
                    last_successful_reconciliation_time: Some(timestamp.clone()).into(),
                    ..Default::default()
                })
                .into(),
                effective_policy: Some(policy).into(),
                created_at: Some(timestamp.clone()).into(),
                updated_at: Some(timestamp).into(),
                ..Default::default()
            }),
        )
        .unwrap();
        let projection_revision = projection.checked_record().unwrap().revision();
        let (projection_key, projection_bytes) = projection.into_desired_state();
        journal
            .commit(
                &JournalTransaction::new(
                    [19; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::DesiredState,
                        projection_key,
                        projection_bytes.clone(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        let (revision, generation, _) =
            retained_create_sandbox_admission_revision_v1(&journal, operation, false)
                .unwrap()
                .unwrap();
        let heads = HistoricalCreateProjectSourceHeadsV1 {
            projection_revision,
            publisher_generation: 1,
            publisher_digest: ObjectDigest::from_bytes([0xd1; 32]),
            cache_domain_head: ObjectDigest::from_bytes([6; 32]),
            revocation_scope: RevocationScopeId::from_bytes([7; 16]),
            revocation_generation: 1,
            revocation_head: ObjectDigest::from_bytes([8; 32]),
        };
        let commitment = create_project_source_commitment_v1(
            operation,
            revision,
            generation,
            sandbox,
            context.project(),
            heads,
        );
        let reservation = source
            .preview_source_project_admission_reservation_v1(
                project_admission_client_nonce_v1(operation, commitment),
                context.project(),
                source.protected_writer_physical_names_v1().unwrap(),
            )
            .unwrap();
        let mut metadata = ProjectAdmissionMetadata {
            admission_revision: revision,
            admission_generation: generation,
            source_commitment: commitment,
            sandbox,
            project: context.project(),
            reservation,
            capacity_id: [1; 32],
            phase: ProjectAdmissionPhase::Prepared,
            challenge: None,
            terminal: None,
            retired_floor: None,
            source_heads: heads,
            original_projection: projection_bytes.clone(),
        };
        let transaction_id = [20; 16];
        let capacity = journal
            .prepare_global_capacity_reservation_v1(
                capacity_request(operation, &metadata, &plan, 3, 8, 32 * 1024),
                transaction_id,
            )
            .unwrap();
        metadata.capacity_id = capacity.reservation_id();
        let effect = EffectLedgerRecord {
            plan: plan.clone(),
            state: EffectState::Planned,
            dispatch: None,
            project_admission: Some(metadata),
        };
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![
                effect_record(operation, &effect).unwrap(),
                capacity.record().clone(),
            ],
        )
        .unwrap();
        journal
            .commit_global_capacity_reservation_v1(capacity, &transaction)
            .unwrap();
        validate_all(&journal).unwrap();
        Self {
            directory,
            source_directory,
            journal,
            source,
            uid,
            operation,
            scope,
            plan,
        }
    }

    fn effect(&self) -> EffectLedgerRecord {
        decode_effect(
            self.journal
                .get(RecordNamespace::Effect, &effect_key(self.operation, 0))
                .unwrap(),
        )
        .unwrap()
    }

    fn reopen(&mut self) {
        let placeholder = Journal::open_protected_at_uid(
            self.directory.path(),
            "fixture-placeholder.journal",
            crate::controller_service::journal::production_journal_limits(),
            self.uid,
        )
        .unwrap()
        .0;
        drop(std::mem::replace(&mut self.journal, placeholder));
        self.journal = Journal::open_protected_at_uid(
            self.directory.path(),
            "controller.journal",
            crate::controller_service::journal::production_journal_limits(),
            self.uid,
        )
        .unwrap()
        .0;
    }
}

#[test]
fn historical_dispatch_claims_rejoin_actual_original_effect_without_current_publisher() {
    use crate::policy_compiler::{
        sign_synthetic_controller_project_dispatch_v1,
        verify_controller_project_dispatch_readback_v1,
    };
    let mut fixture = Fixture::prepared();
    assert!(dispatch_readback_from_original_graph(&fixture.journal, fixture.operation).is_err());
    let effect = fixture.effect();
    let metadata = effect.project_admission.clone().unwrap();
    transfer_metadata(
        &mut fixture.journal,
        fixture.operation,
        effect,
        ProjectAdmissionMetadata {
            phase: ProjectAdmissionPhase::DispatchAuthorized,
            ..metadata.clone()
        },
    )
    .unwrap();
    fixture.reopen();
    let claims =
        dispatch_readback_from_original_graph(&fixture.journal, fixture.operation).unwrap();
    assert_eq!(claims.operation, fixture.operation);
    assert_eq!(claims.sandbox, metadata.sandbox);
    assert_eq!(claims.reservation, metadata.reservation);
    assert_eq!(claims.admission_revision, metadata.admission_revision);
    assert_eq!(claims.source_commitment, metadata.source_commitment);
    let key = ed25519_dalek::SigningKey::from_bytes(&[72; 32]);
    let pin = crate::policy_compiler::PinnedControllerHoldSignerV1::decode(
        &crate::policy_compiler::encode_controller_hold_signer_credential_v1(
            4,
            &key.verifying_key(),
        )
        .unwrap(),
    )
    .unwrap();
    let packet = sign_synthetic_controller_project_dispatch_v1(
        &claims,
        811,
        fixture.journal.snapshot_sequence(),
        4,
        &key,
    )
    .unwrap();
    let verified = verify_controller_project_dispatch_readback_v1(&packet, &pin, 811).unwrap();
    assert_eq!(verified.metadata, claims.metadata);
    assert_eq!(verified.reservation, metadata.reservation);
    let mut terminal_domain = packet;
    terminal_domain[..8].copy_from_slice(b"AOSCTP04");
    assert!(verify_controller_project_dispatch_readback_v1(&terminal_domain, &pin, 811).is_err());
    assert!(
        crate::policy_compiler::sign_fixed_controller_project_dispatch_readback_v1(
            &fixture.journal,
            fixture.operation,
            4,
            &key
        )
        .is_err(),
        "temporary owner fixture cannot stand in for installed fixed Controller custody"
    );
    assert!(
        fixture
            .source
            .source_project_admission_reservation_v1()
            .unwrap()
            .is_none()
    );
}

#[test]
fn original_graph_and_dispatch_suffix_survive_cold_replay_without_source_row() {
    let mut fixture = Fixture::prepared();
    let effect = fixture.effect();
    let metadata = effect.project_admission.clone().unwrap();
    assert!(
        fixture
            .source
            .source_project_admission_reservation_status_v1()
            .unwrap()
            .is_none()
    );
    transfer_metadata(
        &mut fixture.journal,
        fixture.operation,
        effect,
        ProjectAdmissionMetadata {
            phase: ProjectAdmissionPhase::DispatchAuthorized,
            ..metadata.clone()
        },
    )
    .unwrap();
    let authorized = fixture.effect().project_admission.unwrap();
    assert_eq!(authorized.admission_revision, metadata.admission_revision);
    assert_eq!(authorized.source_commitment, metadata.source_commitment);
    assert_eq!(authorized.original_projection, metadata.original_projection);
    assert_eq!(
        fixture
            .journal
            .recover_global_capacity_reservation_v1(authorized.capacity_id)
            .unwrap()
            .request()
            .future_transactions,
        2
    );
    fixture.reopen();
    validate_all(&fixture.journal).unwrap();
    assert_eq!(fixture.effect().project_admission, Some(authorized));
    assert!(
        checked_live_create_sandbox_admission_revision_v1(
            &fixture.journal,
            fixture.operation,
            fixture.scope,
            &fixture.plan
        )
        .unwrap()
        .is_some()
    );
    assert!(fixture.source_directory.path().exists());
}

#[test]
fn original_graph_rejects_changed_child_source_and_same_key_request() {
    let fixture = Fixture::prepared();
    let metadata = fixture.effect().project_admission.unwrap();
    let (_, _, request_digest) =
        retained_create_sandbox_admission_revision_v1(&fixture.journal, fixture.operation, false)
            .unwrap()
            .unwrap();
    let mut changed = metadata.clone();
    changed.sandbox = SandboxId::from_bytes([0xc5; 16]);
    assert!(
        validate_original_projection(
            &fixture.journal,
            fixture.operation,
            &changed,
            &fixture.plan,
            request_digest
        )
        .is_err()
    );
    let altered = crate::reconciler::tests::live_create_sandbox_plan(0xd2).effects[0].clone();
    assert!(
        validate_original_projection(
            &fixture.journal,
            fixture.operation,
            &metadata,
            &altered,
            request_digest
        )
        .is_err()
    );
    assert!(
        checked_live_create_sandbox_admission_revision_v1(
            &fixture.journal,
            fixture.operation,
            fixture.scope,
            &altered
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn changed_dispatch_transfer_is_nonmutating_and_keeps_reserved_suffix() {
    let mut fixture = Fixture::prepared();
    let effect = fixture.effect();
    let metadata = effect.project_admission.clone().unwrap();
    let mut changed = metadata.clone();
    changed.phase = ProjectAdmissionPhase::DispatchAuthorized;
    changed.admission_revision = ObjectDigest::from_bytes([99; 32]);
    let cut = fixture.journal.snapshot_sequence();
    assert!(transfer_metadata(&mut fixture.journal, fixture.operation, effect, changed).is_err());
    assert_eq!(fixture.journal.snapshot_sequence(), cut);
    assert_eq!(fixture.effect().project_admission, Some(metadata));
    validate_all(&fixture.journal).unwrap();
}

#[test]
fn dispatch_without_root_artifact_keeps_exact_flight_when_credentials_expire_or_rotate() {
    let mut fixture = Fixture::prepared();
    let effect = fixture.effect();
    let metadata = effect.project_admission.clone().unwrap();
    transfer_metadata(
        &mut fixture.journal,
        fixture.operation,
        effect,
        ProjectAdmissionMetadata {
            phase: ProjectAdmissionPhase::DispatchAuthorized,
            ..metadata
        },
    )
    .unwrap();
    fixture.reopen();
    let retained = fixture.effect().project_admission.unwrap();
    let before = fixture.journal.snapshot_sequence();
    let deployment_key = ed25519_dalek::SigningKey::from_bytes(&[10; 32]);
    let project_key = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
    let heads = crate::policy_compiler::test_signed_project_heads_for_history_v1(
        &deployment_key,
        &project_key,
        retained.project,
    );
    assert_eq!(
        fixture
            .source
            .preview_source_project_admission_reservation_v1(
                retained.reservation.client_nonce(),
                retained.project,
                retained.reservation.names(),
            )
            .unwrap(),
        retained.reservation
    );
    assert!(
        crate::policy_compiler::verify_policy_deployment_head_v1(
            &heads.deployment,
            &heads.deployment_inputs(),
            &deployment_key.verifying_key(),
            20,
        )
        .is_ok()
    );
    assert!(
        crate::policy_compiler::verify_signed_project_policy_source_v2(
            &heads.project,
            &heads.project_input,
            &project_key.verifying_key(),
            20,
        )
        .is_ok()
    );
    let attempt = |deployment_key: &ed25519_dalek::SigningKey, now| {
        crate::policy_compiler::prepare_fixed_root_project_admission_intent_v1(
            retained.reservation,
            &heads.project,
            &heads.project_input,
            &project_key.verifying_key(),
            3,
            &heads.deployment,
            &heads.deployment_inputs(),
            &deployment_key.verifying_key(),
            2,
            now,
        )
    };
    assert!(
        attempt(&deployment_key, 30).is_err(),
        "expired signed inputs cannot dispatch the retained flight"
    );
    let rotated = ed25519_dalek::SigningKey::from_bytes(&[12; 32]);
    assert!(
        attempt(&rotated, 20).is_err(),
        "a different pin cannot rebase the original signed inputs"
    );
    assert_eq!(fixture.journal.snapshot_sequence(), before);
    assert_eq!(fixture.effect().project_admission, Some(retained.clone()));
    assert!(
        fixture
            .source
            .source_project_admission_reservation_status_v1()
            .unwrap()
            .is_none()
    );
    assert_eq!(
        fixture
            .journal
            .recover_global_capacity_reservation_v1(retained.capacity_id)
            .unwrap()
            .request()
            .future_transactions,
        2
    );
    validate_all(&fixture.journal).unwrap();
    // Positive retry still requires the fixed installed issuers to supply fresh
    // compatible inputs. This fixture proves retention and rejection only;
    // expired credentials do not instead supply negative settlement authority.
}
