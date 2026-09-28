//! Debug-only installed negative-recovery original-Effect fixture.
//!
//! The explicit VM feature is never enabled by the production daemon package.
//! Every entry point also rejects release builds before owner reads or writes;
//! release workspace compilation therefore does not open the fixture path.
//! This initializer admits an exact public request and projection through the
//! ordinary ledger, then retains synthetic historical heads solely to exercise
//! denial and retirement. It neither establishes Source genesis/currentness
//! nor invokes the production positive admission preflight or Root publication.

use std::error::Error;

use aos_proto::aos::sandbox::v1::{
    CreateSandboxRequest, DesiredLifecycle, Duration, ObjectDescriptor, OperationPhase, RetryClass,
    Sandbox, SandboxDesiredState, SandboxObservedState, SandboxPhase, Timestamp,
};
use aos_sandbox_core::{
    ObjectDigest, OperationId, PrincipalId, ProjectId, ResourceId, ResourceKind, RevocationScopeId,
    SandboxId, Selector,
};

use super::{
    ProjectAdmissionMetadata, ProjectAdmissionPhase,
    authorize_controller_project_admission_dispatch_v1, capacity_request,
    controller_project_suffix_budget, effect_record, load_scoped_effect, require_controller_writer,
    retained_controller_project_admission_v1, validate_all,
};
use crate::cli_model::{PublicApiAuditMethodV1, PublicMutationRequestV1};
use crate::controller::ControllerRequestScopeV1;
use crate::controller_query::PublicOperationMethodV1;
use crate::controller_service::public_projection::{
    PublicProjectionPlanV1, PublicProjectionResourceV1,
};
use crate::journal::{
    IdempotencyKey, Journal, JournalError, JournalTransaction, RecordNamespace,
    SourceProjectAdmissionReservationV1,
};
use crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;
use crate::policy_compiler::{
    HistoricalCreateProjectSourceHeadsV1, create_project_source_commitment_v1,
    project_admission_client_nonce_v1,
};
use crate::reconciler::effect::EffectState;
use crate::reconciler::{
    EffectFailure, EffectObservation, EffectPlan, EffectReceipt, OperationPlan,
    PublicMutationEffectV1, PublicOperationAdmissionV1, PublicOperationAuthorizationV1,
    ReconcileOutcome, Reconciler, SingleNodeEffectExecutor, decode_effect, effect_key,
    public_operation_resource_from_journal_v1, retained_create_sandbox_admission_revision_v1,
};

const PROJECT: ProjectId = ProjectId::from_bytes([1; 16]);
const SCOPE_DIGEST: ObjectDigest = ObjectDigest::from_bytes([0xe1; 32]);

/// Derives an actual Source proposal without appending or asserting ancestry.
///
/// # Errors
///
/// Rejects release builds, foreign fixed names or pending issue, or invalid proposal
/// identity. Only the real Source owner supplies the canonical issue and names.
pub fn preview_project_history_vm_reservation_v1(
    owner: &mut ProtectedSourceDomainJournalOwnerV1,
    nonce: [u8; 16],
    project: ProjectId,
) -> Result<SourceProjectAdmissionReservationV1, JournalError> {
    require_debug_fixture()?;
    owner.require_fixed_named_writer_v1()?;
    let names = owner.fixed_physical_names_v1()?;
    owner
        .journal()
        .preview_source_project_admission_reservation_v1(nonce, project, names)
}

/// Retains an installed original Effect at the pre-Root dispatch crash cut.
///
/// Synthetic publisher/cache/revocation heads are deliberately nonauthorizing.
/// The actual request, projection, immutable admission, Controller reservation
/// and dispatch suffix are persisted and validated by their existing owners.
/// Source is only previewed; no reservation, challenge, or ancestry is created.
///
/// # Errors
///
/// Rejects release builds, an occupied flight, incorrect fixed custody, or failed
/// canonical admission/projection/capacity transition. No executor is invoked.
pub fn prepare_project_history_vm_flight_v1(
    journal: Journal,
    source: &mut ProtectedSourceDomainJournalOwnerV1,
    tag: u8,
) -> Result<Journal, Box<dyn Error>> {
    require_debug_fixture()?;
    require_controller_writer(&journal)?;
    if tag == 0 || tag >= 0x80 {
        return Err("invalid VM flight identity".into());
    }
    let scope = ControllerRequestScopeV1::new(SCOPE_DIGEST)?;
    if retained_controller_project_admission_v1(&journal, scope, None)?.is_some() {
        return Err("VM original flight already occupied".into());
    }
    let operation = OperationId::from_bytes([tag; 16]);
    let sandbox = SandboxId::from_bytes([tag + 0x80; 16]);
    let (admission, projection) = admitted_create(operation, sandbox, tag, scope)?;
    let plan = admission.effects[0].clone();
    let request_digest = admission.request_digest();
    let mut reconciler = Reconciler::new(journal, NoExternalEffects);
    reconciler.accept(&admission)?;
    if reconciler.reconcile_once_at(operation, 101)? != ReconcileOutcome::Progressed {
        return Err("VM original Effect did not enter its durable Applying intent".into());
    }
    let mut journal = reconciler.journal;

    let checked_projection = projection.checked_record()?;
    let projection_revision = checked_projection.revision();
    let PublicProjectionResourceV1::Sandbox(projected_sandbox) = checked_projection.resource()
    else {
        return Err("VM original projection is not a sandbox".into());
    };
    let requested_policy = projected_sandbox
        .desired
        .as_option()
        .and_then(|desired| desired.requested_policy.as_option())
        .ok_or("VM original requested policy absent")?;
    let publisher_digest = ObjectDigest::from_bytes(
        requested_policy
            .sha256
            .as_slice()
            .try_into()
            .map_err(|_| "VM original policy digest malformed")?,
    );
    let (key, original_projection) = projection.into_desired_state();
    if journal.get(RecordNamespace::DesiredState, &key) != Some(original_projection.as_slice()) {
        return Err("VM projection was not atomically admitted with the original Effect".into());
    }
    let (revision, generation, retained_request) =
        retained_create_sandbox_admission_revision_v1(&journal, operation, false)?
            .ok_or("VM original admission absent")?;
    if retained_request != request_digest {
        return Err("VM original request digest changed".into());
    }

    let heads = HistoricalCreateProjectSourceHeadsV1 {
        projection_revision,
        publisher_generation: 1,
        publisher_digest,
        cache_domain_head: ObjectDigest::from_bytes([6; 32]),
        revocation_scope: RevocationScopeId::from_bytes([7; 16]),
        revocation_generation: 1,
        revocation_head: ObjectDigest::from_bytes([8; 32]),
    };
    let commitment = create_project_source_commitment_v1(
        operation, revision, generation, sandbox, PROJECT, heads,
    );
    let reservation = preview_project_history_vm_reservation_v1(
        source,
        project_admission_client_nonce_v1(operation, commitment),
        PROJECT,
    )?;
    let mut effect = load_scoped_effect(&journal, operation, scope, &plan)?;
    let mut metadata = ProjectAdmissionMetadata {
        admission_revision: revision,
        admission_generation: generation,
        source_commitment: commitment,
        sandbox,
        project: PROJECT,
        reservation,
        capacity_id: [1; 32],
        phase: ProjectAdmissionPhase::Prepared,
        challenge: None,
        terminal: None,
        retired_floor: None,
        source_heads: heads,
        original_projection,
    };
    effect.project_admission = Some(metadata.clone());
    let bytes = controller_project_suffix_budget(&effect)?;
    let transaction_id = OperationId::new().into_bytes();
    let capacity = journal.prepare_global_capacity_reservation_v1(
        capacity_request(operation, &metadata, &plan, 3, 8, bytes),
        transaction_id,
    )?;
    metadata.capacity_id = capacity.reservation_id();
    effect.project_admission = Some(metadata);
    let reservation_record = capacity.record().clone();
    journal.commit_global_capacity_reservation_v1(
        capacity,
        &JournalTransaction::new(
            transaction_id,
            vec![effect_record(operation, &effect)?, reservation_record],
        )?,
    )?;
    validate_all(&journal)?;
    authorize_controller_project_admission_dispatch_v1(&mut journal, operation, scope, &plan)?;
    Ok(journal)
}

/// Checks the exact original Effect without treating retirement as success.
///
/// # Errors
///
/// Rejects release builds, changed metadata, an unexpected phase, or an
/// unreleased Controller suffix. Source's actual next-issue preview additionally
/// proves that its final ACK was persisted, rather than inferred from a floor.
pub fn require_project_history_vm_flight_v1(
    journal: &Journal,
    source: &mut ProtectedSourceDomainJournalOwnerV1,
    tag: u8,
    retired: bool,
) -> Result<(), Box<dyn Error>> {
    require_debug_fixture()?;
    require_controller_writer(journal)?;
    validate_all(journal)?;
    let operation = OperationId::from_bytes([tag; 16]);
    let effect = decode_effect(
        journal
            .get(RecordNamespace::Effect, &effect_key(operation, 0))
            .ok_or("VM original Effect absent")?,
    )?;
    let metadata = effect
        .project_admission
        .ok_or("VM flight metadata absent")?;
    let expected = if retired {
        ProjectAdmissionPhase::RootRetired
    } else {
        ProjectAdmissionPhase::DispatchAuthorized
    };
    let is_blocked = matches!(effect.state, EffectState::PermanentlyBlocked { .. });
    if metadata.phase != expected
        || !(matches!(effect.state, EffectState::Applying { .. }) || retired && is_blocked)
    {
        return Err("VM original Create phase changed or became applied".into());
    }
    let preview = preview_project_history_vm_reservation_v1(
        source,
        metadata.reservation.client_nonce(),
        metadata.project,
    )?;
    if retired {
        if preview.issue()
            != metadata
                .reservation
                .issue()
                .checked_add(1)
                .ok_or("issue overflow")?
            || journal
                .recover_global_capacity_reservation_v1(metadata.capacity_id)
                .is_ok()
        {
            return Err("VM Source ACK or Controller suffix retirement absent".into());
        }
    } else if preview != metadata.reservation {
        return Err("VM original Source proposal changed".into());
    }
    if is_blocked {
        require_terminal_operation(journal, operation)?;
    }
    Ok(())
}

/// Fails the original operation only after actual cold retirement and ACK joins.
///
/// The ordinary Reconciler permanent-negative transition atomically blocks the
/// Effect and Operation. It creates no Applied receipt or Host no-Apply claim;
/// exact terminal replay uses the same existing transition and appends nothing.
///
/// # Errors
///
/// Rejects release builds, any missing retirement/ACK join, an unexpected
/// original Effect, or failure of the actual protected Reconciler transition.
pub fn fail_retired_project_history_vm_operation_v1(
    journal: Journal,
    source: &mut ProtectedSourceDomainJournalOwnerV1,
    tag: u8,
) -> Result<Journal, Box<dyn Error>> {
    require_debug_fixture()?;
    require_project_history_vm_flight_v1(&journal, source, tag, true)?;
    let operation = OperationId::from_bytes([tag; 16]);
    let mut reconciler = Reconciler::new(journal, NoExternalEffects);
    if reconciler.reconcile_once_at(operation, 102)? != ReconcileOutcome::PermanentlyBlocked {
        return Err("VM negative executor did not terminally block the original operation".into());
    }
    let journal = reconciler.journal;
    require_project_history_vm_flight_v1(&journal, source, tag, true)?;
    require_terminal_operation(&journal, operation)?;
    Ok(journal)
}

fn require_terminal_operation(
    journal: &Journal,
    operation: OperationId,
) -> Result<(), Box<dyn Error>> {
    let public = public_operation_resource_from_journal_v1(journal, operation)?
        .ok_or("VM original public operation absent")?;
    if public.phase.enum_value() != Some(OperationPhase::OPERATION_PHASE_PERMANENTLY_BLOCKED)
        || public.retry_class.enum_value() != Some(RetryClass::RETRY_CLASS_NEVER)
        || public.completed_at.as_option().is_none()
        || public
            .progress
            .as_option()
            .is_none_or(|progress| progress.completed_units != 0)
    {
        return Err(
            "VM original operation lacks its actual non-success terminal projection".into(),
        );
    }
    Ok(())
}

fn require_debug_fixture() -> Result<(), JournalError> {
    if cfg!(debug_assertions) {
        Ok(())
    } else {
        Err(JournalError::ProtectedBoundary)
    }
}

fn admitted_create(
    operation: OperationId,
    sandbox: SandboxId,
    tag: u8,
    scope: ControllerRequestScopeV1,
) -> Result<(OperationPlan, PublicProjectionPlanV1), Box<dyn Error>> {
    let key = format!("q04-negative-flight-{tag}").into_bytes();
    let descriptor = ObjectDescriptor {
        media_type: "application/vnd.aos.vm-negative-fixture".to_owned(),
        sha256: vec![tag; 32],
        encoded_size: 1,
        ..Default::default()
    };
    let request = CreateSandboxRequest {
        project_id: PROJECT.as_bytes().to_vec(),
        expected_project_resource_version: vec![0xa1; 32],
        specification: Some(descriptor.clone()).into(),
        requested_policy: Some(descriptor.clone()).into(),
        idempotency_key: key.clone(),
        operation_timeout: Some(Duration {
            nanoseconds: 1,
            ..Default::default()
        })
        .into(),
        ..Default::default()
    };
    let envelope = PublicMutationRequestV1::new(
        PublicApiAuditMethodV1::CreateSandbox,
        &request.encode_to_vec(),
    )?
    .encode();
    let caller = PrincipalId::from_bytes([0x93; 16]);
    let digest = scope.public_request_digest(caller, PROJECT, &envelope);
    let effect = EffectPlan::authorized_public_mutation(
        PublicOperationMethodV1::CreateSandbox,
        PublicMutationEffectV1::new(caller, PROJECT, 100, envelope)?,
    )?;
    let authorization = PublicOperationAuthorizationV1::new(
        PROJECT,
        ResourceKind::ChildDelegation,
        Selector::Resource {
            resource: ResourceId::from_bytes(*PROJECT.as_bytes()),
        },
    )?;
    let timestamp = Timestamp {
        seconds: 100,
        ..Default::default()
    };
    let projection = PublicProjectionPlanV1::new(
        PROJECT,
        operation,
        PublicProjectionResourceV1::Sandbox(Sandbox {
            sandbox_id: sandbox.as_bytes().to_vec(),
            project_id: PROJECT.as_bytes().to_vec(),
            resource_version:
                crate::production_operation_compiler::admitted_public_resource_version_v1(
                    operation,
                    PublicOperationMethodV1::CreateSandbox,
                    1,
                    digest,
                ),
            desired: Some(SandboxDesiredState {
                specification: Some(descriptor.clone()).into(),
                requested_policy: Some(descriptor.clone()).into(),
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
            effective_policy: Some(descriptor).into(),
            created_at: Some(timestamp.clone()).into(),
            updated_at: Some(timestamp).into(),
            ..Default::default()
        }),
    )?;
    let (desired_key, desired_value) = projection.clone().into_desired_state();
    let admission = OperationPlan::new(
        operation,
        IdempotencyKey::new(key)?,
        digest,
        desired_key,
        desired_value,
        vec![effect],
    )?
    .with_public_operation(PublicOperationAdmissionV1::new(
        PublicOperationMethodV1::CreateSandbox,
        1,
        [tag; 16],
        100,
        authorization,
    )?)?;
    Ok((admission, projection))
}

struct NoExternalEffects;

impl SingleNodeEffectExecutor for NoExternalEffects {
    fn observe(
        &mut self,
        _: OperationId,
        _: u32,
        _: &EffectPlan,
    ) -> Result<EffectObservation, EffectFailure> {
        Err(EffectFailure::Permanent(
            "VM fixture never observes positive effects".to_owned(),
        ))
    }

    fn apply(
        &mut self,
        _: OperationId,
        _: u32,
        _: &EffectPlan,
    ) -> Result<EffectReceipt, EffectFailure> {
        Err(EffectFailure::Permanent(
            "VM fixture never applies positive effects".to_owned(),
        ))
    }
}
