//! Controller Storage-audience signing for one zero-byte output reserve.
//!
//! This source consists of the existing protected AOSCIA01 and AOSCIS01
//! records. It cannot be sent by the current production Controller: original
//! same-session Host proof and Storage dispatch are still closed. Signing and
//! protected one-shot custody establish Controller issuance only.

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerAuthorizationArtifactsV1, ReserveStorageExecutionOutputRequestV1,
};
use aos_sandbox::controller_execution_output_settlement::{
    ControllerExecutionOutputSettlementErrorV1, ProtectedControllerOutputSettlementV1,
    read_current_controller_output_settlement_v1,
};
use aos_sandbox::controller_execution_preissue::{
    ControllerExecutionPreissueV1, ControllerExecutionReserveSourceErrorV1,
    ControllerExecutionReserveSourceV1, prepare_execution_reserve_source_v1,
};
use aos_sandbox::controller_storage_output_reserve_attempt::{
    ControllerStorageOutputReserveAttemptErrorV1, ControllerStorageOutputReserveAttemptV1,
    retain_captured_controller_storage_output_reserve_attempt_v1,
    retain_controller_storage_output_reserve_attempt_v1,
};
use aos_sandbox::publication::{AuthorityPublicationError, CurrentAuthorityPublicationV1};
use aos_sandbox::environment::EnvironmentProtectedJournalOwnerV1;
use aos_sandbox::execution_parent_resource::ExecutionParentResourceSourceV1;
use aos_sandbox::ownership_authority::ProtectedOwnershipClockError;
use aos_sandbox::runtime_scope::CurrentAssignmentTarget;
use aos_sandbox::{AuthorityPublicationStore, EffectFailure, Journal, SignedBrokerPlan};
use aos_sandbox_core::{
    BrokerAssignment, BrokerAudience, BrokerAuthorizationPlan, BrokerGrant,
    InvalidBrokerAuthorizationPlan, ProtocolId, ProtocolVersion, RawPairedClockSample,
};
use aos_sandbox_protocol::storage_output_reserve::{
    StorageOutputReserveRecordsV1, captured_storage_output_reserve_grant_v1,
    storage_output_reserve_grant_v1,
};
use buffa::Message as _;

use crate::DormantBrokerRequestCoordinatesV1;
use crate::controller_plan_signer::{ControllerBrokerPlanSignerError, ControllerBrokerPlanSignerV1};

/// Keeps one exact signed Storage request separate from effect admission.
pub(crate) struct SignedStorageOutputReserveV1 {
    body: Vec<u8>,
    authorization: BrokerAuthorizationArtifactsV1,
}

impl SignedStorageOutputReserveV1 {
    /// Borrows the exact request body committed by the signed plan.
    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }

    /// Borrows the signed Storage plan and current ownership lease.
    pub(crate) const fn authorization(&self) -> &BrokerAuthorizationArtifactsV1 {
        &self.authorization
    }
}

/// Signs one current, zero-byte Controller source for the Storage audience.
///
/// The original Storage request ID comes from the authenticated session
/// coordinates. No service routes this body to Storage until same-session
/// Host proof and protected Storage writer admission are implemented.
///
/// # Errors
///
/// Rejects nonzero output, stale Controller owners, an absent or changed Host
/// settlement, expired source, missing Storage template, or signing failure.
#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_current_storage_output_reserve_v1<T>(
    controller: &mut Journal,
    assignment: &CurrentAssignmentTarget,
    environment_owner: &mut EnvironmentProtectedJournalOwnerV1<'_, '_>,
    parent: &ExecutionParentResourceSourceV1,
    preissue: &ControllerExecutionPreissueV1,
    signer: &ControllerBrokerPlanSignerV1,
    coordinates: DormantBrokerRequestCoordinatesV1,
    clock: &mut T,
) -> Result<SignedStorageOutputReserveV1, EffectFailure>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    if coordinates.request_id() == [0; 16]
        || coordinates.protocol_version() != ProtocolVersion::new(1, 0)
        || coordinates.audience() != Audience::AUDIENCE_NODE_CONTROLLER
        || coordinates.deadline_boottime_nanoseconds() > preissue.deadline_boottime_nanoseconds()
        || preissue.maximum_stdout_bytes() != 0
        || preissue.maximum_stderr_bytes() != 0
    {
        return Err(retryable(
            "Storage output reserve coordinates or mode are invalid",
        ));
    }

    let source = prepare_execution_reserve_source_v1(
        controller,
        assignment,
        environment_owner,
        parent,
        preissue,
        clock,
    )
    .map_err(|_| retryable("accepted Controller output source is unavailable"))?;
    let settlement = read_current_controller_output_settlement_v1(
        controller,
        assignment,
        preissue.execution(),
        preissue.create_operation(),
        clock,
    )
    .map_err(|_| retryable("authenticated Host output settlement is unavailable"))?
    .ok_or_else(|| retryable("authenticated Host output settlement is absent"))?;
    if settlement.original_attempt().source() != &source {
        return Err(retryable(
            "Host output settlement has another Controller source",
        ));
    }
    let attempt_bytes = settlement.original_attempt().canonical_bytes();
    let settlement_bytes = settlement.canonical_bytes();
    StorageOutputReserveRecordsV1::from_canonical_records(&attempt_bytes, &settlement_bytes)
        .map_err(|_| retryable("Storage output reserve records are not canonical"))?;

    let current = AuthorityPublicationStore::new(controller)
        .current(source.sandbox())
        .map_err(|_| retryable("current Storage authority is unavailable"))?
        .ok_or_else(|| retryable("current Storage authority is absent"))?;
    let publication = current.manifest();
    let broker_assignment = publication
        .broker_assignment()
        .map_err(|_| retryable("current Storage assignment is invalid"))?;
    if !current_output_assignment_matches(&current, &source, broker_assignment) {
        return Err(retryable("Storage output reserve assignment is stale"));
    }

    let sample = clock().map_err(|_| retryable("protected Controller clock is unavailable"))?;
    if sample.host_boot_id() != preissue.host_boot_id()
        || sample.boottime_nanoseconds() >= coordinates.deadline_boottime_nanoseconds()
        || sample.boottime_nanoseconds() >= preissue.deadline_boottime_nanoseconds()
    {
        return Err(retryable("Storage output reserve source expired"));
    }
    let body = ReserveStorageExecutionOutputRequestV1 {
        header: Some(coordinates.request_header()).into(),
        canonical_controller_attempt: attempt_bytes,
        canonical_controller_settlement: settlement_bytes.to_vec(),
        ..Default::default()
    }
    .encode_to_vec();
    let grant = storage_output_reserve_grant_v1(broker_assignment, coordinates.request_id(), &body)
        .map_err(|_| retryable("Storage output reserve grant is invalid"))?;
    let template = current
        .templates()
        .iter()
        .find(|candidate| candidate.audience() == BrokerAudience::Storage)
        .ok_or_else(|| retryable("current Storage authorization template is absent"))?;
    let parent_plan = template.plan();
    if parent_plan.assignment() != broker_assignment
        || parent_plan.node() != source.node()
        || parent_plan.protocol() != ProtocolId::StorageBroker
        || parent_plan.protocol_version() != ProtocolVersion::new(1, 0)
    {
        return Err(retryable("Storage output reserve template changed"));
    }
    let now = sample.wall_seconds();
    let expires = now
        .checked_add(30)
        .map(|limit| {
            limit
                .min(parent_plan.expires_seconds())
                .min(current.lease().lease().authority_expires_seconds())
        })
        .ok_or_else(|| retryable("Storage output reserve clock overflowed"))?;
    if now < parent_plan.issued_seconds() || expires <= now {
        return Err(retryable("Storage output reserve authority expired"));
    }
    let plan = output_plan(
        OutputPlanAudience::Storage, broker_assignment, source.node(),
        parent_plan, grant, now, expires,
    )
    .map_err(|_| retryable("Storage output reserve plan is invalid"))?;
    let signed = signer
        .sign_plan(plan, now)
        .map_err(|_| retryable("Storage output reserve signature is unavailable"))?;

    let reread = read_current_controller_output_settlement_v1(
        controller,
        assignment,
        preissue.execution(),
        preissue.create_operation(),
        clock,
    )
    .map_err(|_| retryable("Host output settlement changed after signing"))?;
    let final_source = prepare_execution_reserve_source_v1(
        controller,
        assignment,
        environment_owner,
        parent,
        preissue,
        clock,
    )
    .map_err(|_| retryable("accepted Controller source changed after signing"))?;
    let final_sample =
        clock().map_err(|_| retryable("protected Controller clock is unavailable"))?;
    if reread.as_ref() != Some(&settlement)
        || final_source != source
        || final_sample.host_boot_id() != preissue.host_boot_id()
        || final_sample.boottime_nanoseconds() >= coordinates.deadline_boottime_nanoseconds()
        || final_sample.wall_seconds() >= expires
    {
        return Err(retryable(
            "Storage output reserve source changed before send",
        ));
    }
    retain_controller_storage_output_reserve_attempt_v1(controller, &body, &signed)
        .map_err(|_| retryable("original Storage output attempt needs protected cold query"))?;
    Ok(SignedStorageOutputReserveV1 {
        body,
        authorization: BrokerAuthorizationArtifactsV1 {
            broker_plan: signed.canonical_plan().to_vec(),
            broker_plan_signature: signed.canonical_signature().to_vec(),
            ownership_lease: current.lease().canonical_lease().to_vec(),
            ownership_lease_signature: current.lease().canonical_signature().to_vec(),
            ..Default::default()
        },
    })
}

fn retryable(message: &'static str) -> EffectFailure {
    EffectFailure::Retryable(message.to_owned())
}

// Both issuers compare the same recovered publication/lease/source tuple.
// This is comparison DATA, not a detached currentness or signing permit.
fn current_output_assignment_matches(
    current: &CurrentAuthorityPublicationV1,
    source: &ControllerExecutionReserveSourceV1,
    assignment: BrokerAssignment,
) -> bool {
    let publication = current.manifest();
    let manifest = publication.manifest();
    let lease_assignment = current.lease().lease().assignment();
    !(manifest.sandbox() != source.sandbox()
        || manifest.incarnation() != source.incarnation()
        || manifest.node() != source.node()
        || manifest.epoch().get() != source.assignment_epoch()
        || manifest.desired_generation().get() != source.desired_generation()
        || manifest.namespace_generation().get() != source.namespace_generation()
        || publication.digest() != source.assignment_manifest_digest()
        || lease_assignment.sandbox() != assignment.sandbox()
        || lease_assignment.incarnation() != assignment.incarnation()
        || lease_assignment.epoch() != assignment.epoch()
        || lease_assignment.digest() != assignment.digest()
        || current.lease().lease().node() != source.node())
}

enum OutputPlanAudience {
    Storage,
    Host,
}

#[allow(clippy::too_many_arguments)]
fn output_plan(
    purpose: OutputPlanAudience,
    assignment: BrokerAssignment,
    node: aos_sandbox_core::NodeId,
    parent: &BrokerAuthorizationPlan,
    grant: BrokerGrant,
    now: i64,
    expires: i64,
) -> Result<BrokerAuthorizationPlan, InvalidBrokerAuthorizationPlan> {
    let (audience, protocol) = match purpose {
        OutputPlanAudience::Storage => (BrokerAudience::Storage, ProtocolId::StorageBroker),
        OutputPlanAudience::Host => (BrokerAudience::Host, ProtocolId::HostBroker),
    };
    BrokerAuthorizationPlan::new(
        audience,
        protocol,
        ProtocolVersion::new(1, 0),
        assignment,
        node,
        parent.ownership_authority().clone(),
        vec![grant],
        parent.policy_commitment(),
        parent.revocation_scope(),
        now,
        expires,
        Vec::new(),
    )
}

/// Keeps each returned original separately from the short issuer loan.
pub(super) struct OriginalStorageOutputIssuerV1 {
    started: bool,
    ended: bool,
    source: Option<Result<ControllerExecutionReserveSourceV1, ControllerExecutionReserveSourceErrorV1>>,
    settlement: Option<Result<Option<ProtectedControllerOutputSettlementV1>, ControllerExecutionOutputSettlementErrorV1>>,
    records: Option<Result<StorageOutputReserveRecordsV1, aos_sandbox_protocol::ProtocolValidationError>>,
    current: Option<Result<Option<CurrentAuthorityPublicationV1>, AuthorityPublicationError>>,
    assignment: Option<Result<BrokerAssignment, InvalidBrokerAuthorizationPlan>>,
    sample: Option<Result<RawPairedClockSample, ProtectedOwnershipClockError>>,
    body: Option<Vec<u8>>,
    grant: Option<Result<BrokerGrant, aos_sandbox_protocol::ProtocolValidationError>>,
    plan: Option<Result<BrokerAuthorizationPlan, InvalidBrokerAuthorizationPlan>>,
    signing_sample: Option<Result<RawPairedClockSample, ProtectedOwnershipClockError>>,
    signed: Option<Result<SignedBrokerPlan, ControllerBrokerPlanSignerError>>,
    reread: Option<Result<Option<ProtectedControllerOutputSettlementV1>, ControllerExecutionOutputSettlementErrorV1>>,
    final_source: Option<Result<ControllerExecutionReserveSourceV1, ControllerExecutionReserveSourceErrorV1>>,
    final_sample: Option<Result<RawPairedClockSample, ProtectedOwnershipClockError>>,
    append_entry_sample: Option<Result<RawPairedClockSample, ProtectedOwnershipClockError>>,
    pub(super) retained: Option<Result<ControllerStorageOutputReserveAttemptV1, ControllerStorageOutputReserveAttemptErrorV1>>,
    readback: Option<Result<Option<ControllerStorageOutputReserveAttemptV1>, ControllerStorageOutputReserveAttemptErrorV1>>,
    append_sample: Option<Result<RawPairedClockSample, ProtectedOwnershipClockError>>,
    postcheck_failure: Option<EffectFailure>,
    authorization: Option<BrokerAuthorizationArtifactsV1>,
    validation_failure: Option<EffectFailure>,
    completed: bool,
}

impl OriginalStorageOutputIssuerV1 {
    pub(super) fn empty() -> Self {
        Self {
            started: false, ended: false, source: None, settlement: None, records: None,
            current: None, assignment: None, sample: None, body: None,
            grant: None, plan: None, signing_sample: None, signed: None, reread: None,
            final_source: None, final_sample: None, append_entry_sample: None, retained: None, readback: None,
            append_sample: None, postcheck_failure: None,
            authorization: None, validation_failure: None, completed: false,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(error)) = &self.source { return Some(error); }
        if let Some(Err(error)) = &self.settlement { return Some(error); }
        if let Some(Err(error)) = &self.records { return Some(error); }
        if let Some(Err(error)) = &self.current { return Some(error); }
        if let Some(Err(error)) = &self.assignment { return Some(error); }
        if let Some(Err(error)) = &self.sample { return Some(error); }
        if let Some(Err(error)) = &self.grant { return Some(error); }
        if let Some(Err(error)) = &self.plan { return Some(error); }
        if let Some(Err(error)) = &self.signing_sample { return Some(error); }
        if let Some(Err(error)) = &self.signed { return Some(error); }
        if let Some(Err(error)) = &self.append_entry_sample { return Some(error); }
        if let Some(Err(error)) = &self.retained { return Some(error); }
        if let Some(error) = &self.validation_failure { return Some(error); }
        self.ended.then_some(&OutputIssuerEndedV1 as &dyn std::error::Error)
    }

    pub(super) fn postcheck_debt(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(error)) = &self.reread { return Some(error); }
        if let Some(Err(error)) = &self.final_source { return Some(error); }
        if let Some(Err(error)) = &self.final_sample { return Some(error); }
        if let Some(Err(error)) = &self.readback { return Some(error); }
        if let Some(Err(error)) = &self.append_sample { return Some(error); }
        self.postcheck_failure.as_ref().map(|error| error as &dyn std::error::Error)
    }

    pub(super) fn body(&self) -> Option<&[u8]> {
        self.completed.then_some(())?;
        self.body.as_deref()
    }

    pub(super) fn original_source(&self) -> Option<&ControllerExecutionReserveSourceV1> {
        self.source.as_ref()?.as_ref().ok()
    }

    pub(super) fn authorization(&self) -> Option<&BrokerAuthorizationArtifactsV1> {
        self.completed.then_some(())?;
        self.authorization.as_ref()
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn sign<T>(
        &mut self,
        controller: &mut Journal,
        assignment: &CurrentAssignmentTarget,
        environment: &mut EnvironmentProtectedJournalOwnerV1<'_, '_>,
        parent: &ExecutionParentResourceSourceV1,
        preissue: &ControllerExecutionPreissueV1,
        signer: &ControllerBrokerPlanSignerV1,
        coordinates: DormantBrokerRequestCoordinatesV1,
        clock: &mut T,
    ) where T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError> {
        if self.started { return; }
        self.started = true;
        let mut boundary = OriginalStorageIssuerBoundaryV1 { issuer: self, completed: false };
        let result = boundary.issuer.sign_inner(
            controller, assignment, environment, parent, preissue, signer, coordinates, clock,
        );
        if let Err(error) = result {
            if boundary.issuer.failure().is_none() && boundary.issuer.postcheck_debt().is_none() {
                boundary.issuer.validation_failure = Some(error);
            }
        }
        boundary.completed = boundary.issuer.completed;
    }

    #[allow(clippy::too_many_arguments)]
    fn sign_inner<T>(
        &mut self,
        controller: &mut Journal,
        assignment: &CurrentAssignmentTarget,
        environment: &mut EnvironmentProtectedJournalOwnerV1<'_, '_>,
        parent: &ExecutionParentResourceSourceV1,
        preissue: &ControllerExecutionPreissueV1,
        signer: &ControllerBrokerPlanSignerV1,
        coordinates: DormantBrokerRequestCoordinatesV1,
        clock: &mut T,
    ) -> Result<(), EffectFailure>
    where T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError> {
        let closed = || retryable("original captured Storage output issuer is closed");
        if coordinates.request_id() == [0; 16]
            || coordinates.protocol_version() != ProtocolVersion::new(1, 0)
            || coordinates.audience() != Audience::AUDIENCE_NODE_CONTROLLER
            || coordinates.deadline_boottime_nanoseconds() > preissue.deadline_boottime_nanoseconds()
        {
            return Err(closed());
        }
        self.source = Some(prepare_execution_reserve_source_v1(
            controller, assignment, environment, parent, preissue, clock,
        ));
        let source = self.source.as_ref().and_then(|result| result.as_ref().ok()).ok_or_else(closed)?;
        self.settlement = Some(read_current_controller_output_settlement_v1(
            controller, assignment, preissue.execution(), preissue.create_operation(), clock,
        ));
        let settlement = self.settlement.as_ref().and_then(|result| result.as_ref().ok())
            .and_then(Option::as_ref).ok_or_else(closed)?;
        if settlement.original_attempt().source() != source { return Err(closed()); }
        let attempt_bytes = settlement.original_attempt().canonical_bytes();
        let settlement_bytes = settlement.canonical_bytes();
        self.records = Some(StorageOutputReserveRecordsV1::from_canonical_captured_records(
            &attempt_bytes, &settlement_bytes,
        ));
        if self.records.as_ref().is_none_or(Result::is_err) { return Err(closed()); }
        self.current = Some(AuthorityPublicationStore::new(controller).current(source.sandbox()));
        let current = self.current.as_ref().and_then(|result| result.as_ref().ok())
            .and_then(Option::as_ref).ok_or_else(closed)?;
        self.assignment = Some(current.manifest().broker_assignment());
        let broker_assignment = *self.assignment.as_ref().and_then(|result| result.as_ref().ok()).ok_or_else(closed)?;
        if !current_output_assignment_matches(current, source, broker_assignment) { return Err(closed()); }

        self.sample = Some(clock());
        let sample = self.sample.as_ref().and_then(|result| result.as_ref().ok()).ok_or_else(closed)?;
        if sample.host_boot_id() != preissue.host_boot_id()
            || sample.boottime_nanoseconds() >= coordinates.deadline_boottime_nanoseconds()
            || sample.boottime_nanoseconds() >= preissue.deadline_boottime_nanoseconds()
        {
            return Err(closed());
        }
        let message = ReserveStorageExecutionOutputRequestV1 {
            header: Some(coordinates.request_header()).into(),
            canonical_controller_attempt: attempt_bytes,
            canonical_controller_settlement: settlement_bytes.to_vec(),
            ..Default::default()
        };
        if message.encoded_len() > 4096 { return Err(closed()); }
        self.body = Some(message.encode_to_vec());
        let body = self.body.as_deref().ok_or_else(closed)?;
        self.grant = Some(captured_storage_output_reserve_grant_v1(
            broker_assignment, coordinates.request_id(), body,
        ));
        let template = current.templates().iter()
            .find(|candidate| candidate.audience() == BrokerAudience::Storage).ok_or_else(closed)?;
        let parent_plan = template.plan();
        if parent_plan.assignment() != broker_assignment || parent_plan.node() != source.node()
            || parent_plan.protocol() != ProtocolId::StorageBroker
            || parent_plan.protocol_version() != ProtocolVersion::new(1, 0)
        {
            return Err(closed());
        }
        let now = sample.wall_seconds();
        let expires = now.checked_add(30).map(|limit| limit.min(parent_plan.expires_seconds())
            .min(current.lease().lease().authority_expires_seconds())).ok_or_else(closed)?;
        if now < parent_plan.issued_seconds() || expires <= now { return Err(closed()); }
        if !matches!(&self.grant, Some(Ok(_))) { return Err(closed()); }
        let Some(Ok(grant)) = self.grant.take() else { return Err(closed()); };
        self.plan = Some(output_plan(
            OutputPlanAudience::Storage, broker_assignment, source.node(), parent_plan, grant, now, expires,
        ));
        if !matches!(&self.plan, Some(Ok(_))) { return Err(closed()); }
        self.signing_sample = Some(clock());
        let signing_sample = self.signing_sample.as_ref().and_then(|result| result.as_ref().ok()).ok_or_else(closed)?;
        if signing_sample.host_boot_id() != preissue.host_boot_id()
            || signing_sample.boottime_nanoseconds() >= coordinates.deadline_boottime_nanoseconds()
            || signing_sample.wall_seconds() < now || signing_sample.wall_seconds() >= expires
        {
            return Err(closed());
        }
        let Some(Ok(plan)) = self.plan.take() else { return Err(closed()); };
        self.signed = Some(signer.sign_plan(plan, signing_sample.wall_seconds()));

        // Post-sign observers run even after an actual signing failure. Their
        // separate returned Results cannot replace the resident first cause.
        self.reread = Some(read_current_controller_output_settlement_v1(
            controller, assignment, preissue.execution(), preissue.create_operation(), clock,
        ));
        self.final_source = Some(prepare_execution_reserve_source_v1(
            controller, assignment, environment, parent, preissue, clock,
        ));
        self.final_sample = Some(clock());
        if self.reread.as_ref().and_then(|result| result.as_ref().ok()).and_then(Option::as_ref) != Some(settlement)
            || self.final_source.as_ref().and_then(|result| result.as_ref().ok()) != Some(source)
            || !self.final_sample.as_ref().and_then(|result| result.as_ref().ok()).is_some_and(|sample|
                sample.host_boot_id() == preissue.host_boot_id()
                && sample.boottime_nanoseconds() < coordinates.deadline_boottime_nanoseconds()
                && sample.wall_seconds() < expires)
        {
            return Err(closed());
        }
        let signed = self.signed.as_ref().and_then(|result| result.as_ref().ok()).ok_or_else(closed)?;
        self.append_entry_sample = Some(clock());
        if !self.append_entry_sample.as_ref().and_then(|result| result.as_ref().ok()).is_some_and(|sample|
            sample.host_boot_id() == preissue.host_boot_id()
            && sample.boottime_nanoseconds() < coordinates.deadline_boottime_nanoseconds()
            && sample.wall_seconds() >= now
            && sample.wall_seconds() < expires)
        {
            return Err(closed());
        }
        self.retained = Some(retain_captured_controller_storage_output_reserve_attempt_v1(
            controller, body, signed,
        ));
        self.readback = Some(aos_sandbox::controller_storage_output_reserve_attempt::load_captured_controller_storage_output_reserve_attempt_v1(
            controller, preissue.execution(),
        ));
        self.append_sample = Some(clock());
        if let Some(Ok(retained)) = &self.retained {
            if self.readback.as_ref().and_then(|result| result.as_ref().ok()).and_then(Option::as_ref) != Some(retained) {
                self.postcheck_failure = Some(closed());
            }
        }
        if !self.append_sample.as_ref().and_then(|result| result.as_ref().ok()).is_some_and(|sample|
            sample.host_boot_id() == preissue.host_boot_id()
            && sample.boottime_nanoseconds() < coordinates.deadline_boottime_nanoseconds()
            && sample.wall_seconds() < expires)
        {
            if self.postcheck_debt().is_none() { self.postcheck_failure = Some(closed()); }
        }
        if self.retained.as_ref().is_none_or(Result::is_err) { return Err(closed()); }
        if self.postcheck_debt().is_some() { return Err(closed()); }
        self.authorization = Some(BrokerAuthorizationArtifactsV1 {
            broker_plan: signed.canonical_plan().to_vec(),
            broker_plan_signature: signed.canonical_signature().to_vec(),
            ownership_lease: current.lease().canonical_lease().to_vec(),
            ownership_lease_signature: current.lease().canonical_signature().to_vec(),
            ..Default::default()
        });
        self.completed = true;
        Ok(())
    }
}

struct OriginalStorageIssuerBoundaryV1<'issuer> {
    issuer: &'issuer mut OriginalStorageOutputIssuerV1,
    completed: bool,
}

impl Drop for OriginalStorageIssuerBoundaryV1<'_> {
    fn drop(&mut self) {
        if !self.completed && self.issuer.failure().is_none() && self.issuer.postcheck_debt().is_none() {
            self.issuer.ended = true;
        }
    }
}

/// Retains the separate Host48 issuance, never a retagged Storage quartet.
pub(super) struct OriginalHostOutputIssuerV1 {
    started: bool,
    ended: bool,
    checked: Option<Result<aos_sandbox_protocol::host_storage_output_readback::ValidatedHostStorageOutputReadbackRequestV1, aos_sandbox_protocol::ProtocolValidationError>>,
    original: Option<Result<Option<ControllerStorageOutputReserveAttemptV1>, ControllerStorageOutputReserveAttemptErrorV1>>,
    current: Option<Result<Option<CurrentAuthorityPublicationV1>, AuthorityPublicationError>>,
    sample: Option<Result<RawPairedClockSample, ProtectedOwnershipClockError>>,
    grant: Option<Result<BrokerGrant, aos_sandbox_protocol::ProtocolValidationError>>,
    plan: Option<Result<BrokerAuthorizationPlan, InvalidBrokerAuthorizationPlan>>,
    signing_sample: Option<Result<RawPairedClockSample, ProtectedOwnershipClockError>>,
    signed: Option<Result<SignedBrokerPlan, ControllerBrokerPlanSignerError>>,
    reread: Option<Result<Option<ControllerStorageOutputReserveAttemptV1>, ControllerStorageOutputReserveAttemptErrorV1>>,
    final_sample: Option<Result<RawPairedClockSample, ProtectedOwnershipClockError>>,
    authorization: Option<BrokerAuthorizationArtifactsV1>,
    validation_failure: Option<EffectFailure>,
    completed: bool,
}

impl OriginalHostOutputIssuerV1 {
    pub(super) fn empty() -> Self {
        Self {
            started: false, ended: false, checked: None, original: None, current: None,
            sample: None, grant: None, plan: None, signing_sample: None, signed: None, reread: None,
            final_sample: None, authorization: None, validation_failure: None,
            completed: false,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(error)) = &self.checked { return Some(error); }
        if let Some(Err(error)) = &self.original { return Some(error); }
        if let Some(Err(error)) = &self.current { return Some(error); }
        if let Some(Err(error)) = &self.sample { return Some(error); }
        if let Some(Err(error)) = &self.grant { return Some(error); }
        if let Some(Err(error)) = &self.plan { return Some(error); }
        if let Some(Err(error)) = &self.signing_sample { return Some(error); }
        if let Some(Err(error)) = &self.signed { return Some(error); }
        if let Some(error) = &self.validation_failure { return Some(error); }
        self.ended.then_some(&OutputIssuerEndedV1 as &dyn std::error::Error)
    }

    pub(super) fn postcheck_debt(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(error)) = &self.reread { return Some(error); }
        if let Some(Err(error)) = &self.final_sample { return Some(error); }
        None
    }

    pub(super) fn authorization(&self) -> Option<&BrokerAuthorizationArtifactsV1> {
        self.completed.then_some(())?;
        self.authorization.as_ref()
    }

    pub(super) fn sign<T>(
        &mut self,
        controller: &mut Journal,
        storage: &OriginalStorageOutputIssuerV1,
        original_request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        nomination: &aos_proto::aos::sandbox::local::v1::StorageOutputRegistrationPreparationV1,
        signer: &ControllerBrokerPlanSignerV1,
        clock: &mut T,
    ) where T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError> {
        if self.started { return; }
        self.started = true;
        let mut boundary = OriginalHostIssuerBoundaryV1 { issuer: self };
        let result = boundary.issuer.sign_inner(controller, storage, original_request, nomination, signer, clock);
        if let Err(error) = result {
            if boundary.issuer.failure().is_none() && boundary.issuer.postcheck_debt().is_none() {
                boundary.issuer.validation_failure = Some(error);
            }
        }
    }

    fn sign_inner<T>(
        &mut self,
        controller: &mut Journal,
        storage: &OriginalStorageOutputIssuerV1,
        original_request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        nomination: &aos_proto::aos::sandbox::local::v1::StorageOutputRegistrationPreparationV1,
        signer: &ControllerBrokerPlanSignerV1,
        clock: &mut T,
    ) -> Result<(), EffectFailure>
    where T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError> {
        use aos_sandbox::controller_storage_output_reserve_attempt::load_captured_controller_storage_output_reserve_attempt_v1;
        use aos_sandbox_protocol::host_storage_output_readback::{
            captured_host_storage_output_readback_grant_v1,
            decode_captured_host_storage_output_readback_request_v1,
        };
        let closed = || retryable("original Host output issuer is closed");
        let Some(Ok(original)) = &storage.retained else { return Err(closed()); };
        let Some(Ok(source)) = &storage.source else { return Err(closed()); };
        let Some(Ok(assignment)) = &storage.assignment else { return Err(closed()); };
        if original_request.method() != aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT
            || !aos_sandbox_protocol::storage_output_reserve::continuation::matches_original_request_v1(nomination, original_request)
        {
            return Err(closed());
        }
        let body = nomination.canonical_host_readback_request.as_slice();
        self.sample = Some(clock());
        let sample = self.sample.as_ref().and_then(|result| result.as_ref().ok()).ok_or_else(closed)?;
        self.checked = Some(decode_captured_host_storage_output_readback_request_v1(
            body,
            original_request.peer(),
            // This is only the nominated body's closed audience comparison.
            // Kernel principal fields remain those of the genuine original
            // Storage peer; Host independently verifies its actual session.
            aos_sandbox_protocol::PeerPolicy {
                audience: Audience::AUDIENCE_STORAGE_BROKER,
                ..original_request.peer_policy()
            },
            sample.boottime_nanoseconds(),
        ));
        let checked = self.checked.as_ref().and_then(|result| result.as_ref().ok()).ok_or_else(closed)?;
        if !original.matches_host_readback(checked)
            || sample.host_boot_id() != source.preissue().host_boot_id()
            || checked.header().deadline_boottime_nanoseconds() > source.preissue().deadline_boottime_nanoseconds()
            || checked.header().deadline_boottime_nanoseconds() > original_request.deadline_boottime_nanoseconds()
        {
            return Err(closed());
        }
        self.original = Some(load_captured_controller_storage_output_reserve_attempt_v1(controller, original.execution()));
        if self.original.as_ref().and_then(|result| result.as_ref().ok()).and_then(Option::as_ref) != Some(original) {
            return Err(closed());
        }
        self.current = Some(AuthorityPublicationStore::new(controller).current(source.sandbox()));
        let current = self.current.as_ref().and_then(|result| result.as_ref().ok()).and_then(Option::as_ref).ok_or_else(closed)?;
        if !current_output_assignment_matches(current, source, *assignment) { return Err(closed()); }
        self.grant = Some(captured_host_storage_output_readback_grant_v1(*assignment, *checked.header().request_id(), body));
        let parent = current.templates().iter().find(|template| template.audience() == BrokerAudience::Host)
            .ok_or_else(closed)?.plan();
        if parent.assignment() != *assignment || parent.node() != source.node()
            || parent.protocol() != ProtocolId::HostBroker || parent.protocol_version() != ProtocolVersion::new(1, 0)
        {
            return Err(closed());
        }
        let now = sample.wall_seconds();
        let expires = now.checked_add(30).map(|limit| limit.min(parent.expires_seconds())
            .min(current.lease().lease().authority_expires_seconds())).ok_or_else(closed)?;
        if now < parent.issued_seconds() || expires <= now { return Err(closed()); }
        if !matches!(&self.grant, Some(Ok(_))) { return Err(closed()); }
        let Some(Ok(grant)) = self.grant.take() else { return Err(closed()); };
        self.plan = Some(output_plan(OutputPlanAudience::Host, *assignment, source.node(), parent, grant, now, expires));
        if !matches!(&self.plan, Some(Ok(_))) { return Err(closed()); }
        self.signing_sample = Some(clock());
        let signing_sample = self.signing_sample.as_ref().and_then(|result| result.as_ref().ok()).ok_or_else(closed)?;
        if signing_sample.host_boot_id() != source.preissue().host_boot_id()
            || signing_sample.boottime_nanoseconds() >= checked.header().deadline_boottime_nanoseconds()
            || signing_sample.wall_seconds() < now || signing_sample.wall_seconds() >= expires
        {
            return Err(closed());
        }
        let Some(Ok(plan)) = self.plan.take() else { return Err(closed()); };
        self.signed = Some(signer.sign_plan(plan, signing_sample.wall_seconds()));

        self.reread = Some(load_captured_controller_storage_output_reserve_attempt_v1(controller, original.execution()));
        self.final_sample = Some(clock());
        if self.reread.as_ref().and_then(|result| result.as_ref().ok()).and_then(Option::as_ref) != Some(original)
            || !self.final_sample.as_ref().and_then(|result| result.as_ref().ok()).is_some_and(|sample|
                sample.host_boot_id() == source.preissue().host_boot_id()
                && sample.boottime_nanoseconds() < checked.header().deadline_boottime_nanoseconds()
                && sample.wall_seconds() < expires)
        {
            return Err(closed());
        }
        let signed = self.signed.as_ref().and_then(|result| result.as_ref().ok()).ok_or_else(closed)?;
        self.authorization = Some(BrokerAuthorizationArtifactsV1 {
            broker_plan: signed.canonical_plan().to_vec(),
            broker_plan_signature: signed.canonical_signature().to_vec(),
            ownership_lease: current.lease().canonical_lease().to_vec(),
            ownership_lease_signature: current.lease().canonical_signature().to_vec(),
            ..Default::default()
        });
        self.completed = true;
        Ok(())
    }
}

struct OriginalHostIssuerBoundaryV1<'issuer> {
    issuer: &'issuer mut OriginalHostOutputIssuerV1,
}

impl Drop for OriginalHostIssuerBoundaryV1<'_> {
    fn drop(&mut self) {
        if !self.issuer.completed && self.issuer.failure().is_none() && self.issuer.postcheck_debt().is_none() {
            self.issuer.ended = true;
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("original output issuer ended without resetting its custody")]
struct OutputIssuerEndedV1;
