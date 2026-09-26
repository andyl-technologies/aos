//! Controller Storage-audience signing for one zero-byte output reserve.
//!
//! This source consists of the existing protected AOSCIA01 and AOSCIS01
//! records. It cannot be sent by the current production Controller: original
//! Storage request custody, same-session Host proof, and Storage dispatch are
//! still closed. Signing establishes Controller issuance only.

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerAuthorizationArtifactsV1, ReserveStorageExecutionOutputRequestV1,
};
use aos_sandbox::controller_execution_output_settlement::read_current_controller_output_settlement_v1;
use aos_sandbox::controller_execution_preissue::{
    ControllerExecutionPreissueV1, prepare_execution_reserve_source_v1,
};
use aos_sandbox::environment::EnvironmentProtectedJournalOwnerV1;
use aos_sandbox::execution_parent_resource::ExecutionParentResourceSourceV1;
use aos_sandbox::ownership_authority::ProtectedOwnershipClockError;
use aos_sandbox::runtime_scope::CurrentAssignmentTarget;
use aos_sandbox::{AuthorityPublicationStore, EffectFailure, Journal};
use aos_sandbox_core::{
    BrokerAudience, BrokerAuthorizationPlan, ProtocolId, ProtocolVersion, RawPairedClockSample,
};
use aos_sandbox_protocol::storage_output_reserve::{
    StorageOutputReserveRecordsV1, storage_output_reserve_grant_v1,
};
use buffa::Message as _;

use crate::DormantBrokerRequestCoordinatesV1;
use crate::controller_plan_signer::ControllerBrokerPlanSignerV1;

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
/// coordinates. No service routes this body to Storage until the Host proof
/// and durable original-attempt recovery protocol are implemented.
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
    let manifest = publication.manifest();
    let lease_assignment = current.lease().lease().assignment();
    if manifest.sandbox() != source.sandbox()
        || manifest.incarnation() != source.incarnation()
        || manifest.node() != source.node()
        || manifest.epoch().get() != source.assignment_epoch()
        || manifest.desired_generation().get() != source.desired_generation()
        || manifest.namespace_generation().get() != source.namespace_generation()
        || publication.digest() != source.assignment_manifest_digest()
        || lease_assignment.sandbox() != broker_assignment.sandbox()
        || lease_assignment.incarnation() != broker_assignment.incarnation()
        || lease_assignment.epoch() != broker_assignment.epoch()
        || lease_assignment.digest() != broker_assignment.digest()
        || current.lease().lease().node() != source.node()
    {
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
    let plan = BrokerAuthorizationPlan::new(
        BrokerAudience::Storage,
        ProtocolId::StorageBroker,
        ProtocolVersion::new(1, 0),
        broker_assignment,
        source.node(),
        parent_plan.ownership_authority().clone(),
        vec![grant],
        parent_plan.policy_commitment(),
        parent_plan.revocation_scope(),
        now,
        expires,
        Vec::new(),
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
