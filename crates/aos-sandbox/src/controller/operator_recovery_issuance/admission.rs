//! Atomic public Repair admission and original request custody.
//!
//! The candidate is authenticated wire evidence, not current authority. The
//! admission owner rejoins it to the actual protected publication and public
//! predecessor while the real public peer and Controller writer remain held.
//! The ordinary production recovery compiler remains qualification-gated.
//!
//! ```text
//! storage-repair-attempt-v1/<operation-id[16]>:
//! AOSORA01 | phase:u8 | zero[7] | operation[16] | public-digest[32]
//! storage-body-digest[32] | inventory-packet-digest[32]
//! envelope-length:u32be | exact original authorization envelope
//!
//! storage-repair-admission-inventory-v1/<operation-id[16]>:
//! actual request-id[16] | exact canonical authenticated Inventory packet
//! ```

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_core::{
    BrokerAudience, BrokerPlanExpectation, BrokerPlanRequest, BrokerPlanTrustAnchor, CapabilityId,
    DecodeLimits, OperationId, ProtocolId, ProtocolVersion, ResourceId, ResourceKind, SandboxId,
    Selector, verify_broker_plan,
};
use aos_sandbox_core::format::decode_signature;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use aos_sandbox_protocol::{PeerCredentials, PeerPolicy, decode_request_envelope};

use super::{
    ActivatedOperationCompiler, NodeController, OperatorRecoveryIssuanceErrorV1,
    PublicMutationRequestV1, SingleNodeEffectExecutor, hash, prepare_repair_issuance_v2,
    protected_query_roles,
};
use crate::controller::{ControllerServiceError, OperationCompilationError};
use crate::lifecycle::LifecycleAuthenticatedStorageInventoryV1;
use crate::public_api_session::PublicApiPeer;
use crate::{AcceptOutcome, Journal, JournalRecord, RecordNamespace};

mod draft;
pub use draft::{StorageRepairAdmissionDraftV1, StorageRepairAdmissionPreparationV1};

pub(super) const ATTEMPT_PREFIX: &[u8] = b"storage-repair-attempt-v1/";
pub(super) const INVENTORY_PREFIX: &[u8] = b"storage-repair-admission-inventory-v1/";
const MAGIC: &[u8; 8] = b"AOSORA01";
const PACKET_DOMAIN: &[u8] = b"aos.sandbox.operator-repair-admission-packet.v1\0";

/// Carries a signed Inventory and independently verified exact Storage grant.
///
/// This type does not keep Storage current. Admission checks its assignment,
/// lease, policy and exact request again against protected Controller state;
/// Storage independently verifies them before its existing physical worker.
pub struct StorageRepairAdmissionV1 {
    inventory: LifecycleAuthenticatedStorageInventoryV1,
    inventory_packet_digest: [u8; 32],
    inventory_request_id: [u8; 16],
    inventory_packet: Vec<u8>,
    envelope: Vec<u8>,
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime: u64,
    plan: aos_sandbox_core::VerifiedBrokerPlan,
}

impl StorageRepairAdmissionV1 {
    /// Validates the original wire request against a deployment-pinned plan anchor.
    ///
    /// The privileged caller obtains `inventory` from its actual retained broker
    /// session and `anchor` from fixed protected deployment credentials. Neither
    /// is supplied by the public Recover request.
    ///
    /// # Errors
    ///
    /// Rejects malformed or descriptor-bearing requests, unsupported Storage
    /// methods, invalid signatures, incomplete Inventory, and an uncovered grant.
    #[allow(clippy::too_many_arguments)]
    pub fn from_authenticated_inventory(
        inventory: &AuthenticatedBrokerMethodOutcomeV1,
        envelope: Vec<u8>,
        anchor: &BrokerPlanTrustAnchor,
        node: aos_sandbox_core::NodeId,
        peer: PeerCredentials,
        policy: PeerPolicy,
        now_wall_seconds: i64,
        now_boottime: u64,
    ) -> Result<Self, OperationCompilationError> {
        let request = decode_request_envelope(&envelope, ProtocolId::StorageBroker, 0)
            .map_err(|_| OperationCompilationError::Rejected)?;
        if request.method() != BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN
            || aos_sandbox_protocol::validate_request_descriptor_roles(&request, &[]).is_err()
        {
            return Err(OperationCompilationError::Rejected);
        }
        super::transport::validate_effect_envelope(
            aos_sandbox_protocol::operator_storage_repair_transport_v3::OperatorStorageRepairModeV3::Prepare,
            &envelope,
            request.body(),
        )
        .map_err(|_| OperationCompilationError::Rejected)?;
        let semantics = aos_sandbox_protocol::semantics::storage_repair::CanonicalStorageRepairSemanticsV1::decode(
            request.body(), peer, policy, now_boottime,
        )
        .map_err(|_| OperationCompilationError::Rejected)?;
        let fence = semantics.fence();
        let assignment = aos_sandbox_core::BrokerAssignment::new(
            SandboxId::from_bytes(*fence.sandbox_id()),
            aos_sandbox_core::IncarnationId::from_bytes(*fence.incarnation_id()),
            aos_sandbox_core::AssignmentEpoch::new(fence.assignment_epoch())
                .map_err(|_| OperationCompilationError::Rejected)?,
            aos_sandbox_core::DesiredGeneration::new(fence.desired_generation())
                .map_err(|_| OperationCompilationError::Rejected)?,
            aos_sandbox_core::ObjectDigest::from_bytes(*fence.assignment_digest()),
        )
        .map_err(|_| OperationCompilationError::Rejected)?;
        let artifacts = request
            .authorization()
            .ok_or(OperationCompilationError::Rejected)?;
        let signature = decode_signature(artifacts.broker_plan_signature(), DecodeLimits::default())
            .map_err(|_| OperationCompilationError::Rejected)?;
        let plan = verify_broker_plan(
            artifacts.broker_plan(),
            &signature,
            anchor,
            BrokerPlanExpectation {
                audience: BrokerAudience::Storage,
                protocol: ProtocolId::StorageBroker,
                protocol_version: ProtocolVersion::new(1, 0),
                assignment,
                node,
                now_seconds: now_wall_seconds,
            },
            DecodeLimits::default(),
        )
        .map_err(|_| OperationCompilationError::Rejected)?;
        plan.match_request(BrokerPlanRequest {
            verb: semantics.broker_verb(),
            target: semantics.grant_target(),
            argument_commitment: semantics.argument_commitment(),
            request_bytes: u32::try_from(request.body().len())
                .map_err(|_| OperationCompilationError::Rejected)?,
            descriptor_count: 0,
        })
        .map_err(|_| OperationCompilationError::Rejected)?;
        let inventory_body =
            LifecycleAuthenticatedStorageInventoryV1::from_authenticated_outcome(inventory)
                .map_err(|_| OperationCompilationError::Rejected)?;

        Ok(Self {
            inventory: inventory_body,
            inventory_packet_digest: hash(PACKET_DOMAIN, &[inventory.canonical_packet()]),
            inventory_request_id: inventory.request().request_id(),
            inventory_packet: inventory.canonical_packet().to_vec(),
            envelope,
            peer,
            policy,
            now_boottime,
            plan,
        })
    }
}

impl<C, E> NodeController<C, E>
where
    C: ActivatedOperationCompiler,
    E: SingleNodeEffectExecutor,
{
    /// Atomically admits Repair with its original signed issuance and request.
    ///
    /// This specialized source path does not open the qualification-gated normal
    /// public recovery compiler. It never substitutes a recovered caller for the
    /// live peer, and it performs no physical Storage dispatch.
    ///
    /// # Errors
    ///
    /// Rejects invalid public input, stale peer/capability/publication/current
    /// state, conflicting idempotency, unsafe role credentials or uncertain
    /// operation admission.
    pub fn admit_operator_storage_repair_v1(
        &mut self,
        peer: &PublicApiPeer,
        capability_id: CapabilityId,
        canonical_request: &[u8],
        candidate: StorageRepairAdmissionV1,
    ) -> Result<AcceptOutcome, ControllerServiceError> {
        let digest = self.checked_public_request_digest(peer, canonical_request)?;
        let plan = prepare_admission(
            self.reconciler.journal_mut(),
            peer,
            capability_id,
            canonical_request,
            digest,
            candidate,
        )
        .map_err(|_| OperationCompilationError::Rejected)?;

        peer.recheck().map_err(|_| OperationCompilationError::Rejected)?;
        self.accept_compiled_plan(plan, digest)
    }
}

fn prepare_admission(
    journal: &mut Journal,
    peer: &PublicApiPeer,
    capability_id: CapabilityId,
    canonical: &[u8],
    digest: [u8; 32],
    candidate: StorageRepairAdmissionV1,
) -> Result<crate::OperationPlan, OperatorRecoveryIssuanceErrorV1> {
    let public = PublicMutationRequestV1::decode(canonical)
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let public_request = super::decode_public_request(public.protobuf_body())?;
    let idempotency = crate::IdempotencyKey::new(public_request.idempotency_key().to_vec())
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    match journal.check_idempotency(&idempotency, digest) {
        crate::IdempotencyOutcome::Replay(operation) => {
            return crate::production_operation_compiler::compile_replayed_storage_repair_v1(
                journal, peer, capability_id, canonical, digest, operation,
            )
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding);
        }
        crate::IdempotencyOutcome::Conflict => return Err(OperatorRecoveryIssuanceErrorV1::Binding),
        crate::IdempotencyOutcome::Vacant => {}
    }
    let envelope = decode_request_envelope(&candidate.envelope, ProtocolId::StorageBroker, 0)
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let semantics = aos_sandbox_protocol::semantics::storage_repair::CanonicalStorageRepairSemanticsV1::decode(
        envelope.body(), candidate.peer, candidate.policy, candidate.now_boottime,
    )
    .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let operation = OperationId::from_bytes(semantics.operation_id());
    if journal.get(RecordNamespace::Operation, operation.as_bytes()).is_some() {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    let current = crate::AuthorityPublicationStore::new(journal)
        .current(SandboxId::from_bytes(public_request.resource_id()))
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?
        .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
    let assignment = current
        .manifest()
        .broker_assignment()
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let plan = candidate.plan.plan();
    let template = current
        .templates()
        .iter()
        .find(|template| template.audience() == BrokerAudience::Storage)
        .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
    let artifacts = envelope
        .authorization()
        .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
    if current.manifest().manifest().project() != peer.project()
        || plan.assignment() != assignment
        || plan.node() != current.manifest().manifest().node()
        || plan.ownership_authority() != template.plan().ownership_authority()
        || plan.policy_commitment() != template.plan().policy_commitment()
        || plan.revocation_scope() != template.plan().revocation_scope()
        || artifacts.ownership_lease() != current.lease().canonical_lease()
        || artifacts.ownership_lease_signature() != current.lease().canonical_signature()
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }

    let (signer, owner) = protected_query_roles()?;
    let prepared = prepare_repair_issuance_v2(
        journal,
        digest,
        &signer,
        peer,
        capability_id,
        operation,
        canonical,
        public.protobuf_body(),
        envelope.body(),
        candidate.peer,
        candidate.policy,
        candidate.now_boottime,
        &candidate.inventory,
    )?;
    owner.recheck()?;

    let attempt = original_attempt_record(
        operation,
        digest,
        envelope.body(),
        candidate.inventory_packet_digest,
        &candidate.envelope,
    )?;

    // Exact signed history shares admission's transaction. Its digest alone
    // cannot reconstruct typed authenticated evidence after process restart.
    let mut admission_inventory = candidate.inventory_request_id.to_vec();
    admission_inventory.extend_from_slice(&candidate.inventory_packet);
    let inventory_record = JournalRecord::put(
        RecordNamespace::OperatorRecovery,
        [INVENTORY_PREFIX, operation.as_bytes()].concat(),
        admission_inventory,
    );
    crate::production_operation_compiler::compile_prepared_storage_repair_v1(
        peer,
        canonical,
        digest,
        operation,
        prepared.accepted_wall_seconds,
        vec![prepared.current, prepared.issuance, attempt, inventory_record],
    )
    .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)
}

fn original_attempt_record(
    operation: OperationId,
    public_digest: [u8; 32],
    body: &[u8],
    inventory_digest: [u8; 32],
    envelope: &[u8],
) -> Result<JournalRecord, OperatorRecoveryIssuanceErrorV1> {
    let length = u32::try_from(envelope.len()).map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let mut bytes = Vec::with_capacity(132 + envelope.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
    bytes.extend_from_slice(operation.as_bytes());
    bytes.extend_from_slice(&public_digest);
    bytes.extend_from_slice(&hash(super::REQUEST_DOMAIN, &[body]));
    bytes.extend_from_slice(&inventory_digest);
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(envelope);
    Ok(JournalRecord::put(
        RecordNamespace::OperatorRecovery,
        [ATTEMPT_PREFIX, operation.as_bytes()].concat(),
        bytes,
    ))
}
