//! Prepares exact unsigned Delete cleanup plans through canonical semantics.
//!
//! Root and Controller independently select the real protected resources and
//! current assignment before invoking this pure recipe. Nothing here supplies
//! a native owner, lease renewal, effect admission or signature. Mount Reap
//! uses its separate evidence-bearing canonical request recipe.

use std::error::Error;

use aos_proto::aos::sandbox::local::v1::{
    ApplyNetworkRequest, ApplyStorageRequest, AssignmentFence, Audience,
    BrokerMethod, NetworkAction, RequestHeader, StorageAction, PrepareStorageCatalogRequest,
};
use aos_sandbox_core::{
    BrokerAssignment, BrokerAudience, BrokerAuthorizationPlan, BrokerGrant,
    BrokerGrantTarget, BrokerResourceHandle, BrokerVerb, FeatureRef, ObjectDigest,
    OperationId, ProtocolId, ProtocolVersion, RawPairedClockSample, RevocationScopeId,
    ResourceDimension as D, ResourceVector,
};
use aos_sandbox_ownership_protocol::SignedOwnershipLease;
use buffa::Message as _;

use crate::semantics::{CatalogBindingV1, StorageOperation, StoragePreparationOperationV1};
use crate::semantics::network::NetworkOperation;
use super::{BrokerPlanPreparation, SigningAuthority};

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

/// Describes one cleanup operation using supplied nonauthorizing model DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeleteResourceRequestDataV2 {
    /// Resolves the exact non-destructive catalog needed by a later Destroy7.
    StoragePrepareDestroy {
        /// Names the existing workspace selected from current signed inventory.
        storage_handle: [u8; 32],
        /// Names an exact immutable version, or selects the workspace itself.
        version_handle: Option<[u8; 32]>,
        /// Binds the actual resolver inventory supplied by its genuine owner.
        inventory: CatalogBindingV1,
        /// Binds that owner's exact current catalog predecessor.
        expected_head: CatalogBindingV1,
        /// Preserves the unchanged absolute admitted preparation cutoff.
        preparation_expires_boottime_nanoseconds: u64,
    },

    /// Destroys one existing Storage workspace or exact immutable version.
    StorageDestroy {
        /// Names the existing workspace selected from current signed inventory.
        storage_handle: [u8; 32],
        /// Names an exact version, or selects the workspace itself.
        version_handle: Option<[u8; 32]>,
        /// Binds the actual current Storage publisher catalog.
        catalog: CatalogBindingV1,
    },
    /// Destroys one existing Network already selected by the cleanup graph.
    NetworkDestroy {
        /// Names the broker-owned network from current signed inventory.
        network_handle: [u8; 32],
    },
}

/// Retains exact unsigned preparation and its unarmed canonical request body.
pub struct DeleteResourcePlanPreparationDataV2 {
    method: BrokerMethod,
    body: Vec<u8>,
    preparation: BrokerPlanPreparation,
}

impl DeleteResourcePlanPreparationDataV2 {
    /// Bounds Mount62's complete nested Spec/request construction and signing.
    ///
    /// This adds the sole Mount decoder's complete bounded representation to
    /// the common plan/body invoice. Actual native callers pay before cloning
    /// Spec bytes, authority or request models.
    #[must_use]
    pub fn mount_receiving_demand_v4(authority: &SigningAuthority,
        ownership_signer: &aos_sandbox_core::model::KeyReference,
        specification_bytes: usize, descriptor_text_bytes: usize,
    ) -> Option<ResourceVector> {
        // Closed protobuf bound: two fences308, header121, descriptor92 plus
        // its text, action/generation30, Ready digest47 and Spec field15 plus
        // its bytes. Each tag/length/scalar uses its existing maximum width.
        let body = specification_bytes.checked_add(descriptor_text_bytes)?.checked_add(613)?;
        if body > crate::MAXIMUM_REQUEST_BYTES { return None; }
        Self::receiving_demand_v2(authority, ownership_signer)?
            .checked_add(crate::mount_attachment_anchor::attachment_anchor_request_decoding_demand_v4(
                body).ok()?).ok()
    }

    /// Returns the existing detached-signature producer and decoder ceiling.
    #[must_use]
    pub const fn maximum_artifact_bytes_v2() -> usize {
        super::MAXIMUM_SIGNATURE_ENVELOPE_BYTES
    }

    /// Bounds the closed producer's co-resident pure construction lanes.
    ///
    /// The sole wire decoder limits every request to `MAXIMUM_REQUEST_BYTES`.
    /// The generated requests here have only fixed-width identities/scalars and
    /// one fence; their semantic buffer, protobuf graph and encoded body share
    /// four such capacity lanes. A single grant, one fixed feature, two bounded
    /// key IDs and registered descriptor names fit the existing signature
    /// envelope ceiling. Eight ceiling lanes cover canonical plan, statement,
    /// signing message and the statement temporary, including Vec growth.
    /// Actual policy copies and key text are added from these borrowed owners.
    ///
    /// This is comparison cost DATA. The genuine caller pays before cloning
    /// the authority or constructing any body, plan, statement or message.
    #[must_use]
    pub fn receiving_demand_v2(authority: &SigningAuthority,
        ownership_signer: &aos_sandbox_core::model::KeyReference,
    ) -> Option<ResourceVector> {
        use std::mem::size_of;
        let body = crate::MAXIMUM_REQUEST_BYTES.checked_mul(4)?;
        let messages = aos_sandbox_core::crypto::signature_signing_message_bytes_v1(
            super::MAXIMUM_SIGNATURE_ENVELOPE_BYTES,
        )?.checked_mul(2)?;
        let artifacts = super::MAXIMUM_SIGNATURE_ENVELOPE_BYTES.checked_mul(6)?.checked_add(messages)?;
        let policy = authority.canonical_policy.len().checked_mul(2)?;
        let key_text = authority.signer.stable_key_id().as_str().len().checked_mul(4)?
            .checked_add(ownership_signer.stable_key_id().as_str().len().checked_mul(2)?)?;
        let descriptor_text = authority.policy_descriptor.media_type().as_str().len().checked_mul(3)?
            .checked_add(aos_sandbox_core::PortableMediaType::BrokerAuthorizationPlan.as_str().len())?;
        let feature = "aos.sandbox.authorization.signed-plan-lease".len();
        let bodies = size_of::<PrepareStorageCatalogRequest>()
            .checked_add(size_of::<ApplyStorageRequest>())?.checked_add(size_of::<ApplyNetworkRequest>())?;
        let carriers = size_of::<Self>().checked_add(size_of::<BrokerAuthorizationPlan>())?
            .checked_add(size_of::<BrokerGrant>())?.checked_add(size_of::<FeatureRef>())?
            .checked_add(size_of::<aos_sandbox_core::model::SignatureStatement>())?
            .checked_add(size_of::<super::PreparedArtifact>())?.checked_add(bodies)?.checked_mul(3)?;
        let bytes = body.checked_add(artifacts)?.checked_add(policy)?.checked_add(key_text)?
            .checked_add(descriptor_text)?.checked_add(feature)?.checked_add(carriers)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?))
    }

    /// Returns the sole existing broker method for this concrete operation.
    #[must_use]
    pub const fn method_v2(&self) -> BrokerMethod { self.method }

    /// Borrows the deadline-free body shared by template and actual dispatch.
    #[must_use]
    pub fn deadline_free_body_v2(&self) -> &[u8] { &self.body }

    /// Borrows the complete unsigned plan and signing statement.
    #[must_use]
    pub const fn preparation_v2(&self) -> &BrokerPlanPreparation { &self.preparation }
}

/// Prepares Mount62 through the existing exact attachment-anchor plan engine.
///
/// # Errors
/// Refuses a non-Reap request, changed cleanup lease or original horizon, or
/// any canonical Mount plan/body construction failure. No signature is issued.
#[allow(clippy::too_many_arguments)]
pub fn prepare_delete_mount_reap_plan_v4(
    request: &crate::mount_attachment_anchor::ValidatedAttachmentAnchorRequestV1,
    operation: OperationId,
    policy_digest: ObjectDigest,
    lease: &SignedOwnershipLease,
    sample: RawPairedClockSample,
    cutoff: u64,
    policy_expires: i64,
    authority: SigningAuthority,
    revocation_scope: RevocationScopeId,
) -> Result<DeleteResourcePlanPreparationDataV2> {
    require_mount_lease_v4(request, operation, lease)?;
    let request_id = *request.header().request_id();
    let body = request.deadline_free_request_body_v1(request_id)?;
    let preparation = super::mount_attachment_anchor_plan::prepare_attachment_anchor_plan_v1(
        request, policy_digest, lease, sample, cutoff, policy_expires, authority, revocation_scope)?
        .into_preparation_v2();
    Ok(DeleteResourcePlanPreparationDataV2 {
        method: BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1,
        body, preparation,
    })
}

/// Compares an admitted Mount62 through the same attachment-anchor engine.
///
/// # Errors
/// Refuses a changed Reap request, lease, signed policy horizon, canonical plan
/// or signing statement. The actual Controller loan separately admits signing.
#[allow(clippy::too_many_arguments)]
pub fn prepare_admitted_delete_mount_reap_plan_v4(
    request: &crate::mount_attachment_anchor::ValidatedAttachmentAnchorRequestV1,
    operation: OperationId,
    policy_digest: ObjectDigest,
    lease: &SignedOwnershipLease,
    sample: RawPairedClockSample,
    cutoff: u64,
    policy_expires: i64,
    authority: SigningAuthority,
    revocation_scope: RevocationScopeId,
    canonical_plan: &[u8],
    canonical_statement: &[u8],
) -> Result<DeleteResourcePlanPreparationDataV2> {
    require_mount_lease_v4(request, operation, lease)?;
    let maximum = super::storage_create_plan::plan_expiry_v1(sample, cutoff,
        policy_expires, lease.authority_expires_seconds())?;
    let preparation = super::mount_attachment_anchor_plan::prepare_admitted_attachment_anchor_plan_v1(
        request, policy_digest, lease, sample, cutoff, authority, revocation_scope,
        canonical_plan, canonical_statement)?;
    if preparation.plan_data_v1().expires_seconds() > maximum { return Err(Box::new(Changed)); }
    let body = request.deadline_free_request_body_v1(*request.header().request_id())?;
    Ok(DeleteResourcePlanPreparationDataV2 {
        method: BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1,
        body, preparation,
    })
}

fn require_mount_lease_v4(
    request: &crate::mount_attachment_anchor::ValidatedAttachmentAnchorRequestV1,
    operation: OperationId,
    lease: &SignedOwnershipLease,
) -> Result<()> {
    if request.action() != aos_proto::aos::sandbox::local::v1::AttachmentAnchorActionV1::ATTACHMENT_ANCHOR_ACTION_V1_REAP {
        return Err(Box::new(Changed));
    }
    require_lease_v2(request.fence().broker_assignment()?, operation,
        *request.header().request_id(), lease)
}

/// Prepares a concrete cleanup plan without issuing effect or signing authority.
///
/// The actual caller must fund this construction and independently prove that
/// the selected request belongs to its complete graph, current signed inventory
/// and live accepted Delete original. The verified lease must bind the current
/// cleanup assignment. A historical creation fence cannot replace that scope.
///
/// # Errors
/// Refuses zero identities, another lease assignment, expired original cutoff,
/// policy or lease, malformed resource handles or canonical signing failure.
#[allow(clippy::too_many_arguments)]
pub fn prepare_delete_resource_plan_v2(
    request: DeleteResourceRequestDataV2,
    assignment: BrokerAssignment,
    operation: OperationId,
    request_id: [u8; 16],
    policy_digest: ObjectDigest,
    lease: &SignedOwnershipLease,
    sample: RawPairedClockSample,
    cutoff: u64,
    policy_expires: i64,
    authority: SigningAuthority,
    revocation_scope: RevocationScopeId,
) -> Result<DeleteResourcePlanPreparationDataV2> {
    require_lease_v2(assignment, operation, request_id, lease)?;
    require_preparation_cutoff_v2(request, sample, cutoff)?;
    let expires = super::storage_create_plan::plan_expiry_v1(
        sample, cutoff, policy_expires, lease.authority_expires_seconds(),
    )?;
    prepare_at_v2(request, assignment, operation, request_id, policy_digest,
        lease, sample.wall_seconds(), expires, authority, revocation_scope)
}

/// Compares the exact independently admitted cleanup plan and signing statement.
///
/// No supplied bytes can construct a genuine Delete signing loan. The real
/// Controller signer calls this only while its actual pending/native/Root
/// borrower is current, after paying all canonical decoder and key backing.
///
/// # Errors
/// Refuses changed request, assignment, lease, policy, scope, time, plan or
/// statement, including a plan beyond the unchanged current policy expiry.
#[allow(clippy::too_many_arguments)]
pub fn prepare_admitted_delete_resource_plan_v2(
    request: DeleteResourceRequestDataV2,
    assignment: BrokerAssignment,
    operation: OperationId,
    request_id: [u8; 16],
    policy_digest: ObjectDigest,
    lease: &SignedOwnershipLease,
    sample: RawPairedClockSample,
    cutoff: u64,
    policy_expires: i64,
    authority: SigningAuthority,
    revocation_scope: RevocationScopeId,
    canonical_plan: &[u8],
    canonical_statement: &[u8],
) -> Result<DeleteResourcePlanPreparationDataV2> {
    require_lease_v2(assignment, operation, request_id, lease)?;
    require_preparation_cutoff_v2(request, sample, cutoff)?;
    let plan = aos_sandbox_core::format::decode_broker_authorization_plan(
        canonical_plan, aos_sandbox_core::DecodeLimits::default(),
    )?;
    super::storage_create_plan::require_admitted_clock_v1(
        sample, cutoff, plan.issued_seconds(), plan.expires_seconds(),
        lease.authority_issued_seconds(), lease.authority_expires_seconds(),
    )?;
    let maximum_expiry = super::storage_create_plan::plan_expiry_v1(
        sample, cutoff, policy_expires, lease.authority_expires_seconds(),
    )?;
    if plan.expires_seconds() > maximum_expiry { return Err(Box::new(Changed)); }
    let expected = prepare_at_v2(request, assignment, operation, request_id,
        policy_digest, lease, plan.issued_seconds(), plan.expires_seconds(), authority,
        revocation_scope)?;
    if expected.preparation.canonical_plan() != canonical_plan
        || expected.preparation.signing_request().canonical_statement() != canonical_statement
    { return Err(Box::new(Changed)); }
    Ok(expected)
}

#[allow(clippy::too_many_arguments)]
fn prepare_at_v2(
    request: DeleteResourceRequestDataV2, assignment: BrokerAssignment,
    operation: OperationId, request_id: [u8; 16], policy_digest: ObjectDigest,
    lease: &SignedOwnershipLease, issued: i64, expires: i64,
    authority: SigningAuthority, revocation_scope: RevocationScopeId,
) -> Result<DeleteResourcePlanPreparationDataV2> {
    prepare_plan_parts_v2(request, assignment, operation, request_id, policy_digest,
        lease.node(), lease.signer(), issued, expires, authority, revocation_scope)
}

#[allow(clippy::too_many_arguments)]
fn prepare_plan_parts_v2(request: DeleteResourceRequestDataV2, assignment: BrokerAssignment,
    operation: OperationId, request_id: [u8; 16], policy_digest: ObjectDigest,
    node: aos_sandbox_core::NodeId, ownership_signer: &aos_sandbox_core::model::KeyReference,
    issued: i64, expires: i64, authority: SigningAuthority, revocation_scope: RevocationScopeId,
) -> Result<DeleteResourcePlanPreparationDataV2> {
    let (method, audience, protocol, body, verb, target, commitment) =
        request_parts_v2(request, assignment, operation, request_id)?;
    let maximum = crate::dispatch_template::deadline_free_template_request_bytes_v1(&body)?;
    let grant = BrokerGrant::new(verb, target, commitment, u32::try_from(maximum)?, 0)?;
    let plan = BrokerAuthorizationPlan::new(audience, protocol, ProtocolVersion::new(1, 0),
        assignment, node, ownership_signer.clone(), vec![grant], policy_digest,
        revocation_scope, issued, expires,
        vec![FeatureRef::new("aos.sandbox.authorization.signed-plan-lease", 1, 0)?])?;
    let preparation = BrokerPlanPreparation::new(plan, authority)?;
    if body.len() > crate::MAXIMUM_REQUEST_BYTES
        || preparation.canonical_plan().len() > super::MAXIMUM_SIGNATURE_ENVELOPE_BYTES
        || preparation.signing_request().canonical_statement().len() > super::MAXIMUM_SIGNATURE_ENVELOPE_BYTES {
        return Err(Box::new(Changed));
    }
    Ok(DeleteResourcePlanPreparationDataV2 { method, body, preparation })
}

fn require_preparation_cutoff_v2(request: DeleteResourceRequestDataV2,
    sample: RawPairedClockSample, cutoff: u64,
) -> Result<()> {
    if let DeleteResourceRequestDataV2::StoragePrepareDestroy {
        preparation_expires_boottime_nanoseconds: expires, ..
    } = request {
        if expires <= sample.boottime_nanoseconds() || expires > cutoff {
            return Err(Box::new(Changed));
        }
    }
    Ok(())
}

fn require_lease_v2(assignment: BrokerAssignment, operation: OperationId,
    request_id: [u8; 16], lease: &SignedOwnershipLease,
) -> Result<()> {
    let current = lease.assignment();
    if operation.as_bytes() == &[0; 16] || request_id == [0; 16]
        || current.sandbox() != assignment.sandbox()
        || current.incarnation() != assignment.incarnation()
        || current.epoch() != assignment.epoch()
        || current.digest() != assignment.digest()
        || lease.desired_generation() != assignment.desired_generation()
    { return Err(Box::new(Changed)); }
    Ok(())
}

// Only existing-resource cleanup and its non-destructive catalog resolution
// are selected. Resource creation/clone/quota cannot enter through this recipe.
fn request_parts_v2(request: DeleteResourceRequestDataV2, assignment: BrokerAssignment,
    operation: OperationId, request_id: [u8; 16],
) -> Result<(BrokerMethod, BrokerAudience, ProtocolId, Vec<u8>, BrokerVerb,
    BrokerGrantTarget, aos_sandbox_core::BrokerArgumentCommitment)> {
    let maximum_response_bytes = match request {
        DeleteResourceRequestDataV2::StoragePrepareDestroy { .. } => u32::try_from(
            crate::semantics::storage_prepare::storage_catalog_preparation_response_body_bound_v1(),
        )?,
        DeleteResourceRequestDataV2::StorageDestroy { .. }
        | DeleteResourceRequestDataV2::NetworkDestroy { .. } => 4096,
    };
    let header = Some(RequestHeader {
        protocol_major: 1, protocol_minor: 0,
        request_id: request_id.to_vec(), audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
        deadline_boottime_nanoseconds: 0, maximum_response_bytes,
        ..Default::default()
    }).into();
    let fence = Some(AssignmentFence {
        sandbox_id: assignment.sandbox().as_bytes().to_vec(),
        incarnation_id: assignment.incarnation().as_bytes().to_vec(),
        assignment_epoch: assignment.epoch().get(),
        desired_generation: assignment.desired_generation().get(),
        assignment_digest: assignment.digest().as_bytes().to_vec(),
        ..Default::default()
    }).into();
    match request {
        DeleteResourceRequestDataV2::StoragePrepareDestroy { storage_handle, version_handle,
            inventory, expected_head, preparation_expires_boottime_nanoseconds: expires } => {
            let meaning = StoragePreparationOperationV1::Destroy { storage_handle, version_handle };
            let commitment = meaning.persisted_cleanup_argument_commitment_v2(assignment,
                operation, inventory, expected_head, expires)?;
            let body = PrepareStorageCatalogRequest { header, fence,
                action: StorageAction::STORAGE_ACTION_DESTROY.into(),
                operation_id: operation.as_bytes().to_vec(), storage_handle: storage_handle.to_vec(),
                source_version_handle: version_handle.map_or_else(Vec::new, |handle| handle.to_vec()),
                inventory_generation: inventory.generation(), inventory_digest: inventory.digest().as_bytes().to_vec(),
                expected_catalog_generation: expected_head.generation(),
                expected_catalog_digest: expected_head.digest().as_bytes().to_vec(),
                preparation_expires_boottime_nanoseconds: expires, ..Default::default()
            }.encode_to_vec();
            Ok((BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG, BrokerAudience::Storage,
                ProtocolId::StorageBroker, body, BrokerVerb::StoragePrepareCatalog,
                BrokerGrantTarget::Assignment, commitment))
        }
        DeleteResourceRequestDataV2::StorageDestroy { storage_handle, version_handle, catalog } => {
            if version_handle == Some([0; 32]) { return Err(Box::new(Changed)); }
            let meaning = StorageOperation::Destroy { storage_handle, version_handle };
            let commitment = meaning.persisted_argument_commitment(assignment,
                operation.into_bytes(), catalog)?;
            let body = ApplyStorageRequest { header, fence,
                action: StorageAction::STORAGE_ACTION_DESTROY.into(),
                operation_id: operation.as_bytes().to_vec(), storage_handle: storage_handle.to_vec(),
                source_version_handle: version_handle.map_or_else(Vec::new, |handle| handle.to_vec()),
                ..Default::default()
            }.encode_to_vec();
            Ok((BrokerMethod::BROKER_METHOD_STORAGE_APPLY, BrokerAudience::Storage,
                ProtocolId::StorageBroker, body, meaning.broker_verb(), meaning.grant_target()?, commitment))
        }
        DeleteResourceRequestDataV2::NetworkDestroy { network_handle } => {
            let meaning = NetworkOperation::Destroy { network_handle };
            let commitment = meaning.persisted_cleanup_argument_commitment_v2(assignment)?;
            let target = BrokerGrantTarget::Resource(BrokerResourceHandle::from_bytes(network_handle)?);
            let body = ApplyNetworkRequest { header, fence,
                action: NetworkAction::NETWORK_ACTION_DESTROY.into(),
                network_handle: network_handle.to_vec(), ..Default::default()
            }.encode_to_vec();
            Ok((BrokerMethod::BROKER_METHOD_NETWORK_APPLY, BrokerAudience::Network,
                ProtocolId::NetworkBroker, body, meaning.broker_verb(), target, commitment))
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("the current Delete cleanup assignment, resource or plan differs")]
struct Changed;

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::{AssignmentEpoch, DesiredGeneration, IncarnationId, SandboxId};
    use crate::{PeerCredentials, PeerPolicy};
    use crate::semantics::{CanonicalStorageSemanticsV1};
    use crate::semantics::network::CanonicalNetworkSemanticsV1;

    fn assignment() -> BrokerAssignment {
        BrokerAssignment::new(SandboxId::from_bytes([2; 16]),
            IncarnationId::from_bytes([3; 16]), AssignmentEpoch::new(4),
            DesiredGeneration::new(5), ObjectDigest::from_bytes([6; 32])).unwrap()
    }

    fn peer() -> (PeerCredentials, PeerPolicy) {
        (PeerCredentials { uid: 800, gid: 800, pid: Some(123) },
            PeerPolicy { uid: 800, gid: Some(800), audience: Audience::AUDIENCE_NODE_CONTROLLER })
    }

    #[test]
    fn cleanup_storage_body_and_live_parser_use_exact_same_catalog_and_scope() {
        let catalog = CatalogBindingV1::from_publisher(8, ObjectDigest::from_bytes([9; 32])).unwrap();
        for version_handle in [None, Some([10; 32])] {
            let request = DeleteResourceRequestDataV2::StorageDestroy {
                storage_handle: [7; 32], version_handle, catalog,
            };
            let (method, _, _, body, verb, target, commitment) = request_parts_v2(
                request, assignment(), OperationId::from_bytes([11; 16]), [12; 16]).unwrap();
            assert!(crate::dispatch_template::validate_durable_deadline_free_body(&body));
            let armed = crate::dispatch_template::inject_deadline(&body, 200).unwrap();
            let (peer, policy) = peer();
            let live = CanonicalStorageSemanticsV1::decode(&armed, catalog, peer, policy, 100).unwrap();

            assert_eq!(method, BrokerMethod::BROKER_METHOD_STORAGE_APPLY);
            assert_eq!(verb, BrokerVerb::StorageDestroy);
            assert_eq!(live.broker_verb(), verb);
            assert_eq!(live.grant_target(), target);
            assert_eq!(live.argument_commitment(), commitment);
            assert_eq!(live.operation(), StorageOperation::Destroy {
                storage_handle: [7; 32], version_handle,
            });
            let changed_catalog = CatalogBindingV1::from_publisher(9, ObjectDigest::from_bytes([9; 32])).unwrap();
            let changed = CanonicalStorageSemanticsV1::decode(&armed, changed_catalog, peer, policy, 100).unwrap();
            assert_ne!(changed.argument_commitment(), commitment);
        }
    }

    #[test]
    fn preparation_and_destructive_apply_have_distinct_canonical_plans() {
        let inventory = CatalogBindingV1::from_publisher(8, ObjectDigest::from_bytes([9; 32])).unwrap();
        let head = CatalogBindingV1::from_publisher(10, ObjectDigest::from_bytes([11; 32])).unwrap();
        let request = DeleteResourceRequestDataV2::StoragePrepareDestroy {
            storage_handle: [7; 32], version_handle: None, inventory, expected_head: head,
            preparation_expires_boottime_nanoseconds: 180,
        };
        let (method, _, _, body, verb, target, commitment) = request_parts_v2(
            request, assignment(), OperationId::from_bytes([12; 16]), [13; 16]).unwrap();
        let armed = crate::dispatch_template::inject_deadline(&body, 200).unwrap();
        let (peer, policy) = peer();
        let live = crate::semantics::CanonicalStoragePreparationSemanticsV1::decode(&armed, peer, policy, 100).unwrap();

        assert_eq!(method, BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG);
        assert_eq!(verb, BrokerVerb::StoragePrepareCatalog);
        assert_eq!(target, BrokerGrantTarget::Assignment);
        assert_eq!(live.argument_commitment(), commitment);
        assert_eq!(live.operation(), StoragePreparationOperationV1::Destroy {
            storage_handle: [7; 32], version_handle: None,
        });
        let (_, _, _, _, apply_verb, _, apply_commitment) = request_parts_v2(
            DeleteResourceRequestDataV2::StorageDestroy { storage_handle: [7; 32], version_handle: None, catalog: head },
            assignment(), OperationId::from_bytes([12; 16]), [13; 16]).unwrap();
        assert_eq!(apply_verb, BrokerVerb::StorageDestroy);
        assert_ne!(apply_commitment, commitment);
    }

    #[test]
    fn cleanup_network_body_delegates_the_live_existing_resource_encoder() {
        let request = DeleteResourceRequestDataV2::NetworkDestroy { network_handle: [7; 32] };
        let (method, _, _, body, verb, target, commitment) = request_parts_v2(
            request, assignment(), OperationId::from_bytes([11; 16]), [12; 16]).unwrap();
        let armed = crate::dispatch_template::inject_deadline(&body, 200).unwrap();
        let (peer, policy) = peer();
        let live = CanonicalNetworkSemanticsV1::decode(&armed, peer, policy, 100).unwrap();

        assert_eq!(method, BrokerMethod::BROKER_METHOD_NETWORK_APPLY);
        assert_eq!(verb, BrokerVerb::NetworkDestroy);
        assert_eq!(live.broker_method_v2(), method);
        assert_eq!(live.broker_verb(), verb);
        assert_eq!(live.grant_target(), target);
        assert_eq!(live.argument_commitment(), commitment);
        assert!(NetworkOperation::Prepare { endpoint_ids: Vec::new() }
            .persisted_cleanup_argument_commitment_v2(assignment()).is_err());
    }

    #[test]
    fn longest_closed_cleanup_shape_fits_the_named_producer_lanes() {
        use aos_sandbox_core::model::{KeyReference, KeyUsage, SignaturePurpose, StableKeyId};
        use aos_sandbox_core::{NodeId, ResourceDimension};
        use ed25519_dalek::SigningKey;

        let signer_name = "k".repeat(255);
        let authority = super::super::tests::authority(&signer_name,
            SignaturePurpose::BrokerAuthorization, &SigningKey::from_bytes(&[29; 32]), 30);
        let ownership_signer = KeyReference::new(StableKeyId::new("o".repeat(255)).unwrap(), u64::MAX,
            ObjectDigest::from_bytes([31; 32]), KeyUsage::OwnershipLease);
        let demand = DeleteResourcePlanPreparationDataV2::receiving_demand_v2(&authority, &ownership_signer).unwrap();
        let assignment = BrokerAssignment::new(SandboxId::from_bytes([32; 16]),
            IncarnationId::from_bytes([33; 16]), AssignmentEpoch::new(u64::MAX),
            DesiredGeneration::new(u64::MAX), ObjectDigest::from_bytes([34; 32])).unwrap();
        let predecessor = CatalogBindingV1::from_publisher(u64::MAX, ObjectDigest::from_bytes([35; 32])).unwrap();
        let request = DeleteResourceRequestDataV2::StoragePrepareDestroy {
            storage_handle: [36; 32], version_handle: Some([37; 32]), inventory: predecessor,
            expected_head: predecessor, preparation_expires_boottime_nanoseconds: u64::MAX,
        };
        let prepared = prepare_plan_parts_v2(request, assignment, OperationId::from_bytes([38; 16]),
            [39; 16], ObjectDigest::from_bytes([40; 32]), NodeId::from_bytes([41; 16]),
            &ownership_signer, i64::MIN, i64::MAX, authority, RevocationScopeId::from_bytes([42; 16])).unwrap();

        let plan = &prepared.preparation;
        let body = PrepareStorageCatalogRequest::decode_from_slice(&prepared.body).unwrap();
        assert_eq!(body.header.as_option().unwrap().maximum_response_bytes as usize,
            crate::semantics::storage_prepare::storage_catalog_preparation_response_body_bound_v1());
        assert!(prepared.body.len() < crate::MAXIMUM_REQUEST_BYTES);
        assert!(plan.canonical_plan().len() < super::super::MAXIMUM_SIGNATURE_ENVELOPE_BYTES);
        assert!(plan.signing_request().canonical_statement().len() < super::super::MAXIMUM_SIGNATURE_ENVELOPE_BYTES);
        assert!(plan.signing_request().signing_message().len()
            < super::super::MAXIMUM_SIGNATURE_ENVELOPE_BYTES);
        let resident = prepared.body.len() + plan.canonical_plan().len()
            + plan.signing_request().canonical_statement().len() + plan.signing_request().signing_message().len();
        assert!(demand.get(ResourceDimension::MemoryBytes) >= resident as u64);
        assert_eq!(demand.get(ResourceDimension::MetadataEntries), 0);
    }

    #[test]
    fn zero_cleanup_handles_never_produce_unsigned_request_grants() {
        let catalog = CatalogBindingV1::from_publisher(8, ObjectDigest::from_bytes([9; 32])).unwrap();
        for request in [
            DeleteResourceRequestDataV2::StorageDestroy { storage_handle: [0; 32], version_handle: None, catalog },
            DeleteResourceRequestDataV2::StorageDestroy { storage_handle: [7; 32], version_handle: Some([0; 32]), catalog },
            DeleteResourceRequestDataV2::NetworkDestroy { network_handle: [0; 32] },
        ] {
            assert!(request_parts_v2(request, assignment(), OperationId::from_bytes([11; 16]), [12; 16]).is_err());
        }
    }
}
