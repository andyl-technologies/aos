//! Production lowering for authenticated public controller mutations.
//!
//! Controller-local capability transitions are completed atomically in the
//! protected journal. Mutations that require placement, ownership, or broker
//! effects remain outside this local lowering path and must be supplied by the
//! assignment compiler rather than represented by a synthetic effect.

use aos_proto::aos::sandbox::v1::{Capability, ObjectDescriptor, Timestamp};
use aos_sandbox_core::{CapabilityId, CapabilityRecord, OperationId};
use sha2::{Digest as _, Sha256};

use crate::controller_service::public_projection::{
    PublicProjectionPlanV1, PublicProjectionResourceV1, PublicProjectionStoreV1,
};
use crate::public_mutation_compiler::AuthorizedPublicMutationRequestV1;
use crate::publisher_authority::{PublisherAuthorityLimits, PublisherCapabilityRegistry};
use crate::publisher_policy::{PublisherPolicyLimits, PublisherPolicyStore};
use crate::{
    ActivatedOperationCompiler, IdempotencyOutcome, Journal, OperationCompilationError,
    OperationPlan, PublicOperationAdmissionV1, PublicOperationAuthorizationV1,
};

const CAPABILITY_RESOURCE_VERSION_DOMAIN: &[u8] =
    b"aos.sandbox.public-capability-resource-version.v1\0";

/// Lowers authenticated public requests into durable production operation plans.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProductionOperationCompilerV1;

impl ActivatedOperationCompiler for ProductionOperationCompilerV1 {
    fn compile(
        &mut self,
        _journal: &mut Journal,
        _canonical_request: &[u8],
        _request_digest: [u8; 32],
    ) -> Result<OperationPlan, OperationCompilationError> {
        Err(OperationCompilationError::Rejected)
    }

    fn compile_public(
        &mut self,
        journal: &mut Journal,
        peer: &crate::public_api_session::PublicApiPeer,
        capability_id: CapabilityId,
        canonical_request: &[u8],
        request_digest: [u8; 32],
    ) -> Result<OperationPlan, OperationCompilationError> {
        let authorized = AuthorizedPublicMutationRequestV1::authorize(
            journal,
            peer,
            capability_id,
            canonical_request,
        )
        .map_err(|error| match error {
            crate::public_mutation_compiler::PublicMutationAuthorizationErrorV1::Malformed => {
                OperationCompilationError::Malformed
            }
            crate::public_mutation_compiler::PublicMutationAuthorizationErrorV1::Rejected => {
                OperationCompilationError::Rejected
            }
        })?;
        let request = authorized.request();
        let crate::cli_model::DormantSandboxRequestKindV1::CapabilityRevoke(revoke) =
            request.request()
        else {
            return Err(OperationCompilationError::Rejected);
        };
        let target = CapabilityId::from_bytes(
            revoke
                .capability_id
                .as_slice()
                .try_into()
                .map_err(|_| OperationCompilationError::Malformed)?,
        );
        let mutation = revoke
            .mutation
            .as_option()
            .ok_or(OperationCompilationError::Malformed)?;

        match journal.check_idempotency(request.idempotency_key(), request_digest) {
            IdempotencyOutcome::Replay(operation_id) => {
                return replay_capability_revoke(
                    journal,
                    operation_id,
                    target,
                    request.idempotency_key().clone(),
                    request_digest,
                );
            }
            IdempotencyOutcome::Conflict => return Err(OperationCompilationError::Rejected),
            IdempotencyOutcome::Vacant => {}
        }

        let (capability, authority_record) = {
            let registry =
                PublisherCapabilityRegistry::load(journal, PublisherAuthorityLimits::default())
                    .map_err(|_| OperationCompilationError::Rejected)?;
            let capability = registry
                .resolve_current(target)
                .map_err(|_| OperationCompilationError::Rejected)?;
            let authority_record = registry
                .prepare_revoke_from_trusted_controller(target)
                .map_err(|_| OperationCompilationError::Rejected)?;
            (capability, authority_record)
        };
        if capability.claims().project != peer.project() {
            return Err(OperationCompilationError::Rejected);
        }

        let policy = PublisherPolicyStore::load(journal, PublisherPolicyLimits::default())
            .map_err(|_| OperationCompilationError::Rejected)?
            .current_policy(peer.project())
            .map_err(|_| OperationCompilationError::Rejected)?
            .ok_or(OperationCompilationError::Rejected)?;
        if policy.descriptor().digest() != capability.claims().policy_digest {
            return Err(OperationCompilationError::Rejected);
        }

        let expected_version = capability_resource_version(&capability, false)?;
        if mutation.expected_resource_version != expected_version {
            return Err(OperationCompilationError::Rejected);
        }

        let operation_id = OperationId::new();
        let projection = capability_projection(&capability, policy.descriptor(), true)?;
        let projection = PublicProjectionPlanV1::new(
            peer.project(),
            operation_id,
            PublicProjectionResourceV1::Capability(projection),
        )
        .map_err(|_| OperationCompilationError::Rejected)?;
        let (desired_key, desired_value) = projection.into_desired_state();
        let plan = OperationPlan::completed_local(
            operation_id,
            request.idempotency_key().clone(),
            request_digest,
            desired_key,
            desired_value,
            vec![authority_record],
        )
        .map_err(|_| OperationCompilationError::Rejected)?;
        let authorization = PublicOperationAuthorizationV1::new(
            peer.project(),
            request.resource_kind(),
            request.selector().clone(),
        )
        .map_err(|_| OperationCompilationError::Rejected)?;
        let public = PublicOperationAdmissionV1::new(
            request.operation_method(),
            1,
            operation_id.into_bytes(),
            authorized.accepted_wall_seconds(),
            authorization,
        )
        .map_err(|_| OperationCompilationError::Rejected)?;

        plan.with_public_operation(public)
            .map_err(|_| OperationCompilationError::Rejected)
    }
}

fn replay_capability_revoke(
    journal: &mut Journal,
    operation_id: OperationId,
    capability_id: CapabilityId,
    idempotency_key: crate::IdempotencyKey,
    request_digest: [u8; 32],
) -> Result<OperationPlan, OperationCompilationError> {
    let projections = PublicProjectionStoreV1::new(journal)
        .list_operation(operation_id)
        .map_err(|_| OperationCompilationError::Rejected)?;
    let [projection] = projections.as_slice() else {
        return Err(OperationCompilationError::Rejected);
    };
    let PublicProjectionResourceV1::Capability(capability) = projection.resource() else {
        return Err(OperationCompilationError::Rejected);
    };
    if capability.capability_id.as_slice() != capability_id.as_bytes() || !capability.revoked {
        return Err(OperationCompilationError::Rejected);
    }
    let desired = PublicProjectionPlanV1::new(
        projection.project(),
        operation_id,
        projection.resource().clone(),
    )
    .map_err(|_| OperationCompilationError::Rejected)?;
    let authority_record =
        PublisherCapabilityRegistry::load(journal, PublisherAuthorityLimits::default())
            .and_then(|registry| registry.retained_record_for_atomic_replay(capability_id))
            .map_err(|_| OperationCompilationError::Rejected)?;
    let public = crate::reconciler::recovered_public_operation_admission_v1(journal, operation_id)
        .map_err(|_| OperationCompilationError::Rejected)?
        .ok_or(OperationCompilationError::Rejected)?;
    let (desired_key, desired_value) = desired.into_desired_state();

    OperationPlan::completed_local(
        operation_id,
        idempotency_key,
        request_digest,
        desired_key,
        desired_value,
        vec![authority_record],
    )
    .map_err(|_| OperationCompilationError::Rejected)?
    .with_public_operation(public)
    .map_err(|_| OperationCompilationError::Rejected)
}

fn capability_projection(
    capability: &CapabilityRecord,
    policy: &aos_sandbox_core::ObjectDescriptor,
    revoked: bool,
) -> Result<Capability, OperationCompilationError> {
    let claims = capability.claims();
    Ok(Capability {
        capability_id: claims.id.into_bytes().to_vec(),
        project_id: claims.project.into_bytes().to_vec(),
        sandbox_id: claims
            .sandbox
            .map_or_else(Vec::new, |sandbox| sandbox.into_bytes().to_vec()),
        holder_principal_id: claims.holder.into_bytes().to_vec(),
        resource_version: capability_resource_version(capability, revoked)?,
        not_before: Some(Timestamp {
            seconds: claims.not_before,
            nanoseconds: 0,
            ..Default::default()
        })
        .into(),
        expires_at: Some(Timestamp {
            seconds: claims.expires_at,
            nanoseconds: 0,
            ..Default::default()
        })
        .into(),
        remaining_delegation_depth: claims.delegation.remaining_depth(),
        maximum_fanout: claims.delegation.maximum_fanout(),
        revoked,
        effective_policy: Some(ObjectDescriptor {
            media_type: policy.media_type().as_str().to_owned(),
            sha256: policy.digest().as_bytes().to_vec(),
            encoded_size: policy.encoded_size(),
            ..Default::default()
        })
        .into(),
        ..Default::default()
    })
}

fn capability_resource_version(
    capability: &CapabilityRecord,
    revoked: bool,
) -> Result<Vec<u8>, OperationCompilationError> {
    let claims = serde_json::to_vec(capability).map_err(|_| OperationCompilationError::Rejected)?;
    let digest: [u8; 32] = Sha256::new()
        .chain_update(CAPABILITY_RESOURCE_VERSION_DOMAIN)
        .chain_update([u8::from(revoked)])
        .chain_update((claims.len() as u64).to_be_bytes())
        .chain_update(claims)
        .finalize()
        .into();
    Ok(digest.to_vec())
}
