//! Builds an unaccepted Delete operation from exact current graph preimages.
//!
//! This does not use the ordinary post-acceptance projection adapter. The
//! authenticated original request must name the actual current public version;
//! every selected expectation comes from the same retained graph predecessor.

use super::*;
use aos_sandbox_ledger_replay::delete_graph::{
    DeleteDependencyGraphDataV2, DeleteGraphSelectionDataV2,
};
use aos_sandbox_protocol::domain_ledger::delete_batch::native_value_digest;
use aos_sandbox_protocol::domain_ledger::provisioning_resources::ProvisioningResourceRowKindV1;
use crate::public_mutation_compiler::delete_admission::DeleteAuthorizationBindingV1;

#[derive(Debug, thiserror::Error)]
pub(crate) enum DeleteCandidateOperationErrorV2 {
    #[error(transparent)]
    Admission(#[from] LifecyclePublicMutationAdmissionErrorV1),
    #[error(transparent)]
    Operation(#[from] super::super::LifecyclePublicOperationErrorV1),
    #[error(transparent)]
    Model(#[from] LifecycleModelError),
    #[error("the bounded Delete expectation allocation failed: {0}")]
    Allocation(#[from] std::collections::TryReserveError),
}

// Only the genuine native candidate owner calls this after its full demand.
// Neither the operation nor this exact current-row comparison accepts Delete.
pub(crate) fn authorized_delete_operation_data_v2(
    authorization: &DeleteAuthorizationBindingV1<'_>,
    operation: OperationId,
    graph: &DeleteDependencyGraphDataV2,
    selection: &DeleteGraphSelectionDataV2,
) -> Result<LifecycleOperationV1, DeleteCandidateOperationErrorV2> {
    let invalid = || LifecyclePublicMutationAdmissionErrorV1::InvalidPredecessor;
    let authorized = authorization.authorization();
    let DormantSandboxRequestKindV1::Delete(request) = authorized.request().request() else {
        return Err(invalid().into());
    };
    let root = LifecycleResourceV1::Sandbox(selection.root);
    let original = graph.projections.iter().find(|row| row.resource == root)
        .ok_or_else(invalid)?;
    let PublicProjectionResourceV1::Sandbox(sandbox) = original.record.resource() else {
        return Err(invalid().into());
    };
    let mutation = mutation(request.mutation.as_option())?;
    if graph.project != authorized.project()
        || request.sandbox_id.as_slice() != selection.root.as_bytes()
        || mutation.expected_resource_version.as_slice() != sandbox.resource_version.as_slice()
    {
        return Err(invalid().into());
    }

    let mut expectations = Vec::new();
    expectations.try_reserve_exact(selection.resources.len())?;
    for resource in &selection.resources {
        let expectation = if let Some(row) = graph.projections.iter()
            .find(|row| row.resource == *resource)
        {
            current_expectation_data_v2(&row.record)?
        } else {
            let mut original = None;
            for companion in &graph.companions {
                let fields = companion.fields_v1();
                let kind = if *resource == LifecycleResourceV1::Other(fields.assignment) {
                    Some(ProvisioningResourceRowKindV1::Assignment)
                } else if *resource == LifecycleResourceV1::Other(fields.reservation) {
                    Some(ProvisioningResourceRowKindV1::Reservation)
                } else {
                    None
                };
                if let Some(kind) = kind {
                    if original.is_some() {
                        return Err(invalid().into());
                    }
                    original = Some(companion.encode_v1(kind));
                }
            }
            let original = original.ok_or_else(invalid)?;
            let digest = aos_sandbox_model::ObjectDigest::from_bytes(native_value_digest(&original));
            ResourceExpectationV1::present(*resource, Revision::new(1),
                LifecycleResourceStateDigestV1::from_stored(digest)?)?
        };
        expectations.push(expectation);
    }
    let expected = expectations.iter().find(|expectation| expectation.resource() == root)
        .ok_or_else(invalid)?;
    let ResourceExpectedStateV1::Present { revision, state_digest } = expected.expected() else {
        return Err(invalid().into());
    };
    let fence = DesiredStateFenceV1::new(root,
        DesiredGeneration::new(revision.get()), revision, state_digest)?;
    let admission = LifecyclePublicMutationAdmissionV1 {
        intent: LifecycleIntentV1::DeleteSandbox { sandbox: selection.root, fence },
        expectations,
    };
    super::super::lifecycle_operation_from_public_mutation_v1(
        operation, authorized.caller(), authorized.project(),
        authorized.accepted_wall_seconds(), authorization.input(),
        authorized.request().request(), admission,
    )?.select_delete_batch_layout().map_err(Into::into)
}

pub(crate) fn delete_candidate_projection_generation_data_v2(
    projection: &PublicProjectionRecordV1,
) -> Result<u64, LifecyclePublicMutationAdmissionErrorV1> {
    projection_generation(projection)
}
