//! Joins the sole resource codec to existing accepted operation/gate history.
//!
//! This remains historical DATA validation. It uses the canonical existing
//! Effect, public request, OwnershipGate and Runtime pending decoders; it does
//! not authenticate Root signatures or infer current Native authority.

use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_model::{BrokerVerb, ObjectDigest, RecordNamespace};
use sha2::{Digest as _, Sha256};

use super::{
    ProvisioningModeDataV1, ProvisioningResourceDataErrorV1, ProvisioningResourceRecordsV1,
    ProvisioningResourceRowKindV1, State, decode_provisioning_resource_row_v1,
    provisioning_public_request_digest_v1, validate_provisioning_resource_state_v1,
};
use crate::domain_ledger::effect_history::{EffectHistoryDataError, decode_effect};
use crate::domain_ledger::operation::{decode_operation, effect_key};
use crate::domain_ledger::ownership_gate::{OwnershipGateDataErrorV1, OwnershipGatePlanV1, decode_ownership_gate};
use crate::domain_ledger::public_operation::PublicOperationDataError;
use crate::domain_ledger::runtime_authority_history::{
    RuntimeAuthorityDataErrorV1, crosslinks::gate_plan, decode_pending,
    ledger_read::pending_key,
};
use crate::public_api::{PublicOperationMethodV1, request::DormantSandboxRequestKindV1};

/// Retains the sole decoder refusal selected by historical cross-link validation.
#[derive(Debug, thiserror::Error)]
pub enum ProvisioningResourceLinkErrorV1 {
    /// A recognized companion row is malformed or incomplete.
    #[error(transparent)]
    Resources(#[from] ProvisioningResourceDataErrorV1),
    /// The canonical parent Effect decoder refused its stored input.
    #[error(transparent)]
    Effect(#[from] EffectHistoryDataError),
    /// The canonical Operation decoder refused its stored input.
    #[error(transparent)]
    Operation(#[from] PublicOperationDataError),
    /// The canonical gate decoder refused its stored input.
    #[error(transparent)]
    Gate(#[from] OwnershipGateDataErrorV1),
    /// The canonical pending binding decoder refused its stored input.
    #[error(transparent)]
    Runtime(#[from] RuntimeAuthorityDataErrorV1),
    /// Existing rows name another parent, child, request or publication.
    #[error("provisioning resource historical cross-links differ")]
    Mismatch,
}

/// Validates complete companions against their existing accepted parent and gate.
///
/// Native callers must prepay the existing complete Effect, public request,
/// assignment and publication decoder peaks before entry. This historical pass
/// neither accepts a new operation nor proves native currentness or workspace
/// completion. Prior immutable records remain valid after later public progress.
///
/// # Errors
/// Retains the first existing decoder error or reports an absent/mismatched
/// parent, internal operation, full public request, gate or pending manifest.
pub fn validate_provisioning_resource_links_v1(state: &State)
    -> Result<(), ProvisioningResourceLinkErrorV1>
{
    validate_provisioning_resource_state_v1(state)?;
    for ((namespace, key), value) in state {
        if *namespace != RecordNamespace::DesiredState { continue; }
        if let Some((ProvisioningResourceRowKindV1::Parent, records)) =
            decode_provisioning_resource_row_v1(key, value)?
        {
            validate_parent_and_gate(state, records)?;
        }
    }
    Ok(())
}

fn validate_parent_and_gate(state: &State, records: ProvisioningResourceRecordsV1)
    -> Result<(), ProvisioningResourceLinkErrorV1>
{
    let fields = records.fields_v1();
    let parent = decode_operation(record(state, RecordNamespace::Operation, fields.parent.as_bytes())?)?;
    let expected_method = match fields.mode {
        ProvisioningModeDataV1::CreateStopped => PublicOperationMethodV1::CreateSandbox,
        ProvisioningModeDataV1::StartRunning => PublicOperationMethodV1::StartSandbox,
    };
    if parent.effect_count() != 1
        || parent.public_operation().is_none_or(|metadata| metadata.method() != expected_method)
    {
        return Err(ProvisioningResourceLinkErrorV1::Mismatch);
    }
    let parent_effect = decode_effect(record(state, RecordNamespace::Effect, &effect_key(fields.parent, 0))?)?;
    let context = parent_effect.plan().public_mutation_context()?
        .ok_or(ProvisioningResourceLinkErrorV1::Mismatch)?;
    let request = context.validated_request()?;
    if context.project() != fields.project
        || provisioning_public_request_digest_v1(context.canonical_request()) != fields.public_request
        || !matches!((fields.mode, request),
            (ProvisioningModeDataV1::CreateStopped, DormantSandboxRequestKindV1::Create(_))
            | (ProvisioningModeDataV1::StartRunning, DormantSandboxRequestKindV1::Start(_)))
    {
        return Err(ProvisioningResourceLinkErrorV1::Mismatch);
    }

    let child = decode_operation(record(state, RecordNamespace::Operation,
        fields.publication_operation.as_bytes())?)?;
    if !child.ownership_gated() || child.runtime_intent_digest().is_none()
        || child.public_operation().is_some()
    {
        return Err(ProvisioningResourceLinkErrorV1::Mismatch);
    }
    let pending = decode_pending(record(state, RecordNamespace::RuntimeAuthority,
        &pending_key(fields.publication_operation))?)?;
    let manifest = pending.manifest();
    if pending.operation() != fields.publication_operation
        || manifest.digest() != fields.manifest
        || manifest.manifest().sandbox() != fields.sandbox
        || manifest.manifest().project() != fields.project
        || manifest.manifest().epoch() != fields.epoch
        || pending.source_draft_digest() != fields.source_draft
    {
        return Err(ProvisioningResourceLinkErrorV1::Mismatch);
    }
    let gate = decode_ownership_gate(record(state, RecordNamespace::OwnershipGate,
        fields.publication_operation.as_bytes())?)?;
    let gate = gate_plan(&gate);
    if gate.publication_draft().manifest() != manifest {
        return Err(ProvisioningResourceLinkErrorV1::Mismatch);
    }
    require_provisioning_publication_gate_v1(records, gate)
}

/// Compares one typed companion set to its exact immutable gated draft.
///
/// The atomic plan builder and full historical replay use this same predicate.
/// It grants no admission, signature acceptance or mutable Journal access.
///
/// # Errors
/// Refuses another internal operation, manifest, Source draft or purpose-specific
/// Root plan. It also refuses an absent or duplicated matching signed template.
pub fn require_provisioning_publication_gate_v1(
    records: ProvisioningResourceRecordsV1,
    gate: &OwnershipGatePlanV1,
) -> Result<(), ProvisioningResourceLinkErrorV1> {
    let fields = records.fields_v1();
    let manifest = gate.publication_draft().manifest();
    if gate.operation_id() != fields.publication_operation
        || gate.publication_draft_digest() != fields.source_draft
        || manifest.digest() != fields.manifest
        || manifest.manifest().sandbox() != fields.sandbox
        || manifest.manifest().project() != fields.project
        || manifest.manifest().epoch() != fields.epoch
    {
        return Err(ProvisioningResourceLinkErrorV1::Mismatch);
    }
    let expected_broker_method = match fields.mode {
        ProvisioningModeDataV1::CreateStopped => BrokerMethod::BROKER_METHOD_STORAGE_APPLY,
        ProvisioningModeDataV1::StartRunning => BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
    };
    let expected_verb = match fields.mode {
        ProvisioningModeDataV1::CreateStopped => BrokerVerb::StorageCreateWorkspace,
        ProvisioningModeDataV1::StartRunning => BrokerVerb::HostLaunch,
    };
    let matching_root_plans = gate.publication_draft().templates().iter().filter(|template| {
        template.method() == expected_broker_method
            && template.plan().grants().len() == 1
            && template.plan().grants()[0].verb() == expected_verb
            && ObjectDigest::from_bytes(Sha256::digest(template.canonical_plan()).into()) == fields.root_plan
    }).count();
    if matching_root_plans != 1 {
        return Err(ProvisioningResourceLinkErrorV1::Mismatch);
    }
    Ok(())
}

fn record<'a>(state: &'a State, namespace: RecordNamespace, key: &[u8])
    -> Result<&'a [u8], ProvisioningResourceLinkErrorV1>
{
    state.get(&(namespace, key.to_vec())).map(Vec::as_slice)
        .ok_or(ProvisioningResourceLinkErrorV1::Mismatch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_companions_without_the_actual_parent_and_gate_are_refused() {
        let records = super::super::tests::records(10);
        let state = super::super::tests::state(records);
        validate_provisioning_resource_state_v1(&state).unwrap();

        assert!(matches!(validate_provisioning_resource_links_v1(&state),
            Err(ProvisioningResourceLinkErrorV1::Mismatch)));
    }
}
