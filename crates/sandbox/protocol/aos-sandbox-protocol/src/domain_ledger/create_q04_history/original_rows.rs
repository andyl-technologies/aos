//! Checks the exact original Q04 Create rows as nonauthorizing DATA.
//!
//! The same Operation, Effect, Desired and public-request codecs validate the
//! original signed row trio. Native Controller membership, actual current pins
//! and Root's same-flight gen1 association remain independently required.

use super::{Q04CutIdentityV1, Q04EffectSubgateV1};
use crate::domain_ledger::effect_history::{
    EffectHistoryDataError, EffectLedgerRecord, EffectState, decode_effect_with_q04, encode_effect,
    encode_q04_effect,
};
use crate::domain_ledger::operation::{decode_operation, encode_operation_record};
use crate::domain_ledger::public_operation::{OperationState, PublicOperationDataError};
use crate::domain_ledger::transaction::encode_record_fields;
use crate::public_api::projection::{
    PublicProjectionError, PublicProjectionKindV1, PublicProjectionRecordV1,
    PublicProjectionResourceV1,
};
use aos_sandbox_model::{ObjectDigest, OperationId, ProjectId, RecordNamespace, SandboxId};
use sha2::{Digest as _, Sha256};

/// Retains the existing canonical error class of an original Q04 row.
#[derive(Debug, thiserror::Error)]
pub enum Q04OriginalRowsDataErrorV1 {
    /// Original row semantics do not match the closed Create recipe.
    #[error("corrupt Q04 original rows: {0}")]
    CorruptLedger(&'static str),
    /// The original Operation decoder rejected a retained record.
    #[error(transparent)]
    Operation(#[from] PublicOperationDataError),
    /// The original Effect/context codec rejected a retained record.
    #[error(transparent)]
    Effect(#[from] EffectHistoryDataError),
    /// The original Desired projection failed its canonical decoder.
    #[error(transparent)]
    Projection(#[from] PublicProjectionError),
    /// Retains the exact original row hash boundary or encoder failure.
    #[error(transparent)]
    Hash(#[from] Q04OriginalRowsHashDataErrorV1),
}

// This checks the original signed Claim's row DATA through the same existing
// codecs. It is not a synthetic Journal or complete Controller authority:
// the caller still requires the pinned actual current/held Controller cut.
pub fn validate_original_claim_rows_v1(
    operation_bytes: &[u8],
    desired_bytes: &[u8],
    effect_bytes: &[u8],
    identity: &Q04CutIdentityV1,
) -> Result<(), Q04OriginalRowsDataErrorV1> {
    let rows = read_original_q04_rows_v1(
        operation_bytes,
        desired_bytes,
        effect_bytes,
        Q04OriginalRowBindingV1 {
            operation: identity.operation(),
            sandbox: identity.sandbox(),
            project: identity.project(),
            accepted_generation: identity.accepted_generation(),
            desired_precondition: identity.desired_precondition(),
        },
    )?;
    if rows.before != identity.before_controller_rows() {
        return Err(
            Q04OriginalRowsDataErrorV1::CorruptLedger("Q04 Claim original rows changed").into(),
        );
    }
    if rows.effect_plan_digest()? != identity.effect_plan_digest() {
        return Err(Q04OriginalRowsDataErrorV1::CorruptLedger(
            "Q04 Claim original Effect plan changed",
        )
        .into());
    }
    Ok(())
}

// Borrowed original rows are checked by the same model/ledger codecs before
// Cut construction. These identities must separately join the actual pinned
// Controller readback; this DATA helper supplies no Controller authority.
pub struct Q04OriginalRowBindingV1 {
    pub operation: OperationId,
    pub sandbox: SandboxId,
    pub project: ProjectId,
    pub accepted_generation: u64,
    pub desired_precondition: ObjectDigest,
}

pub struct Q04OriginalRowDataV1 {
    pub before: ObjectDigest,
    effect: EffectLedgerRecord,
}

impl Q04OriginalRowDataV1 {
    pub fn effect_plan_digest(self) -> Result<ObjectDigest, Q04OriginalRowsDataErrorV1> {
        // This owner has only Copy identity besides the effect. Keep every
        // residual field until after hashing, without changing borrowed encoding.
        let effect = self.effect.into_parts();
        let admitted = encode_effect(&EffectLedgerRecord::from_parts((
            effect.0,
            EffectState::Planned,
            None,
            None,
        )))
        .map_err(Q04OriginalRowsDataErrorV1::from)?;
        Ok(ObjectDigest::from_bytes(Sha256::digest(admitted).into()))
    }

    // Root reconstructs the exact planned Applying companion through the
    // same Effect codec. This DATA encoding cannot create a Controller owner
    // or waive its actual full-ledger CAS/current admission checks.
    pub fn applying_effect_with_gate(
        &self,
        gate: &Q04EffectSubgateV1,
    ) -> Result<Vec<u8>, Q04OriginalRowsDataErrorV1> {
        Ok(encode_q04_effect(&self.effect, gate).map_err(Q04OriginalRowsDataErrorV1::from)?)
    }
}

pub fn read_original_q04_rows_v1(
    operation_bytes: &[u8],
    desired_bytes: &[u8],
    effect_bytes: &[u8],
    binding: Q04OriginalRowBindingV1,
) -> Result<Q04OriginalRowDataV1, Q04OriginalRowsDataErrorV1> {
    let operation = decode_operation(operation_bytes).map_err(Q04OriginalRowsDataErrorV1::from)?;
    if operation.state() != OperationState::Applying
        || operation.effect_count() != 1
        || operation.ownership_gated()
        || operation.runtime_intent_digest().is_some()
        || !operation.public_operation().is_some_and(|public| {
            public.method() == crate::public_api::PublicOperationMethodV1::CreateSandbox
                && public.accepted_generation() == binding.accepted_generation
        })
        || encode_operation_record(operation).as_slice() != operation_bytes
    {
        return Err(
            Q04OriginalRowsDataErrorV1::CorruptLedger("Q04 Claim Operation changed").into(),
        );
    }

    let (effect, gate) =
        decode_effect_with_q04(effect_bytes).map_err(Q04OriginalRowsDataErrorV1::from)?;
    if gate.is_some()
        || !matches!(effect.state(), EffectState::Applying { .. })
        || effect.dispatch().is_some()
        || effect.plan().authority().is_some()
        || effect.project_admission().is_some()
        || effect.plan().public_mutation_method()
            != Some(crate::public_api::PublicOperationMethodV1::CreateSandbox)
        || encode_effect(&effect)
            .map_err(Q04OriginalRowsDataErrorV1::from)?
            .as_slice()
            != effect_bytes
    {
        return Err(
            Q04OriginalRowsDataErrorV1::CorruptLedger("Q04 Claim original Effect changed").into(),
        );
    }
    let context = effect
        .plan()
        .public_mutation_context()
        .map_err(Q04OriginalRowsDataErrorV1::from)?
        .ok_or(Q04OriginalRowsDataErrorV1::CorruptLedger(
            "Q04 Claim Create context is absent",
        ))?;
    let request = context
        .validated_request()
        .map_err(Q04OriginalRowsDataErrorV1::from)?;
    let crate::public_api::request::DormantSandboxRequestKindV1::Create(create) = request else {
        return Err(Q04OriginalRowsDataErrorV1::CorruptLedger("Q04 Claim method changed").into());
    };
    let desired = PublicProjectionRecordV1::from_retained_record_bytes(
        PublicProjectionKindV1::Sandbox,
        *binding.sandbox.as_bytes(),
        desired_bytes,
    )?;
    let PublicProjectionResourceV1::Sandbox(resource) = desired.resource() else {
        return Err(
            Q04OriginalRowsDataErrorV1::CorruptLedger("Q04 Claim Desired kind changed").into(),
        );
    };
    let specification =
        resource
            .desired
            .as_option()
            .ok_or(Q04OriginalRowsDataErrorV1::CorruptLedger(
                "Q04 Claim Desired is absent",
            ))?;
    if desired.project() != binding.project
        || desired.operation() != binding.operation
        || desired.revision() != binding.desired_precondition
        || context.project() != binding.project
        || !create.parent_sandbox_id.is_empty()
        || create.project_id.as_slice() != binding.project.as_bytes()
        || create.specification.as_option() != specification.specification.as_option()
        || create.requested_policy.as_option() != specification.requested_policy.as_option()
    {
        return Err(
            Q04OriginalRowsDataErrorV1::CorruptLedger("Q04 Claim Desired/Create changed").into(),
        );
    }

    let before = q04_controller_before_rows_digest_v1(
        binding.operation,
        *binding.sandbox.as_bytes(),
        operation_bytes,
        desired_bytes,
        effect_bytes,
    )?;

    Ok(Q04OriginalRowDataV1 { before, effect })
}

pub fn q04_controller_before_rows_digest_v1(
    operation_id: OperationId,
    sandbox: [u8; 16],
    operation: &[u8],
    desired: &[u8],
    effect: &[u8],
) -> Result<ObjectDigest, Q04OriginalRowsHashDataErrorV1> {
    use crate::public_api::projection::{PublicProjectionKindV1, projection_key};

    let desired_key = projection_key(PublicProjectionKindV1::Sandbox, sandbox);
    let effect_key = crate::domain_ledger::operation::effect_key(operation_id, 0);
    let rows: [(RecordNamespace, &[u8], &[u8]); 3] = [
        (
            RecordNamespace::Operation,
            operation_id.as_bytes(),
            operation,
        ),
        (RecordNamespace::DesiredState, &desired_key, desired),
        (RecordNamespace::Effect, &effect_key, effect),
    ];
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.create-q04.controller-before-rows.v1\0");
    for (namespace, key, value) in rows {
        if value.is_empty() || value.len() > 64 * 1024 {
            return Err(Q04OriginalRowsHashDataErrorV1::ProtectedBoundary);
        }
        digest.update(encode_record_fields(namespace, key, Some(value))?);
    }
    Ok(ObjectDigest::from_bytes(digest.finalize().into()))
}

/// Preserves the exact two failure classes of the original row hash recipe.
#[derive(Debug, thiserror::Error)]
pub enum Q04OriginalRowsHashDataErrorV1 {
    /// A required original row was empty or oversized.
    #[error("invalid original Q04 protected row boundary")]
    ProtectedBoundary,
    /// The sole canonical row encoder rejected an original row.
    #[error(transparent)]
    Transaction(#[from] crate::domain_ledger::JournalTransactionDataError),
}

/// Retains the existing accepted-Create row comparison as nonauthorizing DATA.
pub mod accepted_create;
