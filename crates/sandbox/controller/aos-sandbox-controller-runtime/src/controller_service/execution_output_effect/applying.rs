//! Checks the actual durable Applying intent before the first Host35 exchange.
//!
//! The caller already holds the genuine protected Source/C18 receiving loan.
//! These passive ledger checks narrow its lifecycle entry; they do not replace
//! the signed Controller plan, independent ownership lease, or native checks.

use aos_sandbox_controller_domain::{Journal, RecordNamespace};
use aos_sandbox_model::{OperationId, ResourceDimension, ResourceVector};
use aos_sandbox_protocol::domain_ledger::{
    effect_history::{
        EffectHistoryDataError, EffectState, PublicMutationEffectHistoryV1, decode_effect,
        effect_decoding_receiving_bytes_v1,
    },
    operation::{decode_operation, effect_key},
    public_operation::{OperationState, PublicOperationDataError},
};
use aos_sandbox_protocol::public_api::PublicOperationMethodV1;

#[derive(Debug, thiserror::Error)]
pub(super) enum Error {
    #[error("the protected execution Applying intent is absent or differs")]
    Closed,
    #[error("execution Applying model geometry overflows")]
    Geometry,
    #[error(transparent)]
    Operation(#[from] PublicOperationDataError),
    #[error(transparent)]
    Effect(#[from] EffectHistoryDataError),
}

pub(super) fn demand(
    controller: &Journal,
    operation: OperationId,
) -> Result<ResourceVector, Error> {
    let encoded = controller
        .get(RecordNamespace::Effect, &effect_key(operation, 0))
        .ok_or(Error::Closed)?;
    let bytes = effect_decoding_receiving_bytes_v1(encoded.len())
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<PublicMutationEffectHistoryV1>()))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(Error::Geometry)?;
    Ok(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, bytes))
}

pub(super) fn require_applying(
    controller: &Journal,
    operation: OperationId,
    expected: &PublicMutationEffectHistoryV1,
) -> Result<u32, Error> {
    let recorded = decode_operation(
        controller
            .get(RecordNamespace::Operation, operation.as_bytes())
            .ok_or(Error::Closed)?,
    )?;
    if recorded.state() != OperationState::Applying
        || recorded.effect_count() != 1
        || recorded.ownership_gated()
        || recorded.runtime_intent_digest().is_some()
        || recorded
            .public_operation()
            .is_none_or(|public| public.method() != PublicOperationMethodV1::CreateExecution)
    {
        return Err(Error::Closed);
    }

    let effect = decode_effect(
        controller
            .get(RecordNamespace::Effect, &effect_key(operation, 0))
            .ok_or(Error::Closed)?,
    )?;
    if effect.plan().public_mutation_method() != Some(PublicOperationMethodV1::CreateExecution)
        || effect.dispatch().is_some()
        || effect.plan().public_mutation_context()?.as_ref() != Some(expected)
    {
        return Err(Error::Closed);
    }
    match effect.state() {
        EffectState::Applying { attempt, .. } if *attempt > 0 => Ok(*attempt),
        _ => Err(Error::Closed),
    }
}
