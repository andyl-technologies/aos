//! Prices the same canonical terminal models before either concrete consumer.
//!
//! The append consumer additionally prices its real native append engine. The
//! independent Root consumer prices only its own concrete pure model carrier.

use super::*;
use aos_sandbox_journal::geometry::RecordShape;

enum Consumer {
    NativeAppend,
    IndependentRead,
    RecoverAppend,
    StartModels,
    StopResidualModels,
    StopSuccessModels,
    StopCleanupModels,
}

pub(super) fn start_model_demand_v2(journal: &Journal, parent: OperationId)
    -> Result<ResourceVector, JournalError> {
    receiving_demand_v1(journal, parent, Consumer::StartModels)
}



pub(super) fn stop_terminal_model_demand_v5(journal: &Journal, parent: OperationId, residual: bool)
    -> Result<ResourceVector, JournalError> {
    receiving_demand_v1(journal, parent,
        if residual { Consumer::StopResidualModels } else { Consumer::StopSuccessModels })
}

pub(super) fn stop_cleanup_terminal_model_demand_v1(journal: &Journal, parent: OperationId)
    -> Result<ResourceVector, JournalError> {
    receiving_demand_v1(journal, parent, Consumer::StopCleanupModels)
}

pub(crate) fn recovered_native_append_demand_v1(journal: &Journal, parent: OperationId)
    -> Result<ResourceVector, JournalError> {
    receiving_demand_v1(journal, parent, Consumer::RecoverAppend)
}

pub(super) fn native_append_demand_v1(
    journal: &Journal,
    parent: OperationId,
) -> Result<ResourceVector, JournalError> {
    receiving_demand_v1(journal, parent, Consumer::NativeAppend)
}

pub(super) fn independent_model_demand_v1(
    journal: &Journal,
    parent: OperationId,
) -> Result<ResourceVector, JournalError> {
    receiving_demand_v1(journal, parent, Consumer::IndependentRead)
}

fn receiving_demand_v1(
    journal: &Journal,
    parent: OperationId,
    consumer: Consumer,
) -> Result<ResourceVector, JournalError> {
    let bad = || JournalError::JournalTooLarge;
    let effect = journal
        .get(RecordNamespace::Effect, &effect_key(parent, 0))
        .ok_or(JournalError::ProtectedBoundary)?;
    let operation = journal
        .get(RecordNamespace::Operation, parent.as_bytes())
        .ok_or(JournalError::ProtectedBoundary)?;
    let mut projection = None::<usize>;
    for (key, value) in journal.records(RecordNamespace::DesiredState) {
        if key.starts_with(PROJECTION_KEY_PREFIX)
            && key.get(PROJECTION_KEY_PREFIX.len())
                == Some(&(PublicProjectionKindV1::Sandbox as u8))
        {
            projection = Some(projection.unwrap_or(0).max(value.len()));
        }
    }
    // Selection itself uses the canonical decoder only after this invoice is
    // paid. The maximum is over the actual finite Sandbox namespace roster.
    let projection = projection.ok_or(JournalError::ProtectedBoundary)?;
    let successor = projection.checked_add(match consumer {
        Consumer::StartModels => super::start::START_OBSERVATION_WIRE_GROWTH_V2,
        Consumer::StopResidualModels | Consumer::StopSuccessModels | Consumer::StopCleanupModels => super::start::STOP_OBSERVATION_WIRE_GROWTH_V5,
        _ => 10,
    }).ok_or_else(bad)?;
    let effect_bytes = effect.len().checked_add(match consumer {
        Consumer::StartModels | Consumer::StopSuccessModels | Consumer::StopCleanupModels => aos_sandbox_protocol::domain_ledger::effect_history::LIFECYCLE_EFFECT_RECEIPT_BYTES_V1,
        Consumer::StopResidualModels => aos_sandbox_protocol::domain_ledger::effect_history::STOP_RESIDUAL_LIFECYCLE_RECEIPT_BYTES_V4,
        _ => 0,
    }).ok_or_else(bad)?;
    let key_width = PROJECTION_KEY_PREFIX
        .len()
        .checked_add(1 + 16)
        .ok_or_else(bad)?;
    let rows = [
        RecordShape {
            key_bytes: effect_key(parent, 0).len(),
            value_bytes: Some(effect_bytes),
        },
        RecordShape {
            key_bytes: parent.as_bytes().len(),
            value_bytes: Some(operation.len()),
        },
        RecordShape {
            key_bytes: key_width,
            value_bytes: Some(successor),
        },
    ];
    let native = match consumer {
        Consumer::RecoverAppend => {
            let [effect, operation, projection] = rows;
            journal.append_receiving_demand_v1([
                effect,
                operation,
                projection,
                RecordShape {
                    key_bytes: 16,
                    value_bytes: Some(
                        aos_sandbox_protocol::domain_ledger::operation::OPERATION_RECORD_V2_BYTES,
                    ),
                },
            ].into_iter())
        }.map_err(|cause| match cause {
            crate::journal::JournalAppendReceivingDemandErrorV1::Journal(cause) => cause,
            crate::journal::JournalAppendReceivingDemandErrorV1::Accounting(cause) => JournalError::ReceivingAccounting(cause),
        })?,
        Consumer::NativeAppend => journal
            .append_receiving_demand_v1(rows.into_iter())
            .map_err(|cause| match cause {
                crate::journal::JournalAppendReceivingDemandErrorV1::Journal(cause) => cause,
                crate::journal::JournalAppendReceivingDemandErrorV1::Accounting(cause) => {
                    JournalError::ReceivingAccounting(cause)
                }
            })?,
        Consumer::IndependentRead | Consumer::StartModels | Consumer::StopResidualModels | Consumer::StopSuccessModels | Consumer::StopCleanupModels => ResourceVector::ZERO,
    };
    let state = journal.historical_read_view_v1().materialized_state_v1();
    let selectors =
        crate::cold_launch_publication::completion::controller_selector_model_bytes_v1(state)
            .ok_or_else(bad)?;
    let projection_models =
        aos_sandbox_broker_session_protocol::receiving_geometry::protobuf_carriers_v1(
            u64::try_from(successor).map_err(|_| bad())?,
            u64::try_from(size_of::<aos_sandbox_api::aos::sandbox::v1::Sandbox>()).map_err(|_| bad())?,
        )
        .ok()
        .and_then(|bytes| bytes.checked_mul(4))
        .and_then(|bytes| usize::try_from(bytes).ok())
        .ok_or_else(bad)?;
    let buffers = effect_bytes
        .checked_add(operation.len())
        .and_then(|n| n.checked_add(successor))
        .and_then(|n| n.checked_add(key_width))
        .and_then(|n| n.checked_mul(4))
        .ok_or_else(bad)?;
    let carrier = match consumer {
        Consumer::NativeAppend => size_of::<CreateStoppedControllerTerminalAppendOriginalV1>()
            .checked_add(size_of::<
                CreateStoppedControllerTerminalAppendLoanV1<'static, 'static>,
            >()),
        Consumer::IndependentRead | Consumer::RecoverAppend => Some(size_of::<CreateStoppedMetadataTransitionOriginalV1>()),
        Consumer::StartModels | Consumer::StopResidualModels | Consumer::StopSuccessModels | Consumer::StopCleanupModels => Some(size_of::<LifecycleTerminalMetadataOriginalV4>()),
    }
    .and_then(|bytes| bytes.checked_mul(3))
    .ok_or_else(bad)?;
    let extra = if matches!(consumer, Consumer::RecoverAppend | Consumer::StopCleanupModels) {
        // The joint constructor retains the old recipe while cloning its three
        // rows and the fixed new Operation into a distinct four-row transaction.
        effect_bytes.checked_add(operation.len())
            .and_then(|n| n.checked_add(successor))
            .and_then(|n| n.checked_add(key_width + effect_key(parent, 0).len() + 32))
            .and_then(|n| n.checked_add(aos_sandbox_protocol::domain_ledger::operation::OPERATION_RECORD_V2_BYTES))
            .and_then(|n| n.checked_add(4 * size_of::<JournalRecord>() + size_of::<JournalTransaction>()))
            .and_then(|n| n.checked_mul(3))
            .and_then(|n| n.checked_add(effect_decoding_receiving_bytes_v1(effect.len())?)).ok_or_else(bad)?
    } else { 0 };
    let bytes = selectors
        .checked_add(effect_decoding_receiving_bytes_v1(effect.len()).ok_or_else(bad)?)
        .and_then(|n| n.checked_add(projection_models))
        .and_then(|n| n.checked_add(buffers))
        .and_then(|n| n.checked_add(size_of::<TerminalModelsV1>().checked_mul(3)?))
        .and_then(|n| n.checked_add(carrier))
        .and_then(|n| {
            n.checked_add(size_of::<TerminalMetadataInputV1<'static, 'static>>().checked_mul(3)?)
        })
        .and_then(|n| n.checked_add(extra))
        .and_then(|n| u64::try_from(n).ok())
        .ok_or_else(bad)?;
    let entries =
        crate::cold_launch_publication::completion::controller_selector_namespace_entries_v1(state)
            .and_then(|n| u64::try_from(n).ok())
            .ok_or_else(bad)?;
    native
        .checked_add(
            ResourceVector::ZERO
                .with(D::MemoryBytes, bytes)
                .with(D::MetadataEntries, entries),
        )
        .map_err(JournalError::ReceivingAccounting)
}
