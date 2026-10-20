//! Adds strict pre-ACK and terminal Create comparisons to the whole native audit.
//!
//! This owner observes only COMMITs already validated by the sole native parser.
//! It does not release the pending fence or authorize a terminal append. Its
//! expected immutable rows come from the same held Controller, while the
//! STOPPED projection comes from the historical atomic transaction itself.
//! The separate pre-ACK one-Effect transaction preserves Applying/REQUESTED;
//! its borrowed comparison cannot authorize the later public terminal CAS.

use super::*;
use aos_sandbox_protocol::domain_ledger::effect_history::{
    CreateStoppedTerminalTransactionDataV1, CreateStoppedPreAckTransactionDataV1,
    EffectState, decode_effect_with_q04, CreateStoppedNativeObservationDataV2,
    CreateStoppedNativeObservationErrorV2,
};

pub(super) struct NativeTerminalSelectionV1<'rows> {
    observation: CreateStoppedNativeObservationDataV2<'rows>,
}

impl<'rows> NativeTerminalSelectionV1<'rows> {
    pub(super) fn from_original_v1(journal: &'rows Journal)
        -> Result<Option<Self>, JournalError>
    {
        // Header recognition selects strict validation only. It is never a
        // substitute for the full decoder or a positive completion predicate.
        // Unchanged Applying and ordinary histories allocate no new model.
        if !journal.records(RecordNamespace::Effect).any(|(_, value)|
            value.first() == Some(&6) && value.get(2) == Some(&3)) {
            return Ok(None);
        }
        let history = journal.controller_q04_history_v1()?
            .ok_or(JournalError::ProtectedBoundary)?;
        let identity = &history.identity;
        if history.phases.len() != 8 {
            return Err(JournalError::ProtectedBoundary);
        }
        let key = aos_sandbox_protocol::domain_ledger::operation::effect_key(identity.operation(), 0);
        let effect = journal.get(RecordNamespace::Effect, &key)
            .ok_or(JournalError::ProtectedBoundary)?;
        if journal.records(RecordNamespace::Effect).any(|(other, value)|
            value.first() == Some(&6) && other != key.as_slice()) {
            return Err(JournalError::ProtectedBoundary);
        }
        let (model, gate) = decode_effect_with_q04(effect)
            .map_err(crate::reconciler::ReconcilerError::from)
            .map_err(|cause| JournalError::Q04ControllerLedger(Box::new(cause)))?;
        if !matches!(model.state(), EffectState::Applied { .. }) {
            return Err(JournalError::ProtectedBoundary);
        }
        drop(model);
        let gate = gate.ok_or(JournalError::ProtectedBoundary)?;
        gate.require_cut_identity(identity)?;
        if gate.status() != 4
            || history.phases.last().is_none_or(|phase|
                gate.acknowledgement() != phase.acknowledgement()) {
            return Err(JournalError::ProtectedBoundary);
        }
        let operation = journal.get(RecordNamespace::Operation, identity.operation().as_bytes())
            .ok_or(JournalError::ProtectedBoundary)?;
        use aos_sandbox_protocol::domain_ledger::operation::decode_operation;
        use aos_sandbox_protocol::domain_ledger::public_operation::OperationState;
        let state = decode_operation(operation)
            .map_err(crate::reconciler::ReconcilerError::from)
            .map_err(|cause| JournalError::Q04ControllerLedger(Box::new(cause)))?.state();
        let observation = match state {
            OperationState::Succeeded => {
                let terminal = CreateStoppedTerminalTransactionDataV1::from_data_v1(
                    identity.operation(), identity.project(), identity.sandbox(), operation, effect,
                ).map_err(terminal_error)?;
                CreateStoppedNativeObservationDataV2::terminal_from_state_v2(terminal,
                    journal.historical_read_view_v1().materialized_state_v1())
                    .map_err(JournalError::RecoveredCreateTerminal)?
            },
            OperationState::Applying => {
                use aos_sandbox_protocol::public_api::projection::{projection_key, PublicProjectionKindV1};
                let key = projection_key(PublicProjectionKindV1::Sandbox, *identity.sandbox().as_bytes());
                let projection = journal.get(RecordNamespace::DesiredState, &key)
                    .ok_or(JournalError::ProtectedBoundary)?;
                CreateStoppedNativeObservationDataV2::pre_ack_v2(CreateStoppedPreAckTransactionDataV1::from_data_v1(
                    identity.operation(), identity.project(), identity.sandbox(), operation, effect,
                    &key, projection,
                ).map_err(terminal_error)?)
            }
            _ => return Err(JournalError::ProtectedBoundary),
        };
        Ok(Some(Self { observation }))
    }

    // The actual protected Controller constructor above remains the only
    // selector. Moving its comparison DATA creates no role/native authority.
    pub(super) fn into_observation_v1(self) -> CreateStoppedNativeObservationDataV2<'rows> {
        self.observation
    }

}

fn terminal_error(cause: aos_sandbox_protocol::domain_ledger::effect_history::CreateStoppedTerminalDataErrorV1)
    -> JournalError
{
    JournalError::Q04ControllerLedger(Box::new(cause.into()))
}


pub(super) fn observation_error(cause: CreateStoppedNativeObservationErrorV2) -> JournalError {
    match cause {
        CreateStoppedNativeObservationErrorV2::Ordering => JournalError::ProtectedBoundary,
        CreateStoppedNativeObservationErrorV2::Comparison(cause) => terminal_error(cause),
        CreateStoppedNativeObservationErrorV2::Recovered(cause) => JournalError::RecoveredCreateTerminal(cause),
    }
}

