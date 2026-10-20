//! Selects the actual immutable Stop dispatch or settlement pair from Source.
//!
//! The protected envelope, auxiliary payload and complete atomic-join checks
//! are the existing engines. This reader retains both decoder originals and
//! positive members; it produces comparison DATA and no old native authority.

use super::*;
use crate::lifecycle::protected_journal::{
    LifecycleProtectedJournalProjectionV1, LifecycleProtectedRecordKindV1,
};
use crate::lifecycle::{
    LifecycleAuxiliaryDecodeOriginalV1, LifecycleAuxiliaryPayloadV1, LifecycleAuxiliaryRecordV1,
    LifecycleJournalVerifierV1, lifecycle_atomic_join_digest_v1,
};
use aos_sandbox_protocol::domain_ledger::lifecycle_auxiliary::{
    LIFECYCLE_PROTECTED_DOMAIN_V1, LIFECYCLE_PROTECTED_MAXIMUM_PAYLOAD_BYTES_V1,
    LifecycleAuxiliaryEnvelopeFormatV1, LifecycleAuxiliaryFrameDataV1,
};
use aos_sandbox_protocol::domain_ledger::records::borrowed::ReducerFrameDataV1;
use aos_sandbox_protocol::domain_ledger::stop_dispatch::LifecycleStopDispatchDataV1;
use aos_sandbox_protocol::domain_ledger::stop_completion::LifecycleStopCompletionDataV1;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum StopSelection {
    Dispatch,
    Completion,
    HistoricalDispatch,
}

impl StopSelection {
    fn kind(self) -> u8 {
        match self { Self::Dispatch | Self::HistoricalDispatch => 7, Self::Completion => 8 }
    }

    fn format(self) -> LifecycleAuxiliaryEnvelopeFormatV1 {
        match self {
            Self::Dispatch | Self::HistoricalDispatch => LifecycleAuxiliaryEnvelopeFormatV1::StopDispatch,
            Self::Completion => LifecycleAuxiliaryEnvelopeFormatV1::StopCompletion,
        }
    }

    fn members(self) -> u16 { 1 | (1 << self.kind()) }
}

pub(super) struct StopDispatchReadOriginalV1 {
    operation: LifecycleAuxiliaryDecodeOriginalV1,
    dispatch: LifecycleAuxiliaryDecodeOriginalV1,
    members: Vec<LifecycleAuxiliaryRecordV1>,
    returned: Option<Result<(), Cause>>,
    reentered: bool,
    selection: Option<StopSelection>,
}

impl StopDispatchReadOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            operation: LifecycleAuxiliaryDecodeOriginalV1::new(),
            dispatch: LifecycleAuxiliaryDecodeOriginalV1::new(),
            members: Vec::new(),
            returned: None,
            reentered: false,
            selection: None,
        }
    }

    pub(super) fn observe_once(
        &mut self,
        projection: &LifecycleProtectedJournalProjectionV1,
        verifier: &LifecycleJournalVerifierV1,
        operation: &LifecycleOperationV1,
        record: LifecycleRecordDigestV1,
        selection: StopSelection,
    ) -> Result<(), JournalError> {
        if self.returned.is_some() {
            self.reentered = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.selection = Some(selection);
        self.returned = Some((|| {
            let encoded = selected_members(projection, operation.operation_id(), selection)?;
            // Both real partial decoders remain here on any refused prefix.
            self.operation
                .decode_from_protected_envelope_once(encoded[0], verifier.replay())?;
            self.dispatch
                .decode_from_protected_envelope_once(encoded[1], verifier.replay())?;

            // Their models move only after both canonical envelopes complete.
            // The pair backing and both payload planes were paid before entry.
            self.members.reserve_exact(2);
            self.members.push(
                self.operation
                    .take_completed_once()
                    .ok_or(JournalError::ProtectedBoundary)?,
            );
            self.members.push(
                self.dispatch
                    .take_completed_once()
                    .ok_or(JournalError::ProtectedBoundary)?,
            );
            let digest = lifecycle_atomic_join_digest_v1(&self.members)?;
            if self.members.iter().any(|member| {
                member.operation() != operation.operation_id()
                    || member.operation_record() != self.members[0].operation_record()
                    || member.operation_revision() != self.members[0].operation_revision()
                    || member.declared_members() != selection.members()
                    || member.declared_count() != 2
                    || member.join_digest() != Some(digest)
                    || member.replay_floor() != self.members[0].replay_floor()
            }) {
                return Err(JournalError::ProtectedBoundary.into());
            }
            let LifecycleAuxiliaryPayloadV1::Operation(dispatched) = self.members[0].payload() else {
                return Err(JournalError::ProtectedBoundary.into());
            };
            match selection {
                StopSelection::Dispatch => crate::lifecycle::durable::require_stop_dispatch_ancestor_data_v1(
                    dispatched, self.members[0].operation_record(), operation, record,
                )?,
                StopSelection::HistoricalDispatch => {
                    // This branch only compares an already completed Source
                    // history. Full schema replay validated its revision chain;
                    // the separate C receipt joins the exact terminal record.
                    if operation.phase() != crate::lifecycle::LifecyclePhaseV1::Terminal
                        || operation.terminal_result() != Some(crate::lifecycle::LifecycleTerminalResultV1::Succeeded)
                    { return Err(JournalError::ProtectedBoundary.into()); }
                    crate::lifecycle::require_same_lifecycle_admission_v1(dispatched, operation)?;
                }
                StopSelection::Completion => {
                    if dispatched != operation || self.members[0].operation_record() != record {
                        return Err(JournalError::ProtectedBoundary.into());
                    }
                }
            }
            Ok(())
        })());
        self.completed_record().map(|_| ())
    }

    pub(super) fn completed_record(&self) -> Result<&LifecycleAuxiliaryRecordV1, JournalError> {
        if self.reentered || !matches!(self.returned, Some(Ok(()))) || self.failure().is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.members.get(1).ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn completed(&self) -> Result<&LifecycleStopDispatchDataV1, JournalError> {
        if !matches!(self.selection, Some(StopSelection::Dispatch | StopSelection::HistoricalDispatch)) {
            return Err(JournalError::ProtectedBoundary);
        }
        match self.completed_record()?.payload() {
            LifecycleAuxiliaryPayloadV1::StopDispatch(binding) => Ok(binding),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    pub(super) fn completed_settlement(&self) -> Result<&LifecycleStopCompletionDataV1, JournalError> {
        if self.selection != Some(StopSelection::Completion) {
            return Err(JournalError::ProtectedBoundary);
        }
        match self.completed_record()?.payload() {
            LifecycleAuxiliaryPayloadV1::StopCompletion(binding) => Ok(binding),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.operation
            .failure_view_v1()
            .or_else(|| self.dispatch.failure_view_v1())
            .or_else(|| {
                self.returned
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref() as _)
            })
            .or_else(|| self.reentered.then_some(&CLOSED as _))
    }
}

impl LifecycleHistoricalReadOriginalV1 {
    /// Checks presence through the same paid canonical pair selector.
    pub(crate) fn stop_completion_is_present_data_v1(&self) -> Result<bool, Cause> {
        let (operation, _) = self.operation_v1()?;
        let (projection, _) = self.projection_ready_v1()?;
        optional_selected_members(projection, operation.operation_id(), StopSelection::Completion)
            .map(|members| members.is_some())
    }

    /// Retains the complete actual A7 pair for this already selected old Stop.
    ///
    /// The caller pays the pair and its canonical residual comparison before entry.
    /// Missing legacy bindings refuse; no request triple is reconstructed.
    pub(crate) fn select_stop_dispatch_once_v1(&mut self) -> Result<(), JournalError> {
        self.select_stop_auxiliary_once_v1(StopSelection::Dispatch)
    }

    /// Selects the current A8 pair after its complete shared Source replay.
    ///
    /// This produces comparison DATA, never native completion or append power.
    /// The caller pays the same additional two-model selection plane first.
    pub(crate) fn select_stop_completion_once_v1(&mut self) -> Result<(), JournalError> {
        self.select_stop_auxiliary_once_v1(StopSelection::Completion)
    }

    fn select_stop_auxiliary_once_v1(&mut self, selection: StopSelection) -> Result<(), JournalError> {
        self.operation_v1()?;
        let (_, operation, record) = self
            .selected
            .completed_v1()
            .ok_or(JournalError::ProtectedBoundary)?;
        let projection = self
            .projection
            .projection()
            .ok_or(JournalError::ProtectedBoundary)?;
        let verifier = self
            .recovery
            .completed_v1()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.stop_dispatch
            .observe_once(projection, verifier, operation, *record, selection)
    }

    /// Borrows the literal old prepared SDK packet from the authenticated pair.
    pub(crate) fn stop_dispatch_data_v1(
        &self,
    ) -> Result<&LifecycleStopDispatchDataV1, JournalError> {
        self.operation_v1()?;
        self.stop_dispatch.completed()
    }

    /// Returns the actual A7 auxiliary-record commitment from its held decoder.
    pub(crate) fn stop_dispatch_record_digest_data_v1(&self) -> Result<aos_sandbox_core::ObjectDigest, JournalError> {
        self.stop_dispatch_data_v1()?;
        Ok(self.stop_dispatch.completed_record()?.complete_digest())
    }

    /// Borrows independent settlement DATA only from the completed A8 selector.
    pub(crate) fn stop_completion_data_v1(&self) -> Result<&LifecycleStopCompletionDataV1, JournalError> {
        self.operation_v1()?;
        self.stop_dispatch.completed_settlement()
    }

    /// Returns the actual selected A8 auxiliary-record commitment as DATA.
    pub(crate) fn stop_completion_record_digest_data_v1(&self) -> Result<aos_sandbox_core::ObjectDigest, JournalError> {
        self.stop_completion_data_v1()?;
        Ok(self.stop_dispatch.completed_record()?.complete_digest())
    }
}

fn selected_members<'source>(
    projection: &'source LifecycleProtectedJournalProjectionV1,
    operation: OperationId,
    selection: StopSelection,
) -> Result<[&'source [u8]; 2], Cause> {
    optional_selected_members(projection, operation, selection)?
        .ok_or_else(|| JournalError::ProtectedBoundary.into())
}

pub(super) fn optional_selected_members<'source>(
    projection: &'source LifecycleProtectedJournalProjectionV1,
    operation: OperationId,
    selection: StopSelection,
) -> Result<Option<[&'source [u8]; 2]>, Cause> {
    let mut dispatch = None;
    let mut join = None;
    for envelope in projection.records() {
        if envelope.key().kind() != LifecycleProtectedRecordKindV1::Auxiliary {
            continue;
        }
        // The whole projection has already passed the owning schema replay.
        // Scan only its borrowed canonical framing; do not allocate or discard
        // another ordinary schema decoder's companion/model graph per row.
        let reducer = ReducerFrameDataV1::decode(
            envelope.payload(),
            5,
            5,
            LIFECYCLE_PROTECTED_MAXIMUM_PAYLOAD_BYTES_V1,
            LIFECYCLE_PROTECTED_DOMAIN_V1,
        )?;
        let frame = LifecycleAuxiliaryFrameDataV1::decode(reducer.body)?;
        if frame.operation == operation && frame.kind == selection.kind() {
            if frame.format != selection.format() {
                return Err(JournalError::ProtectedBoundary.into());
            }
            if dispatch.replace(reducer.body).is_some() {
                return Err(JournalError::ProtectedBoundary.into());
            }
            join = Some(frame.atomic_join);
        }
    }
    let Some(dispatch) = dispatch else { return Ok(None); };
    let join = join.ok_or(JournalError::ProtectedBoundary)?;
    let mut member = None;
    for envelope in projection.records() {
        if envelope.key().kind() != LifecycleProtectedRecordKindV1::Auxiliary {
            continue;
        }
        let reducer = ReducerFrameDataV1::decode(
            envelope.payload(),
            5,
            5,
            LIFECYCLE_PROTECTED_MAXIMUM_PAYLOAD_BYTES_V1,
            LIFECYCLE_PROTECTED_DOMAIN_V1,
        )?;
        let frame = LifecycleAuxiliaryFrameDataV1::decode(reducer.body)?;
        if frame.operation == operation && frame.atomic_join == join && frame.kind == 0 {
            if frame.format != selection.format()
                || member.replace(reducer.body).is_some()
            {
                return Err(JournalError::ProtectedBoundary.into());
            }
        }
    }
    Ok(Some([member.ok_or(JournalError::ProtectedBoundary)?, dispatch]))
}
