//! Original canonical completion requests and bounded retained reply history.
//!
//! Complete has no observational Poll operation. Reconciliation repeats the
//! same request against the native last-operation journal, retaining uncertainty
//! until the result is known. A known result is subsequently read from this
//! record, before another original can replace that native per-CPU journal.
//! Checked wire facts correlate this record; its enclosing owner authenticates
//! the actual peer and original callback custody separately.

use super::{
    QmpClient, QmpCommand, QmpError, QmpKvmResponseBytesOperation, QmpKvmResponseBytesPayloadKind,
    QmpKvmResponseBytesRequest, QmpKvmResponseBytesState, QmpTimeoutStream, exchange_component,
    malformed, parse_response_into, validate_request,
};
use crate::qmp::{QmpKvmInitialResponseState, QmpKvmMoreResponseState};

/// Copies bounded original completion facts without allocating payload copies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpKvmCompletionSummary {
    /// Distinguishes native results from uncertain original input echoes.
    pub payload_kind: QmpKvmResponseBytesPayloadKind,
    /// Identifies this original completion operation.
    pub operation_id: u64,
    /// Identifies the original admitted native fragment.
    pub expected_sequence: u64,
    /// Identifies the actual next pending native fragment, if known.
    pub pending_sequence: u64,
    /// Retains the native phase or explicitly unknown input classification.
    pub native_phase: u32,
    /// Retains the original signed native callback result, if known.
    pub callback_result: i32,
    /// Distinguishes native completion results from original request custody.
    pub result_known: bool,
    /// Retains uncertainty from the native owner or the original exchange.
    pub uncertain_effects: bool,
    /// Retains original native owner opacity.
    pub opaque_effects: bool,
    /// Identifies the retained binary payload length without copying its bytes.
    pub data_length: u32,
}

impl QmpKvmCompletionSummary {
    fn from_state(state: &QmpKvmResponseBytesState, uncertain: bool) -> Self {
        let facts = state.observed();
        Self {
            payload_kind: facts.payload_kind,
            operation_id: facts.operation_id,
            expected_sequence: facts.expected_sequence,
            pending_sequence: facts.pending_sequence,
            native_phase: facts.native_phase,
            callback_result: facts.callback_result,
            result_known: facts.result_known,
            uncertain_effects: uncertain,
            opaque_effects: facts.opaque_effects,
            data_length: facts.data_length,
        }
    }
}

/// Retains one original completion and every bounded checked reply or conflict.
///
/// Native input echoes are retained independently from results. Preparation
/// reserves history slots before mutation, while the unchanged baseline owns its
/// original binary bytes. Peer identity and exclusive sequential callback custody
/// remain obligations of the process owner; these typed facts grant no execution
/// or continuation authority.
#[derive(Debug)]
pub struct QmpKvmCompletionTransaction {
    original: QmpKvmResponseBytesRequest,
    baseline: QmpKvmResponseBytesState,
    replies: Vec<QmpKvmResponseBytesState>,
    reply_buffers: Vec<Vec<u8>>,
    maximum_attempts: usize,
    attempts: usize,
    accepted: Option<usize>,
    uncertain_effects: bool,
}

impl QmpKvmCompletionTransaction {
    /// Retains an initial response completion with its original CPU predecessor.
    ///
    /// Completion IDs persist across RUN rows. The owning fresh process supplies
    /// authenticated absence only before any original completion; subsequent
    /// initial callbacks retain the same CPU's preceding known Done result.
    ///
    /// # Errors
    /// Refuses non-native or changed original pending facts, an uncollected or
    /// uncertain callback, exhausted counters or unavailable history reservation.
    pub fn prepare_initial(
        baseline: QmpKvmResponseBytesState,
        callback: &QmpKvmInitialResponseState,
        predecessor: Option<&QmpKvmResponseBytesState>,
        maximum_attempts: usize,
    ) -> Result<Self, QmpError> {
        let observed = baseline.observed();
        let handler = callback.observed();
        if !handler.result_known
            || handler.callback_result < 0
            || handler.uncertain_effects
            || handler.opaque_effects
            || observed.native_phase != 1
            || handler.record_index != observed.record_index
            || handler.generation != observed.generation
            || handler.expected_invocation != observed.invocation
            || handler.vcpu_index != observed.vcpu_index
            || handler.native_vcpu_id != u64::from(observed.native_vcpu_id)
            || handler.exit_sequence != observed.pending_sequence
        {
            return Err(malformed(
                "first completion changed its original collected handler",
            ));
        }
        // Completion identities belong to the original CPU lifetime, not one
        // RUN row. A fresh owner authenticates absence; subsequent originals
        // retain their preceding known Done result before the source overwrites it.
        let operation_id = if let Some(predecessor) = predecessor {
            let prior = predecessor.observed();
            if prior.payload_kind != QmpKvmResponseBytesPayloadKind::NativeResult
                || !prior.result_known
                || prior.native_phase != 3
                || prior.callback_result < 0
                || prior.uncertain_effects
                || prior.opaque_effects
                || prior.vcpu_index != observed.vcpu_index
                || prior.native_vcpu_id != observed.native_vcpu_id
                || prior.invocation >= observed.invocation
                || prior.record_index >= observed.record_index
                || prior.generation > observed.generation
                || prior.qemu_build_id != observed.qemu_build_id
                || prior.qemu_source_hash != observed.qemu_source_hash
                || prior.clock_edition != observed.clock_edition
                || prior.clock_components != observed.clock_components
            {
                return Err(malformed(
                    "initial completion changed its original CPU predecessor",
                ));
            }
            prior
                .operation_id
                .checked_add(1)
                .ok_or_else(|| malformed("original CPU completion identity is exhausted"))?
        } else {
            1
        };
        Self::prepare(baseline, operation_id, maximum_attempts)
    }

    /// Retains the next completion after its original More callback is collected.
    ///
    /// # Errors
    /// Refuses unknown or changed native ancestry, an uncollected/uncertain More
    /// callback, counter exhaustion or unavailable finite history credit.
    pub fn prepare_more(
        baseline: QmpKvmResponseBytesState,
        previous: &QmpKvmResponseBytesState,
        callback: &QmpKvmMoreResponseState,
        maximum_attempts: usize,
    ) -> Result<Self, QmpError> {
        let current = baseline.observed();
        let prior = previous.observed();
        let handler = callback.observed();
        if prior.payload_kind != QmpKvmResponseBytesPayloadKind::NativeResult
            || !prior.result_known
            || prior.native_phase != 2
            || prior.callback_result < 0
            || prior.uncertain_effects
            || prior.opaque_effects
            || !handler.result_known
            || handler.callback_result < 0
            || handler.uncertain_effects
            || handler.opaque_effects
            || current.native_phase != 2
            || handler.completion_id != prior.operation_id
            || handler.exit_sequence != prior.pending_sequence
            || handler.vcpu_index != prior.vcpu_index
            || handler.kernel_vcpu_id != u64::from(prior.native_vcpu_id)
            || current.record_index != prior.record_index
            || current.generation != prior.generation
            || current.invocation != prior.invocation
            || current.vcpu_index != prior.vcpu_index
            || current.native_vcpu_id != prior.native_vcpu_id
            || current.pending_sequence != prior.pending_sequence
            || current.consumed_sequence != prior.consumed_sequence
            || current.revision != prior.revision
            || current.qemu_build_id != prior.qemu_build_id
            || current.qemu_source_hash != prior.qemu_source_hash
            || current.clock_edition != prior.clock_edition
            || current.clock_components != prior.clock_components
            || !same_geometry(&baseline, previous)
            || baseline.bytes() != previous.bytes()
        {
            return Err(malformed(
                "next completion changed its original More ancestry",
            ));
        }
        let operation_id = prior
            .operation_id
            .checked_add(1)
            .ok_or_else(|| malformed("original completion identity is exhausted"))?;
        Self::prepare(baseline, operation_id, maximum_attempts)
    }

    fn prepare(
        baseline: QmpKvmResponseBytesState,
        operation_id: u64,
        maximum_attempts: usize,
    ) -> Result<Self, QmpError> {
        let native = baseline.observed();
        if native.payload_kind != QmpKvmResponseBytesPayloadKind::NativeQuery
            || !native.result_known
            || native.uncertain_effects
            || native.opaque_effects
            || !(1..=1024).contains(&maximum_attempts)
            || native.revision == 0
            || native.revision > u64::MAX - 2
        {
            return Err(malformed(
                "original completion requires finite native Query custody",
            ));
        }
        let original = QmpKvmResponseBytesRequest {
            operation: QmpKvmResponseBytesOperation::Complete,
            record_index: native.record_index,
            generation: native.generation,
            expected_invocation: native.invocation,
            operation_id,
            expected_sequence: native.pending_sequence,
        };
        validate_request(&original)?;
        let mut replies = Vec::new();
        replies
            .try_reserve_exact(maximum_attempts)
            .map_err(|_| malformed("original completion history credit is unavailable"))?;
        let mut reply_buffers = Vec::new();
        reply_buffers
            .try_reserve_exact(maximum_attempts)
            .map_err(|_| malformed("original completion byte slots are unavailable"))?;
        for _ in 0..maximum_attempts {
            let mut buffer = Vec::new();
            buffer
                .try_reserve_exact(4096)
                .map_err(|_| malformed("original completion byte credit is unavailable"))?;
            reply_buffers.push(buffer);
        }
        Ok(Self {
            original,
            baseline,
            replies,
            reply_buffers,
            maximum_attempts,
            attempts: 0,
            accepted: None,
            uncertain_effects: false,
        })
    }

    /// Borrows the unchanged original completion request.
    pub fn original(&self) -> &QmpKvmResponseBytesRequest {
        &self.original
    }

    /// Borrows the source-observed original fragment before any native mutation.
    pub fn baseline(&self) -> &QmpKvmResponseBytesState {
        &self.baseline
    }

    /// Borrows all checked native replies, including preserved conflicting facts.
    pub fn replies(&self) -> &[QmpKvmResponseBytesState] {
        &self.replies
    }

    /// Borrows the latest accepted original state without replacing its history.
    pub fn accepted(&self) -> Option<&QmpKvmResponseBytesState> {
        self.accepted.and_then(|index| self.replies.get(index))
    }

    /// Copies the latest checked facts, including preserved conflicting replies.
    pub fn latest_summary(&self) -> Option<QmpKvmCompletionSummary> {
        self.replies
            .last()
            .map(|state| QmpKvmCompletionSummary::from_state(state, self.uncertain_effects))
    }

    /// Reports sticky native, transport or history uncertainty.
    pub fn uncertain_effects(&self) -> bool {
        self.uncertain_effects
    }

    /// Dispatches the retained original completion once.
    ///
    /// # Errors
    /// Refuses repeated dispatch or exhausted history credit before I/O; native,
    /// transport and changed original results leave the request retained.
    pub fn dispatch_once<S: QmpTimeoutStream>(
        &mut self,
        client: &mut QmpClient<S>,
    ) -> Result<QmpKvmCompletionSummary, QmpError> {
        if self.attempts != 0 {
            return Err(malformed("original completion was already dispatched"));
        }
        self.exchange(client)
    }

    /// Recovers this original against its native last-operation journal.
    ///
    /// A known result is returned locally. Pending reconciliation repeats exactly
    /// the retained Complete request, never a new operation or bare Query. The
    /// owner must authenticate any replacement channel to the same actual child.
    ///
    /// # Errors
    /// Refuses recovery before dispatch or exhausted finite attempt credit and
    /// propagates native/transport/history failures without clearing uncertainty.
    pub fn reconcile<S: QmpTimeoutStream>(
        &mut self,
        client: &mut QmpClient<S>,
    ) -> Result<QmpKvmCompletionSummary, QmpError> {
        if self.attempts == 0 {
            return Err(malformed("original completion has not been dispatched"));
        }
        if let Some(known) = self
            .accepted()
            .filter(|state| state.observed().result_known)
        {
            return Ok(QmpKvmCompletionSummary::from_state(
                known,
                self.uncertain_effects,
            ));
        }
        self.exchange(client)
    }

    fn exchange<S: QmpTimeoutStream>(
        &mut self,
        client: &mut QmpClient<S>,
    ) -> Result<QmpKvmCompletionSummary, QmpError> {
        if self.attempts >= self.maximum_attempts {
            return Err(malformed("original completion attempt credit is exhausted"));
        }
        let buffer = self
            .reply_buffers
            .pop()
            .ok_or_else(|| malformed("original completion byte credit is exhausted"))?;
        self.attempts += 1;
        let request = self.original;
        let result = exchange_component(
            client,
            QmpCommand::KvmResponseBytes { request: &request },
            |value| {
                let state = parse_response_into(&request, value, buffer)?;
                self.replies.push(state);
                let index = self.replies.len() - 1;
                self.validate_original(&self.replies[index])?;
                self.accepted = Some(index);
                let state = &self.replies[index];
                let native = state.observed();
                self.uncertain_effects |=
                    native.uncertain_effects || native.opaque_effects || native.callback_result < 0;
                Ok(QmpKvmCompletionSummary::from_state(
                    state,
                    self.uncertain_effects,
                ))
            },
        );
        if result.is_err() {
            self.uncertain_effects = true;
        }
        result
    }

    fn validate_original(&self, state: &QmpKvmResponseBytesState) -> Result<(), QmpError> {
        let baseline = self.baseline.observed();
        let facts = state.observed();
        if facts.expected_revision != baseline.revision
            || facts.qemu_build_id != baseline.qemu_build_id
            || facts.qemu_source_hash != baseline.qemu_source_hash
            || facts.clock_edition != baseline.clock_edition
            || facts.clock_components != baseline.clock_components
            || facts.vcpu_index != baseline.vcpu_index
            || facts.payload_kind == QmpKvmResponseBytesPayloadKind::NativeResult
                && (facts.native_vcpu_id != baseline.native_vcpu_id
                    || facts.callback_result < 0
                        && facts.consumed_sequence != baseline.consumed_sequence)
            || facts.payload_kind == QmpKvmResponseBytesPayloadKind::OriginalRequest
                && !same_geometry(&self.baseline, state)
        {
            return Err(malformed("completion changed its retained native original"));
        }
        if let Some(previous) = self.accepted()
            && previous.observed().payload_kind == QmpKvmResponseBytesPayloadKind::OriginalRequest
            && facts.payload_kind == QmpKvmResponseBytesPayloadKind::OriginalRequest
            && state != previous
        {
            return Err(malformed(
                "completion changed its retained original input echo",
            ));
        }
        Ok(())
    }
}

fn same_geometry(first: &QmpKvmResponseBytesState, second: &QmpKvmResponseBytesState) -> bool {
    let first = first.observed();
    let second = second.observed();
    (
        first.reason,
        first.address,
        first.data_offset,
        first.length,
        first.count,
        first.size,
        first.direction,
    ) == (
        second.reason,
        second.address,
        second.data_offset,
        second.length,
        second.count,
        second.size,
        second.direction,
    )
}
