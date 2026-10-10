//! Bounded original RUN return observation and one-time acknowledgement.
//!
//! Returned native facts retain the original kernel invocation, clock samples,
//! hidden pending response and sticky uncertainty. Observation and ACK are not
//! guest execution, a device drain or an exact continuation authority.

use serde::{Deserialize, Serialize};

use super::{
    QmpClient, QmpCommand, QmpCommandKind, QmpError, QmpKvmOriginalReturnIdentity,
    QmpTimeoutStream, exchange_component,
};

const ORIGINAL_RETURNED: u32 = 1;

/// Selects original source journal observation or kernel acknowledgement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QmpKvmOriginalReturnOperation {
    /// Observes the already retained original journal row.
    Query,
    /// Acknowledges the same original actual kernel invocation exactly once.
    Ack,
}

/// Binds an operation to the original lifetime row and reserved invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct QmpKvmOriginalReturnRequest {
    /// Selects original observation or acknowledgement.
    pub operation: QmpKvmOriginalReturnOperation,
    /// Identifies the original bounded lifetime journal row.
    pub record_index: u32,
    /// Identifies the original source-owned kernel generation.
    pub generation: u64,
    /// Identifies the originally reserved next kernel invocation.
    pub expected_invocation: u64,
}

/// Retains original native receipt facts without whole-state capture authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct QmpKvmOriginalReturnObservation {
    /// Identifies the original-return component edition, one.
    pub schema_version: u32,
    /// Identifies the original bounded lifetime journal row.
    pub record_index: u32,
    /// Identifies the original source-owned window generation.
    pub generation: u64,
    /// Identifies the originally reserved next invocation.
    pub expected_invocation: u64,
    /// Records the actual retained invocation, or its exact prior no-birth basis.
    pub invocation: u64,
    /// Identifies the actual original kernel CPU; BSP zero remains valid.
    pub native_vcpu_id: u32,
    /// Retains the original signed native RUN syscall result.
    pub native_result: i64,
    /// Records the native generation sampled at original entry.
    pub generation_begin: u64,
    /// Records the native generation sampled at original return.
    pub generation_end: u64,
    /// Records the original native entry clock sample.
    pub current_begin_ns: u64,
    /// Records the original native return clock sample.
    pub current_end_ns: u64,
    /// Retains private callback, MMIO, PIO and opaque pending bits.
    pub pending_mask: u32,
    /// Retains the original kernel response sequence.
    pub response_sequence: u64,
    /// Retains the kernel consumed response sequence.
    pub response_consumed: u64,
    /// Retains the original kernel response revision.
    pub response_revision: u64,
    /// Retains the original kernel response phase.
    pub response_phase: u32,
    /// Retains sticky kernel uncertain and opaque response history.
    pub response_flags: u32,
    /// Retains returned and clock-sampling facts from the native receipt.
    pub receipt_flags: u32,
    /// Records actual invocation of the original native RUN syscall.
    pub issued: bool,
    /// Records retention of a returned kernel original, including uncertain ones.
    pub receipt_known: bool,
    /// Records exact prior acknowledged receipt authentication of a no-birth attempt.
    pub no_birth_known: bool,
    /// Records knowledge of the original one-time kernel ACK result.
    pub ack_known: bool,
    /// Retains the native receipt QUERY result; zero is success.
    pub query_errno: i64,
    /// Retains the original native ACK result; zero is success.
    pub ack_errno: i64,
    /// Remains false because original return custody cannot qualify a node.
    pub profile_qualified: bool,
}

/// Retains a checked journal reply without converting it into live authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpKvmOriginalReturnState {
    observed: QmpKvmOriginalReturnObservation,
}

impl QmpKvmOriginalReturnState {
    /// Borrows original native facts, including pending and uncertain history.
    pub fn observed(&self) -> &QmpKvmOriginalReturnObservation {
        &self.observed
    }
}

impl<S: QmpTimeoutStream> QmpClient<S> {
    /// Observes or acknowledges one original kernel invocation at its stopped cut.
    ///
    /// The controller must retain the request and full original native receipt
    /// before transport. ACK retries use this same original identity and never
    /// invoke RUN or replay device handlers.
    ///
    /// # Errors
    /// Rejects invalid scope before transport, native refusal, missing replies,
    /// changed original rows, unsupported fields or a whole-profile claim.
    /// Ambiguous exchange or malformed replies fence the stream while original
    /// custody remains owned. A fully framed native refusal remains usable.
    pub fn control_native_kvm_original_return(
        &mut self,
        request: &QmpKvmOriginalReturnRequest,
    ) -> Result<QmpKvmOriginalReturnState, QmpError> {
        validate_request(request)?;
        exchange_component(self, QmpCommand::KvmOriginalReturn { request }, |value| {
            parse_response(request, value)
        })
    }
}

fn malformed(reason: &'static str) -> QmpError {
    QmpError::MalformedTypedResponse {
        command: QmpCommandKind::KvmOriginalReturn,
        response: reason.into(),
    }
}

pub(crate) fn validate_request(request: &QmpKvmOriginalReturnRequest) -> Result<(), QmpError> {
    if request.record_index >= 65_536 || request.generation == 0 || request.expected_invocation == 0
    {
        return Err(malformed(
            "original return requires its bounded row and reserved invocation",
        ));
    }
    Ok(())
}

fn parse_response(
    request: &QmpKvmOriginalReturnRequest,
    value: &serde_json::Value,
) -> Result<QmpKvmOriginalReturnState, QmpError> {
    let observed: QmpKvmOriginalReturnObservation = serde_json::from_value(value.clone())
        .map_err(|_| malformed("original return requires its closed edition-one schema"))?;
    if observed.schema_version != 1
        || observed.record_index != request.record_index
        || observed.generation != request.generation
        || observed.expected_invocation != request.expected_invocation
        || observed.pending_mask & !15 != 0
        || observed.response_flags & !3 != 0
        || observed.receipt_flags & !31 != 0
        || observed.response_phase > 5
        || observed.response_consumed > observed.response_sequence
        || observed.current_begin_ns > observed.current_end_ns
        || observed.query_errno > 0
        || observed.ack_errno > 0
        || observed.profile_qualified
        || observed.no_birth_known
            && (observed.receipt_known
                || !observed.issued
                || !observed.ack_known
                || observed.query_errno != 0
                || observed.ack_errno != 0
                || observed.native_result != -11
                || observed.invocation.checked_add(1) != Some(observed.expected_invocation))
        || observed.receipt_known
            && (!observed.issued
                || observed.query_errno != 0
                || observed.invocation != observed.expected_invocation
                || observed.receipt_flags & ORIGINAL_RETURNED == 0)
        || observed.ack_known
            && !observed.no_birth_known
            && (!observed.receipt_known || observed.ack_errno != 0)
        || request.operation == QmpKvmOriginalReturnOperation::Ack && !observed.ack_known
    {
        return Err(malformed(
            "original return changed its row, ancestry or acknowledgement",
        ));
    }
    // Authentic but inconsistent native records must remain representable as
    // retained Unknown. Only the source-owned ledger can classify their exact
    // original generation, native CPU and clock interval against admission.
    Ok(QmpKvmOriginalReturnState { observed })
}

/// Owns one original ACK request and its unchanged retained kernel receipt.
///
/// Preparation correlates a queried receipt with a learned inventory identity;
/// it never authenticates a process, runtime grant or complete device closure.
/// Dispatch occurs once. Reconciliation observes the original row using Query,
/// and cannot erase historical lost-reply or kernel-copy uncertainty.
#[derive(Debug)]
pub struct QmpKvmOriginalAckTransaction {
    original: QmpKvmOriginalReturnRequest,
    baseline: QmpKvmOriginalReturnObservation,
    sent: bool,
    uncertain_effects: bool,
    latest: Option<QmpKvmOriginalReturnState>,
}

impl QmpKvmOriginalAckTransaction {
    /// Retains an unacknowledged original receipt before any ACK transport.
    ///
    /// The inventory and receipt must originate from the same independently
    /// authenticated owning session. Public labels alone supply no authority.
    /// No-birth rows already retain the prior ACK and cannot create a new ACK.
    ///
    /// # Errors
    /// Refuses changed row, CPU, generation or invocation, unknown/no-birth
    /// receipts, already known ACKs or native generation/returned-bit mismatch.
    pub fn prepare(
        identity: &QmpKvmOriginalReturnIdentity,
        receipt: &QmpKvmOriginalReturnState,
    ) -> Result<Self, QmpError> {
        let baseline = *receipt.observed();
        if baseline.record_index != identity.record_index
            || baseline.generation != identity.generation
            || baseline.expected_invocation != identity.expected_invocation
            || u64::from(baseline.native_vcpu_id) != identity.native_vcpu_id
            || !identity.issued
            || !identity.receipt_known
            || identity.no_birth_known
            || identity.ack_known
            || !baseline.issued
            || !baseline.receipt_known
            || baseline.no_birth_known
            || baseline.ack_known
            || baseline.invocation != baseline.expected_invocation
            || baseline.generation_begin != baseline.generation
            || baseline.generation_end != baseline.generation
            || baseline.receipt_flags & ORIGINAL_RETURNED == 0
        {
            return Err(malformed(
                "ACK does not retain the same original native receipt",
            ));
        }
        let original = QmpKvmOriginalReturnRequest {
            operation: QmpKvmOriginalReturnOperation::Ack,
            record_index: baseline.record_index,
            generation: baseline.generation,
            expected_invocation: baseline.expected_invocation,
        };
        validate_request(&original)?;
        Ok(Self {
            original,
            baseline,
            sent: false,
            uncertain_effects: baseline.ack_errno != 0,
            latest: None,
        })
    }

    /// Borrows the unchanged original ACK scope.
    pub fn original(&self) -> &QmpKvmOriginalReturnRequest {
        &self.original
    }

    /// Borrows the full original native receipt, including pending responses.
    pub fn baseline(&self) -> &QmpKvmOriginalReturnObservation {
        &self.baseline
    }

    /// Reports sticky historical ACK uncertainty without releasing custody.
    pub fn uncertain_effects(&self) -> bool {
        self.uncertain_effects
    }

    /// Borrows the latest checked reply, including a retained conflicting receipt.
    pub fn latest(&self) -> Option<&QmpKvmOriginalReturnState> {
        self.latest.as_ref()
    }

    /// Sends the same original kernel ACK once through this owning value.
    ///
    /// # Errors
    /// Refuses repeated dispatch before I/O or returns native/transport failure.
    /// Failed transport retains the original receipt and historical uncertainty.
    pub fn dispatch_once<S: QmpTimeoutStream>(
        &mut self,
        client: &mut QmpClient<S>,
    ) -> Result<QmpKvmOriginalReturnState, QmpError> {
        if self.sent {
            return Err(malformed("original ACK was already sent"));
        }
        self.sent = true;
        let result = client.control_native_kvm_original_return(&self.original);
        self.retain(result)
    }

    /// Observes the original row without issuing another ACK, RUN or callback.
    ///
    /// After an ambiguous transport boundary the old stream remains fenced.
    /// A replacement peer must be independently authenticated to the same child
    /// by the enclosing owner; matching row labels cannot establish this fact.
    ///
    /// # Errors
    /// Refuses before dispatch or returns native/transport/changed-receipt error.
    /// Historical uncertainty and the full original receipt remain retained.
    pub fn reconcile<S: QmpTimeoutStream>(
        &mut self,
        client: &mut QmpClient<S>,
    ) -> Result<QmpKvmOriginalReturnState, QmpError> {
        if !self.sent {
            return Err(malformed("original ACK was not sent"));
        }
        let query = QmpKvmOriginalReturnRequest {
            operation: QmpKvmOriginalReturnOperation::Query,
            ..self.original
        };
        let result = client.control_native_kvm_original_return(&query);
        self.retain(result)
    }

    fn retain(
        &mut self,
        result: Result<QmpKvmOriginalReturnState, QmpError>,
    ) -> Result<QmpKvmOriginalReturnState, QmpError> {
        match result {
            Ok(state) => {
                self.latest = Some(state);
                let mut normalized = *state.observed();
                normalized.ack_known = self.baseline.ack_known;
                normalized.ack_errno = self.baseline.ack_errno;
                if normalized != self.baseline {
                    self.uncertain_effects = true;
                    return Err(malformed(
                        "original ACK receipt changed during reconciliation",
                    ));
                }
                self.uncertain_effects |= state.observed().ack_errno != 0;
                Ok(state)
            }
            Err(error) => {
                self.uncertain_effects = true;
                Err(error)
            }
        }
    }
}

#[cfg(test)]
#[path = "original_return_tests.rs"]
mod tests;
