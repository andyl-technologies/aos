//! Retained first-handler submission and observation on one original RUN row.
//!
//! A source-owned inventory and receipt identify the original. This value holds
//! correlation and conservative effect history; its enclosing native capsule
//! supplies actual same-child custody and finite command/publication credit.

use super::{
    QmpClient, QmpCommand, QmpError, QmpKvmInitialResponseOperation, QmpKvmInitialResponseRequest,
    QmpKvmInitialResponseState, QmpTimeoutStream, exchange_component, malformed, parse_response,
    validate_request,
};
use crate::qmp::{
    QmpKvmOriginalReturnIdentity, QmpKvmOriginalReturnObservation, QmpKvmOriginalReturnState,
};

/// Retains one first-response original before any callback submission.
///
/// Submission is issued once. Recovery polls this lifetime row independently of
/// later response fragments. These facts do not establish a stopped device cut,
/// clock grant, execution readiness or exact continuation authority.
#[derive(Debug)]
pub struct QmpKvmInitialResponseTransaction {
    original: QmpKvmInitialResponseRequest,
    identity: QmpKvmOriginalReturnIdentity,
    receipt: QmpKvmOriginalReturnObservation,
    sent: bool,
    uncertain_effects: bool,
    accepted: Option<QmpKvmInitialResponseState>,
    latest: Option<QmpKvmInitialResponseState>,
}

impl QmpKvmInitialResponseTransaction {
    /// Binds a callback to the same checked original inventory and pending receipt.
    ///
    /// Matching labels are correlation only. The enclosing owner must obtain
    /// both facts from its authenticated original child before retaining this
    /// value within its pre-reserved supervisory capsule.
    ///
    /// # Errors
    /// Refuses changed, unissued, unknown, no-birth, uncertain or non-pending
    /// originals, unsupported native pending masks, and invalid row geometry.
    pub fn prepare(
        identity: &QmpKvmOriginalReturnIdentity,
        receipt: &QmpKvmOriginalReturnState,
    ) -> Result<Self, QmpError> {
        let baseline = *receipt.observed();
        if identity.record_index != baseline.record_index
            || identity.generation != baseline.generation
            || identity.expected_invocation != baseline.expected_invocation
            || identity.native_vcpu_id != u64::from(baseline.native_vcpu_id)
            || identity.vcpu_index >= 4096
            || !identity.issued
            || !identity.receipt_known
            || identity.no_birth_known
            || !baseline.issued
            || !baseline.receipt_known
            || baseline.no_birth_known
            || baseline.native_result < 0
            || baseline.invocation != baseline.expected_invocation
            || baseline.generation_begin != baseline.generation
            || baseline.generation_end != baseline.generation
            || baseline.receipt_flags & 7 != 7
            || baseline.query_errno != 0
            || baseline.response_phase != 1
            || baseline.response_flags != 0
            || baseline.response_sequence == 0
            || baseline.response_consumed >= baseline.response_sequence
            || !matches!(baseline.pending_mask, 1 | 2 | 3 | 5)
        {
            return Err(malformed(
                "first callback requires its original pending native receipt",
            ));
        }

        let original = QmpKvmInitialResponseRequest {
            operation: QmpKvmInitialResponseOperation::Submit,
            record_index: baseline.record_index,
            generation: baseline.generation,
            expected_invocation: baseline.expected_invocation,
        };
        validate_request(&original)?;
        Ok(Self {
            original,
            identity: *identity,
            receipt: baseline,
            sent: false,
            uncertain_effects: false,
            accepted: None,
            latest: None,
        })
    }

    /// Borrows the unchanged original first-response submission.
    pub fn original(&self) -> &QmpKvmInitialResponseRequest {
        &self.original
    }

    /// Borrows the full original pending kernel receipt.
    pub fn baseline(&self) -> &QmpKvmOriginalReturnObservation {
        &self.receipt
    }

    /// Reports sticky transport, native callback or original-history uncertainty.
    pub fn uncertain_effects(&self) -> bool {
        self.uncertain_effects
    }

    /// Borrows the latest structurally checked facts, including a conflicting reply.
    pub fn latest(&self) -> Option<&QmpKvmInitialResponseState> {
        self.latest.as_ref()
    }

    /// Submits the original first callback once, retaining custody on failure.
    ///
    /// # Errors
    /// Refuses repeated submission before I/O or returns native, transport,
    /// original-owner or monotonic-history failure. The original is unchanged.
    pub fn dispatch_once<S: QmpTimeoutStream>(
        &mut self,
        client: &mut QmpClient<S>,
    ) -> Result<QmpKvmInitialResponseState, QmpError> {
        if self.sent {
            return Err(malformed("original first callback was already submitted"));
        }
        self.sent = true;
        self.exchange(client, self.original)
    }

    /// Polls the retained original callback without repeating Submit or RUN.
    ///
    /// After transport ambiguity, the enclosing capsule must authenticate a
    /// replacement channel to the same child. Original row labels never provide
    /// that authority. Accepted lifetime facts remain independent of later More.
    ///
    /// # Errors
    /// Refuses observation before submission or propagates native, transport,
    /// changed-original and regressed-history errors without clearing taint.
    pub fn reconcile<S: QmpTimeoutStream>(
        &mut self,
        client: &mut QmpClient<S>,
    ) -> Result<QmpKvmInitialResponseState, QmpError> {
        if !self.sent {
            return Err(malformed("original first callback was not submitted"));
        }
        self.exchange(
            client,
            QmpKvmInitialResponseRequest {
                operation: QmpKvmInitialResponseOperation::Poll,
                ..self.original
            },
        )
    }

    fn exchange<S: QmpTimeoutStream>(
        &mut self,
        client: &mut QmpClient<S>,
        request: QmpKvmInitialResponseRequest,
    ) -> Result<QmpKvmInitialResponseState, QmpError> {
        let result = exchange_component(
            client,
            QmpCommand::KvmInitialResponse { request: &request },
            |value| {
                let state = parse_response(&request, value)?;
                self.latest = Some(state);
                self.validate_original(&state)?;
                self.accepted = Some(state);
                Ok(state)
            },
        );
        match &result {
            Ok(state) => {
                self.uncertain_effects |= state.observed().uncertain_effects
                    || state.observed().opaque_effects
                    || state.observed().callback_result < 0;
            }
            Err(_) => self.uncertain_effects = true,
        }
        result
    }

    fn validate_original(&self, state: &QmpKvmInitialResponseState) -> Result<(), QmpError> {
        let observed = state.observed();
        if observed.vcpu_index != self.identity.vcpu_index
            || observed.native_vcpu_id != self.identity.native_vcpu_id
            || !observed.submitted
            || observed.exit_sequence != self.receipt.response_sequence
        {
            return Err(malformed(
                "first callback changed its retained original owner or fragment",
            ));
        }
        if let Some(previous) = self.accepted {
            let prior = previous.observed();
            if observed.service_id != prior.service_id
                || prior.completed && !observed.completed
                || prior.result_known && !observed.result_known
                || prior.completed && observed.callback_result != prior.callback_result
                || prior.uncertain_effects && !observed.uncertain_effects
                || prior.opaque_effects && !observed.opaque_effects
            {
                return Err(malformed(
                    "first callback changed or regressed its original result history",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "transaction_tests.rs"]
mod tests;
