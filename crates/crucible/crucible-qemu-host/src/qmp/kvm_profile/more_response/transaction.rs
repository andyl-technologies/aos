//! Retained native More birth, one callback submission and original result cache.

use super::{
    QmpClient, QmpCommand, QmpError, QmpKvmMoreResponseOperation, QmpKvmMoreResponseRequest,
    QmpKvmMoreResponseState, QmpTimeoutStream, exchange_component, malformed, parse_response,
    validate_request,
};
use crate::qmp::{QmpKvmResponseBytesPayloadKind, QmpKvmResponseBytesState};

/// Retains one actual native More result before its paused callback submission.
///
/// Preparation consumes the checked byte result, preserving its original data
/// without another payload allocation. The enclosing authenticated owner must
/// reserve its journal before dispatch. These facts do not qualify execution,
/// physical stop, device closure or exact continuation.
#[derive(Debug)]
pub struct QmpKvmMoreResponseTransaction {
    original: QmpKvmMoreResponseRequest,
    birth: QmpKvmResponseBytesState,
    sent: bool,
    uncertain_effects: bool,
    accepted: Option<QmpKvmMoreResponseState>,
    latest: Option<QmpKvmMoreResponseState>,
}

impl QmpKvmMoreResponseTransaction {
    /// Takes custody of the checked native completion that produced this More.
    ///
    /// An input echo or current Query cannot establish the required original
    /// completion identity. Native labels alone never provide peer authority.
    ///
    /// # Errors
    /// Refuses unknown, opaque, uncertain, negative or non-More native results
    /// before callback submission, including wrong payload classification.
    pub fn prepare(birth: QmpKvmResponseBytesState) -> Result<Self, QmpError> {
        let native = birth.observed();
        if native.payload_kind != QmpKvmResponseBytesPayloadKind::NativeResult
            || !native.result_known
            || native.native_phase != 2
            || native.callback_result < 0
            || native.uncertain_effects
            || native.opaque_effects
        {
            return Err(malformed(
                "More callback requires its checked original native completion",
            ));
        }
        let original = QmpKvmMoreResponseRequest {
            operation: QmpKvmMoreResponseOperation::Submit,
            vcpu_index: native.vcpu_index,
            completion_id: native.operation_id,
            exit_sequence: native.pending_sequence,
        };
        validate_request(&original)?;
        Ok(Self {
            original,
            birth,
            sent: false,
            uncertain_effects: false,
            accepted: None,
            latest: None,
        })
    }

    /// Borrows the unchanged original paused callback submission.
    pub fn original(&self) -> &QmpKvmMoreResponseRequest {
        &self.original
    }

    /// Borrows the full retained native completion and original binary fragment.
    pub fn birth(&self) -> &QmpKvmResponseBytesState {
        &self.birth
    }

    /// Reports sticky native, transport or conflicting-history uncertainty.
    pub fn uncertain_effects(&self) -> bool {
        self.uncertain_effects
    }

    /// Borrows the latest structurally checked facts, including a retained conflict.
    pub fn latest(&self) -> Option<&QmpKvmMoreResponseState> {
        self.latest.as_ref()
    }

    /// Submits this original paused callback once, retaining its birth on failure.
    ///
    /// # Errors
    /// Refuses repeated submission before I/O or propagates native, transport,
    /// original-owner and history failures. The original byte result is unchanged.
    pub fn dispatch_once<S: QmpTimeoutStream>(
        &mut self,
        client: &mut QmpClient<S>,
    ) -> Result<QmpKvmMoreResponseState, QmpError> {
        if self.sent {
            return Err(malformed("original More callback was already submitted"));
        }
        self.sent = true;
        self.exchange(client, self.original)
    }

    /// Recovers the original result without repeating its callback.
    ///
    /// A known result is returned from this retained original record. The source
    /// only caches its current per-CPU callback, so a later original must not
    /// force revalidation or reinterpretation of this historical result. Pending
    /// recovery uses Poll on an authenticated channel to the same native child.
    ///
    /// # Errors
    /// Refuses recovery before Submit and propagates failed, foreign or regressed
    /// observations. Sticky uncertainty is never cleared by a later known result.
    pub fn reconcile<S: QmpTimeoutStream>(
        &mut self,
        client: &mut QmpClient<S>,
    ) -> Result<QmpKvmMoreResponseState, QmpError> {
        if !self.sent {
            return Err(malformed("original More callback was not submitted"));
        }
        if let Some(retained) = self.accepted.filter(|state| state.observed().result_known) {
            return Ok(retained);
        }
        self.exchange(
            client,
            QmpKvmMoreResponseRequest {
                operation: QmpKvmMoreResponseOperation::Poll,
                ..self.original
            },
        )
    }

    fn exchange<S: QmpTimeoutStream>(
        &mut self,
        client: &mut QmpClient<S>,
        request: QmpKvmMoreResponseRequest,
    ) -> Result<QmpKvmMoreResponseState, QmpError> {
        let result = exchange_component(
            client,
            QmpCommand::KvmMoreResponse { request: &request },
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
                    || state.observed().callback_result < 0
            }
            Err(_) => self.uncertain_effects = true,
        }
        result
    }

    fn validate_original(&self, state: &QmpKvmMoreResponseState) -> Result<(), QmpError> {
        let observed = state.observed();
        if observed.kernel_vcpu_id != u64::from(self.birth.observed().native_vcpu_id)
            || !observed.submitted
        {
            return Err(malformed(
                "More callback changed its retained original native owner",
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
                    "More callback changed its original retained history",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "transaction_tests.rs"]
mod tests;
