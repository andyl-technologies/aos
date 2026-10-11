//! Transmits a changed body under a retained ID without replacing its original.
//!
//! Source-qualified callers own the hostile-body population and native phase.
//! This module owns mechanical transport only, with a separately reserved raw
//! archive. A verified conflict response grants no replacement execution.

use crate::envelope::Method;

pub(in crate::client) enum OriginalConflictScope {
    DiscoveryOrNotStarted,
    CompletedLifecycle,
}
use super::*;
use crate::bodies::{EffectCertainty, MethodResult, OperationState, ResponseShape};
use crate::client::reference::conflict_transmissions::OriginalConflictRecorder;

pub(in crate::client) struct OriginalConflictProposal<'a> {
    pub(in crate::client) request_id: &'a Id,
    pub(in crate::client) changed_body: &'a Map<String, Value>,
    pub(in crate::client) scope: OriginalConflictScope,
}

impl ClientSession {
    pub(in crate::client) fn probe_original_body_conflict(
        &mut self,
        custody: &ClientCustody,
        proposal: OriginalConflictProposal<'_>,
        budget: Duration,
        recorder: &OriginalConflictRecorder,
    ) -> Result<Envelope, ProviderError> {
        let OriginalConflictProposal {
            request_id,
            changed_body,
            scope,
        } = proposal;
        self.authority.ensure_live()?;
        self.deadline.reset(budget)?;
        let original = custody
            .controller
            .get(request_id)
            .ok_or(ProviderError::Correlation(
                "conflict original journal entry absent",
            ))?;
        let response = original
            .response
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "conflict original outcome unresolved",
            ))?;
        if original.request.request_hash(RequestOrigin::Controller)? != original.identity {
            return Err(ProviderError::Conflict(
                "conflict original identity changed",
            ));
        }
        original.request.matches_response(response)?;
        let original_body = decode_request(original.request.method, &original.request.body)?;
        let original_response = decode_response(&original_body, &response.body)?;
        match scope {
            OriginalConflictScope::DiscoveryOrNotStarted => {
                let known_refusal = matches!(original_response.shape,
                    ResponseShape::Error { operation_state: OperationState::NotStarted, ref error, .. }
                        if error.effect == EffectCertainty::NotStarted);
                let known_discovery = original.request.method == Method::Discover
                    && matches!(
                        original_response.shape,
                        ResponseShape::Completed {
                            operation_state: OperationState::Completed,
                            ..
                        }
                    )
                    && matches!(original_response.result, Some(MethodResult::Discover(_)));
                if !known_discovery && !known_refusal {
                    return Err(ProviderError::Correlation(
                        "conflict original is outside discovery/refusal scope",
                    ));
                }
            }
            OriginalConflictScope::CompletedLifecycle => {
                super::lifecycle_resend::validate_completed_lifecycle(
                    &original_body,
                    &original_response,
                )?;
            }
        }
        if original.request.method == Method::Hello {
            return Err(ProviderError::Correlation(
                "private hello cannot enter conflict observations",
            ));
        }
        let mut request = original.request.clone();
        request.sequence = self.sequence;
        request.body = changed_body.clone();
        let typed_attempt = decode_request(request.method, &request.body)?;
        if request.request_hash(RequestOrigin::Controller)? == original.identity {
            return Err(ProviderError::Conflict(
                "conflict requires changed original material",
            ));
        }
        let response_credit = usize::try_from(self.authority.limits().frame_bytes.get())
            .map_err(|_| ProviderError::ResourceExhausted("conflict response platform bound"))?;
        let mut attempt = recorder.begin(
            &self.authority,
            &request,
            &original.request,
            response,
            response_credit,
        )?;

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.send(request.clone())?;
            attempt.sent()?;
            let frame = self
                .connection
                .receive()?
                .ok_or(ProviderError::Correlation(
                    "conflict response remains unknown",
                ))?;
            attempt.received(&frame.envelope)?;
            if !matches!(frame.body, ReceivedBody::Response(_)) {
                return Err(ProviderError::Correlation(
                    "conflict received unexpected control",
                ));
            }
            request.matches_response(&frame.envelope)?;
            let returned = decode_response(&typed_attempt, &frame.envelope.body)?;
            if !matches!(returned.shape,
                ResponseShape::Error { operation_state: OperationState::NotStarted, ref error, .. }
                    if error.code == "CONFLICT" && error.effect == EffectCertainty::NotStarted)
            {
                return Err(ProviderError::Conflict(
                    "provider did not refuse changed material as not-started conflict",
                ));
            }
            attempt.completed()?;
            Ok(frame.envelope)
        }));
        match result {
            Ok(result) => {
                if result.is_err() {
                    self.connection.close();
                }
                result
            }
            Err(payload) => {
                self.connection.close();
                std::panic::resume_unwind(payload)
            }
        }
    }
}
