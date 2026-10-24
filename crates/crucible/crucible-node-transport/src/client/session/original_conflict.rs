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
            if !terminal_conflict(&returned.shape, &frame.envelope.extensions) {
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

// Completion belongs to the actual immutable wire response, including its
// refusal certainty and both extension layers. A retryable/error-context reply
// remains an unfinished original attempt, so its archive cannot retire.
fn terminal_conflict(
    response: &ResponseShape,
    envelope_extensions: &crucible_node_format::Extensions,
) -> bool {
    envelope_extensions.is_empty()
        && matches!(response,
        ResponseShape::Error {
            operation_state: OperationState::NotStarted, error, extensions,
        } if error.code == "CONFLICT" && error.effect == EffectCertainty::NotStarted
            && !error.retryable && extensions.is_empty())
}

#[cfg(test)]
mod terminal_conflict_tests {
    use super::*;
    use crate::bodies::ErrorRecord;
    use crucible_node_format::Extensions;

    #[test]
    fn conflict_completion_refuses_retryable_unknown_and_extended_original_replies() {
        let original = ResponseShape::Error {
            operation_state: OperationState::NotStarted,
            error: ErrorRecord {
                code: "CONFLICT".into(),
                message: "original source refusal".into(),
                effect: EffectCertainty::NotStarted,
                retryable: false,
                details: Default::default(),
            },
            extensions: Extensions::new(),
        };
        assert!(terminal_conflict(&original, &Extensions::new()));

        let mut retryable = original.clone();
        if let ResponseShape::Error { error, .. } = &mut retryable {
            error.retryable = true;
        }
        assert!(!terminal_conflict(&retryable, &Extensions::new()));
        let mut uncertain = original.clone();
        if let ResponseShape::Error { error, .. } = &mut uncertain {
            error.effect = EffectCertainty::Unknown;
        }
        assert!(!terminal_conflict(&uncertain, &Extensions::new()));
        let mut running = original.clone();
        if let ResponseShape::Error {
            operation_state, ..
        } = &mut running
        {
            *operation_state = OperationState::Running;
        }
        assert!(!terminal_conflict(&running, &Extensions::new()));
        let mut unknown = original.clone();
        if let ResponseShape::Error { error, .. } = &mut unknown {
            error.code = "unknown-source-code".into();
        }
        assert!(!terminal_conflict(&unknown, &Extensions::new()));

        let mut body_context = original.clone();
        if let ResponseShape::Error { extensions, .. } = &mut body_context {
            extensions.insert("unexpected".into(), Value::Null);
        }
        assert!(!terminal_conflict(&body_context, &Extensions::new()));
        let mut envelope_context = Extensions::new();
        envelope_context.insert("unexpected".into(), Value::Null);
        assert!(!terminal_conflict(&original, &envelope_context));
    }
}
