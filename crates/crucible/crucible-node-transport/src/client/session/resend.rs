//! Explicit wire retransmission of an unchanged retained discovery or refusal.
//!
//! This child belongs beneath `client::session`. It deliberately bypasses the
//! ordinary exchange cache, while keeping the original request and response
//! untouched. The enclosing source-qualified guard supplies the case policy.

use super::*;
use crate::bodies::{EffectCertainty, OperationState, ResponseShape};
use crate::client::reference::transmissions::TransmissionRecorder;
use crate::envelope::Method;

pub(super) enum OriginalResendScope {
    DiscoveryOrNotStarted,
    CompletedLifecycle,
}

impl ClientSession {
    pub(crate) fn resend_original_control(
        &mut self,
        custody: &ClientCustody,
        request_id: &Id,
        budget: Duration,
        recorder: &TransmissionRecorder,
    ) -> Result<Envelope, ProviderError> {
        self.resend_with_scope(
            custody,
            request_id,
            budget,
            recorder,
            OriginalResendScope::DiscoveryOrNotStarted,
        )
    }

    pub(super) fn resend_with_scope(
        &mut self,
        custody: &ClientCustody,
        request_id: &Id,
        budget: Duration,
        recorder: &TransmissionRecorder,
        scope: OriginalResendScope,
    ) -> Result<Envelope, ProviderError> {
        self.authority.ensure_live()?;
        self.deadline.reset(budget)?;
        let original = custody
            .controller
            .get(request_id)
            .ok_or(ProviderError::Correlation(
                "wire resend original journal entry absent",
            ))?;
        let response = original
            .response
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "wire resend original outcome unresolved",
            ))?;
        let identity = original.request.request_hash(RequestOrigin::Controller)?;
        if identity != original.identity {
            return Err(ProviderError::Conflict(
                "wire resend original identity changed",
            ));
        }
        original.request.matches_response(response)?;
        let request_body = decode_request(original.request.method, &original.request.body)?;
        let response_body = decode_response(&request_body, &response.body)?;
        match scope {
            OriginalResendScope::DiscoveryOrNotStarted => {
                let known_refusal = matches!(
                    response_body.shape,
                    ResponseShape::Error { operation_state: OperationState::NotStarted, ref error, .. }
                        if error.effect == EffectCertainty::NotStarted
                );
                if original.request.method != Method::Discover && !known_refusal {
                    return Err(ProviderError::Correlation(
                        "wire resend is limited to discovery or original not-started refusal",
                    ));
                }
                if original.request.method == Method::Hello {
                    return Err(ProviderError::Correlation(
                        "private hello cannot enter wire observations",
                    ));
                }
            }
            OriginalResendScope::CompletedLifecycle => {
                super::lifecycle_resend::validate_completed_lifecycle(
                    &request_body,
                    &response_body,
                )?;
            }
        }

        // Only this actual connection's next transport sequence changes. Its
        // correlation guard still registers the outgoing original before write.
        let mut request = original.request.clone();
        request.sequence = self.sequence;
        if request.request_hash(RequestOrigin::Controller)? != identity {
            return Err(ProviderError::Conflict(
                "wire resend changed semantic request",
            ));
        }
        let maximum_response = usize::try_from(self.authority.limits().frame_bytes.get())
            .map_err(|_| ProviderError::ResourceExhausted("wire resend response platform bound"))?;
        let mut expected = response.clone();
        let mut attempt = recorder.begin(&self.authority, &request, &identity, maximum_response)?;

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // Every row starts Unknown before the first possible write. A
            // partial write or unwind never becomes a cached success.
            self.send(request.clone())?;
            attempt.sent()?;
            let frame = self
                .connection
                .receive()?
                .ok_or(ProviderError::Correlation(
                    "wire resend response remains unknown",
                ))?;
            attempt.received(&frame.envelope)?;
            if !matches!(frame.body, ReceivedBody::Response(_)) {
                return Err(ProviderError::Correlation(
                    "wire resend received unexpected control",
                ));
            }
            request.matches_response(&frame.envelope)?;
            expected.sequence = frame.envelope.sequence;
            if expected != frame.envelope {
                return Err(ProviderError::Conflict(
                    "provider changed original resend outcome",
                ));
            }
            attempt.completed()?;
            Ok(frame.envelope)
        }));
        let result = match result {
            Ok(result) => result,
            Err(payload) => {
                self.connection.close();
                std::panic::resume_unwind(payload);
            }
        };
        if result.is_err() {
            self.connection.close();
        }
        result
    }
}
