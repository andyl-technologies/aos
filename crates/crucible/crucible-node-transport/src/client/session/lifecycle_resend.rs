//! Mechanical duplicates of retained completed lifecycle and window originals.
//!
//! Selection authenticates no source or native state. A separate guard-owned
//! installed policy must authorize the original phase, identity and complete
//! evidence closure. Running, uncertain, canceled and teardown work is excluded.

use super::resend::OriginalResendScope;
use super::*;
use crate::client::reference::transmissions::TransmissionRecorder;

impl ClientSession {
    pub(crate) fn resend_completed_lifecycle_original(
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
            OriginalResendScope::CompletedLifecycle,
        )
    }
}

pub(super) fn validate_completed_lifecycle(
    request: &RequestBody,
    response: &ResponseBody,
) -> Result<(), ProviderError> {
    if !matches!(
        response.shape,
        ResponseShape::Completed {
            operation_state: OperationState::Completed,
            ..
        }
    ) || response.result.is_none()
    {
        return Err(ProviderError::Correlation(
            "lifecycle resend original is not known completed",
        ));
    }
    let supported = match request {
        RequestBody::Realize(_)
        | RequestBody::Admit(_)
        | RequestBody::Activate(_)
        | RequestBody::WorldActivate(_)
        | RequestBody::Input(_)
        | RequestBody::Observe(_)
        | RequestBody::Poll(_)
        | RequestBody::QuantumClose(_) => true,
        RequestBody::Begin(begin) => begin.kind == BeginKind::QuantumBegin,
        RequestBody::Retire(retire) => retire.disposition == RetirementDisposition::Consumed,
        _ => false,
    };
    if !supported {
        return Err(ProviderError::Correlation(
            "lifecycle resend method is outside the selected scope",
        ));
    }
    Ok(())
}
