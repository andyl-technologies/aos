//! Guard-owned explicit wire resends and separately reserved inert observations.
//!
//! This child belongs beneath `client::reference`. The core adapter must first
//! authenticate its exact source-planned request population and native custody.
//! These SDK mechanics cannot authenticate a provider receipt or qualify a case.

use super::*;

use transmissions::{TransmissionLimits, TransmissionObservationHandle, TransmissionRecorder};

impl ReferenceController {
    /// Reserves wire-transmission observations before any original control.
    ///
    /// The default controller has no resend recorder. Its ordinary exchange
    /// cache and traffic remain unchanged. The returned handle is data-only.
    ///
    /// # Errors
    /// Refuses late or repeated installation, foreign connection custody, invalid
    /// finite ceilings or unavailable complete archive reservations.
    pub fn observe_resends(
        &mut self,
        limits: TransmissionLimits,
    ) -> Result<TransmissionObservationHandle, ProviderError> {
        if self.transmissions.is_some() || self.custody.originals().next().is_some() {
            return Err(ProviderError::Correlation(
                "resend recorder must precede original controls",
            ));
        }
        let (recorder, handle) = TransmissionRecorder::reserve(
            self.session.authority(),
            limits,
            &self.bootstrap.admission_token,
        )?;
        self.transmissions = Some(recorder);
        Ok(handle)
    }

    /// Retransmits an unchanged retained discovery or original not-started refusal.
    ///
    /// This operation performs a new actual send/read with the next connection
    /// sequence. It keeps the original request and cached response unchanged.
    /// Source-qualified core callers independently authorize their fixed request
    /// IDs before invoking this mechanical API. It does not grant progress.
    ///
    /// # Errors
    /// Refuses absent recorder or original journal, unsupported control scope,
    /// exhausted transmission credit, changed outcome, or uncertain transport.
    /// Transport errors fence the stream while preserving both journals.
    pub fn resend_original_control(
        &mut self,
        request_id: &Id,
    ) -> Result<ResponseBody, ProviderError> {
        let original = self
            .custody
            .original(crate::envelope::RequestOrigin::Controller, request_id)
            .ok_or(ProviderError::Correlation(
                "wire resend original journal absent",
            ))?;
        evidence::reject_private_envelope(
            &original.request,
            self.bootstrap.admission_token.as_slice(),
        )?;
        if let Some(response) = &original.response {
            evidence::reject_private_envelope(response, self.bootstrap.admission_token.as_slice())?;
        }
        let recorder = self
            .transmissions
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "wire resend observations were not pre-reserved",
            ))?;
        let response = self.session.resend_original_control(
            &self.custody,
            request_id,
            self.budget,
            recorder,
        )?;
        let original = self
            .custody
            .original(crate::envelope::RequestOrigin::Controller, request_id)
            .ok_or(ProviderError::Correlation(
                "wire resend original journal was lost",
            ))?;
        let body = decode_request(original.request.method, &original.request.body)?;
        decode_response(&body, &response.body)
    }
}
