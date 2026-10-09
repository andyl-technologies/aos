//! Guard-authorized completed lifecycle duplicates with retained evidence roots.
//!
//! This mechanical SDK path does not qualify a source, interpret codec-dependent
//! native receipt authority or grant progress. The attached native guard must
//! authenticate the predeclared original operation and complete evidence closure
//! before invoking it. No replacement bodies, owners or operations are accepted.

use super::*;
use crate::envelope::RequestOrigin;

impl ReferenceController {
    /// Sends an unchanged retained completed lifecycle or window original again.
    ///
    /// Direct original response references must already be present as verified
    /// bytes. The source-qualified guard additionally authenticates the complete
    /// codec-declared closure and current native phase before every invocation.
    /// This separate path does not widen `resend_original_control`.
    ///
    /// # Errors
    /// Refuses absent original or recorder, private controls, unavailable original
    /// content, unsupported/running/uncertain work, credit exhaustion, changed
    /// responses or transport loss. The original journals remain unchanged.
    pub fn resend_completed_lifecycle_original(
        &mut self,
        request_id: &Id,
    ) -> Result<ResponseBody, ProviderError> {
        let original = self
            .custody
            .original(RequestOrigin::Controller, request_id)
            .ok_or(ProviderError::Correlation(
                "completed lifecycle original journal absent",
            ))?;
        let response = original
            .response
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "completed lifecycle original unresolved",
            ))?;
        evidence::reject_private_envelope(
            &original.request,
            self.bootstrap.admission_token.as_slice(),
        )?;
        evidence::reject_private_envelope(response, self.bootstrap.admission_token.as_slice())?;
        let request = decode_request(original.request.method, &original.request.body)?;
        let decoded = decode_response(&request, &response.body)?;
        let mut roots = Vec::new();
        references(&Value::Object(response.body.clone()), &mut roots)?;
        for reference in roots {
            if !self
                .profile
                .implementation
                .artifacts
                .iter()
                .any(|artifact| artifact.content == reference)
            {
                self.custody.content().get(&reference)?;
            }
        }
        let recorder = self
            .transmissions
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "lifecycle resend observations were not pre-reserved",
            ))?;
        let response = self.session.resend_completed_lifecycle_original(
            &self.custody,
            request_id,
            self.budget,
            recorder,
        )?;
        // Decode against the same retained request; decoding grants no native
        // receipt authority. Session already compared the entire actual reply.
        let returned = decode_response(&request, &response.body)?;
        if returned != decoded {
            self.session.close();
            return Err(ProviderError::Conflict(
                "completed lifecycle semantic response differs",
            ));
        }
        Ok(returned)
    }
}
