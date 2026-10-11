//! Separately observed same-ID changed-body controls under original custody.
//!
//! Ordinary calls and unchanged resends retain their existing semantics. These
//! mechanical methods require a preinstalled conflict recorder; the attached
//! source-qualified guard independently authorizes each hostile body and phase.

use super::super::session::original_conflict::{OriginalConflictProposal, OriginalConflictScope};
use super::conflict_transmissions::{
    OriginalConflictLimits, OriginalConflictObservationHandle, OriginalConflictRecorder,
};
use super::*;
use crate::envelope::RequestOrigin;

impl ReferenceController {
    /// Reserves a separate finite conflict archive before any original control.
    ///
    /// The returned handle reads inert data without exposing control authority.
    /// Original request/response and changed request/response bytes have separate
    /// roles; this archive cannot represent unchanged-response verification.
    ///
    /// # Errors
    /// Refuses late/repeated installation or unavailable finite reservations.
    pub fn observe_original_conflicts(
        &mut self,
        limits: OriginalConflictLimits,
    ) -> Result<OriginalConflictObservationHandle, ProviderError> {
        if self.conflicts.is_some() || self.custody.originals().next().is_some() {
            return Err(ProviderError::Correlation(
                "conflict recorder must precede original controls",
            ));
        }
        let (recorder, handle) = OriginalConflictRecorder::reserve(
            self.session.authority(),
            limits,
            &self.bootstrap.admission_token,
        )?;
        self.conflicts = Some(recorder);
        Ok(handle)
    }

    /// Transmits changed material under a retained discovery or not-started ID.
    ///
    /// Only body and the actual connection sequence change. This bypasses the
    /// local original cache and requires an actual CONFLICT/NotStarted response.
    /// Source-owned guard policy must authenticate the exact predeclared body and
    /// current native custody before invoking this mechanical transport operation.
    ///
    /// # Errors
    /// Refuses absent original/recorder, private bodies, unchanged material,
    /// unsupported scope, exhausted credits, a different refusal or transport
    /// ambiguity. The original journal and cached outcome remain unchanged.
    ///
    /// # Panics
    /// Resumes a transport verifier unwind after fencing the connection and
    /// retaining the incomplete original conflict observation.
    pub fn probe_original_body_conflict(
        &mut self,
        request_id: &Id,
        changed_body: &serde_json::Map<String, Value>,
    ) -> Result<ResponseBody, ProviderError> {
        self.probe_body_conflict(
            request_id,
            changed_body,
            OriginalConflictScope::DiscoveryOrNotStarted,
        )
    }

    /// Transmits changed material under a retained completed lifecycle ID.
    ///
    /// Direct original receipt bytes must remain possessed. The installed guard
    /// must authenticate their complete codec closure and an exact live native
    /// phase. This separate scope does not widen discovery/refusal conflicts.
    ///
    /// # Errors
    /// Refuses missing evidence, unsupported or uncertain originals, invalid
    /// bodies, exhausted credits, non-conflict replies or ambiguous transport.
    /// Original successful effects and their immutable responses are retained.
    ///
    /// # Panics
    /// Resumes a transport verifier unwind after fencing the connection and
    /// retaining the incomplete original conflict observation.
    pub fn probe_completed_lifecycle_body_conflict(
        &mut self,
        request_id: &Id,
        changed_body: &serde_json::Map<String, Value>,
    ) -> Result<ResponseBody, ProviderError> {
        self.probe_body_conflict(
            request_id,
            changed_body,
            OriginalConflictScope::CompletedLifecycle,
        )
    }

    fn probe_body_conflict(
        &mut self,
        request_id: &Id,
        changed_body: &serde_json::Map<String, Value>,
        scope: OriginalConflictScope,
    ) -> Result<ResponseBody, ProviderError> {
        let original = self
            .custody
            .original(RequestOrigin::Controller, request_id)
            .ok_or(ProviderError::Correlation(
                "conflict original journal absent",
            ))?;
        let response = original
            .response
            .as_ref()
            .ok_or(ProviderError::Correlation("conflict original unresolved"))?;
        let mut attempted = original.request.clone();
        attempted.body = changed_body.clone();
        for frame in [&original.request, response, &attempted] {
            evidence::reject_private_envelope(frame, self.bootstrap.admission_token.as_slice())?;
        }
        if matches!(scope, OriginalConflictScope::CompletedLifecycle) {
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
        }
        let recorder = self.conflicts.as_ref().ok_or(ProviderError::Correlation(
            "conflict observations were not pre-reserved",
        ))?;
        let returned = self.session.probe_original_body_conflict(
            &self.custody,
            OriginalConflictProposal {
                request_id,
                changed_body,
                scope,
            },
            self.budget,
            recorder,
        )?;
        let body = decode_request(returned.method, changed_body)?;
        decode_response(&body, &returned.body)
    }
}
