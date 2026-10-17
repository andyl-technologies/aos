//! Sends only trusted, retained original controls beneath the launch guard.
//!
//! The mechanical SDK retransmission preserves original journal custody. The
//! installed qualifier authorizes the full fixed population and independently
//! rechecks actual provider-only custody before each possible wire effect.

use crucible_node_contract::{Id, canonical};
use crucible_node_provider::bodies::ResponseBody;

use crate::node_contract::{EffectKnowledge, OperationFailure};

use super::{CnpLaunchGuard, CnpReferenceQualification};

const MAXIMUM_RESENDS: usize = 16;
const MAXIMUM_RESPONSE_BYTES: usize = 1024 * 1024;

impl CnpLaunchGuard {
    /// Retransmits a source-planned population of unchanged retained originals.
    ///
    /// This qualification seam grants no execution or native progress. The
    /// original controller, registrar, journals and uncertain transmissions
    /// remain beneath the attached guard. It returns only decoded data replies.
    /// Actual transmitted frames are separately observed by the pre-reserved
    /// SDK transmission archive; the ordinary exchange cache is bypassed.
    ///
    /// # Errors
    /// Refuses by default, unplanned IDs, absent original attached custody or
    /// finite reply reservations. After any possible transmission every error
    /// is Unknown and retains the existing guard and original journals.
    pub fn resend_pre_realization_originals(
        &mut self,
        qualification: &dyn CnpReferenceQualification,
        original_requests: &[Id],
    ) -> Result<Vec<ResponseBody>, OperationFailure> {
        if original_requests.is_empty() || original_requests.len() > MAXIMUM_RESENDS {
            return Err(failure("CNP source resend population ceiling", false));
        }
        for (index, request) in original_requests.iter().enumerate() {
            if original_requests[..index].contains(request) {
                return Err(failure("CNP source resend original repeated", false));
            }
        }
        let mut replies = Vec::new();
        replies
            .try_reserve_exact(original_requests.len())
            .map_err(|_| failure("CNP source resend reply slots unavailable", false))?;
        let maximum_bytes = original_requests
            .len()
            .checked_mul(MAXIMUM_RESPONSE_BYTES)
            .ok_or_else(|| failure("CNP source resend reply bytes overflow", false))?;
        let mut reply_arena = Vec::new();
        reply_arena
            .try_reserve_exact(maximum_bytes)
            .map_err(|_| failure("CNP source resend reply arena unavailable", false))?;
        let custody = self
            .custody
            .as_ref()
            .ok_or_else(|| failure("CNP source resend custody absent", false))?;
        if custody.controller.is_none()
            || custody.handshake.is_none()
            || custody.companion.is_some()
            || custody.runtime.is_some()
        {
            return Err(failure(
                "CNP source resend attached preparation scope differs",
                false,
            ));
        }
        // Cached companion absence is insufficient. The default qualifier
        // refuses, and the concrete source policy checks original body scope
        // plus a bounded actual provider-only census before every invocation.
        qualification.authenticate_pre_realization_resends(self, original_requests)?;
        let mut dispatched = false;
        for request in original_requests {
            qualification
                .authenticate_pre_realization_resends(self, original_requests)
                .map_err(|mut error| {
                    if dispatched {
                        error.effects = EffectKnowledge::Unknown;
                    }
                    error
                })?;
            let controller = self
                .custody
                .as_mut()
                .and_then(|custody| custody.controller.as_mut())
                .ok_or_else(|| failure("CNP source resend original controller lost", dispatched))?;
            dispatched = true;
            let response = controller
                .resend_original_control(request)
                .map_err(|error| failure(&error.to_string(), true))?;
            let value = serde_json::to_value(&response.shape)
                .map_err(|error| failure(&error.to_string(), true))?;
            let bytes = canonical::canonical_json(&value)
                .map_err(|error| failure(&error.to_string(), true))?;
            if bytes.len() > MAXIMUM_RESPONSE_BYTES
                || reply_arena
                    .len()
                    .checked_add(bytes.len())
                    .is_none_or(|total| total > maximum_bytes)
            {
                return Err(failure("CNP source resend raw reply ceiling", true));
            }
            reply_arena.extend_from_slice(&bytes);
            replies.push(response);
        }
        Ok(replies)
    }
}

fn failure(reason: &str, dispatched: bool) -> OperationFailure {
    OperationFailure {
        effects: if dispatched {
            EffectKnowledge::Unknown
        } else {
            EffectKnowledge::None
        },
        reason: reason.into(),
    }
}
