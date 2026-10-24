//! Produces a fresh native proof only under a spent recurring-Observe scope.
//!
//! Baseline Observe retains its ordinary body and proof formats. This private
//! route requires the actual received startup16 owner and published first MAC
//! witness, current transferred model geometry and an already debited action.

use super::*;
use crate::reference_packet::service::ack_emitter::OriginalRestoredSuffixObserveRead;

impl PacketControl {
    /// Produces a fresh proof for the same separately debited native original.
    ///
    /// # Errors
    /// Refuses cached/foreign requests, missing release or scope correspondence,
    /// proof construction failure and failed prefix preparation.
    pub(crate) fn dispatch_original_restored_suffix_observation_with_preflight(
        &mut self,
        request: &Envelope,
        scope: &OriginalRestoredSuffixObserveRead<'_>,
        prepare: &mut dyn FnMut(&PacketControlReply) -> Result<(), ProviderError>,
    ) -> Result<&PacketControlReply, ProviderError> {
        if request.method != Method::Observe
            || !self.immediate
            || self.fenced
            || request
                .request_id
                .0
                .as_ref()
                .is_none_or(|id| self.originals.contains_key(id))
        {
            return Err(ProviderError::Correlation(
                "recurring Observe original dispatch differs",
            ));
        }
        scope.authenticate_control_request_data(request, &self.selection, self)?;
        self.dispatch_prepared_with_restoration_permissions(
            request,
            &mut ReplyPreparation {
                callback: Some(prepare),
                attempted: false,
            },
            OriginalControlPermissionsData {
                canonical_ack_admit: None,
                selected_observe: None,
                restoration_activation: None,
                restoration_observation: None,
                suffix_observation: Some(scope),
                producer_action: None,
            },
        )
    }
}

/// Counts the borrowed private dispatch and callback headers independently.
pub(crate) fn original_restored_suffix_observation_control_counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<&OriginalRestoredSuffixObserveRead<'static>>()
        + size_of::<Option<&OriginalRestoredSuffixObserveRead<'static>>>()
        + size_of::<&PacketControlReply>()
        + size_of::<Result<&PacketControlReply, ProviderError>>()
        + size_of::<ReplyPreparation<'static>>()
        + size_of::<&mut dyn FnMut(&PacketControlReply) -> Result<(), ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
}
