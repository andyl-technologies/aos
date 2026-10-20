//! Routes public Delete into the sole genuine Runtime collection and finalizer.
//!
//! The installed concrete executor keeps authorization, Source/C17, four
//! exclusive Sessions, Cache and Root continuously owned through actual native
//! cleanup and final disposition. Generic public compilation remains closed.

use super::*;

impl<E: SingleNodeEffectExecutor>
    NodeController<crate::production_operation_compiler::ProductionOperationCompilerV1, E>
{
    /// Completes a public Delete through its original protected native owners.
    ///
    /// # Errors
    /// Refuses malformed size, unavailable concrete ownership or original
    /// authorization. Entered failures remain resident with their owed posts.
    #[doc(hidden)]
    pub fn admit_public_original_delete_once_v4(
        &mut self,
        peer: &crate::public_api_session::PublicApiPeer,
        capability: aos_sandbox_core::CapabilityId,
        handle: &[u8],
        canonical_request: &[u8],
    ) -> Result<AcceptOutcome, ControllerServiceError> {
        if canonical_request.is_empty() {
            return Err(ControllerServiceError::EmptyRequest);
        }
        if canonical_request.len() > self.limits.maximum_request_bytes {
            return Err(ControllerServiceError::RequestTooLarge);
        }
        self.reconciler
            .admit_original_delete_once_v4(peer, capability, handle, canonical_request)
            .map_err(|_| OperationCompilationError::Rejected.into())
    }
}
