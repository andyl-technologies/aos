//! Conjoins installed durable release with the same actually reclaimed runtime.
//!
//! The caller keeps the original Option occupied across qualification refusal or
//! unwind. A successful callback must own an opaque installed supervisor permit
//! joining exact original durable histories, disposition and native safe-release;
//! serialization, observed exit or a copied reclamation receipt is insufficient.

use super::{QuarantinedRuntime, RuntimeError, WorldActivation};

/// Supplies independently installed qualification for original retirement release.
///
/// Implementations must authenticate their actual retained supervisor, the
/// original same-world history and durable disposition. The default refuses;
/// this callback is not a native continuation or ordinary capability issuer.
pub trait GracefulRetirementQualification {
    /// Authenticates complete durable history and actual supervisor safe-release.
    ///
    /// # Errors
    /// Refuses unsupported release, foreign current authority, incomplete source
    /// history, uncertain original disposition or unavailable actual native proof.
    fn authenticate_release(
        &self,
        _original: &QuarantinedRuntime,
        _activation: &WorldActivation,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::UnsupportedFacet)
    }
}

impl QuarantinedRuntime {
    /// Releases the same capsule after actual transfer and installed authentication.
    ///
    /// Every fallible check and callback precedes taking the owning Option. A
    /// refusal or unwind retains its Host/COW/native history and admitted credit.
    /// Successful release grants no restoration, rollback or operation replay.
    ///
    /// # Errors
    /// Refuses absent custody, another opaque activation, incomplete original
    /// Shutdown/reaping/transfer, or default-refused installed authentication.
    ///
    /// # Panics
    /// Propagates installed authentication callback panics. Authentication runs
    /// before taking the original Option, so its unwind retains that same owner.
    pub fn release_after_authenticated_supervision(
        original: &mut Option<Self>,
        activation: &WorldActivation,
        qualification: &dyn GracefulRetirementQualification,
    ) -> Result<(), RuntimeError> {
        let retained = original
            .as_ref()
            .ok_or(RuntimeError::OutstandingObligations)?;
        retained.runtime.validate_activation(activation)?;
        if !retained.runtime.graceful_retirement
            || retained.shutdown_failure.is_some()
            || retained.remaining_owners() != 0
            || !retained.retirement_transferred
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        qualification.authenticate_release(retained, activation)?;

        // No adapter or storage callback runs after the unique mailbox is
        // released. Actual nodes retain their graceful purpose on field Drop.
        let retained = original
            .as_mut()
            .ok_or(RuntimeError::OutstandingObligations)?;
        retained.runtime.release_retired_custody_slot()?;
        drop(original.take());
        Ok(())
    }
}
