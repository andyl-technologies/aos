//! Faults abandoned recovery RPC effects and transfers actual durable custody.
//!
//! Creation, final verification, completion, explicit failure and destruction
//! must occur outside the publisher mutex. The consumer keeps the guard alive
//! through its full RPC and native verification, then transfers custody before
//! releasing the exclusive recovery turn. There is no effectful dispatch yet.

use super::*;

/// Retains the original exclusive recovery phase through one actual RPC effect.
///
/// An accepted guard faults on any abandoned/error path, including cancellation
/// during transport or verification. Physical executor source handles and durable
/// reservations/pins survive even if the entire guard is dropped. The guard is
/// neither an allocation guarantee nor permission for unsupported publication.
pub(crate) struct RecoveryManifestEffect<'phase, 'executor> {
    flight: InFlightRetention,
    pub(super) receipt: RecoveryRetainedManifest<'phase, 'executor>,
}

/// Retains lifetime-free durable custody after an unsuccessful recovery effect.
pub(crate) struct RecoveryManifestEffectFailure {
    error: io::Error,
    backing: RecoveryManifestBackingRetention,
}

impl RecoveryManifestEffectFailure {
    /// Returns the actual error and durable custody for the physical failure owner.
    pub(crate) fn into_parts(self) -> (io::Error, RecoveryManifestBackingRetention) {
        (self.error, self.backing)
    }
}

impl<'phase, 'executor> RecoveryManifestEffect<'phase, 'executor> {
    /// Arms an exclusive effect only from an actual current phase-bound receipt.
    ///
    /// # Errors
    /// Refuses changed original phase/session, source or durable pin custody.
    /// No new native RPC is submitted here; existing physical ownership remains.
    pub(super) fn begin(receipt: RecoveryRetainedManifest<'phase, 'executor>) -> io::Result<Self> {
        receipt.check_current()?;
        let flight = InFlightRetention::begin_effect(&receipt.live.phase);
        Ok(Self { flight, receipt })
    }

    /// Borrows exact original recovery authority without acquiring a client lock.
    pub(crate) fn live_context(&self) -> &LiveManifestRecoveryContext<'executor> {
        self.receipt.live
    }

    /// Borrows the actual retained canonical manifest witness for fixed wire IO.
    pub(crate) fn metadata_file(&self) -> &File {
        self.receipt_ref().metadata_file()
    }

    /// Borrows the independently verified manifest claim.
    pub(crate) fn claim(&self) -> &PublicationClaim {
        self.receipt_ref().claim()
    }

    /// Returns the exact canonical body range in the retained metadata pack.
    pub(crate) fn manifest_range(&self) -> ByteRange {
        self.receipt_ref().manifest_range()
    }

    /// Borrows the actual durable retention registration identifier.
    pub(crate) fn retention_id(&self) -> &[u8; 16] {
        self.receipt_ref().retention_id()
    }

    /// Borrows the original stable cache incarnation.
    pub(crate) fn cache_incarnation(&self) -> &[u8; 16] {
        self.receipt_ref().cache_incarnation()
    }

    /// Borrows the actual root/domain/profile binding retained with the source.
    pub(crate) fn layout(&self) -> &Arc<NativeHostLayout<HostDomainLocation>> {
        self.receipt_ref().layout()
    }

    /// Rechecks actual original phase/source/pins before a client mutex is held.
    ///
    /// # Errors
    /// Refuses changed native state or original Drain context. Consumers must
    /// still verify that exact original context atomically under their RPC lock.
    pub(crate) fn check_current(&self) -> io::Result<()> {
        self.receipt_ref()
            .check_current_phase(RecoveryPhase::EffectInFlight)
    }

    /// Transfers durable custody only after full RPC and native verification.
    ///
    /// This must run after releasing the client mutex. It performs original
    /// context and source/pin checks, synchronizes real retained backing/source
    /// allocation and fresh authenticated quota/holds, then releases the phase.
    /// The backing must be the genuine independently verified response receipt.
    /// The consumer must bind its canonical inode/lifecycle to that same RPC
    /// response and put the adopted body in the actual executor-owned registry
    /// before any later fallible completion or cancellable reply. This method
    /// checks claim/root and allocation, not same-response correlation. The
    /// metadata source registry alone does not retain the adopted body.
    ///
    /// # Errors
    /// Returns actual retained backing custody with a faulted phase when final
    /// verification fails. No error reactivates the live recovery phase.
    pub(crate) fn complete(
        self,
        body: &crate::publisher_local::client::PeerPublishedObject<HostDomainLocation>,
    ) -> Result<RecoveryManifestBackingRetention, RecoveryManifestEffectFailure> {
        let measurement = match super::reconcile::complete_effect(&self, body) {
            Ok(measurement) => measurement,
            Err(error) => return Err(self.fail(error)),
        };
        let Self { receipt, flight } = self;
        let backing = RecoveryManifestBackingRetention::from_phase(receipt, Some(measurement));
        flight.complete();
        Ok(backing)
    }

    /// Faults the live phase and retains durable custody for actual failure handling.
    pub(crate) fn fail(self, error: io::Error) -> RecoveryManifestEffectFailure {
        let Self { receipt, flight } = self;
        drop(flight);
        RecoveryManifestEffectFailure {
            error,
            backing: RecoveryManifestBackingRetention::from_phase(receipt, None),
        }
    }

    fn receipt_ref(&self) -> &RecoveryRetainedManifest<'phase, 'executor> {
        &self.receipt
    }
}
