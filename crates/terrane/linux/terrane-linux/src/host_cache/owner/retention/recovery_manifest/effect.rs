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
        receipt.live.executor.reserve_manifest_body_slots()?;
        let flight = InFlightRetention::begin_effect(&receipt.live.phase);
        Ok(Self { flight, receipt })
    }

    /// Borrows exact original recovery authority without acquiring a client lock.
    pub(crate) fn live_context(&self) -> &LiveManifestRecoveryContext<'executor> {
        &*self.receipt.live
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

    /// Registers an owned independently verified response body before final checks.
    ///
    /// This ownership transition performs no fallible verification or IO. The
    /// exclusive guard owns capacity reserved before the RPC. The downstream
    /// consumer must transfer the body immediately after native verification,
    /// before any later fallible correlation/completion step. Insertion alone
    /// asserts no canonical correlation or serving authority.
    pub(crate) fn accept_body(
        self,
        body: crate::publisher_local::client::PeerPublishedObject<HostDomainLocation>,
    ) -> AcceptedRecoveryManifestEffect<'phase, 'executor> {
        let body = Arc::new(body);
        self.receipt
            .live
            .executor
            .retain_adopted_manifest_body(Arc::clone(&body));
        AcceptedRecoveryManifestEffect { effect: self, body }
    }

    fn complete_body(
        self,
        body: Arc<crate::publisher_local::client::PeerPublishedObject<HostDomainLocation>>,
    ) -> Result<RecoveryManifestBodyRetention, RecoveryManifestBodyFailure> {
        let measurement = match super::reconcile::complete_effect(&self, &body) {
            Ok(measurement) => measurement,
            Err(error) => return Err(self.fail_body(error, body)),
        };
        let Self { receipt, flight } = self;
        let (backing, live) =
            RecoveryManifestBackingRetention::from_phase(receipt, Some(measurement));
        let retained = RecoveryManifestBodyRetention::pair(body, backing);
        live.executor.retain_manifest_backing(retained.clone());
        flight.complete();
        Ok(retained)
    }

    fn fail_body(
        self,
        error: io::Error,
        body: Arc<crate::publisher_local::client::PeerPublishedObject<HostDomainLocation>>,
    ) -> RecoveryManifestBodyFailure {
        let Self { receipt, flight } = self;
        drop(flight);
        let (backing, live) = RecoveryManifestBackingRetention::from_phase(receipt, None);
        let retained = RecoveryManifestBodyRetention::pair(body, backing);
        live.executor.retain_manifest_backing(retained.clone());
        RecoveryManifestBodyFailure::new(error, retained)
    }

    /// Faults the live phase and retains durable custody for actual failure handling.
    pub(crate) fn fail(self, error: io::Error) -> RecoveryManifestEffectFailure {
        let Self { receipt, flight } = self;
        drop(flight);
        RecoveryManifestEffectFailure {
            error,
            backing: RecoveryManifestBackingRetention::from_phase(receipt, None).0,
        }
    }

    fn receipt_ref(&self) -> &RecoveryRetainedManifest<'phase, 'executor> {
        &self.receipt
    }
}

/// Retains an actual response body in the physical registry through final checks.
///
/// The body was inserted before this value exists. Dropping it faults the live
/// phase while the executor keeps the accepted body and durable source/pins.
pub(crate) struct AcceptedRecoveryManifestEffect<'phase, 'executor> {
    effect: RecoveryManifestEffect<'phase, 'executor>,
    body: Arc<crate::publisher_local::client::PeerPublishedObject<HostDomainLocation>>,
}

impl AcceptedRecoveryManifestEffect<'_, '_> {
    /// Borrows the actual registered body for same-response lifecycle correlation.
    pub(crate) fn body(
        &self,
    ) -> &crate::publisher_local::client::PeerPublishedObject<HostDomainLocation> {
        &self.body
    }

    /// Borrows original exclusive recovery authority without acquiring a mutex.
    pub(crate) fn live_context(&self) -> &LiveManifestRecoveryContext<'_> {
        self.effect.live_context()
    }

    /// Reconciles registered backing and retains its typed pair before replying.
    ///
    /// Must run outside the Client mutex after same-response native verification.
    /// Success supplies resource custody, not canonical lifecycle/serving proof.
    ///
    /// # Errors
    /// Returns a faulted registered body/metadata pair for native/source/context,
    /// synchronization, measurement or authenticated quota reconciliation errors.
    pub(crate) fn complete(
        self,
    ) -> Result<RecoveryManifestBodyRetention, RecoveryManifestBodyFailure> {
        self.effect.complete_body(self.body)
    }

    /// Faults the effect and retains its actual body/metadata pair on failure.
    pub(crate) fn fail(self, error: io::Error) -> RecoveryManifestBodyFailure {
        self.effect.fail_body(error, self.body)
    }
}
