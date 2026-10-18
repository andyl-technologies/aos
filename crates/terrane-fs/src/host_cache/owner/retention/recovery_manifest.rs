//! Retains manifest reconstruction metadata inside one exclusive recovery turn.
//!
//! The live context borrows the genuine physical executor for its entire life.
//! It owns the original opaque Drain context, never a replacement epoch. Its
//! distinct receipt cannot satisfy ordinary retention/currentness or authorize
//! Resume. The physical owner enters this phase for supported manifest
//! recovery; exhaustive final reconciliation remains required for completion.

use super::{executor::NativeOwnerExecutor, *};
use crate::publisher_local::client::PublisherRecoveryContext;
use std::{cell::Cell, rc::Rc};

mod backing;
mod body;
mod effect;
mod reconcile;
pub(crate) use backing::RecoveryManifestBackingRetention;
pub(crate) use body::{RecoveryManifestBodyFailure, RecoveryManifestBodyRetention};
pub(crate) use effect::{
    AcceptedRecoveryManifestEffect, RecoveryManifestEffect, RecoveryManifestEffectFailure,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum RecoveryPhase {
    Active,
    InFlight,
    EffectInFlight,
    Faulted,
}

/// Faults a live phase if physical retention is abandoned before reconciliation.
struct InFlightRetention {
    phase: Rc<Cell<RecoveryPhase>>,
    reconciled: bool,
}

impl InFlightRetention {
    fn begin(phase: &Rc<Cell<RecoveryPhase>>) -> Self {
        phase.set(RecoveryPhase::InFlight);
        Self {
            phase: Rc::clone(phase),
            reconciled: false,
        }
    }

    fn begin_effect(phase: &Rc<Cell<RecoveryPhase>>) -> Self {
        phase.set(RecoveryPhase::EffectInFlight);
        Self {
            phase: Rc::clone(phase),
            reconciled: false,
        }
    }

    fn complete(mut self) {
        self.reconciled = true;
        self.phase.set(RecoveryPhase::Active);
    }
}

impl Drop for InFlightRetention {
    fn drop(&mut self) {
        if !self.reconciled {
            self.phase.set(RecoveryPhase::Faulted);
        }
    }
}

/// Retains the original publisher barrier and exclusive physical recovery turn.
///
/// Construction is restricted to the actual native executor. Holding it keeps
/// every other physical command excluded, including across a downstream RPC.
pub(crate) struct LiveManifestRecoveryContext<'executor> {
    executor: &'executor mut NativeOwnerExecutor,
    session: Arc<Client<HostDomainLocation>>,
    original: PublisherRecoveryContext<HostDomainLocation>,
    bootstrap_id: [u8; 16],
    generation: Cell<u64>,
    phase: Rc<Cell<RecoveryPhase>>,
}

impl NativeOwnerExecutor {
    /// Borrows this executor for the original active, durably reserved phase.
    ///
    /// The physical owner enters this after the actual bootstrap write. Native
    /// adoption and independent inspection retain resources before final shared
    /// namespace, policy and quota reconciliation may complete recovery.
    ///
    /// # Errors
    /// Refuses another worker, a handoff, stale original barrier, absent exact
    /// bootstrap reservation, cold records or missing synchronized state.
    pub(in crate::host_cache::owner) fn live_manifest_recovery(
        &mut self,
        original: PublisherRecoveryContext<HostDomainLocation>,
        bootstrap_id: [u8; 16],
    ) -> io::Result<LiveManifestRecoveryContext<'_>> {
        self.check_physical_worker()?;
        self.check_recovery_phase()?;
        let (session, generation) = {
            let owner = self
                .custody()
                .lock()
                .map_err(|_| io::Error::other("metadata custody poisoned"))?;
            owner.check_current()?;
            if !owner.recovery_required || !owner.faulted || owner.snapshot.is_none() {
                return Err(invalid(
                    "manifest recovery lacks an active durable bootstrap",
                ));
            }
            owner.check_synchronized_bootstrap(&bootstrap_id)?;
            (owner.preparation.publisher_session(), owner.generation)
        };
        session
            .check_recovery_context(&original)
            .map_err(io::Error::other)?;
        Ok(LiveManifestRecoveryContext {
            executor: self,
            session,
            original,
            bootstrap_id,
            generation: Cell::new(generation),
            phase: Rc::new(Cell::new(RecoveryPhase::Active)),
        })
    }
}

impl<'executor> LiveManifestRecoveryContext<'executor> {
    /// Borrows the actual executor already held exclusively by this live phase.
    ///
    /// This grants no allocation, Running-phase or claim authority.
    pub(super) fn snapshot_executor(&self) -> &NativeOwnerExecutor {
        self.executor
    }

    /// Reserves real physical result and failure capacity before recovery effects.
    ///
    /// # Errors
    /// Refuses stale phase and unavailable bounded registry capacity.
    pub(in crate::host_cache::owner) fn reserve_reconciliation(&mut self) -> io::Result<()> {
        self.check_current()?;
        self.executor.reserve_manifest_reconciliation()
    }

    /// Retains the exact successful Inspector result before later fallible work.
    pub(in crate::host_cache::owner) fn retain_verified(
        &mut self,
        verified: crate::host_cache::recovery_inspection::VerifiedRecoveryManifest,
    ) {
        self.executor.retain_verified_manifest(verified);
    }

    /// Retains failed native resources even when this live phase already faulted.
    pub(in crate::host_cache::owner) fn retain_failure(
        &mut self,
        resources: super::super::recovery_manifests::ManifestFailureResources,
    ) {
        self.executor.retain_manifest_failure(resources);
    }

    /// Returns the same original barrier only after all local effects are settled.
    ///
    /// This does not certify complete namespace/state recovery. The owner still
    /// performs exhaustive final inspection, synchronization and quota checks.
    ///
    /// # Errors
    /// Refuses an in-flight/faulted phase, changed owner/source generation or a
    /// stale original publisher context. It never captures a new barrier.
    pub(in crate::host_cache::owner) fn finish(
        self,
    ) -> io::Result<(PublisherRecoveryContext<HostDomainLocation>, u64)> {
        self.check_current()?;
        let generation = self.generation.get();
        Ok((self.original, generation))
    }

    /// Borrows the original actual publisher session without a new connection.
    pub(crate) fn publisher_session(&self) -> &Arc<Client<HostDomainLocation>> {
        &self.session
    }

    /// Borrows the original acknowledged Drain context, never a fresh snapshot.
    pub(crate) fn publisher_context(&self) -> &PublisherRecoveryContext<HostDomainLocation> {
        &self.original
    }

    /// Rechecks actual owner phase before a downstream publisher mutex is held.
    ///
    /// The exclusive executor borrow remains alive after this check. Consumers
    /// must also check this exact original context under their actual RPC lock.
    ///
    /// # Errors
    /// Refuses changed process/root/owner/generation, absent durable hold or a
    /// changed original publisher session/barrier. It retains no state lock.
    pub(crate) fn check_current(&self) -> io::Result<()> {
        self.check_current_phase(RecoveryPhase::Active)
    }

    fn check_current_phase(&self, expected: RecoveryPhase) -> io::Result<()> {
        self.executor.check_physical_worker()?;
        {
            let owner = self
                .executor
                .custody()
                .lock()
                .map_err(|_| io::Error::other("metadata custody poisoned"))?;
            self.check_owner_phase(&owner, expected)?;
        }
        self.session
            .check_recovery_context(&self.original)
            .map_err(io::Error::other)
    }

    /// Checks genuine active phase and its durable bootstrap custody.
    ///
    /// # Errors
    /// Refuses failed operations or changed owner, reservation and generation.
    pub(super) fn check_owner(&self, owner: &Custody) -> io::Result<()> {
        self.check_owner_phase(owner, RecoveryPhase::Active)
    }

    /// Checks only the accepted producer's current in-flight phase.
    ///
    /// # Errors
    /// Refuses abandoned/completed work and changed actual owner custody.
    pub(super) fn check_producer_owner(&self, owner: &Custody) -> io::Result<()> {
        self.check_owner_phase(owner, RecoveryPhase::InFlight)
    }

    fn check_owner_phase(&self, owner: &Custody, expected: RecoveryPhase) -> io::Result<()> {
        owner.check_current()?;
        if self.phase.get() != expected
            || !owner.faulted
            || !owner.recovery_required
            || owner.snapshot.is_none()
            || owner.generation != self.generation.get()
            || !Arc::ptr_eq(&self.session, &owner.preparation.publisher_session())
            || !owner.state.reservations.iter().any(|hold| {
                hold.id == hex(&self.bootstrap_id)
                    && hold.owner == owner.preparation.config.quota_owner
                    && hold.bytes == owner.preparation.config.metadata_sync_hold_bytes
            })
        {
            return Err(invalid(
                "live manifest recovery no longer owns its durable phase",
            ));
        }
        Ok(())
    }

    /// Advances only after the physical producer invalidates the old generation.
    pub(super) fn advance_generation(&self, owner: &Custody) {
        self.generation.set(owner.generation);
    }

    /// Retains real source descriptors outside state before durability effects.
    ///
    /// # Errors
    /// Refuses another worker or unavailable registry capacity.
    pub(super) fn retain_source(&mut self, source: Arc<NativeManifestSource>) -> io::Result<()> {
        self.executor.retain_manifest_source(source)
    }

    /// Produces a distinct recovery-only receipt after actual durable retention.
    ///
    /// Ordinary retention stays unavailable while this recovery phase is live.
    /// Source/hold registry ownership remains physical even if this future or a
    /// later consumer is abandoned. No public Retain request is self-enqueued.
    ///
    /// # Errors
    /// Refuses stale phase, missing/corrupt metadata, resource limits, failed
    /// durability or unreconciled source/project/kernel charge observations.
    pub(crate) async fn retain_manifest(
        &mut self,
        identity: Identity,
    ) -> io::Result<RecoveryRetainedManifest<'_, 'executor>> {
        self.check_current()?;
        let flight = InFlightRetention::begin(&self.phase);
        let custody = Arc::clone(self.executor.custody());
        let result = super::manifest::retain_recovery(&custody, identity, self).await;
        let retained = match result {
            Ok(retained) => retained,
            Err(error) => {
                self.phase.set(RecoveryPhase::Faulted);
                return Err(error);
            }
        };
        if let Err(error) = self
            .check_current_phase(RecoveryPhase::InFlight)
            .and_then(|()| retained.source.recheck())
        {
            self.phase.set(RecoveryPhase::Faulted);
            return Err(error);
        }
        flight.complete();
        Ok(RecoveryRetainedManifest {
            retained,
            live: self,
        })
    }
}

/// Retains actual synced metadata pins within the original exclusive recovery turn.
///
/// This is deliberately distinct from ordinary `RetainedManifest`; its live
/// borrow excludes another owner command through the complete downstream RPC.
/// It grants no completed recovery, serving, publication or Resume authority.
pub(crate) struct RecoveryRetainedManifest<'phase, 'executor> {
    retained: RetainedManifest,
    live: &'phase mut LiveManifestRecoveryContext<'executor>,
}

impl<'phase, 'executor> RecoveryRetainedManifest<'phase, 'executor> {
    /// Arms downstream effects while retaining the original exclusive turn.
    ///
    /// # Errors
    /// Refuses stale source/pin/phase or original context before any new RPC.
    /// The guard must be created, completed or dropped outside Client mutexes.
    pub(crate) fn begin_effect(self) -> io::Result<RecoveryManifestEffect<'phase, 'executor>> {
        RecoveryManifestEffect::begin(self)
    }

    /// Borrows the exact original live recovery turn for an atomic RPC check.
    pub(crate) fn live_context(&self) -> &LiveManifestRecoveryContext<'_> {
        &*self.live
    }

    /// Borrows independently verified canonical manifest claim bytes.
    pub(crate) fn claim(&self) -> &PublicationClaim {
        self.retained.claim()
    }

    /// Borrows the retained ordinary metadata pack descriptor, never a caller FD.
    pub(crate) fn metadata_file(&self) -> &File {
        self.retained.metadata_file()
    }

    /// Returns the exact verified canonical manifest range in that pack.
    pub(crate) fn manifest_range(&self) -> ByteRange {
        self.retained.manifest_range()
    }

    /// Borrows the actual stable cache incarnation without caller injection.
    pub(crate) fn cache_incarnation(&self) -> &[u8; 16] {
        self.retained.cache_incarnation()
    }

    /// Borrows the actual persisted retention registration identifier.
    pub(crate) fn retention_id(&self) -> &[u8; 16] {
        self.retained.retention_id()
    }

    /// Borrows the retained original root, domain and chunk profile authority.
    pub(crate) fn layout(&self) -> &Arc<NativeHostLayout<HostDomainLocation>> {
        self.retained.layout()
    }

    /// Returns the exact verified metadata-pack identifier under existing keys.
    pub(crate) fn pack_id(&self) -> terrane::pack::PackId {
        self.retained.pack_id()
    }

    /// Borrows the independently verified full metadata-pack identity.
    pub(crate) fn pack_identity(&self) -> &Identity {
        self.retained.pack_identity()
    }

    /// Rechecks real durable pins/source and the original active recovery phase.
    ///
    /// # Errors
    /// Refuses stale owner/session/root/generation, changed source or absent pins.
    /// The consumer must perform this before acquiring its publisher RPC mutex.
    pub(crate) fn check_current(&self) -> io::Result<()> {
        self.check_current_phase(RecoveryPhase::Active)
    }

    fn check_current_phase(&self, phase: RecoveryPhase) -> io::Result<()> {
        self.live.check_current_phase(phase)?;
        let owner = self
            .live
            .executor
            .custody()
            .lock()
            .map_err(|_| io::Error::other("metadata custody poisoned"))?;
        if !Arc::ptr_eq(&self.retained.custody, self.live.executor.custody()) {
            return Err(invalid("recovery metadata belongs to another owner"));
        }
        self.live.check_owner_phase(&owner, phase)?;
        self.retained.check_registration(&owner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancelled_in_flight_retention_never_reactivates_the_live_phase() {
        let phase = Rc::new(Cell::new(RecoveryPhase::Active));
        // This tests cancellation bookkeeping only, without native IO or a
        // synthetic root, reservation, source or durable retention receipt.
        let observed = Rc::clone(&phase);
        let mut future = Box::pin(async move {
            let flight = InFlightRetention::begin(&observed);
            std::future::pending::<()>().await;
            flight.complete();
        });
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(std::future::Future::poll(future.as_mut(), &mut context).is_pending());
        assert!(phase.get() == RecoveryPhase::InFlight);
        assert!(phase.get() != RecoveryPhase::Active);
        drop(future);
        assert!(phase.get() == RecoveryPhase::Faulted);
    }

    #[test]
    fn only_reconciled_retention_returns_to_active() {
        let phase = Rc::new(Cell::new(RecoveryPhase::Active));
        InFlightRetention::begin(&phase).complete();
        assert!(phase.get() == RecoveryPhase::Active);
        drop(InFlightRetention::begin(&phase));
        assert!(phase.get() == RecoveryPhase::Faulted);
    }

    #[test]
    fn abandoned_rpc_effect_faults_without_a_state_or_client_lock() {
        let phase = Rc::new(Cell::new(RecoveryPhase::Active));
        let flight = InFlightRetention::begin_effect(&phase);
        assert!(phase.get() == RecoveryPhase::EffectInFlight);
        drop(flight);
        assert!(phase.get() == RecoveryPhase::Faulted);
    }

    #[test]
    fn reconciled_rpc_effect_releases_the_exclusive_phase() {
        let phase = Rc::new(Cell::new(RecoveryPhase::Active));
        InFlightRetention::begin_effect(&phase).complete();
        assert!(phase.get() == RecoveryPhase::Active);
    }
}
