//! Advances only this same owned Current through typed Ownership bundle checks.
//!
//! Fixed admission precedes framing. A genuine scoped frame retains the same
//! parsed Ready fields across typed admission without callbacks, a phase flag,
//! repeated framing, supplied geometry or caller-built completion.

use aos_sandbox_broker::receiving::{
    RootInitialReceivingOriginalV1, RootObservationErrorV1,
    RootSelectedStartupBorrowV1, RootUpperMutationGuardV1,
};
use aos_sandbox_model::CanonicalAssignmentManifestV1;
use aos_sandbox_ownership_protocol::response_verification::OwnershipResponseVerifyCaptureV1;

use super::super::initial_bundle::{
    RootInitialBundleOwnershipErrorV1 as E, RootInitialBundleOwnershipFrameBorrowV1,
};
use super::RootOwnedCurrentOriginalV1;

impl<'startup> RootOwnedCurrentOriginalV1<'startup> {
    /// Pays fixed borrowed framing from this actual completed Source/trust prefix.
    ///
    /// # Errors
    /// Retains repeated entry, prior purpose, same-Initial, supplier, debit or
    /// selected service refusal. No framing, decoder capsule or native IO runs here.
    pub fn begin_initial_bundle_ownership_fixed_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        if self.bundle_ownership.claim_fixed_once_v1().is_err() {
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        if self.require_initial_source_exchange_complete_v1().is_err() {
            self.bundle_ownership.refuse_unprepared_v1();
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        let predecessor = match self.originals.peer.borrow_current_writers_predecessor_v1(initial) {
            Ok(predecessor) => predecessor,
            Err(error) => {
                self.bundle_ownership.park_predecessor_refusal_v1(error);
                return Err(RootObservationErrorV1::Service);
            }
        };
        let open = self.open.as_ref().ok_or(RootObservationErrorV1::Service)?;
        let trust = self.trust.as_ref().ok_or(RootObservationErrorV1::Service)?;
        self.bundle_ownership.begin_fixed_once_v1(
            &open.prepared, &self.source_exchange, trust, predecessor, startup, exclusion,
        )
    }

    /// Borrows this actual Ready framing through its genuine typed receiving slot.
    ///
    /// # Errors
    /// Retains missing fixed/prior completion, repeated entry, historical framing
    /// or privately derived geometry refusal. No decoder capsule is allocated.
    pub fn borrow_initial_bundle_ownership_once_v1(
        &mut self,
    ) -> Result<RootInitialBundleOwnershipFrameBorrowV1<'_, 'startup>, E> {
        self.require_initial_source_exchange_complete_v1()?;
        let open = self.open.as_ref().ok_or(E::Incomplete)?;
        let trust = self.trust.as_ref().ok_or(E::Incomplete)?;
        let writers = match &self.writers {
            Some(Ok(writers)) => writers,
            _ => return Err(E::Incomplete),
        };
        self.bundle_ownership.borrow_frame_once_v1(
            writers, &open.prepared, &self.ready, &self.source_exchange, trust, &self.originals,
        )
    }

    /// Observes independent location/readback posts after actual typed admission.
    pub fn observe_initial_bundle_ownership_native_posts_once_v1(&mut self) {
        let Some(open) = &self.open else {
            return;
        };
        if let Some(Ok(writers)) = &self.writers {
            self.bundle_ownership.observe_native_posts_once_v1(writers, &open.prepared);
        }
    }

    /// Arms the genuine independently owed Ownership-bundle peer post.
    pub fn arm_initial_bundle_ownership_post_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) {
        let returned = match self.originals.peer.borrow_current_writers_predecessor_v1(initial) {
            Ok(predecessor) => self.bundle_ownership.arm_peer_once_v1(predecessor, startup, exclusion),
            Err(error) => {
                self.bundle_ownership.park_peer_refusal_v1(error);
                Err(())
            }
        };
        if returned.is_err() {
            initial.latch_root_refusal_v1();
        }
    }

    /// Negatively parks an upper arm refusal without suppressing its owed clock.
    pub fn refuse_initial_bundle_ownership_post_arm_once_v1(&mut self) {
        self.bundle_ownership.refuse_peer_arm_once_v1();
    }

    /// Observes the independently owed peer, retained clock and sample ordering.
    pub fn observe_initial_bundle_ownership_post_once_v1(&mut self) {
        let Some(open) = &self.open else {
            return;
        };
        self.bundle_ownership.observe_peer_and_clock_once_v1(
            &self.originals, &open.prepared, &self.source_exchange,
        );
    }

    /// Requires this same typed Ownership verification and all independently owed posts.
    ///
    /// # Errors
    /// Refuses incomplete prior stages, actual decoder/association or response
    /// refusal, or either native/peer/clock post failure.
    pub fn require_initial_bundle_ownership_complete_v1(&self) -> Result<(), E> {
        self.require_initial_source_exchange_complete_v1()?;
        self.bundle_ownership.require_complete_v1()
    }

    /// Borrows verified manifest DATA from this same completed Ownership owner.
    ///
    /// # Errors
    /// Refuses incomplete genuine custody. Manifest DATA cannot construct a
    /// native Cache/Controller purpose, append gate or terminal serving owner.
    pub fn initial_bundle_manifest_data_v1(&self) -> Result<&CanonicalAssignmentManifestV1, E> {
        self.require_initial_bundle_ownership_complete_v1()?;
        self.bundle_ownership.completed_manifest_v1()
    }

    /// Borrows verified response DATA from this same actual completed capture.
    ///
    /// # Errors
    /// Refuses incomplete actual verification. The borrowed capture supplies no
    /// substitute trust, phase, receiver, native purpose or financial permission.
    pub fn initial_bundle_ownership_response_data_v1(&self) -> Result<&OwnershipResponseVerifyCaptureV1, E> {
        self.require_initial_bundle_ownership_complete_v1()?;
        self.bundle_ownership.completed_response_v1()
    }
}
