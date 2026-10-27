//! Advances Initial's same Controller purpose through its real receiving slots.
//!
//! The fixed admission precedes body scope and its independently prearmed peer.
//! Prepared and replay borrowers split actual resident fields across the short
//! upper exclusions. Every entered body retains its independent native, peer and
//! clock posts, including when a later receiving or replay stage refuses.

use aos_sandbox_broker::receiving::{
    RootInitialReceivingOriginalV1, RootObservationErrorV1,
    RootSelectedStartupBorrowV1, RootUpperMutationGuardV1,
};

use crate::native::readonly::RootReadonlyModelOriginalsV1;
use crate::root_policy_inputs_data::RootCurrentPolicyInputDataV1;

use super::super::initial_controller::{
    RootInitialControllerReadonlyErrorV1 as E,
    RootInitialControllerReadonlyPreparedBorrowV1,
};
use super::RootOwnedCurrentOriginalV1;

impl<'startup> RootOwnedCurrentOriginalV1<'startup> {
    /// Pays Initial Controller's fixed stage from the same completed Cache owner.
    ///
    /// # Errors
    /// Retains repeated entry, prior-purpose, genuine predecessor, same-Initial,
    /// checked quote, actual receiving debit or selected service refusal.
    pub fn begin_initial_controller_readonly_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        if self.controller.claim_fixed_once_v1().is_err() {
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        if self.require_initial_cache_proof_complete_v1().is_err() {
            self.controller.refuse_unprepared_v1();
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        let predecessor = match self.originals.peer.borrow_current_writers_predecessor_v1(initial) {
            Ok(predecessor) => predecessor,
            Err(error) => {
                self.controller.park_predecessor_refusal_v1(error);
                initial.latch_root_refusal_v1();
                return Err(RootObservationErrorV1::Service);
            }
        };
        let open = self.open.as_ref().ok_or(RootObservationErrorV1::Service)?;
        self.controller.begin_fixed_once_v1(
            &open.prepared, &self.cache_proof, predecessor, startup, exclusion,
        )
    }

    /// Enters the original body and owed-post scope before its peer arm.
    ///
    /// # Errors
    /// Refuses incomplete fixed admission, repeated scope or the actual saved
    /// opening provenance. It performs no peer, file or clock observation.
    pub fn enter_initial_controller_readonly_body_once_v1(&mut self) -> Result<(), E> {
        let open = self.open.as_ref().ok_or(E::Incomplete)?;
        self.controller.claim_body_scope_once_v1(&open.prepared)
    }

    /// Prearms the independently owed Controller-body peer before file work.
    ///
    /// Actual returned refusal is retained on this owner and denies the same
    /// Initial invocation. The outside-lock body constructor selects it before
    /// native work; a supplied successful arm result cannot enter this scope.
    pub fn arm_initial_controller_readonly_body_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) {
        let returned = match self.originals.peer.borrow_current_writers_predecessor_v1(initial) {
            Ok(predecessor) => self.controller.arm_body_peer_once_v1(predecessor, startup, exclusion),
            Err(error) => {
                self.controller.park_body_peer_refusal_once_v1(error);
                Err(RootObservationErrorV1::Service)
            }
        };
        if returned.is_err() {
            initial.latch_root_refusal_v1();
        }
    }

    /// Negatively parks an upper peer-arm refusal without closing owed posts.
    pub fn refuse_initial_controller_readonly_body_arm_once_v1(&mut self) {
        self.controller.refuse_body_peer_arm_once_v1();
    }

    /// Borrows the same receipt, rooted opening and actual next receiving stages.
    ///
    /// # Errors
    /// Retains body/peer refusal, receipt, coordinates, widths, writer bookend,
    /// first clock, cutoff or original mount-before refusal.
    pub fn borrow_initial_controller_readonly_once_v1<'scope, 'inputs>(
        &'scope mut self,
        policy_data: &'scope RootCurrentPolicyInputDataV1<'inputs>,
    ) -> Result<RootInitialControllerReadonlyPreparedBorrowV1<'scope, 'startup, 'inputs>, E> {
        let open = self.open.as_ref().ok_or(E::Incomplete)?;
        let writers = match &self.writers {
            Some(Ok(writers)) => writers,
            _ => return Err(E::Incomplete),
        };
        self.controller.borrow_prepared_once_v1(
            writers, &open.prepared, &self.ready, &self.cache_proof,
            &self.source_exchange, &self.bundle_ownership, policy_data, &self.originals,
        )
    }

    /// Observes the independently owed native posts of an entered body.
    pub fn observe_initial_controller_readonly_native_posts_once_v1(&mut self) {
        let Some(open) = &self.open else {
            return;
        };
        if let Some(Ok(writers)) = &self.writers {
            self.controller.observe_native_posts_once_v1(writers, &open.prepared);
        }
    }

    /// Observes the same prearmed peer and distinct late clock after native posts.
    pub fn observe_initial_controller_readonly_post_once_v1(&mut self) {
        let Some(open) = &self.open else {
            return;
        };
        self.controller.observe_peer_and_clock_once_v1(
            &self.originals, &open.prepared, &self.source_exchange,
        );
    }

    /// Requires the same three admissions, held model, comparisons and owed posts.
    ///
    /// # Errors
    /// Refuses incomplete actual prior custody, any reached Controller cause or
    /// any independent archive, mount, metadata, peer, clock or interval refusal.
    pub fn require_initial_controller_readonly_complete_v1(&self) -> Result<(), E> {
        self.require_initial_cache_proof_complete_v1()?;
        self.controller.require_complete_v1()
    }

    /// Borrows the same completed Controller model for historical comparisons.
    ///
    /// No map, readback DATA or supplied completion can construct this loan.
    /// The model retains its actual private opening and independent name archive.
    ///
    /// # Errors
    /// Refuses incomplete actual Controller purpose or independently owed posts.
    pub fn initial_controller_readonly_model_v1(&self) -> Result<&RootReadonlyModelOriginalsV1, E> {
        self.require_initial_controller_readonly_complete_v1()?;
        self.controller.model_v1()
    }
}
