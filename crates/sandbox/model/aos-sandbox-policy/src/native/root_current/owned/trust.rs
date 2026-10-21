//! Advances this same owned Current through fixed and typed Ownership trust.
//!
//! The fixed Stage, outside-lock Box/capture, late real receiving recheck,
//! captured-byte typed Stage and independent native posts keep separate slots.

use aos_sandbox_broker::receiving::{
    RootInitialReceivingOriginalV1, RootObservationErrorV1,
    RootSelectedStartupBorrowV1, RootUpperMutationGuardV1,
};

use crate::native::PolicyNativeJournalErrorV1 as NativeError;

use super::super::initial_trust::{
    RootInitialTrustErrorV1 as E, RootInitialTrustOriginalV1 as Trust,
};
use super::RootOwnedCurrentOriginalV1;

impl<'startup> RootOwnedCurrentOriginalV1<'startup> {
    /// Pays the genuine fixed Ownership custody before its Box or native IO.
    ///
    /// # Errors
    /// Retains prior-input, same-Initial, fixed supplier, debit or service refusal.
    pub fn begin_initial_trust_fixed_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        if self.trust_fixed.entered || self.trust.is_some() {
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        self.trust_fixed.entered = true;
        if self.require_initial_policy_inputs_complete_v1().is_err() {
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }

        let mut predecessor = self.originals.peer
            .borrow_current_writers_predecessor_v1(initial)?;
        let (initial, financial) = predecessor.split_initial_v1();
        self.trust_fixed.financial = Some(financial.clone());
        self.trust_fixed.permit = Some((|| {
            self.inputs.require_complete_v1()
                .map_err(|_| NativeError::boundary())?;
            let open = self.open.as_ref()
                .ok_or_else(NativeError::boundary)?;
            let body = open.prepared.body_v1()
                .map_err(|_| NativeError::boundary())?;
            let enrollment = initial.enrollment_v1()
                .ok_or_else(NativeError::boundary)?;

            if initial.failure().is_some()
                || !matches!(initial.recipient_binding_result_v1(), Some(Ok(())))
                || (body.root_recipient, body.root_producer)
                    != (enrollment.recipient_invocation, enrollment.identity.native_fields().invocation)
                || !self.inputs.same_financial_v1(financial)
                || !startup.same_financial_original_data_v1(financial)
            {
                return Err(NativeError::boundary());
            }
            let base = self.inputs.completed_prefix_v1()
                .map_err(|_| NativeError::boundary())?;
            let additional = Trust::fixed_demand_v1()?;
            let demand = base.checked_add(additional)
                .map_err(|_| NativeError::boundary())?;
            if financial.require_receiving_demand_under_upper_exclusion_v1(exclusion, demand).is_err() {
                return Err(NativeError::Financial(financial.clone()));
            }
            Ok(demand)
        })());
        self.trust_fixed.finish_v1(initial, startup, exclusion)
    }

    /// Constructs only the inert boxed trust owner after the real fixed Stage.
    ///
    /// This runs outside L/U at the old allocation slot. It adopts no result,
    /// credential bytes, caller verifier or completed native owner.
    ///
    /// # Errors
    /// Refuses a missing fixed admission, repeated construction or prior failure.
    pub fn construct_initial_trust_once_v1(
        &mut self,
    ) -> Result<(), E> {
        self.require_initial_policy_inputs_complete_v1()
            .map_err(|_| E::Incomplete)?;
        self.trust_fixed.require_complete_v1()?;
        if self.trust.is_some() {
            return Err(E::Incomplete);
        }
        let trust = Trust::new();
        self.trust = Some(Box::new(trust));
        Ok(())
    }

    /// Rechecks the genuine fixed receiving original at its old late entry slot.
    ///
    /// This observes no service and performs no new debit. Capture remains
    /// outside this short actual Initial/L/U loan.
    ///
    /// # Errors
    /// Retains same-original or newly refused native receiving custody.
    pub fn enter_initial_trust_capture_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        _exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let trust = self.trust.as_mut()
            .ok_or(RootObservationErrorV1::Service)?;
        let predecessor = match self.originals.peer.borrow_current_writers_predecessor_v1(initial) {
            Ok(predecessor) => predecessor,
            Err(error) => {
                trust.park_capture_entry_refusal_v1(error);
                return Err(RootObservationErrorV1::Service);
            }
        };
        trust.enter_once_v1(&self.trust_fixed, predecessor, startup)
    }

    /// Negatively parks inability to enter the old trust capture receiving slot.
    ///
    /// The upper retains its owning lock error. Unlike Ready/Pins, the old trust
    /// body had not yet entered its independent post scope, so no IO is invented.
    pub fn refuse_initial_trust_capture_entry_once_v1(&mut self) {
        if let Some(trust) = &mut self.trust {
            trust.refuse_entry_once_v1();
        }
    }

    /// Captures the actual public trust files after same-writer native bookends.
    ///
    /// # Errors
    /// Retains actual fixed-location, full Open readback or credential refusal.
    pub fn capture_initial_trust_credentials_once_v1(
        &mut self,
    ) -> Result<(), E> {
        let trust = self.trust.as_mut()
            .ok_or(E::Incomplete)?;
        let open = self.open.as_ref()
            .ok_or(E::Incomplete)?;
        let writers = match &self.writers {
            Some(Ok(writers)) => writers,
            _ => return Err(E::Incomplete),
        };
        trust.capture_once_v1(writers, &open.prepared)
    }

    /// Pays typed trust decoding from the SAME actual captured file length.
    ///
    /// # Errors
    /// Retains incomplete capture, foreign Initial, supplier, debit or service refusal.
    pub fn begin_initial_trust_typed_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let trust = self.trust.as_mut()
            .ok_or(RootObservationErrorV1::Service)?;
        let predecessor = match self.originals.peer.borrow_current_writers_predecessor_v1(initial) {
            Ok(predecessor) => predecessor,
            Err(error) => {
                trust.park_typed_refusal_v1(error);
                return Err(RootObservationErrorV1::Service);
            }
        };
        trust.begin_typed_once_v1(&self.trust_fixed, predecessor, startup, exclusion)
    }

    /// Constructs the verifier through the sole existing retained typed recipe.
    ///
    /// # Errors
    /// Refuses missing typed admission, malformed public bytes or actual decoder failure.
    pub fn decode_initial_trust_once_v1(
        &mut self,
    ) -> Result<(), E> {
        self.trust.as_mut()
            .ok_or(E::Incomplete)?
            .decode_once_v1()
    }

    /// Observes entered trust credentials and both independent location posts.
    pub fn observe_initial_trust_native_posts_once_v1(&mut self) {
        let Some(trust) = &mut self.trust else {
            return;
        };
        let Some(open) = &self.open else {
            return;
        };
        if let Some(Ok(writers)) = &self.writers {
            trust.observe_native_posts_once_v1(writers, &open.prepared);
        }
    }

    /// Arms the actual independent trust peer post under the same real Initial.
    pub fn arm_initial_trust_post_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) {
        let Some(trust) = &mut self.trust else {
            return;
        };
        let returned = match self.originals.peer.borrow_current_writers_predecessor_v1(initial) {
            Ok(predecessor) => trust.arm_peer_once_v1(predecessor, startup, exclusion),
            Err(error) => {
                trust.park_peer_refusal_v1(error);
                Err(())
            }
        };
        if returned.is_err() {
            initial.latch_root_refusal_v1();
        }
    }

    /// Negatively preserves the owed retained clock after an upper arm refusal.
    pub fn refuse_initial_trust_post_arm_once_v1(&mut self) {
        if let Some(trust) = &mut self.trust {
            trust.refuse_peer_arm_once_v1();
        }
    }

    /// Observes the independently owed trust peer and retained paired clock.
    pub fn observe_initial_trust_post_once_v1(&mut self) {
        let Some(trust) = &mut self.trust else {
            return;
        };
        let Some(open) = &self.open else {
            return;
        };
        trust.observe_peer_and_clock_once_v1(&self.originals, &open.prepared);
    }

    /// Requires actual fixed/typed public trust custody and all independent posts.
    ///
    /// # Errors
    /// Refuses any incomplete or newly closed same-owner stage or original.
    pub fn require_initial_trust_complete_v1(
        &self,
    ) -> Result<(), E> {
        self.require_initial_policy_inputs_complete_v1()
            .map_err(|_| E::Incomplete)?;
        self.trust_fixed.require_complete_v1()?;
        self.trust.as_ref()
            .ok_or(E::Incomplete)?
            .require_complete_v1()
    }

    /// Borrows public verifier DATA from the actual complete native trust owner.
    ///
    /// # Errors
    /// Refuses incomplete actual custody. This DATA cannot construct a later
    /// native purpose, append gate or a replacement currentness interval.
    pub fn initial_ownership_verifier_data_v1(
        &self,
    ) -> Result<&aos_sandbox_ownership_protocol::OwnershipAuthorityVerifier,
        E>
    {
        self.require_initial_trust_complete_v1()?;
        self.trust.as_ref()
            .ok_or(E::Incomplete)?
            .verifier_v1()
    }
}
