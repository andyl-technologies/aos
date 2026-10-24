//! Advances genuine Signed ownership using only short same-Initial loans.

use super::super::{
    initial_controller::RootInitialControllerReadonlyPreparedBorrowV1,
    initial_receiving::RootInitialStageOriginalV1, use_tail::signed::RootSignedBoundErrorV1 as E,
    use_tail::signed::RootSignedBoundOriginalV1, use_tail::signed_input::RootSignedInputBorrowV1,
};
use super::*;
use crate::root_policy_inputs_data::RootCurrentPolicyInputDataV1;

#[derive(Clone, Copy)]
enum Arm {
    Append,
    InputBefore,
    InputAfter,
    Crossing,
    Send,
}

impl<'startup> RootOwnedCurrentOriginalV1<'startup> {
    /// Pays the actual Root4 fixed receiver before constructing its owners.
    ///
    /// # Errors
    /// Retains same-original, quote, financial and service refusal.
    pub fn begin_signed_fixed_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let Some(stage) = &mut self.signed_fixed else {
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        };
        if stage.entered || self.signed.is_some() {
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        stage.entered = true;
        let mut predecessor = match self
            .originals
            .peer
            .borrow_current_writers_predecessor_v1(initial)
        {
            Ok(p) => p,
            Err(error) => {
                self.signed_predecessor.get_or_insert(error);
                initial.latch_root_refusal_v1();
                return Err(RootObservationErrorV1::Service);
            }
        };
        let (initial, financial) = predecessor.split_initial_v1();
        stage.financial = Some(financial.clone());
        stage.permit = Some((|| {
            let open = &self
                .open
                .as_ref()
                .ok_or_else(crate::native::PolicyNativeJournalErrorV1::boundary)?
                .prepared;
            super::super::initial_controller::require_same_initial(
                initial, open, financial, startup,
            )?;
            if !self.use_admitted.same_financial_v1(financial) {
                return Err(crate::native::PolicyNativeJournalErrorV1::boundary());
            }
            let base = self
                .use_admitted
                .completed_prefix_v1()
                .map_err(|_| crate::native::PolicyNativeJournalErrorV1::boundary())?;
            let writers = match &self.writers {
                Some(Ok(w)) => w,
                _ => return Err(crate::native::PolicyNativeJournalErrorV1::boundary()),
            };
            let inputs = writers
                .initial_open_receiving_data_v1()
                .map_err(|_| crate::native::PolicyNativeJournalErrorV1::boundary())?;
            self.signed_quote = Some(RootSignedBoundOriginalV1::fixed_demand_v1(
                inputs.held,
                inputs.supplement,
                &self.use_admitted,
            ));
            let additional = self
                .signed_quote
                .as_ref()
                .and_then(|v| v.as_ref().ok())
                .copied()
                .ok_or_else(crate::native::PolicyNativeJournalErrorV1::geometry)?;
            let complete = base
                .checked_add(additional)
                .map_err(|_| crate::native::PolicyNativeJournalErrorV1::geometry())?;
            if financial
                .require_receiving_demand_under_upper_exclusion_v1(exclusion, complete)
                .is_err()
            {
                return Err(crate::native::PolicyNativeJournalErrorV1::Financial(
                    financial.clone(),
                ));
            }
            Ok(complete)
        })());
        stage.finish_v1(initial, startup, exclusion)
    }

    /// Constructs the same paid Root4 owner outside both locks.
    ///
    /// # Errors
    /// Refuses a missing, failed or already moved fixed original.
    pub fn construct_signed_once_v1(&mut self) -> Result<(), E> {
        if self.signed.is_some() {
            return Err(E::Incomplete);
        }
        self.signed_fixed
            .as_ref()
            .ok_or(E::Incomplete)?
            .require_complete_v1()?;
        let fixed = self.signed_fixed.take().ok_or(E::Incomplete)?;
        self.signed = Some(Box::new(RootSignedBoundOriginalV1::new_after_fixed_v1(
            fixed,
        )));
        Ok(())
    }

    /// Observes the actual before input bookend after both prearms.
    ///
    /// # Errors
    /// Retains prior-purpose, native names, readback or real clock refusal.
    pub fn begin_signed_input_once_v1(&mut self) -> Result<(), E> {
        let open = &self.open.as_ref().ok_or(E::Incomplete)?.prepared;
        let writers = match &mut self.writers {
            Some(Ok(w)) => w,
            _ => return Err(E::Incomplete),
        };
        self.signed
            .as_deref_mut()
            .ok_or(E::Incomplete)?
            .received
            .begin_once_v1(
                writers,
                &self.originals,
                open,
                &self.use_admitted,
                &self.use_reserved,
                &self.refreshed_source_exchange,
                &self.bundle_ownership,
            )
    }

    /// Borrows the real fixed-paid Signed index receiver.
    ///
    /// # Errors
    /// Retains incomplete original bookends or genuine phase/stage refusal.
    pub fn borrow_signed_index_once_v1(
        &mut self,
    ) -> Result<RootSignedInputBorrowV1<'_, 'startup>, E> {
        let open = &self.open.as_ref().ok_or(E::Incomplete)?.prepared;
        let state = self.signed.as_deref_mut().ok_or(E::Incomplete)?;
        state.received.borrow_index_v1(
            &mut self.originals,
            open,
            &self.ready,
            &self.use_admitted,
            &self.use_reserved,
            &self.refreshed_source_exchange,
            &state.fixed,
        )
    }

    /// Pays Signed decoding from its actual received index before allocation.
    ///
    /// # Errors
    /// Retains genuine original, captured geometry, debit or service refusal.
    pub fn begin_signed_variable_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let predecessor = match self
            .originals
            .peer
            .borrow_current_writers_predecessor_v1(initial)
        {
            Ok(p) => p,
            Err(error) => {
                if let Some(state) = self.signed.as_deref_mut() {
                    state.received.variable_predecessor.get_or_insert(error);
                } else {
                    self.signed_predecessor.get_or_insert(error);
                }
                initial.latch_root_refusal_v1();
                return Err(RootObservationErrorV1::Service);
            }
        };
        let Some(open) = &self.open else {
            drop(predecessor);
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        };
        let Some(state) = self.signed.as_deref_mut() else {
            drop(predecessor);
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        };
        state.received.begin_variable_once_v1(
            &open.prepared,
            &self.use_admitted,
            &self.use_reserved,
            &state.fixed,
            predecessor,
            startup,
            exclusion,
        )
    }

    /// Borrows only the same actual variable-paid Signed chunk receiver.
    ///
    /// # Errors
    /// Refuses incomplete original input, Stage or same-financial association.
    pub fn borrow_signed_chunks_once_v1(
        &mut self,
    ) -> Result<RootSignedInputBorrowV1<'_, 'startup>, E> {
        let open = &self.open.as_ref().ok_or(E::Incomplete)?.prepared;
        self.signed
            .as_deref_mut()
            .ok_or(E::Incomplete)?
            .received
            .borrow_chunks_v1(
                &mut self.originals,
                open,
                &self.ready,
                &self.use_admitted,
                &self.use_reserved,
                &self.refreshed_source_exchange,
            )
    }

    /// Verifies exact original signing bytes after receiving every real chunk.
    ///
    /// # Errors
    /// Retains canonical plan/signature/lease/request matching refusal.
    pub fn verify_signed_input_once_v1(&mut self) -> Result<(), E> {
        self.signed
            .as_deref_mut()
            .ok_or(E::Incomplete)?
            .received
            .verify_once_v1(
                &self.use_reserved,
                &self.bundle_ownership,
                &self.refreshed_source_exchange,
            )
    }

    /// Observes the independently owed input after bookend after every entered body.
    pub fn observe_signed_input_after_once_v1(&mut self) {
        let Some(open) = &self.open else {
            return;
        };
        let Some(state) = self.signed.as_deref_mut() else {
            return;
        };
        let Some(Ok(writers)) = &mut self.writers else {
            return;
        };
        state.received.observe_after_once_v1(
            writers,
            &self.originals,
            &open.prepared,
            &self.use_admitted,
            &self.use_reserved,
            &self.refreshed_source_exchange,
        );
    }
}

impl<'startup> RootOwnedCurrentOriginalV1<'startup> {
    /// Arms the actual outer Root4 append post before its entered body.
    ///
    /// # Errors
    /// Retains actual original, receiving, traffic or service refusal.
    pub fn arm_signed_append_post_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        self.arm_signed(Arm::Append, initial, startup, exclusion)
    }

    /// Arms the first actual Signed input bookend before receiving its index.
    ///
    /// # Errors
    /// Retains actual original, receiving, traffic or service refusal.
    pub fn arm_signed_input_before_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        self.arm_signed(Arm::InputBefore, initial, startup, exclusion)
    }

    /// Arms the separate Signed after obligation only after its first arm.
    ///
    /// # Errors
    /// Refuses incomplete first arm, original, receiving or traffic failure.
    pub fn arm_signed_input_after_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        self.arm_signed(Arm::InputAfter, initial, startup, exclusion)
    }

    /// Arms the genuine Root4 crossing after actual Signed preparation.
    ///
    /// # Errors
    /// Retains actual original, currentness, receiving or arm refusal.
    pub fn arm_signed_crossing_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        self.arm_signed(Arm::Crossing, initial, startup, exclusion)
    }

    /// Arms the genuine Root4 send bookend after exact framing.
    ///
    /// # Errors
    /// Retains actual original, framing, receiving or arm refusal.
    pub fn arm_signed_send_post_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        self.arm_signed(Arm::Send, initial, startup, exclusion)
    }

    fn arm_signed(
        &mut self,
        arm: Arm,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let Some(state) = self.signed.as_deref_mut() else {
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        };
        let allowed = match arm {
            Arm::Append => state.append_arm.is_none() && state.fixed.require_complete_v1().is_ok(),
            Arm::InputBefore => {
                state.received.before_arm.is_none() && matches!(state.append_arm, Some(Ok(())))
            }
            Arm::InputAfter => {
                state.received.after_arm.is_none()
                    && matches!(state.received.before_arm, Some(Ok(())))
            }
            Arm::Crossing => matches!(state.primary, Some(Ok(()))),
            Arm::Send => state.send_arm.is_none() && matches!(state.framing, Some(Ok(()))),
        };
        if !allowed {
            state.closed = true;
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        let result = match self
            .originals
            .peer
            .borrow_current_writers_predecessor_v1(initial)
        {
            Ok(predecessor) => match arm {
                Arm::Append => state
                    .append_posts
                    .arm_once_v1(predecessor, startup, exclusion),
                Arm::InputBefore => {
                    state
                        .received
                        .before
                        .arm_once_v1(predecessor, startup, exclusion)
                }
                Arm::InputAfter => {
                    state
                        .received
                        .after
                        .arm_once_v1(predecessor, startup, exclusion)
                }
                Arm::Crossing => state.pair.arm_once_v1(predecessor, startup, exclusion),
                Arm::Send => state
                    .send_posts
                    .arm_once_v1(predecessor, startup, exclusion),
            },
            Err(error) => Err(error),
        };
        let failed = result.is_err();
        match arm {
            Arm::Append => state.append_arm = Some(result),
            Arm::InputBefore => state.received.before_arm = Some(result),
            Arm::InputAfter => state.received.after_arm = Some(result),
            Arm::Send => state.send_arm = Some(result),
            Arm::Crossing => {
                if let Err(error) = result {
                    state.crossing_refusal.get_or_insert(error);
                }
            }
        }
        if failed {
            initial.latch_root_refusal_v1();
            Err(RootObservationErrorV1::Service)
        } else {
            Ok(())
        }
    }

    /// Pays C7 from the actual completed Signed variable receiving prefix.
    ///
    /// # Errors
    /// Retains actual verified input, same-original, quote, debit or service refusal.
    pub fn begin_signed_controller_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let Some(open) = &self.open else {
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        };
        let Some(state) = self.signed.as_deref_mut() else {
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        };
        let Some(stage) = &mut state.controller_stage else {
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        };
        if stage.entered || state.controller.is_some() {
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        stage.entered = true;
        let mut predecessor = match self
            .originals
            .peer
            .borrow_current_writers_predecessor_v1(initial)
        {
            Ok(p) => p,
            Err(error) => {
                state.controller_predecessor.get_or_insert(error);
                initial.latch_root_refusal_v1();
                return Err(RootObservationErrorV1::Service);
            }
        };
        let (initial, financial) = predecessor.split_initial_v1();
        stage.financial = Some(financial.clone());
        stage.permit = Some((|| {
            super::super::initial_controller::require_same_initial(
                initial,
                &open.prepared,
                financial,
                startup,
            )?;
            state
                .received
                .require_complete_v1()
                .map_err(|_| crate::native::PolicyNativeJournalErrorV1::boundary())?;
            if !self.use_admitted.same_financial_v1(financial)
                || !state
                    .fixed
                    .financial
                    .as_ref()
                    .is_some_and(|same| same.same_original_data_v1(financial))
            {
                return Err(crate::native::PolicyNativeJournalErrorV1::boundary());
            }
            let base = state
                .received
                .variable
                .require_complete_v1()
                .map_err(|_| crate::native::PolicyNativeJournalErrorV1::boundary())?;
            state.controller_quote=Some(super::super::initial_controller::RootInitialControllerReadonlyOriginalV1::signed_fixed_demand_v1(&state.received.input));
            let additional = state
                .controller_quote
                .as_ref()
                .and_then(|v| v.as_ref().ok())
                .copied()
                .ok_or_else(crate::native::PolicyNativeJournalErrorV1::geometry)?;
            let complete = base
                .checked_add(additional)
                .map_err(|_| crate::native::PolicyNativeJournalErrorV1::geometry())?;
            if financial
                .require_receiving_demand_under_upper_exclusion_v1(exclusion, complete)
                .is_err()
            {
                return Err(crate::native::PolicyNativeJournalErrorV1::Financial(
                    financial.clone(),
                ));
            }
            Ok(complete)
        })());
        stage.finish_v1(initial, startup, exclusion)
    }

    /// Moves C7's real fixed stage into its reader before outside-lock construction.
    ///
    /// # Errors
    /// Refuses failed, missing or already transferred fixed custody.
    pub fn construct_signed_controller_once_v1(&mut self) -> Result<(), E> {
        let state = self.signed.as_deref_mut().ok_or(E::Incomplete)?;
        if state.controller.is_some() {
            return Err(E::Incomplete);
        }
        state
            .controller_stage
            .as_ref()
            .ok_or(E::Incomplete)?
            .require_complete_v1()?;
        let fixed = state.controller_stage.take().ok_or(E::Incomplete)?;
        state.controller=Some(Box::new(super::super::initial_controller::RootInitialControllerReadonlyOriginalV1::new_signed_after_fixed_v1(fixed)));
        let open = &self.open.as_ref().ok_or(E::Incomplete)?.prepared;
        state
            .controller
            .as_deref_mut()
            .ok_or(E::Incomplete)?
            .claim_body_scope_once_v1(open)?;
        Ok(())
    }

    /// Borrows the same verified Signed input alongside the genuine C7 reader.
    ///
    /// # Errors
    /// Retains prearm, original files, real receipt or same-frame preparation refusal.
    pub fn borrow_signed_controller_once_v1<'cut, 'inputs>(
        &'cut mut self,
        data: &'cut RootCurrentPolicyInputDataV1<'inputs>,
    ) -> Result<RootInitialControllerReadonlyPreparedBorrowV1<'cut, 'startup, 'inputs>, E> {
        let open = &self.open.as_ref().ok_or(E::Incomplete)?.prepared;
        let writers = match &self.writers {
            Some(Ok(w)) => w,
            _ => return Err(E::Incomplete),
        };
        let state = self.signed.as_deref_mut().ok_or(E::Incomplete)?;
        state
            .controller
            .as_deref_mut()
            .ok_or(E::Incomplete)?
            .borrow_signed_prepared_once_v1(
                writers,
                open,
                &self.ready,
                &self.refreshed_cache_proof,
                &self.refreshed_source_exchange,
                &self.bundle_ownership,
                data,
                &self.originals,
                &self.use_authorized,
                &self.use_reserved,
                &self.use_admitted,
                &state.received.input,
            )
            .map_err(E::from)
    }

    /// Prepares Root4 only after the actual C7 and signed verification complete.
    ///
    /// # Errors
    /// Retains native phase, canonical body or exact pair preparation refusal.
    pub fn prepare_signed_once_v1(&mut self) -> Result<(), E> {
        let open = &self.open.as_ref().ok_or(E::Incomplete)?.prepared;
        self.signed
            .as_deref_mut()
            .ok_or(E::Incomplete)?
            .prepare_once_v1(open, &self.use_admitted)
    }

    /// Appends Root4 through the sole native append engine and finite Signed gate.
    ///
    /// # Errors
    /// Retains real crossing, append, exact readback or end refusal.
    pub fn append_signed_once_v1(&mut self) -> Result<(), E> {
        let open = &self.open.as_ref().ok_or(E::Incomplete)?.prepared;
        let writers = match &mut self.writers {
            Some(Ok(w)) => w,
            _ => return Err(E::Incomplete),
        };
        self.signed
            .as_deref_mut()
            .ok_or(E::Incomplete)?
            .append_once_v1(
                open,
                &self.use_admitted,
                &self.use_reserved,
                &self.refreshed_source_exchange,
                writers,
                &self.originals,
                &self.original,
            )
    }

    /// Observes all independently owed Root4 append posts after its entered body.
    pub fn observe_signed_append_posts_once_v1(&mut self) {
        let Some(open) = &self.open else {
            return;
        };
        let Some(Ok(writers)) = &mut self.writers else {
            return;
        };
        let Some(state) = self.signed.as_deref_mut() else {
            return;
        };
        state.observe_append_posts_once_v1(
            &open.prepared,
            &self.use_reserved,
            &self.refreshed_source_exchange,
            writers,
            &self.originals,
        );
    }

    /// Frames the actual durable Root4 receipt after the independent append posts.
    ///
    /// # Errors
    /// Refuses body, post, sequence overflow or exact frame construction failure.
    pub fn frame_signed_once_v1(&mut self) -> Result<(), E> {
        let open = &self.open.as_ref().ok_or(E::Incomplete)?.prepared;
        self.signed
            .as_deref_mut()
            .ok_or(E::Incomplete)?
            .frame_after_posts_once_v1(open, &self.ready)
    }

    /// Writes the actual Root4 frame and always observes its original send posts.
    ///
    /// # Errors
    /// Retains partial IO, native names, readback, clock or end refusal.
    pub fn send_signed_once_v1(&mut self) -> Result<(), E> {
        let open = &self.open.as_ref().ok_or(E::Incomplete)?.prepared;
        let writers = match &mut self.writers {
            Some(Ok(w)) => w,
            _ => return Err(E::Incomplete),
        };
        self.signed
            .as_deref_mut()
            .ok_or(E::Incomplete)?
            .send_once_v1(
                open,
                &self.use_reserved,
                &self.refreshed_source_exchange,
                writers,
                &self.originals,
                &self.original,
            )
    }

    /// Requires the genuine complete Root4 phase without extracting any original.
    ///
    /// # Errors
    /// Refuses any incomplete true stage, typed input, native writer or send/post.
    pub fn require_signed_complete_v1(&self) -> Result<(), E> {
        self.signed
            .as_deref()
            .ok_or(E::Incomplete)?
            .require_complete_v1()
    }

    pub(in crate::native::root_current) fn signed_construction_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;
        // Only the outer Stage and early quote/entry controls are constructed
        // before Root4. The later Box and nested receiver constructors are paid
        // by their actual fixed demand before their first allocation.
        size_of::<RootInitialStageOriginalV1>()
            .checked_mul(2)?
            .checked_add(
                size_of::<(
                    &mut Self,
                    &mut RootInitialReceivingOriginalV1,
                    &RootSelectedStartupBorrowV1<'_>,
                    &RootUpperMutationGuardV1<'_>,
                )>()
                .checked_mul(3)?,
            )?
            .checked_add(size_of::<Result<(), RootObservationErrorV1>>().checked_mul(3)?)?
            .checked_add(
                size_of::<Result<ResourceVector, crate::native::PolicyNativeJournalErrorV1>>()
                    .checked_mul(3)?,
            )?
            .checked_add(
                size_of::<(
                    &super::super::preopen_geometry::ProtectedJournalPreopenReplayExtentV1,
                    ResourceVector,
                    &super::super::use_tail::admitted::RootUseAdmittedOriginalV1,
                )>()
                .checked_mul(3)?,
            )
    }
}

impl RootOwnedCurrentOriginalV1<'_> {
    /// Prearms C7's actual body peer before any receipt or file preparation.
    pub fn arm_signed_controller_body_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) {
        let returned = match self
            .originals
            .peer
            .borrow_current_writers_predecessor_v1(initial)
        {
            Ok(predecessor) => match self
                .signed
                .as_deref_mut()
                .and_then(|state| state.controller.as_deref_mut())
            {
                Some(controller) => {
                    controller.arm_body_peer_once_v1(predecessor, startup, exclusion)
                }
                None => Err(RootObservationErrorV1::Service),
            },
            Err(error) => {
                if let Some(state) = self.signed.as_deref_mut() {
                    state.controller_predecessor.get_or_insert(error);
                } else {
                    self.signed_predecessor.get_or_insert(error);
                }
                Err(RootObservationErrorV1::Service)
            }
        };
        if returned.is_err() {
            initial.latch_root_refusal_v1();
        }
    }

    /// Parks only a negative upper arm result on the genuine C7 original.
    pub fn refuse_signed_controller_body_arm_once_v1(&mut self) {
        if let Some(controller) = self
            .signed
            .as_deref_mut()
            .and_then(|state| state.controller.as_deref_mut())
        {
            controller.refuse_body_peer_arm_once_v1();
        }
    }

    /// Observes the actual entered C7 names, mount, Storage and metadata posts.
    pub fn observe_signed_controller_native_posts_once_v1(&mut self) {
        let Some(open) = &self.open else {
            return;
        };
        let Some(Ok(writers)) = &self.writers else {
            return;
        };
        let Some(state) = self.signed.as_deref_mut() else {
            return;
        };
        if let Some(controller) = state.controller.as_deref_mut() {
            controller.observe_signed_native_posts_once_v1(
                writers,
                &open.prepared,
                &self.use_authorized,
                &self.use_reserved,
                &self.use_admitted,
                &state.received.input,
            );
        }
    }

    /// Observes the same prearmed C7 peer and independent late clock.
    pub fn observe_signed_controller_post_once_v1(&mut self) {
        let Some(open) = &self.open else {
            return;
        };
        if let Some(controller) = self
            .signed
            .as_deref_mut()
            .and_then(|state| state.controller.as_deref_mut())
        {
            controller.observe_peer_and_clock_once_v1(
                &self.originals,
                &open.prepared,
                &self.refreshed_source_exchange,
            );
        }
    }
}
