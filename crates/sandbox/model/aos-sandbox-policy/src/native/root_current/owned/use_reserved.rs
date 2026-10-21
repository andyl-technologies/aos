//! Advances the real Reserved frame and distinct captured Controller purpose.
//!
//! Same-Initial loans exist only inside the original short exclusions. Both
//! genuine history arms precede the Frame6 receive. The separate fixed reader
//! admission precedes its Box; every entered replay retains its owed posts.

use super::super::initial_controller::{
    RootInitialControllerReadonlyErrorV1, RootInitialControllerReadonlyPreparedBorrowV1,
};
use super::super::use_tail::reserved::RootUseReservedErrorV1 as E;
use super::*;
use crate::root_policy_inputs_data::RootCurrentPolicyInputDataV1;

#[derive(Clone, Copy)]
enum FrameArm {
    Before,
    After,
}

impl<'startup> RootOwnedCurrentOriginalV1<'startup> {
    /// Pays the same Root's Reserved frame Stage after completed authorization.
    ///
    /// # Errors
    /// Retains repeated entry, original association, genuine predecessor, quote,
    /// receiving debit or selected service refusal on the same resident owner.
    pub fn begin_use_reserved_frame_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let Some(open) = &self.open else {
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        };
        let predecessor = match self
            .originals
            .peer
            .borrow_current_writers_predecessor_v1(initial)
        {
            Ok(predecessor) => predecessor,
            Err(error) => {
                self.use_reserved.park_predecessor_refusal_v1(error);
                initial.latch_root_refusal_v1();
                return Err(RootObservationErrorV1::Service);
            }
        };
        self.use_reserved.begin_frame_fixed_once_v1(
            &open.prepared,
            &self.use_authorized,
            predecessor,
            startup,
            exclusion,
        )
    }

    /// Constructs the real frame only after its actual fixed admission.
    ///
    /// # Errors
    /// Refuses an absent, failed or repeated receiving Stage.
    pub fn construct_use_reserved_frame_once_v1(&mut self) -> Result<(), E> {
        self.use_reserved.construct_frame_once_v1()
    }

    /// Arms the first independent bookend before receiving the real Frame6.
    ///
    /// # Errors
    /// Retains same-Initial, financial, service, worker or traffic refusal.
    pub fn arm_use_reserved_frame_before_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        self.arm_reserved_frame(FrameArm::Before, initial, startup, exclusion)
    }

    /// Arms the distinct second bookend only after the first arm succeeded.
    ///
    /// # Errors
    /// Retains first-arm, same-Initial, financial, service or traffic refusal.
    pub fn arm_use_reserved_frame_after_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        self.arm_reserved_frame(FrameArm::After, initial, startup, exclusion)
    }

    fn arm_reserved_frame(
        &mut self,
        arm: FrameArm,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let predecessor = match self
            .originals
            .peer
            .borrow_current_writers_predecessor_v1(initial)
        {
            Ok(predecessor) => predecessor,
            Err(error) => {
                self.use_reserved.park_predecessor_refusal_v1(error);
                initial.latch_root_refusal_v1();
                return Err(RootObservationErrorV1::Service);
            }
        };
        let result = match self.use_reserved.frame_mut_v1() {
            Ok(frame) => match arm {
                FrameArm::Before => frame.arm_before_once_v1(predecessor, startup, exclusion),
                FrameArm::After => frame.arm_after_once_v1(predecessor, startup, exclusion),
            },
            Err(_) => Err(RootObservationErrorV1::Service),
        };
        if result.is_err() {
            initial.latch_root_refusal_v1();
        }
        result
    }

    /// Receives the same accepted stream and observes every entered bookend.
    ///
    /// # Errors
    /// Retains endpoint, writer/readback, original clock, deadline IO, exact
    /// Frame6, authorization, bank/head/history-coordinate or owed-post refusal.
    pub fn receive_use_reserved_frame_once_v1(&mut self) -> Result<(), E> {
        let open = &self.open.as_ref().ok_or(E::Incomplete)?.prepared;
        let writers = match &mut self.writers {
            Some(Ok(writers)) => writers,
            _ => return Err(E::Incomplete),
        };
        self.use_reserved.frame_mut_v1()?.receive_once_v1(
            writers,
            &self.original,
            &self.originals,
            open,
            &self.use_authorized,
            &self.ready,
            &self.source_exchange,
            &self.cache_proof,
            &self.controller,
        )
    }

    /// Pays the distinct reader from the same completed Reserved frame Stage.
    ///
    /// # Errors
    /// Retains frame, original association, genuine predecessor, fixed quote,
    /// financial debit or selected service refusal before reader allocation.
    pub fn begin_use_reserved_controller_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let Some(open) = &self.open else {
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        };
        let predecessor = match self
            .originals
            .peer
            .borrow_current_writers_predecessor_v1(initial)
        {
            Ok(predecessor) => predecessor,
            Err(error) => {
                self.use_reserved.park_predecessor_refusal_v1(error);
                initial.latch_root_refusal_v1();
                return Err(RootObservationErrorV1::Service);
            }
        };
        self.use_reserved.begin_controller_fixed_once_v1(
            &open.prepared,
            &self.use_authorized,
            predecessor,
            startup,
            exclusion,
        )
    }

    /// Constructs the paid distinct reader and enters its original post scope.
    ///
    /// # Errors
    /// Refuses failed fixed admission, missing original Open or repeat entry.
    pub fn enter_use_reserved_controller_body_once_v1(&mut self) -> Result<(), E> {
        self.use_reserved.construct_controller_once_v1()?;
        let open = &self.open.as_ref().ok_or(E::Incomplete)?.prepared;
        self.use_reserved
            .controller_mut_v1()?
            .claim_body_scope_once_v1(open)
            .map_err(E::from)
    }

    /// Prearms this distinct Controller purpose before its mount and file work.
    pub fn arm_use_reserved_controller_body_once_v1(
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
            Ok(predecessor) => match self.use_reserved.controller_mut_v1() {
                Ok(controller) => controller.arm_body_peer_once_v1(predecessor, startup, exclusion),
                Err(_) => Err(RootObservationErrorV1::Service),
            },
            Err(error) => {
                self.use_reserved.park_predecessor_refusal_v1(error);
                Err(RootObservationErrorV1::Service)
            }
        };
        if returned.is_err() {
            initial.latch_root_refusal_v1();
        }
    }

    /// Parks an upper arm failure without suppressing already owed native posts.
    pub fn refuse_use_reserved_controller_body_arm_once_v1(&mut self) {
        if let Ok(controller) = self.use_reserved.controller_mut_v1() {
            controller.refuse_body_peer_arm_once_v1();
        }
    }

    /// Borrows the real parsed receipt, distinct reader and actual stage reservoirs.
    ///
    /// # Errors
    /// Retains fixed/body/arm, receipt, physical writer, clock or mount refusal.
    pub fn borrow_use_reserved_controller_once_v1<'cut, 'inputs>(
        &'cut mut self,
        policy: &'cut RootCurrentPolicyInputDataV1<'inputs>,
    ) -> Result<RootInitialControllerReadonlyPreparedBorrowV1<'cut, 'startup, 'inputs>, E> {
        let open = &self.open.as_ref().ok_or(E::Incomplete)?.prepared;
        let writers = match &self.writers {
            Some(Ok(writers)) => writers,
            _ => return Err(E::Incomplete),
        };
        self.use_reserved.borrow_controller_once_v1(
            writers,
            open,
            &self.use_authorized,
            &self.ready,
            &self.cache_proof,
            &self.source_exchange,
            &self.bundle_ownership,
            policy,
            &self.originals,
        )
    }

    /// Observes this entered purpose's independent writer, file and mount posts.
    pub fn observe_use_reserved_controller_native_posts_once_v1(&mut self) {
        let Some(open) = &self.open else {
            return;
        };
        if let Some(Ok(writers)) = &self.writers {
            self.use_reserved.observe_controller_native_posts_once_v1(
                writers,
                &open.prepared,
                &self.use_authorized,
            );
        }
    }

    /// Observes the same prearmed peer, distinct late clock and live comparisons.
    pub fn observe_use_reserved_controller_post_once_v1(&mut self) {
        let Some(open) = &self.open else {
            return;
        };
        if let Ok(controller) = self.use_reserved.controller_mut_v1() {
            controller.observe_peer_and_clock_once_v1(
                &self.originals,
                &open.prepared,
                &self.source_exchange,
            );
        }
    }

    /// Requires both the exact reserved frame and its distinct paid replay.
    ///
    /// # Errors
    /// Refuses actual frame, fixed/native/semantic, replay/model or owed posts.
    pub fn require_use_reserved_complete_v1(&self) -> Result<(), E> {
        self.use_reserved.require_complete_v1()
    }

    pub(in crate::native::root_current) fn use_reserved_construction_control_bytes_v1()
    -> Option<usize> {
        use std::mem::size_of;
        let outer = size_of::<super::super::use_tail::reserved::RootUseReservedOriginalV1>()
            .checked_mul(2)?;
        let stages = size_of::<super::super::initial_receiving::RootInitialStageOriginalV1>()
            .checked_mul(4)?;
        let entries = size_of::<(
            &mut Self,
            &mut RootInitialReceivingOriginalV1,
            &RootSelectedStartupBorrowV1<'_>,
            &RootUpperMutationGuardV1<'_>,
        )>()
        .checked_mul(18)?;
        let loans = size_of::<
            Result<
                crate::native::startup::RootCurrentWritersPredecessorV1<'_, '_, '_>,
                RootObservationErrorV1,
            >,
        >()
        .checked_mul(18)?;
        let arm = size_of::<(
            FrameArm,
            &mut Self,
            &mut RootInitialReceivingOriginalV1,
            &RootSelectedStartupBorrowV1<'_>,
            &RootUpperMutationGuardV1<'_>,
        )>()
        .checked_mul(6)?;
        let results = size_of::<Result<(), RootObservationErrorV1>>()
            .checked_mul(21)?
            .checked_add(size_of::<Result<(), E>>().checked_mul(21)?)?;
        let receiver = size_of::<&mut Self>().checked_mul(21)?;
        let prepared = size_of::<(&mut Self, &RootCurrentPolicyInputDataV1<'_>)>()
            .checked_mul(3)?
            .checked_add(
                size_of::<Result<RootInitialControllerReadonlyPreparedBorrowV1<'_, '_, '_>, E>>()
                    .checked_mul(3)?,
            )?;
        outer
            .checked_add(stages)?
            .checked_add(entries)?
            .checked_add(loans)?
            .checked_add(arm)?
            .checked_add(results)?
            .checked_add(receiver)?
            .checked_add(prepared)
    }
}
