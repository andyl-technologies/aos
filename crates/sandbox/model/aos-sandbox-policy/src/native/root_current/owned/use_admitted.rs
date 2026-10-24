//! Drives local Root Use with short same-Initial loans at each actual arm.
//!
//! No exclusion guard spans preparation, append or std Write. Failed stages
//! retain their real originals and deny the same Initial before returning.

use super::super::use_tail::admitted::RootUseAdmittedErrorV1 as E;
use super::*;

#[derive(Clone, Copy)]
enum Arm {
    Append,
    Crossing,
    Send,
}

impl RootOwnedCurrentOriginalV1<'_> {
    /// Admits Root's local append from its completed Controller prefix.
    ///
    /// # Errors
    /// Retains genuine predecessor, same-financial quote, Stage or service
    /// refusal. Unsigned prospective Controller receiving DATA is not an input.
    pub fn begin_use_admitted_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        if self.use_admitted.fixed.entered || self.use_admitted.closed {
            self.use_admitted.closed = true;
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        self.use_admitted.fixed.entered = true;
        let predecessor = match self
            .originals
            .peer
            .borrow_current_writers_predecessor_v1(initial)
        {
            Ok(predecessor) => predecessor,
            Err(error) => {
                self.use_admitted.predecessor.get_or_insert(error);
                initial.latch_root_refusal_v1();
                return Err(RootObservationErrorV1::Service);
            }
        };
        let open = match &self.open {
            Some(open) => &open.prepared,
            None => {
                drop(predecessor);
                initial.latch_root_refusal_v1();
                return Err(RootObservationErrorV1::Service);
            }
        };
        let writers = match &self.writers {
            Some(Ok(writers)) => writers,
            _ => {
                drop(predecessor);
                initial.latch_root_refusal_v1();
                return Err(RootObservationErrorV1::Service);
            }
        };
        self.use_admitted.begin_once_v1(
            open,
            &self.use_authorized,
            &self.use_reserved,
            &self.refreshed_source_exchange,
            &self.refreshed_cache_proof,
            writers,
            predecessor,
            startup,
            exclusion,
        )
    }

    /// Arms the independent append post before entering the actual body.
    ///
    /// # Errors
    /// Retains same-Initial predecessor, Stage, traffic, arm or reentry refusal.
    pub fn arm_use_admitted_append_post_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        self.arm_use_admitted(Arm::Append, initial, startup, exclusion)
    }

    /// Arms the distinct final-crossing observation after genuine preparation.
    ///
    /// # Errors
    /// Refuses incomplete native purposes, predecessor or actual arm failure.
    /// The enclosing append post remains owed after this returned refusal.
    pub fn arm_use_admitted_crossing_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        self.arm_use_admitted(Arm::Crossing, initial, startup, exclusion)
    }

    /// Arms the independent write post after the exact frame is prepared.
    ///
    /// # Errors
    /// Refuses framing, reentry, genuine predecessor or actual arm failure.
    pub fn arm_use_admitted_send_post_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        self.arm_use_admitted(Arm::Send, initial, startup, exclusion)
    }

    fn arm_use_admitted(
        &mut self,
        arm: Arm,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let allowed = match arm {
            Arm::Append => {
                self.use_admitted.append_arm.is_none()
                    && self.use_admitted.fixed.require_complete_v1().is_ok()
            }
            Arm::Crossing => {
                matches!(self.use_admitted.primary, Some(Ok(())))
                    && self.use_reserved.require_complete_v1().is_ok()
                    && self.refreshed_source_exchange.require_complete_v1().is_ok()
                    && self.refreshed_cache_proof.require_complete_v1().is_ok()
            }
            Arm::Send => {
                self.use_admitted.send_arm.is_none()
                    && matches!(self.use_admitted.framing, Some(Ok(())))
            }
        };
        if !allowed {
            self.use_admitted.closed = true;
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        let result = match self
            .originals
            .peer
            .borrow_current_writers_predecessor_v1(initial)
        {
            Ok(predecessor) => match arm {
                Arm::Append => {
                    self.use_admitted
                        .append_posts
                        .arm_once_v1(predecessor, startup, exclusion)
                }
                Arm::Crossing => {
                    self.use_admitted
                        .pair
                        .arm_once_v1(predecessor, startup, exclusion)
                }
                Arm::Send => {
                    self.use_admitted
                        .send_posts
                        .arm_once_v1(predecessor, startup, exclusion)
                }
            },
            Err(error) => Err(error),
        };
        let failed = result.is_err();
        match arm {
            Arm::Append => self.use_admitted.append_arm = Some(result),
            Arm::Send => self.use_admitted.send_arm = Some(result),
            Arm::Crossing => {
                if let Err(error) = result {
                    self.use_admitted.crossing_refusal.get_or_insert(error);
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

    /// Prepares Root3 from the actual refreshed proofs and protected unsigned plan.
    ///
    /// # Errors
    /// Retains incomplete real stages, prior purposes, canonical rows or reentry.
    pub fn prepare_use_admitted_once_v1(&mut self) -> Result<(), E> {
        let open = &self.open.as_ref().ok_or(E::Incomplete)?.prepared;
        self.use_admitted.prepare_once_v1(
            open,
            &self.use_authorized,
            &self.use_reserved,
            &self.refreshed_source_exchange,
            &self.refreshed_cache_proof,
        )
    }

    /// Appends through the sole native engine and genuine finite Use gate.
    ///
    /// # Errors
    /// Retains crossing, durable append, readback and native-end refusal.
    pub fn append_use_admitted_once_v1(&mut self) -> Result<(), E> {
        let open = &self.open.as_ref().ok_or(E::Incomplete)?.prepared;
        let writers = match &mut self.writers {
            Some(Ok(writers)) => writers,
            _ => return Err(E::Incomplete),
        };
        self.use_admitted.append_once_v1(
            open,
            &self.use_authorized,
            &self.use_reserved,
            &self.refreshed_source_exchange,
            &self.refreshed_cache_proof,
            writers,
            &self.originals,
            &self.original,
        )
    }

    /// Observes all owed append bookends after the attempted body, including refusal.
    pub fn observe_use_admitted_append_posts_once_v1(&mut self) {
        let Some(open) = &self.open else {
            return;
        };
        let Some(Ok(writers)) = &mut self.writers else {
            return;
        };
        self.use_admitted.observe_append_posts_once_v1(
            &open.prepared,
            &self.use_reserved,
            &self.refreshed_source_exchange,
            writers,
            &self.originals,
        );
    }

    /// Frames the actual committed record against the same original Hello.
    ///
    /// # Errors
    /// Refuses failed body/posts, malformed receipt, reentry or sequence overflow.
    pub fn frame_use_admitted_once_v1(&mut self) -> Result<(), E> {
        let open = &self.open.as_ref().ok_or(E::Incomplete)?.prepared;
        self.use_admitted
            .frame_once_v1(open, &self.ready, &self.use_reserved)
    }

    /// Writes through the same owned std stream and observes all owed send posts.
    ///
    /// # Errors
    /// Retains partial write, native bookends, original clock, readback or end
    /// failure. A failed write still reaches the independent send observations.
    pub fn send_use_admitted_once_v1(&mut self) -> Result<(), E> {
        let open = &self.open.as_ref().ok_or(E::Incomplete)?.prepared;
        let writers = match &mut self.writers {
            Some(Ok(writers)) => writers,
            _ => return Err(E::Incomplete),
        };
        self.use_admitted.send_once_v1(
            open,
            &self.use_reserved,
            &self.refreshed_source_exchange,
            writers,
            &self.originals,
            &self.original,
        )
    }

    /// Requires the complete genuine local Root UseAdmitted programme.
    ///
    /// # Errors
    /// Refuses incomplete admission, body, append, exact write or owed post.
    pub fn require_use_admitted_complete_v1(&self) -> Result<(), E> {
        self.use_admitted.require_complete_v1()
    }
}

impl RootOwnedCurrentOriginalV1<'_> {
    pub(in crate::native::root_current) fn use_admitted_construction_control_bytes_v1()
    -> Option<usize> {
        use std::mem::size_of;
        let entries = size_of::<(
            &mut Self,
            &mut RootInitialReceivingOriginalV1,
            &RootSelectedStartupBorrowV1<'_>,
            &RootUpperMutationGuardV1<'_>,
        )>()
        .checked_mul(12)?;
        let arm = size_of::<(
            Arm,
            &mut Self,
            &mut RootInitialReceivingOriginalV1,
            &RootSelectedStartupBorrowV1<'_>,
            &RootUpperMutationGuardV1<'_>,
        )>()
        .checked_mul(9)?
        .checked_add(size_of::<(Arm, bool)>().checked_mul(9)?)?;
        let loans = size_of::<&mut Self>().checked_mul(18)?.checked_add(
            size_of::<
                Result<
                    crate::native::startup::RootCurrentWritersPredecessorV1<'_, '_, '_>,
                    RootObservationErrorV1,
                >,
            >()
            .checked_mul(12)?,
        )?;
        let returns = size_of::<Result<(), RootObservationErrorV1>>()
            .checked_mul(21)?
            .checked_add(size_of::<Result<(), E>>().checked_mul(18)?)?;
        super::super::use_tail::admitted::RootUseAdmittedOriginalV1::construction_control_bytes_v1(
        )?
        .checked_add(entries)?
        .checked_add(arm)?
        .checked_add(loans)?
        .checked_add(returns)
    }

    /// Quotes the twelve native name controls eagerly retained for Root3.
    ///
    /// # Errors
    /// Refuses overflow of the actual retained native control count.
    pub fn use_admitted_owed_names_demand_v1()
    -> Result<ResourceVector, crate::native::PolicyNativeJournalErrorV1> {
        let cells = crate::native::journal::names::RootPolicyNameObservationOriginalV1::retained_control_cells_v1()
            .checked_mul(12).ok_or_else(crate::native::PolicyNativeJournalErrorV1::geometry)?;
        Ok(ResourceVector::ZERO.with(aos_sandbox_model::ResourceDimension::MetadataEntries, cells))
    }
}
