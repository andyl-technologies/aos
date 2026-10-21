//! Drives local Root Use with short same-Initial loans at each actual arm.
//!
//! No exclusion guard spans preparation, append or std Write. Failed stages
//! retain their real originals and deny the same Initial before returning.

use super::*;
use super::super::initial_use_authorized::{RootInitialUseAuthorizedErrorV1 as E,
    RootInitialUseAuthorizedPreparedBorrowV1};

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
    pub fn begin_initial_use_authorized_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        if self.use_authorized.fixed.entered || self.use_authorized.closed {
            self.use_authorized.closed = true;
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        self.use_authorized.fixed.entered = true;
        let predecessor = match self.originals.peer.borrow_current_writers_predecessor_v1(initial) {
            Ok(predecessor) => predecessor,
            Err(error) => {
                self.use_authorized.predecessor.get_or_insert(error);
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
        self.use_authorized.begin_once_v1(open, &self.controller, writers,
            predecessor, startup, exclusion)
    }

    /// Arms the independent append post before entering the actual body.
    ///
    /// # Errors
    /// Retains same-Initial predecessor, Stage, traffic, arm or reentry refusal.
    pub fn arm_initial_use_authorized_append_post_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        self.arm_use_authorized(Arm::Append, initial, startup, exclusion)
    }

    /// Arms the distinct final-crossing observation after genuine preparation.
    ///
    /// # Errors
    /// Refuses incomplete native purposes, predecessor or actual arm failure.
    /// The enclosing append post remains owed after this returned refusal.
    pub fn arm_initial_use_authorized_crossing_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        self.arm_use_authorized(Arm::Crossing, initial, startup, exclusion)
    }

    /// Arms the independent write post after the exact frame is prepared.
    ///
    /// # Errors
    /// Refuses framing, reentry, genuine predecessor or actual arm failure.
    pub fn arm_initial_use_authorized_send_post_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        self.arm_use_authorized(Arm::Send, initial, startup, exclusion)
    }

    fn arm_use_authorized(
        &mut self,
        arm: Arm,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let allowed = match arm {
            Arm::Append => self.use_authorized.append_arm.is_none()
                && self.use_authorized.fixed.require_complete_v1().is_ok(),
            Arm::Crossing => matches!(self.use_authorized.primary, Some(Ok(())))
                && self.controller.require_complete_v1().is_ok()
                && self.source_exchange.require_complete_v1().is_ok()
                && self.cache_proof.require_complete_v1().is_ok(),
            Arm::Send => self.use_authorized.send_arm.is_none()
                && matches!(self.use_authorized.framing, Some(Ok(()))),
        };
        if !allowed {
            self.use_authorized.closed = true;
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        let result = match self.originals.peer.borrow_current_writers_predecessor_v1(initial) {
            Ok(predecessor) => match arm {
                Arm::Append => self.use_authorized.append_posts.arm_once_v1(predecessor, startup, exclusion),
                Arm::Crossing => self.use_authorized.pair.arm_once_v1(predecessor, startup, exclusion),
                Arm::Send => self.use_authorized.send_posts.arm_once_v1(predecessor, startup, exclusion),
            },
            Err(error) => Err(error),
        };
        let failed = result.is_err();
        match arm {
            Arm::Append => self.use_authorized.append_arm = Some(result),
            Arm::Send => self.use_authorized.send_arm = Some(result),
            Arm::Crossing => {
                if let Err(error) = result {
                    self.use_authorized.crossing_refusal.get_or_insert(error);
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

    /// Borrows the actual body beside the same completed native predecessors.
    ///
    /// # Errors
    /// Refuses absent local admission, unarmed append post, incomplete Open or
    /// reentry. Proposed receiving DATA supplies none of these conditions.
    pub fn borrow_initial_use_authorized_once_v1(&mut self)
        -> Result<RootInitialUseAuthorizedPreparedBorrowV1<'_>, E>
    {
        self.use_authorized.fixed.require_complete_v1()?;
        if self.use_authorized.body_borrowed || self.use_authorized.primary.is_some() || self.use_authorized.closed
            || !matches!(self.use_authorized.append_arm, Some(Ok(())))
        {
            self.use_authorized.closed = true;
            return Err(E::Incomplete);
        }
        let open = self.open.as_ref().ok_or(E::Incomplete)?;
        open.require_complete_v1()?;
        self.use_authorized.body_borrowed = true;
        Ok(RootInitialUseAuthorizedPreparedBorrowV1 {
            state: &mut self.use_authorized,
            open: &open.prepared,
            ready: &self.ready,
            source: &self.source_exchange,
            cache: &self.cache_proof,
            ownership: &self.bundle_ownership,
            readonly: &self.controller,
        })
    }

    /// Appends through the sole native engine and genuine finite Use gate.
    ///
    /// # Errors
    /// Retains crossing, durable append, readback and native-end refusal.
    pub fn append_initial_use_authorized_once_v1(&mut self) -> Result<(), E> {
        let open = &self.open.as_ref().ok_or(E::Incomplete)?.prepared;
        let writers = match &mut self.writers {
            Some(Ok(writers)) => writers,
            _ => return Err(E::Incomplete),
        };
        self.use_authorized.append_once_v1(open, &self.controller, &self.source_exchange,
            &self.cache_proof, writers, &self.originals, &self.original)
    }

    /// Observes all owed append bookends after the attempted body, including refusal.
    pub fn observe_initial_use_authorized_append_posts_once_v1(&mut self) {
        let Some(open) = &self.open else {
            return;
        };
        let Some(Ok(writers)) = &mut self.writers else {
            return;
        };
        self.use_authorized.observe_append_posts_once_v1(&open.prepared, &self.controller,
            &self.source_exchange, writers, &self.originals);
    }

    /// Frames the actual committed record against the same original Hello.
    ///
    /// # Errors
    /// Refuses failed body/posts, malformed receipt, reentry or sequence overflow.
    pub fn frame_initial_use_authorized_once_v1(&mut self) -> Result<(), E> {
        let open = &self.open.as_ref().ok_or(E::Incomplete)?.prepared;
        self.use_authorized.frame_once_v1(open, &self.ready, &self.cache_proof)
    }

    /// Writes through the same owned std stream and observes all owed send posts.
    ///
    /// # Errors
    /// Retains partial write, native bookends, original clock, readback or end
    /// failure. A failed write still reaches the independent send observations.
    pub fn send_initial_use_authorized_once_v1(&mut self) -> Result<(), E> {
        let open = &self.open.as_ref().ok_or(E::Incomplete)?.prepared;
        let writers = match &mut self.writers {
            Some(Ok(writers)) => writers,
            _ => return Err(E::Incomplete),
        };
        self.use_authorized.send_once_v1(open, &self.controller, &self.source_exchange,
            writers, &self.originals, &self.original)
    }

    /// Requires the complete genuine local Root UseAuthorized programme.
    ///
    /// # Errors
    /// Refuses incomplete admission, body, append, exact write or owed post.
    pub fn require_initial_use_authorized_complete_v1(&self) -> Result<(), E> {
        self.use_authorized.require_complete_v1()
    }
}

impl RootOwnedCurrentOriginalV1<'_> {
    pub(in crate::native::root_current) fn use_authorized_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;
        let entries = size_of::<(&mut Self, &mut RootInitialReceivingOriginalV1,
            &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>)>().checked_mul(12)?;
        let arm = size_of::<(Arm, &mut Self, &mut RootInitialReceivingOriginalV1,
            &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>)>().checked_mul(9)?
            .checked_add(size_of::<(Arm, bool)>().checked_mul(9)?)?;
        let loans = size_of::<&mut Self>().checked_mul(18)?
            .checked_add(size_of::<Result<RootInitialUseAuthorizedPreparedBorrowV1<'_>, E>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<crate::native::startup::RootCurrentWritersPredecessorV1<'_, '_, '_>,
                RootObservationErrorV1>>().checked_mul(12)?)?;
        let returns = size_of::<Result<(), RootObservationErrorV1>>().checked_mul(21)?
            .checked_add(size_of::<Result<(), E>>().checked_mul(18)?)?;
        entries.checked_add(arm)?.checked_add(loans)?.checked_add(returns)
    }
}


impl RootOwnedCurrentOriginalV1<'_> {
    /// Quotes the twelve native name controls constructed in the incoming owner.
    ///
    /// The actual incoming forecast pays these identities before construction.
    /// The local Use fixed quote keeps their native backing and excludes only
    /// this same once-paid incremental control band.
    ///
    /// # Errors
    /// Refuses checked overflow of the actual native owner's control count.
    pub fn initial_use_authorized_owed_names_demand_v1()
        -> Result<ResourceVector, crate::native::PolicyNativeJournalErrorV1>
    {
        let cells = crate::native::journal::names::RootPolicyNameObservationOriginalV1::retained_control_cells_v1()
            .checked_mul(12).ok_or_else(crate::native::PolicyNativeJournalErrorV1::geometry)?;
        Ok(ResourceVector::ZERO.with(aos_sandbox_model::ResourceDimension::MetadataEntries, cells))
    }
}
