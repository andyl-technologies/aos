//! Owns the genuine listener-to-NoApply peer and every independently owed post.
//!
//! Its constructor requires the actual completed Policy listener, the same
//! native Initial and same selected startup. Native peer/current/post minimums
//! are computed here; still-upper transport geometry supplies no permission.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_broker::receiving::{
    ObservationLifetimeV1, RootInitialReceivingOriginalV1, RootObservationErrorV1,
    RootPrearmedHistoryServicePostV1, RootPurposePeerPostV1 as Post,
    RootPurposePeerPostsOriginalV1, RootSelectedControllerCurrentSampleV1 as Current,
    RootSelectedControllerPeerOriginalV1 as Peer, RootSelectedStartupBorrowV1,
};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_linux_descriptors::unix_stream::RetainedUnixStream;

use crate::native::RootCompletedPolicyListenerOriginalV1;

use super::admission::RootNoApplyPurposeAdmissionOriginalV2 as Admission;
use super::stages::RootNoApplyReceivingErrorV2 as ReceivingError;

/// Retains one genuine NoApply continuation and its native peer/post custody.
///
/// The real completed listener, same Initial and selected startup are required
/// at construction. Native floor authority remains a separate closed owner.
/// Dropping an entered failed or unfinished purpose aborts before field Drop.
pub struct RootNoApplyControllerPeerOriginalV2<'startup> {
    listener: RootCompletedPolicyListenerOriginalV1,
    startup: RootSelectedStartupBorrowV1<'startup>,
    admission: Admission,
    shape: Option<Result<ResourceVector, ReceivingError>>,
    funding: Option<Result<(), ReceivingError>>,
    posts: [Option<Result<(), RootObservationErrorV1>>; 4],
    peer: Option<Peer<'startup>>,
    current: Option<Current>,
    capture: Option<Result<(), RootObservationErrorV1>>,
    initial_settlement: Option<Result<(), RootObservationErrorV1>>,
    current_result: Option<Result<(), RootObservationErrorV1>>,
    final_settlement: Option<Result<(), RootObservationErrorV1>>,
    upper_geometry: ResourceVector,
    final_entered: bool,
    complete: bool,
    closed: Option<RootObservationErrorV1>,
}

impl<'startup> RootNoApplyControllerPeerOriginalV2<'startup> {
    // The old actual upper first payer must charge this inert destination
    // before constructing it. No native archive/sample is created here.
    /// Measures this actual purpose constructor and named API controls.
    ///
    /// The genuine upper first payer consumes this before constructing a
    /// purpose or calling its native completed-listener admission.
    pub fn construction_control_bytes_v2() -> Option<usize> {
        size_of::<Self>()
            .checked_mul(3)?
            .checked_add(Admission::construction_control_bytes_v2()?)?
            .checked_add(Admission::listener_loan_control_bytes_v2()?)?
            .checked_add(Admission::operation_control_bytes_v2()?)?
            .checked_add(Self::public_call_control_bytes_v2()?)
    }

    // Each pair covers its actual argument and returned ABI planes. The
    // enclosing listener pays these before prepare can construct this owner;
    // the later native minimum covers the separately allocated native work.
    fn public_call_control_bytes_v2() -> Option<usize> {
        // prepare's entered local, return and embedding are the three Self
        // planes in construction_control_bytes_v2, not another return here.
        let prepare = size_of::<(
            &RootCompletedPolicyListenerOriginalV1,
            &mut RootInitialReceivingOriginalV1,
            RootSelectedStartupBorrowV1<'static>,
            ResourceVector,
        )>()
        .checked_mul(2)?;

        // capture/current, three independently owed posts, and two positive
        // archive settlements are distinct actual mutable entry points.
        let phases = size_of::<(&mut Self, &RetainedUnixStream)>()
            .checked_add(size_of::<Result<(), RootObservationErrorV1>>())?
            .checked_mul(4)?
            .checked_add(
                size_of::<(&mut Self, &mut RootInitialReceivingOriginalV1)>()
                    .checked_add(size_of::<Result<(), RootObservationErrorV1>>())?
                    .checked_mul(6)?,
            )?
            .checked_add(
                size_of::<&mut Self>()
                    .checked_add(size_of::<Result<(), RootObservationErrorV1>>())?
                    .checked_mul(4)?,
            )?;
        let stage = size_of::<(
            &mut Self,
            &mut RootInitialReceivingOriginalV1,
            super::stages::RootNoApplyStageDataV2,
            ResourceVector,
            ResourceVector,
        )>()
        .checked_add(size_of::<Result<(), RootObservationErrorV1>>())?
        .checked_mul(2)?;

        // Three complete-owner checks, the paid transport comparison, the
        // recipient-bound node and the genuine native peer borrower.
        let checks = size_of::<&Self>()
            .checked_add(size_of::<Result<(), RootObservationErrorV1>>())?
            .checked_mul(6)?
            .checked_add(
                size_of::<(&Self, ResourceVector)>()
                    .checked_add(size_of::<Result<(), RootObservationErrorV1>>())?
                    .checked_mul(2)?,
            )?
            .checked_add(
                size_of::<(&Self, &RootInitialReceivingOriginalV1)>()
                    .checked_add(size_of::<Result<[u8; 16], RootObservationErrorV1>>())?
                    .checked_mul(2)?,
            )?
            .checked_add(
                size_of::<&Self>()
                    .checked_add(size_of::<Result<&Peer<'static>, RootObservationErrorV1>>())?
                    .checked_mul(2)?,
            )?;

        // Six shared cause selectors plus the one selector carrying a Post,
        // and the property-view borrow of those SAME retained native owners.
        let diagnostics = size_of::<&Self>()
            .checked_add(size_of::<Option<&(dyn Error + 'static)>>())?
            .checked_mul(12)?
            .checked_add(
                size_of::<(&Self, Post)>()
                    .checked_add(size_of::<Option<&(dyn Error + 'static)>>())?
                    .checked_mul(2)?,
            )?
            .checked_add(
                size_of::<&Self>()
                    .checked_add(size_of::<(Option<&Peer<'static>>, Option<&Current>)>())?
                    .checked_mul(2)?,
            )?;

        // Two real settlement closures retain their mutable owner borrow.
        // The shape computation and its returned Result precede admission.
        let computations = size_of::<&mut Self>()
            .checked_add(size_of::<Result<(), RootObservationErrorV1>>())?
            .checked_mul(4)?
            .checked_add(size_of::<Result<ResourceVector, ReceivingError>>().checked_mul(2)?)?;
        prepare
            .checked_add(phases)?
            .checked_add(stage)?
            .checked_add(checks)?
            .checked_add(diagnostics)?
            .checked_add(computations)
    }

    // Constructor and ABI planes are prepaid at the genuine listener above.
    // This later minimum covers only actual native captures, their two
    // lifetime allocations, and the four independently owed native posts.
    fn native_minimum_v2() -> Result<ResourceVector, ReceivingError> {
        let invalid = || ReceivingError::EnrollmentUnavailable;
        let memory = 2_usize.checked_mul(3 * size_of::<usize>())
            .and_then(|bytes| bytes.checked_add(
                RootPurposePeerPostsOriginalV1::<RootObservationErrorV1>::operation_control_bytes_v1()?))
            .and_then(|bytes| bytes.checked_add(
                RootSelectedStartupBorrowV1::purpose_post_forwarding_control_bytes_v1::<RootObservationErrorV1>()?))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or_else(invalid)?;
        let mut demand = Peer::fixed_demand()?
            .checked_add(Current::demand_v1()?)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, memory))?;
        let post = RootPrearmedHistoryServicePostV1::demand_v1().ok_or_else(invalid)?;
        for _ in 0..4 {
            demand = demand.checked_add(post)?;
        }
        Ok(demand)
    }

    /// Prepares only this genuine completed listener's NoApply admission.
    ///
    /// The actual caller holds its original short L/U guard. The complete
    /// entered owner is returned even on refusal so no native post is lost.
    pub fn prepare_once_v2(
        listener: &RootCompletedPolicyListenerOriginalV1,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: RootSelectedStartupBorrowV1<'startup>,
        upper_geometry: ResourceVector,
    ) -> Self {
        let mut original = Self {
            listener: listener.clone(),
            startup,
            admission: Admission::new(),
            shape: None,
            funding: None,
            posts: [None, None, None, None],
            peer: None,
            current: None,
            capture: None,
            initial_settlement: None,
            current_result: None,
            final_settlement: None,
            upper_geometry,
            final_entered: false,
            complete: false,
            closed: None,
        };
        original.shape = Some(Self::native_minimum_v2());
        if let Some(Ok(minimum)) = original.shape.as_ref() {
            original.funding = Some(original.admission.arm_once_v2(
                &original.listener,
                initial,
                &original.startup,
                *minimum,
                upper_geometry,
            ));
        } else {
            initial.upper_refusal_original_v1().refuse_v1();
        }
        original.posts[0] = Some(original.admission.observe_post_once_v2(
            initial,
            &original.startup,
            Post::AdmissionBefore,
        ));
        original
    }

    /// Captures the same actual accepted stream outside all receiving guards.
    ///
    /// # Errors
    /// Retains native capture failure and refuses incomplete admission or reentry.
    pub fn capture_once_v2(
        &mut self,
        stream: &RetainedUnixStream,
    ) -> Result<(), RootObservationErrorV1> {
        if self.capture.is_some()
            || self.closed.is_some()
            || !matches!(self.funding, Some(Ok(())))
            || !self.admission.is_positive_v2(Post::AdmissionBefore)
        {
            self.closed.get_or_insert(RootObservationErrorV1::Service);
            return Err(RootObservationErrorV1::Service);
        }
        if self.peer.is_some() || self.current.is_some() {
            self.closed.get_or_insert(RootObservationErrorV1::Service);
            return Err(RootObservationErrorV1::Service);
        }
        self.admission
            .require_armed_v2()
            .map_err(|_| RootObservationErrorV1::Service)?;
        // The same two native constructors follow the paid before observation,
        // after the caller releases L/U, exactly before the first capture.
        self.peer = Some(
            self.startup
                .new_controller_peer_original_v1(ObservationLifetimeV1::begin()),
        );
        self.current = Some(Current::new(ObservationLifetimeV1::begin()));
        self.capture = Some(
            self.peer
                .as_mut()
                .ok_or(RootObservationErrorV1::Service)?
                .capture_once(stream),
        );
        positive(&self.capture)
    }

    // This independently owed post remains callable after a capture refusal.
    /// Runs the independently owed admission-after on its original destination.
    ///
    /// # Errors
    /// Retains the actual post failure, including after failed native capture.
    pub fn finish_capture_post_once_v2(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
    ) -> Result<(), RootObservationErrorV1> {
        if self.posts[1].is_some() {
            self.closed.get_or_insert(RootObservationErrorV1::Service);
            initial.upper_refusal_original_v1().refuse_v1();
            return Err(RootObservationErrorV1::Service);
        }
        self.posts[1] = Some(self.admission.observe_post_once_v2(
            initial,
            &self.startup,
            Post::AdmissionAfter,
        ));
        positive(&self.posts[1])
    }

    // Native archive retirement stays outside every Initial L/U interval.
    /// Retires positive native capture before the original admission post pair.
    ///
    /// # Errors
    /// Refuses incomplete, failed or repeated actual settlement.
    pub fn settle_initial_once_v2(&mut self) -> Result<(), RootObservationErrorV1> {
        if self.initial_settlement.is_some()
            || self.closed.is_some()
            || !matches!(self.capture, Some(Ok(())))
            || !self.admission.is_positive_v2(Post::AdmissionAfter)
            || self.primary_failure_v2().is_some()
        {
            self.closed.get_or_insert(RootObservationErrorV1::Service);
            return Err(RootObservationErrorV1::Service);
        }
        self.initial_settlement = Some((|| {
            self.peer
                .as_mut()
                .ok_or(RootObservationErrorV1::Service)?
                .settle_positive_once()?;
            self.admission
                .settle_admission_positive_once_v2()
                .map_err(|_| RootObservationErrorV1::Service)
        })());
        positive(&self.initial_settlement)
    }

    /// Requires the same actual settled initial peer and continuation prefix.
    ///
    /// # Errors
    /// Refuses any original admission, post, settlement or reached-stage failure.
    pub fn require_initial_v2(&self) -> Result<(), RootObservationErrorV1> {
        if !matches!(self.initial_settlement, Some(Ok(())))
            || self.closed.is_some()
            || self.primary_failure_v2().is_some()
            || self.admission.stages.failure().is_some()
        {
            return Err(RootObservationErrorV1::Service);
        }
        self.peer
            .as_ref()
            .ok_or(RootObservationErrorV1::Service)?
            .require_completed()
    }

    /// Requires the same original complete permit and admission-before post.
    ///
    /// # Errors
    /// Refuses the actual retained shape, funding, arming or before failure.
    pub fn require_prepared_v2(&self) -> Result<(), RootObservationErrorV1> {
        if !matches!(self.funding, Some(Ok(())))
            || !self.admission.is_positive_v2(Post::AdmissionBefore)
        {
            return Err(RootObservationErrorV1::Service);
        }
        self.admission
            .require_armed_v2()
            .map_err(|_| RootObservationErrorV1::Service)
    }

    /// Admits only the reached finite NoApply stage on this same actual Initial.
    ///
    /// # Errors
    /// Retains the complete native stage cause and refuses another original,
    /// unpaid prerequisite, repeated stage or actual receiving/traffic denial.
    pub fn admit_stage_once_v2(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        stage: super::stages::RootNoApplyStageDataV2,
        demand: ResourceVector,
        resident_baseline: ResourceVector,
    ) -> Result<(), RootObservationErrorV1> {
        self.require_initial_v2()?;
        self.admission
            .admit_stage_once_v2(initial, stage, demand, resident_baseline)
            .map_err(|_| RootObservationErrorV1::Service)
    }

    /// Borrows the recipient-bound node from this same real receiving image.
    ///
    /// # Errors
    /// Refuses an unarmed purpose, foreign Initial or original image failure.
    pub fn enrolled_node_data_v2(
        &self,
        initial: &RootInitialReceivingOriginalV1,
    ) -> Result<[u8; 16], RootObservationErrorV1> {
        self.require_initial_v2()?;
        self.admission
            .enrolled_node_data_v2(initial)
            .map_err(|_| RootObservationErrorV1::Service)
    }

    /// Checks a transport amount against its original paid upper geometry.
    ///
    /// This comparison cannot supply admission or alter the retained permit.
    ///
    /// # Errors
    /// Refuses incomplete native admission or an amount beyond actual payment.
    pub fn require_transport_prepaid_v2(
        &self,
        required: ResourceVector,
    ) -> Result<(), RootObservationErrorV1> {
        self.require_initial_v2()?;
        if self.upper_geometry.componentwise_max(required) != self.upper_geometry {
            return Err(RootObservationErrorV1::Service);
        }
        Ok(())
    }

    /// Borrows only this same purpose's actual settled native Controller peer.
    ///
    /// # Errors
    /// Refuses the original purpose or native settlement failure.
    pub fn native_peer_v2(&self) -> Result<&Peer<'startup>, RootObservationErrorV1> {
        self.require_initial_v2()?;
        self.peer.as_ref().ok_or(RootObservationErrorV1::Service)
    }

    /// Borrows the actual continuation's first retained stage cause.
    #[must_use]
    pub fn continuation_failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.admission.stages.failure()
    }

    /// Borrows only native originals selected by this purpose's first cause.
    #[must_use]
    pub fn property_failure_originals_v2(&self) -> (Option<&Peer<'startup>>, Option<&Current>) {
        let Some(first) = self.failure_v2() else {
            return (None, None);
        };
        if let Some(peer) = &self.peer {
            if peer
                .failure()
                .is_some_and(|cause| std::ptr::addr_eq(first as *const _, cause as *const _))
            {
                return (Some(peer), None);
            }
        }
        if let Some(sample) = &self.current {
            if sample
                .failure()
                .is_some_and(|cause| std::ptr::addr_eq(first as *const _, cause as *const _))
            {
                return (None, Some(sample));
            }
        }
        (None, None)
    }

    /// Requires actual native settlement and every original positive post.
    ///
    /// # Errors
    /// Refuses any unfinished or failed actual purpose; no scalar completion
    /// passed by a caller can satisfy this same-owner conjunction.
    pub fn require_completed_v2(&self) -> Result<(), RootObservationErrorV1> {
        if !self.complete
            || !self.final_entered
            || !matches!(self.initial_settlement, Some(Ok(())))
            || !matches!(self.final_settlement, Some(Ok(())))
            || self.failure_v2().is_some()
        {
            return Err(RootObservationErrorV1::Service);
        }
        Ok(())
    }

    // Native currentness runs outside the same short before/after intervals.
    /// Observes the independently prearmed final-before on the same Initial.
    ///
    /// # Errors
    /// Retains original native refusal and rejects a repeated final programme.
    pub fn begin_final_post_once_v2(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
    ) -> Result<(), RootObservationErrorV1> {
        if self.final_entered || self.posts[2].is_some() {
            self.closed.get_or_insert(RootObservationErrorV1::Service);
            initial.upper_refusal_original_v1().refuse_v1();
            return Err(RootObservationErrorV1::Service);
        }
        self.final_entered = true;
        self.posts[2] = Some(self.admission.observe_post_once_v2(
            initial,
            &self.startup,
            Post::FinalBefore,
        ));
        positive(&self.posts[2])
    }

    /// Observes the same prearmed native current sample outside L/U.
    ///
    /// # Errors
    /// Preserves the original current sample cause or incomplete native entry.
    pub fn observe_final_current_once_v2(
        &mut self,
        stream: &RetainedUnixStream,
    ) -> Result<(), RootObservationErrorV1> {
        if !self.final_entered || self.current_result.is_some() {
            self.closed.get_or_insert(RootObservationErrorV1::Service);
            return Err(RootObservationErrorV1::Service);
        }
        // As before, the prearmed sample is reached after protocol refusal as
        // long as the original initial native comparison settled positively.
        if matches!(self.initial_settlement, Some(Ok(()))) {
            if let (Some(peer), Some(sample)) = (&self.peer, &mut self.current) {
                self.current_result = Some(peer.observe_prearmed_current_into_v1(stream, sample));
            }
        }
        positive(&self.current_result)
    }

    /// Observes final-after independently of the native current outcome.
    ///
    /// # Errors
    /// Retains native post refusal and rejects repeated observation.
    pub fn finish_final_post_once_v2(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
    ) -> Result<(), RootObservationErrorV1> {
        if self.posts[3].is_some() {
            self.closed.get_or_insert(RootObservationErrorV1::Service);
            initial.upper_refusal_original_v1().refuse_v1();
            return Err(RootObservationErrorV1::Service);
        }
        self.posts[3] = Some(self.admission.observe_post_once_v2(
            initial,
            &self.startup,
            Post::FinalAfter,
        ));
        positive(&self.posts[3])
    }

    // Only the actual containing successful protocol calls this retirement.
    /// Retires the positive current archive before its original final post pair.
    ///
    /// # Errors
    /// Refuses incomplete protocol, native or post settlement.
    pub fn settle_final_once_v2(&mut self) -> Result<(), RootObservationErrorV1> {
        if self.complete
            || !self.final_entered
            || self.failure_v2().is_some()
            || !matches!(self.current_result, Some(Ok(())))
            || !self.admission.is_positive_v2(Post::FinalBefore)
            || !self.admission.is_positive_v2(Post::FinalAfter)
        {
            self.closed.get_or_insert(RootObservationErrorV1::Service);
            return Err(RootObservationErrorV1::Service);
        }
        self.final_settlement = Some((|| {
            self.current
                .as_mut()
                .ok_or(RootObservationErrorV1::Service)?
                .settle_after_root_post_once_v1()?;
            self.admission
                .settle_final_positive_once_v2()
                .map_err(|_| RootObservationErrorV1::Service)
        })());
        self.complete =
            matches!(self.final_settlement, Some(Ok(()))) && self.failure_v2().is_none();
        positive(&self.final_settlement)
    }

    /// Borrows the actual admission/capture cause before its owed after post.
    #[must_use]
    pub fn capture_failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.admission
            .admission_failure_v2()
            .or_else(|| error(&self.shape))
            .or_else(|| error(&self.funding))
            .or_else(|| self.admission.post_failure_v2(Post::AdmissionBefore))
            .or_else(|| error(&self.posts[0]))
            .or_else(|| self.peer.as_ref().and_then(Peer::failure))
            .or_else(|| error(&self.capture))
    }

    /// Borrows the actual initial admission/peer/post first cause.
    #[must_use]
    pub fn primary_failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.capture_failure_v2()
            .or_else(|| self.admission.post_failure_v2(Post::AdmissionAfter))
            .or_else(|| error(&self.posts[1]))
            .or_else(|| error(&self.initial_settlement))
    }

    /// Borrows the selected actual already-armed post's retained cause.
    #[must_use]
    pub fn post_failure_v2(&self, post: Post) -> Option<&(dyn Error + 'static)> {
        self.admission.post_failure_v2(post)
    }

    /// Borrows the actual final current sample and its original returned cause.
    #[must_use]
    pub fn current_failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.current
            .as_ref()
            .and_then(Current::failure)
            .or_else(|| error(&self.current_result))
    }

    /// Borrows only the original positive retirement's returned cause.
    #[must_use]
    pub fn final_settlement_failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.final_settlement)
    }

    /// Borrows the retained first native, continuation or final-post cause.
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.primary_failure_v2()
            .or_else(|| self.admission.stages.failure())
            .or_else(|| self.admission.post_failure_v2(Post::FinalBefore))
            .or_else(|| error(&self.posts[2]))
            .or_else(|| self.current.as_ref().and_then(Current::failure))
            .or_else(|| error(&self.current_result))
            .or_else(|| self.admission.post_failure_v2(Post::FinalAfter))
            .or_else(|| error(&self.posts[3]))
            .or_else(|| error(&self.final_settlement))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

impl Drop for RootNoApplyControllerPeerOriginalV2<'_> {
    fn drop(&mut self) {
        if !self.complete {
            // Preserve the same whole failed or unfinished native purpose
            // before any retained post, peer, flight or financial field drops.
            std::process::abort();
        }
    }
}

fn positive(
    value: &Option<Result<(), RootObservationErrorV1>>,
) -> Result<(), RootObservationErrorV1> {
    if matches!(value, Some(Ok(()))) {
        Ok(())
    } else {
        Err(RootObservationErrorV1::Service)
    }
}

fn error<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}
