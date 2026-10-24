//! Retains one strict Initial subject chunk through both independent posts.
//!
//! A frame loan borrows the genuine Ready buffer, owned accepted originals and
//! the original completed Open. It exposes finite stages, never the mutable raw
//! reader. Upper lexical scheduling releases real Initial/L before each native
//! observation. Only the full positive conjunction disposes native custody.

use std::error::Error;

use aos_sandbox_broker::kernel_clock::RetainedKernelPairedClockAttemptV1;
use aos_sandbox_broker::receiving::{
    RootInitialReceivingOriginalV1, RootObservationErrorV1,
    RootSelectedControllerSubjectSampleV1, RootSelectedStartupBorrowV1,
    RootSubjectReadinessV1, RootUpperMutationGuardV1,
};
use aos_sandbox_model::RawPairedClockSample;
use aos_sandbox_linux::unix_stream::{
    RetainedSubjectStreamReadV1, SubjectStreamReadErrorV1, SubjectStreamReceiveGeometryV1,
};

use super::history_post::RootCurrentHistoryPostOriginalV1;
use super::initial_open::{
    RootInitialClockErrorV1, RootInitialOpenErrorV1 as E,
    RootInitialOpenPreparedOriginalV1,
};
use super::owned::RootCurrentAcceptedOriginalsV1;
use super::initial_source_exchange::RootInitialSourceExchangeOriginalV1;

pub(super) struct RootInitialSubjectOriginalV1 {
    before_history: Option<RootCurrentHistoryPostOriginalV1>,
    before_arm: Option<Result<(), RootObservationErrorV1>>,
    before: Option<Result<(), RootObservationErrorV1>>,
    readiness: RootSubjectReadinessV1,
    received: Option<Result<(), SubjectStreamReadErrorV1>>,
    subject: Option<RootSelectedControllerSubjectSampleV1>,
    binding: Option<Result<(), RootObservationErrorV1>>,
    copied: Option<Result<(), SubjectStreamReadErrorV1>>,
    after_history: Option<RootCurrentHistoryPostOriginalV1>,
    after_arm: Option<Result<(), RootObservationErrorV1>>,
    after: Option<Result<(), RootObservationErrorV1>>,
    clock_original: Option<RetainedKernelPairedClockAttemptV1<RootInitialClockErrorV1>>,
    clock: Option<Result<RawPairedClockSample, RootInitialClockErrorV1>>,
    cutoff: Option<Result<(), E>>,
    reached: u64,
    closed: bool,
}

impl RootInitialSubjectOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            before_history: None,
            before_arm: None,
            before: None,
            readiness: RootSubjectReadinessV1::default(),
            received: None,
            subject: None,
            binding: None,
            copied: None,
            after_history: None,
            after_arm: None,
            after: None,
            clock_original: None,
            clock: None,
            cutoff: None,
            reached: 0,
            closed: false,
        }
    }

    fn require_empty_v1(&self) -> Result<(), E> {
        if self.closed || self.before_history.is_some() || self.before_arm.is_some()
            || self.before.is_some() || self.readiness.entered() || self.received.is_some()
            || self.subject.is_some() || self.binding.is_some() || self.copied.is_some()
            || self.after_history.is_some() || self.after_arm.is_some() || self.after.is_some()
            || self.clock_original.is_some() || self.clock.is_some() || self.cutoff.is_some()
        {
            return Err(E::Boundary);
        }
        Ok(())
    }

    pub(super) fn disposed_v1(&self) -> bool {
        self.reached != 0 && self.require_empty_v1().is_ok()
    }

    pub(super) fn borrow_frame_v1<'cut, 'startup>(
        &'cut mut self,
        buffer: &'cut mut RetainedSubjectStreamReadV1,
        originals: &'cut mut RootCurrentAcceptedOriginalsV1<'startup>,
        open: &'cut RootInitialOpenPreparedOriginalV1,
        geometry: SubjectStreamReceiveGeometryV1,
    ) -> Result<RootInitialSubjectFrameBorrowV1<'cut, 'startup>, E> {
        let bound_cutoff = open.body_v1()?.cutoff;
        Ok(RootInitialSubjectFrameBorrowV1 {
            state: self,
            buffer,
            originals,
            open,
            geometry,
            bound_cutoff,
        })
    }

    // Only the actual completed Source owner supplies this shorter interval.
    // The scalar never enters through the public mechanical frame API.
    pub(super) fn borrow_source_frame_v1<'cut, 'startup>(
        &'cut mut self,
        buffer: &'cut mut RetainedSubjectStreamReadV1,
        originals: &'cut mut RootCurrentAcceptedOriginalsV1<'startup>,
        open: &'cut RootInitialOpenPreparedOriginalV1,
        source: &RootInitialSourceExchangeOriginalV1,
        geometry: SubjectStreamReceiveGeometryV1,
    ) -> Result<RootInitialSubjectFrameBorrowV1<'cut, 'startup>, E> {
        open.body_v1()?;
        let bound_cutoff = source.original_cutoff_v1().map_err(|_| E::Boundary)?;
        Ok(RootInitialSubjectFrameBorrowV1 {
            state: self,
            buffer,
            originals,
            open,
            geometry,
            bound_cutoff,
        })
    }

    pub(super) fn failure_v1<'a>(
        &'a self,
        buffer: &'a RetainedSubjectStreamReadV1,
    ) -> Option<&'a (dyn Error + 'static)> {
        self.before_history.as_ref().and_then(RootCurrentHistoryPostOriginalV1::failure_v1)
            .or_else(|| cause(&self.before_arm))
            .or_else(|| cause(&self.before))
            .or_else(|| self.readiness.failure())
            .or_else(|| retained_cause(&self.received, buffer))
            .or_else(|| self.subject.as_ref().and_then(|subject| subject.failure()))
            .or_else(|| cause(&self.binding))
            .or_else(|| retained_cause(&self.copied, buffer))
            .or_else(|| self.after_history.as_ref().and_then(RootCurrentHistoryPostOriginalV1::failure_v1))
            .or_else(|| cause(&self.after_arm))
            .or_else(|| cause(&self.after))
            .or_else(|| self.clock_original.as_ref().and_then(|clock| clock.failure()))
            .or_else(|| cause(&self.clock))
            .or_else(|| cause(&self.cutoff))
    }
}

/// Borrows the actual native Ready frame and its unchanged accepted originals.
///
/// This finite mechanical loan has no public constructor or mutable reader
/// accessor. It cannot receive a caller-supplied completion result. Each arm
/// rejoins the same Initial briefly; native observations run after L is released.
pub struct RootInitialSubjectFrameBorrowV1<'cut, 'startup> {
    state: &'cut mut RootInitialSubjectOriginalV1,
    buffer: &'cut mut RetainedSubjectStreamReadV1,
    originals: &'cut mut RootCurrentAcceptedOriginalsV1<'startup>,
    open: &'cut RootInitialOpenPreparedOriginalV1,
    geometry: SubjectStreamReceiveGeometryV1,
    bound_cutoff: u64,
}

impl RootInitialSubjectFrameBorrowV1<'_, '_> {
    /// Borrows the exact first reached cause on this same native frame.
    ///
    /// The upper adapter can retain its classification before attempting a
    /// later after-arm exclusion. This performs no observation or completion.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.state.failure_v1(self.buffer)
    }

    /// Reports whether this same prepared frame has received its exact extent.
    #[must_use]
    pub fn completed_exact_v1(&self) -> bool {
        self.buffer.completed_exact()
    }

    /// Requires the previous native sample's actual positive disposal.
    ///
    /// # Errors
    /// Refuses retained failed custody, repeated entry or an incomplete step.
    pub fn require_empty_once_v1(&self) -> Result<(), E> {
        self.state.require_empty_v1()
    }

    /// Arms the actual before history obligation under the original real L.
    ///
    /// # Errors
    /// Retains same-Initial, Stage, service-arm or traffic refusal before receive.
    pub fn arm_before_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        if self.state.require_empty_v1().is_err() || self.buffer.completed_exact() {
            self.state.closed = true;
            return Err(RootObservationErrorV1::Service);
        }
        self.state.before_arm = Some(match self.originals.peer.borrow_current_writers_predecessor_v1(initial) {
            Ok(predecessor) => {
                self.state.before_history = Some(RootCurrentHistoryPostOriginalV1::arm_once_v1(
                    predecessor, startup, exclusion,
                ));
                self.state.before_history.as_ref().ok_or(RootObservationErrorV1::Service)?
                    .require_armed_v1()
            }
            Err(error) => Err(error),
        });
        match &self.state.before_arm {
            Some(Ok(())) => Ok(()),
            _ => Err(RootObservationErrorV1::Service),
        }
    }

    /// Observes the actual before programme outside the upper exclusion.
    ///
    /// # Errors
    /// Refuses an unarmed or negative real programme before any native receive.
    pub fn observe_before_once_v1(&mut self) -> Result<(), E> {
        if self.state.before.is_some() {
            self.state.closed = true;
            return Err(E::Boundary);
        }
        positive(&self.state.before_arm)?;
        self.state.before = Some(observe_history(
            self.state.before_history.as_mut(), self.originals,
        ));
        positive(&self.state.before)?;
        // Old Create recheck drops its positive whole post before readiness.
        drop(self.state.before_history.take());
        Ok(())
    }

    /// Polls and receives once from the same strict retained stream.
    ///
    /// A negative read remains resident and does not suppress the owed after.
    pub fn poll_receive_once_v1(&mut self) {
        if self.state.received.is_some() || self.state.subject.is_some()
            || self.state.readiness.entered() || !matches!(self.state.before, Some(Ok(())))
        {
            self.state.closed = true;
            return;
        }
        let cutoff = match self.open.body_v1() {
            Ok(_) => self.bound_cutoff,
            Err(_) => {
                self.state.closed = true;
                return;
            }
        };
        if matches!(self.state.before, Some(Ok(())))
            && self.state.readiness.wait_retained_once_v1(&self.originals.stream, cutoff)
        {
            self.state.received = Some(self.buffer.receive_next_with_geometry_once(
                &mut self.originals.stream, &self.geometry,
            ));
            self.state.subject = Some(RootSelectedControllerSubjectSampleV1::default());
        }
    }

    /// Binds the actual nominated subject before copying its pending payload.
    ///
    /// # Errors
    /// Refuses repeated binding; reached native refusals remain on their owners.
    pub fn observe_subject_copy_once_v1(&mut self) -> Result<(), E> {
        if self.state.binding.is_some() || self.state.copied.is_some()
            || !self.state.readiness.entered() || self.state.after_arm.is_some()
        {
            self.state.closed = true;
            return Err(E::Boundary);
        }
        if matches!(self.state.received, Some(Ok(()))) {
            let sample = self.state.subject.as_mut().ok_or(E::Boundary)?;
            self.state.binding = Some(match self.originals.peer.native_peer_original_v1() {
                Ok(peer) => match self.buffer.pending_chunk() {
                    Ok(chunk) => sample.capture_once(peer, &self.originals.stream, chunk),
                    Err(_) => Err(RootObservationErrorV1::Service),
                },
                Err(error) => Err(error),
            });
            if matches!(self.state.binding, Some(Ok(()))) {
                self.state.copied = Some(self.buffer.append_pending_payload_once());
            }
        }
        Ok(())
    }

    /// Arms the independently owed after under the same actual Initial/L.
    ///
    /// This retains refusal without returning early from the owed clock path.
    pub fn arm_after_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) {
        if self.state.after_arm.is_some() || self.state.after.is_some()
            || !matches!(self.state.before, Some(Ok(())))
            || !self.state.readiness.entered()
            || (matches!(self.state.received, Some(Ok(()))) && self.state.binding.is_none())
            || (matches!(self.state.binding, Some(Ok(()))) && self.state.copied.is_none())
        {
            self.state.closed = true;
            initial.latch_root_refusal_v1();
            return;
        }
        self.state.after_arm = Some(match self.originals.peer.borrow_current_writers_predecessor_v1(initial) {
            Ok(predecessor) => {
                self.state.after_history = Some(RootCurrentHistoryPostOriginalV1::arm_once_v1(
                    predecessor, startup, exclusion,
                ));
                match &self.state.after_history {
                    Some(history) => history.require_armed_v1(),
                    None => Err(RootObservationErrorV1::Service),
                }
            }
            Err(error) => Err(error),
        });
        if !matches!(self.state.after_arm, Some(Ok(()))) {
            initial.latch_root_refusal_v1();
        }
    }

    /// Records inability to reacquire the actual upper after-arm exclusion.
    ///
    /// The upper owner retains that original lock error at its old frontier.
    /// This nonissuing marker performs no observation or arm, cannot complete
    /// the frame, and leaves the independently owed late clock reachable.
    pub fn refuse_after_arm_once_v1(&mut self) {
        self.state.closed = true;
        if self.state.after_arm.is_none() && self.state.after.is_none()
            && matches!(self.state.before, Some(Ok(())))
            && self.state.readiness.entered()
        {
            self.state.after_arm = Some(Err(RootObservationErrorV1::Service));
            self.state.after = Some(Err(RootObservationErrorV1::Service));
        }
    }

    /// Observes the independent after despite any native, subject or copy error.
    pub fn observe_after_once_v1(&mut self) {
        if self.state.after.is_some() || self.state.after_arm.is_none() || self.state.clock.is_some() {
            self.state.closed = true;
            return;
        }
        self.state.after = Some(match &self.state.after_arm {
            Some(Ok(())) => observe_history(self.state.after_history.as_mut(), self.originals),
            _ => Err(RootObservationErrorV1::Service),
        });
        if matches!(self.state.after, Some(Ok(()))) {
            // Old positive recheck disposal precedes the distinct late clock.
            drop(self.state.after_history.take());
        }
    }

    /// Observes the distinct late pair and checks the same immutable Open clock.
    pub fn observe_clock_once_v1(&mut self) {
        if self.state.clock_original.is_some() || self.state.clock.is_some()
            || self.state.cutoff.is_some() || self.state.after.is_none()
        {
            self.state.closed = true;
            return;
        }
        self.state.clock_original = Some(RetainedKernelPairedClockAttemptV1::default());
        self.state.clock = Some(match &mut self.state.clock_original {
            Some(clock) => clock.observe_once(None),
            None => {
                self.state.closed = true;
                return;
            }
        });
        self.state.cutoff = Some(self.require_clock_v1());
    }

    fn require_clock_v1(&self) -> Result<(), E> {
        let current = *positive(&self.state.clock)?;
        let body = self.open.body_v1()?;
        self.open.clock_original_v1().require_current_v1(current, body.cutoff)?;
        if current.boottime_nanoseconds() >= self.bound_cutoff {
            return Err(E::Boundary);
        }
        Ok(())
    }

    /// Requires every reached original before, native, copy, after and clock.
    ///
    /// # Errors
    /// Refuses any absent, failed, repeated or still-unreturned stage.
    pub fn require_positive_once_v1(&self) -> Result<(), E> {
        if self.state.closed || !self.state.readiness.positive() {
            return Err(E::Boundary);
        }
        positive(&self.state.before_arm)?;
        positive(&self.state.before)?;
        positive(&self.state.received)?;
        positive(&self.state.binding)?;
        positive(&self.state.copied)?;
        positive(&self.state.after_arm)?;
        positive(&self.state.after)?;
        positive(&self.state.cutoff).map(|_| ())
    }

    /// Disposes only this fully positive sample before the next native receive.
    ///
    /// # Errors
    /// Leaves failed native custody resident and refuses counter exhaustion.
    pub fn dispose_positive_once_v1(&mut self) -> Result<(), E> {
        self.require_positive_once_v1()?;
        self.state.reached = self.state.reached.checked_add(1).ok_or(E::Boundary)?;
        let chunk = self.buffer.take_copied_chunk_once().map_err(|_| E::Boundary)?;
        drop(chunk);
        drop(self.state.subject.take());
        self.state.before_arm = None;
        self.state.before = None;
        self.state.readiness = RootSubjectReadinessV1::default();
        self.state.received = None;
        self.state.binding = None;
        self.state.copied = None;
        self.state.after_arm = None;
        self.state.after = None;
        self.state.clock_original = None;
        self.state.clock = None;
        self.state.cutoff = None;
        Ok(())
    }
}

fn observe_history(
    history: Option<&mut RootCurrentHistoryPostOriginalV1>,
    originals: &RootCurrentAcceptedOriginalsV1<'_>,
) -> Result<(), RootObservationErrorV1> {
    let history = history.ok_or(RootObservationErrorV1::Service)?;
    let mut accepted = history.borrow_accepted_v1(&originals.peer, &originals.stream)?;
    accepted.observe_shared_once_v1()
}

fn positive<T, F>(slot: &Option<Result<T, F>>) -> Result<&T, E> {
    slot.as_ref().and_then(|result| result.as_ref().ok()).ok_or(E::Boundary)
}

fn cause<T, F: Error + 'static>(slot: &Option<Result<T, F>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}

fn retained_cause<'a>(
    slot: &'a Option<Result<(), SubjectStreamReadErrorV1>>,
    buffer: &'a RetainedSubjectStreamReadV1,
) -> Option<&'a (dyn Error + 'static)> {
    if matches!(slot, Some(Err(SubjectStreamReadErrorV1::Retained))) {
        buffer.failure().or_else(|| cause(slot))
    } else {
        cause(slot)
    }
}
