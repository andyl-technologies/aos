//! Posts each paid selected Q04 current crossing without resetting its origin.
//!
//! The original service sampler keeps its own traffic debit. The distinct
//! Controller sample, paired clocks and independent Root post are priced here
//! before construction and stay resident until the whole Q04 flight retires.

use std::any::Any;
use std::error::Error;
use std::sync::Arc;
use std::time::Instant;

use aos_sandbox_core::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::unix_stream::{RetainedUnixStream, UnixStreamSubjectChunk};

use crate::kernel_clock::RetainedKernelPairedClockAttemptV1;
use crate::receiving::{
    ObservationLifetimeV1, RootSelectedControllerCurrentSampleV1,
    RootSelectedControllerPeerOriginalV1, RootSelectedControllerSubjectSampleV1,
    RootSelectedCurrentnessFailureOriginalV1, RootServiceCurrentnessOriginalV1,
    RootStartupNativeOriginalV1,
};

use super::super::super::root_permanent::RootPermanentNativeOriginalV1;
use super::{ClockError, MAXIMUM_FLIGHT, RootObservationErrorV1 as Closed, cause, positive};

pub(super) struct Q04CurrentCrossingV1 {
    startup: Option<Result<(), Closed>>,
    startup_cause: Option<RootSelectedCurrentnessFailureOriginalV1>,
    controller: Q04ControllerObservationV1,
    controller_return: Option<Result<(), Closed>>,
    queue: Option<std::io::Result<()>>,
    clock: RetainedKernelPairedClockAttemptV1<ClockError>,
    current: Option<Result<RawPairedClockSample, ClockError>>,
    primary: Option<Closed>,
    body_panic: Option<Box<dyn Any + Send>>,
    root_post: RootServiceCurrentnessOriginalV1,
    root_post_result: Option<Result<(), Closed>>,
    post_clock: RetainedKernelPairedClockAttemptV1<ClockError>,
    post_sample: Option<Result<RawPairedClockSample, ClockError>>,
    interval: Option<Result<(), Closed>>,
    settlement: Option<Result<(), Closed>>,
    post_panic: Option<Box<dyn Any + Send>>,
    clock_panic: Option<Box<dyn Any + Send>>,
}

enum Q04ControllerObservationV1 {
    Current(RootSelectedControllerCurrentSampleV1),
    Subject(RootSelectedControllerSubjectSampleV1),
}

impl Q04ControllerObservationV1 {
    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Current(sample) => sample.failure(),
            Self::Subject(sample) => sample.failure(),
        }
    }

    fn settle_once_v1(&mut self) -> Result<(), Closed> {
        match self {
            Self::Current(sample) => sample.settle_after_root_post_once_v1(),
            Self::Subject(sample) => sample.require_complete_v1(),
        }
    }
}

impl Q04CurrentCrossingV1 {
    pub(super) fn new(lifetime: ObservationLifetimeV1, subject: bool) -> Self {
        let controller = if subject {
            Q04ControllerObservationV1::Subject(RootSelectedControllerSubjectSampleV1::default())
        } else {
            Q04ControllerObservationV1::Current(RootSelectedControllerCurrentSampleV1::new(
                lifetime,
            ))
        };
        Self {
            startup: None,
            startup_cause: None,
            controller,
            controller_return: None,
            queue: None,
            clock: Default::default(),
            current: None,
            primary: None,
            body_panic: None,
            root_post: RootServiceCurrentnessOriginalV1::new(),
            root_post_result: None,
            post_clock: Default::default(),
            post_sample: None,
            interval: None,
            settlement: None,
            post_panic: None,
            clock_panic: None,
        }
    }

    pub(super) fn demand_v1(resident_count: usize, subject: bool) -> Option<ResourceVector> {
        let controller = if subject {
            RootSelectedControllerSubjectSampleV1::demand_v1().ok()?
        } else {
            RootSelectedControllerCurrentSampleV1::demand_v1().ok()?
        };
        let clock =
            RetainedKernelPairedClockAttemptV1::<ClockError>::dominant_requested_bytes_v1()?;
        // Preserve the already paid old Vec while its possible replacement
        // allocation and the next constructor/result are simultaneously live.
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(resident_count.checked_add(3)?)?
            .checked_add(std::mem::size_of::<Result<(), Closed>>().checked_mul(18)?)?
            .checked_add(
                std::mem::size_of::<Result<RawPairedClockSample, Closed>>().checked_mul(6)?,
            )?
            .checked_add(
                std::mem::size_of::<Result<Result<(), Closed>, Box<dyn Any + Send>>>()
                    .checked_mul(9)?,
            )?
            .checked_add(clock.checked_mul(2)?)?;
        ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(
                D::OpenFiles,
                2 * RetainedKernelPairedClockAttemptV1::<ClockError>::MAXIMUM_RETAINED_FILES_V1
                    as u64,
            )
            .checked_add(controller)
            .ok()?
            .checked_add(RootServiceCurrentnessOriginalV1::demand()?)
            .ok()
    }

    pub(super) fn observe_once_v1(
        &mut self,
        startup: &RootStartupNativeOriginalV1,
        permanent: &Arc<RootPermanentNativeOriginalV1>,
        peer: &RootSelectedControllerPeerOriginalV1<'_>,
        stream: &RetainedUnixStream,
        original: RawPairedClockSample,
        started: Instant,
        chunk: Option<&UnixStreamSubjectChunk>,
    ) -> Result<RawPairedClockSample, Closed> {
        let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.observe_startup_prefix_v1(startup)?;
            let _invocation = permanent.enter_native()?;
            self.observe_controller_prefix_v1(peer, stream, chunk)?;
            self.observe_original_clock_v1(original, started)
        }));
        self.park_body_return_v1(body);
        self.finish_native_posts_v1(startup, permanent, original, started)
    }

    fn observe_startup_prefix_v1(
        &mut self,
        startup: &RootStartupNativeOriginalV1,
    ) -> Result<(), Closed> {
        self.startup = Some(
            startup
                .borrow_selected_startup_v1()
                .and_then(|startup| startup.recheck_v1()),
        );
        if self.startup.as_ref().is_some_and(Result::is_err) {
            self.startup_cause = startup.selected_currentness_failure_original_v1();
        }
        positive(&self.startup)?;
        Ok(())
    }

    fn observe_controller_prefix_v1(
        &mut self,
        peer: &RootSelectedControllerPeerOriginalV1<'_>,
        stream: &RetainedUnixStream,
        chunk: Option<&UnixStreamSubjectChunk>,
    ) -> Result<(), Closed> {
        self.controller_return = Some(match (&mut self.controller, chunk) {
            (Q04ControllerObservationV1::Current(sample), None) => {
                peer.observe_prearmed_current_into_v1(stream, sample)
            }
            (Q04ControllerObservationV1::Subject(sample), Some(chunk)) => {
                sample.capture_once(peer, stream, chunk)
            }
            _ => Err(Closed::Service),
        });
        positive(&self.controller_return)?;
        self.queue = Some(require_open_queue(stream));
        positive(&self.queue)?;
        Ok(())
    }

    fn observe_original_clock_v1(
        &mut self,
        original: RawPairedClockSample,
        started: Instant,
    ) -> Result<(), Closed> {
        super::original_clock::observe_original_clock_v1(
            &mut self.clock,
            &mut self.current,
            original,
            started,
        )
    }

    fn park_body_return_v1(&mut self, body: Result<Result<(), Closed>, Box<dyn Any + Send>>) {
        match body {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                self.primary.get_or_insert(error);
            }
            Err(payload) => {
                self.body_panic = Some(payload);
            }
        }
    }

    pub(super) fn observe_input_prefix_once_v1(
        &mut self,
        startup: &RootStartupNativeOriginalV1,
        permanent: &Arc<RootPermanentNativeOriginalV1>,
        peer: &RootSelectedControllerPeerOriginalV1<'_>,
        stream: &RetainedUnixStream,
    ) -> Result<(), Closed> {
        let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.observe_startup_prefix_v1(startup)?;
            let _invocation = permanent.enter_native()?;
            self.observe_controller_prefix_v1(peer, stream, None)
        }));
        self.park_body_return_v1(body);
        if self.primary.is_none() && self.body_panic.is_none() {
            Ok(())
        } else {
            Err(Closed::Service)
        }
    }

    pub(super) fn finish_input_prefix_once_v1(
        &mut self,
        startup: &RootStartupNativeOriginalV1,
        permanent: &Arc<RootPermanentNativeOriginalV1>,
        original: RawPairedClockSample,
        started: Instant,
        refused: bool,
    ) -> Result<RawPairedClockSample, Closed> {
        if refused {
            self.primary.get_or_insert(Closed::Service);
        }
        if self.primary.is_none() && self.body_panic.is_none() {
            let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _invocation = permanent.enter_native()?;
                self.observe_original_clock_v1(original, started)
            }));
            self.park_body_return_v1(body);
        }
        self.finish_native_posts_v1(startup, permanent, original, started)
    }

    fn finish_native_posts_v1(
        &mut self,
        startup: &RootStartupNativeOriginalV1,
        permanent: &Arc<RootPermanentNativeOriginalV1>,
        original: RawPairedClockSample,
        started: Instant,
    ) -> Result<RawPairedClockSample, Closed> {
        // Each owed attempt has its own unwind frontier. A Root post panic
        // cannot suppress the separately paid final original-clock sample.
        let root_post = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.root_post_result = Some((|| {
                let enrollment = permanent
                    .enrollment()
                    .enrollment_v1()
                    .ok_or(Closed::Service)?;
                let mut invocation = permanent.enter_observation()?;
                self.root_post.observe_once(
                    startup,
                    permanent.service.kernel(),
                    enrollment.recipient_invocation,
                    enrollment.identity.native_fields().invocation,
                );
                if self.root_post.is_positive() {
                    Ok(())
                } else {
                    invocation.refuse();
                    Err(Closed::Service)
                }
            })());
        }));
        if let Err(payload) = root_post {
            self.post_panic = Some(payload);
        }
        let clock_post = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _invocation = permanent.enter_observation()?;
            self.post_sample = Some(self.post_clock.observe_once(Some(original)));
            self.interval = Some(
                if self.post_sample.as_ref().is_some_and(Result::is_ok)
                    && started.elapsed() < MAXIMUM_FLIGHT
                {
                    Ok(())
                } else {
                    Err(Closed::Service)
                },
            );
            Ok::<(), Closed>(())
        }));
        match clock_post {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                self.interval = Some(Err(error));
            }
            Err(payload) => {
                self.clock_panic = Some(payload);
            }
        }
        if self.failure().is_some()
            || self.body_panic.is_some()
            || self.post_panic.is_some()
            || self.clock_panic.is_some()
        {
            return Err(Closed::Service);
        }
        self.settlement = Some(self.controller.settle_once_v1());
        if self.is_complete_v1() {
            positive(&self.post_sample).copied()
        } else {
            Err(Closed::Service)
        }
    }

    pub(super) fn is_complete_v1(&self) -> bool {
        self.failure().is_none()
            && self.body_panic.is_none()
            && self.post_panic.is_none()
            && self.clock_panic.is_none()
            && matches!(self.settlement, Some(Ok(())))
            && matches!(self.interval, Some(Ok(())))
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.startup_cause
            .as_ref()
            .map(|cause| cause as _)
            .or_else(|| cause(&self.startup))
            .or_else(|| self.controller.failure())
            .or_else(|| cause(&self.controller_return))
            .or_else(|| cause(&self.queue))
            .or_else(|| self.clock.failure())
            .or_else(|| cause(&self.current))
            .or_else(|| self.primary.as_ref().map(|error| error as _))
            .or_else(|| self.root_post.failure())
            .or_else(|| cause(&self.root_post_result))
            .or_else(|| self.post_clock.failure())
            .or_else(|| cause(&self.post_sample))
            .or_else(|| cause(&self.interval))
            .or_else(|| cause(&self.settlement))
    }
}

// Same original Root queue predicate; this observation supplies no role grant.
fn require_open_queue(stream: &RetainedUnixStream) -> std::io::Result<()> {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    let descriptor = stream.as_fd();
    let mut descriptors = [PollFd::new(&descriptor, PollFlags::RDHUP)];
    poll(
        &mut descriptors,
        Some(&Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }),
    )?;
    if descriptors[0]
        .revents()
        .intersects(PollFlags::RDHUP | PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "original Q04 queue ended",
        ));
    }
    Ok(())
}
