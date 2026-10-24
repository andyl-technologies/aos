//! Keeps Q04 on its consumed selected Root flight and original native interval.
//!
//! Only real Initial custody binds this inert owner to Permanent. The accepted
//! stream is parked before the first Q04 clock; admission retains failed native
//! prefixes and independently posts the prearmed Root sample. No role journal,
//! policy verifier, current floor or Authority grant is constructed here.

use std::any::Any;
use std::error::Error;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_linux_descriptors::unix_stream::RetainedUnixStream;
use aos_linux_descriptors::unix_stream::RetainedUnixStreamAdmissionOriginalV1;
use aos_sandbox_linux::unix_stream::UnixStreamSubjectChunk;

use crate::kernel_clock::{KernelPairedClockErrorV1, RetainedKernelPairedClockAttemptV1};
use crate::receiving::{
    ObservationLifetimeV1, RootObservationErrorV1, RootSelectedControllerPeerOriginalV1,
    RootServiceCurrentnessOriginalV1, RootStartupNativeOriginalV1,
};

use super::super::root_permanent::RootPermanentNativeOriginalV1;
use super::{RootInitialReceivingOriginalV1, RootJournalFinancialOriginalV1};

mod crossing;
mod input_current;
mod original_clock;
use crossing::Q04CurrentCrossingV1;
pub use input_current::RootQ04InputCurrentLoanV1;

const MAXIMUM_FLIGHT: Duration = Duration::from_secs(65);

/// Borrows this actual Q04 endpoint while its permanent native fence is held.
///
/// Only the armed original constructs this loan. Actual callers end the borrow
/// before financial, role or currentness reentry; no callback is invoked here.
pub struct RootQ04NativeStreamLoanV1<'native> {
    _invocation: super::super::root_invocation::RootNativeInvocationGuardV1<'native>,
    stream: &'native mut RetainedUnixStream,
}

impl RootQ04NativeStreamLoanV1<'_> {
    /// Borrows the same original endpoint under the still-held native guard.
    #[must_use]
    pub fn stream_v1(&self) -> &RetainedUnixStream {
        self.stream
    }

    /// Borrows the same original subject receiver under the native guard.
    #[must_use]
    pub fn stream_mut_v1(&mut self) -> &mut RetainedUnixStream {
        self.stream
    }
}

#[derive(Debug, thiserror::Error)]
enum ClockError {
    #[error("the original Q04 kernel interval is unavailable")]
    Stale,
    #[error(transparent)]
    Kernel(#[from] aos_linux_descriptors::Error),
}

impl KernelPairedClockErrorV1 for ClockError {
    fn stale() -> Self {
        Self::Stale
    }

    fn kernel(error: aos_linux_descriptors::Error) -> Self {
        Self::Kernel(error)
    }
}

/// Retains one actual selected Q04 transport without granting a semantic role.
///
/// Construction is inert. Initial alone associates the destination with its
/// same consumed flight before admission can observe a clock or adopt a stream.
/// An entered unretired owner aborts before native custody can be released.
pub struct RootQ04TransportOriginalV1<'startup> {
    startup: &'startup RootStartupNativeOriginalV1,
    financial: Option<RootJournalFinancialOriginalV1>,
    lifetime: Option<ObservationLifetimeV1>,
    arm: Option<Result<(), RootObservationErrorV1>>,
    original: Option<UnixStream>,
    request: Option<[u8; 32]>,
    started: Option<Instant>,
    clock: RetainedKernelPairedClockAttemptV1<ClockError>,
    original_pair: Option<Result<RawPairedClockSample, ClockError>>,
    startup_before: Option<Result<(), RootObservationErrorV1>>,
    startup_cause: Option<crate::receiving::RootSelectedCurrentnessFailureOriginalV1>,
    duplicate: Option<Result<OwnedFd, rustix::io::Errno>>,
    adoption: Option<RetainedUnixStreamAdmissionOriginalV1>,
    adoption_result: Option<Result<(), RootObservationErrorV1>>,
    admission_post: Option<Result<(), RootObservationErrorV1>>,
    admission_post_panic: Option<Box<dyn Any + Send>>,
    stream: Option<RetainedUnixStream>,
    endpoint: Option<Result<(), aos_linux_descriptors::Error>>,
    subject_reporting: Option<Result<(), aos_sandbox_linux::seqpacket::SeqpacketError>>,
    qualifier: Option<RootSelectedControllerPeerOriginalV1<'startup>>,
    qualification: Option<Result<(), RootObservationErrorV1>>,
    root_post: RootServiceCurrentnessOriginalV1,
    root_post_entered: bool,
    root_post_result: Option<Result<(), RootObservationErrorV1>>,
    post_clock: RetainedKernelPairedClockAttemptV1<ClockError>,
    post_pair: Option<Result<RawPairedClockSample, ClockError>>,
    settlement: Option<Result<(), RootObservationErrorV1>>,
    primary: Option<RootObservationErrorV1>,
    admission_panic: Option<Box<dyn Any + Send>>,
    post_panic: Option<Box<dyn Any + Send>>,
    clock_panic: Option<Box<dyn Any + Send>>,
    entered: bool,
    authority_claimed: bool,
    retired: bool,
    closed: Option<RootObservationErrorV1>,
    crossings: Vec<Q04CurrentCrossingV1>,
    original_clocks: Vec<original_clock::OriginalClockV1>,
    input_prefix_pending: bool,
    crossing_reservation: Option<std::collections::TryReserveError>,
    crossing_funding: Option<super::RootFinancialClosedV1>,
}

impl<'startup> RootQ04TransportOriginalV1<'startup> {
    /// Creates vacant destinations without IO, allocation or role admission.
    #[must_use]
    pub fn new(startup: &'startup RootStartupNativeOriginalV1) -> Self {
        Self {
            startup,
            financial: None,
            lifetime: None,
            arm: None,
            original: None,
            request: None,
            started: None,
            clock: Default::default(),
            original_pair: None,
            startup_before: None,
            startup_cause: None,
            duplicate: None,
            adoption: None,
            adoption_result: None,
            admission_post: None,
            admission_post_panic: None,
            stream: None,
            endpoint: None,
            subject_reporting: None,
            qualifier: None,
            qualification: None,
            root_post: RootServiceCurrentnessOriginalV1::new(),
            root_post_entered: false,
            root_post_result: None,
            settlement: None,
            primary: None,
            post_clock: Default::default(),
            post_pair: None,
            admission_panic: None,
            post_panic: None,
            clock_panic: None,
            entered: false,
            authority_claimed: false,
            retired: false,
            closed: None,
            crossings: Vec::new(),
            original_clocks: Vec::new(),
            input_prefix_pending: false,
            crossing_reservation: None,
            crossing_funding: None,
        }
    }

    /// Prices the actual native origin, qualifier, failed prefix and owed post.
    ///
    /// The upper work/control and protocol vectors remain separately required.
    #[must_use]
    pub fn fixed_demand_v1() -> Option<ResourceVector> {
        let (admission, descriptors) =
            RetainedUnixStreamAdmissionOriginalV1::receiving_obligations_v1()?;
        let clock =
            RetainedKernelPairedClockAttemptV1::<ClockError>::dominant_requested_bytes_v1()?;
        let bytes =
            std::mem::size_of::<Self>()
                .checked_mul(3)?
                .checked_add(
                    std::mem::size_of::<Result<(), RootObservationErrorV1>>().checked_mul(4)?,
                )?
                .checked_add(std::mem::size_of::<Box<Self>>().checked_mul(3)?)?
                .checked_add(
                    std::mem::size_of::<Result<[u32; 4], RootObservationErrorV1>>()
                        .checked_mul(3)?,
                )?
                .checked_add(
                    std::mem::size_of::<
                        Result<
                            aos_linux_descriptors::unix_stream::UnixStreamPeerCredentials,
                            RootObservationErrorV1,
                        >,
                    >()
                    .checked_mul(3)?,
                )?
                .checked_add(
                    std::mem::size_of::<
                        Result<(RawPairedClockSample, Instant), RootObservationErrorV1>,
                    >()
                    .checked_mul(3)?,
                )?
                .checked_add(
                    std::mem::size_of::<Result<&[u8; 32], RootObservationErrorV1>>()
                        .checked_mul(3)?,
                )?
                .checked_add(std::mem::size_of::<RootQ04NativeStreamLoanV1<'_>>().checked_mul(3)?)?
                .checked_add(
                    std::mem::size_of::<
                        Result<RootQ04NativeStreamLoanV1<'_>, RootObservationErrorV1>,
                    >()
                    .checked_mul(3)?,
                )?
                .checked_add(2 * std::mem::size_of::<usize>() + 2 * std::mem::align_of::<Self>())?
                .checked_add(admission.checked_mul(2)?)?
                .checked_add(clock.checked_mul(2)?)?
                .checked_add(4 * std::mem::size_of::<Arc<RootPermanentNativeOriginalV1>>())?
                .checked_add(
                    3 * (std::mem::size_of::<std::sync::atomic::AtomicBool>()
                        + 2 * std::mem::size_of::<usize>()
                        + 2 * std::mem::align_of::<usize>()),
                )?;
        let native = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(
                D::OpenFiles,
                u64::try_from(descriptors)
                    .ok()?
                    .checked_add(1)?
                    .checked_add(
                    2 * RetainedKernelPairedClockAttemptV1::<ClockError>::MAXIMUM_RETAINED_FILES_V1
                        as u64,
                )?,
            );
        native
            .checked_add(RootSelectedControllerPeerOriginalV1::fixed_demand().ok()?)
            .ok()?
            .checked_add(RootServiceCurrentnessOriginalV1::demand()?)
            .ok()?
            .checked_add(crate::receiving::RootQ04OriginBorrowerV1::fixed_carrier_demand_v1()?)
            .ok()
    }

    /// Parks the actual accepted stream before the original Q04 clock frontier.
    ///
    /// `accepted` is the same flight's retained endpoint. Its native cookie is
    /// compared with this stream after origin capture; no second connection is
    /// opened. A rejected offered stream remains resident until termination.
    ///
    /// # Errors
    /// Retains original clock, startup, duplicate/adoption, peer or post failure.
    /// Reentry never observes another origin or replaces an acquired prefix.
    pub fn admit_original_once_v1(
        &mut self,
        original: UnixStream,
        accepted: &RetainedUnixStream,
        request: [u8; 32],
    ) -> Result<(), RootObservationErrorV1> {
        if self.original.is_some() || self.entered {
            // A rejected native offer cannot be destroyed on an ordinary error.
            std::process::abort();
        }
        self.original = Some(original);
        self.request = Some(request);
        self.entered = true;
        let body =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.admit_inner(accepted)));
        match body {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                self.primary = Some(error);
            }
            Err(payload) => {
                self.admission_panic = Some(payload);
            }
        }
        let adoption_post = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.admission_post = Some((|| {
                if let Some(adoption) = &mut self.adoption {
                    let permanent = self
                        .financial
                        .as_ref()
                        .map(RootJournalFinancialOriginalV1::q04_permanent_v1)
                        .ok_or(RootObservationErrorV1::Service)?;
                    let _invocation = permanent.enter_observation()?;
                    adoption.finish_negative_shutdown_once();
                }
                Ok(())
            })());
        }));
        if let Err(payload) = adoption_post {
            self.admission_post_panic = Some(payload);
        }
        // This separate prepaid native observation is attempted after every
        // entered body, including an unreturned clock/peer/adoption panic.
        let post = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.post_root_once()));
        if let Err(payload) = post {
            self.post_panic = Some(payload);
        }
        let clock_post = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let original = self
                .original_pair
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .copied();
            let permanent = self
                .financial
                .as_ref()
                .map(RootJournalFinancialOriginalV1::q04_permanent_v1)
                .ok_or(RootObservationErrorV1::Service)?;
            let _invocation = permanent.enter_observation()?;
            self.post_pair = Some(self.post_clock.observe_once(original));
            Ok::<(), RootObservationErrorV1>(())
        }));
        match clock_post {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                self.closed.get_or_insert(error);
            }
            Err(payload) => {
                self.clock_panic = Some(payload);
            }
        }
        if self.primary.is_some()
            || self.admission_panic.is_some()
            || self.post_panic.is_some()
            || self.admission_post_panic.is_some()
            || !matches!(self.admission_post, Some(Ok(())))
            || self.clock_panic.is_some()
            || !matches!(self.post_pair, Some(Ok(_)))
            || !matches!(self.root_post_result, Some(Ok(())))
        {
            if let Some(lifetime) = &self.lifetime {
                lifetime.close();
            }
            return Err(RootObservationErrorV1::Service);
        }
        self.settlement = Some(
            self.qualifier
                .as_mut()
                .ok_or(RootObservationErrorV1::Service)?
                .settle_positive_once(),
        );
        if self.failure().is_none() {
            Ok(())
        } else {
            if let Some(lifetime) = &self.lifetime {
                lifetime.close();
            }
            Err(RootObservationErrorV1::Service)
        }
    }

    fn admit_inner(&mut self, accepted: &RetainedUnixStream) -> Result<(), RootObservationErrorV1> {
        self.require_arm()?;
        let request = self.request.ok_or(RootObservationErrorV1::Service)?;
        let identities = self.startup.fields().profile.identities;
        if request[..8] != *aos_sandbox_protocol::domain_ledger::create_q04_history::Q04_ORIGINAL_QUERY_MAGIC_V1
            || request[8..24] == [0; 16]
            || request[24..] != [0; 8]
            || identities.iter().any(|identity| *identity == 0)
        {
            return Err(RootObservationErrorV1::Service);
        }

        // Preserve the legacy Q04 frontier: once/UID checks, then Instant and
        // paired kernel origin, before startup, duplicate, adoption and peer.
        let permanent = self
            .financial
            .as_ref()
            .map(RootJournalFinancialOriginalV1::q04_permanent_v1)
            .map(Arc::clone)
            .ok_or(RootObservationErrorV1::Service)?;
        {
            let _invocation = permanent.enter_native()?;
            self.started = Some(Instant::now());
            self.original_pair = Some(self.clock.observe_once(None));
        }
        if !matches!(self.original_pair, Some(Ok(_))) {
            return Err(RootObservationErrorV1::Service);
        }
        self.startup_before = Some(
            self.startup
                .borrow_selected_startup_v1()
                .and_then(|startup| startup.recheck_v1()),
        );
        if self.startup_before.as_ref().is_some_and(Result::is_err) {
            self.startup_cause = self.startup.selected_currentness_failure_original_v1();
        }
        positive(&self.startup_before)?;

        let _invocation = permanent.enter_native()?;
        self.duplicate = Some(rustix::io::fcntl_dupfd_cloexec(
            self.original
                .as_ref()
                .ok_or(RootObservationErrorV1::Service)?,
            0,
        ));
        match self.duplicate.take() {
            Some(Ok(descriptor)) => {
                self.adoption = Some(RetainedUnixStreamAdmissionOriginalV1::new(descriptor));
            }
            returned => {
                self.duplicate = returned;
                return Err(RootObservationErrorV1::Service);
            }
        }
        let adoption = self
            .adoption
            .as_mut()
            .ok_or(RootObservationErrorV1::Service)?;
        self.adoption_result = Some(
            adoption
                .capture_once()
                .map_err(|_| RootObservationErrorV1::Service),
        );
        positive(&self.adoption_result)?;
        self.stream = Some(
            adoption
                .take_completed_once()
                .map_err(|_| RootObservationErrorV1::Service)?,
        );
        let stream = self
            .stream
            .as_mut()
            .ok_or(RootObservationErrorV1::Service)?;
        self.endpoint = Some(accepted.require_same_endpoint_v1(stream.as_fd()));
        positive(&self.endpoint)?;
        self.subject_reporting = Some(stream.enable_subject_reporting().map_err(aos_sandbox_linux::seqpacket::SeqpacketError::from));
        positive(&self.subject_reporting)?;
        self.qualifier = Some(RootSelectedControllerPeerOriginalV1::new(
            self.startup,
            self.lifetime
                .as_ref()
                .ok_or(RootObservationErrorV1::Service)?
                .clone(),
        ));
        self.qualification = Some(
            self.qualifier
                .as_mut()
                .ok_or(RootObservationErrorV1::Service)?
                .capture_once(stream),
        );
        positive(&self.qualification).map(|_| ())
    }

    fn post_root_once(&mut self) -> Result<(), RootObservationErrorV1> {
        if self.root_post_entered {
            return Err(RootObservationErrorV1::Service);
        }
        self.root_post_entered = true;
        self.root_post_result = Some((|| {
            let permanent = self
                .financial
                .as_ref()
                .map(RootJournalFinancialOriginalV1::q04_permanent_v1)
                .ok_or(RootObservationErrorV1::Service)?;
            let enrollment = permanent
                .enrollment()
                .enrollment_v1()
                .ok_or(RootObservationErrorV1::Service)?;
            let mut invocation = permanent.enter_observation()?;
            self.root_post.observe_once(
                self.startup,
                permanent.service.kernel(),
                enrollment.recipient_invocation,
                enrollment.identity.native_fields().invocation,
            );
            if self.root_post.is_positive() {
                Ok(())
            } else {
                invocation.refuse();
                Err(RootObservationErrorV1::Service)
            }
        })());
        positive(&self.root_post_result).map(|_| ())
    }

    fn require_arm(&self) -> Result<(), RootObservationErrorV1> {
        if self.closed.is_some()
            || !matches!(self.arm, Some(Ok(())))
            || self.retired
            || self
                .lifetime
                .as_ref()
                .is_none_or(|lifetime| !lifetime.is_open())
        {
            return Err(RootObservationErrorV1::Service);
        }
        let permanent = self
            .financial
            .as_ref()
            .map(RootJournalFinancialOriginalV1::q04_permanent_v1)
            .ok_or(RootObservationErrorV1::Service)?;
        let _invocation = permanent.enter_native()?;
        if self
            .financial
            .as_ref()
            .is_none_or(|original| original.failure_v1().is_some())
        {
            return Err(RootObservationErrorV1::Service);
        }
        Ok(())
    }

    /// Borrows the exact retained origin as comparison DATA without resampling.
    ///
    /// # Errors
    /// Refuses absent or failed original observation and any incomplete admission.
    pub fn original_clock_data_v1(
        &self,
    ) -> Result<(RawPairedClockSample, Instant), RootObservationErrorV1> {
        self.require_ready_v1()?;
        self.retained_original_clock_data_v1()
    }

    /// Copies only this Origin's retained first pair and Instant as DATA.
    ///
    /// This performs no readiness, deadline, native or observation entry.
    /// Actual role/currentness lenders separately enforce their reached gates.
    ///
    /// # Errors
    /// Refuses a missing or unsuccessful original pair or absent saved Instant.
    pub fn retained_original_clock_data_v1(
        &self,
    ) -> Result<(RawPairedClockSample, Instant), RootObservationErrorV1> {
        Ok((
            *positive(&self.original_pair)?,
            self.started.ok_or(RootObservationErrorV1::Service)?,
        ))
    }

    /// Requires the same completed native admission without issuing a role.
    ///
    /// # Errors
    /// Refuses failed/partial custody, original expiry or unsettled qualification.
    pub fn require_ready_v1(&self) -> Result<(), RootObservationErrorV1> {
        if self.require_arm().is_err() {
            if let Some(lifetime) = &self.lifetime {
                lifetime.close();
            }
            return Err(RootObservationErrorV1::Service);
        }
        if self.failure().is_some()
            || self.admission_panic.is_some()
            || self.post_panic.is_some()
            || self.admission_post_panic.is_some()
            || self.clock_panic.is_some()
            || self
                .crossings
                .iter()
                .any(|crossing| !crossing.is_complete_v1())
            || self
                .original_clocks
                .iter()
                .any(|clock| !clock.is_complete_v1())
            || !matches!(self.settlement, Some(Ok(())))
            || self
                .started
                .is_none_or(|started| started.elapsed() >= MAXIMUM_FLIGHT)
        {
            if let Some(lifetime) = &self.lifetime {
                lifetime.close();
            }
            return Err(RootObservationErrorV1::Service);
        }
        self.qualifier
            .as_ref()
            .ok_or(RootObservationErrorV1::Service)?
            .require_completed()
    }

    /// Returns the actual qualified peer's credentials as comparison DATA.
    ///
    /// This copy contains PID/UID/GID only; it exposes no descriptor or native
    /// operation outside the separately guarded stream loan.
    ///
    /// # Errors
    /// Refuses incomplete, expired, failed or retired selected transport custody.
    pub fn qualified_peer_credentials_data_v1(
        &self,
    ) -> Result<aos_linux_descriptors::unix_stream::UnixStreamPeerCredentials, RootObservationErrorV1>
    {
        self.require_ready_v1()?;
        self.stream
            .as_ref()
            .map(|stream| stream.peer().credentials())
            .ok_or(RootObservationErrorV1::Service)
    }

    /// Borrows the exact accepted discriminator without receiving another query.
    ///
    /// # Errors
    /// Refuses failed, incomplete, expired or retired native admission.
    pub fn accepted_query_data_v1(&self) -> Result<&[u8; 32], RootObservationErrorV1> {
        self.require_ready_v1()?;
        self.request.as_ref().ok_or(RootObservationErrorV1::Service)
    }

    /// Returns the same qualified startup profile's expected identity tuple.
    ///
    /// The tuple contains Controller UID/GID, physical Source UID and Cache UID.
    /// Physical Source uses Controller's UID; the startup profile separately
    /// records Cache and Source signer UIDs. This is comparison DATA only.
    ///
    /// # Errors
    /// Refuses incomplete, failed, expired or retired native qualification.
    pub fn expected_identities_data_v1(&self) -> Result<[u32; 4], RootObservationErrorV1> {
        self.require_ready_v1()?;
        Ok([
            self.startup.fields().profile.identities[0],
            self.startup.fields().profile.identities[1],
            self.startup.fields().profile.identities[0],
            self.startup.fields().profile.identities[2],
        ])
    }

    /// Claims this actual accepted origin for one Authority nonce programme.
    ///
    /// This denial-only latch observes no clock and produces no nonce or role.
    /// The resident Authority factory retains this same concrete transport and
    /// sets up its own genuine per-flight owner only after this entry succeeds.
    ///
    /// # Errors
    /// Permanently refuses failed readiness or any repeated Authority entry.
    pub fn claim_authority_flight_once_v1(&mut self) -> Result<(), RootObservationErrorV1> {
        if self.require_ready_v1().is_err() || self.authority_claimed {
            self.closed.get_or_insert(RootObservationErrorV1::Service);
            if let Some(lifetime) = &self.lifetime {
                lifetime.close();
            }
            return Err(RootObservationErrorV1::Service);
        }
        self.authority_claimed = true;
        Ok(())
    }

    /// Rejoins another genuine financial original to this same selected flight.
    ///
    /// The caller holds no external financial or native guard during this
    /// comparison. The actual owner performs its existing intrinsic join.
    ///
    /// # Errors
    /// Refuses an incomplete transport, foreign Permanent or refused original.
    pub fn require_same_financial_original_v1(
        &self,
        original: &RootJournalFinancialOriginalV1,
    ) -> Result<(), RootObservationErrorV1> {
        self.require_ready_v1()?;
        self.financial
            .as_ref()
            .ok_or(RootObservationErrorV1::Service)?
            .require_same_v1(original)
            .map_err(|_| RootObservationErrorV1::Service)
    }

    /// Compares only the intrinsic financial allocation held by this Origin.
    ///
    /// This passive association is neither readiness nor permission to enter
    /// native work. Actual currentness remains at its original reached slots.
    #[must_use]
    pub fn same_financial_original_data_v1(
        &self,
        original: &RootJournalFinancialOriginalV1,
    ) -> bool {
        match self.financial.as_ref() {
            Some(financial) => financial.same_original_data_v1(original),
            None => false,
        }
    }

    /// Holds the same Permanent native phase across one actual stream IO step.
    ///
    /// # Errors
    /// Refuses an incomplete/closed transport or ended/refused invocation.
    pub fn borrow_native_stream_v1(
        &mut self,
    ) -> Result<RootQ04NativeStreamLoanV1<'_>, RootObservationErrorV1> {
        self.require_ready_v1()?;
        let permanent = self
            .financial
            .as_ref()
            .map(RootJournalFinancialOriginalV1::q04_permanent_v1)
            .ok_or(RootObservationErrorV1::Service)?;
        let invocation = permanent.enter_native()?;
        let stream = self
            .stream
            .as_mut()
            .ok_or(RootObservationErrorV1::Service)?;
        Ok(RootQ04NativeStreamLoanV1 {
            _invocation: invocation,
            stream,
        })
    }

    /// Observes one fresh current crossing under the unchanged original origin.
    ///
    /// Each destination is prequoted before construction and retained through
    /// final disposal. Refused or unreturned crossings cannot be replaced.
    ///
    /// # Errors
    /// Retains the actual payment, Root, Controller, queue, clock or post cause.
    pub fn observe_current_once_v1(
        &mut self,
    ) -> Result<RawPairedClockSample, RootObservationErrorV1> {
        self.observe_crossing_once_v1(None)
    }

    /// Joins a real received chunk to this same retained qualified Controller.
    ///
    /// The caller keeps the chunk resident through this crossing, cumulative
    /// copy and its separately owed final current check. This call pays before
    /// constructing the actual subject destination and shares the Root posts.
    ///
    /// # Errors
    /// Retains actual subject/native, funding, queue, clock or independent post
    /// failure; refusal closes this same origin rather than replacing its peer.
    pub fn observe_subject_once_v1(
        &mut self,
        chunk: &UnixStreamSubjectChunk,
    ) -> Result<RawPairedClockSample, RootObservationErrorV1> {
        self.observe_crossing_once_v1(Some(chunk))
    }

    fn observe_crossing_once_v1(
        &mut self,
        chunk: Option<&UnixStreamSubjectChunk>,
    ) -> Result<RawPairedClockSample, RootObservationErrorV1> {
        self.prepare_crossing_once_v1(chunk.is_some(), false)?;
        let crossing = self
            .crossings
            .last_mut()
            .ok_or(RootObservationErrorV1::Service)?;
        let returned = crossing.observe_once_v1(
            self.startup,
            self.financial
                .as_ref()
                .map(RootJournalFinancialOriginalV1::q04_permanent_v1)
                .ok_or(RootObservationErrorV1::Service)?,
            self.qualifier
                .as_ref()
                .ok_or(RootObservationErrorV1::Service)?,
            self.stream
                .as_ref()
                .ok_or(RootObservationErrorV1::Service)?,
            *positive(&self.original_pair)?,
            self.started.ok_or(RootObservationErrorV1::Service)?,
            chunk,
        );
        if returned.is_err() {
            if let Some(lifetime) = &self.lifetime {
                lifetime.close();
            }
            self.closed.get_or_insert(RootObservationErrorV1::Service);
        }
        returned
    }

    fn prepare_crossing_once_v1(
        &mut self,
        subject: bool,
        input: bool,
    ) -> Result<(), RootObservationErrorV1> {
        self.require_ready_v1()?;
        let count = self
            .crossings
            .len()
            .checked_add(1)
            .ok_or(RootObservationErrorV1::Service)?;
        let demand = Q04CurrentCrossingV1::demand_v1(count, subject)
            .ok_or(RootObservationErrorV1::Service)?;
        let demand = if input {
            let bytes = std::mem::size_of::<RootQ04InputCurrentLoanV1<'_, '_>>()
                .checked_mul(3)
                .and_then(|bytes| {
                    bytes.checked_add(
                        std::mem::size_of::<
                            Result<RootQ04InputCurrentLoanV1<'_, '_>, RootObservationErrorV1>,
                        >()
                        .checked_mul(3)?,
                    )
                })
                .and_then(|bytes| {
                    // Public negative-post result, its shared finisher and
                    // the retained-post diagnostic each have three planes.
                    bytes.checked_add(
                        std::mem::size_of::<Result<(), RootObservationErrorV1>>().checked_mul(9)?,
                    )
                })
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(RootObservationErrorV1::Service)?;
            demand
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
                .map_err(|_| RootObservationErrorV1::Service)?
        } else {
            demand
        };
        let funding = self
            .financial
            .as_ref()
            .ok_or(RootObservationErrorV1::Service)?
            .debit_q04_transport_v1(demand);
        if let Err(error) = funding {
            self.crossing_funding = Some(error);
            if let Some(lifetime) = &self.lifetime {
                lifetime.close();
            }
            return Err(RootObservationErrorV1::Service);
        }
        if let Err(error) = self.crossings.try_reserve_exact(1) {
            self.crossing_reservation = Some(error);
            if let Some(lifetime) = &self.lifetime {
                lifetime.close();
            }
            return Err(RootObservationErrorV1::Service);
        }
        self.crossings.push(Q04CurrentCrossingV1::new(
            self.lifetime
                .as_ref()
                .ok_or(RootObservationErrorV1::Service)?
                .clone(),
            subject,
        ));
        Ok(())
    }

    /// Borrows the first actual native diagnostic without another observation.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        cause(&self.arm)
            .or_else(|| self.clock.failure())
            .or_else(|| cause(&self.original_pair))
            .or_else(|| self.startup_cause.as_ref().map(|cause| cause as _))
            .or_else(|| cause(&self.startup_before))
            .or_else(|| cause(&self.duplicate))
            .or_else(|| {
                self.adoption
                    .as_ref()
                    .and_then(|original| original.failure())
            })
            .or_else(|| cause(&self.adoption_result))
            .or_else(|| cause(&self.endpoint))
            .or_else(|| cause(&self.subject_reporting))
            .or_else(|| self.qualifier.as_ref().and_then(|peer| peer.failure()))
            .or_else(|| cause(&self.qualification))
            .or_else(|| self.primary.as_ref().map(|error| error as _))
            .or_else(|| cause(&self.admission_post))
            .or_else(|| self.root_post.failure())
            .or_else(|| cause(&self.root_post_result))
            .or_else(|| self.post_clock.failure())
            .or_else(|| cause(&self.post_pair))
            .or_else(|| cause(&self.settlement))
            .or_else(|| {
                self.crossing_funding
                    .as_ref()
                    .and_then(|_| self.financial.as_ref()?.failure_v1())
            })
            .or_else(|| self.crossing_reservation.as_ref().map(|error| error as _))
            .or_else(|| {
                self.crossings
                    .iter()
                    .find_map(Q04CurrentCrossingV1::failure)
            })
            .or_else(|| {
                self.original_clocks
                    .iter()
                    .find_map(original_clock::OriginalClockV1::failure)
            })
            .or_else(|| self.closed.as_ref().map(|error| error as _))
    }
}

impl RootInitialReceivingOriginalV1 {
    /// Arms the once-only Q04 origin on this actual consumed selected flight.
    ///
    /// This does no IO. The upper owner must prepay fixed_demand_v1 before
    /// constructing dynamic qualifier backing or invoking native admission.
    ///
    /// # Errors
    /// Refuses foreign startup, reused destination, earlier refusal or a missing
    /// consumed flight with a positive primary and still-owed final observation.
    pub fn arm_q04_transport_origin_once_v1(
        &mut self,
        startup: &RootStartupNativeOriginalV1,
        destination: &mut RootQ04TransportOriginalV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        if destination.arm.is_some()
            || destination.original.is_some()
            || !std::ptr::eq(startup, destination.startup)
        {
            destination
                .closed
                .get_or_insert(RootObservationErrorV1::Service);
            self.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        destination.arm = Some(self.claim_q04_transport_origin_once_v1(startup));
        positive(&destination.arm)?;
        destination.lifetime = Some(ObservationLifetimeV1::begin());
        destination.financial = Some(
            self.journal_financial_original_v1()
                .map_err(|_| RootObservationErrorV1::Service)?,
        );
        Ok(())
    }

    /// Retires only the native Q04 owner after this flight's actual final post.
    ///
    /// The upper private Q04 finisher separately requires terminal role
    /// clearance before entering this native-only disposal boundary. This
    /// method does not complete finance or authenticate semantic role DATA.
    ///
    /// # Errors
    /// Refuses incomplete native posts, another actual Permanent, any failed
    /// origin or repeated disposition. Failed native prefixes remain resident.
    pub fn retire_q04_transport_after_native_posts_v1(
        &mut self,
        destination: &mut RootQ04TransportOriginalV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        self.require_q04_transport_native_posts_v1()?;
        if destination.retired
            || destination.failure().is_some()
            || destination.admission_panic.is_some()
            || destination.post_panic.is_some()
            || destination.admission_post_panic.is_some()
            || destination.clock_panic.is_some()
            || !matches!(destination.settlement, Some(Ok(())))
            || destination
                .crossings
                .iter()
                .any(|crossing| !crossing.is_complete_v1())
            || destination
                .original_clocks
                .iter()
                .any(|clock| !clock.is_complete_v1())
            || !self
                .permanent
                .as_ref()
                .zip(
                    destination
                        .financial
                        .as_ref()
                        .map(RootJournalFinancialOriginalV1::q04_permanent_v1),
                )
                .is_some_and(|(left, right)| Arc::ptr_eq(left, right))
        {
            self.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        if let Some(lifetime) = &destination.lifetime {
            lifetime.close();
        }
        destination.retired = true;
        Ok(())
    }
}

impl Drop for RootQ04TransportOriginalV1<'_> {
    fn drop(&mut self) {
        if self.entered && !self.retired {
            std::process::abort();
        }
    }
}

fn positive<T, E>(value: &Option<Result<T, E>>) -> Result<&T, RootObservationErrorV1> {
    value
        .as_ref()
        .and_then(|result| result.as_ref().ok())
        .ok_or(RootObservationErrorV1::Service)
}

fn cause<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value
        .as_ref()
        .and_then(|result| result.as_ref().err())
        .map(|error| error as _)
}
