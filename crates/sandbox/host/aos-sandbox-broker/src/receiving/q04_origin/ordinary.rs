//! Retains the existing ordinary Q04 transport without a selected lender.
//!
//! This explicit legacy entry preserves the original accepted connection,
//! peer and 65-second clock. It cannot borrow Initial, Permanent or a selected
//! receiving grant. Missing legacy startup remains negative custody only.

use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use aos_sandbox_model::RawPairedClockSample;
use aos_linux_descriptors::unix_stream::RetainedUnixStream;
use aos_linux_descriptors::unix_stream::UnixStreamPeerCredentials;
use aos_sandbox_linux::unix_stream::UnixStreamSubjectChunk;

use crate::controller_receiving::profile::root_flight::{
    ControllerRootFlightErrorV1, require_open_receive_queue_v1,
};
use crate::kernel_clock::{KernelPairedClockErrorV1, ordinary_kernel_pair};
use crate::receiving::{
    RootControllerPolicyPeerV1, RootObservationErrorV1, RootStartupNativeOriginalV1,
};

const MAXIMUM_FLIGHT: Duration = Duration::from_secs(65);

/// Preserves the existing ordinary Q04 transport error classification.
#[derive(Debug, thiserror::Error)]
pub enum RootQ04OrdinaryTransportErrorV1 {
    /// The actual original, fixed request or peer association differs.
    #[error("the original Q04 continuation cut changed")]
    ChangedCut,
    /// The original kernel or monotonic deadline has expired.
    #[error("the original Q04 flight deadline expired")]
    Expired,
    /// The ordinary kernel sampler could not construct its paired DATA.
    #[error("Source genesis owner or credential is not current")]
    ClockStale,
    /// The ordinary paired clock preserves its actual kernel error.
    #[error(transparent)]
    ClockKernel(aos_linux_descriptors::Error),
    /// The original ordinary readiness operation failed.
    #[error(transparent)]
    Readiness(ControllerRootFlightErrorV1),
    /// The actual startup or genuine Controller peer changed.
    #[error(transparent)]
    Startup(#[from] RootObservationErrorV1),
    /// The original descriptor, send or shutdown operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Strict native stream adoption or identity checking failed.
    #[error(transparent)]
    Kernel(#[from] aos_linux_descriptors::Error),
    /// The original stream subject-reporting operation failed.
    #[error(transparent)]
    Subject(#[from] aos_sandbox_linux::seqpacket::SeqpacketError),
}

impl KernelPairedClockErrorV1 for RootQ04OrdinaryTransportErrorV1 {
    fn stale() -> Self {
        Self::ClockStale
    }

    fn kernel(error: aos_linux_descriptors::Error) -> Self {
        Self::ClockKernel(error)
    }
}

/// Owns only the actual ordinary Q04 accepted transport and legacy startup.
///
/// Construction is inert. A failed or uncleared entered original must remain
/// resident through process termination. No selected admission is inferred
/// from the absence of financial custody.
pub struct RootQ04OrdinaryTransportOriginalV1<'startup> {
    startup: Option<&'startup RootStartupNativeOriginalV1>,
    identities: [u32; 4],
    original: UnixStream,
    request: [u8; 32],
    stream: Option<RetainedUnixStream>,
    peer: Option<RootControllerPolicyPeerV1<'startup>>,
    clock: Option<RawPairedClockSample>,
    started: Option<Instant>,
    entered: bool,
    admitted: bool,
    authority_claimed: bool,
    shutdown: Option<Result<(), std::io::Error>>,
    retired: bool,
}

impl<'startup> RootQ04OrdinaryTransportOriginalV1<'startup> {
    /// Parks the same ordinary accepted stream before its original effects.
    ///
    /// The identities retain the existing privileged daemon configuration in
    /// Q04 order: Controller UID/GID, physical Source UID and Cache UID. An
    /// absent startup can retain a negative original but never becomes ready.
    #[must_use]
    pub fn new(
        original: UnixStream,
        startup: Option<&'startup RootStartupNativeOriginalV1>,
        request: [u8; 32],
        identities: [u32; 4],
    ) -> Self {
        Self {
            startup,
            identities,
            original,
            request,
            stream: None,
            peer: None,
            clock: None,
            started: None,
            entered: false,
            admitted: false,
            authority_claimed: false,
            shutdown: None,
            retired: false,
        }
    }

    /// Runs the existing ordinary clock, startup, duplicate and peer prefix.
    ///
    /// # Errors
    /// Preserves fixed-request/identity refusal before the clock, missing
    /// startup after that clock, and actual duplicate/adoption/peer errors.
    pub fn admit_original_once_v1(&mut self) -> Result<(), RootQ04OrdinaryTransportErrorV1> {
        use RootQ04OrdinaryTransportErrorV1 as Error;
        if self.entered || self.started.is_some() || self.clock.is_some()
            || self.stream.is_some() || self.peer.is_some()
            || self.request[..8] != *aos_sandbox_protocol::domain_ledger::create_q04_history::Q04_ORIGINAL_QUERY_MAGIC_V1
            || self.request[8..24] == [0;16] || self.request[24..] != [0;8]
            || self.identities.iter().any(|identity| *identity == 0)
        { return Err(Error::ChangedCut); }
        self.entered = true;

        self.started = Some(Instant::now());
        self.clock = Some(ordinary_kernel_pair::<RootQ04OrdinaryTransportErrorV1>()?);
        let startup = self.startup.ok_or(Error::ChangedCut)?;
        // Selected startup has its own closed native origin. A failed or
        // unarmed selected lender cannot enter this ordinary branch.
        if startup.initial_owner.is_some()
            || self.identities
                != [
                    startup.fields().profile.identities[0],
                    startup.fields().profile.identities[1],
                    startup.fields().profile.identities[0],
                    startup.fields().profile.identities[2],
                ]
        {
            return Err(Error::ChangedCut);
        }
        startup.recheck_ordinary()?;

        let duplicate =
            rustix::io::fcntl_dupfd_cloexec(&self.original, 0).map_err(std::io::Error::from)?;
        self.stream = Some(RetainedUnixStream::from_owned(duplicate)?);
        let stream = self.stream.as_mut().ok_or(Error::ChangedCut)?;
        stream.enable_subject_reporting().map_err(aos_sandbox_linux::seqpacket::SeqpacketError::from)?;
        let peer = startup.observe_controller_policy_peer(stream)?;
        if stream.peer().credentials().uid() != self.identities[0]
            || stream.peer().credentials().gid() != self.identities[1]
        {
            return Err(Error::ChangedCut);
        }
        self.peer = Some(peer);
        self.admitted = true;
        Ok(())
    }

    /// Requires the actual ordinary startup and completed original prefix.
    ///
    /// # Errors
    /// Refuses selected, absent, failed, unentered or retired transport custody.
    pub fn require_ready_v1(&self) -> Result<(), RootQ04OrdinaryTransportErrorV1> {
        use RootQ04OrdinaryTransportErrorV1 as Error;
        let startup = self.startup.ok_or(Error::ChangedCut)?;
        if startup.initial_owner.is_some()
            || !self.admitted
            || self.retired
            || self.stream.is_none()
            || self.peer.is_none()
            || self.clock.is_none()
            || self.started.is_none()
        {
            return Err(Error::ChangedCut);
        }
        Ok(())
    }

    pub(super) fn require_ordinary_original_v1(
        &self,
    ) -> Result<(), RootQ04OrdinaryTransportErrorV1> {
        self.require_ready_v1()
    }

    pub(super) fn original_clock_data_v1(
        &self,
    ) -> Result<(RawPairedClockSample, Instant), RootQ04OrdinaryTransportErrorV1> {
        self.require_ready_v1()?;
        self.retained_original_clock_data_v1()
    }

    pub(super) fn retained_original_clock_data_v1(
        &self,
    ) -> Result<(RawPairedClockSample, Instant), RootQ04OrdinaryTransportErrorV1> {
        Ok((
            self.clock
                .ok_or(RootQ04OrdinaryTransportErrorV1::ChangedCut)?,
            self.started
                .ok_or(RootQ04OrdinaryTransportErrorV1::ChangedCut)?,
        ))
    }

    pub(super) fn accepted_query_data_v1(
        &self,
    ) -> Result<&[u8; 32], RootQ04OrdinaryTransportErrorV1> {
        self.require_ready_v1()?;
        Ok(&self.request)
    }

    pub(super) fn expected_identities_data_v1(
        &self,
    ) -> Result<[u32; 4], RootQ04OrdinaryTransportErrorV1> {
        self.require_ready_v1()?;
        Ok(self.identities)
    }

    pub(super) fn qualified_peer_credentials_data_v1(
        &self,
    ) -> Result<UnixStreamPeerCredentials, RootQ04OrdinaryTransportErrorV1> {
        self.require_ready_v1()?;
        Ok(self
            .stream
            .as_ref()
            .ok_or(RootQ04OrdinaryTransportErrorV1::ChangedCut)?
            .peer()
            .credentials())
    }

    pub(super) fn claim_authority_flight_once_v1(
        &mut self,
    ) -> Result<(), RootQ04OrdinaryTransportErrorV1> {
        self.require_ready_v1()?;
        if self.authority_claimed {
            return Err(RootQ04OrdinaryTransportErrorV1::ChangedCut);
        }
        self.authority_claimed = true;
        Ok(())
    }

    pub(super) fn stream_mut_v1(
        &mut self,
    ) -> Result<&mut RetainedUnixStream, RootQ04OrdinaryTransportErrorV1> {
        self.require_ready_v1()?;
        self.stream
            .as_mut()
            .ok_or(RootQ04OrdinaryTransportErrorV1::ChangedCut)
    }

    pub(super) fn observe_startup_once_v1(&self) -> Result<(), RootQ04OrdinaryTransportErrorV1> {
        self.startup
            .ok_or(RootQ04OrdinaryTransportErrorV1::ChangedCut)?
            .recheck_ordinary()?;
        Ok(())
    }

    pub(super) fn observe_peer_once_v1(&self) -> Result<(), RootQ04OrdinaryTransportErrorV1> {
        self.peer
            .as_ref()
            .ok_or(RootQ04OrdinaryTransportErrorV1::ChangedCut)?
            .recheck_stream(
                self.stream
                    .as_ref()
                    .ok_or(RootQ04OrdinaryTransportErrorV1::ChangedCut)?,
            )?;
        Ok(())
    }

    pub(super) fn observe_queue_once_v1(&self) -> Result<(), RootQ04OrdinaryTransportErrorV1> {
        require_open_receive_queue_v1(
            self.stream
                .as_ref()
                .ok_or(RootQ04OrdinaryTransportErrorV1::ChangedCut)?
                .as_fd(),
        )
        .map_err(RootQ04OrdinaryTransportErrorV1::Readiness)
    }

    pub(super) fn observe_prefix_once_v1(&self) -> Result<(), RootQ04OrdinaryTransportErrorV1> {
        self.observe_startup_once_v1()?;
        self.observe_peer_once_v1()?;
        self.observe_queue_once_v1()
    }

    pub(super) fn observe_subject_once_v1(
        &self,
        chunk: &UnixStreamSubjectChunk,
    ) -> Result<(), RootQ04OrdinaryTransportErrorV1> {
        self.peer
            .as_ref()
            .ok_or(RootQ04OrdinaryTransportErrorV1::ChangedCut)?
            .require_chunk(
                self.stream
                    .as_ref()
                    .ok_or(RootQ04OrdinaryTransportErrorV1::ChangedCut)?,
                chunk,
            )?;
        Ok(())
    }

    pub(super) fn observe_original_clock_once_v1(
        &self,
    ) -> Result<RawPairedClockSample, RootQ04OrdinaryTransportErrorV1> {
        use RootQ04OrdinaryTransportErrorV1 as Error;
        let original = self.clock.ok_or(Error::ChangedCut)?;
        let started = self.started.ok_or(Error::ChangedCut)?;
        let current = ordinary_kernel_pair::<RootQ04OrdinaryTransportErrorV1>()?;
        crate::kernel_clock::require_original_clock::<Error>(Some(original), current).map_err(
            |cause| match cause {
                Error::ClockStale => Error::Expired,
                cause => cause,
            },
        )?;
        if started.elapsed() >= MAXIMUM_FLIGHT {
            return Err(Error::Expired);
        }
        Ok(current)
    }

    /// Ends the original socket once at the existing final-clearance frontier.
    ///
    /// # Errors
    /// Returns a marker while retaining the actual original shutdown result.
    pub fn shutdown_original_once_v1(&mut self) -> Result<(), RootQ04OrdinaryTransportErrorV1> {
        if self.shutdown.is_some() {
            return Err(RootQ04OrdinaryTransportErrorV1::ChangedCut);
        }
        self.shutdown = Some(self.original.shutdown(std::net::Shutdown::Both));
        if matches!(self.shutdown, Some(Ok(()))) {
            Ok(())
        } else {
            Err(RootQ04OrdinaryTransportErrorV1::ChangedCut)
        }
    }

    /// Borrows the exact final shutdown result without replacing its cause.
    #[must_use]
    pub fn shutdown_result(&self) -> Option<&Result<(), std::io::Error>> {
        self.shutdown.as_ref()
    }

    /// Retires this transport after its original shutdown completed.
    ///
    /// The upper typed programme separately requires actual Authority and
    /// publication clearance before calling this transport-only method.
    ///
    /// # Errors
    /// Refuses an incomplete original or failed/unreturned shutdown.
    pub fn retire_after_shutdown_once_v1(&mut self) -> Result<(), RootQ04OrdinaryTransportErrorV1> {
        self.require_ready_v1()?;
        if !matches!(self.shutdown, Some(Ok(()))) {
            return Err(RootQ04OrdinaryTransportErrorV1::ChangedCut);
        }
        self.retired = true;
        Ok(())
    }
}

impl Drop for RootQ04OrdinaryTransportOriginalV1<'_> {
    fn drop(&mut self) {
        if self.entered && !self.retired {
            std::process::abort();
        }
    }
}
