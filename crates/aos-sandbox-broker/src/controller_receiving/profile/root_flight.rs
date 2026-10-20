//! Retains the fixed Controller-to-Root connection and original native interval.
//!
//! Only the genuine measured Controller profile constructs this owner. The
//! connection, partial adoption, qualified Root peer and original clocks stay
//! together; comparison DATA cannot adopt a socket or replace their origin.
//! Upper coordinators retain their semantic results and independently owed
//! wait bookends outside each native operation's return boundary.

use std::cell::{Cell, Ref, RefCell, RefMut};
use std::os::fd::{AsFd as _, OwnedFd};
use std::time::{Duration, Instant};

use aos_sandbox_core::RawPairedClockSample;
use aos_sandbox_linux::unix_stream::{
    RetainedUnixStream, RetainedUnixStreamAdmissionOriginalV1, UnixStreamSubjectChunk,
};
use rustix::event::{PollFlags, Timespec};
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};

mod q04_wire;
pub use q04_wire::{ControllerRootQ04CacheLoanV1, ControllerRootQ04FinalObservationLoanV1};

use super::{ControllerSelfProfileOriginalV1, ControllerStartupRootPeerV1};

const MAXIMUM_FLIGHT: Duration = Duration::from_secs(60);

/// Preserves a native Root connection, clock or qualified-peer refusal.
#[derive(Debug, thiserror::Error)]
pub enum ControllerRootFlightErrorV1 {
    /// The same original, native order or bounded interval is unavailable.
    #[error("the original Controller Root flight is unavailable")]
    Stale,
    /// The actual fixed connection or stream syscall failed.
    #[error(transparent)]
    Transport(#[from] std::io::Error),
    /// The actual retained kernel observation failed.
    #[error(transparent)]
    Kernel(#[from] aos_sandbox_linux::Error),
    /// The actual stream subject-reporting setup failed.
    #[error(transparent)]
    Subject(#[from] aos_sandbox_linux::seqpacket::SeqpacketError),
}

impl crate::kernel_clock::KernelPairedClockErrorV1 for ControllerRootFlightErrorV1 {
    fn stale() -> Self {
        Self::Stale
    }

    fn kernel(error: aos_sandbox_linux::Error) -> Self {
        Self::Kernel(error)
    }
}

/// Captures one genuine Root opening interval before its first connection.
///
/// Its fields are private. A later connection may borrow this actual opaque
/// original; no API accepts a caller-supplied clock pair or start instant.
pub struct ControllerRootOpeningClockV1 {
    started: Option<Instant>,
    initial: Option<Result<RawPairedClockSample, ControllerRootFlightErrorV1>>,
    claimed: Cell<bool>,
}

impl ControllerRootOpeningClockV1 {
    /// Creates vacant original destinations without observing a clock.
    #[must_use]
    pub fn new() -> Self {
        Self {
            started: None,
            initial: None,
            claimed: Cell::new(false),
        }
    }

    /// Records the one actual Instant and paired kernel sample.
    ///
    /// # Errors
    /// Retains a kernel failure or refuses another original capture.
    pub fn capture_once(&mut self) -> Result<(), ControllerRootFlightErrorV1> {
        if self.started.is_some() || self.initial.is_some() {
            return Err(ControllerRootFlightErrorV1::Stale);
        }
        self.started = Some(Instant::now());
        self.initial = Some(crate::kernel_clock::ordinary_kernel_pair());
        self.original_data().map(|_| ())
    }

    /// Copies the actual captured pair and Instant as comparison DATA.
    ///
    /// # Errors
    /// Refuses an absent or unsuccessful original capture.
    pub fn original_data(
        &self,
    ) -> Result<(Instant, RawPairedClockSample), ControllerRootFlightErrorV1> {
        Ok((
            self.started.ok_or(ControllerRootFlightErrorV1::Stale)?,
            self.initial
                .as_ref()
                .and_then(|sample| sample.as_ref().ok())
                .copied()
                .ok_or(ControllerRootFlightErrorV1::Stale)?,
        ))
    }

    /// Reports whether this actual opening capture entered, including unwind.
    #[must_use]
    pub fn was_entered_v1(&self) -> bool {
        self.started.is_some()
    }

    /// Borrows the actual original capture failure without another observation.
    #[must_use]
    pub fn failure(&self) -> Option<&ControllerRootFlightErrorV1> {
        self.initial.as_ref()?.as_ref().err()
    }
}

impl Default for ControllerRootOpeningClockV1 {
    fn default() -> Self {
        Self::new()
    }
}

/// Retains one actual receive from the same genuine Controller Root original.
///
/// Its private association and sequence prevent supplied subject DATA or a
/// previously consumed fragment from advancing the original wire receiver.
pub struct ControllerRootReceivedChunkV1 {
    original: [u8; 16],
    sequence: u64,
    subject: UnixStreamSubjectChunk,
}

impl ControllerRootReceivedChunkV1 {
    /// Borrows the bytes returned by this same actual native receive.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        self.subject.payload()
    }
}

/// Retains one genuine fixed Root client connection and its complete prefix.
///
/// Construction grants no semantic Root, Source or Cache continuation. The
/// actual original-frame receiver must separately earn every wire phase.
pub struct ControllerRootFlightOriginalV1<'profile> {
    profile: &'profile ControllerSelfProfileOriginalV1,
    opening: ControllerRootOpeningClockV1,
    original: Option<(Instant, RawPairedClockSample)>,
    raw: Option<OwnedFd>,
    stream: Option<RefCell<RetainedUnixStream>>,
    adoption: RefCell<Option<RetainedUnixStreamAdmissionOriginalV1>>,
    peer: Option<ControllerStartupRootPeerV1<'profile>>,
    client_nonce: Option<[u8; 16]>,
    entered: bool,
    received_sequence: Cell<u64>,
    pending_sequence: Cell<Option<u64>>,
    shutdown_observed: Cell<bool>,
    q04_wire: RefCell<q04_wire::Original>,
    poisoned: Cell<bool>,
}

impl<'profile> ControllerRootFlightOriginalV1<'profile> {
    /// Reports actual additional constructor and native-return carrier bytes.
    ///
    /// The enclosing original invocation already pays this resident layout.
    /// This supplier adds its new constructor/return overlap, retained-admission
    /// backing and concrete opaque receive/clock/proof projection planes.
    #[must_use]
    pub fn additional_control_bytes_v1() -> Option<usize> {
        let (admission, _) = RetainedUnixStreamAdmissionOriginalV1::receiving_obligations_v1()?;
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(std::mem::size_of::<Option<aos_sandbox_linux::Error>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Option<Result<(), aos_sandbox_linux::Error>>>().checked_mul(3)?)?
            .checked_add(q04_wire::Original::additional_control_bytes_v1()?)?
            .checked_add(admission.checked_sub(std::mem::size_of::<RetainedUnixStreamAdmissionOriginalV1>())?)?
            .checked_add(std::mem::size_of::<ControllerRootOpeningClockV1>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<Result<(Instant, RawPairedClockSample), ControllerRootFlightErrorV1>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<(Instant, RawPairedClockSample)>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<[u8; 16], ControllerRootFlightErrorV1>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<u32, ControllerRootFlightErrorV1>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<Ref<'_, RetainedUnixStream>, ControllerRootFlightErrorV1>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<RefMut<'_, RetainedUnixStream>, ControllerRootFlightErrorV1>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<ControllerRootReceivedChunkV1>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<ControllerRootReceivedChunkV1,
                aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<RawPairedClockSample, ControllerRootFlightErrorV1>>().checked_mul(3)?)?
            // Classifier argument and constructed/returned/retained bool are
            // distinct new planes; the old inline errno fold remains shared.
            .checked_add(std::mem::size_of::<(&Result<(), ControllerRootFlightErrorV1>, bool)>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<(), ControllerRootFlightErrorV1>>().checked_mul(6)?)
    }

    /// Parks the genuine profile before native connection or clock effects.
    #[must_use]
    pub fn new(profile: &'profile ControllerSelfProfileOriginalV1) -> Self {
        Self {
            profile,
            opening: ControllerRootOpeningClockV1::new(),
            original: None,
            raw: None,
            stream: None,
            adoption: RefCell::new(None),
            peer: None,
            client_nonce: None,
            entered: false,
            received_sequence: Cell::new(0),
            pending_sequence: Cell::new(None),
            shutdown_observed: Cell::new(false),
            q04_wire: RefCell::new(q04_wire::Original::new()),
            poisoned: Cell::new(false),
        }
    }

    /// Connects once to the fixed Root socket from this actual original.
    ///
    /// # Errors
    /// Retains a failed connection/adoption prefix and refuses repeated entry.
    pub fn connect_once(&mut self) -> Result<(), ControllerRootFlightErrorV1> {
        if self.entered {
            self.poisoned.set(true);
            return Err(ControllerRootFlightErrorV1::Stale);
        }
        self.entered = true;
        self.opening.capture_once()?;
        let original = self.opening.original_data()?;
        self.connect_at_original(original, false)
    }

    /// Connects under the resource-Global caller's actual prearmed original.
    ///
    /// No scalar clock or descriptor can populate this continuation.
    ///
    /// # Errors
    /// Retains native refusal or rejects absent, failed or repeated originals.
    pub fn connect_with_opening_once(
        &mut self,
        opening: &ControllerRootOpeningClockV1,
    ) -> Result<(), ControllerRootFlightErrorV1> {
        if self.entered {
            self.poisoned.set(true);
            return Err(ControllerRootFlightErrorV1::Stale);
        }
        self.entered = true;
        let original = opening.original_data()?;
        if opening.claimed.replace(true) {
            return Err(ControllerRootFlightErrorV1::Stale);
        }
        self.connect_at_original(original, false)
    }

    /// Connects the existing ordinary route with pre-admission absence retries.
    ///
    /// Only NOENT and CONNREFUSED may discard an unaccepted raw socket; no
    /// accepted endpoint, adopted prefix, peer or nonce is ever replaced.
    ///
    /// # Errors
    /// Preserves native refusal or the same original absolute deadline.
    pub fn connect_ordinary_once(&mut self) -> Result<(), ControllerRootFlightErrorV1> {
        if self.entered {
            self.poisoned.set(true);
            return Err(ControllerRootFlightErrorV1::Stale);
        }
        self.entered = true;
        self.opening.capture_once()?;
        let original = self.opening.original_data()?;
        self.connect_at_original(original, true)
    }

    fn connect_at_original(
        &mut self,
        original: (Instant, RawPairedClockSample),
        retry_unadmitted: bool,
    ) -> Result<(), ControllerRootFlightErrorV1> {
        self.original = Some(original);
        let (started, _) = original;
        self.profile
            .recheck()
            .map_err(|_| ControllerRootFlightErrorV1::Stale)?;
        loop {
            let connected = self.connect_raw_once(started + MAXIMUM_FLIGHT);
            let unadmitted = connection_not_admitted(&connected);
            if retry_unadmitted && unadmitted {
                self.raw = None;
                std::thread::sleep(
                    require_remaining(started + MAXIMUM_FLIGHT)?.min(Duration::from_millis(25)),
                );
                continue;
            }
            connected?;
            break;
        }
        let descriptor = if retry_unadmitted {
            // The old ordinary route owns only the one connected description.
            self.raw.take().ok_or(ControllerRootFlightErrorV1::Stale)?
        } else {
            let socket = self
                .raw
                .as_ref()
                .ok_or(ControllerRootFlightErrorV1::Stale)?;
            rustix::io::fcntl_dupfd_cloexec(socket, 0).map_err(std::io::Error::from)?
        };
        *self.adoption.get_mut() = Some(RetainedUnixStreamAdmissionOriginalV1::new(descriptor));
        let adoption = self
            .adoption
            .get_mut()
            .as_mut()
            .ok_or(ControllerRootFlightErrorV1::Stale)?;
        if let Err(cause) = adoption.capture_once() {
            return Err(ControllerRootFlightErrorV1::Kernel(
                match adoption.take_capture_error_once_v1() {
                    Some(original) => original,
                    None => cause,
                },
            ));
        }
        self.stream = Some(RefCell::new(adoption.take_completed_once()?));
        let stream = self
            .stream
            .as_mut()
            .ok_or(ControllerRootFlightErrorV1::Stale)?
            .get_mut();
        stream.enable_subject_reporting()?;
        self.peer = Some(
            self.profile
                .observe_original_peer(stream)
                .map_err(|_| ControllerRootFlightErrorV1::Stale)?,
        );
        self.client_nonce = Some(crate::root_nonce::fresh_root_nonce()?);
        Ok(())
    }

    fn connect_raw_once(&mut self, deadline: Instant) -> Result<(), ControllerRootFlightErrorV1> {
        require_remaining(deadline)?;
        self.raw = Some(
            rustix::net::socket_with(
                AddressFamily::UNIX,
                SocketType::STREAM,
                SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
                None,
            )
            .map_err(std::io::Error::from)?,
        );
        let socket = self
            .raw
            .as_ref()
            .ok_or(ControllerRootFlightErrorV1::Stale)?;
        let address = SocketAddrUnix::new(
            aos_sandbox_protocol::root_settlement::POLICY_AUTHORITY_FIXED_SOCKET_PATH_V2,
        )
        .map_err(std::io::Error::from)?;
        match rustix::net::connect(socket, &address) {
            Ok(()) => {}
            Err(rustix::io::Errno::INPROGRESS) => {
                wait_original_root_v1(socket.as_fd(), PollFlags::OUT, deadline)?;
                rustix::net::sockopt::socket_error(socket)
                    .map_err(std::io::Error::from)?
                    .map_err(std::io::Error::from)?;
            }
            Err(error) => return Err(std::io::Error::from(error).into()),
        }
        require_remaining(deadline)?;
        Ok(())
    }

    /// Observes the same original clock independently of transport refusal.
    ///
    /// # Errors
    /// Preserves kernel failure or refuses changed boot, reversed time or expiry.
    pub fn independent_clock(&self) -> Result<RawPairedClockSample, ControllerRootFlightErrorV1> {
        let (started, original) = self.original_data()?;
        let current = crate::kernel_clock::ordinary_kernel_pair::<ControllerRootFlightErrorV1>()?;
        original
            .validate_later_sample(current)
            .map_err(|_| ControllerRootFlightErrorV1::Stale)?;
        let deadline = original
            .boottime_nanoseconds()
            .checked_add(60_000_000_000)
            .ok_or(ControllerRootFlightErrorV1::Stale)?;
        if current.boottime_nanoseconds() >= deadline {
            return Err(ControllerRootFlightErrorV1::Stale);
        }
        require_remaining(started + MAXIMUM_FLIGHT)?;
        Ok(current)
    }

    /// Samples the original signing boundary after the same native peer checks.
    ///
    /// # Errors
    /// Refuses changed custody, kernel failure, clock discontinuity or expiry.
    pub fn signing_boundary_clock(
        &self,
    ) -> Result<RawPairedClockSample, ControllerRootFlightErrorV1> {
        self.recheck()?;
        let (started, original) = self.original_data()?;
        let current = crate::kernel_clock::ordinary_kernel_pair::<ControllerRootFlightErrorV1>()?;
        original
            .validate_later_sample(current)
            .map_err(|_| ControllerRootFlightErrorV1::Stale)?;
        if self.poisoned.get() || started.elapsed() >= MAXIMUM_FLIGHT {
            return Err(ControllerRootFlightErrorV1::Stale);
        }
        Ok(current)
    }

    /// Copies the actual native connection's original clock association.
    ///
    /// # Errors
    /// Refuses an absent original capture; this never observes another clock.
    pub fn original_data(
        &self,
    ) -> Result<(Instant, RawPairedClockSample), ControllerRootFlightErrorV1> {
        self.original.ok_or(ControllerRootFlightErrorV1::Stale)
    }

    /// Copies the entropy actually generated for this fixed connection.
    ///
    /// # Errors
    /// Refuses an incomplete actual connection or failed entropy acquisition.
    pub fn client_nonce_data(&self) -> Result<[u8; 16], ControllerRootFlightErrorV1> {
        self.client_nonce.ok_or(ControllerRootFlightErrorV1::Stale)
    }

    /// Copies this actual measured peer's configured Source identity as DATA.
    ///
    /// # Errors
    /// Refuses an incomplete native Root-peer qualification.
    pub fn source_uid_data(&self) -> Result<u32, ControllerRootFlightErrorV1> {
        Ok(self
            .peer
            .as_ref()
            .ok_or(ControllerRootFlightErrorV1::Stale)?
            .source_uid())
    }

    /// Poisons this same original without observing or adopting another owner.
    pub fn refuse(&self) {
        self.poisoned.set(true);
    }

    /// Reports the original poison marker without native entry.
    #[must_use]
    pub fn is_refused(&self) -> bool {
        self.poisoned.get()
    }

    fn stream(&self) -> Result<Ref<'_, RetainedUnixStream>, ControllerRootFlightErrorV1> {
        self.stream
            .as_ref()
            .ok_or(ControllerRootFlightErrorV1::Stale)?
            .try_borrow()
            .map_err(|_| ControllerRootFlightErrorV1::Stale)
    }

    fn stream_mut(&self) -> Result<RefMut<'_, RetainedUnixStream>, ControllerRootFlightErrorV1> {
        self.stream
            .as_ref()
            .ok_or(ControllerRootFlightErrorV1::Stale)?
            .try_borrow_mut()
            .map_err(|_| ControllerRootFlightErrorV1::Stale)
    }

    /// Rechecks the same live Root stream, profile and original absolute bound.
    ///
    /// # Errors
    /// Preserves actual stream/queue failures or refuses changed peer or age.
    pub fn recheck(&self) -> Result<(), ControllerRootFlightErrorV1> {
        let (started, _) = self.original_data()?;
        if self.poisoned.get() || started.elapsed() >= MAXIMUM_FLIGHT {
            return Err(ControllerRootFlightErrorV1::Stale);
        }
        let stream = self.stream()?;
        stream.revalidate_original()?;
        require_open_receive_queue_v1(stream.as_fd())?;
        self.peer
            .as_ref()
            .ok_or(ControllerRootFlightErrorV1::Stale)?
            .recheck_stream(&stream)
            .map_err(|_| ControllerRootFlightErrorV1::Stale)?;
        require_remaining(started + MAXIMUM_FLIGHT).map(|_| ())
    }

    /// Observes the final peer/clock after the genuine upper terminal position.
    ///
    /// This mechanical operation tolerates the original receive queue's EOF;
    /// its successful sample does not supply terminal semantic evidence.
    ///
    /// # Errors
    /// Preserves native errors or refuses changed original peer, boot or age.
    pub fn terminal_clock(&self) -> Result<RawPairedClockSample, ControllerRootFlightErrorV1> {
        let (started, original) = self.original_data()?;
        if self.poisoned.get() || started.elapsed() >= MAXIMUM_FLIGHT {
            return Err(ControllerRootFlightErrorV1::Stale);
        }
        let stream = self.stream()?;
        stream.revalidate_original()?;
        self.peer
            .as_ref()
            .ok_or(ControllerRootFlightErrorV1::Stale)?
            .recheck_stream(&stream)
            .map_err(|_| ControllerRootFlightErrorV1::Stale)?;
        let now = crate::kernel_clock::ordinary_kernel_pair::<ControllerRootFlightErrorV1>()?;
        original
            .validate_later_sample(now)
            .map_err(|_| ControllerRootFlightErrorV1::Stale)?;
        require_remaining(started + MAXIMUM_FLIGHT)?;
        Ok(now)
    }

    /// Compares a received native subject with this same actual Root peer.
    ///
    /// # Errors
    /// Refuses changed original, native subject, process or immutable profile.
    pub fn require_chunk(
        &self,
        chunk: &ControllerRootReceivedChunkV1,
    ) -> Result<(), ControllerRootFlightErrorV1> {
        self.recheck()?;
        let stream = self.stream()?;
        self.require_pending_chunk(chunk)?;
        self.peer
            .as_ref()
            .ok_or(ControllerRootFlightErrorV1::Stale)?
            .require_chunk(&stream, &chunk.subject)
            .map_err(|_| ControllerRootFlightErrorV1::Stale)?;
        // The observer consumes only this opaque original receive, after the
        // old subject frontier. Its refusal disables loans without replacing
        // the upper parser's chronologically retained semantic cause.
        self.q04_wire
            .try_borrow_mut()
            .map_err(|_| ControllerRootFlightErrorV1::Stale)?
            .observe_received(
                chunk.payload(),
                self.client_nonce_data()?,
                self.source_uid_data()?,
            );
        self.pending_sequence.set(None);
        Ok(())
    }

    /// Compares the real final subject without requiring an open receive queue.
    ///
    /// # Errors
    /// Refuses changed original peer or native subject identity.
    pub fn require_terminal_chunk(
        &self,
        chunk: &ControllerRootReceivedChunkV1,
    ) -> Result<(), ControllerRootFlightErrorV1> {
        let stream = self.stream()?;
        self.require_pending_chunk(chunk)?;
        self.peer
            .as_ref()
            .ok_or(ControllerRootFlightErrorV1::Stale)?
            .require_chunk(&stream, &chunk.subject)
            .map_err(|_| ControllerRootFlightErrorV1::Stale)?;
        // The observer consumes only this opaque original receive, after the
        // old subject frontier. Its refusal disables loans without replacing
        // the upper parser's chronologically retained semantic cause.
        self.q04_wire
            .try_borrow_mut()
            .map_err(|_| ControllerRootFlightErrorV1::Stale)?
            .observe_received(
                chunk.payload(),
                self.client_nonce_data()?,
                self.source_uid_data()?,
            );
        self.pending_sequence.set(None);
        Ok(())
    }

    /// Parks one actual retaining receive before upper classification and posts.
    ///
    /// # Errors
    /// Refuses an unavailable original borrow; native receive errors stay in
    /// the actual destination and are not projected before upper bookends.
    pub fn receive_chunk_into(
        &self,
        maximum: usize,
        destination: &mut Option<
            Result<
                ControllerRootReceivedChunkV1,
                aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1,
            >,
        >,
    ) -> Result<(), ControllerRootFlightErrorV1> {
        self.require_receive_destination()?;
        let original = self.client_nonce_data()?;
        let sequence = self.received_sequence.get();
        *destination = Some(
            self.stream_mut()?
                .try_receive_subject_chunk_retaining(maximum)
                .map(|subject| {
                    self.pending_sequence.set(Some(sequence));
                    self.received_sequence.set(sequence + 1);
                    ControllerRootReceivedChunkV1 {
                        original,
                        sequence,
                        subject,
                    }
                }),
        );
        Ok(())
    }

    /// Receives the existing ordinary nonretaining fragment without a new role.
    ///
    /// # Errors
    /// Preserves the actual subject error or refuses an unavailable original.
    pub fn receive_ordinary_chunk(
        &self,
        maximum: usize,
    ) -> Result<ControllerRootReceivedChunkV1, ControllerRootFlightErrorV1> {
        self.require_receive_destination()?;
        let original = self.client_nonce_data()?;
        let sequence = self.received_sequence.get();
        let subject = self.stream_mut()?.try_receive_subject_chunk(maximum)?;
        self.pending_sequence.set(Some(sequence));
        self.received_sequence.set(sequence + 1);
        Ok(ControllerRootReceivedChunkV1 {
            original,
            sequence,
            subject,
        })
    }

    fn require_receive_destination(&self) -> Result<(), ControllerRootFlightErrorV1> {
        if self.pending_sequence.get().is_some() || self.received_sequence.get() == u64::MAX {
            return Err(ControllerRootFlightErrorV1::Stale);
        }
        Ok(())
    }

    fn require_pending_chunk(
        &self,
        chunk: &ControllerRootReceivedChunkV1,
    ) -> Result<(), ControllerRootFlightErrorV1> {
        if chunk.original != self.client_nonce_data()?
            || self.pending_sequence.get() != Some(chunk.sequence)
        {
            return Err(ControllerRootFlightErrorV1::Stale);
        }
        Ok(())
    }

    /// Parks the actual nonblocking send before any upper post or classification.
    ///
    /// # Errors
    /// Refuses only an unavailable original borrow; the actual send errno stays
    /// in the caller's resident result destination.
    pub fn send_into(
        &self,
        bytes: &[u8],
        destination: &mut Option<rustix::io::Result<usize>>,
    ) -> Result<(), ControllerRootFlightErrorV1> {
        let stream = self.stream()?;
        *destination = Some(rustix::net::send(
            stream.as_fd(),
            bytes,
            rustix::net::SendFlags::DONTWAIT | rustix::net::SendFlags::NOSIGNAL,
        ));
        if let Some(Ok(sent)) = destination.as_ref() {
            self.q04_wire
                .try_borrow_mut()
                .map_err(|_| ControllerRootFlightErrorV1::Stale)?
                .observe_sent(
                    bytes
                        .get(..*sent)
                        .ok_or(ControllerRootFlightErrorV1::Stale)?,
                    self.client_nonce_data()?,
                );
        }
        Ok(())
    }

    /// Parks the same native poll while semantic wait posts remain above return.
    ///
    /// # Errors
    /// Refuses only an unavailable original borrow; native poll errors and flags
    /// remain in the two actual caller-owned destinations.
    pub fn poll_into(
        &self,
        interest: PollFlags,
        timeout: &Timespec,
        result: &mut Option<rustix::io::Result<usize>>,
        flags: &mut Option<PollFlags>,
    ) -> Result<(), ControllerRootFlightErrorV1> {
        let stream = self.stream()?;
        crate::fixed_stream_readiness::poll_fixed_stream_once_v1(
            stream.as_fd(),
            interest,
            timeout,
            result,
            flags,
        );
        Ok(())
    }

    /// Parks the actual terminal peek before independent upper named checks.
    ///
    /// # Errors
    /// Refuses only an unavailable original borrow; the actual errno remains
    /// in the original invocation's retained terminal result.
    pub fn peek_shutdown_into(
        &self,
        byte: &mut [u8; 1],
        destination: &mut Option<rustix::io::Result<usize>>,
    ) -> Result<(), ControllerRootFlightErrorV1> {
        let stream = self.stream()?;
        *destination = Some(
            rustix::net::recv(
                stream.as_fd(),
                &mut *byte,
                rustix::net::RecvFlags::PEEK | rustix::net::RecvFlags::DONTWAIT,
            )
            .map(|(_, received)| received),
        );
        if matches!(destination.as_ref(), Some(Ok(0))) {
            self.shutdown_observed.set(true);
        }
        Ok(())
    }

    /// Shuts down this same original without releasing its qualified custody.
    ///
    /// # Errors
    /// Preserves the actual shutdown failure or unavailable original borrow.
    pub fn shutdown(&self) -> Result<(), ControllerRootFlightErrorV1> {
        let primary = if let Some(stream) = &self.stream {
            let stream = stream
                .try_borrow()
                .map_err(|_| ControllerRootFlightErrorV1::Stale)?;
            rustix::net::shutdown(stream.as_fd(), rustix::net::Shutdown::Both)
                .map_err(std::io::Error::from)
                .map_err(ControllerRootFlightErrorV1::Transport)
        } else if let Some(raw) = &self.raw {
            rustix::net::shutdown(raw, rustix::net::Shutdown::Both)
                .map_err(std::io::Error::from)
                .map_err(ControllerRootFlightErrorV1::Transport)
        } else {
            Ok(())
        };
        // This independently owed failed-adoption post runs even if the raw
        // original shutdown failed; its prefix and actual outcome stay held.
        let mut admission = self
            .adoption
            .try_borrow_mut()
            .map_err(|_| ControllerRootFlightErrorV1::Stale)?;
        let secondary = if let Some(adoption) = admission.as_mut() {
            adoption.finish_negative_shutdown_once();
            adoption
                .failure()
                .and_then(|cause| cause.downcast_ref::<rustix::io::Errno>())
                .copied()
                .map_or(Ok(()), |error| {
                    Err(ControllerRootFlightErrorV1::Transport(
                        std::io::Error::from(error),
                    ))
                })
        } else {
            Ok(())
        };
        primary?;
        secondary
    }
}

impl Drop for ControllerRootFlightOriginalV1<'_> {
    fn drop(&mut self) {
        if let Some(stream) = &mut self.stream {
            let _shutdown =
                rustix::net::shutdown(stream.get_mut().as_fd(), rustix::net::Shutdown::Both);
        } else if let Some(raw) = &self.raw {
            let _shutdown = rustix::net::shutdown(raw, rustix::net::Shutdown::Both);
        }
        if let Some(adoption) = self.adoption.get_mut().as_mut() {
            adoption.finish_negative_shutdown_once();
        }
    }
}

/// Observes whether the same live stream receive queue has already shut down.
///
/// The descriptor remains borrowed; this observation creates no peer or role.
///
/// # Errors
/// Refuses shutdown/error readiness or preserves the actual poll error.
pub fn require_open_receive_queue_v1(
    descriptor: std::os::fd::BorrowedFd<'_>,
) -> Result<(), ControllerRootFlightErrorV1> {
    let mut result = None;
    let mut flags = None;
    crate::fixed_stream_readiness::poll_fixed_stream_once_v1(
        descriptor,
        PollFlags::RDHUP,
        &Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        &mut result,
        &mut flags,
    );
    result
        .ok_or(ControllerRootFlightErrorV1::Stale)?
        .map_err(std::io::Error::from)?;
    if flags
        .ok_or(ControllerRootFlightErrorV1::Stale)?
        .intersects(PollFlags::RDHUP | PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL)
    {
        return Err(ControllerRootFlightErrorV1::Stale);
    }
    Ok(())
}

// Only these pre-admission failures can discard the unaccepted raw socket.
fn connection_not_admitted(connected: &Result<(), ControllerRootFlightErrorV1>) -> bool {
    matches!(connected,
        Err(ControllerRootFlightErrorV1::Transport(error))
            if matches!(error.raw_os_error(), Some(code)
                if code == rustix::io::Errno::NOENT.raw_os_error()
                    || code == rustix::io::Errno::CONNREFUSED.raw_os_error()))
}

fn require_remaining(deadline: Instant) -> Result<Duration, ControllerRootFlightErrorV1> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(ControllerRootFlightErrorV1::Stale)
}

// The same actual ordinary wait has no semantic callbacks. Resource-Global
// waits remain upper and retain their own original owner/clock post vectors.
/// Waits on the same borrowed native endpoint within its existing deadline.
///
/// This native-only ordinary wait grants no role and accepts no semantic hooks.
///
/// # Errors
/// Preserves native poll errors and refuses expiry or invalid readiness.
pub fn wait_original_root_v1(
    descriptor: std::os::fd::BorrowedFd<'_>,
    interest: PollFlags,
    deadline: Instant,
) -> Result<(), ControllerRootFlightErrorV1> {
    loop {
        let remaining = require_remaining(deadline)?.min(Duration::from_millis(100));
        let timeout = Timespec {
            tv_sec: 0,
            tv_nsec: i64::from(remaining.subsec_nanos()),
        };
        let mut result = None;
        let mut flags = None;
        crate::fixed_stream_readiness::poll_fixed_stream_once_v1(
            descriptor,
            interest,
            &timeout,
            &mut result,
            &mut flags,
        );
        match result {
            Some(Ok(_)) => {}
            Some(Err(rustix::io::Errno::INTR)) => continue,
            Some(Err(error)) => return Err(std::io::Error::from(error).into()),
            None => return Err(ControllerRootFlightErrorV1::Stale),
        }
        require_remaining(deadline)?;
        let flags = flags.ok_or(ControllerRootFlightErrorV1::Stale)?;
        if flags.intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL) {
            return Err(ControllerRootFlightErrorV1::Stale);
        }
        if flags.intersects(interest) {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd as _;
    use std::os::unix::net::UnixStream;

    #[test]
    fn an_elapsed_deadline_never_admits_io() {
        let (socket, _peer) = UnixStream::pair().unwrap();
        let deadline = Instant::now() - Duration::from_millis(1);

        assert!(matches!(
            require_remaining(deadline),
            Err(ControllerRootFlightErrorV1::Stale),
        ));
        assert!(matches!(
            wait_original_root_v1(socket.as_fd(), PollFlags::OUT, deadline),
            Err(ControllerRootFlightErrorV1::Stale),
        ));

        // The same real endpoint is writable; expiry alone refused the wait.
        assert!(
            wait_original_root_v1(
                socket.as_fd(),
                PollFlags::OUT,
                Instant::now() + Duration::from_secs(5),
            )
            .is_ok()
        );
    }

    #[test]
    fn only_unadmitted_absence_or_refusal_allows_connection_retry() {
        for errno in [rustix::io::Errno::NOENT, rustix::io::Errno::CONNREFUSED] {
            let returned = Err(ControllerRootFlightErrorV1::Transport(std::io::Error::from(
                errno,
            )));
            assert!(connection_not_admitted(&returned));
        }
        for errno in [
            rustix::io::Errno::AGAIN,
            rustix::io::Errno::TIMEDOUT,
            rustix::io::Errno::INTR,
            rustix::io::Errno::CONNRESET,
            rustix::io::Errno::ACCESS,
        ] {
            let returned = Err(ControllerRootFlightErrorV1::Transport(std::io::Error::from(
                errno,
            )));
            assert!(!connection_not_admitted(&returned));
        }
        assert!(!connection_not_admitted(&Err(
            ControllerRootFlightErrorV1::Stale,
        )));
        assert!(!connection_not_admitted(&Ok(())));
    }
}
