//! Deadline-bounded record exchange for record-subject services.
//!
//! Plain, closed descriptor-reply, and provisioned worker adapters share one
//! retry engine. Its private profiles preserve each carrier's interruption and
//! clock ordering. Worker records provision capacity first and wait after both
//! backpressure and interrupted attempts; one fixed receive profile rejects
//! io_uring rights before its success bookend.
//!
//! These operations return transport data only; peers, descriptor roles,
//! authority, currentness, acknowledgements, framing, and worker quiescence
//! remain caller-owned. Received records retain their original subject and
//! complete ordered descriptor table until returned or dropped on failure.

use std::os::fd::{AsFd, BorrowedFd};
use std::time::Duration;

use rustix::event::{PollFd, PollFlags, Timespec, poll};

use super::descriptor_subject::{
    DescriptorSubjectSocket, ReceivedDescriptorRecord, WorkerObserverRecordKindV1,
};
use super::{ReceivedRecord, RecordSubjectListener, SeqpacketError, SeqpacketSocket};

/// Reports a bounded exchange failure without assigning service policy.
#[derive(Debug, thiserror::Error)]
pub enum BoundedRecordError {
    /// The record carrier failed.
    #[error(transparent)]
    Transport(#[from] SeqpacketError),
    /// Polling failed.
    #[error(transparent)]
    Io(#[from] rustix::io::Errno),
    /// Boot time was invalid or the exchange deadline expired.
    #[error("bounded record exchange deadline expired or clock was invalid")]
    Clock,
}

/// Reports a provisioned worker exchange failure with its original owned cause.
#[derive(Debug, thiserror::Error)]
pub enum WorkerRecordError {
    /// The native record carrier or capacity provision failed.
    #[error(transparent)]
    Transport(#[from] SeqpacketError),
    /// Readiness polling failed.
    #[error(transparent)]
    Poll(#[from] rustix::io::Errno),
    /// The fixed received-descriptor inspection failed.
    #[error(transparent)]
    Linux(#[from] aos_linux_descriptors::Error),
    /// Clock conversion, timeout conversion, or the deadline check failed.
    #[error(transparent)]
    Clock(#[from] WorkerRecordClockError),
}

/// Identifies a worker record clock or deadline failure without service policy.
#[derive(Debug, thiserror::Error)]
pub enum WorkerRecordClockError {
    /// Boot time seconds could not be represented as an unsigned integer.
    #[error("CLOCK_BOOTTIME seconds are invalid")]
    InvalidSeconds,
    /// Boot time nanoseconds could not be represented as an unsigned integer.
    #[error("CLOCK_BOOTTIME nanoseconds are invalid")]
    InvalidNanoseconds,
    /// Converting the sampled boot time to nanoseconds overflowed.
    #[error("CLOCK_BOOTTIME overflowed")]
    Overflow,
    /// The whole-transfer deadline elapsed or readiness timed out.
    #[error("worker record transfer deadline elapsed")]
    Expired,
    /// The remaining duration could not be represented as a polling timeout.
    #[error("worker record transfer deadline is invalid")]
    InvalidTimeout,
}

/// Sends one worker record and its exact borrowed descriptor table before a deadline.
///
/// Capacity is provisioned once before sampling `CLOCK_BOOTTIME`. An empty
/// table uses the native plain sender; a nonempty table uses the native bounded
/// descriptor sender. Backpressure and interrupted attempts both wait for
/// readiness. The call borrows the original socket and rights throughout the
/// exchange and checks the deadline again after atomic success.
///
/// # Errors
///
/// Returns [`WorkerRecordError`] for capacity, native transport, polling, clock,
/// or deadline failure. Native fatal-outcome disposal remains carrier-owned.
pub fn send_provisioned_worker_record(
    socket: &mut DescriptorSubjectSocket,
    payload: &[u8],
    descriptors: &[BorrowedFd<'_>],
    deadline: u64,
) -> Result<(), WorkerRecordError> {
    socket.provision_packet_capacity(payload.len())?;
    exchange_record(&WorkerProfile, socket, PollFlags::OUT, deadline, |socket| {
        if descriptors.is_empty() {
            socket.send(payload)
        } else {
            socket.send_with_descriptors(payload, descriptors)
        }
    })
}

/// Receives one complete worker record with an exact descriptor count before a deadline.
///
/// Capacity precedes the first clock check; descriptor-count validation remains
/// inside the native receive attempt. Backpressure and interruption both wait
/// for readiness. A late success drops the complete received record, including
/// its original kernel subject and ordered owned descriptor table.
///
/// # Errors
///
/// Returns [`WorkerRecordError`] for capacity, native transport, polling, clock,
/// or deadline failure. Peer authentication and descriptor roles remain upper
/// protocol responsibilities.
pub fn receive_provisioned_worker_record(
    socket: &mut DescriptorSubjectSocket,
    maximum: usize,
    expected_descriptors: usize,
    deadline: u64,
) -> Result<ReceivedDescriptorRecord, WorkerRecordError> {
    socket.provision_packet_capacity(maximum)?;
    exchange_record(&WorkerProfile, socket, PollFlags::IN, deadline, |socket| {
        socket.receive(maximum, expected_descriptors)
    })
}

/// Receives one worker record and rejects io_uring rights before its success clock check.
///
/// Uses the same capacity, exact-count, retry, and custody rules as
/// [`receive_provisioned_worker_record`]. Each received right is inspected in
/// its original table order before sampling the final clock. Inspection failure
/// therefore precedes competing late expiry and drops the complete record.
///
/// # Errors
///
/// Returns [`WorkerRecordError`] for the underlying exchange, unavailable
/// descriptor inspection, or a forbidden io_uring descriptor. This mechanical
/// restriction assigns no descriptor role and grants no worker authority.
pub fn receive_provisioned_worker_record_without_io_uring(
    socket: &mut DescriptorSubjectSocket,
    maximum: usize,
    expected_descriptors: usize,
    deadline: u64,
) -> Result<ReceivedDescriptorRecord, WorkerRecordError> {
    socket.provision_packet_capacity(maximum)?;
    exchange_record(
        &InspectedWorkerProfile,
        socket,
        PollFlags::IN,
        deadline,
        |socket| socket.receive(maximum, expected_descriptors),
    )
}

/// Retains a fixed worker receive's first failure and all outstanding custody.
///
/// Fatal native errors keep the complete original receive attempt. A record
/// received after the deadline stays owned here alongside its deadline error;
/// the caller may inspect it but cannot project the failure to successful work.
pub struct RetainedWorkerReceiveErrorV1<Record> {
    attempt: WorkerObserverReceiveAttemptV1<Record>,
}

/// Owns the fixed descriptor-channel worker receive's negative disposition.
pub type WorkerObserverReceiveErrorV1 = RetainedWorkerReceiveErrorV1<ReceivedDescriptorRecord>;

/// Owns the fixed zero-rights ZFS receive's negative disposition.
pub type ZfsWorkerReceiveErrorV1 = RetainedWorkerReceiveErrorV1<ReceivedRecord>;

#[derive(Debug)]
struct WorkerObserverReceiveAttemptV1<Record> {
    provision: Option<Result<(), SeqpacketError>>,
    before: Option<Result<(), WorkerRecordError>>,
    returned: Option<Result<Record, super::RetainedSeqpacketReceiveErrorV1>>,
    after: Option<Result<(), WorkerRecordError>>,
    wait: Option<Result<(), WorkerRecordError>>,
    first: WorkerObserverFailureSite,
}

#[derive(Debug)]
enum WorkerObserverFailureSite {
    Provision,
    Before,
    Receive,
    After,
    Wait,
}

impl<Record> RetainedWorkerReceiveErrorV1<Record> {
    /// Borrows the actual record retained after a late native success.
    #[must_use]
    pub fn received_record(&self) -> Option<&Record> {
        self.attempt.returned.as_ref()?.as_ref().ok()
    }

    /// Borrows the first native, capacity, poll or deadline failure.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.attempt.first {
            WorkerObserverFailureSite::Provision =>
                self.attempt.provision.as_ref()?.as_ref().err().map(|error| error as _),
            WorkerObserverFailureSite::Before =>
                self.attempt.before.as_ref()?.as_ref().err().map(|error| error as _),
            WorkerObserverFailureSite::Receive =>
                self.attempt.returned.as_ref()?.as_ref().err().map(|error| error as _),
            WorkerObserverFailureSite::After =>
                self.attempt.after.as_ref()?.as_ref().err().map(|error| error as _),
            WorkerObserverFailureSite::Wait =>
                self.attempt.wait.as_ref()?.as_ref().err().map(|error| error as _),
        }
    }
}

impl<Record> std::fmt::Debug for RetainedWorkerReceiveErrorV1<Record> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("WorkerObserverReceiveErrorV1")
            .field("first", &self.attempt.first)
            .field("late_record_retained", &self.received_record().is_some())
            .finish_non_exhaustive()
    }
}

impl<Record> std::fmt::Display for RetainedWorkerReceiveErrorV1<Record> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.failure() {
            Some(error) => write!(formatter, "fixed worker observer receive refused: {error}"),
            None => formatter.write_str("fixed worker observer receive refused"),
        }
    }
}

impl<Record> std::error::Error for RetainedWorkerReceiveErrorV1<Record> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.failure()
    }
}

/// Receives one fixed worker observer record while retaining failed originals.
///
/// Capacity 4096 precedes the first clock. Both proven nonconsuming EAGAIN and
/// EINTR wait before retrying, using the existing worker clock/poll mechanics.
/// Only those completed no-acquisition attempts may be disposed before reuse of
/// the same prepaid peak. Fatal/ambiguous attempts and late successful records
/// remain owned in the error. A late deadline can leave the channel connected:
/// the application owner must retain the error and close its failed interval
/// before any further receive, rather than project the record to successful work.
///
/// # Errors
/// Returns an owning [`WorkerObserverReceiveErrorV1`] for capacity, native
/// transport, subject/table, wait, clock or late-success refusal.
pub fn receive_worker_observer_record_v1(
    socket: &mut DescriptorSubjectSocket,
    kind: WorkerObserverRecordKindV1,
    deadline: u64,
) -> Result<ReceivedDescriptorRecord, WorkerObserverReceiveErrorV1> {
    receive_fixed_worker_record(socket, WorkerObserverProfile(kind), deadline)
}

/// Selects one fixed zero-rights ZFS worker record without application authority.
#[derive(Clone, Copy, Debug)]
pub enum ZfsWorkerRecordKindV1 {
    /// Existing READY ceiling.
    Ready,
    /// Existing fixed Storage worker request ceiling.
    Request,
    /// Existing fixed Storage worker acknowledgement ceiling.
    Acknowledgement,
    /// Existing mutation/atomic stdout+stderr result ceiling.
    MutationResult,
    /// Existing physical observation result ceiling.
    ObservationResult,
    /// Closed version-three Capture created-report width on the same worker.
    CaptureCreatedV3,
}

impl ZfsWorkerRecordKindV1 {
    /// Returns this existing fixed wire ceiling as passive transport DATA.
    #[must_use]
    pub const fn maximum_payload_bytes(self) -> usize {
        match self {
            Self::Ready => 4096,
            Self::Request => 24 * 1024,
            Self::Acknowledgement => 10,
            Self::MutationResult => 132 * 1024,
            Self::ObservationResult => 52,
            Self::CaptureCreatedV3 => 226,
        }
    }
}

/// Receives one fixed ZFS worker record using the same retained retry engine.
///
/// The ordinary ZFS receiver does not resize socket queues. This adapter
/// likewise retains their installed capacity and uses the fixed logical bound;
/// it does not shrink a large existing reply queue to the observer's4096bytes.
///
/// # Errors
/// Owns capacity/native/subject/wait/deadline failures and late records.
pub fn receive_zfs_worker_record_v1(
    socket: &mut SeqpacketSocket,
    kind: ZfsWorkerRecordKindV1,
    deadline: u64,
) -> Result<ReceivedRecord, ZfsWorkerReceiveErrorV1> {
    receive_fixed_worker_record(socket, ZfsWorkerProfile(kind), deadline)
}

/// Receives the fixed two-pipe Capture reply through the existing retry engine.
///
/// # Errors
/// Retains both actual native samples and any late successful descriptor table.
pub fn receive_capture_worker_pipes_v3(
    socket: &mut SeqpacketSocket, deadline: u64,
) -> Result<ReceivedDescriptorRecord, WorkerObserverReceiveErrorV1> {
    receive_fixed_worker_record(socket, CapturePipesProfileV3, deadline)
}

struct CapturePipesProfileV3;

impl FixedWorkerReceiveProfile<SeqpacketSocket, ReceivedDescriptorRecord> for CapturePipesProfileV3 {
    fn provision(&self, _: &SeqpacketSocket) -> Option<Result<(), SeqpacketError>> { None }

    fn receive(&self, socket: &mut SeqpacketSocket)
        -> Result<ReceivedDescriptorRecord, super::RetainedSeqpacketReceiveErrorV1>
    {
        socket.receive_capture_worker_pipes_retaining_v3()
    }

    fn wait(&self, socket: &SeqpacketSocket, deadline: u64) -> Result<(), WorkerRecordError> {
        socket.as_fd().map_err(WorkerRecordError::from)
            .and_then(|fd| wait_worker_before(&NativeWorkerWait, fd, PollFlags::IN, deadline))
    }
}

// These closed native profiles select the common engine. No public callback,
// arbitrary record bound, parser or worker-service authority is exposed.
trait FixedWorkerReceiveProfile<Socket, Record> {
    fn after_receive(&self, deadline: u64) -> Result<(), WorkerRecordError> {
        check_worker_deadline(deadline)
    }
    fn provision(&self, socket: &Socket) -> Option<Result<(), SeqpacketError>>;
    fn receive(&self, socket: &mut Socket)
        -> Result<Record, super::RetainedSeqpacketReceiveErrorV1>;
    fn wait(&self, socket: &Socket, deadline: u64) -> Result<(), WorkerRecordError>;
}

struct WorkerObserverProfile(WorkerObserverRecordKindV1);

impl FixedWorkerReceiveProfile<DescriptorSubjectSocket, ReceivedDescriptorRecord> for WorkerObserverProfile {
    fn provision(&self, socket: &DescriptorSubjectSocket) -> Option<Result<(), SeqpacketError>> {
        Some(socket.provision_packet_capacity(self.0.maximum_payload_bytes_v1()))
    }

    fn receive(&self, socket: &mut DescriptorSubjectSocket)
        -> Result<ReceivedDescriptorRecord, super::RetainedSeqpacketReceiveErrorV1>
    {
        socket.receive_worker_observer_retaining_v1(self.0)
    }

    fn wait(&self, socket: &DescriptorSubjectSocket, deadline: u64) -> Result<(), WorkerRecordError> {
        socket.as_fd().map_err(WorkerRecordError::from)
            .and_then(|fd| wait_worker_before(&NativeWorkerWait, fd, PollFlags::IN, deadline))
    }
}

struct ZfsWorkerProfile(ZfsWorkerRecordKindV1);

impl FixedWorkerReceiveProfile<SeqpacketSocket, ReceivedRecord> for ZfsWorkerProfile {
    fn provision(&self, _socket: &SeqpacketSocket) -> Option<Result<(), SeqpacketError>> {
        None
    }

    fn receive(&self, socket: &mut SeqpacketSocket)
        -> Result<ReceivedRecord, super::RetainedSeqpacketReceiveErrorV1>
    {
        socket.receive_zfs_worker_retaining_v1(self.0.maximum_payload_bytes())
    }

    fn wait(&self, socket: &SeqpacketSocket, deadline: u64) -> Result<(), WorkerRecordError> {
        socket.as_fd().map_err(WorkerRecordError::from)
            .and_then(|fd| wait_worker_before(&NativeWorkerWait, fd, PollFlags::IN, deadline))
    }
}

fn receive_fixed_worker_record<Socket, Record, Profile: FixedWorkerReceiveProfile<Socket, Record>>(
    socket: &mut Socket,
    profile: Profile,
    deadline: u64,
) -> Result<Record, RetainedWorkerReceiveErrorV1<Record>> {
    let mut attempt = WorkerObserverReceiveAttemptV1 {
        provision: profile.provision(socket),
        before: None,
        returned: None,
        after: None,
        wait: None,
        first: WorkerObserverFailureSite::Provision,
    };
    if matches!(attempt.provision, Some(Err(_))) {
        return Err(RetainedWorkerReceiveErrorV1 { attempt });
    }

    loop {
        attempt.before = Some(check_worker_deadline(deadline));
        if !matches!(attempt.before, Some(Ok(()))) {
            attempt.first = WorkerObserverFailureSite::Before;
            return Err(RetainedWorkerReceiveErrorV1 { attempt });
        }
        attempt.returned = Some(profile.receive(socket));
        match attempt.returned.as_ref() {
            Some(Ok(_)) => {
                attempt.after = Some(profile.after_receive(deadline));
                if !matches!(attempt.after, Some(Ok(()))) {
                    attempt.first = WorkerObserverFailureSite::After;
                    return Err(RetainedWorkerReceiveErrorV1 { attempt });
                }
                // Only the positive completion transfers the actual record.
                return match attempt.returned.take() {
                    Some(Ok(record)) => Ok(record),
                    other => {
                        // Preserve unexpected internal state and fail closed;
                        // this branch cannot turn a missing result into work.
                        attempt.returned = other;
                        attempt.first = WorkerObserverFailureSite::Receive;
                        Err(RetainedWorkerReceiveErrorV1 { attempt })
                    }
                };
            }
            Some(Err(error)) if error.is_nonconsuming_would_block()
                || error.is_nonconsuming_interrupted() => {}
            _ => {
                attempt.first = WorkerObserverFailureSite::Receive;
                return Err(RetainedWorkerReceiveErrorV1 { attempt });
            }
        }

        // Keep the exact nonconsuming native result through its readiness
        // wait too. A failed wait retains both observations; only a complete
        // positive wait can precede disposal/reuse of this actual peak.
        attempt.wait = Some(profile.wait(socket, deadline));
        if !matches!(attempt.wait, Some(Ok(()))) {
            attempt.first = WorkerObserverFailureSite::Wait;
            return Err(RetainedWorkerReceiveErrorV1 { attempt });
        }
        // The lower proof requires !raw.received for every native sample and
        // complete original posts. No record or ancillary acquisition is being
        // disposed, and the positive wait leaves no independent later debt.
        drop(attempt.returned.take());
        drop(attempt.before.take());
        drop(attempt.wait.take());
    }
}

/// Returns fixed retained worker-deadline wrapper obligations as comparison DATA.
///
/// This supplements the actual strict receiver geometry with its complete
/// owning failure/result slots and existing native wait/clock stack. It grants
/// no service payment, receiving original or worker authority.
#[must_use]
pub fn worker_observer_record_obligations_v1() -> (usize, usize) {
    let (bytes, files) = DescriptorSubjectSocket::worker_observer_receive_obligations_v1();
    let wrapper = std::mem::size_of::<WorkerObserverReceiveAttemptV1<ReceivedDescriptorRecord>>()
        + std::mem::size_of::<Result<ReceivedDescriptorRecord, WorkerObserverReceiveErrorV1>>()
        + std::mem::size_of::<[PollFd<'_>; 1]>()
        + 2 * std::mem::size_of::<Timespec>()
        + std::mem::size_of::<Duration>()
        + 4 * std::mem::size_of::<u64>();
    (bytes + wrapper, files)
}

/// Prices a fixed descriptor worker receive through the same retaining engine.
#[must_use]
pub fn descriptor_worker_record_obligations_v1(
    kind: WorkerObserverRecordKindV1,
) -> Option<(usize, usize, usize)> {
    let (bytes, files) = DescriptorSubjectSocket::worker_descriptor_receive_obligations_v1(kind);
    let old = worker_observer_record_obligations_v1().0;
    let raw = DescriptorSubjectSocket::worker_observer_receive_obligations_v1().0;
    let wrapper = old.checked_sub(raw)?;
    // Six bounded attempt fields, four wait/clock temporaries and the native
    // wrapper/result namespaces supplement the actual shared raw census.
    let cells = DescriptorSubjectSocket::worker_descriptor_receive_metadata_cells_v1()?
        .checked_add(6 + 4 + 2)?;
    Some((bytes.checked_add(wrapper)?, files, cells))
}

/// Returns actual fixed ZFS receive reservoir and FD comparison obligations.
#[must_use]
pub fn zfs_worker_record_obligations_v1(kind: ZfsWorkerRecordKindV1) -> Option<(usize, usize)> {
    let (bytes, files) = SeqpacketSocket::zfs_worker_receive_obligations_v1(kind.maximum_payload_bytes())?;
    let wrapper = std::mem::size_of::<WorkerObserverReceiveAttemptV1<ReceivedRecord>>()
        + std::mem::size_of::<Result<ReceivedRecord, ZfsWorkerReceiveErrorV1>>()
        + std::mem::size_of::<[PollFd<'_>; 1]>()
        + 2 * std::mem::size_of::<Timespec>()
        + std::mem::size_of::<Duration>()
        + 4 * std::mem::size_of::<u64>();
    Some((bytes.checked_add(wrapper)?, files))
}

/// Waits once for the already-owned Capture cancellation listener.
///
/// This is only standing ingress readiness. It establishes no clock bound,
/// connection identity, Stop permission or resource disposal. The caller keeps
/// its continuously occupied original and retains this actual wait result.
///
/// # Errors
/// Returns the existing readiness primitive's actual native polling failure.
pub fn wait_capture_stop_listener_v4(
    listener: &RecordSubjectListener,
) -> Result<(), BoundedRecordError> {
    wait_unbounded(listener.as_fd(), PollFlags::IN)
}

/// Returns the fixed native standing-wait frame without acquiring descriptors.
#[must_use]
pub fn capture_stop_listener_wait_bytes_v4() -> Option<usize> {
    std::mem::size_of::<[PollFd<'_>; 1]>()
        .checked_add(std::mem::size_of::<Result<usize, rustix::io::Errno>>())
}

/// Waits for one checked connection, rejecting a stale queued child.
///
/// # Errors
///
/// Returns [`BoundedRecordError`] for listener or polling failure.
pub fn accept_connection(
    listener: &mut RecordSubjectListener,
) -> Result<Option<SeqpacketSocket>, BoundedRecordError> {
    loop {
        listener.validate_current()?;
        match listener.accept() {
            Ok(connection) => return Ok(Some(connection)),
            Err(SeqpacketError::WouldBlock) => wait_unbounded(listener.as_fd(), PollFlags::IN)?,
            Err(SeqpacketError::Interrupted) => {}
            // A queued child may predate the listener's identity options.
            Err(SeqpacketError::Kernel(aos_linux_descriptors::Error::InvalidInput {
                field: "record subject options",
                ..
            })) => return Ok(None),
            Err(error) => return Err(error.into()),
        }
    }
}

/// Receives one complete record before a `CLOCK_BOOTTIME` deadline.
///
/// # Errors
///
/// Returns [`BoundedRecordError`] for transport, polling, or deadline failure.
pub fn receive(
    socket: &mut SeqpacketSocket,
    maximum_bytes: usize,
    deadline: u64,
) -> Result<ReceivedRecord, BoundedRecordError> {
    record_before(socket, PollFlags::IN, deadline, |socket| {
        socket.receive(maximum_bytes)
    })
}

/// Sends one complete record before a `CLOCK_BOOTTIME` deadline.
///
/// # Errors
///
/// Returns [`BoundedRecordError`] for transport, polling, or deadline failure.
pub fn send(
    socket: &mut SeqpacketSocket,
    payload: &[u8],
    deadline: u64,
) -> Result<(), BoundedRecordError> {
    record_before(socket, PollFlags::OUT, deadline, |socket| {
        socket.send(payload)
    })
}

/// Sends one descriptor-channel record without transferring any descriptors.
///
/// The adapter uses the existing non-retaining sender. It does not retry a
/// fatal or consumed outcome, authenticate a peer, or establish delivery debt.
///
/// # Errors
///
/// Returns [`BoundedRecordError`] for transport, polling, or deadline failure.
pub fn send_descriptor_record(
    socket: &mut DescriptorSubjectSocket,
    payload: &[u8],
    deadline: u64,
) -> Result<(), BoundedRecordError> {
    record_before(socket, PollFlags::OUT, deadline, |socket| {
        socket.send(payload)
    })
}

/// Receives one descriptor-channel record with an exact zero-descriptor table.
///
/// The kernel-nominated subject remains untrusted application evidence. Fatal
/// ancillary failures keep the existing receiver's descriptor-disposal policy.
///
/// # Errors
///
/// Returns [`BoundedRecordError`] for transport, polling, or deadline failure.
pub fn receive_zero_descriptors(
    socket: &mut DescriptorSubjectSocket,
    maximum_bytes: usize,
    deadline: u64,
) -> Result<ReceivedDescriptorRecord, BoundedRecordError> {
    record_before(socket, PollFlags::IN, deadline, |socket| {
        socket.receive(maximum_bytes, 0)
    })
}

/// Receives one closed mount-scope reply with zero or five descriptors.
///
/// This adapter preserves the existing mount-scope ancillary parser. It does
/// not validate descriptor roles, authenticate Host, or authorize a mount.
///
/// # Errors
///
/// Returns [`BoundedRecordError`] for transport, polling, or deadline failure.
pub fn receive_mount_scope_reply(
    socket: &mut DescriptorSubjectSocket,
    maximum_bytes: usize,
    deadline: u64,
) -> Result<ReceivedDescriptorRecord, BoundedRecordError> {
    record_before(socket, PollFlags::IN, deadline, |socket| {
        socket.receive_mount_scope_reply(maximum_bytes)
    })
}

// Concrete carriers preserve their existing descriptor/clock error ordering.
// This private seam exposes neither a socket profile nor an authority backend.
trait BoundedRecordSocket {
    fn wait_readiness(&self, events: PollFlags, deadline: u64) -> Result<(), BoundedRecordError>;
}

impl BoundedRecordSocket for SeqpacketSocket {
    fn wait_readiness(&self, events: PollFlags, deadline: u64) -> Result<(), BoundedRecordError> {
        wait_until(self.as_fd()?, events, deadline)
    }
}

impl BoundedRecordSocket for DescriptorSubjectSocket {
    fn wait_readiness(&self, events: PollFlags, deadline: u64) -> Result<(), BoundedRecordError> {
        // The descriptor carrier previously sampled time before borrowing its
        // poll descriptor; an expired deadline must keep that precedence.
        let timeout = deadline_timeout(deadline)?;
        poll_readiness(self.as_fd()?, events, &timeout)
    }
}

fn record_before<Socket: BoundedRecordSocket, Record>(
    socket: &mut Socket,
    events: PollFlags,
    deadline: u64,
    attempt: impl FnMut(&mut Socket) -> Result<Record, SeqpacketError>,
) -> Result<Record, BoundedRecordError> {
    exchange_record(&BoundedProfile, socket, events, deadline, attempt)
}

enum InterruptedAttempt {
    Retry,
    Wait,
}

// Only the concrete native profiles below select these stages in production.
// The private operation seam carries the original mutable socket loan.
trait RecordProfile<Socket, Record> {
    type Error: From<SeqpacketError>;

    const INTERRUPTED: InterruptedAttempt;

    fn check_deadline(&self, deadline: u64) -> Result<(), Self::Error>;
    fn wait(&self, socket: &Socket, events: PollFlags, deadline: u64) -> Result<(), Self::Error>;
    fn inspect(&self, record: &Record) -> Result<(), Self::Error>;
}

struct BoundedProfile;

impl<Socket: BoundedRecordSocket, Record> RecordProfile<Socket, Record> for BoundedProfile {
    type Error = BoundedRecordError;

    const INTERRUPTED: InterruptedAttempt = InterruptedAttempt::Retry;

    fn check_deadline(&self, deadline: u64) -> Result<(), Self::Error> {
        check_deadline(deadline)
    }

    fn wait(&self, socket: &Socket, events: PollFlags, deadline: u64) -> Result<(), Self::Error> {
        socket.wait_readiness(events, deadline)
    }

    fn inspect(&self, _: &Record) -> Result<(), Self::Error> {
        Ok(())
    }
}

struct WorkerProfile;

impl<Record> RecordProfile<DescriptorSubjectSocket, Record> for WorkerProfile {
    type Error = WorkerRecordError;

    const INTERRUPTED: InterruptedAttempt = InterruptedAttempt::Wait;

    fn check_deadline(&self, deadline: u64) -> Result<(), Self::Error> {
        check_worker_deadline(deadline)
    }

    fn wait(
        &self,
        socket: &DescriptorSubjectSocket,
        events: PollFlags,
        deadline: u64,
    ) -> Result<(), Self::Error> {
        wait_worker_before(&NativeWorkerWait, socket.as_fd()?, events, deadline)
    }

    fn inspect(&self, _: &Record) -> Result<(), Self::Error> {
        Ok(())
    }
}

struct InspectedWorkerProfile;

impl RecordProfile<DescriptorSubjectSocket, ReceivedDescriptorRecord> for InspectedWorkerProfile {
    type Error = WorkerRecordError;

    const INTERRUPTED: InterruptedAttempt = InterruptedAttempt::Wait;

    fn check_deadline(&self, deadline: u64) -> Result<(), Self::Error> {
        check_worker_deadline(deadline)
    }

    fn wait(
        &self,
        socket: &DescriptorSubjectSocket,
        events: PollFlags,
        deadline: u64,
    ) -> Result<(), Self::Error> {
        wait_worker_before(&NativeWorkerWait, socket.as_fd()?, events, deadline)
    }

    fn inspect(&self, record: &ReceivedDescriptorRecord) -> Result<(), Self::Error> {
        for descriptor in record.descriptors() {
            crate::no_setid::reject_io_uring_descriptor(descriptor.as_fd())?;
        }
        Ok(())
    }
}

fn exchange_record<Socket, Record, Profile: RecordProfile<Socket, Record>>(
    profile: &Profile,
    socket: &mut Socket,
    events: PollFlags,
    deadline: u64,
    mut attempt: impl FnMut(&mut Socket) -> Result<Record, SeqpacketError>,
) -> Result<Record, Profile::Error> {
    loop {
        profile.check_deadline(deadline)?;
        match attempt(socket) {
            Ok(record) => {
                profile.inspect(&record)?;
                profile.check_deadline(deadline)?;
                return Ok(record);
            }
            Err(SeqpacketError::WouldBlock) => profile.wait(socket, events, deadline)?,
            Err(SeqpacketError::Interrupted) => match Profile::INTERRUPTED {
                InterruptedAttempt::Retry => {}
                InterruptedAttempt::Wait => profile.wait(socket, events, deadline)?,
            },
            Err(error) => return Err(error.into()),
        }
    }
}

fn worker_boottime() -> Result<u64, WorkerRecordError> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec).map_err(|_| WorkerRecordClockError::InvalidSeconds)?;
    let nanoseconds =
        u64::try_from(now.tv_nsec).map_err(|_| WorkerRecordClockError::InvalidNanoseconds)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or_else(|| WorkerRecordClockError::Overflow.into())
}

fn check_worker_deadline(deadline: u64) -> Result<(), WorkerRecordError> {
    if worker_boottime()? >= deadline {
        return Err(WorkerRecordClockError::Expired.into());
    }

    Ok(())
}

// The sole production adapter directly samples and polls native objects.
// Alternate stage implementations exist only in the test module.
trait WorkerWait {
    fn before_poll(&self) -> Result<(), WorkerRecordError> { Ok(()) }
    fn boottime(&self) -> Result<u64, WorkerRecordError>;
    fn poll(
        &self,
        descriptor: BorrowedFd<'_>,
        events: PollFlags,
        timeout: &Timespec,
    ) -> Result<usize, rustix::io::Errno>;
}

struct NativeWorkerWait;

impl WorkerWait for NativeWorkerWait {
    fn boottime(&self) -> Result<u64, WorkerRecordError> {
        worker_boottime()
    }

    fn poll(
        &self,
        descriptor: BorrowedFd<'_>,
        events: PollFlags,
        timeout: &Timespec,
    ) -> Result<usize, rustix::io::Errno> {
        let mut descriptors = [PollFd::new(&descriptor, events)];
        poll(&mut descriptors, Some(timeout))
    }
}

fn wait_worker_before(
    wait: &impl WorkerWait,
    descriptor: BorrowedFd<'_>,
    events: PollFlags,
    deadline: u64,
) -> Result<(), WorkerRecordError> {
    loop {
        let remaining = deadline
            .checked_sub(wait.boottime()?)
            .filter(|remaining| *remaining != 0)
            .ok_or(WorkerRecordClockError::Expired)?;
        let timeout = Timespec::try_from(Duration::from_nanos(remaining))
            .map_err(|_| WorkerRecordClockError::InvalidTimeout)?;
        wait.before_poll()?;
        match wait.poll(descriptor, events, &timeout) {
            Ok(0) => return Err(WorkerRecordClockError::Expired.into()),
            Ok(_) => {
                if wait.boottime()? >= deadline {
                    return Err(WorkerRecordClockError::Expired.into());
                }
                return Ok(());
            }
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

/// Reads nonnegative `CLOCK_BOOTTIME` nanoseconds.
///
/// # Errors
///
/// Returns [`BoundedRecordError::Clock`] for negative or overflowing time.
pub fn boottime() -> Result<u64, BoundedRecordError> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec).map_err(|_| BoundedRecordError::Clock)?;
    let nanoseconds = u64::try_from(now.tv_nsec).map_err(|_| BoundedRecordError::Clock)?;

    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(BoundedRecordError::Clock)
}

/// Waits for the staged root-export preview on the same retained endpoint.
///
/// This nonconsuming adapter uses the existing deadline/poll engine. It neither
/// receives a packet nor restores a failed channel, admits a role or extends
/// the caller's original deadline. A genuine payer must precede entry.
///
/// # Errors
/// Returns the actual closed-carrier, deadline or native poll refusal.
pub fn wait_storage_root_export_request_v2(
    socket: &DescriptorSubjectSocket,
    original_deadline: u64,
) -> Result<(), BoundedRecordError> {
    wait_until(socket.as_fd()?, PollFlags::IN, original_deadline)
}

/// Waits for readability of the actual retained Capture worker pidfd.
///
/// This shares the bounded poll engine, does not signal or reap a process, and
/// does not establish aggregate emptiness or physical completion. The genuine
/// resident caller retains the actual poll result and separately checks those
/// independently owed observations before native disposal.
///
/// # Errors
/// Returns the existing original-cutoff, clock or native poll refusal.
pub fn wait_capture_worker_exit_v3(pidfd: &aos_linux_descriptors::pidfd::PidFd,
    original_deadline: u64) -> Result<(), BoundedRecordError> {
    wait_until(pidfd.as_fd(), PollFlags::IN, original_deadline)
}

fn check_deadline(deadline: u64) -> Result<(), BoundedRecordError> {
    if boottime()? >= deadline {
        return Err(BoundedRecordError::Clock);
    }

    Ok(())
}

fn wait_unbounded(fd: BorrowedFd<'_>, events: PollFlags) -> Result<(), BoundedRecordError> {
    let mut descriptors = [PollFd::from_borrowed_fd(fd, events)];
    match poll(&mut descriptors, None) {
        Ok(_) | Err(rustix::io::Errno::INTR) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn wait_until(
    fd: BorrowedFd<'_>,
    events: PollFlags,
    deadline: u64,
) -> Result<(), BoundedRecordError> {
    let timeout = deadline_timeout(deadline)?;
    poll_readiness(fd, events, &timeout)
}

fn deadline_timeout(deadline: u64) -> Result<Timespec, BoundedRecordError> {
    let remaining = deadline
        .checked_sub(boottime()?)
        .filter(|remaining| *remaining > 0)
        .ok_or(BoundedRecordError::Clock)?;
    Ok(Timespec {
        tv_sec: i64::try_from(remaining / 1_000_000_000).map_err(|_| BoundedRecordError::Clock)?,
        tv_nsec: i64::try_from(remaining % 1_000_000_000).map_err(|_| BoundedRecordError::Clock)?,
    })
}

fn poll_readiness(
    fd: BorrowedFd<'_>,
    events: PollFlags,
    timeout: &Timespec,
) -> Result<(), BoundedRecordError> {
    let mut descriptors = [PollFd::from_borrowed_fd(fd, events)];
    match poll(&mut descriptors, Some(timeout)) {
        Ok(0) => Err(BoundedRecordError::Clock),
        Ok(_) | Err(rustix::io::Errno::INTR) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod worker_tests {
    //! Worker-only retry stages retain the actual socket and received rights.

    #![allow(clippy::unwrap_used)]

    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::os::fd::AsFd;

    use super::*;

    struct ScriptedWait {
        clocks: RefCell<VecDeque<Result<u64, WorkerRecordError>>>,
        polls: RefCell<VecDeque<Result<usize, rustix::io::Errno>>>,
        trace: RefCell<Vec<&'static str>>,
        timeouts: RefCell<Vec<Timespec>>,
    }

    impl ScriptedWait {
        fn new(
            clocks: impl IntoIterator<Item = u64>,
            polls: Vec<Result<usize, rustix::io::Errno>>,
        ) -> Self {
            Self {
                clocks: RefCell::new(clocks.into_iter().map(Ok).collect()),
                polls: RefCell::new(polls.into()),
                trace: RefCell::new(Vec::new()),
                timeouts: RefCell::new(Vec::new()),
            }
        }
    }

    impl WorkerWait for ScriptedWait {
        fn boottime(&self) -> Result<u64, WorkerRecordError> {
            self.trace.borrow_mut().push("clock");
            self.clocks.borrow_mut().pop_front().unwrap()
        }

        fn poll(
            &self,
            _: BorrowedFd<'_>,
            _: PollFlags,
            timeout: &Timespec,
        ) -> Result<usize, rustix::io::Errno> {
            self.trace.borrow_mut().push("poll");
            self.timeouts.borrow_mut().push(*timeout);
            self.polls.borrow_mut().pop_front().unwrap()
        }
    }

    struct ScriptedWorkerProfile {
        wait: ScriptedWait,
        reject: bool,
    }

    impl<Record> RecordProfile<DescriptorSubjectSocket, Record> for ScriptedWorkerProfile {
        type Error = WorkerRecordError;

        const INTERRUPTED: InterruptedAttempt = InterruptedAttempt::Wait;

        fn check_deadline(&self, deadline: u64) -> Result<(), Self::Error> {
            if self.wait.boottime()? >= deadline {
                return Err(WorkerRecordClockError::Expired.into());
            }
            Ok(())
        }

        fn wait(
            &self,
            socket: &DescriptorSubjectSocket,
            events: PollFlags,
            deadline: u64,
        ) -> Result<(), Self::Error> {
            self.wait.trace.borrow_mut().push("borrow");
            wait_worker_before(&self.wait, socket.as_fd()?, events, deadline)
        }

        fn inspect(&self, _: &Record) -> Result<(), Self::Error> {
            self.wait.trace.borrow_mut().push("inspect");
            if self.reject {
                return Err(aos_linux_descriptors::Error::invalid("descriptor inspection", "test refusal").into());
            }
            Ok(())
        }
    }

    fn pair() -> (DescriptorSubjectSocket, DescriptorSubjectSocket) {
        let (first, second) = aos_linux_descriptors::native::seqpacket_pair().unwrap();
        (
            DescriptorSubjectSocket::from_owned(first).unwrap(),
            DescriptorSubjectSocket::from_owned(second).unwrap(),
        )
    }

    #[test]
    fn worker_socket_and_poll_interruptions_preserve_every_clock_and_retry_stage() {
        for interrupted in [false, true] {
            let (mut socket, _peer) = pair();
            let profile = ScriptedWorkerProfile {
                wait: ScriptedWait::new(
                    [10, 20, 30, 40, 50, 60],
                    vec![Err(rustix::io::Errno::INTR), Ok(1)],
                ),
                reject: false,
            };
            let first = if interrupted {
                SeqpacketError::Interrupted
            } else {
                SeqpacketError::WouldBlock
            };
            let mut outcomes = VecDeque::from([Err(first), Ok(())]);

            exchange_record(&profile, &mut socket, PollFlags::OUT, 100, |_| {
                profile.wait.trace.borrow_mut().push("attempt");
                outcomes.pop_front().unwrap()
            })
            .unwrap();

            assert_eq!(
                *profile.wait.trace.borrow(),
                [
                    "clock", "attempt", "borrow", "clock", "poll", "clock", "poll", "clock",
                    "clock", "attempt", "inspect", "clock",
                ]
            );
            let timeouts = profile.wait.timeouts.borrow();
            assert_eq!((timeouts[0].tv_sec, timeouts[0].tv_nsec), (0, 80));
            assert_eq!((timeouts[1].tv_sec, timeouts[1].tv_nsec), (0, 70));
            assert!(profile.wait.clocks.borrow().is_empty());
            assert!(profile.wait.polls.borrow().is_empty());
            assert!(outcomes.is_empty());
        }
    }

    #[test]
    fn worker_readiness_and_next_attempt_expiry_prevent_the_retry() {
        for clocks in [vec![10, 20, 100], vec![10, 20, 30, 100]] {
            let (mut socket, _peer) = pair();
            let profile = ScriptedWorkerProfile {
                wait: ScriptedWait::new(clocks, vec![Ok(1)]),
                reject: false,
            };
            let attempts = Cell::new(0);

            let result = exchange_record(&profile, &mut socket, PollFlags::IN, 100, |_| {
                attempts.set(attempts.get() + 1);
                Err::<(), _>(SeqpacketError::WouldBlock)
            });

            assert!(matches!(
                result,
                Err(WorkerRecordError::Clock(WorkerRecordClockError::Expired))
            ));
            assert_eq!(attempts.get(), 1);
            assert_eq!(profile.wait.timeouts.borrow().len(), 1);
            assert!(profile.wait.clocks.borrow().is_empty());
        }
    }

    #[test]
    fn worker_wait_failure_and_timeout_precede_any_success_clock_or_retry() {
        for outcome in [Err(rustix::io::Errno::BADF), Ok(0)] {
            let (mut socket, _peer) = pair();
            let profile = ScriptedWorkerProfile {
                wait: ScriptedWait::new([10, 20, 100], vec![outcome]),
                reject: false,
            };
            let attempts = Cell::new(0);

            let result = exchange_record(&profile, &mut socket, PollFlags::IN, 100, |_| {
                attempts.set(attempts.get() + 1);
                Err::<(), _>(SeqpacketError::Interrupted)
            });

            match outcome {
                Err(expected) => assert!(
                    matches!(result, Err(WorkerRecordError::Poll(actual)) if actual == expected)
                ),
                Ok(_) => assert!(matches!(
                    result,
                    Err(WorkerRecordError::Clock(WorkerRecordClockError::Expired))
                )),
            }
            assert_eq!(attempts.get(), 1);
            assert_eq!(profile.wait.clocks.borrow().len(), 1);
            assert_eq!(
                *profile.wait.trace.borrow(),
                ["clock", "borrow", "clock", "poll"]
            );
        }
    }

    #[test]
    fn worker_closed_poll_borrow_precedes_competing_wait_clock_failure() {
        let (mut socket, _peer) = pair();
        let profile = ScriptedWorkerProfile {
            wait: ScriptedWait::new([10, 100], vec![]),
            reject: false,
        };

        let result = exchange_record(&profile, &mut socket, PollFlags::IN, 100, |socket| {
            socket.close();
            Err::<(), _>(SeqpacketError::WouldBlock)
        });

        assert!(matches!(
            result,
            Err(WorkerRecordError::Transport(SeqpacketError::Closed))
        ));
        assert_eq!(*profile.wait.trace.borrow(), ["clock", "borrow"]);
        assert_eq!(profile.wait.clocks.borrow().len(), 1);
    }

    #[test]
    fn worker_fatal_atomic_error_does_not_poll_inspect_or_sample_again() {
        let (mut socket, _peer) = pair();
        let profile = ScriptedWorkerProfile {
            wait: ScriptedWait::new([10, 100], vec![]),
            reject: true,
        };

        let result = exchange_record(&profile, &mut socket, PollFlags::IN, 100, |_| {
            Err::<(), _>(SeqpacketError::InvalidMaximum)
        });

        assert!(matches!(
            result,
            Err(WorkerRecordError::Transport(SeqpacketError::InvalidMaximum))
        ));
        assert_eq!(*profile.wait.trace.borrow(), ["clock"]);
        assert_eq!(profile.wait.clocks.borrow().len(), 1);
    }

    #[test]
    fn worker_clock_causes_remain_owned_and_precede_the_atomic_attempt() {
        for reason in [
            WorkerRecordClockError::InvalidSeconds,
            WorkerRecordClockError::InvalidNanoseconds,
            WorkerRecordClockError::Overflow,
        ] {
            let expected = std::mem::discriminant(&reason);
            let (mut socket, _peer) = pair();
            let profile = ScriptedWorkerProfile {
                wait: ScriptedWait::new([], vec![]),
                reject: false,
            };
            profile
                .wait
                .clocks
                .borrow_mut()
                .push_back(Err(reason.into()));

            let result = exchange_record(
                &profile,
                &mut socket,
                PollFlags::IN,
                100,
                |_| -> Result<(), SeqpacketError> {
                    panic!("invalid clock must precede the attempt")
                },
            );

            assert!(
                matches!(result, Err(WorkerRecordError::Clock(actual)) if std::mem::discriminant(&actual) == expected)
            );
            assert_eq!(*profile.wait.trace.borrow(), ["clock"]);
        }
    }

    #[test]
    fn inspection_refusal_precedes_late_clock_and_both_drop_the_complete_record() {
        for reject in [false, true] {
            let (mut sender, mut receiver) = pair();
            let (reader, writer) = rustix::pipe::pipe_with(
                rustix::pipe::PipeFlags::NONBLOCK | rustix::pipe::PipeFlags::CLOEXEC,
            )
            .unwrap();
            send_provisioned_worker_record(
                &mut sender,
                b"consumed",
                &[writer.as_fd(), writer.as_fd()],
                u64::MAX,
            )
            .unwrap();
            drop(writer);
            let profile = ScriptedWorkerProfile {
                wait: ScriptedWait::new([10, 100], vec![]),
                reject,
            };

            let result = exchange_record(&profile, &mut receiver, PollFlags::IN, 100, |socket| {
                socket.receive(64, 2)
            });

            if reject {
                assert!(matches!(result, Err(WorkerRecordError::Linux(_))));
                assert_eq!(profile.wait.clocks.borrow().len(), 1);
                assert_eq!(*profile.wait.trace.borrow(), ["clock", "inspect"]);
            } else {
                assert!(matches!(
                    result,
                    Err(WorkerRecordError::Clock(WorkerRecordClockError::Expired))
                ));
                assert!(profile.wait.clocks.borrow().is_empty());
                assert_eq!(*profile.wait.trace.borrow(), ["clock", "inspect", "clock"]);
            }
            assert_eq!(rustix::io::read(&reader, &mut [0_u8; 1]).unwrap(), 0);
            assert!(matches!(
                receiver.receive(64, 0),
                Err(SeqpacketError::WouldBlock)
            ));
        }
    }

    #[test]
    fn provisioned_worker_profiles_preserve_zero_one_two_rights_order_and_subject() {
        for inspected in [false, true] {
            for count in 0..=2 {
                let (mut sender, mut receiver) = pair();
                let first = tempfile::tempfile().unwrap();
                let second = tempfile::tempfile().unwrap();
                let rights = [first.as_fd(), second.as_fd()];

                send_provisioned_worker_record(&mut sender, b"worker", &rights[..count], u64::MAX)
                    .unwrap();
                let receive = if inspected {
                    receive_provisioned_worker_record_without_io_uring
                } else {
                    receive_provisioned_worker_record
                };
                let record = receive(&mut receiver, 64, count, u64::MAX).unwrap();

                assert_eq!(record.payload(), b"worker");
                assert_eq!(record.descriptors().len(), count);
                assert_eq!(
                    record.subject().credentials().pid().get(),
                    std::process::id()
                );
                for (received, sent) in record.descriptors().iter().zip(rights) {
                    assert_eq!(
                        rustix::fs::fstat(received).unwrap().st_ino,
                        rustix::fs::fstat(sent).unwrap().st_ino
                    );
                    assert!(aos_linux_descriptors::native::is_cloexec(received.as_fd()).unwrap());
                }
            }
        }
    }

    #[test]
    fn provisioned_worker_capacity_and_native_count_validation_keep_their_frontiers() {
        let (mut socket, _peer) = pair();
        assert!(matches!(
            send_provisioned_worker_record(&mut socket, b"", &[], 0),
            Err(WorkerRecordError::Transport(SeqpacketError::InvalidMaximum))
        ));
        for receive in [
            receive_provisioned_worker_record,
            receive_provisioned_worker_record_without_io_uring,
        ] {
            assert!(matches!(
                receive(&mut socket, 0, 0, 0),
                Err(WorkerRecordError::Transport(SeqpacketError::InvalidMaximum))
            ));
            assert!(matches!(
                receive(&mut socket, 64, 3, 0),
                Err(WorkerRecordError::Clock(WorkerRecordClockError::Expired))
            ));
            assert!(matches!(
                receive(&mut socket, 64, 3, u64::MAX),
                Err(WorkerRecordError::Transport(SeqpacketError::InvalidMaximum))
            ));
        }
    }

    #[test]
    fn provisioned_worker_wrong_right_count_closes_the_carrier_and_disposes_all_rights() {
        for inspected in [false, true] {
            for count in 1..=2 {
                let (mut sender, mut receiver) = pair();
                let (reader, writer) = rustix::pipe::pipe_with(
                    rustix::pipe::PipeFlags::NONBLOCK | rustix::pipe::PipeFlags::CLOEXEC,
                )
                .unwrap();
                let rights = vec![writer.as_fd(); count];
                send_provisioned_worker_record(&mut sender, b"wrong", &rights, u64::MAX).unwrap();
                drop(rights);
                drop(writer);
                let receive = if inspected {
                    receive_provisioned_worker_record_without_io_uring
                } else {
                    receive_provisioned_worker_record
                };

                assert!(matches!(
                    receive(&mut receiver, 64, 0, u64::MAX),
                    Err(WorkerRecordError::Transport(_))
                ));
                assert!(matches!(receiver.as_fd(), Err(SeqpacketError::Closed)));
                assert_eq!(rustix::io::read(&reader, &mut [0_u8; 1]).unwrap(), 0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Retry classification and deadline checks preserve carrier custody.

    #![allow(
        clippy::unwrap_used,
        reason = "Test fixture failures intentionally panic."
    )]

    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::os::fd::{AsFd, OwnedFd};

    use super::*;

    fn packet_socket_pair() -> (DescriptorSubjectSocket, DescriptorSubjectSocket) {
        let (first, second) = rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::SEQPACKET,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        (
            DescriptorSubjectSocket::from_owned(first).unwrap(),
            DescriptorSubjectSocket::from_owned(second).unwrap(),
        )
    }

    fn packet_before<Packet>(
        socket: &mut DescriptorSubjectSocket,
        events: PollFlags,
        deadline: u64,
        attempt: impl FnMut(&mut DescriptorSubjectSocket) -> Result<Packet, SeqpacketError>,
    ) -> Result<Packet, WorkerRecordError> {
        exchange_record(&WorkerProfile, socket, events, deadline, attempt)
    }

    #[test]
    fn packet_backpressure_and_interruption_both_wait_before_retrying() {
        for interrupted in [false, true] {
            let (mut socket, _peer) = packet_socket_pair();
            socket.close();
            let attempts = Cell::new(0);

            let result =
                packet_before(&mut socket, rustix::event::PollFlags::OUT, u64::MAX, |_| {
                    attempts.set(attempts.get() + 1);
                    if attempts.get() > 1 {
                        return Ok(());
                    }
                    Err::<(), _>(if interrupted {
                        SeqpacketError::Interrupted
                    } else {
                        SeqpacketError::WouldBlock
                    })
                });

            // A retry without the original poll-descriptor borrow would invoke
            // the attempt again instead of returning this closed-carrier error.
            assert!(matches!(
                result,
                Err(WorkerRecordError::Transport(SeqpacketError::Closed))
            ));
            assert_eq!(attempts.get(), 1);
        }
    }

    #[test]
    fn packet_backpressure_and_interruption_retry_after_writable_poll() {
        for interrupted in [false, true] {
            let (mut socket, _peer) = packet_socket_pair();
            let first_error = if interrupted {
                SeqpacketError::Interrupted
            } else {
                SeqpacketError::WouldBlock
            };
            let mut outcomes = VecDeque::from([Err(first_error), Ok(())]);

            packet_before(&mut socket, rustix::event::PollFlags::OUT, u64::MAX, |_| {
                outcomes.pop_front().unwrap()
            })
            .unwrap();

            assert!(outcomes.is_empty());
        }
    }

    #[test]
    fn fatal_packet_errors_are_returned_without_retry() {
        let (mut socket, _peer) = packet_socket_pair();
        let attempts = Cell::new(0);

        let result = packet_before(&mut socket, rustix::event::PollFlags::OUT, u64::MAX, |_| {
            attempts.set(attempts.get() + 1);
            Err::<(), _>(SeqpacketError::InvalidMaximum)
        });

        assert!(matches!(
            result,
            Err(WorkerRecordError::Transport(SeqpacketError::InvalidMaximum))
        ));
        assert_eq!(attempts.get(), 1);
    }

    #[test]
    fn expired_packet_deadline_precedes_the_atomic_attempt() {
        let (mut socket, _peer) = packet_socket_pair();
        let attempts = Cell::new(0);

        let result = packet_before(&mut socket, rustix::event::PollFlags::OUT, 0, |_| {
            attempts.set(attempts.get() + 1);
            Ok(())
        });

        assert!(matches!(
            result,
            Err(WorkerRecordError::Clock(WorkerRecordClockError::Expired))
        ));
        assert_eq!(attempts.get(), 0);
    }

    #[derive(Clone, Copy)]
    enum WaitFailure {
        Clock,
        Io(rustix::io::Errno),
    }

    struct ScriptedSocket {
        waits: Cell<usize>,
        failure: Option<WaitFailure>,
    }

    impl BoundedRecordSocket for ScriptedSocket {
        fn wait_readiness(&self, _: PollFlags, _: u64) -> Result<(), BoundedRecordError> {
            self.waits.set(self.waits.get() + 1);

            match self.failure {
                Some(WaitFailure::Clock) => Err(BoundedRecordError::Clock),
                Some(WaitFailure::Io(error)) => Err(BoundedRecordError::Io(error)),
                None => Ok(()),
            }
        }
    }

    fn descriptor_pair() -> (DescriptorSubjectSocket, OwnedFd) {
        let (receiver, sender) = aos_linux_descriptors::native::seqpacket_pair().unwrap();
        (
            DescriptorSubjectSocket::from_owned(receiver).unwrap(),
            sender,
        )
    }

    #[test]
    fn interrupted_attempts_retry_without_polling() {
        let mut socket = ScriptedSocket {
            waits: Cell::new(0),
            failure: None,
        };
        let mut outcomes = VecDeque::from([Err(SeqpacketError::Interrupted), Ok(())]);

        record_before(&mut socket, PollFlags::IN, u64::MAX, |_| {
            outcomes.pop_front().unwrap()
        })
        .unwrap();

        assert!(outcomes.is_empty());
        assert_eq!(socket.waits.get(), 0);
    }

    #[test]
    fn would_block_waits_before_retrying() {
        let mut socket = ScriptedSocket {
            waits: Cell::new(0),
            failure: None,
        };
        let mut outcomes = VecDeque::from([Err(SeqpacketError::WouldBlock), Ok(())]);

        record_before(&mut socket, PollFlags::OUT, u64::MAX, |_| {
            outcomes.pop_front().unwrap()
        })
        .unwrap();

        assert!(outcomes.is_empty());
        assert_eq!(socket.waits.get(), 1);
    }

    #[test]
    fn fatal_attempts_do_not_wait_or_retry() {
        let mut socket = ScriptedSocket {
            waits: Cell::new(0),
            failure: None,
        };
        let attempts = Cell::new(0);

        let result = record_before(&mut socket, PollFlags::IN, u64::MAX, |_| {
            attempts.set(attempts.get() + 1);
            Err::<(), _>(SeqpacketError::Closed)
        });

        assert!(matches!(
            result,
            Err(BoundedRecordError::Transport(SeqpacketError::Closed))
        ));
        assert_eq!(attempts.get(), 1);
        assert_eq!(socket.waits.get(), 0);
    }

    #[test]
    fn wait_failures_do_not_retry_the_attempt() {
        for failure in [WaitFailure::Clock, WaitFailure::Io(rustix::io::Errno::IO)] {
            let mut socket = ScriptedSocket {
                waits: Cell::new(0),
                failure: Some(failure),
            };
            let attempts = Cell::new(0);

            let result = record_before(&mut socket, PollFlags::IN, u64::MAX, |_| {
                attempts.set(attempts.get() + 1);
                Err::<(), _>(SeqpacketError::WouldBlock)
            });

            match failure {
                WaitFailure::Clock => assert!(matches!(result, Err(BoundedRecordError::Clock))),
                WaitFailure::Io(expected) => {
                    assert!(
                        matches!(result, Err(BoundedRecordError::Io(error)) if error == expected)
                    );
                }
            }
            assert_eq!(attempts.get(), 1);
            assert_eq!(socket.waits.get(), 1);
        }
    }

    #[test]
    fn expired_deadline_precedes_the_attempt() {
        let mut socket = ScriptedSocket {
            waits: Cell::new(0),
            failure: None,
        };
        let attempts = Cell::new(0);

        let result = record_before(&mut socket, PollFlags::OUT, 0, |_| {
            attempts.set(attempts.get() + 1);
            Ok(())
        });

        assert!(matches!(result, Err(BoundedRecordError::Clock)));
        assert_eq!(attempts.get(), 0);
        assert_eq!(socket.waits.get(), 0);
    }

    #[test]
    fn expired_receive_preserves_a_queued_plain_record() {
        let (mut receiver, sender) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        crate::uapi::send_seqpacket(sender.as_fd(), b"queued").unwrap();

        assert!(matches!(
            receive(&mut receiver, 64, 0),
            Err(BoundedRecordError::Clock)
        ));

        let record = receive(&mut receiver, 64, u64::MAX).unwrap();
        assert_eq!(record.payload(), b"queued");
    }

    #[test]
    fn expired_receive_preserves_queued_closed_profile_records_and_rights() {
        for (scope, descriptor_count) in [(false, 0), (true, 0), (true, 5)] {
            let (mut receiver, sender) = descriptor_pair();
            let file = tempfile::tempfile().unwrap();
            let descriptors = vec![file.as_fd(); descriptor_count];
            if descriptors.is_empty() {
                crate::uapi::send_seqpacket(sender.as_fd(), b"queued").unwrap();
            } else {
                crate::uapi::send_seqpacket_rights(sender.as_fd(), b"queued", &descriptors)
                    .unwrap();
            }
            let receive_profile = if scope {
                receive_mount_scope_reply
            } else {
                receive_zero_descriptors
            };

            assert!(matches!(
                receive_profile(&mut receiver, 64, 0),
                Err(BoundedRecordError::Clock)
            ));

            let record = receive_profile(&mut receiver, 64, u64::MAX).unwrap();
            assert_eq!(record.payload(), b"queued");
            assert_eq!(record.descriptors().len(), descriptor_count);
            assert_eq!(
                record.subject().credentials().pid().get(),
                std::process::id()
            );
            for descriptor in record.descriptors() {
                assert!(aos_linux_descriptors::native::is_cloexec(descriptor.as_fd()).unwrap());
            }
        }
    }

    #[test]
    fn expired_send_does_not_queue_a_plain_or_descriptor_record() {
        let (mut plain_receiver, sender) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut plain_sender = SeqpacketSocket::from_owned(sender).unwrap();
        let (mut descriptor_receiver, sender) = descriptor_pair();
        let mut descriptor_sender = DescriptorSubjectSocket::from_owned(sender).unwrap();

        assert!(matches!(
            send(&mut plain_sender, b"expired", 0),
            Err(BoundedRecordError::Clock)
        ));
        assert!(matches!(
            send_descriptor_record(&mut descriptor_sender, b"expired", 0),
            Err(BoundedRecordError::Clock)
        ));

        assert!(matches!(
            plain_receiver.receive(64),
            Err(SeqpacketError::WouldBlock)
        ));
        assert!(matches!(
            descriptor_receiver.receive(64, 0),
            Err(SeqpacketError::WouldBlock)
        ));
    }

    #[test]
    fn bounded_descriptor_adapters_preserve_closed_receive_profiles() {
        for scope in [false, true] {
            let (mut receiver, sender) = descriptor_pair();
            let file = tempfile::tempfile().unwrap();
            crate::uapi::send_seqpacket_rights(sender.as_fd(), b"unexpected", &[file.as_fd()])
                .unwrap();
            let receive_profile = if scope {
                receive_mount_scope_reply
            } else {
                receive_zero_descriptors
            };

            assert!(matches!(
                receive_profile(&mut receiver, 64, u64::MAX),
                Err(BoundedRecordError::Transport(_))
            ));
            assert!(matches!(receiver.as_fd(), Err(SeqpacketError::Closed)));
        }
    }

    #[test]
    fn closed_carriers_preserve_poll_descriptor_and_clock_error_precedence() {
        let (mut plain, _sender) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let (mut descriptor, _sender) = descriptor_pair();
        plain.close();
        descriptor.close();

        assert!(matches!(
            plain.wait_readiness(PollFlags::IN, 0),
            Err(BoundedRecordError::Transport(SeqpacketError::Closed))
        ));
        assert!(matches!(
            descriptor.wait_readiness(PollFlags::IN, 0),
            Err(BoundedRecordError::Clock)
        ));
    }
}


#[cfg(test)]
mod fixed_worker_observer_tests {
    use super::*;

    fn pair() -> (DescriptorSubjectSocket, SeqpacketSocket) {
        let (first, second) = aos_linux_descriptors::native::seqpacket_pair().unwrap();
        (
            DescriptorSubjectSocket::from_owned_retaining(first).unwrap(),
            SeqpacketSocket::from_owned(second).unwrap(),
        )
    }

    #[test]
    fn expired_fixed_receive_keeps_the_queued_record_and_original_channel() {
        let (mut receiver, mut sender) = pair();
        sender.send(&[1; 313]).unwrap();

        let refused = receive_worker_observer_record_v1(
            &mut receiver, WorkerObserverRecordKindV1::ReadyOrResult, 0,
        ).unwrap_err();

        assert!(refused.received_record().is_none());
        assert!(refused.failure().unwrap().is::<WorkerRecordError>());
        let record = receiver.receive_worker_observer_retaining_v1(
            WorkerObserverRecordKindV1::ReadyOrResult,
        ).unwrap();
        assert_eq!(record.payload(), &[1; 313]);
    }

    #[test]
    fn bounded_fixed_receive_keeps_supported_full_request_and_two_original_rights() {
        let (mut receiver, mut sender) = pair();
        let first = std::fs::File::open("/dev/null").unwrap();
        let second = std::fs::File::open("/dev/zero").unwrap();
        sender.send_with_descriptors(&[2; 4096], &[first.as_fd(), second.as_fd()]).unwrap();

        let record = receive_worker_observer_record_v1(
            &mut receiver, WorkerObserverRecordKindV1::Request, u64::MAX,
        ).unwrap();

        assert_eq!(record.payload(), &[2; 4096]);
        assert_eq!(record.descriptors().len(), 2);
        for (received, original) in record.descriptors().iter().zip([&first, &second]) {
            let received = rustix::fs::fstat(received).unwrap();
            let original = rustix::fs::fstat(original).unwrap();
            assert_eq!((received.st_dev, received.st_ino), (original.st_dev, original.st_ino));
        }
    }

    #[test]
    fn malformed_fixed_receive_retains_actual_native_cause_and_closes_original() {
        let (mut receiver, mut sender) = pair();
        let file = std::fs::File::open("/dev/null").unwrap();
        sender.send_with_descriptors(&[3; 313], &[file.as_fd(); 5]).unwrap();

        let refused = receive_worker_observer_record_v1(
            &mut receiver, WorkerObserverRecordKindV1::ReadyOrResult, u64::MAX,
        ).unwrap_err();

        assert!(refused.failure().unwrap().is::<super::super::RetainedSeqpacketReceiveErrorV1>());
        assert!(refused.received_record().is_none());
        assert!(receiver.as_fd().is_err());
    }
}

/// Selects an existing no-rights ZFS request or acknowledgment packet ceiling.
#[derive(Clone, Copy, Debug)]
pub enum ZfsWorkerSendKindV1 {
    /// Existing typed mutation, atomic or observation request ceiling.
    Request,
    /// Existing fixed acknowledgment ceiling.
    Acknowledgment,
    /// Fixed106-byte acknowledgment of one exact authenticated Capture report.
    ///
    /// It promises neither a durable676 commit nor physical/F retirement.
    CaptureReportAcknowledgment,
}

/// Retains the complete bounded send, wait and independent deadline results.
///
/// This owns transport DATA only. The genuine entered worker financial owner
/// and its upper semantic/control posts remain separate requirements.
#[derive(Debug)]
pub struct ZfsWorkerSendAttemptV1 {
    original: FixedWorkerSendAttemptV1<super::StorageSeqpacketSendAttemptV1>,
}

/// Selects the existing fixed worker frame and exact borrowed rights shape.
///
/// These transport bounds grant no descriptor roles, worker identity or payment.
#[derive(Clone, Copy, Debug)]
pub enum DescriptorWorkerSendKindV1 {
    /// First fixed4096-byte request frame carrying the two retained originals.
    RequestFirst,
    /// Later fixed4096-byte request frame carrying no additional rights.
    RequestContinuation,
    /// Existing ten-byte no-rights worker acknowledgment.
    Acknowledgment,
    /// Fixed8192-byte maximum method31 request carrying no transferred rights.
    GuestRootPublicationRequestV2,
    /// Exact observation-only startup health request, eight bytes and no rights.
    GuestRootStartupHealthV2,
    /// Closed physical Capture proof carrying its two existing FIFO originals.
    ///
    /// Its caller validates the fixed application codec. This mechanical
    /// profile adds no capacity provisioning or descriptor authority.
    StorageCaptureProof,
    /// Closed physical Capture terminal acknowledgment without transferred FDs.
    StorageCaptureAck,
}

/// Retains a fixed descriptor-worker send, clocks and readiness observations.
#[derive(Debug)]
pub struct DescriptorWorkerSendAttemptV1 {
    original: FixedWorkerSendAttemptV1<Result<
        super::descriptor_subject::DescriptorWorkerNativeSendAttemptV1, SeqpacketError,
    >>,
}

#[derive(Debug)]
struct FixedWorkerSendAttemptV1<Native> {
    provision: Option<Result<(), SeqpacketError>>,
    before: Option<Result<(), WorkerRecordError>>,
    sent: Option<Native>,
    after: Option<Result<(), WorkerRecordError>>,
    wait: Option<Result<(), WorkerRecordError>>,
    bound: Option<SeqpacketError>,
    first: Option<FixedWorkerSendFailureV1>,
}

#[derive(Clone, Copy, Debug)]
enum FixedWorkerSendFailureV1 {
    Bound,
    Provision,
    Before,
    Send,
    After,
    Wait,
}

trait FixedWorkerNativeSendReceiptV1 {
    fn is_sent(&self) -> bool;
    fn is_nonconsuming(&self) -> bool;
    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)>;
}

impl FixedWorkerNativeSendReceiptV1 for super::StorageSeqpacketSendAttemptV1 {
    fn is_sent(&self) -> bool { super::StorageSeqpacketSendAttemptV1::is_sent(self) }
    fn is_nonconsuming(&self) -> bool { super::StorageSeqpacketSendAttemptV1::is_nonconsuming(self) }
    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        super::StorageSeqpacketSendAttemptV1::failure(self)
    }
}

impl FixedWorkerNativeSendReceiptV1 for Result<
    super::descriptor_subject::DescriptorWorkerNativeSendAttemptV1, SeqpacketError,
> {
    fn is_sent(&self) -> bool {
        self.as_ref().is_ok_and(|receipt| receipt.is_sent())
    }

    fn is_nonconsuming(&self) -> bool {
        self.as_ref().is_ok_and(|receipt| receipt.is_nonconsuming())
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Ok(receipt) => receipt.failure(),
            Err(error) => Some(error),
        }
    }
}

impl<Native: FixedWorkerNativeSendReceiptV1> FixedWorkerSendAttemptV1<Native> {
    fn is_sent(&self) -> bool {
        self.first.is_none()
            && self.sent.as_ref().is_some_and(FixedWorkerNativeSendReceiptV1::is_sent)
            && matches!(self.after, Some(Ok(())))
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            FixedWorkerSendFailureV1::Bound => self.bound.as_ref().map(|error| error as _),
            FixedWorkerSendFailureV1::Provision => self.provision.as_ref()?.as_ref().err().map(|error| error as _),
            FixedWorkerSendFailureV1::Before => self.before.as_ref()?.as_ref().err().map(|error| error as _),
            FixedWorkerSendFailureV1::Send => self.sent.as_ref()?.failure(),
            FixedWorkerSendFailureV1::After => self.after.as_ref()?.as_ref().err().map(|error| error as _),
            FixedWorkerSendFailureV1::Wait => self.wait.as_ref()?.as_ref().err().map(|error| error as _),
        }
    }
}

impl ZfsWorkerSendAttemptV1 {
    /// Reports a full native send followed by its positive deadline observation.
    #[must_use]
    pub fn is_sent(&self) -> bool { self.original.is_sent() }

    /// Borrows the actual earliest refusal without disposing later observations.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.failure()
    }
}

impl DescriptorWorkerSendAttemptV1 {
    /// Reports a full native send with positive carrier and deadline posts.
    #[must_use]
    pub fn is_sent(&self) -> bool { self.original.is_sent() }

    /// Borrows the earliest actual send, native, wait or deadline refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.failure()
    }

    /// Prices actual bounded/native receipt frames and native error carriers.
    #[must_use]
    pub fn requested_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(super::descriptor_subject::DescriptorWorkerNativeSendAttemptV1::requested_bytes_v1()?)?
            .checked_add(4 * 256)
    }
}

trait FixedWorkerSendProfileV1<Socket, Native> {
    fn maximum(&self) -> usize;
    fn maximum_attempts(&self) -> Option<usize> { None }
    fn shape_error(&self) -> Option<SeqpacketError> { None }
    fn provision(&self, socket: &Socket) -> Option<Result<(), SeqpacketError>>;
    fn send(&self, socket: &mut Socket, packet: &[u8]) -> Native;
    fn wait(&self, socket: &Socket, deadline: u64) -> Result<(), WorkerRecordError>;
}

struct ZfsSendProfileV1(ZfsWorkerSendKindV1);

impl FixedWorkerSendProfileV1<SeqpacketSocket, super::StorageSeqpacketSendAttemptV1>
    for ZfsSendProfileV1
{
    fn maximum(&self) -> usize {
        match self.0 {
            ZfsWorkerSendKindV1::Request => 24 * 1024,
            ZfsWorkerSendKindV1::Acknowledgment => 10,
            ZfsWorkerSendKindV1::CaptureReportAcknowledgment => 106,
        }
    }
    fn provision(&self, _: &SeqpacketSocket) -> Option<Result<(), SeqpacketError>> { None }
    fn send(&self, socket: &mut SeqpacketSocket, packet: &[u8]) -> super::StorageSeqpacketSendAttemptV1 {
        socket.send_storage_session_retaining_v1(packet)
    }
    fn wait(&self, socket: &SeqpacketSocket, deadline: u64) -> Result<(), WorkerRecordError> {
        socket.as_fd().map_err(WorkerRecordError::from)
            .and_then(|fd| wait_worker_before(&NativeWorkerWait, fd, PollFlags::OUT, deadline))
    }
}

struct DescriptorSendProfileV1<'rights, 'fd> {
    kind: DescriptorWorkerSendKindV1,
    rights: &'rights [BorrowedFd<'fd>],
}

impl FixedWorkerSendProfileV1<DescriptorSubjectSocket, Result<
    super::descriptor_subject::DescriptorWorkerNativeSendAttemptV1, SeqpacketError,
>> for DescriptorSendProfileV1<'_, '_> {
    fn maximum(&self) -> usize {
        match self.kind {
            DescriptorWorkerSendKindV1::RequestFirst | DescriptorWorkerSendKindV1::RequestContinuation => 4096,
            DescriptorWorkerSendKindV1::Acknowledgment => 10,
            DescriptorWorkerSendKindV1::GuestRootPublicationRequestV2 => 8192,
            DescriptorWorkerSendKindV1::GuestRootStartupHealthV2 => 8,
            DescriptorWorkerSendKindV1::StorageCaptureProof | DescriptorWorkerSendKindV1::StorageCaptureAck => 4096,
        }
    }
    fn shape_error(&self) -> Option<SeqpacketError> {
        let expected = match self.kind {
            DescriptorWorkerSendKindV1::RequestFirst | DescriptorWorkerSendKindV1::StorageCaptureProof => 2,
            _ => 0,
        };
        (self.rights.len() != expected).then_some(SeqpacketError::InvalidMaximum)
    }
    fn provision(&self, socket: &DescriptorSubjectSocket) -> Option<Result<(), SeqpacketError>> {
        match self.kind {
            DescriptorWorkerSendKindV1::RequestFirst => Some(socket.provision_packet_capacity(4096)),
            DescriptorWorkerSendKindV1::GuestRootPublicationRequestV2 => Some(socket.provision_packet_capacity(8192)),
            DescriptorWorkerSendKindV1::GuestRootStartupHealthV2 => Some(socket.provision_packet_capacity(8)),
            _ => None,
        }
    }
    fn send(&self, socket: &mut DescriptorSubjectSocket, packet: &[u8])
        -> Result<super::descriptor_subject::DescriptorWorkerNativeSendAttemptV1, SeqpacketError>
    {
        socket.send_worker_record_retaining_v1(packet, self.rights)
    }
    fn wait(&self, socket: &DescriptorSubjectSocket, deadline: u64) -> Result<(), WorkerRecordError> {
        socket.as_fd().map_err(WorkerRecordError::from)
            .and_then(|fd| wait_worker_before(&NativeWorkerWait, fd, PollFlags::OUT, deadline))
    }
}

struct CapturePipesSendProfileV3<'rights, 'fd>(&'rights [BorrowedFd<'fd>; 2]);

impl FixedWorkerSendProfileV1<SeqpacketSocket, super::StorageSeqpacketSendAttemptV1>
    for CapturePipesSendProfileV3<'_, '_>
{
    fn maximum(&self) -> usize { 4096 }
    fn provision(&self, _: &SeqpacketSocket) -> Option<Result<(), SeqpacketError>> { None }
    fn send(&self, socket: &mut SeqpacketSocket, packet: &[u8]) -> super::StorageSeqpacketSendAttemptV1 {
        socket.send_capture_worker_pipes_retaining_v3(packet, *self.0)
    }
    fn wait(&self, socket: &SeqpacketSocket, deadline: u64) -> Result<(), WorkerRecordError> {
        socket.as_fd().map_err(WorkerRecordError::from)
            .and_then(|fd| wait_worker_before(&NativeWorkerWait, fd, PollFlags::OUT, deadline))
    }
}

/// Sends the fixed Capture worker pipe reply through the same bounded sender.
///
/// Rights remain borrowed from the actual worker original. Fatal or late
/// results stay in the returned receipt; this grants no readiness or disposal.
#[must_use]
pub fn send_capture_worker_pipes_v3(
    socket: &mut SeqpacketSocket, packet: &[u8], pipes: [BorrowedFd<'_>; 2], deadline: u64,
) -> ZfsWorkerSendAttemptV1 {
    ZfsWorkerSendAttemptV1 {
        original: send_fixed_worker_record_v1(socket, packet, CapturePipesSendProfileV3(&pipes), deadline),
    }
}

// Both fixed carrier wrappers share this exact clock/native/wait/disposal engine.
fn send_fixed_worker_record_v1<Socket, Native, Profile>(
    socket: &mut Socket, packet: &[u8], profile: Profile, deadline: u64,
) -> FixedWorkerSendAttemptV1<Native>
where
    Native: FixedWorkerNativeSendReceiptV1,
    Profile: FixedWorkerSendProfileV1<Socket, Native>,
{
    let mut attempt = FixedWorkerSendAttemptV1 {
        provision: None, before: None, sent: None, after: None, wait: None,
        bound: None, first: None,
    };
    let maximum = profile.maximum();
    if packet.is_empty() || packet.len() > maximum {
        attempt.bound = Some(if packet.is_empty() {
            SeqpacketError::EmptyRecord
        } else {
            SeqpacketError::RecordTooLarge { actual: packet.len(), maximum }
        });
    } else {
        attempt.bound = profile.shape_error();
    }
    if attempt.bound.is_some() {
        attempt.first = Some(FixedWorkerSendFailureV1::Bound);
        return attempt;
    }
    attempt.provision = profile.provision(socket);
    if matches!(attempt.provision, Some(Err(_))) {
        attempt.first = Some(FixedWorkerSendFailureV1::Provision);
        return attempt;
    }
    let mut native_attempts = 0_usize;
    loop {
        attempt.before = Some(check_worker_deadline(deadline));
        if !matches!(attempt.before, Some(Ok(()))) {
            attempt.first = Some(FixedWorkerSendFailureV1::Before);
            return attempt;
        }
        native_attempts += 1;
        attempt.sent = Some(profile.send(socket, packet));
        let Some(sent) = attempt.sent.as_ref() else { std::process::abort() };
        if sent.is_sent() {
            attempt.after = Some(check_worker_deadline(deadline));
            if !matches!(attempt.after, Some(Ok(()))) {
                attempt.first = Some(FixedWorkerSendFailureV1::After);
            }
            return attempt;
        }
        if !sent.is_nonconsuming()
            || profile.maximum_attempts().is_some_and(|maximum| native_attempts >= maximum)
        {
            // A finite selected profile retains its actual final EAGAIN/EINTR
            // rather than replacing that native cause with a synthetic retry.
            attempt.first = Some(FixedWorkerSendFailureV1::Send);
            return attempt;
        }
        attempt.wait = Some(profile.wait(socket, deadline));
        if !matches!(attempt.wait, Some(Ok(()))) {
            attempt.first = Some(FixedWorkerSendFailureV1::Wait);
            return attempt;
        }
        // Only the actual no-acquisition native result, positive carrier posts
        // and completed wait may be disposed before the same slot is reused.
        drop(attempt.sent.take());
        drop(attempt.before.take());
        drop(attempt.wait.take());
    }
}

/// Sends one actual bounded ZFS packet through the shared retaining worker engine.
///
/// Queue sizing, no-rights framing, native counts and retry policy are unchanged.
/// Fatal/partial sends and late successes retain the whole receipt and never retry.
#[must_use]
pub fn send_zfs_worker_record_v1(
    socket: &mut SeqpacketSocket, packet: &[u8], kind: ZfsWorkerSendKindV1, deadline: u64,
) -> ZfsWorkerSendAttemptV1 {
    ZfsWorkerSendAttemptV1 {
        original: send_fixed_worker_record_v1(socket, packet, ZfsSendProfileV1(kind), deadline),
    }
}

/// Sends one closed fixed descriptor-worker frame with its actual borrowed rights.
///
/// Only the first request frame carries two rights. Continuations and the ACK
/// carry none. Capacity, native send, carrier posts and deadline/wait results
/// remain resident on refusal; this supplies no worker or financial authority.
#[must_use]
pub fn send_descriptor_worker_record_v1(
    socket: &mut DescriptorSubjectSocket, packet: &[u8], rights: &[BorrowedFd<'_>],
    kind: DescriptorWorkerSendKindV1, deadline: u64,
) -> DescriptorWorkerSendAttemptV1 {
    DescriptorWorkerSendAttemptV1 {
        original: send_fixed_worker_record_v1(socket, packet, DescriptorSendProfileV1 { kind, rights }, deadline),
    }
}


/// Names the existing Network worker packet and exact borrowed rights shape.
#[derive(Clone, Copy, Debug)]
pub enum NetworkWorkerSendKindV4 {
    /// Existing64KiB first preparation frame with the host namespace right.
    PreparationFirst,
    /// V2 first frame: signed63 host right or signed9 target+host rights.
    PreparationFirstV2,
    /// Existing64KiB continuation with no additional rights.
    PreparationContinuation,
    /// Existing184+512KiB observation request with host and target rights.
    ObservationRequest,
    /// Existing ten-byte acknowledgement without rights.
    Acknowledgment,
}

/// Retains a bounded Network send and its exact original effect-gate refusal.
#[derive(Debug)]
pub struct NetworkWorkerSendAttemptV4<E> {
    original: FixedWorkerSendAttemptV1<NetworkWorkerNativeSendV4<E>>,
}

#[derive(Debug)]
struct NetworkWorkerNativeSendV4<E> {
    receipt: Result<super::descriptor_subject::DescriptorWorkerNativeSendAttemptV1, SeqpacketError>,
    gate: Option<NetworkWorkerNativeGateFailureV4<E>>,
}

#[derive(Debug)]
enum NetworkWorkerNativeGateFailureV4<E> {
    Cutoff(aos_linux_descriptors::Error),
    Original(E),
}

impl<E: std::error::Error + 'static> FixedWorkerNativeSendReceiptV1
    for NetworkWorkerNativeSendV4<E>
{
    fn is_sent(&self) -> bool {
        self.gate.is_none() && self.receipt.is_sent()
    }
    fn is_nonconsuming(&self) -> bool {
        self.gate.is_none() && self.receipt.is_nonconsuming()
    }
    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.gate.as_ref() {
            Some(NetworkWorkerNativeGateFailureV4::Cutoff(error)) => Some(error),
            Some(NetworkWorkerNativeGateFailureV4::Original(error)) => Some(error),
            None => self.receipt.failure(),
        }
    }
}

impl<E: std::error::Error + 'static> NetworkWorkerSendAttemptV4<E> {
    /// Reports an atomic full send with positive original and deadline posts.
    #[must_use]
    pub fn is_sent(&self) -> bool {
        self.original.is_sent()
    }

    /// Borrows the earliest actual native, original-gate or deadline refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.failure()
    }

    /// Borrows only the failed actual final native effect gate, if selected.
    #[must_use]
    pub fn original_gate_failure_v4(&self) -> Option<&E> {
        if !matches!(self.original.first, Some(FixedWorkerSendFailureV1::Send)) {
            return None;
        }
        match self.original.sent.as_ref()?.gate.as_ref()? {
            NetworkWorkerNativeGateFailureV4::Original(error) => Some(error),
            NetworkWorkerNativeGateFailureV4::Cutoff(_) => None,
        }
    }

    /// Prices the compiled receipt and both bounded native-attempt frames.
    #[must_use]
    pub fn receiving_bytes_v4() -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(
                super::descriptor_subject::DescriptorWorkerNativeSendAttemptV1::requested_bytes_v1(
                )?
                .checked_mul(2)?,
            )?
            .checked_add(std::mem::size_of::<[PollFd<'_>; 1]>())?
            .checked_add(4 * std::mem::size_of::<Timespec>())?
            .checked_add(super::NetworkWorkerNativeCutoffV4::receiving_bytes_v4()?.checked_mul(2)?)
    }
}

struct NetworkWorkerWaitV4(super::NetworkWorkerNativeCutoffV4);

impl WorkerWait for NetworkWorkerWaitV4 {
    fn boottime(&self) -> Result<u64, WorkerRecordError> {
        self.0.check_v4()?;
        worker_boottime()
    }
    fn before_poll(&self) -> Result<(), WorkerRecordError> {
        Ok(self.0.check_v4()?)
    }
    fn poll(
        &self,
        fd: BorrowedFd<'_>,
        events: PollFlags,
        timeout: &Timespec,
    ) -> Result<usize, rustix::io::Errno> {
        NativeWorkerWait.poll(fd, events, timeout)
    }
}

struct NetworkWorkerReceiveProfileV4 {
    kind: super::NetworkWorkerRecordKindV4,
    cutoff: super::NetworkWorkerNativeCutoffV4,
}

impl FixedWorkerReceiveProfile<DescriptorSubjectSocket, ReceivedDescriptorRecord>
    for NetworkWorkerReceiveProfileV4
{
    fn after_receive(&self, deadline: u64) -> Result<(), WorkerRecordError> {
        self.cutoff.check_v4()?;
        check_worker_deadline(deadline)
    }
    fn provision(&self, socket: &DescriptorSubjectSocket) -> Option<Result<(), SeqpacketError>> {
        Some(
            self.cutoff
                .check_v4()
                .map_err(SeqpacketError::from)
                .and_then(|()| {
                    socket.provision_packet_capacity(self.kind.maximum_payload_bytes_v4())
                }),
        )
    }
    fn receive(
        &self,
        socket: &mut DescriptorSubjectSocket,
    ) -> Result<ReceivedDescriptorRecord, super::RetainedSeqpacketReceiveErrorV1> {
        socket.receive_network_worker_retaining_v4(self.kind, self.cutoff)
    }
    fn wait(
        &self,
        socket: &DescriptorSubjectSocket,
        deadline: u64,
    ) -> Result<(), WorkerRecordError> {
        let fd = socket.as_fd().map_err(WorkerRecordError::from)?;
        wait_worker_before(
            &NetworkWorkerWaitV4(self.cutoff),
            fd,
            PollFlags::IN,
            deadline,
        )
    }
}

/// Receives one closed Network record through the shared retained retry engine.
///
/// # Errors
/// Retains all native failures and any late/partial record. Original BOOTTIME
/// and absolute WALL checks precede each preview, consume and readiness poll.
pub fn receive_network_worker_record_v4(
    socket: &mut DescriptorSubjectSocket,
    kind: super::NetworkWorkerRecordKindV4,
    cutoff: super::NetworkWorkerNativeCutoffV4,
) -> Result<ReceivedDescriptorRecord, WorkerObserverReceiveErrorV1> {
    receive_fixed_worker_record(
        socket,
        NetworkWorkerReceiveProfileV4 { kind, cutoff },
        cutoff.original_deadline_v4(),
    )
}

/// Waits for the issued worker's next record under its original transport cut.
///
/// This shares the existing Network poll/clock reducer and grants no Source or
/// effect authority. After a wait refusal the caller may only attempt its
/// separately prepaid nonblocking negative/disposition receive, retaining the
/// wait error; it cannot renew the deadline or infer successful completion.
///
/// # Errors
/// Retains the actual native poll, conversion or unchanged cutoff refusal.
pub fn wait_network_worker_record_ready_data_v2(
    socket: &DescriptorSubjectSocket,
    cutoff: super::NetworkWorkerNativeCutoffV4,
) -> Result<(), WorkerRecordError> {
    let fd = socket.as_fd().map_err(WorkerRecordError::from)?;
    wait_worker_before(&NetworkWorkerWaitV4(cutoff), fd, PollFlags::IN,
        cutoff.original_deadline_v4())
}

struct NetworkWorkerSendProfileV4<'rights, 'fd, 'gate, E> {
    kind: NetworkWorkerSendKindV4,
    rights: &'rights [BorrowedFd<'fd>],
    cutoff: super::NetworkWorkerNativeCutoffV4,
    gate: std::cell::RefCell<&'gate mut dyn FnMut() -> Result<(), E>>,
}

impl<E: std::error::Error + 'static>
    FixedWorkerSendProfileV1<DescriptorSubjectSocket, NetworkWorkerNativeSendV4<E>>
    for NetworkWorkerSendProfileV4<'_, '_, '_, E>
{
    fn maximum(&self) -> usize {
        match self.kind {
            NetworkWorkerSendKindV4::PreparationFirst
            | NetworkWorkerSendKindV4::PreparationFirstV2
            | NetworkWorkerSendKindV4::PreparationContinuation => 64 * 1024,
            NetworkWorkerSendKindV4::ObservationRequest => 184 + 512 * 1024,
            NetworkWorkerSendKindV4::Acknowledgment => 10,
        }
    }
    fn maximum_attempts(&self) -> Option<usize> {
        Some(2)
    }
    fn shape_error(&self) -> Option<SeqpacketError> {
        if matches!(self.kind, NetworkWorkerSendKindV4::PreparationFirstV2) {
            return (!matches!(self.rights.len(), 1 | 2)).then_some(SeqpacketError::InvalidMaximum);
        }
        let expected = match self.kind {
            NetworkWorkerSendKindV4::PreparationFirst => 1,
            NetworkWorkerSendKindV4::ObservationRequest => 2,
            _ => 0,
        };
        (self.rights.len() != expected).then_some(SeqpacketError::InvalidMaximum)
    }
    fn provision(&self, socket: &DescriptorSubjectSocket) -> Option<Result<(), SeqpacketError>> {
        Some(
            self.cutoff
                .check_v4()
                .map_err(SeqpacketError::from)
                .and_then(|()| socket.provision_packet_capacity(self.maximum())),
        )
    }
    fn send(
        &self,
        socket: &mut DescriptorSubjectSocket,
        packet: &[u8],
    ) -> NetworkWorkerNativeSendV4<E> {
        let mut original_gate = self.gate.borrow_mut();
        let mut gate = || {
            self.cutoff
                .check_v4()
                .map_err(NetworkWorkerNativeGateFailureV4::Cutoff)?;
            original_gate().map_err(NetworkWorkerNativeGateFailureV4::Original)
        };
        let (receipt, gate) =
            socket.send_worker_record_with_gate_v4(packet, self.rights, Some(&mut gate));
        NetworkWorkerNativeSendV4 { receipt, gate }
    }
    fn wait(
        &self,
        socket: &DescriptorSubjectSocket,
        deadline: u64,
    ) -> Result<(), WorkerRecordError> {
        let fd = socket.as_fd().map_err(WorkerRecordError::from)?;
        wait_worker_before(
            &NetworkWorkerWaitV4(self.cutoff),
            fd,
            PollFlags::OUT,
            deadline,
        )
    }
}

/// Sends one existing Network packet through the same bounded native engine.
///
/// At most two actual native sends enter. The caller's same-original gate runs
/// after framing/carrier checks immediately before every actual syscall; all
/// retries consume another gate entry. A final native refusal remains owned.
#[must_use]
pub fn send_network_worker_record_v4<E: std::error::Error + 'static>(
    socket: &mut DescriptorSubjectSocket,
    packet: &[u8],
    rights: &[BorrowedFd<'_>],
    kind: NetworkWorkerSendKindV4,
    cutoff: super::NetworkWorkerNativeCutoffV4,
    gate: &mut dyn FnMut() -> Result<(), E>,
) -> NetworkWorkerSendAttemptV4<E> {
    NetworkWorkerSendAttemptV4 {
        original: send_fixed_worker_record_v1(
            socket,
            packet,
            NetworkWorkerSendProfileV4 {
                kind,
                rights,
                cutoff,
                gate: std::cell::RefCell::new(gate),
            },
            cutoff.original_deadline_v4(),
        ),
    }
}

/// Returns the complete fixed Network receive wrapper and native backing shape.
#[must_use]
pub fn network_worker_record_obligations_v4(
    kind: super::NetworkWorkerRecordKindV4,
) -> Option<(usize, usize)> {
    let (raw, files) = DescriptorSubjectSocket::network_worker_receive_obligations_v4(kind)?;
    let wrapper = worker_observer_record_obligations_v1()
        .0
        .checked_sub(DescriptorSubjectSocket::worker_observer_receive_obligations_v1().0)?;
    Some((raw.checked_add(wrapper)?, files))
}

#[cfg(test)]
mod network_worker_native_tests {
    use super::*;
    use std::os::fd::AsFd as _;

    fn pair() -> (DescriptorSubjectSocket, DescriptorSubjectSocket) {
        let (first, second) = aos_linux_descriptors::native::seqpacket_pair().unwrap();
        (
            DescriptorSubjectSocket::from_owned_retaining(first).unwrap(),
            DescriptorSubjectSocket::from_owned_retaining(second).unwrap(),
        )
    }

    fn horizon() -> super::super::NetworkWorkerNativeCutoffV4 {
        let boot = worker_boottime().unwrap();
        let wall = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
        super::super::NetworkWorkerNativeCutoffV4::new(
            boot,
            wall.tv_sec,
            boot + 5_000_000_000,
            None,
        )
    }

    #[test]
    fn refused_final_native_gate_keeps_original_error_and_emits_no_bytes_or_rights() {
        let (mut sender, mut receiver) = pair();
        let file = std::fs::File::open("/dev/null").unwrap();
        let mut calls = 0;
        let mut gate = || -> Result<(), std::io::Error> {
            calls += 1;
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        };

        let refused = send_network_worker_record_v4(
            &mut sender,
            &[7; 544],
            &[file.as_fd()],
            NetworkWorkerSendKindV4::PreparationFirst,
            horizon(),
            &mut gate,
        );

        assert_eq!(calls, 1);
        assert!(!refused.is_sent());
        let cause = refused.original_gate_failure_v4().unwrap();
        assert_eq!(cause.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(std::ptr::eq(
            refused
                .failure()
                .unwrap()
                .downcast_ref::<std::io::Error>()
                .unwrap(),
            cause
        ));
        let native = refused.original.sent.as_ref().unwrap();
        assert!(native.receipt.as_ref().unwrap().retains_descriptor());
        // The same failed sender was shut down without a packet; no borrowed
        // right became a delivered record on the original peer.
        let received = receiver.receive_network_worker_retaining_v4(
            super::super::NetworkWorkerRecordKindV4::PreparationReady,
            horizon(),
        );
        assert!(received.is_err());
    }

    #[test]
    fn genuine_preparation_ready_keeps_exact_original_namespace_role_order() {
        let (mut sender, mut receiver) = pair();
        let file = std::fs::File::open("/dev/null").unwrap();
        sender
            .send_with_descriptors(&[4; 544], &[file.as_fd()])
            .unwrap();

        let received = receive_network_worker_record_v4(
            &mut receiver,
            super::super::NetworkWorkerRecordKindV4::PreparationReady,
            horizon(),
        )
        .unwrap();

        assert_eq!(received.payload(), &[4; 544]);
        assert_eq!(received.descriptors().len(), 1);
        let actual = rustix::fs::fstat(&received.descriptors()[0]).unwrap();
        let original = rustix::fs::fstat(&file).unwrap();
        assert_eq!(
            (actual.st_dev, actual.st_ino),
            (original.st_dev, original.st_ino)
        );
    }

    #[test]
    fn expired_wall_refuses_before_the_actual_native_send() {
        let (mut sender, _receiver) = pair();
        let boot = worker_boottime().unwrap();
        let wall = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
        let cutoff = super::super::NetworkWorkerNativeCutoffV4::new(
            boot,
            wall.tv_sec,
            boot + 5_000_000_000,
            Some(wall.tv_sec),
        );
        let mut gate = || -> Result<(), std::io::Error> {
            panic!("expired absolute wall ceiling must precede the effect callback")
        };

        let refused = send_network_worker_record_v4(
            &mut sender,
            &[1; 10],
            &[],
            NetworkWorkerSendKindV4::Acknowledgment,
            cutoff,
            &mut gate,
        );

        assert!(!refused.is_sent());
        assert!(refused.original_gate_failure_v4().is_none());
        assert!(refused.failure().unwrap().is::<SeqpacketError>());
        assert!(refused.original.sent.is_none());
    }
}
