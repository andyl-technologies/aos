//! Deadline-bounded record exchange for record-subject services.
//!
//! Plain and closed descriptor-reply adapters share one retry engine. These
//! operations return transport data only; peers, descriptor roles, authority,
//! currentness, acknowledgements, and worker quiescence remain caller-owned.

use std::os::fd::{AsFd, BorrowedFd};
use std::time::Duration;

use rustix::event::{PollFd, PollFlags, Timespec, poll};

use super::descriptor_subject::{DescriptorSubjectSocket, ReceivedDescriptorRecord};
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

#[derive(Debug, thiserror::Error)]
pub enum WorkerRecordError {
    #[error(transparent)]
    Transport(#[from] SeqpacketError),
    #[error(transparent)]
    Poll(#[from] rustix::io::Errno),
    #[error(transparent)]
    Linux(#[from] crate::Error),
    #[error(transparent)]
    Clock(#[from] WorkerRecordClockError),
}

#[derive(Debug, thiserror::Error)]
pub enum WorkerRecordClockError {
    #[error("CLOCK_BOOTTIME seconds are invalid")]
    InvalidSeconds,
    #[error("CLOCK_BOOTTIME nanoseconds are invalid")]
    InvalidNanoseconds,
    #[error("CLOCK_BOOTTIME overflowed")]
    Overflow,
    #[error("worker record transfer deadline elapsed")]
    Expired,
    #[error("worker record transfer deadline is invalid")]
    InvalidTimeout,
}

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
            Err(SeqpacketError::Kernel(crate::Error::InvalidInput {
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
    let seconds = u64::try_from(now.tv_sec)
        .map_err(|_| WorkerRecordClockError::InvalidSeconds)?;
    let nanoseconds = u64::try_from(now.tv_nsec)
        .map_err(|_| WorkerRecordClockError::InvalidNanoseconds)?;
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

trait WorkerWait {
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
        fn new(clocks: impl IntoIterator<Item = u64>, polls: Vec<Result<usize, rustix::io::Errno>>) -> Self {
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
                return Err(crate::Error::invalid("descriptor inspection", "test refusal").into());
            }
            Ok(())
        }
    }

    fn pair() -> (DescriptorSubjectSocket, DescriptorSubjectSocket) {
        let (first, second) = crate::uapi::seqpacket_pair().unwrap();
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
                wait: ScriptedWait::new([10, 20, 30, 40, 50, 60], vec![Err(rustix::io::Errno::INTR), Ok(1)]),
                reject: false,
            };
            let first = if interrupted { SeqpacketError::Interrupted } else { SeqpacketError::WouldBlock };
            let mut outcomes = VecDeque::from([Err(first), Ok(())]);

            exchange_record(&profile, &mut socket, PollFlags::OUT, 100, |_| {
                profile.wait.trace.borrow_mut().push("attempt");
                outcomes.pop_front().unwrap()
            }).unwrap();

            assert_eq!(*profile.wait.trace.borrow(), [
                "clock", "attempt", "borrow", "clock", "poll", "clock", "poll",
                "clock", "clock", "attempt", "inspect", "clock",
            ]);
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

            assert!(matches!(result, Err(WorkerRecordError::Clock(WorkerRecordClockError::Expired))));
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
                Err(expected) => assert!(matches!(result, Err(WorkerRecordError::Poll(actual)) if actual == expected)),
                Ok(_) => assert!(matches!(result, Err(WorkerRecordError::Clock(WorkerRecordClockError::Expired)))),
            }
            assert_eq!(attempts.get(), 1);
            assert_eq!(profile.wait.clocks.borrow().len(), 1);
            assert_eq!(*profile.wait.trace.borrow(), ["clock", "borrow", "clock", "poll"]);
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

        assert!(matches!(result, Err(WorkerRecordError::Transport(SeqpacketError::Closed))));
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

        assert!(matches!(result, Err(WorkerRecordError::Transport(SeqpacketError::InvalidMaximum))));
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
            profile.wait.clocks.borrow_mut().push_back(Err(reason.into()));

            let result = exchange_record(&profile, &mut socket, PollFlags::IN, 100, |_| -> Result<(), SeqpacketError> {
                panic!("invalid clock must precede the attempt")
            });

            assert!(matches!(result, Err(WorkerRecordError::Clock(actual)) if std::mem::discriminant(&actual) == expected));
            assert_eq!(*profile.wait.trace.borrow(), ["clock"]);
        }
    }

    #[test]
    fn inspection_refusal_precedes_late_clock_and_both_drop_the_complete_record() {
        for reject in [false, true] {
            let (mut sender, mut receiver) = pair();
            let (reader, writer) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::NONBLOCK | rustix::pipe::PipeFlags::CLOEXEC).unwrap();
            send_provisioned_worker_record(&mut sender, b"consumed", &[writer.as_fd(), writer.as_fd()], u64::MAX).unwrap();
            drop(writer);
            let profile = ScriptedWorkerProfile {
                wait: ScriptedWait::new([10, 100], vec![]),
                reject,
            };

            let result = exchange_record(&profile, &mut receiver, PollFlags::IN, 100, |socket| socket.receive(64, 2));

            if reject {
                assert!(matches!(result, Err(WorkerRecordError::Linux(_))));
                assert_eq!(profile.wait.clocks.borrow().len(), 1);
                assert_eq!(*profile.wait.trace.borrow(), ["clock", "inspect"]);
            } else {
                assert!(matches!(result, Err(WorkerRecordError::Clock(WorkerRecordClockError::Expired))));
                assert!(profile.wait.clocks.borrow().is_empty());
                assert_eq!(*profile.wait.trace.borrow(), ["clock", "inspect", "clock"]);
            }
            assert_eq!(rustix::io::read(&reader, &mut [0_u8; 1]).unwrap(), 0);
            assert!(matches!(receiver.receive(64, 0), Err(SeqpacketError::WouldBlock)));
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

                send_provisioned_worker_record(&mut sender, b"worker", &rights[..count], u64::MAX).unwrap();
                let receive = if inspected {
                    receive_provisioned_worker_record_without_io_uring
                } else {
                    receive_provisioned_worker_record
                };
                let record = receive(&mut receiver, 64, count, u64::MAX).unwrap();

                assert_eq!(record.payload(), b"worker");
                assert_eq!(record.descriptors().len(), count);
                assert_eq!(record.subject().credentials().pid().get(), std::process::id());
                for (received, sent) in record.descriptors().iter().zip(rights) {
                    assert_eq!(rustix::fs::fstat(received).unwrap().st_ino, rustix::fs::fstat(sent).unwrap().st_ino);
                    assert!(crate::uapi::is_cloexec(received.as_fd()).unwrap());
                }
            }
        }
    }

    #[test]
    fn provisioned_worker_capacity_and_native_count_validation_keep_their_frontiers() {
        let (mut socket, _peer) = pair();
        assert!(matches!(send_provisioned_worker_record(&mut socket, b"", &[], 0), Err(WorkerRecordError::Transport(SeqpacketError::InvalidMaximum))));
        for receive in [receive_provisioned_worker_record, receive_provisioned_worker_record_without_io_uring] {
            assert!(matches!(receive(&mut socket, 0, 0, 0), Err(WorkerRecordError::Transport(SeqpacketError::InvalidMaximum))));
            assert!(matches!(receive(&mut socket, 64, 3, 0), Err(WorkerRecordError::Clock(WorkerRecordClockError::Expired))));
            assert!(matches!(receive(&mut socket, 64, 3, u64::MAX), Err(WorkerRecordError::Transport(SeqpacketError::InvalidMaximum))));
        }
    }

    #[test]
    fn provisioned_worker_wrong_right_count_closes_the_carrier_and_disposes_all_rights() {
        for inspected in [false, true] {
            for count in 1..=2 {
                let (mut sender, mut receiver) = pair();
                let (reader, writer) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::NONBLOCK | rustix::pipe::PipeFlags::CLOEXEC).unwrap();
                let rights = vec![writer.as_fd(); count];
                send_provisioned_worker_record(&mut sender, b"wrong", &rights, u64::MAX).unwrap();
                drop(rights);
                drop(writer);
                let receive = if inspected {
                    receive_provisioned_worker_record_without_io_uring
                } else {
                    receive_provisioned_worker_record
                };

                assert!(matches!(receive(&mut receiver, 64, 0, u64::MAX), Err(WorkerRecordError::Transport(_))));
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
        let (receiver, sender) = crate::uapi::seqpacket_pair().unwrap();
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
                assert!(crate::uapi::is_cloexec(descriptor.as_fd()).unwrap());
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
