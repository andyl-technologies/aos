//! Retains the shared native record IO of fixed local Ownership carriers.
//!
//! This private mechanism owns no payer, trust key, service role or authority.
//! Genuine service and Create originals admit its complete actual layouts and
//! independently validate their own process/profile/Journal/currentness posts.

use std::error::Error;
use std::time::{Duration, Instant};
use aos_sandbox_linux::seqpacket::{RecordBindingError, ReceivedRecord,
    RetainedSeqpacketReceiveErrorV1, RetainedSeqpacketSendErrorV1, SeqpacketError, SeqpacketSocket};
use rustix::event::{PollFd, PollFlags, Timespec, poll};

/// Bounds one fixed local Ownership record exchange.
pub const TIMEOUT: Duration = Duration::from_secs(30);
const IO_CLOSED: OwnershipRecordIoClosedV1 = OwnershipRecordIoClosedV1;

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the retained local Ownership record IO is closed")]
/// Marks refused IO while the owning exchange retains its actual cause.
pub struct OwnershipRecordIoClosedV1;

#[derive(Default)]
/// Retains actual record IO and deadline/native results without a MAC or payer.
pub struct OwnershipRecordIoV1 {
    /// Retains the actual local exchange start.
    pub start: Option<Instant>,
    /// Retains the bounded local deadline.
    pub deadline: Option<Instant>,
    /// Retains the last actual local deadline observation.
    pub last_now: Option<Instant>,
    /// Retains the whole actual received record or native owning error.
    pub received: Option<Result<ReceivedRecord, RetainedSeqpacketReceiveErrorV1>>,
    /// Retains the received record's same-socket comparison Result.
    pub binding: Option<Result<(), RecordBindingError>>,
    /// Retains the exact credential comparison Result.
    pub subject: Option<Result<(), OwnershipRecordIoClosedV1>>,
    /// Retains the actual receive wait and deadline outcome.
    pub receive_wait: SocketWait,
    /// Retains the post-receive deadline comparison Result.
    pub received_timely: Option<Result<(), OwnershipRecordIoClosedV1>>,
    /// Retains the actual send wait and deadline outcome.
    pub send_wait: SocketWait,
    /// Retains the post-send deadline comparison Result.
    pub sent_timely: Option<Result<(), OwnershipRecordIoClosedV1>>,
    /// Retains the complete actual native send Result.
    pub sent: Option<Result<(), RetainedSeqpacketSendErrorV1>>,
    /// Retains the exact encoded outgoing frame bytes.
    pub outgoing: Option<Vec<u8>>,
    original_cutoff: Option<u64>,
    before_send: BootCutObservation,
    after_send: BootCutObservation,
    before_receive: BootCutObservation,
    after_receive: BootCutObservation,
}

impl OwnershipRecordIoV1 {
    /// Records the actual local start and bounded deadline once.
    ///
    /// # Errors
    /// Refuses reentry or an unrepresentable actual deadline.
    pub fn arm_deadline_once(&mut self) -> Result<(), OwnershipRecordIoClosedV1> {
        if self.start.is_some() { return Err(IO_CLOSED); }
        let start = Instant::now();
        self.start = Some(start);
        self.deadline = start.checked_add(TIMEOUT);
        self.deadline.ok_or(IO_CLOSED).map(|_| ())
    }

    // Only the actual Create owner supplies its unchanged original cutoff.
    // These inert copies confer no financial/currentness authority.
    /// Records the caller-held immutable cutoff comparison DATA once.
    ///
    /// # Errors
    /// Refuses a repeated cutoff; this supplies no original clock or grant.
    pub fn set_original_cutoff_once(&mut self, cutoff: u64) -> Result<(), OwnershipRecordIoClosedV1> {
        if self.original_cutoff.is_some() || cutoff == 0 { return Err(IO_CLOSED); }
        self.original_cutoff = Some(cutoff);
        Ok(())
    }

    /// Borrows the same exchange owner's recorded deadline DATA.
    ///
    /// # Errors
    /// Refuses an absent or already installed deadline.
    pub fn adopt_deadline_from(&mut self, original: &Self) -> Result<(), OwnershipRecordIoClosedV1> {
        if self.start.is_some() || original.start.is_none() || original.deadline.is_none() {
            return Err(IO_CLOSED);
        }
        self.start = original.start;
        self.deadline = original.deadline;
        self.original_cutoff = original.original_cutoff;
        Ok(())
    }

    /// Borrows the earliest reached receive/native/deadline cause.
    pub fn receive_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.before_receive.failure().or_else(|| error(&self.received)).or_else(|| error(&self.binding))
            .or_else(|| error(&self.subject)).or_else(|| self.receive_wait.failure())
            .or_else(|| error(&self.received_timely)).or_else(|| self.after_receive.failure())
    }

    /// Borrows the earliest reached send/native/deadline cause.
    pub fn send_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.send_wait.failure().or_else(|| self.before_send.failure()).or_else(|| error(&self.sent))
            .or_else(|| error(&self.sent_timely)).or_else(|| self.after_send.failure())
    }
}

/// Receives through the existing strict native record engine.
///
/// The caller separately prepays its actual fixed role and validates MAC/session
/// authority; payload bounds and UID/GID comparisons alone supply neither.
///
/// # Errors
/// Retains complete receive, subject, binding, wait and clock Results.
pub fn receive(socket: &mut SeqpacketSocket, exchange: &mut OwnershipRecordIoV1, maximum: usize, uid: u32, gid: u32) -> Result<(), OwnershipRecordIoClosedV1> {
    let until = exchange.deadline.ok_or(IO_CLOSED)?;
    loop {
        exchange.before_receive.observe(exchange.original_cutoff)?;
        exchange.received = Some(socket.receive_local_ownership_retaining_v1(maximum));
        if matches!(&exchange.received, Some(Err(error)) if error.is_nonconsuming_would_block() || error.is_nonconsuming_interrupted()) {
            // Only the lower's actual completed no-acquisition classification
            // permits disposal/retry. Fatal/consumed/late records stay resident.
            drop(exchange.received.take());
            wait_with_cutoff(socket, &mut exchange.receive_wait, PollFlags::IN, until, exchange.original_cutoff)?;
            continue;
        }
        break;
    }
    let record = exchange.received.as_ref().and_then(|result| result.as_ref().ok()).ok_or(IO_CLOSED)?;
    exchange.binding = Some(socket.compare_local_ownership_received_original_v1(record));
    exchange.subject = Some(if record.subject().credentials().uid() == uid
        && record.subject().credentials().gid() == gid { Ok(()) } else { Err(IO_CLOSED) });
    exchange.after_receive.observe(exchange.original_cutoff)?;
    exchange.last_now = Some(Instant::now());
    exchange.received_timely = Some(if exchange.last_now.is_some_and(|now| now <= until) { Ok(()) } else { Err(IO_CLOSED) });
    if !matches!(exchange.binding, Some(Ok(()))) || !matches!(exchange.subject, Some(Ok(())))
        || !matches!(exchange.received_timely, Some(Ok(()))) { return Err(IO_CLOSED); }
    Ok(())
}

/// Sends the actual parked outgoing record through the same retained engine.
///
/// # Errors
/// Retains native send/wait/clock Results, including late positive native sends.
pub fn send(socket: &mut SeqpacketSocket, exchange: &mut OwnershipRecordIoV1) -> Result<(), OwnershipRecordIoClosedV1> {
    let until = exchange.deadline.ok_or(IO_CLOSED)?;
    wait_with_cutoff(socket, &mut exchange.send_wait, PollFlags::OUT, until, exchange.original_cutoff)?;
    exchange.before_send.observe(exchange.original_cutoff)?;
    exchange.sent = Some(socket.send_retaining(exchange.outgoing.as_ref().ok_or(IO_CLOSED)?));
    exchange.sent.as_ref().and_then(|result| result.as_ref().ok()).ok_or(IO_CLOSED)?;
    exchange.after_send.observe(exchange.original_cutoff)?;
    exchange.last_now = Some(Instant::now());
    exchange.sent_timely = Some(if exchange.last_now.is_some_and(|now| now <= until) { Ok(()) } else { Err(IO_CLOSED) });
    exchange.sent_timely.as_ref().and_then(|result| result.as_ref().ok()).ok_or(IO_CLOSED)?;
    Ok(())
}

// Receive and send retain distinct wait outcomes. A completed receive wait
// cannot conceal a later send timeout, and posts cannot outrank either one.
#[derive(Default)]
/// Retains one actual native wait and its chronological timeout result.
pub struct SocketWait {
    observed_at: Option<Instant>,
    timeout: Option<Result<Timespec, std::num::TryFromIntError>>,
    descriptor: Option<Result<(), SeqpacketError>>,
    /// Retains the complete native poll Result.
    pub poll: Option<Result<usize, rustix::io::Errno>>,
    revents: Option<PollFlags>,
    /// Retains the actual wait classification before later independent posts.
    pub outcome: Option<Result<(), OwnershipRecordIoClosedV1>>,
    cutoff: BootCutObservation,
}

impl SocketWait {
    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.cutoff.failure().or_else(|| error(&self.timeout)).or_else(|| error(&self.descriptor))
            .or_else(|| error(&self.poll)).or_else(|| error(&self.outcome))
    }
}

#[cfg(test)]
/// Waits on the supplied original socket under its recorded finite deadline.
///
/// # Errors
/// Retains actual poll/deadline outcomes and rejects invalid readiness.
pub fn wait(socket: &SeqpacketSocket, observation: &mut SocketWait, interest: PollFlags, until: Instant) -> Result<(), OwnershipRecordIoClosedV1> {
    wait_with_cutoff(socket, observation, interest, until, None)
}

fn wait_with_cutoff(socket: &SeqpacketSocket, observation: &mut SocketWait,
    interest: PollFlags, until: Instant, cutoff: Option<u64>) -> Result<(), OwnershipRecordIoClosedV1> {
    // Previous successful/no-acquisition waits have no lasting effects. The
    // same paid peak is reused; any terminal refusal remains in this slot.
    *observation = SocketWait::default();
    let result = (|| {
        loop {
            let now = Instant::now();
            observation.observed_at = Some(now);
            let duration = until.checked_duration_since(now)
                .filter(|duration| !duration.is_zero()).ok_or(IO_CLOSED)?;
            observation.cutoff.observe(cutoff)?;
            let duration = match (cutoff, observation.cutoff.nanoseconds.as_ref()) {
                (Some(cutoff), Some(Ok(Some(current)))) => duration.min(Duration::from_nanos(
                    cutoff.checked_sub(*current).filter(|remaining| *remaining != 0).ok_or(IO_CLOSED)?)),
                (None, _) => duration,
                _ => return Err(IO_CLOSED),
            };
            observation.timeout = Some(Timespec::try_from(duration));
            let timeout = observation.timeout.as_ref()
                .and_then(|result| result.as_ref().ok()).ok_or(IO_CLOSED)?;
            let fd = match socket.as_fd() {
                Ok(fd) => { observation.descriptor = Some(Ok(())); fd }
                Err(cause) => { observation.descriptor = Some(Err(cause)); return Err(IO_CLOSED); }
            };
            let mut descriptors = [PollFd::new(&fd, interest)];
            observation.poll = Some(poll(&mut descriptors, Some(timeout)));
            observation.revents = Some(descriptors[0].revents());
            match observation.poll.as_ref() {
                Some(Ok(_)) if descriptors[0].revents().contains(interest) => return Ok(()),
                Some(Err(rustix::io::Errno::INTR)) => {
                    // EINTR acquires nothing. Dispose only this completed
                    // transient before retrying under the original deadline.
                    drop(observation.poll.take());
                }
                _ => return Err(IO_CLOSED),
            }
        }
    })();
    observation.outcome = Some(result);
    result
}

#[derive(Default)]
struct BootCutObservation {
    native: Option<rustix::time::Timespec>,
    nanoseconds: Option<Result<Option<u64>, std::num::TryFromIntError>>,
    admitted: Option<Result<(), OwnershipRecordIoClosedV1>>,
}

impl BootCutObservation {
    fn observe(&mut self, cutoff: Option<u64>) -> Result<(), OwnershipRecordIoClosedV1> {
        let Some(cutoff) = cutoff else { return Ok(()); };
        let native = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        self.native = Some(native);
        self.nanoseconds = Some((|| {
            let seconds = u64::try_from(native.tv_sec)?;
            let nanos = u64::try_from(native.tv_nsec)?;
            // Overflow is retained as an unavailable cut with the full sample;
            // representable kernel seconds/nanoseconds remain independently held.
            Ok::<_, std::num::TryFromIntError>(seconds.checked_mul(1_000_000_000).and_then(|value| value.checked_add(nanos)))
        })());
        self.admitted = Some(if self.nanoseconds.as_ref().and_then(|result| result.as_ref().ok()).copied().flatten()
            .is_some_and(|current| current < cutoff) { Ok(()) } else { Err(IO_CLOSED) });
        self.admitted.as_ref().and_then(|result| result.as_ref().ok()).map(|_| ()).ok_or(IO_CLOSED)
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.nanoseconds).or_else(|| error(&self.admitted))
    }
}

fn error<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_original_boottime_cutoff_prevents_actual_send() {
        let (mut socket, endpoint) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut peer = SeqpacketSocket::from_owned(endpoint).unwrap();
        let mut io = OwnershipRecordIoV1::default();
        io.arm_deadline_once().unwrap();
        io.set_original_cutoff_once(1).unwrap();
        io.outgoing = Some(vec![1, 2, 3]);

        assert!(send(&mut socket, &mut io).is_err());

        assert!(io.sent.is_none());
        assert!(io.send_failure().is_some());
        assert!(matches!(peer.receive(3), Err(SeqpacketError::WouldBlock)));
    }
}
