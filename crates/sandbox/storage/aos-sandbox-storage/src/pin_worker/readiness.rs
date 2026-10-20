//! Shares worker readiness with retained clock, poll and flag observations.
//!
//! Polling acquires no descriptor and grants no effect authority. A selected
//! waiter retains its actual before/poll/after results before classification;
//! only a complete positive nonconsuming observation can reuse local scratch.
//! The ordinary adapter preserves its existing syscall order and diagnostics.

use super::*;
use rustix::event::{PollFd, PollFlags, Timespec};

#[derive(Clone, Copy)]
enum First { Before, Timeout, Poll, After, Completion, Closed }

pub(crate) struct WorkerReadinessOriginalV1 {
    before: Option<rustix::time::Timespec>,
    before_value: Option<Result<u64, ZfsWorkerError>>,
    timeout: Option<Result<Timespec, ZfsWorkerError>>,
    poll: Option<Result<usize, rustix::io::Errno>>,
    revents: Option<PollFlags>,
    after: Option<rustix::time::Timespec>,
    after_value: Option<Result<u64, ZfsWorkerError>>,
    completion: Option<Result<(), ZfsWorkerError>>,
    first: Option<First>,
    closed: Option<ZfsWorkerError>,
    entered: bool,
}

impl WorkerReadinessOriginalV1 {
    pub(crate) fn new() -> Self {
        Self {
            before: None, before_value: None, timeout: None, poll: None,
            revents: None, after: None, after_value: None, completion: None,
            first: None, closed: None, entered: false,
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Before => self.before_value.as_ref()?.as_ref().err().map(|error| error as _),
            First::Timeout => self.timeout.as_ref()?.as_ref().err().map(|error| error as _),
            First::Poll => self.poll.as_ref()?.as_ref().err().map(|error| error as _),
            First::After => self.after_value.as_ref()?.as_ref().err().map(|error| error as _),
            First::Completion => self.completion.as_ref()?.as_ref().err().map(|error| error as _),
            First::Closed => self.closed.as_ref().map(|error| error as _),
        }
    }

    pub(crate) fn is_complete(&self) -> bool {
        matches!(self.completion, Some(Ok(()))) && self.first.is_none()
    }

    pub(crate) fn requested_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(std::mem::size_of::<PollFd<'static>>())?
            .checked_add(5 * 256)
    }
}

pub(crate) fn wait_with_originals_v1(
    descriptor: BorrowedFd<'_>,
    events: PollFlags,
    deadline: u64,
    mut retained: Option<&mut WorkerReadinessOriginalV1>,
) -> Result<(), ZfsWorkerError> {
    if let Some(original) = retained.as_deref_mut() {
        if original.entered {
            original.closed.get_or_insert_with(marker);
            original.first.get_or_insert(First::Closed);
            return Err(marker());
        }
        original.entered = true;
    }
    loop {
        let now = match retained.as_deref_mut() {
            Some(original) => {
                let sample = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
                original.before = Some(sample);
                original.before_value = Some(boottime_from_timespec_v1(sample));
                match original.before_value.as_ref() {
                    Some(Ok(value)) => *value,
                    _ => { original.first = Some(First::Before); return Err(marker()); }
                }
            }
            None => boottime_now_nanoseconds()?,
        };
        let remaining = deadline.checked_sub(now).filter(|remaining| *remaining != 0);
        let Some(remaining) = remaining else {
            return refuse_completion(&mut retained, ZfsWorkerError::Protocol(
                "workspace pin whole-transfer deadline elapsed",
            ));
        };
        let timeout = Timespec::try_from(std::time::Duration::from_nanos(remaining))
            .map_err(|_| ZfsWorkerError::Protocol("workspace pin transfer deadline is invalid"));
        let timeout = match retained.as_deref_mut() {
            Some(original) => {
                original.timeout = Some(timeout);
                match original.timeout.as_ref() {
                    Some(Ok(value)) => *value,
                    _ => { original.first = Some(First::Timeout); return Err(marker()); }
                }
            }
            None => timeout?,
        };
        let mut descriptors = [PollFd::new(&descriptor, events)];
        let result = rustix::event::poll(&mut descriptors, Some(&timeout));
        if let Some(original) = retained.as_deref_mut() {
            original.revents = Some(descriptors[0].revents());
            original.poll = Some(result);
            let native_failed = matches!(original.poll, Some(Err(error)) if error != rustix::io::Errno::INTR);
            if native_failed { original.first = Some(First::Poll); }
            if matches!(original.poll, Some(Ok(0))) {
                original.completion = Some(Err(ZfsWorkerError::Protocol(
                    "workspace pin whole-transfer deadline elapsed",
                )));
                original.first = Some(First::Completion);
            }

            // The actual entered poll owes this local clock even on refusal.
            // Preserve an earlier native error before the later cutoff debt;
            // retryable INTR is an observation, not a primary failure.
            let sample = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
            original.after = Some(sample);
            original.after_value = Some(boottime_from_timespec_v1(sample));
            let current = match original.after_value.as_ref() {
                Some(Ok(value)) => *value < deadline,
                _ => { original.first.get_or_insert(First::After); false }
            };
            if !current {
                if original.completion.is_none() {
                    original.completion = Some(Err(ZfsWorkerError::Protocol(
                        "workspace pin whole-transfer deadline elapsed",
                    )));
                }
                original.first.get_or_insert(First::Completion);
            }
            if original.first.is_some() { return Err(marker()); }
            match original.poll.as_ref() {
                Some(Ok(0)) => return refuse_completion(&mut retained, ZfsWorkerError::Protocol(
                    "workspace pin whole-transfer deadline elapsed",
                )),
                Some(Ok(_)) => { original.completion = Some(Ok(())); return Ok(()); }
                Some(Err(error)) if *error == rustix::io::Errno::INTR => {
                    // Nonconsuming poll + independent local post completed;
                    // actually dispose those compact observations before retry.
                    original.before = None;
                    original.before_value = None;
                    original.timeout = None;
                    original.poll = None;
                    original.revents = None;
                    original.after = None;
                    original.after_value = None;
                }
                _ => std::process::abort(),
            }
        } else {
            // Byte-for-byte equivalent ordinary native result order: INTR
            // retries without another after clock, and native Err stays raw.
            match result {
                Ok(0) => return Err(ZfsWorkerError::Protocol("workspace pin whole-transfer deadline elapsed")),
                Ok(_) => return ensure_before_deadline(deadline),
                Err(rustix::io::Errno::INTR) => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }
}

fn refuse_completion(
    retained: &mut Option<&mut WorkerReadinessOriginalV1>,
    error: ZfsWorkerError,
) -> Result<(), ZfsWorkerError> {
    match retained.as_deref_mut() {
        Some(original) => {
            original.completion = Some(Err(error));
            original.first.get_or_insert(First::Completion);
            Err(marker())
        }
        None => Err(error),
    }
}

fn marker() -> ZfsWorkerError {
    ZfsWorkerError::Protocol("worker readiness original retained")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd as _;

    #[test]
    fn real_ready_pipe_keeps_native_readiness_until_explicit_owner_disposal() {
        let (read, write) = rustix::pipe::pipe().unwrap();
        rustix::io::write(&write, b"x").unwrap();
        let deadline = boottime_now_nanoseconds().unwrap() + 1_000_000_000;
        let mut original = WorkerReadinessOriginalV1::new();

        wait_with_originals_v1(read.as_fd(), PollFlags::IN, deadline, Some(&mut original)).unwrap();
        assert!(original.is_complete());
        assert!(matches!(original.poll, Some(Ok(1))));
        assert!(original.revents.unwrap().contains(PollFlags::IN));
        let first_poll = original.poll;

        assert!(wait_with_originals_v1(read.as_fd(), PollFlags::IN, deadline, Some(&mut original)).is_err());
        assert_eq!(original.poll, first_poll);
        assert!(!original.is_complete());
        assert!(original.failure().is_some());
    }

    #[test]
    fn expired_wait_keeps_actual_clock_and_never_polls_or_consumes_bytes() {
        let (read, write) = rustix::pipe::pipe().unwrap();
        rustix::io::write(&write, b"y").unwrap();
        let mut original = WorkerReadinessOriginalV1::new();

        assert!(wait_with_originals_v1(read.as_fd(), PollFlags::IN, 0, Some(&mut original)).is_err());
        assert!(original.before.is_some());
        assert!(original.poll.is_none());
        let first = original.failure().unwrap() as *const dyn std::error::Error as *const ();
        assert!(wait_with_originals_v1(read.as_fd(), PollFlags::IN, u64::MAX, Some(&mut original)).is_err());
        assert_eq!(first, original.failure().unwrap() as *const dyn std::error::Error as *const ());
        let mut byte = [0];
        assert_eq!(rustix::io::read(&read, &mut byte).unwrap(), 1);
        assert_eq!(byte, *b"y");
    }
}
