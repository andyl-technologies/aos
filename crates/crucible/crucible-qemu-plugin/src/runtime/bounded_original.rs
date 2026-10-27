//! Fixed-credit original messages retained before any modeled worker admission.
//!
//! Producers never wait for receiver capacity or an ownership mutex. A refused
//! submission returns its same owned message; the caller must retain it or
//! terminate under actual supervision. Receiving preserves the original message
//! in this allocation until the caller's independently admitted effect takes it.

// SPDX-License-Identifier: GPL-2.0-or-later

use std::collections::VecDeque;
use std::sync::{Condvar, Mutex, TryLockError};

/// Retains bounded queued messages and one received original message.
pub struct BoundedOriginalMailbox<T> {
    process_id: u32,
    maximum_outstanding: usize,
    state: Mutex<MailboxState<T>>,
    available: Condvar,
}

struct MailboxState<T> {
    next_sequence: u64,
    queue: VecDeque<OriginalMessage<T>>,
    received: Option<OriginalMessage<T>>,
}

struct OriginalMessage<T> {
    sequence: u64,
    message: T,
}

/// Owns the exact refused producer payload; no branch silently consumes it.
#[derive(Debug)]
pub struct SubmissionRefusal<T> {
    /// Records the concrete failed queue transition, without an effect claim.
    pub reason: MailboxRefusal,
    /// Retains the same owned message returned by the producer attempt.
    pub original: T,
}

/// Refuses an ownership or finite-credit transition without consuming a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MailboxRefusal {
    /// Refuses inherited queue state before touching another process's mutex.
    ForeignProcess,
    /// Reports transient ownership contention with the original payload retained.
    Busy,
    /// Reports sticky poisoned ownership.
    Poisoned,
    /// Reports absent, excessive or exhausted finite outstanding-message credit.
    CreditExhausted,
    /// Reports exhausted monotone queue identity before publication.
    IdentityExhausted,
    /// Rejects a mismatched or already consumed original receive identity.
    ForeignSequence,
}

impl<T> BoundedOriginalMailbox<T> {
    /// Allocates finite queue credit before the actual producer path is installed.
    ///
    /// # Errors
    /// Rejects credit outside one through three or insufficient bounded allocation.
    pub fn new(maximum_outstanding: usize) -> Result<Self, MailboxRefusal> {
        if !(1..=3).contains(&maximum_outstanding) {
            return Err(MailboxRefusal::CreditExhausted);
        }
        let mut queue = VecDeque::new();
        queue
            .try_reserve_exact(maximum_outstanding)
            .map_err(|_| MailboxRefusal::CreditExhausted)?;

        Ok(Self {
            process_id: std::process::id(),
            maximum_outstanding,
            state: Mutex::new(MailboxState {
                next_sequence: 1,
                queue,
                received: None,
            }),
            available: Condvar::new(),
        })
    }

    /// Retains only after finite credit, leaving every refused payload owned.
    ///
    /// # Errors
    /// Returns the same owned payload on process, mutex, credit or identity failure.
    pub fn try_submit(&self, message: T) -> Result<u64, SubmissionRefusal<T>> {
        if std::process::id() != self.process_id {
            return Err(SubmissionRefusal {
                reason: MailboxRefusal::ForeignProcess,
                original: message,
            });
        }
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(error) => {
                return Err(SubmissionRefusal {
                    reason: match error {
                        TryLockError::WouldBlock => MailboxRefusal::Busy,
                        TryLockError::Poisoned(_) => MailboxRefusal::Poisoned,
                    },
                    original: message,
                });
            }
        };
        let outstanding = state.queue.len() + usize::from(state.received.is_some());
        let reason = if outstanding == self.maximum_outstanding {
            Some(MailboxRefusal::CreditExhausted)
        } else if state.next_sequence == u64::MAX {
            Some(MailboxRefusal::IdentityExhausted)
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(SubmissionRefusal {
                reason,
                original: message,
            });
        }

        let sequence = state.next_sequence;
        state.next_sequence += 1;
        state.queue.push_back(OriginalMessage { sequence, message });
        drop(state);
        self.available.notify_one();
        Ok(sequence)
    }

    /// Waits only on the actual idle receiver, retaining before modeled entry.
    ///
    /// This method must never run under BQL or callback/model admission. It is a
    /// channel operation, not native worker self-enrollment or an effect permit.
    ///
    /// # Errors
    /// Rejects a foreign process or poisoned ownership while retaining queue data.
    pub fn receive_original(&self) -> Result<u64, MailboxRefusal> {
        if std::process::id() != self.process_id {
            return Err(MailboxRefusal::ForeignProcess);
        }
        let mut state = self.state.lock().map_err(|_| MailboxRefusal::Poisoned)?;
        loop {
            if let Some(original) = &state.received {
                return Ok(original.sequence);
            }
            if let Some(original) = state.queue.pop_front() {
                let sequence = original.sequence;
                state.received = Some(original);
                return Ok(sequence);
            }
            state = self
                .available
                .wait(state)
                .map_err(|_| MailboxRefusal::Poisoned)?;
        }
    }

    /// Checks process identity and poison without receiving or taking a lock.
    ///
    /// This observation does not establish worker or native effect permission.
    pub fn lifetime_valid(&self) -> bool {
        self.process_id == std::process::id() && !self.state.is_poisoned()
    }

    /// Moves the same retained payload to its caller's already admitted operation.
    ///
    /// The sequence supplies correlation only. The concrete installed caller,
    /// not this queue, must validate genuine worker and native-cut permission.
    ///
    /// # Errors
    /// Rejects a foreign process, contention, poison or a foreign original sequence.
    pub fn take_received(&self, sequence: u64) -> Result<T, MailboxRefusal> {
        if std::process::id() != self.process_id {
            return Err(MailboxRefusal::ForeignProcess);
        }
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => return Err(MailboxRefusal::Busy),
            Err(TryLockError::Poisoned(_)) => return Err(MailboxRefusal::Poisoned),
        };
        if state.received.as_ref().map(|message| message.sequence) != Some(sequence) {
            return Err(MailboxRefusal::ForeignSequence);
        }
        state
            .received
            .take()
            .map(|message| message.message)
            .ok_or(MailboxRefusal::ForeignSequence)
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Original channel ownership assertions deliberately panic; no native backend is qualified.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn submit_retrying_busy<T>(mailbox: &BoundedOriginalMailbox<T>, mut original: T) -> u64 {
        for _ in 0..100_000 {
            match mailbox.try_submit(original) {
                Ok(sequence) => return sequence,
                Err(SubmissionRefusal {
                    reason: MailboxRefusal::Busy,
                    original: retained,
                }) => {
                    original = retained;
                    std::thread::yield_now();
                }
                Err(refused) => panic!("unexpected original queue refusal: {:?}", refused.reason),
            }
        }
        panic!("original queue contention did not resolve");
    }

    #[test]
    fn received_original_keeps_finite_credit_until_consumed() {
        let mailbox = BoundedOriginalMailbox::new(1).unwrap();
        let original = Box::new([19u8; 128]);
        let address = std::ptr::from_ref(original.as_ref());
        let sequence = mailbox.try_submit(original).ok().unwrap();

        assert_eq!(mailbox.receive_original().unwrap(), sequence);
        assert_eq!(mailbox.receive_original().unwrap(), sequence);
        let overflow = mailbox.try_submit(Box::new([23u8; 128])).err().unwrap();
        assert_eq!(overflow.reason, MailboxRefusal::CreditExhausted);
        assert_eq!(*overflow.original, [23; 128]);
        assert_eq!(
            mailbox.take_received(sequence + 1).err(),
            Some(MailboxRefusal::ForeignSequence)
        );
        let received = mailbox.take_received(sequence).unwrap();
        assert_eq!(std::ptr::from_ref(received.as_ref()), address);
        assert_eq!(*received, [19; 128]);
        assert_eq!(
            mailbox.take_received(sequence).err(),
            Some(MailboxRefusal::ForeignSequence)
        );
    }

    #[test]
    fn mutex_busy_returns_the_actual_unconsumed_producer_message() {
        let mailbox = BoundedOriginalMailbox::new(1).unwrap();
        let state = mailbox.state.lock().unwrap();
        let original = Box::new([31u8; 128]);
        let address = std::ptr::from_ref(original.as_ref());

        let refused = mailbox.try_submit(original).err().unwrap();
        assert_eq!(refused.reason, MailboxRefusal::Busy);
        assert_eq!(std::ptr::from_ref(refused.original.as_ref()), address);
        assert!(state.queue.is_empty());
        drop(state);
        let sequence = mailbox.try_submit(refused.original).ok().unwrap();
        assert_eq!(mailbox.receive_original().unwrap(), sequence);
        assert_eq!(*mailbox.take_received(sequence).unwrap(), [31; 128]);
    }

    #[test]
    fn actual_blocked_receiver_retains_all_original_fifo_entries() {
        let mailbox = Arc::new(BoundedOriginalMailbox::new(3).unwrap());
        let reader = Arc::clone(&mailbox);
        let worker = std::thread::spawn(move || reader.receive_original().unwrap());

        let first = submit_retrying_busy(&mailbox, String::from("original-first"));
        assert_eq!(worker.join().unwrap(), first);
        let second = mailbox
            .try_submit(String::from("original-second"))
            .ok()
            .unwrap();
        let third = mailbox
            .try_submit(String::from("original-third"))
            .ok()
            .unwrap();
        assert_eq!(
            mailbox
                .try_submit(String::from("overflow-retained"))
                .err()
                .unwrap()
                .original,
            "overflow-retained"
        );
        assert_eq!(mailbox.take_received(first).unwrap(), "original-first");
        assert_eq!(mailbox.receive_original().unwrap(), second);
        assert_eq!(mailbox.take_received(second).unwrap(), "original-second");
        assert_eq!(mailbox.receive_original().unwrap(), third);
        assert_eq!(mailbox.take_received(third).unwrap(), "original-third");
    }

    #[test]
    fn identity_exhaustion_retains_current_payload_before_queue_publication() {
        let mailbox = BoundedOriginalMailbox::new(1).unwrap();
        mailbox.state.lock().unwrap().next_sequence = u64::MAX;
        let refused = mailbox
            .try_submit(String::from("original-at-exhaustion"))
            .err()
            .unwrap();

        assert_eq!(refused.reason, MailboxRefusal::IdentityExhausted);
        assert_eq!(refused.original, "original-at-exhaustion");
        assert!(mailbox.state.lock().unwrap().queue.is_empty());
    }
}
