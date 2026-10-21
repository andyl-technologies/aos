//! Retains the actual bounded request read before its independent post check.
//!
//! This inline journal belongs to the same child as its mapped slot handle.
//! A received payload remains owned after the bounded read ends, including on
//! post refusal. Source must separately retain the live publisher epoch and
//! issue any action or physical-return loan.
// SPDX-License-Identifier: GPL-2.0-only

use super::{ControlIntentFacts, snapshot_with_interleave};
use crucible_qemu_shmem::{FingerprintSampleSlot, NodeSlot};
use std::sync::{Mutex, MutexGuard, TryLockError};

mod payload;
pub(in crate::runtime) use payload::{Payload, PayloadBorrow};

/// Keeps captured output separate from the first and independent post results.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::runtime) struct ReadOutcome {
    pub(in crate::runtime) facts: Option<ControlIntentFacts>,
    pub(in crate::runtime) first: i32,
    pub(in crate::runtime) post: i32,
    pub(in crate::runtime) read_attempted: bool,
    pub(in crate::runtime) reader_released: bool,
}

impl ReadOutcome {
    fn refused(status: i32) -> Self {
        Self {
            facts: None,
            first: status,
            post: 0,
            read_attempted: false,
            reader_released: false,
        }
    }

    pub(in crate::runtime) fn status(self) -> i32 {
        if self.first != 0 {
            self.first
        } else {
            self.post
        }
    }
}

struct ReadJournal {
    // This counts actual local reads, not Host publisher births or operations.
    sequence: u64,
    borrow_sequence: u64,
    active: bool,
    local_reader_released: bool,
    outcome: ReadOutcome,
    pending: Option<PendingRequest>,
}

/// Owns the actual received payload in the complete child's prepaid storage.
///
/// This value is deliberately neither Copy nor Clone. Its local read serial
/// identifies this storage generation; it is not a Host publisher birth or an
/// Original. There is no payload retirement route until the same module owner
/// is joined to Native's genuine received-delivery return.
struct PendingRequest {
    serial: u64,
    process: u32,
    facts: ControlIntentFacts,
    canonical_holder: *mut *mut Payload,
    borrow: Option<payload::PayloadBorrowState>,
}

/// Lives inside the complete child Layout before its actual Source allocation.
pub(in crate::runtime) struct ProtectedReader {
    journal: Mutex<ReadJournal>,
    // This borrower is installed only while Source lends the complete typed
    // child. Runtime pinning and nominal member parents retain its backing.
    receiver: Option<std::ptr::NonNull<Mutex<crate::runtime::command_receive::CommandReceive>>>,
}

impl ProtectedReader {
    pub(in crate::runtime) const fn new() -> Self {
        Self {
            receiver: None,
            journal: Mutex::new(ReadJournal {
                sequence: 0,
                borrow_sequence: 0,
                active: false,
                local_reader_released: true,
                pending: None,
                outcome: ReadOutcome {
                    facts: None,
                    first: 0,
                    post: 0,
                    read_attempted: false,
                    reader_released: false,
                },
            }),
        }
    }

    /// Binds the actual stable receiver borrower before callback publication.
    ///
    /// # Safety
    /// The receiver belongs to the same prepaid pinned Runtime and remains live
    /// through all genuine child/member/callback/received-request last uses.
    pub(in crate::runtime) unsafe fn bind_receiver(
        &mut self,
        receiver: std::ptr::NonNull<Mutex<crate::runtime::command_receive::CommandReceive>>,
    ) -> Result<(), i32> {
        if self.receiver.is_some() {
            return Err(-libc::EALREADY);
        }
        self.receiver = Some(receiver);
        Ok(())
    }

    #[cfg(test)]
    pub(in crate::runtime) fn receiver_is_absent(&self) -> bool {
        self.receiver.is_none()
    }

    pub(in crate::runtime) fn ready_facts(&self) -> super::ReadyObservation {
        let Some(receiver) = self.receiver else {
            return super::ReadyObservation {
                facts: None,
                status: -libc::ENOKEY,
            };
        };
        // SAFETY: actual prepublication typed binding retains the same pinned
        // Runtime. The real ready callback does no typed Bridge mutation and
        // Source independently checks creating-thread/outside-BQL/lender state.
        let receiver = unsafe { receiver.as_ref() };
        match receiver.try_lock() {
            Ok(mut receiver) => receiver.ready_facts(),
            Err(TryLockError::WouldBlock) => super::ReadyObservation {
                facts: None,
                status: -libc::EBUSY,
            },
            Err(TryLockError::Poisoned(_)) => super::ReadyObservation {
                facts: None,
                status: -libc::EOWNERDEAD,
            },
        }
    }

    /// Reads the actual owned slot without an operation, dispatch or ACK.
    pub(in crate::runtime) fn read(
        &self,
        slot: &NodeSlot,
        sampler: Option<&FingerprintSampleSlot>,
    ) -> ReadOutcome {
        self.read_with_post_interleave(slot, sampler, || {})
    }

    /// Borrows the retained payload without detaching it from its paid child.
    ///
    /// The journal remains locked through the receiver, including unwind. This
    /// supplies local payload access only, with no ACK, publisher or operation
    /// authority. Neither a copied tuple nor the local serial can return it.
    ///
    /// # Errors
    /// Refuses an absent payload, an active read, a foreign process, contention
    /// or poisoned ownership. Poisoning retains the payload and blocks reuse.
    fn with_pending_request<T>(
        &self,
        receive: impl FnOnce(&PendingRequest) -> T,
    ) -> Result<T, i32> {
        let journal = match self.journal.try_lock() {
            Ok(journal) => journal,
            Err(TryLockError::WouldBlock) => return Err(-libc::EBUSY),
            Err(TryLockError::Poisoned(_)) => return Err(-libc::EOWNERDEAD),
        };
        if journal.active || !journal.local_reader_released {
            return Err(-libc::EBUSY);
        }
        let pending = journal.pending.as_ref().ok_or(-libc::ENOENT)?;
        if pending.process != std::process::id() || pending.serial != journal.sequence {
            return Err(-libc::ESTALE);
        }

        Ok(receive(pending))
    }

    fn read_with_post_interleave(
        &self,
        slot: &NodeSlot,
        sampler: Option<&FingerprintSampleSlot>,
        interleave: impl FnOnce(),
    ) -> ReadOutcome {
        let mut journal = match self.journal.try_lock() {
            Ok(journal) => journal,
            Err(TryLockError::WouldBlock) => return ReadOutcome::refused(-libc::EBUSY),
            Err(TryLockError::Poisoned(_)) => return ReadOutcome::refused(-libc::EOWNERDEAD),
        };
        if journal.active || !journal.local_reader_released || journal.pending.is_some() {
            return ReadOutcome::refused(-libc::EBUSY);
        }
        let Some(sequence) = journal.sequence.checked_add(1) else {
            return ReadOutcome::refused(-libc::EOVERFLOW);
        };
        journal.sequence = sequence;
        journal.active = true;
        journal.local_reader_released = false;
        journal.outcome = ReadOutcome::refused(0);
        journal.outcome.read_attempted = true;
        let mut entered = LocalRead { journal };
        let opening_token = slot.control_boundary_token();

        match snapshot_with_interleave(slot, sampler, || {}) {
            Ok(facts) => {
                // Deposit the owned payload before exposing a factual copy or
                // running the independent post. Ending the reader cannot
                // retire this separately retained received-request lifetime.
                entered.journal.pending = Some(PendingRequest {
                    serial: sequence,
                    process: std::process::id(),
                    facts,
                    canonical_holder: std::ptr::null_mut(),
                    borrow: None,
                });
                entered.journal.outcome.facts = Some(facts);
            }
            Err(status) => entered.journal.outcome.first = status,
        }
        // Captured request bytes are retained before the independent post.
        // The production path invokes no callback or effect while locked.
        interleave();
        let received_token = entered
            .journal
            .outcome
            .facts
            .map_or(u64::from(opening_token), |facts| facts.control_sequence);
        if u64::from(slot.control_boundary_token()) != received_token {
            entered.journal.outcome.post = -libc::EAGAIN;
        }
        entered.finish()
    }
}

struct LocalRead<'a> {
    journal: MutexGuard<'a, ReadJournal>,
}

impl LocalRead<'_> {
    fn finish(mut self) -> ReadOutcome {
        self.journal.outcome.reader_released = true;
        let outcome = self.journal.outcome;
        // Finish actual local custody and unlock before emitting a released
        // output. Unwinding never emits this completion flag to Source.
        drop(self);
        outcome
    }
}

impl Drop for LocalRead<'_> {
    fn drop(&mut self) {
        self.journal.active = false;
        // This retires only the local bounded reader, not any Source receive
        // owner, publisher membership, action parent or material borrower.
        self.journal.local_reader_released = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acknowledged_after_capture_retains_received_tuple_and_post_refusal() {
        let slot = NodeSlot::new(crucible_qemu_shmem::KIND_VM);
        let token = slot
            .request_control_boundary(73, Some(9))
            .unwrap_or_else(|error| panic!("publish request: {error}"));
        let reader = ProtectedReader::new();

        let observed = reader.read_with_post_interleave(&slot, None, || {
            slot.acknowledge_control_boundary();
        });

        assert_eq!(observed.first, 0);
        assert_eq!(observed.post, -libc::EAGAIN);
        let progress = super::super::ReceiveProgress::from(observed);
        assert_eq!(
            (
                progress.read_attempted,
                progress.request_received,
                progress.reader_released
            ),
            (1, 1, 1)
        );
        let facts = observed
            .facts
            .unwrap_or_else(|| panic!("received tuple must survive post refusal"));
        assert_eq!(facts.control_sequence, u64::from(token));
        assert_eq!(facts.command_producer_ordinal, 73);
        assert_eq!(facts.sample_generation, 9);
        let journal = reader
            .journal
            .lock()
            .unwrap_or_else(|error| panic!("inspect local journal: {error}"));
        assert_eq!(journal.outcome, observed);
        assert!(!journal.active);
        assert!(journal.local_reader_released);
    }

    #[test]
    fn overlapping_read_refuses_without_overwriting_entered_observation() {
        let slot = NodeSlot::new(crucible_qemu_shmem::KIND_VM);
        slot.request_control_boundary(12, None)
            .unwrap_or_else(|error| panic!("publish request: {error}"));
        let reader = ProtectedReader::new();

        let observed = reader.read_with_post_interleave(&slot, None, || {
            assert_eq!(reader.read(&slot, None).status(), -libc::EBUSY);
        });

        assert_eq!(observed.status(), 0);
        let journal = reader
            .journal
            .lock()
            .unwrap_or_else(|error| panic!("inspect local journal: {error}"));
        assert_eq!(journal.sequence, 1);
        assert_eq!(journal.outcome, observed);
    }

    #[test]
    fn received_payload_excludes_replacement_after_local_read_and_mapped_ack() {
        let slot = NodeSlot::new(crucible_qemu_shmem::KIND_VM);
        let token = slot.request_control_boundary(73, Some(9)).unwrap();
        let reader = ProtectedReader::new();
        let received = reader.read(&slot, None);
        assert_eq!(received.status(), 0);
        assert!(received.reader_released);

        slot.acknowledge_control_boundary();
        let next_token = slot.request_control_boundary(74, Some(11)).unwrap();
        assert_ne!(next_token, token);
        let refused = reader.read(&slot, None);

        assert_eq!(refused.status(), -libc::EBUSY);
        assert!(!refused.read_attempted);
        reader
            .with_pending_request(|pending| {
                assert_eq!(pending.serial, 1);
                assert_eq!(pending.facts, received.facts.unwrap());
                assert_eq!(pending.facts.control_sequence, u64::from(token));
                assert_eq!(pending.facts.command_producer_ordinal, 73);
            })
            .unwrap();
        assert_eq!(slot.control_boundary_token(), next_token);
        assert_eq!(slot.control_boundary_fault_command_frontier(), 74);
    }

    #[test]
    fn pending_payload_borrow_retains_the_actual_journal_until_receiver_returns() {
        let slot = NodeSlot::new(crucible_qemu_shmem::KIND_VM);
        slot.request_control_boundary(12, None).unwrap();
        let reader = ProtectedReader::new();
        let received = reader.read(&slot, None);

        reader
            .with_pending_request(|pending| {
                assert_eq!(pending.facts, received.facts.unwrap());
                assert_eq!(reader.read(&slot, None).status(), -libc::EBUSY);
                assert_eq!(reader.with_pending_request(|_| ()), Err(-libc::EBUSY));
            })
            .unwrap();

        assert_eq!(reader.read(&slot, None).status(), -libc::EBUSY);
        reader.with_pending_request(|_| ()).unwrap();
        assert!(slot.control_boundary_is_requested());
    }

    #[test]
    fn negative_post_retains_the_owned_payload_before_the_signed_result() {
        let slot = NodeSlot::new(crucible_qemu_shmem::KIND_VM);
        let token = slot.request_control_boundary(73, Some(9)).unwrap();
        let reader = ProtectedReader::new();

        let received = reader.read_with_post_interleave(&slot, None, || {
            slot.acknowledge_control_boundary();
        });

        assert_eq!(received.status(), -libc::EAGAIN);
        reader
            .with_pending_request(|pending| {
                assert_eq!(pending.facts, received.facts.unwrap());
                assert_eq!(pending.facts.control_sequence, u64::from(token));
            })
            .unwrap();
        assert_eq!(reader.read(&slot, None).status(), -libc::EBUSY);
    }

    #[test]
    fn unwind_after_payload_deposit_retains_uncertain_custody_and_refuses_reuse() {
        let slot = NodeSlot::new(crucible_qemu_shmem::KIND_VM);
        let token = slot.request_control_boundary(73, Some(9)).unwrap();
        let reader = ProtectedReader::new();

        let panicked = std::panic::catch_unwind(|| {
            reader.read_with_post_interleave(&slot, None, || panic!("post interrupted"));
        });

        assert!(panicked.is_err());
        assert_eq!(reader.read(&slot, None).status(), -libc::EOWNERDEAD);
        assert_eq!(reader.with_pending_request(|_| ()), Err(-libc::EOWNERDEAD));
        let journal = reader.journal.lock().err().unwrap().into_inner();
        let pending = journal.pending.as_ref().unwrap();
        assert_eq!(pending.facts.control_sequence, u64::from(token));
        assert_eq!(pending.facts.command_producer_ordinal, 73);
        assert!(!journal.outcome.reader_released);
        assert!(!journal.active);
        assert!(journal.local_reader_released);
        assert_eq!(slot.control_boundary_token(), token);
    }

    #[test]
    fn empty_read_does_not_create_a_pending_payload() {
        let slot = NodeSlot::new(crucible_qemu_shmem::KIND_VM);
        let reader = ProtectedReader::new();

        assert_eq!(reader.read(&slot, None).status(), -libc::ENOENT);
        assert_eq!(reader.with_pending_request(|_| ()), Err(-libc::ENOENT));
        slot.request_control_boundary(12, None).unwrap();
        let received = reader.read(&slot, None);

        assert_eq!(received.status(), 0);
        reader
            .with_pending_request(|pending| {
                assert_eq!(pending.serial, 2);
                assert_eq!(pending.facts.command_producer_ordinal, 12);
            })
            .unwrap();
    }
}
