//! Owns separate control/Park return journals and Host frontier exclusion.
//!
//! Native writes the return journal only under its actual retained writable
//! setup-mapping loan. The standing Source publication remains read-only.
//! These atomic accessors implement bytes, never an operation or writer grant.

use super::*;
use crucible_qemu_protocol::boundary_action::{ACTION_RETURN_BYTES, ActionDecodeError, ActionReturn};
use crucible_qemu_protocol::parent_park_return::{PARENT_PARK_RETURN_BYTES, ParentParkReturn};

const _: () = assert!(PARENT_PARK_RETURN_BYTES == ACTION_RETURN_BYTES);

impl NodeSlot {
    /// Observes the next existing token without publishing or ringing a wake.
    ///
    /// # Errors
    /// Refuses an exhausted generation or a pending request with another
    /// immutable frontier/sample tuple.
    pub fn preview_action_token(
        &self,
        frontier: u64,
        capture: Option<u32>,
    ) -> Result<u32, ActionDecodeError> {
        if capture.is_some_and(|capture| capture & 1 == 0) {
            return Err(ActionDecodeError);
        }
        let token = self.control_boundary_ack.load(Ordering::Acquire);
        if token & 1 == 0 {
            if self
                .control_boundary_fault_command_frontier
                .load(Ordering::Acquire)
                != frontier
                || self
                    .control_boundary_capture_request
                    .load(Ordering::Acquire)
                    != capture.unwrap_or(0)
            {
                return Err(ActionDecodeError);
            }
            Ok(token)
        } else {
            token.checked_add(1).ok_or(ActionDecodeError)
        }
    }

    /// Reserves the actual single-producer frontier through physical return.
    ///
    /// # Errors
    /// Refuses an invalid birth sequence or another still-retained action.
    pub fn retain_action_frontier(&self, loan_sequence: u64) -> Result<(), ActionDecodeError> {
        if loan_sequence == 0 || loan_sequence & 1 != 0 || loan_sequence == u64::MAX {
            return Err(ActionDecodeError);
        }
        self.boundary_action_hold
            .compare_exchange(0, loan_sequence, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| ActionDecodeError)
    }

    /// Returns whether an actual action still owns the command frontier.
    pub fn action_frontier_is_retained(&self) -> bool {
        self.boundary_action_hold.load(Ordering::Acquire) != 0
    }

    /// Releases only the same Host frontier after authenticated physical return.
    ///
    /// # Errors
    /// Refuses stale sequence, absent ownership or another action's retained cut.
    pub fn release_action_frontier(&self, loan_sequence: u64) -> Result<(), ActionDecodeError> {
        if loan_sequence == 0 {
            return Err(ActionDecodeError);
        }
        self.boundary_action_hold
            .compare_exchange(loan_sequence, 0, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| ActionDecodeError)
    }

    /// Publishes return bytes under the same actual Native journal writer.
    ///
    /// # Errors
    /// Refuses invalid syntax, regressed publication, a changed writer epoch or
    /// a different retained Host action. This method issues no writer authority.
    pub fn publish_action_return(
        &self,
        expected_sequence: u64,
        journal: ActionReturn,
    ) -> Result<u64, ActionDecodeError> {
        if journal.binding.park_request.is_some() {
            return Err(ActionDecodeError);
        }
        self.publish_return(
            &self.boundary_action_return,
            expected_sequence,
            journal.binding.loan_sequence,
            &journal.encode()?,
        )
    }

    /// Publishes Park bytes only through the distinct protected MODULE journal.
    ///
    /// The actual setup/module owner must separately lend the writer role.
    /// This atomic byte accessor does not issue that role or physical return.
    ///
    /// # Errors
    /// Refuses control records, invalid syntax, a stale writer sequence or a
    /// different retained Host request.
    pub fn publish_parent_park_return(
        &self,
        expected_sequence: u64,
        journal: ParentParkReturn,
    ) -> Result<u64, ActionDecodeError> {
        self.publish_return(
            &self.parent_park_return,
            expected_sequence,
            journal.binding.loan_sequence,
            &journal.encode().map_err(|_| ActionDecodeError)?,
        )
    }

    fn publish_return(
        &self,
        words: &[AtomicU64; 24],
        expected_sequence: u64,
        loan_sequence: u64,
        bytes: &[u8; ACTION_RETURN_BYTES],
    ) -> Result<u64, ActionDecodeError> {
        if self.boundary_action_hold.load(Ordering::Acquire) != loan_sequence {
            return Err(ActionDecodeError);
        }
        let sequence = expected_sequence
            .checked_add(2)
            .filter(|value| *value < u64::MAX)
            .ok_or(ActionDecodeError)?;
        if expected_sequence & 1 != 0 {
            return Err(ActionDecodeError);
        }
        words[0]
            .compare_exchange(
                expected_sequence.to_be(),
                (sequence - 1).to_be(),
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .map_err(|_| ActionDecodeError)?;
        for (word, bytes) in words[1..].iter().zip(bytes.as_chunks::<8>().0) {
            word.store(u64::from_be_bytes(*bytes).to_be(), Ordering::SeqCst);
        }
        words[0]
            .compare_exchange(
                (sequence - 1).to_be(),
                sequence.to_be(),
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .map_err(|_| ActionDecodeError)?;
        Ok(sequence)
    }

    /// Reads one whole physical journal without retrying or creating a clock.
    ///
    /// # Errors
    /// Refuses invalidation or malformed bytes. A concurrent writer yields
    /// `None`; the caller retries only under its real retained operation.
    pub fn observe_action_return(&self) -> Result<Option<ActionReturn>, ActionDecodeError> {
        self.observe_return(&self.boundary_action_return)?
            .map(|bytes| ActionReturn::decode(&bytes))
            .transpose()
    }

    /// Reads the independent protected MODULE Park journal without retrying.
    ///
    /// # Errors
    /// Refuses invalidation, malformed records or the control return variant.
    /// A concurrent publication yields `None` and never acknowledges a request.
    pub fn observe_parent_park_return(
        &self,
    ) -> Result<Option<ParentParkReturn>, ActionDecodeError> {
        self.observe_return(&self.parent_park_return)?
            .map(|bytes| ParentParkReturn::decode(&bytes).map_err(|_| ActionDecodeError))
            .transpose()
    }

    fn observe_return(
        &self,
        words: &[AtomicU64; 24],
    ) -> Result<Option<[u8; ACTION_RETURN_BYTES]>, ActionDecodeError> {
        let before = u64::from_be(words[0].load(Ordering::SeqCst));
        if before == u64::MAX {
            return Err(ActionDecodeError);
        }
        if before == 0 || before & 1 != 0 {
            return Ok(None);
        }
        let mut bytes = [0; ACTION_RETURN_BYTES];
        for (target, word) in bytes
            .as_chunks_mut::<8>()
            .0
            .iter_mut()
            .zip(words[1..].iter())
        {
            target.copy_from_slice(&u64::from_be(word.load(Ordering::SeqCst)).to_be_bytes());
        }
        if u64::from_be(words[0].load(Ordering::SeqCst)) != before {
            return Ok(None);
        }
        Ok(Some(bytes))
    }
}
