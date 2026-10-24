//! Constructor-owned physical I/O and descriptor journals for one original socket.
//!
//! The selected installer prepares this owner before HELLO. Initial and staged
//! adapters use the same socket, administrative budget and preallocated byte
//! banks. Every physical prefix is retained before returning to a parser. This
//! owner supplies no native adoption, source readiness or operation retirement.

use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::sync::{Mutex, OnceLock};

use crucible_qemu_protocol::bounded_setup::{
    AdministrativeIoProgress, BoundedSetupError, SetupReceiveJournal, SetupTransferProgress,
    read_once, write_once,
};
use crucible_qemu_protocol::whole_control::staged::{
    StagedControlProfile,
    administrative::{AdministrativeIoBudget, AdministrativeIoCounters},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum WholeSocketError {
    #[error("original selected socket belongs to another process")]
    Process,
    #[error("original selected socket owner is busy or poisoned")]
    Ownership,
    #[error("selected socket constructor backing exceeds its original quota")]
    Capacity,
    #[error("original selected socket transfer was refused: {0}")]
    Transfer(#[from] BoundedSetupError),
}

#[derive(Clone, Copy, Default)]
struct PhysicalAttempt {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
        )
    )]
    first_byte: usize,
    prepared: usize,
    offered: usize,
    attempted: bool,
    actual: usize,
    retryable: bool,
    peer_closed: bool,
    refused: bool,
}

struct AdministrativeJournal {
    budget: AdministrativeIoBudget,
    reads: Box<[PhysicalAttempt]>,
    writes: Box<[PhysicalAttempt]>,
    read_bytes: Box<[u8]>,
    offered_write_bytes: Box<[u8]>,
    read_extent: usize,
    write_extent: usize,
    read_count: usize,
    write_count: usize,
    setup: Option<SetupReceiveJournal>,
    refused: bool,
}

/// Owns the same socket and all lifetime administrative and received-FD material.
pub(crate) struct OriginalWholeSocket {
    process: u32,
    socket: OnceLock<UnixStream>,
    journal: Mutex<AdministrativeJournal>,
    received_setup: OnceLock<SetupReceiveJournal>,
    owned_storage_bytes: u64,
}

impl std::fmt::Debug for OriginalWholeSocket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OriginalWholeSocket")
            .field("process", &self.process)
            .field("owned_storage_bytes", &self.owned_storage_bytes)
            .finish_non_exhaustive()
    }
}

impl OriginalWholeSocket {
    /// Counts byte banks and physical-attempt metadata before allocating them.
    pub(crate) fn required_bytes(profile: &StagedControlProfile) -> Result<u64, WholeSocketError> {
        let compute = &profile.compute;
        compute
            .administrative_read_attempt_limit
            .checked_add(compute.administrative_write_attempt_limit)
            .and_then(|count| count.checked_mul(std::mem::size_of::<PhysicalAttempt>() as u64))
            .and_then(|bytes| bytes.checked_add(compute.administrative_read_byte_limit))
            .and_then(|bytes| bytes.checked_add(compute.administrative_write_byte_limit))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>() as u64))
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<AdministrativeJournal>() as u64)
            })
            .ok_or(WholeSocketError::Capacity)
    }

    /// Preallocates original custody before claiming the native control FD.
    ///
    /// The caller adds every other provider arena before this reservation and
    /// retains the returned owner before transferring the original native FD.
    /// No descriptor has moved and no socket syscall occurs on refusal.
    pub(crate) fn prepare(
        profile: &StagedControlProfile,
        other_owned_bytes: u64,
    ) -> Result<Self, WholeSocketError> {
        profile.validate().map_err(|_| WholeSocketError::Capacity)?;
        let required = Self::required_bytes(profile)?;
        if required
            .checked_add(other_owned_bytes)
            .is_none_or(|bytes| bytes > profile.compute.provider_history_byte_limit)
        {
            return Err(WholeSocketError::Capacity);
        }
        let compute = &profile.compute;
        let journal = AdministrativeJournal {
            budget: AdministrativeIoBudget::new(profile).map_err(|_| WholeSocketError::Capacity)?,
            reads: backing(compute.administrative_read_attempt_limit)?,
            writes: backing(compute.administrative_write_attempt_limit)?,
            read_bytes: backing(compute.administrative_read_byte_limit)?,
            offered_write_bytes: backing(compute.administrative_write_byte_limit)?,
            read_extent: 0,
            write_extent: 0,
            read_count: 0,
            write_count: 0,
            setup: Some(SetupReceiveJournal::new()),
            refused: false,
        };
        Ok(Self {
            process: std::process::id(),
            socket: OnceLock::new(),
            journal: Mutex::new(journal),
            received_setup: OnceLock::new(),
            owned_storage_bytes: required,
        })
    }

    /// Adopts the literal native one-shot transfer into its preowned slot.
    ///
    /// A refused replacement returns the complete stream to its owning caller;
    /// no descriptor is dropped, cloned or replaced by this operation.
    pub(super) fn install_original_socket(&self, socket: UnixStream) -> Result<(), UnixStream> {
        if self.process != std::process::id() {
            return Err(socket);
        }
        self.socket.set(socket)
    }

    #[cfg(test)]
    fn new(
        socket: UnixStream,
        profile: &StagedControlProfile,
        other_owned_bytes: u64,
    ) -> Result<Self, WholeSocketError> {
        let owner = Self::prepare(profile, other_owned_bytes)?;
        owner
            .install_original_socket(socket)
            .map_err(|_| WholeSocketError::Ownership)?;
        Ok(owner)
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
        )
    )]
    pub(crate) const fn owned_storage_bytes(&self) -> u64 {
        self.owned_storage_bytes
    }

    /// Borrows the one original socket for non-owning readiness polling.
    pub(crate) fn descriptor(&self) -> Result<BorrowedFd<'_>, WholeSocketError> {
        self.check_process()?;
        self.socket
            .get()
            .map(AsFd::as_fd)
            .ok_or(WholeSocketError::Ownership)
    }

    /// Reads once and retains its exact prefix before any caller interpretation.
    pub(crate) fn read_step(
        &self,
        destination: &mut [u8],
        now_monotonic_ns: u64,
    ) -> Result<AdministrativeIoProgress, WholeSocketError> {
        self.check_process()?;
        let mut journal = self
            .journal
            .try_lock()
            .map_err(|_| WholeSocketError::Ownership)?;
        if journal.refused || journal.read_count == journal.reads.len() {
            journal.refused = true;
            return Err(WholeSocketError::Capacity);
        }
        let index = journal.read_count;
        let first_byte = journal.read_extent;
        let ceiling = destination.len().min(journal.read_bytes.len() - first_byte);
        journal.reads[index] = PhysicalAttempt {
            first_byte,
            prepared: ceiling,
            ..Default::default()
        };
        journal.read_count += 1;
        let before = journal.budget.counters();
        let result = read_once(
            self.descriptor()?,
            &mut destination[..ceiling],
            &mut journal.budget,
            now_monotonic_ns,
        );
        let after = journal.budget.counters();
        journal.reads[index].attempted = after.read_attempts == before.read_attempts + 1;
        journal.reads[index].offered = if journal.reads[index].attempted {
            ceiling
        } else {
            0
        };
        match result {
            Ok(progress) => {
                if after.read_bytes - before.read_bytes != progress.actual_bytes as u64 {
                    journal.refused = true;
                    return Err(WholeSocketError::Ownership);
                }
                let end = first_byte + progress.actual_bytes;
                journal.read_bytes[first_byte..end]
                    .copy_from_slice(&destination[..progress.actual_bytes]);
                journal.read_extent = end;
                journal.reads[index].actual = progress.actual_bytes;
                journal.reads[index].retryable = progress.retryable;
                journal.reads[index].peer_closed = progress.peer_closed;
                Ok(progress)
            }
            Err(error) => {
                journal.refused = true;
                journal.reads[index].refused = true;
                Err(error.into())
            }
        }
    }

    /// Retains all offered bytes before one permanently charged write attempt.
    pub(crate) fn write_step(
        &self,
        source: &[u8],
        now_monotonic_ns: u64,
    ) -> Result<AdministrativeIoProgress, WholeSocketError> {
        self.check_process()?;
        let mut journal = self
            .journal
            .try_lock()
            .map_err(|_| WholeSocketError::Ownership)?;
        if journal.refused || journal.write_count == journal.writes.len() {
            journal.refused = true;
            return Err(WholeSocketError::Capacity);
        }
        let index = journal.write_count;
        let first_byte = journal.write_extent;
        let offered = source
            .len()
            .min(journal.offered_write_bytes.len() - first_byte);
        let end = first_byte + offered;
        journal.offered_write_bytes[first_byte..end].copy_from_slice(&source[..offered]);
        journal.write_extent = end;
        journal.writes[index] = PhysicalAttempt {
            first_byte,
            prepared: offered,
            ..Default::default()
        };
        journal.write_count += 1;
        let before = journal.budget.counters();
        let result = write_once(
            self.descriptor()?,
            &source[..offered],
            &mut journal.budget,
            now_monotonic_ns,
        );
        let after = journal.budget.counters();
        journal.writes[index].attempted = after.write_attempts == before.write_attempts + 1;
        journal.writes[index].offered =
            usize::try_from(after.offered_write_bytes - before.offered_write_bytes)
                .map_err(|_| WholeSocketError::Capacity)?;
        match result {
            Ok(progress) => {
                journal.writes[index].actual = progress.actual_bytes;
                journal.writes[index].retryable = progress.retryable;
                journal.writes[index].peer_closed = progress.peer_closed;
                Ok(progress)
            }
            Err(error) => {
                journal.refused = true;
                journal.writes[index].refused = true;
                Err(error.into())
            }
        }
    }

    /// Receives one fixed setup/SCM prefix under the same lifetime read budget.
    pub(crate) fn receive_setup_step(
        &self,
        now_monotonic_ns: u64,
    ) -> Result<SetupTransferProgress, WholeSocketError> {
        self.check_process()?;
        if self.received_setup.get().is_some() {
            return Ok(SetupTransferProgress {
                actual_bytes: 0,
                complete: true,
            });
        }
        let mut journal = self
            .journal
            .try_lock()
            .map_err(|_| WholeSocketError::Ownership)?;
        if journal.refused || journal.read_count == journal.reads.len() {
            journal.refused = true;
            return Err(WholeSocketError::Capacity);
        }
        let index = journal.read_count;
        let first_byte = journal.read_extent;
        let prefix_before = journal
            .setup
            .as_ref()
            .ok_or(WholeSocketError::Ownership)?
            .retained_prefix()
            .len();
        journal.reads[index] = PhysicalAttempt {
            first_byte,
            prepared: if prefix_before < 4 {
                4 - prefix_before
            } else {
                13 - prefix_before
            },
            ..Default::default()
        };
        journal.read_count += 1;
        let before = journal.budget.counters();
        let AdministrativeJournal { budget, setup, .. } = &mut *journal;
        let result = setup
            .as_mut()
            .ok_or(WholeSocketError::Ownership)?
            .try_receive_step(self.descriptor()?, budget, now_monotonic_ns);
        // Even malformed/truncated SCM messages retain all received bytes and
        // strong original descriptors before an error is returned.
        let retained = journal
            .setup
            .as_ref()
            .ok_or(WholeSocketError::Ownership)?
            .retained_prefix();
        let actual = retained.len() - prefix_before;
        if actual > journal.read_bytes.len() - first_byte {
            journal.refused = true;
            return Err(WholeSocketError::Capacity);
        }
        let mut prefix = [0; 13];
        prefix[..actual].copy_from_slice(&retained[prefix_before..]);
        journal.read_bytes[first_byte..first_byte + actual].copy_from_slice(&prefix[..actual]);
        journal.read_extent += actual;
        journal.reads[index].actual = actual;
        let after = journal.budget.counters();
        journal.reads[index].attempted = after.read_attempts == before.read_attempts + 1;
        journal.reads[index].offered = if journal.reads[index].attempted {
            journal.reads[index].prepared
        } else {
            0
        };
        if after.read_bytes - before.read_bytes != actual as u64 {
            journal.refused = true;
            return Err(WholeSocketError::Ownership);
        }
        match result {
            Ok(progress) => {
                if progress.complete {
                    let setup = journal.setup.take().ok_or(WholeSocketError::Ownership)?;
                    self.received_setup
                        .set(setup)
                        .map_err(|_| WholeSocketError::Ownership)?;
                }
                Ok(progress)
            }
            Err(error) => {
                journal.refused = true;
                journal.reads[index].refused = true;
                Err(error.into())
            }
        }
    }

    /// Borrows the same fully received descriptor journal without moving its FDs.
    pub(crate) fn received_setup(&self) -> Result<&SetupReceiveJournal, WholeSocketError> {
        self.check_process()?;
        self.received_setup.get().ok_or(WholeSocketError::Ownership)
    }

    /// Validates all physical prefixes against the same lifetime budget.
    ///
    /// Failed offers stay in the original journal with zero physical debit;
    /// partial writes retain their entire prepared suffix and charged offer.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
        )
    )]
    pub(crate) fn counters(&self) -> Result<AdministrativeIoCounters, WholeSocketError> {
        self.check_process()?;
        let journal = self
            .journal
            .try_lock()
            .map_err(|_| WholeSocketError::Ownership)?;
        let counters = journal.budget.counters();
        let mut reads = 0u64;
        let mut read_bytes = 0u64;
        for attempt in &journal.reads[..journal.read_count] {
            if attempt.actual > attempt.offered
                || attempt.offered > attempt.prepared
                || attempt.first_byte + attempt.actual > journal.read_extent
            {
                return Err(WholeSocketError::Ownership);
            }
            reads += u64::from(attempt.attempted);
            read_bytes += attempt.actual as u64;
        }
        let mut writes = 0u64;
        let mut offered_bytes = 0u64;
        for attempt in &journal.writes[..journal.write_count] {
            if attempt.actual > attempt.offered
                || attempt.offered > attempt.prepared
                || attempt.first_byte + attempt.prepared > journal.write_extent
            {
                return Err(WholeSocketError::Ownership);
            }
            writes += u64::from(attempt.attempted);
            offered_bytes += attempt.offered as u64;
        }
        if counters.read_attempts != reads
            || counters.read_bytes != read_bytes
            || counters.write_attempts != writes
            || counters.offered_write_bytes != offered_bytes
        {
            return Err(WholeSocketError::Ownership);
        }
        Ok(counters)
    }

    fn check_process(&self) -> Result<(), WholeSocketError> {
        if self.process != std::process::id() {
            return Err(WholeSocketError::Process);
        }
        Ok(())
    }
}

fn backing<T: Default + Clone>(count: u64) -> Result<Box<[T]>, WholeSocketError> {
    let count = usize::try_from(count).map_err(|_| WholeSocketError::Capacity)?;
    let mut backing = Vec::new();
    backing
        .try_reserve_exact(count)
        .map_err(|_| WholeSocketError::Capacity)?;
    backing.resize(count, T::default());
    Ok(backing.into_boxed_slice())
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- Actual original-socket controls fail on invariant violations.
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crucible_qemu_protocol::bounded_setup::SetupSendJournal;
    use crucible_qemu_protocol::whole_control::WholeControlProfile;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, OwnedFd};

    fn profile() -> StagedControlProfile {
        StagedControlProfile {
            compute: WholeControlProfile {
                scope: [7; 32],
                operation_capacity: 2,
                body_byte_limit: 1024,
                native_history_byte_limit: 1_000_000,
                provider_history_byte_limit: 1_000_000,
                administrative_read_attempt_limit: 100,
                administrative_read_byte_limit: 100_000,
                administrative_write_attempt_limit: 100,
                administrative_write_byte_limit: 100_000,
                deadline_monotonic_ns: 1000,
                cpu_retirement_limit: 100,
                event_step_limit: 100,
                input_byte_limit: 100,
                input_record_limit: 10,
                output_byte_limit: 100,
                output_record_limit: 10,
            },
            input_stage_limit: 3,
            stage_body_byte_limit: 1024,
        }
    }

    #[test]
    fn actual_empty_read_and_physical_prefixes_share_the_original_lifetime_budget() {
        let (source, mut host) = UnixStream::pair().unwrap();
        let actor = OriginalWholeSocket::new(source, &profile(), 0).unwrap();
        let original_fd = actor.descriptor().unwrap().as_raw_fd();
        assert!(actor.owned_storage_bytes() > 200_000);
        let mut body = [0; 13];
        assert!(actor.read_step(&mut body, 0).unwrap().retryable);
        host.write_all(b"abc").unwrap();
        let prefix = actor.read_step(&mut body, 0).unwrap();
        assert_eq!(prefix.actual_bytes, 3);
        assert_eq!(&body[..3], b"abc");
        assert_eq!(actor.write_step(b"initial", 0).unwrap().actual_bytes, 7);
        let mut initial = [0; 7];
        host.read_exact(&mut initial).unwrap();
        assert_eq!(&initial, b"initial");

        // Moving into the later grammar retains the same descriptor and debit.
        let staged_actor = actor;
        assert_eq!(staged_actor.descriptor().unwrap().as_raw_fd(), original_fd);
        staged_actor.write_step(b"staged", 0).unwrap();
        let counts = staged_actor.counters().unwrap();
        assert_eq!((counts.read_attempts, counts.read_bytes), (2, 3));
        assert_eq!((counts.write_attempts, counts.offered_write_bytes), (2, 13));
    }

    #[test]
    fn failed_first_deadline_retains_prepared_prefix_without_inventing_physical_credit() {
        let (source, _host) = UnixStream::pair().unwrap();
        let actor = OriginalWholeSocket::new(source, &profile(), 0).unwrap();
        assert!(actor.write_step(b"retained", 1000).is_err());
        let counts = actor.counters().unwrap();
        assert_eq!((counts.write_attempts, counts.offered_write_bytes), (0, 0));
        assert!(actor.write_step(b"retry", 0).is_err());
        assert_eq!(actor.counters().unwrap(), counts);
        let journal = actor.journal.lock().unwrap();
        assert_eq!(
            &journal.offered_write_bytes[..journal.write_extent],
            b"retained"
        );
    }

    #[test]
    fn actual_scm_transfer_keeps_three_received_originals_and_same_byte_journal() {
        let (source, host) = UnixStream::pair().unwrap();
        let actor = OriginalWholeSocket::new(source, &profile(), 0).unwrap();
        let descriptors: [OwnedFd; 3] = std::array::from_fn(|_| {
            let (descriptor, _peer) = UnixStream::pair().unwrap();
            descriptor.into()
        });
        let originals = descriptors.each_ref().map(|fd| socket_identity(fd.as_fd()));
        let mut sender = SetupSendJournal::new(4096, descriptors);
        let mut sender_budget = AdministrativeIoBudget::new(&profile()).unwrap();
        assert!(
            sender
                .try_send_step(host.as_fd(), &mut sender_budget, 0)
                .unwrap()
                .complete
        );
        let prefix = actor.receive_setup_step(0).unwrap();
        assert_eq!(prefix.actual_bytes, 4);
        assert!(!prefix.complete);
        {
            let journal = actor.journal.lock().unwrap();
            let partial = journal.setup.as_ref().unwrap();
            for (index, original) in originals.iter().enumerate() {
                assert_eq!(
                    socket_identity(partial.retained_descriptor(index).unwrap()),
                    *original
                );
            }
        }
        assert!(actor.receive_setup_step(0).unwrap().complete);
        let received = actor.received_setup().unwrap().descriptors().unwrap();
        let identities = received.map(socket_identity);
        assert_eq!(identities, originals);
        assert_eq!(actor.counters().unwrap().read_bytes, 13);
        assert_eq!(actor.counters().unwrap().read_attempts, 2);
        actor.write_step(b"setup-ack", 0).unwrap();
        assert_eq!(actor.counters().unwrap().offered_write_bytes, 9);
        assert_eq!(
            actor
                .received_setup()
                .unwrap()
                .descriptors()
                .unwrap()
                .map(socket_identity),
            originals
        );
    }

    fn socket_identity(fd: BorrowedFd<'_>) -> (u64, u64) {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: The borrowed live FD is queried into a correctly sized stat;
        // its contents are read only after fstat reports complete initialization.
        assert_eq!(unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) }, 0);
        // SAFETY: Successful fstat initialized every field read below.
        let stat = unsafe { stat.assume_init() };
        (stat.st_dev, stat.st_ino)
    }
}
