//! Owns the standing Source's live publication and cancellation event.
//!
//! The real Main Source admission prices the complete holder, one kernel page,
//! temporary fdinfo/encoding scratch and physical descriptors before birth.
//! Every shared word is an atomic big-endian u64; a sequence check never races
//! ordinary payload accesses. The host alone maps writable before future-write
//! sealing. Native receives an independently retained read-only file role and
//! the distinct standing cancellation event, never Setup's amendment wake.
// SPDX-License-Identifier: Apache-2.0

use std::os::fd::{AsRawFd, OwnedFd};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crucible_host_resources::host_services::process_birth::SourceHostControlLease;
use crucible_host_resources::host_supervision::{
    FundedSourcePublisher, HostOperationState, HostSupervisionError, SourceSupervisionPublisher,
    SourceSupervisionSnapshot,
};
use rustix::fs::{MemfdFlags, OFlags, SealFlags};

use crate::linux_attempt_host::{InstalledSourceAdmission, InstalledSourceSubject};

mod action;
pub(crate) use action::ActionSourceProducer;
mod parent_park_return;

pub(crate) const SOURCE_PUBLICATION_BYTES: usize = 1504;
pub(crate) const SOURCE_PAYLOAD_BYTES: usize = 1496;
pub(crate) const SOURCE_CORROBORATION_BYTES: usize = 1520;
const WORDS: usize = SOURCE_PUBLICATION_BYTES / 8;
const HEADER_BYTES: usize = 232;
const BACKING_PAGE_BYTES: u64 = 4096;

/// Retains the same physical Source publication through startup and runtime.
#[derive(Clone, Debug)]
pub(crate) struct OriginalSourceSupervision {
    publisher: FundedSourcePublisher<SourcePublisher>,
}

struct SourcePublisher {
    reader: OwnedFd,
    cancellation: OwnedFd,
    state: Mutex<PublicationState>,
    subject: InstalledSourceSubject,
    artifact: [u8; 32],
    mapping: AtomicPublication,
    action_loans: [Mutex<Option<crucible_host_resources::host_supervision::HostActionLoan>>; 4],
    retained_mapping: Mutex<Option<crucible_qemu_shmem::MappedSetupRegion>>,
    action_mapping: Mutex<Option<(crucible_qemu_shmem::SetupRegionBackingIdentity, u32)>>,
    action_wake: Mutex<Option<Arc<std::fs::File>>>,
    _admission: InstalledSourceAdmission,
}

impl std::fmt::Debug for SourcePublisher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourcePublisher")
            .field("subject", &self.subject)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct PublicationState {
    sequence: u64,
    origin: Option<u64>,
    outer_revision: u64,
    roster_revision: u64,
    initial: Option<[u8; SOURCE_PAYLOAD_BYTES]>,
    cancellation_identity: [u64; 3],
    latest: Option<SourceSupervisionSnapshot>,
    action: Option<action::PendingAction>,
    last_action_return: Option<crucible_qemu_protocol::boundary_action::ActionReturn>,
    last_parent_park_return: Option<parent_park_return::VerifiedParkReturn>,
}

#[derive(Debug)]
struct AtomicPublication {
    words: NonNull<AtomicU64>,
    _control: Option<SourceHostControlLease>,
}

// SAFETY: the retained mapping has a fixed lifetime and aligned atomic words.
// Every mapped access is atomic; host writers are also serialized by state.
unsafe impl Send for AtomicPublication {}
// SAFETY: no reference exposes ordinary mutable bytes or native pointers.
unsafe impl Sync for AtomicPublication {}

impl OriginalSourceSupervision {
    pub(crate) fn host_allocation_extent() -> Option<u64> {
        Self::publication_allocation_extent()?
            .checked_add(
                u64::try_from(FundedSourcePublisher::<SourcePublisher>::allocation_bytes().ok()?)
                    .ok()?,
            )?
            .checked_add(
                4 * crucible_host_resources::host_supervision::HostActionLoan::metadata_bytes(),
            )
    }

    fn publication_allocation_extent() -> Option<u64> {
        (std::mem::size_of::<SourcePublisher>() as u64)
            .checked_add(std::mem::size_of::<SourceSupervisionError>() as u64)?
            .checked_add(BACKING_PAGE_BYTES)?
            .checked_add(
                (SOURCE_CORROBORATION_BYTES + 3 * SOURCE_PAYLOAD_BYTES + 368 + 4097) as u64,
            )?
            .checked_add(
                crucible_host_resources::host_supervision::HostActionLoan::cohort_scratch_bytes(),
            )?
            .checked_add(std::mem::size_of::<SourceHostControlLease>() as u64)
    }

    /// Constructs physical standing controls after their actual Main debit.
    ///
    /// # Errors
    /// Refuses changed admission, insufficient controls, unsupported kernel
    /// sealing, descriptor identity failure or uncertain initial publication.
    pub(crate) fn prepare(
        admission: &InstalledSourceAdmission,
    ) -> Result<Self, SourceSupervisionError> {
        admission
            .check()
            .map_err(SourceSupervisionError::Admission)?;
        let extent =
            Self::publication_allocation_extent().ok_or(SourceSupervisionError::Geometry)?;
        let allocation_extent = FundedSourcePublisher::<SourcePublisher>::allocation_bytes()
            .ok()
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(SourceSupervisionError::Geometry)?;
        let allocation = admission
            .host_purpose()
            .reserve_controls(0, allocation_extent)
            .map_err(SourceSupervisionError::Host)?;
        // The constructor enters only after both disjoint real peaks are held.
        let control = admission
            .host_purpose()
            .reserve_controls(4, extent)
            .map_err(SourceSupervisionError::Host)?;
        construct_source_publication(admission, control, allocation)
    }

    /// Corroborates the actual admission object, never its copied wire subject.
    pub(crate) fn belongs_to(&self, admission: &InstalledSourceAdmission) -> bool {
        self.publisher._admission.same_owner(admission)
    }

    pub(crate) fn corroboration(
        &self,
    ) -> Result<[u8; SOURCE_CORROBORATION_BYTES], SourceSupervisionError> {
        let state = self.publisher.state.lock().map_err(|_| {
            self.publisher.invalidate();
            SourceSupervisionError::Original(HostSupervisionError::Unavailable)
        })?;
        let initial = state
            .initial
            .as_ref()
            .ok_or(SourceSupervisionError::Geometry)?;
        let stat =
            rustix::fs::fstat(&self.publisher.reader).map_err(SourceSupervisionError::Kernel)?;
        if stat.st_size != SOURCE_PUBLICATION_BYTES as i64 {
            return Err(SourceSupervisionError::Geometry);
        }
        let mut bytes = [0; SOURCE_CORROBORATION_BYTES];
        for (offset, value) in [
            (0, stat.st_dev),
            (8, stat.st_ino),
            (16, SOURCE_PUBLICATION_BYTES as u64),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }
        bytes[24..].copy_from_slice(initial);
        Ok(bytes)
    }

    pub(crate) fn duplicate_roles(&self) -> Result<[OwnedFd; 2], rustix::io::Errno> {
        Ok([
            rustix::io::fcntl_dupfd_cloexec(&self.publisher.reader, super::CHILD_SOURCE_FD_MIN)?,
            rustix::io::fcntl_dupfd_cloexec(
                &self.publisher.cancellation,
                super::CHILD_SOURCE_FD_MIN,
            )?,
        ])
    }
}

/// Enters physical/candidate construction only after its same Main peak is held.
fn construct_source_publication(
    admission: &InstalledSourceAdmission,
    control: SourceHostControlLease,
    allocation: SourceHostControlLease,
) -> Result<OriginalSourceSupervision, SourceSupervisionError> {
    let writer = rustix::fs::memfd_create(
        c"crucible-source-supervision",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )
    .map_err(SourceSupervisionError::Kernel)?;
    rustix::fs::ftruncate(&writer, SOURCE_PUBLICATION_BYTES as u64)
        .map_err(SourceSupervisionError::Kernel)?;
    let mapping = AtomicPublication::new(&writer, control)?;
    let seals = SealFlags::GROW | SealFlags::SHRINK | SealFlags::FUTURE_WRITE | SealFlags::SEAL;
    rustix::fs::fcntl_add_seals(&writer, seals).map_err(SourceSupervisionError::Kernel)?;
    if !rustix::fs::fcntl_get_seals(&writer)
        .map_err(SourceSupervisionError::Kernel)?
        .contains(seals)
    {
        return Err(SourceSupervisionError::Geometry);
    }
    let reader = super::plugin_startup::reopen_readonly(writer.as_raw_fd())
        .map_err(SourceSupervisionError::Observation)?;
    if rustix::fs::fcntl_getfl(&reader)
        .map_err(SourceSupervisionError::Kernel)?
        .intersection(OFlags::ACCMODE)
        != OFlags::RDONLY
    {
        return Err(SourceSupervisionError::Geometry);
    }
    drop(writer);
    let cancellation = rustix::event::eventfd(
        0,
        rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
    )
    .map_err(SourceSupervisionError::Kernel)?;
    let stat = rustix::fs::fstat(&cancellation).map_err(SourceSupervisionError::Kernel)?;
    let event_id = super::plugin_startup::event_identity(cancellation.as_raw_fd())
        .map_err(SourceSupervisionError::Observation)?;
    if event_id > i32::MAX as u64 + 1 {
        return Err(SourceSupervisionError::Geometry);
    }
    let publisher = FundedSourcePublisher::new(
        SourcePublisher {
            mapping,
            reader,
            cancellation,
            state: Mutex::new(PublicationState {
                sequence: 0,
                origin: None,
                outer_revision: 0,
                roster_revision: 0,
                initial: None,
                cancellation_identity: [stat.st_dev, stat.st_ino, event_id],
                latest: None,
                action: None,
                last_action_return: None,
                last_parent_park_return: None,
            }),
            subject: admission.subject(),
            artifact: admission.artifact_digest(),
            action_loans: std::array::from_fn(|_| Mutex::new(None)),
            retained_mapping: Mutex::new(None),
            action_mapping: Mutex::new(None),
            action_wake: Mutex::new(None),
            _admission: admission.clone(),
        },
        allocation,
    )
    .map_err(SourceSupervisionError::Original)?;
    let owner = OriginalSourceSupervision { publisher };
    let callback = owner.publisher.standing();
    admission
        .supervisor()
        .retain_source_publication(admission.host_purpose(), &callback)
        .map_err(SourceSupervisionError::Original)?;
    Ok(owner)
}

impl SourceSupervisionPublisher for SourcePublisher {
    fn publish(&self, snapshot: SourceSupervisionSnapshot) -> Result<(), HostSupervisionError> {
        let result = self.publish_snapshot(snapshot);
        if result.is_err() {
            self.mapping.invalidate();
            let _ = rustix::io::write(&self.cancellation, &1_u64.to_ne_bytes());
        }
        result
    }

    fn invalidate(&self) {
        self.mapping.invalidate();
        let _ = rustix::io::write(&self.cancellation, &1_u64.to_ne_bytes());
    }
}

impl SourcePublisher {
    fn publish_snapshot(
        &self,
        snapshot: SourceSupervisionSnapshot,
    ) -> Result<(), HostSupervisionError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        self.publish_locked(&mut state, snapshot)
    }

    fn publish_locked(
        &self,
        state: &mut PublicationState,
        snapshot: SourceSupervisionSnapshot,
    ) -> Result<(), HostSupervisionError> {
        if snapshot.outer.cap_id != self.subject.containing_cap
            || state
                .origin
                .is_some_and(|origin| origin != snapshot.outer.original_monotonic_ns)
            || snapshot.outer.revision < state.outer_revision
            || snapshot.roster_revision < state.roster_revision
        {
            return Err(HostSupervisionError::Unavailable);
        }
        let roster = crate::ram_control::budgets_to_wire(snapshot.budgets)
            .map_err(|_| HostSupervisionError::InvalidBudget)?;
        let roster = crucible_qemu_protocol::ram_control::encode_ram_control_budgets(&roster)
            .map_err(|_| HostSupervisionError::InvalidBudget)?;
        let allowance = snapshot
            .outer
            .allowance
            .map(|value| {
                u64::try_from(value.as_nanos())
                    .ok()
                    .filter(|value| *value > 0 && *value <= i64::MAX as u64)
                    .ok_or(HostSupervisionError::InvalidBudget)
            })
            .transpose()?;
        let mut payload = [0; SOURCE_PAYLOAD_BYTES];
        payload[..8].copy_from_slice(b"CRUCSRV4");
        payload[8..12].copy_from_slice(&4_u32.to_be_bytes());
        payload[12..16].copy_from_slice(&(SOURCE_PAYLOAD_BYTES as u32).to_be_bytes());
        payload[16..48].copy_from_slice(&snapshot.outer.cap_id);
        payload[64] = u8::from(allowance.is_some());
        payload[65] = match snapshot.outer.state {
            HostOperationState::Running => 0,
            HostOperationState::Completed => 1,
            HostOperationState::Expired => 2,
            HostOperationState::Canceled => 3,
        };
        payload[88..120].copy_from_slice(&self.subject.containing_cap);
        payload[120..152].copy_from_slice(&self.subject.reservation);
        payload[192..196].copy_from_slice(&(roster.len() as u32).to_be_bytes());
        // The actual paid publisher retains every born loan in action_loans.
        // Publication loses local-abandon privilege before the request write;
        // only the assigned mapping's physical-return journal can settle it.
        payload[196..200].copy_from_slice(
            &crucible_qemu_protocol::source_supervision::SOURCE_PRODUCER_RETENTION_EDITION
                .to_be_bytes(),
        );
        payload[200..232].copy_from_slice(&self.artifact);
        for (offset, value) in [
            (48, snapshot.outer.original_monotonic_ns),
            (56, snapshot.outer.revision),
            (72, self.subject.account_generation),
            (80, self.subject.process_generation),
            (152, snapshot.roster_revision),
            (160, state.cancellation_identity[0]),
            (168, state.cancellation_identity[1]),
            (176, state.cancellation_identity[2]),
            (184, allowance.unwrap_or(0)),
        ] {
            payload[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }
        let end = HEADER_BYTES
            .checked_add(roster.len())
            .filter(|end| *end <= payload.len())
            .ok_or(HostSupervisionError::InvalidBudget)?;
        payload[HEADER_BYTES..end].copy_from_slice(&roster);
        if let Some(action) = state.action.as_ref() {
            if !action.clearing && action.observation.borrowed_mask != 0 {
                let bytes = action
                    .observation
                    .encode()
                    .map_err(|_| HostSupervisionError::InvalidBudget)?;
                payload[600..].copy_from_slice(&bytes);
            }
        }
        crucible_qemu_protocol::source_supervision::decode_source_supervision_payload(&payload)
            .map_err(|_| HostSupervisionError::InvalidBudget)?;
        let sequence = publish_payload_if_changed(self.mapping.words(), state.sequence, &payload)?;
        state.sequence = sequence;
        state.origin = Some(snapshot.outer.original_monotonic_ns);
        state.outer_revision = snapshot.outer.revision;
        state.roster_revision = snapshot.roster_revision;
        state.latest = Some(snapshot);
        if state.initial.is_none() {
            state.initial = Some(payload);
        }
        let action_notified = (|| {
            if state.action.is_some() {
                let wake = self
                    .action_wake
                    .lock()
                    .map_err(|_| HostSupervisionError::Unavailable)?;
                let wake = wake.as_ref().ok_or(HostSupervisionError::Unavailable)?;
                // This is the same admitted Node eventfd, not the terminal
                // cancellation event. It reports changed facts only; the
                // actual token and retained Source/parent still gate effects.
                match rustix::io::write(wake.as_ref(), &1_u64.to_ne_bytes()) {
                    Ok(8) | Err(rustix::io::Errno::AGAIN) => {}
                    _ => return Err(HostSupervisionError::Unavailable),
                }
            }
            Ok(())
        })();
        let cancellation_notified = if snapshot.outer.state != HostOperationState::Running {
            match rustix::io::write(&self.cancellation, &1_u64.to_ne_bytes()) {
                Ok(8) | Err(rustix::io::Errno::AGAIN) => Ok(()),
                _ => Err(HostSupervisionError::Unavailable),
            }
        } else {
            Ok(())
        };
        // A failed action notification cannot suppress real terminal Source
        // cancellation. Preserve the first result after attempting both cuts.
        action_notified.and(cancellation_notified)
    }
}

impl AtomicPublication {
    fn new(
        writer: &OwnedFd,
        control: SourceHostControlLease,
    ) -> Result<Self, SourceSupervisionError> {
        // SAFETY: this newly created fixed memfd owns the requested 1504-byte
        // extent. mmap returns page alignment suitable for AtomicU64; shared
        // accesses use only atomic words, never ordinary mutable payload bytes.
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                SOURCE_PUBLICATION_BYTES,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                writer.as_raw_fd(),
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(SourceSupervisionError::Observation(
                std::io::Error::last_os_error(),
            ));
        }
        let Some(words) = NonNull::new(pointer.cast()) else {
            // SAFETY: even address zero can be returned by mmap on a permissive
            // host. Refuse that representation, closing the actual same map.
            if unsafe { libc::munmap(pointer, SOURCE_PUBLICATION_BYTES) } != 0 {
                std::mem::forget(control);
            }
            return Err(SourceSupervisionError::Geometry);
        };
        Ok(Self {
            words,
            _control: Some(control),
        })
    }

    fn words(&self) -> &[AtomicU64; WORDS] {
        // SAFETY: the retained mapping has exactly WORDS aligned atomic words;
        // it stays mapped until this owner drops, after its borrower references.
        unsafe { &*self.words.as_ptr().cast::<[AtomicU64; WORDS]>() }
    }

    fn invalidate(&self) {
        self.words()[0].store(u64::MAX.to_be(), Ordering::SeqCst);
    }
}

/// Keeps a live standing sequence stable until its complete payload changes.
///
/// Actual publisher serialization still surrounds the whole call. Repeated
/// polling of unchanged facts must not invalidate a retained Native action;
/// every changed field still publishes a new epoch. All reads stay atomic so a
/// concurrent terminal invalidation cannot be overwritten or hidden as a no-op.
fn publish_payload_if_changed(
    words: &[AtomicU64; WORDS],
    expected: u64,
    payload: &[u8; SOURCE_PAYLOAD_BYTES],
) -> Result<u64, HostSupervisionError> {
    if expected == u64::MAX
        || expected & 1 != 0
        || u64::from_be(words[0].load(Ordering::SeqCst)) != expected
    {
        return Err(HostSupervisionError::Unavailable);
    }

    let mut unchanged = expected != 0;
    for (word, bytes) in words[1..].iter().zip(payload.chunks_exact(8)) {
        let mut value = [0; 8];
        value.copy_from_slice(bytes);
        unchanged &= word.load(Ordering::SeqCst) == u64::from_be_bytes(value).to_be();
    }

    if u64::from_be(words[0].load(Ordering::SeqCst)) != expected {
        return Err(HostSupervisionError::Unavailable);
    }
    if unchanged {
        return Ok(expected);
    }

    let sequence = expected
        .checked_add(2)
        .filter(|value| *value < u64::MAX)
        .ok_or(HostSupervisionError::IdentityExhausted)?;

    // Invalidation can win before entry or during the bounded payload walk.
    // Neither transition may replace its terminal sequence with a live one.
    transition_sequence(&words[0], expected, sequence - 1)?;
    for (word, bytes) in words[1..].iter().zip(payload.chunks_exact(8)) {
        let mut value = [0; 8];
        value.copy_from_slice(bytes);
        word.store(u64::from_be_bytes(value).to_be(), Ordering::SeqCst);
    }
    transition_sequence(&words[0], sequence - 1, sequence)?;
    Ok(sequence)
}

/// Changes the actual shared sequence only while the expected epoch still owns it.
fn transition_sequence(
    word: &AtomicU64,
    expected: u64,
    replacement: u64,
) -> Result<(), HostSupervisionError> {
    if expected == u64::MAX || replacement == u64::MAX {
        return Err(HostSupervisionError::Unavailable);
    }
    word.compare_exchange(
        expected.to_be(),
        replacement.to_be(),
        Ordering::SeqCst,
        Ordering::SeqCst,
    )
    .map(|_| ())
    .map_err(|_| HostSupervisionError::Unavailable)
}

impl Drop for AtomicPublication {
    fn drop(&mut self) {
        self.invalidate();
        // SAFETY: this is the exact fixed mapping retained by this owner.
        if unsafe { libc::munmap(self.words.as_ptr().cast(), SOURCE_PUBLICATION_BYTES) } != 0 {
            // Keep the same entire Main Source peak on uncertain unmapping;
            // neither local uniqueness nor a descriptor close proves it gone.
            if let Some(control) = self._control.take() {
                std::mem::forget(control);
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SourceSupervisionError {
    #[error("Source admission refused: {0}")]
    Admission(#[source] crate::linux_attempt_host::OriginalActorAccountError),
    #[error("Source host funding refused: {0}")]
    Host(#[source] crucible_host_resources::host_services::process_birth::ServiceBirthError),
    #[error("Source supervision refused: {0}")]
    Original(#[source] HostSupervisionError),
    #[error("Source kernel publication failed: {0}")]
    Kernel(#[source] rustix::io::Errno),
    #[error("Source physical observation failed: {0}")]
    Observation(#[source] std::io::Error),
    #[error("Source publication geometry is invalid")]
    Geometry,
}

/// Preserves actual nominal-issuer and physical publication causes independently.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SourceEmissionError {
    #[error("installed Source purpose refused: {0}")]
    Purpose(#[from] crate::linux_attempt_host::InstalledProcessPurposeError),
    #[error("standing Source publication refused: {0}")]
    Publication(#[from] SourceSupervisionError),
}

#[cfg(test)]
mod sequence_tests {
    use super::*;

    // These exercise the real transition primitive; no Source authority or
    // kernel mapping is manufactured by a component atomic-word fixture.
    #[test]
    fn invalidation_before_publication_refuses_odd_begin() {
        let sequence = AtomicU64::new(0);
        sequence.store(u64::MAX.to_be(), Ordering::SeqCst);

        assert!(transition_sequence(&sequence, 0, 1).is_err());
        assert_eq!(u64::from_be(sequence.load(Ordering::SeqCst)), u64::MAX);
    }

    #[test]
    fn invalidation_between_payload_begin_and_finish_cannot_revive() {
        let sequence = AtomicU64::new(0);
        transition_sequence(&sequence, 0, 1).unwrap();
        sequence.store(u64::MAX.to_be(), Ordering::SeqCst);

        assert!(transition_sequence(&sequence, 1, 2).is_err());
        assert!(transition_sequence(&sequence, 0, 1).is_err());
        assert!(transition_sequence(&sequence, u64::MAX, 1).is_err());
        assert_eq!(u64::from_be(sequence.load(Ordering::SeqCst)), u64::MAX);
    }

    #[test]
    fn invalidation_after_even_publication_refuses_the_next_epoch() {
        let sequence = AtomicU64::new(0);
        transition_sequence(&sequence, 0, 1).unwrap();
        transition_sequence(&sequence, 1, 2).unwrap();
        assert_eq!(u64::from_be(sequence.load(Ordering::SeqCst)), 2);
        sequence.store(u64::MAX.to_be(), Ordering::SeqCst);

        assert!(transition_sequence(&sequence, 2, 3).is_err());
        assert_eq!(u64::from_be(sequence.load(Ordering::SeqCst)), u64::MAX);
    }

    #[test]
    fn identical_full_payload_preserves_the_actual_published_epoch() {
        let words = std::array::from_fn(|_| AtomicU64::new(0));
        let payload = [0; SOURCE_PAYLOAD_BYTES];

        assert_eq!(publish_payload_if_changed(&words, 0, &payload), Ok(2));
        assert_eq!(publish_payload_if_changed(&words, 2, &payload), Ok(2));
        assert_eq!(u64::from_be(words[0].load(Ordering::SeqCst)), 2);
    }

    #[test]
    fn each_actual_payload_word_change_publishes_a_new_epoch() {
        let words = std::array::from_fn(|_| AtomicU64::new(0));
        let mut payload = [0; SOURCE_PAYLOAD_BYTES];
        let mut sequence = publish_payload_if_changed(&words, 0, &payload).unwrap();

        for index in 0..WORDS - 1 {
            payload[index * 8 + 7] = 1;
            let next = publish_payload_if_changed(&words, sequence, &payload).unwrap();

            assert_eq!(next, sequence + 2);
            assert_eq!(u64::from_be(words[index + 1].load(Ordering::SeqCst)), 1);
            assert_eq!(publish_payload_if_changed(&words, next, &payload), Ok(next));
            sequence = next;
        }
    }

    #[test]
    fn unchanged_payload_cannot_hide_foreign_odd_or_terminal_sequence() {
        let words = std::array::from_fn(|_| AtomicU64::new(0));
        let payload = [0; SOURCE_PAYLOAD_BYTES];
        publish_payload_if_changed(&words, 0, &payload).unwrap();

        for actual in [0_u64, 3, 4, u64::MAX] {
            words[0].store(actual.to_be(), Ordering::SeqCst);

            assert_eq!(
                publish_payload_if_changed(&words, 2, &payload),
                Err(HostSupervisionError::Unavailable),
            );
            assert_eq!(u64::from_be(words[0].load(Ordering::SeqCst)), actual);
        }
    }

    #[test]
    fn final_even_epoch_can_repeat_but_never_wrap_on_changed_facts() {
        let words = std::array::from_fn(|_| AtomicU64::new(0));
        let mut payload = [0; SOURCE_PAYLOAD_BYTES];
        let last = u64::MAX - 1;
        words[0].store(last.to_be(), Ordering::SeqCst);

        assert_eq!(publish_payload_if_changed(&words, last, &payload), Ok(last));
        payload[0] = 1;
        assert_eq!(
            publish_payload_if_changed(&words, last, &payload),
            Err(HostSupervisionError::IdentityExhausted),
        );
        assert_eq!(u64::from_be(words[0].load(Ordering::SeqCst)), last);
        assert_eq!(words[1].load(Ordering::SeqCst), 0);
    }
}
