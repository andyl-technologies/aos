//! Checks real discard effects and unresolved journal/body custody.

// SPDX-License-Identifier: GPL-2.0-only

use super::*;

struct AnonymousPage(*mut c_void);

impl AnonymousPage {
    fn new() -> Self {
        // SAFETY: this test owns one fresh private anonymous mapping until Drop.
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE_BYTES,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        assert_ne!(address, libc::MAP_FAILED);
        // SAFETY: the test exclusively owns this complete writable mapping.
        unsafe { std::ptr::write_bytes(address.cast::<u8>(), 0xa7, PAGE_BYTES) };
        Self(address)
    }

    fn resident(&self) -> bool {
        let mut resident = 0_u8;
        // SAFETY: the mapping and the one-byte output cover this exact query.
        let status = unsafe { libc::mincore(self.0, PAGE_BYTES, &mut resident) };
        assert_eq!(status, 0);
        resident & 1 != 0
    }
}

impl Drop for AnonymousPage {
    fn drop(&mut self) {
        // SAFETY: no worker was born and this test still owns the exact mapping.
        assert_eq!(unsafe { libc::munmap(self.0, PAGE_BYTES) }, 0);
    }
}

#[test]
fn actual_discard_success_is_separate_from_journal_settlement() {
    let page = AnonymousPage::new();
    let mut effect = Effect::Started;
    assert!(page.resident());

    // SAFETY: this test exclusively owns the page; no guest/native issuer is
    // simulated. Only the syscall effect is under test, with no live accessors.
    let result = unsafe { discard_page(page.0 as u64) }.map_err(RamError::from);
    effect.finish(result).unwrap();

    effect.check_complete().unwrap();
    assert!(!page.resident());
    let mut journal = EvictionJournal::new(0, page.0 as u64, PageState::default());
    journal.discard = effect;
    assert!(!journal.residency_returned);
    assert!(journal.check_settled().is_err());
}

#[test]
fn actual_kernel_discard_refusal_retains_the_original_effect_error() {
    let page = AnonymousPage::new();
    let mut effect = Effect::Started;

    // SAFETY: madvise rejects an unaligned address without modifying the
    // exclusively owned mapping. The negative case exercises the real syscall.
    let result = unsafe { discard_page(page.0 as u64 + 1) }.map_err(RamError::from);
    let error = effect.finish(result).unwrap_err();

    assert!(matches!(&error, RamError::Io(error) if error.raw_os_error() == Some(libc::EINVAL)));
    assert_eq!(effect.check_complete().unwrap_err(), error);
    assert!(page.resident());
    // SAFETY: the refused syscall left the original exclusive mapping intact.
    let bytes = unsafe { std::slice::from_raw_parts(page.0.cast::<u8>(), PAGE_BYTES) };
    assert_eq!(bytes, &[0xa7; PAGE_BYTES]);
}

#[test]
fn unfinished_journal_blocks_scratch_fork_and_metadata_refund() {
    let extent = FaultWorkOwner::required_metadata_bytes().unwrap();
    let budget = MetadataBudget::new(extent);
    let owner = FaultWorkOwner::prepare(&budget).unwrap();
    {
        let mut work = owner.try_lock().unwrap();
        // This is pending-custody evidence only. It issues no native token,
        // Source operation, resident entitlement or physical-effect success.
        work.eviction = Some(EvictionJournal::new(0, 0, PageState::default()));
        work.scratch[53] = 0x9d;

        assert!(work.idle_scratch().is_err());
        assert_eq!(work.scratch[53], 0x9d);
    }
    assert!(owner.check_settled().is_err());

    drop(owner);

    assert_eq!(budget.used_bytes(), extent);
}

#[test]
fn unfinished_journal_cannot_acknowledge_a_requested_capture() {
    let extent = FaultWorkOwner::required_metadata_bytes().unwrap();
    let budget = MetadataBudget::new(extent);
    let owner = FaultWorkOwner::prepare(&budget).unwrap();
    let mut work = owner.try_lock().unwrap();
    work.eviction = Some(EvictionJournal::new(0, 0, PageState::default()));
    owner.request_pause(91).unwrap();

    assert!(owner.acknowledge_pause_at_boundary(&work).is_err());
    assert!(!owner.pause_acknowledged(91));
    assert!(owner.release_pause(91).is_err());
}

#[test]
fn completed_or_uncertain_end_cannot_retry_a_late_busy_or_again() {
    // This checks the real dispatch decision over saved call history. It does
    // not issue a native certificate or claim a real physical end occurred.
    for status in [-libc::EBUSY, -libc::EAGAIN] {
        let journal = PlacementDispatchJournal::default();
        assert!(journal.retry_before_action(status, 0));
        assert!(!journal.retry_before_action(status, 7));

        journal.end_entered.store(true, Ordering::Release);
        assert!(!journal.retry_before_action(status, 0));

        journal.end_status.store(0, Ordering::Release);
        journal.end_returned.store(true, Ordering::Release);
        journal.action_completed.store(true, Ordering::Release);
        journal.callback_status.store(0, Ordering::Release);
        journal.callback_returned.store(true, Ordering::Release);
        journal.runner_entered.store(true, Ordering::Release);
        journal.runner_status.store(status, Ordering::Release);
        journal.runner_returned.store(true, Ordering::Release);
        journal.record_first_negative(status);
        assert!(!journal.retry_before_action(status, 0));
        assert!(journal.reset().is_err());
        assert_eq!(journal.end_status.load(Ordering::Acquire), 0);
        assert_eq!(journal.callback_status.load(Ordering::Acquire), 0);
        assert_eq!(journal.runner_status.load(Ordering::Acquire), status);
    }
}

#[test]
fn failed_preservation_still_saves_the_owned_writeback_post_without_completion() {
    use crate::paged_ram::source::ObservationOperationError;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    struct RefusingWriteback {
        posts: Arc<AtomicUsize>,
        completions: Arc<AtomicUsize>,
    }

    impl SourceOperation for RefusingWriteback {
        fn wait_slice(&self) -> io::Result<Duration> {
            self.posts.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::from_raw_os_error(libc::ETIMEDOUT))
        }

        fn complete(&self) -> io::Result<()> {
            self.completions.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::from_raw_os_error(libc::ECANCELED))
        }

        fn wait_slice_for_observation(&self) -> Result<Duration, ObservationOperationError> {
            self.wait_slice().map_err(Into::into)
        }

        fn complete_observation(&self) -> Result<(), ObservationOperationError> {
            self.complete().map_err(Into::into)
        }
    }

    // This negative-only Original interface cannot admit successful work. The
    // control exercises the production result/post join, not a Source issuer.
    let posts = Arc::new(AtomicUsize::new(0));
    let completions = Arc::new(AtomicUsize::new(0));
    let mut journal = EvictionJournal::new(0, 0, PageState::default());
    journal.preservation = Effect::Started;
    journal.writeback = Some(Box::new(RefusingWriteback {
        posts: posts.clone(),
        completions: completions.clone(),
    }));
    let counters = PagingCounters::default();
    let first = RamError::from(io::Error::from_raw_os_error(libc::EIO));

    let result = journal.finish_preservation(Err(first.clone()), &counters);

    assert_eq!(result, Err(first.clone()));
    assert!(matches!(&journal.preservation, Effect::Failed(error) if *error == first));
    assert!(
        matches!(&journal.writeback_post, Effect::Failed(RamError::Io(error))
        if error.raw_os_error() == Some(libc::ETIMEDOUT))
    );
    assert_eq!(posts.load(Ordering::SeqCst), 1);
    assert_eq!(completions.load(Ordering::SeqCst), 0);
    assert!(matches!(journal.writeback_completion, Effect::NotStarted));
    assert!(journal.writeback.is_some());
    assert_eq!(counters.preserved_writes.load(Ordering::Acquire), 0);
}
