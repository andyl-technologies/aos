//! Exercises bounded data-only refusal custody with real durable test ledgers.
//!
//! These controls create no native catalog, node, process, or release authority.

// crucible-lint: allow panic-shortcut -- Inert refusal custody controls panic on failed assertions and injected storage unwind.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::super::super::tests::{request, storage};
use super::*;
use crucible_cas::content_store::{
    ContentId, DirectoryRefBackend, MutableRefBackend, RefBackendCapabilities, RefCasOutcome,
    RefName, RefPublicationGuard, RefScanPage, StoreError,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU8, AtomicUsize, Ordering},
};

struct FaultRefs {
    inner: DirectoryRefBackend,
    fault: AtomicU8,
    attempts: AtomicUsize,
    visited: Mutex<std::collections::BTreeSet<String>>,
    succeed_execution: Option<String>,
}

impl MutableRefBackend for FaultRefs {
    fn capabilities(&self) -> RefBackendCapabilities {
        self.inner.capabilities()
    }

    fn acquire_publication_guard(&self) -> Result<Box<dyn RefPublicationGuard + '_>, StoreError> {
        self.inner.acquire_publication_guard()
    }

    fn read_ref(&self, name: &RefName) -> Result<Option<ContentId>, StoreError> {
        self.inner.read_ref(name)
    }

    fn scan_refs(
        &self,
        namespace: &RefName,
        after: Option<&RefName>,
        limit: usize,
    ) -> Result<RefScanPage, StoreError> {
        self.inner.scan_refs(namespace, after, limit)
    }

    fn compare_exchange(
        &self,
        name: &RefName,
        expected: Option<ContentId>,
        next: ContentId,
    ) -> Result<RefCasOutcome, StoreError> {
        self.attempts.fetch_add(1, Ordering::AcqRel);
        self.visited.lock().unwrap().insert(name.as_str().into());
        let fault = if self
            .succeed_execution
            .as_ref()
            .is_some_and(|execution| name.as_str().ends_with(execution))
        {
            0
        } else {
            self.fault.load(Ordering::Acquire)
        };
        match fault {
            1 => Err(StoreError::Quota),
            2 => panic!("injected data-only CAS unwind"),
            3 => {
                let _ = self.inner.compare_exchange(name, expected, next)?;
                Err(StoreError::Quota)
            }
            _ => self.inner.compare_exchange(name, expected, next),
        }
    }
}

fn original(ledger: &CapabilityPreparationLedger, nonce: u8) -> Refusal {
    let mut authored = request();
    authored.execution = format!("{nonce:02x}").repeat(16);
    let reservation = ledger.reserve(&authored).unwrap();
    assert!(reservation.original_dispatch);
    Refusal::new(reservation, ledger.clone())
}

#[test]
fn bounded_mailbox_keeps_excess_original_without_allocating_a_native_lane() {
    let directory = tempfile::tempdir().unwrap();
    let (blobs, refs) = storage(directory.path());
    let ledger = CapabilityPreparationLedger::new(blobs, refs).unwrap();
    let mut queue = Refusals {
        originals: BTreeMap::new(),
        maximum: 1,
        cursor: None,
    };
    let mut first = Some(original(&ledger, 0x81));
    let mut excess = Some(original(&ledger, 0x82));
    let original_request = excess.as_ref().unwrap().reservation.record.request.clone();

    queue.retain_original(&mut first);
    queue.retain_original(&mut excess);

    assert!(first.is_none());
    assert_eq!(queue.len(), 1);
    assert_eq!(
        excess.as_ref().unwrap().reservation.record.request,
        original_request
    );
    assert!(matches!(
        ledger.state(&"82".repeat(16)).unwrap().outcome,
        CapabilityPreparationState::AwaitingAdmission {}
    ));

    queue.poll();
    queue.retain_original(&mut excess);
    assert!(excess.is_none());
    assert_eq!(queue.len(), 1);
    queue.poll();
    assert_eq!(queue.len(), 0);
}

#[test]
fn cas_refusal_and_unwind_retain_original_and_identical_terminal_placement() {
    let directory = tempfile::tempdir().unwrap();
    let (blobs, _) = storage(directory.path());
    let refs = Arc::new(FaultRefs {
        inner: DirectoryRefBackend::new(directory.path().join("fault-refs")),
        fault: AtomicU8::new(0),
        attempts: AtomicUsize::new(0),
        visited: Mutex::new(std::collections::BTreeSet::new()),
        succeed_execution: None,
    });
    let ledger = CapabilityPreparationLedger::new(blobs, refs.clone()).unwrap();
    let mut queue = Refusals::new();
    let mut incoming = Some(original(&ledger, 0x83));
    queue.retain_original(&mut incoming);
    let execution = "83".repeat(16);

    refs.fault.store(1, Ordering::Release);
    queue.poll();
    assert!(queue.originals[&execution].sealed.is_some());
    assert_eq!(queue.len(), 1);
    assert!(matches!(
        ledger.state(&execution).unwrap().outcome,
        CapabilityPreparationState::AwaitingAdmission {}
    ));

    refs.fault.store(2, Ordering::Release);
    queue.poll();
    assert_eq!(queue.len(), 1);

    // Publication may commit before returning an error. Retain the same original
    // until a later exact-byte reconciliation verifies that committed identity.
    refs.fault.store(3, Ordering::Release);
    queue.poll();
    assert_eq!(queue.len(), 1);
    let sealed = super::super::super::encode(&ledger.state(&execution).unwrap()).unwrap();
    assert!(matches!(
        ledger.state(&execution).unwrap().outcome,
        CapabilityPreparationState::Unavailable { .. }
    ));

    refs.fault.store(0, Ordering::Release);
    queue.poll();
    assert_eq!(queue.len(), 0);
    let mut duplicate = request();
    duplicate.execution = execution;
    let original_duplicate = ledger.reserve(&duplicate).unwrap();
    assert!(!original_duplicate.original_dispatch);
    assert_eq!(
        super::super::super::encode(&original_duplicate.record).unwrap(),
        sealed
    );
}

#[test]
fn duplicate_reservation_cannot_replace_held_original_and_production_bound_matches_ledger() {
    let directory = tempfile::tempdir().unwrap();
    let (blobs, refs) = storage(directory.path());
    let ledger = CapabilityPreparationLedger::new(blobs, refs).unwrap();
    let mut queue = Refusals::new();
    assert_eq!(queue.maximum, MAXIMUM_RECORDS);
    let mut first = Some(original(&ledger, 0x84));
    queue.retain_original(&mut first);
    let mut duplicate_request = request();
    duplicate_request.execution = "84".repeat(16);
    let duplicate = ledger.reserve(&duplicate_request).unwrap();
    let mut rejected = Some(Refusal::new(duplicate, ledger.clone()));

    queue.retain_original(&mut rejected);

    assert_eq!(queue.len(), 1);
    assert!(rejected.is_some());
    assert!(!rejected.as_ref().unwrap().reservation.original_dispatch);
    assert!(matches!(
        ledger.state(&duplicate_request.execution).unwrap().outcome,
        CapabilityPreparationState::AwaitingAdmission {}
    ));
}

#[test]
fn data_only_refusal_keeps_shutdown_pending_without_native_owner_or_thread_credit() {
    let directory = tempfile::tempdir().unwrap();
    let (blobs, refs) = storage(directory.path());
    let ledger = CapabilityPreparationLedger::new(blobs, refs).unwrap();
    let mut authored = request();
    authored.execution = "85".repeat(16);
    let reservation = ledger.reserve(&authored).unwrap();
    let mut lanes = super::super::Lanes::new();

    let held = lanes.refuse(reservation, ledger.clone());

    assert!(held.is_none());
    assert_eq!(lanes.len(), 0);
    assert!(!lanes.is_empty());
    assert_eq!(lanes.refusals.len(), 1);
    let mut fallback = std::collections::VecDeque::with_capacity(MAXIMUM_RECORDS);
    lanes.poll(&mut fallback);
    assert!(lanes.is_empty());
    assert!(matches!(
        ledger.state(&authored.execution).unwrap().outcome,
        CapabilityPreparationState::Unavailable { .. }
    ));
}

#[test]
fn rejected_transfer_preserves_preallocated_fallback_through_storage_failure() {
    let directory = tempfile::tempdir().unwrap();
    let (blobs, _) = storage(directory.path());
    let refs = Arc::new(FaultRefs {
        inner: DirectoryRefBackend::new(directory.path().join("fallback-refs")),
        fault: AtomicU8::new(0),
        attempts: AtomicUsize::new(0),
        visited: Mutex::new(std::collections::BTreeSet::new()),
        succeed_execution: None,
    });
    let ledger = CapabilityPreparationLedger::new(blobs, refs.clone()).unwrap();
    let mut authored = request();
    authored.execution = "86".repeat(16);
    let reservation = ledger.reserve(&authored).unwrap();
    let original_request = reservation.record.request.clone();
    let mut lanes = super::super::Lanes::new();
    lanes.refusals.maximum = 0;
    let mut fallback = std::collections::VecDeque::with_capacity(MAXIMUM_RECORDS);
    let reserved = fallback.capacity();

    let rejected = lanes.refuse(reservation, ledger.clone()).unwrap();
    fallback.push_back(rejected);
    refs.fault.store(1, Ordering::Release);
    lanes.poll(&mut fallback);

    assert_eq!(lanes.len(), 0);
    assert_eq!(fallback.len(), 1);
    assert_eq!(fallback.capacity(), reserved);
    assert_eq!(fallback[0].reservation.record.request, original_request);
    assert!(matches!(
        ledger.state(&authored.execution).unwrap().outcome,
        CapabilityPreparationState::AwaitingAdmission {}
    ));

    refs.fault.store(0, Ordering::Release);
    lanes.poll(&mut fallback);
    assert!(fallback.is_empty());
    assert_eq!(fallback.capacity(), reserved);
    assert!(matches!(
        ledger.state(&authored.execution).unwrap().outcome,
        CapabilityPreparationState::Unavailable { .. }
    ));
}

#[test]
fn many_failed_originals_share_bounded_turn_attempts_without_starving_either_holder() {
    let directory = tempfile::tempdir().unwrap();
    let (blobs, _) = storage(directory.path());
    let refs = Arc::new(FaultRefs {
        inner: DirectoryRefBackend::new(directory.path().join("fair-refs")),
        fault: AtomicU8::new(0),
        attempts: AtomicUsize::new(0),
        visited: Mutex::new(std::collections::BTreeSet::new()),
        succeed_execution: None,
    });
    let ledger = CapabilityPreparationLedger::new(blobs, refs.clone()).unwrap();
    let mut lanes = super::super::Lanes::new();
    lanes.refusals.maximum = 16;
    let mut fallback = std::collections::VecDeque::with_capacity(MAXIMUM_RECORDS);
    for nonce in 1..=25 {
        let original = original(&ledger, nonce);
        if let Some(original) = lanes.refuse(original.reservation, ledger.clone()) {
            fallback.push_back(original);
        }
    }
    assert_eq!(lanes.refusals.len(), 16);
    assert_eq!(fallback.len(), 9);
    refs.attempts.store(0, Ordering::Release);
    refs.visited.lock().unwrap().clear();
    refs.fault.store(1, Ordering::Release);

    for _ in 0..8 {
        let before = refs.attempts.load(Ordering::Acquire);
        lanes.poll(&mut fallback);
        let after = refs.attempts.load(Ordering::Acquire);
        assert_eq!(
            after - before,
            super::super::MAXIMUM_REFUSAL_ATTEMPTS_PER_TURN
        );
        assert_eq!(lanes.len(), 0);
    }
    assert_eq!(refs.visited.lock().unwrap().len(), 25);
    assert_eq!(lanes.refusals.len(), 16);
    assert_eq!(fallback.len(), 9);

    refs.fault.store(0, Ordering::Release);
    for _ in 0..8 {
        lanes.poll(&mut fallback);
    }
    assert!(lanes.is_empty());
    assert!(fallback.is_empty());
    for nonce in 1..=25 {
        assert!(matches!(
            ledger
                .state(&format!("{nonce:02x}").repeat(16))
                .unwrap()
                .outcome,
            CapabilityPreparationState::Unavailable { .. }
        ));
    }
}

#[test]
fn mixed_wrapped_fallback_success_never_repeats_a_visited_failed_original() {
    let directory = tempfile::tempdir().unwrap();
    let (blobs, _) = storage(directory.path());
    let completed = "a1".repeat(16);
    let refs = Arc::new(FaultRefs {
        inner: DirectoryRefBackend::new(directory.path().join("mixed-refs")),
        fault: AtomicU8::new(0),
        attempts: AtomicUsize::new(0),
        visited: Mutex::new(std::collections::BTreeSet::new()),
        succeed_execution: Some(completed.clone()),
    });
    let ledger = CapabilityPreparationLedger::new(blobs, refs.clone()).unwrap();
    let mut lanes = super::super::Lanes::new();
    let mut fallback = std::collections::VecDeque::with_capacity(MAXIMUM_RECORDS);
    for nonce in 0xa1..=0xa4 {
        fallback.push_back(original(&ledger, nonce));
    }
    let reserved = fallback.capacity();
    // Start at C: C/D fail, then A completes. Removing A must not repeat D
    // before B receives its first attempt in this same actor turn.
    fallback.rotate_left(2);
    refs.attempts.store(0, Ordering::Release);
    refs.visited.lock().unwrap().clear();
    refs.fault.store(1, Ordering::Release);

    lanes.poll(&mut fallback);

    assert_eq!(refs.attempts.load(Ordering::Acquire), 4);
    assert_eq!(refs.visited.lock().unwrap().len(), 4);
    assert_eq!(fallback.len(), 3);
    assert_eq!(fallback.capacity(), reserved);
    assert!(matches!(
        ledger.state(&completed).unwrap().outcome,
        CapabilityPreparationState::Unavailable { .. }
    ));
    for nonce in 0xa2..=0xa4 {
        let execution = format!("{nonce:02x}").repeat(16);
        assert!(
            refs.visited
                .lock()
                .unwrap()
                .iter()
                .any(|name| name.ends_with(&execution))
        );
        assert!(
            fallback
                .iter()
                .any(|held| held.reservation.record.execution == execution)
        );
        assert!(matches!(
            ledger.state(&execution).unwrap().outcome,
            CapabilityPreparationState::AwaitingAdmission {}
        ));
    }

    refs.attempts.store(0, Ordering::Release);
    refs.visited.lock().unwrap().clear();
    lanes.poll(&mut fallback);
    assert_eq!(refs.attempts.load(Ordering::Acquire), 3);
    assert_eq!(refs.visited.lock().unwrap().len(), 3);
    assert_eq!(fallback.len(), 3);
    assert_eq!(fallback.capacity(), reserved);
}
