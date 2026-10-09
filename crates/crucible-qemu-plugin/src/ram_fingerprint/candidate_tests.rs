//! Checks private candidates, omitted dirties, and independent cleanup failures.

// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};

const ALLOWANCE: u64 = 1024 * 1024;
static SERIAL: Mutex<()> = Mutex::new(());
static OMIT: AtomicBool = AtomicBool::new(false);
static READ_STATUS: AtomicI32 = AtomicI32::new(0);
static CLOSE_STATUS: AtomicI32 = AtomicI32::new(0);
static BEGINS: AtomicUsize = AtomicUsize::new(0);
static CLOSES: AtomicUsize = AtomicUsize::new(0);
static READS: AtomicUsize = AtomicUsize::new(0);

extern "C" fn begin(full: u32, token: u64, out: *mut CaptureHeader) -> c_int {
    assert_eq!((full, token), (0, 53));
    BEGINS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: the claim lends exclusive initialized output for this callback.
    unsafe {
        out.write(CaptureHeader {
            schema: CAPTURE_SCHEMA,
            region_count: 1,
            topology_generation: 41,
            capture_generation: 27,
            metadata_budget_bytes: ALLOWANCE,
        });
    }
    0
}

extern "C" fn region(generation: u64, token: u64, index: u32, out: *mut CaptureRegion) -> c_int {
    assert_eq!((generation, token, index), (27, 53, 0));
    let mut native = CaptureRegion {
        id_length: 3,
        class: 1,
        mask: 7,
        logical_length: 4096,
        ..CaptureRegion::default()
    };
    native.id[..3].copy_from_slice(b"ram");
    // SAFETY: the observer lends exclusive descriptor output until return.
    unsafe { out.write(native) };
    0
}

extern "C" fn next(
    generation: u64,
    token: u64,
    cursor: *mut u64,
    out: *mut CapturePage,
    bytes: *mut u8,
    capacity: usize,
) -> c_int {
    assert_eq!((generation, token, capacity), (27, 53, 4096));
    READS.fetch_add(1, Ordering::Relaxed);
    let failure = READ_STATUS.load(Ordering::Relaxed);
    if failure != 0 {
        return failure;
    }
    // SAFETY: cursor and the page/scratch outputs are live exclusive loans.
    unsafe {
        if cursor.read() != 0 || OMIT.load(Ordering::Relaxed) {
            return 1;
        }
        out.write(CapturePage {
            region_index: 0,
            valid_length: 4096,
            page_index: 0,
            page_version: 1,
        });
        std::ptr::write_bytes(bytes, 2, capacity);
        cursor.write(1);
    }
    0
}

extern "C" fn finish(generation: u64, token: u64, commit: u32) -> c_int {
    assert_eq!((generation, token, commit), (27, 53, 0));
    CLOSES.fetch_add(1, Ordering::Relaxed);
    CLOSE_STATUS.load(Ordering::Relaxed)
}

fn fixture() -> (RootCache, NativeApis) {
    OMIT.store(false, Ordering::Relaxed);
    READ_STATUS.store(0, Ordering::Relaxed);
    CLOSE_STATUS.store(0, Ordering::Relaxed);
    BEGINS.store(0, Ordering::Relaxed);
    CLOSES.store(0, Ordering::Relaxed);
    READS.store(0, Ordering::Relaxed);
    let budget = MetadataBudget::new(ALLOWANCE);
    let descriptor = RegionDescriptor::new("ram", RegionClass::MutableMain, 4096).unwrap();
    let topology = Topology::new(vec![descriptor.clone()], Limits::default()).unwrap();
    let tree =
        RegionTree::from_page_digests(4096, &[PageDigest::hash(&[1; 4096]).unwrap()], &budget)
            .unwrap();
    let snapshot = RamSnapshot::new(topology, vec![tree], &budget).unwrap();
    let roots = SCOPES.map(|scope| snapshot.scoped_root(scope).unwrap());
    let records = encode_records(&snapshot, &budget).unwrap();
    let view = CachedView {
        topology_generation: 41,
        budget: budget.clone(),
        snapshot,
        roots,
        logical_bytes: [4096; 3],
        native_regions: vec![descriptor],
        records,
        source: None,
        _inventory_reservation: budget.reserve_bytes(1024).unwrap(),
    };
    (
        RootCache {
            budget: Some(budget),
            view: Some(view),
            ..RootCache::default()
        },
        NativeApis {
            begin,
            region,
            next,
            finish,
            ..super::tests::apis()
        },
    )
}

#[test]
fn candidate_changes_identity_without_publishing_records_or_acknowledging_pages() {
    let _serial = SERIAL.lock().unwrap();
    let (cache, apis) = fixture();
    let view = cache.view.as_ref().unwrap();
    let original = view.roots;
    let record = view.records[0].bytes.as_ptr();
    let used = view.budget.used_bytes();
    let mut cleanup = CaptureClose::default();

    let (root, bytes) = cache
        .observe_candidate(apis, Scope::Execution, 53, &mut cleanup)
        .unwrap();

    assert_ne!(root, original[0]);
    assert_eq!(bytes, 4096);
    assert_eq!(cache.view.as_ref().unwrap().roots, original);
    assert_eq!(
        cache.view.as_ref().unwrap().records[0].bytes.as_ptr(),
        record
    );
    assert_eq!(view.budget.used_bytes(), used);
    assert_eq!(
        (cleanup.generation, cleanup.status, cleanup.attempted),
        (27, 0, 1)
    );
    assert_eq!(CLOSES.load(Ordering::Relaxed), 1);
}

#[test]
fn omitted_dirty_notification_keeps_stale_candidate_for_independent_full_reader_to_reject() {
    let _serial = SERIAL.lock().unwrap();
    let (cache, apis) = fixture();
    OMIT.store(true, Ordering::Relaxed);
    let view = cache.view.as_ref().unwrap();
    let full = view
        .snapshot
        .updated("ram", &[(0, PageDigest::hash(&[2; 4096]).unwrap())])
        .unwrap();
    let mut cleanup = CaptureClose::default();

    let (root, _) = cache
        .observe_candidate(apis, Scope::Execution, 53, &mut cleanup)
        .unwrap();

    assert_eq!(root, view.roots[0]);
    assert_ne!(root, full.scoped_root(Scope::Execution).unwrap());
    assert_eq!((cleanup.status, cleanup.attempted), (0, 1));
    assert_eq!(CLOSES.load(Ordering::Relaxed), 1);
}

#[test]
fn original_page_failure_and_failed_no_ack_cleanup_are_both_retained() {
    let _serial = SERIAL.lock().unwrap();
    let (cache, apis) = fixture();
    READ_STATUS.store(-libc::EIO, Ordering::Relaxed);
    CLOSE_STATUS.store(-libc::ESTALE, Ordering::Relaxed);
    let mut cleanup = CaptureClose::default();

    let result = cache.observe_candidate(apis, Scope::Execution, 53, &mut cleanup);

    assert!(matches!(result, Err(RamError::Native { status, .. }) if status == -libc::EIO));
    assert_eq!(
        (cleanup.generation, cleanup.status, cleanup.attempted),
        (27, -libc::ESTALE, 1)
    );
    assert_eq!(CLOSES.load(Ordering::Relaxed), 1);
}

#[test]
fn cleanup_refusal_prevents_an_otherwise_complete_candidate_from_escaping() {
    let _serial = SERIAL.lock().unwrap();
    let (cache, apis) = fixture();
    CLOSE_STATUS.store(-libc::ESTALE, Ordering::Relaxed);
    let mut cleanup = CaptureClose::default();

    let result = cache.observe_candidate(apis, Scope::Execution, 53, &mut cleanup);

    assert!(matches!(result, Err(RamError::Native { status, .. }) if status == -libc::ESTALE));
    assert_eq!((cleanup.status, cleanup.attempted), (-libc::ESTALE, 1));
    assert_eq!(CLOSES.load(Ordering::Relaxed), 1);
}

struct PanickingProofSource {
    record: crucible_ram::RootRecord,
    requests: AtomicUsize,
}

impl RamProofSource for PanickingProofSource {
    fn source_record(&self) -> &crucible_ram::RootRecord {
        &self.record
    }

    fn source_root(&self) -> RamRootDigest {
        self.record.digest()
    }

    fn proof(
        &self,
        _region_id: &str,
        _page_index: u64,
    ) -> Result<crucible_ram::PageProof, RamError> {
        self.requests.fetch_add(1, Ordering::Relaxed);
        panic!("injected retained proof-source panic");
    }
}

#[test]
fn proof_source_panic_retains_failed_cleanup_without_publishing_the_candidate() {
    let _serial = SERIAL.lock().unwrap();
    let (mut cache, apis) = fixture();
    let view = cache.view.as_mut().unwrap();
    let source = Arc::new(PanickingProofSource {
        record: view.snapshot.root_record(Scope::Exact).unwrap(),
        requests: AtomicUsize::new(0),
    });
    view.snapshot = RamSnapshot::from_root_record(&source.record, &view.budget).unwrap();
    view.source = Some(source.clone());
    let original = view.roots;
    let record = view.records[0].bytes.as_ptr();
    let used = view.budget.used_bytes();
    CLOSE_STATUS.store(-libc::ESTALE, Ordering::Relaxed);
    let mut cleanup = CaptureClose::default();

    let result = cache.observe_candidate(apis, Scope::Execution, 53, &mut cleanup);

    assert!(matches!(
        result,
        Err(RamError::Invariant("RAM candidate observation panicked"))
    ));
    assert_eq!(source.requests.load(Ordering::Relaxed), 1);
    assert_eq!(
        (cleanup.generation, cleanup.status, cleanup.attempted),
        (27, -libc::ESTALE, 1)
    );
    assert_eq!(CLOSES.load(Ordering::Relaxed), 1);
    let view = cache.view.as_ref().unwrap();
    assert_eq!(view.roots, original);
    assert_eq!(view.records[0].bytes.as_ptr(), record);
    assert_eq!(view.budget.used_bytes(), used);
}

#[test]
fn a_different_account_or_stale_topology_refuses_without_renewing_admission() {
    let _serial = SERIAL.lock().unwrap();
    let (mut cache, apis) = fixture();
    let original = cache.budget.take().unwrap();
    cache.budget = Some(MetadataBudget::new(ALLOWANCE));
    let mut cleanup = CaptureClose::default();

    assert!(
        cache
            .observe_candidate(apis, Scope::Execution, 53, &mut cleanup)
            .is_err()
    );
    assert_eq!(BEGINS.load(Ordering::Relaxed), 0);
    assert_eq!(cleanup.attempted, 0);

    cache.budget = Some(original);
    cache.view.as_mut().unwrap().topology_generation += 1;
    assert!(
        cache
            .observe_candidate(apis, Scope::Execution, 53, &mut cleanup)
            .is_err()
    );
    assert_eq!(READS.load(Ordering::Relaxed), 0);
    assert_eq!((cleanup.status, cleanup.attempted), (0, 1));
    assert_eq!(CLOSES.load(Ordering::Relaxed), 1);
}
