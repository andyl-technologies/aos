//! Exercises native capture validation and independent dirty acknowledgement.

// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;

struct ImmutableProofSource {
    snapshot: RamSnapshot,
    record: crucible_ram::RootRecord,
    requests: std::sync::atomic::AtomicUsize,
}

impl RamProofSource for ImmutableProofSource {
    fn source_record(&self) -> &crucible_ram::RootRecord {
        &self.record
    }

    fn source_root(&self) -> RamRootDigest {
        self.record.digest()
    }

    fn proof(&self, id: &str, page: u64) -> Result<crucible_ram::PageProof, RamError> {
        self.requests
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.snapshot
            .region_tree(id)
            .ok_or("missing source region")?
            .proof(id, page)
            .map_err(display_error)
    }
}

#[test]
fn child_proof_rebind_preserves_changed_identity_and_returns_prior_custody() {
    let budget = MetadataBudget::new(1024 * 1024);
    let descriptor = RegionDescriptor::new("ram", RegionClass::MutableMain, 4096).unwrap();
    let topology = Topology::new(vec![descriptor.clone()], Limits::default()).unwrap();
    let tree =
        RegionTree::from_page_digests(4096, &[PageDigest::hash(&[1; 4096]).unwrap()], &budget)
            .unwrap();
    let original = RamSnapshot::new(topology, vec![tree], &budget).unwrap();
    let changed = original
        .updated("ram", &[(0, PageDigest::hash(&[2; 4096]).unwrap())])
        .unwrap();
    let source = Arc::new(ImmutableProofSource {
        snapshot: original.clone(),
        record: original.root_record(Scope::Exact).unwrap(),
        requests: std::sync::atomic::AtomicUsize::new(0),
    });
    let replacement = Arc::new(ImmutableProofSource {
        snapshot: original.clone(),
        record: source.record.clone(),
        requests: std::sync::atomic::AtomicUsize::new(0),
    });
    let roots = SCOPES.map(|scope| changed.scoped_root(scope).unwrap());
    let records = encode_records(&changed, &budget).unwrap();
    let record_pointer = records[0].bytes.as_ptr();
    let mut cache = RootCache {
        budget: Some(budget.clone()),
        view: Some(CachedView {
            topology_generation: 7,
            budget: budget.clone(),
            snapshot: changed.clone(),
            roots,
            logical_bytes: [4096; 3],
            native_regions: vec![descriptor],
            records,
            source: Some(source.clone()),
            _inventory_reservation: budget.reserve_bytes(1024).unwrap(),
        }),
        ..RootCache::default()
    };
    assert!(cache.rebind_proof_source(replacement.clone()).is_err());
    cache.frozen = true;
    let wrong_base = Arc::new(ImmutableProofSource {
        record: changed.root_record(Scope::Exact).unwrap(),
        snapshot: changed,
        requests: std::sync::atomic::AtomicUsize::new(0),
    });
    assert!(cache.rebind_proof_source(wrong_base).is_err());
    let prior_accounting = budget.used_bytes();
    let prior = cache.rebind_proof_source(replacement.clone()).unwrap();

    assert_eq!(prior.source_root(), source.source_root());
    assert!(Arc::ptr_eq(
        &prior,
        &(source.clone() as Arc<dyn RamProofSource>)
    ));
    assert_eq!(cache.view.as_ref().unwrap().roots, roots);
    assert_ne!(roots[1], prior.source_root());
    assert_eq!(
        cache.view.as_ref().unwrap().records[0].bytes.as_ptr(),
        record_pointer
    );
    assert_eq!(budget.used_bytes(), prior_accounting);
    assert_eq!(
        source.requests.load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    assert_eq!(
        replacement
            .requests
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[test]
fn opaque_restore_hydrates_only_written_paths_without_reverting_changes() {
    let budget = MetadataBudget::new(1024 * 1024);
    let descriptor = RegionDescriptor::new("ram", RegionClass::MutableMain, 8192).unwrap();
    let original_pages = [
        PageDigest::hash(&[1; 4096]).unwrap(),
        PageDigest::hash(&[2; 4096]).unwrap(),
    ];
    let topology = Topology::new(vec![descriptor.clone()], Limits::default()).unwrap();
    let tree = RegionTree::from_page_digests(8192, &original_pages, &budget).unwrap();
    let original = RamSnapshot::new(topology, vec![tree], &budget).unwrap();
    let record = original.root_record(Scope::Exact).unwrap();
    let source = ImmutableProofSource {
        snapshot: original.clone(),
        record,
        requests: std::sync::atomic::AtomicUsize::new(0),
    };
    let opaque = RamSnapshot::from_root_record(&source.record, &budget).unwrap();
    assert_eq!(
        opaque.scoped_root(Scope::Exact).unwrap(),
        source.record.digest()
    );
    assert_eq!(
        source.requests.load(std::sync::atomic::Ordering::Relaxed),
        0
    );

    let changed_first = PageDigest::hash(&[3; 4096]).unwrap();
    let mut batch = vec![(0, changed_first)];
    assert!(
        apply_batch(
            opaque.clone(),
            std::slice::from_ref(&descriptor),
            Some(0),
            &mut batch,
            None
        )
        .is_err()
    );
    assert_eq!(batch.len(), 1);
    let first = apply_batch(
        opaque,
        std::slice::from_ref(&descriptor),
        Some(0),
        &mut batch,
        Some(&source),
    )
    .unwrap();
    assert_eq!(
        first.region_tree("ram").unwrap().page_digest(0).unwrap(),
        changed_first
    );
    assert_eq!(
        source.requests.load(std::sync::atomic::Ordering::Relaxed),
        1
    );

    let changed_second = PageDigest::hash(&[4; 4096]).unwrap();
    let mut batch = vec![(1, changed_second)];
    let both = apply_batch(
        first.clone(),
        std::slice::from_ref(&descriptor),
        Some(0),
        &mut batch,
        Some(&source),
    )
    .unwrap();
    assert_eq!(
        both.region_tree("ram").unwrap().page_digest(0).unwrap(),
        changed_first
    );
    assert_eq!(
        both.region_tree("ram").unwrap().page_digest(1).unwrap(),
        changed_second
    );
    assert_eq!(
        source.requests.load(std::sync::atomic::Ordering::Relaxed),
        2
    );
    assert_eq!(
        original.region_tree("ram").unwrap().page_digest(0).unwrap(),
        original_pages[0]
    );

    let mut batch = vec![(0, PageDigest::hash(&[5; 4096]).unwrap())];
    apply_batch(both, &[descriptor], Some(0), &mut batch, Some(&source)).unwrap();
    assert_eq!(
        source.requests.load(std::sync::atomic::Ordering::Relaxed),
        2
    );
}

#[derive(Default)]
struct FakeNative {
    pages: Vec<(u32, u64, Vec<u8>)>,
    commits: usize,
    aborts: usize,
    full_requests: Vec<u32>,
    fail_commit: bool,
}

static FAKE: Mutex<FakeNative> = Mutex::new(FakeNative {
    pages: Vec::new(),
    commits: 0,
    aborts: 0,
    full_requests: Vec::new(),
    fail_commit: false,
});

extern "C" fn begin(full: u32, header: *mut CaptureHeader) -> c_int {
    FAKE.lock().unwrap().full_requests.push(full);
    // SAFETY: the observer lends writable storage for this synchronous call.
    unsafe {
        header.write(CaptureHeader {
            schema: 1,
            region_count: 2,
            topology_generation: 1,
            capture_generation: 1,
            metadata_budget_bytes: 1024 * 1024,
        });
    }
    0
}

extern "C" fn region(_generation: u64, index: u32, output: *mut CaptureRegion) -> c_int {
    let mut descriptor = CaptureRegion::default();
    // Native iteration deliberately differs from canonical identifier order.
    descriptor.id[0] = if index == 0 { b'z' } else { b'a' };
    descriptor.id_length = 1;
    descriptor.class = if index == 0 { 1 } else { 3 };
    descriptor.mask = if index == 0 { 7 } else { 6 };
    descriptor.logical_length = if index == 0 { 4097 } else { 1 };
    // SAFETY: the observer lends writable storage for this synchronous call.
    unsafe {
        output.write(descriptor);
    }
    0
}

extern "C" fn next(
    _generation: u64,
    cursor: *mut u64,
    output: *mut CapturePage,
    bytes: *mut u8,
    capacity: usize,
) -> c_int {
    let native = FAKE.lock().unwrap();
    // SAFETY: cursor points to the observer's live scalar for this call.
    let index = unsafe { cursor.read() } as usize;
    let Some((region, page, data)) = native.pages.get(index) else {
        return 1;
    };
    assert!(data.len() <= capacity);
    // SAFETY: the observer lends exact output and scratch capacities; no pointer
    // is retained after the synchronous native page copy.
    unsafe {
        output.write(CapturePage {
            region_index: *region,
            page_index: *page,
            valid_length: data.len() as u32,
            page_version: 1,
        });
        std::ptr::copy_nonoverlapping(data.as_ptr(), bytes, data.len());
        cursor.write((index + 1) as u64);
    }
    0
}

extern "C" fn finish(_generation: u64, commit: u32) -> c_int {
    let mut native = FAKE.lock().unwrap();
    if commit == 1 {
        if native.fail_commit {
            return -libc::ESTALE;
        }
        native.commits += 1;
    } else {
        native.aborts += 1;
    }
    0
}

extern "C" fn register(_observer: Option<RootObserver>) -> c_int {
    0
}
extern "C" fn register_record(_observer: Option<RecordObserver>) -> c_int {
    0
}
extern "C" fn register_transaction(_observer: Option<TransactionObserver>) -> c_int {
    0
}

extern "C" fn register_admission(_observer: Option<AdmissionObserver>) -> c_int {
    0
}

fn apis() -> NativeApis {
    NativeApis {
        begin,
        region,
        next,
        finish,
        register,
        register_record,
        register_transaction,
        admission_region: region,
        register_admission,
    }
}

#[test]
fn coherent_stream_preserves_unchanged_roots_and_refuses_missing_pages() {
    *FAKE.lock().unwrap() = FakeNative::default();
    let mut cache = RootCache::default();

    FAKE.lock().unwrap().pages = vec![(0, 0, vec![7; 4096]), (0, 1, vec![8])];
    assert!(cache.refresh(apis()).is_err());
    assert!(cache.view.is_none());
    assert_eq!(FAKE.lock().unwrap().aborts, 1);
    assert_eq!(FAKE.lock().unwrap().commits, 0);

    FAKE.lock().unwrap().pages.push((1, 0, vec![9]));
    cache.refresh(apis()).unwrap();
    let initial = cache.view.as_ref().unwrap().snapshot.clone();
    let initial_root = initial.scoped_root(Scope::Execution).unwrap();
    assert_eq!(
        cache.view.as_ref().unwrap().logical_bytes,
        [4097, 4098, 4098]
    );
    assert_eq!(initial.topology().regions()[0].id(), "a");
    for (index, scope) in SCOPES.into_iter().enumerate() {
        let record = crucible_ram::RootRecord::decode(
            &cache.view.as_ref().unwrap().records[index].bytes,
            Limits::default(),
        )
        .unwrap();
        assert_eq!(record.scope(), scope);
        assert_eq!(record.digest(), cache.view.as_ref().unwrap().roots[index]);
    }
    let retained_record = cache.view.as_ref().unwrap().records[0].bytes.as_ptr();
    let retained_metadata = cache.view.as_ref().unwrap().budget.used_bytes();

    FAKE.lock().unwrap().pages.clear();
    cache.refresh(apis()).unwrap();
    assert_eq!(cache.view.as_ref().unwrap().roots[0], initial_root);
    assert_eq!(
        cache.view.as_ref().unwrap().records[0].bytes.as_ptr(),
        retained_record
    );
    assert_eq!(
        cache.view.as_ref().unwrap().budget.used_bytes(),
        retained_metadata
    );

    FAKE.lock().unwrap().pages = vec![(0, 1, vec![10])];
    cache.refresh(apis()).unwrap();
    let changed = &cache.view.as_ref().unwrap().snapshot;
    assert_ne!(changed.scoped_root(Scope::Execution).unwrap(), initial_root);
    assert_eq!(
        initial.region_tree("z").unwrap().page_digest(1).unwrap(),
        PageDigest::hash(&[8]).unwrap()
    );
    assert_eq!(
        changed.region_tree("z").unwrap().page_digest(0).unwrap(),
        PageDigest::hash(&vec![7; 4096]).unwrap()
    );
    assert_eq!(
        changed.region_tree("a").unwrap().digest(),
        initial.region_tree("a").unwrap().digest()
    );

    let committed = changed.scoped_root(Scope::Execution).unwrap();
    FAKE.lock().unwrap().pages = vec![(0, 1, vec![11]), (0, 1, vec![12])];
    assert!(cache.refresh(apis()).is_err());
    assert_eq!(cache.view.as_ref().unwrap().roots[0], committed);
    let native = FAKE.lock().unwrap();
    assert_eq!(native.commits, 3);
    assert_eq!(native.aborts, 2);
    assert_eq!(native.full_requests, [1, 1, 0, 0, 0]);
    drop(native);

    let prior_records = cache.view.as_ref().unwrap().records[0].bytes.clone();
    let prior_metadata = cache.view.as_ref().unwrap().budget.used_bytes();
    {
        let mut native = FAKE.lock().unwrap();
        native.pages = vec![(0, 1, vec![15])];
        native.fail_commit = true;
    }
    assert!(cache.refresh(apis()).is_err());
    assert_eq!(cache.view.as_ref().unwrap().roots[0], committed);
    assert_eq!(cache.view.as_ref().unwrap().records[0].bytes, prior_records);
    assert_eq!(
        cache.view.as_ref().unwrap().budget.used_bytes(),
        prior_metadata
    );
    assert_eq!(FAKE.lock().unwrap().commits, 3);
    assert_eq!(FAKE.lock().unwrap().aborts, 3);
    FAKE.lock().unwrap().fail_commit = false;

    let afterimage = [13_u8];
    let pages = [PreparedPage {
        region_index: 0,
        valid_length: 1,
        page_index: 1,
        page_version: 2,
        bytes: afterimage.as_ptr(),
    }];
    cache.prepare_mutation(7, 1, &pages).unwrap();
    assert_eq!(cache.view.as_ref().unwrap().roots[0], committed);
    assert_ne!(cache.pending.as_ref().unwrap().roots[0], committed);
    assert!(cache.refresh(apis()).is_err());
    assert!(cache.finish_mutation(8, 1, true).is_err());
    cache.finish_mutation(7, 1, false).unwrap();
    assert_eq!(cache.view.as_ref().unwrap().roots[0], committed);

    cache.prepare_mutation(9, 1, &pages).unwrap();
    let repeated_afterimage = [14_u8];
    let repeated_pages = [PreparedPage {
        region_index: 0,
        valid_length: 1,
        page_index: 1,
        page_version: 2,
        bytes: repeated_afterimage.as_ptr(),
    }];
    cache.prepare_mutation(9, 1, &repeated_pages).unwrap();
    assert_eq!(cache.view.as_ref().unwrap().roots[0], committed);
    let candidate = cache.pending.as_ref().unwrap().roots[0];
    cache.finish_mutation(9, 1, true).unwrap();
    assert_eq!(cache.view.as_ref().unwrap().roots[0], candidate);
    assert!(cache.pending.is_none());
}

#[test]
fn private_native_capture_layouts_are_fixed() {
    assert_eq!(std::mem::size_of::<CaptureHeader>(), 32);
    assert_eq!(std::mem::size_of::<CaptureRegion>(), 280);
    assert_eq!(std::mem::size_of::<CapturePage>(), 24);
    assert_eq!(std::mem::size_of::<PreparedPage>(), 32);
}
