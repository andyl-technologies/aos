//! Exercises original root-inventory credit, allocation and first-refusal custody.
//!
//! The finite component account supplies Rust storage only. It certifies no
//! installed filesystem project, native execution or full fixture bootstrap.

use std::alloc::Layout;
use std::sync::Arc;

use crucible_cas::owned_decode::{DecodeAdmissionError, DecodeResourceAuthority, ResourceLoan};
use crucible_linux_resource::host_services::{
    HostServiceAllocator, HostServiceError, HostServiceLease,
};
use crucible_linux_resource::test_support::TestAllocationObserver;

use super::*;

const CAPACITY: u64 = 4 * 1024 * 1024;

pub(in crate::campaign_gc) struct Original {
    pub(in crate::campaign_gc) bank: HostServiceAllocator,
    pub(in crate::campaign_gc) budget: DecodeBudget,
    guard: Arc<Authority>,
    // This parent remains live through every synchronous account/error borrower.
    _structure: HostServiceLease,
}

impl Original {
    pub(in crate::campaign_gc) fn new() -> Self {
        let bank = HostServiceAllocator::new(1, 1, CAPACITY).expect("finite original root purpose");
        let bytes = ResourceLoan::allocation_bytes::<Authority>()
            + ResourceLoan::allocation_bytes::<HostServiceError>()
            + HostServiceLease::metadata_bytes();
        let structure = bank
            .reserve_resources(0, 0, bytes)
            .expect("original incoming controls");
        let authority = Arc::new(Authority {
            bank: bank.clone(),
            capacity_failure: DecodeAdmissionError::new(HostServiceError::CapacityExhausted),
        });
        let budget =
            DecodeBudget::new(authority.clone(), CAPACITY).expect("same original decoding account");
        Self {
            bank,
            budget,
            guard: authority,
            _structure: structure,
        }
    }

    pub(in crate::campaign_gc) fn resources(
        &self,
    ) -> Arc<dyn crucible_cas::content_store::StorePhysicalQuotaGuard> {
        self.guard.clone()
    }
}

struct Authority {
    bank: HostServiceAllocator,
    capacity_failure: DecodeAdmissionError,
}

impl DecodeResourceAuthority for Authority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        self.bank.verify_live().map_err(DecodeAdmissionError::new)
    }

    fn reserve(&self, bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
        let charged = bytes
            .checked_add(HostServiceLease::metadata_bytes())
            .and_then(|n| n.checked_add(ResourceLoan::allocation_bytes::<HostServiceLease>()))
            .ok_or_else(|| self.capacity_failure.clone())?;
        let lease = self
            .bank
            .reserve_resources(0, 0, charged)
            .map_err(|source| match source {
                HostServiceError::CapacityExhausted => self.capacity_failure.clone(),
                other => DecodeAdmissionError::new(other),
            })?;
        Ok(ResourceLoan::new(lease))
    }
}

impl crucible_cas::content_store::StorePhysicalQuotaGuard for Authority {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        self.verify()?;
        Ok(CAPACITY)
    }

    fn verify(&self) -> Result<(), StoreError> {
        self.bank.verify_live().map_err(|_| StoreError::Quota)
    }

    fn reserve_resources(&self, descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        if descriptors != 0 {
            return Err(StoreError::Unsupported {
                capability: "root-test-purpose-has-no-descriptors",
            });
        }
        DecodeResourceAuthority::reserve(self, bytes).map_err(|source| {
            StoreError::DecodeAdmission {
                source,
                custody: None,
            }
        })
    }
}

fn id(index: usize) -> ContentId {
    ContentId::for_bytes(
        crucible_cas::content_store::ObjectKind::Trace,
        1,
        &index.to_be_bytes(),
    )
}

fn leaf_extent() -> usize {
    // Pinned LeafNode fields: parent pointer, two u16 fields, eleven keys/unit values.
    let bytes = std::mem::size_of::<usize>() + 4 + 11 * std::mem::size_of::<ContentId>();
    let alignment = std::mem::align_of::<usize>().max(std::mem::align_of::<ContentId>());
    bytes.next_multiple_of(alignment)
}

#[test]
fn empty_roots_buy_no_storage_and_duplicates_share_one_original_batch() {
    let original = Original::new();
    let (mut roots, counts) =
        TestAllocationObserver::count(|| RootAccumulator::new(&original.budget));
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    let key = id(0);
    roots.insert(key).expect("first actual root");
    let (_, counts) = TestAllocationObserver::count(|| {
        for _ in 0..512 {
            roots.insert(key).expect("duplicate root");
        }
    });
    assert_eq!(roots.admitted_unique, ROOT_ADMISSION_BATCH);
    assert_eq!(roots.unique.len(), 1);
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    drop(roots);
    original
        .budget
        .verify_live()
        .expect("same original remains live");
}

#[test]
fn each_original_tree_closes_while_its_same_credit_remains_live() {
    for target in 0..4 {
        for unwind in [false, true] {
            let original = Original::new();
            let mut roots = RootAccumulator::new(&original.budget);
            let first = id(0);
            let second = id(1);
            let (_, ordinary) =
                TestAllocationObserver::capture_controls([leaf_extent(); 3], || {
                    roots
                        .insert(first)
                        .expect("funded unique and ordinary trees");
                });
            let (_, direct) = TestAllocationObserver::capture_controls([leaf_extent(); 3], || {
                roots
                    .insert_pending_write_back(second)
                    .expect("funded direct and pending trees");
            });
            assert!(ordinary[0].is_some() && ordinary[1].is_some() && ordinary[2].is_none());
            assert!(direct[0].is_some() && direct[1].is_some() && direct[2].is_none());
            let control =
                [ordinary[0], ordinary[1], direct[0], direct[1]][target].expect("actual tree node");
            let (outcome, retained) =
                TestAllocationObserver::observe(&original.bank, control, || {
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                        let _roots = roots;
                        if unwind {
                            panic!("root prefix unwind");
                        }
                    }))
                });
            assert_eq!(outcome.is_err(), unwind);
            let paid = 4
                * 3
                * (std::mem::size_of::<ContentId>() + 4 * std::mem::size_of::<usize>())
                * ROOT_ADMISSION_BATCH;
            assert!(retained.is_some_and(|bytes| bytes >= paid as u64));
            original
                .budget
                .verify_live()
                .expect("tree close did not close original");
        }
    }
}

#[test]
fn denied_second_batch_allocates_no_tree_and_preserves_the_original_cause() {
    let original = Original::new();
    // A different already admitted purpose occupies the SAME bank before roots.
    // The decode allowance is unchanged; aggregate original-bank admission refuses.
    let _occupied = original
        .bank
        .reserve_resources(0, 0, CAPACITY - 300_000)
        .expect("other original purpose");
    let mut roots = RootAccumulator::new(&original.budget);
    for index in 0..ROOT_ADMISSION_BATCH {
        roots.insert(id(index)).expect("first funded root batch");
    }
    let key = id(ROOT_ADMISSION_BATCH);
    let (refusal, counts) = TestAllocationObserver::count(|| roots.insert(key));
    let RootInsertionError::Admission(StoreError::DecodeAdmission { source, custody }) =
        refusal.expect_err("second original-bank batch must refuse")
    else {
        panic!("original admission category");
    };
    assert!(custody.is_some());
    assert_eq!(
        std::error::Error::source(&source)
            .expect("typed original source")
            .downcast_ref::<HostServiceError>(),
        Some(&HostServiceError::CapacityExhausted)
    );
    assert_eq!(roots.unique.len(), ROOT_ADMISSION_BATCH);
    assert_eq!(roots.ordinary.len(), ROOT_ADMISSION_BATCH);
    assert!(!roots.unique.contains(&key));
    assert_eq!(roots.admitted_unique, ROOT_ADMISSION_BATCH);
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    let first = original
        .budget
        .failure()
        .expect("same account report")
        .expect("sticky first cause");
    assert_eq!(first.to_string(), source.to_string());
    assert!(std::ptr::eq(
        std::error::Error::source(&first).expect("saved original source"),
        std::error::Error::source(&source).expect("returned original source"),
    ));
    drop(roots);
    drop(custody);
}

#[test]
fn successful_second_batch_covers_each_root_category_before_growth() {
    let original = Original::new();
    let mut roots = RootAccumulator::new(&original.budget);
    for index in 0..=ROOT_ADMISSION_BATCH {
        match index % 3 {
            0 => roots.insert(id(index)),
            1 => roots.insert_direct(id(index)),
            _ => roots.insert_pending_write_back(id(index)),
        }
        .expect("same original pays actual new root batch");
    }
    assert_eq!(roots.admitted_unique, 2 * ROOT_ADMISSION_BATCH);
    assert_eq!(roots.unique.len(), ROOT_ADMISSION_BATCH + 1);
    assert_eq!(roots.ordinary.len(), 86);
    assert_eq!(roots.direct.len(), 171);
    assert_eq!(roots.pending_write_back.len(), 85);

    drop(roots);
    original
        .budget
        .verify_live()
        .expect("original after all trees");
    drop(original);
}

#[test]
fn maximum_observations_still_count_duplicates_before_new_admission() {
    let original = Original::new();
    let mut roots = RootAccumulator::new(&original.budget);
    let key = id(0);
    for _ in 0..MAX_CAMPAIGN_GC_MANIFEST_ENTRIES {
        roots.insert(key).expect("bounded duplicate observation");
    }
    assert!(matches!(
        roots.insert_direct(key),
        Err(RootInsertionError::Limit)
    ));
    assert!(roots.direct.is_empty());
    assert_eq!(roots.unique.len(), 1);
    assert_eq!(roots.admitted_unique, ROOT_ADMISSION_BATCH);
}

#[test]
fn each_pinned_batch_covers_initial_nodes_and_transient_split_ancestry() {
    let alignment = std::mem::align_of::<ContentId>().max(std::mem::align_of::<usize>());
    let node = Layout::array::<ContentId>(11).expect("keys").size()
        + 13 * std::mem::size_of::<usize>()
        + 4
        + 7 * (alignment - 1);
    let ancestry = 2 * (MAX_CAMPAIGN_GC_MANIFEST_ENTRIES.ilog2() as usize + 2);
    for count in
        (ROOT_ADMISSION_BATCH..=MAX_CAMPAIGN_GC_MANIFEST_ENTRIES).step_by(ROOT_ADMISSION_BATCH)
    {
        let paid =
            count * 3 * (std::mem::size_of::<ContentId>() + 4 * std::mem::size_of::<usize>());
        let live_and_splitting = (1 + count / 5 + ancestry) * node;
        assert!(
            paid >= live_and_splitting,
            "batch {count}: {paid} < {live_and_splitting}"
        );
    }
    eprintln!(
        "root geometry: RootAccumulator={} leaf={} internal-node bound={node}",
        std::mem::size_of::<RootAccumulator<'_>>(),
        leaf_extent()
    );
}

fn archive_id() -> CampaignArchiveManifestId {
    let content = ContentId::for_bytes(
        crucible_cas::content_store::ObjectKind::Projection,
        2,
        b"archive-vector-control",
    );
    CampaignArchiveManifestId::parse(&format!("crucible.campaign.archive-manifest@{content}"))
        .expect("typed archive identity")
}

fn retained_original_bytes(original: &Original) -> u64 {
    let credit = original
        .bank
        .reserve_resources(0, 0, 1)
        .expect("one-byte observer body");
    // The probe must physically allocate even when capture is inlined.
    let (probe, identity) =
        TestAllocationObserver::capture(1, || std::hint::black_box(Box::new(0_u8)));
    let ((), paid) =
        TestAllocationObserver::observe(&original.bank, identity.expect("observer body"), || {
            drop(probe)
        });
    drop(credit);
    paid.expect("actual original retained counter") - 1
}

#[test]
fn archive_collection_grows_from_four_and_preserves_duplicate_order() {
    let original = Original::new();
    let archive = archive_id();
    let (mut archives, counts) = TestAllocationObserver::count(Vec::new);
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);

    reserve_archive_slot(&mut archives, &original.budget).expect("first four bodies paid");
    assert_eq!(archives.capacity(), 4);
    archives.push(archive);
    let (_, counts) = TestAllocationObserver::count(|| {
        for _ in 1..4 {
            reserve_archive_slot(&mut archives, &original.budget).expect("already paid capacity");
            archives.push(archive);
        }
    });
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);

    reserve_archive_slot(&mut archives, &original.budget).expect("full replacement body paid");
    archives.push(archive);
    assert_eq!(archives.capacity(), 8);
    assert_eq!(archives.as_slice(), &[archive; 5]);
    eprintln!(
        "archive ID body={} alignment={}",
        std::mem::size_of::<CampaignArchiveManifestId>(),
        std::mem::align_of::<CampaignArchiveManifestId>()
    );
}

#[test]
fn denied_archive_growth_changes_no_payload_and_retains_actual_admission() {
    for prefix in [0, 32] {
        let original = Original::new();
        let archive = archive_id();
        let mut archives = Vec::new();
        for _ in 0..prefix {
            reserve_archive_slot(&mut archives, &original.budget).expect("paid archive prefix");
            archives.push(archive);
        }
        let body =
            std::mem::size_of::<CampaignArchiveManifestId>() * if prefix == 0 { 4 } else { 64 };
        let paid = retained_original_bytes(&original);
        let _occupied = original
            .bank
            .reserve_resources(0, 0, CAPACITY - paid - (body as u64 - 1))
            .expect("same-bank remainder leaves less than the replacement body");
        let before = (archives.as_ptr(), archives.len(), archives.capacity());
        let (refusal, counts) =
            TestAllocationObserver::count(|| reserve_archive_slot(&mut archives, &original.budget));
        let RootInsertionError::Admission(StoreError::DecodeAdmission { source, custody }) =
            refusal.expect_err("full new body must refuse")
        else {
            panic!("original archive admission category");
        };
        assert!(custody.is_some());
        assert_eq!(
            std::error::Error::source(&source)
                .expect("typed original source")
                .downcast_ref::<HostServiceError>(),
            Some(&HostServiceError::CapacityExhausted)
        );
        assert_eq!(
            (archives.as_ptr(), archives.len(), archives.capacity()),
            before
        );
        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        let first = original
            .budget
            .failure()
            .expect("original report")
            .expect("saved refusal");
        assert!(std::ptr::eq(
            std::error::Error::source(&first).expect("saved source"),
            std::error::Error::source(&source).expect("returned source")
        ));
    }
}

#[test]
fn archive_payload_free_keeps_original_credit_on_return_and_unwind() {
    for unwind in [false, true] {
        let original = Original::new();
        let roots = RootAccumulator::new(&original.budget);
        let archive = archive_id();
        let mut archives = Vec::new();
        let layout = Layout::array::<CampaignArchiveManifestId>(4).expect("selected Vec body");
        let (_, identity, _) = TestAllocationObserver::capture_layout_and_count(layout, || {
            reserve_archive_slot(&mut archives, roots.original).expect("original archive bodies");
            archives.push(archive);
        });
        let identity = identity.expect("actual Vec payload");
        let base = std::num::NonZeroUsize::new(archives.as_ptr() as usize)
            .expect("live original Vec base");
        assert_eq!(
            identity,
            crucible_linux_resource::test_support::AllocationIdentity::from_address(base)
        );
        let (outcome, retained) = TestAllocationObserver::observe(&original.bank, identity, || {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _archives = archives;
                if unwind {
                    panic!("archive collection unwind");
                }
            }))
        });
        assert_eq!(outcome.is_err(), unwind);
        let paid = retained.expect("original counter before actual System free");
        assert!(paid >= layout.size() as u64);
        // A fresh same-bank probe after that physical free must still find
        // exactly the retained debit; dropping a buffer never refunds it.
        let _remainder = original
            .bank
            .reserve_resources(0, 0, CAPACITY - paid)
            .expect("unchanged original remainder after free");
        assert!(matches!(
            original.bank.reserve_resources(0, 0, 1),
            Err(HostServiceError::CapacityExhausted)
        ));
        drop(roots);
    }
}

struct ArchiveMarks {
    resources: Arc<dyn crucible_cas::content_store::StorePhysicalQuotaGuard>,
}

impl crucible_cas::content_store::ImmutableBlobBackend for ArchiveMarks {
    fn name(&self) -> &str {
        "archive-inventory-control"
    }

    fn capabilities(&self) -> crucible_cas::content_store::BackendCapabilities {
        Default::default()
    }

    fn metadata_resources(
        &self,
    ) -> Result<Arc<dyn crucible_cas::content_store::StorePhysicalQuotaGuard>, StoreError> {
        Ok(self.resources.clone())
    }

    fn contains(&self, _id: ContentId) -> Result<bool, StoreError> {
        panic!("refusal must precede archive inspection")
    }

    fn read(
        &self,
        _id: ContentId,
        _range: Option<crucible_cas::content_store::ByteRange>,
    ) -> Result<crucible_cas::content_store::BlobHandle, StoreError> {
        panic!("refusal must precede archive inspection")
    }

    fn put_if_absent(
        &self,
        _id: ContentId,
        _source: &crucible_cas::content_store::BlobHandle,
    ) -> Result<crucible_cas::content_store::PutReceipt, StoreError> {
        panic!("metadata-only inventory writes no objects")
    }
}

struct RepeatedArchiveFence<'a> {
    original: Box<dyn RefInventoryFence + 'a>,
    calls: usize,
}

impl RefInventoryFence for RepeatedArchiveFence<'_> {
    fn visit_refs(
        &mut self,
        visitor: &mut dyn FnMut(
            crucible_cas::content_store::RefInventoryRecord,
        ) -> Result<(), StoreError>,
    ) -> Result<RefInventorySummary, StoreError> {
        self.original.visit_refs(&mut |record| {
            for _ in 0..2 {
                self.calls += 1;
                assert!(visitor(record.clone()).is_err());
            }
            Err(StoreError::InvalidComposition {
                reason: "later inventory producer failure",
            })
        })
    }
}

#[test]
fn hostile_archive_visitor_preserves_first_admission_and_never_inspects() {
    use crucible_cas::content_store::{
        MemoryRefBackend, MutableRefBackend, RefName, RefStoreAdmin,
    };

    let original = Original::new();
    // This finite incoming model purpose precedes its controls and one ref.
    // The production claim remains the archive Vec body, not fixture bootstrap.
    let _fixture_credit = original
        .resources()
        .reserve_resources(0, 16 * 1024)
        .expect("finite incoming ref fixture purpose");
    let marks = Arc::new(ArchiveMarks {
        resources: original.resources(),
    });
    let refs = Arc::new(MemoryRefBackend::new());
    let name = RefName::new("archives/repeated").expect("archive ref name");
    refs.compare_exchange(&name, None, archive_id().content_id())
        .expect("one actual ref");
    let repository = CampaignRepository::new(
        marks.clone(),
        refs.clone(),
        crucible_campaign::CampaignRamAdmission::Unavailable,
    );
    let mut fence = RepeatedArchiveFence {
        original: refs
            .acquire_ref_inventory_fence()
            .expect("actual ref inventory"),
        calls: 0,
    };
    let mut boundary_calls = 0;
    let mut boundary = || {
        boundary_calls += 1;
        Ok(())
    };
    let operation =
        super::super::CampaignGcOperationContext::new(marks, &original.budget, &mut boundary)
            .expect("same original operation");
    let paid = retained_original_bytes(&original);
    let _occupied = original
        .bank
        .reserve_resources(0, 0, CAPACITY - paid - 1)
        .expect("same bank refuses first archive body");
    let mut roots = RootAccumulator::new(&original.budget);
    let mut exact = None;

    let Err(CampaignGcRootInventoryError::Admission(StoreError::DecodeAdmission {
        source,
        custody,
    })) = inventory_authoritative_refs(&repository, &mut fence, &mut exact, &mut roots, &operation)
    else {
        panic!("first actual archive admission must win");
    };
    assert!(custody.is_some());
    let first = original
        .budget
        .failure()
        .expect("original report")
        .expect("sticky actual cause");
    assert!(std::ptr::eq(
        std::error::Error::source(&first).expect("saved source"),
        std::error::Error::source(&source).expect("returned source")
    ));
    assert_eq!(fence.calls, 2);
    assert!(roots.unique.is_empty());
    drop(roots);
    drop(operation);
    assert_eq!(boundary_calls, 2);
}
