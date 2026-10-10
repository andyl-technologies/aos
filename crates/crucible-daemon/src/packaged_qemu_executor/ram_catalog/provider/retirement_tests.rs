//! Exercises actual cache closure with SQLite's intrinsic facade loan.
//!
//! The finite component authority models admission and closed-namespace custody;
//! it does not authenticate a kernel project quota or qualify native paging.

use super::*;
use crucible_cas::owned_decode::{DecodeBudget, ResourceLoan};
use std::sync::Barrier;

const RESIDENT_BYTES: u64 = 8 * 1024 * 1024;

struct ComponentQuota {
    allocator: HostServiceAllocator,
    closed: Arc<AtomicBool>,
    supervisor: HostOperationSupervisor,
}

struct ComponentCredit {
    _lease: HostServiceLease,
    _closed: Arc<AtomicBool>,
}

impl StorePhysicalQuotaGuard for ComponentQuota {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        self.verify()?;
        Ok(RESIDENT_BYTES)
    }

    fn verify(&self) -> Result<(), StoreError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(StoreError::Unauthorized);
        }
        self.allocator
            .verify_live()
            .map_err(|_| StoreError::Quota)?;
        self.supervisor
            .begin(HostOperationClass::Writeback)
            .map_err(sqlite_supervision_error)?
            .complete()
            .map(|_| ())
            .map_err(sqlite_supervision_error)
    }

    fn reserve_resources(&self, descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.verify()?;
        let bytes = bytes
            .checked_add(ResourceLoan::allocation_bytes::<ComponentCredit>())
            .and_then(|bytes| bytes.checked_add(HostServiceLease::metadata_bytes()))
            .ok_or(StoreError::Quota)?;
        let lease = self
            .allocator
            .reserve_resources(0, descriptors, bytes)
            .map_err(|_| StoreError::Quota)?;
        self.verify()?;
        Ok(ResourceLoan::new(ComponentCredit {
            _lease: lease,
            _closed: self.closed.clone(),
        }))
    }
}

struct ComponentSupervisor(HostServiceAllocator);
struct ComponentOperation;

impl SqliteCatalogSupervisor for ComponentSupervisor {
    fn reserve_resident_bytes(&self, bytes: u64) -> Result<ResourceLoan, StoreError> {
        let bytes = bytes
            .checked_add(ResourceLoan::allocation_bytes::<HostServiceLease>())
            .and_then(|bytes| bytes.checked_add(HostServiceLease::metadata_bytes()))
            .ok_or(StoreError::Quota)?;
        self.0
            .reserve_resources(0, 0, bytes)
            .map(ResourceLoan::new)
            .map_err(|_| StoreError::Quota)
    }

    fn begin(
        &self,
        _: SqliteCatalogOperationKind,
    ) -> Result<Box<dyn SqliteCatalogOperation>, StoreError> {
        Ok(Box::new(ComponentOperation))
    }
}

impl SqliteCatalogOperation for ComponentOperation {
    fn check(&self) -> Result<(), StoreError> {
        Ok(())
    }

    fn complete(self: Box<Self>) -> Result<(), StoreError> {
        Ok(())
    }
}

struct Fixture {
    cache: CatalogCache,
    directory: PathBuf,
    allocator: HostServiceAllocator,
    quota: Weak<dyn StorePhysicalQuotaGuard>,
    supervisor: HostOperationSupervisor,
    _root: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let heap = crucible_cas::content_store::fixture_sqlite_heap()
        .expect("authored SQLite fixture process");
    fixture_with_heap(64 * 1024 * 1024, &heap)
}

fn fixture_with_heap(
    sqlite_heap_bytes: u64,
    heap: &crucible_cas::content_store::SqliteProcessHeap,
) -> Fixture {
    let root = tempfile::tempdir().expect("component catalog directory");
    let directory = root.path().to_path_buf();
    let allocator = HostServiceAllocator::new(1, 16, RESIDENT_BYTES)
        .expect("finite independent component admission");
    let supervisor = HostOperationSupervisor::new(
        crucible_linux_resource::host_supervision::HostOperationBudgets::default(),
        Some(std::time::Duration::from_secs(120)),
    )
    .expect("finite original namespace supervision");
    let closed = Arc::new(AtomicBool::new(false));
    let quota: Arc<dyn StorePhysicalQuotaGuard> = Arc::new(ComponentQuota {
        allocator: allocator.clone(),
        closed: closed.clone(),
        supervisor: supervisor.clone(),
    });
    let retained_quota = Arc::downgrade(&quota);
    let original = DecodeBudget::for_store(quota.clone()).expect("original account before effects");
    let backend = SqliteBlobBackend::open_with_physical_quota(
        "retirement-component",
        &directory,
        quota.clone(),
        sqlite_heap_bytes,
        Arc::new(ComponentSupervisor(allocator.clone())),
        heap,
    )
    .expect("real SQLite facade and intrinsic resource loan");
    let fence = File::create(directory.join("retention.lock")).expect("component retained fence");
    let storage = ProductionRamCatalogStorage {
        backend,
        quota,
        retention_fence: Arc::new(fence),
        original,
    };
    Fixture {
        cache: CatalogCache {
            entries: Box::new([Some((
                directory.clone(),
                CatalogEntry::Open { storage, closed },
            ))]),
        },
        directory,
        allocator,
        quota: retained_quota,
        supervisor,
        _root: root,
    }
}

#[test]
fn actual_sqlite_intrinsic_loan_closes_before_final_namespace_proof() {
    let mut fixture = fixture();
    let storage = fixture
        .cache
        .close_for_retirement(&fixture.directory)
        .expect("unique original owner retires")
        .expect("cached catalog");

    assert!(storage.backend.is_none(), "the actual facade has closed");
    assert!(matches!(
        storage.quota.verify(),
        Err(StoreError::Unauthorized)
    ));
    drop(storage);
    assert!(fixture.quota.upgrade().is_none());
    assert!(
        fixture
            .allocator
            .reserve_resources(0, 0, RESIDENT_BYTES)
            .is_ok()
    );
}

#[test]
fn child_reader_custody_refuses_closure_until_the_final_reader_drops() {
    let mut fixture = fixture();
    let Some(CatalogEntry::Open { storage, .. }) = fixture.cache.get(&fixture.directory) else {
        panic!("actual cached open catalog");
    };
    let child = storage
        .original
        .child()
        .expect("same original operation account");
    let reader = child
        .reserve_scratch_bytes(128)
        .expect("retained reader custody");

    assert!(matches!(
        fixture.cache.close_for_retirement(&fixture.directory),
        Err(StoreError::Quota)
    ));
    assert!(matches!(
        fixture.cache.cached_open(&fixture.directory),
        Err(StoreError::Unauthorized)
    ));
    let Some(CatalogEntry::Open { storage, .. }) = fixture.cache.get(&fixture.directory) else {
        panic!("saved parent retained until its children close");
    };
    assert!(
        storage.original.child().is_err(),
        "closure grants no renewed allowance"
    );

    drop(child);
    assert!(matches!(
        fixture.cache.close_for_retirement(&fixture.directory),
        Err(StoreError::Quota)
    ));
    drop(reader);
    let storage = fixture
        .cache
        .close_for_retirement(&fixture.directory)
        .expect("retry after final reader")
        .expect("same catalog");
    drop(storage);
    assert!(
        fixture
            .allocator
            .reserve_resources(0, 0, RESIDENT_BYTES)
            .is_ok()
    );
}

#[test]
fn raw_resource_loan_keeps_closed_catalog_custody_after_backend_close() {
    let mut fixture = fixture();
    let loan = fixture
        .quota
        .upgrade()
        .expect("same original quota")
        .reserve_resources(0, 256)
        .expect("external resource loan");

    assert!(matches!(
        fixture.cache.close_for_retirement(&fixture.directory),
        Err(StoreError::Quota)
    ));
    assert!(
        matches!(fixture.cache.get(&fixture.directory), Some(CatalogEntry::Closed { storage, .. }) if storage.backend.is_none())
    );
    assert!(matches!(
        fixture.cache.cached_open(&fixture.directory),
        Err(StoreError::Unauthorized)
    ));
    assert!(
        fixture
            .allocator
            .reserve_resources(0, 0, RESIDENT_BYTES)
            .is_err()
    );

    drop(loan);
    let storage = fixture
        .cache
        .close_for_retirement(&fixture.directory)
        .expect("retry preserves the already closed backend")
        .expect("same catalog endpoints");
    drop(storage);
    assert!(fixture.quota.upgrade().is_none());
    assert!(
        fixture
            .allocator
            .reserve_resources(0, 0, RESIDENT_BYTES)
            .is_ok()
    );
}

#[test]
fn cached_open_cannot_reopen_admission_after_concurrent_closure() {
    let fixture = fixture();
    let cache = Arc::new(Mutex::new(fixture.cache));
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let reader_cache = cache.clone();
    let directory = fixture.directory.clone();
    let reader_entered = entered.clone();
    let reader_release = release.clone();
    let reader = std::thread::spawn(move || {
        let storage = reader_cache
            .lock()
            .expect("actual cache mutex")
            .cached_open(&directory)
            .expect("open before closure")
            .expect("same catalog");
        reader_entered.wait();
        reader_release.wait();
        drop(storage);
    });
    entered.wait();
    {
        let mut cache = cache.lock().expect("actual closure mutex");
        assert!(matches!(
            cache.close_for_retirement(&fixture.directory),
            Err(StoreError::Quota)
        ));
        assert!(matches!(
            cache.cached_open(&fixture.directory),
            Err(StoreError::Unauthorized)
        ));
    }
    release.wait();
    reader.join().expect("reader releases all original aliases");
    let storage = cache
        .lock()
        .expect("same retry mutex")
        .close_for_retirement(&fixture.directory)
        .expect("retry after concurrent reader")
        .expect("cached endpoints");
    drop(storage);
    assert!(
        fixture
            .allocator
            .reserve_resources(0, 0, RESIDENT_BYTES)
            .is_ok()
    );
}

struct ComponentRoot(crucible_cas::content_store::ContentId);
struct ComponentRetention;

impl crucible_cas::ram::RamRootLease for ComponentRoot {
    fn root(&self) -> crucible_cas::content_store::ContentId {
        self.0
    }
}

impl crucible_cas::ram::RamRetention for ComponentRetention {
    fn retain_object(
        &self,
        _: crucible_cas::content_store::ContentId,
    ) -> Result<(), crucible_cas::ram::RamStoreError> {
        Ok(())
    }

    fn retain_root(
        &self,
        root: crucible_cas::content_store::ContentId,
    ) -> Result<Arc<dyn crucible_cas::ram::RamRootLease>, crucible_cas::ram::RamStoreError> {
        // This component claim is incoming fixture ownership, not native GC authority.
        Ok(Arc::new(ComponentRoot(root)))
    }
}

fn available_resident_bytes(allocator: &HostServiceAllocator) -> u64 {
    let mut low = 0;
    let mut high = RESIDENT_BYTES;
    while low < high {
        let middle = low + (high - low).div_ceil(2);
        match allocator.reserve_resources(0, 0, middle) {
            Ok(probe) => {
                drop(probe);
                low = middle;
            }
            Err(_) => high = middle - 1,
        }
    }
    low
}

#[test]
fn actual_lazy_source_keeps_each_page_account_independent_and_response_owned() {
    use crucible_cas::ram::{RamStore, RamStoreLimits};
    use crucible_linux_resource::host_supervision::HostOperationBudgets;
    use crucible_qemu::ram_source::{QemuRamBacking, QemuRamReadBoundaryError};
    use crucible_ram::{Limits, RegionClass, RegionDescriptor, Scope, Topology};

    // The fixed 512 KiB process purpose is incompatible with the ordinary 8 MiB
    // fixture scope. Preserve this exact child process and its original cap.
    const ISOLATED: &str = "CRUCIBLE_NAMESPACE_SOURCE_ISOLATED";
    if std::env::var_os(ISOLATED).is_none() {
        let status = std::process::Command::new(
            std::env::current_exe().expect("actual unit-test executable"),
        )
        .args([
            "--exact",
            "packaged_qemu_executor::ram_catalog::provider::retirement_tests::actual_lazy_source_keeps_each_page_account_independent_and_response_owned",
            "--nocapture",
        ])
        .env(ISOLATED, "1")
        .status()
        .expect("isolated actual source/read profile");
        assert!(status.success(), "actual source/read child test failed");
        return;
    }

    let heap = crucible_cas::content_store::isolated_small_fixture_sqlite_heap()
        .expect("authored isolated 512 KiB SQLite process");
    let mut fixture = fixture_with_heap(512 * 1024, &heap);
    let storage = fixture
        .cache
        .cached_open(&fixture.directory)
        .expect("original cached storage")
        .expect("same catalog");
    let account = storage.original.child().expect("capture operation account");
    let store = RamStore::new(
        storage.backend.clone(),
        crucible_cas::content_store::DurabilityRequirement::new(1, false)
            .expect("one local receipt"),
        RamStoreLimits::default(),
    )
    .expect("actual quota-bound RAM store");
    let topology = Topology::new(
        vec![
            RegionDescriptor::new("machine.ram", RegionClass::MutableMain, 4096)
                .expect("one logical page"),
        ],
        Limits::default(),
    )
    .expect("bounded topology");
    let root = store
        .capture(
            topology,
            Scope::Exact,
            &mut |_, _, output| {
                output.fill(7);
                Ok(())
            },
            &ComponentRetention,
            &account,
            &mut || Ok(()),
        )
        .expect("actual persisted page");
    let response_store = store.clone();
    let response_root = root.clone();
    let response_original = storage.original.clone();
    let source = crucible_api::ProductionPagedRamSource::new(
        crucible::NodeId {
            name: "component".to_owned(),
        },
        store,
        root,
        storage.original.clone(),
        &mut || Ok(()),
    )
    .expect("actual source retains original parent");
    drop(account);
    drop(storage);

    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(std::time::Duration::from_secs(120)),
    )
    .expect("finite component supervision");
    supervisor
        .begin(HostOperationClass::Preparation)
        .expect("completed setup scope")
        .complete()
        .expect("source does not capture this expired setup scope");
    let available = available_resident_bytes(&fixture.allocator);
    for _ in 0..64 {
        let operation = supervisor
            .begin(HostOperationClass::PageIn)
            .expect("new actual PageIn scope");
        source
            .with_page_response(
                "machine.ram",
                0,
                &mut || {
                    operation
                        .wait_slice()
                        .map(|_| ())
                        .map_err(QemuRamReadBoundaryError::from)
                },
                &mut |read, _| {
                    assert_eq!(read.bytes(), &[7; 4096]);
                    assert!(
                        available_resident_bytes(&fixture.allocator) < available,
                        "the consumer retains actual original page/proof allocations"
                    );
                    operation.complete().expect("same PageIn completes");
                    assert!(
                        available_resident_bytes(&fixture.allocator) < available,
                        "operation completion does not refund the live response"
                    );
                },
            )
            .expect("page uses the saved original namespace");
    }
    assert_eq!(
        available_resident_bytes(&fixture.allocator),
        available,
        "completed page operations leave no cumulative parent ledger"
    );

    // The host interface consumes within a scope. The still-active direct CAS
    // API independently proves a retained response can outlive its source.
    let response_account = response_original.child().expect("same original child");
    let read = response_store
        .read_page_with_proof(
            &response_root,
            "machine.ram",
            0,
            &response_account,
            &mut || Ok(()),
        )
        .expect("retained page response");
    drop(response_account);
    drop(response_original);
    drop(response_root);
    drop(response_store);
    fixture
        .supervisor
        .cancel()
        .expect("cancel the original namespace owner");
    let unrelated = supervisor
        .begin(HostOperationClass::PageIn)
        .expect("unrelated caller remains live");
    let error = source
        .with_page_response(
            "machine.ram",
            0,
            &mut || {
                unrelated
                    .wait_slice()
                    .map(|_| ())
                    .map_err(QemuRamReadBoundaryError::from)
            },
            &mut |_, _| panic!("canceled namespace cannot produce a page"),
        )
        .expect_err("a fresh unrelated PageIn cannot renew original cancellation");
    assert!(matches!(
        error,
        crucible_qemu::ram_source::QemuRamSourceError::RamBackingFailure {
            kind: crucible::BackendOperationalFailureKind::Canceled,
            ..
        }
    ));
    drop(error);
    unrelated
        .complete()
        .expect("unrelated caller still completes");
    let mut first_polls = 0;
    let error = source
        .with_page_response(
            "machine.ram",
            0,
            &mut || {
                first_polls += 1;
                unrelated
                    .wait_slice()
                    .map(|_| ())
                    .map_err(QemuRamReadBoundaryError::from)
            },
            &mut |_, _| panic!("completed caller cannot produce a page"),
        )
        .expect_err("completed caller refusal precedes canceled namespace admission");
    assert_eq!(first_polls, 1);
    assert!(matches!(
        error,
        crucible_qemu::ram_source::QemuRamSourceError::Supervision(
            crucible_linux_resource::host_supervision::HostSupervisionError::Terminal {
                state: crucible_linux_resource::host_supervision::HostOperationState::Completed,
            }
        )
    ));
    drop(error);
    drop(source);
    assert!(
        matches!(
            fixture.cache.close_for_retirement(&fixture.directory),
            Err(StoreError::Quota)
        ),
        "returned page and proof custody outlive the source"
    );
    assert_eq!(read.bytes(), &[7; 4096]);
    drop(read);
    let storage = fixture
        .cache
        .close_for_retirement(&fixture.directory)
        .expect("retry after response consumer closes")
        .expect("same namespace");
    drop(storage);
    assert!(
        fixture
            .allocator
            .reserve_resources(0, 0, RESIDENT_BYTES)
            .is_ok()
    );
}
