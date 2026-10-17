//! Exercises real paused SQLite comparisons and generic physical continuations.
//!
//! The finite portable fixture retains the original 256 MiB namespace policy.
//! Its counters do not qualify production process bootstrap or native timing.

use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crucible_cas::content_store::{
    ContentId, DirectoryBlobBackend, DurabilityRequirement, ImmutableBlobBackend,
    SqliteBlobBackend, SqliteCatalogOperation, SqliteCatalogOperationKind, SqliteCatalogSupervisor,
    SqliteCommitOutcome, SqliteScopeError, StoreError, StorePhysicalQuotaGuard,
    fixture_sqlite_heap,
};
use crucible_cas::owned_decode::{DecodeBudget, ResourceLoan};
use crucible_cas::ram::{
    LeasedRamRoot, RamPageChange, RamRetention, RamRootLease, RamStore, RamStoreError,
    RamStoreLimits,
};
use crucible_ram::{Limits, RegionClass, RegionDescriptor, Scope, Topology};

const CAPACITY: u64 = 256 << 20;

struct Quota {
    live: AtomicBool,
    used: Arc<AtomicU64>,
}

struct Loan {
    used: Arc<AtomicU64>,
    bytes: u64,
}

impl Drop for Loan {
    fn drop(&mut self) {
        self.used.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

impl Quota {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            live: AtomicBool::new(true),
            used: Arc::new(AtomicU64::new(0)),
        })
    }
}

impl StorePhysicalQuotaGuard for Quota {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(CAPACITY)
    }

    fn verify(&self) -> Result<(), StoreError> {
        if self.live.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(StoreError::Unauthorized)
        }
    }

    fn reserve_resources(&self, _: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.verify()?;
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes).filter(|next| *next <= CAPACITY)
            })
            .map_err(|_| StoreError::Quota)?;
        Ok(ResourceLoan::new(Loan {
            used: self.used.clone(),
            bytes,
        }))
    }
}

struct Supervisor(Arc<Quota>);
struct Operation;

impl SqliteCatalogOperation for Operation {
    fn check(&self) -> Result<(), StoreError> {
        Ok(())
    }

    fn complete(self: Box<Self>) -> Result<(), StoreError> {
        Ok(())
    }
}

impl SqliteCatalogSupervisor for Supervisor {
    fn reserve_resident_bytes(&self, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.0.reserve_resources(0, bytes)
    }

    fn begin(
        &self,
        _: SqliteCatalogOperationKind,
    ) -> Result<Box<dyn SqliteCatalogOperation>, StoreError> {
        Ok(Box::new(Operation))
    }
}

struct Retention;
struct Lease(ContentId);

impl RamRootLease for Lease {
    fn root(&self) -> ContentId {
        self.0
    }
}

impl RamRetention for Retention {
    fn retain_object(&self, _: ContentId) -> Result<(), RamStoreError> {
        Ok(())
    }

    fn retain_root(&self, id: ContentId) -> Result<Arc<dyn RamRootLease>, RamStoreError> {
        Ok(Arc::new(Lease(id)))
    }
}

type TestResult<T> = Result<T, Box<dyn Error>>;

fn fixture(sqlite: bool) -> TestResult<(tempfile::TempDir, RamStore, Arc<Quota>, DecodeBudget)> {
    let root = tempfile::tempdir()?;
    let physical = Quota::new();
    let original = DecodeBudget::for_store(Quota::new())?;
    let backend: Arc<dyn ImmutableBlobBackend> = if sqlite {
        SqliteBlobBackend::open_with_physical_quota(
            "paused-comparison",
            root.path(),
            physical.clone(),
            8 << 20,
            Arc::new(Supervisor(physical.clone())),
            &fixture_sqlite_heap()?,
        )?
    } else {
        DirectoryBlobBackend::new_with_physical_quota(
            "generic-comparison",
            root.path(),
            physical.clone(),
        )?
    };
    let store = RamStore::new(
        backend,
        DurabilityRequirement::new(1, false)?,
        RamStoreLimits::default(),
    )?;
    Ok((root, store, physical, original))
}

fn roots(store: &RamStore, original: &DecodeBudget) -> TestResult<(LeasedRamRoot, LeasedRamRoot)> {
    let topology = Topology::new(
        vec![RegionDescriptor::new(
            "main",
            RegionClass::MutableMain,
            4096 * 256,
        )?],
        Limits::default(),
    )?;
    let before = store.capture(
        topology,
        Scope::Exact,
        &mut |_, index, bytes| {
            bytes.fill((index % 251) as u8);
            Ok(())
        },
        &Retention,
        &original.child()?,
        &mut || Ok(()),
    )?;
    let after = store.update(
        &before,
        [RamPageChange {
            region_id: "main".into(),
            page_index: 129,
            bytes: vec![255; 4096],
        }],
        &Retention,
        &original.child()?,
        &mut || Ok(()),
    )?;
    Ok((before, after))
}

#[test]
fn real_sqlite_comparison_preserves_eighty_poll_bound_and_reentrant_visitor() {
    let (_directory, store, _physical, original) = fixture(true).unwrap();
    let (before, after) = roots(&store, &original).unwrap();
    let operation = original.child().unwrap();
    let mut boundaries = 0;
    let mut pages = Vec::new();

    let changed = store
        .visit_differing_pages(
            &before,
            &after,
            &mut |region, page| {
                let response = store.read_page_with_proof(
                    &after,
                    region,
                    page,
                    &original.child().unwrap(),
                    &mut || Ok(()),
                )?;
                assert_eq!(response.bytes(), &[255; 4096]);
                pages.push(page);
                Ok(())
            },
            &operation,
            &mut || {
                boundaries += 1;
                Ok(())
            },
        )
        .unwrap();

    assert_eq!(changed, 1);
    assert_eq!(pages, [129]);
    assert!(boundaries <= 80, "boundaries={boundaries}");
    eprintln!("real_sqlite_comparison_boundaries={boundaries}");
}

#[test]
fn same_original_refuses_resume_after_callback_poison_and_preserves_first_error() {
    let (_directory, store, _physical, original) = fixture(true).unwrap();
    let (before, after) = roots(&store, &original).unwrap();
    let operation = original.child().unwrap();
    let mut visitors = 0;
    let mut first = None;

    let error = store
        .visit_differing_pages(
            &before,
            &after,
            &mut |_, _| {
                visitors += 1;
                first = Some(operation.charge_bytes(u64::MAX).unwrap_err());
                Ok(())
            },
            &operation,
            &mut || Ok(()),
        )
        .unwrap_err();

    let RamStoreError::Store(error) = &error else {
        panic!("lost owning failure: {error:?}")
    };
    let StoreError::DecodeAdmission { source, .. } = error.original_failure() else {
        panic!("lost original admission: {error:?}");
    };
    assert_eq!(Some(source), first.as_ref());
    assert_eq!(visitors, 1);
    original.verify_live().unwrap();
}

#[test]
fn generic_and_sqlite_defaults_retain_actual_physical_refusal_under_live_original() {
    for sqlite in [false, true] {
        let (_directory, store, physical, original) = fixture(sqlite).unwrap();
        let (before, after) = roots(&store, &original).unwrap();
        physical.live.store(false, Ordering::SeqCst);

        let error = store
            .visit_differing_pages(
                &before,
                &after,
                &mut |_, _| panic!("a refused physical owner cannot visit"),
                &original.child().unwrap(),
                &mut || Ok(()),
            )
            .unwrap_err();

        let RamStoreError::Store(error) = error else {
            panic!("lost storage failure")
        };
        assert!(matches!(error.original_failure(), StoreError::Unauthorized));
        original.verify_live().unwrap();
    }
}

fn scope(error: &StoreError) -> Option<&SqliteScopeError> {
    let mut current: &(dyn Error + 'static) = error;
    loop {
        if let Some(scope) = current.downcast_ref::<SqliteScopeError>() {
            return Some(scope);
        }
        current = current.source()?;
    }
}

#[test]
fn corrupt_pending_record_retains_scope_and_actual_eof_refusal_dominates() {
    let (directory, store, _physical, original) = fixture(true).unwrap();
    let (before, _after) = roots(&store, &original).unwrap();
    let mut complete_polls = 0;
    store
        .visit_differing_pages(
            &before,
            &before,
            &mut |_, _| panic!("equal references cannot visit"),
            &original.child().unwrap(),
            &mut || {
                complete_polls += 1;
                Ok(())
            },
        )
        .unwrap();
    assert!(complete_polls >= 2);
    let foreign = fixture_sqlite_heap()
        .unwrap()
        .open_connection(
            directory.path().join("objects.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
        )
        .unwrap();
    foreign
        .execute("UPDATE objects SET body = zeroblob(length(body))", [])
        .unwrap();

    for refuse_eof in [false, true] {
        let operation = original.child().unwrap();
        let mut first = None;
        let mut calls = 0;
        let error = store
            .visit_differing_pages(
                &before,
                &before,
                &mut |_, _| panic!("corrupt records cannot visit"),
                &operation,
                &mut || {
                    calls += 1;
                    if refuse_eof && calls == complete_polls - 1 {
                        first = Some(operation.charge_bytes(u64::MAX).unwrap_err());
                    }
                    Ok(())
                },
            )
            .unwrap_err();
        let RamStoreError::Store(error) = error else {
            panic!("lost owning SQL cause")
        };
        if refuse_eof {
            let StoreError::DecodeAdmission { source, .. } = error.original_failure() else {
                panic!("actual EOF refusal lost to pending corruption: {error:?}");
            };
            assert_eq!(Some(source), first.as_ref());
        } else {
            let StoreError::RamReadValidation { source } = &error else {
                panic!("lost pending validation/provider distinction: {error:?}");
            };
            let RamStoreError::Store(first) = source.first_validation() else {
                panic!("lost actual hash mismatch");
            };
            assert!(matches!(
                first.original_failure(),
                StoreError::Corrupt { .. }
            ));
            let RamStoreError::Store(provider) = source.storage_failure() else {
                panic!("lost complete provider scope");
            };
            let retained = scope(provider).expect("the actual SQL scope remains retained");
            assert_eq!(retained.outcome(), SqliteCommitOutcome::NotCommitted);
            assert!(retained.rollback_failure().is_none());
            assert!(retained.restoration_failure().is_none());
        }
        original.verify_live().unwrap();
    }
}
