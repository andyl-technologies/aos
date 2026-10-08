//! Concrete composite receipt outcomes, refusal ordering and metadata geometry.

use super::*;
use crate::content_store::composition::{TieredStore, TieredStoreChild, WriteThroughStore};
use crate::content_store::test_resources::FixtureResourceBudget;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct Quota {
    resources: FixtureResourceBudget,
    live: AtomicBool,
    reservations: AtomicUsize,
}

impl StorePhysicalQuotaGuard for Quota {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(128 * 1024 * 1024)
    }

    fn reserve_resources(
        &self,
        descriptors: u64,
        bytes: u64,
    ) -> Result<crate::owned_decode::ResourceLoan, StoreError> {
        self.verify()?;
        self.reservations.fetch_add(1, Ordering::SeqCst);
        self.resources.reserve(descriptors, bytes)
    }

    fn verify(&self) -> Result<(), StoreError> {
        if self.live.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(StoreError::Unauthorized)
        }
    }
}

fn account() -> (Arc<Quota>, DecodeBudget) {
    let quota = Arc::new(Quota {
        resources: FixtureResourceBudget::new(512, 128 * 1024 * 1024),
        live: AtomicBool::new(true),
        reservations: AtomicUsize::new(0),
    });
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    (quota, original)
}

// All leaves in one fixture retain the same originally prepaid binder control.
struct FixtureMemoryBinder {
    quota: Arc<Quota>,
    _control_credit: crate::owned_decode::ResourceLoan,
}

impl StorePhysicalQuotaBinder for FixtureMemoryBinder {
    fn reserve_memory_namespace(
        &self,
        bytes: u64,
    ) -> Result<crate::owned_decode::ResourceLoan, StoreError> {
        self.quota.reserve_resources(0, bytes)
    }

    fn verify_memory_namespace(&self) -> Result<(), StoreError> {
        self.quota.verify()
    }

    fn bind(
        &self,
        _root: &std::path::Path,
        _project_id: u32,
        _maximum_physical_bytes: u64,
        _maximum_inodes: u64,
    ) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        Err(StoreError::Unsupported {
            capability: "composite-memory-fixture-disk-binding",
        })
    }
}

fn memory_namespace(quota: &Arc<Quota>) -> Result<StorePhysicalQuotaBinderHandle, StoreError> {
    let bytes = StorePhysicalQuotaBinderHandle::allocation_bytes::<FixtureMemoryBinder>()?;
    let credit =
        quota.reserve_resources(0, u64::try_from(bytes).map_err(|_| StoreError::Quota)?)?;
    Ok(StorePhysicalQuotaBinderHandle::new(FixtureMemoryBinder {
        quota: quota.clone(),
        _control_credit: credit,
    }))
}

fn memory_leaf(name: &str, original: StorePhysicalQuotaBinderHandle) -> Arc<MemoryBlobBackend> {
    // Each leaf lifetime publishes at most the fixture's one singleton object.
    Arc::new(MemoryBlobBackend::new_admitted(name, 1024 * 1024, 1, original).unwrap())
}

fn object(byte: u8) -> (ContentId, BlobHandle) {
    let body = vec![byte; 1024];
    (
        ContentId::for_bytes(ObjectKind::RamExtent, 1, &body),
        BlobHandle::from_bytes(body),
    )
}

fn tiered(children: Vec<Arc<dyn ImmutableBlobBackend>>) -> TieredStore {
    TieredStore::new(
        "tiered",
        children
            .into_iter()
            .map(|backend| TieredStoreChild {
                backend,
                readable: true,
                writable: true,
                promote_reads: false,
            })
            .collect(),
    )
    .unwrap()
}

#[test]
fn nested_writers_preserve_all_placements_until_outer_acceptance() {
    let (quota, original) = account();
    let namespace = memory_namespace(&quota).unwrap();
    let first = memory_leaf("first", namespace.clone());
    let second = memory_leaf("second", namespace.clone());
    let third = memory_leaf("third", namespace);
    let inner =
        Arc::new(WriteThroughStore::new("inner", vec![first.clone(), second.clone()]).unwrap());
    let store = tiered(vec![inner, third.clone()]);
    let bound = store
        .checked_publication_metadata(ObjectKind::RamExtent)
        .unwrap();
    assert_eq!(bound.maximum_placements, 3);
    assert_eq!(bound.maximum_backend_name_bytes, "firstsecondthird".len());
    let input = object(13);
    let receipt = store
        .put_many_if_absent_with_boundary(&original, std::slice::from_ref(&input), &mut || Ok(()))
        .unwrap();
    assert_eq!(receipt[0].placements.len(), 3);
    assert_eq!(
        receipt[0]
            .placements
            .iter()
            .map(|p| p.backend.as_str())
            .collect::<Vec<_>>(),
        ["first", "second", "third"]
    );
    assert!(first.contains(input.0).unwrap());
    assert!(second.contains(input.0).unwrap());
    assert!(third.contains(input.0).unwrap());
    let error = receipt
        .accept_with_boundary(&mut || Err(StoreError::Unavailable))
        .unwrap_err();
    let StoreError::CompositeScope { source } = &error else {
        panic!("full aggregate owner: {error:?}");
    };
    assert_eq!(source.prior_publications().len(), 2);
    assert!(matches!(
        source.work_failure(),
        Some(StoreError::Unavailable)
    ));
    let retained = source.work_failure().unwrap();
    let exposed = std::error::Error::source(source)
        .and_then(|cause| cause.downcast_ref::<StoreError>())
        .unwrap();
    assert!(std::ptr::eq(retained, exposed));
    assert!(quota.resources.usage().unwrap().1 > 1024);
    drop(error);
    drop(store);
    drop(first);
    drop(second);
    drop(third);
    drop(original);
    assert_eq!(quota.resources.usage().unwrap(), (0, 0));
}

struct AdversarialWriter {
    leaf: Arc<MemoryBlobBackend>,
    published: Arc<AtomicBool>,
    consume_and_succeed: bool,
}

impl ImmutableBlobBackend for AdversarialWriter {
    fn name(&self) -> &str {
        self.leaf.name()
    }
    fn capabilities(&self) -> BackendCapabilities {
        self.leaf.capabilities()
    }
    fn checked_publication_metadata(
        &self,
        kind: ObjectKind,
    ) -> Result<CheckedPublicationMetadata, StoreError> {
        self.leaf.checked_publication_metadata(kind)
    }
    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.leaf.contains(id)
    }
    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.leaf.read(id, range)
    }
    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.leaf.put_if_absent(id, source)
    }
    fn put_many_if_absent_with_boundary(
        &self,
        original: &DecodeBudget,
        objects: &[(ContentId, BlobHandle)],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<PutBatchReceipt, StoreError> {
        let receipt = self
            .leaf
            .put_many_if_absent_with_boundary(original, objects, boundary)?;
        self.published.store(true, Ordering::SeqCst);
        assert!(boundary().is_err());
        assert!(boundary().is_err());
        if self.consume_and_succeed {
            Ok(receipt)
        } else {
            receipt.check(|_| Err(StoreError::NotFound { id: objects[0].0 }))
        }
    }
}

#[test]
fn first_refusal_survives_overwrite_and_consumed_success_without_next_writer_effects() {
    for consume_and_succeed in [false, true] {
        let (quota, original) = account();
        let namespace = memory_namespace(&quota).unwrap();
        let first = memory_leaf("first", namespace.clone());
        let current = memory_leaf("current", namespace.clone());
        let last = memory_leaf("last", namespace);
        let published = Arc::new(AtomicBool::new(false));
        let adversarial = Arc::new(AdversarialWriter {
            leaf: current.clone(),
            published: published.clone(),
            consume_and_succeed,
        });
        let store = tiered(vec![first.clone(), adversarial, last.clone()]);
        let input = object(17);
        let mut refusals = 0;
        let error = store
            .put_many_if_absent_with_boundary(&original, std::slice::from_ref(&input), &mut || {
                if published.load(Ordering::SeqCst) {
                    refusals += 1;
                    Err(StoreError::Unavailable)
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert_eq!(refusals, 1);
        assert!(first.contains(input.0).unwrap());
        assert!(current.contains(input.0).unwrap());
        assert!(!last.contains(input.0).unwrap());
        assert!(!error.confirmed_absence(input.0));
        let StoreError::CompositeScope { source } = &error else {
            panic!("full composite cause: {error:?}");
        };
        assert!(matches!(
            source.first_boundary(),
            Some(StoreError::Unavailable)
        ));
        assert_eq!(source.prior_publications().len(), 1);
        let Some(StoreError::MemoryScope {
            source: current_outcome,
        }) = source.work_failure()
        else {
            panic!("actual current outcome retained");
        };
        assert_eq!(current_outcome.outcome().published_objects, 1);
        assert_eq!(current_outcome.outcome().accepted_objects, 1);
        drop(error);
        drop(store);
        drop(first);
        drop(current);
        drop(last);
        drop(original);
        assert_eq!(quota.resources.usage().unwrap(), (0, 0));
    }
}

#[test]
fn original_refusal_under_foreign_scope_precedes_all_writes_and_callbacks() {
    let (quota, original) = account();
    let (_other_quota, other) = account();
    let namespace = memory_namespace(&quota).unwrap();
    let first = memory_leaf("first", namespace.clone());
    let second = memory_leaf("second", namespace);
    let store = tiered(vec![first.clone(), second.clone()]);
    let input = object(23);
    let baseline = quota.resources.usage().unwrap();
    quota.live.store(false, Ordering::SeqCst);
    let _foreign_scope = other.enter();
    let mut callbacks = 0;
    let error = store
        .put_many_if_absent_with_boundary(&original, std::slice::from_ref(&input), &mut || {
            callbacks += 1;
            Ok(())
        })
        .unwrap_err();
    assert_eq!(callbacks, 0);
    assert!(matches!(error.original_failure(), StoreError::Unauthorized));
    assert!(!first.contains(input.0).unwrap());
    assert!(!second.contains(input.0).unwrap());
    assert_eq!(quota.resources.usage().unwrap(), baseline);
}

#[test]
fn single_writer_delegates_without_metadata_inventory_or_composite_loans() {
    let (direct_quota, direct_original) = account();
    let (tier_quota, tier_original) = account();
    let direct = memory_leaf("leaf", memory_namespace(&direct_quota).unwrap());
    let child = memory_leaf("leaf", memory_namespace(&tier_quota).unwrap());
    let store = tiered(vec![child]);
    let input = object(29);
    direct_quota.reservations.store(0, Ordering::SeqCst);
    let direct_receipt = direct
        .put_many_if_absent_with_boundary(
            &direct_original,
            std::slice::from_ref(&input),
            &mut || Ok(()),
        )
        .unwrap();
    tier_quota.reservations.store(0, Ordering::SeqCst);
    let tier_receipt = store
        .put_many_if_absent_with_boundary(&tier_original, std::slice::from_ref(&input), &mut || {
            Ok(())
        })
        .unwrap();
    assert_eq!(
        direct_quota.reservations.load(Ordering::SeqCst),
        tier_quota.reservations.load(Ordering::SeqCst)
    );
    assert_eq!(&*direct_receipt, &*tier_receipt);
}

#[test]
fn geometry_matches_actual_allocation_types() {
    println!(
        "composite geometry: metadata={} PutReceipt={} PlacementReceipt={} PutBatchReceipt={} AcceptedVec={} Failure={} alignFailure={} ScopeError={} DecodeScratch={} StoreError={}",
        std::mem::size_of::<CheckedPublicationMetadata>(),
        std::mem::size_of::<PutReceipt>(),
        std::mem::size_of::<PlacementReceipt>(),
        std::mem::size_of::<PutBatchReceipt>(),
        std::mem::size_of::<Accepted<Vec<PutReceipt>>>(),
        std::alloc::Layout::new::<CompositeFailure>().size(),
        std::alloc::Layout::new::<CompositeFailure>().align(),
        std::mem::size_of::<CompositeScopeError>(),
        std::mem::size_of::<DecodeScratch>(),
        std::mem::size_of::<StoreError>()
    );
    println!(
        "common results: BlobHandle={} OwnedBlobBytes={} CheckedReader={} PutBatchReceipt={}",
        std::mem::size_of::<Result<BlobHandle, StoreError>>(),
        std::mem::size_of::<Result<OwnedBlobBytes, StoreError>>(),
        std::mem::size_of::<Result<CheckedReader, StoreError>>(),
        std::mem::size_of::<Result<PutBatchReceipt, StoreError>>()
    );
}

struct DeclaredWriter {
    leaf: Arc<MemoryBlobBackend>,
    declared: Option<CheckedPublicationMetadata>,
    publications: AtomicUsize,
}

struct DeclaredComposite {
    child: Arc<dyn ImmutableBlobBackend>,
    metadata: CheckedPublicationMetadata,
}

impl ImmutableBlobBackend for DeclaredComposite {
    fn name(&self) -> &str {
        self.child.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.child.capabilities()
    }

    fn checked_publication_metadata(
        &self,
        _: ObjectKind,
    ) -> Result<CheckedPublicationMetadata, StoreError> {
        Ok(self.metadata)
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.child.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.child.read(id, range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.child.put_if_absent(id, source)
    }

    fn put_many_if_absent_with_boundary(
        &self,
        original: &DecodeBudget,
        objects: &[(ContentId, BlobHandle)],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<PutBatchReceipt, StoreError> {
        self.child
            .put_many_if_absent_with_boundary(original, objects, boundary)
    }
}

fn durability_bound_refusal(understate_count: bool) {
    let (quota, original) = account();
    let first_root = tempfile::tempdir().unwrap();
    let second_root = tempfile::tempdir().unwrap();
    let first =
        DirectoryBlobBackend::new_with_physical_quota("first", first_root.path(), quota.clone())
            .unwrap();
    let second =
        DirectoryBlobBackend::new_with_physical_quota("second", second_root.path(), quota.clone())
            .unwrap();
    let child =
        Arc::new(WriteThroughStore::new("writers", vec![first.clone(), second.clone()]).unwrap());
    let declaration = Arc::new(DeclaredComposite {
        child,
        metadata: CheckedPublicationMetadata {
            maximum_placements: if understate_count { 1 } else { 2 },
            maximum_backend_name_bytes: if understate_count {
                "firstsecond".len()
            } else {
                0
            },
        },
    });
    let policy = crate::content_store::composition::DurabilityPolicyStore::new(
        "policy",
        declaration,
        [(
            ObjectKind::RamExtent,
            DurabilityRequirement::new(1, false).unwrap(),
        )]
        .into_iter()
        .collect(),
    );
    let input = object(73);
    let error = policy
        .put_many_if_absent_with_boundary(&original, std::slice::from_ref(&input), &mut || Ok(()))
        .unwrap_err();

    assert!(first.contains(input.0).unwrap());
    assert!(second.contains(input.0).unwrap());
    let StoreError::CompositeScope { source } = &error else {
        panic!("the actual returned multiwriter owner survives: {error:?}");
    };
    assert_eq!(source.prior_publications().len(), 2);
    assert!(matches!(
        source.work_failure(),
        Some(StoreError::InvalidComposition {
            reason: "checked durability receipt exceeds declared metadata",
        })
    ));
    assert!(quota.resources.usage().unwrap().1 > 0);

    drop(error);
    drop(policy);
    drop(first);
    drop(second);
    drop(original);
    assert_eq!(quota.resources.usage().unwrap(), (0, 0));
}

#[test]
fn durability_refuses_actual_multiwriter_placements_above_declared_tree_bound() {
    durability_bound_refusal(true);
}

#[test]
fn durability_refuses_actual_multiwriter_labels_above_declared_byte_bound() {
    durability_bound_refusal(false);
}

impl ImmutableBlobBackend for DeclaredWriter {
    fn name(&self) -> &str {
        self.leaf.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.leaf.capabilities()
    }

    fn checked_publication_metadata(
        &self,
        _kind: ObjectKind,
    ) -> Result<CheckedPublicationMetadata, StoreError> {
        self.declared.ok_or(StoreError::Unsupported {
            capability: "test-undeclared-checked-publication",
        })
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.leaf.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.leaf.read(id, range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.leaf.put_if_absent(id, source)
    }

    fn put_many_if_absent_with_boundary(
        &self,
        original: &DecodeBudget,
        objects: &[(ContentId, BlobHandle)],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<PutBatchReceipt, StoreError> {
        self.publications.fetch_add(1, Ordering::SeqCst);
        self.leaf
            .put_many_if_absent_with_boundary(original, objects, boundary)
    }
}

#[test]
fn unknown_bounds_refuse_before_any_writer_and_dishonest_bounds_retain_actual_outcome() {
    for declared in [
        None,
        Some(CheckedPublicationMetadata {
            maximum_placements: 0,
            maximum_backend_name_bytes: 0,
        }),
        Some(CheckedPublicationMetadata {
            maximum_placements: 1,
            maximum_backend_name_bytes: 0,
        }),
    ] {
        let (quota, original) = account();
        let namespace = memory_namespace(&quota).unwrap();
        let first = memory_leaf("first", namespace.clone());
        let second = memory_leaf("second", namespace);
        let declared_writer = Arc::new(DeclaredWriter {
            leaf: second.clone(),
            declared,
            publications: AtomicUsize::new(0),
        });
        let store = tiered(vec![first.clone(), declared_writer.clone()]);
        let input = object(31);
        let mut callbacks = 0;
        let error = store
            .put_many_if_absent_with_boundary(&original, std::slice::from_ref(&input), &mut || {
                callbacks += 1;
                Ok(())
            })
            .unwrap_err();
        if declared.is_none() {
            assert_eq!(callbacks, 0);
            assert_eq!(declared_writer.publications.load(Ordering::SeqCst), 0);
            assert!(!first.contains(input.0).unwrap());
            assert!(!second.contains(input.0).unwrap());
        } else {
            assert_eq!(declared_writer.publications.load(Ordering::SeqCst), 1);
            assert!(first.contains(input.0).unwrap());
            assert!(second.contains(input.0).unwrap());
            let StoreError::CompositeScope { source } = &error else {
                panic!("retained prior publication");
            };
            assert_eq!(source.prior_publications().len(), 1);
            let Some(StoreError::MemoryScope { source: outcome }) = source.work_failure() else {
                panic!("actual dishonest leaf publication");
            };
            assert_eq!(outcome.outcome().published_objects, 1);
            assert!(matches!(
                outcome.work_failure(),
                StoreError::InvalidComposition { .. }
            ));
        }
        drop(error);
        drop(store);
        drop(declared_writer);
        drop(first);
        drop(second);
        drop(original);
        assert_eq!(quota.resources.usage().unwrap(), (0, 0));
    }
}

struct Supervisor(Arc<Quota>);

impl SqliteCatalogSupervisor for Supervisor {
    fn reserve_resident_bytes(
        &self,
        bytes: u64,
    ) -> Result<crate::owned_decode::ResourceLoan, StoreError> {
        self.0.reserve_resources(0, bytes)
    }

    fn begin(
        &self,
        _kind: SqliteCatalogOperationKind,
    ) -> Result<Box<dyn SqliteCatalogOperation>, StoreError> {
        self.0.verify()?;
        Ok(Box::new(Operation(self.0.clone())))
    }
}

struct Operation(Arc<Quota>);

impl SqliteCatalogOperation for Operation {
    fn check(&self) -> Result<(), StoreError> {
        self.0.verify()
    }

    fn complete(self: Box<Self>) -> Result<(), StoreError> {
        self.0.verify()
    }
}

#[test]
fn real_sql_commit_survives_directory_uncertainty_and_independent_cleanup_failure() {
    let name = "content_store::composite_publication::tests::real_sql_commit_survives_directory_uncertainty_and_independent_cleanup_failure";
    if std::env::var_os("CRUCIBLE_COMPOSITE_SQL_CHILD").is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("CRUCIBLE_COMPOSITE_SQL_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let (quota, original) = account();
    let sql_root = tempfile::tempdir().unwrap();
    let directory_root = tempfile::tempdir().unwrap();
    let sql = SqliteBlobBackend::open_with_physical_quota(
        "sql",
        sql_root.path(),
        quota.clone(),
        8 * 1024 * 1024,
        Arc::new(Supervisor(quota.clone())),
    )
    .unwrap();
    let directory = Arc::new(DirectoryBlobBackend::new(
        "directory",
        directory_root.path(),
    ));
    let store = tiered(vec![sql.clone(), directory.clone()]);
    let input = object(37);
    let text = input.0.encode();
    let digest = text.rsplit('.').next().unwrap();
    let path = directory_root
        .path()
        .join("objects")
        .join(&digest[..2])
        .join(text);
    let shard = path.parent().unwrap();
    let mut injected = false;
    let mut refusals = 0;
    let error = store
        .put_many_if_absent_with_boundary(&original, std::slice::from_ref(&input), &mut || {
            if injected {
                panic!("callback after first refusal");
            }
            if path.exists() {
                for entry in std::fs::read_dir(shard).unwrap() {
                    let entry = entry.unwrap();
                    if entry.file_name().to_string_lossy().starts_with(".staging-") {
                        std::fs::remove_file(entry.path()).unwrap();
                        std::fs::create_dir(entry.path()).unwrap();
                        injected = true;
                        refusals += 1;
                        return Err(StoreError::Unavailable);
                    }
                }
            }
            Ok(())
        })
        .unwrap_err();
    assert!(injected);
    assert_eq!(refusals, 1);
    assert!(sql.contains(input.0).unwrap());
    assert!(path.exists());
    let StoreError::CompositeScope { mut source } = error else {
        panic!("all composite outcomes retained");
    };
    assert_eq!(source.prior_publications().len(), 1);
    assert!(matches!(
        source.first_boundary(),
        Some(StoreError::Unavailable)
    ));
    let Some(StoreError::DirectoryScope {
        source: directory_outcome,
    }) = source.work_failure()
    else {
        panic!("actual Directory outcome");
    };
    assert_eq!(directory_outcome.outcome().published_objects, 1);
    assert_eq!(directory_outcome.outcome().durable_objects, 0);
    assert!(directory_outcome.outcome().durability_uncertain);
    assert!(matches!(
        directory_outcome.cleanup_failure(),
        Some(StoreError::Io {
            operation: "remove-object-staging",
            ..
        })
    ));
    // Consume the retained concrete token through its own original check to
    // prove its actual SQL outcome survived the later independent failure.
    let prior = source.body.as_mut().unwrap().prior.pop().unwrap();
    let prior_error = prior
        .check(|_| Err(StoreError::Corrupt { id: input.0 }))
        .unwrap_err();
    let StoreError::SqliteScope {
        source: sql_outcome,
    } = &prior_error
    else {
        panic!("original SQL accepted token");
    };
    assert_eq!(sql_outcome.outcome(), SqliteCommitOutcome::Committed);
    assert!(sql_outcome.rollback_failure().is_none());
    assert!(sql_outcome.restoration_failure().is_none());
    drop(prior_error);
    drop(source);
    drop(store);
    drop(sql);
    drop(directory);
    drop(original);
    assert_eq!(quota.resources.usage().unwrap(), (0, 0));
}

struct NameConversionProbe<'a>(&'a AtomicBool);

impl From<NameConversionProbe<'_>> for String {
    fn from(probe: NameConversionProbe<'_>) -> Self {
        probe.0.store(true, Ordering::SeqCst);
        String::from("unadmitted leaf")
    }
}

#[test]
fn memory_fixture_namespace_uses_original_guard_before_factory_and_retains_shared_credit() {
    let (quota, original) = account();
    let baseline = quota.resources.usage().unwrap();
    let initial_reservations = quota.reservations.load(Ordering::SeqCst);
    let control =
        StorePhysicalQuotaBinderHandle::allocation_bytes::<FixtureMemoryBinder>().unwrap();
    let namespace = memory_namespace(&quota).unwrap();
    let shared = namespace.clone();
    drop(namespace);

    assert_eq!(
        quota.resources.usage().unwrap(),
        (baseline.0, baseline.1 + control as u64)
    );
    assert_eq!(
        quota.reservations.load(Ordering::SeqCst),
        initial_reservations + 1
    );
    let leaf = memory_leaf("qualified", shared.clone());
    assert_eq!(leaf.max_objects(), Some(1));
    assert_eq!(
        leaf.checked_publication_metadata(ObjectKind::RamExtent)
            .unwrap()
            .maximum_placements,
        1
    );
    let retained = quota.resources.usage().unwrap();
    assert_eq!(
        retained.1,
        baseline.1 + control as u64 + MemoryBlobBackend::map_namespace_bytes(1).unwrap()
    );

    quota.live.store(false, Ordering::SeqCst);
    let converted = AtomicBool::new(false);
    let before_refusal = quota.reservations.load(Ordering::SeqCst);
    let error =
        MemoryBlobBackend::new_admitted(NameConversionProbe(&converted), 1024 * 1024, 1, shared)
            .unwrap_err();
    assert!(matches!(error, StoreError::Unauthorized));
    assert!(!converted.load(Ordering::SeqCst));
    assert_eq!(quota.reservations.load(Ordering::SeqCst), before_refusal);
    assert_eq!(quota.resources.usage().unwrap(), retained);

    drop(leaf);
    assert_eq!(quota.resources.usage().unwrap(), baseline);
    drop(original);
    assert_eq!(quota.resources.usage().unwrap(), (0, 0));
    eprintln!(
        "fixture binder body={} control={} handle={} namespace={}",
        std::mem::size_of::<FixtureMemoryBinder>(),
        control,
        std::mem::size_of::<StorePhysicalQuotaBinderHandle>(),
        MemoryBlobBackend::map_namespace_bytes(1).unwrap()
    );
}
