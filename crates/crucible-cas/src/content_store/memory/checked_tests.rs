//! Actual Memory publication effects, immutable identity and caller credit lifetimes.

use super::tests::{CacheTestError, Lease, Quota, Retention};
use super::*;
use crate::owned_decode::DecodeBudget;
use std::sync::atomic::AtomicBool;

pub(super) fn account() -> (Arc<Quota>, DecodeBudget) {
    let quota = Arc::new(Quota {
        resources: crate::content_store::test_resources::FixtureResourceBudget::new(
            128,
            64 * 1024 * 1024,
        ),
        closed: AtomicBool::new(false),
    });
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    (quota, original)
}

// Independently authored finite namespace N; it is neither the source S nor
// the current operation A. Fixture controls are outside production funding.
fn admitted_backend(name: &str, logical_bytes: u64) -> MemoryBlobBackend {
    let namespace = Arc::new(Quota {
        resources: crate::content_store::test_resources::FixtureResourceBudget::new(128, 16_384),
        closed: AtomicBool::new(false),
    });
    MemoryBlobBackend::new_admitted(
        name,
        logical_bytes,
        64,
        super::tests::namespace_binder(namespace),
    )
    .unwrap()
}

struct BorrowedSource {
    body: Arc<[u8]>,
    source: DecodeBudget,
}

impl BlobSource for BorrowedSource {
    fn checked_read_access(&self) -> CheckedReadAccess {
        CheckedReadAccess::Whole
    }

    fn logical_length(&self) -> u64 {
        self.body.len() as u64
    }

    fn open(&self) -> Result<Box<dyn std::io::Read + Send>, StoreError> {
        Err(StoreError::Unsupported {
            capability: "raw-test-source",
        })
    }

    fn read_all_with_boundary(
        &self,
        caller: &DecodeBudget,
        maximum: u64,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<OwnedBlobBytes, StoreError> {
        let mut reader = std::io::Cursor::new(self.body.as_ref());
        batch::read_reader_under(
            &self.source,
            caller,
            self.logical_length(),
            maximum,
            boundary,
            &mut |output, _| {
                std::io::Read::read(&mut reader, output).map_err(|source| StoreError::StreamIo {
                    operation: "test-borrowed-source",
                    source,
                })
            },
        )
    }
}

#[test]
fn completed_publication_retains_payload_payer_but_new_reads_use_current_original() {
    let (source_quota, source_original) = account();
    let (publication_quota, publication_original) = account();
    let (lookup_quota, lookup_original) = account();
    let (read_quota, read_original) = account();
    let backend = admitted_backend("memory", 1024 * 1024);
    let bytes: Arc<[u8]> = vec![19; 65 * 1024].into();
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    let source = BlobHandle::new(BorrowedSource {
        body: bytes,
        source: source_original.clone(),
    });
    let receipt = backend
        .put_many_if_absent_with_boundary(
            &publication_original,
            &[(id, source.clone())],
            &mut || Ok(()),
        )
        .unwrap()
        .accept_with_boundary(&mut || Ok(()))
        .unwrap();
    drop(receipt);
    drop(source);
    drop(source_original);
    drop(publication_original);
    source_quota.closed.store(true, Ordering::SeqCst);
    publication_quota.closed.store(true, Ordering::SeqCst);

    let body = backend
        .state
        .lock()
        .unwrap()
        .objects
        .get(&id)
        .unwrap()
        .clone();
    let handle = backend
        .read_with_boundary(&lookup_original, id, None, &mut || Ok(()))
        .unwrap();
    drop(lookup_original);
    lookup_quota.closed.store(true, Ordering::SeqCst);
    let baseline = read_quota.resources.usage().unwrap();
    let owners = Arc::strong_count(body.0.as_ref().unwrap());
    let output = handle
        .read_all_with_boundary(&read_original, 1024 * 1024, &mut || {
            assert_eq!(
                Arc::strong_count(body.0.as_ref().unwrap()),
                owners,
                "complete reads borrow the actual body"
            );
            Ok(())
        })
        .unwrap();
    assert_eq!(&*output, body.bytes().unwrap());
    assert_eq!(
        read_quota.resources.usage().unwrap().1,
        baseline.1 + body.bytes().unwrap().len() as u64
    );
    assert!(
        matches!(&body.0.as_ref().unwrap().bytes, MemoryBytes::Checked(bytes) if bytes.original_account().verify_live().is_err())
    );

    let mut reader =
        <BlobHandle as BlobSource>::open_with_boundary(&handle, &read_original, &mut || Ok(()))
            .unwrap();
    let read_usage = read_quota.resources.usage().unwrap();
    let probe = reader.original_account().reserve_scratch_bytes(17).unwrap();
    assert_eq!(read_quota.resources.usage().unwrap().1, read_usage.1 + 17);
    drop(probe);
    drop(handle);
    assert_eq!(lookup_quota.resources.usage().unwrap(), (0, 0));
    backend
        .acquire_inventory_fence()
        .unwrap()
        .delete_candidate(id)
        .unwrap();
    drop(backend);
    drop(body);
    assert!(source_quota.resources.usage().unwrap().1 > 65 * 1024);
    assert!(publication_quota.resources.usage().unwrap().1 > 0);
    let mut buffer = [0_u8; 64 * 1024];
    assert_eq!(
        reader.read_with_boundary(&mut [], &mut || Ok(())).unwrap(),
        0
    );
    assert_eq!(
        reader
            .read_with_boundary(&mut buffer, &mut || Ok(()))
            .unwrap(),
        buffer.len()
    );
    assert_eq!(
        reader
            .read_with_boundary(&mut buffer, &mut || Ok(()))
            .unwrap(),
        1024
    );
    assert_eq!(
        reader
            .read_with_boundary(&mut buffer, &mut || Ok(()))
            .unwrap(),
        0
    );
    drop(reader);
    assert_eq!(source_quota.resources.usage().unwrap(), (0, 0));
    assert_eq!(publication_quota.resources.usage().unwrap(), (0, 0));
    drop(read_original);
    assert!(read_quota.resources.usage().unwrap().1 >= output.len() as u64);
    drop(output);
    assert_eq!(read_quota.resources.usage().unwrap(), (0, 0));
}

#[test]
fn final_acceptance_failure_preserves_new_insertions_and_duplicate_authentication() {
    let (quota, original) = account();
    let backend = admitted_backend("memory", 4096);
    let bytes = [7; 23];
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    let source = BlobHandle::from_bytes(bytes);
    let receipt = backend
        .put_many_if_absent_with_boundary(
            &original,
            &[(id, source.clone()), (id, source)],
            &mut || Ok(()),
        )
        .unwrap();
    let error = receipt
        .accept_with_boundary(&mut || Err(StoreError::Unavailable))
        .unwrap_err();
    let StoreError::MemoryScope { source } = &error else {
        panic!("actual Memory scope: {error:?}")
    };
    assert_eq!(
        source.outcome(),
        MemoryPublicationOutcome {
            published_objects: 1,
            accepted_objects: 2
        }
    );
    assert!(matches!(source.work_failure(), StoreError::Unavailable));
    assert_eq!(backend.object_count().unwrap(), 1);
    drop(original);
    drop(backend);
    assert!(
        quota.resources.usage().unwrap().1 > 0,
        "failure owns its prepaid Box after backend closes"
    );
    drop(error);
    assert_eq!(quota.resources.usage().unwrap(), (0, 0));
}

#[test]
fn every_publication_boundary_preserves_exact_visible_effects_on_cancellation() {
    let (_, original) = account();
    let bytes = [7; 23];
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    let mut total = 0;
    admitted_backend("probe", 4096)
        .put_many_if_absent_with_boundary(
            &original,
            &[(id, BlobHandle::from_bytes(bytes))],
            &mut || {
                total += 1;
                Ok(())
            },
        )
        .unwrap();

    for refused_call in 1..=total {
        let (quota, original) = account();
        let backend = admitted_backend("memory", 4096);
        let mut calls = 0;
        let error = backend
            .put_many_if_absent_with_boundary(
                &original,
                &[(id, BlobHandle::from_bytes(bytes))],
                &mut || {
                    calls += 1;
                    if calls == refused_call {
                        quota.closed.store(true, Ordering::SeqCst);
                    }
                    Ok(())
                },
            )
            .unwrap_err();
        let observed = backend.object_count().unwrap() as u8;
        match &error {
            StoreError::MemoryScope { source } => {
                assert_eq!(
                    source.outcome().published_objects,
                    observed,
                    "boundary {refused_call}"
                );
                assert!(matches!(
                    source.work_failure().original_failure(),
                    StoreError::Unauthorized
                ));
            }
            _ => assert_eq!(observed, 0, "unscoped pre-effect failure at {refused_call}"),
        }
        drop(backend);
        drop(original);
        drop(error);
        assert_eq!(
            quota.resources.usage().unwrap(),
            (0, 0),
            "boundary {refused_call}"
        );
    }
}

#[test]
fn checked_reader_cancellation_is_sticky_and_does_not_donate_to_foreign_tls() {
    let (_, publication) = account();
    let (read_quota, read_original) = account();
    let (foreign_quota, foreign) = account();
    let backend = admitted_backend("memory", 4096);
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &[7; 23]);
    backend
        .put_many_if_absent_with_boundary(
            &publication,
            &[(id, BlobHandle::from_bytes([7; 23]))],
            &mut || Ok(()),
        )
        .unwrap();
    let handle = backend
        .read_with_boundary(&read_original, id, None, &mut || Ok(()))
        .unwrap();
    let foreign_usage = foreign_quota.resources.usage().unwrap();
    let mut scope = None;
    let mut reader =
        <BlobHandle as BlobSource>::open_with_boundary(&handle, &read_original, &mut || {
            if scope.is_none() {
                scope = Some(foreign.enter());
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(foreign_quota.resources.usage().unwrap(), foreign_usage);
    let mut output = [0; 23];
    assert_eq!(
        reader
            .read_with_boundary(&mut output, &mut || Ok(()))
            .unwrap(),
        23
    );
    let error = reader
        .read_with_boundary(&mut output, &mut || {
            read_quota.closed.store(true, Ordering::SeqCst);
            Ok(())
        })
        .unwrap_err();
    assert!(matches!(error.original_failure(), StoreError::Unauthorized));
    assert!(matches!(
        reader.read_with_boundary(&mut output, &mut || Ok(())),
        Err(StoreError::Unsupported {
            capability: "failed-checked-blob-reader"
        })
    ));
    drop(scope);
}

#[test]
fn cold_ram_directory_read_through_physical_memory_cache_keeps_original_page_bank()
-> Result<(), CacheTestError> {
    use crate::content_store::composition::ReadThroughStore;
    use crate::content_store::physical_quota::PhysicalQuotaStore;
    use crate::ram::{RamStore, RamStoreLimits};
    use crucible_ram::{Limits, RegionClass, RegionDescriptor, Scope, Topology};

    let directory = tempfile::tempdir()?;
    let (quota, capture_original) = account();
    let source =
        DirectoryBlobBackend::new_with_physical_quota("source", directory.path(), quota.clone())?;
    let memory = Arc::new(admitted_backend("memory", 64 * 1024 * 1024));
    let cache = Arc::new(PhysicalQuotaStore::new(
        "cache",
        memory.clone(),
        memory.clone(),
        quota.clone(),
    )?);
    let composed = Arc::new(ReadThroughStore::new("read-through", cache.clone(), source));
    let ram = RamStore::new(
        composed,
        DurabilityRequirement::new(1, false)?,
        RamStoreLimits::default(),
    )?;
    let captured = ram.capture(
        Topology::new(
            vec![RegionDescriptor::new(
                "main",
                RegionClass::MutableMain,
                4096,
            )?],
            Limits::default(),
        )?,
        Scope::Exact,
        &mut |_, _, bytes| {
            bytes.fill(11);
            Ok(())
        },
        &Retention,
        &capture_original,
        &mut || Ok(()),
    )?;
    let root = ram.open_with_metadata_resources(
        Arc::new(Lease(captured.object_id())),
        &capture_original,
        &mut || Ok(()),
    )?;
    drop(captured);
    drop(capture_original);
    assert!(crate::owned_decode::current_budget().is_none());

    // Capture publishes to the authoritative child. Removing every promoted
    // metadata object leaves an actual cold Memory cache before the page read.
    {
        let mut fence = memory.acquire_inventory_fence()?;
        let mut ids = Vec::new();
        fence.visit_inventory(&mut |record| {
            ids.push(record.id());
            Ok(())
        })?;
        for id in ids {
            fence.delete_candidate(id)?;
        }
    }
    assert_eq!(memory.object_count()?, 0);
    let page_original = DecodeBudget::for_store(quota.clone())?;
    let page = ram.read_page(&root, "main", 0, &page_original, &mut || Ok(()))?;
    assert_eq!(page, vec![11; 4096]);
    assert!(memory.object_count()? > 0);
    let mut page_id = None;
    {
        let mut fence = memory.acquire_inventory_fence()?;
        fence.visit_inventory(&mut |record| {
            if record.id().kind() == ObjectKind::RamExtent {
                page_id = Some(record.id());
            }
            Ok(())
        })?;
    }
    let id = page_id.ok_or(StoreError::InvalidId)?;
    let handle = cache.read_with_boundary(&page_original, id, None, &mut || Ok(()))?;
    let output = handle.read_all_with_boundary(&page_original, 64 * 1024, &mut || Ok(()))?;
    memory.acquire_inventory_fence()?.delete_candidate(id)?;
    drop(handle);
    drop(page);
    drop(page_original);
    drop(root);
    drop(ram);
    drop(cache);
    drop(memory);
    assert!(quota.resources.usage()?.1 >= output.len() as u64);
    drop(output);
    assert_eq!(quota.resources.usage()?, (0, 0));
    Ok(())
}

#[test]
fn physical_facade_final_refusal_preserves_actual_memory_outcome_and_original_credits() {
    use crate::content_store::physical_quota::PhysicalQuotaStore;

    let (quota, original) = account();
    let (foreign_quota, foreign) = account();
    let memory = Arc::new(admitted_backend("memory", 4096));
    let facade =
        PhysicalQuotaStore::new("facade", memory.clone(), memory.clone(), quota.clone()).unwrap();
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &[7; 23]);
    let receipt = facade
        .put_many_if_absent_with_boundary(
            &original,
            &[(id, BlobHandle::from_bytes([7; 23]))],
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(receipt[0].placements[0].backend, "facade");
    let foreign_usage = foreign_quota.resources.usage().unwrap();
    let mut scope = None;
    let error = receipt
        .accept_with_boundary(&mut || {
            scope = Some(foreign.enter());
            quota.closed.store(true, Ordering::SeqCst);
            Ok(())
        })
        .unwrap_err();
    assert_eq!(foreign_quota.resources.usage().unwrap(), foreign_usage);
    let StoreError::MemoryScope { source } = &error else {
        panic!("retained actual Memory outcome: {error:?}")
    };
    assert_eq!(source.outcome().published_objects, 1);
    assert_eq!(source.outcome().accepted_objects, 1);
    assert!(matches!(
        source.work_failure().original_failure(),
        StoreError::Unauthorized
    ));
    drop(scope);
    drop(original);
    drop(facade);
    drop(memory);
    assert!(quota.resources.usage().unwrap().1 > 0);
    drop(error);
    assert_eq!(quota.resources.usage().unwrap(), (0, 0));
}

#[test]
fn authenticated_range_cannot_publish_partial_bytes_under_whole_source_identity() {
    let (_, original) = account();
    let backend = admitted_backend("source", 4096);
    let bytes = [7; 23];
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    backend
        .put_many_if_absent_with_boundary(
            &original,
            &[(id, BlobHandle::from_bytes(bytes))],
            &mut || Ok(()),
        )
        .unwrap();
    let range = backend
        .read_with_boundary(
            &original,
            id,
            Some(ByteRange {
                offset: 3,
                length: 7,
            }),
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(
        &*range
            .read_all_with_boundary(&original, 4096, &mut || Ok(()))
            .unwrap(),
        &[7; 7]
    );
    let destination = admitted_backend("destination", 4096);
    let error = destination
        .put_many_if_absent_with_boundary(&original, &[(id, range)], &mut || Ok(()))
        .unwrap_err();
    assert!(
        matches!(error.original_failure(), StoreError::Corrupt { id: failed } if *failed == id)
    );
    assert_eq!(destination.object_count().unwrap(), 0);
}

#[test]
fn inaccessible_empty_terminal_slot_refuses_while_valid_empty_object_authenticates() {
    let absent = MemoryBody(None);
    assert!(matches!(absent.bytes(), Err(StoreError::Unavailable)));
    let (_, original) = account();
    let backend = admitted_backend("memory", 4096);
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &[]);
    backend
        .put_many_if_absent_with_boundary(
            &original,
            &[(id, BlobHandle::from_bytes([]))],
            &mut || Ok(()),
        )
        .unwrap();
    let handle = backend
        .read_with_boundary(&original, id, None, &mut || Ok(()))
        .unwrap();
    assert!(
        handle
            .read_all_with_boundary(&original, 0, &mut || Ok(()))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn failure_box_reservation_refuses_before_source_copy_or_visible_effects() {
    use std::sync::atomic::AtomicUsize;

    struct CountingSource {
        source: BorrowedSource,
        attempts: Arc<AtomicUsize>,
    }

    impl BlobSource for CountingSource {
        fn checked_read_access(&self) -> CheckedReadAccess {
            CheckedReadAccess::Whole
        }

        fn logical_length(&self) -> u64 {
            self.source.logical_length()
        }

        fn open(&self) -> Result<Box<dyn std::io::Read + Send>, StoreError> {
            self.source.open()
        }

        fn read_all_with_boundary(
            &self,
            caller: &DecodeBudget,
            maximum: u64,
            boundary: &mut dyn FnMut() -> Result<(), StoreError>,
        ) -> Result<OwnedBlobBytes, StoreError> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            self.source
                .read_all_with_boundary(caller, maximum, boundary)
        }
    }

    let (source_quota, source_original) = account();
    let (publication_quota, publication_original) = account();
    let backend = admitted_backend("memory", 4096);
    let attempts = Arc::new(AtomicUsize::new(0));
    let source = BlobHandle::new(CountingSource {
        source: BorrowedSource {
            body: vec![7; 23].into(),
            source: source_original,
        },
        attempts: attempts.clone(),
    });
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &[7; 23]);
    let baseline = publication_quota.resources.usage().unwrap().1;
    let probe = batch::admit_receipts(&publication_original, 1, backend.name.len()).unwrap();
    let receipt_bytes = publication_quota.resources.usage().unwrap().1 - baseline;
    drop(probe);
    let source_baseline = source_quota.resources.usage().unwrap();
    // Leave exactly the receipt extent available, with no capacity to create
    // the concrete recursive Failure Box before copying or mutating anything.
    let retained = publication_original
        .reserve_scratch_bytes(64 * 1024 * 1024 - baseline - receipt_bytes)
        .unwrap();
    let error = backend
        .put_many_if_absent_with_boundary(
            &publication_original,
            &[(id, source.clone())],
            &mut || Ok(()),
        )
        .unwrap_err();
    assert!(matches!(error, StoreError::DecodeAdmission { .. }));
    assert_eq!(attempts.load(Ordering::SeqCst), 0);
    assert_eq!(backend.object_count().unwrap(), 0);
    assert_eq!(source_quota.resources.usage().unwrap(), source_baseline);
    drop(error);
    drop(retained);
}

#[test]
fn concrete_memory_payment_geometry_preserves_single_body_allocation() {
    let (source_bytes, source_allocation, reader_bytes) = super::checked::allocation_geometry();
    let object_bytes = std::mem::size_of::<MemoryObject>();
    let body_bytes = std::mem::size_of::<MemoryBody>();
    let optional_body_bytes = std::mem::size_of::<Option<MemoryBody>>();
    let slot_bytes = std::mem::size_of::<(ContentId, MemoryBody)>();
    let namespace_bound = MemoryBlobBackend::map_namespace_bytes(64).unwrap();
    let failure_bytes = super::checked_publication::failure_allocation_bytes();
    assert_eq!(body_bytes, std::mem::size_of::<Arc<MemoryObject>>());
    assert!(optional_body_bytes >= body_bytes);
    assert!(source_allocation >= source_bytes as u64);
    assert!(failure_bytes >= std::mem::size_of::<StoreError>());
    println!(
        "Memory geometry object={object_bytes} body={body_bytes} optional_body={optional_body_bytes} map_slot={slot_bytes} namespace_bound={namespace_bound} object_control={} source={source_bytes} source_allocation={source_allocation} reader={reader_bytes} store_error={} failure={failure_bytes}",
        object_bytes + 2 * std::mem::size_of::<usize>(),
        std::mem::size_of::<StoreError>()
    );
}

#[test]
fn read_through_original_revocation_after_memory_insert_retains_actual_publication_outcome() {
    use crate::content_store::composition::ReadThroughStore;
    use crate::content_store::physical_quota::PhysicalQuotaStore;

    struct CacheFixture {
        _directory: tempfile::TempDir,
        quota: Arc<Quota>,
        original: DecodeBudget,
        memory: Arc<MemoryBlobBackend>,
        store: ReadThroughStore,
        id: ContentId,
    }

    fn fixture() -> CacheFixture {
        let directory = tempfile::tempdir().unwrap();
        let (quota, original) = account();
        let source = DirectoryBlobBackend::new_with_physical_quota(
            "source",
            directory.path(),
            quota.clone(),
        )
        .unwrap();
        let bytes = [7; 23];
        let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
        source
            .put_if_absent(id, &BlobHandle::from_bytes(bytes))
            .unwrap();
        let memory = Arc::new(admitted_backend("memory", 4096));
        let cache = Arc::new(
            PhysicalQuotaStore::new("cache", memory.clone(), memory.clone(), quota.clone())
                .unwrap(),
        );
        let store = ReadThroughStore::new("read-through", cache, source);
        CacheFixture {
            _directory: directory,
            quota,
            original,
            memory,
            store,
            id,
        }
    }

    let successful = fixture();
    let mut total = 0;
    successful
        .store
        .read_with_boundary(&successful.original, successful.id, None, &mut || {
            total += 1;
            Ok(())
        })
        .unwrap();
    let mut canceled_after_insert = 0;
    for refused_call in 1..=total {
        let canceled = fixture();
        let mut calls = 0;
        let error = canceled
            .store
            .read_with_boundary(&canceled.original, canceled.id, None, &mut || {
                calls += 1;
                if calls == refused_call {
                    canceled.quota.closed.store(true, Ordering::SeqCst);
                }
                // Original admission may refuse even when the callback itself succeeds.
                Ok(())
            })
            .err()
            .expect("the existing caller's revocation must stop the read");
        if canceled.memory.object_count().unwrap() > 0 {
            canceled_after_insert += 1;
            let StoreError::MemoryScope { source } = &error else {
                panic!("boundary {refused_call} lost actual Memory insertion: {error:?}");
            };
            assert_eq!(
                source.outcome().published_objects,
                1,
                "boundary {refused_call}"
            );
            assert!(matches!(
                source.work_failure().original_failure(),
                StoreError::Unauthorized
            ));
        }
    }
    assert!(
        canceled_after_insert > 0,
        "exercise actual promotion effects before original-only refusal"
    );
}
