//! Durable RAM storage beyond a fixed packed index under real Service ownership.
//!
//! A synthetic page producer supplies 131072 distinct pages using one bounded
//! buffer. This qualifies storage indexing, authenticated traversal, and GC
//! batching only; it launches no guest and asserts no guest-state transparency.

use super::*;
use crate::packaged_qemu_executor::hot_fork::retained_service::RetainedTemplateServiceFactory;
use crucible_api::host_operational::{
    HostRamCaptureScope, HostRamInventoryLimits, HostRamInventoryRegion,
    HostRamInventoryRegionClass, HostRamInventoryTopology, HostResourceVector,
};
use crucible_cas::content_store::{
    BlobHandle, BlobStoreAdmin, ContentId, DurabilityRequirement, ObjectKind, RefCasOutcome,
    RefName, RefRemoveOutcome, StoreError,
};
use crucible_cas::ram::{RamStore, RamStoreLimits, maximum_ram_root_decoding_bytes};

const PAGE_COUNT: u64 = 131_072;
const LOGICAL_BYTES: u64 = PAGE_COUNT * 4096;
const TREE_COUNT: u64 = PAGE_COUNT * 2 - 1;
const GRAPH_OBJECTS: u64 = PAGE_COUNT + TREE_COUNT + 1;
const MIB: u64 = 1024 * 1024;

// The existing bounded cleanup contract permits at most 1,048,576 inodes.
// The unchanged 393,216-object RAM workload remains below that ceiling.
const STORAGE_CATALOG_INODES: u64 = 1_048_576;

// Authentication retains one full Service and checks a separate future
// assignment peak. Registry and catalog each reserve another CPU before it.
const INSTALLATION_CPUS: u32 = 2 + 2 + 1 + 1;

const STORAGE_SERVICE_RESOURCES: HostResourceVector = HostResourceVector {
    resident_peak_bytes: 513 * MIB,
    backing_peak_bytes: 1024 * MIB,
    metadata_bytes: 128 * MIB,
    staging_bytes: 16 * MIB,
    paging_io_slots: 1,
    cpu_slots: 2,
    // Native process ceiling, four node services and its original watcher.
    task_slots: 64 + 4 + 1,
    file_descriptors: 1056,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Inventory {
    pages: u64,
    trees: u64,
    roots: u64,
    logical_bytes: u64,
}

#[test]
#[ignore = "requires the isolated AOS ext4 quota VM and real catalog/Replay Services"]
fn production_ram_storage_scales_past_packed_index_limit() {
    let source = paging_scenario();
    let admins = std::cell::RefCell::new(None);
    environment::with_native_repository_environment_with_catalog(
        "storage-scale",
        61_000,
        environment::NativeCatalogBudget {
            resources: HostResourceVector {
                resident_peak_bytes: 768 * MIB,
                backing_peak_bytes: 16 * 1024 * MIB,
                metadata_bytes: 512 * MIB,
                staging_bytes: 32 * MIB,
                paging_io_slots: 1,
                cpu_slots: 1,
                task_slots: 1,
                file_descriptors: 128,
            },
            maximum_inodes: STORAGE_CATALOG_INODES,
            installation_capacity: Some(
                ExecutorCapacity::new(8, INSTALLATION_CPUS, 4096 * MIB, 32 * 1024 * MIB, 1_000_000)
                    .expect("explicit full storage qualification host capacity"),
            ),
            installation_operational_capacity: Some(
                crate::HostOperationalCapacity::new(16, 1024, 8192, 1024 * MIB, 128 * MIB)
                    .expect("independently authored metadata and descriptor capacity"),
            ),
        },
        |root, storage| {
            *admins.borrow_mut() = Some((
                storage.blob_admin.clone(),
                storage.ref_admin.clone(),
                storage.refs.clone(),
            ));
            super::super::hot_fork_native::native_repository(&source, root, storage)
        },
        storage_profile,
        |prepared, config, repository| {
            let (blobs, refs, references) = admins
                .borrow_mut()
                .take()
                .expect("original paired physical views");
            let before = prepared
                .actor
                .with_supervisor(|actor| Ok(actor.host_resource_availability()))
                .expect("original actor complete capacity");
            let service = RetainedTemplateServiceFactory::new(prepared, config)
                .start_for_archive_authentication(&source, ExecutionCancellation::default())
                .expect("actual full-vector Replay Service before storage work");
            let supervisor = service
                .context()
                .host_operation_supervisor()
                .expect("actual original Service supervisor");
            let operation = supervisor
                .begin(HostOperationClass::Transfer)
                .expect("original storage qualification operation");
            let cancellation = service.context().cancellation().clone();
            let mut store_boundary = || {
                operation.wait_slice().map(|_| ()).map_err(|source| {
                    cancellation.cancel();
                    StoreError::Supervision {
                        source: Box::new(source),
                    }
                })
            };
            let resources = repository
                .blob_backend()
                .metadata_resources()
                .expect("actual admitted source namespace metadata authority");
            let decoding = crucible::owned_decode::DecodeBudget::for_store(resources.clone())
                .expect("original namespace decoding authority");
            let _decode_scope = decoding.enter();
            let capture_bytes = maximum_ram_root_decoding_bytes()
                .expect("closed root allocation bound")
                .checked_add(1024 * 1024)
                .expect("bounded capture frontier and page batch scratch");
            let capture_credit = resources
                .reserve_resources(0, capture_bytes)
                .expect("root metadata and streaming capture buffers admitted before allocation");
            let topology = HostRamInventoryTopology::new(
                vec![
                    HostRamInventoryRegion::new(
                        "storage.scale",
                        HostRamInventoryRegionClass::MutableMain,
                        LOGICAL_BYTES,
                    )
                    .expect("one synthetic logical storage region"),
                ],
                HostRamInventoryLimits::default(),
            )
            .expect("canonical bounded synthetic topology");
            let ram = RamStore::new(
                repository.blob_backend(),
                DurabilityRequirement::new(1, false).expect("durability"),
                RamStoreLimits::default(),
            )
            .expect("actual scalable Directory publication");
            let retention = repository
                .ram_retention_authority()
                .acquire()
                .expect("original publication retention");
            let started = monotonic_nanoseconds();
            let mut supplied = 0;
            let root = ram
                .capture(
                    topology,
                    HostRamCaptureScope::Exact,
                    &mut |_, index, bytes| {
                        assert_eq!(index, supplied);
                        bytes.fill((index % 251) as u8);
                        bytes[..8].copy_from_slice(&index.to_be_bytes());
                        supplied += 1;
                        Ok(())
                    },
                    &retention,
                    &decoding,
                    &mut || store_boundary().map_err(Into::into),
                )
                .expect("complete non-deduplicating durable root publication");
            let capture_ns = monotonic_nanoseconds() - started;
            assert_eq!(supplied, PAGE_COUNT);
            let root_id = root.object_id();
            let owner =
                RefName::new("storage-scale/owned-root").expect("durable logical root owner");
            assert_eq!(
                references
                    .compare_exchange(&owner, None, root_id)
                    .expect("publish exact owning ref"),
                RefCasOutcome::Advanced { next: root_id }
            );
            drop(retention);

            let physical = inventory(blobs.as_ref(), &mut store_boundary);
            assert_eq!(physical.pages, PAGE_COUNT);
            assert_eq!(physical.trees, TREE_COUNT);
            assert_eq!(physical.roots, 1);
            assert!(physical.pages > crate::campaign_gc::MAX_CAMPAIGN_GC_MANIFEST_ENTRIES as u64);
            let read_start = monotonic_nanoseconds();
            let verified = ram
                .verify(&root, &decoding, &mut || {
                    store_boundary().map_err(Into::into)
                })
                .expect("authenticated full graph without flat page inventory");
            let read_ns = monotonic_nanoseconds() - read_start;
            assert_eq!(verified.pages, PAGE_COUNT);
            assert_eq!(verified.logical_bytes, LOGICAL_BYTES);

            let reopened_retention = repository
                .ram_retention_authority()
                .acquire()
                .expect("independently retained read source");
            let reopened = ram
                .open_with_metadata_resources(
                    crucible_cas::ram::RamRetention::retain_root(&reopened_retention, root_id)
                        .expect("real read claim"),
                    &decoding,
                    &mut || store_boundary().map_err(Into::into),
                )
                .expect("admitted reopen of actual durable root");
            drop(reopened_retention);
            let warm_start = monotonic_nanoseconds();
            let warm = ram
                .verify(&reopened, &decoding, &mut || {
                    store_boundary().map_err(Into::into)
                })
                .expect("repeated complete authenticated read");
            let warm_ns = monotonic_nanoseconds() - warm_start;
            assert_eq!(verified, warm);
            for index in [0, PAGE_COUNT / 2, PAGE_COUNT - 1] {
                let page = ram
                    .read_page(&reopened, "storage.scale", index, &decoding, &mut || {
                        store_boundary().map_err(Into::into)
                    })
                    .expect("bounded proof lookup");
                assert_eq!(&page[..8], &index.to_be_bytes());
                assert!(page[8..].iter().all(|byte| *byte == (index % 251) as u8));
            }
            for index in 0_u64..3 {
                store_boundary().expect("original operation before unrelated object publication");
                let bytes = index.to_be_bytes();
                let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
                repository
                    .blob_backend()
                    .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
                    .expect("unrelated real physical object");
            }
            let journal_root = config.lifecycle.run_state_root().join("storage-scale-gc");
            let provider = config
                .lifecycle
                .ram_catalog_provider()
                .expect("original catalog provider");
            provider
                .prepare_directory(&journal_root)
                .expect("contained quota-backed GC journals");
            let collect = |pass: u64, boundary: &mut dyn FnMut() -> Result<(), StoreError>| {
                let storage = provider
                    .open_catalog(&journal_root.join(format!("marks-{pass}")))
                    .expect("actual admitted supervised mark catalog");
                let original = storage.original;
                let maintenance =
                    crate::CampaignGcOperationContext::new(storage.backend, &original, boundary)
                        .expect("same original complete work boundary");
                prepared
                    .actor
                    .with_supervisor(|actor| {
                        Ok(crate::campaign_gc::native_storage::collect_one_batch(
                            &repository,
                            refs.as_ref(),
                            blobs.as_ref(),
                            actor.startup_ledger_mut(),
                            &maintenance,
                            &journal_root.join(format!("journal-{pass}")),
                        ))
                    })
                    .expect("same real Directory ledger")
                    .expect("shared fenced planner and bounded apply")
            };
            let (reachable, unrelated) = collect(0, &mut store_boundary);
            assert!(reachable >= GRAPH_OBJECTS);
            assert_eq!(unrelated, 3);
            assert_eq!(inventory(blobs.as_ref(), &mut store_boundary), physical);

            assert_eq!(
                references
                    .compare_remove(&owner, root_id)
                    .expect("remove exact durable owner after all read checks"),
                RefRemoveOutcome::Removed
            );
            drop(reopened);
            drop(root);
            drop(capture_credit);
            let mut collected = 0;
            let mut batches = 0;
            loop {
                let (_, count) = collect(batches + 1, &mut store_boundary);
                if count == 0 {
                    break;
                }
                assert!(count <= crate::campaign_gc::MAX_CAMPAIGN_GC_MANIFEST_ENTRIES as u64);
                collected += count;
                batches += 1;
                assert!(batches <= 8, "bounded graph must be fully collectible");
            }
            assert_eq!(collected, GRAPH_OBJECTS);
            assert!(batches > 1);
            assert_eq!(
                inventory(blobs.as_ref(), &mut store_boundary),
                Inventory::default()
            );
            assert!(matches!(
                repository.blob_backend().read(root_id, None),
                Err(StoreError::NotFound { id }) if id == root_id
            ));
            operation
                .complete()
                .expect("original full-work operation completed");
            service
                .release_after_world_cleanup()
                .expect("actual no-native Service cleanup");
            drop(service);
            assert_eq!(
                prepared
                    .actor
                    .with_supervisor(|actor| Ok(actor.host_resource_availability()))
                    .expect("original actor after cleanup"),
                before
            );

            println!("ram_storage_scale_distinct_pages={PAGE_COUNT}");
            println!("ram_storage_scale_distinct_tree_objects={TREE_COUNT}");
            println!("ram_storage_scale_logical_bytes={LOGICAL_BYTES}");
            println!("ram_storage_scale_encoded_bytes={}", physical.logical_bytes);
            println!(
                "ram_storage_scale_verified_object_reads={}",
                verified.object_visits
            );
            println!("ram_storage_scale_capture_ns={capture_ns}");
            println!("ram_storage_scale_first_read_ns={read_ns}");
            println!("ram_storage_scale_repeated_read_ns={warm_ns}");
            println!("ram_storage_scale_gc_batches={batches}");
            println!("ram_storage_scale_gc_deleted_objects={collected}");
            println!("ram_storage_scale_rooted_graph_retained=true");
            println!("ram_storage_scale_final_reader_release_before_collection=true");
            println!("ram_storage_scale_complete_vector_restored=true");
            println!("RAM_STORAGE_SCALE_PASS");
        },
    );
}

fn storage_profile(config: PackagedQemuExecutorConfig) -> PackagedQemuExecutorConfig {
    config
        .with_retained_template_resources(STORAGE_SERVICE_RESOURCES)
        .expect("independently authored full Service matches the native launch floor")
        .with_host_operation_budgets(crucible_api::host_operational::HostOperationBudgets {
            classes: [HostOperationBudget::finite(Duration::from_secs(14_400));
                crucible_linux_resource::host_supervision::HOST_OPERATION_CLASS_COUNT],
        })
        .expect("finite complete storage roster before catalog and actor admission")
}

#[test]
fn storage_profile_authors_native_service_and_separate_assignment_headroom() {
    let directory = tempfile::TempDir::new().expect("component profile directory");
    let profile = storage_profile(config(&directory, 1));
    let service = profile
        .retained_template_resources()
        .expect("explicit retained Service");
    let assignment = profile.assignment_resources().expect("explicit assignment");

    assert_eq!(service, STORAGE_SERVICE_RESOURCES);
    assert_eq!(service.task_slots, 69);

    let quota = crucible_linux_resource::LinuxProjectQuotaLimits::new(
        16 * 1024 * MIB,
        STORAGE_CATALOG_INODES,
    )
    .expect("storage profile respects the existing bounded inode cleanup contract");
    assert_eq!(quota.maximum_inodes(), STORAGE_CATALOG_INODES);
    assert!(quota.maximum_inodes() > GRAPH_OBJECTS);
    assert!(
        crucible_linux_resource::LinuxProjectQuotaLimits::new(
            16 * 1024 * MIB,
            STORAGE_CATALOG_INODES + 1,
        )
        .is_err()
    );

    assert_eq!(
        u64::from(INSTALLATION_CPUS),
        service.cpu_slots + assignment.cpu_slots + 1 + 1
    );
    assert_eq!(
        profile.host_operation_budgets(),
        Some(crucible_api::host_operational::HostOperationBudgets {
            classes: [HostOperationBudget::finite(Duration::from_secs(14_400));
                crucible_linux_resource::host_supervision::HOST_OPERATION_CLASS_COUNT],
        })
    );
}

fn inventory(
    admin: &dyn BlobStoreAdmin,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Inventory {
    boundary().expect("original inventory boundary");
    let mut fence = admin
        .acquire_inventory_fence()
        .expect("same physical quota admin fence");
    let mut result = Inventory::default();
    fence
        .visit_inventory(&mut |record| {
            boundary()?;
            match record.id().kind() {
                ObjectKind::RamExtent => result.pages += 1,
                ObjectKind::RamTree => result.trees += 1,
                ObjectKind::ExactManifest if record.id().schema_version() == 1 => result.roots += 1,
                _ => return Ok(()),
            }
            result.logical_bytes += record.logical_length();
            Ok(())
        })
        .expect("complete streamed physical inventory");
    result
}

fn monotonic_nanoseconds() -> u64 {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    u64::try_from(now.tv_sec)
        .expect("positive operational seconds")
        .checked_mul(1_000_000_000)
        .and_then(|seconds| {
            seconds.checked_add(u64::try_from(now.tv_nsec).expect("positive nanos"))
        })
        .expect("bounded operational evidence clock")
}
