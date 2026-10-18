//! Real canonical RAM capture, archive, restore and maintenance at volume scale.
//!
//! Page bytes are generated into one reusable buffer. Traversal retains one
//! binary path, and inventory streams counters instead of a closure-sized set.
//! The quota binder models the same finite fixture bank; it is not kernel or
//! process-wide accounting evidence.

use super::super::codec::{TreeNode, TreeRef};
use super::*;
use std::collections::BTreeMap;
use std::path::Path;

use crate::content_store::{
    BlobInventoryFence, DirectoryRefBackend, MutableRefBackend, RefStoreAdmin, StoreGraph,
    StoreGraphAdmin, StoreGraphConfig, StoreGraphKeyring, StoreGraphNamespaceAuthorizers,
    StoreGraphObjectProfilers, StoreGraphPhysicalQuotaBinders, StoreGraphS3Clients, StoreNodeId,
    StoreNodeSpec, StorePhysicalQuotaBinder, StorePhysicalQuotaBinderHandle,
    StorePhysicalQuotaGuard, StorePhysicalQuotaPolicyId,
};
use crate::owned_decode::DecodeBudget;

mod archive_sender;
mod cost;
mod pending_publication;
mod shared_metadata;

const VOLUME_BYTES: u64 = 512 << 20;
const VOLUME_PAGES: u64 = VOLUME_BYTES / 4096;
const VOLUME_OBJECTS: u64 = 3 * VOLUME_PAGES;

struct Binder(Arc<dyn StorePhysicalQuotaGuard>);

impl StorePhysicalQuotaBinder for Binder {
    fn bind(
        &self,
        _: &Path,
        _: u32,
        _: u64,
        _: u64,
    ) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        Ok(self.0.clone())
    }
}

struct Fixture {
    store: RamStore,
    admin: StoreGraphAdmin,
    refs: Arc<dyn MutableRefBackend>,
    ref_admin: Arc<dyn RefStoreAdmin>,
    original: DecodeBudget,
    quota: Arc<FixtureRamQuota>,
}

impl Fixture {
    fn new(root: &Path) -> Self {
        Self::with_quota(root, Self::new_quota())
    }

    fn new_quota() -> Arc<FixtureRamQuota> {
        Arc::new(FixtureRamQuota(
            crate::content_store::test_resources::FixtureResourceBudget::new(128, 256 << 20),
        ))
    }

    fn with_quota(root: &Path, quota: Arc<FixtureRamQuota>) -> Self {
        Self::with_admitted(
            root,
            quota,
            BTreeSet::from([
                ObjectKind::RamExtent,
                ObjectKind::RamTree,
                ObjectKind::ExactManifest,
                ObjectKind::Trace,
            ]),
        )
    }

    fn with_admitted(
        root: &Path,
        quota: Arc<FixtureRamQuota>,
        admitted_kinds: BTreeSet<ObjectKind>,
    ) -> Self {
        let guard: Arc<dyn StorePhysicalQuotaGuard> = quota.clone();
        Self::with_guard(root, quota, guard, admitted_kinds)
    }

    fn with_guard(
        root: &Path,
        quota: Arc<FixtureRamQuota>,
        guard: Arc<dyn StorePhysicalQuotaGuard>,
        admitted_kinds: BTreeSet<ObjectKind>,
    ) -> Self {
        let physical = StoreNodeId::new("physical").unwrap();
        let packed = StoreNodeId::new("packed").unwrap();
        let policy = StorePhysicalQuotaPolicyId::new("model/packed-volume").unwrap();
        let mut binders = StoreGraphPhysicalQuotaBinders::new();
        binders
            .insert(
                policy.clone(),
                StorePhysicalQuotaBinderHandle::new(Binder(guard)),
            )
            .unwrap();
        let (graph, admin) = StoreGraph::build_with_admin_and_all_capabilities(
            StoreGraphConfig {
                gc_mark_root: None,
                root: physical.clone(),
                admitted_kinds,
                nodes: BTreeMap::from([
                    (
                        physical,
                        StoreNodeSpec::PhysicalQuota {
                            child: packed.clone(),
                            policy,
                            project_id: 42,
                            // Fixed disk headroom includes old and replacement
                            // realizations. The portable binder does not enforce it.
                            maximum_physical_bytes: 4 << 30,
                            maximum_inodes: 1 << 20,
                        },
                    ),
                    (
                        packed,
                        StoreNodeSpec::Packed {
                            root: root.join("objects"),
                            target_pack_bytes: 1 << 20,
                        },
                    ),
                ]),
            },
            &StoreGraphKeyring::new(),
            &StoreGraphNamespaceAuthorizers::new(),
            &StoreGraphObjectProfilers::new(),
            &binders,
            &StoreGraphS3Clients::new(),
            None,
        )
        .unwrap();
        let store = RamStore::new(
            Arc::new(graph),
            DurabilityRequirement::new(1, false).unwrap(),
            RamStoreLimits::default(),
        )
        .unwrap();
        let original = fixture_original(&store);
        let (refs, ref_admin) = DirectoryRefBackend::new_with_physical_quota_and_admin(
            root.join("refs"),
            quota.clone(),
        )
        .unwrap();
        Self {
            store,
            admin,
            refs,
            ref_admin,
            original,
            quota,
        }
    }

    fn retention(&self) -> FencedRamRetention {
        RamRetentionAuthority::new(self.refs.clone())
            .acquire()
            .unwrap()
    }

    fn objects(&self) -> u64 {
        self.admin.packed_repack()[0]
            .accounting_with_boundary(&self.original, &mut || Ok(()))
            .unwrap()
            .logical_objects()
    }
}

fn random_page(_: &RegionDescriptor, index: u64, bytes: &mut [u8]) -> Result<(), RamStoreError> {
    fill_page(index, bytes);
    Ok(())
}

fn fill_page(index: u64, bytes: &mut [u8]) {
    let mut hash = blake3::Hasher::new();
    hash.update(b"packed-volume-page");
    hash.update(&index.to_be_bytes());
    hash.finalize_xof().fill(bytes);
}

pub(super) fn assert_exhausted_original_precedes_pages() {
    let directory = tempfile::tempdir().unwrap();
    let fixture = Fixture::new(directory.path());
    let retention = fixture.retention();
    fixture
        .store
        .admit_ram_publication(&topology(VOLUME_BYTES), Scope::Exact)
        .unwrap();
    let before = fixture.quota.0.usage().unwrap();
    let failed = fixture.original.child().unwrap();
    let pressure = fixture
        .quota
        .0
        .reserve(0, (256 << 20) - fixture.quota.0.usage().unwrap().1)
        .unwrap();
    let index_before =
        std::fs::read(directory.path().join("objects/.packed-admin/index-v1")).unwrap();
    let mut reads = 0;
    let mut callbacks = 0;
    let (error, cause, repeated) = {
        let mut attempt = || {
            fixture.store.capture(
                topology(VOLUME_BYTES),
                Scope::Exact,
                &mut |_, _, _| {
                    reads += 1;
                    Ok(())
                },
                &retention,
                &failed,
                &mut || {
                    callbacks += 1;
                    Ok(())
                },
            )
        };
        let error = attempt().unwrap_err();
        let cause = failed.check().unwrap_err();
        let RamStoreError::Store(StoreError::DecodeAdmission { source, .. }) = &error else {
            panic!("exhausted original retains actual typed admission: {error:?}");
        };
        assert_eq!(source, &cause);
        assert!(matches!(
            std::error::Error::source(&cause)
                .unwrap()
                .downcast_ref::<StoreError>(),
            Some(StoreError::Quota)
        ));
        drop(pressure);
        let repeated = attempt().unwrap_err();
        let RamStoreError::Store(StoreError::DecodeAdmission { source, .. }) = &repeated else {
            panic!("same operation cannot renew failed admission: {repeated:?}");
        };
        assert_eq!(source, &cause);
        (error, cause, repeated)
    };
    assert_eq!(reads, 0);
    assert_eq!(callbacks, 0);
    assert_eq!(
        std::fs::read(directory.path().join("objects/.packed-admin/index-v1")).unwrap(),
        index_before
    );
    drop((error, repeated, cause, failed));
    fixture.original.verify_live().unwrap();
    assert_eq!(fixture.quota.0.usage().unwrap(), before);

    let operation = fixture.original.child().unwrap();
    let root = fixture
        .store
        .capture(
            topology(4096),
            Scope::Exact,
            &mut random_page,
            &retention,
            &operation,
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(fixture.objects(), 3);
    drop((root, operation, retention));
}

#[test]
fn packed_canonical_round_trip_and_fenced_maintenance() {
    exercise_volume(4096 * 8);
}

#[test]
fn packed_incompressible_512_mib_capture_archive_restore_and_repack() {
    exercise_volume(VOLUME_BYTES);
}

#[test]
fn packed_shared_canonical_round_trip_and_fenced_maintenance() {
    exercise_volume_with_retention(4096 * 8, true);
}

#[test]
fn packed_shared_512_mib_capture_archive_restore_and_repack() {
    exercise_volume_with_retention(VOLUME_BYTES, true);
}

#[test]
fn packed_repack_depth_first_read_costs() {
    cost::assert_repack_read_costs(32 << 20);
}

#[test]
fn packed_repack_512_mib_depth_first_read_costs() {
    cost::assert_repack_read_costs(VOLUME_BYTES);
}

fn exercise_volume(bytes: u64) {
    exercise_volume_with_retention(bytes, false);
}

fn exercise_volume_with_retention(bytes: u64, shared_metadata: bool) {
    let complete = VolumeStage::start(bytes, "exercise");
    let setup = VolumeStage::start(bytes, "setup");
    let source_directory = tempfile::tempdir().unwrap();
    let destination_directory = tempfile::tempdir().unwrap();
    let fixture = |path: &Path| {
        if shared_metadata {
            let (fixture, shared) = shared_metadata::volume_fixture(path);
            (fixture, Some(shared))
        } else {
            (Fixture::new(path), None)
        }
    };
    let (source, source_cache) = fixture(source_directory.path());
    let (destination, destination_cache) = fixture(destination_directory.path());
    let source_bank = source.quota.clone();
    let destination_bank = destination.quota.clone();

    exercise_volume_on_fixtures(
        bytes,
        source_directory.path(),
        source,
        destination,
        source_cache,
        destination_cache,
        setup,
    );
    if shared_metadata {
        assert_eq!(source_bank.0.usage().unwrap(), (0, 0));
        assert_eq!(destination_bank.0.usage().unwrap(), (0, 0));
    }
    complete.finish(format_args!(
        "pages={} objects={} logical_bytes={bytes}",
        bytes / 4096,
        3 * (bytes / 4096),
    ));
}

fn exercise_volume_on_fixtures(
    bytes: u64,
    source_directory: &Path,
    source: Fixture,
    destination: Fixture,
    source_cache: Option<Arc<shared_metadata::SharedQuota>>,
    destination_cache: Option<Arc<shared_metadata::SharedQuota>>,
    setup: VolumeStage,
) {
    let source_retention = source.retention();
    let pages = bytes / 4096;
    let objects = 3 * pages;
    if bytes == VOLUME_BYTES {
        assert_eq!(pages, VOLUME_PAGES);
        assert_eq!(objects, VOLUME_OBJECTS);
    }
    source
        .store
        .admit_ram_publication(&topology(bytes), Scope::Exact)
        .unwrap();
    setup.finish(format_args!(
        "pages={pages} objects={objects} logical_bytes={bytes}"
    ));
    let capture = VolumeStage::start(bytes, "capture");
    let root = source
        .store
        .capture(
            topology(bytes),
            Scope::Exact,
            &mut random_page,
            &source_retention,
            &source.original,
            &mut || Ok(()),
        )
        .unwrap();
    capture.finish(format_args!(
        "expected_objects={objects} root={}",
        root.object_id()
    ));
    drop(source_retention);
    let accounting = VolumeStage::start(bytes, "source_accounting");
    assert_eq!(source.objects(), objects);
    accounting.finish(format_args!("objects={objects}"));
    assert_restored(&source, &root, pages, "source_initial_restore");

    let destination_retention = destination.retention();
    let owning_manifest =
        ContentId::for_bytes(ObjectKind::ExactManifest, 6, b"packed volume archive owner");
    let first_archive = VolumeStage::start(bytes, "first_archive");
    let archive = source
        .store
        .transfer_archive_to(
            &root,
            owning_manifest,
            &destination.store,
            "packed-volume-destination",
            [91; 32],
            &destination_retention,
            &source.original,
            &destination.original,
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(archive.root().object_id(), root.object_id());
    assert_eq!(archive.report().copied_objects, objects);
    assert!(archive.report().copied_bytes >= bytes);
    first_archive.finish(format_args!(
        "copied_objects={} copied_bytes={} existing_objects={} object_visits={}",
        archive.report().copied_objects,
        archive.report().copied_bytes,
        archive.report().authenticated_existing_objects,
        archive.report().object_visits,
    ));
    let destination_accounting = VolumeStage::start(bytes, "destination_accounting");
    assert_eq!(destination.objects(), objects);
    destination_accounting.finish(format_args!("objects={objects}"));
    assert_restored(&destination, archive.root(), pages, "destination_restore");
    let repeated_archive = VolumeStage::start(bytes, "repeated_archive");
    let repeated = source
        .store
        .transfer_archive_to(
            &root,
            owning_manifest,
            &destination.store,
            "packed-volume-destination",
            [92; 32],
            &destination_retention,
            &source.original,
            &destination.original,
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(repeated.report().copied_objects, 0);
    assert!(repeated.report().authenticated_existing_objects > 0);
    repeated_archive.finish(format_args!(
        "copied_objects={} copied_bytes={} existing_objects={} object_visits={}",
        repeated.report().copied_objects,
        repeated.report().copied_bytes,
        repeated.report().authenticated_existing_objects,
        repeated.report().object_visits,
    ));
    drop((repeated, destination_retention));

    // The old source's already-open pack inode must outlive repack unlink.
    let pin = VolumeStage::start(bytes, "pin_before_repack");
    let first_page = first_page(&source.store, root.regions[0], &source.original);
    let handle = source
        .store
        .backend
        .read_with_boundary(&source.original, first_page, None, &mut || Ok(()))
        .unwrap();
    let scope = source.original.enter();
    let mut pinned = handle.open_with_boundary(&mut || Ok(())).unwrap();
    let repack = source.admin.packed_repack();
    pin.finish(format_args!("object={first_page}"));
    let repack_plan = VolumeStage::start(bytes, "repack_plan");
    let plan = repack[0]
        .plan_repack_with_boundary(&source.original, &mut || Ok(()))
        .unwrap();
    repack_plan.finish(format_args!("expected_objects={objects}"));
    let repack_apply = VolumeStage::start(bytes, "repack_apply");
    let report = repack[0]
        .apply_repack_with_boundary(&source.original, &plan, &mut || Ok(()))
        .unwrap();
    assert_eq!(report.before().logical_objects(), objects);
    assert_eq!(report.after().logical_objects(), objects);
    repack_apply.finish(format_args!(
        "before_objects={} after_objects={}",
        report.before().logical_objects(),
        report.after().logical_objects(),
    ));
    let pinned_read = VolumeStage::start(bytes, "pinned_read_after_repack");
    let mut hasher = crate::content_store::content_hasher(
        first_page.kind(),
        first_page.schema_version(),
        handle.logical_length(),
    );
    let mut buffer = [0_u8; 4096];
    let mut count = 0;
    loop {
        let n = pinned
            .read_with_boundary(&mut buffer, &mut || Ok(()))
            .unwrap();
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
        count += n as u64;
    }
    assert_eq!(count, handle.logical_length());
    assert_eq!(*hasher.finalize().as_bytes(), first_page.digest());
    pinned_read.finish(format_args!("bytes={count}"));
    drop((pinned, handle, scope));
    assert_restored(&source, &root, pages, "source_restore_after_repack");
    if source_cache.is_some() {
        let cold = crate::content_store::packed_read_costs();
        assert_eq!(cold.lookups, objects - 1);
        assert!(cold.authenticated_manifests > 0);
        assert!(cold.authenticated_manifests <= report.after().packs());
        assert!(cold.authenticated_rows <= objects);

        // Keep the entire lifecycle's cache live: no stage flush may make the
        // repacked working set appear smaller than its real overlapping debt.
        assert_restored(&source, &root, pages, "source_restore_after_repack_warm");
        let warm = crate::content_store::packed_read_costs();
        assert_eq!(warm.lookups, cold.lookups);
        assert_eq!(warm.pack_switches, cold.pack_switches);
        assert_eq!(warm.authenticated_manifests, 0);
        assert_eq!(warm.authenticated_rows, 0);
        assert_eq!(warm.authenticated_manifest_bytes, 0);
    }

    // Reopening authenticates the complete persisted generation under the
    // same finite namespace bank, independently of the still-live old graph.
    let reopen = VolumeStage::start(bytes, "reopen");
    let restarted = match &source_cache {
        Some(shared) => shared.reopen_fixture(source_directory),
        None => Fixture::with_quota(source_directory, source.quota.clone()),
    };
    assert_eq!(restarted.objects(), objects);
    let reopened = restarted
        .store
        .open_with_metadata_resources(root.lease.clone(), &source.original, &mut || Ok(()))
        .unwrap();
    assert_eq!(reopened.object_id(), root.object_id());
    reopen.finish(format_args!(
        "objects={objects} root={}",
        reopened.object_id()
    ));
    assert_restored(&restarted, &reopened, pages, "reopened_restore");
    if source_cache.is_some() {
        let reopened_cost = crate::content_store::packed_read_costs();
        assert_eq!(reopened_cost.lookups, objects - 1);
        assert_eq!(reopened_cost.authenticated_manifests, 0);
    }
    drop((reopened, restarted));

    // Complete authenticated marking is streamed under actual GC exclusion.
    // One explicit non-RAM orphan is the only deletion candidate; this fixture
    // does not claim the daemon's complete campaign collection planner.
    let orphan_publication = VolumeStage::start(bytes, "orphan_publication");
    let orphan_bytes = b"packed-volume-unreachable-trace";
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, orphan_bytes);
    let orphan_source = BlobHandle::from_bytes(orphan_bytes.to_vec());
    let publication = source
        .store
        .backend
        .put_many_if_absent_with_boundary(&source.original, &[(orphan, orphan_source)], &mut || {
            Ok(())
        })
        .unwrap();
    let accepted = publication.accept_with_boundary(&mut || Ok(())).unwrap();
    drop(accepted);
    orphan_publication.finish(format_args!("objects=1"));
    let marking = VolumeStage::start(bytes, "mark_reachable");
    let ref_fence = source.ref_admin.acquire_ref_inventory_fence().unwrap();
    let mut reachable = 0;
    source
        .store
        .visit_inventory_graph(
            root.object_id(),
            ref_fence.as_ref(),
            &source.original,
            &mut || Ok(()),
            &mut |id| {
                assert_ne!(id, orphan);
                reachable += 1;
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(reachable, objects);
    marking.finish(format_args!("objects={reachable}"));
    let physical_inventory = VolumeStage::start(bytes, "physical_inventory");
    let physical = source.admin.physical();
    let inventory_scope = source.original.enter();
    let mut inventory = physical[0]
        .admin()
        .acquire_inventory_fence_with_boundary(&mut || Ok(()))
        .unwrap();
    let mut counted = 0;
    let summary = inventory
        .visit_inventory_with_boundary(
            &mut |_| {
                counted += 1;
                Ok(())
            },
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(counted, objects + 1);
    physical_inventory.finish(format_args!("objects={counted}"));
    drop(summary);
    let deletion = VolumeStage::start(bytes, "delete_orphan");
    let deleted = inventory
        .delete_candidates_with_boundary(&[orphan], &mut || Ok(()))
        .unwrap();
    drop((deleted, inventory, inventory_scope, ref_fence));
    deletion.finish(format_args!("candidate_objects=1"));
    let final_accounting = VolumeStage::start(bytes, "final_accounting");
    assert_eq!(source.objects(), objects);
    final_accounting.finish(format_args!("objects={objects}"));
    assert_restored(&source, &root, pages, "source_final_restore");
    source.original.verify_live().unwrap();
    destination.original.verify_live().unwrap();
    if let Some(shared) = source_cache {
        shared.assert_reclaimed();
    }
    if let Some(shared) = destination_cache {
        shared.assert_reclaimed();
    }
}

// A start record locates interrupted stages; only completed stages have an end
// record. These measurements neither renew an original nor certify performance.
struct VolumeStage {
    name: &'static str,
    started: Option<std::time::Instant>,
}

// crucible-lint: allow clippy-disallowed-method -- fixture stage timing reports progress without supplying operational time.
#[allow(
    clippy::disallowed_methods,
    reason = "Reports fixture stage durations without supplying guest or operational time."
)]
impl VolumeStage {
    fn start(bytes: u64, name: &'static str) -> Self {
        crate::content_store::reset_packed_read_costs();
        let started = if bytes == VOLUME_BYTES {
            // crucible-lint: allow direct-diagnostic -- fixed workload progress only.
            eprintln!("packed_volume_stage_begin={name}");
            Some(std::time::Instant::now())
        } else {
            None
        };
        Self { name, started }
    }

    fn finish(self, counts: std::fmt::Arguments<'_>) {
        if let Some(started) = self.started {
            // crucible-lint: allow direct-diagnostic -- completed fixed workload stage only.
            eprintln!(
                "packed_volume_stage_end={} elapsed_ns={} {counts} packed_read_costs={:?}",
                self.name,
                started.elapsed().as_nanos(),
                crate::content_store::packed_read_costs(),
            );
        }
    }
}

fn first_page(store: &RamStore, mut reference: TreeRef, original: &DecodeBudget) -> ContentId {
    let mut boundary = || Ok(());
    let mut work = Work::new(store.limits, original, &mut boundary).unwrap();
    loop {
        match store.read_tree(reference, &mut work).unwrap() {
            TreeNode::Branch { left, .. } => reference = left,
            TreeNode::Leaf { page, .. } => return page,
            TreeNode::Padding => panic!("incompressible volume has no padding"),
        }
    }
}

fn assert_restored(fixture: &Fixture, root: &LeasedRamRoot, pages: u64, stage: &'static str) {
    let timing = VolumeStage::start(pages * 4096, stage);
    let mut restored = 0;
    let report = fixture
        .store
        .visit_pages(
            root,
            &fixture.original,
            &mut || Ok(()),
            &mut |_, index, bytes| {
                let mut expected = [0_u8; 4096];
                fill_page(index, &mut expected);
                assert_eq!(bytes, expected);
                assert_eq!(index, restored);
                restored += 1;
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(restored, pages);
    assert_eq!(report.pages, pages);
    assert_eq!(report.logical_bytes, pages * 4096);
    timing.finish(format_args!(
        "pages={} logical_bytes={} object_visits={}",
        report.pages, report.logical_bytes, report.object_visits,
    ));
}

fn capture_pages(fixture: &Fixture, pages: u64) -> LeasedRamRoot {
    let retention = fixture.retention();
    fixture
        .store
        .capture(
            topology(pages * 4096),
            Scope::Exact,
            &mut random_page,
            &retention,
            &fixture.original,
            &mut || Ok(()),
        )
        .unwrap()
}

#[test]
fn page_traversal_preserves_order_lengths_and_linear_object_visits() {
    let directory = tempfile::tempdir().unwrap();
    let fixture = Fixture::new(directory.path());
    let root = capture_pages(&fixture, 8);
    let baseline = fixture.quota.0.usage().unwrap();
    let mut visited = 0;

    let report = fixture
        .store
        .visit_pages(
            &root,
            &fixture.original,
            &mut || Ok(()),
            &mut |region, index, bytes| {
                assert_eq!(region.id(), "main");
                assert_eq!(index, visited);
                let mut expected = [0_u8; 4096];
                fill_page(index, &mut expected);
                assert_eq!(bytes, expected);
                visited += 1;
                Ok(())
            },
        )
        .unwrap();

    assert_eq!(report.pages, 8);
    assert_eq!(report.logical_bytes, 8 * 4096);
    assert_eq!(report.object_visits, 15 + 8);
    assert_eq!(visited, 8);
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
    assert_eq!(
        fixture
            .store
            .verify(&root, &fixture.original, &mut || Ok(()))
            .unwrap(),
        report
    );
}

#[test]
fn page_traversal_final_visitor_refusal_keeps_the_original_failure_and_closes_storage() {
    let directory = tempfile::tempdir().unwrap();
    let fixture = Fixture::new(directory.path());
    let root = capture_pages(&fixture, 3);
    let baseline = fixture.quota.0.usage().unwrap();
    let operation = fixture.original.child().unwrap();
    let mut visited = 0;

    let error = fixture
        .store
        .visit_pages(&root, &operation, &mut || Ok(()), &mut |_, index, _| {
            visited += 1;
            if index == 2 {
                operation.charge_bytes(u64::MAX).unwrap_err();
            }
            Ok(())
        })
        .unwrap_err();

    assert_eq!(visited, 3);
    assert!(operation.check().is_err());
    drop((error, operation));
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
    fixture.original.verify_live().unwrap();
}

#[test]
fn page_traversal_retains_the_typed_visitor_failure_without_visiting_later_pages() {
    let directory = tempfile::tempdir().unwrap();
    let fixture = Fixture::new(directory.path());
    let root = capture_pages(&fixture, 3);
    let baseline = fixture.quota.0.usage().unwrap();
    let mut visited = 0;

    let error = fixture
        .store
        .visit_pages(&root, &fixture.original, &mut || Ok(()), &mut |_, _, _| {
            visited += 1;
            Err(RamStoreError::Invalid("actual page visitor failure"))
        })
        .unwrap_err();

    let RamStoreError::Store(StoreError::RamValidation { source }) = &error else {
        panic!("actual visitor cause remains typed: {error:?}");
    };
    assert!(matches!(
        source.storage_failure(),
        RamStoreError::Invalid("actual page visitor failure")
    ));
    assert_eq!(visited, 1);
    drop(error);
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
}

#[test]
fn page_traversal_authenticates_later_page_bytes_after_the_reader_is_retained() {
    use std::os::unix::fs::FileExt;

    let directory = tempfile::tempdir().unwrap();
    let fixture = Fixture::new(directory.path());
    let root = capture_pages(&fixture, 3);
    let baseline = fixture.quota.0.usage().unwrap();
    let mut expected = [0_u8; 4096];
    fill_page(1, &mut expected);
    let (path, offset) = std::fs::read_dir(directory.path().join("objects/packs"))
        .unwrap()
        .filter_map(|entry| {
            let path = entry.unwrap().path();
            let bytes = std::fs::read(&path).unwrap();
            bytes
                .windows(expected.len())
                .position(|bytes| bytes == expected)
                .map(|offset| (path, offset))
        })
        .next()
        .expect("the real second page exists in a physical pack");
    let mut visited = 0;

    let error = fixture
        .store
        .visit_pages(
            &root,
            &fixture.original,
            &mut || Ok(()),
            &mut |_, index, _| {
                visited += 1;
                if index == 0 {
                    let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
                    file.write_all_at(&[expected[0] ^ 1], offset as u64)
                        .unwrap();
                }
                Ok(())
            },
        )
        .unwrap_err();

    assert_eq!(visited, 1);
    drop(error);
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
}
