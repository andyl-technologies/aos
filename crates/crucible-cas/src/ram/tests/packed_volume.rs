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

const VOLUME_BYTES: u64 = 512 << 20;
const VOLUME_PAGES: u64 = VOLUME_BYTES / 4096;
const VOLUME_OBJECTS: u64 = 3 * VOLUME_PAGES;

struct Binder(Arc<FixtureRamQuota>);

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
        let quota = Arc::new(FixtureRamQuota(
            crate::content_store::test_resources::FixtureResourceBudget::new(128, 256 << 20),
        ));
        Self::with_quota(root, quota)
    }

    fn with_quota(root: &Path, quota: Arc<FixtureRamQuota>) -> Self {
        let physical = StoreNodeId::new("physical").unwrap();
        let packed = StoreNodeId::new("packed").unwrap();
        let policy = StorePhysicalQuotaPolicyId::new("model/packed-volume").unwrap();
        let mut binders = StoreGraphPhysicalQuotaBinders::new();
        binders
            .insert(
                policy.clone(),
                StorePhysicalQuotaBinderHandle::new(Binder(quota.clone())),
            )
            .unwrap();
        let (graph, admin) = StoreGraph::build_with_admin_and_all_capabilities(
            StoreGraphConfig {
                gc_mark_root: None,
                root: physical.clone(),
                admitted_kinds: BTreeSet::from([
                    ObjectKind::RamExtent,
                    ObjectKind::RamTree,
                    ObjectKind::ExactManifest,
                    ObjectKind::Trace,
                ]),
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

fn exercise_volume(bytes: u64) {
    let source_directory = tempfile::tempdir().unwrap();
    let destination_directory = tempfile::tempdir().unwrap();
    let source = Fixture::new(source_directory.path());
    let destination = Fixture::new(destination_directory.path());
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
    drop(source_retention);
    assert_eq!(source.objects(), objects);
    // crucible-lint: allow direct-diagnostic -- this fixed volume fixture reports completed stages, not performance qualification.
    eprintln!("packed volume captured: bytes={bytes} objects={objects}");
    assert_restored(&source, &root, pages);

    let destination_retention = destination.retention();
    let owning_manifest =
        ContentId::for_bytes(ObjectKind::ExactManifest, 6, b"packed volume archive owner");
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
    assert_eq!(destination.objects(), objects);
    assert_restored(&destination, archive.root(), pages);
    // crucible-lint: allow direct-diagnostic -- this fixed volume fixture reports completed stages, not performance qualification.
    eprintln!("packed volume archived and restored: objects={objects}");
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
    drop((repeated, destination_retention));

    // The old source's already-open pack inode must outlive repack unlink.
    let first_page = first_page(&source.store, root.regions[0], &source.original);
    let handle = source
        .store
        .backend
        .read_with_boundary(&source.original, first_page, None, &mut || Ok(()))
        .unwrap();
    let scope = source.original.enter();
    let mut pinned = handle.open_with_boundary(&mut || Ok(())).unwrap();
    let repack = source.admin.packed_repack();
    let plan = repack[0]
        .plan_repack_with_boundary(&source.original, &mut || Ok(()))
        .unwrap();
    let report = repack[0]
        .apply_repack_with_boundary(&source.original, &plan, &mut || Ok(()))
        .unwrap();
    assert_eq!(report.before().logical_objects(), objects);
    assert_eq!(report.after().logical_objects(), objects);
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
    drop((pinned, handle, scope));
    assert_restored(&source, &root, pages);

    // Reopening authenticates the complete persisted generation under the
    // same finite namespace bank, independently of the still-live old graph.
    let restarted = Fixture::with_quota(source_directory.path(), source.quota.clone());
    assert_eq!(restarted.objects(), objects);
    let reopened = restarted
        .store
        .open_with_metadata_resources(root.lease.clone(), &source.original, &mut || Ok(()))
        .unwrap();
    assert_eq!(reopened.object_id(), root.object_id());
    assert_restored(&restarted, &reopened, pages);
    drop((reopened, restarted));

    // Complete authenticated marking is streamed under actual GC exclusion.
    // One explicit non-RAM orphan is the only deletion candidate; this fixture
    // does not claim the daemon's complete campaign collection planner.
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
    drop(summary);
    let deleted = inventory
        .delete_candidates_with_boundary(&[orphan], &mut || Ok(()))
        .unwrap();
    drop((deleted, inventory, inventory_scope, ref_fence));
    assert_eq!(source.objects(), objects);
    assert_restored(&source, &root, pages);
    source.original.verify_live().unwrap();
    destination.original.verify_live().unwrap();
    // crucible-lint: allow direct-diagnostic -- this fixed volume fixture reports completed stages, not performance qualification.
    eprintln!("packed volume repacked and fenced maintenance complete: objects={objects}");
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

fn assert_restored(fixture: &Fixture, root: &LeasedRamRoot, pages: u64) {
    let mut boundary = || Ok(());
    let mut work = Work::new(fixture.store.limits, &fixture.original, &mut boundary).unwrap();
    let mut restored = 0;
    restore_tree(&fixture.store, root.regions[0], 0, &mut restored, &mut work);
    assert_eq!(restored, pages);
}

fn restore_tree(
    store: &RamStore,
    reference: TreeRef,
    first: u64,
    restored: &mut u64,
    work: &mut Work<'_>,
) {
    match store.read_tree(reference, work).unwrap() {
        TreeNode::Padding => panic!("power-of-two incompressible volume has no padding"),
        TreeNode::Leaf { page, digest } => {
            let stored = store.read_page_object(page, digest, work).unwrap();
            let mut expected = [0_u8; 4096];
            fill_page(first, &mut expected);
            assert_eq!(stored.bytes(), expected);
            *restored += 1;
        }
        TreeNode::Branch { left, right } => {
            restore_tree(store, left, first, restored, work);
            restore_tree(
                store,
                right,
                first + (1_u64 << (reference.height - 1)),
                restored,
                work,
            );
        }
    }
}
