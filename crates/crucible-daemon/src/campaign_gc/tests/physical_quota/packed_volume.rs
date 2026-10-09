//! Real daemon marking and deletion of a unique-page Packed RAM volume.
//!
//! Capture and GC borrow the same existing 256MiB/128-descriptor fixture bank.
//! The daemon's disk-backed mark tree owns membership; this fixture retains
//! scalar counts and three page proofs rather than a closure-sized collection.
//! The portable binder does not certify installed filesystem or process quotas.

use super::*;
use crucible_api::host_operational::{
    HostRamCaptureScope as Scope, HostRamInventoryLimits as Limits,
    HostRamInventoryRegion as RegionDescriptor, HostRamInventoryRegionClass as RegionClass,
    HostRamInventoryTopology as Topology,
};
use crucible_cas::content_store::{DurabilityRequirement, StorePhysicalQuotaBinderHandle};
use crucible_cas::owned_decode::DecodeBudget;
use crucible_cas::ram::{RamStore, RamStoreLimits};

const PAGE_BYTES: u64 = 4096;
const VOLUME_BYTES: u64 = 512 << 20;
const VOLUME_OBJECTS: u64 = 393_216;

#[test]
fn packed_unique_page_component_gc_retains_root_and_physically_removes_orphan() {
    exercise_volume(8 * PAGE_BYTES);
}

#[test]
fn packed_unique_page_512_mib_gc_retains_root_and_physically_removes_orphan() {
    exercise_volume(VOLUME_BYTES);
}

fn exercise_volume(bytes: u64) {
    let directory = tempfile::tempdir().expect("Packed GC volume");
    let guard = Arc::new(ToggleQuotaGuard::new());
    assert_eq!(guard.resources.maximum_resident_bytes(), 256 << 20);
    assert_eq!(guard.resources.maximum_file_descriptors(), 128);
    let (graph, admin) = packed_graph(directory.path(), guard.clone());
    let graph = Arc::new(graph);
    let original = DecodeBudget::for_store(guard.clone()).expect("original shared volume account");
    let (refs, ref_admin) = DirectoryRefBackend::new_with_physical_quota_and_admin(
        directory.path().join("refs"),
        guard.clone(),
    )
    .expect("same-account retention namespace");
    let repository = CampaignRepository::new(
        graph.clone(),
        refs,
        crucible_campaign::CampaignRamAdmission::Available(original.clone()),
    );
    let ram = RamStore::new(
        graph.clone(),
        DurabilityRequirement::new(1, false).expect("durable RAM publication"),
        RamStoreLimits::default(),
    )
    .expect("Packed RAM store");
    let topology = Topology::new(
        vec![
            RegionDescriptor::new("machine.ram", RegionClass::MutableMain, bytes)
                .expect("volume descriptor"),
        ],
        Limits::default(),
    )
    .expect("volume topology");
    ram.admit_ram_publication(&topology, Scope::Exact)
        .expect("original volume admission");
    let publication = repository
        .ram_retention_authority()
        .acquire()
        .expect("actual RAM publication fence");
    let capture = original.child().expect("same-bank capture operation");
    let root = ram
        .capture(
            topology,
            Scope::Exact,
            &mut |_, index, buffer| {
                fill_page(index, buffer);
                Ok(())
            },
            &publication,
            &capture,
            &mut || Ok(()),
        )
        .expect("unique-page volume capture");
    let retained = root.clone();
    drop((root, publication, capture));

    let pages = bytes / PAGE_BYTES;
    let expected_objects = 3 * pages;
    if bytes == VOLUME_BYTES {
        assert_eq!(pages, 131_072);
        assert_eq!(expected_objects, VOLUME_OBJECTS);
    }
    let packs = directory.path().join("objects/packs");
    let retained_storage = physical_pack_totals(&packs);
    let orphan_bytes = b"daemon-packed-volume-unreachable-trace";
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, orphan_bytes);
    let receipt = graph
        .put_many_if_absent_with_boundary(
            &original,
            &[(orphan, BlobHandle::from_bytes(orphan_bytes.to_vec()))],
            &mut || Ok(()),
        )
        .expect("separate orphan pack publication");
    drop(
        receipt
            .accept_with_boundary(&mut || Ok(()))
            .expect("durable orphan receipt"),
    );
    let with_orphan = physical_pack_totals(&packs);
    assert_eq!(with_orphan.0, retained_storage.0 + 1);
    assert!(with_orphan.1 > retained_storage.1);

    // The existing 300-second maintenance scope begins once and spans both
    // actual daemon phases. Capture creates no replacement GC deadline.
    let mut fixture = crate::campaign_gc::ComponentGcOperation::with_resources(guard.clone());
    let operation = fixture.context();
    let mut ledger = MemoryAssignmentLedger::default();
    let prepared = super::super::super::plan_single_host_campaign_gc(
        &repository,
        ref_admin.as_ref(),
        &mut ledger,
        None,
        None,
        crate::campaign_gc::CampaignGcMaintenance::new(&admin, &operation),
    )
    .expect("daemon authenticates the complete RAM closure");
    assert_eq!(prepared.reachable_objects(), expected_objects);
    assert_eq!(prepared.roots().iter().count(), 1);
    assert_eq!(prepared.roots().iter().next(), Some(retained.object_id()));
    assert_eq!(prepared.candidates().len(), 1);
    assert_eq!(
        prepared.candidates().iter().next().expect("orphan").id(),
        orphan
    );
    let (mut journal, _) =
        DirectoryCampaignGcJournal::create(directory.path().join("journal"), &prepared, &operation)
            .expect("daemon planned journal");
    let report = super::super::super::apply_single_host_campaign_gc(
        &mut journal,
        &repository,
        ref_admin.as_ref(),
        &mut ledger,
        None,
        None,
        crate::campaign_gc::CampaignGcMaintenance::new(&admin, &operation),
    )
    .expect("daemon applies the same authenticated plan");
    assert_eq!(report.status(), CampaignGcApplyStatus::Applied);
    assert_eq!(report.candidates(), 1);
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Complete);
    assert!(
        !graph
            .contains(orphan)
            .expect("orphan absent after daemon GC")
    );
    assert_eq!(physical_pack_totals(&packs), retained_storage);

    let accounting = admin.packed_repack()[0]
        .accounting_with_boundary(operation.original(), &mut || operation.check())
        .expect("same-original complete Packed accounting");
    assert_eq!(accounting.logical_objects(), expected_objects);
    assert_eq!(accounting.packs(), retained_storage.0);
    assert_eq!(accounting.physical_bytes(), retained_storage.1);
    for index in [0, pages / 2, pages - 1] {
        let page = ram
            .read_page_with_proof(
                &retained,
                "machine.ram",
                index,
                operation.original(),
                &mut || operation.check().map_err(Into::into),
            )
            .expect("retained root still authenticates its actual page");
        let mut expected = [0; PAGE_BYTES as usize];
        fill_page(index, &mut expected);
        assert_eq!(page.bytes(), expected);
        page.proof()
            .verify(page.bytes(), retained.record(), retained.logical_digest())
            .expect("retained canonical page proof");
    }
    operation
        .check()
        .expect("same GC deadline and resources remain live");
}

fn packed_graph(
    root: &Path,
    guard: Arc<ToggleQuotaGuard>,
) -> (StoreGraph, crucible_cas::content_store::StoreGraphAdmin) {
    let physical = StoreNodeId::new("physical").expect("physical node");
    let packed = StoreNodeId::new("packed").expect("Packed node");
    let policy = StorePhysicalQuotaPolicyId::new("model/packed-gc-volume").expect("quota policy");
    let mut binders = StoreGraphPhysicalQuotaBinders::new();
    binders
        .insert(
            policy.clone(),
            StorePhysicalQuotaBinderHandle::new(ToggleQuotaBinder { guard }),
        )
        .expect("same original quota binder");
    StoreGraph::build_with_admin_and_all_capabilities(
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
                        project_id: 47,
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
    .expect("actual PhysicalQuota-to-Packed graph")
}

fn fill_page(index: u64, bytes: &mut [u8]) {
    let mut hash = blake3::Hasher::new();
    hash.update(b"packed-volume-page");
    hash.update(&index.to_be_bytes());
    hash.finalize_xof().fill(bytes);
}

fn physical_pack_totals(packs: &Path) -> (u64, u64) {
    std::fs::read_dir(packs)
        .expect("physical pack directory")
        .try_fold((0_u64, 0_u64), |(count, bytes), entry| {
            let metadata = entry?.metadata()?;
            assert!(metadata.is_file());
            Ok::<_, std::io::Error>((count + 1, bytes + metadata.len()))
        })
        .expect("physical pack file lengths")
}
