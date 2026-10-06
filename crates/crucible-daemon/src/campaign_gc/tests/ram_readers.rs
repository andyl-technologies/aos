//! GC retains each lazy reader's authenticated RAM graph without freezing unrelated collection.

use super::*;
use crucible_api::host_operational::{
    HostRamCaptureScope as Scope, HostRamInventoryLimits as Limits,
    HostRamInventoryRegion as RegionDescriptor, HostRamInventoryRegionClass as RegionClass,
    HostRamInventoryTopology as Topology,
};
use crucible_cas::ram::{RamStore, RamStoreLimits};

#[test]
fn live_lazy_ram_reader_and_fork_allow_unrelated_gc_then_release_the_exact_graph() {
    let directory = tempfile::tempdir().expect("reader storage");
    let blobs = Arc::new(DirectoryBlobBackend::new(
        "reader-gc",
        directory.path().join("objects"),
    ));
    let refs = Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let repository = CampaignRepository::new(blobs.clone(), refs.clone());
    let ram = RamStore::new(
        blobs.clone(),
        crucible_cas::content_store::DurabilityRequirement::new(1, false).expect("durable reader"),
        RamStoreLimits::default(),
    )
    .expect("RAM store");
    let publication = repository
        .ram_retention_authority()
        .acquire()
        .expect("short publication fence");
    let topology = Topology::new(
        vec![
            RegionDescriptor::new("machine.ram", RegionClass::MutableMain, 4096 * 5 + 19)
                .expect("RAM descriptor"),
        ],
        Limits::default(),
    )
    .expect("topology");
    let source = ram
        .capture(
            topology,
            Scope::Exact,
            &mut |_, index, bytes| {
                bytes.fill((index + 1) as u8);
                Ok(())
            },
            &publication,
            &mut || Ok(()),
        )
        .expect("root publication");
    let fork = source.clone();
    drop(publication);

    let orphan_bytes = b"unrelated reclaimable object".to_vec();
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, &orphan_bytes);
    blobs
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes))
        .expect("unrelated object");
    let physical =
        CampaignGcRawPhysicalStore::new("reader-gc", blobs.as_ref()).expect("physical authority");
    let graph = hash("crucible.test.reader-gc.graph.v1", 0x31);
    let mut ledger = MemoryAssignmentLedger::default();
    let prepared = plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        graph,
        &[physical],
    )
    .expect("GC inventory proceeds while lazy source and fork exist");
    assert_eq!(
        prepared.roots().iter().collect::<Vec<_>>(),
        vec![source.object_id()]
    );
    assert_eq!(prepared.candidates().len(), 1);
    assert_eq!(
        prepared.candidates().iter().next().expect("orphan").id(),
        orphan
    );
    let (mut journal, _) =
        DirectoryCampaignGcJournal::create(directory.path().join("first-gc"), &prepared)
            .expect("first GC journal");
    let report = apply_single_host_campaign_gc(
        &mut journal,
        CampaignGcApplySources::new(&repository, refs.as_ref(), &mut ledger, None, None),
        graph,
        &[physical],
    )
    .expect("unrelated object is collectible during lazy reads");
    assert_eq!(report.status(), CampaignGcApplyStatus::Applied);
    assert!(!blobs.contains(orphan).expect("orphan absent"));

    drop(source);
    let (bytes, proof) = ram
        .read_page_with_proof(&fork, "machine.ram", 5, &mut || Ok(()))
        .expect("fork still reads actual retained tail page");
    assert_eq!(bytes, vec![6; 19]);
    proof
        .verify(&bytes, fork.record(), fork.logical_digest())
        .expect("retained page proof");
    let root = fork.object_id();
    drop(fork);

    let released = plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        graph,
        &[physical],
    )
    .expect("last reader releases only its exact graph");
    assert!(released.roots().iter().next().is_none());
    assert!(
        released
            .candidates()
            .iter()
            .any(|candidate| candidate.id() == root)
    );
    let (mut journal, _) =
        DirectoryCampaignGcJournal::create(directory.path().join("released-gc"), &released)
            .expect("released GC journal");
    apply_single_host_campaign_gc(
        &mut journal,
        CampaignGcApplySources::new(&repository, refs.as_ref(), &mut ledger, None, None),
        graph,
        &[physical],
    )
    .expect("released graph reclaimed");
    assert!(!blobs.contains(root).expect("released root absent"));
}
