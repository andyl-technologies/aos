//! Bounded deletion plans over larger physical inventories.

use super::*;

#[test]
fn larger_inventory_keeps_live_root_and_continues_in_a_fresh_batch() {
    let mut gc_fixture = crate::campaign_gc::ComponentGcOperation::new();
    let gc_operation = gc_fixture.context();

    let node = StoreNodeId::new("batch-primary").expect("physical node");
    let (graph, admin) = StoreGraph::build_with_admin(StoreGraphConfig {
        root: node.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
        nodes: BTreeMap::from([(
            node,
            StoreNodeSpec::Memory {
                max_logical_bytes: 2 * 1024 * 1024,
            },
        )]),
    })
    .expect("memory graph");
    let graph = Arc::new(graph);
    let refs = Arc::new(MemoryRefBackend::new());
    let repository = CampaignRepository::new(graph.clone(), refs.clone());
    let live = ContentEnvelope::new(
        "crucible.test.gc.retained-batch-root",
        1,
        BTreeSet::new(),
        b"live".to_vec(),
    )
    .expect("live envelope");
    let live_id = live.content_id(ObjectKind::Trace);
    graph
        .put_if_absent(live_id, &BlobHandle::from_bytes(live.canonical_bytes()))
        .expect("store live object");
    refs.compare_exchange(
        &RefName::new("retained/batch-root").expect("live ref"),
        None,
        live_id,
    )
    .expect("publish live root");
    for index in 0..=MAX_CAMPAIGN_GC_MANIFEST_ENTRIES {
        let bytes = (index as u64).to_le_bytes();
        let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
        graph
            .put_if_absent(id, &BlobHandle::from_bytes(bytes))
            .expect("store orphan");
    }

    let mut ledger = MemoryAssignmentLedger::default();
    let first = super::super::plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        crate::campaign_gc::CampaignGcMaintenance::new(&admin, &gc_operation),
    )
    .expect("bounded first batch");
    assert_eq!(first.candidates().len(), MAX_CAMPAIGN_GC_MANIFEST_ENTRIES);
    assert_eq!(first.reachable_objects(), 1);
    assert!(first.candidates().iter().all(|entry| entry.id() != live_id));

    // Simulate completion by deleting exactly the admitted batch under the
    // physical authority. The next plan must rediscover the remaining orphan.
    let leaves = admin.physical();
    let mut fence = leaves[0]
        .admin()
        .acquire_inventory_fence()
        .expect("physical fence");
    for candidate in first.candidates().iter() {
        fence
            .delete_candidate(candidate.id())
            .expect("delete batch");
    }
    drop(fence);

    let second = super::super::plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        crate::campaign_gc::CampaignGcMaintenance::new(&admin, &gc_operation),
    )
    .expect("fresh continuation batch");
    assert_eq!(second.candidates().len(), 1);
    assert!(
        second
            .candidates()
            .iter()
            .all(|entry| entry.id() != live_id)
    );
    assert!(graph.contains(live_id).expect("live object remains"));
}
