//! Campaign-store composition matrix gate.
//!
//! The matrix permutes the transparent verification, metrics, and durability
//! layers over a routed graph whose branches exercise mirrored durable writes,
//! memory-to-directory tiers, durable deferred transfer, packing, physical
//! administration, and restart.

// crucible-lint: allow panic-shortcut -- gate assertions identify the violated composition invariant.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};

use crucible_cas::content_store::{
    BlobHandle, ByteRange, DurabilityRequirement, ImmutableBlobBackend, ObjectKind,
    PackedBlobBackend, PlannedDeleteDisposition, StoreError, StoreGraph, StoreGraphConfig,
    StoreGraphPhysicalRetention, StoreNodeId, StoreNodeSpec, StoreTierPolicy,
    WriteBackRetentionAdmin,
};
use tempfile::TempDir;

const PACK_TARGET_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy)]
enum TransparentLayer {
    Durability,
    Metrics,
    Verified,
}

const ALLOWED_LAYER_ORDERS: [[TransparentLayer; 3]; 6] = [
    [
        TransparentLayer::Durability,
        TransparentLayer::Metrics,
        TransparentLayer::Verified,
    ],
    [
        TransparentLayer::Durability,
        TransparentLayer::Verified,
        TransparentLayer::Metrics,
    ],
    [
        TransparentLayer::Metrics,
        TransparentLayer::Durability,
        TransparentLayer::Verified,
    ],
    [
        TransparentLayer::Metrics,
        TransparentLayer::Verified,
        TransparentLayer::Durability,
    ],
    [
        TransparentLayer::Verified,
        TransparentLayer::Durability,
        TransparentLayer::Metrics,
    ],
    [
        TransparentLayer::Verified,
        TransparentLayer::Metrics,
        TransparentLayer::Durability,
    ],
];

#[test]
fn allowed_layer_orders_preserve_ids_errors_durability_and_restart() {
    let temporary = TempDir::new().expect("campaign-store composition roots");

    for (ordinal, order) in ALLOWED_LAYER_ORDERS.into_iter().enumerate() {
        assert_composition(temporary.path().join(ordinal.to_string()), order);
    }
}

#[test]
fn sqlite_leaf_preserves_authenticated_objects_and_physical_gc_after_restart() {
    let temporary = TempDir::new().expect("SQLite graph root");
    let leaf = node("sqlite");
    let config = StoreGraphConfig {
        root: leaf.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact]),
        nodes: BTreeMap::from([(
            leaf,
            StoreNodeSpec::Sqlite {
                root: temporary.path().join("objects"),
            },
        )]),
    };
    let bytes = b"durable campaign fact";
    let id = crucible_cas::content_store::ContentId::for_bytes(ObjectKind::CampaignFact, 1, bytes);

    let (graph, admin) = StoreGraph::build_with_admin(config.clone()).expect("SQLite graph");
    let sqlite_configuration = graph.configuration_id();
    let directory = StoreGraph::build(StoreGraphConfig {
        root: node("sqlite"),
        admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact]),
        nodes: BTreeMap::from([(
            node("sqlite"),
            StoreNodeSpec::Directory {
                root: temporary.path().join("objects"),
            },
        )]),
    })
    .expect("same path with a different leaf kind");
    assert_ne!(sqlite_configuration, directory.configuration_id());
    drop(directory);
    assert!(
        graph
            .put_if_absent(id, &BlobHandle::from_bytes(bytes))
            .expect("durable put")
            .is_durable()
    );
    assert_eq!(read_all(&graph, id), bytes);
    assert_eq!(admin.physical().len(), 1);
    drop(admin);
    drop(graph);

    let (restarted, admin) = StoreGraph::build_with_admin(config.clone()).expect("restarted graph");
    assert_eq!(restarted.configuration_id(), sqlite_configuration);
    assert_eq!(read_all(&restarted, id), bytes);
    let physical = admin.physical();
    let mut fence = physical[0]
        .admin()
        .acquire_inventory_fence()
        .expect("SQLite inventory fence");
    assert_eq!(
        fence
            .visit_inventory(&mut |_| Ok(()))
            .expect("complete physical inventory")
            .objects(),
        1
    );
    assert_eq!(
        fence.delete_candidate(id).expect("planned GC deletion"),
        PlannedDeleteDisposition::Deleted
    );
    drop(fence);
    drop(physical);
    drop(admin);
    drop(restarted);

    let (reopened, admin) = StoreGraph::build_with_admin(config).expect("reopen after GC");
    assert!(
        !reopened
            .contains(id)
            .expect("deleted object remains absent")
    );
    let physical = admin.physical();
    let mut fence = physical[0]
        .admin()
        .acquire_inventory_fence()
        .expect("reopened inventory fence");
    assert_eq!(
        fence
            .visit_inventory(&mut |_| Ok(()))
            .expect("reopened physical inventory")
            .objects(),
        0
    );
}

fn assert_composition(root: std::path::PathBuf, order: [TransparentLayer; 3]) {
    let config = graph_config(&root, order);
    let (graph, admin) = StoreGraph::build_with_admin(config.clone()).expect("admitted graph");
    let fact_bytes = b"campaign-store composition fact";
    let fact =
        crucible_cas::content_store::ContentId::for_bytes(ObjectKind::CampaignFact, 1, fact_bytes);
    let ram_bytes = b"campaign-store composition RAM extent";
    let ram =
        crucible_cas::content_store::ContentId::for_bytes(ObjectKind::RamExtent, 1, ram_bytes);
    let finding_bytes = b"campaign-store composition deferred finding";
    let finding =
        crucible_cas::content_store::ContentId::for_bytes(ObjectKind::Finding, 1, finding_bytes);

    let fact_receipt = graph
        .put_if_absent(fact, &BlobHandle::from_bytes(fact_bytes))
        .expect("mirrored fact put");
    assert_eq!(fact_receipt.id, fact);
    assert_eq!(fact_receipt.durable_placements(), 2);

    let ram_receipt = graph
        .put_if_absent(ram, &BlobHandle::from_bytes(ram_bytes))
        .expect("tiered RAM put");
    assert_eq!(ram_receipt.id, ram);
    assert_eq!(ram_receipt.durable_placements(), 1);

    let cache = admin
        .physical()
        .into_iter()
        .find(|physical| physical.node().as_str() == "memory")
        .expect("tier cache administration");
    assert_eq!(
        cache.retention(ObjectKind::RamExtent),
        Some(StoreGraphPhysicalRetention::Cache)
    );
    assert!(matches!(cache.read(ram), Err(StoreError::NotFound { .. })));
    assert_eq!(read_all(&graph, ram), ram_bytes);
    assert_eq!(read_physical(cache, ram), ram_bytes);

    let mut cache_inventory = cache
        .admin()
        .acquire_inventory_fence()
        .expect("cache fence");
    assert_eq!(
        cache_inventory
            .delete_candidate(ram)
            .expect("evict reconstructible cache object"),
        PlannedDeleteDisposition::Deleted
    );
    drop(cache_inventory);
    assert!(matches!(cache.read(ram), Err(StoreError::NotFound { .. })));
    assert_eq!(read_all(&graph, ram), ram_bytes);
    assert_eq!(read_physical(cache, ram), ram_bytes);

    let finding_receipt = graph
        .put_if_absent(finding, &BlobHandle::from_bytes(finding_bytes))
        .expect("stage durable deferred finding");
    assert_eq!(finding_receipt.id, finding);
    assert_eq!(finding_receipt.durable_placements(), 1);
    let archive = admin
        .physical()
        .into_iter()
        .find(|physical| physical.node().as_str() == "packed")
        .expect("packed archive administration");
    assert_eq!(
        archive.retention(ObjectKind::Finding),
        Some(StoreGraphPhysicalRetention::Required)
    );
    assert!(matches!(
        archive.read(finding),
        Err(StoreError::NotFound { .. })
    ));

    let mut pending = graph
        .acquire_write_back_retention_fence()
        .expect("pending transfer fence");
    let mut pending_ids = Vec::new();
    let pending_summary = pending
        .visit_roots(&mut |root| {
            assert_eq!(root.node(), "write-back");
            assert_eq!(root.logical_length(), finding_bytes.len() as u64);
            pending_ids.push(root.id());
            Ok(())
        })
        .expect("pending transfer inventory");
    assert_eq!(pending_ids, vec![finding]);
    assert_eq!(pending_summary.roots(), 1);
    drop(pending);

    let range = ByteRange::new(2, 11).expect("bounded fact range");
    assert_eq!(
        graph
            .read(fact, Some(range))
            .expect("verified fact range")
            .read_all(range.length)
            .expect("read verified fact range"),
        fact_bytes[2..13]
    );

    for kind in [
        ObjectKind::CampaignFact,
        ObjectKind::RamExtent,
        ObjectKind::Finding,
    ] {
        let missing = crucible_cas::content_store::ContentId::for_bytes(kind, 1, b"missing");
        assert!(matches!(
            graph.read(missing, None),
            Err(StoreError::NotFound { id }) if id == missing
        ));
        assert!(matches!(
            graph.put_if_absent(missing, &BlobHandle::from_bytes(b"wrong bytes")),
            Err(StoreError::Corrupt { id }) if id == missing
        ));
    }
    let unadmitted =
        crucible_cas::content_store::ContentId::for_bytes(ObjectKind::Trace, 1, b"unadmitted");
    assert!(matches!(
        graph.read(unadmitted, None),
        Err(StoreError::InvalidGraph { .. })
    ));

    let physical_nodes = admin
        .physical()
        .into_iter()
        .map(|physical| physical.node().as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        physical_nodes,
        vec!["directory", "memory", "packed", "staging"]
    );
    let staging = admin
        .physical()
        .into_iter()
        .find(|physical| physical.node().as_str() == "staging")
        .expect("deferred staging administration");
    assert_eq!(
        staging.retention(ObjectKind::Finding),
        Some(StoreGraphPhysicalRetention::Cache)
    );
    assert_eq!(read_physical(staging, finding), finding_bytes);
    assert_eq!(graph.metrics().len(), 1);

    drop(admin);
    drop(graph);

    let packed = PackedBlobBackend::open("packed", root.join("packed"), PACK_TARGET_BYTES)
        .expect("reopen packed leaf");
    let repack = packed.plan_repack().expect("plan deterministic repack");
    packed
        .apply_repack(&repack)
        .expect("apply deterministic repack");
    assert_eq!(read_all(&packed, fact), fact_bytes);
    drop(packed);

    let (restarted, restarted_admin) =
        StoreGraph::build_with_admin(config.clone()).expect("restart admitted graph");
    assert_eq!(read_all(&restarted, fact), fact_bytes);
    assert_eq!(read_all(&restarted, ram), ram_bytes);
    assert_eq!(read_all(&restarted, finding), finding_bytes);
    let mut recovered = restarted
        .acquire_write_back_retention_fence()
        .expect("restarted pending transfer fence");
    let mut recovered_ids = Vec::new();
    let recovered_summary = recovered
        .visit_roots(&mut |root| {
            recovered_ids.push(root.id());
            Ok(())
        })
        .expect("recovered pending transfer inventory");
    assert_eq!(recovered_ids, vec![finding]);
    assert_eq!(recovered_summary.generation(), pending_summary.generation());
    drop(recovered);

    let flush = restarted
        .flush_write_back(1)
        .expect("complete deferred transfer");
    assert_eq!(flush.completed(), 1);
    assert_eq!(flush.pending(), 0);
    let mut completed = restarted
        .acquire_write_back_retention_fence()
        .expect("completed transfer fence");
    assert_eq!(
        completed
            .visit_roots(&mut |_| Ok(()))
            .expect("completed transfer inventory")
            .roots(),
        0
    );
    drop(completed);

    let packed = restarted_admin
        .packed_repack()
        .into_iter()
        .find(|physical| physical.node().as_str() == "packed")
        .expect("packed repack authority");
    assert_eq!(
        packed
            .accounting()
            .expect("packed accounting")
            .logical_objects(),
        2
    );
    let plan = packed.plan_repack().expect("packed repack plan");
    packed
        .apply_repack(&plan)
        .expect("packed repack after transfer");
    assert_eq!(read_all(&restarted, fact), fact_bytes);
    assert_eq!(read_all(&restarted, finding), finding_bytes);
    assert_eq!(restarted_admin.physical().len(), 4);

    drop(restarted_admin);
    drop(restarted);

    let (reopened, reopened_admin) =
        StoreGraph::build_with_admin(config).expect("reopen repacked graph");
    assert_eq!(read_all(&reopened, fact), fact_bytes);
    assert_eq!(read_all(&reopened, ram), ram_bytes);
    assert_eq!(read_all(&reopened, finding), finding_bytes);
    let packed = reopened_admin
        .packed_repack()
        .into_iter()
        .find(|physical| physical.node().as_str() == "packed")
        .expect("reopened packed accounting");
    assert_eq!(
        packed
            .accounting()
            .expect("reopened packed accounting")
            .logical_objects(),
        2
    );
}

fn graph_config(root: &std::path::Path, order: [TransparentLayer; 3]) -> StoreGraphConfig {
    let directory = node("directory");
    let memory = node("memory");
    let packed = node("packed");
    let staging = node("staging");
    let mirror = node("mirror");
    let tiers = node("tiers");
    let deferred = node("write-back");
    let routed = node("routed");
    let mut nodes = BTreeMap::from([
        (
            directory.clone(),
            StoreNodeSpec::Directory {
                root: root.join("directory"),
            },
        ),
        (
            memory.clone(),
            StoreNodeSpec::Memory {
                max_logical_bytes: 4 * 1024 * 1024,
            },
        ),
        (
            packed.clone(),
            StoreNodeSpec::Packed {
                root: root.join("packed"),
                target_pack_bytes: PACK_TARGET_BYTES,
            },
        ),
        (
            staging.clone(),
            StoreNodeSpec::Directory {
                root: root.join("staging"),
            },
        ),
        (
            mirror.clone(),
            StoreNodeSpec::WriteThrough {
                children: vec![directory.clone(), packed.clone()],
            },
        ),
        (
            tiers.clone(),
            StoreNodeSpec::Tiered {
                tiers: vec![
                    StoreTierPolicy {
                        child: memory,
                        readable: true,
                        writable: false,
                        promote_reads: true,
                    },
                    StoreTierPolicy {
                        child: directory,
                        readable: true,
                        writable: true,
                        promote_reads: false,
                    },
                ],
            },
        ),
        (
            deferred.clone(),
            StoreNodeSpec::WriteBack {
                staging,
                destination: packed,
                journal_root: root.join("journal"),
                maximum_pending_objects: 8,
                maximum_pending_bytes: 4 * 1024 * 1024,
            },
        ),
        (
            routed.clone(),
            StoreNodeSpec::Routed {
                routes: BTreeMap::from([
                    (ObjectKind::CampaignFact, mirror),
                    (ObjectKind::RamExtent, tiers),
                    (ObjectKind::Finding, deferred),
                ]),
            },
        ),
    ]);

    let admitted = BTreeSet::from([
        ObjectKind::CampaignFact,
        ObjectKind::RamExtent,
        ObjectKind::Finding,
    ]);
    let mut child = routed;
    for (depth, layer) in order.into_iter().enumerate() {
        let id = node(&format!("layer-{depth}"));
        let spec = match layer {
            TransparentLayer::Durability => StoreNodeSpec::DurabilityPolicy {
                child: child.clone(),
                requirements: BTreeMap::from([
                    (
                        ObjectKind::CampaignFact,
                        DurabilityRequirement::new(2, false).expect("fact durability"),
                    ),
                    (
                        ObjectKind::RamExtent,
                        DurabilityRequirement::new(1, false).expect("RAM durability"),
                    ),
                    (
                        ObjectKind::Finding,
                        DurabilityRequirement::new(1, true).expect("finding durability"),
                    ),
                ]),
            },
            TransparentLayer::Metrics => StoreNodeSpec::Metrics {
                child: child.clone(),
            },
            TransparentLayer::Verified => StoreNodeSpec::Verified {
                child: child.clone(),
            },
        };
        nodes.insert(id.clone(), spec);
        child = id;
    }

    StoreGraphConfig {
        root: child,
        admitted_kinds: admitted,
        nodes,
    }
}

fn read_all(
    backend: &dyn ImmutableBlobBackend,
    id: crucible_cas::content_store::ContentId,
) -> Vec<u8> {
    let handle = backend.read(id, None).expect("open authenticated object");
    handle
        .read_all(handle.logical_length())
        .expect("read authenticated object")
}

fn read_physical(
    physical: crucible_cas::content_store::StoreGraphPhysicalAdmin<'_>,
    id: crucible_cas::content_store::ContentId,
) -> Vec<u8> {
    let handle = physical.read(id).expect("open physical placement");
    handle
        .read_all(handle.logical_length())
        .expect("authenticate physical placement")
}

fn node(value: &str) -> StoreNodeId {
    StoreNodeId::new(value).expect("valid store node ID")
}
