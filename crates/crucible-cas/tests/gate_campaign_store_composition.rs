//! Campaign-store composition matrix gate.
//!
//! The matrix permutes the transparent verification, metrics, and durability
//! layers over a routed graph whose branches exercise mirrored durable writes,
//! memory-to-directory tiers, packing, promotion, physical administration,
//! and restart.

// crucible-lint: allow panic-shortcut -- gate assertions identify the violated composition invariant.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};

use crucible_cas::content_store::{
    BlobHandle, ByteRange, DurabilityRequirement, ImmutableBlobBackend, ObjectKind,
    PackedBlobBackend, StoreError, StoreGraph, StoreGraphConfig, StoreNodeId, StoreNodeSpec,
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

fn assert_composition(root: std::path::PathBuf, order: [TransparentLayer; 3]) {
    let config = graph_config(&root, order);
    let (graph, admin) = StoreGraph::build_with_admin(config.clone()).expect("admitted graph");
    let fact_bytes = b"campaign-store composition fact";
    let fact =
        crucible_cas::content_store::ContentId::for_bytes(ObjectKind::CampaignFact, 1, fact_bytes);
    let ram_bytes = b"campaign-store composition RAM extent";
    let ram =
        crucible_cas::content_store::ContentId::for_bytes(ObjectKind::RamExtent, 1, ram_bytes);

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
    assert_eq!(read_all(&graph, ram), ram_bytes);

    let range = ByteRange::new(2, 11).expect("bounded fact range");
    assert_eq!(
        graph
            .read(fact, Some(range))
            .expect("verified fact range")
            .read_all(range.length)
            .expect("read verified fact range"),
        fact_bytes[2..13]
    );

    let missing =
        crucible_cas::content_store::ContentId::for_bytes(ObjectKind::CampaignFact, 1, b"missing");
    assert!(matches!(
        graph.read(missing, None),
        Err(StoreError::NotFound { id }) if id == missing
    ));
    assert!(matches!(
        graph.put_if_absent(missing, &BlobHandle::from_bytes(b"wrong bytes")),
        Err(StoreError::Corrupt { id }) if id == missing
    ));
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
    assert_eq!(physical_nodes, vec!["directory", "memory", "packed"]);
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
        StoreGraph::build_with_admin(config).expect("restart admitted graph");
    assert_eq!(read_all(&restarted, fact), fact_bytes);
    assert_eq!(read_all(&restarted, ram), ram_bytes);
    assert_eq!(restarted_admin.physical().len(), 3);
}

fn graph_config(root: &std::path::Path, order: [TransparentLayer; 3]) -> StoreGraphConfig {
    let directory = node("directory");
    let memory = node("memory");
    let packed = node("packed");
    let mirror = node("mirror");
    let tiers = node("tiers");
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
            mirror.clone(),
            StoreNodeSpec::WriteThrough {
                children: vec![directory.clone(), packed],
            },
        ),
        (
            tiers.clone(),
            StoreNodeSpec::Tiered {
                tiers: vec![memory, directory],
                write_tier: 1,
                promote_reads: true,
            },
        ),
        (
            routed.clone(),
            StoreNodeSpec::Routed {
                routes: BTreeMap::from([
                    (ObjectKind::CampaignFact, mirror),
                    (ObjectKind::RamExtent, tiers),
                ]),
            },
        ),
    ]);

    let admitted = BTreeSet::from([ObjectKind::CampaignFact, ObjectKind::RamExtent]);
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

fn node(value: &str) -> StoreNodeId {
    StoreNodeId::new(value).expect("valid store node ID")
}
