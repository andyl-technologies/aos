//! Verification-evidence and physical-repair authority tests.

use super::*;

#[test]
fn verification_evidence_bounds_source_passes_through_a_mirror_graph() {
    let temp = TempDir::new().expect("temporary directory");
    let root = node_id("root");
    let router = node_id("router");
    let mirror = node_id("mirror");
    let directory = node_id("directory");
    let memory = node_id("memory");
    let graph = StoreGraph::build(StoreGraphConfig {
        root: root.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact]),
        nodes: BTreeMap::from([
            (
                root,
                StoreNodeSpec::Verified {
                    child: router.clone(),
                },
            ),
            (
                router,
                StoreNodeSpec::Routed {
                    routes: BTreeMap::from([(ObjectKind::CampaignFact, mirror.clone())]),
                },
            ),
            (
                mirror,
                StoreNodeSpec::WriteThrough {
                    children: vec![directory.clone(), memory.clone()],
                },
            ),
            (
                directory,
                StoreNodeSpec::Directory {
                    root: temp.path().join("objects"),
                },
            ),
            (
                memory,
                StoreNodeSpec::Memory {
                    max_logical_bytes: 1024 * 1024,
                },
            ),
        ]),
    })
    .expect("valid mirror graph");
    let bytes = vec![0x5a; 128 * 1024];
    let opens = Arc::new(AtomicUsize::new(0));
    let bytes_read = Arc::new(AtomicUsize::new(0));
    let source = BlobHandle::new(Arc::new(CountingSource {
        bytes: Arc::from(bytes.clone()),
        opens: opens.clone(),
        bytes_read: bytes_read.clone(),
    }));
    let id = ContentId::for_bytes(ObjectKind::CampaignFact, 1, &bytes);
    let receipt = graph
        .put_if_absent(id, &source)
        .expect("mirrored streaming put");

    assert_eq!(receipt.placements.len(), 2);
    assert_eq!(opens.load(Ordering::SeqCst), 3);
    assert_eq!(bytes_read.load(Ordering::SeqCst), bytes.len() * 3);
}

#[test]
fn physical_repair_restores_only_missing_or_corrupt_authenticated_placements() {
    let temp = TempDir::new().expect("temporary repair directory");
    let source_root = temp.path().join("source");
    let target_root = temp.path().join("target");
    let mirror = node_id("mirror");
    let source = node_id("source");
    let target = node_id("target");
    let (_graph, maintenance) = StoreGraph::build_with_admin(StoreGraphConfig {
        root: mirror.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
        nodes: BTreeMap::from([
            (
                mirror,
                StoreNodeSpec::WriteThrough {
                    children: vec![source.clone(), target.clone()],
                },
            ),
            (
                source.clone(),
                StoreNodeSpec::Directory {
                    root: source_root.clone(),
                },
            ),
            (
                target.clone(),
                StoreNodeSpec::Directory {
                    root: target_root.clone(),
                },
            ),
        ]),
    })
    .expect("repair graph");
    let bytes = b"authenticated physical repair".to_vec();
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    let source_backend = DirectoryBlobBackend::new("source", &source_root);
    source_backend
        .put_if_absent(id, &BlobHandle::from_bytes(bytes.clone()))
        .expect("seed source placement");
    let target_capability = maintenance
        .physical()
        .into_iter()
        .find(|capability| capability.node() == &target)
        .expect("target repair capability");
    let initial_generation = target_capability
        .admin()
        .acquire_inventory_fence()
        .expect("initial target inventory fence")
        .visit_inventory(&mut |_| Ok(()))
        .expect("initial target inventory")
        .generation();
    let target_backend = DirectoryBlobBackend::new("target", &target_root);
    let intervening_bytes = b"intervening target placement";
    let intervening = ContentId::for_bytes(ObjectKind::Trace, 1, intervening_bytes);
    target_backend
        .put_if_absent(
            intervening,
            &BlobHandle::from_bytes(intervening_bytes.to_vec()),
        )
        .expect("change target generation after planning");
    assert!(matches!(
        target_capability.repair_with_authenticated_bytes(id, bytes.clone(), initial_generation),
        Err(StoreError::Incompatible)
    ));
    let current_generation = target_capability
        .admin()
        .acquire_inventory_fence()
        .expect("current target inventory fence")
        .visit_inventory(&mut |_| Ok(()))
        .expect("current target inventory")
        .generation();

    assert_eq!(
        target_capability
            .repair_with_authenticated_bytes(id, bytes.clone(), current_generation)
            .expect("repair missing placement"),
        StoreGraphPhysicalRepairDisposition::ReplacedMissing
    );
    assert_eq!(
        target_capability
            .repair_with_authenticated_bytes(id, bytes.clone(), current_generation)
            .expect("inspect healthy placement"),
        StoreGraphPhysicalRepairDisposition::AlreadyAuthenticated
    );

    fs::write(object_path(&target_root, id), b"corrupt replacement")
        .expect("corrupt target placement");
    let corrupt_generation = target_capability
        .admin()
        .acquire_inventory_fence()
        .expect("corrupt target inventory fence")
        .visit_inventory(&mut |_| Ok(()))
        .expect("corrupt target inventory")
        .generation();
    assert_eq!(
        target_capability
            .repair_with_authenticated_bytes(id, bytes.clone(), corrupt_generation)
            .expect("repair corrupt placement"),
        StoreGraphPhysicalRepairDisposition::ReplacedCorrupt
    );
    assert_eq!(
        read_bytes(&DirectoryBlobBackend::new("target", &target_root), id, None)
            .expect("read repaired target"),
        bytes
    );
    assert!(matches!(
        target_capability.repair_with_authenticated_bytes(
            id,
            b"wrong".to_vec(),
            corrupt_generation
        ),
        Err(StoreError::Corrupt { id: corrupt }) if corrupt == id
    ));
}
