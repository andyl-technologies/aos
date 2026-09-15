//! GC application, interruption, and backend-restart regressions.

use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

#[test]
fn stale_ref_and_blob_generations_fail_before_deletion() {
    let mut ref_fixture = apply_fixture(1);
    let temp = tempfile::TempDir::new().expect("temporary journal parent");
    let (mut ref_journal, _) =
        DirectoryCampaignGcJournal::create(temp.path().join("ref-journal"), &ref_fixture.prepared)
            .expect("create ref-stale journal");
    let orphan = ref_fixture
        .prepared
        .candidates()
        .iter()
        .next()
        .expect("orphan candidate")
        .id();
    ref_fixture
        .refs
        .compare_exchange(
            &RefName::new("retained/new-root").expect("new ref"),
            None,
            orphan,
        )
        .expect("advance ref generation");
    let physical = CampaignGcRawPhysicalStore::new("apply-primary", ref_fixture.blobs.as_ref())
        .expect("ref-stale physical store");
    assert!(matches!(
        apply_single_host_campaign_gc(
            &mut ref_journal,
            CampaignGcApplySources::new(
                &ref_fixture.repository,
                ref_fixture.refs.as_ref(),
                &mut ref_fixture.ledger,
                None,
                None,
            ),
            ref_fixture.graph,
            &[physical],
        ),
        Err(CampaignGcApplyError::RefBasisChanged)
    ));
    assert_eq!(ref_journal.phase(), CampaignGcJournalPhase::Planned);
    assert_eq!(ref_fixture.blobs.object_count().expect("object count"), 1);

    let mut blob_fixture = apply_fixture(1);
    let (mut blob_journal, _) = DirectoryCampaignGcJournal::create(
        temp.path().join("blob-journal"),
        &blob_fixture.prepared,
    )
    .expect("create blob-stale journal");
    let additional_bytes = b"post-plan object";
    let additional = ContentId::for_bytes(ObjectKind::Trace, 1, additional_bytes);
    blob_fixture
        .blobs
        .put_if_absent(additional, &BlobHandle::from_bytes(additional_bytes))
        .expect("advance blob generation");
    let physical = CampaignGcRawPhysicalStore::new("apply-primary", blob_fixture.blobs.as_ref())
        .expect("blob-stale physical store");
    assert!(matches!(
        apply_single_host_campaign_gc(
            &mut blob_journal,
            CampaignGcApplySources::new(
                &blob_fixture.repository,
                blob_fixture.refs.as_ref(),
                &mut blob_fixture.ledger,
                None,
                None,
            ),
            blob_fixture.graph,
            &[physical],
        ),
        Err(CampaignGcApplyError::PhysicalBasisChanged { .. })
    ));
    assert_eq!(blob_journal.phase(), CampaignGcJournalPhase::Planned);
    assert_eq!(blob_fixture.blobs.object_count().expect("object count"), 2);
}

#[test]
fn stale_ledger_generation_fails_before_deletion() {
    let blobs = Arc::new(MemoryBlobBackend::new("ledger-primary", 1024 * 1024));
    let refs = Arc::new(MemoryRefBackend::new());
    let repository = CampaignRepository::new(blobs.clone(), refs.clone());
    let orphan_bytes = b"ledger stale orphan";
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, orphan_bytes);
    blobs
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes))
        .expect("store ledger stale orphan");
    let mut ledger = SyntheticRetentionLedger { generation: 1 };
    let graph = hash("crucible.test.gc.ledger-store-graph.v1", 0x65);
    let physical = CampaignGcRawPhysicalStore::new("ledger-primary", blobs.as_ref())
        .expect("ledger physical store");
    let prepared = plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        graph,
        &[physical],
    )
    .expect("plan ledger stale GC");
    let temp = tempfile::TempDir::new().expect("temporary journal parent");
    let (mut journal, _) =
        DirectoryCampaignGcJournal::create(temp.path().join("journal"), &prepared)
            .expect("create ledger stale journal");
    ledger.generation = 2;

    assert!(matches!(
        apply_single_host_campaign_gc(
            &mut journal,
            CampaignGcApplySources::new(&repository, refs.as_ref(), &mut ledger, None, None,),
            graph,
            &[physical],
        ),
        Err(CampaignGcApplyError::LedgerBasisChanged)
    ));
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Planned);
    assert!(blobs.contains(orphan).expect("orphan retained"));
}

#[test]
fn interrupted_apply_retains_journal_and_requires_a_fresh_plan() {
    let mut fixture = apply_fixture(2);
    let temp = tempfile::TempDir::new().expect("temporary journal parent");
    let (mut journal, _) =
        DirectoryCampaignGcJournal::create(temp.path().join("journal"), &fixture.prepared)
            .expect("create interrupted journal");
    let failing = FailAfterFirstDeleteAdmin {
        inner: fixture.blobs.as_ref(),
        deletes: AtomicUsize::new(0),
    };
    let physical =
        CampaignGcRawPhysicalStore::new("apply-primary", &failing).expect("failing physical store");
    assert!(matches!(
        apply_single_host_campaign_gc(
            &mut journal,
            CampaignGcApplySources::new(
                &fixture.repository,
                fixture.refs.as_ref(),
                &mut fixture.ledger,
                None,
                None,
            ),
            fixture.graph,
            &[physical],
        ),
        Err(CampaignGcApplyError::Blob { .. })
    ));
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Applying);
    assert_eq!(fixture.blobs.object_count().expect("object count"), 1);
    assert!(matches!(
        apply_single_host_campaign_gc(
            &mut journal,
            CampaignGcApplySources::new(
                &fixture.repository,
                fixture.refs.as_ref(),
                &mut fixture.ledger,
                None,
                None,
            ),
            fixture.graph,
            &[physical],
        ),
        Err(CampaignGcApplyError::InterruptedJournal)
    ));
    assert_eq!(fixture.blobs.object_count().expect("object count"), 1);
}

#[test]
fn directory_plan_journal_and_apply_survive_full_backend_restart() {
    let temp = tempfile::TempDir::new().expect("temporary GC root");
    let blob_root = temp.path().join("blobs");
    let ref_root = temp.path().join("refs");
    let ledger_root = temp.path().join("ledger");
    let journal_root = temp.path().join("journal");
    let graph = hash("crucible.test.gc.directory-store-graph.v1", 0x71);

    let blobs = Arc::new(DirectoryBlobBackend::new("directory-primary", &blob_root));
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(blobs.clone(), refs.clone());
    let live = ContentEnvelope::new(
        "crucible.test.gc-directory-live",
        1,
        BTreeSet::new(),
        b"live".to_vec(),
    )
    .expect("live envelope");
    let live_id = live.content_id(ObjectKind::Trace);
    blobs
        .put_if_absent(live_id, &BlobHandle::from_bytes(live.canonical_bytes()))
        .expect("store live directory object");
    refs.compare_exchange(
        &RefName::new("retained/directory-gc").expect("directory ref"),
        None,
        live_id,
    )
    .expect("publish directory root");
    let orphan_bytes = b"directory orphan";
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, orphan_bytes);
    blobs
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes))
        .expect("store directory orphan");
    let mut ledger = DirectoryAssignmentLedger::open(&ledger_root).expect("open directory ledger");
    let physical = CampaignGcRawPhysicalStore::new("directory-primary", blobs.as_ref())
        .expect("directory physical store");
    let prepared = plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        graph,
        &[physical],
    )
    .expect("plan directory GC");
    let (journal, _) = DirectoryCampaignGcJournal::create(&journal_root, &prepared)
        .expect("create directory journal");
    drop(journal);
    drop(ledger);
    drop(repository);
    drop(refs);
    drop(blobs);

    let blobs = Arc::new(DirectoryBlobBackend::new("directory-primary", &blob_root));
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(blobs.clone(), refs.clone());
    let mut ledger =
        DirectoryAssignmentLedger::open(&ledger_root).expect("reopen directory ledger");
    let mut journal =
        DirectoryCampaignGcJournal::open(&journal_root).expect("reopen directory journal");
    let physical = CampaignGcRawPhysicalStore::new("directory-primary", blobs.as_ref())
        .expect("reopened physical store");
    let report = apply_single_host_campaign_gc(
        &mut journal,
        CampaignGcApplySources::new(&repository, refs.as_ref(), &mut ledger, None, None),
        graph,
        &[physical],
    )
    .expect("apply after restart");
    assert_eq!(report.status(), CampaignGcApplyStatus::Applied);
    assert!(blobs.contains(live_id).expect("live placement"));
    assert!(!blobs.contains(orphan).expect("orphan placement"));
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Complete);
}

#[test]
fn compressed_graph_admin_drives_plaintext_accounted_gc_across_restart() {
    let temp = tempfile::TempDir::new().expect("temporary compressed GC root");
    let blob_root = temp.path().join("compressed");
    let ref_root = temp.path().join("refs");
    let ledger_root = temp.path().join("ledger");
    let journal_root = temp.path().join("journal");
    let compressed_node = StoreNodeId::new("compressed-primary").expect("compressed node");
    let graph_config = || StoreGraphConfig {
        root: compressed_node.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::RamExtent, ObjectKind::Trace]),
        nodes: BTreeMap::from([(
            compressed_node.clone(),
            StoreNodeSpec::CompressedDirectory {
                root: blob_root.clone(),
                maximum_logical_object_bytes: 1024 * 1024,
            },
        )]),
    };

    let (graph, admin) = StoreGraph::build_with_admin(graph_config()).expect("compressed graph");
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(graph.clone(), refs.clone());
    let live = ContentEnvelope::new(
        "crucible.test.gc-compressed-live",
        1,
        BTreeSet::new(),
        vec![b'L'; 64 * 1024],
    )
    .expect("live envelope");
    let live_bytes = live.canonical_bytes();
    let live_id = live.content_id(ObjectKind::RamExtent);
    graph
        .put_if_absent(live_id, &BlobHandle::from_bytes(live_bytes.clone()))
        .expect("store live compressed object");
    refs.compare_exchange(
        &RefName::new("retained/compressed-gc").expect("compressed ref"),
        None,
        live_id,
    )
    .expect("publish compressed root");
    let orphan_bytes = vec![b'O'; 128 * 1024];
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, &orphan_bytes);
    graph
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes.clone()))
        .expect("store compressed orphan");

    let mut ledger = DirectoryAssignmentLedger::open(&ledger_root).expect("open compressed ledger");
    let prepared = super::super::plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        &admin,
    )
    .expect("plan compressed GC");
    assert_eq!(prepared.plan().physical().len(), 1);
    assert_eq!(prepared.plan().physical()[0].objects(), 2);
    assert_eq!(
        prepared.plan().physical()[0].logical_bytes(),
        u64::try_from(live_bytes.len() + orphan_bytes.len()).expect("logical byte total")
    );
    assert_eq!(prepared.candidates().len(), 1);
    assert_eq!(
        prepared.candidates().logical_bytes(),
        u64::try_from(orphan_bytes.len()).expect("orphan logical bytes")
    );
    assert_eq!(
        prepared.candidates().iter().next().expect("orphan").id(),
        orphan
    );
    let (journal, _) = DirectoryCampaignGcJournal::create(&journal_root, &prepared)
        .expect("create compressed GC journal");
    drop(journal);
    drop(ledger);
    drop(repository);
    drop(refs);
    drop(graph);
    drop(admin);

    let (graph, admin) =
        StoreGraph::build_with_admin(graph_config()).expect("restart compressed graph");
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(graph.clone(), refs.clone());
    let mut ledger =
        DirectoryAssignmentLedger::open(&ledger_root).expect("reopen compressed ledger");
    let mut journal =
        DirectoryCampaignGcJournal::open(&journal_root).expect("reopen compressed GC journal");
    let report = super::super::apply_single_host_campaign_gc(
        &mut journal,
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        &admin,
    )
    .expect("apply compressed GC after restart");
    assert_eq!(report.status(), CampaignGcApplyStatus::Applied);
    assert_eq!(report.candidates(), 1);
    assert_eq!(
        report.logical_bytes(),
        u64::try_from(orphan_bytes.len()).expect("reported orphan bytes")
    );
    assert!(graph.contains(live_id).expect("live compressed placement"));
    assert!(!graph.contains(orphan).expect("orphan compressed placement"));
    assert_eq!(
        graph
            .read(live_id, None)
            .expect("read retained compressed object")
            .read_all(1024 * 1024)
            .expect("authenticate retained compressed object"),
        live_bytes
    );
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Complete);
}

#[test]
fn encrypted_graph_admin_drives_plaintext_accounted_gc_across_restart() {
    run_encrypted_graph_gc_restart(false);
}

#[test]
fn compressed_encrypted_graph_admin_drives_plaintext_accounted_gc_across_restart() {
    run_encrypted_graph_gc_restart(true);
}

fn run_encrypted_graph_gc_restart(compressed: bool) {
    let temp = tempfile::TempDir::new().expect("temporary encrypted GC root");
    let blob_root = temp.path().join("encrypted");
    let ref_root = temp.path().join("refs");
    let ledger_root = temp.path().join("ledger");
    let journal_root = temp.path().join("journal");
    let encrypted_node = StoreNodeId::new("encrypted-primary").expect("encrypted node");
    let key_id = StoreEncryptionKeyId::new("gc-key-1").expect("GC key ID");
    let graph_config = || StoreGraphConfig {
        root: encrypted_node.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::RamExtent, ObjectKind::Trace]),
        nodes: BTreeMap::from([(
            encrypted_node.clone(),
            if compressed {
                StoreNodeSpec::CompressedEncryptedDirectory {
                    root: blob_root.clone(),
                    maximum_logical_object_bytes: 1024 * 1024,
                    key_id: key_id.clone(),
                }
            } else {
                StoreNodeSpec::EncryptedDirectory {
                    root: blob_root.clone(),
                    maximum_logical_object_bytes: 1024 * 1024,
                    key_id: key_id.clone(),
                }
            },
        )]),
    };
    let graph_keys = || {
        let mut keys = StoreGraphKeyring::new();
        keys.insert(
            key_id.clone(),
            StoreEncryptionKey::new([0x6d; 32]).expect("GC key"),
        )
        .expect("insert GC key");
        keys
    };

    let keys = graph_keys();
    let (graph, admin) =
        StoreGraph::build_with_admin_and_keys(graph_config(), &keys).expect("encrypted graph");
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(graph.clone(), refs.clone());
    let live = ContentEnvelope::new(
        "crucible.test.gc-encrypted-live",
        1,
        BTreeSet::new(),
        vec![b'L'; 64 * 1024],
    )
    .expect("live envelope");
    let live_bytes = live.canonical_bytes();
    let live_id = live.content_id(ObjectKind::RamExtent);
    graph
        .put_if_absent(live_id, &BlobHandle::from_bytes(live_bytes.clone()))
        .expect("store live encrypted object");
    refs.compare_exchange(
        &RefName::new("retained/encrypted-gc").expect("encrypted ref"),
        None,
        live_id,
    )
    .expect("publish encrypted root");
    let orphan_bytes = vec![b'O'; 128 * 1024];
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, &orphan_bytes);
    graph
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes.clone()))
        .expect("store encrypted orphan");

    let mut ledger = DirectoryAssignmentLedger::open(&ledger_root).expect("open encrypted ledger");
    let prepared = super::super::plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        &admin,
    )
    .expect("plan encrypted GC");
    assert_eq!(prepared.plan().physical()[0].objects(), 2);
    assert_eq!(
        prepared.plan().physical()[0].logical_bytes(),
        u64::try_from(live_bytes.len() + orphan_bytes.len()).expect("logical byte total")
    );
    assert_eq!(prepared.candidates().len(), 1);
    let (journal, _) = DirectoryCampaignGcJournal::create(&journal_root, &prepared)
        .expect("create encrypted GC journal");
    drop(journal);
    drop(ledger);
    drop(repository);
    drop(refs);
    drop(graph);
    drop(admin);
    drop(keys);

    let keys = graph_keys();
    let (graph, admin) = StoreGraph::build_with_admin_and_keys(graph_config(), &keys)
        .expect("restart encrypted graph");
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(graph.clone(), refs.clone());
    let mut ledger =
        DirectoryAssignmentLedger::open(&ledger_root).expect("reopen encrypted ledger");
    let mut journal =
        DirectoryCampaignGcJournal::open(&journal_root).expect("reopen encrypted GC journal");
    let report = super::super::apply_single_host_campaign_gc(
        &mut journal,
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        &admin,
    )
    .expect("apply encrypted GC after restart");
    assert_eq!(report.status(), CampaignGcApplyStatus::Applied);
    assert_eq!(report.candidates(), 1);
    assert_eq!(
        report.logical_bytes(),
        u64::try_from(orphan_bytes.len()).expect("reported orphan bytes")
    );
    assert!(graph.contains(live_id).expect("live encrypted placement"));
    assert!(!graph.contains(orphan).expect("orphan encrypted placement"));
    assert_eq!(
        graph
            .read(live_id, None)
            .expect("read retained encrypted object")
            .read_all(1024 * 1024)
            .expect("authenticate retained encrypted object"),
        live_bytes
    );
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Complete);
}

#[test]
fn logical_quota_graph_gc_reclaims_admission_capacity_across_restart() {
    let temp = tempfile::TempDir::new().expect("temporary quota GC root");
    let blob_root = temp.path().join("objects");
    let quota_root = temp.path().join("quota");
    let ref_root = temp.path().join("refs");
    let ledger_root = temp.path().join("ledger");
    let journal_root = temp.path().join("journal");
    let quota_node = StoreNodeId::new("quota-primary").expect("quota node");
    let directory_node = StoreNodeId::new("directory-child").expect("directory child");
    let graph_config = || StoreGraphConfig {
        root: quota_node.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::RamExtent, ObjectKind::Trace]),
        nodes: BTreeMap::from([
            (
                quota_node.clone(),
                StoreNodeSpec::LogicalQuota {
                    child: directory_node.clone(),
                    state_root: quota_root.clone(),
                    maximum_objects: 2,
                    maximum_logical_bytes: 1024 * 1024,
                },
            ),
            (
                directory_node.clone(),
                StoreNodeSpec::Directory {
                    root: blob_root.clone(),
                },
            ),
        ]),
    };

    let (graph, admin) = StoreGraph::build_with_admin(graph_config()).expect("quota GC graph");
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(graph.clone(), refs.clone());
    let live = ContentEnvelope::new(
        "crucible.test.gc-quota-live",
        1,
        BTreeSet::new(),
        b"quota live".to_vec(),
    )
    .expect("quota live envelope");
    let live_id = live.content_id(ObjectKind::RamExtent);
    graph
        .put_if_absent(live_id, &BlobHandle::from_bytes(live.canonical_bytes()))
        .expect("store quota live object");
    refs.compare_exchange(
        &RefName::new("retained/quota-gc").expect("quota ref"),
        None,
        live_id,
    )
    .expect("publish quota root");
    let orphan_bytes = b"quota orphan";
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, orphan_bytes);
    graph
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes))
        .expect("store quota orphan");
    let rejected_bytes = b"quota initially full";
    let rejected = ContentId::for_bytes(ObjectKind::Trace, 1, rejected_bytes);
    assert!(matches!(
        graph.put_if_absent(rejected, &BlobHandle::from_bytes(rejected_bytes)),
        Err(StoreError::Quota)
    ));

    assert_eq!(admin.physical().len(), 1);
    assert_eq!(admin.physical()[0].node(), &quota_node);
    let mut ledger = DirectoryAssignmentLedger::open(&ledger_root).expect("open quota GC ledger");
    let prepared = super::super::plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        &admin,
    )
    .expect("plan quota GC");
    assert_eq!(prepared.candidates().len(), 1);
    assert_eq!(
        prepared.candidates().iter().next().expect("orphan").id(),
        orphan
    );
    let (journal, _) = DirectoryCampaignGcJournal::create(&journal_root, &prepared)
        .expect("create quota GC journal");
    drop(journal);
    drop(ledger);
    drop(repository);
    drop(refs);
    drop(graph);
    drop(admin);

    let (graph, admin) =
        StoreGraph::build_with_admin(graph_config()).expect("restart quota GC graph");
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(graph.clone(), refs.clone());
    let mut ledger = DirectoryAssignmentLedger::open(&ledger_root).expect("reopen quota GC ledger");
    let mut journal =
        DirectoryCampaignGcJournal::open(&journal_root).expect("reopen quota GC journal");
    let report = super::super::apply_single_host_campaign_gc(
        &mut journal,
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        &admin,
    )
    .expect("apply quota GC after restart");
    assert_eq!(report.status(), CampaignGcApplyStatus::Applied);
    assert!(graph.contains(live_id).expect("quota live placement"));
    assert!(!graph.contains(orphan).expect("quota orphan placement"));
    graph
        .put_if_absent(rejected, &BlobHandle::from_bytes(rejected_bytes))
        .expect("GC reclaimed quota admission capacity");
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Complete);
}

#[test]
fn packed_graph_admin_drives_restart_safe_logical_gc_without_deleting_live_pack_bytes() {
    let temp = tempfile::TempDir::new().expect("temporary packed GC root");
    let pack_root = temp.path().join("packs");
    let ref_root = temp.path().join("refs");
    let ledger_root = temp.path().join("ledger");
    let journal_root = temp.path().join("journal");
    let packed_node = StoreNodeId::new("packed-primary").expect("packed node");
    let graph_config = || StoreGraphConfig {
        root: packed_node.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::RamExtent, ObjectKind::Trace]),
        nodes: BTreeMap::from([(
            packed_node.clone(),
            StoreNodeSpec::Packed {
                root: pack_root.clone(),
                target_pack_bytes: 64 * 1024,
            },
        )]),
    };

    let (graph, admin) = StoreGraph::build_with_admin(graph_config()).expect("packed graph");
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(graph.clone(), refs.clone());
    let live = ContentEnvelope::new(
        "crucible.test.gc-packed-live",
        1,
        BTreeSet::new(),
        b"live".to_vec(),
    )
    .expect("live envelope");
    let live_id = live.content_id(ObjectKind::RamExtent);
    graph
        .put_if_absent(live_id, &BlobHandle::from_bytes(live.canonical_bytes()))
        .expect("store live packed object");
    refs.compare_exchange(
        &RefName::new("retained/packed-gc").expect("packed ref"),
        None,
        live_id,
    )
    .expect("publish packed root");
    let orphan_bytes = b"packed orphan";
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, orphan_bytes);
    graph
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes))
        .expect("store packed orphan");

    let packed = PackedBlobBackend::open("packed-primary", &pack_root, 64 * 1024)
        .expect("packed maintenance leaf");
    let repack = packed.plan_repack().expect("packed coalescing plan");
    let repacked = packed
        .apply_repack(&repack)
        .expect("coalesce packed objects");
    assert_eq!(repacked.after().packs(), 1);
    assert_eq!(repacked.after().logical_objects(), 2);

    let mut ledger = DirectoryAssignmentLedger::open(&ledger_root).expect("open packed ledger");
    assert_eq!(admin.physical().len(), 1);
    let prepared = super::super::plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        &admin,
    )
    .expect("plan packed GC");
    assert_eq!(
        prepared.plan().store_graph(),
        CampaignHash::from_bytes(admin.configuration_id().as_bytes())
    );
    assert_eq!(prepared.candidates().len(), 1);
    assert_eq!(
        prepared.candidates().iter().next().expect("orphan").id(),
        orphan
    );
    let (journal, _) = DirectoryCampaignGcJournal::create(&journal_root, &prepared)
        .expect("create packed GC journal");
    drop(journal);

    let verified = StoreNodeId::new("verified-root").expect("verified root");
    let (different_graph, different_admin) = StoreGraph::build_with_admin(StoreGraphConfig {
        root: verified.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::RamExtent, ObjectKind::Trace]),
        nodes: BTreeMap::from([
            (
                verified,
                StoreNodeSpec::Verified {
                    child: packed_node.clone(),
                },
            ),
            (
                packed_node.clone(),
                StoreNodeSpec::Packed {
                    root: pack_root.clone(),
                    target_pack_bytes: 64 * 1024,
                },
            ),
        ]),
    })
    .expect("different composition over same packed leaf");
    let mut journal =
        DirectoryCampaignGcJournal::open(&journal_root).expect("reopen planned journal");
    assert!(matches!(
        super::super::apply_single_host_campaign_gc(
            &mut journal,
            &repository,
            refs.as_ref(),
            &mut ledger,
            None,
            None,
            &different_admin,
        ),
        Err(CampaignGcApplyError::StoreGraphChanged)
    ));
    assert!(graph.contains(orphan).expect("orphan retained on mismatch"));
    drop(journal);
    drop(different_admin);
    drop(different_graph);

    drop(ledger);
    drop(repository);
    drop(refs);
    drop(graph);
    drop(admin);
    drop(packed);

    let (graph, admin) =
        StoreGraph::build_with_admin(graph_config()).expect("restart packed graph");
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(graph.clone(), refs.clone());
    let mut ledger = DirectoryAssignmentLedger::open(&ledger_root).expect("reopen packed ledger");
    let mut journal =
        DirectoryCampaignGcJournal::open(&journal_root).expect("reopen packed GC journal");
    let report = super::super::apply_single_host_campaign_gc(
        &mut journal,
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        &admin,
    )
    .expect("apply packed GC after restart");
    assert_eq!(report.status(), CampaignGcApplyStatus::Applied);
    assert!(graph.contains(live_id).expect("live packed placement"));
    assert!(!graph.contains(orphan).expect("orphan packed placement"));
    let packed = PackedBlobBackend::open("packed-primary", &pack_root, 64 * 1024)
        .expect("reopen packed accounting");
    let accounting = packed.accounting().expect("packed post-GC accounting");
    assert_eq!(accounting.logical_objects(), 1);
    assert_eq!(accounting.packs(), 1);
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Complete);
}

struct FailAfterFirstDeleteAdmin<'a> {
    inner: &'a MemoryBlobBackend,
    deletes: AtomicUsize,
}

impl BlobStoreAdmin for FailAfterFirstDeleteAdmin<'_> {
    fn acquire_inventory_fence(&self) -> Result<Box<dyn BlobInventoryFence + '_>, StoreError> {
        Ok(Box::new(FailAfterFirstDeleteFence {
            inner: self.inner.acquire_inventory_fence()?,
            deletes: &self.deletes,
        }))
    }
}

struct FailAfterFirstDeleteFence<'a> {
    inner: Box<dyn BlobInventoryFence + 'a>,
    deletes: &'a AtomicUsize,
}

struct SyntheticRetentionLedger {
    generation: u8,
}

impl AssignmentRetentionAdmin for SyntheticRetentionLedger {
    type Error = std::convert::Infallible;

    fn acquire_retention_fence(
        &mut self,
    ) -> Result<Box<dyn AssignmentRetentionFence<BackendError = Self::Error> + '_>, Self::Error>
    {
        Ok(Box::new(SyntheticRetentionFence {
            generation: self.generation,
        }))
    }
}

struct SyntheticRetentionFence {
    generation: u8,
}

impl AssignmentRetentionFence for SyntheticRetentionFence {
    type BackendError = std::convert::Infallible;

    fn visit_roots(
        &mut self,
        _visitor: &mut dyn FnMut(
            AssignmentRetentionRoot,
        ) -> Result<(), AssignmentRetentionVisitorError>,
    ) -> Result<AssignmentRetentionSummary, AssignmentRetentionInventoryError<Self::BackendError>>
    {
        Ok(AssignmentRetentionSummary::new(
            AssignmentRetentionGeneration::from_bytes([self.generation; 32]),
            0,
            0,
            0,
            0,
        ))
    }

    fn load_attempt(
        &mut self,
        _key: AttemptExecutionKey,
    ) -> Result<Option<AttemptRuntimeState>, Self::BackendError> {
        Ok(None)
    }

    fn compare_exchange_attempt(
        &mut self,
        _key: AttemptExecutionKey,
        _expected: Option<AttemptRuntimeState>,
        _next: Option<AttemptRuntimeState>,
    ) -> Result<AttemptStateCas, Self::BackendError> {
        Ok(AttemptStateCas::Conflict { current: None })
    }
}

impl BlobInventoryFence for FailAfterFirstDeleteFence<'_> {
    fn visit_inventory(
        &mut self,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
    ) -> Result<BlobInventorySummary, StoreError> {
        self.inner.visit_inventory(visitor)
    }

    fn delete_candidate(&mut self, id: ContentId) -> Result<PlannedDeleteDisposition, StoreError> {
        if self.deletes.load(Ordering::Relaxed) == 1 {
            return Err(StoreError::Quota);
        }
        let disposition = self.inner.delete_candidate(id)?;
        self.deletes.fetch_add(1, Ordering::Relaxed);
        Ok(disposition)
    }
}
