//! Durable GC journal and graph-aware apply tests.

use super::*;

#[test]
fn external_journal_reopens_exact_plan_and_durable_phase() {
    let prepared = journal_plan_fixture(0x41);
    let different = journal_plan_fixture(0x42);
    let temp = tempfile::TempDir::new().expect("temporary journal parent");
    let root = temp.path().join("gc-journal");

    let (mut journal, disposition) =
        DirectoryCampaignGcJournal::create(&root, &prepared).expect("create journal");
    assert_eq!(disposition, CampaignGcJournalCreateDisposition::Created);
    assert!(root.join("plan-v2").is_file());
    assert!(root.join("candidates-v2").is_file());
    assert!(!root.join("plan-v1").exists());
    assert!(!root.join("candidates-v1").exists());
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Planned);
    assert_eq!(journal.plan(), prepared.plan());
    assert_eq!(journal.roots(), prepared.roots());
    assert_eq!(journal.candidates(), prepared.candidates());
    assert_eq!(
        journal.begin_apply().expect("begin apply"),
        CampaignGcJournalTransition::Advanced
    );
    assert_eq!(
        journal.begin_apply().expect("repeat begin apply"),
        CampaignGcJournalTransition::Existing
    );
    let retained_lock_description = journal
        .duplicate_lock_for_test()
        .expect("duplicate GC journal lock descriptor");
    drop(journal);

    let lock_probe = super::super::journal::try_acquire_lock_for_test(&root)
        .expect("logical owner drop releases retained GC lock description");
    drop(lock_probe);
    let mut reopened = DirectoryCampaignGcJournal::open(&root).expect("reopen applying journal");
    assert_eq!(reopened.phase(), CampaignGcJournalPhase::Applying);
    assert_eq!(
        reopened.mark_complete().expect("complete apply"),
        CampaignGcJournalTransition::Advanced
    );
    assert_eq!(
        reopened.mark_complete().expect("repeat completion"),
        CampaignGcJournalTransition::Existing
    );
    drop(reopened);

    let (complete, disposition) =
        DirectoryCampaignGcJournal::create(&root, &prepared).expect("reopen exact journal");
    assert_eq!(disposition, CampaignGcJournalCreateDisposition::Existing);
    assert_eq!(complete.phase(), CampaignGcJournalPhase::Complete);
    drop(complete);
    assert!(matches!(
        DirectoryCampaignGcJournal::create(&root, &different),
        Err(CampaignGcJournalError::PlanMismatch)
    ));
    drop(retained_lock_description);
}

#[test]
fn external_journal_cancellation_is_durable_idempotent_and_terminal() {
    let prepared = journal_plan_fixture(0x43);
    let temp = tempfile::TempDir::new().expect("temporary journal parent");
    let root = temp.path().join("cancelled-gc-journal");

    let (mut journal, disposition) =
        DirectoryCampaignGcJournal::create(&root, &prepared).expect("create cancellable journal");
    assert_eq!(disposition, CampaignGcJournalCreateDisposition::Created);
    assert_eq!(
        journal.cancel().expect("cancel planned journal"),
        CampaignGcJournalTransition::Advanced
    );
    assert_eq!(
        journal.cancel().expect("repeat journal cancellation"),
        CampaignGcJournalTransition::Existing
    );
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Cancelled);
    assert!(matches!(
        journal.begin_apply(),
        Err(CampaignGcJournalError::InvalidTransition)
    ));
    assert!(matches!(
        journal.mark_complete(),
        Err(CampaignGcJournalError::InvalidTransition)
    ));
    drop(journal);

    let mut reopened = DirectoryCampaignGcJournal::open(&root).expect("reopen cancelled journal");
    assert_eq!(reopened.phase(), CampaignGcJournalPhase::Cancelled);
    assert_eq!(
        reopened.cancel().expect("repeat reopened cancellation"),
        CampaignGcJournalTransition::Existing
    );
    drop(reopened);
    let (existing, disposition) =
        DirectoryCampaignGcJournal::create(&root, &prepared).expect("reopen exact cancelled plan");
    assert_eq!(disposition, CampaignGcJournalCreateDisposition::Existing);
    assert_eq!(existing.phase(), CampaignGcJournalPhase::Cancelled);
}

#[test]
fn external_journal_rejects_incomplete_and_corrupt_state() {
    let temp = tempfile::TempDir::new().expect("temporary journal parent");
    let incomplete = temp.path().join("incomplete");
    fs::create_dir(&incomplete).expect("create incomplete journal");
    assert!(matches!(
        DirectoryCampaignGcJournal::open(&incomplete),
        Err(CampaignGcJournalError::Incomplete)
    ));

    let prepared = journal_plan_fixture(0x51);
    let complete = temp.path().join("complete");
    let (journal, _) =
        DirectoryCampaignGcJournal::create(&complete, &prepared).expect("create complete journal");
    drop(journal);
    fs::write(complete.join("state-v1"), b"corrupt").expect("corrupt journal state");
    assert!(matches!(
        DirectoryCampaignGcJournal::open(&complete),
        Err(CampaignGcJournalError::InvalidState)
    ));
}

#[test]
fn apply_revalidates_every_basis_then_deletes_and_completes() {
    let mut fixture = apply_fixture(2);
    let temp = tempfile::TempDir::new().expect("temporary journal parent");
    let (mut journal, _) =
        DirectoryCampaignGcJournal::create(temp.path().join("journal"), &fixture.prepared)
            .expect("create apply journal");
    let report = apply_single_host_campaign_gc(
        &mut journal,
        &fixture.repository,
        fixture.refs.as_ref(),
        &mut fixture.ledger,
        empty_write_back(),
        None,
        &fixture.admin,
    )
    .expect("apply exact plan");
    assert_eq!(report.status(), CampaignGcApplyStatus::Applied);
    assert_eq!(report.candidates(), 2);
    assert_eq!(
        report.logical_bytes(),
        fixture.prepared.candidates().logical_bytes()
    );
    assert_eq!(physical_object_count(&fixture.admin), 0);
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Complete);

    let replay = apply_single_host_campaign_gc(
        &mut journal,
        &fixture.repository,
        fixture.refs.as_ref(),
        &mut fixture.ledger,
        empty_write_back(),
        None,
        &fixture.admin,
    )
    .expect("replay completed apply");
    assert_eq!(replay.status(), CampaignGcApplyStatus::AlreadyComplete);
    assert_eq!(replay.candidates(), report.candidates());
}

#[test]
fn cancelled_apply_fails_before_basis_checks_and_preserves_every_candidate() {
    let mut fixture = apply_fixture(2);
    let temp = tempfile::TempDir::new().expect("temporary journal parent");
    let root = temp.path().join("cancelled-apply-journal");
    let (mut journal, _) = DirectoryCampaignGcJournal::create(&root, &fixture.prepared)
        .expect("create cancelled apply journal");
    journal.cancel().expect("cancel apply journal");
    drop(journal);

    let mut reopened = DirectoryCampaignGcJournal::open(&root).expect("reopen cancelled apply");
    assert!(matches!(
        apply_single_host_campaign_gc(
            &mut reopened,
            &fixture.repository,
            fixture.refs.as_ref(),
            &mut fixture.ledger,
            empty_write_back(),
            None,
            &fixture.admin,
        ),
        Err(CampaignGcApplyError::CancelledJournal)
    ));
    assert_eq!(reopened.phase(), CampaignGcJournalPhase::Cancelled);
    assert_eq!(physical_object_count(&fixture.admin), 2);
}

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
    assert!(matches!(
        apply_single_host_campaign_gc(
            &mut ref_journal,
            &ref_fixture.repository,
            ref_fixture.refs.as_ref(),
            &mut ref_fixture.ledger,
            empty_write_back(),
            None,
            &ref_fixture.admin,
        ),
        Err(CampaignGcApplyError::RefBasisChanged)
    ));
    assert_eq!(ref_journal.phase(), CampaignGcJournalPhase::Planned);
    assert_eq!(physical_object_count(&ref_fixture.admin), 1);

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
    assert!(matches!(
        apply_single_host_campaign_gc(
            &mut blob_journal,
            &blob_fixture.repository,
            blob_fixture.refs.as_ref(),
            &mut blob_fixture.ledger,
            empty_write_back(),
            None,
            &blob_fixture.admin,
        ),
        Err(CampaignGcApplyError::PhysicalBasisChanged { .. })
    ));
    assert_eq!(blob_journal.phase(), CampaignGcJournalPhase::Planned);
    assert_eq!(physical_object_count(&blob_fixture.admin), 2);
}

#[test]
fn stale_ledger_generation_fails_before_deletion() {
    let (blobs, admin) = memory_gc_graph("ledger-primary", BTreeSet::from([ObjectKind::Trace]));
    let refs = Arc::new(MemoryRefBackend::new());
    let repository = CampaignRepository::new(blobs.clone(), refs.clone());
    let orphan_bytes = b"ledger stale orphan";
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, orphan_bytes);
    blobs
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes))
        .expect("store ledger stale orphan");
    let mut ledger = SyntheticRetentionLedger { generation: 1 };
    let prepared = plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        empty_write_back(),
        None,
        &admin,
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
            &repository,
            refs.as_ref(),
            &mut ledger,
            empty_write_back(),
            None,
            &admin,
        ),
        Err(CampaignGcApplyError::LedgerBasisChanged)
    ));
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Planned);
    assert!(blobs.contains(orphan).expect("orphan retained"));
}

#[test]
fn interrupted_apply_retains_journal_and_requires_a_fresh_graph_aware_plan() {
    let mut fixture = apply_fixture(2);
    let temp = tempfile::TempDir::new().expect("temporary journal parent");
    let root = temp.path().join("interrupted-journal");
    let (mut journal, _) = DirectoryCampaignGcJournal::create(&root, &fixture.prepared)
        .expect("create interrupted journal");
    assert_eq!(
        journal.begin_apply().expect("persist applying phase"),
        CampaignGcJournalTransition::Advanced
    );
    drop(journal);

    let mut restarted =
        DirectoryCampaignGcJournal::open(&root).expect("reopen interrupted journal");
    assert!(matches!(
        apply_single_host_campaign_gc(
            &mut restarted,
            &fixture.repository,
            fixture.refs.as_ref(),
            &mut fixture.ledger,
            empty_write_back(),
            None,
            &fixture.admin,
        ),
        Err(CampaignGcApplyError::InterruptedJournal)
    ));
    assert_eq!(restarted.phase(), CampaignGcJournalPhase::Applying);
    assert_eq!(physical_object_count(&fixture.admin), 2);
}

#[test]
fn directory_plan_journal_and_apply_survive_full_backend_restart() {
    let temp = tempfile::TempDir::new().expect("temporary GC root");
    let blob_root = temp.path().join("blobs");
    let ref_root = temp.path().join("refs");
    let ledger_root = temp.path().join("ledger");
    let journal_root = temp.path().join("journal");
    let (blobs, admin) = directory_gc_graph(
        "directory-primary",
        &blob_root,
        BTreeSet::from([ObjectKind::Trace]),
    );
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
    let prepared = plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        empty_write_back(),
        None,
        &admin,
    )
    .expect("plan directory GC");
    let (journal, _) = DirectoryCampaignGcJournal::create(&journal_root, &prepared)
        .expect("create directory journal");
    drop(journal);
    drop(ledger);
    drop(repository);
    drop(refs);
    drop(blobs);
    drop(admin);

    let (blobs, admin) = directory_gc_graph(
        "directory-primary",
        &blob_root,
        BTreeSet::from([ObjectKind::Trace]),
    );
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(blobs.clone(), refs.clone());
    let mut ledger =
        DirectoryAssignmentLedger::open(&ledger_root).expect("reopen directory ledger");
    let mut journal =
        DirectoryCampaignGcJournal::open(&journal_root).expect("reopen directory journal");
    let report = apply_single_host_campaign_gc(
        &mut journal,
        &repository,
        refs.as_ref(),
        &mut ledger,
        empty_write_back(),
        None,
        &admin,
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
        empty_write_back(),
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
        empty_write_back(),
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
        empty_write_back(),
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
        empty_write_back(),
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
        empty_write_back(),
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
        empty_write_back(),
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
        empty_write_back(),
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
            empty_write_back(),
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
        empty_write_back(),
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

struct ApplyFixture {
    blobs: Arc<StoreGraph>,
    admin: StoreGraphAdmin,
    refs: Arc<MemoryRefBackend>,
    repository: CampaignRepository,
    ledger: MemoryAssignmentLedger,
    prepared: CampaignGcPreparedPlan,
}

fn apply_fixture(orphan_count: u8) -> ApplyFixture {
    let (blobs, admin) = memory_gc_graph("apply-primary", BTreeSet::from([ObjectKind::Trace]));
    let refs = Arc::new(MemoryRefBackend::new());
    let repository = CampaignRepository::new(blobs.clone(), refs.clone());
    for index in 0..orphan_count {
        let bytes = [index; 8];
        let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
        blobs
            .put_if_absent(id, &BlobHandle::from_bytes(bytes))
            .expect("store apply orphan");
    }
    let mut ledger = MemoryAssignmentLedger::default();
    let prepared = plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        empty_write_back(),
        None,
        &admin,
    )
    .expect("prepare apply fixture");
    ApplyFixture {
        blobs,
        admin,
        refs,
        repository,
        ledger,
        prepared,
    }
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

fn journal_plan_fixture(graph_byte: u8) -> CampaignGcPreparedPlan {
    let backend = format!("journal-primary-{graph_byte:02x}");
    let (blobs, admin) = memory_gc_graph(&backend, BTreeSet::from([ObjectKind::Trace]));
    let refs = Arc::new(MemoryRefBackend::new());
    let repository = CampaignRepository::new(blobs.clone(), refs.clone());
    let orphan_bytes = b"journal orphan";
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, orphan_bytes);
    blobs
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes))
        .expect("store journal orphan");
    let mut ledger = MemoryAssignmentLedger::default();
    plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        empty_write_back(),
        None,
        &admin,
    )
    .expect("prepare journal plan")
}
