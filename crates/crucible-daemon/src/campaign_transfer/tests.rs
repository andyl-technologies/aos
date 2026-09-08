//! Restart and operation-binding tests for campaign archive transfers.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crucible::{Checkpoint, CheckpointKind, Configuration, ScenarioDef, VirtualTime};
use crucible_campaign::{
    CampaignArchiveCheckpointResolver, CampaignArchivePlan, CampaignArchivePolicy,
    CampaignCommandId, CampaignHash, CampaignLineage, CampaignMode, CampaignName, CampaignPolicy,
    CampaignRepository, CampaignRepositoryError, CampaignSeed, ConfigurationId, ExactCheckpointId,
    ExplorerPolicy, FairnessPolicy, PinChange, PinRequest, PinRetention, RetentionPolicy,
    ScenarioDefId,
};
use crucible_cas::content_store::{
    BlobHandle, DirectoryBlobBackend, DirectoryRefBackend, DurabilityRequirement,
    ImmutableBlobBackend, MemoryBlobBackend, MemoryRefBackend,
};
use crucible_qemu::{QemuReplayOracleValidation, QemuVmSnapshot};

use super::*;

struct ReturningCheckpoint(ExactCheckpointId);

impl CampaignArchiveCheckpointResolver for ReturningCheckpoint {
    fn resolve_checkpoint(
        &mut self,
        _configuration: ConfigurationId,
        _pin_fact: crucible_campaign::CampaignFactId,
    ) -> Result<ExactCheckpointId, CampaignRepositoryError> {
        Ok(self.0)
    }
}

fn archive_plan() -> CampaignArchivePlan {
    let repository = CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new("transfer-test", 64 * 1024 * 1024)),
        Arc::new(MemoryRefBackend::new()),
    );
    plan_in_repository(&repository)
}

fn plan_in_repository(repository: &CampaignRepository) -> CampaignArchivePlan {
    let scenario = ScenarioDefId::from_hash(CampaignHash::derive("transfer-test", b"scenario"));
    let genesis = ConfigurationId::from_hash(CampaignHash::derive("transfer-test", b"genesis"));
    let scenario_artifact = repository
        .publish_scenario_artifact(scenario, 1, b"scenario".to_vec())
        .expect("scenario artifact");
    let genesis_artifact = repository
        .publish_configuration_artifact(
            scenario,
            scenario_artifact,
            genesis,
            1,
            b"genesis".to_vec(),
        )
        .expect("genesis artifact");
    let lineage = CampaignLineage::new(
        scenario,
        scenario_artifact,
        genesis,
        genesis_artifact,
        "crucible-transfer-test",
        "qemu-transfer-test",
        BTreeMap::from([("control".to_owned(), 1)]),
        1,
        1,
    )
    .expect("lineage");
    let policy = CampaignPolicy::new(
        scenario,
        CampaignSeed::from_bytes([0x51; 32]),
        CampaignMode::Strict,
        ExplorerPolicy::Exhaustive {
            maximum_cardinality: 1,
        },
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeSet::new(),
        FairnessPolicy::new(0, 0).expect("fairness"),
        RetentionPolicy::new(true, 1, true, true),
        true,
    )
    .expect("policy");
    let head = repository
        .create("source", &lineage, &policy, &BTreeMap::new())
        .expect("create campaign");
    repository
        .plan_campaign_archive(
            head.snapshot_id(),
            CampaignArchivePolicy::Metadata,
            [],
            None,
        )
        .expect("archive plan")
}

#[test]
fn same_manifest_transfers_to_two_destinations_remain_independent() {
    let plan = archive_plan();
    let temporary = tempfile::tempdir().expect("temporary journal root");
    let mut journal = DirectoryCampaignTransferJournal::open(temporary.path().join("journal"))
        .expect("open journal");
    let first = CampaignTransferOperationId::for_archive(
        plan.manifest_id(),
        "destination-a",
        "archive",
        None,
        DurabilityRequirement::new(1, false).expect("durability"),
    )
    .expect("first operation");
    let second = CampaignTransferOperationId::for_archive(
        plan.manifest_id(),
        "destination-b",
        "archive",
        None,
        DurabilityRequirement::new(1, false).expect("durability"),
    )
    .expect("second operation");
    assert_ne!(first, second);

    journal
        .begin(first, TransferJournalRole::Source, &plan)
        .expect("begin first transfer");
    journal
        .begin(second, TransferJournalRole::Source, &plan)
        .expect("begin second transfer");
    journal.complete(first).expect("complete first transfer");
    assert!(!journal.contains(first).expect("first record state"));
    assert!(journal.contains(second).expect("second record state"));

    drop(journal);
    let reopened = DirectoryCampaignTransferJournal::open(temporary.path().join("journal"))
        .expect("reopen journal");
    assert!(reopened.contains(second).expect("reopened second record"));
}

#[test]
fn reopening_cleans_a_torn_staging_file_without_losing_complete_records() {
    let plan = archive_plan();
    let temporary = tempfile::tempdir().expect("temporary journal root");
    let journal_root = temporary.path().join("journal");
    let operation = CampaignTransferOperationId::for_archive(
        plan.manifest_id(),
        "destination",
        "archive",
        Some("campaign"),
        DurabilityRequirement::new(1, false).expect("durability"),
    )
    .expect("operation");
    let mut journal = DirectoryCampaignTransferJournal::open(&journal_root).expect("open journal");
    journal
        .begin(operation, TransferJournalRole::Source, &plan)
        .expect("begin transfer");
    drop(journal);

    let torn = journal_root
        .join(STAGING_DIRECTORY)
        .join(format!("{}.staging", "a".repeat(64)));
    fs::write(&torn, b"torn record prefix").expect("write torn staging file");

    let reopened = DirectoryCampaignTransferJournal::open(&journal_root).expect("reopen journal");
    assert!(!torn.exists());
    assert!(
        reopened
            .contains(operation)
            .expect("complete record retained")
    );
}

#[test]
fn retries_reestablish_durability_after_visible_journal_mutations() {
    let plan = archive_plan();
    let temporary = tempfile::tempdir().expect("temporary journal root");
    let mut journal = DirectoryCampaignTransferJournal::open(temporary.path().join("journal"))
        .expect("open journal");
    let operation = CampaignTransferOperationId::for_archive(
        plan.manifest_id(),
        "destination",
        "archive",
        None,
        DurabilityRequirement::new(1, false).expect("durability"),
    )
    .expect("operation");

    fail_next_directory_sync();
    assert!(matches!(
        journal.begin(operation, TransferJournalRole::Source, &plan),
        Err(CampaignTransferJournalError::Io { .. })
    ));
    assert!(journal.contains(operation).expect("visible record"));
    fail_next_directory_sync();
    assert!(matches!(
        journal.begin(operation, TransferJournalRole::Source, &plan),
        Err(CampaignTransferJournalError::Io { .. })
    ));
    journal
        .begin(operation, TransferJournalRole::Source, &plan)
        .expect("retry durable record publication");

    fail_next_directory_sync();
    assert!(matches!(
        journal.complete(operation),
        Err(CampaignTransferJournalError::Io { .. })
    ));
    assert!(!journal.contains(operation).expect("visible removal"));
    fail_next_directory_sync();
    assert!(matches!(
        journal.complete(operation),
        Err(CampaignTransferJournalError::Io { .. })
    ));
    journal
        .complete(operation)
        .expect("retry durable record removal");
}

#[test]
fn reopening_retries_parent_sync_after_a_visible_journal_directory() {
    let temporary = tempfile::tempdir().expect("temporary journal parent");
    let journal_root = temporary.path().join("journal");

    fail_next_directory_sync();
    assert!(matches!(
        DirectoryCampaignTransferJournal::open(&journal_root),
        Err(CampaignTransferJournalError::Io { .. })
    ));
    assert!(journal_root.is_dir());

    fail_next_directory_sync();
    assert!(matches!(
        DirectoryCampaignTransferJournal::open(&journal_root),
        Err(CampaignTransferJournalError::Io { .. })
    ));
    DirectoryCampaignTransferJournal::open(&journal_root)
        .expect("retry resyncs the visible journal directory");
}

#[test]
fn existing_child_directory_retries_its_parent_sync() {
    let temporary = tempfile::tempdir().expect("temporary journal parent");
    let journal_root = temporary.path().join("journal");
    fs::create_dir(&journal_root).expect("create journal directory");
    fs::create_dir(journal_root.join(RECORDS_DIRECTORY)).expect("create visible records directory");

    fail_next_directory_sync();
    assert!(matches!(
        create_child_directory(&journal_root, RECORDS_DIRECTORY),
        Err(CampaignTransferJournalError::Io { .. })
    ));
    create_child_directory(&journal_root, RECORDS_DIRECTORY)
        .expect("retry resyncs the visible records directory");
}

#[test]
fn bounded_record_reader_rejects_an_oversized_file() {
    let temporary = tempfile::tempdir().expect("temporary record directory");
    let record = temporary.path().join("oversized.record");
    fs::File::create(&record)
        .and_then(|file| file.set_len(MAX_TRANSFER_RECORD_BYTES + 1))
        .expect("create oversized sparse record");

    assert!(matches!(
        read_bounded_file(&record),
        Err(CampaignTransferJournalError::ObjectLimit)
    ));
}

#[test]
fn durable_transfer_stages_source_metadata_and_retries_idempotently() {
    let temporary = tempfile::tempdir().expect("temporary transfer root");
    let source = CampaignRepository::new(
        Arc::new(DirectoryBlobBackend::new(
            "source",
            temporary.path().join("source-objects"),
        )),
        Arc::new(DirectoryRefBackend::new(
            temporary.path().join("source-refs"),
        )),
    );
    let destination = CampaignRepository::new(
        Arc::new(DirectoryBlobBackend::new(
            "destination",
            temporary.path().join("destination-objects"),
        )),
        Arc::new(DirectoryRefBackend::new(
            temporary.path().join("destination-refs"),
        )),
    );
    let plan = plan_in_repository(&source);
    let mut source_journal =
        DirectoryCampaignTransferJournal::open(temporary.path().join("source-transfer-journal"))
            .expect("source journal");
    let mut destination_journal = DirectoryCampaignTransferJournal::open(
        temporary.path().join("destination-transfer-journal"),
    )
    .expect("destination journal");
    let durability = DurabilityRequirement::new(1, false).expect("durability");
    let first = {
        let mut source_endpoint =
            CampaignArchiveTransferEndpoint::new(&source, &mut source_journal, "source", true);
        let mut destination_endpoint = CampaignArchiveTransferEndpoint::new(
            &destination,
            &mut destination_journal,
            "destination",
            true,
        );

        transfer_campaign_archive_durably(
            &mut source_endpoint,
            &mut destination_endpoint,
            &plan,
            "metadata",
            None,
            durability,
        )
        .expect("first transfer")
    };
    assert!(first.copied_objects > 0);
    assert_eq!(
        destination
            .inspect_campaign_archive_ref("metadata")
            .expect("inspect destination archive")
            .manifest_id(),
        plan.manifest_id()
    );

    let mut source_endpoint =
        CampaignArchiveTransferEndpoint::new(&source, &mut source_journal, "source", true);
    let mut destination_endpoint = CampaignArchiveTransferEndpoint::new(
        &destination,
        &mut destination_journal,
        "destination",
        true,
    );

    let retry = transfer_campaign_archive_durably(
        &mut source_endpoint,
        &mut destination_endpoint,
        &plan,
        "metadata",
        None,
        durability,
    )
    .expect("idempotent retry");
    assert_eq!(retry.copied_objects, 0);
    assert_eq!(retry.existing_objects, plan.transfer_objects().len() as u64);
}

#[test]
fn durable_transfer_rejects_read_only_source_before_journaling() {
    let temporary = tempfile::tempdir().expect("temporary transfer root");
    let source = CampaignRepository::new(
        Arc::new(DirectoryBlobBackend::new(
            "source",
            temporary.path().join("source-objects"),
        )),
        Arc::new(DirectoryRefBackend::new(
            temporary.path().join("source-refs"),
        )),
    );
    let destination = CampaignRepository::new(
        Arc::new(DirectoryBlobBackend::new(
            "destination",
            temporary.path().join("destination-objects"),
        )),
        Arc::new(DirectoryRefBackend::new(
            temporary.path().join("destination-refs"),
        )),
    );
    let plan = plan_in_repository(&source);
    let mut source_journal =
        DirectoryCampaignTransferJournal::open(temporary.path().join("source-transfer-journal"))
            .expect("source journal");
    let mut destination_journal = DirectoryCampaignTransferJournal::open(
        temporary.path().join("destination-transfer-journal"),
    )
    .expect("destination journal");
    let durability = DurabilityRequirement::new(1, false).expect("durability");
    let mut source_endpoint =
        CampaignArchiveTransferEndpoint::new(&source, &mut source_journal, "source", false);
    let mut destination_endpoint = CampaignArchiveTransferEndpoint::new(
        &destination,
        &mut destination_journal,
        "destination",
        true,
    );

    assert!(matches!(
        transfer_campaign_archive_durably(
            &mut source_endpoint,
            &mut destination_endpoint,
            &plan,
            "metadata",
            None,
            durability,
        ),
        Err(CampaignArchiveTransferError::SourceReadOnly)
    ));
    assert!(
        !source_endpoint
            .journal
            .contains(
                CampaignTransferOperationId::for_archive(
                    plan.manifest_id(),
                    "destination",
                    "metadata",
                    None,
                    durability,
                )
                .expect("operation")
            )
            .expect("source journal state")
    );
}

#[test]
fn invalid_publication_intent_is_rejected_before_transfer_ownership() {
    let temporary = tempfile::tempdir().expect("temporary transfer root");
    let source = CampaignRepository::new(
        Arc::new(DirectoryBlobBackend::new(
            "source",
            temporary.path().join("source-objects"),
        )),
        Arc::new(DirectoryRefBackend::new(
            temporary.path().join("source-refs"),
        )),
    );
    let destination = CampaignRepository::new(
        Arc::new(DirectoryBlobBackend::new(
            "destination",
            temporary.path().join("destination-objects"),
        )),
        Arc::new(DirectoryRefBackend::new(
            temporary.path().join("destination-refs"),
        )),
    );
    let plan = plan_in_repository(&source);
    let mut source_journal =
        DirectoryCampaignTransferJournal::open(temporary.path().join("source-transfer-journal"))
            .expect("source journal");
    let mut destination_journal = DirectoryCampaignTransferJournal::open(
        temporary.path().join("destination-transfer-journal"),
    )
    .expect("destination journal");
    let durability = DurabilityRequirement::new(1, false).expect("durability");
    let operation = CampaignTransferOperationId::for_archive(
        plan.manifest_id(),
        "destination",
        "metadata",
        Some("ordinary-head"),
        durability,
    )
    .expect("operation");
    let mut source_endpoint =
        CampaignArchiveTransferEndpoint::new(&source, &mut source_journal, "source", true);
    let mut destination_endpoint = CampaignArchiveTransferEndpoint::new(
        &destination,
        &mut destination_journal,
        "destination",
        true,
    );

    assert!(matches!(
        transfer_campaign_archive_durably(
            &mut source_endpoint,
            &mut destination_endpoint,
            &plan,
            "metadata",
            Some("ordinary-head"),
            durability,
        ),
        Err(CampaignArchiveTransferError::Repository(
            CampaignRepositoryError::InvalidRequest { .. }
        ))
    ));
    assert!(
        !source_endpoint
            .journal
            .contains(operation)
            .expect("source journal state")
    );
    assert!(
        !destination_endpoint
            .journal
            .contains(operation)
            .expect("destination journal state")
    );
}

#[test]
fn destination_rejects_checkpoint_whose_configuration_disagrees_with_manifest() {
    let temporary = tempfile::tempdir().expect("temporary transfer root");
    let source_backend = Arc::new(DirectoryBlobBackend::new(
        "source",
        temporary.path().join("source-objects"),
    ));
    let source = CampaignRepository::new(
        source_backend.clone(),
        Arc::new(DirectoryRefBackend::new(
            temporary.path().join("source-refs"),
        )),
    );
    let scenario =
        ScenarioDef::from_canonical_material("crucible.test.archive-transfer", "source-scenario");
    let configuration = Configuration::genesis(scenario.clone());
    let scenario_id = ScenarioDefId::from_hash(CampaignHash::from_bytes(scenario.id().bytes));
    let configuration_id =
        ConfigurationId::from_hash(CampaignHash::from_bytes(configuration.id().bytes));
    let scenario_artifact = source
        .publish_scenario_artifact(scenario_id, 1, b"scenario".to_vec())
        .expect("scenario artifact");
    let configuration_artifact = source
        .publish_configuration_artifact(
            scenario_id,
            scenario_artifact,
            configuration_id,
            1,
            b"configuration".to_vec(),
        )
        .expect("configuration artifact");
    let lineage = CampaignLineage::new(
        scenario_id,
        scenario_artifact,
        configuration_id,
        configuration_artifact,
        "crucible-transfer-test",
        "qemu-transfer-test",
        BTreeMap::from([("control".to_owned(), 1)]),
        1,
        1,
    )
    .expect("lineage");
    let campaign = CampaignName::new("source").expect("campaign");
    source
        .create(
            campaign.as_str(),
            &lineage,
            &CampaignPolicy::new(
                scenario_id,
                CampaignSeed::from_bytes([0x51; 32]),
                CampaignMode::Strict,
                ExplorerPolicy::Exhaustive {
                    maximum_cardinality: 1,
                },
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeSet::new(),
                FairnessPolicy::new(0, 0).expect("fairness"),
                RetentionPolicy::new(true, 1, true, true),
                true,
            )
            .expect("policy"),
            &BTreeMap::new(),
        )
        .expect("create campaign");
    let expected_snapshot = source.head(campaign.as_str()).expect("head").snapshot_id();
    source
        .apply_pin(
            campaign.as_str(),
            &PinRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "crucible.test.archive-transfer.command",
                    b"pin",
                )),
                expected_snapshot,
                change: PinChange::new(
                    configuration_id,
                    Some(PinRetention::Exact),
                    "retain for transfer",
                )
                .expect("pin change"),
            },
        )
        .expect("pin campaign");

    let other_scenario =
        ScenarioDef::from_canonical_material("crucible.test.archive-transfer", "other-scenario");
    let other_configuration = Configuration::genesis(other_scenario);
    let checkpoint = Checkpoint::from_recorded_configuration(
        &other_configuration,
        None,
        VirtualTime::default(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .expect("checkpoint");
    let snapshot = QemuVmSnapshot::diskless(checkpoint, QemuReplayOracleValidation::NotRun)
        .expect("QEMU snapshot");
    let source_checkpoint_backend: Arc<dyn ImmutableBlobBackend> = source_backend;
    let source_checkpoints = ExactCheckpointStore::new(source_checkpoint_backend, 1024 * 1024)
        .expect("source checkpoint store");
    let prepared = source_checkpoints
        .prepare(&snapshot, BlobHandle::from_bytes(vec![0x5a; 4096]))
        .expect("prepare checkpoint");
    let wrong_checkpoint = source_checkpoints
        .publish(&prepared)
        .expect("publish checkpoint")
        .root();
    let mut resolver = ReturningCheckpoint(wrong_checkpoint);
    let plan = source
        .plan_campaign_archive(
            source
                .head(campaign.as_str())
                .expect("pinned head")
                .snapshot_id(),
            CampaignArchivePolicy::Executable,
            [],
            Some(&mut resolver),
        )
        .expect("executable plan");

    let destination_backend = Arc::new(DirectoryBlobBackend::new(
        "destination",
        temporary.path().join("destination-objects"),
    ));
    let destination = CampaignRepository::new(
        destination_backend.clone(),
        Arc::new(DirectoryRefBackend::new(
            temporary.path().join("destination-refs"),
        )),
    );
    let destination_checkpoint_backend: Arc<dyn ImmutableBlobBackend> = destination_backend;
    let destination_checkpoints =
        ExactCheckpointStore::new(destination_checkpoint_backend, 1024 * 1024)
            .expect("destination checkpoint store");
    let mut source_journal =
        DirectoryCampaignTransferJournal::open(temporary.path().join("source-transfer-journal"))
            .expect("source journal");
    let mut destination_journal = DirectoryCampaignTransferJournal::open(
        temporary.path().join("destination-transfer-journal"),
    )
    .expect("destination journal");
    let durability = DurabilityRequirement::new(1, false).expect("durability");
    let operation = CampaignTransferOperationId::for_archive(
        plan.manifest_id(),
        "destination",
        "executable",
        Some("imported"),
        durability,
    )
    .expect("operation");
    let mut source_endpoint =
        CampaignArchiveTransferEndpoint::new(&source, &mut source_journal, "source", true);
    let mut destination_endpoint = CampaignArchiveTransferEndpoint::new_with_checkpoints(
        &destination,
        &mut destination_journal,
        "destination",
        true,
        &destination_checkpoints,
    );

    assert!(matches!(
        transfer_campaign_archive_durably(
            &mut source_endpoint,
            &mut destination_endpoint,
            &plan,
            "executable",
            Some("imported"),
            durability,
        ),
        Err(CampaignArchiveTransferError::CheckpointConfigurationMismatch)
    ));
    assert!(
        source_endpoint
            .journal
            .contains(operation)
            .expect("source ownership retained")
    );
    assert!(
        destination_endpoint
            .journal
            .contains(operation)
            .expect("destination ownership retained")
    );
    assert!(matches!(
        destination.inspect_campaign_archive_ref("executable"),
        Err(CampaignRepositoryError::NotFound)
    ));
    assert!(matches!(
        destination.head("imported"),
        Err(CampaignRepositoryError::NotFound)
    ));
}

#[test]
fn corrupt_destination_object_retains_ownership_and_retries_after_repair() {
    let temporary = tempfile::tempdir().expect("temporary transfer root");
    let source_backend = Arc::new(DirectoryBlobBackend::new(
        "source",
        temporary.path().join("source-objects"),
    ));
    let source = CampaignRepository::new(
        source_backend.clone(),
        Arc::new(DirectoryRefBackend::new(
            temporary.path().join("source-refs"),
        )),
    );
    let destination_backend = Arc::new(DirectoryBlobBackend::new(
        "destination",
        temporary.path().join("destination-objects"),
    ));
    let destination = CampaignRepository::new(
        destination_backend.clone(),
        Arc::new(DirectoryRefBackend::new(
            temporary.path().join("destination-refs"),
        )),
    );
    let plan = plan_in_repository(&source);
    let damaged = plan.selected()[0];
    let source_handle = source_backend
        .read(damaged.id(), None)
        .expect("source object");
    destination_backend
        .put_if_absent(damaged.id(), &source_handle)
        .expect("seed destination object");
    let damaged_path = directory_object_path(destination_backend.root(), damaged.id());
    fs::write(&damaged_path, b"corrupt object frame").expect("corrupt destination object");

    let source_journal_root = temporary.path().join("source-transfer-journal");
    let destination_journal_root = temporary.path().join("destination-transfer-journal");
    let durability = DurabilityRequirement::new(1, false).expect("durability");
    let operation = CampaignTransferOperationId::for_archive(
        plan.manifest_id(),
        "destination",
        "metadata",
        None,
        durability,
    )
    .expect("operation");
    {
        let mut source_journal =
            DirectoryCampaignTransferJournal::open(&source_journal_root).expect("source journal");
        let mut destination_journal =
            DirectoryCampaignTransferJournal::open(&destination_journal_root)
                .expect("destination journal");
        let mut source_endpoint =
            CampaignArchiveTransferEndpoint::new(&source, &mut source_journal, "source", true);
        let mut destination_endpoint = CampaignArchiveTransferEndpoint::new(
            &destination,
            &mut destination_journal,
            "destination",
            true,
        );

        assert!(matches!(
            transfer_campaign_archive_durably(
                &mut source_endpoint,
                &mut destination_endpoint,
                &plan,
                "metadata",
                None,
                durability,
            ),
            Err(CampaignArchiveTransferError::Repository(
                CampaignRepositoryError::Store(
                    crucible_cas::content_store::StoreError::Corrupt { .. }
                )
            ))
        ));
    }

    fs::remove_file(&damaged_path).expect("remove corrupt object for repair");
    let mut source_journal = DirectoryCampaignTransferJournal::open(&source_journal_root)
        .expect("reopen source journal");
    let mut destination_journal = DirectoryCampaignTransferJournal::open(&destination_journal_root)
        .expect("reopen destination journal");
    assert!(
        source_journal
            .contains(operation)
            .expect("source ownership survived restart")
    );
    assert!(
        destination_journal
            .contains(operation)
            .expect("destination ownership survived restart")
    );
    let mut source_endpoint =
        CampaignArchiveTransferEndpoint::new(&source, &mut source_journal, "source", true);
    let mut destination_endpoint = CampaignArchiveTransferEndpoint::new(
        &destination,
        &mut destination_journal,
        "destination",
        true,
    );

    transfer_campaign_archive_durably(
        &mut source_endpoint,
        &mut destination_endpoint,
        &plan,
        "metadata",
        None,
        durability,
    )
    .expect("retry after destination repair");
    assert!(
        !source_endpoint
            .journal
            .contains(operation)
            .expect("source ownership retired")
    );
    assert!(
        !destination_endpoint
            .journal
            .contains(operation)
            .expect("destination ownership retired")
    );
}

fn directory_object_path(root: &Path, id: crucible_cas::content_store::ContentId) -> PathBuf {
    let encoded = id.encode();
    let digest = encoded.rsplit_once('.').expect("content ID digest").1;
    root.join(id.kind().as_str())
        .join(id.schema_version().to_string())
        .join(&digest[..2])
        .join(digest)
}
