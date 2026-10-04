//! Exact-pin materialization journal regressions.

// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for failure localization.
#![allow(clippy::expect_used)]

use crucible_campaign::{
    CampaignCommandId, CampaignLineage, CampaignMode, CampaignPolicy, CampaignSeed, ExactRational,
    ExplorerPolicy, FairnessPolicy, PinChange, PinRequest, ProgressiveWideningPolicy, PuctPolicy,
    RetentionPolicy, ScenarioDefId,
};
use crucible_cas::content_store::{
    BackendCapabilities, BlobHandle, ByteRange, ImmutableBlobBackend, MemoryBlobBackend,
    MemoryRefBackend, ObjectKind, PlacementReceipt, PutReceipt, StoreError, StoreGraph,
    StoreGraphConfig, StoreNodeId, StoreNodeSpec,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::*;

const STORE_LIMIT: u64 = 1024 * 1024;

#[test]
fn exact_pin_owner_drop_releases_a_duplicated_writer_descriptor() {
    let directory = tempfile::tempdir().expect("selection directory");
    let store =
        DirectoryExactPinMaterializationStore::open(directory.path()).expect("first writer");
    let inherited = store
        .writer_lock
        .try_clone()
        .expect("duplicate inherited writer descriptor");

    assert!(DirectoryExactPinMaterializationStore::open(directory.path()).is_err());
    drop(store);

    let replacement = DirectoryExactPinMaterializationStore::open(directory.path())
        .expect("owner drop releases inherited lock");
    drop(replacement);
    drop(inherited);
}

struct TestDurableBackend {
    memory: MemoryBlobBackend,
}

impl TestDurableBackend {
    fn new() -> Self {
        Self {
            memory: MemoryBlobBackend::new("exact-pin-materialization-test", 64 * STORE_LIMIT),
        }
    }
}

impl ImmutableBlobBackend for TestDurableBackend {
    fn name(&self) -> &str {
        "exact-pin-materialization-test"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            durable: true,
            deferred_write: false,
            range_read: true,
            streaming_read: true,
            conditional_create: true,
            streaming_put: true,
            repair_inventory: false,
            planned_delete: false,
        }
    }

    fn contains(&self, id: crucible_cas::content_store::ContentId) -> Result<bool, StoreError> {
        self.memory.contains(id)
    }

    fn read(
        &self,
        id: crucible_cas::content_store::ContentId,
        range: Option<ByteRange>,
    ) -> Result<BlobHandle, StoreError> {
        self.memory.read(id, range)
    }

    fn put_if_absent(
        &self,
        id: crucible_cas::content_store::ContentId,
        source: &BlobHandle,
    ) -> Result<PutReceipt, StoreError> {
        self.memory.put_if_absent(id, source)?;
        Ok(PutReceipt {
            id,
            placements: vec![PlacementReceipt {
                backend: self.name().to_owned(),
                durable: true,
                logical_length: source.logical_length(),
            }],
        })
    }
}

struct Fixture {
    repository: CampaignRepository,
    refs: Arc<MemoryRefBackend>,
    checkpoints: ExactCheckpointStore,
    campaign: CampaignName,
    configuration: ConfigurationId,
    pin_fact: CampaignFactId,
    checkpoint: ExactCheckpointId,
}

#[test]
fn gc_requires_current_selection_and_ignores_stale_record_after_unpin() {
    let temp = tempfile::tempdir().expect("exact-pin GC root");
    let node = StoreNodeId::new("durable").expect("store node");
    let (graph, admin) = StoreGraph::build_with_admin(StoreGraphConfig {
        root: node.clone(),
        admitted_kinds: BTreeSet::from([
            ObjectKind::CampaignFact,
            ObjectKind::CampaignSnapshot,
            ObjectKind::MerkleNode,
            ObjectKind::Scenario,
            ObjectKind::Configuration,
            ObjectKind::Policy,
            ObjectKind::ExactManifest,
            ObjectKind::RamExtent,
            ObjectKind::DiskExtent,
            ObjectKind::DeviceState,
            ObjectKind::Observation,
            ObjectKind::Finding,
            ObjectKind::Projection,
            ObjectKind::Trace,
        ]),
        nodes: BTreeMap::from([(
            node,
            StoreNodeSpec::Directory {
                root: temp.path().join("objects"),
            },
        )]),
    })
    .expect("durable store graph");
    let graph = Arc::new(graph);
    let backend: Arc<dyn ImmutableBlobBackend> = graph.clone();
    let fixture = fixture_with_backend("gc", backend);
    let mut ledger = crate::MemoryAssignmentLedger::default();
    let mut selections = DirectoryExactPinMaterializationStore::open(temp.path().join("pins"))
        .expect("selection store");

    assert!(matches!(
        crate::plan_single_host_campaign_gc(
            &fixture.repository,
            fixture.refs.as_ref(),
            &mut ledger,
            None,
            None,
            &admin,
        ),
        Err(crate::CampaignGcPlanningError::MissingExactPinMaterialization { .. })
    ));
    select_fixture(&mut selections, &fixture).expect("select exact materialization");
    let planned = crate::plan_single_host_campaign_gc(
        &fixture.repository,
        fixture.refs.as_ref(),
        &mut ledger,
        None,
        Some(&mut selections),
        &admin,
    )
    .expect("plan with exact materialization");
    let exact_closure = fixture
        .checkpoints
        .authenticated_production_closure_ids(fixture.checkpoint)
        .expect("complete exact checkpoint closure");
    assert!(exact_closure.len() > 1);
    assert!(
        exact_closure
            .iter()
            .all(|id| planned.roots().iter().any(|root| root == *id))
    );
    assert!(
        planned
            .candidates()
            .iter()
            .all(|candidate| !exact_closure.contains(&candidate.id()))
    );
    let (mut journal, _) =
        crate::DirectoryCampaignGcJournal::create(temp.path().join("gc-journal"), &planned)
            .expect("persist exact-pin GC plan");

    let head = fixture
        .repository
        .head(fixture.campaign.as_str())
        .expect("current pinned head");
    let unpin = PinRequest {
        command: CampaignCommandId::from_hash(CampaignHash::derive(
            "crucible.test.exact-pin-materialization.unpin.v1",
            b"gc",
        )),
        expected_snapshot: head.snapshot_id(),
        change: PinChange::new(fixture.configuration, None, "release exact materialization")
            .expect("unpin change"),
    };
    fixture
        .repository
        .apply_pin(fixture.campaign.as_str(), &unpin)
        .expect("unpin campaign");

    assert!(matches!(
        crate::apply_single_host_campaign_gc(
            &mut journal,
            &fixture.repository,
            fixture.refs.as_ref(),
            &mut ledger,
            None,
            Some(&mut selections),
            &admin,
        ),
        Err(crate::CampaignGcApplyError::RefBasisChanged)
    ));
    assert!(
        graph
            .contains(fixture.checkpoint.content_id())
            .expect("checkpoint retained after stale plan rejection")
    );

    let after_unpin = crate::plan_single_host_campaign_gc(
        &fixture.repository,
        fixture.refs.as_ref(),
        &mut ledger,
        None,
        Some(&mut selections),
        &admin,
    )
    .expect("plan after unpin with stale selection record");
    assert!(
        !after_unpin
            .roots()
            .iter()
            .any(|root| root == fixture.checkpoint.content_id())
    );
    assert!(
        after_unpin
            .candidates()
            .iter()
            .any(|candidate| candidate.id() == fixture.checkpoint.content_id())
    );
    drop(admin);
    drop(graph);
}

#[test]
fn selection_authenticates_pin_and_checkpoint_and_survives_restart() {
    let temp = tempfile::tempdir().expect("selection journal root");
    let fixture = fixture("round-trip");
    let mut store = DirectoryExactPinMaterializationStore::open(temp.path())
        .expect("open exact-pin selection store");

    assert_eq!(
        select_fixture(&mut store, &fixture).expect("select exact checkpoint"),
        ExactPinSelectionDisposition::Stored
    );
    assert_eq!(
        select_fixture(&mut store, &fixture).expect("replay exact selection"),
        ExactPinSelectionDisposition::Existing
    );

    let path = store.selection_path(&fixture.campaign, fixture.configuration);
    let bytes = fs::read(&path).expect("read canonical selection");
    let decoded = decode_selection(&bytes).expect("decode canonical selection");
    assert_eq!(decoded.campaign(), &fixture.campaign);
    assert_eq!(decoded.configuration(), fixture.configuration);
    assert_eq!(decoded.pin_fact(), fixture.pin_fact);
    assert_eq!(decoded.checkpoint(), fixture.checkpoint);
    let authenticated = decoded
        .authenticate_current(&fixture.repository, &fixture.checkpoints)
        .expect("authenticate retained current-schema checkpoint");
    assert_eq!(authenticated.root(), fixture.checkpoint);
    assert_eq!(
        authenticated.configuration().bytes,
        fixture.configuration.as_hash().as_bytes()
    );

    assert_eq!(
        CampaignHash::derive(
            "crucible.test.exact-pin-materialization-selection-golden.v1",
            &bytes,
        )
        .to_hex(),
        // The current closure includes the v6 scheduler continuation and its
        // World-bound I/O ledger. Authenticate the pin and closure above before
        // pinning these recanonicalized selection bytes.
        "547dbea896dc4d2c24b24e3b0b1caf58ef75daa24bf52a423dfb09bdd49c77ea"
    );
    drop(store);

    let mut reopened = DirectoryExactPinMaterializationStore::open(temp.path())
        .expect("reopen exact-pin selection store");
    let mut fence = reopened
        .acquire_exact_pin_retention_fence()
        .expect("acquire restarted selection fence");
    assert_eq!(
        fence
            .selection(&fixture.campaign, fixture.configuration)
            .expect("load restarted selection"),
        Some(decoded)
    );
}

#[test]
fn imported_selection_never_replaces_an_existing_campaign_owner() {
    let temp = tempfile::tempdir().expect("selection journal root");
    let fixture = fixture("import-conflict");
    let original = ExactPinMaterializationSelection::prepare(
        &fixture.repository,
        &fixture.checkpoints,
        &fixture.campaign,
        fixture.configuration,
        fixture.checkpoint,
    )
    .expect("prepare original selection");
    let mut conflicting = original.clone();
    let conflicting_content = crucible_cas::content_store::ContentId::for_bytes(
        crucible_cas::content_store::ObjectKind::ExactManifest,
        5,
        b"conflicting imported checkpoint",
    );
    conflicting.checkpoint = ExactCheckpointId::parse(&format!(
        "crucible.executor.exact-checkpoint-root@{conflicting_content}"
    ))
    .expect("conflicting checkpoint ID");
    let mut store = DirectoryExactPinMaterializationStore::open(temp.path())
        .expect("open exact-pin selection store");

    assert_eq!(
        store
            .select(original.clone())
            .expect("install original selection"),
        ExactPinSelectionDisposition::Stored
    );
    assert!(matches!(
        store.select_import_if_absent_inner(&conflicting),
        Err(ExactPinRetentionError::SelectionConflict { .. })
    ));
    let mut fence = store
        .acquire_exact_pin_retention_fence()
        .expect("acquire exact-pin selection fence");
    assert_eq!(
        fence
            .selection(&fixture.campaign, fixture.configuration)
            .expect("read preserved selection"),
        Some(original)
    );
}

#[test]
fn selection_rejects_unpinned_configuration_before_journal_write() {
    let temp = tempfile::tempdir().expect("selection journal root");
    let expected = fixture("expected");
    let foreign_configuration = ConfigurationId::from_hash(CampaignHash::derive(
        "crucible.test.foreign-checkpoint-configuration.v1",
        b"foreign checkpoint configuration",
    ));
    let mut store = DirectoryExactPinMaterializationStore::open(temp.path())
        .expect("open exact-pin selection store");

    assert!(matches!(
        ExactPinMaterializationSelection::prepare(
            &expected.repository,
            &expected.checkpoints,
            &expected.campaign,
            foreign_configuration,
            expected.checkpoint,
        ),
        Err(ExactPinRetentionError::PinNotExact { .. })
    ));
    assert!(
        store
            .acquire_exact_pin_retention_fence()
            .expect("selection fence")
            .selection(&expected.campaign, expected.configuration)
            .expect("selection lookup")
            .is_none()
    );
}

#[test]
fn archive_preparation_refuses_foreign_pin_and_unpromoted_checkpoint_without_replacing_owner() {
    let temp = tempfile::tempdir().expect("archive selection journal");
    let fixture = fixture_with_backend_and_encoding(
        "archive-refusal",
        Arc::new(TestDurableBackend::new()),
        true,
    );
    let head = fixture
        .repository
        .head(fixture.campaign.as_str())
        .expect("pinned source snapshot");
    let mut store = DirectoryExactPinMaterializationStore::open(temp.path())
        .expect("open retained selection owner");
    select_fixture(&mut store, &fixture).expect("retain existing operational selection");
    let path = store.selection_path(&fixture.campaign, fixture.configuration);
    let original = fs::read(&path).expect("original durable selection bytes");
    let foreign_content = crucible_cas::content_store::ContentId::for_bytes(
        ObjectKind::CampaignFact,
        15,
        b"foreign archive pin fact",
    );
    let declared_foreign_fact = CampaignFactId::parse(&format!(
        "crucible.campaign.fact@{}",
        foreign_content.encode()
    ))
    .expect("foreign pin fact identity");
    let absent_checkpoint_content = crucible_cas::content_store::ContentId::for_bytes(
        ObjectKind::ExactManifest,
        5,
        b"absent archive checkpoint",
    );
    let absent_checkpoint =
        ExactCheckpointId::try_from(absent_checkpoint_content).expect("absent checkpoint identity");

    // The authenticated snapshot pin must reject the foreign declaration
    // before attempting to load even an absent checkpoint.
    assert!(matches!(
        ExactPinMaterializationSelection::prepare_at_snapshot(
            &fixture.repository,
            &fixture.checkpoints,
            &fixture.campaign,
            head.snapshot_id(),
            fixture.configuration,
            declared_foreign_fact,
            absent_checkpoint,
        ),
        Err(ExactPinRetentionError::PinFactMismatch { expected, actual })
            if expected == declared_foreign_fact && actual == fixture.pin_fact
    ));
    assert!(
        fixture
            .checkpoints
            .load_attempt_checkpoint(fixture.checkpoint)
            .expect("authenticate actual stored production closure")
            .promotion_source()
            .is_none()
    );
    assert!(matches!(
        ExactPinMaterializationSelection::prepare_at_snapshot(
            &fixture.repository,
            &fixture.checkpoints,
            &fixture.campaign,
            head.snapshot_id(),
            fixture.configuration,
            fixture.pin_fact,
            fixture.checkpoint,
        ),
        Err(ExactPinRetentionError::CheckpointReplayOracleNotReady { checkpoint })
            if checkpoint == fixture.checkpoint
    ));

    assert_eq!(
        fs::read(&path).expect("preserved selection bytes"),
        original
    );
    assert_eq!(
        fixture
            .repository
            .head(fixture.campaign.as_str())
            .expect("preserved campaign ref")
            .snapshot_id(),
        head.snapshot_id()
    );
    drop(store);

    let mut reopened = DirectoryExactPinMaterializationStore::open(temp.path())
        .expect("restart retained selection owner");
    let mut fence = reopened
        .acquire_exact_pin_retention_fence()
        .expect("restarted retention fence");
    let retained = fence
        .selection(&fixture.campaign, fixture.configuration)
        .expect("read preserved selection after restart")
        .expect("original owner remains selected");
    assert_eq!(retained.checkpoint(), fixture.checkpoint);
    assert_eq!(retained.pin_fact(), fixture.pin_fact);
    retained
        .authenticate_current(&fixture.repository, &fixture.checkpoints)
        .expect("original operational selection still authenticates");
}

#[test]
fn oversized_selection_refusal_preserves_an_unrelated_owner_across_restart() {
    let temp = tempfile::tempdir().expect("bounded selection journal");
    let damaged = fixture("oversized");
    let unrelated = fixture("unrelated");
    let mut store =
        DirectoryExactPinMaterializationStore::open(temp.path()).expect("open selection owner");
    select_fixture(&mut store, &damaged).expect("select first checkpoint");
    select_fixture(&mut store, &unrelated).expect("select unrelated checkpoint");
    let damaged_path = store.selection_path(&damaged.campaign, damaged.configuration);
    let unrelated_path = store.selection_path(&unrelated.campaign, unrelated.configuration);
    let unrelated_bytes = fs::read(&unrelated_path).expect("unrelated durable selection");
    fs::write(
        &damaged_path,
        vec![0; MAX_SELECTION_RECORD_BYTES as usize + 1],
    )
    .expect("write one oversized record");
    drop(store);

    let mut reopened = DirectoryExactPinMaterializationStore::open(temp.path())
        .expect("reopen journal without eagerly reading record contents");
    assert!(matches!(
        reopened.clear(&damaged.campaign, damaged.configuration),
        Err(ExactPinRetentionError::Corrupt { reason })
            if reason == "selection-record-size"
    ));
    let mut fence = reopened
        .acquire_exact_pin_retention_fence()
        .expect("restarted bounded inventory fence");
    assert!(matches!(
        fence.selection(&damaged.campaign, damaged.configuration),
        Err(ExactPinRetentionError::Corrupt { reason })
            if reason == "selection-record-size"
    ));
    let retained = fence
        .selection(&unrelated.campaign, unrelated.configuration)
        .expect("unrelated selection remains readable")
        .expect("unrelated owner remains selected");
    retained
        .authenticate_current(&unrelated.repository, &unrelated.checkpoints)
        .expect("unrelated checkpoint still authenticates");
    assert_eq!(
        fs::read(&unrelated_path).expect("unrelated bytes after refusal"),
        unrelated_bytes
    );
    assert_eq!(
        fs::metadata(&damaged_path)
            .expect("refused record remains present")
            .len(),
        MAX_SELECTION_RECORD_BYTES + 1
    );
}

#[test]
fn clear_is_idempotent_and_corruption_fails_closed() {
    let temp = tempfile::tempdir().expect("selection journal root");
    let fixture = fixture("clear");
    let mut store = DirectoryExactPinMaterializationStore::open(temp.path())
        .expect("open exact-pin selection store");
    select_fixture(&mut store, &fixture).expect("select checkpoint");
    assert_eq!(
        store
            .clear(&fixture.campaign, fixture.configuration)
            .expect("clear selection"),
        ExactPinSelectionClearDisposition::Removed
    );
    assert_eq!(
        store
            .clear(&fixture.campaign, fixture.configuration)
            .expect("replay clear"),
        ExactPinSelectionClearDisposition::Absent
    );

    select_fixture(&mut store, &fixture).expect("restore selection");
    let path = store.selection_path(&fixture.campaign, fixture.configuration);
    let mut bytes = fs::read(&path).expect("read selection");
    let index = SELECTION_MAGIC.len() + 3;
    bytes[index] ^= 0x80;
    fs::write(&path, bytes).expect("corrupt selection");
    assert!(matches!(
        store
            .acquire_exact_pin_retention_fence()
            .expect("selection fence")
            .selection(&fixture.campaign, fixture.configuration),
        Err(ExactPinRetentionError::Corrupt { .. })
    ));
}

fn fixture(name: &str) -> Fixture {
    let backend = Arc::new(TestDurableBackend::new());
    fixture_with_backend(name, backend)
}

fn select_fixture(
    store: &mut DirectoryExactPinMaterializationStore,
    fixture: &Fixture,
) -> Result<ExactPinSelectionDisposition, ExactPinRetentionError> {
    let selection = ExactPinMaterializationSelection::prepare(
        &fixture.repository,
        &fixture.checkpoints,
        &fixture.campaign,
        fixture.configuration,
        fixture.checkpoint,
    )?;
    store.select(selection)
}

fn fixture_with_backend(name: &str, backend: Arc<dyn ImmutableBlobBackend>) -> Fixture {
    fixture_with_backend_and_encoding(name, backend, false)
}

fn fixture_with_backend_and_encoding(
    name: &str,
    backend: Arc<dyn ImmutableBlobBackend>,
    supported_artifacts: bool,
) -> Fixture {
    let production_directory = tempfile::tempdir().expect("production checkpoint fixture");
    let production = crucible_api::build_exact_ram_production_checkpoint_codec_fixture(
        production_directory.path(),
    )
    .expect("production checkpoint fixture");
    let refs = Arc::new(MemoryRefBackend::new());
    let repository = CampaignRepository::new(backend.clone(), refs.clone());
    let scenario_source = production.source().clone();
    let scenario = scenario_source.scenario_def();
    let configuration = production.configuration().clone();
    let scenario_id = ScenarioDefId::from_hash(CampaignHash::from_bytes(scenario.id().bytes));
    let configuration_id =
        ConfigurationId::from_hash(CampaignHash::from_bytes(configuration.id().bytes));
    // Existing selection goldens retain their schema-1 metadata. Archive
    // admission additionally decodes the supported scenario/configuration pair.
    let (scenario_schema, configuration_schema) = if supported_artifacts {
        let scenario = crate::encode_crucible_scenario_artifact(&scenario_source)
            .expect("encode supported scenario artifact");
        let configuration =
            crate::encode_crucible_configuration_artifact(&scenario, &configuration.schedule)
                .expect("encode supported configuration artifact");
        (scenario.payload_schema(), configuration.payload_schema())
    } else {
        (1, 1)
    };

    let scenario_artifact = repository
        .publish_scenario_artifact(
            scenario_id,
            scenario_schema,
            scenario_source.to_compact_binary(),
        )
        .expect("scenario artifact");
    let configuration_artifact = repository
        .publish_configuration_artifact(
            scenario_id,
            scenario_artifact,
            configuration_id,
            configuration_schema,
            configuration.schedule.to_compact_binary(),
        )
        .expect("configuration artifact");
    let lineage = CampaignLineage::new(
        scenario_id,
        scenario_artifact,
        configuration_id,
        configuration_artifact,
        "crucible-v1",
        "qemu-build-v1",
        BTreeMap::from([(String::from("control"), 1)]),
        scenario_schema,
        configuration_schema,
    )
    .expect("lineage");
    let policy = policy(scenario_id);
    let campaign = CampaignName::new(format!("exact-pin-{name}")).expect("campaign name");
    let created = repository
        .create(campaign.as_str(), &lineage, &policy, &BTreeMap::new())
        .expect("create campaign");
    let pin = PinRequest {
        command: CampaignCommandId::from_hash(CampaignHash::derive(
            "crucible.test.exact-pin-materialization.command.v1",
            name.as_bytes(),
        )),
        expected_snapshot: created.snapshot_id(),
        change: PinChange::new(
            configuration_id,
            Some(PinRetention::Exact),
            "retain exact materialization",
        )
        .expect("pin change"),
    };
    repository
        .apply_pin(campaign.as_str(), &pin)
        .expect("pin campaign");
    let mut pin_fact = None;
    repository
        .visit_pin_retention_roots(campaign.as_str(), &mut |record| {
            pin_fact = Some(record.fact());
        })
        .expect("pin inventory");

    let checkpoints = ExactCheckpointStore::new(backend, STORE_LIMIT).expect("checkpoint store");
    let prepared = checkpoints
        .prepare_production_closure(production.closure().clone())
        .expect("prepare checkpoint");
    let checkpoint = checkpoints
        .publish_production_closure(&prepared)
        .expect("publish checkpoint")
        .root();

    Fixture {
        repository,
        refs,
        checkpoints,
        campaign,
        configuration: configuration_id,
        pin_fact: pin_fact.expect("exact pin fact"),
        checkpoint,
    }
}

fn policy(scenario: ScenarioDefId) -> CampaignPolicy {
    let widening = ProgressiveWideningPolicy::new(
        ExactRational::new(1, 1).expect("rational"),
        ExactRational::new(1, 2).expect("rational"),
        1,
        100,
        1,
    )
    .expect("widening");
    CampaignPolicy::new(
        CampaignPolicy::identity(
            scenario,
            CampaignSeed::from_bytes([7; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::TreeSearch {
                widening: Some(widening),
                puct: PuctPolicy::new(1_000_000, 1, 0),
            },
        ),
        CampaignPolicy::rules(
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0).expect("fairness"),
            RetentionPolicy::new(true, 1, true, true),
            true,
        ),
    )
    .expect("policy")
}
