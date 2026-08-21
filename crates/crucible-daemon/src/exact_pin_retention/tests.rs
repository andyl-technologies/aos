//! Exact-pin materialization journal regressions.

// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for failure localization.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crucible::{Checkpoint, CheckpointKind, Configuration, ScenarioDef};
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
use crucible_qemu::{QemuReplayOracleValidation, QemuVmSnapshot};

use super::*;

const STORE_LIMIT: u64 = 1024 * 1024;

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
    assert!(
        planned
            .roots()
            .iter()
            .any(|root| root == fixture.checkpoint.content_id())
    );
    assert!(
        !planned
            .candidates()
            .iter()
            .any(|candidate| candidate.id() == fixture.checkpoint.content_id())
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
    assert_eq!(
        CampaignHash::derive(
            "crucible.test.exact-pin-materialization-selection-golden.v1",
            &bytes,
        )
        .to_hex(),
        "ca7198fa080f09a40df4c9142425566ad40958c1d9d8c30404749aee642614bb"
    );
    assert_eq!(decoded.campaign(), &fixture.campaign);
    assert_eq!(decoded.configuration(), fixture.configuration);
    assert_eq!(decoded.pin_fact(), fixture.pin_fact);
    assert_eq!(decoded.checkpoint(), fixture.checkpoint);
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
fn selection_rejects_wrong_checkpoint_before_journal_write() {
    let temp = tempfile::tempdir().expect("selection journal root");
    let expected = fixture("expected");
    let foreign = fixture("foreign");
    let mut store = DirectoryExactPinMaterializationStore::open(temp.path())
        .expect("open exact-pin selection store");

    assert!(matches!(
        ExactPinMaterializationSelection::prepare(
            &expected.repository,
            &foreign.checkpoints,
            &expected.campaign,
            expected.configuration,
            foreign.checkpoint,
        ),
        Err(ExactPinRetentionError::CheckpointConfigurationMismatch { .. })
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
    let refs = Arc::new(MemoryRefBackend::new());
    let repository = CampaignRepository::new(backend.clone(), refs.clone());
    let scenario =
        ScenarioDef::from_canonical_material("crucible.test.exact-pin-materialization", name);
    let configuration = Configuration::genesis(scenario.clone());
    let scenario_id = ScenarioDefId::from_hash(CampaignHash::from_bytes(scenario.id().bytes));
    let configuration_id =
        ConfigurationId::from_hash(CampaignHash::from_bytes(configuration.id().bytes));
    let scenario_artifact = repository
        .publish_scenario_artifact(scenario_id, 1, name.as_bytes().to_vec())
        .expect("scenario artifact");
    let configuration_artifact = repository
        .publish_configuration_artifact(
            scenario_id,
            scenario_artifact,
            configuration_id,
            1,
            name.as_bytes().to_vec(),
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
        1,
        1,
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

    let checkpoint = Checkpoint::from_recorded_configuration(
        &configuration,
        None,
        crucible::VirtualTime::default(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .expect("checkpoint");
    let snapshot = QemuVmSnapshot::diskless(checkpoint, QemuReplayOracleValidation::NotRun)
        .expect("QEMU snapshot");
    let checkpoints = ExactCheckpointStore::new(backend, STORE_LIMIT).expect("checkpoint store");
    let prepared = checkpoints
        .prepare(&snapshot, BlobHandle::from_bytes(vec![0x5a; 4096]))
        .expect("prepare checkpoint");
    let checkpoint = checkpoints
        .publish(&prepared)
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
        scenario,
        CampaignSeed::from_bytes([7; 32]),
        CampaignMode::Strict,
        ExplorerPolicy::TreeSearch {
            widening: Some(widening),
            puct: PuctPolicy::new(1_000_000, 1, 0),
        },
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeSet::new(),
        FairnessPolicy::new(0, 0).expect("fairness"),
        RetentionPolicy::new(true, 1, true, true),
        true,
    )
    .expect("policy")
}
