//! Exact-pin materialization journal regressions.

// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for failure localization.
#![allow(clippy::expect_used)]

use crucible_campaign::{
    CampaignCommandId, CampaignLineage, CampaignMode, CampaignPolicy, CampaignSeed, ExactRational,
    ExplorerPolicy, FairnessPolicy, PinChange, PinRequest, ProgressiveWideningPolicy, PuctPolicy,
    RetentionPolicy, ScenarioDefId,
};
use crucible_cas::content_store::{
    BackendCapabilities, BlobHandle, ByteRange, DirectoryBlobBackend, ImmutableBlobBackend,
    MemoryRefBackend, ObjectKind, PutReceipt, RefStoreAdmin, StoreError, StoreGraph,
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
    directory: DirectoryBlobBackend,
    _root: tempfile::TempDir,
}

impl TestDurableBackend {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("exact-pin checkpoint objects");
        Self {
            directory: DirectoryBlobBackend::new("exact-pin-materialization-test", root.path()),
            _root: root,
        }
    }
}

impl ImmutableBlobBackend for TestDurableBackend {
    fn name(&self) -> &str {
        "exact-pin-materialization-test"
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.directory.capabilities()
    }

    fn admit_object_graph(&self, objects: &[(ObjectKind, u64)]) -> Result<(), StoreError> {
        self.directory.admit_object_graph(objects)
    }

    fn contains(&self, id: crucible_cas::content_store::ContentId) -> Result<bool, StoreError> {
        self.directory.contains(id)
    }

    fn read(
        &self,
        id: crucible_cas::content_store::ContentId,
        range: Option<ByteRange>,
    ) -> Result<BlobHandle, StoreError> {
        self.directory.read(id, range)
    }

    fn put_if_absent(
        &self,
        id: crucible_cas::content_store::ContentId,
        source: &BlobHandle,
    ) -> Result<PutReceipt, StoreError> {
        self.directory.put_if_absent(id, source)
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
            ObjectKind::RamTree,
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
    let fixture = fixture_with_backend("gc", backend.clone());
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
    let exact_closure = {
        let inventory = fixture
            .refs
            .acquire_ref_inventory_fence()
            .expect("selected ref inventory fence");
        let closure = fixture
            .repository
            .authenticated_storage_closure([fixture.checkpoint.content_id()], inventory.as_ref())
            .expect("authenticated exact checkpoint frontier");
        assert_eq!(closure.ram_roots().len(), 1);
        let ram_store = crucible_cas::ram::RamStore::new(
            backend,
            crucible_cas::content_store::DurabilityRequirement::new(1, false)
                .expect("durable RAM policy"),
            crucible_cas::ram::RamStoreLimits::default(),
        )
        .expect("RAM inventory store");
        let mut retained = closure.objects().clone();
        for root in closure.ram_roots() {
            ram_store
                .visit_inventory_graph(*root, inventory.as_ref(), &mut |id| {
                    retained.insert(id);
                    Ok(())
                })
                .expect("authenticated transitive RAM inventory");
        }
        retained
    };
    assert!(exact_closure.len() > 1);
    assert!(
        exact_closure
            .iter()
            .any(|id| id.kind() == ObjectKind::RamTree)
    );
    assert!(
        exact_closure
            .iter()
            .any(|id| id.kind() == ObjectKind::RamExtent)
    );
    assert!(
        planned
            .roots()
            .iter()
            .any(|root| root == fixture.checkpoint.content_id())
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
    assert!(after_unpin.candidates().iter().any(|candidate| {
        candidate.id().kind() == ObjectKind::RamExtent && exact_closure.contains(&candidate.id())
    }));
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
        // Authenticate the current paged closure before pinning its selection
        // bytes, including the scheduler continuation and World-bound I/O ledger.
        "ecd18a83117b26c4b2e543d49666f6566d2e0052a29c8f47d0a747c4f4fd8fd2"
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
        6,
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
    let scenario_artifact = repository
        .publish_scenario_artifact(scenario_id, 1, scenario_source.to_compact_binary())
        .expect("scenario artifact");
    let configuration_artifact = repository
        .publish_configuration_artifact(
            scenario_id,
            scenario_artifact,
            configuration_id,
            1,
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

    let checkpoints =
        ExactCheckpointStore::new(backend, STORE_LIMIT, repository.ram_retention_authority())
            .expect("checkpoint store")
            .with_ram_root_resources(
                crate::exact_checkpoint_store::test_support::fixture_ram_root_resources()
                    .expect("finite component RAM-root credit"),
            );
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
