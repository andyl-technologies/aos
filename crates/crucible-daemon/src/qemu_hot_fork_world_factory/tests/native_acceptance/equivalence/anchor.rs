//! Native anchor roots and ancestor children against thin replay.
//!
//! A two-VM world parks at a network fault phase marker, after which curl
//! makes two guest selections. Three attempts follow one campaign path:
//!
//! ```text
//! D  discovery from genesis      --NextChoice--> A  (all VMs parked; network choice)
//! N  branch at A, link_down      --NextChoice--> G  (curl's first guest choice)
//! C  branch at G, u64 = 7        --NextChoice--> H  (curl's second guest choice)
//! ```
//!
//! N and C each run once by thin replay and once through the production
//! hot-first router over a managed pool that starts empty. N finds no root,
//! so the router keeps an anchor root at A and ends that execution
//! retryable; N's requeued execution runs as the anchor's hot child. C has
//! no root at G and runs as a child of the anchor, replaying the suffix from
//! A to G inside the child. Each pair must prepare equal semantic results:
//! the same child configuration, discoveries, measurements, properties,
//! coverage, effect trace, and terminal fingerprints.

use std::fmt::Debug;

use crucible::{NetworkFaultPhase, NetworkFaultSelectable};
use crucible_campaign::{ChoiceDiscovery, ConfigurationArtifact, ResolvedSelection};

use super::*;
use crate::managed_qemu_hot_fork_source_world_pool::ManagedQemuPublishedRootSink;
use crate::{
    AttemptExecutionDisposition, AttemptExecutionProduct, AttemptExecutionReconciliationStep,
    PreparedSemanticAttemptResult, QemuFreshExecutionRunner, QemuPublishedRootSink,
};

const THIN_LANE: &str = "anchor-thin";
const ROOT_LANE: &str = "anchor-root";
const CHILD_LANE: &str = "anchor-child";
const GUEST_SELECTABLE: &str = "hot-fork.retry-quanta";

/// Campaign state shared by every attempt of the fixture path.
struct AnchorCampaign {
    scenario: crucible::ScenarioDefForm,
    lineage: CampaignLineage,
    repository: Arc<CampaignRepository>,
    store: CampaignExecutorStore,
}

impl AnchorCampaign {
    fn new(scenario: crucible::ScenarioDefForm, lineage: CampaignLineage) -> Self {
        let repository = Arc::new(CampaignRepository::new(
            Arc::new(MemoryBlobBackend::new("native-anchor", 16 * 1024 * 1024)),
            Arc::new(MemoryRefBackend::new()),
        ));
        Self {
            scenario,
            lineage,
            store: CampaignExecutorStore::new(Arc::clone(&repository)),
            repository,
        }
    }

    /// Decodes an observed child against the campaign's selection records.
    fn child_configuration(&self, prepared: &PreparedSemanticAttemptResult) -> Configuration {
        let scenario_artifact =
            encode_crucible_scenario_artifact(&self.scenario).expect("encode anchor scenario");
        decode_crucible_configuration_artifact_with_selections(
            &self.scenario,
            &scenario_artifact,
            prepared.observation().child(),
            &self.store,
        )
        .expect("decode the observed child configuration")
    }

    /// Publishes one branch selection with its choice records and resolves it.
    fn publish_selection(
        &self,
        discovery: &ChoiceDiscovery,
        selection: &Selection,
    ) -> ResolvedSelection {
        self.repository
            .publish_choice_domain(discovery.domain())
            .expect("publish choice domain");
        self.repository
            .publish_selectable(discovery.declaration())
            .expect("publish selectable");
        self.repository
            .publish_choice_opportunity(discovery.opportunity())
            .expect("publish choice opportunity");
        self.repository
            .publish_selection(selection)
            .expect("publish branch selection");
        self.repository
            .resolve_selection(selection.id().expect("branch selection id"))
            .expect("resolve branch selection")
    }

    /// Builds the branch attempt that applies `selection` at `parent`.
    ///
    /// The start is decoded as repository dispatch decodes it, so recorded
    /// network fault branches come from the published selection records.
    fn branch(
        &self,
        prior: &BranchPath,
        parent: &ConfigurationArtifact,
        discovery: &ChoiceDiscovery,
        selection: &Selection,
    ) -> CrucibleAttemptExecution {
        let resolved = self.publish_selection(discovery, selection);
        let SelectionOrigin::CampaignBranch { branch_point, edge } = selection.origin() else {
            panic!("anchor fixture selections are campaign branches")
        };
        let mut segments = prior.segments().to_vec();
        segments.push(BranchPathSegment::new(branch_point, edge));
        let path = BranchPath::new(segments).expect("branch path");
        let attempt = Attempt::new(
            AttemptStart::Branch {
                edge,
                parent: parent.id().expect("parent artifact id"),
                selection: selection.id().expect("branch selection id"),
            },
            path.id().expect("branch path id"),
            StopCondition::NextChoice,
        )
        .expect("branch attempt");

        CrucibleAttemptExecution::decoded_branch_for_test(
            &self.store,
            self.lineage.clone(),
            self.scenario.clone(),
            attempt,
            path,
            parent.clone(),
            resolved,
        )
        .expect("decode the branch start as dispatch does")
    }
}

/// Returns the single discovery of the named selectable.
fn discovery_named<'a>(
    prepared: &'a PreparedSemanticAttemptResult,
    name: &str,
) -> &'a ChoiceDiscovery {
    let mut matching = prepared
        .observation()
        .discovered_choices()
        .iter()
        .filter(|discovery| discovery.declaration().name() == name);
    let discovery = matching
        .next()
        .unwrap_or_else(|| panic!("the observation discovers `{name}`"));
    assert!(matching.next().is_none(), "one `{name}` discovery");
    discovery
}

/// Executes one attempt, then reconciles it without publication.
///
/// Reconciling as canceled shuts every attempt world down, so no observed
/// child is ever promoted into the pool and every root there is an anchor.
fn realize<R>(
    runner: &mut R,
    input: &CrucibleAttemptExecution,
    context: &AttemptExecutionContext,
    label: &str,
) -> (PreparedSemanticAttemptResult, CrucibleMaterializationTier)
where
    R: CrucibleExecutionRunner,
    R::Error: Debug,
{
    let outcome = runner
        .execute(input, context)
        .unwrap_or_else(|failure| panic!("{label}: execution failed: {failure:?}"));
    let tier = outcome.materialization();
    let AttemptExecutionProduct::PreparedSemantic(result) = outcome.product() else {
        panic!("{label}: next-choice attempts prepare semantic results")
    };
    let prepared = result.as_ref().clone();

    loop {
        let step = runner
            .reconcile_execution(AttemptExecutionDisposition::Canceled)
            .unwrap_or_else(|failure| panic!("{label}: reconciliation failed: {failure:?}"));
        if step == AttemptExecutionReconciliationStep::Complete {
            break;
        }
    }
    eprintln!("native-anchor phase={label} tier={tier:?}");
    (prepared, tier)
}

/// Builds a production thin-replay runner on its own host lane.
fn thin_runner(
    paths: &NativeGatePaths,
    artifacts: &Arc<dyn DagStore>,
) -> impl CrucibleExecutionRunner<Error: Debug> {
    let lifecycles = QemuAttemptProductionVmLifecycleFactory::new(
        lifecycle_config(
            paths,
            paths.run_state_root.join(THIN_LANE),
            Arc::clone(artifacts),
        ),
        ComposedQemuAttemptResourceGuardFactory::new(open_host(paths, THIN_LANE, 17_000)),
    );
    let (lifecycles, evidence) =
        QemuObservedFreshAttemptLifecycleFactory::with_evidence(lifecycles);
    let runner = QemuFreshExecutionRunner::new(lifecycles, QemuFreshModeledDriver);
    QemuTerminalEvidenceExecutionRunner::new(runner, evidence)
}

/// Builds the packaged hot-first composition over `pool`.
///
/// The thin tier retains published roots into the same pool, which also
/// enables anchoring, and children fork on their own host lane.
fn routed_runner(
    paths: &NativeGatePaths,
    artifacts: &Arc<dyn DagStore>,
    pool: &SharedManagedQemuHotForkSourceWorldPool<
        FactoryReapingDemotionSink,
        MemoryHotCheckpointFallbackRetentionStore,
    >,
) -> impl CrucibleExecutionRunner<Error: Debug> {
    let evidence = QemuAttemptExecutionEvidence::default();

    let fallback_lifecycles = QemuAttemptProductionVmLifecycleFactory::new(
        lifecycle_config(
            paths,
            paths.run_state_root.join(ROOT_LANE),
            Arc::clone(artifacts),
        ),
        ComposedQemuAttemptResourceGuardFactory::new(open_host(paths, ROOT_LANE, 17_100)),
    );
    let fallback_lifecycles = QemuObservedFreshAttemptLifecycleFactory::with_shared_evidence(
        fallback_lifecycles,
        evidence.clone(),
    );
    let sink: Arc<dyn QemuPublishedRootSink> = Arc::new(ManagedQemuPublishedRootSink::new(
        pool.clone(),
        HotCheckpointHotnessSignals::new(),
    ));
    let fallback = QemuFreshExecutionRunner::new(fallback_lifecycles, QemuFreshModeledDriver)
        .with_published_root_retention(sink);

    let hot_lifecycles = QemuProductionHotForkWorldLifecycleFactory::new(
        pool.provider().expect("worker source provider"),
        ComposedQemuAttemptResourceGuardFactory::new(open_host(paths, CHILD_LANE, 17_200)),
        paths.run_state_root.join(CHILD_LANE),
        crucible_qemu::QemuShutdownPolicy::fast_test(),
        crucible_qemu::QemuAsyncDriverPolicy::fast_test(),
    );
    let hot_lifecycles = QemuObservedFreshAttemptLifecycleFactory::with_shared_evidence(
        hot_lifecycles,
        evidence.clone(),
    );
    let hot = QemuHotForkWorldExecutionRunner::new(hot_lifecycles, QemuFreshModeledDriver);

    QemuTerminalEvidenceExecutionRunner::new(
        QemuHotFirstExecutionRouter::new(hot, fallback),
        evidence,
    )
}

/// Opens an empty pool sized for the anchor root and one live child.
fn empty_root_pool() -> SharedManagedQemuHotForkSourceWorldPool<
    FactoryReapingDemotionSink,
    MemoryHotCheckpointFallbackRetentionStore,
> {
    let ceilings = HotCheckpointResourceProfile::new(16 << 30, 8 << 30, 16, 16, 16_384, 64)
        .expect("anchor pool ceilings");
    let limits =
        HotCheckpointLimits::new(2, ceilings, 64, 1_000_000_000).expect("anchor pool limits");
    let pool = ManagedQemuHotForkSourceWorldPool::open(
        limits,
        FactoryReapingDemotionSink,
        MemoryHotCheckpointFallbackRetentionStore::new(),
    )
    .expect("open the managed source pool");
    SharedManagedQemuHotForkSourceWorldPool::new(pool)
}

#[test]
#[ignore = "requires the packaged patched QEMU, cgroup v2, and project quotas"]
fn production_anchor_and_ancestor_hot_forks_match_thin_replay() {
    let paths = NativeGatePaths::from_environment();
    let fixture = fs::read_to_string(&paths.fixture).expect("read representative scenario");
    let artifacts: Arc<dyn DagStore> = Arc::new(LocalDagStore::new(&paths.artifacts));
    let (scenario, artifacts) =
        scenario::build_network_fault_anchor(&fixture, artifacts, &paths.kernel, &paths.root_image)
            .expect("build the network fault anchor scenario");
    let launch_identity = crucible_qemu::QemuLaunchArtifactIdentity::authenticate(
        paths.qemu.clone(),
        paths.plugin.clone(),
    )
    .expect("authenticate installed QEMU and plugin build markers");
    let discovery = execution_input_for_scenario_configuration_with_stop_and_qemu_build(
        scenario.clone(),
        Configuration::genesis(scenario.scenario_def()),
        StopCondition::NextChoice,
        launch_identity.qemu_build_id(),
    );
    let campaign = AnchorCampaign::new(scenario.clone(), discovery.lineage().clone());
    let mut thin = thin_runner(&paths, &artifacts);
    let pool = empty_root_pool();
    let mut routed = routed_runner(&paths, &artifacts, &pool);

    // D: thin replay from genesis stops at the joined park with the network choice.
    let (observed_park, tier) = realize(
        &mut thin,
        &discovery,
        &native_execution_context(&discovery, 0xa0),
        "discovery",
    );
    assert_eq!(tier, CrucibleMaterializationTier::ThinReplay);
    let park = campaign.child_configuration(&observed_park);
    let network = discovery_named(&observed_park, "fault.network");
    let selectable = NetworkFaultSelectable::from_records(
        &scenario,
        &park,
        network.declaration(),
        network.opportunity(),
        network.domain(),
    )
    .expect("the discovery is a first-phase network fault at the park");
    let fault = selectable
        .branch_selection(
            NetworkFaultSelectable::selected_value("link_down", "primary", 1_000, 0, 0)
                .expect("network fault value"),
        )
        .expect("network fault branch selection");
    let network_branch = campaign.branch(
        discovery.path(),
        observed_park.observation().child(),
        network,
        &fault,
    );
    assert_eq!(
        network_branch
            .signal_fault_replay()
            .network_branches()
            .len(),
        1
    );
    assert_eq!(
        network_branch.signal_fault_replay().network_branches()[0].phase(),
        NetworkFaultPhase::First
    );

    // N: the router finds no root and keeps one at the park, ending that
    // execution retryable; the requeued execution forks N from the root.
    let (thin_network, tier) = realize(
        &mut thin,
        &network_branch,
        &native_execution_context(&network_branch, 0xa1),
        "network-thin",
    );
    assert_eq!(tier, CrucibleMaterializationTier::ThinReplay);
    let anchored = routed
        .execute(
            &network_branch,
            &native_execution_context(&network_branch, 0xa2),
        )
        .expect_err("the anchored execution ends retryable");
    assert!(
        matches!(anchored, AttemptWorkerFailure::Retryable(_)),
        "network-anchor: {anchored:?}"
    );
    let (routed_network, tier) = realize(
        &mut routed,
        &network_branch,
        &native_execution_context(&network_branch, 0xa2),
        "network-routed",
    );
    assert_eq!(tier, CrucibleMaterializationTier::HotFork);
    assert_eq!(routed_network, thin_network);
    println!("anchor_hot_fork_equivalence=true");

    // C: no root exists at G, so the router forks from the anchor at A.
    let guest_choice = campaign.child_configuration(&thin_network);
    assert!(guest_choice.schedule.starts_with(&park.schedule));
    assert!(guest_choice.schedule.len() > park.schedule.len());
    let guest = discovery_named(&thin_network, GUEST_SELECTABLE);
    let continuation = Selection::new_campaign_branch(
        guest.opportunity(),
        guest.domain(),
        ChoiceValue::Integer(IntegerValue::Unsigned(7)),
        guest
            .opportunity()
            .branch_point_id(ConfigurationId::from_hash(CampaignHash::from_bytes(
                guest_choice.id().bytes,
            ))),
    )
    .expect("guest continuation selection");
    let guest_branch = campaign.branch(
        network_branch.path(),
        thin_network.observation().child(),
        guest,
        &continuation,
    );
    let (thin_guest, tier) = realize(
        &mut thin,
        &guest_branch,
        &native_execution_context(&guest_branch, 0xa3),
        "guest-thin",
    );
    assert_eq!(tier, CrucibleMaterializationTier::ThinReplay);
    let (routed_guest, tier) = realize(
        &mut routed,
        &guest_branch,
        &native_execution_context(&guest_branch, 0xa4),
        "guest-routed",
    );
    assert_eq!(tier, CrucibleMaterializationTier::HotFork);
    assert_eq!(routed_guest, thin_guest);
    // The continuation ran to curl's second choice.
    let _second_choice = discovery_named(&thin_guest, GUEST_SELECTABLE);
    println!("ancestor_hot_fork_equivalence=true");

    // Neither child was promoted, so the pool held exactly the anchor.
    drop(routed);
    assert_eq!(
        pool.orderly_shutdown()
            .expect("retire the anchor root")
            .len(),
        1
    );
    println!("anchor_roots_retired=1");
}
