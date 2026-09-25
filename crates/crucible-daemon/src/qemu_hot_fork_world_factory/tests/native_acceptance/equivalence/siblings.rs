//! Live native siblings admitted through one authenticated managed source.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crucible_campaign::{
    CampaignMode, CampaignPolicy, CampaignRepository, CampaignSeed, ExplorerPolicy, FairnessPolicy,
    ProgressiveWideningPolicy, PuctPolicy, RetentionPolicy,
};
use crucible_cas::content_store::{MemoryBlobBackend, MemoryRefBackend};

use super::*;
use crate::{
    AuthenticatedQemuHotForkSourceBasis, HotCheckpointFallback, HotCheckpointHotnessSignals,
    HotCheckpointLimits, HotCheckpointResourceProfile, ManagedQemuHotForkSourceWorldPool,
    MemoryHotCheckpointFallbackRetentionStore, ProductionQemuHotForkSourceFactory,
    SharedManagedQemuHotForkSourceWorldPool, encode_crucible_configuration_artifact,
    encode_crucible_scenario_artifact,
};

const SIBLING_MEMORY_MIB: u32 = 512;
const CHILD_PRIVATE_LIMIT_KIB: u64 = 512 * 256 + 32 * 1024;
const SOURCE_PRIVATE_GROWTH_LIMIT_KIB: u64 = 16 * 1024;

#[test]
#[ignore = "requires the packaged patched QEMU, cgroup v2, and project quotas"]
fn production_managed_source_keeps_one_two_and_four_native_siblings_live() {
    let paths = NativeGatePaths::from_environment();
    let fixture = fs::read_to_string(&paths.fixture).expect("read representative scenario");
    let artifacts: Arc<dyn DagStore> = Arc::new(LocalDagStore::new(&paths.artifacts));
    let (scenario, artifacts) = scenario::build_single_node_equivalence_with_memory(
        &fixture,
        artifacts,
        SIBLING_MEMORY_MIB,
        &paths.kernel,
        &paths.root_image,
    )
    .expect("build native sibling scenario");
    let launch_identity = crucible_qemu::QemuLaunchArtifactIdentity::authenticate(
        paths.qemu.clone(),
        paths.plugin.clone(),
    )
    .expect("authenticate installed QEMU and plugin build markers");
    let input = execution_input_for_scenario_with_qemu_build(
        scenario.clone(),
        launch_identity.qemu_build_id(),
    );
    let (basis, store) = authenticated_genesis_basis(&scenario, &input);
    let source_context = execution_context(&input, 0xe0);
    let source_host = open_host(&paths, "simultaneous-source", 13_000);
    let source_config = lifecycle_config(
        &paths,
        paths.run_state_root.join("simultaneous-source"),
        artifacts,
    );
    let source_lifecycles = QemuAttemptProductionVmLifecycleFactory::new(
        source_config,
        ComposedQemuAttemptResourceGuardFactory::new(source_host),
    );
    let mut source_factory = ProductionQemuHotForkSourceFactory::new(
        basis.clone(),
        source_lifecycles,
        launch_identity.qemu_build_id(),
    )
    .expect("bind authenticated native source factory");
    let authenticated = source_factory
        .capture(&source_context)
        .expect("capture authenticated canonical genesis source");
    let source_checkpoint = {
        let source = authenticated.source_world_for_test();
        (
            source.continuation().configuration().id(),
            source.continuation().scheduler().clone(),
            source.continuation().fault_checkpoint_identity(),
        )
    };

    // These are aggregate admission ceilings for the parent and four 512-MiB
    // children. The managed pool still measures each actual source itself.
    let ceilings = HotCheckpointResourceProfile::new(16 << 30, 8 << 30, 16, 16, 16_384, 64)
        .expect("native sibling ceilings");
    let limits = HotCheckpointLimits::new(1, ceilings, 16, 1_000_000_000)
        .expect("native sibling lease limits");
    let mut pool = ManagedQemuHotForkSourceWorldPool::open(
        limits,
        FactoryReapingDemotionSink,
        MemoryHotCheckpointFallbackRetentionStore::new(),
    )
    .expect("open native managed source pool");
    pool.admit_authenticated_source(
        authenticated,
        HotCheckpointHotnessSignals::new(),
        HotCheckpointFallback::Thin(basis.source_artifact()),
    )
    .expect("admit repository-authenticated canonical source");
    let shared = SharedManagedQemuHotForkSourceWorldPool::new(pool);
    let source_processes = cgroup_processes(&paths.cgroup_root.join("simultaneous-source"));
    assert_eq!(source_processes.len(), 1);
    let source_memory = process_memory_evidence(&source_processes);
    let source_allocated_bytes =
        allocated_tree_bytes(&paths.storage_root.join("simultaneous-source"));
    let child_disk_limit_bytes = source_allocated_bytes / 2 + 16 * 1024 * 1024;
    let source_scheduler = basis.source().clone();
    let mut project_ids = BTreeSet::from_iter(13_000..13_064);

    for sibling_count in [1_usize, 2, 4] {
        let mut children = Vec::with_capacity(sibling_count);
        let mut lanes = Vec::with_capacity(sibling_count);
        let mut all_processes = BTreeSet::new();

        for index in 0..sibling_count {
            let lane = format!("simultaneous-{sibling_count}-{index}");
            let project_id_start = 14_000
                + u32::try_from(sibling_count).expect("sibling count fits project ID") * 1_000
                + u32::try_from(index).expect("sibling index fits project ID") * 100;
            assert!(
                (project_id_start..project_id_start + 64)
                    .all(|project_id| project_ids.insert(project_id))
            );
            let context = execution_context(
                &input,
                0xe1 + u8::try_from(index).expect("sibling execution byte"),
            );
            let target = open_host(&paths, &lane, project_id_start);
            let mut factory = QemuProductionHotForkWorldLifecycleFactory::new(
                shared
                    .provider()
                    .expect("independent managed source provider"),
                ComposedQemuAttemptResourceGuardFactory::new(target),
                paths.run_state_root.join(&lane),
                crucible_qemu::QemuShutdownPolicy::fast_test(),
                crucible_qemu::QemuAsyncDriverPolicy::fast_test(),
            );
            let mut lifecycle = match factory
                .try_start(&input, &context)
                .expect("fork managed native sibling")
            {
                QemuHotForkWorldLifecycleStart::Started(lifecycle) => lifecycle,
                QemuHotForkWorldLifecycleStart::Declined => {
                    panic!("authenticated managed source declined a sibling")
                }
            };
            let materialization = lifecycle
                .start_materialization()
                .expect("materialize managed native sibling");
            assert_eq!(
                materialization.restored_configuration(),
                Some(&source_scheduler)
            );
            let checkpoint = {
                let owner = lifecycle.source_world_owner_for_test();
                let source = owner.lock().expect("inspect retained native source");
                (
                    source.continuation().configuration().id(),
                    source.continuation().scheduler().clone(),
                    source.continuation().fault_checkpoint_identity(),
                )
            };
            assert_eq!(
                checkpoint, source_checkpoint,
                "source changed while siblings forked"
            );
            assert_eq!(cgroup_processes(&paths.cgroup_root.join(&lane)).len(), 1);
            assert!(paths.storage_root.join(&lane).is_dir());
            assert!(paths.run_state_root.join(&lane).is_dir());
            lanes.push(lane);
            children.push((factory, lifecycle));
        }

        let source_after_forks = cgroup_processes(&paths.cgroup_root.join("simultaneous-source"));
        assert_eq!(source_after_forks, source_processes);
        let mut aggregate_private_rss_kib = 0_u64;
        let mut aggregate_allocated_bytes = 0_u64;
        for lane in &lanes {
            let processes = cgroup_processes(&paths.cgroup_root.join(lane));
            assert_eq!(processes.len(), 1);
            assert!(all_processes.insert(processes[0]));
            let memory = process_memory_evidence(&processes);
            assert!(
                memory.private_rss_kib <= CHILD_PRIVATE_LIMIT_KIB,
                "{sibling_count} live siblings: {lane} copied too much private RAM"
            );
            aggregate_private_rss_kib += memory.private_rss_kib;
            let allocated_bytes = allocated_tree_bytes(&paths.storage_root.join(lane));
            assert!(
                allocated_bytes <= child_disk_limit_bytes,
                "{sibling_count} live siblings: {lane} copied too much source storage"
            );
            aggregate_allocated_bytes += allocated_bytes;
        }
        let source_process_set = source_processes.iter().copied().collect::<BTreeSet<_>>();
        assert!(all_processes.is_disjoint(&source_process_set));
        let source_live_memory = process_memory_evidence(&source_after_forks);
        let aggregate_world_private_rss_kib =
            source_live_memory.private_rss_kib + aggregate_private_rss_kib;
        assert!(
            aggregate_private_rss_kib
                <= CHILD_PRIVATE_LIMIT_KIB * u64::try_from(sibling_count).expect("sibling count")
        );
        assert!(
            source_live_memory
                .private_dirty_kib
                .saturating_sub(source_memory.private_dirty_kib)
                <= SOURCE_PRIVATE_GROWTH_LIMIT_KIB,
            "retained source grew while siblings were live"
        );
        assert!(
            source_live_memory
                .private_rss_kib
                .saturating_sub(source_memory.private_rss_kib)
                <= SOURCE_PRIVATE_GROWTH_LIMIT_KIB,
            "retained source acquired too much private RSS while siblings were live"
        );
        super::super::resource_isolation::assert_live_sibling_lanes_are_physically_private(
            &paths.cgroup_root,
            &paths.storage_root,
            &lanes,
        )
        .expect("sibling ring, socket, and overlay isolation");
        assert!(
            shared.orderly_shutdown().is_err(),
            "live leases forbid source retirement"
        );
        println!("simultaneous_{sibling_count}_child_private_rss_kib={aggregate_private_rss_kib}");
        println!(
            "simultaneous_{sibling_count}_world_private_rss_kib={aggregate_world_private_rss_kib}"
        );
        println!("simultaneous_{sibling_count}_child_allocated_bytes={aggregate_allocated_bytes}");

        let mut first_boundary = None;
        for (_factory, lifecycle) in &mut children {
            let boundary =
                drive_to_pending_boundary(lifecycle, &scenario, EquivalenceTopology::SingleNode);
            if let Some(expected) = &first_boundary {
                assert_eq!(
                    &boundary, expected,
                    "live siblings diverged at the choice boundary"
                );
            } else {
                first_boundary = Some(boundary);
            }
        }

        for (mut factory, mut lifecycle) in children {
            QemuFreshAttemptLifecycleOwner::shutdown(&mut lifecycle)
                .expect("shutdown managed native sibling");
            reconcile_native_world(&mut lifecycle);
            let checkpoint = {
                let owner = lifecycle.source_world_owner_for_test();
                let source = owner
                    .lock()
                    .expect("inspect retained source after sibling exit");
                (
                    source.continuation().configuration().id(),
                    source.continuation().scheduler().clone(),
                    source.continuation().fault_checkpoint_identity(),
                )
            };
            assert_eq!(checkpoint, source_checkpoint);
            assert!(factory.recover(lifecycle).is_ok());
        }
        for lane in &lanes {
            assert!(cgroup_processes(&paths.cgroup_root.join(lane)).is_empty());
        }
        assert_eq!(
            cgroup_processes(&paths.cgroup_root.join("simultaneous-source")),
            source_processes
        );
    }

    assert!(
        process_memory_evidence(&source_processes)
            .private_dirty_kib
            .saturating_sub(source_memory.private_dirty_kib)
            <= SOURCE_PRIVATE_GROWTH_LIMIT_KIB,
        "retained source grew more than 16 MiB after three sibling cohorts"
    );
    assert_eq!(
        shared
            .orderly_shutdown()
            .expect("retire released source")
            .len(),
        1
    );
    store
        .load_configuration_artifact(basis.source_artifact())
        .expect("canonical thin fallback remains available after source retirement");
    assert!(cgroup_processes(&paths.cgroup_root.join("simultaneous-source")).is_empty());
    println!("simultaneous_sibling_counts=1,2,4");
    println!("simultaneous_source_boundary=authenticated-canonical-genesis");
    println!(
        "simultaneous_source_private_rss_baseline_kib={}",
        source_memory.private_rss_kib
    );
    println!("simultaneous_source_private_growth_limit_kib={SOURCE_PRIVATE_GROWTH_LIMIT_KIB}");
    println!("simultaneous_child_boundary_equivalence=1,2,4");
    println!(
        "simultaneous_child_resource_isolation=cgroup,storage,run-state,project-id,ring,socket,overlay"
    );
    println!("simultaneous_source_retirement=after-last-lease-release");
}

fn authenticated_genesis_basis(
    scenario: &crucible::ScenarioDefForm,
    input: &CrucibleAttemptExecution,
) -> (AuthenticatedQemuHotForkSourceBasis, CampaignExecutorStore) {
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "native-sibling-source",
            16 * 1024 * 1024,
        )),
        Arc::new(MemoryRefBackend::new()),
    ));
    let scenario_artifact =
        encode_crucible_scenario_artifact(scenario).expect("encode native sibling scenario");
    let scenario_content = repository
        .publish_scenario_artifact(
            scenario_artifact.scenario(),
            scenario_artifact.payload_schema(),
            scenario_artifact.payload().to_vec(),
        )
        .expect("publish native sibling scenario");
    let genesis = Configuration::genesis(scenario.scenario_def());
    let genesis_artifact =
        encode_crucible_configuration_artifact(&scenario_artifact, &genesis.schedule)
            .expect("encode native sibling genesis");
    let genesis_content = repository
        .publish_configuration_artifact(
            genesis_artifact.scenario(),
            genesis_artifact.scenario_artifact(),
            genesis_artifact.configuration(),
            genesis_artifact.payload_schema(),
            genesis_artifact.payload().to_vec(),
        )
        .expect("publish native sibling genesis");
    assert_eq!(scenario_content, input.lineage().scenario_content());
    assert_eq!(genesis_content, input.lineage().genesis_content());

    let widening = ProgressiveWideningPolicy::new(
        ExactRational::new(1, 1).expect("widening numerator"),
        ExactRational::new(1, 2).expect("widening exponent"),
        1,
        100,
        1,
    )
    .expect("native sibling widening policy");
    let policy = CampaignPolicy::new(
        CampaignPolicy::identity(
            scenario_artifact.scenario(),
            CampaignSeed::from_bytes([0x51; 32]),
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
            FairnessPolicy::new(0, 0).expect("fairness policy"),
            RetentionPolicy::new(true, 1, true, true),
            true,
        ),
    )
    .expect("native sibling campaign policy");
    repository
        .create(
            "native-sibling-source",
            input.lineage(),
            &policy,
            &BTreeMap::new(),
        )
        .expect("create native sibling campaign");
    let store = CampaignExecutorStore::new(repository);
    let basis = AuthenticatedQemuHotForkSourceBasis::authenticate(
        &store,
        input.lineage().id().expect("native sibling lineage ID"),
        &ExecutorCompatibilityProfile::from_lineage(input.lineage()),
    )
    .expect("authenticate published native sibling genesis");
    (basis, store)
}
