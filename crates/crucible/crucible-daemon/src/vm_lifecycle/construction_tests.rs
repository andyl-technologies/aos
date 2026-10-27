//! Restored production scheduler event-log dependency tests.

use super::*;
use crucible_engine::model::{
    MemoryDagStore, NodeTemplate, Plan, Properties, ReadyPoint, ScenarioSelectableLimits,
    ScenarioSelectables, WhiteBoxPolicy, WorldNode,
};

#[test]
fn exact_restore_defers_network_fault_replay_to_checkpoint_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let world = World::from_nodes(vec![WorldNode {
        id: NodeId {
            name: String::from("router-a"),
        },
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::from("network-restore-guard-test"),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: 1,
        kernel: None,
        root_image: None,
        initrd: None,
    }])?;
    let base = ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(20),
    )?;
    let scenario = base.with_selectables(ScenarioSelectables::new(
        &world,
        ScenarioSelectableLimits::default(),
        vec![crucible_engine::NetworkFaultSelectable::declaration()?],
    )?)?;
    let parent = Configuration::genesis(scenario.scenario_def());
    let selectable = crucible_engine::NetworkFaultSelectable::next(
        &scenario,
        &parent,
        crucible_engine::NetworkFaultPhase::First,
        VirtualTime { ticks: 10_000 },
        &[],
    )?
    .ok_or("missing network fault group")?;
    let selected = selectable.branch_selection(selectable.declaration_ref().default().clone())?;
    let branch = selectable.resolve_branch(&selected)?;
    let replay = SignalFaultCampaignReplayPlan::empty(branch.selected().clone())
        .with_network_branches(vec![branch])?;

    assert!(reject_fresh_fault_replay_on_restore(false, Some(&replay)).is_ok());
    assert!(reject_fresh_fault_replay_on_restore(true, Some(&replay)).is_ok());
    Ok(())
}

/// Raw console bytes per append; four appends seal one event-log segment.
///
/// A console entry encodes its bytes twice, so each append encodes to about
/// 5/16 of the seal target.
const SEALING_CHUNK_BYTES: usize = crucible_engine::EVENT_LOG_SEAL_TARGET_BYTES * 5 / 32;

fn sealing_runtime(label: &str) -> SchedulerLivenessScenario {
    SchedulerLivenessScenario::from_canonical_material(
        label,
        8,
        SimInstant { ticks: 8 },
        Vec::new(),
        Vec::new(),
    )
}

/// Builds a store-backed scheduler whose log has sealed one segment.
fn sealed_source(runtime: SchedulerLivenessScenario, store: Arc<dyn DagStore>) -> SingleScheduler {
    let mut source = SingleScheduler::new_with_event_log_segment_store(runtime, store)
        .unwrap_or_else(|error| panic!("source scheduler is valid: {error}"));
    for _ in 0..4 {
        QuantumLoop::append_backend_observable_events(
            &mut source,
            vec![ObservableEvent::console_output(
                VirtualTime { ticks: 0 },
                NodeId {
                    name: String::from("resumed-node"),
                },
                vec![7; SEALING_CHUNK_BYTES],
            )],
        )
        .unwrap_or_else(|error| panic!("source observation is retained: {error}"));
    }
    source
}

#[test]
fn resumed_capture_reads_authenticated_event_log_segments_from_new_run_store() {
    let scenario = ScenarioDef::from_canonical_material(
        "crucible.test.production-event-log-restore",
        "resumed-capture",
    );
    let runtime = sealing_runtime("resumed-capture-runtime").with_scenario_def(scenario);
    let source_store: Arc<dyn DagStore> = Arc::new(MemoryDagStore::new());
    let source = sealed_source(runtime.clone(), Arc::clone(&source_store));
    let checkpoint = source
        .checkpoint()
        .unwrap_or_else(|error| panic!("source scheduler captures: {error}"));
    assert_eq!(checkpoint.event_log_segments().len(), 1);

    // Restore reads the sealed segments from the new run's own store, so it
    // refuses until they are hydrated there.
    let resumed_store: Arc<dyn DagStore> = Arc::new(MemoryDagStore::new());
    let mut resumed =
        SingleScheduler::new_with_event_log_segment_store(runtime, Arc::clone(&resumed_store))
            .unwrap_or_else(|error| panic!("resumed scheduler is valid: {error}"));
    assert!(checkpoint.restore_into(&mut resumed).is_err());

    ProductionEventLogSegments::store(source_store)
        .hydrate(&checkpoint, resumed_store.as_ref())
        .unwrap_or_else(|error| {
            panic!("authenticated segments hydrate the new run store: {error}")
        });
    checkpoint
        .restore_into(&mut resumed)
        .unwrap_or_else(|error| panic!("scheduler continuation restores: {error}"));
    let recaptured = resumed
        .checkpoint()
        .unwrap_or_else(|error| panic!("resumed scheduler captures: {error}"));
    assert_eq!(
        recaptured.event_log_segments(),
        checkpoint.event_log_segments()
    );
    resumed
        .verify_event_log_segments()
        .unwrap_or_else(|error| panic!("resumed capture names present segments: {error}"));
}

#[test]
fn event_log_hydration_rejects_changed_bytes_before_writing() {
    let source_store: Arc<dyn DagStore> = Arc::new(MemoryDagStore::new());
    let source = sealed_source(
        sealing_runtime("changed-event-log-runtime"),
        Arc::clone(&source_store),
    );
    let checkpoint = source
        .checkpoint()
        .unwrap_or_else(|error| panic!("source scheduler captures: {error}"));
    let identity = checkpoint
        .event_log_segments()
        .first()
        .map(|segment| segment.object)
        .unwrap_or_else(|| panic!("source checkpoint references a segment"));

    // A repository opener that returns the stored bytes with one byte changed.
    let changed: super::checkpoint_event_log::ClosureObjectOpener = Arc::new(move |object| {
        let mut bytes = source_store.get(&object).map_err(std::io::Error::other)?;
        if let Some(last) = bytes.last_mut() {
            *last ^= 1;
        }
        Ok(Box::new(std::io::Cursor::new(bytes)) as Box<dyn std::io::Read + Send>)
    });

    let resumed_store = MemoryDagStore::new();
    assert!(
        ProductionEventLogSegments::repository(changed)
            .hydrate(&checkpoint, &resumed_store)
            .is_err()
    );
    assert!(resumed_store.get(&identity).is_err());
}

#[test]
fn branch_plan_launch_window_keeps_only_servable_entries() -> Result<(), Box<dyn std::error::Error>>
{
    use crucible_qemu_protocol::app_random_branch_plan::{
        AppRandomBranchPlan, AppRandomBranchPlanEntry,
    };

    let node = NodeId {
        name: String::from("node-a"),
    };
    let stream = crucible_qemu_protocol::app_random_transport::app_random_stream_name(&node.name, "b");
    let entries = [0_u64, 3, 7]
        .into_iter()
        .map(|draw| AppRandomBranchPlanEntry::new(draw, draw, draw + 1, [0x5a; 32], stream.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    let plan = AppRandomBranchPlan::new(entries)?;

    let genesis = branch_plan_launch_window(&plan, 0, &node)?;
    let resumed = branch_plan_launch_window(&plan, 3, &node)?;
    let exhausted = branch_plan_launch_window(&plan, 8, &node)?;

    assert_eq!(genesis, plan);
    let served = resumed
        .entries()
        .iter()
        .map(AppRandomBranchPlanEntry::draw_index)
        .collect::<Vec<_>>();
    assert_eq!(served, [3, 7]);
    assert!(exhausted.entries().is_empty());
    Ok(())
}
