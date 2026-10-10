//! Simultaneous physical comparisons backed by one accepted owner graph.
//!
//! The original Execution and three independent Services retain four complete
//! world vectors. Services carry the authenticated semantic basis; they do not
//! mint campaign executions or selected roots. Both children stay live during
//! RAM and continuation checks, then every source and watcher is reaped.

use super::*;
use crate::QemuProductionHotForkWorldLifecycle;
use crate::qemu_resource_guard::{
    ComposedQemuAttemptResourceGuard, LinuxQemuAttemptHostResourceOwner,
};

pub(super) type ChildGuard = ComposedQemuAttemptResourceGuard<LinuxQemuAttemptHostResourceOwner>;
pub(super) type ChildFactory = QemuProductionHotForkWorldLifecycleFactory<
    QemuSingleHotForkSourceWorldProvider,
    ComposedQemuAttemptResourceGuardFactory<LinuxQemuAttemptHostResourceFactory>,
>;

pub(super) struct ActiveChild {
    pub(super) factory: ChildFactory,
    pub(super) lifecycle: QemuProductionHotForkWorldLifecycle<ChildGuard>,
    pub(super) config: PackagedQemuExecutorConfig,
    pub(super) ready: u64,
}

impl ActiveChild {
    pub(super) fn start(
        config: PackagedQemuExecutorConfig,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        world: ProductionVmHotForkSourceWorld,
    ) -> Self {
        let key = QemuHotForkSourceWorldKey::for_execution(
            input,
            context,
            context
                .runtime_basis()
                .expect("actual accepted runtime provenance"),
        )
        .expect("authenticated semantic source lookup");
        let host = LinuxQemuAttemptHostResourceFactory::open(config.host.clone())
            .expect("independent child process and disk namespaces");
        let mut factory = QemuProductionHotForkWorldLifecycleFactory::new(
            QemuSingleHotForkSourceWorldProvider::new(key, world),
            ComposedQemuAttemptResourceGuardFactory::new(host),
            config.lifecycle.run_state_root().to_path_buf(),
            QemuShutdownPolicy {
                control_quit_wait: Duration::from_secs(30),
                qmp_quit_wait: Duration::from_secs(30),
                sigterm_wait: Duration::from_secs(30),
                sigkill_wait: Duration::from_secs(30),
                reap_wait: Duration::from_secs(30),
            },
            QemuAsyncDriverPolicy::new(
                Duration::from_secs(300),
                Duration::from_secs(300),
                Duration::from_secs(300),
                Duration::from_secs(300),
            ),
        );
        let started = operational_monotonic_nanoseconds();
        let lifecycle = match factory
            .try_start(input, context)
            .expect("real staged native child admission")
        {
            QemuHotForkWorldLifecycleStart::Started(child) => child,
            QemuHotForkWorldLifecycleStart::Declined => {
                panic!("authenticated retained source declined")
            }
        };
        let ready = operational_monotonic_nanoseconds().saturating_sub(started);
        Self {
            factory,
            lifecycle,
            config,
            ready,
        }
    }

    pub(super) fn assert_boundary(
        &mut self,
        source: &ScenarioDefForm,
        expected: &BoundaryEvidence,
    ) {
        let pending = drain_exact_pending(&mut self.lifecycle);
        let actual = capture_boundary_evidence(
            &mut self.lifecycle,
            source,
            expected.configuration.clone(),
            pending,
            topology(source),
        );
        assert_eq!(&actual, expected);
    }

    pub(super) fn ram(&mut self, context: &AttemptExecutionContext) -> BTreeMap<String, Vec<u8>> {
        let closure = self
            .lifecycle
            .capture_attempt_checkpoint(context)
            .expect("actual coherent RAM page roots from this independently owned child")
            .into_closure();
        closure
            .ram_sources()
            .iter()
            .map(|source| (source.node().name.clone(), source.root().record().encode()))
            .collect()
    }

    pub(super) fn stop(mut self) -> ProductionVmHotForkSourceWorld {
        self.lifecycle
            .shutdown()
            .expect("all child processes and services physically reaped");
        let mut complete = false;
        for _ in 0..64 {
            if self
                .lifecycle
                .reconcile_execution_disposition(crate::AttemptExecutionDisposition::Canceled)
                .expect("same actual source-side disposition proof")
                == AttemptExecutionReconciliationStep::Complete
            {
                complete = true;
                break;
            }
        }
        assert!(complete);
        assert!(self.factory.recover(self.lifecycle).is_ok());
        assert!(cgroup_processes(self.config.host.cgroup_root()).is_empty());
        self.factory
            .source_provider_mut_for_test()
            .take_available()
            .expect("identical original source recovered after child cleanup")
    }
}

pub(super) fn world_config(
    config: &PackagedQemuExecutorConfig,
    lane: &str,
    project: u32,
) -> PackagedQemuExecutorConfig {
    let host = &config.host;
    let mut world = config.clone();
    world.host = LinuxQemuAttemptHostConfig::new(
        host.cgroup_root().join(lane),
        host.run_root().join(lane),
        format!("equivalence-{lane}"),
        project,
        1,
        host.child_user_id(),
        host.child_group_id(),
        host.maximum_tasks(),
        host.maximum_file_descriptors(),
        host.maximum_node_host_service_tasks(),
        host.maximum_node_host_service_file_descriptors(),
        host.maximum_node_host_service_resident_bytes(),
        host.watcher_service_resident_bytes(),
        host.maximum_inodes(),
        Duration::from_secs(30),
    )
    .expect("authored disjoint cgroup and project-quota namespace");
    world.lifecycle = Arc::new(
        config
            .admitted_lifecycle_config()
            .expect("actual catalog authority admits the independent world projection")
            .with_run_state_root(config.lifecycle.run_state_root().join(lane)),
    );
    world
}

pub(super) fn run(
    model: &ResumeModel<'_>,
    input: &CrucibleAttemptExecution,
    context: &AttemptExecutionContext,
) -> RunEvidence {
    let source = input.scenario();
    let before = available_resources(model.prepared);
    let source_factory = RetainedTemplateServiceFactory::new(model.prepared, &model.config);
    let causal = Arc::new(
        source_factory
            .start_causal_source_for_test(source, context)
            .expect("independent causal-source Service under the genuine active Execution"),
    );
    let mut selected = context.take_selected_checkpoint();
    let exact = Arc::new(
        source_factory
            .start_for_resume(source, model.checkpoint, context, &mut selected)
            .expect("independent exact source consumes its one real selected-root claim"),
    );
    assert!(selected.is_none());
    let comparison = source_factory
        .start_comparison_child_for_test(source, context)
        .expect("independently charged comparison-child Service in the accepted graph");
    assert!(!comparison.context().host_ram_retained_template());
    assert_ne!(
        context.host_ram_owner_id(),
        comparison.context().host_ram_owner_id()
    );
    assert_ne!(
        causal.context().host_ram_owner_id(),
        exact.context().host_ram_owner_id()
    );
    for owner in [causal.context(), exact.context(), comparison.context()] {
        extend_native_operations(owner);
    }
    let service_peak = model
        .config
        .retained_template_resources()
        .expect("authored complete world vector");
    assert_template_charge(model.prepared, before, service_peak, 3);

    let causal_config = world_config(&model.config, "causal", 47_000);
    let mut causal_factory = fresh_factory(&causal_config, "world");
    let mut causal_parent = causal_factory
        .begin_fresh(&source.scenario_def(), source, causal.context())
        .expect("genuine fresh causal oracle");
    let boundary = drive_to_depth(&mut causal_parent, source, model.depth, causal.context());
    assert_eq!(boundary, model.captured.boundary);
    let causal_world = causal_parent
        .prepare_hot_fork_source_world()
        .expect("execution-origin retained barriers")
        .with_cleanup_observer(causal.clone());

    let exact_config = world_config(&model.config, "exact", 47_100);
    let mut exact_factory = fresh_factory(&exact_config, "world");
    let mut exact_parent = exact_factory
        .begin_resume(
            &model.prepared.checkpoints,
            model.checkpoint,
            crate::QemuExactResumeBasis::new(
                &source.scenario_def(),
                source,
                &boundary.configuration,
                None,
            ),
            exact.context(),
        )
        .expect("genuine selected-root restore");
    let pending = drain_exact_pending(&mut exact_parent);
    let exact_boundary = capture_boundary_evidence(
        &mut exact_parent,
        source,
        boundary.configuration.clone(),
        pending,
        topology(source),
    );
    assert_eq!(exact_boundary, boundary);
    let exact_world = exact_parent
        .prepare_hot_fork_source_world()
        .expect("exact-origin retained barriers")
        .with_cleanup_observer(exact.clone());
    assert_eq!(
        prepared_world_evidence(&causal_world, topology(source)),
        prepared_world_evidence(&exact_world, topology(source))
    );

    let mut first = ActiveChild::start(
        world_config(&model.config, "first-child", 47_200),
        input,
        context,
        causal_world,
    );
    let mut second = ActiveChild::start(
        world_config(&model.config, "second-child", 47_300),
        input,
        comparison.context(),
        exact_world,
    );
    first.assert_boundary(source, &boundary);
    second.assert_boundary(source, &boundary);
    let first_pids = cgroup_processes(first.config.host.cgroup_root());
    let second_pids = cgroup_processes(second.config.host.cgroup_root());
    assert_eq!(first_pids.len(), source.world().vm_nodes().len());
    assert_eq!(second_pids.len(), source.world().vm_nodes().len());
    assert!(first_pids.iter().all(|pid| !second_pids.contains(pid)));
    let first_before = first.ram(context);
    let second_before = second.ram(comparison.context());
    assert_eq!(first_before, second_before);

    let hot_first = continue_from_pending(
        &mut first.lifecycle,
        source,
        boundary.configuration.clone(),
        boundary.pending.clone(),
        context,
    );
    let changed = first.ram(context);
    assert_ne!(
        changed
            .get("curl")
            .expect("live Curl RAM after continuation"),
        first_before.get("curl").expect("initial Curl RAM"),
        "the known guest continuation must write private RAM"
    );
    assert_eq!(
        second.ram(comparison.context()),
        second_before,
        "a live sibling must retain its unchanged RAM roots"
    );
    let hot_second = continue_from_pending(
        &mut second.lifecycle,
        source,
        boundary.configuration.clone(),
        boundary.pending.clone(),
        comparison.context(),
    );
    let reference = model
        .captured
        .continuation
        .as_ref()
        .expect("completed original fresh causal continuation");
    assert_continuation_equivalent("simultaneous execution-origin child", &hot_first, reference);
    assert_continuation_equivalent("simultaneous exact-origin child", &hot_second, reference);
    assert_continuation_equivalent("simultaneous siblings", &hot_first, &hot_second);
    let result = RunEvidence {
        ready_samples: vec![first.ready, second.ready],
        completed_children: 2,
        ..RunEvidence::default()
    };

    let mut causal_parent = first
        .stop()
        .recover()
        .expect("causal parent private state recovered");
    let mut exact_parent = second
        .stop()
        .recover()
        .expect("exact parent private state recovered");
    comparison
        .release_after_world_cleanup()
        .expect("actual comparison-child watcher join and Service discharge");
    let pending = drain_exact_pending(&mut causal_parent);
    let unchanged_causal = capture_boundary_evidence(
        &mut causal_parent,
        source,
        boundary.configuration.clone(),
        pending,
        topology(source),
    );
    let pending = drain_exact_pending(&mut exact_parent);
    let unchanged_exact = capture_boundary_evidence(
        &mut exact_parent,
        source,
        boundary.configuration.clone(),
        pending,
        topology(source),
    );
    assert_eq!(unchanged_causal, boundary);
    assert_eq!(unchanged_exact, boundary);
    causal_parent
        .shutdown()
        .expect("causal source physically reaped");
    exact_parent
        .shutdown()
        .expect("exact source physically reaped");
    causal
        .release_after_world_cleanup()
        .expect("actual causal-source watcher join and full-vector discharge");
    exact
        .release_after_world_cleanup()
        .expect("actual exact-source watcher join and full-vector discharge");
    assert_eq!(available_resources(model.prepared), before);
    println!("concurrent_live_children=2");
    println!("concurrent_comparison_owner_graph=one-active-execution,three-independent-services");
    println!(
        "concurrent_comparison_vm_processes={}",
        first_pids.len() + second_pids.len()
    );
    result
}
