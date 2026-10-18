//! Simultaneous physical comparisons backed by one accepted owner graph.
//!
//! The original Execution and three independent Services retain four complete
//! world vectors. Services carry the authenticated semantic basis; they do not
//! mint campaign executions or selected roots. Both children stay live during
//! RAM and continuation checks, then every source and watcher is reaped.

use super::*;
pub(super) type ChildFactory = QemuProductionHotForkWorldLifecycleFactory<
    QemuSingleHotForkSourceWorldProvider,
    ComposedQemuAttemptResourceGuardFactory<LinuxQemuAttemptHostResourceFactory>,
>;

pub(super) struct ActiveChild {
    pub(super) factory: ChildFactory,
    pub(super) lifecycle: <ChildFactory as QemuHotForkWorldLifecycleFactory>::Lifecycle,
    pub(super) config: PackagedQemuExecutorConfig,
    pub(super) ready: u64,
}

pub(super) type ChildResources =
    ComposedQemuAttemptResourceGuardFactory<LinuxQemuAttemptHostResourceFactory>;

pub(super) struct PreparedChild {
    factory: ChildFactory,
    launch: crate::qemu_hot_fork_world_factory::PreparedTargetLaunch<ChildResources>,
    config: PackagedQemuExecutorConfig,
    started: u64,
}

impl PreparedChild {
    pub(super) fn service_main_handle(&self) -> crate::lifecycle_cleanup::ServiceMainHandle {
        self.launch.service_main_handle()
    }

    pub(super) fn start(
        mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> ActiveChild {
        let lifecycle = match self
            .factory
            .finish_prepared_target(self.launch, input, context)
            .expect("same preclaimed native Target launches under its actual Service")
        {
            QemuHotForkWorldLifecycleStart::Started(child) => child,
            QemuHotForkWorldLifecycleStart::Declined => panic!("preclaimed native Target declined"),
        };
        ActiveChild {
            factory: self.factory,
            lifecycle,
            config: self.config,
            ready: operational_monotonic_nanoseconds().saturating_sub(self.started),
        }
    }
}

impl ActiveChild {
    fn factory(
        config: &PackagedQemuExecutorConfig,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        world: ProductionVmHotForkSourceWorld,
    ) -> ChildFactory {
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
        let factory = QemuProductionHotForkWorldLifecycleFactory::new(
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
        factory
    }

    pub(super) fn prepare(
        config: PackagedQemuExecutorConfig,
        input: &CrucibleAttemptExecution,
        original: &AttemptExecutionContext,
        world: ProductionVmHotForkSourceWorld,
    ) -> PreparedChild {
        let mut factory = Self::factory(&config, input, original, world);
        let started = operational_monotonic_nanoseconds();
        let launch = factory
            .prepare_independent_target(input, original)
            .expect("genuine Target Main admission before comparison Service")
            .expect("authenticated retained source is available");
        PreparedChild {
            factory,
            launch,
            config,
            started,
        }
    }

    pub(super) fn start(
        config: PackagedQemuExecutorConfig,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        world: ProductionVmHotForkSourceWorld,
    ) -> Self {
        let mut factory = Self::factory(&config, input, context, world);
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
    let causal_config = world_config(&model.config, "causal", 47_000);
    let mut causal_factory = fresh_factory(&causal_config, "world");
    let exact_config = world_config(&model.config, "exact", 47_100);
    let mut exact_factory = fresh_factory(&exact_config, "world");
    let causal = crate::packaged_qemu_executor::tests::paging_native::main_service::NativeServiceScope::causal(
        causal_factory.prepare_source_construction().expect("same actual causal Source Main role"),
        &source_factory, source, context,
    );
    let exact = crate::packaged_qemu_executor::tests::paging_native::main_service::NativeServiceScope::resume(
        exact_factory.prepare_source_construction().expect("same actual exact Source Main role"),
        &source_factory, source, model.checkpoint, context,
    );
    let mut causal_parent = causal_factory
        .begin_fresh(&source.scenario_def(), source, causal.context())
        .expect("genuine fresh causal oracle");
    let boundary = drive_to_depth(&mut causal_parent, source, model.depth, causal.context());
    assert_eq!(boundary, model.captured.boundary);
    let causal_world = causal_parent
        .prepare_hot_fork_source_world()
        .expect("execution-origin retained barriers");

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
        .expect("exact-origin retained barriers");
    assert_eq!(
        prepared_world_evidence(&causal_world, topology(source)),
        prepared_world_evidence(&exact_world, topology(source))
    );

    let prepared_second = ActiveChild::prepare(
        world_config(&model.config, "second-child", 47_300),
        input,
        context,
        exact_world,
    );
    let mut comparison = crate::packaged_qemu_executor::tests::paging_native::main_service::NativeServiceScope::comparison(
        prepared_second.service_main_handle(), &source_factory, source, context,
    );
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

    let mut second = prepared_second.start(input, comparison.context());
    let mut first = ActiveChild::start(
        world_config(&model.config, "first-child", 47_200),
        input,
        context,
        causal_world,
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
    comparison.release_context_aliases();
    let mut exact_parent = second
        .stop()
        .recover()
        .expect("exact parent private state recovered");
    comparison.assert_released();
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
    drop(causal_parent);
    drop(exact_parent);
    let causal_terminal = causal
        .into_retirement()
        .expect("actual causal Source World and watcher returned");
    let exact_terminal = exact
        .into_retirement()
        .expect("actual exact Source World and watcher returned");
    println!("concurrent_causal_retirement={causal_terminal}");
    println!("concurrent_exact_retirement={exact_terminal}");
    drop(causal_terminal);
    drop(exact_terminal);
    assert_eq!(available_resources(model.prepared), before);
    println!("concurrent_live_children=2");
    println!("concurrent_comparison_owner_graph=one-active-execution,three-independent-services");
    println!(
        "concurrent_comparison_vm_processes={}",
        first_pids.len() + second_pids.len()
    );
    result
}
