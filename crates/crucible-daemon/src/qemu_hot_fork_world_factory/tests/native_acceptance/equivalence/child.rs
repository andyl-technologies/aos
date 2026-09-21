//! Production hot-child construction, continuation, and cleanup.

use super::evidence::ContinuationEvidence;
use super::*;
use crate::qemu_hot_fork_world::QemuProductionHotForkRetainedLineage;
use crate::qemu_resource_guard::{
    ComposedQemuAttemptResourceGuard, LinuxQemuAttemptHostResourceOwner,
};

pub(super) fn run_hot_child(request: NativeHotChildStart<'_>) -> ContinuationEvidence {
    start_hot_child(request).finish()
}

type NativeHotChildResourceFactory =
    ComposedQemuAttemptResourceGuardFactory<LinuxQemuAttemptHostResourceFactory>;
type NativeHotChildResourceGuard =
    ComposedQemuAttemptResourceGuard<LinuxQemuAttemptHostResourceOwner>;
type NativeHotChildFactory = QemuProductionHotForkWorldLifecycleFactory<
    QemuSingleHotForkSourceWorldProvider,
    NativeHotChildResourceFactory,
>;

pub(super) struct ActiveNativeHotChild {
    factory: NativeHotChildFactory,
    lifecycle: QemuProductionHotForkWorldLifecycle<NativeHotChildResourceGuard>,
    source: crucible::ScenarioDefForm,
    boundary: Configuration,
    pending: QemuNodeSelectablePendingRequest,
    measurement: NativeHotChildMeasurement,
    cgroup: PathBuf,
    lineage: Option<Box<QemuProductionHotForkRetainedLineage<NativeHotChildResourceGuard>>>,
    promotion_boundary: Option<BoundaryEvidence>,
}

pub(super) struct PromotedNativeHotTemplate {
    pub(super) world: ProductionVmHotForkSourceWorld,
    pub(super) lineage: Box<QemuProductionHotForkRetainedLineage<NativeHotChildResourceGuard>>,
    pub(super) source: crucible::ScenarioDefForm,
    pub(super) boundary: BoundaryEvidence,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct NativeHotChildMeasurement {
    pub(super) world_launch_nanoseconds: u64,
    pub(super) ready_nanoseconds: u64,
    pub(super) ready_millis: u64,
    pub(super) processes: usize,
    pub(super) private_dirty_kib: u64,
    pub(super) private_rss_kib: u64,
    pub(super) rss_anon_kib: u64,
    pub(super) allocated_bytes: u64,
    pub(super) vm_pte_kib: u64,
    pub(super) vm_data_kib: u64,
    pub(super) anon_huge_pages_kib: u64,
    pub(super) numa_resident_pages: u64,
    pub(super) numa_nodes: usize,
    pub(super) node_launch_sum_nanoseconds: u64,
    pub(super) node_launch_max_nanoseconds: u64,
    pub(super) node_launch_count: usize,
}

pub(super) struct NativeHotChildStart<'a> {
    pub(super) paths: &'a NativeGatePaths,
    pub(super) lane: &'a str,
    pub(super) project_id_start: u32,
    pub(super) source: crucible::ScenarioDefForm,
    pub(super) expected_boundary: &'a BoundaryEvidence,
    pub(super) checkpoint: Option<ExactCheckpointId>,
    pub(super) execution_byte: u8,
    pub(super) world: ProductionVmHotForkSourceWorld,
    pub(super) topology: EquivalenceTopology,
}

impl ActiveNativeHotChild {
    pub(super) fn live_processes(&self) -> usize {
        self.lifecycle
            .fault_evidence_snapshot()
            .expect("inspect concurrent hot child ownership")
            .nodes
            .iter()
            .filter(|node| node.backend_owned)
            .count()
    }

    pub(super) const fn measurement(&self) -> NativeHotChildMeasurement {
        self.measurement
    }

    pub(super) fn finish_without_continuation(mut self) {
        QemuFreshAttemptLifecycleOwner::shutdown(&mut self.lifecycle).expect("shutdown hot child");
        reconcile_native_world(&mut self.lifecycle);
        assert!(self.factory.recover(self.lifecycle).is_ok());
        assert!(self.factory.sources.available());
        if let Some(lineage) = self.lineage {
            let source = self
                .factory
                .sources
                .take_available()
                .expect("recover final descendant template");
            lineage
                .retire_source_world(source)
                .expect("retire descendant template lineage");
        }
    }

    pub(super) fn finish_without_continuation_and_recover(
        mut self,
    ) -> ProductionVmHotForkSourceWorld {
        QemuFreshAttemptLifecycleOwner::shutdown(&mut self.lifecycle).expect("shutdown hot child");
        reconcile_native_world(&mut self.lifecycle);
        assert!(self.factory.recover(self.lifecycle).is_ok());
        self.factory
            .sources
            .take_available()
            .expect("recover reusable production source world")
    }

    pub(super) fn promote(self) -> PromotedNativeHotTemplate {
        let Self {
            factory: _,
            lifecycle,
            source,
            boundary: _,
            pending: _,
            measurement: _,
            cgroup: _,
            lineage,
            promotion_boundary,
        } = self;
        let (world, lineage) = lifecycle
            .promote_into_descendant_template(lineage)
            .expect("promote native hot child as descendant template");
        PromotedNativeHotTemplate {
            world,
            lineage: Box::new(lineage),
            source,
            boundary: promotion_boundary.expect("capture descendant template boundary"),
        }
    }

    pub(super) fn advance_to_next_semantic_depth(&mut self) {
        let selected = select_pending_configuration(
            &mut self.lifecycle,
            &self.source,
            self.boundary.clone(),
            &self.pending,
        );
        let boundary = drive_configuration_to_pending_boundary(
            &mut self.lifecycle,
            &self.source,
            selected,
            EquivalenceTopology::SingleNode,
        );
        self.boundary = boundary.configuration.clone();
        self.pending = boundary.pending.clone();
        self.promotion_boundary = Some(boundary);
    }

    pub(super) fn finish(mut self) -> ContinuationEvidence {
        let evidence = continue_from_pending(
            &mut self.lifecycle,
            &self.source,
            self.boundary,
            self.pending,
        );
        QemuFreshAttemptLifecycleOwner::shutdown(&mut self.lifecycle).expect("shutdown hot child");
        reconcile_native_world(&mut self.lifecycle);
        assert!(self.factory.recover(self.lifecycle).is_ok());
        assert!(self.factory.sources.available());
        evidence
    }

    pub(super) fn finish_measured(mut self) -> (ContinuationEvidence, u64, ProcessMemoryEvidence) {
        let started = operational_monotonic_nanoseconds();
        let evidence = continue_from_pending(
            &mut self.lifecycle,
            &self.source,
            self.boundary,
            self.pending,
        );
        let elapsed = operational_monotonic_nanoseconds().saturating_sub(started);
        let processes = cgroup_processes(&self.cgroup);
        let memory = process_memory_evidence(&processes);
        QemuFreshAttemptLifecycleOwner::shutdown(&mut self.lifecycle).expect("shutdown hot child");
        reconcile_native_world(&mut self.lifecycle);
        assert!(self.factory.recover(self.lifecycle).is_ok());
        assert!(self.factory.sources.available());
        self.factory
            .sources
            .take_available()
            .expect("recover measured production source world")
            .retire()
            .expect("retire measured production source world");
        (evidence, elapsed, memory)
    }
}

pub(super) fn start_hot_child(request: NativeHotChildStart<'_>) -> ActiveNativeHotChild {
    start_hot_child_with_lineage(request, None)
}

pub(super) fn start_descendant_hot_child(
    request: NativeHotChildStart<'_>,
    lineage: Box<QemuProductionHotForkRetainedLineage<NativeHotChildResourceGuard>>,
) -> ActiveNativeHotChild {
    start_hot_child_with_lineage(request, Some(lineage))
}

fn start_hot_child_with_lineage(
    request: NativeHotChildStart<'_>,
    lineage: Option<Box<QemuProductionHotForkRetainedLineage<NativeHotChildResourceGuard>>>,
) -> ActiveNativeHotChild {
    let NativeHotChildStart {
        paths,
        lane,
        project_id_start,
        source,
        expected_boundary,
        checkpoint,
        execution_byte,
        world,
        topology,
    } = request;
    let boundary = expected_boundary.configuration.clone();
    let input = execution_input_for_scenario_configuration(source.clone(), boundary.clone());
    let context = execution_context(&input, execution_byte).with_resume_checkpoint(checkpoint);
    let key = QemuHotForkSourceWorldKey::for_execution(
        &input,
        &context,
        context.runtime_basis().expect("hot child runtime basis"),
    )
    .expect("derive hot child source key");
    assert_eq!(context.resume_checkpoint(), checkpoint);
    let provider = QemuSingleHotForkSourceWorldProvider::new(key, world);
    let target = open_host(paths, lane, project_id_start);
    let mut factory = QemuProductionHotForkWorldLifecycleFactory::new(
        provider,
        ComposedQemuAttemptResourceGuardFactory::new(target),
        paths.run_state_root.join(lane),
        crucible_qemu::QemuShutdownPolicy::fast_test(),
        crucible_qemu::QemuAsyncDriverPolicy::fast_test(),
    );
    let fork_started = operational_monotonic_nanoseconds();
    let mut lifecycle = match factory
        .try_start(&input, &context)
        .expect("start production hot child")
    {
        QemuHotForkWorldLifecycleStart::Started(lifecycle) => lifecycle,
        QemuHotForkWorldLifecycleStart::Declined => panic!("prepared hot source was declined"),
    };
    let world_launch_nanoseconds = operational_monotonic_nanoseconds().saturating_sub(fork_started);
    let materialization = lifecycle
        .start_materialization()
        .expect("inspect hot child materialization");
    let processes = cgroup_processes(&paths.cgroup_root.join(lane));
    let memory = process_memory_evidence(&processes);
    let allocated_bytes = allocated_tree_bytes(&paths.storage_root.join(lane));
    assert_eq!(materialization.restored_configuration(), Some(&boundary));
    let pending = drain_exact_pending(&mut lifecycle);
    let actual_boundary = capture_boundary_evidence(
        &mut lifecycle,
        &source,
        boundary.clone(),
        pending.clone(),
        topology,
    );
    assert_eq!(&actual_boundary, expected_boundary);
    let ready_nanoseconds = operational_monotonic_nanoseconds().saturating_sub(fork_started);
    let node_launch_sum_nanoseconds = factory
        .node_launch_nanoseconds()
        .iter()
        .map(|(_, elapsed)| *elapsed)
        .sum();
    let node_launch_max_nanoseconds = factory
        .node_launch_nanoseconds()
        .iter()
        .map(|(_, elapsed)| *elapsed)
        .max()
        .unwrap_or(0);
    let node_launch_count = factory.node_launch_nanoseconds().len();
    let measurement = NativeHotChildMeasurement {
        world_launch_nanoseconds,
        ready_nanoseconds,
        ready_millis: ready_nanoseconds / 1_000_000,
        processes: processes.len(),
        private_dirty_kib: memory.private_dirty_kib,
        private_rss_kib: memory.private_rss_kib,
        rss_anon_kib: memory.rss_anon_kib,
        allocated_bytes,
        vm_pte_kib: memory.vm_pte_kib,
        vm_data_kib: memory.vm_data_kib,
        anon_huge_pages_kib: memory.anon_huge_pages_kib,
        numa_resident_pages: memory.numa_resident_pages,
        numa_nodes: memory.numa_nodes,
        node_launch_sum_nanoseconds,
        node_launch_max_nanoseconds,
        node_launch_count,
    };
    ActiveNativeHotChild {
        factory,
        lifecycle,
        source,
        boundary,
        pending,
        measurement,
        cgroup: paths.cgroup_root.join(lane),
        lineage,
        promotion_boundary: None,
    }
}
