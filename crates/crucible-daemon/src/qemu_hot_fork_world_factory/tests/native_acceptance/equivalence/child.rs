//! Production hot-child construction, continuation, and cleanup.

use super::evidence::ContinuationEvidence;
use super::*;
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
}

#[derive(Clone, Copy, Debug)]
pub(super) struct NativeHotChildMeasurement {
    pub(super) ready_millis: u64,
    pub(super) processes: usize,
    pub(super) private_dirty_kib: u64,
    pub(super) private_rss_kib: u64,
    pub(super) rss_anon_kib: u64,
    pub(super) allocated_bytes: u64,
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
}

pub(super) fn start_hot_child(request: NativeHotChildStart<'_>) -> ActiveNativeHotChild {
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
    let materialization = lifecycle
        .start_materialization()
        .expect("inspect hot child materialization");
    let ready_millis = operational_elapsed_milliseconds(fork_started);
    let processes = cgroup_processes(&paths.cgroup_root.join(lane));
    let private_dirty_kib = processes
        .iter()
        .map(|process| process_status_kib(*process, "smaps_rollup", "Private_Dirty:"))
        .sum();
    let private_clean_kib = processes
        .iter()
        .map(|process| process_status_kib(*process, "smaps_rollup", "Private_Clean:"))
        .sum::<u64>();
    let rss_anon_kib = processes
        .iter()
        .map(|process| process_status_kib(*process, "status", "RssAnon:"))
        .sum();
    let allocated_bytes = allocated_tree_bytes(&paths.storage_root.join(lane));
    let measurement = NativeHotChildMeasurement {
        ready_millis,
        processes: processes.len(),
        private_dirty_kib,
        private_rss_kib: private_dirty_kib.saturating_add(private_clean_kib),
        rss_anon_kib,
        allocated_bytes,
    };
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
    ActiveNativeHotChild {
        factory,
        lifecycle,
        source,
        boundary,
        pending,
        measurement,
    }
}
