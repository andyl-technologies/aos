//! Production plugin assertions under the actual accepted assignment actor.
//!
//! Four-vCPU reference and preempted generations run sequentially inside one
//! live repository worker. The block recovery generation uses a second genuine
//! accepted request with its own authored one-vCPU machine. Both keep original
//! supervision, full host admission, physical quota, and terminal reconciliation.

use super::super::hot_fork_native::{native_repository, native_request};
use super::accepted_promotion::extend_native_operations;
use super::*;
use crate::{
    AttemptExecutionInput, AttemptExecutionModel, AttemptExecutionProduct, RepositoryAttemptWorker,
    decode_crucible_attempt_execution,
};
use crucible_api::host_operational::{HostOperationalError, HostResourceVector};
use crucible_campaign::{CampaignExecutorStore, ExecutorService, SubmitAttemptDisposition};

mod admission;
mod driver;

#[test]
#[ignore = "requires the isolated AOS production plugin VM, actual quota and managed native RAM"]
fn production_managed_plugin_flight_preserves_preemption_idle_trace_and_block_recovery() {
    let block_only =
        driver::block_recovery_only_requested().expect("explicit diagnostic selection");
    if !block_only {
        run_worker(false);
    }
    if std::env::var_os("CRUCIBLE_PHASE4_PARTITION_PROBE").is_none() {
        run_worker(true);
    }
    println!("PASS");
    println!("gate=gate:production-rust-plugin-flight");
    println!("production_accepted_assignment=true");
}

fn run_worker(block: bool) {
    let source = scenario(block);
    let lane = if block { "plugin-block" } else { "plugin-four" };
    let project = if block { 33_100 } else { 33_000 };
    let catalog = environment::NativeCatalogBudget {
        resources: HostResourceVector {
            resident_peak_bytes: 384 * 1024 * 1024,
            backing_peak_bytes: 1024 * 1024 * 1024,
            metadata_bytes: 256 * 1024 * 1024,
            staging_bytes: 8 * 1024 * 1024,
            paging_io_slots: 1,
            cpu_slots: 1,
            task_slots: 1,
            file_descriptors: 128,
        },
        maximum_inodes: 262_144,
        installation_capacity: Some(
            ExecutorCapacity::new(1, 6, 8 << 30, 16 << 30, 150_000)
                .expect("four execution CPUs and two retained services"),
        ),
        installation_operational_capacity: Some(
            crate::HostOperationalCapacity::new(16, 1024, 16_384, 2 << 30, 256 << 20)
                .expect("independent full-vector service and assignment metadata"),
        ),
    };
    environment::with_native_repository_environment_with_catalog(
        lane,
        project,
        catalog,
        |root, storage| native_repository(&source, root, storage),
        resources,
        |prepared, config, repository| {
            let request = native_request(&repository, config);
            let queued = prepared
                .actor
                .with_supervisor(|actor| {
                    assert!(matches!(
                        actor
                            .submit_attempt(&request)
                            .map_err(|_| HostOperationalError::Unavailable)?
                            .disposition(),
                        SubmitAttemptDisposition::Accepted { .. }
                    ));
                    actor.next_queued().ok_or(HostOperationalError::Unavailable)
                })
                .expect("real accepted plugin assertion assignment");
            let store = CampaignExecutorStore::new(repository);
            let mut worker = RepositoryAttemptWorker::new(
                store.clone(),
                PluginFlightModel {
                    config: config.clone(),
                    store,
                    block,
                    complete: false,
                },
            );
            let (queued, result) = worker.execute(queued).into_parts();
            assert!(
                worker.model().complete,
                "native plugin driver must complete every assertion: {result:?}"
            );
            assert!(matches!(result, Err(AttemptWorkerFailure::Canceled(_))));
            prepared
                .actor
                .with_supervisor(|actor| {
                    actor
                        .stage_and_reconcile_cancellation(&queued)
                        .map_err(|_| HostOperationalError::Unavailable)
                })
                .expect("reconcile same assignment only after actual reap");
        },
    );
}

fn resources(mut config: PackagedQemuExecutorConfig) -> PackagedQemuExecutorConfig {
    config.capacity = ExecutorCapacity::new(1, 6, 8 << 30, 16 << 30, 150_000)
        .expect("explicit aggregate plugin flight capacity");
    config.host_operational_capacity =
        crate::HostOperationalCapacity::new(16, 1024, 16_384, 2 << 30, 256 << 20)
            .expect("explicit aggregate metadata and staging subsets");
    let project = if config.host.attempt_namespace().ends_with("plugin-block") {
        33_100
    } else {
        33_000
    };
    config.host = LinuxQemuAttemptHostConfig::new(
        config.host.cgroup_root(),
        config.host.run_root(),
        config.host.attempt_namespace(),
        project,
        1,
        65_534,
        65_534,
        128,
        2048,
        12,
        64,
        32 << 20,
        config.host.watcher_service_resident_bytes(),
        4096,
        Duration::from_secs(30),
    )
    .expect("explicit native and outside-host assertion service ceilings");
    config
        .with_assignment_resources(
            HostResourceVector {
                resident_peak_bytes: 2 << 30,
                backing_peak_bytes: 4 << 30,
                metadata_bytes: 512 << 20,
                staging_bytes: 32 << 20,
                paging_io_slots: 2,
                cpu_slots: 4,
                task_slots: 141,
                file_descriptors: 2112,
            },
            AttemptResourceLimits::new(4, 512 << 20, 1024 << 20, 50_000)
                .expect("original four-vCPU modeled request bounds"),
        )
        .expect("independently authored complete plugin assignment")
}

fn scenario(block: bool) -> ScenarioDefForm {
    let world = World::from_nodes(vec![crucible::WorldNode {
        id: NodeId {
            name: if block {
                "block-recovery-hot-fork-node"
            } else {
                "plugin-flight-node"
            }
            .into(),
        },
        arch: crucible::VmArchitecture::X86_64,
        memory_mib: 128,
        cmdline: String::new(),
        ready_point: crucible::ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: crucible::WhiteBoxPolicy::Disabled,
        smp_vcpus: if block { 1 } else { 4 },
        kernel: None,
        root_image: None,
        initrd: None,
    }])
    .expect("original native plugin machine shape");
    ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(42),
    )
    .expect("canonical actual accepted plugin source")
}

struct PluginFlightModel {
    config: PackagedQemuExecutorConfig,
    store: CampaignExecutorStore,
    block: bool,
    complete: bool,
}

impl AttemptExecutionModel for PluginFlightModel {
    type Error = std::io::Error;

    fn execute(
        &mut self,
        input: &AttemptExecutionInput,
        context: &AttemptExecutionContext,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        assert!(context.host_outer_cap_owner().is_some());
        extend_native_operations(context);
        let input = decode_crucible_attempt_execution(&self.store, input)
            .expect("authenticated actual plugin scenario");
        let mut factory =
            admission::AdmittedFlightFactory::new(&self.config, context, input.scenario())
                .expect("production accepted world factory");
        let qemu = environment::environment_path("CRUCIBLE_PAGING_QEMU");
        let plugin = environment::environment_path("CRUCIBLE_PAGING_PLUGIN");
        let kernel = environment::environment_path("CRUCIBLE_PAGING_KERNEL");
        let firmware = environment::environment_path("CRUCIBLE_PLUGIN_FLIGHT_FIRMWARE");
        let run_root = self.config.host.run_root();
        let result = if self.block {
            driver::run_block(
                &mut factory,
                &qemu,
                &plugin,
                &kernel,
                &environment::environment_path("CRUCIBLE_PLUGIN_FLIGHT_BLOCK_INITRD"),
                &firmware,
                run_root,
            )
        } else {
            driver::run_four(
                &mut factory,
                &qemu,
                &plugin,
                &kernel,
                &environment::environment_path("CRUCIBLE_PLUGIN_FLIGHT_IDLE_INITRD"),
                &firmware,
                run_root,
            )
        };
        result.unwrap_or_else(|error| panic!("admitted native plugin assertion failed: {error}"));
        self.complete = true;
        context.cancellation().cancel();
        Err(AttemptWorkerFailure::Canceled(std::io::Error::other(
            "native plugin assertions completed and actual worlds reaped",
        )))
    }
}
