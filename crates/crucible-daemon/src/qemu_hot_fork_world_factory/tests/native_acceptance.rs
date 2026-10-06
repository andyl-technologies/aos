//! Native real-QEMU acceptance for atomic production whole-world forks.

// crucible-lint: allow panic-shortcut -- ignored native gate assertions use panic shortcuts.
#![allow(clippy::expect_used)]

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crucible::LocalDagStore;
use crucible::model::DagStore;
use crucible_api::ProductionVmLifecycleConfig;
use crucible_qemu::QemuRootImageFormat;

use super::*;

#[path = "native_acceptance/equivalence.rs"]
mod equivalence;
#[path = "native_acceptance/failures.rs"]
mod failures;
#[path = "native_acceptance/final_audit.rs"]
mod final_audit;
#[path = "native_acceptance/isolation_native_negative.rs"]
mod isolation_native_negative;
#[path = "native_acceptance/isolation_negative.rs"]
mod isolation_negative;
#[path = "native_acceptance/resource_isolation.rs"]
mod resource_isolation;
#[path = "native_acceptance/scenario.rs"]
mod scenario;

const MAX_SOURCE_QUANTA: u64 = 30_000;
const NATIVE_RENDEZVOUS_INTERVAL_TICKS: u64 = 50_000_000_000;
const NATIVE_TERMINAL_MARGIN_NANOS: u64 = 30_000_000_000;
const NATIVE_RUN_CEILING_TICKS: u64 =
    (scenario::REACTIVATION_NANOS + NATIVE_TERMINAL_MARGIN_NANOS) * crucible::SIM_TICKS_PER_NS;

struct NativeGatePaths {
    qemu: PathBuf,
    plugin: PathBuf,
    kernel: PathBuf,
    root_image: PathBuf,
    fixture: PathBuf,
    artifacts: PathBuf,
    cgroup_root: PathBuf,
    storage_root: PathBuf,
    run_state_root: PathBuf,
}

impl NativeGatePaths {
    fn from_environment() -> Self {
        Self {
            qemu: required_path("CRUCIBLE_ATOMIC_WORLD_QEMU"),
            plugin: required_path("CRUCIBLE_ATOMIC_WORLD_PLUGIN"),
            kernel: required_path("CRUCIBLE_ATOMIC_WORLD_KERNEL"),
            root_image: required_path("CRUCIBLE_ATOMIC_WORLD_ROOT"),
            fixture: required_path("CRUCIBLE_ATOMIC_WORLD_SCENARIO"),
            artifacts: required_path("CRUCIBLE_ATOMIC_WORLD_ARTIFACTS"),
            cgroup_root: required_path("CRUCIBLE_ATOMIC_WORLD_CGROUP"),
            storage_root: required_path("CRUCIBLE_ATOMIC_WORLD_STORAGE"),
            run_state_root: required_path("CRUCIBLE_ATOMIC_WORLD_RUN_STATE"),
        }
    }
}

#[test]
#[ignore = "requires the packaged patched QEMU, cgroup v2, and project quotas"]
fn production_source_idle_prefix_reaches_exact_tick() {
    run_atomic_world_case(crate::packaged_qemu_executor::NativeAtomicWorldCase::Idle);
}

#[test]
#[ignore = "requires the packaged patched QEMU, cgroup v2, and project quotas"]
fn production_factory_forks_complete_live_world_atomically() {
    run_atomic_world_case(crate::packaged_qemu_executor::NativeAtomicWorldCase::Complete);
}

#[test]
#[ignore = "requires isolated AOS paging kernel, actual mapped virtqueue and original Service"]
fn production_managed_dma_maps_block_reclaim_until_real_completion() {
    let paths = NativeGatePaths::from_environment();
    let fixture = fs::read_to_string(&paths.fixture).expect("original real block traffic");
    let artifacts: Arc<dyn DagStore> = Arc::new(LocalDagStore::new(&paths.artifacts));
    let (source, artifacts) = scenario::build_single_node_equivalence(
        &fixture,
        artifacts,
        &paths.kernel,
        &paths.root_image,
    )
    .expect("actual one-VM virtio-block traffic");
    let config = lifecycle_config(
        &paths,
        paths.run_state_root.join("dma-borrowers"),
        artifacts,
    );
    crate::packaged_qemu_executor::run_dma_borrowers_native(source, config);
}

fn run_atomic_world_case(case: crate::packaged_qemu_executor::NativeAtomicWorldCase) {
    let paths = NativeGatePaths::from_environment();
    let fixture = fs::read_to_string(&paths.fixture).expect("reviewed traffic scenario");
    let artifacts: Arc<dyn DagStore> = Arc::new(LocalDagStore::new(&paths.artifacts));
    let (source, artifacts) =
        scenario::build(&fixture, artifacts, &paths.kernel, &paths.root_image)
            .expect("reviewed mixed-state world");
    let lifecycle = lifecycle_config(&paths, paths.run_state_root.join("atomic-world"), artifacts);
    crate::packaged_qemu_executor::run_atomic_world_native(source, lifecycle, case);
}

fn lifecycle_config(
    paths: &NativeGatePaths,
    run_state_root: PathBuf,
    artifacts: Arc<dyn DagStore>,
) -> ProductionVmLifecycleConfig {
    let config = ProductionVmLifecycleConfig::new(
        &paths.qemu,
        &paths.plugin,
        &paths.kernel,
        &paths.root_image,
        run_state_root,
    )
    .with_root_image_format(QemuRootImageFormat::Raw)
    .with_kernel_cmdline_prefix("console=ttyS0 net.ifnames=0 root=/dev/vda rw init=/init")
    .with_signal_artifacts(Arc::clone(&artifacts))
    .with_world_artifacts(artifacts);

    let config = if std::env::var_os("CRUCIBLE_PHASE7_IDLE_TRACE").is_some() {
        config.with_rr_control_boundary_trace()
    } else {
        config
    };

    native_lifecycle_bounds(config)
}

fn native_lifecycle_bounds(config: ProductionVmLifecycleConfig) -> ProductionVmLifecycleConfig {
    // The terminal ceiling must outlive the 81-second reactivation. The
    // 50-millisecond rendezvous interval bounds each RUN independently.
    config
        .with_run_ceiling_ticks(NATIVE_RUN_CEILING_TICKS)
        .with_rendezvous_interval_ticks(NATIVE_RENDEZVOUS_INTERVAL_TICKS)
        .with_quantum_budget(MAX_SOURCE_QUANTA)
        .with_completion_timeout(Duration::from_secs(300))
}

#[test]
fn native_lifecycle_bounds_cover_the_last_fault_event() {
    let config = native_lifecycle_bounds(ProductionVmLifecycleConfig::new(
        "qemu",
        "plugin",
        "kernel",
        "root",
        "run-state",
    ));
    let last_fault_ticks = scenario::REACTIVATION_NANOS * crucible::SIM_TICKS_PER_NS;
    let ninep_fault_end_ticks = (scenario::PERMANENT_FAILURE_NANOS
        + scenario::NINEP_FAULT_WINDOW_NANOS)
        * crucible::SIM_TICKS_PER_NS;

    assert!(config.run_ceiling_ticks() > last_fault_ticks);
    assert!(config.run_ceiling_ticks() > ninep_fault_end_ticks);
    assert_eq!(
        config.rendezvous_interval_ticks(),
        Some(NATIVE_RENDEZVOUS_INTERVAL_TICKS)
    );
    assert!(NATIVE_RENDEZVOUS_INTERVAL_TICKS < config.run_ceiling_ticks());
}

fn required_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("{name} must be set")))
}

pub(crate) use resource_isolation::assert_live_children_are_physically_private as assert_native_atomic_resources_private;
pub(crate) use resource_isolation::assert_native_sibling_resources_private;
