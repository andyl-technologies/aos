//! Exercises repeated completed-quantum clamps through the production node.
//!
//! A busy, diskless firmware loop runs twenty thousand increasing scheduler
//! ceilings. Each step uses the real node's device servicing and mandatory
//! completed-quantum acknowledgement under its original one-second guard.
//! This isolates busy firmware control delivery; it does not qualify Linux
//! replay, idle timer wakes, network fault settlement, or hot-fork children.
//!
//! ```text
//! crucible-qemu-rom-clamp-stress QEMU PLUGIN FIRMWARE CGROUP_ROOT RUN_ROOT [baseline|ack-poll-100us]
//! ```

#![forbid(unsafe_code)]

use std::error::Error;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use crucible::{AdvanceOutcome, SimulationBackend, VirtualTime};
use crucible_qemu::{
    LinuxQemuAttemptHostConfig, LinuxQemuAttemptHostFactory, QemuLiveNodeIdentity,
    QemuLiveNodeStepGateConfig, QemuNode, QemuProductionFreshLaunchAdmission,
    launch_qemu_production_fresh_node,
};

const STEP_COUNT: u64 = 20_000;
const STEP_PS: u64 = 1_000;
const MEMORY_BYTES: u64 = 512 * 1024 * 1024;
const DISK_BYTES: u64 = 1024 * 1024 * 1024;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crucible-qemu-rom-clamp-stress: {error}");
            let mut source = error.source();
            while let Some(cause) = source {
                eprintln!("caused by: {cause}");
                source = cause.source();
            }
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args_os()
        .skip(1)
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    let experiment = if arguments.len() == 6 {
        let mode = arguments.pop().ok_or("missing experiment mode")?;
        Some(experiment_mode(&mode)?)
    } else {
        None
    };
    let [qemu, plugin, firmware, cgroup_root, run_root] = arguments.as_slice() else {
        return Err("expected QEMU PLUGIN FIRMWARE CGROUP_ROOT RUN_ROOT".into());
    };
    let host = LinuxQemuAttemptHostConfig::new(
        cgroup_root,
        run_root,
        "rom-clamp-stress",
        23_700,
        1,
        65534,
        65534,
        64,
        4096,
        Duration::from_secs(15),
    )?;
    let mut factory = LinuxQemuAttemptHostFactory::open(host)?;
    let mut owner = factory.begin(1, MEMORY_BYTES, DISK_BYTES)?;
    let config = QemuLiveNodeStepGateConfig::new(qemu, plugin, firmware, firmware, run_root)
        .with_firmware_boot()
        .with_vm_shape(64, 1)
        .with_completion_timeout(Duration::from_secs(1));
    #[cfg(feature = "test-support")]
    let config = if experiment == Some(true) {
        config.with_short_clamp_ack_poll_for_test()
    } else {
        config
    };
    let mut directory = owner.prepare_generation_run_directory(config.resource_requirements())?;
    directory.prepare_fresh_artifacts_guarded(qemu, None, owner.process_contract()?)?;
    let launch = config.with_run_directory(directory.path());
    let mut node = launch_qemu_production_fresh_node(
        &launch,
        QemuProductionFreshLaunchAdmission::admit(
            &launch,
            &directory,
            owner.process_contract()?,
            QemuLiveNodeIdentity::new("rom-clamp-node", "rom-clamp-router", "rom-clamp-crash"),
        )?,
    )?;

    let started = experiment.map(|_| diagnostic_clock());
    let drive = drive_clamps(&mut node);
    let elapsed = started.map(|start| diagnostic_clock().saturating_duration_since(start));
    // Cleanup runs even when the original step fails. Its result cannot replace
    // that step's primary error; success requires both reap and resource release.
    let shutdown = node.shutdown_child();
    drop(node);
    drop(directory);
    let finish = owner.finish();
    if let Err(error) = drive {
        eprintln!("cleanup: shutdown={shutdown:?}; finish={finish:?}");
        return Err(error);
    }
    let shutdown = shutdown?;
    finish?;
    if !shutdown.reaped || shutdown.leaked || !shutdown.failures.is_empty() {
        return Err(format!("owned child did not shut down cleanly: {shutdown:?}").into());
    }

    if let Some(elapsed) = elapsed {
        println!(
            "experiment_ack_poll_us={}",
            if experiment == Some(true) { 100 } else { 1000 }
        );
        println!("host_drive_elapsed_us={}", elapsed.as_micros());
        println!("qemu_cpu_time=unavailable");
    }
    println!("PASS");
    println!("completed_quantum_clamps={STEP_COUNT}");
    println!("step_ps={STEP_PS}");
    println!("clamp_guard_ms=1000");
    println!("guest_profile=busy-firmware-no-network");
    println!("owned_cleanup=complete");
    Ok(())
}

fn drive_clamps(node: &mut QemuNode) -> Result<(), Box<dyn Error>> {
    let initial = node.logical_time_calibration()?;
    let initial_offset = initial.offset()?;
    for step in 1..=STEP_COUNT {
        let target = initial
            .logical_icount
            .checked_add(step * STEP_PS)
            .ok_or("firmware stress ceiling overflow")?;
        let observation = SimulationBackend::step_to(node, VirtualTime { ticks: target })?;
        if observation.requested_ceiling.ticks != target
            || observation.reached.ticks != target
            || observation.outcome != AdvanceOutcome::ReachedHorizon
        {
            return Err(
                format!("step {step} did not reach its exact ceiling: {observation:?}").into(),
            );
        }
        let calibration = node.logical_time_calibration()?;
        if calibration.logical_icount != target || calibration.offset()? != initial_offset {
            return Err(
                format!("step {step} changed the busy calibration: {calibration:?}").into(),
            );
        }
    }
    let final_calibration = node.logical_time_calibration()?;
    if final_calibration.raw_icount <= initial.raw_icount {
        return Err("firmware did not retire instructions across completed clamps".into());
    }
    println!("initial_ps={}", initial.logical_icount);
    println!("final_ps={}", final_calibration.logical_icount);
    println!("initial_raw={}", initial.raw_icount);
    println!("final_raw={}", final_calibration.raw_icount);
    Ok(())
}

/// Measures the experiment only; host elapsed time never selects guest state.
// crucible-lint: allow clippy-disallowed-method -- diagnostic wall time measures this controlled comparison only.
#[allow(clippy::disallowed_methods)]
fn diagnostic_clock() -> std::time::Instant {
    std::time::Instant::now()
}

fn experiment_mode(mode: &std::path::Path) -> Result<bool, Box<dyn Error>> {
    #[cfg(feature = "test-support")]
    match mode.to_str() {
        Some("baseline") => Ok(false),
        Some("ack-poll-100us") => Ok(true),
        _ => Err("expected baseline or ack-poll-100us experiment mode".into()),
    }
    #[cfg(not(feature = "test-support"))]
    {
        let _ = mode;
        Err("ACK polling experiments require the test-support feature".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn experiment_modes_require_explicit_supported_feature() {
        #[cfg(feature = "test-support")]
        {
            assert!(
                !experiment_mode(std::path::Path::new("baseline"))
                    .unwrap_or_else(|error| panic!("baseline mode: {error}"))
            );
            assert!(
                experiment_mode(std::path::Path::new("ack-poll-100us"))
                    .unwrap_or_else(|error| panic!("candidate mode: {error}"))
            );
        }
        #[cfg(not(feature = "test-support"))]
        {
            assert!(experiment_mode(std::path::Path::new("baseline")).is_err());
            assert!(experiment_mode(std::path::Path::new("ack-poll-100us")).is_err());
        }
        assert!(experiment_mode(std::path::Path::new("ack-poll-0us")).is_err());
        assert!(experiment_mode(std::path::Path::new("100")).is_err());
    }
}
