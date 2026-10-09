//! Real scheduler/UART sentinel correctness flight, excluded from timed runs.
//!
//! Invoke only in a disposable VM with dedicated empty cgroup-v2 and ext4
//! project-quota roots. This test launches the original guarded source and
//! dispatches through the real scheduler, not a copied RUN or native owner.

#![cfg(test)]

use std::path::PathBuf;
use std::time::Duration;

use crucible::{
    BackendQuantumLoop, ConcurrentQuantumLoop, ExactLocalEvent, NetworkLookahead, NodeCounter,
    QuantumRequest, SchedulerLivenessScenario, SchedulerNodeActivity, SchedulerNodeId,
    SchedulerScenarioNode, SchedulingNodeKind, SimInstant, SingleScheduler,
};

use super::{
    child_files::{GuardedSource, launch_guarded_source},
    *,
};
use crate::QemuNodeSet;
use crate::node_set::ConsoleSentinelProbe;

fn input(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(std::env::var_os(name)
        .ok_or_else(|| format!("missing owned VM fixture input {name}"))?
        .into())
}

#[test]
#[ignore = "requires reviewed native31 and disposable cgroup/project-quota VM roots"]
fn real_scheduler_uart_stops_before_following_ram_store() -> Result<(), Box<dyn std::error::Error>>
{
    let qemu = input("CRUCIBLE_CONSOLE_CAUSAL_QEMU")?;
    let plugin = input("CRUCIBLE_CONSOLE_CAUSAL_PLUGIN")?;
    let kernel = input("CRUCIBLE_CONSOLE_CAUSAL_KERNEL")?;
    let firmware = input("CRUCIBLE_CONSOLE_CAUSAL_FIRMWARE")?;
    let cgroup_root = input("CRUCIBLE_CONSOLE_CAUSAL_CGROUP_ROOT")?;
    let run_root = input("CRUCIBLE_CONSOLE_CAUSAL_RUN_ROOT")?;
    let config = QemuLiveNodeStepGateConfig::new(qemu, plugin, kernel, firmware, &run_root)
        .with_firmware_boot()
        // The matching launch builder seals its native console plan and fixed
        // frontend into setup, rather than merely redirecting stderr.
        .with_console_capture()
        .with_vm_shape(128, 1)
        .with_completion_timeout(Duration::from_secs(60));
    let GuardedSource {
        factory: _factory,
        mut source_owner,
        source_directory,
        node,
        source_vmstate_path: _,
    } = launch_guarded_source(&config, &cgroup_root, &run_root)?;
    let identity = node_id(GATE_NODE);
    let mut source_node = Some(node);
    let mut actor: Option<BackendQuantumLoop<SingleScheduler, QemuNodeSet>> = None;

    // Every fallible post-launch operation stays inside this scope. Until the
    // actor is installed the source holder owns the node; after transfer the
    // retained actor owns it even if probe installation or driving fails.
    let operation = (|| -> Result<(), Box<dyn std::error::Error>> {
        let node = source_node
            .as_mut()
            .ok_or("guarded source holder lost its node")?;
        let ready = node.native_console_ready_counter_for_test()?;
        if node.current_icount()?.retired != ready.ticks {
            return Err("actual Ready owner and paused handoff counter differ".into());
        }
        let scheduler_node = SchedulerNodeId {
            node: identity.clone(),
            kind: SchedulingNodeKind::Vm,
        };
        let scenario = SchedulerLivenessScenario::from_canonical_material(
            "native-console-real-uart-sentinel-v1",
            4,
            SimInstant {
                ticks: 8_000_000_000,
            },
            vec![SchedulerScenarioNode {
                id: scheduler_node.clone(),
                counter: ready,
                activity: SchedulerNodeActivity::Runnable,
                network_lookahead: NetworkLookahead::Infinite,
                exact_local_event: ExactLocalEvent::NoArmedTimer,
            }],
            Vec::new(),
        )
        .with_ready_point_counter(scheduler_node, NodeCounter { ticks: ready.ticks });
        let scheduler = SingleScheduler::new(scenario)?;
        let probe = ConsoleSentinelProbe::new(
            identity.clone(),
            ready,
            source_directory.prepare_console_sentinel_for_test()?,
        );
        let retained_actor = actor.insert(BackendQuantumLoop::new(scheduler, QemuNodeSet::new()));
        let node = source_node
            .take()
            .ok_or("guarded source holder lost its node")?;
        if retained_actor
            .backend_mut()
            .insert(identity.clone(), node)
            .is_some()
        {
            return Err("source node was unexpectedly replaced".into());
        }
        retained_actor
            .backend_mut()
            .install_console_sentinel_probe_for_test(probe.clone())?;

        // The original worker observes before returning its original outcome.
        // Core may continue that outcome within the same drive call.
        retained_actor.drive_concurrent_quantum(
            QuantumRequest {
                configuration: retained_actor.loop_impl().configuration().clone(),
                control: Vec::new(),
            },
            1,
        )?;
        let samples = probe.samples()?;
        let [sample] = samples.as_slice() else {
            return Err("expected exactly one actual UART operation-stop observation".into());
        };
        if sample.byte != 0
            || sample.origin.byte != b'X'
            || sample.origin.logical_generation != 0
            || sample.authorization.phase
                != crucible_protocol::native_console::NativeConsolePhase::Grant
            || sample.authorization.logical_generation != sample.origin.logical_generation
            || sample.origin.node_sequence != 1
            || sample.origin.stream_sequence != 1
            || sample.origin.emitted_ps <= ready.ticks
            || sample.accounted_ps < sample.origin.emitted_ps
        {
            return Err(
                "real UART origin/sentinel/accounted boundary violated causal contract".into(),
            );
        }
        Ok(())
    })();

    // No early return separates node containment from attempt-owner finish.
    // Report cleanup failures separately while preserving the operation error.
    let retained_node = match actor.as_mut() {
        Some(actor) => actor.backend_mut().take(&identity),
        None => source_node.take(),
    };
    let cleanup: Result<(), Box<dyn std::error::Error>> = match retained_node {
        Some(mut node) => node.force_crash_and_reap_for_gate().map_err(Into::into),
        None => Err("original fixture lost the guarded source during cleanup".into()),
    };
    drop(source_node);
    drop(actor);
    drop(source_directory);
    let finish = source_owner.finish();
    if let Err(error) = &cleanup {
        eprintln!("console causal fixture explicit source cleanup failed: {error}");
    }
    if let Err(error) = &finish {
        eprintln!("console causal fixture attempt-owner finish failed: {error}");
    }
    operation?;
    cleanup?;
    finish?;
    Ok(())
}
