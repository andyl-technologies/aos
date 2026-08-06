//! Certifies the production lifecycle's two-VM hostless World network route.
//!
//! This is an integration-style example for readers who want to see how the
//! Crucible model controls real QEMU processes. It exercises five related
//! behaviors in one executable:
//!
//! 1. Two guests exchange frames over a deterministic, lossy virtual link.
//! 2. The search API exposes a branch where a particular frame is lost.
//! 3. The selected network branch is replayed in a fresh lifecycle.
//!
//! The executable expects paths to QEMU, the Crucible QEMU plugin, a kernel, a
//! raw root image, and an initrd, in that order. The repository's Nix checks
//! normally provide those artifacts. Successful output is intentionally
//! machine-readable so the surrounding gate can certify each behavior.

use std::error::Error;
use std::time::Duration;

use crucible::{
    Icount, LinkDef, LinkLossProbability, NodeId, NodeTemplate, Plan, Properties, QuantumLoop,
    QuantumRequest, ReadyPoint, ScenarioDefForm, Seed, SimDuration, WhiteBoxPolicy, World,
    WorldNode,
};
use crucible_api::{
    ProductionRootImageFormat, ProductionVmLifecycleConfig, build_production_vm_lifecycle_loop,
};

/// Creates a minimal VM description whose artifacts come from backend config.
///
/// `kernel`, `root_image`, and `initrd` are absent here because every node in
/// this certification run uses the paths supplied to
/// [`ProductionVmLifecycleConfig`]. The defaults keep the scenario focused on
/// lifecycle and network behavior rather than guest sizing.
fn node(name: &str) -> WorldNode {
    WorldNode {
        id: NodeId {
            name: String::from(name),
        },
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 0 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }
}

/// Runs the network and replay certifications.
///
/// # Errors
///
/// Returns an error when arguments are invalid, a scenario or lifecycle cannot
/// be built, QEMU execution fails, or any expected decision, frame delivery,
/// process transition, checkpoint, or replay is not observed.
fn main() -> Result<(), Box<dyn Error>> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let [qemu, plugin, kernel, root_image, initrd] = args.as_slice() else {
        return Err(
            "usage: crucible-qemu-live-world-network QEMU PLUGIN KERNEL ROOT INITRD".into(),
        );
    };
    // ---------------------------------------------------------------------
    // Stage 1: build and run a two-node world with a lossy network link.
    // ---------------------------------------------------------------------
    let left = NodeId {
        name: String::from("node-a"),
    };
    let right = NodeId {
        name: String::from("node-b"),
    };
    let link = LinkDef::with_transport(
        left.clone(),
        right.clone(),
        SimDuration {
            nanos: 3_999_000_000,
        },
        SimDuration { nanos: 0 },
        LinkLossProbability::from_millionths(250_000)?,
        None,
    )?;
    // The link has 3.999 seconds of simulated latency and a 25% loss rate.
    // Loss is a deterministic Crucible choice derived from the scenario seed,
    // not randomness sampled from the host operating system.
    let world = World::from_nodes_and_links(vec![node(&left.name), node(&right.name)], vec![link])?;
    // An empty plan and property set are sufficient here: this first stage is
    // inspecting backend decisions directly rather than waiting for assertions
    // to produce a terminal verdict.
    let source = ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(0x5eed),
    )?;
    let scenario = source.scenario_def();
    // The quantum budget controls how many authoritative scheduler quanta the
    // lifecycle admits; the run ceiling separately bounds retired instructions.
    let config = ProductionVmLifecycleConfig::new(qemu, plugin, kernel, root_image)
        .with_root_image_format(ProductionRootImageFormat::Raw)
        .with_initrd(initrd)
        .with_kernel_cmdline_prefix("console=ttyS0 quiet net.ifnames=0 init=/init")
        .with_run_ceiling_icount(12_000_000_000)
        .with_quantum_budget(4_000_000_000)
        .with_completion_timeout(Duration::from_secs(180));
    let mut lifecycle = build_production_vm_lifecycle_loop(&scenario, &source, &config)?;
    let mut configuration = crucible::Configuration::genesis(scenario.clone());
    let mut network_decisions = 0_usize;
    let mut delivered_frames = 0_usize;
    let mut selected_branch = None;
    // Twelve quanta are enough for the purpose-built guests to emit traffic and
    // for delayed frames to reach the opposite guest. The loop also waits until
    // search exposes a counterfactual `loss-fire` choice for later replay.
    for quantum in 0..12_u64 {
        let outcome = lifecycle.drive_quantum(QuantumRequest {
            configuration,
            control: Vec::new(),
        })?;
        configuration = outcome.configuration;
        network_decisions = network_decisions.saturating_add(
            outcome
                .decisions
                .iter()
                .filter(|decision| matches!(decision, crucible::Decision::FaultFires(_)))
                .count(),
        );
        // Backend-input events are frames that have completed the simulated
        // route and are ready to be injected into a destination QEMU process.
        delivered_frames = delivered_frames.saturating_add(
            outcome
                .resolved_events
                .iter()
                .filter(|event| {
                    matches!(
                        event.payload,
                        crucible::ScheduledEventPayload::BackendInput(_)
                    )
                })
                .count(),
        );
        // Search frontiers describe alternate decisions reachable from the
        // current execution. Selecting the exact choice object, rather than
        // reconstructing it by name, preserves all replay metadata.
        selected_branch = lifecycle
            .search_frontiers()?
            .into_iter()
            .flat_map(|frontier| frontier.choices.choices().to_vec())
            .find(|choice| {
                matches!(
                    choice.decisions().first(),
                    Some(crucible::Decision::Override(override_decision))
                        if override_decision.choice.name == "loss-fire"
                )
            });
        if network_decisions > 0 && delivered_frames > 0 && selected_branch.is_some() {
            println!("completed_quantum={quantum}");
            break;
        }
    }
    let selected_branch = selected_branch.ok_or_else(|| {
        format!(
            "no live loss branch after 12 quanta: network_decisions={network_decisions} delivered_frames={delivered_frames}"
        )
    })?;
    if network_decisions == 0 || delivered_frames == 0 {
        return Err(format!(
            "no complete guest-output route after 12 quanta: network_decisions={network_decisions} delivered_frames={delivered_frames}"
        )
        .into());
    }
    lifecycle.shutdown()?;

    // ---------------------------------------------------------------------
    // Stage 2: replay the exact lossy-network branch found in Stage 1.
    // ---------------------------------------------------------------------
    let override_decision = match selected_branch.decisions().first() {
        Some(crucible::Decision::Override(override_decision)) => override_decision.clone(),
        _ => return Err("live loss branch did not begin with its exact override".into()),
    };
    let expected_decisions = selected_branch.decisions().to_vec();
    // Branch choices are configured before lifecycle construction so the fresh
    // run consumes the override at the same deterministic decision point.
    let branch_config = config
        .clone()
        .with_branch_network_choices(vec![override_decision]);
    let mut branch = build_production_vm_lifecycle_loop(&scenario, &source, &branch_config)?;
    let mut branch_configuration = crucible::Configuration::genesis(scenario);
    let mut branch_matched = false;
    // A branch can contain more than one decision. Window comparison verifies
    // the complete ordered sequence occurs contiguously in one quantum outcome.
    for _ in 0..12_u64 {
        let outcome = branch.drive_quantum(QuantumRequest {
            configuration: branch_configuration,
            control: Vec::new(),
        })?;
        branch_configuration = outcome.configuration;
        if outcome
            .decisions
            .windows(expected_decisions.len())
            .any(|window| window == expected_decisions)
        {
            branch_matched = true;
            break;
        }
    }
    branch.shutdown()?;
    if !branch_matched {
        return Err("live QEMU replay did not consume the selected network branch".into());
    }
    println!("PASS");
    println!("gate=gate:live-world-network");
    println!("backend=production-qemu-lifecycle");
    println!("topology=two-vm-hostless-world-link");
    println!("network_decisions={network_decisions}");
    println!("delivered_frames={delivered_frames}");
    println!("search_branch=loss-fire");
    println!("branch_decisions_match=true");
    Ok(())
}
