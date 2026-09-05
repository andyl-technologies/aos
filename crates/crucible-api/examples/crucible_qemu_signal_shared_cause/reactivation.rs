//! Explicit Boot after host-only time advancement, including cold exact restore.

use super::*;

const BOOT_NANOS: u64 = INACTIVE_COMPLETION_NANOS + 1024;
pub(super) const COMPLETION_NANOS: u64 = BOOT_NANOS + 1_000_000_000;
const BOOT_BINDING: &str = "inactive-world-boot";

pub(super) fn boot_signal() -> Result<(SignalId, SignalNode), Box<dyn Error>> {
    let event = signal_id(BOOT_BINDING)?;
    let schema = signal_id("inactive-world-boot-v1")?;
    Ok((
        event.clone(),
        SignalNode {
            id: event,
            domain: SignalDomain::Event,
            output: SignalShape::new(
                SignalValueType::Event(schema.clone()),
                SignalUnit::Dimensionless,
                0,
            )?,
            inputs: Vec::new(),
            kind: SignalNodeKind::Source(SignalSourceSpecification::EventSequence {
                events: vec![SignalPoint {
                    coordinate: SignalCoordinate::Event {
                        parent: Box::new(SignalCoordinate::VirtualTime { nanos: BOOT_NANOS }),
                        sequence: 0,
                    },
                    sequence: 0,
                    value: SignalValue::Event {
                        schema,
                        payload: b"boot".to_vec(),
                    },
                }],
            }),
        },
    ))
}

pub(super) fn boot_binding(
    program: &crucible::model::SignalProgram,
) -> Result<FaultBinding, Box<dyn Error>> {
    event_binding(
        BOOT_BINDING,
        &signal_id(BOOT_BINDING)?,
        ResolvedFaultTarget::Node {
            node: id("node-a")?,
        },
        EffectSpecification::Node(NodeEffectSpecification::Lifecycle {
            transition: NodeLifecycleTransition::Boot,
            downtime_nanos: 0,
            boot_policy: NodeBootPolicy::Immediate,
            volatile_state_policy: NodeStatePolicy::Preserve,
            device_state_policy: NodeStatePolicy::Preserve,
        }),
        program,
    )
}

pub(super) fn run(
    source: &ScenarioDefForm,
    config: &ProductionVmLifecycleConfig,
) -> Result<(), Box<dyn Error>> {
    let scenario = source.scenario_def();
    let mut lifecycle = build_production_vm_lifecycle_loop(&scenario, source, config)?;
    let (restarted, configuration) = drive_to_restarted_node(
        &mut lifecycle,
        Configuration::genesis(scenario.clone()),
        "reactivation-prelude",
    )?;
    let (inactive, configuration) =
        drive_to_terminal_matrix(&mut lifecycle, configuration, &restarted)?;
    let closure = lifecycle
        .capture_checkpoint(&configuration)?
        .ok_or("inactive reactivation checkpoint absent")?;
    let checkpoint = checkpoint_reference(&configuration, inactive.frontier, closure);
    let expected = drive(&mut lifecycle, configuration.clone(), &inactive)?;
    lifecycle.shutdown()?;
    let mut restored =
        build_production_vm_lifecycle_loop_from_checkpoint(&scenario, source, config, &checkpoint)?;
    let replayed = drive(&mut restored, configuration, &inactive)?;
    restored.shutdown()?;
    if expected != replayed {
        return Err(
            "cold inactive restore changed reactivation evidence or event-log segments".into(),
        );
    }
    println!("PASS");
    println!("inactive_world_boot_reactivation=true");
    println!("reactivated_guest_progress=true");
    println!("reactivation_checkpoint_evidence_match=true");
    Ok(())
}

fn drive(
    lifecycle: &mut ProductionVmLifecycleLoop,
    mut configuration: Configuration,
    before: &ProductionFaultEvidenceSnapshot,
) -> Result<(ProductionFaultEvidenceSnapshot, Vec<ContentHash>), Box<dyn Error>> {
    let prior = before
        .nodes
        .iter()
        .find(|node| node.node.name == "node-a")
        .ok_or("powered-off node absent")?;
    let failed = before
        .nodes
        .iter()
        .find(|node| node.node.name == "node-b")
        .ok_or("permanently failed node absent")?;
    let mut advanced = false;
    let mut segments = Vec::new();
    for quantum in 0..16 {
        eprintln!("shared-cause phase=reactivation quantum={quantum} begin");
        let outcome = lifecycle.drive_quantum(QuantumRequest {
            configuration,
            control: Vec::new(),
        })?;
        configuration = outcome.configuration;
        advanced |= outcome.advanced_node.as_ref().is_some_and(|node| {
            node.node.name == "node-a" && node.kind == crucible::SchedulingNodeKind::Vm
        });
        eprintln!(
            "shared-cause phase=reactivation quantum={quantum} frontier={} advanced_vm={advanced}",
            outcome.frontier.ticks
        );
        if let Some(segment) = outcome.event_log_segment_hash {
            segments.push(segment);
        }
        if lifecycle.terminal_verdict_for_stop().is_none() {
            continue;
        }
        let evidence = lifecycle.fault_evidence_snapshot()?;
        let current = evidence
            .nodes
            .iter()
            .find(|node| node.node.name == "node-a")
            .ok_or("reactivated node absent")?;
        let boot = evidence
            .resolved_effect_trace
            .as_ref()
            .into_iter()
            .flat_map(|trace| &trace.work_items)
            .flat_map(|item| &item.records)
            .filter(|record| record.binding.as_str() == BOOT_BINDING)
            .collect::<Vec<_>>();
        // Reaching the selected RUN ceiling makes the scheduler node idle.
        // The advanced VM outcome above proves execution resumed after Boot;
        // the final service and ownership evidence must still remain live.
        if !advanced
            || outcome.frontier.ticks != COMPLETION_NANOS
            || !matches!(
                lifecycle.terminal_verdict_for_stop(),
                Some(crucible::QuantumTerminalVerdict::Passed)
            )
            || current.generation != prior.generation
            || current.service_state != "running"
            || current.scheduler_activity != SchedulerNodeActivity::Idle
            || !current.backend_owned
            || current.process_ownership != "exact"
            || evidence
                .nodes
                .iter()
                .find(|node| node.node.name == "node-b")
                != Some(failed)
            || boot.len() != 1
            || boot[0].coordinate.virtual_nanos != BOOT_NANOS
            || boot[0].coordinate.retired_instructions.is_none()
            || boot[0].effect != EffectKind::NodeLifecycle
            || boot[0].action_kind != BindingActionKind::Apply
            || segments.is_empty()
        {
            return Err(format!(
                "reactivation did not preserve ownership, authenticate Boot, and resume guest progress at the exact deadline: frontier={}, advanced_vm={advanced}, verdict={:?}, prior={prior:?}, current={current:?}, boot_records={boot:?}",
                outcome.frontier.ticks,
                lifecycle.terminal_verdict_for_stop(),
            ).into());
        }
        return Ok((evidence, segments));
    }
    Err("reactivation did not complete within 16 quanta".into())
}
