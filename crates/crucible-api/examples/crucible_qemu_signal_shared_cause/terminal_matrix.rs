//! Bounded live PowerOff and PermanentFailure matrix driver.

use super::*;

pub(super) const TERMINAL_MATRIX_EVENT_NANOS: u64 = 12_000_000_000;
pub(super) const INACTIVE_CHECKPOINT_NANOS: u64 = TERMINAL_MATRIX_EVENT_NANOS + 1024;
pub(super) const INACTIVE_COMPLETION_NANOS: u64 = INACTIVE_CHECKPOINT_NANOS + 1024;

pub(super) fn terminal_matrix_signal() -> Result<(SignalId, SignalNode), Box<dyn Error>> {
    let event = signal_id("terminal-matrix-event")?;
    let schema = signal_id("terminal-matrix-event-v1")?;
    let node = SignalNode {
        id: event.clone(),
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
                    parent: Box::new(SignalCoordinate::VirtualTime {
                        nanos: TERMINAL_MATRIX_EVENT_NANOS,
                    }),
                    sequence: 0,
                },
                sequence: 0,
                value: SignalValue::Event {
                    schema,
                    payload: b"terminal-matrix".to_vec(),
                },
            }],
        }),
    };
    Ok((event, node))
}

pub(super) fn terminal_matrix_bindings(
    event: &SignalId,
    program: &crucible::model::SignalProgram,
) -> Result<Vec<FaultBinding>, Box<dyn Error>> {
    Ok(vec![
        event_binding(
            "terminal-matrix-power-off",
            event,
            ResolvedFaultTarget::Node {
                node: id("node-a")?,
            },
            EffectSpecification::Node(NodeEffectSpecification::Lifecycle {
                transition: NodeLifecycleTransition::PowerOff,
                downtime_nanos: 0,
                boot_policy: NodeBootPolicy::Immediate,
                volatile_state_policy: NodeStatePolicy::Preserve,
                device_state_policy: NodeStatePolicy::Clear,
            }),
            program,
        )?,
        event_binding(
            "terminal-matrix-permanent-failure",
            event,
            ResolvedFaultTarget::Node {
                node: id("node-b")?,
            },
            EffectSpecification::Node(NodeEffectSpecification::Lifecycle {
                transition: NodeLifecycleTransition::PermanentFailure,
                downtime_nanos: 0,
                boot_policy: NodeBootPolicy::Immediate,
                volatile_state_policy: NodeStatePolicy::Preserve,
                device_state_policy: NodeStatePolicy::Clear,
            }),
            program,
        )?,
    ])
}

pub(super) fn drive_to_restarted_node(
    lifecycle: &mut ProductionVmLifecycleLoop,
    mut configuration: Configuration,
    phase: &'static str,
) -> Result<(ProductionFaultEvidenceSnapshot, Configuration), Box<dyn Error>> {
    for quantum in 0..64 {
        eprintln!("shared-cause phase={phase} quantum={quantum} begin");
        let outcome = lifecycle.drive_quantum(QuantumRequest {
            configuration,
            control: Vec::new(),
        })?;
        configuration = outcome.configuration;
        let evidence = lifecycle.fault_evidence_snapshot()?;
        eprintln!(
            "shared-cause phase={phase} quantum={quantum} frontier={} generation={:?}",
            evidence.frontier.ticks,
            evidence
                .nodes
                .iter()
                .find(|node| node.node.name == "node-a")
                .map(|node| node.generation),
        );
        if reached_restarted_node(&evidence) {
            return Ok((evidence, configuration));
        }
    }
    Err("node-a did not restart after the shared-cause event within 64 quanta".into())
}

pub(super) fn drive_to_terminal_matrix(
    lifecycle: &mut ProductionVmLifecycleLoop,
    mut configuration: Configuration,
    before: &ProductionFaultEvidenceSnapshot,
) -> Result<(ProductionFaultEvidenceSnapshot, Configuration), Box<dyn Error>> {
    for quantum in 0..16 {
        eprintln!("shared-cause phase=terminal-matrix quantum={quantum} begin");
        let outcome = lifecycle.drive_quantum(QuantumRequest {
            configuration,
            control: Vec::new(),
        })?;
        configuration = outcome.configuration;
        let evidence = lifecycle.fault_evidence_snapshot()?;
        let checkpoint_fired = outcome.event_log_entries.iter().any(|entry| {
            matches!(entry.payload(), crucible::SchedulerEventLogPayload::TriggerFired(firing)
                if firing.event() == &crucible::EventId::from_name("inactive-world-checkpoint")
                    && firing.at().ticks == INACTIVE_CHECKPOINT_NANOS)
        });
        if exact_terminal_matrix(before, &evidence)
            && evidence.frontier.ticks == INACTIVE_CHECKPOINT_NANOS
            && checkpoint_fired
            && outcome.advanced_node.is_none()
            && lifecycle.terminal_verdict_for_stop().is_none()
        {
            return Ok((evidence, configuration));
        }
    }
    Err("PowerOff/PermanentFailure production matrix did not settle within 16 quanta".into())
}

/// Requires a real powered-off world to complete without another backend RUN.
pub(super) fn complete_inactive_world(
    lifecycle: &mut ProductionVmLifecycleLoop,
    configuration: Configuration,
    before: &ProductionFaultEvidenceSnapshot,
) -> Result<ContentHash, Box<dyn Error>> {
    let outcome = lifecycle.drive_quantum(QuantumRequest {
        configuration,
        control: Vec::new(),
    })?;
    let fired = outcome.event_log_entries.iter().any(|entry| {
        matches!(entry.payload(), crucible::SchedulerEventLogPayload::TriggerFired(firing)
            if firing.event() == &crucible::EventId::from_name("inactive-world-complete")
                && firing.at().ticks == INACTIVE_COMPLETION_NANOS)
    });
    if outcome.advanced_node.is_some()
        || outcome.frontier.ticks != INACTIVE_COMPLETION_NANOS
        || !fired
        || !matches!(
            lifecycle.terminal_verdict_for_stop(),
            Some(crucible::QuantumTerminalVerdict::Passed)
        )
        || lifecycle.fault_evidence_snapshot()?.nodes != before.nodes
    {
        return Err("inactive-world completion changed node ownership, ran a backend, or missed its exact trigger".into());
    }
    outcome.event_log_segment_hash.ok_or_else(|| {
        "inactive-world completion emitted no authenticated event-log segment".into()
    })
}

pub(super) fn checkpoint_reference(
    configuration: &Configuration,
    frontier: crucible::VirtualTime,
    closure: ContentHash,
) -> Checkpoint {
    let mut checkpoint =
        Checkpoint::new(configuration.id(), configuration.id(), CheckpointKind::Fat);
    checkpoint.scenario_ref = configuration.def.id();
    checkpoint.virtual_time = frontier;
    checkpoint.execution_closure = Some(closure);
    checkpoint
}
