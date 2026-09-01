//! Bounded live PowerOff and PermanentFailure matrix driver.

use super::*;

pub(super) const TERMINAL_MATRIX_EVENT_NANOS: u64 = 12_000_000_000;

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
) -> Result<ProductionFaultEvidenceSnapshot, Box<dyn Error>> {
    for quantum in 0..16 {
        eprintln!("shared-cause phase=terminal-matrix quantum={quantum} begin");
        let outcome = lifecycle.drive_quantum(QuantumRequest {
            configuration,
            control: Vec::new(),
        })?;
        configuration = outcome.configuration;
        let evidence = lifecycle.fault_evidence_snapshot()?;
        if exact_terminal_matrix(before, &evidence) {
            return Ok(evidence);
        }
    }
    Err("PowerOff/PermanentFailure production matrix did not settle within 16 quanta".into())
}
