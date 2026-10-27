//! Fail-closed refusals for recorded effects that thin replay cannot enact.

use super::*;

use crucible_engine::model::{FaultCoordinate, FaultObjectId, ResolvedFaultTarget};
use crucible_engine::{ContentHash, EventId, VirtualTime};

/// Returns a committed fault effect on `target` at the last input's time.
fn committed_effect(
    target: ResolvedFaultTarget,
) -> Result<FaultObservation, Box<dyn std::error::Error>> {
    Ok(FaultObservation {
        semantic_version: 1,
        kind: FaultObservationKind::EffectCommitted,
        coordinate: FaultCoordinate {
            virtual_ticks: 2,
            retired_instructions: None,
        },
        binding: Some(FaultObjectId::parse("replay-fault")?),
        target: Some(target),
        opportunity: None,
        evidence: ContentHash::from_bytes(b"replay fault evidence"),
    })
}

/// Rebased receiver whose log ends with one recorded fault observation.
struct FaultedReceiver {
    world: World,
    receiver: NodeId,
    scheduler: SingleScheduler,
    /// Event-log sequence of the appended observation.
    fault_sequence: u64,
}

/// Records both rebased-receiver inputs, then appends `observation`.
fn scheduler_with_fault(
    observation: FaultObservation,
) -> Result<FaultedReceiver, Box<dyn std::error::Error>> {
    let RebasedReceiver {
        world,
        receiver,
        scenario,
    } = rebased_receiver_scenario([1, 2])?;
    let mut scheduler = SingleScheduler::new(scenario)?;
    drive_until_resolved_inputs(&mut scheduler, 2)?;
    let append = scheduler.append_fault_observations([observation])?;
    let fault_sequence = append
        .entries
        .first()
        .ok_or("fault observation did not append")?
        .sequence();

    Ok(FaultedReceiver {
        world,
        receiver,
        scheduler,
        fault_sequence,
    })
}

/// Returns the receiver's replay plan, or the typed refusal that replaces it.
fn plan(
    faulted: &FaultedReceiver,
) -> Result<Result<Vec<ReplayStep>, QemuVmRealizationError>, Box<dyn std::error::Error>> {
    let checkpoint = faulted.scheduler.checkpoint()?;
    let segments = faulted.scheduler.event_log_segment_store();

    Ok(authenticated_replay_steps(
        &faulted.world,
        faulted.scheduler.configuration(),
        &checkpoint,
        segments.as_ref(),
        1,
        &faulted.receiver,
        2,
    ))
}

#[test]
fn replay_plan_refuses_a_recorded_node_fault_command_before_replay_work()
-> Result<(), Box<dyn std::error::Error>> {
    let target = ResolvedFaultTarget::Node {
        node: FaultObjectId::parse("receiver")?,
    };
    let faulted = scheduler_with_fault(committed_effect(target)?)?;

    let refusal = plan(&faulted)?
        .err()
        .ok_or("a node fault command must refuse guarded replay")?;

    assert_eq!(
        refusal,
        QemuVmRealizationError::ReplayOracleUnsupported {
            node: String::from("receiver"),
            effect: QemuReplayOracleUnsupportedEffect::VmFaultEffect {
                sequence: faulted.fault_sequence,
                kind: FaultObservationKind::EffectCommitted,
                target: Some(crucible_engine::model::FaultTargetKind::Node),
            },
        }
    );
    Ok(())
}

#[test]
fn replay_plan_refuses_a_recorded_storage_fault_command() -> Result<(), Box<dyn std::error::Error>>
{
    let target = ResolvedFaultTarget::BlockDevice {
        device: ContentHash::from_bytes(b"receiver root image"),
    };
    let faulted = scheduler_with_fault(committed_effect(target)?)?;

    let refusal = plan(&faulted)?
        .err()
        .ok_or("a storage fault command must refuse guarded replay")?;

    assert!(
        refusal.to_string().contains("block_device"),
        "unexpected refusal: {refusal}"
    );
    Ok(())
}

#[test]
fn replay_plan_admits_a_network_fault_whose_effect_reaches_the_vm_as_inputs()
-> Result<(), Box<dyn std::error::Error>> {
    let target = ResolvedFaultTarget::NetworkForwarder {
        forwarder: FaultObjectId::parse("replay-forwarder")?,
    };
    let faulted = scheduler_with_fault(committed_effect(target)?)?;

    let inputs = plan(&faulted)??
        .iter()
        .filter(|step| matches!(step, ReplayStep::Input { .. }))
        .count();

    assert_eq!(inputs, 2);
    Ok(())
}

#[test]
fn replay_plan_refuses_a_lifecycle_action_on_the_replayed_node_only() {
    let receiver = NodeId {
        name: String::from("receiver"),
    };
    let application = |node: &str| TriggerActionApplication {
        sequence: 0,
        event: EventId::from_name("restart"),
        at: VirtualTime { ticks: 1 },
        path: Vec::new(),
        action: Action::StopNode {
            node: NodeId {
                name: node.to_owned(),
            },
        },
    };

    assert_eq!(
        reject_node_lifecycle_action(&receiver, 7, &application("receiver")),
        Err(QemuVmRealizationError::ReplayOracleUnsupported {
            node: String::from("receiver"),
            effect: QemuReplayOracleUnsupportedEffect::NodeLifecycleAction { sequence: 7 },
        })
    );
    assert_eq!(
        reject_node_lifecycle_action(&receiver, 7, &application("sender")),
        Ok(())
    );
}
