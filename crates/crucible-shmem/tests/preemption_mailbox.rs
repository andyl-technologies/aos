//! Exercises the ABI-v5 scheduler-to-plugin preemption mailbox.

use crucible_shmem::{
    KIND_VM, NodeSlot, PreemptionMailboxError, SchedulerPreemptionCommand, SchedulerPreemptionKind,
};

fn switch(at_icount: u64) -> SchedulerPreemptionCommand {
    SchedulerPreemptionCommand {
        at_icount,
        deadline_icount: 100,
        ceiling_icount: 200,
        kind: SchedulerPreemptionKind::VcpuSwitch {
            from_vcpu: 0,
            to_vcpu: 1,
        },
    }
}

#[test]
fn preemption_mailbox_round_trips_switch_interrupt_and_acknowledgement() {
    let slot = NodeSlot::new(KIND_VM);
    assert_eq!(slot.pending_preemption_command(), Ok(None));

    let sequence = slot
        .publish_preemption_command(switch(140))
        .unwrap_or_else(|error| panic!("valid preemption should publish: {error}"));
    let pending = slot
        .pending_preemption_command()
        .unwrap_or_else(|error| panic!("published preemption should decode: {error}"))
        .unwrap_or_else(|| panic!("published preemption should be pending"));
    assert_eq!(pending.sequence, sequence);
    assert_eq!(pending.command, switch(140));
    assert_eq!(slot.consumed_preemption_sequence(), 0);

    slot.acknowledge_preemption_command(sequence)
        .unwrap_or_else(|error| panic!("matching preemption should acknowledge: {error}"));
    assert_eq!(slot.consumed_preemption_sequence(), sequence);
    assert_eq!(slot.pending_preemption_command(), Ok(None));

    let interrupt = SchedulerPreemptionCommand {
        at_icount: 175,
        deadline_icount: 100,
        ceiling_icount: 200,
        kind: SchedulerPreemptionKind::InterruptAt {
            target_vcpu: 1,
            irq: 32,
        },
    };
    let interrupt_sequence = slot
        .publish_preemption_command(interrupt)
        .unwrap_or_else(|error| panic!("valid interrupt should publish: {error}"));
    let pending_interrupt = slot
        .pending_preemption_command()
        .unwrap_or_else(|error| panic!("published interrupt should decode: {error}"))
        .unwrap_or_else(|| panic!("published interrupt should be pending"));
    assert_eq!(pending_interrupt.sequence, interrupt_sequence);
    assert_eq!(pending_interrupt.command, interrupt);
    slot.acknowledge_preemption_command(interrupt_sequence)
        .unwrap_or_else(|error| panic!("matching interrupt should acknowledge: {error}"));
}

#[test]
fn preemption_mailbox_rejects_overwrite_wrong_ack_and_invalid_window() {
    let slot = NodeSlot::new(KIND_VM);
    let sequence = slot
        .publish_preemption_command(switch(120))
        .unwrap_or_else(|error| panic!("first preemption should publish: {error}"));
    assert_eq!(
        slot.publish_preemption_command(SchedulerPreemptionCommand {
            at_icount: 130,
            deadline_icount: 100,
            ceiling_icount: 200,
            kind: SchedulerPreemptionKind::InterruptAt {
                target_vcpu: 1,
                irq: 32,
            },
        }),
        Err(PreemptionMailboxError::CommandOutstanding {
            published_sequence: sequence,
            consumed_sequence: 0,
        })
    );
    assert!(matches!(
        slot.acknowledge_preemption_command(sequence.wrapping_add(1)),
        Err(PreemptionMailboxError::AcknowledgeMismatch { .. })
    ));

    slot.acknowledge_preemption_command(sequence)
        .unwrap_or_else(|error| panic!("first preemption should acknowledge: {error}"));
    assert_eq!(
        slot.publish_preemption_command(SchedulerPreemptionCommand {
            at_icount: 99,
            deadline_icount: 100,
            ceiling_icount: 200,
            kind: SchedulerPreemptionKind::InterruptAt {
                target_vcpu: 1,
                irq: 32,
            },
        }),
        Err(PreemptionMailboxError::CommandOutsideWindow {
            at_icount: 99,
            deadline_icount: 100,
            ceiling_icount: 200,
        })
    );
    assert_eq!(
        slot.publish_preemption_command(SchedulerPreemptionCommand {
            at_icount: 150,
            deadline_icount: 200,
            ceiling_icount: 100,
            kind: SchedulerPreemptionKind::VcpuSwitch {
                from_vcpu: 0,
                to_vcpu: 1,
            },
        }),
        Err(PreemptionMailboxError::InvalidWindow {
            deadline_icount: 200,
            ceiling_icount: 100,
        })
    );
}
