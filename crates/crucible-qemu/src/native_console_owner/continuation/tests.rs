//! Closed checkpoint-shape controls, without native emission or phase providers.

use crucible_protocol::native_console::{
    NativeConsoleDevice, NativeConsolePlan, NativeConsoleStream,
};

use super::*;

fn saved_suffix() -> Result<ConsoleOriginContinuation, ConsoleOwnerError> {
    let device = NativeConsoleDevice::Serial16550;
    let plan = NativeConsolePlan {
        slot: 0,
        logical_generation: 0,
        node_sequence_base: 0,
        streams: vec![NativeConsoleStream {
            stream: 1,
            device,
            device_identity: device.fixed_console_identity(),
            owner_mask: 1,
            sequence_base: 0,
        }],
    };
    // Earlier observations were already handed off. Only the final suffix
    // remains in host custody; its origins are explicitly modeled saved data.
    let pending = [(5, 5, b'a'), (6, 6, b'b')]
        .into_iter()
        .map(
            |(node_sequence, stream_sequence, byte)| RetainedConsoleByte {
                origin: NativeConsoleByteOrigin {
                    device: crucible::ContentHash {
                        bytes: device.fixed_console_identity(),
                    },
                    stream: 1,
                    logical_generation: 0,
                    node_sequence,
                    stream_sequence,
                    emitted_ps: 60,
                    raw_prefix: 0,
                    vcpu: 0,
                    byte,
                },
                projection: ConsoleProjection::Boot,
            },
        )
        .collect();
    Ok(ConsoleOriginContinuation {
        node: NodeId { name: "vm".into() },
        ready_counter: NodeCounter { ticks: 100 },
        plan: plan.encode()?,
        sequence: 6,
        ring_end: 6,
        stream_sequences: vec![6],
        pending,
        projection: ConsoleProjection::Boot,
    })
}

#[test]
fn saved_origin_requires_declared_vcpu_owner() -> Result<(), ConsoleOwnerError> {
    let saved = saved_suffix()?;
    assert_eq!(ConsoleOriginContinuation::decode(&saved.encode()?)?, saved);

    let mut foreign = saved.clone();
    foreign.pending[0].origin.vcpu = 1;
    assert!(ConsoleOriginContinuation::decode(&foreign.encode()?).is_err());

    let mut outside_vocabulary = saved;
    outside_vocabulary.pending[0].origin.vcpu = 64;
    assert!(ConsoleOriginContinuation::decode(&outside_vocabulary.encode()?).is_err());
    Ok(())
}

#[test]
fn saved_stream_suffix_is_contiguous_and_reaches_accepted_tail() -> Result<(), ConsoleOwnerError> {
    let saved = saved_suffix()?;
    assert_eq!(ConsoleOriginContinuation::decode(&saved.encode()?)?, saved);

    for first_sequence in [0, 4, 6, 7] {
        let mut malformed = saved.clone();
        malformed.pending[0].origin.stream_sequence = first_sequence;
        assert!(ConsoleOriginContinuation::decode(&malformed.encode()?).is_err());
    }
    let mut missing_tail = saved.clone();
    missing_tail.stream_sequences[0] = 7;
    assert!(ConsoleOriginContinuation::decode(&missing_tail.encode()?).is_err());

    let mut below_node_base = saved;
    let mut plan = NativeConsolePlan::decode(&below_node_base.plan)?;
    plan.node_sequence_base = 5;
    below_node_base.plan = plan.encode()?;
    assert!(ConsoleOriginContinuation::decode(&below_node_base.encode()?).is_err());
    Ok(())
}

#[test]
fn saved_accepted_node_tail_equals_closed_stream_totals() -> Result<(), ConsoleOwnerError> {
    let mut saved = saved_suffix()?;
    // With no queued observations, only the accepted closed-plan counters
    // remain. A larger node tail cannot hide behind an empty pending suffix.
    saved.pending.clear();
    assert_eq!(ConsoleOriginContinuation::decode(&saved.encode()?)?, saved);

    let mut too_many_node_bytes = saved.clone();
    too_many_node_bytes.sequence = 7;
    assert!(ConsoleOriginContinuation::decode(&too_many_node_bytes.encode()?).is_err());

    let mut too_many_stream_bytes = saved;
    too_many_stream_bytes.stream_sequences[0] = 7;
    assert!(ConsoleOriginContinuation::decode(&too_many_stream_bytes.encode()?).is_err());
    Ok(())
}
