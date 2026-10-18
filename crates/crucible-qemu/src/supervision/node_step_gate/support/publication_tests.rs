//! Original priming operations retried under one source-acquisition budget.

use super::*;
use crate::supervision::host_io_runtime::tests::publication_access::MappedPublication;

#[test]
fn priming_retries_busy_origin_without_repeating_canary_or_scheduler_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let mut mapped = MappedPublication::new()?;
    mapped.set_producer_sequence(1)?;
    let deadline = HostSupervisionDeadline::start(Duration::from_secs(1));
    let file = mapped.file.try_clone()?;
    let producer_sequence =
        mapped.layout.node_slots_off + crucible_shmem::NODE_SLOT_PUBLISH_GEN_OFFSET as u64;
    let payload = vec![4, 5, 6];
    let mut refused = false;

    prime_publication_operation(
        &mut mapped.channel,
        &deadline,
        1,
        "publish boot backpressure canary",
        |channel| {
            let result = channel.deliver_frame_at(
                BackendInput {
                    node: node_id("publication"),
                    payload: payload.clone(),
                },
                Icount { retired: 1 },
            );
            if result
                .as_ref()
                .is_err_and(|error| error.is_publication_unavailable())
            {
                assert!(!refused);
                refused = true;
                // This explicit modeled writer completes its real shared mapping
                // after the actual channel has returned its effect-free refusal.
                use std::os::unix::fs::FileExt;
                file.write_all_at(&2_u32.to_ne_bytes(), producer_sequence)
                    .map_err(|error| {
                        crate::QemuNodeChannelError::new(
                            "complete modeled publication",
                            error.to_string(),
                        )
                    })?;
            }
            result
        },
    )?;
    assert!(refused);
    let mut pending = prime_publication_operation(
        &mut mapped.channel,
        &deadline,
        1,
        "start priming quantum",
        |channel| {
            channel.start_quantum(
                MappedPublication::horizon(),
                crate::QemuQuantumStopCondition::Ceiling,
            )
        },
    )?;
    let network = mapped.channel.checkpoint_network_transport()?;
    assert_eq!(network.inbound.frames.len(), 1);
    assert_eq!(network.inbound.frames[0].payload()?, payload);
    let authorized = mapped.producer.node_slot(0)?.snapshot();
    assert_eq!(authorized.max_advance_icount, 1);
    // Canary delivery and the subsequent RUN each publish exactly one
    // scheduler tuple; a refused acquisition publishes neither.
    assert_eq!(authorized.advance_publication_sequence, 4);
    // This host-only consumer discharges the real transport obligation; it
    // does not stand in for an authenticated guest or QEMU callback.
    let rings = mapped.producer.node_directed_ring_pair_mut(
        0,
        0,
        crucible_shmem::SLOT_NET_ROUTER as u32,
        crucible_shmem::SLOT_NET_ROUTER as u32,
        0,
    )?;
    let canary = rings
        .second
        .header
        .dequeue(rings.second.entries)?
        .ok_or("canary transport was empty")?;
    assert_eq!(canary.payload()?, payload);
    assert_eq!(canary.seq, 0);
    mapped.producer.node_slot(0)?.publish_reached_icount(1)?;
    let completion = mapped.channel.poll_quantum(&mut pending)?;
    assert_eq!(completion.ceiling.retired, 1);
    assert_eq!(completion.final_state.current_icount.retired, 1);
    Ok(())
}

#[test]
fn expired_priming_acquisition_budget_permits_no_channel_operation()
-> Result<(), Box<dyn std::error::Error>> {
    let mut mapped = MappedPublication::new()?;
    let before = mapped.producer.node_slot(0)?.snapshot();
    mapped.set_producer_sequence(1)?;
    let deadline = HostSupervisionDeadline::start(Duration::ZERO);
    let mut called = false;

    let error = prime_publication_operation(
        &mut mapped.channel,
        &deadline,
        100,
        "start priming quantum",
        |channel| {
            called = true;
            channel.start_quantum(
                MappedPublication::horizon(),
                crate::QemuQuantumStopCondition::Ceiling,
            )
        },
    )
    .err()
    .ok_or("expired original budget issued a RUN")?;

    assert!(matches!(
        error,
        QemuLiveNodeStepGateError::PrimeStalled {
            ceiling_icount: 100
        }
    ));
    assert!(!called);
    mapped.set_producer_sequence(before.publish_gen)?;
    assert_eq!(mapped.producer.node_slot(0)?.try_snapshot(), Some(before));
    Ok(())
}

#[test]
fn consumed_completion_keeps_its_original_frames_during_busy_clock_reread()
-> Result<(), Box<dyn std::error::Error>> {
    let mut mapped = MappedPublication::new()?;
    let mut pending = mapped.channel.start_quantum(
        MappedPublication::horizon(),
        crate::QemuQuantumStopCondition::Ceiling,
    )?;
    mapped.producer.node_slot(0)?.publish_reached_icount(100)?;
    let frame = crucible_shmem::FrameEntry::new(100, 0, 7, b"original completed frame")?;
    {
        let rings = mapped.producer.node_directed_ring_pair_mut(
            0,
            0,
            crucible_shmem::SLOT_NET_ROUTER as u32,
            crucible_shmem::SLOT_NET_ROUTER as u32,
            0,
        )?;
        rings.first.header.enqueue(rings.first.entries, &frame)?;
    }
    let completion = mapped.channel.poll_quantum(&mut pending)?;
    assert_eq!(completion.emitted_frames.len(), 1);
    let original_frames = completion.emitted_frames.clone();
    assert!(
        mapped
            .channel
            .checkpoint_network_transport()?
            .outbound
            .frames
            .is_empty()
    );
    let coherent = mapped.producer.node_slot(0)?.snapshot();
    mapped.set_producer_sequence(coherent.publish_gen + 1)?;
    let file = mapped.file.try_clone()?;
    let offset = mapped.layout.node_slots_off + crucible_shmem::NODE_SLOT_PUBLISH_GEN_OFFSET as u64;
    let deadline = HostSupervisionDeadline::start(Duration::from_secs(1));
    let mut refused = false;

    let current = prime_publication_operation(
        &mut mapped.channel,
        &deadline,
        100,
        "read completed priming icount",
        |channel| {
            let result = channel.current_icount();
            if result
                .as_ref()
                .is_err_and(|error| error.is_publication_unavailable())
            {
                assert!(!refused);
                refused = true;
                assert_eq!(completion.emitted_frames, original_frames);
                use std::os::unix::fs::FileExt;
                file.write_all_at(&(coherent.publish_gen + 2).to_ne_bytes(), offset)
                    .map_err(|error| {
                        crate::QemuNodeChannelError::new(
                            "finish modeled clock publication",
                            error.to_string(),
                        )
                    })?;
            }
            result
        },
    )?;

    assert!(refused);
    assert_eq!(
        current.retired,
        completion.final_state.current_icount.retired
    );
    assert_eq!(completion.emitted_frames, original_frames);
    assert!(
        mapped
            .channel
            .checkpoint_network_transport()?
            .outbound
            .frames
            .is_empty()
    );
    Ok(())
}
