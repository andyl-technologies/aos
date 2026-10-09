//! Socket-level original custody tests with a mechanical provider fixture.

use super::*;
use crucible_node_contract::{HashRef, Id, Phase, Position};
use crucible_protocol::node_control::{BoundaryPolicy, ExecutionKind, OwnerScope};

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn coordinate(time: u64) -> Position {
    Position {
        time_ps: U64::new(time),
        microstep: U64::new(0),
        phase: Phase::BoundaryControl,
    }
}

fn hash(domain: &str) -> HashRef {
    HashRef {
        algorithm: "blake3-256".into(),
        domain: domain.into(),
        digest: "01".repeat(32),
    }
}

fn command(sequence: u64, start: u64, limit: u64) -> ExecutionCommand {
    ExecutionCommand {
        sequence: U64::new(sequence),
        scope: OwnerScope {
            session: id("test/session"),
            incarnation: id("test/incarnation"),
            activation: id("test/activation"),
            node: id("test/node"),
            owner: id("test/owner"),
            world_generation: U64::new(1),
            owner_generation: U64::new(1),
            world_binding: hash("cnp.world-binding.v1"),
            owner_binding: hash("cnp.owner-binding.v1"),
        },
        operation: id(&format!("test/operation/{sequence}")),
        grant: id(&format!("test/grant/{sequence}")),
        input_epoch: id("test/input-epoch"),
        input_batch: id("test/input-batch"),
        input_batch_hash: hash("cnp.input-batch.v1"),
        closed_input_prefix: coordinate(limit),
        authorization_digest: [7; 32],
        kind: ExecutionKind::ExactRun {
            start: coordinate(start),
            limit: coordinate(limit),
            boundary_policy: BoundaryPolicy::HorizonPark,
        },
    }
}

fn channels() -> (NativeQemuControlTransport, NativeChannel) {
    let (transport, endpoint) = NativeQemuControlTransport::prepare(NativePreparation {
        scope: command(1, 0, 110).scope,
        boundary: coordinate(0),
        maximum_commands: U64::new(4),
    })
    .unwrap();
    assert_ne!(*endpoint.scope_digest(), [0; 32]);
    let provider = NativeChannel::from_prepared_socket(endpoint.into_socket()).unwrap();
    assert!(matches!(
        provider.receive().unwrap(),
        Some(NativeFrame::Prepare(_))
    ));
    (transport, provider)
}

fn facts(original: &ExecutionCommand) -> NativeStopFacts {
    NativeStopFacts {
        sequence: original.sequence,
        command_digest: original.identity_digest().unwrap(),
        kind: NativeStopKind::HorizonPark,
        reached: original.kind.limit(),
        retired_count: U64::new(2),
        pending_classes: u32::MAX,
        next_native_deadline_ps: None,
        next_service_deadline_ps: Some(U64::new(150)),
        pending_service_credit_ps: U64::new(10),
    }
}

#[test]
fn launch_pins_edition_and_retains_original_command_and_stop() {
    let original = command(1, 0, 110);
    let (mut transport, endpoint) = NativeQemuControlTransport::prepare_for_edition(
        NativePreparation {
            scope: original.scope.clone(),
            boundary: coordinate(0),
            maximum_commands: U64::new(4),
        },
        NativeControlEdition::OwnedCustody,
    )
    .unwrap();
    assert_eq!(endpoint.edition(), NativeControlEdition::OwnedCustody);
    let provider = NativeChannel::from_prepared_socket_for_edition(
        endpoint.into_socket(),
        NativeControlEdition::OwnedCustody,
    )
    .unwrap();
    assert!(matches!(
        provider.receive().unwrap(),
        Some(NativeFrame::Prepare(_))
    ));
    assert!(transport.transmit_original(original.clone()).is_err());
    let park = crucible_protocol::node_control::NativeCpuParkFacts {
        prepared_scope_hash: original.scope.identity_digest().unwrap(),
        roster_sha256: [9; 32],
        coverage: 1,
        cpu_count: 1,
        current_ps: U64::new(0),
        retired_count: U64::new(0),
        next_service_deadline_ps: None,
        pending_service_credit_ps: U64::new(0),
    };
    provider.send(&NativeFrame::CpuPark(park.clone())).unwrap();
    transport.poll_original().unwrap();
    let observation = crucible_protocol::node_control::NativeWriterObservation {
        prepared_scope_hash: park.prepared_scope_hash,
        sequence: U64::new(0),
        command_digest: [0; 32],
        gate_generation: U64::new(1),
        current_ps: U64::new(0),
        retired_count: U64::new(0),
        aio_generation: U64::new(1),
        bh_generation: U64::new(1),
        handler_generation: U64::new(1),
        admissions_in_flight: U64::new(0),
        coverage: 7,
        flags: 15,
        roster_sha256: park.roster_sha256,
        cpus: vec![crucible_protocol::node_control::NativeWriterCpu {
            cpu_index: 0,
            interrupt_mask: 0,
            exception_index: -1,
            flags: 0,
            work_count: U64::new(0),
            next_work_sequence: U64::new(1),
        }],
        work: vec![],
        aio: vec![],
        bottom_halves: vec![],
        handlers: vec![],
    };
    assert!(transport.request_writer_observation(U64::new(0)).unwrap());
    assert!(matches!(
        provider.receive().unwrap(),
        Some(NativeFrame::QueryWriters(_))
    ));
    let bytes = observation.encode().unwrap();
    let chunk = crucible_protocol::node_control::NativeWriterChunk {
        prepared_scope_hash: park.prepared_scope_hash,
        sequence: U64::new(0),
        object_digest: *blake3::hash(&bytes).as_bytes(),
        total_bytes: U64::new(bytes.len() as u64),
        offset: U64::new(0),
        bytes,
    };
    let mut changed = chunk.clone();
    changed.bytes[8] ^= 1;
    provider.send(&NativeFrame::WriterChunk(changed)).unwrap();
    assert!(transport.poll_original().is_err());
    assert!(transport.writer_observation(U64::new(0)).is_none());
    provider
        .send(&NativeFrame::WriterChunk(chunk.clone()))
        .unwrap();
    transport.poll_original().unwrap();
    provider.send(&NativeFrame::WriterChunk(chunk)).unwrap();
    transport.poll_original().unwrap();
    assert_eq!(
        transport.writer_observation(U64::new(0)),
        Some(&observation)
    );
    transport.transmit_original(original.clone()).unwrap();
    assert_eq!(
        provider.receive().unwrap(),
        Some(NativeFrame::Command(Box::new(original.clone())))
    );
    assert!(
        provider
            .send(&NativeFrame::Stopped(facts(&original)))
            .unwrap()
    );
    transport.poll_original().unwrap();
    assert_eq!(
        transport.original_facts(original.sequence),
        Some(&facts(&original))
    );
    let mut stopped = observation.clone();
    stopped.sequence = original.sequence;
    stopped.command_digest = original.identity_digest().unwrap();
    stopped.current_ps = U64::new(110);
    stopped.retired_count = U64::new(2);
    stopped.aio = vec![crucible_protocol::node_control::NativeWriterAio {
        context_id: U64::new(1),
        home_thread_id: -1,
        active_polls: 0,
        active_dispatches: 0,
        pending_bhs: 0,
        active_bhs: 0,
        queued_coroutines: 0,
        flags: 0,
    }];
    stopped.bottom_halves = (1..=150)
        .map(|identity| crucible_protocol::node_control::NativeWriterBh {
            bh_id: U64::new(identity),
            context_id: U64::new(1),
            active_callbacks: 0,
            flags: 0,
        })
        .collect();
    let bytes = stopped.encode().unwrap();
    assert!(bytes.len() > crucible_protocol::node_control::NATIVE_WRITER_CHUNK_BYTES);
    let digest = *blake3::hash(&bytes).as_bytes();
    for (index, slice) in bytes
        .chunks(crucible_protocol::node_control::NATIVE_WRITER_CHUNK_BYTES)
        .enumerate()
    {
        assert!(
            transport
                .request_writer_observation(original.sequence)
                .unwrap()
        );
        assert!(matches!(
            provider.receive().unwrap(),
            Some(NativeFrame::QueryWriters(_))
        ));
        let chunk = crucible_protocol::node_control::NativeWriterChunk {
            prepared_scope_hash: stopped.prepared_scope_hash,
            sequence: original.sequence,
            object_digest: digest,
            total_bytes: U64::new(bytes.len() as u64),
            offset: U64::new(
                (index * crucible_protocol::node_control::NATIVE_WRITER_CHUNK_BYTES) as u64,
            ),
            bytes: slice.to_vec(),
        };
        provider
            .send(&NativeFrame::WriterChunk(chunk.clone()))
            .unwrap();
        transport.poll_original().unwrap();
        provider.send(&NativeFrame::WriterChunk(chunk)).unwrap();
        transport.poll_original().unwrap();
    }
    assert_eq!(
        transport.writer_observation(original.sequence),
        Some(&stopped)
    );
    transport
        .transmit_acknowledgement(original.sequence)
        .unwrap();
    let Some(NativeFrame::Acknowledge(ack)) = provider.receive().unwrap() else {
        panic!("original ACK");
    };
    provider.send(&NativeFrame::Acknowledged(ack)).unwrap();
    transport.poll_original().unwrap();
    assert_eq!(
        transport.writer_observation(original.sequence),
        Some(&stopped)
    );
    assert_eq!(
        transport.writer_observation(U64::new(0)),
        Some(&observation)
    );
}

#[test]
fn lost_native_ack_reply_retains_the_original_owner_until_identical_recovery() {
    let (mut transport, provider) = channels();
    let first = command(1, 0, 110);
    assert_eq!(
        transport.transmit_original(first.clone()).unwrap(),
        (CommandJournalDisposition::New, true)
    );
    assert_eq!(
        provider.receive().unwrap(),
        Some(NativeFrame::Command(Box::new(first.clone())))
    );

    provider.send(&NativeFrame::Stopped(facts(&first))).unwrap();
    assert_eq!(
        transport.poll_original().unwrap(),
        Some(NativeFrame::Stopped(facts(&first)))
    );
    assert!(transport.transmit_acknowledgement(first.sequence).unwrap());
    let Some(NativeFrame::Acknowledge(ack)) = provider.receive().unwrap() else {
        panic!("original ACK");
    };

    assert!(transport.transmit_original(command(2, 110, 200)).is_err());
    assert!(transport.transmit_acknowledgement(first.sequence).unwrap());
    assert_eq!(
        provider.receive().unwrap(),
        Some(NativeFrame::Acknowledge(ack.clone()))
    );
    provider
        .send(&NativeFrame::Acknowledged(ack.clone()))
        .unwrap();
    assert_eq!(
        transport.poll_original().unwrap(),
        Some(NativeFrame::Acknowledged(ack))
    );
    assert_eq!(
        transport.original_facts(first.sequence),
        Some(&facts(&first))
    );
    assert_eq!(
        transport.transmit_original(command(2, 110, 200)).unwrap(),
        (CommandJournalDisposition::New, true)
    );
}

#[test]
fn conflicting_or_overshooting_facts_never_replace_original_stopped_custody() {
    let (mut transport, provider) = channels();
    let original = command(1, 0, 110);
    transport.transmit_original(original.clone()).unwrap();
    provider.receive().unwrap();
    let mut overshoot = facts(&original);
    overshoot.reached = coordinate(111);
    provider.send(&NativeFrame::Stopped(overshoot)).unwrap();
    assert!(transport.poll_original().is_err());
    assert!(transport.original_facts(original.sequence).is_none());

    let actual = facts(&original);
    provider
        .send(&NativeFrame::Stopped(actual.clone()))
        .unwrap();
    transport.poll_original().unwrap();
    let mut changed = actual.clone();
    changed.pending_service_credit_ps = U64::new(11);
    provider.send(&NativeFrame::Stopped(changed)).unwrap();
    assert!(transport.poll_original().is_err());
    assert_eq!(transport.original_facts(original.sequence), Some(&actual));
    assert!(transport.transmit_original(command(2, 110, 200)).is_err());
}

#[test]
fn native_journal_ack_requires_the_original_digest_and_authorization() {
    let (mut transport, provider) = channels();
    let original = command(1, 0, 110);
    transport.transmit_original(original.clone()).unwrap();
    provider.receive().unwrap();
    provider
        .send(&NativeFrame::Stopped(facts(&original)))
        .unwrap();
    transport.poll_original().unwrap();
    provider
        .send(&NativeFrame::Acknowledged(ReceiptAcknowledgement {
            sequence: original.sequence,
            command_digest: original.identity_digest().unwrap(),
            authorization_digest: [9; 32],
        }))
        .unwrap();
    assert!(transport.poll_original().is_err());
    assert!(transport.transmit_original(command(2, 110, 200)).is_err());
}

#[test]
fn cpu_only_facts_preserve_pinned_initial_scope_and_reject_changed_history() {
    let (mut host, provider) = channels();
    assert!(host.request_cpu_park().unwrap());
    let Some(NativeFrame::QueryCpuPark(scope)) = provider.receive().unwrap() else {
        panic!("original pinned CPU-only request");
    };
    let facts = NativeCpuParkFacts {
        coverage: 1,
        cpu_count: 1,
        current_ps: U64::new(0),
        retired_count: U64::new(0),
        next_service_deadline_ps: None,
        pending_service_credit_ps: U64::new(0),
        prepared_scope_hash: scope,
        roster_sha256: [2; 32],
    };
    let foreign = NativeCpuParkFacts {
        prepared_scope_hash: [3; 32],
        ..facts.clone()
    };
    provider.send(&NativeFrame::CpuPark(foreign)).unwrap();
    assert!(host.poll_original().is_err());
    assert!(host.prepared_cpu_park().is_none());

    provider.send(&NativeFrame::CpuPark(facts.clone())).unwrap();
    host.poll_original().unwrap();
    let changed = NativeCpuParkFacts {
        retired_count: U64::new(1),
        ..facts.clone()
    };
    provider.send(&NativeFrame::CpuPark(changed)).unwrap();
    assert!(host.poll_original().is_err());
    assert_eq!(host.prepared_cpu_park(), Some(&facts));
}

#[test]
fn timer_assembly_retains_large_original_after_lost_reply_and_rejects_changed_digest() {
    use crucible_protocol::node_control::{
        NATIVE_TIMER_CHUNK_BYTES, NativeTimerArm, NativeTimerChunk, NativeTimerList,
        NativeTimerObservation,
    };
    let (mut host, provider) = channels();
    let original = command(1, 0, 110);
    host.transmit_original(original.clone()).unwrap();
    provider.receive().unwrap();
    provider
        .send(&NativeFrame::Stopped(facts(&original)))
        .unwrap();
    host.poll_original().unwrap();
    let observation = NativeTimerObservation {
        prepared_scope_hash: original.scope.identity_digest().unwrap(),
        sequence: U64::new(1),
        command_digest: original.identity_digest().unwrap(),
        current_ps: U64::new(110),
        mutation_generation: U64::new(100),
        lists: vec![NativeTimerList {
            identity: U64::new(1),
            timer_count: 100,
            flags: 3,
        }],
        timers: (0..100)
            .map(|index| NativeTimerArm {
                identity: U64::new(index + 1),
                list: U64::new(1),
                arm_generation: U64::new(index + 1),
                expiry_ps: U64::new(200),
                fifo_ordinal: U64::new(index),
                attributes: 0,
                scale: 1,
            })
            .collect(),
    };
    let bytes = observation.encode().unwrap();
    assert!(bytes.len() > NATIVE_TIMER_CHUNK_BYTES);
    let digest = *blake3::hash(&bytes).as_bytes();
    for (index, slice) in bytes.chunks(NATIVE_TIMER_CHUNK_BYTES).enumerate() {
        assert!(host.request_timer_observation(U64::new(1)).unwrap());
        assert!(matches!(
            provider.receive().unwrap(),
            Some(NativeFrame::QueryTimers(_))
        ));
        let chunk = NativeTimerChunk {
            prepared_scope_hash: observation.prepared_scope_hash,
            sequence: U64::new(1),
            object_digest: digest,
            total_bytes: U64::new(bytes.len() as u64),
            offset: U64::new((index * NATIVE_TIMER_CHUNK_BYTES) as u64),
            bytes: slice.to_vec(),
        };
        provider
            .send(&NativeFrame::TimerChunk(chunk.clone()))
            .unwrap();
        host.poll_original().unwrap();
        // A lost old response can arrive again without advancing assembly twice.
        provider
            .send(&NativeFrame::TimerChunk(chunk.clone()))
            .unwrap();
        host.poll_original().unwrap();
        let mut changed = chunk;
        changed.object_digest[0] ^= 1;
        provider.send(&NativeFrame::TimerChunk(changed)).unwrap();
        assert!(host.poll_original().is_err());
    }
    assert_eq!(host.timer_observation(U64::new(1)), Some(&observation));
    host.transmit_acknowledgement(U64::new(1)).unwrap();
    let Some(NativeFrame::Acknowledge(ack)) = provider.receive().unwrap() else {
        panic!("original ack");
    };
    provider.send(&NativeFrame::Acknowledged(ack)).unwrap();
    host.poll_original().unwrap();
    assert_eq!(host.timer_observation(U64::new(1)), Some(&observation));
}
