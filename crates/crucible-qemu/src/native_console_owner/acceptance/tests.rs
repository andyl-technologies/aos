//! Real mapped host publisher/clamp controls with modeled native frontier owners.
//!
//! The slot, setup, request claim, ring, runtime cache and receipt inventory are
//! genuine host implementations. UART execution, CLOSED-RR custody and the
//! pre-ACK native frontier writer are explicit external test providers.

use std::io::Read;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use crucible_protocol::native_console::{
    NativeConsoleFrontier, NativeConsoleOrigin, NativeConsoleRecord,
};
use crucible_shmem::mmap_setup_region;

use super::*;
use crate::native_console_owner::tests::{FixtureError, LaunchFixture};
use crate::{QemuHostIoRuntime, QemuShmemHotPathChannel};

mod terminal_fingerprint;

fn custody(fixture: &LaunchFixture) -> Result<&ConsoleLaunchCustody, FixtureError> {
    fixture
        .setup
        .console_custody
        .as_ref()
        .ok_or(ConsoleOwnerError::Storage.into())
}

fn mapped(fixture: &LaunchFixture) -> Result<MappedSetupRegion, FixtureError> {
    Ok(mmap_setup_region(
        fixture.setup.shmem_as_fd(),
        fixture.setup.region().region_len,
    )?)
}

fn start(channel: &mut crate::QemuMappedQuantumShmemHotPath, ps: u64) -> Result<(), FixtureError> {
    QemuShmemHotPathChannel::start_quantum(
        channel,
        crucible::ExecutionHorizon {
            icount: crucible::Icount { retired: ps },
        },
        AdvanceStopCondition::Ceiling,
    )?;
    Ok(())
}

fn stage(
    region: &MappedSetupRegion,
    authorization: NativeConsoleAuthorization,
    emitted_ps: u64,
    bytes: &[u8],
) -> Result<(), FixtureError> {
    stage_with_raw_prefix(region, authorization, emitted_ps, bytes, 0)
}

fn stage_with_raw_prefix(
    region: &MappedSetupRegion,
    authorization: NativeConsoleAuthorization,
    emitted_ps: u64,
    bytes: &[u8],
    raw_prefix: u64,
) -> Result<(), FixtureError> {
    let segment = region
        .native_console_segment(0)
        .map_err(ConsoleOwnerError::from)?;
    let records: Vec<_> = bytes
        .iter()
        .enumerate()
        .map(|(index, byte)| NativeConsoleRecord {
            owner: authorization.owner,
            origin: NativeConsoleOrigin {
                stream: 1,
                logical_generation: authorization.logical_generation,
                node_sequence: authorization.prior_sequence + index as u64 + 1,
                stream_sequence: authorization.prior_sequence + index as u64 + 1,
                logical_ps: emitted_ps + index as u64,
                raw_prefix,
                vcpu: 0,
                byte: *byte,
            },
            authorization_advance: authorization.advance,
            phase: authorization.phase,
        })
        .collect();
    segment
        .ring
        .stage_native_console(segment.records, &records)?;
    Ok(())
}

fn publish_native_frontier(
    fixture: &LaunchFixture,
    region: &MappedSetupRegion,
    authorization: NativeConsoleAuthorization,
    ps: u64,
) -> Result<NativeConsoleFrontier, FixtureError> {
    let segment = region
        .native_console_segment(0)
        .map_err(ConsoleOwnerError::from)?;
    let paired = segment.clamp.snapshot()?;
    let plan_hash = custody(fixture)?.lock()?.accepted.plan.digest()?;
    let ring_end = segment.ring.write_index();
    let frontier = NativeConsoleFrontier {
        sequence: authorization.prior_sequence + ring_end - authorization.prior_ring_end,
        ring_end,
        logical_ps: ps,
        raw_prefix: 1,
        owner: authorization.owner,
        accepted_advance: paired.advance,
        logical_generation: authorization.logical_generation,
        request: paired.request,
        plan_hash,
    };
    // Modeled single native producer: frontier precedes its original control
    // publication and odd ACK. This does not prove the real GPL lexical join.
    segment.frontier.store(frontier)?;
    let slot = region
        .node_slot(0)
        .map_err(|_| ConsoleOwnerError::Storage)?;
    slot.publish_control_boundary(ps, 1)?;
    slot.acknowledge_control_boundary();
    Ok(frontier)
}

fn settle_real_runtime(
    fixture: &LaunchFixture,
    region: &MappedSetupRegion,
    authorization: NativeConsoleAuthorization,
    ps: u64,
) -> Result<crate::QemuCompletedQuantumBoundary, FixtureError> {
    let slot = region
        .node_slot(0)
        .map_err(|_| ConsoleOwnerError::Storage)?;
    slot.publish_reached_icount(ps)?;
    let (mut notifications, wake) = UnixStream::pair()?;
    notifications.set_read_timeout(Some(Duration::from_secs(1)))?;
    let mut runtime = crate::QemuLiveHostIoRuntime::from_shmem_fd(
        fixture.setup.shmem_as_fd(),
        wake.as_fd(),
        fixture.setup.region().region_len,
        0,
    )?;
    runtime.retain_console_launch(&fixture.setup)?;
    let host = std::thread::spawn(move || {
        let result = runtime.fence_priming_handoff(Duration::from_secs(1));
        (runtime, result)
    });
    let publication = (|| -> Result<(), FixtureError> {
        let mut counter = [0; 8];
        notifications.read_exact(&mut counter)?;
        assert_eq!(u64::from_ne_bytes(counter), 1);
        publish_native_frontier(fixture, region, authorization, ps)?;
        Ok(())
    })();
    // Reap the original host waiter even if the modeled provider refuses.
    let (runtime, result) = host.join().map_err(|_| FixtureError::PeerPanicked)?;
    publication?;
    result?;
    runtime
        .completed_quantum_boundary()
        .ok_or(ConsoleOwnerError::Storage.into())
}

fn modeled_completed_cache(
    fixture: &LaunchFixture,
    region: &MappedSetupRegion,
    authorization: NativeConsoleAuthorization,
    ps: u64,
) -> Result<crate::QemuCompletedQuantumBoundary, FixtureError> {
    let slot = region
        .node_slot(0)
        .map_err(|_| ConsoleOwnerError::Storage)?;
    slot.publish_reached_icount(ps)?;
    let discovery = slot.snapshot();
    custody(fixture)?.publish_clamp(
        slot,
        crucible_shmem::authorize_advance_ceiling(ps, ps, None)?,
    )?;
    let request = custody(fixture)?.request_boundary(region, 0, None)?;
    publish_native_frontier(fixture, region, authorization, ps)?;
    crate::QemuCompletedQuantumBoundary::accepted(
        region.backing_identity(),
        0,
        discovery,
        request,
        0,
        slot.snapshot(),
    )
    .ok_or(ConsoleOwnerError::Storage.into())
}

#[test]
fn real_priming_clamp_retires_empty_cold_prefix_and_reuses_outstanding_capacity()
-> Result<(), FixtureError> {
    let fixture = LaunchFixture::cold(1)?;
    let region = mapped(&fixture)?;
    let mut channel = fixture.hot_path()?;
    let custody = custody(&fixture)?;
    let mut first = None;
    for ps in [100, 200, 300] {
        start(&mut channel, ps)?;
        let authorization = custody.authorization_snapshot()?;
        assert_eq!(authorization.logical_generation, 0);
        if let Some(previous) = first {
            assert_eq!(authorization.phase, NativeConsolePhase::Grant);
            assert!(custody.lock()?.original_authorization(previous).is_none());
        } else {
            assert_eq!(authorization.phase, NativeConsolePhase::ColdSetup);
            first = Some(authorization.owner.authorization);
        }
        let boundary = settle_real_runtime(&fixture, &region, authorization, ps)?;
        let owner = custody.lock()?;
        assert!(owner.issued.is_empty());
        assert!(owner.clamp.is_none());
        assert!(owner.accepted.pending.is_empty());
        assert_eq!(owner.accepted.node_sequence, 0);
        assert_eq!(
            owner.accepted.accepted_request,
            Some(
                region
                    .native_console_segment(0)
                    .map_err(ConsoleOwnerError::from)?
                    .frontier
                    .copy()?
                    .request
            )
        );
        assert_eq!(boundary.calibration().logical_icount, ps);
    }
    fixture.finish()
}

#[test]
fn accepted_bytes_keep_original_dispatch_origin_across_pre_entry_regrant()
-> Result<(), FixtureError> {
    let fixture = LaunchFixture::cold(2)?;
    let region = mapped(&fixture)?;
    let mut channel = fixture.hot_path()?;
    start(&mut channel, 100)?;
    let custody = custody(&fixture)?;
    let original = custody.authorization_snapshot()?;
    QemuShmemHotPathChannel::deliver_frame_at(
        &mut channel,
        crucible::BackendInput {
            node: crucible::NodeId { name: "vm".into() },
            payload: vec![7],
        },
        crucible::Icount { retired: 50 },
    )?;
    let last = custody.authorization_snapshot()?;
    assert_ne!(original.owner.authorization, last.owner.authorization);
    // The modeled runtime retained the original immutable dispatch body before
    // the latest table changed. Historical operation ownership is not inferred.
    stage(&region, original, 50, &[0, 255])?;
    settle_real_runtime(&fixture, &region, original, 100)?;
    let owner = custody.lock()?;
    assert!(owner.issued.is_empty());
    assert_eq!(
        owner
            .accepted
            .pending
            .iter()
            .map(|origin| origin.origin.byte)
            .collect::<Vec<_>>(),
        vec![0, 255]
    );
    assert_eq!(owner.accepted.pending[0].origin.logical_generation, 0);
    assert_eq!(owner.accepted.pending[0].origin.emitted_ps, 50);
    assert_eq!(owner.accepted.pending[1].origin.emitted_ps, 51);
    assert_eq!(owner.accepted.pending[0].origin.raw_prefix, 0);
    assert_eq!(owner.accepted.pending[1].origin.node_sequence, 2);
    assert_eq!(owner.accepted.ring_end, 2);
    assert_eq!(owner.accepted_emission_for_test(1), Some(original));
    assert_eq!(owner.accepted_emission_for_test(2), Some(original));
    assert_eq!(owner.accepted_emission_for_test(3), None);
    assert_ne!(owner.accepted_emission_for_test(2), Some(last));
    assert_eq!(
        region
            .native_console_segment(0)
            .map_err(ConsoleOwnerError::from)?
            .ring
            .read_index(),
        2
    );
    drop(owner);
    fixture.finish()
}

#[test]
fn consumer_refusal_keeps_owned_prefix_receipts_and_read_cursor() -> Result<(), FixtureError> {
    let fixture = LaunchFixture::cold(1)?;
    let region = mapped(&fixture)?;
    let mut channel = fixture.hot_path()?;
    start(&mut channel, 100)?;
    let custody = custody(&fixture)?;
    let authorization = custody.authorization_snapshot()?;
    stage(&region, authorization, 50, b"a")?;
    let boundary = modeled_completed_cache(&fixture, &region, authorization, 100)?;
    let mut owner = custody.lock()?;
    let result = owner.accept_completed_with_consumer(&region, boundary, |ring, prefix| {
        assert!(ring.hold_hot_fork_consumers().quiescent());
        let refused = ring.acknowledge_native_console_prefix(prefix);
        let released = ring.release_hot_fork_consumers();
        assert!(!released.held());
        assert_eq!(released.in_flight(), 0);
        refused
    });
    assert!(matches!(result, Err(ConsoleOwnerError::Prefix(_))));
    assert_eq!(owner.accepted_emission_for_test(1), None);
    assert_eq!(owner.issued.len(), 1);
    assert!(owner.clamp.is_some());
    assert!(owner.accepted.pending.is_empty());
    let prepared = owner
        .accepted
        .prepared
        .as_ref()
        .ok_or(ConsoleOwnerError::Storage)?;
    assert_eq!(prepared.origins[0].origin.byte, b'a');
    assert_eq!(prepared.origins[0].origin.emitted_ps, 50);
    assert_eq!(
        region
            .native_console_segment(0)
            .map_err(ConsoleOwnerError::from)?
            .ring
            .read_index(),
        0
    );
    assert!(owner.accept_completed(&region, boundary).is_err());
    drop(owner);
    fixture.finish()
}

#[test]
fn later_real_regrant_refuses_stale_clamp_without_retiring_either_receipt()
-> Result<(), FixtureError> {
    let fixture = LaunchFixture::cold(2)?;
    let region = mapped(&fixture)?;
    let mut channel = fixture.hot_path()?;
    start(&mut channel, 100)?;
    let custody = custody(&fixture)?;
    let original = custody.authorization_snapshot()?;
    let boundary = modeled_completed_cache(&fixture, &region, original, 100)?;
    QemuShmemHotPathChannel::deliver_frame_at(
        &mut channel,
        crucible::BackendInput {
            node: crucible::NodeId { name: "vm".into() },
            payload: vec![7],
        },
        crucible::Icount { retired: 100 },
    )?;
    let later = custody.authorization_snapshot()?;
    let mut owner = custody.lock()?;
    assert!(owner.accept_completed(&region, boundary).is_err());
    assert_eq!(owner.issued.len(), 2);
    assert_eq!(
        owner.original_authorization(original.owner.authorization),
        Some(original)
    );
    assert_eq!(
        owner.original_authorization(later.owner.authorization),
        Some(later)
    );
    assert!(owner.clamp.is_some());
    assert_eq!(
        region
            .native_console_segment(0)
            .map_err(ConsoleOwnerError::from)?
            .ring
            .read_index(),
        0
    );
    drop(owner);
    fixture.finish()
}

#[test]
fn covered_old_authorization_cannot_return_as_a_later_empty_frontier() -> Result<(), FixtureError> {
    let fixture = LaunchFixture::cold(1)?;
    let region = mapped(&fixture)?;
    let mut channel = fixture.hot_path()?;
    let custody = custody(&fixture)?;
    start(&mut channel, 100)?;
    let old = custody.authorization_snapshot()?;
    settle_real_runtime(&fixture, &region, old, 100)?;
    start(&mut channel, 200)?;
    let current = custody.authorization_snapshot()?;
    assert_ne!(old.owner.authorization, current.owner.authorization);
    // A deliberately stale external native frontier cannot replace the
    // current paired full-body owner, even with a fresh exact control ACK.
    let boundary = modeled_completed_cache(&fixture, &region, old, 200)?;
    let mut owner = custody.lock()?;
    assert!(owner.accept_completed(&region, boundary).is_err());
    assert_eq!(owner.issued.len(), 1);
    assert_eq!(
        owner.original_authorization(current.owner.authorization),
        Some(current)
    );
    assert!(
        owner
            .original_authorization(old.owner.authorization)
            .is_none()
    );
    assert!(owner.accepted.pending.is_empty());
    assert!(owner.clamp.is_some());
    drop(owner);
    fixture.finish()
}

#[test]
fn successive_priming_clamps_retain_undelivered_boot_origins_without_restamping()
-> Result<(), FixtureError> {
    let fixture = LaunchFixture::cold(1)?;
    let region = mapped(&fixture)?;
    let mut channel = fixture.hot_path()?;
    let custody = custody(&fixture)?;
    for (ceiling, emitted, byte) in [(100, 60, b'a'), (200, 160, b'b')] {
        start(&mut channel, ceiling)?;
        let authorization = custody.authorization_snapshot()?;
        stage(&region, authorization, emitted, &[byte])?;
        settle_real_runtime(&fixture, &region, authorization, ceiling)?;
    }
    let owner = custody.lock()?;
    assert!(owner.issued.is_empty());
    assert_eq!(owner.accepted.pending.len(), 2);
    assert_eq!(owner.accepted.pending[0].origin.emitted_ps, 60);
    assert_eq!(owner.accepted.pending[1].origin.emitted_ps, 160);
    assert_eq!(owner.accepted.pending[0].origin.byte, b'a');
    assert_eq!(owner.accepted.pending[1].origin.byte, b'b');
    assert_eq!(owner.accepted.pending[1].origin.node_sequence, 2);
    assert_eq!(owner.accepted.pending[1].origin.stream_sequence, 2);
    assert_eq!(
        region
            .native_console_segment(0)
            .map_err(ConsoleOwnerError::from)?
            .ring
            .read_index(),
        2
    );
    // These origins have NOT been projected through a guessed later RUN map.
    // Genuine boot assertion visibility and checkpoint custody remain open.
    drop(owner);
    fixture.finish()
}

#[test]
fn retained_origin_bytes_preserve_the_existing_sixteen_mib_policy() {
    use crate::native_console_owner::MAX_CONSOLE_OBSERVATION_BYTES;

    assert!(validate_console_retention(4096, 1).is_ok());
    assert!(validate_console_retention(MAX_CONSOLE_OBSERVATION_BYTES - 1, 1).is_ok());
    assert!(validate_console_retention(MAX_CONSOLE_OBSERVATION_BYTES, 0).is_ok());
    assert_eq!(
        validate_console_retention(MAX_CONSOLE_OBSERVATION_BYTES, 1),
        Err(NativeConsoleError::Length)
    );
    assert_eq!(
        validate_console_retention(usize::MAX, 1),
        Err(NativeConsoleError::Length)
    );
}

/// Models only persisted semantic mapping bytes; native completion stays the
/// existing explicitly external provider, while projection uses the real codec.
fn checkpoint_projection(
    anchor_time: u64,
) -> Result<super::super::observation::ConsoleProjection, FixtureError> {
    let mut bytes = b"NCMAP001".to_vec();
    bytes.extend_from_slice(&2_u32.to_le_bytes());
    bytes.extend_from_slice(b"vm");
    for value in [0, 100, anchor_time, 100, 0] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    let map = crucible::NativeConsoleMappingLease::from_canonical_bytes(&bytes)
        .map_err(ConsoleOwnerError::from)?;
    Ok(super::super::observation::ConsoleProjection::Run(
        std::sync::Arc::new(map),
    ))
}

#[test]
fn canonical_drain_keeps_boot_origin_and_original_run_map_after_rebase() -> Result<(), FixtureError>
{
    let fixture = LaunchFixture::cold(1)?;
    let region = mapped(&fixture)?;
    let mut channel = fixture.hot_path()?;
    let custody = custody(&fixture)?;
    start(&mut channel, 100)?;
    let body = custody.authorization_snapshot()?;
    stage(&region, body, 60, b"b")?;
    settle_real_runtime(&fixture, &region, body, 100)?;

    custody.lock()?.projection = checkpoint_projection(0)?;
    start(&mut channel, 200)?;
    let body = custody.authorization_snapshot()?;
    stage(&region, body, 160, b"r")?;
    settle_real_runtime(&fixture, &region, body, 200)?;
    custody.lock()?.projection = checkpoint_projection(500)?;

    let observations = custody.drain_observations(
        &crucible::NodeId { name: "vm".into() },
        crucible::NodeCounter { ticks: 100 },
    )?;
    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].at().ticks, 0);
    assert_eq!(observations[1].at().ticks, 60);
    for (event, (ps, byte, sequence)) in observations.iter().zip([(60, b'b', 1), (160, b'r', 2)]) {
        let crucible::ObservableEventPayload::NativeConsoleByte { origin, .. } = event.payload()
        else {
            panic!("canonical drain must retain complete byte origin");
        };
        assert_eq!(
            (origin.emitted_ps, origin.byte, origin.node_sequence),
            (ps, byte, sequence)
        );
        assert_eq!(origin.raw_prefix, 0);
    }
    assert!(fixture.pending_origins()?.is_empty());
    fixture.finish()
}

#[test]
fn projection_refusal_keeps_whole_consumed_origin_queue() -> Result<(), FixtureError> {
    let fixture = LaunchFixture::cold(1)?;
    let region = mapped(&fixture)?;
    let mut channel = fixture.hot_path()?;
    let custody = custody(&fixture)?;
    start(&mut channel, 100)?;
    let body = custody.authorization_snapshot()?;
    stage(&region, body, 60, b"ab")?;
    settle_real_runtime(&fixture, &region, body, 100)?;
    custody.lock()?.projection = checkpoint_projection(0)?;
    assert!(
        custody
            .drain_observations(
                &crucible::NodeId { name: "vm".into() },
                crucible::NodeCounter { ticks: 101 }
            )
            .is_err()
    );
    assert_eq!(fixture.pending_origins()?.len(), 2);
    assert!(
        custody
            .drain_observations(
                &crucible::NodeId {
                    name: "foreign".into()
                },
                crucible::NodeCounter { ticks: 100 }
            )
            .is_err()
    );
    assert_eq!(fixture.pending_origins()?.len(), 2);
    assert_eq!(
        region
            .native_console_segment(0)
            .map_err(ConsoleOwnerError::from)?
            .ring
            .read_index(),
        2
    );
    fixture.finish()
}

#[test]
fn consumed_checkpoint_preserves_origins_without_restoring_execution_credit()
-> Result<(), FixtureError> {
    let fixture = LaunchFixture::cold(1)?;
    let region = mapped(&fixture)?;
    let mut channel = fixture.hot_path()?;
    let custody = custody(&fixture)?;
    let node = crucible::NodeId { name: "vm".into() };
    let ready = crucible::NodeCounter { ticks: 100 };
    start(&mut channel, 100)?;
    assert!(custody.checkpoint_origins(&node, ready).is_err());
    let body = custody.authorization_snapshot()?;
    stage(&region, body, 60, b"ab")?;
    settle_real_runtime(&fixture, &region, body, 100)?;
    custody.lock()?.projection = checkpoint_projection(0)?;
    let saved = custody.checkpoint_origins(&node, ready)?;
    let bytes = saved.encode()?;
    let decoded = crate::native_console_owner::ConsoleOriginContinuation::decode(&bytes)?;
    assert_eq!(decoded, saved);
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(crate::native_console_owner::ConsoleOriginContinuation::decode(&trailing).is_err());
    let mut malformed = bytes;
    malformed[0] ^= 1;
    assert!(crate::native_console_owner::ConsoleOriginContinuation::decode(&malformed).is_err());
    assert!(
        custody
            .restore_origins(
                &crucible::NodeId {
                    name: "foreign".into()
                },
                &decoded
            )
            .is_err()
    );
    assert_eq!(custody.accepted_emission_for_test(2)?, Some(body));
    assert_eq!(custody.restore_origins(&node, &decoded)?, ready);
    assert_eq!(custody.accepted_emission_for_test(2)?, None);
    // A saved physical request is deliberately unavailable as new permission.
    assert!(start(&mut channel, 200).is_err());
    assert_eq!(fixture.pending_origins()?.len(), 2);
    let events = custody.drain_observations(&node, ready)?;
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].at().ticks, 0);
    assert_eq!(events[1].at().ticks, 0);
    fixture.finish()
}

/// Supplies explicitly modeled native occurrence custody inside the real writer.
fn modeled_operation_stop(
    region: &MappedSetupRegion,
    body: NativeConsoleAuthorization,
    ps: u64,
    publication: u64,
) -> Result<crucible_protocol::native_console::NativeConsoleOperationStop, FixtureError> {
    let segment = region
        .native_console_segment(0)
        .map_err(ConsoleOwnerError::from)?;
    let slot = region
        .node_slot(0)
        .map_err(|_| ConsoleOwnerError::Storage)?;
    let before = slot.try_snapshot().ok_or(ConsoleOwnerError::Unavailable)?;
    let mut stop = None;
    slot.publish_pause_quiesced_with_effect(ps, 1, |writer| {
        let row = crucible_protocol::native_console::NativeConsoleOperationStop {
            publication,
            ring_end: segment.ring.write_index(),
            node_sequence: body.prior_sequence + segment.ring.write_index() - body.prior_ring_end,
            logical_ps: writer.logical(),
            raw_prefix: writer.raw(),
            owner: body.owner,
            authorization_advance: body.advance,
            logical_generation: body.logical_generation,
            vcpu: 0,
            closed_generation: writer.closed_generation(),
            control_boundary_ack: before.control_boundary_ack,
            stopped_advance: before.advance_publication_sequence,
        };
        segment.operation_stop.store(row)?;
        stop = Some(row);
        Ok::<_, NativeConsoleError>(())
    })
    .map_err(|source| FixtureError::Peer(source.to_string()))?;
    stop.ok_or(ConsoleOwnerError::Storage.into())
}

#[test]
fn accounted_console_stop_discovery_keeps_emission_and_stopped_coordinates_distinct()
-> Result<(), FixtureError> {
    let fixture = LaunchFixture::cold(2)?;
    let region = mapped(&fixture)?;
    let mut channel = fixture.hot_path()?;
    start(&mut channel, 200)?;
    let custody = custody(&fixture)?;
    let body = custody.authorization_snapshot()?;
    let slot = region
        .node_slot(0)
        .map_err(|_| ConsoleOwnerError::Storage)?;
    slot.publish_pause_quiesced(100, 1)?;
    assert!(
        custody
            .observe_operation_stop(&region, slot.snapshot())?
            .is_none()
    );

    stage(&region, body, 80, b"AB")?;
    let row = modeled_operation_stop(&region, body, 100, 2)?;
    let receipt = custody
        .observe_operation_stop(&region, slot.snapshot())?
        .ok_or(ConsoleOwnerError::Storage)?;
    assert!(receipt.matches_coordinate(100, 1));
    assert_eq!(row.node_sequence, 2);
    let segment = region
        .native_console_segment(0)
        .map_err(ConsoleOwnerError::from)?;
    let tail = segment
        .ring
        .peek_native_console_operation_tail(segment.records, 2)?
        .ok_or(ConsoleOwnerError::Storage)?;
    assert_eq!(tail.origin.logical_ps, 81);
    assert_eq!(tail.origin.raw_prefix, 0);
    assert_eq!(segment.ring.read_index(), 0);
    assert_eq!(custody.lock()?.issued.len(), 1);
    fixture.finish()
}

#[test]
fn accounted_console_discovery_requires_republished_current_framing_and_original_owner()
-> Result<(), FixtureError> {
    let fixture = LaunchFixture::cold(2)?;
    let region = mapped(&fixture)?;
    let mut channel = fixture.hot_path()?;
    start(&mut channel, 200)?;
    let custody = custody(&fixture)?;
    let body = custody.authorization_snapshot()?;
    stage(&region, body, 80, b"A")?;
    modeled_operation_stop(&region, body, 100, 2)?;
    let slot = region
        .node_slot(0)
        .map_err(|_| ConsoleOwnerError::Storage)?;
    assert!(
        custody
            .observe_operation_stop(&region, slot.snapshot())?
            .is_some()
    );

    slot.publish_pause_quiesced(100, 1)?;
    assert!(
        custody
            .observe_operation_stop(&region, slot.snapshot())?
            .is_none()
    );
    let row = modeled_operation_stop(&region, body, 100, 4)?;
    assert!(
        custody
            .observe_operation_stop(&region, slot.snapshot())?
            .is_some()
    );
    let mut foreign = row;
    foreign.publication = 6;
    foreign.owner.process += 1;
    region
        .native_console_segment(0)
        .map_err(ConsoleOwnerError::from)?
        .operation_stop
        .store(foreign)?;
    assert!(
        custody
            .observe_operation_stop(&region, slot.snapshot())
            .is_err()
    );
    assert_eq!(custody.lock()?.issued.len(), 1);
    assert_eq!(
        region
            .native_console_segment(0)
            .map_err(ConsoleOwnerError::from)?
            .ring
            .read_index(),
        0
    );
    fixture.finish()
}

#[test]
fn console_stop_frontier_mismatch_refuses_before_origin_custody_and_ring_consume()
-> Result<(), FixtureError> {
    let fixture = LaunchFixture::cold(2)?;
    let region = mapped(&fixture)?;
    let mut channel = fixture.hot_path()?;
    start(&mut channel, 200)?;
    let custody = custody(&fixture)?;
    let body = custody.authorization_snapshot()?;
    stage(&region, body, 80, b"A")?;
    modeled_operation_stop(&region, body, 100, 2)?;
    let slot = region
        .node_slot(0)
        .map_err(|_| ConsoleOwnerError::Storage)?;
    let receipt = custody
        .observe_operation_stop(&region, slot.snapshot())?
        .ok_or(ConsoleOwnerError::Storage)?;
    let boundary = modeled_completed_cache(&fixture, &region, body, 110)?;
    assert!(
        custody
            .accept_completed_with_stop(&region, boundary, Some(receipt))
            .is_err()
    );
    let owner = custody.lock()?;
    assert!(owner.accepted.prepared.is_none());
    assert!(owner.accepted.pending.is_empty());
    assert_eq!(owner.issued.len(), 1);
    assert!(owner.clamp.is_some());
    assert_eq!(
        region
            .native_console_segment(0)
            .map_err(ConsoleOwnerError::from)?
            .ring
            .read_index(),
        0
    );
    drop(owner);
    fixture.finish()
}

#[test]
fn real_runtime_queued_console_prefix_waits_for_discovery_before_any_clamp()
-> Result<(), FixtureError> {
    let fixture = LaunchFixture::cold(2)?;
    let region = mapped(&fixture)?;
    let slot = region.node_slot(0)?;
    slot.publish_reached_icount(0)?;
    let mut channel = fixture.hot_path()?;
    let pending = QemuShmemHotPathChannel::start_quantum(
        &mut channel,
        crucible::ExecutionHorizon {
            icount: crucible::Icount { retired: 200 },
        },
        AdvanceStopCondition::Ceiling,
    )?;
    let custody = custody(&fixture)?;
    let body = custody.authorization_snapshot()?;
    stage(&region, body, 80, b"AB")?;
    // Model the genuine producer's unavailable suffix: original pause fields
    // close coherently, but no accounted stopped-operation row is committed.
    slot.publish_pause_quiesced(100, 1)?;
    let original = slot.snapshot();
    let segment = region.native_console_segment(0)?;
    // This fixture issues through its explicitly external authorization table;
    // the mapped table stays absent rather than supplying invented ownership.
    let mapped_authorization = segment.authorization.snapshot();
    assert_eq!(mapped_authorization, Err(NativeConsoleError::Sequence));
    let (mut notifications, wake) = UnixStream::pair()?;
    notifications.set_read_timeout(Some(Duration::from_secs(1)))?;
    let mut runtime = crate::QemuLiveHostIoRuntime::from_shmem_fd(
        fixture.setup.shmem_as_fd(),
        wake.as_fd(),
        fixture.setup.region().region_len,
        0,
    )?;
    runtime.retain_console_launch(&fixture.setup)?;
    runtime.prepare_advance_completion(Duration::from_secs(1))?;
    runtime.retain_advance_initial_state(pending.initial_state());
    runtime.arm_advance_completion_fence(pending.completion_fence())?;
    runtime.set_advance_completion_poll_slice(Some(Duration::from_millis(2)))?;

    assert_eq!(
        runtime.await_child(
            crate::QemuAsyncWait::AdvanceCompletion,
            Duration::from_secs(1)
        )?,
        crate::QemuAsyncWaitOutcome::Pending,
    );
    let mut initial_wake = [0; 8];
    notifications.read_exact(&mut initial_wake)?;
    assert_eq!(slot.snapshot(), original);
    assert_eq!(segment.authorization.snapshot(), mapped_authorization);
    assert_eq!(custody.authorization_snapshot()?, body);
    assert_eq!(segment.ring.read_index(), 0);
    assert_eq!(segment.ring.write_index(), 2);
    assert!(runtime.completed_quantum_boundary().is_none());
    assert!(custody.lock()?.clamp.is_none());
    assert_eq!(custody.lock()?.issued.len(), 1);
    assert!(custody.lock()?.accepted.pending_origins().is_empty());

    // Another original writer can replace framing without supplying discovery.
    // The same pending wait must still preserve custody rather than consume it.
    slot.publish_pause_quiesced(100, 1)?;
    assert_eq!(
        runtime.repoll_child(
            crate::QemuAsyncWait::AdvanceCompletion,
            Duration::from_secs(1)
        )?,
        crate::QemuAsyncWaitOutcome::Pending,
    );
    assert_eq!(slot.control_boundary_token(), original.control_boundary_ack);
    assert_eq!(slot.snapshot().max_advance_icount, 200);
    assert_eq!(segment.ring.read_index(), 0);
    assert!(custody.lock()?.clamp.is_none());
    assert_eq!(custody.lock()?.issued.len(), 1);

    modeled_operation_stop(&region, body, 100, 2)?;
    assert!(
        custody
            .observe_operation_stop(&region, slot.snapshot())?
            .is_some()
    );
    assert_eq!(segment.ring.read_index(), 0);
    fixture.finish()
}

/// Retains the real mapped accepted stop for the production node resume controls.
pub(crate) fn accepted_console_stop_fixture() -> Result<AcceptedConsoleStopFixture, FixtureError> {
    let fixture = LaunchFixture::cold(2)?;
    let region = mapped(&fixture)?;
    let mut channel = fixture.hot_path()?;
    let custody = custody(&fixture)?;
    // Preserve the real launch order: ColdSetup first retires an empty prefix,
    // then the next RUN owns a fresh Grant and the preceding stopped report.
    start(&mut channel, 50)?;
    let cold = custody.authorization_snapshot()?;
    settle_real_runtime(&fixture, &region, cold, 50)?;
    let accepted = custody.lock()?.accepted.accepted_request;
    assert!(accepted.is_some());
    let (mut notifications, wake) = UnixStream::pair()?;
    notifications.set_read_timeout(Some(Duration::from_secs(1)))?;
    let mut runtime = crate::QemuLiveHostIoRuntime::from_shmem_fd(
        fixture.setup.shmem_as_fd(),
        wake.as_fd(),
        fixture.setup.region().region_len,
        0,
    )?;
    runtime.retain_console_launch(&fixture.setup)?;
    runtime.prepare_advance_completion(Duration::from_secs(1))?;
    let initial_report_generation = region.node_slot(0)?.snapshot().publish_gen;
    let mut pending = QemuShmemHotPathChannel::start_quantum(
        &mut channel,
        crucible::ExecutionHorizon {
            icount: crucible::Icount { retired: 200 },
        },
        AdvanceStopCondition::Ceiling,
    )?;
    let body = custody.authorization_snapshot()?;
    assert_eq!(body.phase, NativeConsolePhase::Grant);
    // The authentic priming receipt already accounted one raw instruction.
    stage_with_raw_prefix(&region, body, 80, b"AB", 1)?;
    let plan_hash = custody.lock()?.accepted.plan.digest()?;
    let native = mapped(&fixture)?;
    runtime.retain_advance_initial_state(pending.initial_state());
    runtime.arm_advance_completion_fence(pending.completion_fence())?;
    let provider = std::thread::spawn(move || -> Result<UnixStream, FixtureError> {
        let mut wake = [0; 8];
        notifications.read_exact(&mut wake)?;
        let slot = native
            .node_slot(0)
            .map_err(|_| ConsoleOwnerError::Storage)?;
        // The first doorbell cannot request an Observation or retire the
        // fresh Grant through the old expired-IDLE report.
        assert_eq!(
            slot.control_boundary_token(),
            accepted
                .map(|token| token + 1)
                .ok_or(ConsoleOwnerError::Storage)?
        );
        assert_eq!(slot.snapshot().publish_gen, initial_report_generation);
        assert_eq!(slot.snapshot().current_icount, 50);
        assert_eq!(slot.snapshot().max_advance_icount, 200);
        modeled_operation_stop(&native, body, 100, 2)?;
        notifications.read_exact(&mut wake)?;
        let segment = native
            .native_console_segment(0)
            .map_err(ConsoleOwnerError::from)?;
        assert_eq!(segment.ring.read_index(), 0);
        let pair = segment.clamp.snapshot()?;
        segment.frontier.store(NativeConsoleFrontier {
            sequence: 2,
            ring_end: 2,
            logical_ps: 100,
            raw_prefix: 1,
            owner: body.owner,
            accepted_advance: pair.advance,
            logical_generation: body.logical_generation,
            request: pair.request,
            plan_hash,
        })?;
        slot.publish_control_boundary(100, 1)?;
        slot.acknowledge_control_boundary();
        Ok(notifications)
    });
    let completed = runtime.await_child(
        crate::QemuAsyncWait::AdvanceCompletion,
        Duration::from_secs(1),
    );
    // Always reap the original modeled peer, including host refusal paths.
    let peer = provider.join().map_err(|_| FixtureError::PeerPanicked)?;
    let notifications = peer?;
    assert_eq!(completed?, crate::QemuAsyncWaitOutcome::Completed);
    let boundary = runtime
        .completed_quantum_boundary()
        .ok_or(ConsoleOwnerError::Storage)?;
    assert_eq!(boundary.console_output_sequence(), Some(2));
    assert_eq!(boundary.calibration().logical_icount, 100);
    assert_eq!(boundary.calibration().raw_icount, 1);
    pending.completed_boundary = Some(boundary);
    let report = QemuShmemHotPathChannel::poll_quantum(&mut channel, &mut pending)?;
    assert!(matches!(report.outcome, crucible::AdvanceOutcome::Paused { at } if at.retired == 100));
    let owner = custody.lock()?;
    assert!(owner.issued.is_empty());
    assert_eq!(
        owner
            .accepted
            .pending_origins()
            .iter()
            .map(|origin| origin.emitted_ps)
            .collect::<Vec<_>>(),
        vec![80, 81]
    );
    assert_eq!(
        region
            .native_console_segment(0)
            .map_err(ConsoleOwnerError::from)?
            .ring
            .read_index(),
        2
    );
    drop(owner);
    Ok(AcceptedConsoleStopFixture {
        fixture,
        region,
        channel,
        runtime,
        notifications,
        boundary,
    })
}

/// Owns the original setup and accepted console stop through the next quantum.
pub(crate) struct AcceptedConsoleStopFixture {
    pub(crate) fixture: LaunchFixture,
    pub(crate) region: MappedSetupRegion,
    pub(crate) channel: crate::QemuMappedQuantumShmemHotPath,
    pub(crate) runtime: crate::QemuLiveHostIoRuntime,
    pub(crate) notifications: UnixStream,
    pub(crate) boundary: crate::QemuCompletedQuantumBoundary,
}

#[test]
fn accepted_native_advisory_tail_preserves_real_custody_and_refuses_contention()
-> Result<(), FixtureError> {
    let case = accepted_console_stop_fixture()?;
    let custody = custody(&case.fixture)?;
    let authorization = custody.authorization_snapshot()?;
    let before = custody.lock()?.accepted.checkpoint_parts()?;
    let frontier = case.region.native_console_segment(0)?.frontier.copy()?;
    let read_index = case.region.native_console_segment(0)?.ring.read_index();

    assert_eq!(custody.accepted_byte_tail(), Some(b"AB".to_vec()));
    assert_eq!(custody.accepted_byte_tail(), Some(b"AB".to_vec()));
    let owner = custody.lock()?;
    assert_eq!(custody.accepted_byte_tail(), None);
    let after = owner.accepted.checkpoint_parts()?;
    assert_eq!(after.sequence, before.sequence);
    assert_eq!(after.ring_end, before.ring_end);
    assert_eq!(after.stream_sequences, before.stream_sequences);
    assert_eq!(after.pending, before.pending);
    assert!(owner.issued.is_empty());
    drop(owner);
    assert_eq!(custody.authorization_snapshot()?, authorization);
    assert_eq!(
        case.region.native_console_segment(0)?.frontier.copy()?,
        frontier
    );
    assert_eq!(
        case.region.native_console_segment(0)?.ring.read_index(),
        read_index
    );
    case.fixture.finish()
}

#[test]
fn advisory_tail_bounds_the_copy_without_mutating_its_input_queue() -> Result<(), FixtureError> {
    let case = accepted_console_stop_fixture()?;
    let custody = custody(&case.fixture)?;
    let mut owner = custody.lock()?;
    let original = owner.accepted.pending.clone();
    // This synthetic queue tests only suffix copying, not native acceptance.
    let mut retained = original[0].clone();
    owner.accepted.pending.clear();
    for index in 0..4101 {
        retained.origin.byte = (index % 251) as u8;
        owner.accepted.pending.push(retained.clone());
    }
    let before = owner.accepted.pending.clone();

    let tail = owner.accepted.advisory_byte_tail();
    assert_eq!(tail.len(), 4096);
    assert_eq!(
        tail,
        (5..4101)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>()
    );
    assert_eq!(owner.accepted.pending, before);
    owner.accepted.pending = original;
    drop(owner);
    case.fixture.finish()
}

#[test]
fn real_runtime_console_stop_clamps_before_consumption_and_reports_its_exact_byte_tail()
-> Result<(), FixtureError> {
    accepted_console_stop_fixture()?.fixture.finish()
}

#[test]
fn wrapped_actual_control_publication_accepts_only_its_owned_completed_frontier()
-> Result<(), FixtureError> {
    use std::os::unix::fs::FileExt;

    let fixture = LaunchFixture::cold(2)?;
    let region = mapped(&fixture)?;
    let mut channel = fixture.hot_path()?;
    start(&mut channel, 200)?;
    let custody = custody(&fixture)?;
    let body = custody.authorization_snapshot()?;
    stage(&region, body, 80, b"A")?;
    let layout = region.layout().map_err(|_| ConsoleOwnerError::Storage)?;
    let file = std::fs::File::from(fixture.setup.shmem_as_fd().try_clone_to_owned()?);
    // Explicit stopped native counter provider, with no concurrent writer.
    // The two genuine slot writers below perform the actual wrap to even zero.
    file.write_all_at(
        &(u32::MAX - 3).to_le_bytes(),
        layout.node_slots_off + crucible_shmem::NODE_SLOT_PUBLISH_GEN_OFFSET as u64,
    )?;
    let boundary = modeled_completed_cache(&fixture, &region, body, 100)?;
    assert_eq!(region.node_slot(0)?.snapshot().publish_gen, 0);
    custody.accept_completed_with_stop(&region, boundary, None)?;
    assert_eq!(custody.lock()?.accepted.node_sequence(), 1);
    assert!(custody.lock()?.issued.is_empty());
    assert_eq!(region.native_console_segment(0)?.ring.read_index(), 1);
    fixture.finish()
}

#[test]
fn accepted_prefix_observation_pairs_capture_without_new_authorization() -> Result<(), FixtureError>
{
    use crucible_protocol::native_console::NativeConsoleControlKind;

    let fixture = LaunchFixture::cold(2)?;
    let region = mapped(&fixture)?;
    let mut channel = fixture.hot_path()?;
    start(&mut channel, 100)?;
    let custody = custody(&fixture)?;
    let body = custody.authorization_snapshot()?;
    let completed = modeled_completed_cache(&fixture, &region, body, 100)?;
    custody.accept_completed_with_stop(&region, completed, None)?;
    let slot = region.node_slot(0)?;
    let segment = region.native_console_segment(0)?;
    let before_slot = slot.snapshot();
    let before_frontier = segment.frontier.copy()?;
    let before_body = custody.authorization_snapshot()?;
    let (accepted, incarnation, ordinal, publication) = {
        let owner = custody.lock()?;
        assert!(owner.issued.is_empty());
        (
            owner.accepted.accepted_request,
            owner.next_incarnation,
            owner.next_ordinal,
            owner.next_clamp_publication,
        )
    };

    let request = custody.request_boundary(&region, 0, Some(3))?;
    let pair = segment.clamp.snapshot()?;
    assert_eq!(pair.kind, NativeConsoleControlKind::Observation);
    assert_eq!(pair.last_issued, None);
    assert_eq!(pair.publication, publication);
    assert_eq!(pair.request, request);
    assert_eq!(pair.capture, 3);
    assert_eq!(pair.advance, before_slot.advance_publication_sequence);
    assert_eq!(pair.ceiling, before_slot.max_advance_icount);
    assert_eq!(custody.request_boundary(&region, 0, Some(3))?, request);
    assert_eq!(segment.clamp.snapshot()?, pair);
    assert!(custody.request_boundary(&region, 0, Some(5)).is_err());
    assert!(custody.request_boundary(&region, 1, Some(3)).is_err());
    assert_eq!(segment.clamp.snapshot()?, pair);
    assert_eq!(slot.control_boundary_token(), request);
    assert_eq!(segment.frontier.copy()?, before_frontier);
    assert_eq!(custody.authorization_snapshot()?, before_body);
    {
        let owner = custody.lock()?;
        assert_eq!(owner.accepted.accepted_request, accepted);
        assert_eq!(owner.next_incarnation, incarnation);
        assert_eq!(owner.next_ordinal, ordinal);
        assert_eq!(owner.next_clamp_publication, publication + 2);
        assert!(owner.issued.is_empty());
    }

    // Modeled native completion only: real CLOSED/Observed admission belongs
    // to the separate native controls. The host must retain its old prefix.
    slot.publish_control_boundary(100, 1)?;
    slot.acknowledge_control_boundary();
    let next = custody.request_boundary(&region, 0, Some(5))?;
    assert_eq!(next, request.wrapping_add(2));
    assert_eq!(segment.clamp.snapshot()?.publication, publication + 2);
    assert_eq!(custody.lock()?.accepted.accepted_request, accepted);
    slot.acknowledge_control_boundary();
    start(&mut channel, 200)?;
    assert!(custody.lock()?.control_observation.is_none());
    assert!(custody.request_boundary(&region, 0, None).is_err());
    fixture.finish()
}

#[test]
fn native_run_fresh_same_coordinate_idle_uses_original_acceptance() -> Result<(), FixtureError> {
    let fixture = LaunchFixture::cold(2)?;
    let region = mapped(&fixture)?;
    let mut channel = fixture.hot_path()?;
    let custody = custody(&fixture)?;
    start(&mut channel, 50)?;
    let cold = custody.authorization_snapshot()?;
    settle_real_runtime(&fixture, &region, cold, 50)?;
    let accepted = custody
        .lock()?
        .accepted
        .accepted_request
        .ok_or(ConsoleOwnerError::Storage)?;
    let (mut notifications, wake) = UnixStream::pair()?;
    notifications.set_read_timeout(Some(Duration::from_secs(1)))?;
    let mut runtime = crate::QemuLiveHostIoRuntime::from_shmem_fd(
        fixture.setup.shmem_as_fd(),
        wake.as_fd(),
        fixture.setup.region().region_len,
        0,
    )?;
    runtime.retain_console_launch(&fixture.setup)?;
    runtime.prepare_advance_completion(Duration::from_secs(1))?;
    let pending = QemuShmemHotPathChannel::start_quantum(
        &mut channel,
        crucible::ExecutionHorizon {
            icount: crucible::Icount { retired: 200 },
        },
        AdvanceStopCondition::Ceiling,
    )?;
    runtime.retain_advance_initial_state(pending.initial_state());
    runtime.arm_advance_completion_fence(pending.completion_fence())?;
    let body = custody.authorization_snapshot()?;
    let native = mapped(&fixture)?;
    let plan_hash = custody.lock()?.accepted.plan.digest()?;
    let provider = std::thread::spawn(move || -> Result<(), FixtureError> {
        let slot = native.node_slot(0)?;
        let mut wake = [0; 8];
        notifications.read_exact(&mut wake)?;
        assert_eq!(slot.control_boundary_token(), accepted + 1);
        // This real slot writer republishes the same coordinate and expired
        // timer deadline. It is a modeled native report, not a RUNNING stamp.
        let _wait = slot.publish_idle(50, 50)?;
        notifications.read_exact(&mut wake)?;
        let segment = native.native_console_segment(0)?;
        let pair = segment.clamp.snapshot()?;
        assert_eq!(
            pair.kind,
            crucible_protocol::native_console::NativeConsoleControlKind::Acceptance
        );
        assert_eq!(pair.last_issued, Some(body));
        segment.frontier.store(NativeConsoleFrontier {
            sequence: 0,
            ring_end: 0,
            logical_ps: 50,
            raw_prefix: 1,
            owner: body.owner,
            accepted_advance: pair.advance,
            logical_generation: body.logical_generation,
            request: pair.request,
            plan_hash,
        })?;
        slot.publish_control_boundary(50, 1)?;
        slot.acknowledge_control_boundary();
        Ok(())
    });
    let completed = runtime.await_child(
        crate::QemuAsyncWait::AdvanceCompletion,
        Duration::from_secs(1),
    );
    let peer = provider.join().map_err(|_| FixtureError::PeerPanicked)?;
    peer?;
    assert_eq!(completed?, crate::QemuAsyncWaitOutcome::Completed);
    let boundary = runtime
        .completed_quantum_boundary()
        .ok_or(ConsoleOwnerError::Storage)?;
    assert_eq!(boundary.calibration().logical_icount, 50);
    assert_eq!(boundary.calibration().raw_icount, 1);
    assert!(custody.lock()?.issued.is_empty());
    assert_eq!(region.native_console_segment(0)?.ring.read_index(), 0);
    fixture.finish()
}

struct CheckpointPauseObservation {
    result: Result<(), crate::QemuAsyncDriverRuntimeError>,
    observed: crucible_shmem::NodeSlotSnapshot,
    paired: crucible_protocol::native_console::NativeConsoleClamp,
    original_advance: u64,
}

/// Uses the real pause waiter and mapped custody with an external native peer.
fn checkpoint_pause_with_observation_ack(
    acknowledge_pause: bool,
    delayed_ack: bool,
) -> Result<CheckpointPauseObservation, FixtureError> {
    let fixture = LaunchFixture::cold(2)?;
    let region = mapped(&fixture)?;
    let mut channel = fixture.hot_path()?;
    start(&mut channel, 100)?;
    let authorization = custody(&fixture)?.authorization_snapshot()?;
    settle_real_runtime(&fixture, &region, authorization, 100)?;

    let slot = region.node_slot(0)?;
    slot.publish_reached_icount(100)?;
    let original_advance = slot.snapshot().advance_publication_sequence;
    let (mut notifications, wake) = UnixStream::pair()?;
    notifications.set_read_timeout(Some(Duration::from_secs(1)))?;
    let mut runtime = crate::QemuLiveHostIoRuntime::from_shmem_fd_with_poll_interval(
        fixture.setup.shmem_as_fd(),
        wake.as_fd(),
        fixture.setup.region().region_len,
        0,
        Duration::from_millis(1),
    )?;
    runtime.retain_console_launch(&fixture.setup)?;
    let host = std::thread::spawn(move || runtime.quiesce_for_checkpoint(Duration::from_secs(2)));

    let publication = (|| -> Result<_, FixtureError> {
        let mut counter = [0; 8];
        notifications.read_exact(&mut counter)?;
        assert_eq!(u64::from_ne_bytes(counter), 1);

        // The external peer completes the original pre-pause control probe.
        // This is not a native console commit or QEMU execution assertion.
        slot.publish_control_boundary(100, 1)?;
        slot.acknowledge_control_boundary();
        notifications.read_exact(&mut counter)?;
        assert_eq!(u64::from_ne_bytes(counter), 1);

        // Publish the real new IDLE generation while retaining the latest even
        // Observation request. An IDLE publication does not acknowledge it.
        let pending = region.native_console_segment(0)?.clamp.snapshot()?;
        slot.publish_idle(100, 100)?;
        let observed = slot.snapshot();
        if acknowledge_pause {
            if delayed_ack {
                // Wait for the original pause loop's re-notification. IDLE
                // alone must not return ready before this exact late ACK.
                notifications.read_exact(&mut counter)?;
                assert_eq!(u64::from_ne_bytes(counter), 1);
                assert_eq!(slot.snapshot().control_boundary_ack, pending.request);
            }
            // Positive counterpart: the external peer supplies the exact ACK.
            // The actual native committed-prefix predicate is tested separately.
            slot.acknowledge_control_boundary();
        }
        Ok((observed, pending))
    })();

    // Always reap the original waiter, including a failed peer publication.
    let result = host.join().map_err(|_| FixtureError::PeerPanicked)?;
    let (observed, pending) = publication?;
    fixture.finish()?;
    Ok(CheckpointPauseObservation {
        result,
        observed,
        paired: pending,
        original_advance,
    })
}

#[test]
fn checkpoint_pause_requires_latest_console_observation_ack() -> Result<(), FixtureError> {
    let CheckpointPauseObservation {
        result,
        observed,
        paired: pending,
        original_advance,
    } = checkpoint_pause_with_observation_ack(false, false)?;

    assert_eq!(
        pending.kind,
        crucible_protocol::native_console::NativeConsoleControlKind::Observation
    );
    assert_eq!(observed.advance_publication_sequence, original_advance + 2);
    assert_eq!(pending.advance, observed.advance_publication_sequence);
    assert_eq!(pending.ceiling, 100);
    assert_eq!(pending.capture, 0);
    assert_eq!(observed.control_boundary_ack, pending.request);
    assert_eq!(observed.control_boundary_ack & 1, 0);
    assert_eq!(observed.status, crucible_shmem::STATUS_IDLE);
    assert_eq!(observed.current_icount, observed.idle_wake_icount);
    assert_eq!(observed.device_io_active, 0);

    eprintln!(
        "checkpoint_pending_observation request={} ack={} advance={} capture={} pause_result={result:?}",
        pending.request, observed.control_boundary_ack, pending.advance, pending.capture,
    );
    let error = result.err().ok_or_else(|| {
        FixtureError::Peer("checkpoint pause returned before its latest Observation ACK".into())
    })?;
    assert_eq!(error.operation, "await checkpoint pause");
    Ok(())
}

#[test]
fn checkpoint_pause_accepts_exact_latest_console_observation_ack() -> Result<(), FixtureError> {
    let CheckpointPauseObservation {
        result,
        observed,
        paired: pending,
        original_advance,
    } = checkpoint_pause_with_observation_ack(true, false)?;

    assert_eq!(pending.advance, original_advance + 2);
    assert_eq!(observed.control_boundary_ack, pending.request);
    result?;
    Ok(())
}

#[test]
fn checkpoint_pause_progresses_after_exact_late_console_observation_ack() -> Result<(), FixtureError>
{
    let CheckpointPauseObservation {
        result,
        paired,
        observed,
        ..
    } = checkpoint_pause_with_observation_ack(true, true)?;
    assert_eq!(observed.control_boundary_ack, paired.request);
    result?;
    Ok(())
}

#[test]
fn checkpoint_observation_refuses_changed_advance_and_unpaired_request() -> Result<(), FixtureError>
{
    let fixture = LaunchFixture::cold(2)?;
    let region = mapped(&fixture)?;
    let mut channel = fixture.hot_path()?;
    start(&mut channel, 100)?;
    let owner = custody(&fixture)?;
    let body = owner.authorization_snapshot()?;
    settle_real_runtime(&fixture, &region, body, 100)?;
    let slot = region.node_slot(0)?;

    owner.request_boundary(&region, 0, None)?;
    slot.publish_control_boundary(100, 1)?;
    slot.acknowledge_control_boundary();
    assert!(owner.checkpoint_observation_is_settled(&region, &slot.snapshot())?);

    let ceiling = crucible_shmem::authorize_advance_ceiling(100, 100, None)?;
    slot.publish_scheduler_advance(ceiling, AdvanceStopCondition::Ceiling)?;
    assert!(!owner.checkpoint_observation_is_settled(&region, &slot.snapshot())?);
    owner.request_boundary(&region, 0, None)?;
    slot.acknowledge_control_boundary();
    assert!(owner.checkpoint_observation_is_settled(&region, &slot.snapshot())?);

    // The external peer's next ACK cannot repair an unpaired host request.
    slot.request_control_boundary(0, Some(3))?;
    slot.acknowledge_control_boundary();
    assert!(!owner.checkpoint_observation_is_settled(&region, &slot.snapshot())?);
    fixture.finish()
}

mod publication_handoff;

mod completed_observation;

mod request_contention;
