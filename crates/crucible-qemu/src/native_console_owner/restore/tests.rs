//! Genuine mapped Restore issuance with explicitly modeled QMP/native load owners.
//!
//! These controls exercise host requests, AUTH, ring cursor and custody only.
//! The QMP whole-load receipt and native CLOSED/frontier/ACK are external test
//! providers, not TCG, migration, READY or physical restore qualifications.

use super::*;
use crate::native_console_owner::tests::{FixtureError, LaunchFixture};
use crucible::{ContentHash, NodeCounter, NodeId};
use crucible_shmem::mmap_setup_region;

fn load() -> (
    crate::qmp::QmpCheckpointIdentity,
    crate::qmp::QmpCheckpointRestore,
) {
    let identity = crate::qmp::QmpCheckpointIdentity::new(
        ContentHash { bytes: [1; 32] },
        ContentHash { bytes: [2; 32] },
        ContentHash { bytes: [3; 32] },
    );
    (
        identity,
        crate::qmp::QmpCheckpointRestore::for_test(identity, ContentHash { bytes: [4; 32] }),
    )
}

#[test]
fn stopped_restore_keeps_canonical_prefix_and_pairs_fresh_body_before_requests()
-> Result<(), FixtureError> {
    let fixture = LaunchFixture::cold(2)?;
    let custody = fixture
        .setup
        .console_custody
        .as_ref()
        .ok_or(ConsoleOwnerError::Storage)?;
    let region = mmap_setup_region(
        fixture.setup.shmem_as_fd(),
        fixture.setup.region().region_len,
    )?;
    let node = NodeId { name: "vm".into() };
    let mut saved = custody.checkpoint_origins(&node, NodeCounter { ticks: 100 })?;
    // Captured canonical prefix is modeled saved native state. Its physical
    // endpoint must still be installed into this actual fresh mapped ring.
    saved.sequence = 7;
    saved.ring_end = 23;
    saved.stream_sequences[0] = 7;
    let slot = region.node_slot(0)?;
    slot.arm_external_state_restore_ceiling(200)?;
    let (expected, loaded) = load();
    let mut channel = fixture.hot_path()?;
    let boundary =
        channel.arm_console_logical_time_restore_boundary(100, &saved, loaded, expected)?;
    let generation = boundary.logical_generation();
    let request = slot.control_boundary_token();
    let segment = region.native_console_segment(0)?;
    let body = segment.authorization.snapshot()?;
    let pair = region.native_console_clamp_for_request(0)?;
    assert_eq!((generation, request), (1, 2));
    assert_eq!(body.phase, NativeConsolePhase::Restore);
    assert_eq!(body.phase_token, u64::from(generation));
    assert_eq!(body.logical_generation, 0);
    assert_eq!((body.prior_sequence, body.prior_ring_end), (7, 23));
    assert_eq!(pair.last_issued, Some(body));
    assert_eq!(body.advance, pair.advance);
    assert_eq!(pair.ceiling, 200);
    assert_eq!(slot.snapshot().logical_time_restore_target, 100);
    assert_eq!(
        (segment.ring.read_index(), segment.ring.write_index()),
        (23, 23)
    );
    assert!(custody.lock()?.accepted.restored);
    assert_eq!(custody.lock()?.issued.len(), 1);
    assert!(custody.restore_origins(&node, &saved).is_err());

    // Native whole-load/CLOSED/frontier publication is explicitly modeled.
    // Its exact acknowledgement still drives the real host empty-prefix
    // acceptance and covered-ledger retirement methods below.
    let restore = slot
        .pending_logical_time_restore()
        .ok_or(ConsoleOwnerError::Storage)?;
    slot.acknowledge_logical_time_restore(restore, 100, 2)?;
    let mut frontier = crucible_protocol::native_console::NativeConsoleFrontier {
        sequence: 7,
        ring_end: 23,
        logical_ps: 100,
        raw_prefix: 3,
        owner: body.owner,
        accepted_advance: pair.advance,
        logical_generation: 0,
        request,
        plan_hash: fixture.plan_hash()?,
    };
    segment.frontier.store(frontier)?;
    assert_eq!(slot.acknowledge_control_boundary(), request.wrapping_add(1));
    let calibration = crate::QemuLogicalTimeCalibration {
        logical_icount: 100,
        raw_icount: 2,
    };
    assert!(channel.logical_time_restore_boundary_acknowledged(boundary, calibration)?);
    assert!(
        channel
            .accept_console_logical_time_restore(boundary, calibration)
            .is_err()
    );
    assert!(custody.lock()?.accepted.restored);
    assert_eq!(custody.lock()?.issued.len(), 1);
    assert_eq!(segment.ring.read_index(), 23);
    frontier.raw_prefix = 2;
    segment.frontier.store(frontier)?;
    channel.accept_console_logical_time_restore(boundary, calibration)?;
    assert!(!custody.lock()?.accepted.restored);
    assert!(custody.lock()?.issued.is_empty());
    assert_eq!(
        custody.restore_origins(&node, &saved)?,
        NodeCounter { ticks: 100 }
    );
    assert!(!custody.lock()?.accepted.restored);
    assert!(custody.lock()?.pending_node_restore.is_none());
    assert_eq!(custody.lock()?.accepted.checkpoint_parts()?.sequence, 7);
    Ok(())
}

#[test]
fn foreign_load_refuses_before_cursor_auth_or_request_changes() -> Result<(), FixtureError> {
    let fixture = LaunchFixture::cold(2)?;
    let custody = fixture
        .setup
        .console_custody
        .as_ref()
        .ok_or(ConsoleOwnerError::Storage)?;
    let region = mmap_setup_region(
        fixture.setup.shmem_as_fd(),
        fixture.setup.region().region_len,
    )?;
    let node = NodeId { name: "vm".into() };
    let saved = custody.checkpoint_origins(&node, NodeCounter { ticks: 100 })?;
    let (expected, loaded) = load();
    let foreign = crate::qmp::QmpCheckpointIdentity::new(
        ContentHash { bytes: [9; 32] },
        expected.target(),
        expected.frontier(),
    );
    assert!(
        custody
            .arm_stopped_restore(&region, &node, &saved, loaded, foreign, 100)
            .is_err()
    );
    let slot = region.node_slot(0)?;
    assert_eq!(slot.control_boundary_token(), 1);
    assert!(slot.pending_logical_time_restore().is_none());
    assert!(
        region
            .native_console_segment(0)?
            .authorization
            .snapshot()
            .is_err()
    );
    assert!(custody.lock()?.issued.is_empty());
    Ok(())
}

#[test]
fn refused_composite_restore_preserves_cursor_checkpoint_and_issuance_custody()
-> Result<(), FixtureError> {
    for ring_busy in [false, true] {
        let fixture = LaunchFixture::cold(2)?;
        let custody = fixture
            .setup
            .console_custody
            .as_ref()
            .ok_or(ConsoleOwnerError::Storage)?;
        let region = mmap_setup_region(
            fixture.setup.shmem_as_fd(),
            fixture.setup.region().region_len,
        )?;
        let node = NodeId { name: "vm".into() };
        let before = custody.checkpoint_origins(&node, NodeCounter { ticks: 100 })?;
        let mut saved = before.clone();
        saved.sequence = 7;
        saved.ring_end = 23;
        saved.stream_sequences[0] = 7;
        let slot = region.node_slot(0)?;
        slot.arm_external_state_restore_ceiling(200)?;
        let segment = region.native_console_segment(0)?;
        let counters = {
            let owner = custody.lock()?;
            (
                owner.next_ordinal,
                owner.next_incarnation,
                owner.next_publication,
                owner.next_clamp_publication,
            )
        };
        let request = if ring_busy {
            assert!(segment.ring.hold_hot_fork_producers().quiescent());
            1
        } else {
            slot.request_control_boundary(7, None)?
        };
        let (expected, loaded) = load();

        let refusal = custody.arm_stopped_restore(&region, &node, &saved, loaded, expected, 100);
        if ring_busy {
            assert!(matches!(
                refusal,
                Err(ConsoleOwnerError::RestoreRing(
                    crucible_shmem::SpscRingError::RestoreCursorBusy
                ))
            ));
            assert!(segment.ring.producer_barrier_snapshot().quiescent());
            assert!(!segment.ring.release_hot_fork_producers().held());
        } else {
            assert!(matches!(
                refusal,
                Err(ConsoleOwnerError::Clamp(
                    crucible_shmem::NodeSlotError::RestoreControlBoundaryAlreadyPending { .. }
                ))
            ));
        }

        assert_eq!(
            (segment.ring.read_index(), segment.ring.write_index()),
            (0, 0)
        );
        assert!(!segment.ring.consumer_barrier_snapshot().held());
        assert!(!segment.ring.producer_barrier_snapshot().held());
        assert_eq!(
            custody.checkpoint_origins(&node, NodeCounter { ticks: 100 })?,
            before
        );
        let owner = custody.lock()?;
        assert_eq!(
            (
                owner.next_ordinal,
                owner.next_incarnation,
                owner.next_publication,
                owner.next_clamp_publication,
            ),
            counters
        );
        assert!(owner.issued.is_empty());
        assert!(owner.clamp.is_none());
        assert!(owner.pending_node_restore.is_none());
        assert!(!owner.accepted.restored);
        assert!(segment.authorization.snapshot().is_err());
        assert!(segment.clamp.snapshot().is_err());
        assert_eq!(slot.control_boundary_token(), request);
        assert!(slot.pending_logical_time_restore().is_none());
    }
    Ok(())
}

#[test]
fn competing_request_claim_refuses_composite_restore_without_mutation() -> Result<(), FixtureError>
{
    let fixture = LaunchFixture::cold(2)?;
    let custody = fixture
        .setup
        .console_custody
        .as_ref()
        .ok_or(ConsoleOwnerError::Storage)?;
    let region = mmap_setup_region(
        fixture.setup.shmem_as_fd(),
        fixture.setup.region().region_len,
    )?;
    let node = NodeId { name: "vm".into() };
    let before = custody.checkpoint_origins(&node, NodeCounter { ticks: 100 })?;
    let mut saved = before.clone();
    saved.sequence = 7;
    saved.ring_end = 23;
    saved.stream_sequences[0] = 7;
    let slot = region.node_slot(0)?;
    slot.arm_external_state_restore_ceiling(200)?;
    let (expected, loaded) = load();
    let refusal = std::cell::RefCell::new(None);

    // This is the real common request claim, held before its fields publish.
    // Reentrant Restore uses the actual composite owner rather than a copied
    // lower-level effect or synthetic pending-request scalar.
    let request = slot.request_control_boundary_with_prepared_fields(
        7,
        None,
        |_| {
            *refusal.borrow_mut() =
                Some(custody.arm_stopped_restore(&region, &node, &saved, loaded, expected, 100));
        },
        |_| {},
    )?;
    assert!(matches!(
        refusal.into_inner(),
        Some(Err(ConsoleOwnerError::Unavailable))
    ));

    let segment = region.native_console_segment(0)?;
    assert_eq!(
        (segment.ring.read_index(), segment.ring.write_index()),
        (0, 0)
    );
    assert!(!segment.ring.consumer_barrier_snapshot().held());
    assert!(!segment.ring.producer_barrier_snapshot().held());
    assert_eq!(
        custody.checkpoint_origins(&node, NodeCounter { ticks: 100 })?,
        before
    );
    let owner = custody.lock()?;
    assert!(owner.issued.is_empty());
    assert!(owner.clamp.is_none());
    assert!(owner.pending_node_restore.is_none());
    assert!(!owner.accepted.restored);
    assert_eq!(
        (
            owner.next_ordinal,
            owner.next_incarnation,
            owner.next_publication
        ),
        (1, 10, 2)
    );
    assert!(segment.authorization.snapshot().is_err());
    assert!(segment.clamp.snapshot().is_err());
    assert_eq!(slot.control_boundary_token(), request);
    assert!(slot.pending_logical_time_restore().is_none());
    Ok(())
}

#[test]
fn wrapped_actual_restore_publication_accepts_its_exact_loaded_pair() -> Result<(), FixtureError> {
    use std::os::unix::fs::FileExt;

    let fixture = LaunchFixture::cold(2)?;
    let custody = fixture
        .setup
        .console_custody
        .as_ref()
        .ok_or(ConsoleOwnerError::Storage)?;
    let region = mmap_setup_region(
        fixture.setup.shmem_as_fd(),
        fixture.setup.region().region_len,
    )?;
    let saved =
        custody.checkpoint_origins(&NodeId { name: "vm".into() }, NodeCounter { ticks: 100 })?;
    let slot = region.node_slot(0)?;
    slot.arm_external_state_restore_ceiling(200)?;
    let (expected, loaded) = load();
    let mut channel = fixture.hot_path()?;
    let boundary =
        channel.arm_console_logical_time_restore_boundary(100, &saved, loaded, expected)?;
    let segment = region.native_console_segment(0)?;
    let body = segment.authorization.snapshot()?;
    let pair = segment.clamp.snapshot()?;
    let layout = region.layout().map_err(|_| ConsoleOwnerError::Storage)?;
    let file = std::fs::File::from(fixture.setup.shmem_as_fd().try_clone_to_owned()?);
    // The native whole-loader/closed owner is explicitly modeled. The actual
    // slot's existing restore writer performs the original wrapping close.
    file.write_all_at(
        &(u32::MAX - 1).to_le_bytes(),
        layout.node_slots_off + crucible_shmem::NODE_SLOT_PUBLISH_GEN_OFFSET as u64,
    )?;
    let restore = slot
        .pending_logical_time_restore()
        .ok_or(ConsoleOwnerError::Storage)?;
    slot.acknowledge_logical_time_restore(restore, 100, 2)?;
    assert_eq!(slot.snapshot().publish_gen, 0);
    segment
        .frontier
        .store(crucible_protocol::native_console::NativeConsoleFrontier {
            sequence: 0,
            ring_end: 0,
            logical_ps: 100,
            raw_prefix: 2,
            owner: body.owner,
            accepted_advance: pair.advance,
            logical_generation: 0,
            request: pair.request,
            plan_hash: fixture.plan_hash()?,
        })?;
    slot.acknowledge_control_boundary();
    channel.accept_console_logical_time_restore(
        boundary,
        crate::QemuLogicalTimeCalibration {
            logical_icount: 100,
            raw_icount: 2,
        },
    )?;
    assert!(!custody.lock()?.accepted.restored);
    assert!(custody.lock()?.issued.is_empty());
    assert_eq!(segment.ring.read_index(), 0);
    fixture.finish()
}
