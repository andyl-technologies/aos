//! Terminal capture after an original same-boundary input regrant.
//!
//! Setup, input publication, receipt custody, clamp and fingerprint waits use
//! the real mapped host implementations. Native CLOSED and digest publication
//! are explicit modeled providers; this is not physical QEMU qualification.

use super::*;
use crucible_protocol::native_console::NativeConsoleControlKind;

#[test]
fn terminal_fingerprint_settles_original_same_boundary_input_grant() -> Result<(), FixtureError> {
    let mut case = accepted_console_stop_fixture()?;
    let launch = custody(&case.fixture)?;
    let original = launch.lock()?.accepted.pending_origins();
    let accepted = case.region.native_console_segment(0)?.frontier.copy()?;
    let owned = case.boundary.calibration();
    assert_eq!(owned.logical_icount, 100);

    QemuShmemHotPathChannel::deliver_frame_at(
        &mut case.channel,
        crucible::BackendInput {
            node: crucible::NodeId { name: "vm".into() },
            payload: vec![7],
        },
        crucible::Icount {
            retired: owned.logical_icount,
        },
    )?;
    let grant = launch.authorization_snapshot()?;
    {
        let owner = launch.lock()?;
        assert_eq!(owner.issued.len(), 1);
        assert_eq!(owner.issued[0].body, grant);
        assert!(owner.clamp.is_none());
        assert_eq!(grant.phase, NativeConsolePhase::Grant);
        assert_eq!(grant.prior_sequence, accepted.sequence);
        assert_eq!(grant.prior_ring_end, accepted.ring_end);
        assert_eq!(grant.phase_token, u64::from(accepted.request));
    }

    let native = mapped(&case.fixture)?;
    let mut notifications = case.notifications.try_clone()?;
    notifications.set_read_timeout(Some(Duration::from_secs(1)))?;
    let provider = std::thread::spawn(move || -> Result<(), FixtureError> {
        let mut wake = [0; 8];
        notifications.read_exact(&mut wake)?;
        assert_eq!(u64::from_ne_bytes(wake), 1);
        let segment = native.native_console_segment(0)?;
        let pair = segment.clamp.snapshot()?;
        assert_eq!(pair.kind, NativeConsoleControlKind::Acceptance);
        assert_eq!(pair.capture, 0);
        assert_eq!(pair.last_issued, Some(grant));
        assert_eq!(pair.ceiling, owned.logical_icount);
        assert!(segment.authorization.snapshot().is_err());
        segment.frontier.store(NativeConsoleFrontier {
            owner: grant.owner,
            accepted_advance: pair.advance,
            request: pair.request,
            ..accepted
        })?;
        let slot = native.node_slot(0)?;
        slot.publish_control_boundary(owned.logical_icount, owned.raw_icount)?;
        slot.acknowledge_control_boundary();

        notifications.read_exact(&mut wake)?;
        assert_eq!(u64::from_ne_bytes(wake), 1);
        let observation = segment.clamp.snapshot()?;
        assert_eq!(observation.kind, NativeConsoleControlKind::Observation);
        assert!(observation.last_issued.is_none());
        assert_ne!(observation.capture, 0);
        assert_eq!(segment.frontier.copy()?.request, pair.request);
        slot.publish_control_boundary(owned.logical_icount, owned.raw_icount)?;
        slot.acknowledge_control_boundary();
        native
            .fingerprint_sample(0)?
            .publish(&crucible_shmem::FingerprintSample::default())
            .map_err(|error| FixtureError::Peer(error.to_string()))?;
        assert!(
            native
                .fingerprint_sample(0)?
                .acknowledge_capture_v1(observation.capture)
        );
        Ok(())
    });

    let result = case
        .runtime
        .prepare_terminal_fingerprint(
            Some(case.boundary),
            crucible::Icount {
                retired: owned.logical_icount,
            },
            Duration::from_secs(1),
        )
        .and_then(|()| {
            case.runtime
                .publish_current_execution_fingerprint(Duration::from_secs(1))
        });
    let provided = provider.join().map_err(|_| FixtureError::PeerPanicked)?;
    // A failed original host call is the RED evidence; the modeled provider's
    // bounded missing-wake cleanup must not replace that actual refusal.
    if let Err(error) = result {
        case.fixture.finish()?;
        return Err(error.into());
    }
    provided?;
    let owner = launch.lock()?;
    assert!(owner.issued.is_empty());
    assert!(owner.clamp.is_none());
    assert_eq!(owner.accepted.pending_origins(), original);
    assert_eq!(owner.accepted.node_sequence(), accepted.sequence);
    assert_eq!(owner.accepted.ring_end(), accepted.ring_end);
    assert_eq!(launch.authorization_snapshot()?, grant);
    assert_eq!(
        case.region.node_slot(0)?.snapshot().current_icount,
        owned.logical_icount
    );
    assert_eq!(
        case.region.node_slot(0)?.snapshot().logical_time_raw_icount,
        owned.raw_icount
    );
    drop(owner);
    case.fixture.finish()
}

#[derive(Clone, Copy, Debug)]
enum Refusal {
    MissingNodeReceipt,
    ForeignNodeReceipt,
    MovedOwnedCoordinate,
    MovedRaw,
    Done,
    ActiveDevice,
    PendingRestore,
    UnacceptedByte,
    OldPendingClamp,
}

#[test]
fn terminal_fingerprint_refuses_unowned_or_unsettled_grants_before_effects()
-> Result<(), FixtureError> {
    for refusal in [
        Refusal::MissingNodeReceipt,
        Refusal::ForeignNodeReceipt,
        Refusal::MovedOwnedCoordinate,
        Refusal::MovedRaw,
        Refusal::Done,
        Refusal::ActiveDevice,
        Refusal::PendingRestore,
        Refusal::UnacceptedByte,
        Refusal::OldPendingClamp,
    ] {
        let mut case = accepted_console_stop_fixture()?;
        QemuShmemHotPathChannel::deliver_frame_at(
            &mut case.channel,
            crucible::BackendInput {
                node: crucible::NodeId { name: "vm".into() },
                payload: vec![7],
            },
            crucible::Icount { retired: 100 },
        )?;
        let launch = custody(&case.fixture)?;
        let slot = case.region.node_slot(0)?;
        let mut completed = Some(case.boundary);
        let mut at = crucible::Icount { retired: 100 };
        let foreign = if matches!(refusal, Refusal::ForeignNodeReceipt) {
            Some(accepted_console_stop_fixture()?)
        } else {
            None
        };
        match refusal {
            Refusal::MissingNodeReceipt => completed = None,
            Refusal::ForeignNodeReceipt => {
                completed = foreign.as_ref().map(|other| other.boundary);
            }
            Refusal::MovedOwnedCoordinate => at.retired += 1,
            Refusal::MovedRaw => slot.publish_control_boundary(100, 2)?,
            Refusal::Done => slot.mark_done(),
            Refusal::ActiveDevice => slot.mark_device_io_active(),
            Refusal::PendingRestore => {
                slot.arm_logical_time_restore(100)?;
            }
            Refusal::UnacceptedByte => {
                stage_with_raw_prefix(
                    &case.region,
                    launch.authorization_snapshot()?,
                    100,
                    b"X",
                    1,
                )?;
            }
            Refusal::OldPendingClamp => {
                let ceiling = crucible_shmem::authorize_advance_ceiling(100, 100, None)
                    .map_err(|_| ConsoleOwnerError::Storage)?;
                launch.publish_clamp(slot, ceiling)?;
                launch.request_boundary(&case.region, 0, None)?;
            }
        }
        let body = launch.authorization_snapshot()?;
        let before = slot.snapshot();
        let segment = case.region.native_console_segment(0)?;
        let frontier = segment.frontier.copy()?;
        let ring = (segment.ring.read_index(), segment.ring.write_index());
        let pair = segment.clamp.snapshot();
        let (issued, origins, clamp) = {
            let owner = launch.lock()?;
            (
                owner.issued.clone(),
                owner.accepted.pending_origins(),
                owner.clamp,
            )
        };

        let error = case
            .runtime
            .prepare_terminal_fingerprint(completed, at, Duration::from_secs(1))
            .err()
            .ok_or(ConsoleOwnerError::Storage)?;
        assert_eq!(
            error.operation, "prepare terminal console fingerprint",
            "{refusal:?}"
        );
        assert_eq!(slot.snapshot(), before, "{refusal:?}");
        assert_eq!(launch.authorization_snapshot()?, body, "{refusal:?}");
        assert_eq!(segment.frontier.copy()?, frontier, "{refusal:?}");
        assert_eq!(
            (segment.ring.read_index(), segment.ring.write_index()),
            ring,
            "{refusal:?}"
        );
        assert_eq!(segment.clamp.snapshot(), pair, "{refusal:?}");
        let owner = launch.lock()?;
        assert_eq!(owner.issued, issued, "{refusal:?}");
        assert_eq!(owner.accepted.pending_origins(), origins, "{refusal:?}");
        assert_eq!(owner.clamp, clamp, "{refusal:?}");
        drop(owner);
        if let Some(foreign) = foreign {
            foreign.fixture.finish()?;
        }
        case.fixture.finish()?;
    }
    Ok(())
}
