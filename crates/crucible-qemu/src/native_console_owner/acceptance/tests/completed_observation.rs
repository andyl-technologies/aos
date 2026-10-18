//! Completed observation of a genuinely retired mapped console prefix.
//!
//! The first acceptance, receipt retirement, runtime clamp and shared writers
//! are real host implementations. The stopped native callback is modeled: it
//! acknowledges the exact new request without rewriting the accepted frontier.
//! These controls supply no native READY, CLOSED or physical UART authority.

use super::*;
use crucible_protocol::native_console::NativeConsoleControlKind;

struct AcceptedState {
    request: Option<u32>,
    origins: Vec<crucible::NativeConsoleByteOrigin>,
    streams: Vec<u64>,
    sequence: u64,
    ring_end: u64,
    authorization: NativeConsoleAuthorization,
    incarnation: u64,
    ordinal: u64,
}

impl AcceptedState {
    fn retain(fixture: &LaunchFixture) -> Result<Self, FixtureError> {
        let custody = custody(fixture)?;
        let authorization = custody.authorization_snapshot()?;
        let owner = custody.lock()?;
        assert!(owner.issued.is_empty());
        assert!(owner.accepted.has_accepted_control());
        Ok(Self {
            request: owner.accepted.accepted_request,
            origins: owner.accepted.pending_origins(),
            streams: owner.accepted.stream_sequences.clone(),
            sequence: owner.accepted.node_sequence,
            ring_end: owner.accepted.ring_end,
            authorization,
            incarnation: owner.next_incarnation,
            ordinal: owner.next_ordinal,
        })
    }

    fn assert_retained(&self, fixture: &LaunchFixture) -> Result<(), FixtureError> {
        let custody = custody(fixture)?;
        assert_eq!(custody.authorization_snapshot()?, self.authorization);
        let owner = custody.lock()?;
        assert_eq!(owner.accepted.accepted_request, self.request);
        assert_eq!(owner.accepted.pending_origins(), self.origins);
        assert_eq!(owner.accepted.stream_sequences, self.streams);
        assert_eq!(owner.accepted.node_sequence, self.sequence);
        assert_eq!(owner.accepted.ring_end, self.ring_end);
        assert_eq!(owner.next_incarnation, self.incarnation);
        assert_eq!(owner.next_ordinal, self.ordinal);
        assert!(owner.issued.is_empty());
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
enum ModeledCompletion {
    Exact,
    ForeignOwner,
    ChangedPrefix,
    ChangedRingEnd,
    ChangedRequest,
    ChangedRaw,
    ChangedLogical,
    ChangedPlan,
    UnacceptedRingByte,
    ChangedAdvance,
    MissingAck,
}

fn complete_observation_once(
    case: &mut AcceptedConsoleStopFixture,
    completion: ModeledCompletion,
) -> Result<Result<(), crate::QemuAsyncDriverRuntimeError>, FixtureError> {
    let native = mapped(&case.fixture)?;
    let original = native.native_console_segment(0)?.frontier.copy()?;
    let authorization = custody(&case.fixture)?.authorization_snapshot()?;
    let mut notifications = case.notifications.try_clone()?;
    notifications.set_read_timeout(Some(Duration::from_secs(1)))?;

    let provider = std::thread::spawn(move || -> Result<(), FixtureError> {
        let mut wake = [0; 8];
        notifications.read_exact(&mut wake)?;
        assert_eq!(u64::from_ne_bytes(wake), 1);
        let segment = native.native_console_segment(0)?;
        let pair = segment.clamp.snapshot()?;
        assert_eq!(pair.kind, NativeConsoleControlKind::Observation);
        assert_eq!(pair.last_issued, None);
        assert_eq!(pair.ceiling, 100);
        assert_eq!(segment.frontier.copy()?, original);

        // Negative providers alter only their declared native output. No
        // accepted host receipt or authorization is edited to accommodate it.
        let mut frontier = original;
        match completion {
            ModeledCompletion::Exact
            | ModeledCompletion::MissingAck
            | ModeledCompletion::UnacceptedRingByte
            | ModeledCompletion::ChangedAdvance => {}
            ModeledCompletion::ForeignOwner => frontier.owner.process += 1,
            ModeledCompletion::ChangedPrefix => frontier.sequence += 1,
            ModeledCompletion::ChangedRingEnd => frontier.ring_end += 1,
            ModeledCompletion::ChangedRequest => frontier.request += 2,
            ModeledCompletion::ChangedRaw => frontier.raw_prefix += 1,
            ModeledCompletion::ChangedLogical => frontier.logical_ps += 1,
            ModeledCompletion::ChangedPlan => frontier.plan_hash[0] ^= 1,
        }
        if frontier != original {
            segment.frontier.store(frontier)?;
        }
        if matches!(completion, ModeledCompletion::UnacceptedRingByte) {
            // Deliberately unaccepted storage, not a new native execution grant.
            stage_with_raw_prefix(&native, authorization, 100, b"X", 1)?;
        }
        let slot = native.node_slot(0)?;
        if matches!(completion, ModeledCompletion::ChangedAdvance) {
            let ceiling = crucible_shmem::authorize_advance_ceiling(100, 100, None)
                .map_err(|_| ConsoleOwnerError::Storage)?;
            slot.publish_scheduler_advance(ceiling, AdvanceStopCondition::Ceiling)?;
        }
        slot.publish_control_boundary(100, 1)?;
        if !matches!(completion, ModeledCompletion::MissingAck) {
            slot.acknowledge_control_boundary();
        }
        Ok(())
    });

    // There is exactly one original handoff call, including negative cases.
    let result = case.runtime.fence_priming_handoff(Duration::from_secs(1));
    let provided = provider.join().map_err(|_| FixtureError::PeerPanicked)?;
    if result.is_ok() {
        provided?;
    } else if let Err(error) = provided {
        // The original RED returns Field before its wake. Preserve that error
        // rather than replacing it with the modeled provider's bounded timeout.
        if !result.as_ref().is_err_and(|error| {
            error
                .to_string()
                .contains("native-console field is invalid")
        }) {
            return Err(error);
        }
    }
    Ok(result)
}

#[test]
fn completed_no_authorization_handoff_preserves_the_genuinely_accepted_prefix()
-> Result<(), FixtureError> {
    let mut case = accepted_console_stop_fixture()?;
    let before = AcceptedState::retain(&case.fixture)?;
    let segment = case.region.native_console_segment(0)?;
    let frontier = segment.frontier.copy()?;
    // This fixture's original publisher owns a separate authorization table.
    // The mapped table remains uncommitted and must not acquire fake AUTH.
    let mapped_authorization = segment.authorization.snapshot();
    let authorization = custody(&case.fixture)?.authorization_snapshot()?;
    let cursor = (segment.ring.read_index(), segment.ring.write_index());
    let prior = case.region.node_slot(0)?.snapshot();

    complete_observation_once(&mut case, ModeledCompletion::Exact)??;

    before.assert_retained(&case.fixture)?;
    let segment = case.region.native_console_segment(0)?;
    let pair = segment.clamp.snapshot()?;
    let after = case.region.node_slot(0)?.snapshot();
    assert_eq!(segment.frontier.copy()?, frontier);
    assert_eq!(segment.authorization.snapshot(), mapped_authorization);
    assert_eq!(
        custody(&case.fixture)?.authorization_snapshot()?,
        authorization
    );
    assert_eq!(
        (segment.ring.read_index(), segment.ring.write_index()),
        cursor
    );
    assert_eq!(pair.kind, NativeConsoleControlKind::Observation);
    assert_eq!(pair.last_issued, None);
    assert_eq!(pair.request, prior.control_boundary_ack.wrapping_add(1));
    assert_eq!(after.control_boundary_ack, pair.request.wrapping_add(1));
    assert_eq!(after.advance_publication_sequence, pair.advance);
    assert_eq!(
        pair.advance,
        prior.advance_publication_sequence.wrapping_add(2)
    );
    assert!(custody(&case.fixture)?.lock()?.clamp.is_none());
    let completed = case
        .runtime
        .completed_quantum_boundary()
        .ok_or(ConsoleOwnerError::Storage)?;
    assert_eq!(completed.console_output_sequence(), None);
    assert_eq!(completed.calibration(), case.boundary.calibration());

    start(&mut case.channel, 200)?;
    let next = custody(&case.fixture)?.authorization_snapshot()?;
    assert_eq!(next.phase, NativeConsolePhase::Grant);
    assert_eq!(
        next.phase_token,
        u64::from(before.request.ok_or(ConsoleOwnerError::Storage)?)
    );
    assert_eq!(next.prior_sequence, before.sequence);
    assert_eq!(next.prior_ring_end, before.ring_end);
    case.fixture.finish()
}

#[test]
fn completed_observation_refuses_changed_native_prefix_and_missing_ack_without_retirement()
-> Result<(), FixtureError> {
    for completion in [
        ModeledCompletion::ForeignOwner,
        ModeledCompletion::ChangedPrefix,
        ModeledCompletion::ChangedRingEnd,
        ModeledCompletion::ChangedRequest,
        ModeledCompletion::ChangedRaw,
        ModeledCompletion::ChangedLogical,
        ModeledCompletion::ChangedPlan,
        ModeledCompletion::UnacceptedRingByte,
        ModeledCompletion::ChangedAdvance,
        ModeledCompletion::MissingAck,
    ] {
        let mut case = accepted_console_stop_fixture()?;
        let before = AcceptedState::retain(&case.fixture)?;
        let segment = case.region.native_console_segment(0)?;
        let cursor = (segment.ring.read_index(), segment.ring.write_index());

        let result = complete_observation_once(&mut case, completion)?;

        assert!(
            result.is_err(),
            "changed modeled completion {completion:?} was accepted"
        );
        assert!(
            !result.as_ref().is_err_and(|error| error
                .to_string()
                .contains("native-console field is invalid")),
            "negative never reached the Observation lifecycle: {completion:?}"
        );
        before.assert_retained(&case.fixture)?;
        let segment = case.region.native_console_segment(0)?;
        let expected_write = if matches!(completion, ModeledCompletion::UnacceptedRingByte) {
            cursor.1 + 1
        } else {
            cursor.1
        };
        assert_eq!(
            (segment.ring.read_index(), segment.ring.write_index()),
            (cursor.0, expected_write)
        );
        assert!(custody(&case.fixture)?.lock()?.clamp.is_some());
        case.fixture.finish()?;
    }
    Ok(())
}

fn assert_unaccepted_empty_clamp_is_refused(
    fixture: &LaunchFixture,
    region: &MappedSetupRegion,
) -> Result<(), FixtureError> {
    let custody = custody(fixture)?;
    {
        let owner = custody.lock()?;
        assert!(owner.issued.is_empty());
        assert!(!owner.accepted.has_accepted_control());
    }
    let slot = region.node_slot(0)?;
    let before = slot.snapshot();
    let segment = region.native_console_segment(0)?;
    let before_pair = segment.clamp.snapshot();
    let before_authorization = segment.authorization.snapshot();
    let before_frontier = segment.frontier.copy();
    let before_cursor = (segment.ring.read_index(), segment.ring.write_index());
    let ceiling = crucible_shmem::authorize_advance_ceiling(
        before.current_icount,
        before.current_icount,
        None,
    )
    .map_err(|_| ConsoleOwnerError::Storage)?;

    let result = custody.publish_clamp(slot, ceiling);

    assert!(matches!(
        result,
        Err(ConsoleOwnerError::Shape(NativeConsoleError::Binding))
    ));
    assert_eq!(slot.snapshot(), before);
    assert_eq!(segment.clamp.snapshot(), before_pair);
    assert_eq!(segment.authorization.snapshot(), before_authorization);
    assert_eq!(segment.frontier.copy(), before_frontier);
    assert_eq!(
        (segment.ring.read_index(), segment.ring.write_index()),
        before_cursor
    );
    assert!(custody.lock()?.clamp.is_none());
    Ok(())
}

#[test]
fn empty_completed_clamp_cannot_bootstrap_or_replace_pending_restore_custody()
-> Result<(), FixtureError> {
    let cold = LaunchFixture::cold(2)?;
    let region = mapped(&cold)?;
    assert_unaccepted_empty_clamp_is_refused(&cold, &region)?;
    cold.finish()?;

    let case = accepted_console_stop_fixture()?;
    {
        let mut owner = custody(&case.fixture)?.lock()?;
        let parts = owner.accepted.checkpoint_parts()?;
        // The real host restore transition deliberately forgets physical ACK
        // authority until its separate native stopped-restore owner rejoins.
        owner.accepted.restore_owned_parts(
            parts.sequence,
            parts.ring_end,
            parts.stream_sequences,
            parts.pending,
        );
        assert!(owner.accepted.restored);
        assert_eq!(owner.accepted.accepted_request, None);
    }
    assert_unaccepted_empty_clamp_is_refused(&case.fixture, &case.region)?;
    case.fixture.finish()
}

#[test]
fn accepted_prefix_observation_cannot_use_a_foreign_mapping() -> Result<(), FixtureError> {
    let case = accepted_console_stop_fixture()?;
    let before = AcceptedState::retain(&case.fixture)?;
    let foreign = LaunchFixture::cold(2)?;
    let foreign_region = mapped(&foreign)?;
    let own_slot = case.region.node_slot(0)?.snapshot();
    let foreign_slot = foreign_region.node_slot(0)?.snapshot();

    let result = custody(&case.fixture)?.request_boundary(&foreign_region, 0, None);

    assert!(matches!(
        result,
        Err(ConsoleOwnerError::Shape(NativeConsoleError::Binding))
    ));
    before.assert_retained(&case.fixture)?;
    assert_eq!(case.region.node_slot(0)?.snapshot(), own_slot);
    assert_eq!(foreign_region.node_slot(0)?.snapshot(), foreign_slot);
    assert!(custody(&case.fixture)?.lock()?.clamp.is_none());
    foreign.finish()?;
    case.fixture.finish()
}

fn refuse_changed_current_coordinate(logical: u64, raw: u64) -> Result<(), FixtureError> {
    let case = accepted_console_stop_fixture()?;
    let retained = AcceptedState::retain(&case.fixture)?;
    let custody = custody(&case.fixture)?;
    let slot = case.region.node_slot(0)?;
    let discovery = slot.snapshot();
    let segment = case.region.native_console_segment(0)?;
    let frontier = segment.frontier.copy()?;
    let cursor = (segment.ring.read_index(), segment.ring.write_index());
    let ceiling = crucible_shmem::authorize_advance_ceiling(100, 100, None)
        .map_err(|_| ConsoleOwnerError::Storage)?;
    custody.publish_clamp(slot, ceiling)?;
    let request = custody.request_boundary(&case.region, 0, None)?;
    let pair = segment.clamp.snapshot()?;
    assert_eq!(pair.kind, NativeConsoleControlKind::Observation);

    // The modeled callback and real coherent cache constructor retain the
    // original clock before a later real publication changes only the slot.
    slot.publish_control_boundary(100, 1)?;
    slot.acknowledge_control_boundary();
    let completed = crate::QemuCompletedQuantumBoundary::accepted(
        case.region.backing_identity(),
        0,
        discovery,
        request,
        0,
        slot.snapshot(),
    )
    .ok_or(ConsoleOwnerError::Storage)?;
    slot.publish_control_boundary(logical, raw)?;

    let result = custody.accept_completed_with_stop(&case.region, completed, None);

    assert!(matches!(
        result,
        Err(ConsoleOwnerError::Shape(NativeConsoleError::Binding))
    ));
    retained.assert_retained(&case.fixture)?;
    assert_eq!(segment.frontier.copy()?, frontier);
    assert_eq!(segment.clamp.snapshot()?, pair);
    assert_eq!(
        (segment.ring.read_index(), segment.ring.write_index()),
        cursor
    );
    assert!(custody.lock()?.clamp.is_some());
    case.fixture.finish()
}

#[test]
fn completed_observation_refuses_changed_current_logical_coordinate() -> Result<(), FixtureError> {
    refuse_changed_current_coordinate(99, 1)
}

#[test]
fn completed_observation_refuses_changed_current_raw_coordinate() -> Result<(), FixtureError> {
    refuse_changed_current_coordinate(100, 2)
}
