//! Original mapped runtime request handoff with a CAS-minted modeled writer.
//!
//! These controls exercise host custody, one clamp, its request and paired ACK.
//! Claim `2` models only the public native-writer reservation. It supplies no
//! QEMU callback, READY phase, physical execution or stopped-output authority.

use super::*;
use std::num::NonZeroU32;
use std::sync::mpsc;

use crucible_protocol::native_console::NativeConsoleClamp;
use crucible_shmem::{ModeledControlBoundaryPublication, NodeSlotSnapshot};

struct ClampCase {
    fixture: LaunchFixture,
    region: MappedSetupRegion,
    runtime: crate::QemuLiveHostIoRuntime,
    notifications: UnixStream,
    discovery: NodeSlotSnapshot,
    authorization: NativeConsoleAuthorization,
    original_pair: Result<NativeConsoleClamp, NativeConsoleError>,
}

impl ClampCase {
    fn new() -> Result<Self, FixtureError> {
        let fixture = LaunchFixture::cold(2)?;
        let region = mapped(&fixture)?;
        let mut channel = fixture.hot_path()?;
        start(&mut channel, 50)?;
        let authorization = custody(&fixture)?.authorization_snapshot()?;
        let slot = region.node_slot(0)?;
        slot.publish_reached_icount(50)?;
        let discovery = slot.snapshot();
        let original_pair = region.native_console_segment(0)?.clamp.snapshot();

        let (notifications, wake) = UnixStream::pair()?;
        notifications.set_read_timeout(Some(Duration::from_secs(1)))?;
        let mut runtime = crate::QemuLiveHostIoRuntime::from_shmem_fd(
            fixture.setup.shmem_as_fd(),
            wake.as_fd(),
            fixture.setup.region().region_len,
            0,
        )?;
        runtime.retain_console_launch(&fixture.setup)?;

        Ok(Self {
            fixture,
            region,
            runtime,
            notifications,
            discovery,
            authorization,
            original_pair,
        })
    }

    fn assert_unpublished(
        &self,
        writer: &ModeledControlBoundaryPublication<'_>,
    ) -> Result<(), FixtureError> {
        let slot = self.region.node_slot(0)?;
        assert_ne!(writer.observed_claim(), 0);
        assert!(slot.try_snapshot().is_none());
        self.assert_retained_without_request()
    }

    fn assert_retained_without_request(&self) -> Result<(), FixtureError> {
        let slot = self.region.node_slot(0)?;
        assert_eq!(
            slot.control_boundary_token(),
            self.discovery.control_boundary_ack
        );
        assert_eq!(slot.control_boundary_fault_command_frontier(), 0);
        assert_eq!(
            self.region.native_console_segment(0)?.clamp.snapshot(),
            self.original_pair
        );
        assert_eq!(
            custody(&self.fixture)?.authorization_snapshot()?,
            self.authorization
        );

        let (advance, request, issued, last) = self.fixture.retained_fence()?;
        assert_eq!(advance, self.discovery.advance_publication_sequence + 2);
        assert_eq!(request, None);
        assert_eq!(issued, 1);
        assert_eq!(last, Some(self.authorization));
        assert!(self.runtime.completed_quantum_boundary().is_none());
        Ok(())
    }
}

fn modeled_writer(
    slot: &crucible_shmem::NodeSlot,
    value: u32,
) -> Result<ModeledControlBoundaryPublication<'_>, FixtureError> {
    let value = NonZeroU32::new(value)
        .unwrap_or_else(|| panic!("modeled competitor must have a nonzero claim"));
    Ok(slot.try_claim_control_boundary_publication_for_test(value)?)
}

enum RequestWindow {
    NativeUnavailable,
    FailedOriginalCall,
}

#[test]
fn single_original_clamp_waits_for_modeled_native_release_then_exact_ack()
-> Result<(), FixtureError> {
    let mut case = ClampCase::new()?;
    let native = mapped(&case.fixture)?;
    let slot = case.region.node_slot(0)?;
    let plan_hash = custody(&case.fixture)?.lock()?.accepted.plan.digest()?;
    let authorization = case.authorization;
    let discovery = case.discovery;
    let original_pair = case.original_pair;
    let original_publication = custody(&case.fixture)?.lock()?.next_clamp_publication;
    let mut notifications = case.notifications.try_clone()?;
    let (claimed_tx, claimed_rx) = mpsc::sync_channel(1);
    let (window_tx, window_rx) = mpsc::sync_channel(1);
    let (released_tx, released_rx) = mpsc::sync_channel(1);
    let hook_window = window_tx.clone();

    case.runtime
        .on_native_publication_unavailable_for_test(move |_deadline| {
            hook_window
                .send(RequestWindow::NativeUnavailable)
                .unwrap_or_else(|error| panic!("original request window: {error}"));
            released_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap_or_else(|error| panic!("modeled release rendezvous: {error}"));
        });
    let provider = std::thread::spawn(move || -> Result<bool, FixtureError> {
        let slot = native.node_slot(0)?;
        let writer = modeled_writer(slot, 2)?;
        claimed_tx
            .send(())
            .map_err(|error| FixtureError::Peer(error.to_string()))?;
        let window = window_rx
            .recv_timeout(Duration::from_secs(1))
            .map_err(|error| FixtureError::Peer(error.to_string()))?;
        if matches!(window, RequestWindow::FailedOriginalCall) {
            // The RED original returns before the hook. Reap this same provider
            // without obscuring the actual original refusal or repeating the clamp.
            drop(writer);
            return Ok(false);
        }

        assert_eq!(writer.observed_claim(), 2);
        assert!(slot.try_snapshot().is_none());
        assert_eq!(
            slot.control_boundary_token(),
            discovery.control_boundary_ack
        );
        assert_eq!(
            slot.load_scheduler_advance_publication()?.sequence(),
            discovery.advance_publication_sequence + 2
        );
        assert_eq!(
            native.native_console_segment(0)?.clamp.snapshot(),
            original_pair
        );
        drop(writer);
        assert!(slot.try_snapshot().is_some());
        released_tx
            .send(())
            .map_err(|error| FixtureError::Peer(error.to_string()))?;

        let mut counter = [0; 8];
        notifications.read_exact(&mut counter)?;
        assert_eq!(u64::from_ne_bytes(counter), 1);
        // The wake must occur after the shared claim closed, and after its one
        // full pair was retained. The frontier below is an external provider.
        let snapshot = slot.try_snapshot().ok_or(ConsoleOwnerError::Storage)?;
        let segment = native.native_console_segment(0)?;
        let pair = segment.clamp.snapshot()?;
        assert_eq!(pair.request, discovery.control_boundary_ack + 1);
        assert_eq!(pair.advance, discovery.advance_publication_sequence + 2);
        assert_eq!(pair.last_issued, Some(authorization));
        assert_eq!(snapshot.control_boundary_ack, pair.request);
        segment.frontier.store(NativeConsoleFrontier {
            sequence: 0,
            ring_end: 0,
            logical_ps: 50,
            raw_prefix: 1,
            owner: authorization.owner,
            accepted_advance: pair.advance,
            logical_generation: authorization.logical_generation,
            request: pair.request,
            plan_hash,
        })?;
        slot.publish_control_boundary(50, 1)?;
        assert_eq!(slot.acknowledge_control_boundary(), pair.request + 1);
        Ok(true)
    });
    let claimed = claimed_rx.recv_timeout(Duration::from_secs(1));
    let result = if claimed.is_ok() {
        // Exactly one original clamp invocation. Its unavailable acquisition
        // must preserve the already-issued ceiling, original body and deadline.
        case.runtime
            .clamp_completed_quantum_for_test(&discovery, Duration::from_secs(1))
    } else {
        drop(window_tx);
        let peer = provider.join().map_err(|_| FixtureError::PeerPanicked)?;
        peer?;
        return Err(FixtureError::Peer(
            "modeled writer failed before acquisition".into(),
        ));
    };
    if result.is_err() {
        let _ = window_tx.try_send(RequestWindow::FailedOriginalCall);
    }
    let peer = provider.join().map_err(|_| FixtureError::PeerPanicked)?;
    // Preserve the original runtime error on the RED source; a provider's
    // cleanup result cannot turn that failure into a generic rendezvous error.
    if let Err(error) = result {
        case.fixture.finish()?;
        return Err(error.into());
    }
    assert!(peer?);

    let observed = slot.snapshot();
    assert_eq!(
        observed.advance_publication_sequence,
        discovery.advance_publication_sequence + 2
    );
    assert_eq!(
        observed.control_boundary_ack,
        discovery.control_boundary_ack + 2
    );
    let boundary = case
        .runtime
        .completed_quantum_boundary()
        .ok_or(ConsoleOwnerError::Storage)?;
    assert_eq!(boundary.calibration().logical_icount, 50);
    assert_eq!(boundary.calibration().raw_icount, 1);
    assert_eq!(
        custody(&case.fixture)?.authorization_snapshot()?,
        authorization
    );
    {
        let owner = custody(&case.fixture)?.lock()?;
        assert!(owner.issued.is_empty());
        assert_eq!(owner.next_clamp_publication, original_publication + 2);
    }
    assert_eq!(case.region.native_console_segment(0)?.ring.read_index(), 0);
    case.fixture.finish()
}

#[test]
fn original_clamp_deadline_refuses_held_native_without_request_or_pair() -> Result<(), FixtureError>
{
    let mut case = ClampCase::new()?;
    let writer = modeled_writer(case.region.node_slot(0)?, 2)?;
    let error = case
        .runtime
        .clamp_completed_quantum_for_test(&case.discovery, Duration::ZERO)
        .err()
        .ok_or(ConsoleOwnerError::Storage)?;
    assert!(
        error
            .to_string()
            .contains("acknowledge completed-quantum clamp")
    );
    assert!(error.to_string().contains("requested token unpublished"));
    assert_eq!(writer.observed_claim(), 2);
    case.assert_unpublished(&writer)?;
    drop(writer);
    assert!(case.region.node_slot(0)?.try_snapshot().is_some());
    // Never repeat the timed-out clamp or fabricate its missing request.
    case.fixture.finish()
}

#[test]
fn original_clamp_host_and_unknown_claims_remain_fatal() -> Result<(), FixtureError> {
    for competitor in [1, 7] {
        let mut case = ClampCase::new()?;
        let writer = modeled_writer(case.region.node_slot(0)?, competitor)?;
        let error = case
            .runtime
            .clamp_completed_quantum_for_test(&case.discovery, Duration::from_secs(1))
            .err()
            .ok_or(ConsoleOwnerError::Storage)?;
        assert!(error.to_string().contains("retain console request"));
        assert!(error.to_string().contains("control boundary publication"));
        assert_eq!(writer.observed_claim(), competitor);
        case.assert_unpublished(&writer)?;
        drop(writer);
        assert!(case.region.node_slot(0)?.try_snapshot().is_some());
        case.fixture.finish()?;
    }
    Ok(())
}

#[test]
fn original_clamp_never_commits_when_native_release_follows_deadline_expiry()
-> Result<(), FixtureError> {
    let mut case = ClampCase::new()?;
    let native = mapped(&case.fixture)?;
    let (claimed_tx, claimed_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let (released_tx, released_rx) = mpsc::sync_channel(1);

    case.runtime
        .on_native_publication_unavailable_for_test(move |deadline| {
            // Observe the same borrowed deadline used by the original clamp. No
            // sleep duration, newly started clock or renewed budget is an oracle.
            while deadline.has_time_remaining() {
                std::thread::yield_now();
            }
            assert!(
                deadline
                    .remaining()
                    .is_none_or(|remaining| remaining.is_zero())
            );
            release_tx
                .send(())
                .unwrap_or_else(|error| panic!("late release: {error}"));
            released_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap_or_else(|error| panic!("late release completion: {error}"));
        });
    let provider = std::thread::spawn(move || -> Result<(), FixtureError> {
        let slot = native.node_slot(0)?;
        let writer = modeled_writer(slot, 2)?;
        claimed_tx
            .send(())
            .map_err(|error| FixtureError::Peer(error.to_string()))?;
        release_rx
            .recv_timeout(Duration::from_secs(1))
            .map_err(|error| FixtureError::Peer(error.to_string()))?;
        assert_eq!(writer.observed_claim(), 2);
        assert!(slot.try_snapshot().is_none());
        drop(writer);
        assert!(slot.try_snapshot().is_some());
        released_tx
            .send(())
            .map_err(|error| FixtureError::Peer(error.to_string()))?;
        Ok(())
    });
    let claimed = claimed_rx.recv_timeout(Duration::from_secs(1));
    let result = if claimed.is_ok() {
        case.runtime
            .clamp_completed_quantum_for_test(&case.discovery, Duration::from_millis(1))
    } else {
        let peer = provider.join().map_err(|_| FixtureError::PeerPanicked)?;
        peer?;
        return Err(FixtureError::Peer(
            "late-release writer failed before acquisition".into(),
        ));
    };
    let peer = provider.join().map_err(|_| FixtureError::PeerPanicked)?;
    peer?;
    let error = result.err().ok_or(ConsoleOwnerError::Storage)?;
    assert!(
        error
            .to_string()
            .contains("acknowledge completed-quantum clamp")
    );
    assert!(error.to_string().contains("requested token unpublished"));
    assert!(case.region.node_slot(0)?.try_snapshot().is_some());
    case.assert_retained_without_request()?;

    case.notifications.set_nonblocking(true)?;
    let mut counter = [0; 8];
    assert!(matches!(case.notifications.read(&mut counter),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock));
    case.fixture.finish()
}
