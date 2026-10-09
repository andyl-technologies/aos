//! Absolute operational watchdogs for one original native fixture wait.

use super::*;

/// Keeps one wall-clock limit across original frame filtering and queue drains.
pub(super) struct OriginalDeadline(Instant);

impl OriginalDeadline {
    /// Starts the fixed operational lifetime of one original wait.
    // crucible-lint: allow clippy-disallowed-method -- This fixture watchdog never participates in native modeled time.
    #[allow(clippy::disallowed_methods)]
    pub(super) fn after(duration: Duration) -> Self {
        Self(Instant::now() + duration)
    }

    /// Starts the ten-second original native fixture watchdog.
    pub(super) fn native() -> Self {
        Self::after(Duration::from_secs(10))
    }

    // Check before AND after the native read: an always-ready queue must not
    // bypass the deadline, and late frames cannot turn timeout into success.
    /// Refuses an expired original wait without resetting its deadline.
    ///
    /// # Errors
    /// Returns `TimedOut` once the original wall-clock deadline is reached.
    // crucible-lint: allow clippy-disallowed-method -- This fixture watchdog never participates in native modeled time.
    #[allow(clippy::disallowed_methods)]
    pub(super) fn check(&self) -> Result<(), Box<dyn Error>> {
        if Instant::now() >= self.0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original native fixture deadline expired",
            )
            .into());
        }
        Ok(())
    }

    /// Filters original validated frames under the same absolute watchdog.
    ///
    /// # Errors
    /// Propagates native polling or child supervision errors and returns
    /// `TimedOut` when the original deadline expires, even on a ready queue.
    pub(super) fn next_matching(
        &self,
        mut poll: impl FnMut() -> Result<Option<NativeFrame>, Box<dyn Error>>,
        mut check_child: impl FnMut() -> Result<(), Box<dyn Error>>,
        accept: impl Fn(&NativeFrame) -> bool,
    ) -> Result<NativeFrame, Box<dyn Error>> {
        loop {
            self.check()?;
            let frame = poll()?;
            self.check()?;
            if let Some(frame) = frame {
                if accept(&frame) {
                    return Ok(frame);
                }
            } else {
                check_child()?;
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    /// Drains a finite original queue without extending the wait's deadline.
    ///
    /// # Errors
    /// Propagates polling errors or returns `TimedOut` when continuous incoming
    /// frames prevent the original queue from becoming empty before the limit.
    pub(super) fn drain(
        &self,
        mut poll: impl FnMut() -> Result<Option<NativeFrame>, Box<dyn Error>>,
        mut observe: impl FnMut(&NativeFrame),
    ) -> Result<(), Box<dyn Error>> {
        loop {
            self.check()?;
            let frame = poll()?;
            self.check()?;
            let Some(frame) = frame else {
                return Ok(());
            };
            observe(&frame);
        }
    }
}

/// Checks the same owned native child's liveness.
///
/// # Errors
/// Propagates kernel wait errors or refuses an exited original child.
pub(super) fn check_child(child: &mut Child) -> Result<(), Box<dyn Error>> {
    if let Some(status) = child.try_wait()? {
        return Err(io::Error::other(format!("native QEMU exited early: {status}")).into());
    }
    Ok(())
}

/// Identifies execution receipts without treating administrative facts as one.
pub(super) fn is_execution_frame(frame: &NativeFrame) -> bool {
    !matches!(
        frame,
        NativeFrame::CpuPark(_)
            | NativeFrame::WriterChunk(_)
            | NativeFrame::PhaseTimerChunk(_)
            | NativeFrame::InitializationCut(_)
            | NativeFrame::InitializationStopped(_)
            | NativeFrame::InitializationAcknowledged(_)
    )
}

#[test]
fn continuous_validated_administrative_frames_cannot_extend_original_deadline()
-> Result<(), Box<dyn Error>> {
    use crucible_protocol::node_control::{NativeChannel, NativeCpuParkFacts};

    let (mut native, endpoint) = NativeQemuControlTransport::prepare(NativePreparation {
        scope: original(1, 0, 110).scope,
        boundary: position(0),
        maximum_commands: U64::new(4),
    })?;
    let park = NativeCpuParkFacts {
        coverage: 1,
        cpu_count: 1,
        current_ps: U64::new(0),
        retired_count: U64::new(0),
        next_service_deadline_ps: None,
        pending_service_credit_ps: U64::new(0),
        prepared_scope_hash: *endpoint.scope_digest(),
        roster_sha256: [1; 32],
    };
    let provider = NativeChannel::from_prepared_socket(endpoint.into_socket())?;
    assert!(matches!(provider.receive()?, Some(NativeFrame::Prepare(_))));
    let frame = NativeFrame::CpuPark(park.clone());
    assert!(provider.send(&frame)?);
    assert_eq!(native.poll_original()?, Some(frame.clone()));

    // This is a mechanical socket peer, never a qualified QEMU capability.
    // Each read validates the same actual protocol frame and replenishes it,
    // leaving a continuously ready discarded-frame source without test reruns.
    let deadline = OriginalDeadline::after(Duration::from_millis(100));
    let result = deadline.next_matching(
        || {
            assert!(provider.send(&frame)?);
            Ok(native.poll_original()?)
        },
        || Ok(()),
        is_execution_frame,
    );
    let error = result
        .err()
        .ok_or("continuous frame source unexpectedly completed")?;
    assert_eq!(
        error.downcast_ref::<io::Error>().map(io::Error::kind),
        Some(io::ErrorKind::TimedOut)
    );
    assert_eq!(native.prepared_cpu_park(), Some(&park));

    Ok(())
}

#[test]
fn continuously_ready_drain_checks_the_same_original_deadline() -> Result<(), Box<dyn Error>> {
    let deadline = OriginalDeadline::after(Duration::from_millis(20));
    let result = deadline.drain(
        || {
            Ok(Some(NativeFrame::CpuPark(
                crucible_protocol::node_control::NativeCpuParkFacts {
                    coverage: 1,
                    cpu_count: 1,
                    current_ps: U64::new(0),
                    retired_count: U64::new(0),
                    next_service_deadline_ps: None,
                    pending_service_credit_ps: U64::new(0),
                    prepared_scope_hash: [1; 32],
                    roster_sha256: [1; 32],
                },
            )))
        },
        |_| {},
    );
    let error = result
        .err()
        .ok_or("continuous drain unexpectedly completed")?;
    assert_eq!(
        error.downcast_ref::<io::Error>().map(io::Error::kind),
        Some(io::ErrorKind::TimedOut)
    );
    Ok(())
}
