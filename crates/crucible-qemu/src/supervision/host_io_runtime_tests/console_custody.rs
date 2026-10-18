//! Genuine runtime clamp/request custody with external console phase admission.

use super::*;
use crate::QemuShmemHotPathChannel;
use crate::native_console_owner::tests::{FixtureError, LaunchFixture};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;

#[test]
fn real_clamp_and_request_retain_exact_custody_when_eventfd_write_fails() -> Result<(), FixtureError>
{
    let fixture = LaunchFixture::new(3)?;
    let mut hot_path = fixture.hot_path()?;
    QemuShmemHotPathChannel::start_quantum(
        &mut hot_path,
        crucible::ExecutionHorizon {
            icount: crucible::Icount { retired: 100 },
        },
        crucible_shmem::AdvanceStopCondition::Ceiling,
    )?;
    let (reader, wake) = UnixStream::pair()?;
    let mut runtime = QemuLiveHostIoRuntime::from_shmem_fd(
        fixture.setup.shmem_as_fd(),
        wake.as_fd(),
        fixture.setup.region().region_len,
        0,
    )?;
    runtime.retain_console_launch(&fixture.setup)?;
    drop(reader);
    let snapshot = runtime
        .region
        .node_slot(0)
        .map_err(map_slot_error)?
        .snapshot();

    // The actual clamp and request publish before the original failed write.
    assert!(
        runtime
            .clamp_completed_quantum(&snapshot, Duration::from_secs(1))
            .is_err()
    );
    let (advance, request, issued_through, last_issued) = fixture.retained_fence()?;
    assert_eq!(advance, 4);
    assert_eq!(request, Some(2));
    assert_eq!(issued_through, 1);
    assert_eq!(last_issued.map(|body| body.advance), Some(2));
    let paired = runtime
        .region
        .native_console_clamp_for_request(0)
        .map_err(crate::native_console_owner::ConsoleOwnerError::from)?;
    assert_eq!(paired.request, 2);
    assert_eq!(paired.advance, advance);
    assert_eq!(paired.last_issued, last_issued);
    assert_eq!(paired.ceiling, snapshot.current_icount);

    let observed = runtime
        .region
        .node_slot(0)
        .map_err(map_slot_error)?
        .snapshot();
    assert_eq!(observed.advance_publication_sequence, advance);
    assert_eq!(
        observed.control_boundary_ack,
        request.ok_or_else(|| FixtureError::Peer("missing request custody".into()))?
    );

    // Repeating the same original request never replaces the fence or receipt.
    assert!(runtime.signal_wake(None).is_err());
    assert_eq!(
        fixture.retained_fence()?,
        (advance, request, issued_through, last_issued)
    );
    fixture.finish()
}
