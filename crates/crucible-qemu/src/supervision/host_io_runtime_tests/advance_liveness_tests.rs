//! Tests the original advance watchdog and bounded host liveness yields.

use super::*;

// crucible-lint: allow clippy-disallowed-method -- this test measures host wait liveness only; elapsed time never enters modeled state.
#[allow(clippy::disallowed_methods)]
#[test]
fn advance_completion_poll_respects_elapsed_host_deadline() -> Result<(), Box<dyn std::error::Error>>
{
    use std::io::Write;
    use std::os::fd::AsFd;
    use std::time::Instant;

    let allocation =
        crucible_shmem::RegionAllocation::new_model(crucible_shmem::RegionConfig::new(1, 2))?;
    let layout = allocation.layout();
    let bytes = allocation.setup_region_bytes()?;
    let mut shmem = std::fs::File::from(crate::spawn::memfd_region(layout.region_size)?);
    shmem.write_all(&bytes)?;
    let plugin = crucible_shmem::mmap_setup_region(shmem.as_fd(), layout.region_size)?;
    let ceiling = authorize_advance_ceiling(0, 100, None)?;
    let slot = plugin.node_slot(0)?;
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)?;
    slot.publish_reached_icount(0)?;

    let wake = tempfile::tempfile()?;
    let mut runtime = QemuLiveHostIoRuntime::from_shmem_fd_with_poll_interval(
        shmem.as_fd(),
        wake.as_fd(),
        layout.region_size,
        0,
        Duration::from_nanos(1),
    )?;
    let timeout = Duration::from_millis(30);
    let started = Instant::now();

    let outcome = runtime.await_child(QemuAsyncWait::AdvanceCompletion, timeout)?;

    assert_eq!(outcome, QemuAsyncWaitOutcome::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(1));
    Ok(())
}

// crucible-lint: allow clippy-disallowed-method -- elapsed host time checks the original watchdog, never virtual coordinates or replay evidence.
#[allow(clippy::disallowed_methods)]
#[test]
fn advance_completion_poll_slices_retain_the_original_absolute_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    use std::os::fd::AsFd;
    use std::time::Instant;

    let allocation =
        crucible_shmem::RegionAllocation::new_model(crucible_shmem::RegionConfig::new(1, 2))?;
    let layout = allocation.layout();
    let mut shmem = std::fs::File::from(crate::spawn::memfd_region(layout.region_size)?);
    shmem.write_all(&allocation.setup_region_bytes()?)?;
    let plugin = crucible_shmem::mmap_setup_region(shmem.as_fd(), layout.region_size)?;
    let ceiling = authorize_advance_ceiling(0, 100, None)?;
    plugin
        .node_slot(0)?
        .publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)?;
    plugin.node_slot(0)?.publish_reached_icount(0)?;
    let wake = tempfile::tempfile()?;
    let mut runtime =
        QemuLiveHostIoRuntime::from_shmem_fd(shmem.as_fd(), wake.as_fd(), layout.region_size, 0)?;
    assert!(
        runtime
            .set_advance_completion_poll_slice(Some(Duration::ZERO))
            .is_err()
    );
    assert_eq!(runtime.advance_completion_poll_slice, None);
    runtime.set_advance_completion_poll_slice(Some(Duration::from_millis(2)))?;
    let budget = Duration::from_millis(20);
    let started = Instant::now();
    let mut outcome = runtime.await_child(QemuAsyncWait::AdvanceCompletion, budget)?;

    while outcome != QemuAsyncWaitOutcome::TimedOut && started.elapsed() < Duration::from_secs(1) {
        assert_eq!(outcome, QemuAsyncWaitOutcome::Pending);
        outcome = runtime.repoll_child(QemuAsyncWait::AdvanceCompletion, budget)?;
    }

    assert_eq!(outcome, QemuAsyncWaitOutcome::TimedOut);
    assert!(started.elapsed() >= budget);
    assert_eq!(plugin.node_slot(0)?.snapshot().current_icount, 0);
    assert!(runtime.completed_boundary.is_none());
    runtime.set_advance_completion_poll_slice(None)?;
    assert_eq!(runtime.advance_completion_poll_slice, None);

    // A fresh advance still observes a genuine mapped terminal publication
    // before yielding an expired local slice. Pending invents no such state.
    plugin
        .node_slot(0)?
        .publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)?;
    runtime.set_advance_completion_poll_slice(Some(Duration::from_nanos(1)))?;
    assert_eq!(
        runtime.await_child(QemuAsyncWait::AdvanceCompletion, Duration::from_secs(1))?,
        QemuAsyncWaitOutcome::Pending,
    );
    plugin.node_slot(0)?.mark_done();
    assert_eq!(
        runtime.repoll_child(QemuAsyncWait::AdvanceCompletion, Duration::from_secs(1))?,
        QemuAsyncWaitOutcome::Completed,
    );
    Ok(())
}
