//! QEMU child exit-status ownership regressions.

use std::error::Error;
use std::process::Command;

use rustix::process::{Pid, WaitId, WaitIdOptions, waitid};

use super::*;

#[test]
fn child_poll_preserves_clean_exit_status_and_disarms_drop_cleanup() -> Result<(), Box<dyn Error>> {
    let child = Command::new("true").spawn()?;
    let mut child = QemuNodeChild::new(child);
    wait_for_test_child_exit_pending(&child)?;
    let status = child
        .try_wait_natural_exit()?
        .ok_or("child remained live after closing its output pipe")?;

    assert!(status.success());
    assert!(child.reaped());
    drop(child);
    Ok(())
}

#[cfg(unix)]
#[test]
fn child_poll_preserves_signal_termination_as_unclean() -> Result<(), Box<dyn Error>> {
    use std::os::unix::process::ExitStatusExt as _;

    let child = Command::new("sleep").arg("60").spawn()?;
    let mut child = QemuNodeChild::new(child);
    signal_child(
        child.child.id(),
        libc::SIGTERM,
        "terminate child test fixture",
    )?;
    wait_for_test_child_exit_pending(&child)?;
    let status = child
        .try_wait_natural_exit()?
        .ok_or("signaled child remained live after closing its output pipe")?;

    assert!(!status.success());
    assert_eq!(status.signal(), Some(libc::SIGTERM));
    assert!(child.reaped());
    Ok(())
}

#[test]
fn failed_helper_cleanup_reaps_original_child_and_is_idempotent() -> Result<(), Box<dyn Error>> {
    let child = Command::new("sleep").arg("60").spawn()?;
    let mut child = QemuNodeChild::new(child);
    let process_id = child.process_id();

    // A zero deadline can leave cleanup pending; retry must use the original
    // Child instead of rediscovering wait authority from a process number.
    let _first_cleanup = child.force_kill_and_reap_failed_helper(Duration::ZERO);
    child.force_kill_and_reap_failed_helper(Duration::from_secs(5))?;

    assert_eq!(child.process_id(), process_id);
    assert!(child.reaped());
    child.force_kill_and_reap_failed_helper(Duration::ZERO)?;
    assert!(child.try_wait_natural_exit().is_err());
    Ok(())
}

fn wait_for_test_child_exit_pending(child: &QemuNodeChild) -> Result<(), Box<dyn Error>> {
    let pid = Pid::from_child(&child.child);
    waitid(
        WaitId::Pid(pid),
        WaitIdOptions::EXITED | WaitIdOptions::NOWAIT,
    )?
    .ok_or("waitid returned no status for a blocking child-exit wait")?;
    Ok(())
}
