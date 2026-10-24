//! QEMU child exit-status ownership regressions.

use std::error::Error;
use std::process::Command;

use rustix::process::{Pid, WaitId, WaitIdOptions, waitid};

use super::*;
use crate::node::source_child::OwnedNodeChild;

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
    assert!(matches!(
        child.try_wait_natural_exit_raw(),
        Err(ChildNaturalWaitFailure::AlreadyReaped)
    ));
    let refusal = child
        .try_wait_natural_exit()
        .expect_err("the public poll still refuses an already reaped child");
    assert_eq!(refusal.operation, "poll natural QEMU exit");
    assert_eq!(refusal.message, "child was already reaped");
    assert_eq!(
        refusal.to_string(),
        "poll natural QEMU exit failed: child was already reaped"
    );
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

#[test]
fn helper_poll_retains_the_actual_wait_error_without_boxing() -> Result<(), Box<dyn Error>> {
    struct ReapedOnDrop<'a>(&'a mut QemuNodeChild);

    impl Drop for ReapedOnDrop<'_> {
        fn drop(&mut self) {
            self.0.mark_reaped();
        }
    }

    let child = Command::new("true").spawn()?;
    let mut child = QemuNodeChild::new(child);
    wait_for_test_child_exit_pending(&child)?;
    let pid = match &child.child {
        OwnedNodeChild::Ordinary(child) => Pid::from_child(child),
        #[cfg(target_os = "linux")]
        OwnedNodeChild::Source(_) | OwnedNodeChild::Transferred => {
            return Err("fixture requires an ordinary child".into());
        }
    };
    let (waited, _) = rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty())?
        .ok_or("blocking waitpid returned no child")?;
    // Retain this test's actual wait receipt through every assertion/unwind;
    // the wrapper must remain unmarked only while testing the real ECHILD cut.
    let reaped = ReapedOnDrop(&mut child);
    assert_eq!(waited, pid);

    let result = reaped.0.try_wait_natural_exit_raw();
    let (public_result, public_counts) =
        crucible_host_resources::test_support::TestAllocationObserver::count(|| {
            reaped.0.try_wait_natural_exit()
        });
    let (bounded_result, counts) =
        crucible_host_resources::test_support::TestAllocationObserver::count(|| {
            crate::shutdown::wait_child_raw(&mut reaped.0.child, Duration::ZERO)
        });

    let bounded_error = bounded_result.expect_err("the actual wait owner observes kernel ECHILD");
    assert_eq!(bounded_error.raw_os_error(), Some(libc::ECHILD));
    assert!(bounded_error.get_ref().is_none());
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);

    let failure = result.expect_err("the kernel child was already reaped externally");
    let crate::QemuSpawnError::Io { operation, source } =
        crate::QemuSpawnError::from_helper_wait("poll helper fixture", failure)
    else {
        panic!("actual ECHILD must retain the original I/O error");
    };
    assert_eq!(operation, "poll helper fixture");
    assert_eq!(source.raw_os_error(), Some(libc::ECHILD));
    assert!(
        source.get_ref().is_none(),
        "the OS error was not boxed text"
    );
    let public = public_result.expect_err("the public poll retains the kernel ECHILD cause");
    assert_eq!(public.operation, "poll natural QEMU exit");
    assert!(public.message.is_empty());
    assert_eq!(public.io_source().unwrap().raw_os_error(), Some(libc::ECHILD));
    assert!(public.io_source().unwrap().get_ref().is_none());
    assert_eq!(public_counts.allocations, 0);
    assert_eq!(public_counts.reallocations, 0);
    assert!(!public_counts.overflow);
    assert_eq!(
        public.to_string(),
        format!("poll natural QEMU exit failed: {source}"),
    );
    drop(reaped);
    assert!(child.reaped());
    Ok(())
}

fn wait_for_test_child_exit_pending(child: &QemuNodeChild) -> Result<(), Box<dyn Error>> {
    let pid = match &child.child {
        OwnedNodeChild::Ordinary(child) => Pid::from_child(child),
        #[cfg(target_os = "linux")]
        OwnedNodeChild::Source(_) | OwnedNodeChild::Transferred => {
            return Err("fixture requires an ordinary child".into());
        }
    };
    waitid(
        WaitId::Pid(pid),
        WaitIdOptions::EXITED | WaitIdOptions::NOWAIT,
    )?
    .ok_or("waitid returned no status for a blocking child-exit wait")?;
    Ok(())
}
