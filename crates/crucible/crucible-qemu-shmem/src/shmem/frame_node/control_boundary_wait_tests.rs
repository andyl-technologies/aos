//! Real shared-futex race, counter, deadline and signal controls.
//!
//! The signal case runs alone in a fresh copy of the current test executable.
//! Peer parking is proven by a kernel wake count, never by an assumed delay.
//! Test-only wake probes are not production polling or execution authority.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, mpsc};
use std::time::Instant;

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Bounds only test-kernel rendezvous, never a modeled deadline or state.
// crucible-lint: allow clippy-disallowed-method -- host time bounds isolated futex controls and never enters modeled state.
#[allow(clippy::disallowed_methods)]
fn test_host_now() -> Instant {
    Instant::now()
}

#[test]
fn completed_ack_and_load_to_park_race_do_not_block() -> TestResult {
    let slot = NodeSlot::new(KIND_VM);
    let request = slot.request_control_boundary(0, None)?;
    let expected = slot.control_boundary_token();
    assert_eq!(expected, request);
    assert_eq!(slot.acknowledge_control_boundary_and_notify()?, request + 1);

    assert_eq!(
        slot.wait_control_boundary_ack(expected, Duration::from_secs(1))?,
        ControlBoundaryWaitOutcome::ValueChanged
    );
    assert_eq!(slot.control_boundary_token(), request + 1);
    assert_eq!(slot.acknowledge_control_boundary_and_notify()?, request + 1);
    assert_eq!(
        slot.wait_control_boundary_ack(request, Duration::ZERO)?,
        ControlBoundaryWaitOutcome::ValueChanged
    );
    Ok(())
}

/// Proves parking from the kernel count, with a finite test-only probe budget.
fn wake_parked(slot: &NodeSlot) -> TestResult {
    let limit = test_host_now() + Duration::from_secs(2);
    while test_host_now() < limit {
        if futex::futex_wake_nonprivate(&slot.control_boundary_ack, 1)?.waiters_woken == 1 {
            return Ok(());
        }
        std::thread::yield_now();
    }
    Err("the kernel never observed the test waiter parked".into())
}

#[test]
fn parked_waiter_spurious_wake_preserves_request_then_real_producer_completes() -> TestResult {
    let allocation = crate::RegionAllocation::new_model(crate::RegionConfig::new(1, 4))?;
    let file = mapped_ack_file(&allocation)?;
    let host = crate::mmap_setup_region(file.as_fd(), allocation.layout().region_size)?;
    let producer = crate::mmap_setup_region(file.as_fd(), allocation.layout().region_size)?;
    let slot = producer.node_slot(0)?;
    assert!(!std::ptr::eq(host.node_slot(0)?, slot));
    let request = slot.request_control_boundary(0, None)?;
    let (woken, observed) = mpsc::channel();
    let waiter = std::thread::spawn(move || -> Result<_, String> {
        let peer = host.node_slot(0).map_err(|error| error.to_string())?;
        let first = peer
            .wait_control_boundary_ack(request, Duration::from_secs(2))
            .map_err(|error| error.to_string())?;
        let token = peer.control_boundary_token();
        woken
            .send((first, token))
            .unwrap_or_else(|error| panic!("test receiver closed: {error}"));
        peer.wait_control_boundary_ack(request, Duration::from_secs(2))
            .map_err(|error| error.to_string())
    });

    let observation = (|| -> TestResult {
        // A wake with no release is advisory: it cannot manufacture an odd ACK.
        wake_parked(slot)?;
        if observed.recv_timeout(Duration::from_secs(2))?
            != (ControlBoundaryWaitOutcome::Woken, request)
        {
            return Err("spurious wake changed or completed the original request".into());
        }
        if slot.acknowledge_control_boundary_and_notify()? != request + 1 {
            return Err("the original notification published a different ACK".into());
        }
        Ok(())
    })();
    let result = waiter.join().map_err(|_| "test waiter panicked")?;
    observation?;
    let result = result?;
    assert!(matches!(
        result,
        ControlBoundaryWaitOutcome::Woken | ControlBoundaryWaitOutcome::ValueChanged
    ));
    assert_eq!(slot.control_boundary_token(), request + 1);
    Ok(())
}

fn mapped_ack_file(
    allocation: &crate::RegionAllocation,
) -> Result<std::fs::File, Box<dyn std::error::Error>> {
    // SAFETY: the static name is NUL-terminated and no pointers are retained.
    let descriptor = unsafe {
        libc::memfd_create(
            c"control-ack-test".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful memfd_create transfers a fresh descriptor to File.
    let mut file = unsafe { std::fs::File::from_raw_fd(descriptor) };
    file.write_all(&allocation.setup_region_bytes()?)?;
    // SAFETY: this owned descriptor is seal-capable; these seals preserve size.
    if unsafe {
        libc::fcntl(
            file.as_raw_fd(),
            libc::F_ADD_SEALS,
            libc::F_SEAL_SHRINK | libc::F_SEAL_GROW,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(file)
}

#[test]
fn separate_process_park_and_spurious_wake_use_shared_ack_key() -> TestResult {
    let allocation = crate::RegionAllocation::new_model(crate::RegionConfig::new(1, 4))?;
    let file = mapped_ack_file(&allocation)?;
    let producer = crate::mmap_setup_region(file.as_fd(), allocation.layout().region_size)?;
    let slot = producer.node_slot(0)?;
    let request = slot.request_control_boundary(0, None)?;

    // SAFETY: F_DUPFD duplicates only this owned test memfd without CLOEXEC;
    // the new descriptor is independently owned and closed after child spawn.
    let raw = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 3) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful F_DUPFD returned a new descriptor owned by this scope.
    let inherited = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "frame_node::control_boundary_wait::tests::isolated_process_wait",
            "--nocapture",
        ])
        .env(
            "CRUCIBLE_TEST_CONTROL_ACK_FD",
            inherited.as_raw_fd().to_string(),
        )
        .env(
            "CRUCIBLE_TEST_CONTROL_ACK_LEN",
            allocation.layout().region_size.to_string(),
        )
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    drop(inherited);
    let result = (|| -> TestResult {
        let mut output = BufReader::new(child.stdout.take().ok_or("child stdout absent")?);
        let mut line = String::new();
        loop {
            if output.read_line(&mut line)? == 0 {
                return Err("child exited before ready".into());
            }
            if line.contains("ACK_WAITER_READY") {
                break;
            }
            line.clear();
        }
        // A private futex key cannot wake the other process's mapping. The
        // kernel count independently proves this peer actually parked.
        wake_parked(slot)?;
        line.clear();
        loop {
            if output.read_line(&mut line)? == 0 {
                return Err("child exited before spurious wake".into());
            }
            if line.contains("ACK_SPURIOUS_PENDING") {
                break;
            }
            line.clear();
        }
        if slot.control_boundary_token() != request {
            return Err("spurious child wake changed the original request".into());
        }
        if slot.acknowledge_control_boundary_and_notify()? != request + 1 {
            return Err("child completion has a different original ACK".into());
        }
        let mut tail = String::new();
        output.read_to_string(&mut tail)?;
        if !tail.contains("1 passed") {
            return Err(format!("child did not finish its one control: {tail}").into());
        }
        Ok(())
    })();
    if result.is_err() {
        // Only this directly spawned child is signaled. Failure never leaves
        // a waiter owned by the test outside its cleanup/join scope.
        let _termination = child.kill();
    }
    let status = child.wait()?;
    result?;
    assert!(status.success(), "isolated ACK waiter failed: {status}");
    Ok(())
}

#[test]
fn isolated_process_wait() -> TestResult {
    let Some(descriptor) = std::env::var_os("CRUCIBLE_TEST_CONTROL_ACK_FD") else {
        return Ok(());
    };
    let raw: libc::c_int = descriptor
        .to_str()
        .ok_or("descriptor is not UTF-8")?
        .parse()?;
    let length: u64 = std::env::var("CRUCIBLE_TEST_CONTROL_ACK_LEN")?.parse()?;
    // SAFETY: this exact test-only descriptor is inherited from the parent;
    // no other owner in the isolated child adopts or closes it.
    let file = unsafe { std::fs::File::from_raw_fd(raw) };
    let region = crate::mmap_setup_region(file.as_fd(), length)?;
    let slot = region.node_slot(0)?;
    let request = slot.control_boundary_token();
    assert_eq!(request & 1, 0);
    println!("ACK_WAITER_READY");
    std::io::stdout().flush()?;
    assert_eq!(
        slot.wait_control_boundary_ack(request, Duration::from_secs(2))?,
        ControlBoundaryWaitOutcome::Woken
    );
    assert_eq!(slot.control_boundary_token(), request);
    println!("ACK_SPURIOUS_PENDING");
    std::io::stdout().flush()?;
    assert!(matches!(
        slot.wait_control_boundary_ack(request, Duration::from_secs(2))?,
        ControlBoundaryWaitOutcome::Woken | ControlBoundaryWaitOutcome::ValueChanged
    ));
    assert_eq!(slot.control_boundary_token(), request.wrapping_add(1));
    Ok(())
}

#[test]
fn absent_ack_uses_supplied_budget_and_wrap_preserves_full_word() -> TestResult {
    let slot = NodeSlot::new(KIND_VM);
    slot.control_boundary_ack
        .store(u32::MAX - 2, Ordering::Release);
    let request = slot.request_control_boundary(0, None)?;
    assert_eq!(request, u32::MAX - 1);
    assert_eq!(
        slot.wait_control_boundary_ack(request, Duration::from_millis(1))?,
        ControlBoundaryWaitOutcome::TimedOut
    );
    assert_eq!(slot.control_boundary_token(), request);
    assert_eq!(slot.acknowledge_control_boundary_and_notify()?, u32::MAX);
    assert_eq!(slot.request_control_boundary(0, None)?, 0);
    assert_eq!(slot.acknowledge_control_boundary_and_notify()?, 1);
    assert_eq!(
        slot.wait_control_boundary_ack(0, Duration::ZERO)?,
        ControlBoundaryWaitOutcome::ValueChanged
    );
    Ok(())
}

#[test]
fn notification_failure_is_returned_after_truthful_ack_release() -> TestResult {
    let slot = NodeSlot::new(KIND_VM);
    let request = slot.request_control_boundary(0, None)?;
    let failure = FutexError::Syscall {
        operation: "modeled ACK wake refusal",
        errno: libc::EPERM,
    };
    assert_eq!(
        slot.acknowledge_with_notification(|| Err(failure.clone())),
        Err(failure)
    );
    assert_eq!(slot.control_boundary_token(), request + 1);
    assert_eq!(slot.acknowledge_control_boundary_and_notify()?, request + 1);
    Ok(())
}

#[test]
fn interrupted_wait_is_exercised_in_an_isolated_signal_process() -> TestResult {
    let result = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "frame_node::control_boundary_wait::tests::isolated_signal_wait",
            "--nocapture",
        ])
        .env("CRUCIBLE_TEST_CONTROL_ACK_SIGNAL", "1")
        .output()?;
    assert!(
        result.status.success(),
        "signal child failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("1 passed"));
    Ok(())
}

extern "C" fn signal_handler(_signal: libc::c_int) {}

#[test]
fn isolated_signal_wait() -> TestResult {
    if std::env::var_os("CRUCIBLE_TEST_CONTROL_ACK_SIGNAL").as_deref()
        != Some(std::ffi::OsStr::new("1"))
    {
        return Ok(());
    }
    // SAFETY: this process runs exactly this test. The zeroed sigaction is
    // populated before use; the handler performs no operation and never
    // unwinds. No unrelated process/thread signal disposition is modified.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = signal_handler as *const () as usize;
    // SAFETY: the mask and action are live, writable values for these calls.
    unsafe {
        assert_eq!(libc::sigemptyset(&mut action.sa_mask), 0);
        assert_eq!(
            libc::sigaction(libc::SIGUSR1, &action, std::ptr::null_mut()),
            0
        );
    }
    let slot = NodeSlot::new(KIND_VM);
    let request = slot.request_control_boundary(0, None)?;
    let done = Arc::new(AtomicBool::new(false));
    let signal_done = Arc::clone(&done);
    // SAFETY: the handle identifies this live thread until the sender joins.
    let target = unsafe { libc::pthread_self() };
    let sender = std::thread::spawn(move || {
        let limit = test_host_now() + Duration::from_secs(2);
        while !signal_done.load(Ordering::Acquire) && test_host_now() < limit {
            // SAFETY: the original thread is live through this joined scope.
            assert_eq!(unsafe { libc::pthread_kill(target, libc::SIGUSR1) }, 0);
            std::thread::yield_now();
        }
    });
    let result = slot.wait_control_boundary_ack(request, Duration::from_secs(1));
    done.store(true, Ordering::Release);
    sender.join().map_err(|_| "signal sender panicked")?;

    assert_eq!(result?, ControlBoundaryWaitOutcome::Interrupted);
    assert_eq!(slot.control_boundary_token(), request);
    assert_eq!(
        slot.wait_control_boundary_ack(request, Duration::ZERO)?,
        ControlBoundaryWaitOutcome::TimedOut
    );
    Ok(())
}
