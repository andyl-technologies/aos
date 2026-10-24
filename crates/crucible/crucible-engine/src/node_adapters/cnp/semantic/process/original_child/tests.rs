//! Exercises original birth transfer, descriptor waits and refusal ownership.
//!
//! Native controls run only when explicitly selected by the owning qualifier.
//! Manually constructed invalid descriptors below are negative fixtures; none
//! constructs a Source, native permission or accepted process owner.

// crucible-lint: allow panic-shortcut -- These controls localize actual child custody failures.
#![allow(clippy::unwrap_used)]
#![cfg(target_os = "linux")]

use std::{
    cell::RefCell,
    os::{fd::AsRawFd, unix::fs::DirBuilderExt, unix::process::CommandExt},
    path::PathBuf,
    process::{Command, Stdio},
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use rustix::process::{PidfdFlags, Signal, getpid, pidfd_open, pidfd_send_signal};

use super::*;
use crate::node_adapters::cnp::semantic::process::{
    CnpSemanticLaunchReservation, CnpSemanticProcessCustody, CnpSemanticProcessSlot,
};

struct Slot(Rc<RefCell<Option<CnpSemanticProcessCustody>>>);

impl CnpSemanticProcessSlot for Slot {
    fn identity(&self) -> crucible_node_format::U64 {
        73.into()
    }

    fn retain(&mut self, custody: CnpSemanticProcessCustody) {
        assert!(self.0.borrow().is_none());
        *self.0.borrow_mut() = Some(custody);
    }
}

struct Fixture {
    directory: PathBuf,
    custody: Option<CnpSemanticProcessCustody>,
    launch_error: Option<ProviderError>,
}

impl Fixture {
    fn new(parent_pipe: bool) -> Self {
        Self::new_mode(parent_pipe, true)
    }

    fn new_mode(parent_pipe: bool, original_pidfd: bool) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);

        let ordinal = NEXT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .unwrap();
        let directory = std::env::temp_dir().join(format!(
            "crucible-original-pidfd-{}-{ordinal}",
            std::process::id()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let executable = std::env::current_exe().unwrap();
        let measured =
            crucible_node_transport::conformance::measure_executable(&executable).unwrap();
        let returned = Rc::new(RefCell::new(None));
        let slot = Box::new(Slot(Rc::clone(&returned)));
        let mut reservation = if original_pidfd {
            CnpSemanticLaunchReservation::reserve_complete_original_child(
                directory.clone(),
                measured,
                slot,
            )
        } else {
            CnpSemanticLaunchReservation::reserve_complete_bytes(directory.clone(), measured, slot)
        };
        let mut command = Command::new(executable);
        command
            .args([
                "--ignored",
                "--nocapture",
                "original_child::tests::original_pidfd_child_entry",
                "--test-threads=1",
            ])
            .env("CRUCIBLE_ORIGINAL_PIDFD_CHILD", &directory)
            .stdin(Stdio::null())
            .stdout(if parent_pipe {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stderr(Stdio::null())
            .process_group(0);
        let launch_error = reservation.launch(&mut command).err();
        // The real launch guard delivers the same whole process owner to its
        // original slot. Reaping remains permitted after source-read revocation.
        drop(reservation);
        let custody = returned.borrow_mut().take();
        assert!(custody.is_some());
        Self {
            directory,
            custody,
            launch_error,
        }
    }

    fn finish(mut self) {
        for _ in 0..500 {
            if self.custody.as_mut().unwrap().poll_reclamation().unwrap() {
                self.custody.take();
                std::fs::remove_dir_all(&self.directory).unwrap();
                return;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        panic!("original child cleanup did not prove reaping and an empty group");
    }

    fn owner(&mut self) -> &mut OriginalChild {
        assert!(self.launch_error.is_none());
        let custody = self.custody.as_mut().unwrap();
        assert!(custody.child.is_none());
        custody.original_child.as_mut().unwrap()
    }

    // crucible-lint: allow operational-time -- Bounds actual native fixture polling, never simulation time.
    #[allow(clippy::disallowed_methods)]
    fn exit_status(&mut self) -> std::process::ExitStatus {
        let started = Instant::now();
        loop {
            if let Some(status) = self.owner().try_wait().unwrap() {
                return status;
            }
            assert!(started.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(mut custody) = self.custody.take() {
            for _ in 0..500 {
                if matches!(custody.poll_reclamation(), Ok(true)) {
                    let _removed = std::fs::remove_dir_all(&self.directory);
                    return;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            // Failed cleanup is still custody, not a successful reap. Keep the
            // entire owner until this bounded test process exits.
            std::mem::forget(custody);
        }
    }
}

#[test]
#[ignore = "subprocess entry for explicit original-child descriptor controls"]
fn original_pidfd_child_entry() {
    let Some(directory) = std::env::var_os("CRUCIBLE_ORIGINAL_PIDFD_CHILD") else {
        return;
    };
    let directory = PathBuf::from(directory);
    for _ in 0..2500 {
        if directory.join("exit-seven").is_file() {
            std::process::exit(7);
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    std::process::exit(9);
}

#[test]
#[ignore = "requires the actual source-built Linux child executable and pidfd support"]
fn actual_original_birth_retains_descriptor_and_pending_waits_without_std_child() {
    let mut fixture = Fixture::new(false);
    let owner = fixture.owner();
    let descriptor = owner.descriptor.as_ref().unwrap().as_raw_fd();

    for _ in 0..3 {
        assert!(owner.try_wait().unwrap().is_none());
        assert_eq!(owner.descriptor.as_ref().unwrap().as_raw_fd(), descriptor);
        assert!(owner.exit.is_none());
        owner.retained_metadata_data().unwrap();
    }
    assert!(owner.ensure_unreaped().is_ok());
    fixture.finish();
}

#[test]
#[ignore = "requires the actual source-built Linux child executable and pidfd support"]
fn actual_original_exit_reaps_once_and_repeats_the_same_typed_status() {
    let mut fixture = Fixture::new(false);
    let descriptor = fixture.owner().descriptor.as_ref().unwrap().as_raw_fd();
    std::fs::write(fixture.directory.join("exit-seven"), b"original exit").unwrap();

    let status = fixture.exit_status();
    assert_eq!(status.code(), Some(7));
    assert_eq!(fixture.owner().try_wait().unwrap(), Some(status));
    assert_eq!(fixture.owner().try_wait().unwrap(), Some(status));
    assert!(fixture.owner().ensure_unreaped().is_err());
    assert_eq!(
        fixture.owner().descriptor.as_ref().unwrap().as_raw_fd(),
        descriptor
    );
    fixture.finish();
}

#[test]
#[ignore = "requires the actual source-built Linux child executable and pidfd support"]
fn actual_original_signal_reaps_the_same_descriptor_and_caches_signal_status() {
    use std::os::unix::process::ExitStatusExt;

    let mut fixture = Fixture::new(false);
    fixture.owner().ensure_origin().unwrap();
    pidfd_send_signal(fixture.owner().descriptor.as_ref().unwrap(), Signal::KILL).unwrap();

    let status = fixture.exit_status();
    assert_eq!(status.signal(), Some(9));
    assert_eq!(fixture.owner().try_wait().unwrap(), Some(status));
    fixture.finish();
}

#[test]
#[ignore = "requires the actual source-built Linux child executable"]
fn actual_parent_stream_refusal_retains_the_same_std_child_and_original_supervisor() {
    let mut fixture = Fixture::new(true);
    assert!(matches!(
        fixture.launch_error.as_ref(),
        Some(ProviderError::Correlation(
            "selected original child identity or parent streams differ"
        ))
    ));
    let custody = fixture.custody.as_mut().unwrap();
    assert!(custody.original_child.is_none());
    let child = custody.child.as_mut().unwrap();
    assert_eq!(child.id(), custody.provider_pid);
    assert!(child.stdout.is_some());
    assert!(child.try_wait().unwrap().is_none());
    fixture.finish();
}

fn negative_descriptor(descriptor: OwnedFd) -> OriginalChild {
    OriginalChild {
        descriptor: Some(descriptor),
        process: std::process::id(),
        thread: std::thread::current().id(),
        exit: None,
        failed: false,
    }
}

#[test]
fn foreign_creator_refuses_before_using_an_actual_invalid_descriptor() {
    let file = std::fs::File::open("/dev/null").unwrap();
    let mut owner = negative_descriptor(file.into());
    let descriptor = owner.descriptor.as_ref().unwrap().as_raw_fd();
    owner.process = owner.process.wrapping_add(1);

    assert!(matches!(
        owner.try_wait(),
        Err(ProviderError::Correlation(
            "original child descriptor belongs to another process"
        ))
    ));
    assert!(owner.retained_metadata_data().is_err());
    assert!(!owner.failed);
    assert!(owner.exit.is_none());
    assert_eq!(owner.descriptor.as_ref().unwrap().as_raw_fd(), descriptor);
    owner.process = std::process::id();
}

#[test]
fn unsupported_descriptor_refuses_stickily_without_a_pid_fallback() {
    let file = std::fs::File::open("/dev/null").unwrap();
    let mut owner = negative_descriptor(file.into());
    let descriptor = owner.descriptor.as_ref().unwrap().as_raw_fd();

    assert!(owner.try_wait().is_err());
    assert!(owner.failed);
    assert!(owner.exit.is_none());
    assert!(matches!(
        owner.try_wait(),
        Err(ProviderError::Correlation(
            "original child descriptor wait is unresolved"
        ))
    ));
    assert_eq!(owner.descriptor.as_ref().unwrap().as_raw_fd(), descriptor);
}

#[test]
#[ignore = "requires Linux pidfd support; opens only the current process descriptor"]
fn actual_nonchild_echild_remains_unresolved_and_retains_its_descriptor() {
    let descriptor = pidfd_open(getpid(), PidfdFlags::empty()).unwrap();
    let mut owner = negative_descriptor(descriptor);
    let descriptor = owner.descriptor.as_ref().unwrap().as_raw_fd();

    assert!(matches!(
        owner.try_wait(),
        Err(ProviderError::Io(error)) if error.raw_os_error() == Some(rustix::io::Errno::CHILD.raw_os_error())
    ));
    assert!(owner.failed);
    assert!(owner.exit.is_none());
    assert!(owner.try_wait().is_err());
    assert_eq!(owner.descriptor.as_ref().unwrap().as_raw_fd(), descriptor);
}

#[test]
#[ignore = "requires actual source-built Linux child and pidfd acquisition"]
fn actual_post_acquisition_refusal_keeps_the_same_original_std_child() {
    let mut fixture = Fixture::new_mode(false, false);
    assert!(fixture.launch_error.is_none());
    let custody = fixture.custody.as_mut().unwrap();
    let child = custody.child.as_ref().unwrap();
    let pid = child.id();
    let mut reached = false;
    let result = OriginalChild::capture_with_checkpoint(
        child,
        custody.provider_pid,
        custody.kernel_identity.as_ref().unwrap(),
        custody.executable_guard.as_ref().unwrap(),
        || {
            reached = true;
            Err(ProviderError::Correlation(
                "injected post-acquisition refusal",
            ))
        },
    );

    assert!(reached);
    assert!(matches!(
        result,
        Err(ProviderError::Correlation(
            "injected post-acquisition refusal"
        ))
    ));
    assert!(custody.original_child.is_none());
    let original = custody.child.as_mut().unwrap();
    assert_eq!(original.id(), pid);
    assert!(original.try_wait().unwrap().is_none());
    fixture.finish();
}
