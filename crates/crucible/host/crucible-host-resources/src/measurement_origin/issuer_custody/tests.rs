//! Exercises direct-child custody under ordinary local test authority.
//!
//! These helpers cannot issue a usable PID1/source grant. Fallback cleanup owns
//! only the identity observed directly from its own actual Child birth; it is
//! distinct from production expiry cleanup and never uses peer or proc discovery.

use super::*;
use rustix::process::{Signal, WaitOptions, kill_process, waitpid};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::Stdio;

struct TestChildFallback {
    pid: rustix::process::Pid,
}

impl TestChildFallback {
    fn for_actual_birth(child: &Child) -> Self {
        Self {
            pid: rustix::process::Pid::from_raw(i32::try_from(child.id()).unwrap()).unwrap(),
        }
    }
}

impl Drop for TestChildFallback {
    fn drop(&mut self) {
        // ECHILD means our direct child has already been reaped. Check child
        // ownership before signaling so a recycled numeric PID is never killed.
        if matches!(waitpid(Some(self.pid), WaitOptions::NOHANG), Ok(None)) {
            let _ = kill_process(self.pid, Signal::KILL);
            let _ = waitpid(Some(self.pid), WaitOptions::empty());
        }
    }
}

fn interval(span: Duration) -> OriginalInterval {
    let start_ns = monotonic_ns().unwrap();
    OriginalInterval {
        start_ns,
        end_ns: start_ns
            .checked_add(u64::try_from(span.as_nanos()).unwrap())
            .unwrap(),
    }
}

fn helper_command() -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args([
        "--exact",
        "measurement_origin::issuer_custody::tests::actual_child_helper",
        "--ignored",
        "--test-threads=1",
    ]);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn wait_until_expired(original: OriginalInterval) {
    while let Ok(left) = original.remaining() {
        let timeout =
            rustix::event::Timespec::try_from(left.min(Duration::from_millis(5))).unwrap();
        rustix::event::poll(&mut [], Some(&timeout)).unwrap();
    }
}

#[test]
#[ignore = "spawned only as the controlled direct child of custody tests"]
fn actual_child_helper() {
    loop {
        let _ = rustix::event::poll(&mut [], None);
    }
}

#[test]
fn actual_postbirth_expiry_retains_child_before_postcheck() {
    let original = interval(Duration::from_millis(100));
    let mut owner = IssuerRecord::empty();
    owner.prepare(original).unwrap();
    let child = helper_command().spawn().unwrap();
    let fallback = TestChildFallback::for_actual_birth(&child);
    let actual_pid = child.id();
    wait_until_expired(original);

    let error = owner.publish_child(child).unwrap_err();
    owner.retain_work(error);
    owner.cleanup_direct_child();

    assert!(matches!(
        owner.first_work,
        Some(MeasurementOriginError::Clock)
    ));
    assert_eq!(owner.state, IssuerState::Quarantined);
    assert_eq!(owner.child.as_ref().map(Child::id), Some(actual_pid));
    assert!(owner.child.as_mut().unwrap().try_wait().unwrap().is_none());
    assert!(matches!(
        owner.clock_failure,
        Some(OriginalClockRefusal::Expired)
    ));
    // Expiry grants no additional cleanup window. The trusted test fallback
    // reaps its own helper separately; this is not a production wait witness.
    drop(fallback);
}

#[test]
fn actual_peer_failure_retains_nonclone_first_and_reaps_same_child() {
    let original = interval(Duration::from_secs(30));
    let mut owner = IssuerRecord::empty();
    owner.prepare(original).unwrap();
    let child = helper_command().spawn().unwrap();
    let fallback = TestChildFallback::for_actual_birth(&child);
    let actual_pid = child.id();
    owner.publish_child(child).unwrap();
    let (peer, remote) = UnixStream::pair().unwrap();
    owner.peer = Some(peer);
    drop(remote);

    let mut request = [0; 32];
    let first = read_issuance(owner.peer.as_mut().unwrap(), &mut request, original).unwrap_err();
    owner.retain_work(first);
    owner.retain_work(MeasurementOriginError::Authentication(
        "later failure must not replace first",
    ));
    owner.cleanup_direct_child();

    assert!(matches!(
        &owner.first_work,
        Some(MeasurementOriginError::Authentication(
            "issuance channel closed"
        ))
    ));
    assert_eq!(owner.child.as_ref().map(Child::id), Some(actual_pid));
    assert_eq!(owner.state, IssuerState::DirectReaped);
    assert!(owner.status.is_some());
    assert!(owner.peer.is_some());
    assert!(owner.prepare(original).is_err());
    assert!(owner.first_work.is_some());
    drop(fallback);
}

#[test]
fn actual_socket_io_error_is_retained_without_replacing_it() {
    let original = interval(Duration::from_secs(30));
    let mut owner = IssuerRecord::empty();
    owner.prepare(original).unwrap();
    let (peer, remote) = UnixStream::pair().unwrap();
    owner.peer = Some(peer);
    drop(remote);

    let first = write_issuance(owner.peer.as_mut().unwrap(), &[1], original).unwrap_err();
    owner.retain_work(first);
    let original_error = owner.first_work.as_ref().unwrap() as *const MeasurementOriginError;
    owner.retain_work(MeasurementOriginError::Authentication("later peer error"));

    assert!(matches!(
        &owner.first_work,
        Some(MeasurementOriginError::IoBoundary { source, after: None })
            if source.kind() == std::io::ErrorKind::BrokenPipe
    ));
    assert_eq!(
        owner.first_work.as_ref().unwrap() as *const MeasurementOriginError,
        original_error
    );
    assert!(owner.peer.is_some());
}

#[test]
fn panic_after_publication_keeps_actual_poisoned_owner_accessible() {
    let original = interval(Duration::from_secs(30));
    let mut record = IssuerRecord::empty();
    record.prepare(original).unwrap();
    let slot = Mutex::new(record);
    let child = helper_command().spawn().unwrap();
    let fallback = TestChildFallback::for_actual_birth(&child);
    let actual_pid = child.id();

    let unwound = catch_unwind(AssertUnwindSafe(|| {
        let mut owner = slot.lock().unwrap();
        owner.publish_child(child).unwrap();
        panic!("deliberate panic after actual child publication");
    }));

    assert!(unwound.is_err());
    let mut owner = slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    owner.poisoned = true;
    assert_eq!(owner.child.as_ref().map(Child::id), Some(actual_pid));
    assert!(owner.prepare(original).is_err());
    assert!(
        owner.first_work.is_none(),
        "poison is not an owned panic payload"
    );
    owner.cleanup_direct_child();
    assert!(owner.status.is_some());
    drop(owner);
    drop(fallback);
}

#[test]
fn production_missing_external_purpose_refuses_before_issuance_effects() {
    let mut owner = IssuerRecord::empty();
    owner.prepare(interval(Duration::from_secs(30))).unwrap();
    let first = owner.issue_actor().unwrap_err();
    owner.retain_work(first);

    assert!(matches!(
        owner.first_work,
        Some(MeasurementOriginError::MissingIssuerPurpose)
    ));
    assert!(owner.listener.is_none());
    assert!(owner.policy_file.is_none());
    assert!(owner.actor_file.is_none());
    assert!(owner.record.is_none());
    assert!(owner.peer.is_none());
    assert!(owner.child.is_none());
    assert_eq!(owner.state, IssuerState::Prepared);
}

#[test]
fn actual_reap_is_published_before_expired_postcheck_without_signal() {
    let original = interval(Duration::from_millis(250));
    let mut owner = IssuerRecord::empty();
    owner.prepare(original).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--list"])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = command.spawn().unwrap();
    let fallback = TestChildFallback::for_actual_birth(&child);
    owner.publish_child(child).unwrap();
    // Obtain a factual successful wait from this actual Child, then exercise
    // the same production publication method after the original end passes.
    let status = loop {
        if let Some(status) = owner.child.as_mut().unwrap().try_wait().unwrap() {
            break status;
        }
        let timeout = rustix::event::Timespec::try_from(Duration::from_millis(1)).unwrap();
        rustix::event::poll(&mut [], Some(&timeout)).unwrap();
    };
    wait_until_expired(original);

    assert!(matches!(
        owner.publish_wait_status(Some(status)),
        Err(MeasurementOriginError::Clock)
    ));
    owner.cleanup_direct_child();
    assert_eq!(owner.status, Some(status));
    assert_eq!(owner.state, IssuerState::DirectReaped);
    assert!(owner.kill_failure.is_none());
    assert!(owner.wait_failure.is_none());
    drop(fallback);
}

#[test]
fn expired_original_refuses_before_spawn_and_layout_is_explicit() {
    let original = interval(Duration::from_millis(1));
    wait_until_expired(original);
    let mut owner = IssuerRecord::empty();
    assert!(matches!(
        owner.prepare(original),
        Err(MeasurementOriginError::Clock)
    ));
    assert!(matches!(
        owner.spawn_prepared(&mut helper_command()),
        Err(MeasurementOriginError::Clock)
    ));
    assert!(owner.child.is_none());

    let record = std::alloc::Layout::new::<IssuerRecord>();
    let slot = std::alloc::Layout::new::<Mutex<IssuerRecord>>();
    eprintln!(
        "issuer geometry: record={} align={} static-slot={} align={} Child={} OriginError={}",
        record.size(),
        record.align(),
        slot.size(),
        slot.align(),
        std::mem::size_of::<Child>(),
        std::mem::size_of::<MeasurementOriginError>()
    );
    assert!(slot.size() >= record.size());
    assert_eq!(std::mem::size_of::<IssuerCustodyRefusal>(), 0);
}
