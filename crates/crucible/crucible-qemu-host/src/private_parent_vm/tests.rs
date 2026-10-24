//! Exercises actual child publication and original owner refusal custody.

use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn admitted() -> ParentRecord {
    let mut record = ParentRecord::empty();
    record
        .admit(ExternalSourceContract {
            resident_bytes: 1 << 30,
            backing_bytes: 1 << 30,
            tasks: 64,
            descriptors: 2048,
        })
        .unwrap();
    record.deadline = Some(crate::supervision::HostSupervisionDeadline::start(
        Duration::from_secs(30),
    ));
    record
}

fn child() -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "private_parent_vm::tests::child_helper",
            "--ignored",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

#[test]
#[ignore = "runs only as an owned child of the custody controls"]
fn child_helper() {}

#[test]
fn postbirth_refusal_keeps_actual_child_and_original_account() {
    let mut record = admitted();
    record.deadline = Some(crate::supervision::HostSupervisionDeadline::start(
        Duration::ZERO,
    ));
    let born = child();
    let actual_id = born.id();

    let result = record.publish_child(born);
    let kept = record
        .child
        .as_ref()
        .is_some_and(|child| child.id() == actual_id);
    // The causal wrong-order control must also reap the exact child this test
    // actually spawned. This test-only PID comes directly from its owned Child.
    if let Some(child) = record.child.as_mut() {
        let status = child.wait().unwrap();
        record.exit = Some(status);
        assert!(status.success());
    } else {
        let pid = rustix::process::Pid::from_raw(actual_id as i32).unwrap();
        rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty()).unwrap();
    }

    assert!(matches!(result, Err(ParentFailure::Deadline)));
    assert!(
        kept,
        "actual Child must be published before postcheck refusal"
    );
    assert!(record.account.is_some());
    record.retain(result.unwrap_err());
    assert!(matches!(record.first, Some(ParentFailure::Deadline)));
}

#[test]
fn caller_panic_keeps_actual_child_in_accessible_original_record() {
    let mut record = admitted();
    let actual_id;
    {
        let born = child();
        actual_id = born.id();
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                record.publish_child(born).unwrap();
                panic!("post-publication caller failure");
            }))
            .is_err()
        );
    }

    assert_eq!(record.child.as_ref().unwrap().id(), actual_id);
    assert!(record.account.is_some());
    assert!(record.child.as_mut().unwrap().wait().unwrap().success());
}

#[test]
fn real_primary_and_cleanup_are_retained_separately() {
    let mut record = admitted();
    let primary = std::io::Error::from_raw_os_error(13);
    let cleanup = std::io::Error::from_raw_os_error(5);

    record.retain(ParentFailure::Io(primary));
    record.retain_cleanup(Err(ParentFailure::Io(cleanup)));
    record.retain(ParentFailure::Deadline);

    assert!(
        matches!(&record.first, Some(ParentFailure::Io(error)) if error.raw_os_error() == Some(13))
    );
    assert!(
        matches!(&record.cleanup, Some(ParentFailure::Io(error)) if error.raw_os_error() == Some(5))
    );
    assert!(record.account.is_some());
}

#[test]
fn actual_io_primary_survives_late_original_end_and_distinct_cleanup() {
    use std::io::Write;

    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("absent");
    let primary = fs::File::open(&missing).unwrap_err();
    let readable = root.path().join("read-only");
    fs::write(&readable, b"retained").unwrap();
    let cleanup = fs::File::open(&readable)
        .unwrap()
        .write_all(b"x")
        .unwrap_err();
    let mut record = admitted();
    record.deadline = Some(crate::supervision::HostSupervisionDeadline::start(
        Duration::ZERO,
    ));

    // This is the existing test-only original clock, not a registered-owner
    // grant. The actual IO outcome precedes its independent late postcheck.
    let completed = record.postchecked(Err(ParentFailure::Io(primary)));
    record.retain(completed.unwrap_err());
    record.retain_cleanup(Err(ParentFailure::Io(cleanup)));

    assert!(matches!(&record.first,
        Some(ParentFailure::Io(error)) if error.raw_os_error() == Some(libc::ENOENT)
    ));
    assert!(matches!(&record.cleanup,
        Some(ParentFailure::Io(error)) if error.raw_os_error() == Some(libc::EBADF)
    ));
    assert!(record.post_expired);
    assert!(record.account.is_some());
    eprintln!(
        "target Parent Mutex record={} setup={} watcher_error={} release_error={}",
        std::mem::size_of::<Mutex<ParentRecord>>(),
        std::mem::size_of::<crate::linux_attempt_host::OriginalParentSetup>(),
        std::mem::size_of::<crate::linux_cgroup::LinuxQemuCgroupWatcherWaitError>(),
        std::mem::size_of::<crate::linux_cgroup::LinuxQemuCgroupReleaseError>(),
    );
}

#[test]
fn original_account_is_once_only_and_guest_is_not_double_charged() {
    let mut record = admitted();
    let account = record.account.as_ref().unwrap();
    assert_eq!(account.resident_ceiling(), 21 << 30);
    assert_eq!(account.backing_ceiling(), 65 << 30);

    assert!(matches!(
        record.admit(ExternalSourceContract {
            resident_bytes: 1,
            backing_bytes: 1,
            tasks: 1,
            descriptors: 1,
        }),
        Err(ParentFailure::Occupied)
    ));
    assert_eq!(
        record.account.as_ref().unwrap().resident_ceiling(),
        21 << 30
    );
}

#[test]
fn installed_floor_refuses_without_retiring_or_replacing_original_payment() {
    let mut record = admitted();
    assert!(matches!(
        record
            .account
            .as_ref()
            .unwrap()
            .verify_installed_floor(1 << 30, 1, 1),
        Err(AdmissionError::SourceFloor)
    ));
    record.retain(ParentFailure::Admission(AdmissionError::SourceFloor));
    assert_eq!(
        record.account.as_ref().unwrap().resident_ceiling(),
        21 << 30
    );
    assert!(record.owner.is_none());
    assert!(record.child.is_none());
}

#[test]
fn unrelated_actual_peer_cannot_receive_parent_evidence() {
    use std::io::Read;
    use std::os::unix::net::UnixStream;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("original.sock");
    let pins = tempfile::tempfile().unwrap();
    let mut record = admitted();
    record.bridge = Some(bridge::Bridge::untrusted_test_endpoint(path.clone(), pins));
    let born = child();
    let actual_pid = born.id();
    record.publish_child(born).unwrap();
    let mut unrelated = UnixStream::connect(&path).unwrap();
    unrelated.set_nonblocking(true).unwrap();

    let result = record.exchange_parent_evidence();
    let mut byte = [0];
    let unread = unrelated.read(&mut byte);
    record.exit = Some(record.child.as_mut().unwrap().wait().unwrap());

    assert!(matches!(
        result,
        Err(ParentFailure::CompiledInput(
            "actual owned QEMU bridge peer"
        ))
    ));
    assert!(matches!(unread, Err(error) if error.kind() == std::io::ErrorKind::WouldBlock));
    assert_eq!(record.child.as_ref().unwrap().id(), actual_pid);
    assert!(record.bridge.as_ref().unwrap().has_retained_test_peer());
    assert!(record.account.is_some());
}

#[test]
fn poll_slice_borrows_original_remaining_and_expired_end_refuses() {
    let mut record = admitted();
    assert_eq!(record.poll_timeout().unwrap().tv_nsec, 10_000_000);

    record.deadline = Some(crate::supervision::HostSupervisionDeadline::start(
        Duration::from_millis(5),
    ));
    match record.poll_timeout() {
        Ok(timeout) => {
            assert_eq!(timeout.tv_sec, 0);
            assert!(timeout.tv_nsec > 0 && timeout.tv_nsec <= 5_000_000);
        }
        Err(ParentFailure::Deadline) => {}
        Err(other) => panic!("unexpected original deadline refusal: {other:?}"),
    }

    record.deadline = Some(crate::supervision::HostSupervisionDeadline::start(
        Duration::ZERO,
    ));
    assert!(matches!(
        record.poll_timeout(),
        Err(ParentFailure::Deadline)
    ));
    assert!(record.account.is_some());
}
