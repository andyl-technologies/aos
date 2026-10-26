//! Exercises original kernel read leases and permanent break refusal.

// crucible-lint: allow panic-shortcut -- Actual kernel controls use assertions as their oracle.
#![allow(clippy::unwrap_used)]

use super::*;
use std::{os::unix::fs::OpenOptionsExt, path::PathBuf, sync::atomic::AtomicU64};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "crucible-read-lease-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn file(&self) -> PathBuf {
        let path = self.0.join("source");
        std::fs::write(&path, b"source-one").unwrap();
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn installed(path: &std::path::Path) -> (Arc<File>, LinuxReadLease) {
    let owner = Arc::new(LinuxReadLeaseOwner::new().unwrap());
    let file = Arc::new(File::open(path).unwrap());
    let lease = LinuxReadLease::acquire(Arc::clone(&file), owner).unwrap();
    (file, lease)
}

#[test]
fn original_lease_is_kernel_checked_and_released_before_owner_exit() {
    let directory = Fixture::new();
    let path = directory.file();
    let (file, lease) = installed(&path);
    assert!(lease.verify_current().is_ok());
    assert_eq!(
        descriptor_integer(&file, libc::F_GETLEASE, 0).unwrap(),
        libc::F_RDLCK
    );

    drop(lease);

    assert_eq!(
        descriptor_integer(&file, libc::F_GETLEASE, 0).unwrap(),
        libc::F_UNLCK
    );
    assert!(
        File::options()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
            .is_ok()
    );
}

#[test]
fn pending_write_break_is_sticky_after_equal_bytes_are_restored() {
    let directory = Fixture::new();
    let path = directory.file();
    let (file, lease) = installed(&path);
    let writer = File::options()
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&path);

    assert_eq!(writer.unwrap_err().raw_os_error(), Some(libc::EAGAIN));
    assert_eq!(
        descriptor_integer(&file, libc::F_GETLEASE, 0).unwrap(),
        libc::F_UNLCK
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"source-one");
    assert!(matches!(
        lease.verify_current(),
        Err(LinuxReadLeaseError::Revoked)
    ));

    // Release the broken capability solely to finish the independent writer.
    // Equal restored bytes cannot repair this original revoked token.
    descriptor_integer(&file, libc::F_SETLEASE, libc::F_UNLCK).unwrap();
    std::fs::write(&path, b"source-two").unwrap();
    std::fs::write(&path, b"source-one").unwrap();
    assert!(matches!(
        lease.verify_current(),
        Err(LinuxReadLeaseError::Revoked)
    ));
}

#[test]
fn pending_truncate_never_changes_bytes_before_refusal() {
    let directory = Fixture::new();
    let path = directory.file();
    let (_, lease) = installed(&path);

    let writer = File::options()
        .write(true)
        .truncate(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&path);

    assert_eq!(writer.unwrap_err().raw_os_error(), Some(libc::EAGAIN));
    assert_eq!(std::fs::read(&path).unwrap(), b"source-one");
    assert!(lease.verify_current().is_err());
}

#[test]
fn existing_writer_and_write_capable_original_are_refused() {
    let directory = Fixture::new();
    let path = directory.file();
    let owner = Arc::new(LinuxReadLeaseOwner::new().unwrap());
    let writer = Arc::new(File::options().write(true).open(&path).unwrap());
    let readonly = Arc::new(File::open(&path).unwrap());

    assert!(matches!(
        LinuxReadLease::acquire(Arc::clone(&writer), Arc::clone(&owner)),
        Err(LinuxReadLeaseError::InvalidDescriptor)
    ));
    let result = LinuxReadLease::acquire(readonly, owner);
    assert!(
        matches!(result, Err(LinuxReadLeaseError::Io(ref error)) if error.raw_os_error() == Some(libc::EAGAIN))
    );
}

#[test]
fn foreign_process_refuses_before_touching_worker_or_kernel_owner() {
    let directory = Fixture::new();
    let path = directory.file();
    let owner = Arc::new(LinuxReadLeaseOwner::new().unwrap());
    let file = Arc::new(File::open(path).unwrap());
    let mut lease = LinuxReadLease::acquire(file, owner).unwrap();
    let actual = lease.owner.process;
    Arc::get_mut(&mut lease.owner).unwrap().process = actual.wrapping_add(1);

    assert!(matches!(
        lease.verify_current(),
        Err(LinuxReadLeaseError::WrongProcess)
    ));
    Arc::get_mut(&mut lease.owner).unwrap().process = actual;
    assert!(matches!(
        lease.verify_current(),
        Err(LinuxReadLeaseError::Revoked)
    ));
}

#[test]
fn renamed_equal_bytes_require_an_independent_namespace_fence() {
    use std::os::unix::fs::MetadataExt;

    let directory = Fixture::new();
    let path = directory.file();
    let (file, lease) = installed(&path);
    let replacement = directory.0.join("replacement");
    std::fs::write(&replacement, b"source-one").unwrap();

    std::fs::rename(replacement, &path).unwrap();

    // A lease protects the original inode, not directory entry selection.
    assert!(lease.verify_current().is_ok());
    assert_ne!(
        file.metadata().unwrap().ino(),
        std::fs::metadata(path).unwrap().ino()
    );
}

#[test]
fn writable_mapping_blocks_initial_lease_after_writer_descriptor_closes() {
    let directory = Fixture::new();
    let path = directory.file();
    let writer = File::options().read(true).write(true).open(&path).unwrap();
    // SAFETY: the valid descriptor and ten-byte regular file stay alive during
    // mmap. The test does not dereference this mapping and unmaps it afterward.
    let mapping = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            10,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            writer.as_raw_fd(),
            0,
        )
    };
    assert_ne!(mapping, libc::MAP_FAILED);
    drop(writer);
    let owner = Arc::new(LinuxReadLeaseOwner::new().unwrap());
    let readonly = Arc::new(File::open(&path).unwrap());

    let result = LinuxReadLease::acquire(readonly, owner);

    // SAFETY: this is the original successful mapping and its exact extent.
    assert_eq!(unsafe { libc::munmap(mapping, 10) }, 0);
    assert!(
        matches!(result, Err(LinuxReadLeaseError::Io(ref error)) if error.raw_os_error() == Some(libc::EAGAIN))
    );
}

#[test]
fn actual_fork_child_refuses_and_drops_without_joining_parent_worker() {
    let directory = Fixture::new();
    let path = directory.file();
    let (file, lease) = installed(&path);
    // SAFETY: the child performs the bounded wrong-process branch and drops
    // only its inherited references, then immediately uses _exit. It runs no
    // fixture callbacks, assertions, signal handlers or notification joins.
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        let refused = matches!(
            lease.verify_current(),
            Err(LinuxReadLeaseError::WrongProcess)
        );
        drop(lease);
        // SAFETY: _exit terminates only this child without process-wide Rust
        // teardown or inherited test-harness/notification-thread locks.
        unsafe { libc::_exit(if refused { 0 } else { 1 }) };
    }

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut status = 0;
    let mut timed_out = false;
    loop {
        // SAFETY: the status pointer is initialized and writable; this parent
        // owns the exact unreaped child returned by the preceding fork.
        let waited = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
        if waited == child {
            break;
        }
        assert_eq!(waited, 0);
        if std::time::Instant::now() >= deadline {
            timed_out = true;
            // SAFETY: the original unreaped child PID cannot have been reused.
            unsafe {
                libc::kill(child, libc::SIGKILL);
                libc::waitpid(child, &mut status, 0);
            }
            break;
        }
        thread::sleep(Duration::from_millis(2));
    }

    assert!(
        !timed_out,
        "inherited owner must not join a vanished parent thread"
    );
    assert_eq!(status, 0);
    assert!(lease.verify_current().is_ok());
    assert_eq!(
        descriptor_integer(&file, libc::F_GETLEASE, 0).unwrap(),
        libc::F_RDLCK
    );
}

#[test]
fn notification_worker_preserves_callers_sigio_mask() {
    fn sigio_blocked() -> bool {
        let mut mask = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
        // SAFETY: querying with null new-set changes no mask; the successful
        // call initializes the complete old mask used by sigismember below.
        unsafe {
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), mask.as_mut_ptr()),
                0
            );
            libc::sigismember(&mask.assume_init(), libc::SIGIO) == 1
        }
    }

    let before = sigio_blocked();
    let owner = LinuxReadLeaseOwner::new().unwrap();
    assert_eq!(sigio_blocked(), before);

    drop(owner);

    assert_eq!(sigio_blocked(), before);
}

#[test]
fn successful_acquisition_then_pending_break_never_allows_initial_fallback() {
    let directory = Fixture::new();
    let path = directory.file();
    let (_, lease) = installed(&path);
    let writer = File::options()
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&path);
    assert_eq!(writer.unwrap_err().raw_os_error(), Some(libc::EAGAIN));

    // Exercise the same post-SETLEASE validator with an actual pending break,
    // not an injected permission flag or manufactured kernel result.
    let result = LinuxReadLease::validate_acquired(lease);

    assert!(
        matches!(result, Err(LinuxReadLeaseError::AcquiredLeaseRevoked(ref error)) if matches!(error.as_ref(), LinuxReadLeaseError::Revoked))
    );
    assert_eq!(std::fs::read(path).unwrap(), b"source-one");
}

#[test]
fn duplicate_acquisition_preserves_original_owner_and_never_renews() {
    let directory = Fixture::new();
    let path = directory.file();
    let (file, lease) = installed(&path);
    let original_owner = notification_owner(&file).unwrap();
    let replacement = Arc::new(LinuxReadLeaseOwner::new().unwrap());

    let result = LinuxReadLease::acquire(Arc::clone(&file), replacement);

    assert!(matches!(result, Err(LinuxReadLeaseError::AlreadyLeased)));
    let retained_owner = notification_owner(&file).unwrap();
    assert_eq!(retained_owner.kind, original_owner.kind);
    assert_eq!(retained_owner.id, original_owner.id);
    assert!(lease.verify_current().is_ok());
}

#[test]
fn initial_fallback_never_adopts_a_later_available_kernel_lease() {
    let directory = Fixture::new();
    let path = directory.file();
    let writer = File::options().write(true).open(&path).unwrap();
    let owner = Arc::new(LinuxReadLeaseOwner::new().unwrap());
    let original = LinuxReadLeaseFile::open(&path, Some(owner)).unwrap();
    assert!(original.lease().is_none());

    drop(writer);

    assert!(original.lease().is_none());
    assert_eq!(
        descriptor_integer(original.file(), libc::F_GETLEASE, 0).unwrap(),
        libc::F_UNLCK
    );
    assert_eq!(std::fs::read(path).unwrap(), b"source-one");
}

#[test]
fn owning_original_keeps_a_broken_token_and_never_enters_fallback() {
    let directory = Fixture::new();
    let path = directory.file();
    let owner = Arc::new(LinuxReadLeaseOwner::new().unwrap());
    let original = LinuxReadLeaseFile::open(&path, Some(owner)).unwrap();
    original.lease().unwrap().verify_current().unwrap();
    let writer = File::options()
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&path);
    assert_eq!(writer.unwrap_err().raw_os_error(), Some(libc::EAGAIN));
    assert!(original.lease().unwrap().verify_current().is_err());

    // Release only to let the independent test writer finish immediately.
    // Production exposes no reacquisition or state-replacement transition.
    descriptor_integer(original.file(), libc::F_SETLEASE, libc::F_UNLCK).unwrap();
    std::fs::write(&path, b"source-two").unwrap();
    std::fs::write(&path, b"source-one").unwrap();

    assert!(original.lease().is_some());
    assert!(original.lease().unwrap().verify_current().is_err());
}

#[test]
fn capacity_data_keeps_actual_descriptor_layout_after_unlink_without_a_worker() {
    let fixture = Fixture::new();
    let path = fixture.file();
    let original = LinuxReadLeaseFile::open(&path, None).unwrap();
    let expected = LinuxReadLeaseFileCapacityData {
        descriptor_value_bytes: std::mem::size_of::<File>(),
        descriptor_value_alignment: std::mem::align_of::<File>(),
        has_lease_worker: false,
    };
    assert_eq!(original.retained_capacity_data(), expected);

    std::fs::remove_file(path).unwrap();

    assert_eq!(original.retained_capacity_data(), expected);
    assert!(original.lease().is_none());
    assert_eq!(Arc::strong_count(&original.file), 1);
}

#[test]
fn capacity_data_reports_acquired_worker_after_revocation_without_fallback() {
    let fixture = Fixture::new();
    let path = fixture.file();
    let owner = Arc::new(LinuxReadLeaseOwner::new().unwrap());
    let original = LinuxReadLeaseFile::open(&path, Some(owner)).unwrap();
    let lease = original.lease().unwrap();
    lease.verify_current().unwrap();
    let before = original.retained_capacity_data();
    assert!(before.has_lease_worker);
    let references = Arc::strong_count(&original.file);

    lease.revoked.set(true);

    assert_eq!(original.retained_capacity_data(), before);
    assert!(original.lease().unwrap().verify_current().is_err());
    assert_eq!(Arc::strong_count(&original.file), references);
}
