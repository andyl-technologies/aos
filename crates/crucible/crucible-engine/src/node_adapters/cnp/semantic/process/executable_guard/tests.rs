//! Exercises actual native executable identity and original kernel byte guards.

// crucible-lint: allow panic-shortcut -- Actual resource controls use assertions as their independent oracle.
#![allow(clippy::unwrap_used)]

use std::{
    fs::{File, OpenOptions},
    os::unix::{fs::OpenOptionsExt, process::CommandExt},
    path::Path,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use super::*;

const CHILD_FILTER: &str = "executable_guard::tests::original_executable_child";

struct NativeFixture {
    directory: PathBuf,
    executable: PathBuf,
    child: Child,
}

impl NativeFixture {
    // crucible-lint: allow operational-time -- This bounds native startup and is never a simulation clock.
    #[allow(clippy::disallowed_methods)]
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "crucible-executable-guard-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let executable = directory.join("original-peer");
        fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        let child = child_command(&executable, &directory)
            .process_group(0)
            .spawn()
            .unwrap();
        let fixture = Self {
            directory,
            executable,
            child,
        };
        let started = Instant::now();
        while !fixture.directory.join("ready").is_file() {
            assert!(started.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(2));
        }
        fixture
    }

    fn kernel(&self) -> KernelIdentity {
        KernelIdentity::capture(self.child.id()).unwrap()
    }

    fn measured(&self) -> ContentRef {
        crucible_node_transport::conformance::measure_executable(&self.executable).unwrap()
    }

    fn guard(&self) -> OriginalExecutable {
        OriginalExecutable::open(self.child.id(), &self.measured(), &self.kernel()).unwrap()
    }

    fn data_guard(&self, writable: bool) -> (PathBuf, Option<File>, OriginalExecutable) {
        use std::os::unix::fs::symlink;

        let path = self.directory.join("complete-source-bytes");
        fs::write(&path, b"original-source").unwrap();
        let writer = writable.then(|| OpenOptions::new().write(true).open(&path).unwrap());
        let selection = self.directory.join("source-selection");
        symlink(&path, &selection).unwrap();
        let expected =
            canonical::content_ref(b"original-source", "application/octet-stream").unwrap();
        let guard =
            OriginalExecutable::open_original(selection, &expected, &self.kernel()).unwrap();
        (path, writer, guard)
    }
}

impl Drop for NativeFixture {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _signal = self.child.kill();
        }
        let _reaped = self.child.wait();
        let _cleanup = fs::remove_dir_all(&self.directory);
    }
}

fn child_command(executable: &Path, directory: &Path) -> Command {
    let mut command = Command::new(executable);
    command
        .args(["--ignored", "--nocapture", CHILD_FILTER, "--test-threads=1"])
        .env("CRUCIBLE_EXECUTABLE_GUARD_CHILD", directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

#[test]
#[ignore = "subprocess entry point for bounded original executable controls"]
fn original_executable_child() {
    let Some(directory) = std::env::var_os("CRUCIBLE_EXECUTABLE_GUARD_CHILD") else {
        return;
    };
    let directory = PathBuf::from(directory);
    fs::write(directory.join("ready"), b"original child ready").unwrap();
    for _ in 0..30_000 {
        if directory.join("exec-next").is_file() {
            let next = directory.join("replacement-peer");
            let _removed = fs::remove_file(directory.join("exec-next"));
            let error = child_command(&next, &directory).exec();
            panic!("original child exec refused: {error}");
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
#[ignore = "requires actual source-built native executable and Linux read leases"]
fn original_native_executable_is_measured_completely_and_retained() {
    let fixture = NativeFixture::new();
    let kernel = fixture.kernel();
    let guard = fixture.guard();
    assert!(guard.original.lease().is_some());
    for _ in 0..4 {
        guard.ensure_current(&kernel).unwrap();
    }

    let foreign =
        canonical::content_ref(b"different complete bytes", "application/octet-stream").unwrap();
    assert!(OriginalExecutable::open(fixture.child.id(), &foreign, &kernel).is_err());
    guard.ensure_current(&kernel).unwrap();
}

#[test]
#[ignore = "requires actual source-built native executable and Linux namespace controls"]
fn renamed_executable_and_equal_replacement_cannot_revive_original_guard() {
    let fixture = NativeFixture::new();
    let kernel = fixture.kernel();
    let guard = fixture.guard();
    let moved = fixture.directory.join("moved-original");
    let replacement = fixture.directory.join("equal-bytes");
    fs::copy(&fixture.executable, &replacement).unwrap();

    fs::rename(&fixture.executable, &moved).unwrap();
    fs::rename(&replacement, &fixture.executable).unwrap();
    assert!(guard.ensure_current(&kernel).is_err());
    fs::remove_file(&fixture.executable).unwrap();
    fs::rename(moved, &fixture.executable).unwrap();

    assert!(guard.ensure_current(&kernel).is_err());
}

#[test]
#[ignore = "requires actual source-built native executable and original kernel birth facts"]
// crucible-lint: allow operational-time -- This bounds one real exec transition, not modeled time.
#[allow(clippy::disallowed_methods)]
fn same_pid_exec_to_equal_bytes_changes_original_descriptor_identity() {
    let fixture = NativeFixture::new();
    let kernel = fixture.kernel();
    let guard = fixture.guard();
    let replacement = fixture.directory.join("replacement-peer");
    fs::copy(&fixture.executable, &replacement).unwrap();
    let replacement_inode = fs::metadata(&replacement).unwrap().ino();
    fs::write(
        fixture.directory.join("exec-next"),
        b"original exec transition",
    )
    .unwrap();

    let started = Instant::now();
    while fs::metadata(format!("/proc/{}/exe", fixture.child.id()))
        .unwrap()
        .ino()
        != replacement_inode
    {
        assert!(started.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(2));
    }

    // PID/start/group facts alone survive exec and cannot authorize new bytes.
    kernel.ensure_current().unwrap();
    assert!(guard.ensure_current(&kernel).is_err());
}

#[test]
#[ignore = "requires actual original child exit and kernel incarnation refusal"]
fn reaped_original_child_revokes_executable_guard_permanently() {
    let mut fixture = NativeFixture::new();
    let kernel = fixture.kernel();
    let guard = fixture.guard();

    fixture.child.kill().unwrap();
    fixture.child.wait().unwrap();

    assert!(guard.ensure_current(&kernel).is_err());
    assert!(guard.ensure_current(&kernel).is_err());
}

#[test]
#[ignore = "requires actual kernel pending read-lease break and complete-byte restoration"]
fn pending_write_break_keeps_original_bytes_and_permanently_refuses() {
    let fixture = NativeFixture::new();
    let kernel = fixture.kernel();
    let (path, _, guard) = fixture.data_guard(false);
    assert!(guard.original.lease().is_some());
    // O_NONBLOCK avoids extending the original kernel break deadline.
    let writer = OpenOptions::new()
        .write(true)
        .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
        .open(&path);

    assert_eq!(writer.unwrap_err().raw_os_error(), Some(11));
    assert_eq!(fs::read(&path).unwrap(), b"original-source");
    assert!(guard.ensure_current(&kernel).is_err());
    assert!(guard.original.lease().is_some());
    assert!(guard.ensure_current(&kernel).is_err());
}

#[test]
#[ignore = "requires actual complete-byte fallback with a preexisting writer"]
fn initial_unsupported_lease_reads_changed_bytes_and_stays_revoked_after_restore() {
    let fixture = NativeFixture::new();
    let kernel = fixture.kernel();
    let (path, writer, guard) = fixture.data_guard(true);
    assert!(guard.original.lease().is_none());
    drop(writer);
    guard.ensure_current(&kernel).unwrap();
    assert!(guard.original.lease().is_none());

    fs::write(&path, b"modified-source").unwrap();
    assert!(guard.measure_complete().is_err());
    assert!(guard.ensure_current(&kernel).is_err());
    fs::write(&path, b"original-source").unwrap();

    assert!(guard.ensure_current(&kernel).is_err());
    assert!(guard.original.lease().is_none());
}

#[test]
fn self_process_cannot_supply_original_child_kernel_identity() {
    assert!(matches!(
        KernelIdentity::capture(std::process::id()),
        Err(ProviderError::Correlation(
            "generic original kernel ownership changed"
        ))
    ));
}

#[test]
#[ignore = "requires actual source-built original child and complete executable byte checks"]
fn complete_byte_path_measures_actual_original_child_and_revocation_stays_sticky() {
    let fixture = NativeFixture::new();
    let identity = fixture.kernel();
    let reference = fixture.measured();
    let mut original =
        OriginalExecutable::open_complete_bytes(fixture.child.id(), &reference, &identity).unwrap();

    assert!(original.original.lease().is_none());
    original.ensure_current(&identity).unwrap();
    let expected = original.expected.clone();
    original.expected.hash.digest = "0".repeat(64);
    assert!(original.ensure_current(&identity).is_err());
    assert!(original.revoked.get());
    original.expected = expected;
    assert!(original.ensure_current(&identity).is_err());
    assert!(original.original.lease().is_none());
}

#[test]
fn executable_capacity_data_keeps_real_path_spares_and_descriptor_after_revocation() {
    use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;

    let fixture = NativeFixture::new();
    let mut original = OriginalExecutable::open_complete_bytes(
        fixture.child.id(),
        &fixture.measured(),
        &fixture.kernel(),
    )
    .unwrap();
    original.process_path.reserve(173);
    original.original_target.reserve(257);
    let paths = original.process_path.capacity() + original.original_target.capacity();
    let reference = &original.expected;
    let reference_bytes = reference.hash.algorithm.capacity()
        + reference.hash.domain.capacity()
        + reference.hash.digest.capacity()
        + reference.media_type.capacity();
    let mut census = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);
    original.record_capacity_data(&mut census).unwrap();
    let before = census.finish();

    assert_eq!(before.vector_banks, 2);
    assert_eq!(before.vector_capacity_bytes, paths);
    assert_eq!(before.string_capacity_bytes, reference_bytes);
    assert_eq!(before.shared_backing_views, 1);
    assert_eq!(before.shared_value_bytes, std::mem::size_of::<File>());
    let prefix = String::with_capacity(113);
    let mut short = OriginalOwnerCapacityMetadataData::new(3, None);
    short.observe(&prefix).unwrap();
    assert_eq!(
        original.record_capacity_data(&mut short),
        Err(crate::node_contract::RuntimeError::ResourceLimit)
    );
    let partial = short.finish();
    assert_eq!(partial.capacity_records, 3);
    assert_eq!(partial.string_capacity_bytes, prefix.capacity());
    assert_eq!(partial.vector_capacity_bytes, paths);

    original.revoked.set(true);
    let mut repeated = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);
    original.record_capacity_data(&mut repeated).unwrap();
    original.record_capacity_data(&mut repeated).unwrap();
    let after = repeated.finish();
    assert_eq!(after.capacity_records, before.capacity_records * 2);
    assert_eq!(after.vector_capacity_bytes, paths * 2);
    assert_eq!(after.shared_backing_views, 2);
    assert!(original.ensure_current(&fixture.kernel()).is_err());
}

#[test]
fn executable_capacity_data_refuses_worker_and_foreign_origin_before_rows() {
    use crate::node_contract::{
        RuntimeError, restored_owner_history::OriginalOwnerCapacityMetadataData,
    };

    let fixture = NativeFixture::new();
    let mut original = fixture.guard();
    assert!(original.original.lease().is_some());
    let mut census = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);
    assert_eq!(
        original.record_capacity_data(&mut census),
        Err(RuntimeError::UnsupportedFacet)
    );
    assert_eq!(census.finish().capacity_records, 0);

    original.creator = std::process::id().wrapping_add(1);
    let mut foreign = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);
    assert_eq!(
        original.record_capacity_data(&mut foreign),
        Err(RuntimeError::ForeignAuthority)
    );
    assert_eq!(foreign.finish().capacity_records, 0);
    original.creator = std::process::id();
}
