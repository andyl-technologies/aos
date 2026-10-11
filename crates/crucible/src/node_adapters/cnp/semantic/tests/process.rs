//! Actual original process capsule retention and independently observed reclamation.

// crucible-lint: allow panic-shortcut -- Fixture assertions panic when original process custody is lost.
// crucible-lint: allow rust-allow -- Actual native process fixture assertions intentionally panic.
#![allow(clippy::unwrap_used)]

use std::{
    cell::RefCell,
    os::unix::{fs::DirBuilderExt, process::CommandExt},
    process::{Command, Stdio},
    rc::Rc,
};

use crucible_node_contract::{U64, canonical};
use crucible_node_provider::conformance::measure_executable;

use super::super::{CnpSemanticLaunchGuard, CnpSemanticProcessCustody, CnpSemanticProcessSlot};

struct Slot(Rc<RefCell<Vec<CnpSemanticProcessCustody>>>);

impl CnpSemanticProcessSlot for Slot {
    fn identity(&self) -> U64 {
        U64::new(1)
    }

    fn retain(&mut self, custody: CnpSemanticProcessCustody) {
        let mut retained = self.0.borrow_mut();
        assert!(
            retained.is_empty(),
            "exactly one native capsule was pre-reserved"
        );
        retained.push(custody);
    }
}

fn reclaim(original: &mut CnpSemanticProcessCustody) {
    super::operational_poll::original_poll(|| original.poll_reclamation().unwrap().then_some(()));
    assert!(original.kernel_resources_reclaimed().unwrap());
}

#[test]
fn generic_launch_drop_keeps_same_child_until_actual_reaping() {
    let directory = Directory::new();
    let operational = directory.path().join("original");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&operational)
        .unwrap();
    let executable = std::env::current_exe().unwrap();
    let measured = measure_executable(&executable).unwrap();
    let retained = Rc::new(RefCell::new(Vec::new()));
    let slot = Box::new(Slot(retained.clone()));
    let child = Command::new(executable)
        .args([
            "--ignored",
            "--exact",
            "node_adapters::cnp::semantic::tests::process::generic_owned_process",
            "--nocapture",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .process_group(0)
        .spawn()
        .unwrap();
    let original_pid = child.id();
    let guard = CnpSemanticLaunchGuard::new(child, operational, measured, slot)
        .ok()
        .unwrap();
    guard.custody().unwrap().authenticate_process().unwrap();
    drop(guard);

    let mut owned = retained.borrow_mut();
    assert_eq!(owned.len(), 1);
    assert_eq!(owned[0].provider_pid(), original_pid);
    assert!(!owned[0].kernel_resources_reclaimed().unwrap());
    reclaim(&mut owned[0]);
    // Repeated administrative cleanup reads the original reap; it cannot kill
    // a new numeric PID or create another semantic effect.
    assert!(owned[0].poll_reclamation().unwrap());
}

#[test]
fn foreign_executable_failure_retains_original_process_guard() {
    let directory = Directory::new();
    let executable = std::env::current_exe().unwrap();
    let retained = Rc::new(RefCell::new(Vec::new()));
    let slot = Box::new(Slot(retained.clone()));
    let child = Command::new(executable)
        .args([
            "--ignored",
            "--exact",
            "node_adapters::cnp::semantic::tests::process::generic_owned_process",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .process_group(0)
        .spawn()
        .unwrap();
    let original_pid = child.id();
    let foreign =
        canonical::content_ref(b"different executable", "application/octet-stream").unwrap();
    let failure = CnpSemanticLaunchGuard::new(child, directory.path().to_owned(), foreign, slot)
        .err()
        .unwrap();
    assert_eq!(
        failure.guard.custody().unwrap().provider_pid(),
        original_pid
    );
    drop(failure);
    let mut owned = retained.borrow_mut();
    assert_eq!(owned[0].provider_pid(), original_pid);
    reclaim(&mut owned[0]);
}

#[test]
#[ignore = "native process helper, launched with original held stdin"]
fn generic_owned_process() {
    let mut input = [0; 1];
    use std::io::Read;
    // The original pipe is retained beneath Child; EOF does not stand in for a
    // common native readiness or qualified physical-stop certificate.
    let _ = std::io::stdin().read(&mut input);
}

struct Directory(std::path::PathBuf);

impl Directory {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path =
            std::path::PathBuf::from(format!("/tmp/cnp-owned-{}-{sequence}", std::process::id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
