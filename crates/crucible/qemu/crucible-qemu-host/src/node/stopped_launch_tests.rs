//! Checks the actual stopped-child signal and unique nonblocking reap authority.
//!
//! These controls use a genuine subprocess but install no QEMU, native Source,
//! cgroup or resource authority. They qualify only the physical wait transition.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::QemuNodeChild;

const PARK_HELPER: &str = "CRUCIBLE_STOPPED_LAUNCH_PARK_HELPER";

#[test]
fn stopped_launch_wait_helper() {
    if std::env::var_os(PARK_HELPER).is_some() {
        loop {
            std::thread::park();
        }
    }
}

// crucible-lint: allow clippy-disallowed-method -- the test-only clock bounds actual subprocess containment and cannot affect modeled execution.
#[allow(clippy::disallowed_methods)]
#[test]
fn stopped_child_poll_requires_actual_reap_and_remains_idempotent() {
    let process = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "node::stopped_launch_tests::stopped_launch_wait_helper",
            "--nocapture",
        ])
        .env(PARK_HELPER, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut child = QemuNodeChild::new(process);
    assert!(!child.reaped);

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.kill_and_poll_reap().unwrap() {
            true => break,
            false => {
                assert!(!child.reaped);
                assert!(
                    Instant::now() < deadline,
                    "actual killed child did not reap"
                );
                std::thread::yield_now();
            }
        }
    }

    assert!(child.reaped);
    assert!(child.child.try_wait().unwrap().is_some());
    assert!(child.kill_and_poll_reap().unwrap());
}
