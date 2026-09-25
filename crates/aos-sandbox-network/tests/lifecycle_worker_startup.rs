//! Launched-process checks for the fixed lifecycle admission worker startup.

use std::fs::File;
use std::os::fd::AsRawFd as _;
use std::process::{Command, Output, Stdio};

use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};

struct RestoredDescriptorFlags<'a> {
    descriptor: &'a File,
    flags: FdFlags,
}

impl Drop for RestoredDescriptorFlags<'_> {
    fn drop(&mut self) {
        let _ = fcntl_setfd(self.descriptor, self.flags);
    }
}

fn run_worker(guarded: bool) -> std::io::Result<Output> {
    let worker = env!("CARGO_BIN_EXE_aos-sandbox-network-lifecycle-worker");
    let mut command = if guarded {
        let mut command = Command::new(env!("AOS_NO_SETID_TEST_LAUNCHER"));
        command.arg(worker);
        command
    } else {
        Command::new(worker)
    };

    command
        .args(std::iter::repeat_n("/dev/null", 7))
        .stdin(Stdio::null())
        .output()
}

#[test]
fn launched_worker_rejects_an_extra_inherited_descriptor_before_ready() {
    let support = Command::new(env!("AOS_NO_SETID_TEST_LAUNCHER"))
        .arg("--probe")
        .status()
        .expect("query AOS no-set-ID kernel support");
    if support.code() == Some(77) {
        // Stock build hosts cannot reach the descriptor check. The pure
        // descriptor-table test remains authoritative for that contract.
        let unguarded = run_worker(false).expect("launch unguarded worker process");
        assert!(!unguarded.status.success(), "unguarded worker succeeded");
        assert!(
            String::from_utf8_lossy(&unguarded.stderr).contains("Network startup guard failed"),
            "{}",
            String::from_utf8_lossy(&unguarded.stderr)
        );
        return;
    }
    assert!(
        support.success(),
        "no-set-ID kernel probe failed: {support}"
    );

    let baseline = run_worker(true).expect("launch baseline guarded worker process");
    let baseline_error = String::from_utf8_lossy(&baseline.stderr);
    assert!(
        !baseline.status.success(),
        "baseline unexpectedly succeeded"
    );
    assert!(
        !baseline_error.contains("inherited an unexpected descriptor"),
        "{baseline_error}"
    );

    let ambient = File::open("/dev/null").expect("open ambient descriptor");
    assert!(ambient.as_raw_fd() >= 3);
    let original_flags = fcntl_getfd(&ambient).expect("read ambient descriptor flags");
    let restore = RestoredDescriptorFlags {
        descriptor: &ambient,
        flags: original_flags,
    };
    let mut inherited_flags = original_flags;
    inherited_flags.remove(FdFlags::CLOEXEC);
    fcntl_setfd(&ambient, inherited_flags).expect("make ambient descriptor inheritable");

    let extra = run_worker(true).expect("launch guarded worker with ambient descriptor");
    drop(restore);

    let extra_error = String::from_utf8_lossy(&extra.stderr);
    assert!(!extra.status.success(), "extra-descriptor worker succeeded");
    assert!(
        extra_error.contains("inherited an unexpected descriptor"),
        "{extra_error}"
    );
}
