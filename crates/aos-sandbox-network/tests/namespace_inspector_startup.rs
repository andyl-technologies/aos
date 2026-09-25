//! Launched-process checks for the fixed namespace-inspector startup guard.

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

fn run_inspector(guarded: bool) -> std::io::Result<Output> {
    let inspector = env!("CARGO_BIN_EXE_aos-sandbox-network-namespace-inspector");
    let mut command = if guarded {
        let mut command = Command::new(env!("AOS_NO_SETID_TEST_LAUNCHER"));
        command.arg(inspector);
        command
    } else {
        Command::new(inspector)
    };

    command.stdin(Stdio::null()).output()
}

#[test]
fn inspector_requires_kernel_guard_before_admitting_inherited_descriptors() {
    let support = Command::new(env!("AOS_NO_SETID_TEST_LAUNCHER"))
        .arg("--probe")
        .status()
        .expect("query AOS no-set-ID kernel support");
    if support.code() == Some(77) {
        let unguarded = run_inspector(false).expect("launch unguarded inspector");
        assert!(!unguarded.status.success(), "unguarded inspector succeeded");
        assert!(
            String::from_utf8_lossy(&unguarded.stderr).contains("PR_GET_AOS_NO_SETID"),
            "{}",
            String::from_utf8_lossy(&unguarded.stderr)
        );
        return;
    }
    assert!(
        support.success(),
        "no-set-ID kernel probe failed: {support}"
    );

    let unguarded = run_inspector(false).expect("launch unguarded inspector");
    let unguarded_error = String::from_utf8_lossy(&unguarded.stderr);
    assert!(!unguarded.status.success(), "unguarded inspector succeeded");
    assert!(
        unguarded_error.contains("PR_GET_AOS_NO_SETID"),
        "{unguarded_error}"
    );

    let baseline = run_inspector(true).expect("launch guarded inspector");
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

    let extra = run_inspector(true).expect("launch guarded inspector with ambient descriptor");
    drop(restore);

    let extra_error = String::from_utf8_lossy(&extra.stderr);
    assert!(
        !extra.status.success(),
        "extra-descriptor inspector succeeded"
    );
    assert!(
        extra_error.contains("inherited an unexpected descriptor"),
        "{extra_error}"
    );
}
