//! Process-boundary tests for the fixed mount helper launcher.

use std::os::fd::AsFd as _;
use std::path::Path;

use aos_sandbox_mount::spawn::{
    DescriptorMapping, MOUNT_NAMESPACE_FD, PLAN_FD, TARGET_ROOT_FD, TARGET_SLOT_FD,
    run_helper_status,
};

#[test]
fn spawned_helper_gets_exact_fds_and_empty_environment() {
    let file = tempfile::tempfile().unwrap_or_else(|error| panic!("temporary file: {error}"));
    let mappings = [
        DescriptorMapping {
            target: PLAN_FD,
            source: file.as_fd(),
        },
        DescriptorMapping {
            target: MOUNT_NAMESPACE_FD,
            source: file.as_fd(),
        },
        DescriptorMapping {
            target: TARGET_ROOT_FD,
            source: file.as_fd(),
        },
        DescriptorMapping {
            target: TARGET_SLOT_FD,
            source: file.as_fd(),
        },
    ];
    let executable = Path::new(env!("CARGO_BIN_EXE_aos-sandbox-mount-helper"));
    let status = run_helper_status(executable, &mappings)
        .unwrap_or_else(|error| panic!("helper launch failed: {error}"));
    assert_eq!(status, 1, "unsealed plan input must fail inside the helper");
}
