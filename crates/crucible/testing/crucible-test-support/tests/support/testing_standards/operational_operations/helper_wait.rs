//! Binds image-helper polling to its creator's saved Original and child.
//!
//! Only the bounded sleep is classified. The receiver retains process cleanup
//! and unresolved diagnostic custody; this contract issues neither custody.

use super::{Companion, Contract};

pub(super) const CONTRACT: Contract = Contract {
    package: "crucible-qemu-host",
    target: "src/spawn/helper_receiver",
    required: &[
        (
            r#"pub(super) fn wait_image_tool(
    child: &mut QemuNodeChild,
    original: &crucible_host_resources::host_supervision::HostOperationGuard,
    operation: &'static str,
) -> Result<(), QemuSpawnError>"#,
            1,
        ),
        (
            r#"let deadline = HostSupervisionDeadline::start(GUARDED_IMAGE_TOOL_TIMEOUT);
loop {
    let remaining = wait_slice(original)?;
    match child.try_wait_natural_exit_raw()"#,
            1,
        ),
        ("Ok(None) if deadline.has_time_remaining() =>", 1),
        (
            r#"Ok(None) => {
    return Err(QemuSpawnError::GuardedImageToolTimeout { operation });
}"#,
            1,
        ),
        (
            r#"pub(super) fn wait_slice(
    original: &crucible_host_resources::host_supervision::HostOperationGuard,
) -> Result<Duration, QemuSpawnError> {
    original.wait_slice().map_err(|source| QemuSpawnError::SourceAdmission {
        source: source.into(),
    })
}"#,
            1,
        ),
    ],
    expressions: &[(
        "thread::sleep(GUARDED_IMAGE_TOOL_POLL_INTERVAL.min(remaining));",
        1,
    )],
    identifiers: &[],
    companions: &[
        Companion {
            path: "crates/crucible/qemu/crucible-qemu-host/src/spawn.rs",
            required: &[
                (
                    r#"process_contract.with_spawned_helper(command, operation, |child, original| {
    helper_receiver::wait_image_tool(child, original, operation)
})"#,
                    1,
                ),
                (
                    r#"let mut status = None;
loop {
    let remaining = helper_receiver::wait_slice(original)?;
    if !deadline.has_time_remaining() {
        return Err(QemuSpawnError::GuardedQemuProbeTimeout);
    }"#,
                    1,
                ),
                (
                    r#"if !progressed {
    thread::sleep(GUARDED_IMAGE_TOOL_POLL_INTERVAL.min(remaining));
}"#,
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible/qemu/crucible-qemu-host/src/linux_attempt_host/original_node/helper_receiver.rs",
            required: &[
                ("let before = self.origin.wait_slice();", 1),
                (
                    "let post = HelperPost { original: &self.origin, slot: &mut slot, };",
                    1,
                ),
                ("Some(child) => body(child, &self.origin),", 1),
                ("self.slot.after = self.original.wait_slice().err();", 1),
            ],
        },
    ],
};
