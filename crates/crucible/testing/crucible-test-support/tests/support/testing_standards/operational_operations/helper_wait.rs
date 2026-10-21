//! Binds image-helper polling to its creator's saved Original and child.
//!
//! Only the two bounded sleeps are classified. The receiver retains process cleanup
//! and unresolved diagnostic custody; this contract issues neither custody.

use super::{Companion, Contract};

pub(super) const CONTRACT: Contract = Contract {
    package: "crucible-qemu-host",
    target: "src/spawn/helper_receiver",
    required: &[
        ("pub(crate) const DESCRIPTOR_PEAK: u64 = 3 * 2 + 2;", 1),
        (
            r#"pub(crate) fn retained_control_bytes() -> Option<u64> {
    std::mem::size_of::<crate::node::RetainedChild>()
        .checked_add(std::mem::size_of::<RetainedHelperOutput>())
        .and_then(|bytes| bytes.checked_add(MAXIMUM_PROBE_OUTPUT_BYTES.checked_mul(2)?))
        .and_then(|bytes| u64::try_from(bytes).ok())
}"#,
            1,
        ),
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
        (
            r#"pub(super) fn wait_probe(
    child: &mut QemuNodeChild,
    original: &crucible_host_resources::host_supervision::HostOperationGuard,
    input: &[u8],
    maximum_output_bytes: usize,
    deadline: &HostSupervisionDeadline,
    output: &mut Option<RetainedHelperOutput>,
) -> Result<Output, QemuSpawnError>"#,
            1,
        ),
        (
            r#"loop {
    let remaining = wait_slice(original)?;
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
        (
            r#"fn prepare_storage() -> Option<RetainedHelperOutput> {
    Some(RetainedHelperOutput::PartialProbe(PartialProbeOutput {
        stdout: ProbeCapture::new(MAXIMUM_PROBE_OUTPUT_BYTES),
        stderr: ProbeCapture::new(MAXIMUM_PROBE_OUTPUT_BYTES),
        status: None,
    }))
}"#,
            1,
        ),
    ],
    expressions: &[(
        "thread::sleep(GUARDED_IMAGE_TOOL_POLL_INTERVAL.min(remaining));",
        2,
    )],
    identifiers: &[],
    companions: &[
        Companion {
            path: "crates/crucible/qemu/crucible-qemu-host/src/linux_attempt_host/original_roster/process_purpose.rs",
            required: &[
                (
                    r#".checked_add(helper_error_bytes)
.and_then(|bytes| {
    bytes.checked_add(crate::spawn::helper_receiver::MAXIMUM_PROBE_OUTPUT_BYTES.checked_mul(2)?,)
})"#,
                    1,
                ),
                (
                    r#"let (_, peak, descriptors) = source_admission::source_host_peak()?;
let host = normal.reserve_source_host_purpose(peak, descriptors, &original)
    .map_err(|source| InstalledProcessPurposeError::Original(source.into()))?;
let payer = host.downgrade();
controller.retain_source_host(host)?;
slot.source_control_payer = Some(payer);
purpose.ready = true;"#,
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible/qemu/crucible-qemu-host/src/linux_attempt_host/original_roster/process_purpose/source_admission.rs",
            required: &[
                (
                    r#"let host = slot.source_controller.as_ref()
    .ok_or(InstalledProcessPurposeError::Identity)?
    .retained_source_host()?.clone();
if !host.belongs_to(normal) || slot.source_control_payer.is_none() {
    return Err(InstalledProcessPurposeError::Identity);
}"#,
                    1,
                ),
                (
                    ".and_then(|bytes| bytes.checked_add(crate::spawn::helper_receiver::retained_control_bytes()?))",
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible/qemu/crucible-qemu-host/src/spawn.rs",
            required: &[
                (
                    r#"process_contract.with_spawned_helper(command, operation, |child, original, _output| {
    helper_receiver::wait_image_tool(child, original, operation)
})"#,
                    1,
                ),
                (
                    r#"helper_receiver::wait_probe(
    child, original, input, maximum_output_bytes, &deadline, output,
)"#,
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
                (
                    "Some(child) => body(child, &self.origin, &mut slot.output),",
                    1,
                ),
                (
                    r#"let controls = match self.reserve_helper_controls() {
    Ok(controls) => controls,
    Err(source) => {
        slot.save_first(crate::QemuSpawnError::SourceAdmission { source });
        return;
    }
};
slot.controls = Some(controls);
slot.probe_prepared |= T::CAPTURES_PROBE;
slot.output = T::prepare_storage();
let child = match command.spawn()"#,
                    1,
                ),
                (
                    r#"let controls = self.retained_source_host()?
    .reserve_controls(crate::spawn::helper_receiver::DESCRIPTOR_PEAK, bytes)?;
controls.verify_original_capacity(
    &self.origin, crate::spawn::helper_receiver::DESCRIPTOR_PEAK, bytes,
)?;"#,
                    1,
                ),
                ("self.slot.after = self.original.wait_slice().err();", 1),
            ],
        },
    ],
};
