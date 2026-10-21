//! Binds image-helper polling to its creator's saved Original and child.
//!
//! Only the two bounded sleeps are classified. The receiver retains process cleanup
//! and unresolved diagnostic custody; this contract issues neither custody.

use super::{Companion, Contract};

#[path = "helper_wait/funding.rs"]
mod funding;
#[path = "helper_wait/probe_output.rs"]
mod probe_output;

pub(super) const CONTRACT: Contract = Contract {
    package: "crucible-qemu-host",
    target: "src/spawn/helper_receiver",
    required: &[
        ("pub(crate) const DESCRIPTOR_PEAK: u64 = 3 * 2 + 2;", 1),
        (
            r#"pub(crate) fn retained_control_bytes() -> Option<u64> {
    std::mem::size_of::<crate::node::RetainedChild>()
        .checked_add(std::mem::size_of::<RetainedHelperOutput>())
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<GuardedProbeOutput>()))
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
        probe_output::OWNER,
        probe_output::RECEIVER,
        probe_output::HANDOFF,
        probe_output::CONSUMER,
        funding::MAIN,
        funding::CONTROLLER,
        funding::FIRST,
        funding::JOURNAL,
        funding::ORIGINAL,
        funding::SHARED,
        funding::ERASED,
        funding::API,
        funding::CLAIM,
        Companion {
            path: "crates/crucible/host/crucible-host-resources/src/host_services/process_birth/executor_purpose/source_host.rs",
            required: &[
                (
                    "pub struct AuthenticatedSourceHostPurpose { held: RetainedControl<SourceHostState>, }",
                    1,
                ),
                (
                    r#"pub struct SourceHostControlPayer {
    purpose: AuthenticatedSourceHostPurpose,
}
impl SourceHostControlPayer {
    pub fn reserve_controls(&self, descriptors: u64, bytes: u64,)
        -> Result<SourceHostControlLease, ServiceBirthError>
    {
        self.purpose.reserve_controls(descriptors, bytes)
    }
}"#,
                    1,
                ),
                (
                    r#"pub fn retain_control_payer(&self) -> SourceHostControlPayer {
    SourceHostControlPayer { purpose: self.clone(), }
}"#,
                    1,
                ),
                (
                    r#"held: RetainedControl::new(SourceHostState {
    issuer, window: Some(window),
    child: Mutex::new(SourceChildState::default()),
    controls: Mutex::new(SourceControlState::default()),
    control_peak, descriptor_peak,
    descriptors: Some(descriptors), metadata: Some(metadata),
}),"#,
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible/host/crucible-host-resources/src/host_services/process_birth/executor_purpose/source_host/retained_control.rs",
            required: &[
                (
                    "pub(super) struct RetainedControl<T> { shared: Option<Arc<T>>, }",
                    1,
                ),
                (
                    r#"pub(super) fn new(value: T) -> Self {
    Self { shared: Some(Arc::new(value)), }
}"#,
                    1,
                ),
                (
                    r#"fn shared(&self) -> &Arc<T> {
    match &self.shared {
        Some(shared) => shared,
        None => unreachable!("a live control retains its original allocation"),
    }
}"#,
                    1,
                ),
                (
                    r#"impl<T> Clone for RetainedControl<T> {
    fn clone(&self) -> Self { Self { shared: self.shared.clone(), } }
}"#,
                    1,
                ),
                (
                    r#"impl<T> Drop for RetainedControl<T> {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.take() {
            drop(Arc::into_inner(shared));
        }
    }
}"#,
                    1,
                ),
            ],
        },
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
                    r#"let host = slot.source_controller.as_ref()
    .ok_or(InstalledProcessPurposeError::Identity)?
    .retained_source_host()?;
if !host.belongs_to(normal) {
    return Err(InstalledProcessPurposeError::Identity);
}
slot.source_control_payer = Some(host.retain_control_payer());
purpose.ready = true;"#,
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible/qemu/crucible-qemu-host/src/linux_attempt_host/original_roster/process_purpose/source_admission.rs",
            required: &[
                (
                    ".and_then(|bytes| { bytes.checked_add(controller_peak_bytes().ok()?) })",
                    1,
                ),
                (
                    ".and_then(|bytes| bytes.checked_add(crate::spawn::helper_first::control_peak_bytes()?))",
                    1,
                ),
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
                    r#"pub(crate) fn issued(
    source: QemuSpawnError,
    receiver: &crate::linux_attempt_host::SourceCleanupLender,
) -> Self {
    Self {
        source,
        receiver: Some(QemuIssuedHelperReceiver::from_lender(receiver.clone())),
    }
}"#,
                    1,
                ),
                (
                    r#"pub fn retained_receiver_identity(&self) -> Option<QemuIssuedHelperReceiver> {
    self.receiver.clone()
}"#,
                    1,
                ),
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
