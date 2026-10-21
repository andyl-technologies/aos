//! Requires successful probe bytes to move with their actual existing loan.

use super::super::Companion;

pub(super) const OWNER: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/spawn/helper_receiver/probe_output.rs",
    required: &[
        (
            r#"pub(crate) struct FundedProbeOutput<Funding> {
    output: Output,
    _funding: Funding,
}"#,
            1,
        ),
        (
            "pub(crate) type GuardedProbeOutput = FundedProbeOutput<SourceHostControlLease>;",
            1,
        ),
        (
            r#"impl<Funding> FundedProbeOutput<Funding> {
    pub(super) fn new(output: Output, funding: Funding) -> Self {
        Self {
            output,
            _funding: funding,
        }
    }

    pub(crate) fn output(&self) -> &Output {
        &self.output
    }
}"#,
            1,
        ),
    ],
};

pub(super) const RECEIVER: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/spawn/helper_receiver.rs",
    required: &[
        ("type Received = GuardedProbeOutput;", 1),
        (
            r#"fn receive(
    self,
    controls: crucible_host_resources::host_services::process_birth::SourceHostControlLease,
) -> Self::Received {
    GuardedProbeOutput::new(self, controls)
}"#,
            1,
        ),
    ],
};

pub(super) const HANDOFF: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/linux_attempt_host/original_node/helper_receiver.rs",
    required: &[(
        r#"if slot.child.is_none() && slot.first_cleanup.is_none() && slot.output.is_some() {
    let controls = slot.controls.take().ok_or_else(refused)?;
    let output = slot.output.take().ok_or_else(refused)?;
    let output = T::take(output).ok_or_else(refused)?;
    drop(slot.effect_original.take());
    return Ok(output.receive(controls));
}"#,
        1,
    )],
};

pub(super) const CONSUMER: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/launch/whitebox_setup.rs",
    required: &[
        ("validate_x86_whitebox_probe_output(output.output())", 1),
        (
            r#"fn validate_x86_whitebox_probe_output(
    output: &std::process::Output,
) -> Result<QemuWhiteboxSetupValidation, QemuWhiteboxSetupError>"#,
            1,
        ),
        (
            r#"let stdout = std::str::from_utf8(&output.stdout)
    .map_err(|source| QemuWhiteboxSetupError::MonitorOutputUtf8 { source })?;
validate_x86_whitebox_hmp_mtree(stdout)"#,
            1,
        ),
    ],
};
