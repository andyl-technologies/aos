//! Routes helper births into their constructor-bound issued Source recipient.
//!
//! The contract keeps only weak nominal links. The source's existing fixed
//! controller owns the child before any pipe validation or independent post.
//! Polling borrows that same creation Original; a command limit cannot renew it.

use super::*;

impl QemuChildProcessContract {
    /// Projects an inert weak identity for this contract's genuine helper owner.
    ///
    /// The actual first-bound Source lender validates its active incarnation
    /// before this projection. The weak reference grants no helper effect,
    /// Cleanup, return loan or funding; cleanup still uses that owner's saved
    /// lender and Original. Missing or unavailable custody returns `None`.
    #[must_use]
    pub fn issued_helper_receiver(
        &self,
    ) -> Option<std::sync::Weak<crate::OriginalNativeFreshLaunchError>> {
        let lender = self.attempt_binding.helper_receiver.get()?;
        let controller = lender.controller().ok()?;
        Some(std::sync::Arc::downgrade(&controller))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn bind_helper_receiver(
        &self,
        receiver: crate::linux_attempt_host::SourceCleanupLender,
    ) -> Result<(), QemuSpawnError> {
        if let Some(bound) = self.attempt_binding.helper_receiver.get() {
            return if bound.same_identity(&receiver) {
                Ok(())
            } else {
                Err(helper_custody_refusal())
            };
        }
        self.attempt_binding
            .helper_receiver
            .set(receiver)
            .map_err(|_| helper_custody_refusal())
    }

    /// Validates the actual first-bound helper recipient before any birth.
    ///
    /// # Errors
    /// Refuses absent, expired, mismatched or unavailable Source custody.
    pub fn require_issued_helper_receiver(&self) -> Result<(), QemuSpawnError> {
        #[cfg(target_os = "linux")]
        {
            let lender = self
                .attempt_binding
                .helper_receiver
                .get()
                .ok_or_else(helper_custody_refusal)?;
            lender
                .controller()
                .map(|_| ())
                .map_err(|_| helper_custody_refusal())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(helper_custody_refusal())
        }
    }

    pub(super) fn with_spawned_helper<T: HelperOutput>(
        &self,
        command: Command,
        operation: &'static str,
        body: impl FnOnce(
            &mut QemuNodeChild,
            &crucible_host_resources::host_supervision::HostOperationGuard,
            &mut Option<RetainedHelperOutput>,
        ) -> Result<T, QemuSpawnError>,
    ) -> Result<T, QemuGuardedImagePreparationError> {
        #[cfg(target_os = "linux")]
        {
            let receiver =
                self.attempt_binding.helper_receiver.get().ok_or_else(|| {
                    QemuGuardedImagePreparationError::local(helper_custody_refusal())
                })?;
            let controller = receiver
                .controller()
                .map_err(|_| QemuGuardedImagePreparationError::local(helper_custody_refusal()))?;
            controller.with_spawned_helper(receiver, command, operation, body)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (command, operation, body);
            Err(QemuGuardedImagePreparationError::local(
                helper_custody_refusal(),
            ))
        }
    }
}

pub(crate) fn helper_custody_refusal() -> QemuSpawnError {
    invalid_input(
        "retain guarded helper",
        "issued helper custody is unavailable or still occupied",
    )
}

/// Borrows the creation Original's remaining slice without entering new work.
///
/// # Errors
/// Preserves the same Original's cancellation, expiry or supervision refusal.
pub(super) fn wait_slice(
    original: &crucible_host_resources::host_supervision::HostOperationGuard,
) -> Result<Duration, QemuSpawnError> {
    original
        .wait_slice()
        .map_err(|source| QemuSpawnError::SourceAdmission {
            source: source.into(),
        })
}

/// Observes an image helper under its creator's existing operation.
///
/// # Errors
/// Preserves operation refusal, command timeout, unsuccessful exit or wait IO.
/// The caller retains the child and remains responsible for physical cleanup.
pub(super) fn wait_image_tool(
    child: &mut QemuNodeChild,
    original: &crucible_host_resources::host_supervision::HostOperationGuard,
    operation: &'static str,
) -> Result<(), QemuSpawnError> {
    let deadline = HostSupervisionDeadline::start(GUARDED_IMAGE_TOOL_TIMEOUT);
    loop {
        // The command limit can only tighten the saved Original. A local
        // timeout never permits polling or waiting after that Original refuses.
        let remaining = wait_slice(original)?;
        match child.try_wait_natural_exit_raw() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => {
                return Err(QemuSpawnError::GuardedImageTool { operation, status });
            }
            Ok(None) if deadline.has_time_remaining() => {
                thread::sleep(GUARDED_IMAGE_TOOL_POLL_INTERVAL.min(remaining));
            }
            Ok(None) => {
                return Err(QemuSpawnError::GuardedImageToolTimeout { operation });
            }
            Err(error) => return Err(QemuSpawnError::from_helper_wait(operation, error)),
        }
    }
}

/// Polls the probe while its original receiver owns both partial captures.
///
/// # Errors
/// Preserves pipe, read, write, Original, timeout and output-limit refusal. Every
/// byte collected before refusal remains in `output`; the caller owns cleanup.
pub(super) fn wait_probe(
    child: &mut QemuNodeChild,
    original: &crucible_host_resources::host_supervision::HostOperationGuard,
    input: &[u8],
    maximum_output_bytes: usize,
    deadline: &HostSupervisionDeadline,
    output: &mut Option<RetainedHelperOutput>,
) -> Result<Output, QemuSpawnError> {
    let (child_stdin, child_stdout, child_stderr) = child.take_guarded_probe_pipes()?;
    nonblocking_probe_pipe(&child_stdin)
        .and_then(|()| nonblocking_probe_pipe(&child_stdout))
        .and_then(|()| nonblocking_probe_pipe(&child_stderr))?;
    let mut stdin = (!input.is_empty()).then_some(child_stdin);
    let mut stdout = child_stdout;
    let mut stderr = child_stderr;
    let mut written = 0;
    let Some(RetainedHelperOutput::PartialProbe(capture)) = output else {
        return Err(helper_custody_refusal());
    };
    let stdout_capture = &mut capture.stdout;
    let stderr_capture = &mut capture.stderr;
    stdout_capture.maximum_bytes = maximum_output_bytes;
    stderr_capture.maximum_bytes = maximum_output_bytes;

    loop {
        let remaining = wait_slice(original)?;
        if !deadline.has_time_remaining() {
            return Err(QemuSpawnError::GuardedQemuProbeTimeout);
        }

        let mut progressed = false;
        if let Some(pipe) = stdin.as_mut() {
            match pipe.write(&input[written..]) {
                Ok(0) => {
                    return Err(QemuSpawnError::Io {
                        operation: "write guarded QEMU setup probe input",
                        source: io::ErrorKind::WriteZero.into(),
                    });
                }
                Ok(count) => {
                    written += count;
                    progressed = true;
                    if written == input.len() {
                        stdin = None;
                    }
                }
                Err(error) if retryable_probe_io(&error) => {}
                Err(source) => {
                    return Err(QemuSpawnError::Io {
                        operation: "write guarded QEMU setup probe input",
                        source,
                    });
                }
            }
        }

        match stdout_capture.read_once(&mut stdout) {
            Ok(read_progressed) => progressed |= read_progressed,
            Err(source) => {
                return Err(QemuSpawnError::Io {
                    operation: "read guarded QEMU setup probe stdout",
                    source,
                });
            }
        }
        match stderr_capture.read_once(&mut stderr) {
            Ok(read_progressed) => progressed |= read_progressed,
            Err(source) => {
                return Err(QemuSpawnError::Io {
                    operation: "read guarded QEMU setup probe stderr",
                    source,
                });
            }
        }
        if stdout_capture.exceeded || stderr_capture.exceeded {
            return Err(QemuSpawnError::GuardedQemuProbeOutputLimit {
                maximum_bytes: maximum_output_bytes,
            });
        }

        if capture.status.is_none() {
            match child.try_wait_natural_exit_raw() {
                Ok(observed) => capture.status = observed,
                Err(error) => {
                    return Err(QemuSpawnError::from_helper_wait(
                        "poll guarded QEMU setup probe",
                        error,
                    ));
                }
            }
        }
        if stdout_capture.eof
            && stderr_capture.eof
            && stdin.is_none()
            && let Some(status) = capture.status
        {
            return Ok(Output {
                status,
                stdout: std::mem::take(&mut stdout_capture.bytes),
                stderr: std::mem::take(&mut stderr_capture.bytes),
            });
        }

        if !progressed {
            thread::sleep(GUARDED_IMAGE_TOOL_POLL_INTERVAL.min(remaining));
        }
    }
}

/// Moves either existing helper output into the same fixed recipient journal.
pub(crate) trait HelperOutput: Sized {
    const CAPTURES_PROBE: bool;
    fn prepare_storage() -> Option<RetainedHelperOutput>;
    fn retain(self) -> RetainedHelperOutput;
    fn take(output: RetainedHelperOutput) -> Option<Self>;
}

pub(crate) enum RetainedHelperOutput {
    Image,
    Probe(std::process::Output),
    PartialProbe(PartialProbeOutput),
}

/// Bounds both diagnostic allocations within the Source constructor recipe.
pub(crate) const MAXIMUM_PROBE_OUTPUT_BYTES: usize = 1024 * 1024;

/// Covers three stdio pipe pairs and libstd's fork/exec error-channel pair.
///
/// The pinned Rust 1.98.1 command creates these before discarding child ends.
/// Helpers install pre-exec authority, and do not request an optional pidfd.
/// Reserving only the three returned parent ends would miss this birth overlap.
pub(crate) const DESCRIPTOR_PEAK: u64 = 3 * 2 + 2;

/// Measures one helper's child journal and both full diagnostic capacities.
///
/// The containing Main Source reserves this fixed overlap before helper birth.
/// This query creates no payer, operation or physical-return evidence.
pub(crate) fn retained_control_bytes() -> Option<u64> {
    std::mem::size_of::<crate::node::RetainedChild>()
        .checked_add(std::mem::size_of::<RetainedHelperOutput>())
        .and_then(|bytes| bytes.checked_add(MAXIMUM_PROBE_OUTPUT_BYTES.checked_mul(2)?))
        .and_then(|bytes| u64::try_from(bytes).ok())
}

/// Keeps in-progress bytes in the receiving journal across error and unwind.
pub(crate) struct PartialProbeOutput {
    pub(super) stdout: ProbeCapture,
    pub(super) stderr: ProbeCapture,
    status: Option<std::process::ExitStatus>,
}

impl RetainedHelperOutput {
    pub(crate) fn probe_status(&self) -> Option<std::process::ExitStatus> {
        match self {
            Self::Probe(output) => Some(output.status),
            Self::PartialProbe(output) => output.status,
            Self::Image => None,
        }
    }

    pub(crate) fn probe_bytes(&self) -> Option<(&[u8], &[u8])> {
        match self {
            Self::Probe(output) => Some((&output.stdout, &output.stderr)),
            Self::PartialProbe(output) => Some((&output.stdout.bytes, &output.stderr.bytes)),
            Self::Image => None,
        }
    }
}

impl HelperOutput for () {
    const CAPTURES_PROBE: bool = false;

    fn prepare_storage() -> Option<RetainedHelperOutput> {
        None
    }

    fn retain(self) -> RetainedHelperOutput {
        RetainedHelperOutput::Image
    }
    fn take(output: RetainedHelperOutput) -> Option<Self> {
        match output {
            RetainedHelperOutput::Image => Some(()),
            _ => None,
        }
    }
}

impl HelperOutput for std::process::Output {
    const CAPTURES_PROBE: bool = true;

    fn prepare_storage() -> Option<RetainedHelperOutput> {
        Some(RetainedHelperOutput::PartialProbe(PartialProbeOutput {
            stdout: ProbeCapture::new(MAXIMUM_PROBE_OUTPUT_BYTES),
            stderr: ProbeCapture::new(MAXIMUM_PROBE_OUTPUT_BYTES),
            status: None,
        }))
    }

    fn retain(self) -> RetainedHelperOutput {
        RetainedHelperOutput::Probe(self)
    }
    fn take(output: RetainedHelperOutput) -> Option<Self> {
        match output {
            RetainedHelperOutput::Probe(output) => Some(output),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_host_resources::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };

    const CHILD_PROBE: &str = "CRUCIBLE_HELPER_PARTIAL_PROBE_COMPONENT";
    const CHILD_WAIT: &str = "CRUCIBLE_HELPER_ORIGINAL_WAIT_COMPONENT";
    const CHILD_CASE: &str = "spawn::helper_receiver::tests::image_wait_component_child";

    // These controls exercise the production wait with a real process and a
    // component Original. They issue no native Source, receiver or funding.
    #[test]
    fn image_wait_retains_the_live_child_when_its_same_original_is_canceled()
    -> Result<(), Box<dyn std::error::Error>> {
        let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let original = supervisor.begin(HostOperationClass::Preparation)?;
        let child = Command::new(std::env::current_exe()?)
            .args(["--exact", CHILD_CASE])
            .env(CHILD_WAIT, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let mut child = QemuNodeChild::new(child);
        assert!(child.try_wait_natural_exit_raw().unwrap().is_none());

        // Cancellation occurs after process birth and the creation entry cut.
        original.wait_slice()?;
        supervisor.cancel()?;
        let first = original.wait_slice().unwrap_err();
        let observed = wait_image_tool(&mut child, &original, "component image wait");

        assert!(matches!(
            observed,
            Err(QemuSpawnError::SourceAdmission {
                source: crate::linux_attempt_host::OriginalActorAccountError::Supervision(source),
            }) if source == first
        ));
        assert!(child.try_wait_natural_exit_raw().unwrap().is_none());
        // The process owner, rather than the wait's returned error, still
        // performs physical containment and reap on this component path.
        drop(child);
        Ok(())
    }

    #[test]
    fn image_wait_observes_success_under_the_existing_original()
    -> Result<(), Box<dyn std::error::Error>> {
        let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let original = supervisor.begin(HostOperationClass::Preparation)?;
        let operation_id = original.status()?.operation_id;
        let child = Command::new(std::env::current_exe()?)
            .args(["--exact", CHILD_CASE])
            .env_remove(CHILD_WAIT)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let mut child = QemuNodeChild::new(child);

        wait_image_tool(&mut child, &original, "component image wait")?;

        assert_eq!(original.status()?.operation_id, operation_id);
        original.complete()?;
        Ok(())
    }

    #[test]
    fn probe_timeout_retains_both_partial_streams_and_the_live_child()
    -> Result<(), Box<dyn std::error::Error>> {
        let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let original = supervisor.begin(HostOperationClass::Preparation)?;
        let deadline = HostSupervisionDeadline::start(Duration::from_secs(2));
        let mut output = <Output as HelperOutput>::prepare_storage();
        let child = Command::new(std::env::current_exe()?)
            .args(["--exact", CHILD_CASE, "--nocapture"])
            .env(CHILD_PROBE, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut child = QemuNodeChild::new(child);

        let result = wait_probe(&mut child, &original, &[], 1024, &deadline, &mut output);

        assert!(matches!(
            result,
            Err(QemuSpawnError::GuardedQemuProbeTimeout)
        ));
        let (stdout, stderr) = output.as_ref().unwrap().probe_bytes().unwrap();
        assert!(
            stdout
                .windows(b"partial probe stdout".len())
                .any(|bytes| bytes == b"partial probe stdout")
        );
        assert_eq!(stderr, b"partial probe stderr");
        assert!(output.as_ref().unwrap().probe_status().is_none());
        assert!(child.try_wait_natural_exit_raw().unwrap().is_none());
        drop(child);
        Ok(())
    }

    #[test]
    fn probe_output_limit_keeps_the_first_bounded_bytes_and_child_custody()
    -> Result<(), Box<dyn std::error::Error>> {
        let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let original = supervisor.begin(HostOperationClass::Preparation)?;
        let deadline = HostSupervisionDeadline::start(Duration::from_secs(2));
        let mut output = <Output as HelperOutput>::prepare_storage();
        let child = Command::new(std::env::current_exe()?)
            .args(["--exact", CHILD_CASE, "--nocapture"])
            .env(CHILD_PROBE, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut child = QemuNodeChild::new(child);

        let result = wait_probe(&mut child, &original, &[], 7, &deadline, &mut output);

        assert!(matches!(
            result,
            Err(QemuSpawnError::GuardedQemuProbeOutputLimit { maximum_bytes: 7 })
        ));
        let (stdout, stderr) = output.as_ref().unwrap().probe_bytes().unwrap();
        assert!(stdout.len() <= 7);
        assert!(stderr.len() <= 7);
        assert!(!stdout.is_empty() || !stderr.is_empty());
        assert!(child.try_wait_natural_exit_raw().unwrap().is_none());
        drop(child);
        Ok(())
    }

    #[test]
    fn probe_capture_never_grows_beyond_its_prepaid_capacity() {
        let mut capture = ProbeCapture::new(7);
        let capacity = capture.bytes.capacity();
        let mut input = &b"overlong diagnostic"[..];

        assert!(capture.read_once(&mut input).unwrap());

        assert_eq!(capture.bytes, b"overlon");
        assert!(capture.exceeded);
        assert_eq!(capture.bytes.capacity(), capacity);
        assert_eq!(capacity, 7);
    }

    #[test]
    fn image_wait_component_child() -> std::io::Result<()> {
        if std::env::var_os(CHILD_PROBE).is_some() {
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(b"partial probe stdout")?;
            stdout.flush()?;
            std::io::stderr().write_all(b"partial probe stderr")?;
            loop {
                std::thread::park();
            }
        }
        if std::env::var_os(CHILD_WAIT).is_some() {
            std::io::copy(&mut std::io::stdin(), &mut std::io::sink())?;
        }
        Ok(())
    }
}
