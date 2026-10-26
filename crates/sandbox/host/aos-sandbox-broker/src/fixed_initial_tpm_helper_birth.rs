//! Retains native birth of a fixed initial TPM helper without releasing auth.
//!
//! The genuine Source pays construction before the inert owner is allocated,
//! then pays its observed finite stack and complete native setup before IO.
//! The existing fixed-process supervisor owns the fork, exec confirmation,
//! pidfd, bounded output and failed setup. A driving borrow keeps that same
//! child alive while the held ELF/loader and original proc descriptors are
//! compared. Dropping the borrow fences and signals the child while retaining
//! its native originals and cleanup debt in this owner.
//!
//! The handoff sends public HELLO and validates the retained child ACK. It
//! receives no credential path or exported key. A private Source borrow sends
//! AUTH only after the actual child ACK. The same carrier then bounds an initial
//! Read, at most one Extend and a final Read, retaining native replies before
//! admission. Decoded projections are DATA; Security owns approval, public-area
//! interpretation and checkpoint authority.

use std::os::fd::OwnedFd;
use std::time::Duration;

use aos_linux_descriptors::Error as LinuxError;
use aos_sandbox_linux::pidfd::{
    PidFdProcObservationsV1, PidFdProcOriginalsV1, PidFdProcessIdentity,
    prepare_proc_observations_v1,
};
use aos_sandbox_linux::process::{
    FixedProcessBoottimeCutV1, FixedProcessCaptureV1, FixedProcessDrivenInputsV1,
    FixedProcessDrivenProgressV1, FixedProcessDrivenSessionV1, FixedProcessDrivingLoanV1,
    FixedProcessPreparedInvocationV1, FixedProcessRequest, FixedProcessRunOriginalV3,
    prepare_fixed_process_driven_invocation_v1,
};
use aos_sandbox_linux::seqpacket::{RecordSubjectSeqpacketPairOriginalV2, SeqpacketSocket};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use rustix::process::{Resource, Rlimit, getrlimit};
use rustix::time::{ClockId, Timespec, clock_gettime};

use crate::fixed_tpm_helper_image::{
    FixedTpmHelperPurposeV1, HelperExecutedImageOriginalV1, MeasuredHelperImageV1,
};

mod handoff;
use handoff::InitialHelperHandoffOriginalV1;

const OUTPUT_BYTES: usize = 4096;
const CHILD_TIMEOUT: Duration = Duration::from_secs(60);

/// Refuses incomplete native setup or a mismatched initial helper process.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("fixed initial TPM helper birth is incomplete or refused")]
pub struct InitialTpmHelperBirthClosedV1;

/// Retains the initial helper's actual image, channel and process reservoir.
///
/// Construction grants no receiving permission. The genuine owner separately
/// pays the fixed construction demand, observes the actual finite stack, then
/// pays the native demand before preparing or driving this value.
#[must_use = "retain the actual native owner through failed birth and owed posts"]
pub struct FixedInitialTpmHelperBirthOriginalV1 {
    image: MeasuredHelperImageV1,
    pair: RecordSubjectSeqpacketPairOriginalV2,
    channel: Option<SeqpacketSocket>,
    child_endpoint: Option<OwnedFd>,
    executable_duplicate: Option<std::io::Result<OwnedFd>>,
    prepared: Option<Result<FixedProcessPreparedInvocationV1, LinuxError>>,
    process: Option<FixedProcessDrivenSessionV1>,
    stack: Option<Rlimit>,
    stack_before_spawn: Option<Rlimit>,
    clock: Option<Timespec>,
    cut: Option<FixedProcessBoottimeCutV1>,
    observations: Option<PidFdProcObservationsV1>,
    proc_capture: [PidFdProcOriginalsV1; 2],
    identity: Option<PidFdProcessIdentity>,
    context_matches: Option<bool>,
    executed: HelperExecutedImageOriginalV1,
    handoff: InitialHelperHandoffOriginalV1,
    entered: bool,
    driven: bool,
    measured: bool,
    first: Option<InitialTpmHelperBirthClosedV1>,
}

impl FixedInitialTpmHelperBirthOriginalV1 {
    /// Parks the exact measured image without native IO or process creation.
    #[must_use]
    pub fn new(image: MeasuredHelperImageV1) -> Self {
        Self {
            image,
            pair: RecordSubjectSeqpacketPairOriginalV2::zero_rights_parent_v1(),
            channel: None,
            child_endpoint: None,
            executable_duplicate: None,
            prepared: None,
            process: None,
            stack: None,
            stack_before_spawn: None,
            clock: None,
            cut: None,
            observations: None,
            proc_capture: std::array::from_fn(|_| PidFdProcOriginalsV1::new()),
            identity: None,
            context_matches: None,
            executed: HelperExecutedImageOriginalV1::new(),
            handoff: InitialHelperHandoffOriginalV1::new(),
            entered: false,
            driven: false,
            measured: false,
            first: None,
        }
    }

    /// Supplies fixed construction/return overlap before allocating this owner.
    #[must_use]
    pub fn construction_demand_v1() -> Option<ResourceVector> {
        Some(ResourceVector::ZERO.with(
            D::MemoryBytes,
            u64::try_from(std::mem::size_of::<Self>().checked_mul(3)?).ok()?,
        ))
    }

    /// Samples the actual inherited stack limit once, without launching a child.
    ///
    /// # Errors
    /// Refuses reuse, a normal-runtime image purpose or an unbounded/zero stack.
    /// The actual scalar observation remains resident after refusal.
    pub fn observe_stack_once_v1(&mut self) -> Result<(), InitialTpmHelperBirthClosedV1> {
        if self.stack.is_some() || self.first.is_some() {
            return Err(self.refuse());
        }
        if initial_context(self.image.purpose_data_v1()).is_none() {
            return Err(self.refuse());
        }
        self.stack = Some(getrlimit(Resource::Stack));
        if self.native_receiving_demand_v1().is_none() {
            return Err(self.refuse());
        }
        Ok(())
    }

    /// Quotes actual finite stack, native setup, proc capture and mapped-image IO.
    ///
    /// The existing pair and spawn suppliers bound their real descriptors.
    /// The enclosing Source separately owns the measured image and its terminal
    /// posts. This DATA is not a debit or a process-creation permission.
    #[must_use]
    pub fn native_receiving_demand_v1(&self) -> Option<ResourceVector> {
        let stack = self.stack?;
        stack.current.filter(|value| *value > 0)?;
        let runtime = crate::fixed_tpm_helper_runtime::helper_runtime_bytes_v1(stack)?;
        let (pair_bytes, pair_files) =
            RecordSubjectSeqpacketPairOriginalV2::receiving_obligations_v2()?;
        let (spawn_bytes, spawn_files) =
            FixedProcessDrivenSessionV1::path_spawn_receiving_demand_v2()?;
        let bytes = std::mem::size_of::<FixedProcessDrivenSessionV1>()
            .checked_mul(3)?
            .checked_add(pair_bytes)?
            .checked_add(spawn_bytes)?
            .checked_add(PidFdProcOriginalsV1::receiving_bytes_v1()?.checked_mul(2)?)?
            // Prepared path/argv CStrings, fixed output prefixes and their
            // construction overlap, timer/wait/error carriers and proc paths.
            .checked_add(FixedProcessRunOriginalV3::representation_from_lengths_v3(
                self.image.path().as_os_str().as_encoded_bytes().len(),
                0,
                0,
                OUTPUT_BYTES,
                OUTPUT_BYTES,
            )?)?
            .checked_add(OUTPUT_BYTES.checked_mul(4)?)?
            .checked_add(InitialHelperHandoffOriginalV1::receiving_bytes_v1()?)?;
        let files = pair_files
            .checked_add(spawn_files)?
            .checked_add(10)?
            .checked_add(InitialHelperHandoffOriginalV1::receiving_files_v1()?)?;
        let traffic = PidFdProcOriginalsV1::stat_maximum_requested_read_bytes_v1()?
            .checked_add(PidFdProcOriginalsV1::context_maximum_requested_read_bytes_v1()?)?
            .checked_add(InitialHelperHandoffOriginalV1::traffic_bytes_v1()?)?
            .checked_add(FixedProcessRunOriginalV3::bounded_output_bytes_v3(
                OUTPUT_BYTES,
                OUTPUT_BYTES,
            )?)?;
        let native = ResourceVector::ZERO
            .with(
                D::MemoryBytes,
                u64::try_from(bytes).ok()?.checked_add(runtime)?,
            )
            .with(D::OpenFiles, u64::try_from(files).ok()?)
            .with(D::Pids, 1)
            .with(D::ConcurrentOperations, 1)
            .with(D::OutputBytes, u64::try_from(traffic).ok()?);
        native
            .checked_add(HelperExecutedImageOriginalV1::receiving_with_input_demand_v1()?)
            .ok()
    }

    /// Borrows the exact original image for its separately funded terminal post.
    #[must_use]
    pub fn image_original_v1(&self) -> &MeasuredHelperImageV1 {
        &self.image
    }

    /// Prepares only the fixed image, stdin socket and original native reservoir.
    ///
    /// No caller supplies a path, descriptor, environment, role or deadline.
    /// No child is launched until the single driving borrow is advanced.
    ///
    /// # Errors
    /// Retains pair, duplicate and preparation failures; refuses reuse, missing
    /// finite stack, changed limits, invalid purpose or native deadline overflow.
    pub fn prepare_once_v1(&mut self) -> Result<(), InitialTpmHelperBirthClosedV1> {
        if self.entered || self.first.is_some() {
            return Err(self.refuse());
        }
        self.entered = true;
        let result = self.prepare_inner();
        result.map_err(|_| self.refuse())
    }

    fn prepare_inner(&mut self) -> Result<(), InitialTpmHelperBirthClosedV1> {
        self.native_receiving_demand_v1()
            .ok_or(InitialTpmHelperBirthClosedV1)?;
        initial_context(self.image.purpose_data_v1()).ok_or(InitialTpmHelperBirthClosedV1)?;
        self.stack_before_spawn = Some(getrlimit(Resource::Stack));
        if self.stack_before_spawn != self.stack {
            return Err(InitialTpmHelperBirthClosedV1);
        }
        self.clock = Some(clock_gettime(ClockId::Boottime));
        self.cut = Some(
            FixedProcessBoottimeCutV1::new(
                deadline(self.clock.ok_or(InitialTpmHelperBirthClosedV1)?)
                    .ok_or(InitialTpmHelperBirthClosedV1)?,
            )
            .map_err(|_| InitialTpmHelperBirthClosedV1)?,
        );
        self.pair
            .prepare_retaining_v2()
            .map_err(|_| InitialTpmHelperBirthClosedV1)?;
        self.channel = Some(
            self.pair
                .take_parent_socket()
                .map_err(|_| InitialTpmHelperBirthClosedV1)?,
        );
        self.child_endpoint = Some(
            self.pair
                .take_child_endpoint()
                .map_err(|_| InitialTpmHelperBirthClosedV1)?,
        );
        if self.channel.is_none() || self.child_endpoint.is_none() {
            return Err(InitialTpmHelperBirthClosedV1);
        }
        self.executable_duplicate =
            Some(self.image.executable_description_v1().try_clone_to_owned());
        if !matches!(self.executable_duplicate, Some(Ok(_))) {
            return Err(InitialTpmHelperBirthClosedV1);
        }
        self.prepared = Some(prepare_fixed_process_driven_invocation_v1(
            FixedProcessRequest {
                executable: self.image.path(),
                arguments: &[],
                timeout: CHILD_TIMEOUT,
                maximum_stdout_bytes: OUTPUT_BYTES,
                maximum_stderr_bytes: OUTPUT_BYTES,
            },
        ));
        if !matches!(self.prepared, Some(Ok(_))) {
            return Err(InitialTpmHelperBirthClosedV1);
        }

        // Every fallible preparation is parked before this infallible move
        // into the existing resident supervisor. Failed setup stays there too.
        let (Some(Ok(prepared)), Some(Ok(executable)), Some(stdin), Some(cut)) = (
            self.prepared.take(),
            self.executable_duplicate.take(),
            self.child_endpoint.take(),
            self.cut,
        ) else {
            std::process::abort();
        };
        self.process = Some(FixedProcessDrivenSessionV1::park_path_retaining_spawn_v2(
            prepared,
            FixedProcessDrivenInputsV1 {
                executable,
                stdin: Some(stdin),
                inherited: Vec::new(),
                capture: FixedProcessCaptureV1::new(),
            },
            cut,
        ));
        Ok(())
    }

    /// Borrows the one actual supervisor without exporting a channel or pidfd.
    ///
    /// # Errors
    /// Refuses unprepared, failed or previously driven custody. Dropping the
    /// successful loan fences/signals and retains the process and cleanup debt.
    pub fn drive_once_v1(
        &mut self,
    ) -> Result<InitialTpmHelperDrivingLoanV1<'_>, InitialTpmHelperBirthClosedV1> {
        if !self.entered || self.driven || self.first.is_some() || self.process.is_none() {
            return Err(self.refuse());
        }
        self.driven = true;
        let process = self.process.as_mut().ok_or(InitialTpmHelperBirthClosedV1)?;
        Ok(InitialTpmHelperDrivingLoanV1 {
            driving: process.drive(),
            image: &self.image,
            stack: self.stack.ok_or(InitialTpmHelperBirthClosedV1)?,
            stack_before_spawn: &mut self.stack_before_spawn,
            observations: &mut self.observations,
            proc_capture: &mut self.proc_capture,
            identity: &mut self.identity,
            context_matches: &mut self.context_matches,
            executed: &mut self.executed,
            measured: &mut self.measured,
            first: &mut self.first,
            started: false,
            channel: self.channel.as_mut().ok_or(InitialTpmHelperBirthClosedV1)?,
            handoff: &mut self.handoff,
            cut: self.cut.ok_or(InitialTpmHelperBirthClosedV1)?,
        })
    }

    fn refuse(&mut self) -> InitialTpmHelperBirthClosedV1 {
        *self.first.get_or_insert(InitialTpmHelperBirthClosedV1)
    }
}

/// Keeps the exact native child borrowed through handoff, NV and cleanup.
///
/// This loan exports no auth destination, credential bytes or channel.
/// Its private fields can be obtained only from the retained fixed-image owner.
#[must_use = "keep the actual child borrow through carrier disposition"]
pub struct InitialTpmHelperDrivingLoanV1<'owner> {
    driving: FixedProcessDrivingLoanV1<'owner>,
    image: &'owner MeasuredHelperImageV1,
    stack: Rlimit,
    stack_before_spawn: &'owner mut Option<Rlimit>,
    observations: &'owner mut Option<PidFdProcObservationsV1>,
    proc_capture: &'owner mut [PidFdProcOriginalsV1; 2],
    identity: &'owner mut Option<PidFdProcessIdentity>,
    context_matches: &'owner mut Option<bool>,
    executed: &'owner mut HelperExecutedImageOriginalV1,
    measured: &'owner mut bool,
    first: &'owner mut Option<InitialTpmHelperBirthClosedV1>,
    started: bool,
    channel: &'owner mut SeqpacketSocket,
    handoff: &'owner mut InitialHelperHandoffOriginalV1,
    cut: FixedProcessBoottimeCutV1,
}

impl InitialTpmHelperDrivingLoanV1<'_> {
    /// Starts and measures only this owner's fixed root initial helper once.
    ///
    /// The same supervisor confirms exec and owns its pidfd. Actual original
    /// stat/context and executable/loader-map observations precede any future
    /// HELLO or private authentication. All failed native prefixes remain held.
    ///
    /// # Errors
    /// Refuses changed stack, nonroot parent, missing/exited child, incomplete
    /// exec confirmation, native capture failure or a foreign helper MAC/image.
    pub fn start_child_once_v1(&mut self) -> Result<(), InitialTpmHelperBirthClosedV1> {
        if self.started || self.first.is_some() {
            self.first.get_or_insert(InitialTpmHelperBirthClosedV1);
            return Err(InitialTpmHelperBirthClosedV1);
        }
        self.started = true;
        let result = self.start_inner();
        if result.is_err() {
            self.first.get_or_insert(InitialTpmHelperBirthClosedV1);
        }
        result
    }

    fn start_inner(&mut self) -> Result<(), InitialTpmHelperBirthClosedV1> {
        *self.stack_before_spawn = Some(getrlimit(Resource::Stack));
        if *self.stack_before_spawn != Some(self.stack)
            || !rustix::process::geteuid().is_root()
            || !rustix::process::getegid().is_root()
        {
            return Err(InitialTpmHelperBirthClosedV1);
        }
        // PATH spawn confirms exec synchronously. Two bounded supervisor turns
        // install the run and obtain its live original-child observation.
        for _ in 0..2 {
            if matches!(
                self.driving.advance_once(),
                FixedProcessDrivenProgressV1::Ended | FixedProcessDrivenProgressV1::Debt
            ) {
                return Err(InitialTpmHelperBirthClosedV1);
            }
        }
        let (child, _) = self
            .driving
            .original_child()
            .ok_or(InitialTpmHelperBirthClosedV1)?;
        *self.observations = Some(prepare_proc_observations_v1(child));
        let observations = self
            .observations
            .as_mut()
            .ok_or(InitialTpmHelperBirthClosedV1)?;
        *self.identity = Some(
            observations
                .capture_stat_retaining_v1(child, &mut self.proc_capture[0])
                .map_err(|_| InitialTpmHelperBirthClosedV1)?,
        );
        let context = observations
            .capture_context_retaining_v1(child, &mut self.proc_capture[1])
            .map_err(|_| InitialTpmHelperBirthClosedV1)?;
        *self.context_matches = Some(context_matches(
            context,
            initial_context(self.image.purpose_data_v1()).ok_or(InitialTpmHelperBirthClosedV1)?,
        ));
        if *self.context_matches != Some(true) {
            return Err(InitialTpmHelperBirthClosedV1);
        }
        self.image
            .require_executed_retaining_v1(
                self.identity.ok_or(InitialTpmHelperBirthClosedV1)?.pid(),
                self.executed,
            )
            .map_err(|_| InitialTpmHelperBirthClosedV1)?;
        *self.measured = true;
        Ok(())
    }
}

fn initial_context(purpose: FixedTpmHelperPurposeV1) -> Option<&'static [u8]> {
    match purpose {
        FixedTpmHelperPurposeV1::InitialController => {
            Some(b"system_u:system_r:aos_method46_initial_controller_helper_t")
        }
        FixedTpmHelperPurposeV1::InitialStorage => {
            Some(b"system_u:system_r:aos_method46_initial_storage_helper_t")
        }
        _ => None,
    }
}

fn deadline(now: Timespec) -> Option<u64> {
    u64::try_from(now.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(now.tv_nsec).ok()?)?
        .checked_add(u64::try_from(CHILD_TIMEOUT.as_nanos()).ok()?)
}

fn context_matches(observed: &[u8], expected: &[u8]) -> bool {
    let observed = observed
        .strip_suffix(b"\n")
        .or_else(|| observed.strip_suffix(b"\0"))
        .unwrap_or(observed);
    !expected.is_empty() && observed == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_context_refuses_normal_purposes_and_crossed_or_padded_roles() {
        for purpose in [
            FixedTpmHelperPurposeV1::Broker,
            FixedTpmHelperPurposeV1::RuntimeDeployment,
            FixedTpmHelperPurposeV1::ControllerNix,
            FixedTpmHelperPurposeV1::NixOwner,
        ] {
            assert!(initial_context(purpose).is_none());
        }
        let controller = initial_context(FixedTpmHelperPurposeV1::InitialController).unwrap();
        let storage = initial_context(FixedTpmHelperPurposeV1::InitialStorage).unwrap();
        assert!(!context_matches(controller, storage));
        assert!(!context_matches(storage, controller));
        for expected in [controller, storage] {
            for suffix in [b"".as_slice(), b"\n", b"\0"] {
                assert!(context_matches(&[expected, suffix].concat(), expected));
            }
            for suffix in [b"\0\0".as_slice(), b"\n\0", b"\0\n", b":s0", b" "] {
                assert!(!context_matches(&[expected, suffix].concat(), expected));
            }
            assert!(!context_matches(
                &[b"foreign-", expected].concat(),
                expected
            ));
        }
    }
}
