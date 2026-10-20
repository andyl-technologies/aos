//! Retains the original supervised occurrence independently of every Source loan.
//!
//! Neither DATA receipts nor equal artifact hashes construct this owner. A job
//! starts from the sealed installed mechanism and retains its original L2 attempt
//! through failed export, wait, empty-group cleanup and same-Source acceptance.

use super::{
    installation::VerifiedSourceBirthMechanism,
    request_wire::{self, ExportError, ExportWorkspace, JobContext, RequestInput, RequestReceipt},
    result_wire::WireError,
};
use crate::node_adapters::cnp::PacketCompleteSemanticSource;
use crate::node_contract::RuntimeError;
use crucible_host_resources::{
    LinuxPureWorkerAttempt, LinuxPureWorkerAttemptIdentity, LinuxPureWorkerCompletion,
    LinuxPureWorkerError, LinuxPureWorkerOutcome, LinuxPureWorkerProgramIdentity,
};
use crucible_node_format::Id;
use std::{fmt, rc::Rc, thread::ThreadId};

#[path = "job/storage.rs"]
mod storage;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Reserving,
    Reserved,
    Prepared,
    Exporting,
    Exported,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct SourceBinding {
    address: usize,
    process: u32,
    thread: ThreadId,
}

/// Retains the first actual operational or export refusal without rendering input.
#[derive(Debug)]
pub enum SourceBirthJobFailure {
    /// Retains an original installed-mechanism or Source-binding guard failure.
    Runtime(RuntimeError),
    /// Retains the actual original Linux preparation, execution or cleanup error.
    Linux(LinuxPureWorkerError),
    /// Retains the real export error and any original concrete input-writer cause.
    Export {
        /// Owns the actual request writer's first failure.
        error: ExportError,
        /// Owns the same concrete attempt's input cause, when it has one.
        input: Option<LinuxPureWorkerError>,
    },
    /// Retains the actual closed result-envelope refusal after transfer.
    Result(WireError),
    /// Retains a valid failed worker header; its diagnostic remains in Completion.
    Worker(super::result_wire::ResultHeader),
    /// Retains the actual operational literal-workspace constructor refusal.
    Workspace(super::literal_value::StreamError),
}

impl fmt::Display for SourceBirthJobFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Runtime(_) => "SourceBirth original guard refused",
            Self::Linux(_) => "SourceBirth original Linux operation failed",
            Self::Export { .. } => "SourceBirth original input export failed",
            Self::Result(_) => "SourceBirth original result refused",
            Self::Worker(_) => "SourceBirth original worker derivation failed",
            Self::Workspace(_) => "SourceBirth original export workspace failed",
        })
    }
}

impl std::error::Error for SourceBirthJobFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
            Self::Linux(error) => Some(error),
            Self::Export { error, .. } => Some(error),
            Self::Result(error) => Some(error),
            Self::Worker(_) => None,
            Self::Workspace(error) => Some(error),
        }
    }
}

/// Owns one actual supervised request independently of the original Source.
///
/// This type is neither Clone nor deserializable. Its receipt is ordinary DATA;
/// only a later same-Source join with its sealed physical completion can accept
/// bank ranges. Dropping a job irrevocably cancels acceptance, including after
/// physical cleanup. Active cleanup remains with the original L2 owners.
#[must_use = "retain or explicitly cancel and drain the original supervised job"]
pub struct SourceBirthDerivationJob {
    mechanism: Rc<VerifiedSourceBirthMechanism>,
    attempt: Option<LinuxPureWorkerAttempt>,
    attempt_identity: Option<LinuxPureWorkerAttemptIdentity>,
    program_identity: Option<LinuxPureWorkerProgramIdentity>,
    binding: Option<SourceBinding>,
    context: Option<JobContext>,
    receipt: Option<RequestReceipt>,
    completion: Option<LinuxPureWorkerCompletion>,
    failed_outcome: Option<LinuxPureWorkerOutcome>,
    failure: Option<SourceBirthJobFailure>,
    phase: Phase,
    workspace_reserved: bool,
    workspace_requested: Option<[usize; 2]>,
    workspace_observed: Option<[usize; 2]>,
}

impl SourceBirthDerivationJob {
    /// Installs a pending owner before authenticating and reserving actual work.
    ///
    /// The real deployment reservation and installed mechanism must already be
    /// retained by the caller. No Source reference is accepted by this operation.
    ///
    /// # Errors
    /// Refuses an occupied output, revoked mechanism or genuine Linux reservation
    /// failure. A started failure stays in the caller's original output slot.
    pub fn reserve_into(
        mechanism: Rc<VerifiedSourceBirthMechanism>,
        output: &mut Option<Self>,
    ) -> Result<(), RuntimeError> {
        if output.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        *output = Some(Self {
            mechanism,
            attempt: None,
            attempt_identity: None,
            program_identity: None,
            binding: None,
            context: None,
            receipt: None,
            completion: None,
            failed_outcome: None,
            failure: None,
            phase: Phase::Reserving,
            workspace_reserved: false,
            workspace_requested: None,
            workspace_observed: None,
        });
        let job = output.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        if let Err(error) = job.mechanism.deployment_lease() {
            return job.fail(SourceBirthJobFailure::Runtime(error));
        }
        if let Err(error) = job.mechanism.authenticate_current() {
            return job.fail(SourceBirthJobFailure::Runtime(error));
        }
        match job.mechanism.reserve_attempt() {
            Ok(attempt) => {
                job.attempt_identity = Some(attempt.identity());
                job.program_identity = Some(attempt.program_identity());
                job.attempt = Some(attempt);
                job.phase = Phase::Reserved;
                Ok(())
            }
            Err(error) => job.fail(SourceBirthJobFailure::Linux(error)),
        }
    }

    /// Prepares the original quota-owned input before any Source export loan.
    ///
    /// # Errors
    /// Refuses repeated/wrong phase, currentness failure or actual input setup.
    /// Original failure and any filesystem prefix remain with this job/attempt.
    pub fn prepare_input(&mut self) -> Result<(), RuntimeError> {
        self.require(Phase::Reserved)?;
        self.authenticate()?;
        let attempt = self
            .attempt
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if let Err(error) = attempt.prepare_input() {
            return self.fail(SourceBirthJobFailure::Linux(error));
        }
        self.phase = Phase::Prepared;
        Ok(())
    }

    /// Allocates the admitted reusable literal frame bank before a Source loan.
    ///
    /// The lifetime can be chosen by the subsequent synchronous export; this
    /// constructor stores no Source reference and returns the actual empty bank.
    /// Recorded requested/capacity values describe history, not retained backing
    /// after the returned bank is consumed by the writer.
    ///
    /// # Errors
    /// Refuses repeated/wrong phase, currentness, unrepresentable slot geometry
    /// or the actual allocation/capacity check. Failure stays in this job.
    pub fn reserve_workspace<'input>(&mut self) -> Result<ExportWorkspace<'input>, RuntimeError> {
        self.require(Phase::Prepared)?;
        if self.workspace_reserved {
            return Err(RuntimeError::DuplicateOperation);
        }
        self.workspace_reserved = true;
        self.authenticate()?;
        let slots = self.mechanism.workspace_slots();
        let requested = match ExportWorkspace::requested_bytes(slots) {
            Ok(requested) => requested,
            Err(error) => return self.fail(SourceBirthJobFailure::Workspace(error)),
        };
        self.workspace_requested = Some(requested);
        match ExportWorkspace::new(slots) {
            Ok(workspace) => {
                self.workspace_observed = Some(workspace.retained_bytes());
                Ok(workspace)
            }
            Err(error) => self.fail(SourceBirthJobFailure::Workspace(error)),
        }
    }

    /// Starts the same sealed input after all original Source loans have ended.
    ///
    /// # Errors
    /// Refuses absent original export, duplicate/wrong phase, currentness failure
    /// or actual Linux launch failure. It never supplies a Source/Ready result.
    pub fn start(&mut self) -> Result<(), RuntimeError> {
        self.require(Phase::Exported)?;
        self.authenticate()?;
        let attempt = self
            .attempt
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if let Err(error) = attempt.start() {
            return self.fail(SourceBirthJobFailure::Linux(error));
        }
        self.phase = Phase::Running;
        Ok(())
    }

    /// Polls the original physical completion without borrowing any Source.
    ///
    /// The actual sealed completion is retained before returning true. This says
    /// nothing about its wire frame, semantic result or accepted bank authority.
    ///
    /// # Errors
    /// Refuses a non-running job, changed mechanism or actual Linux failure.
    /// Failure never removes the job or its active cleanup obligation.
    pub fn poll(&mut self) -> Result<bool, RuntimeError> {
        self.require(Phase::Running)?;
        self.authenticate()?;
        let attempt = self
            .attempt
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        match attempt.take_completion() {
            Ok(Some(completion)) => {
                self.completion = Some(completion);
                self.phase = Phase::Completed;
                Ok(true)
            }
            Ok(None) => Ok(false),
            Err(error) => self.fail(SourceBirthJobFailure::Linux(error)),
        }
    }

    /// Revokes result acceptance on the original attempt in every phase.
    pub fn cancel(&mut self) {
        if let Some(attempt) = &self.attempt {
            attempt.cancel();
        }
        self.phase = Phase::Cancelled;
    }

    /// Drains original cleanup after cancellation, failure or deployment revocation.
    ///
    /// A previously retained genuine completion already proves physical cleanup;
    /// cancellation correctly prevents using it as acceptance-currentness proof.
    /// This operation therefore never retakes its consumed outcome or attempts
    /// to authenticate permission as a prerequisite for resource cleanup.
    ///
    /// # Errors
    /// Retains actual Linux drain failures and returns the existing refusal. A
    /// false result means the original attempt still owns pending/quarantined work.
    pub fn poll_cleanup(&mut self) -> Result<bool, RuntimeError> {
        if self.completion.is_some() || self.failed_outcome.is_some() {
            return Ok(true);
        }
        let Some(attempt) = self.attempt.as_mut() else {
            // A failed reservation installed no attempt in this owner.
            return Ok(true);
        };
        match attempt.take_outcome() {
            Ok(Some(outcome)) => {
                self.failed_outcome = Some(outcome);
                Ok(true)
            }
            Ok(None) => Ok(false),
            Err(error) => self.fail(SourceBirthJobFailure::Linux(error)),
        }
    }

    /// Borrows the first actual owned failure without rendering original input.
    pub fn failure(&self) -> Option<&SourceBirthJobFailure> {
        self.failure.as_ref()
    }

    pub(in crate::node_adapters::cnp) fn associate(
        &mut self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<LinuxPureWorkerAttemptIdentity, RuntimeError> {
        self.require(Phase::Prepared)?;
        if self.binding.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        let attempt = self
            .attempt_identity
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .clone();
        self.binding = Some(SourceBinding::of(source));
        Ok(attempt)
    }

    pub(in crate::node_adapters::cnp) fn export<'a>(
        &mut self,
        private_launch: &Id,
        launch: &'a crucible_node_transport::reference_packet::service::PacketNative5LaunchValidationProjection<'a>,
        expected: super::derive::ExpectedCoordinator<'a>,
        registration: &'a crate::node_adapters::cnp::PacketCompleteAckHostRegistrationPlan,
        workspace: ExportWorkspace<'a>,
    ) -> Result<RequestReceipt, RuntimeError> {
        self.require(Phase::Prepared)?;
        if self.binding.is_none()
            || self.context.is_some()
            || self.receipt.is_some()
            || !self.workspace_reserved
        {
            return Err(RuntimeError::DuplicateOperation);
        }
        if self.workspace_observed != Some(workspace.retained_bytes()) {
            return self.fail(SourceBirthJobFailure::Runtime(RuntimeError::ResourceLimit));
        }
        self.authenticate()?;
        let bindings = self.mechanism.bindings_data();
        let mut task = blake3::Hasher::new_derive_key("crucible.source-birth.job-correlation/1");
        task.update(private_launch.as_str().as_bytes());
        task.update(&bindings.installation);
        let context = JobContext {
            task_digest: *task.finalize().as_bytes(),
            worker_digest: bindings.worker,
            algorithm_digest: bindings.algorithm,
        };
        // Task/digest equality is correlation only. The original Source binding
        // and strong actual AttemptIdentity remain the separate private join.
        self.context = Some(context);
        self.phase = Phase::Exporting;
        let original_limits = self.mechanism.limits_data();
        let limits = (|| {
            Ok::<_, RuntimeError>(request_wire::OperationalLimits {
                maximum_input_bytes: usize::try_from(original_limits.input_bytes)
                    .map_err(|_| RuntimeError::ResourceLimit)?,
                maximum_elements: usize::try_from(original_limits.elements)
                    .map_err(|_| RuntimeError::ResourceLimit)?,
                maximum_output_bytes: usize::try_from(original_limits.bank_bytes)
                    .map_err(|_| RuntimeError::ResourceLimit)?,
                maximum_diagnostic_bytes: usize::try_from(original_limits.diagnostic_bytes)
                    .map_err(|_| RuntimeError::ResourceLimit)?,
            })
        })();
        let limits = match limits {
            Ok(limits) => limits,
            Err(error) => return self.fail(SourceBirthJobFailure::Runtime(error)),
        };
        let attempt = self
            .attempt
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let result = request_wire::write_request(
            RequestInput {
                context,
                launch,
                expected,
                registration,
            },
            attempt,
            limits,
            workspace,
        );
        match result {
            Ok(receipt) => {
                self.receipt = Some(receipt);
                self.phase = Phase::Exported;
                Ok(receipt)
            }
            Err(error) => {
                let input = self
                    .attempt
                    .as_mut()
                    .and_then(LinuxPureWorkerAttempt::take_input_error);
                self.fail(SourceBirthJobFailure::Export { error, input })
            }
        }
    }

    pub(in crate::node_adapters::cnp) fn same_mechanism(
        &self,
        mechanism: &Rc<VerifiedSourceBirthMechanism>,
    ) -> bool {
        Rc::ptr_eq(&self.mechanism, mechanism)
    }

    pub(in crate::node_adapters::cnp) fn owns_source_binding(
        &self,
        source: &PacketCompleteSemanticSource,
        attempt: &LinuxPureWorkerAttemptIdentity,
    ) -> bool {
        self.binding == Some(SourceBinding::of(source))
            && self.attempt_identity.as_ref() == Some(attempt)
    }

    pub(in crate::node_adapters::cnp) fn physical_output_present(&self) -> bool {
        self.completion.is_some() || self.failed_outcome.is_some()
    }

    pub(in crate::node_adapters::cnp) fn refuse_runtime(&mut self, error: RuntimeError) {
        let _: Result<(), RuntimeError> = self.fail(SourceBirthJobFailure::Runtime(error));
    }

    pub(in crate::node_adapters::cnp) fn refuse_worker(
        &mut self,
        header: super::result_wire::ResultHeader,
    ) {
        let _: Result<(), RuntimeError> = self.fail(SourceBirthJobFailure::Worker(header));
    }

    pub(in crate::node_adapters::cnp) fn verify_for_source(
        &self,
        source: &PacketCompleteSemanticSource,
        expected_attempt: &LinuxPureWorkerAttemptIdentity,
        mechanism: &Rc<VerifiedSourceBirthMechanism>,
    ) -> Result<(), RuntimeError> {
        if self.binding != Some(SourceBinding::of(source))
            || self.phase != Phase::Completed
            || self.failure.is_some()
            || self.attempt_identity.as_ref() != Some(expected_attempt)
            || !Rc::ptr_eq(mechanism, &self.mechanism)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.mechanism.authenticate_current()?;
        self.completion
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .verify_original(
                expected_attempt,
                self.program_identity
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
            )
            .map_err(|_| RuntimeError::ForeignAuthority)
    }

    pub(in crate::node_adapters::cnp) fn receipt(&self) -> Result<RequestReceipt, RuntimeError> {
        self.receipt.ok_or(RuntimeError::OwnerUnavailable)
    }

    pub(in crate::node_adapters::cnp) fn stdout(&self) -> Result<&[u8], RuntimeError> {
        self.completion
            .as_ref()
            .map(|completion| completion.outcome().stdout.as_slice())
            .ok_or(RuntimeError::OwnerUnavailable)
    }

    pub(in crate::node_adapters::cnp) fn result_limits(
        &self,
    ) -> Result<super::result_wire::WireLimits, RuntimeError> {
        let limits = self.mechanism.limits_data();
        Ok(super::result_wire::WireLimits {
            maximum_frame_bytes: limits.stdout_bytes,
            maximum_diagnostic_bytes: usize::try_from(limits.diagnostic_bytes)
                .map_err(|_| RuntimeError::ResourceLimit)?,
        })
    }

    pub(in crate::node_adapters::cnp) fn refuse_result(&mut self, error: WireError) {
        let _: Result<(), RuntimeError> = self.fail(SourceBirthJobFailure::Result(error));
    }

    fn require(&self, expected: Phase) -> Result<(), RuntimeError> {
        if self.failure.is_some() || self.phase != expected {
            return Err(RuntimeError::DuplicateOperation);
        }
        Ok(())
    }

    fn authenticate(&mut self) -> Result<(), RuntimeError> {
        if let Err(error) = self.mechanism.authenticate_current() {
            return self.fail(SourceBirthJobFailure::Runtime(error));
        }
        Ok(())
    }

    fn fail<T>(&mut self, error: SourceBirthJobFailure) -> Result<T, RuntimeError> {
        if let Some(attempt) = &self.attempt {
            attempt.cancel();
        }
        if self.failure.is_none() {
            self.failure = Some(error);
        }
        self.phase = Phase::Failed;
        Err(RuntimeError::OwnerUnavailable)
    }
}

impl Drop for SourceBirthDerivationJob {
    fn drop(&mut self) {
        // L2 Drop only cancels before physical release. This outer original also
        // revokes an already-completed result's future acceptance.
        self.cancel();
    }
}

#[cfg(test)]
#[path = "job/tests.rs"]
mod tests;

impl SourceBinding {
    fn of(source: &PacketCompleteSemanticSource) -> Self {
        Self {
            address: source as *const PacketCompleteSemanticSource as usize,
            process: std::process::id(),
            thread: std::thread::current().id(),
        }
    }
}
