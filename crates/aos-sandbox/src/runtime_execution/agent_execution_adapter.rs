//! Dormant guest-local execution compilation and observation handoff.
//!
//! The adapter consumes reducer-issued operations and produces closed requests
//! for a future guest-local process supervisor. A move-only handoff is the sole
//! input to the dormant process-effect adapter. No public API accepts a caller
//! echoed binding, phase, or result as execution observation evidence.

#[cfg(unix)]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::io::Read as _;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

use aos_sandbox_core::{AuditId, ExecutionId, ObjectDigest, PrincipalId};
use sha2::{Digest as _, Sha256};

use aos_sandbox_agent::{
    AgentExecutionOperationV1, AgentExecutionOutcomeV1, AgentExecutionPhaseV1,
    AgentOperationRequestV1,
};

use super::agent_reducer::{
    AgentDecisionV1, AgentReservationRecoveryTokenV1, PreparedAgentOperationV1,
};

#[cfg(unix)]
const EXECUTABLE_CREDENTIAL_PATH: &str = "/run/credentials/aos-sandbox-agent/guest-executable-v1";
#[cfg(unix)]
const EXECUTABLE_CREDENTIAL_MAGIC: &[u8; 8] = b"AOSGEX01";
#[cfg(unix)]
const EXECUTABLE_CREDENTIAL_BYTES: usize = 104;
#[cfg(unix)]
const O_CLOEXEC: i32 = 0o2_000_000;
#[cfg(unix)]
const O_NOFOLLOW: i32 = 0o400_000;

/// Identifies the fixed guest-local executable selected by protected packaging.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuestExecutableCredentialV1 {
    executable_digest: ObjectDigest,
    credential_binding: ObjectDigest,
}

impl GuestExecutableCredentialV1 {
    /// Constructs a nonauthorizing protected-package descriptor.
    ///
    /// Execution authority still requires a reducer-issued move-only prepared
    /// operation; this descriptor alone cannot cross an effect boundary.
    ///
    /// # Errors
    ///
    /// Returns [`GuestExecutionAdapterErrorV1::InvalidCredential`] for a zero
    /// executable or protected-package binding.
    fn new(
        executable_digest: ObjectDigest,
        credential_binding: ObjectDigest,
    ) -> Result<Self, GuestExecutionAdapterErrorV1> {
        if executable_digest.as_bytes() == &[0; 32] || credential_binding.as_bytes() == &[0; 32] {
            return Err(GuestExecutionAdapterErrorV1::InvalidCredential);
        }
        Ok(Self {
            executable_digest,
            credential_binding,
        })
    }

    /// Returns the fixed executable content commitment.
    #[must_use]
    pub const fn executable_digest(self) -> ObjectDigest {
        self.executable_digest
    }

    /// Returns the protected package/provisioning commitment.
    #[must_use]
    pub const fn credential_binding(self) -> ObjectDigest {
        self.credential_binding
    }
}

/// Owns the fixed protected guest executable provisioning record.
#[cfg(unix)]
pub struct DormantGuestProvisioningOwnerV1 {
    executable: GuestExecutableCredentialV1,
}

#[cfg(unix)]
impl DormantGuestProvisioningOwnerV1 {
    /// Opens and authenticates the fixed root-owned provisioning record.
    ///
    /// The fixed path is not caller-selectable. The file must be a root-owned,
    /// non-symlink regular file with no group/other permissions and canonical
    /// `AOSGEX01` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`GuestExecutionAdapterErrorV1`] for unavailable I/O, unsafe
    /// ownership/mode/type, malformed bytes, or checksum mismatch.
    pub fn open() -> Result<Self, GuestExecutionAdapterErrorV1> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(O_CLOEXEC | O_NOFOLLOW)
            .open(EXECUTABLE_CREDENTIAL_PATH)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
            return Err(GuestExecutionAdapterErrorV1::InvalidCredential);
        }
        let mut bytes = Vec::new();
        file.by_ref()
            .take((EXECUTABLE_CREDENTIAL_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() != EXECUTABLE_CREDENTIAL_BYTES
            || bytes.get(..8) != Some(EXECUTABLE_CREDENTIAL_MAGIC.as_slice())
        {
            return Err(GuestExecutionAdapterErrorV1::InvalidCredential);
        }
        let expected: [u8; 32] = Sha256::digest(&bytes[..72]).into();
        if bytes[72..] != expected {
            return Err(GuestExecutionAdapterErrorV1::InvalidCredential);
        }
        Ok(Self {
            executable: GuestExecutableCredentialV1::new(
                read_digest(&bytes, 8)?,
                read_digest(&bytes, 40)?,
            )?,
        })
    }

    /// Constructs the dormant adapter from retained protected provisioning.
    #[must_use]
    pub const fn adapter(&self) -> DormantGuestExecutionAdapterV1 {
        DormantGuestExecutionAdapterV1::new(self.executable)
    }

    /// Returns the fixed executable credential authenticated by this owner.
    #[must_use]
    pub const fn credential(&self) -> GuestExecutableCredentialV1 {
        self.executable
    }
}

/// Binds an admitted forced command to its execution principal and audit row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuestForcedCommandCredentialV1 {
    execution: ExecutionId,
    specification_digest: ObjectDigest,
    admission_commitment: ObjectDigest,
    principal: PrincipalId,
    audit: AuditId,
}

impl GuestForcedCommandCredentialV1 {
    /// Returns the admitted execution identity.
    #[must_use]
    pub const fn execution(self) -> ExecutionId {
        self.execution
    }

    /// Returns the exact canonical execution-specification commitment.
    #[must_use]
    pub const fn specification_digest(self) -> ObjectDigest {
        self.specification_digest
    }

    /// Returns the durable admission commitment.
    #[must_use]
    pub const fn admission_commitment(self) -> ObjectDigest {
        self.admission_commitment
    }

    /// Returns the authenticated execution principal.
    #[must_use]
    pub const fn principal(self) -> PrincipalId {
        self.principal
    }

    /// Returns the durable audit identity.
    #[must_use]
    pub const fn audit(self) -> AuditId {
        self.audit
    }
}

/// Names one closed request for a future guest-local supervisor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GuestLocalExecutionRequestV1 {
    /// Starts the exact admitted forced command with a fixed executable.
    Start {
        /// Fixed packaged executable descriptor.
        executable: GuestExecutableCredentialV1,
        /// Admission-derived forced-command credential.
        forced_command: GuestForcedCommandCredentialV1,
        /// Exact canonical execution-specification bytes.
        specification_bytes: Vec<u8>,
    },
    /// Changes the PTY geometry of an exact execution.
    Resize {
        /// Execution identity.
        execution: ExecutionId,
        /// Positive rows.
        rows: u16,
        /// Positive columns.
        columns: u16,
    },
    /// Delivers one closed portable signal.
    Signal {
        /// Execution identity.
        execution: ExecutionId,
        /// Portable signal code in 1 through 64.
        signal_code: u8,
    },
    /// Cancels an exact nonterminal execution.
    Cancel(ExecutionId),
    /// Observes an exact execution without mutation.
    Observe(ExecutionId),
    /// Enters the complete guest-local quiesce barrier.
    BeginQuiesce,
    /// Leaves the exact guest-local quiesce barrier.
    EndQuiesce,
}

/// Carries one reducer-issued request across the dormant guest effect boundary.
#[must_use = "the authorized guest request must be observed or retained for recovery"]
pub struct GuestLocalExecutionHandoffV1 {
    prepared: PreparedAgentOperationV1,
    request: GuestLocalExecutionRequestV1,
    handoff_binding: ObjectDigest,
}

impl GuestLocalExecutionHandoffV1 {
    /// Borrows the exact reservation and reducer decision behind the handoff.
    #[must_use]
    pub(super) const fn prepared(&self) -> &PreparedAgentOperationV1 {
        &self.prepared
    }

    /// Borrows the exact closed guest-local request.
    #[must_use]
    pub const fn request(&self) -> &GuestLocalExecutionRequestV1 {
        &self.request
    }

    /// Returns the binding retained across the private effect boundary.
    #[must_use]
    pub const fn handoff_binding(&self) -> ObjectDigest {
        self.handoff_binding
    }

    pub(crate) fn into_prepared(self) -> PreparedAgentOperationV1 {
        self.prepared
    }
}

/// Owns an effect-adapter observation bound to one exact prepared request.
#[must_use = "the observation must be durably committed through the controller"]
pub struct ObservedGuestLocalExecutionV1 {
    prepared: PreparedAgentOperationV1,
    phase: AgentExecutionPhaseV1,
    result_bytes: Vec<u8>,
    handoff_binding: ObjectDigest,
}

impl ObservedGuestLocalExecutionV1 {
    pub(super) fn from_supervisor(
        prepared: PreparedAgentOperationV1,
        phase: AgentExecutionPhaseV1,
        result_bytes: Vec<u8>,
        handoff_binding: ObjectDigest,
    ) -> Self {
        Self {
            prepared,
            phase,
            result_bytes,
            handoff_binding,
        }
    }

    /// Borrows the exact protected reservation that authorized the effect.
    #[must_use]
    pub(super) const fn prepared(&self) -> &PreparedAgentOperationV1 {
        &self.prepared
    }

    /// Returns the adapter-observed execution phase.
    #[must_use]
    pub const fn phase(&self) -> AgentExecutionPhaseV1 {
        self.phase
    }

    /// Borrows the adapter-captured canonical result bytes.
    #[must_use]
    pub fn result_bytes(&self) -> &[u8] {
        &self.result_bytes
    }

    pub(super) const fn handoff_binding(&self) -> ObjectDigest {
        self.handoff_binding
    }
}

/// Compiles reducer-issued operations into fixed guest-local requests.
pub struct DormantGuestExecutionAdapterV1 {
    executable: GuestExecutableCredentialV1,
}

impl DormantGuestExecutionAdapterV1 {
    /// Constructs a dormant adapter for one fixed packaged executable.
    #[must_use]
    pub const fn new(executable: GuestExecutableCredentialV1) -> Self {
        Self { executable }
    }

    /// Compiles an already protected-owner-reserved operation into one handoff.
    ///
    /// # Errors
    ///
    /// Returns [`GuestExecutionAdapterErrorV1`] when the reducer decision and
    /// exact operation cannot form the closed guest-local effect vocabulary.
    pub(super) fn compile_reserved(
        &self,
        prepared: PreparedAgentOperationV1,
    ) -> Result<GuestLocalExecutionHandoffV1, GuestExecutionAdapterErrorV1> {
        let request = compile_request(self.executable, &prepared)?;
        let handoff_binding = handoff_binding(prepared.request(), &request);
        Ok(GuestLocalExecutionHandoffV1 {
            prepared,
            request,
            handoff_binding,
        })
    }

    /// Verifies that an opaque effect observation belongs to this adapter.
    #[must_use]
    pub(super) fn authenticates(&self, observed: &ObservedGuestLocalExecutionV1) -> bool {
        compile_request(self.executable, observed.prepared()).is_ok_and(|expected| {
            observed.handoff_binding == handoff_binding(observed.prepared().request(), &expected)
                && phase_is_compatible(observed.prepared().decision(), observed.phase)
                && !observed.result_bytes.is_empty()
                && observed.result_bytes.len() <= 1_048_576
        })
    }
}

/// Reports preparation as a handoff, exact replay, or retained ambiguity.
#[must_use]
pub enum DormantGuestExecutionPreparationV1 {
    /// A newly reserved operation is ready for the dormant process adapter.
    Handoff(GuestLocalExecutionHandoffV1),
    /// A byte-identical completed request returns its durable outcome.
    ExactReplay(AgentExecutionOutcomeV1),
    /// The exact outstanding operation must be recovered without redispatch.
    OutstandingRecoveryRequired,
    /// Reservation commit ambiguity must be recovered before dispatch.
    ReservationRecoveryRequired(AgentReservationRecoveryTokenV1),
}

fn compile_request(
    executable: GuestExecutableCredentialV1,
    prepared: &PreparedAgentOperationV1,
) -> Result<GuestLocalExecutionRequestV1, GuestExecutionAdapterErrorV1> {
    match prepared.request().operation() {
        AgentExecutionOperationV1::Authorize {
            execution,
            specification_bytes,
            specification_digest,
            admission_commitment,
            principal,
            audit,
        } => Ok(GuestLocalExecutionRequestV1::Start {
            executable,
            forced_command: GuestForcedCommandCredentialV1 {
                execution: *execution,
                specification_digest: *specification_digest,
                admission_commitment: *admission_commitment,
                principal: *principal,
                audit: *audit,
            },
            specification_bytes: specification_bytes.clone(),
        }),
        AgentExecutionOperationV1::ResizeTerminal {
            execution,
            rows,
            columns,
        } => Ok(GuestLocalExecutionRequestV1::Resize {
            execution: *execution,
            rows: *rows,
            columns: *columns,
        }),
        AgentExecutionOperationV1::Signal {
            execution,
            signal_code,
        } => Ok(GuestLocalExecutionRequestV1::Signal {
            execution: *execution,
            signal_code: *signal_code,
        }),
        AgentExecutionOperationV1::Cancel { execution } => {
            Ok(GuestLocalExecutionRequestV1::Cancel(*execution))
        }
        AgentExecutionOperationV1::Observe { execution } => {
            Ok(GuestLocalExecutionRequestV1::Observe(*execution))
        }
        AgentExecutionOperationV1::BeginQuiesce => Ok(GuestLocalExecutionRequestV1::BeginQuiesce),
        AgentExecutionOperationV1::EndQuiesce => Ok(GuestLocalExecutionRequestV1::EndQuiesce),
    }
}

fn phase_is_compatible(decision: AgentDecisionV1, phase: AgentExecutionPhaseV1) -> bool {
    match decision {
        AgentDecisionV1::HandoffExecution(_) => matches!(
            phase,
            AgentExecutionPhaseV1::Authorized
                | AgentExecutionPhaseV1::Starting
                | AgentExecutionPhaseV1::Running
                | AgentExecutionPhaseV1::Failed
        ),
        AgentDecisionV1::ResizeTerminal { .. }
        | AgentDecisionV1::Signal { .. }
        | AgentDecisionV1::Observe(_) => matches!(
            phase,
            AgentExecutionPhaseV1::Starting
                | AgentExecutionPhaseV1::Running
                | AgentExecutionPhaseV1::Exited
                | AgentExecutionPhaseV1::Canceled
                | AgentExecutionPhaseV1::Failed
                | AgentExecutionPhaseV1::Lost
        ),
        AgentDecisionV1::Cancel(_) => matches!(
            phase,
            AgentExecutionPhaseV1::Canceled
                | AgentExecutionPhaseV1::Exited
                | AgentExecutionPhaseV1::Failed
                | AgentExecutionPhaseV1::Lost
        ),
        AgentDecisionV1::BeginQuiesce => phase == AgentExecutionPhaseV1::Quiesced,
        AgentDecisionV1::EndQuiesce => phase == AgentExecutionPhaseV1::Ready,
    }
}

fn handoff_binding(
    request: &AgentOperationRequestV1,
    guest_request: &GuestLocalExecutionRequestV1,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.agent.guest-local-handoff.v1\0");
    digest.update(request.session().digest().as_bytes());
    digest.update(request.sequence().get().to_be_bytes());
    digest.update(request.operation_id().as_bytes());
    digest.update(request.request_commitment().as_bytes());
    digest.update([request.operation().code()]);
    match guest_request {
        GuestLocalExecutionRequestV1::Start {
            executable,
            forced_command,
            specification_bytes,
        } => {
            digest.update(executable.executable_digest().as_bytes());
            digest.update(executable.credential_binding().as_bytes());
            digest.update(forced_command.execution().as_bytes());
            digest.update(forced_command.specification_digest().as_bytes());
            digest.update(forced_command.admission_commitment().as_bytes());
            digest.update(forced_command.principal().as_bytes());
            digest.update(forced_command.audit().as_bytes());
            digest.update((specification_bytes.len() as u64).to_be_bytes());
            digest.update(specification_bytes);
        }
        GuestLocalExecutionRequestV1::Resize {
            execution,
            rows,
            columns,
        } => {
            digest.update(execution.as_bytes());
            digest.update(rows.to_be_bytes());
            digest.update(columns.to_be_bytes());
        }
        GuestLocalExecutionRequestV1::Signal {
            execution,
            signal_code,
        } => {
            digest.update(execution.as_bytes());
            digest.update([*signal_code]);
        }
        GuestLocalExecutionRequestV1::Cancel(execution)
        | GuestLocalExecutionRequestV1::Observe(execution) => {
            digest.update(execution.as_bytes());
        }
        GuestLocalExecutionRequestV1::BeginQuiesce => digest.update([6]),
        GuestLocalExecutionRequestV1::EndQuiesce => digest.update([7]),
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

/// Reports dormant guest-local compilation and completion failure.
#[derive(Debug, thiserror::Error)]
pub enum GuestExecutionAdapterErrorV1 {
    /// Fixed executable or protected package binding is a zero sentinel.
    #[error("guest executable credential is invalid")]
    InvalidCredential,
    /// External observation does not match the exact one-shot handoff.
    #[error("guest execution observation is invalid")]
    InvalidObservation,
    /// Fixed protected provisioning I/O failed.
    #[error("guest executable provisioning I/O failed: {0}")]
    ProvisioningIo(#[from] std::io::Error),
}

#[cfg(unix)]
fn read_digest(bytes: &[u8], offset: usize) -> Result<ObjectDigest, GuestExecutionAdapterErrorV1> {
    bytes
        .get(offset..offset + 32)
        .and_then(|value| value.try_into().ok())
        .map(ObjectDigest::from_bytes)
        .ok_or(GuestExecutionAdapterErrorV1::InvalidCredential)
}
