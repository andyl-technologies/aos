//! Dormant typed process-effect preparation for the guest agent.
//!
//! The adapter consumes the reducer's move-only handoff and projects it into
//! process, PTY, resize, signal, and credential effects. The dormant supervisor
//! invokes injected operating-system effects and exclusively mints an
//! [`crate::runtime_execution::ObservedGuestLocalExecutionV1`]. Callers cannot
//! echo a binding, phase, or result through this source-only seam.

use aos_sandbox_core::{
    AuditId, DecodeLimits, ExecutionCredentialsV1, ExecutionId, ExecutionTerminalModeV1,
    ObjectDigest, PrincipalId, decode_execution_spec_v1, execution_spec_digest_v1,
};

use aos_sandbox_agent::AgentExecutionPhaseV1;

use super::agent_execution_adapter::{
    GuestExecutableCredentialV1, GuestForcedCommandCredentialV1, GuestLocalExecutionHandoffV1,
    GuestLocalExecutionRequestV1, ObservedGuestLocalExecutionV1,
};

/// Binds a process effect to its admitted guest identity and audit row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DormantGuestCredentialEffectV1 {
    execution: ExecutionId,
    principal: PrincipalId,
    audit: AuditId,
    admission_commitment: ObjectDigest,
    guest_credentials: ExecutionCredentialsV1,
}

impl DormantGuestCredentialEffectV1 {
    /// Returns the exact admitted execution identity.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the authenticated portable principal.
    #[must_use]
    pub const fn principal(&self) -> PrincipalId {
        self.principal
    }

    /// Returns the durable audit identity.
    #[must_use]
    pub const fn audit(&self) -> AuditId {
        self.audit
    }

    /// Returns the protected admission commitment.
    #[must_use]
    pub const fn admission_commitment(&self) -> ObjectDigest {
        self.admission_commitment
    }

    /// Borrows the exact guest user and group projection.
    #[must_use]
    pub const fn guest_credentials(&self) -> &ExecutionCredentialsV1 {
        &self.guest_credentials
    }
}

/// Names one closed guest-local effect for a future syscall implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DormantGuestProcessEffectV1 {
    /// Starts a fixed executable with admitted credentials and optional PTY.
    StartProcess {
        /// Fixed packaged executable authenticated at the guest boundary.
        executable: GuestExecutableCredentialV1,
        /// Admission-derived credential and audit effect.
        credential: DormantGuestCredentialEffectV1,
        /// Exact canonical execution specification.
        specification_bytes: Vec<u8>,
        /// Whether the effect must allocate and own a PTY.
        allocate_pty: bool,
    },
    /// Applies terminal geometry to the PTY owned by one execution.
    ResizePty {
        /// Exact execution identity.
        execution: ExecutionId,
        /// Positive row count.
        rows: u16,
        /// Positive column count.
        columns: u16,
    },
    /// Delivers one portable signal to the exact execution process group.
    DeliverSignal {
        /// Exact execution identity.
        execution: ExecutionId,
        /// Closed portable signal code in `1..=64`.
        signal_code: u8,
    },
    /// Cancels one exact nonterminal process group.
    CancelProcess(ExecutionId),
    /// Inspects one exact process and its terminal state without mutation.
    ObserveProcess(ExecutionId),
    /// Enters the complete guest-local process quiesce barrier.
    BeginQuiesce,
    /// Leaves the exact guest-local process quiesce barrier.
    EndQuiesce,
}

/// Retains the sole reducer handoff beside its typed process effect.
#[must_use = "the dormant guest effect must be executed or retained for recovery"]
pub struct PreparedDormantGuestProcessEffectV1 {
    handoff: GuestLocalExecutionHandoffV1,
    effect: DormantGuestProcessEffectV1,
}

impl PreparedDormantGuestProcessEffectV1 {
    /// Borrows the exact typed process effect.
    #[must_use]
    pub const fn effect(&self) -> &DormantGuestProcessEffectV1 {
        &self.effect
    }

    /// Returns the protected handoff binding retained for the effect owner.
    #[must_use]
    pub const fn handoff_binding(&self) -> ObjectDigest {
        self.handoff.handoff_binding()
    }

    /// Recovers the intact reducer handoff without claiming an observation.
    #[must_use]
    pub fn into_handoff(self) -> GuestLocalExecutionHandoffV1 {
        self.handoff
    }

    pub(super) const fn prepared(&self) -> &super::agent_reducer::PreparedAgentOperationV1 {
        self.handoff.prepared()
    }
}

pub(super) struct DormantGuestProcessPreparationFailureV1 {
    error: DormantGuestProcessEffectErrorV1,
    handoff: GuestLocalExecutionHandoffV1,
}

impl DormantGuestProcessPreparationFailureV1 {
    pub(super) fn into_parts(
        self,
    ) -> (
        DormantGuestProcessEffectErrorV1,
        GuestLocalExecutionHandoffV1,
    ) {
        (self.error, self.handoff)
    }
}

/// Compiles reducer handoffs into the closed guest effect vocabulary.
///
/// This projection is nonauthorizing. The runtime execution owner must
/// authenticate the embedded reservation before any effect boundary is crossed.
pub struct DormantGuestProcessEffectAdapterV1;

impl DormantGuestProcessEffectAdapterV1 {
    /// Constructs the source-only process-effect adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Consumes one protected handoff into an exact typed effect.
    ///
    /// # Errors
    ///
    /// Returns [`DormantGuestProcessEffectErrorV1`] when Start contains a
    /// malformed or substituted execution specification or credential binding.
    pub(super) fn prepare(
        &mut self,
        handoff: GuestLocalExecutionHandoffV1,
    ) -> Result<PreparedDormantGuestProcessEffectV1, DormantGuestProcessPreparationFailureV1> {
        let effect = match handoff.request() {
            GuestLocalExecutionRequestV1::Start {
                executable,
                forced_command,
                specification_bytes,
            } => prepare_start_effect(*executable, *forced_command, specification_bytes),
            GuestLocalExecutionRequestV1::Resize {
                execution,
                rows,
                columns,
            } => Ok(DormantGuestProcessEffectV1::ResizePty {
                execution: *execution,
                rows: *rows,
                columns: *columns,
            }),
            GuestLocalExecutionRequestV1::Signal {
                execution,
                signal_code,
            } => Ok(DormantGuestProcessEffectV1::DeliverSignal {
                execution: *execution,
                signal_code: *signal_code,
            }),
            GuestLocalExecutionRequestV1::Cancel(execution) => {
                Ok(DormantGuestProcessEffectV1::CancelProcess(*execution))
            }
            GuestLocalExecutionRequestV1::Observe(execution) => {
                Ok(DormantGuestProcessEffectV1::ObserveProcess(*execution))
            }
            GuestLocalExecutionRequestV1::BeginQuiesce => {
                Ok(DormantGuestProcessEffectV1::BeginQuiesce)
            }
            GuestLocalExecutionRequestV1::EndQuiesce => Ok(DormantGuestProcessEffectV1::EndQuiesce),
        };
        let effect = match effect {
            Ok(effect) => effect,
            Err(error) => {
                return Err(DormantGuestProcessPreparationFailureV1 { error, handoff });
            }
        };
        Ok(PreparedDormantGuestProcessEffectV1 { handoff, effect })
    }
}

impl Default for DormantGuestProcessEffectAdapterV1 {
    fn default() -> Self {
        Self::new()
    }
}

/// Reports a process state obtained from the injected observation effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DormantObservedProcessStateV1 {
    /// The process exists and remains runnable.
    Running { process_id: u32 },
    /// The process exited normally with the supplied status.
    Exited { status: i32 },
    /// The process was canceled by the guest supervisor.
    Canceled,
    /// The process can no longer be accounted for.
    Lost,
}

/// Performs the concrete guest-local effects used by the dormant supervisor.
///
/// Implementations are injected by the independently built guest-agent entry
/// seam. The supervisor derives canonical result bytes itself; this interface
/// never accepts result bytes, a handoff binding, or a terminal phase.
pub trait DormantGuestProcessEffectsV1 {
    /// Concrete credential preparation retained until process creation.
    type CredentialHandle;
    /// Concrete PTY allocation retained until process creation.
    type PtyHandle;
    /// Adapter-specific effect failure.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Applies the exact admitted user and group projection.
    ///
    /// # Errors
    ///
    /// Returns the implementation error when credential preparation fails.
    fn apply_credentials(
        &mut self,
        credential: &DormantGuestCredentialEffectV1,
    ) -> Result<Self::CredentialHandle, Self::Error>;

    /// Allocates a controlling PTY for one exact execution.
    ///
    /// # Errors
    ///
    /// Returns the implementation error when PTY creation or ownership fails.
    fn allocate_pty(&mut self, execution: ExecutionId) -> Result<Self::PtyHandle, Self::Error>;

    /// Starts the fixed packaged executable under prepared credentials and PTY.
    ///
    /// # Errors
    ///
    /// Returns the implementation error when process creation fails.
    fn start_process(
        &mut self,
        executable: GuestExecutableCredentialV1,
        specification_bytes: &[u8],
        credential: Self::CredentialHandle,
        pty: Option<Self::PtyHandle>,
    ) -> Result<u32, Self::Error>;

    /// Changes the exact execution PTY geometry.
    ///
    /// # Errors
    ///
    /// Returns the implementation error when the PTY is absent or rejected.
    fn resize_pty(
        &mut self,
        execution: ExecutionId,
        rows: u16,
        columns: u16,
    ) -> Result<(), Self::Error>;

    /// Delivers one portable signal to the exact execution process group.
    ///
    /// # Errors
    ///
    /// Returns the implementation error when signal delivery fails.
    fn deliver_signal(
        &mut self,
        execution: ExecutionId,
        signal_code: u8,
    ) -> Result<(), Self::Error>;

    /// Cancels one exact execution process group.
    ///
    /// # Errors
    ///
    /// Returns the implementation error when cancellation fails.
    fn cancel_process(&mut self, execution: ExecutionId) -> Result<(), Self::Error>;

    /// Obtains kernel-backed state for one exact execution.
    ///
    /// # Errors
    ///
    /// Returns the implementation error when process observation fails.
    fn observe_process(
        &mut self,
        execution: ExecutionId,
    ) -> Result<DormantObservedProcessStateV1, Self::Error>;

    /// Enters the complete local process quiesce barrier.
    ///
    /// # Errors
    ///
    /// Returns the implementation error when any process cannot quiesce.
    fn begin_quiesce(&mut self) -> Result<(), Self::Error>;

    /// Leaves the exact local process quiesce barrier.
    ///
    /// # Errors
    ///
    /// Returns the implementation error when the barrier cannot be released.
    fn end_quiesce(&mut self) -> Result<(), Self::Error>;
}

pub(super) enum DormantGuestProcessAttemptDispositionV1 {
    BeforeEffect,
    OutcomeUnknown,
}

pub(super) struct DormantGuestProcessAttemptFailureV1 {
    disposition: DormantGuestProcessAttemptDispositionV1,
    error: DormantGuestProcessSupervisorErrorV1,
    prepared: PreparedDormantGuestProcessEffectV1,
}

impl DormantGuestProcessAttemptFailureV1 {
    pub(super) fn into_parts(
        self,
    ) -> (
        DormantGuestProcessAttemptDispositionV1,
        DormantGuestProcessSupervisorErrorV1,
        PreparedDormantGuestProcessEffectV1,
    ) {
        (self.disposition, self.error, self.prepared)
    }
}

/// Executes protected process effects and exclusively mints observations.
pub struct DormantGuestProcessSupervisorV1<Effects> {
    effects: Effects,
}

impl<Effects> DormantGuestProcessSupervisorV1<Effects>
where
    Effects: DormantGuestProcessEffectsV1,
{
    /// Constructs a supervisor around concrete injected guest effects.
    #[must_use]
    pub const fn new(effects: Effects) -> Self {
        Self { effects }
    }

    /// Executes one move-only prepared effect and mints its bound observation.
    ///
    /// The result bytes are derived only from concrete effect return values.
    /// Callers cannot supply a phase, result payload, or handoff binding.
    ///
    /// # Errors
    ///
    /// Returns [`DormantGuestProcessSupervisorErrorV1`] if any injected effect
    /// fails or returns an invalid process identifier.
    pub(super) fn execute(
        &mut self,
        prepared: PreparedDormantGuestProcessEffectV1,
        mut recheck: impl FnMut(
            &super::agent_reducer::PreparedAgentOperationV1,
        ) -> Result<(), DormantGuestProcessSupervisorErrorV1>,
    ) -> Result<ObservedGuestLocalExecutionV1, DormantGuestProcessAttemptFailureV1> {
        let execution = self.execute_effect(prepared.prepared(), prepared.effect(), &mut recheck);
        let (phase, result_bytes) = match execution {
            Ok(observation) => observation,
            Err((disposition, error)) => {
                return Err(DormantGuestProcessAttemptFailureV1 {
                    disposition,
                    error,
                    prepared,
                });
            }
        };
        let handoff_binding = prepared.handoff_binding();
        let handoff = prepared.into_handoff();

        Ok(ObservedGuestLocalExecutionV1::from_supervisor(
            handoff.into_prepared(),
            phase,
            result_bytes,
            handoff_binding,
        ))
    }

    fn execute_effect(
        &mut self,
        prepared: &super::agent_reducer::PreparedAgentOperationV1,
        effect: &DormantGuestProcessEffectV1,
        recheck: &mut impl FnMut(
            &super::agent_reducer::PreparedAgentOperationV1,
        ) -> Result<(), DormantGuestProcessSupervisorErrorV1>,
    ) -> Result<
        (AgentExecutionPhaseV1, Vec<u8>),
        (
            DormantGuestProcessAttemptDispositionV1,
            DormantGuestProcessSupervisorErrorV1,
        ),
    > {
        match effect {
            DormantGuestProcessEffectV1::StartProcess {
                executable,
                credential,
                specification_bytes,
                allocate_pty,
            } => {
                let credential_handle = self
                    .effects
                    .apply_credentials(credential)
                    .map_err(before_effect_failure)?;
                let pty = if *allocate_pty {
                    Some(
                        self.effects
                            .allocate_pty(credential.execution())
                            .map_err(before_effect_failure)?,
                    )
                } else {
                    None
                };
                recheck(prepared).map_err(|error| {
                    (DormantGuestProcessAttemptDispositionV1::BeforeEffect, error)
                })?;
                let process_id = self
                    .effects
                    .start_process(*executable, specification_bytes, credential_handle, pty)
                    .map_err(outcome_unknown_failure)?;
                if process_id == 0 {
                    return Err((
                        DormantGuestProcessAttemptDispositionV1::OutcomeUnknown,
                        DormantGuestProcessSupervisorErrorV1::InvalidEffectResult,
                    ));
                }
                Ok((
                    AgentExecutionPhaseV1::Running,
                    encode_effect_result(1, &process_id.to_be_bytes()),
                ))
            }
            DormantGuestProcessEffectV1::ResizePty {
                execution,
                rows,
                columns,
            } => {
                recheck(prepared).map_err(|error| {
                    (DormantGuestProcessAttemptDispositionV1::BeforeEffect, error)
                })?;
                self.effects
                    .resize_pty(*execution, *rows, *columns)
                    .map_err(outcome_unknown_failure)?;
                let mut result = Vec::with_capacity(4);
                result.extend_from_slice(&rows.to_be_bytes());
                result.extend_from_slice(&columns.to_be_bytes());
                Ok((
                    AgentExecutionPhaseV1::Running,
                    encode_effect_result(2, &result),
                ))
            }
            DormantGuestProcessEffectV1::DeliverSignal {
                execution,
                signal_code,
            } => {
                recheck(prepared).map_err(|error| {
                    (DormantGuestProcessAttemptDispositionV1::BeforeEffect, error)
                })?;
                self.effects
                    .deliver_signal(*execution, *signal_code)
                    .map_err(outcome_unknown_failure)?;
                Ok((
                    AgentExecutionPhaseV1::Running,
                    encode_effect_result(3, &[*signal_code]),
                ))
            }
            DormantGuestProcessEffectV1::CancelProcess(execution) => {
                recheck(prepared).map_err(|error| {
                    (DormantGuestProcessAttemptDispositionV1::BeforeEffect, error)
                })?;
                self.effects
                    .cancel_process(*execution)
                    .map_err(outcome_unknown_failure)?;
                Ok((
                    AgentExecutionPhaseV1::Canceled,
                    encode_effect_result(4, execution.as_bytes()),
                ))
            }
            DormantGuestProcessEffectV1::ObserveProcess(execution) => {
                recheck(prepared).map_err(|error| {
                    (DormantGuestProcessAttemptDispositionV1::BeforeEffect, error)
                })?;
                let observation = self
                    .effects
                    .observe_process(*execution)
                    .map_err(outcome_unknown_failure)?;
                Ok(encode_process_observation(observation))
            }
            DormantGuestProcessEffectV1::BeginQuiesce => {
                recheck(prepared).map_err(|error| {
                    (DormantGuestProcessAttemptDispositionV1::BeforeEffect, error)
                })?;
                self.effects
                    .begin_quiesce()
                    .map_err(outcome_unknown_failure)?;
                Ok((
                    AgentExecutionPhaseV1::Quiesced,
                    encode_effect_result(9, b"quiesced"),
                ))
            }
            DormantGuestProcessEffectV1::EndQuiesce => {
                recheck(prepared).map_err(|error| {
                    (DormantGuestProcessAttemptDispositionV1::BeforeEffect, error)
                })?;
                self.effects
                    .end_quiesce()
                    .map_err(outcome_unknown_failure)?;
                Ok((
                    AgentExecutionPhaseV1::Ready,
                    encode_effect_result(10, b"ready"),
                ))
            }
        }
    }

    /// Returns the injected effect implementation for orderly dormant teardown.
    #[must_use]
    pub fn into_effects(self) -> Effects {
        self.effects
    }
}

fn effect_failure<Error>(error: Error) -> DormantGuestProcessSupervisorErrorV1
where
    Error: std::error::Error,
{
    DormantGuestProcessSupervisorErrorV1::Effect(error.to_string())
}

fn before_effect_failure<Error>(
    error: Error,
) -> (
    DormantGuestProcessAttemptDispositionV1,
    DormantGuestProcessSupervisorErrorV1,
)
where
    Error: std::error::Error,
{
    (
        DormantGuestProcessAttemptDispositionV1::BeforeEffect,
        effect_failure(error),
    )
}

fn outcome_unknown_failure<Error>(
    error: Error,
) -> (
    DormantGuestProcessAttemptDispositionV1,
    DormantGuestProcessSupervisorErrorV1,
)
where
    Error: std::error::Error,
{
    (
        DormantGuestProcessAttemptDispositionV1::OutcomeUnknown,
        effect_failure(error),
    )
}

fn encode_process_observation(
    observation: DormantObservedProcessStateV1,
) -> (AgentExecutionPhaseV1, Vec<u8>) {
    match observation {
        DormantObservedProcessStateV1::Running { process_id } => (
            AgentExecutionPhaseV1::Running,
            encode_effect_result(5, &process_id.to_be_bytes()),
        ),
        DormantObservedProcessStateV1::Exited { status } => (
            AgentExecutionPhaseV1::Exited,
            encode_effect_result(6, &status.to_be_bytes()),
        ),
        DormantObservedProcessStateV1::Canceled => (
            AgentExecutionPhaseV1::Canceled,
            encode_effect_result(7, b"canceled"),
        ),
        DormantObservedProcessStateV1::Lost => (
            AgentExecutionPhaseV1::Lost,
            encode_effect_result(8, b"lost"),
        ),
    }
}

fn encode_effect_result(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(8 + 1 + 4 + payload.len());
    result.extend_from_slice(b"AOSGER01");
    result.push(kind);
    result.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    result.extend_from_slice(payload);
    result
}

/// Reports failure before an observation can be minted.
#[derive(Debug, thiserror::Error)]
pub enum DormantGuestProcessSupervisorErrorV1 {
    /// The protected owner no longer authenticates the prepared reservation.
    #[error("dormant guest process effect lost protected currentness: {0}")]
    ProtectedCurrentness(String),
    /// One concrete injected guest effect failed.
    #[error("dormant guest process effect failed: {0}")]
    Effect(String),
    /// A concrete effect returned a sentinel process identity.
    #[error("dormant guest process effect returned an invalid result")]
    InvalidEffectResult,
}

fn prepare_start_effect(
    executable: GuestExecutableCredentialV1,
    forced_command: GuestForcedCommandCredentialV1,
    specification_bytes: &[u8],
) -> Result<DormantGuestProcessEffectV1, DormantGuestProcessEffectErrorV1> {
    let specification = decode_execution_spec_v1(
        specification_bytes,
        DecodeLimits {
            maximum_bytes: specification_bytes.len(),
            maximum_collection_items: 65_536,
            maximum_total_items: 262_144,
            maximum_byte_string_bytes: 15 * 1_048_576,
            maximum_text_bytes: 1_048_576,
            maximum_depth: 128,
        },
    )
    .map_err(|_| DormantGuestProcessEffectErrorV1::InvalidStart)?;
    if specification.execution() != forced_command.execution()
        || execution_spec_digest_v1(&specification) != forced_command.specification_digest()
        || specification.principal() != forced_command.principal()
        || specification.audit() != forced_command.audit()
    {
        return Err(DormantGuestProcessEffectErrorV1::InvalidStart);
    }

    Ok(DormantGuestProcessEffectV1::StartProcess {
        executable,
        credential: DormantGuestCredentialEffectV1 {
            execution: forced_command.execution(),
            principal: forced_command.principal(),
            audit: forced_command.audit(),
            admission_commitment: forced_command.admission_commitment(),
            guest_credentials: specification.command().credentials().clone(),
        },
        specification_bytes: specification_bytes.to_vec(),
        allocate_pty: specification.io().terminal_mode() == ExecutionTerminalModeV1::Pty,
    })
}

/// Reports source-only guest process-effect projection failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DormantGuestProcessEffectErrorV1 {
    /// Start bytes or their credential projection are malformed or substituted.
    #[error("dormant guest process start effect is invalid")]
    InvalidStart,
}
