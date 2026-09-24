//! Durable controller dispatch identity for execution effects and observations.
//!
//! The accepted controller effect retains the authenticated caller, project,
//! and canonical public request. This protected admission context, not the
//! mutable execution projection, is the source for Host requests after a
//! restart. A later Observe derives its specification binding from the
//! admitted Create intent and needs its own protected operation identity.
//! Controls can supersede the projection while an earlier effect is pending.

use aos_proto::aos::sandbox::local::v1::{
    ApplyHostExecutionRequestV1, BrokerAuthorizationArtifactsV1, BrokerDescriptorEntry,
    BrokerDescriptorRole, BrokerMethod, BrokerRequestEnvelope, HostExecutionActionV1,
    HostExecutionCompletionStatusV1, HostExecutionPhaseV1, QueryHostExecutionRequestV1,
    RequestHeader,
};
use aos_proto::aos::sandbox::v1::{ExecutionIoMode, ExecutionPhase};
use aos_sandbox::cli_model::DormantSandboxRequestKindV1;
use aos_sandbox::controller_execution_spec_attempt::{
    ControllerExecutionSpecAttemptV1, load_controller_execution_spec_attempt_v1,
};
use aos_sandbox::controller_service::public_projection::{
    PublicProjectionKindV1, PublicProjectionPlanV1, PublicProjectionResourceV1,
    PublicProjectionStoreV1,
};
use aos_sandbox::execution_guest_identity::read_execution_guest_identity_v1;
use aos_sandbox::production_operation_compiler::{
    PublicExecutionControlDispatchV1, lower_public_execution_control_v1,
};
use aos_sandbox::runtime_execution::{
    RuntimeExecutionEvidenceError, decode_authorize_completion_binding_v1,
    decode_control_completion_phase_v1, decode_observe_completion_phase_v1,
};
use aos_sandbox::runtime_scope::CurrentAssignmentTarget;
use aos_sandbox::{
    AuthorityPublicationStore, EffectFailure, EffectReceipt, Journal, JournalRecord,
    JournalTransaction, PublicMutationEffectV1, RecordNamespace,
};
use aos_sandbox_core::runtime_backend::{BackendExecutionPhaseV1, EffectOperationV1};
use aos_sandbox_core::{
    BrokerAudience, BrokerAuthorizationPlan, BrokerGrant, ExecutionEndpointCapabilityV1,
    ExecutionId, ExecutionOutputModeV1, ExecutionSpecV1, ExecutionTerminalModeV1, NodeId,
    ObjectDigest, OperationId, ProjectId, ProtocolId, ProtocolVersion, SandboxId,
    encode_execution_spec_v1, execution_spec_digest_v1,
};
use aos_sandbox_linux::immutable_file::SealedReadOnlyCredential;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
};
use aos_sandbox_protocol::host_execution::{
    HOST_EXECUTION_CONTROL_CONTENT_V1, HostExecutionSpecContentFieldsV1,
    MAXIMUM_HOST_EXECUTION_SPEC_BYTES,
};
use aos_sandbox_protocol::host_execution::{
    HostExecutionTerminalResultV1, decode_host_execution_outcome_v1,
    decode_host_execution_terminal_result_v1,
};
use aos_sandbox_protocol::semantics::{
    host_execution_apply_grant_v1, host_execution_query_content_grant_v1,
};
use buffa::Message as _;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};
use ssh_key::{PublicKey, public::Ed25519PublicKey};

use crate::controller_plan_signer::ControllerBrokerPlanSignerV1;
use crate::controller_retained_exchange::{RetainedBrokerExchangeV1, RetainedExchangeErrorsV1};
use crate::{DormantAuthenticatedBrokerSessionV1, DormantBrokerRequestCoordinatesV1};

use super::REQUEST_SCOPE;

const PUBLIC_REQUEST_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.controller-public-request.v1\0";
const EXECUTION_RECEIPT_DOMAIN: &[u8] = b"aos.sandbox.controller.execution-receipt.v1\0";
const CONTROL_PROJECTION_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.controller.execution-control-projection.v1\0";
const RETAINED_RECOVERY: &str = "execution effect retains protected Host session recovery custody";
const SESSION_UNUSABLE: &str = "execution effect Host session is unusable";
const ERRORS: RetainedExchangeErrorsV1 = RetainedExchangeErrorsV1 {
    absent: "execution exchange custody is absent",
    retained: RETAINED_RECOVERY,
    unusable: SESSION_UNUSABLE,
};

/// Carries one exact execution operation into the Host carrier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControllerExecutionIntentV1 {
    operation_id: OperationId,
    projection_operation_id: OperationId,
    execution_id: [u8; 16],
    action: ControllerExecutionActionV1,
    specification: Option<ExecutionSpecV1>,
    observation_specification_digest: Option<ObjectDigest>,
    source_operation_commitment: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControllerExecutionActionV1 {
    Authorize,
    Resize { rows: u16, columns: u16 },
    Signal { signal_code: u8 },
    Cancel,
    Observe,
}

/// Carries the receipt together with the exact authenticated guest observation.
pub(crate) struct ControllerExecutionCompletionV1 {
    pub(crate) receipt: EffectReceipt,
    phase: BackendExecutionPhaseV1,
    observation_sequence: u64,
    terminal: Option<HostExecutionTerminalResultV1>,
}

impl ControllerExecutionCompletionV1 {
    fn public_phase(&self) -> Result<ExecutionPhase, EffectFailure> {
        match self.phase {
            BackendExecutionPhaseV1::Running => Ok(ExecutionPhase::EXECUTION_PHASE_RUNNING),
            BackendExecutionPhaseV1::Authorized | BackendExecutionPhaseV1::Starting => {
                Err(EffectFailure::Retryable(
                    "execution authorization awaits a distinct Host Observe".to_owned(),
                ))
            }
            // Host now authenticates the Guest terminal bytes. Public terminal
            // publication still needs termination semantics and capture custody.
            BackendExecutionPhaseV1::Exited
                if matches!(
                    self.terminal,
                    Some(HostExecutionTerminalResultV1::Exited(_))
                ) =>
            {
                Err(EffectFailure::Retryable(
                    "execution exit requires public result projection".to_owned(),
                ))
            }
            BackendExecutionPhaseV1::Canceled
                if self.terminal == Some(HostExecutionTerminalResultV1::Canceled) =>
            {
                Err(EffectFailure::Retryable(
                    "execution cancellation requires public result and capture disposition"
                        .to_owned(),
                ))
            }
            BackendExecutionPhaseV1::Exited | BackendExecutionPhaseV1::Canceled => {
                Err(EffectFailure::Retryable(
                    "Host terminal completion awaits signed Guest result readback".to_owned(),
                ))
            }
            _ => Err(EffectFailure::Permanent(
                "control completion has an unsupported phase".to_owned(),
            )),
        }
    }

    fn is_terminal(&self) -> bool {
        matches!(
            self.phase,
            BackendExecutionPhaseV1::Exited
                | BackendExecutionPhaseV1::Canceled
                | BackendExecutionPhaseV1::Failed
                | BackendExecutionPhaseV1::Lost
        )
    }
}

/// Separates authenticated absence from an exact guest control completion.
pub(crate) enum ControllerExecutionObservationV1 {
    Absent,
    Applied(ControllerExecutionCompletionV1),
}

impl ControllerExecutionActionV1 {
    // Apply encoding and signed-request validation must agree on every field.
    fn wire_fields(self) -> (HostExecutionActionV1, u32, u32, u32) {
        match self {
            Self::Authorize => (
                HostExecutionActionV1::HOST_EXECUTION_ACTION_AUTHORIZE,
                0,
                0,
                0,
            ),
            Self::Resize { rows, columns } => (
                HostExecutionActionV1::HOST_EXECUTION_ACTION_RESIZE,
                u32::from(rows),
                u32::from(columns),
                0,
            ),
            Self::Signal { signal_code } => (
                HostExecutionActionV1::HOST_EXECUTION_ACTION_SIGNAL,
                0,
                0,
                u32::from(signal_code),
            ),
            Self::Cancel => (HostExecutionActionV1::HOST_EXECUTION_ACTION_CANCEL, 0, 0, 0),
            Self::Observe => (
                HostExecutionActionV1::HOST_EXECUTION_ACTION_OBSERVE,
                0,
                0,
                0,
            ),
        }
    }

    fn effect_operation(self) -> EffectOperationV1 {
        match self {
            Self::Authorize => EffectOperationV1::AuthorizeExecution,
            Self::Resize { rows, columns } => EffectOperationV1::ResizeTerminal { rows, columns },
            Self::Signal { signal_code } => EffectOperationV1::Signal { signal_code },
            Self::Cancel => EffectOperationV1::Cancel,
            Self::Observe => EffectOperationV1::Observe,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExecutionAuthorizationKindV1 {
    Apply,
    Query,
}

impl ExecutionAuthorizationKindV1 {
    fn broker_method(self) -> BrokerMethod {
        match self {
            Self::Apply => BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION,
            Self::Query => BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION,
        }
    }
}

impl ControllerExecutionIntentV1 {
    fn descriptor_content(&self) -> Result<Vec<u8>, EffectFailure> {
        let bytes = self
            .specification
            .as_ref()
            .map(encode_execution_spec_v1)
            .unwrap_or_else(|| HOST_EXECUTION_CONTROL_CONTENT_V1.to_vec());
        if bytes.is_empty() || bytes.len() > MAXIMUM_HOST_EXECUTION_SPEC_BYTES {
            return Err(EffectFailure::Permanent(
                "execution specification exceeds sealed content ceiling".to_owned(),
            ));
        }
        Ok(bytes)
    }

    /// Publishes the observed control phase only after verified Host success.
    ///
    /// A retry reads the protected record first, making the projection write
    /// idempotent. An already superseded public projection is never replaced.
    ///
    /// # Errors
    ///
    /// Returns an error when the projection is absent, superseded, malformed,
    /// or cannot be durably committed.
    pub(crate) fn commit_control_projection(
        &self,
        project: ProjectId,
        journal: &mut Journal,
        completion: &ControllerExecutionCompletionV1,
    ) -> Result<(), EffectFailure> {
        if self.action == ControllerExecutionActionV1::Authorize {
            return Err(EffectFailure::Retryable(
                "execution authorization cannot publish a public phase".to_owned(),
            ));
        }
        let current = PublicProjectionStoreV1::new(journal)
            .get(PublicProjectionKindV1::Execution, self.execution_id)
            .map_err(retryable)?
            .ok_or_else(|| {
                EffectFailure::Retryable("execution control projection is absent".to_owned())
            })?;
        if current.project() != project || current.operation() != self.projection_operation_id {
            return Err(EffectFailure::Retryable(
                "execution control projection was superseded".to_owned(),
            ));
        }
        let PublicProjectionResourceV1::Execution(execution) = current.resource() else {
            return Err(EffectFailure::Permanent(
                "execution control projection has another resource kind".to_owned(),
            ));
        };
        let phase = completion.public_phase()?;
        let already_published = if self.action == ControllerExecutionActionV1::Observe {
            execution.observation_sequence == completion.observation_sequence
        } else {
            execution.observation_sequence >= completion.observation_sequence
        };
        if execution.phase.as_known() == Some(phase)
            && already_published
            && (!completion.is_terminal() || execution.access.as_option().is_none())
        {
            return Ok(());
        }
        let expected_previous_phase = match self.action {
            ControllerExecutionActionV1::Authorize => ExecutionPhase::EXECUTION_PHASE_REQUESTED,
            ControllerExecutionActionV1::Observe
                if execution.phase.as_known() == Some(ExecutionPhase::EXECUTION_PHASE_RUNNING) =>
            {
                ExecutionPhase::EXECUTION_PHASE_RUNNING
            }
            ControllerExecutionActionV1::Observe => ExecutionPhase::EXECUTION_PHASE_REQUESTED,
            _ => ExecutionPhase::EXECUTION_PHASE_RUNNING,
        };
        let stale_observation = if self.action == ControllerExecutionActionV1::Observe {
            completion.observation_sequence <= execution.observation_sequence
        } else {
            completion.observation_sequence < execution.observation_sequence
        };
        if execution.phase.as_known() != Some(expected_previous_phase) || stale_observation {
            return Err(EffectFailure::Retryable(
                "execution control projection is no longer current".to_owned(),
            ));
        }

        let mut observed = execution.clone();
        observed.phase = phase.into();
        observed.observation_sequence = completion.observation_sequence;
        if completion.is_terminal() {
            observed.access = None.into();
        }
        let (key, value) = PublicProjectionPlanV1::new(
            project,
            self.projection_operation_id,
            PublicProjectionResourceV1::Execution(observed),
        )
        .map_err(retryable)?
        .into_desired_state();
        let digest = Sha256::new()
            .chain_update(CONTROL_PROJECTION_TRANSACTION_DOMAIN)
            .chain_update(self.operation_id.as_bytes())
            .finalize();
        let transaction_id: [u8; 16] = digest[..16].try_into().map_err(|_| {
            EffectFailure::Permanent("execution projection transaction is invalid".to_owned())
        })?;
        if transaction_id == [0; 16] {
            return Err(EffectFailure::Permanent(
                "execution projection transaction is invalid".to_owned(),
            ));
        }
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                key,
                value,
            )],
        )
        .map_err(retryable)?;
        journal.commit(&transaction).map_err(retryable)?;
        Ok(())
    }

    pub(crate) fn from_request(
        operation_id: OperationId,
        context: &PublicMutationEffectV1,
    ) -> Result<Self, EffectFailure> {
        let request = context
            .validated_request()
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
        let (execution_id, action) = match request {
            DormantSandboxRequestKindV1::ExecutionControl(request) => {
                let PublicExecutionControlDispatchV1::Effect(effect) =
                    lower_public_execution_control_v1(&request)
                        .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                else {
                    return Err(EffectFailure::Permanent(
                        "execution attachment requires a separate route".to_owned(),
                    ));
                };
                let action = match effect {
                    EffectOperationV1::ResizeTerminal { rows, columns } => {
                        ControllerExecutionActionV1::Resize { rows, columns }
                    }
                    EffectOperationV1::Signal { signal_code } => {
                        ControllerExecutionActionV1::Signal { signal_code }
                    }
                    _ => {
                        return Err(EffectFailure::Permanent(
                            "execution control action is unsupported".to_owned(),
                        ));
                    }
                };
                (request.execution_id, action)
            }
            DormantSandboxRequestKindV1::CancelExec(request) => {
                (request.execution_id, ControllerExecutionActionV1::Cancel)
            }
            _ => {
                return Err(EffectFailure::Permanent(
                    "execution effect has the wrong public method".to_owned(),
                ));
            }
        };
        let execution_id: [u8; 16] = execution_id.as_slice().try_into().map_err(|_| {
            EffectFailure::Permanent("execution effect identity is invalid".to_owned())
        })?;

        let source_operation_commitment: [u8; 32] = Sha256::new()
            .chain_update(PUBLIC_REQUEST_DIGEST_DOMAIN)
            .chain_update(REQUEST_SCOPE)
            .chain_update(context.caller().as_bytes())
            .chain_update(context.project().as_bytes())
            .chain_update((context.canonical_request().len() as u64).to_be_bytes())
            .chain_update(context.canonical_request())
            .finalize()
            .into();

        Ok(Self {
            operation_id,
            projection_operation_id: operation_id,
            execution_id,
            action,
            specification: None,
            observation_specification_digest: None,
            source_operation_commitment,
        })
    }

    /// Binds a retained specification attempt to the exact Create request,
    /// selected assignment, and guest credential policy before Host dispatch.
    ///
    /// The protected attempt is historical custody. Production Create remains
    /// closed until independent Host and Storage owners are held across spec
    /// admission and the effect handoff.
    ///
    /// # Errors
    ///
    /// Returns an error when the specification substitutes the command, holder
    /// key, principal, audit identity, guest credentials, assignment, or current
    /// requested execution.
    #[allow(dead_code)]
    pub(crate) fn from_retained_create_attempt(
        operation_id: OperationId,
        context: &PublicMutationEffectV1,
        journal: &Journal,
        assignment: &CurrentAssignmentTarget,
        attempt: &ControllerExecutionSpecAttemptV1,
    ) -> Result<Self, EffectFailure> {
        let retained = load_controller_execution_spec_attempt_v1(journal, attempt.execution())
            .map_err(retryable)?
            .ok_or_else(|| {
                EffectFailure::Retryable("protected execution spec attempt is absent".to_owned())
            })?;
        if retained != *attempt
            || retained.create_operation() != operation_id
            || !retained.matches_accepted_request(context.canonical_request())
        {
            return Err(EffectFailure::Permanent(
                "execution spec attempt differs from admitted Create custody".to_owned(),
            ));
        }
        let specification = retained.decoded_specification().map_err(retryable)?;
        let DormantSandboxRequestKindV1::Exec(request) = context
            .validated_request()
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
        else {
            return Err(EffectFailure::Permanent(
                "execution authorization has the wrong public method".to_owned(),
            ));
        };
        let projection = PublicProjectionStoreV1::new(journal)
            .get(
                PublicProjectionKindV1::Execution,
                *specification.execution().as_bytes(),
            )
            .map_err(retryable)?
            .ok_or_else(|| EffectFailure::Retryable("execution projection is absent".to_owned()))?;
        let PublicProjectionResourceV1::Execution(execution) = projection.resource() else {
            return Err(EffectFailure::Permanent(
                "execution projection has another resource kind".to_owned(),
            ));
        };
        let command = request.command.as_option().ok_or_else(|| {
            EffectFailure::Permanent("execution request has no command".to_owned())
        })?;
        let exact_arguments = specification.command().arguments() == command.arguments;
        let exact_environment = specification.command().environment_overlay().len()
            == command.environment.len()
            && specification
                .command()
                .environment_overlay()
                .iter()
                .zip(&command.environment)
                .all(|(admitted, requested)| {
                    admitted.name() == requested.name && admitted.value() == requested.value
                });
        let expected_io = match command.io_mode.as_known() {
            Some(ExecutionIoMode::EXECUTION_IO_MODE_STREAM) => {
                specification.io().terminal_mode() == ExecutionTerminalModeV1::None
                    && specification.io().output_mode() == ExecutionOutputModeV1::Stream
            }
            Some(ExecutionIoMode::EXECUTION_IO_MODE_PTY) => {
                specification.io().terminal_mode() == ExecutionTerminalModeV1::Pty
                    && specification.io().output_mode() == ExecutionOutputModeV1::Stream
            }
            Some(ExecutionIoMode::EXECUTION_IO_MODE_DETACHED_CAPTURE) => {
                specification.io().terminal_mode() == ExecutionTerminalModeV1::None
                    && matches!(
                        specification.io().output_mode(),
                        ExecutionOutputModeV1::Capture {
                            maximum_stdout_bytes,
                            maximum_stderr_bytes,
                        } if command.maximum_stdout_bytes == Some(maximum_stdout_bytes)
                            && command.maximum_stderr_bytes == Some(maximum_stderr_bytes)
                            && maximum_stdout_bytes.checked_add(maximum_stderr_bytes)
                                == Some(command.detached_capture_bytes)
                    )
            }
            _ => false,
        };
        let expected_timeout = command
            .execution_timeout
            .as_option()
            .is_some_and(|duration| duration.nanoseconds == specification.timeout().nanoseconds());
        let expected_working_directory = specification
            .command()
            .working_directory()
            .components()
            .iter()
            .map(|component| component.as_bytes())
            .collect::<Vec<_>>()
            .join(&b'/');
        let holder_key = specification.io().access_route().public_key();
        let conservative_route =
            specification
                .io()
                .access_route()
                .capabilities()
                .iter()
                .all(|capability| {
                    matches!(
                        capability,
                        ExecutionEndpointCapabilityV1::StandardInput
                            | ExecutionEndpointCapabilityV1::StandardOutput
                            | ExecutionEndpointCapabilityV1::StandardError
                            | ExecutionEndpointCapabilityV1::TerminalResize
                    )
                });
        let key_matches = if command.io_mode.as_known()
            == Some(ExecutionIoMode::EXECUTION_IO_MODE_DETACHED_CAPTURE)
        {
            holder_key.is_none()
        } else {
            holder_key.is_some_and(|key| {
                VerifyingKey::from_bytes(key.key_material())
                    .ok()
                    .and_then(|key| {
                        PublicKey::new(Ed25519PublicKey::from(key).into(), "")
                            .to_openssh()
                            .ok()
                    })
                    .is_some_and(|line| request.client_public_key == line.as_bytes())
            })
        };
        if projection.project() != context.project()
            || projection.operation() != operation_id
            || execution.phase.as_known() != Some(ExecutionPhase::EXECUTION_PHASE_REQUESTED)
            || execution.sandbox_id != request.sandbox_id
            || execution.sandbox_incarnation_id != specification.target().incarnation().as_bytes()
            || execution.assignment_epoch != specification.target().assignment_epoch().get()
            || execution.audit_id != operation_id.as_bytes()
            || specification.target().sandbox().as_bytes() != request.sandbox_id.as_slice()
            || specification.principal() != context.caller()
            || specification.audit().as_bytes() != operation_id.as_bytes()
            || !exact_arguments
            || !exact_environment
            || expected_working_directory != command.working_directory
            || !expected_io
            || !expected_timeout
            || !key_matches
            || !conservative_route
            || !command.sandbox_shell.is_empty()
        {
            return Err(EffectFailure::Permanent(
                "execution specification differs from its admitted Create request".to_owned(),
            ));
        }
        aos_sandbox::create_holder_proof::verify_create_holder_proof_v1(&request).map_err(
            |_| EffectFailure::Permanent("execution holder proof is invalid".to_owned()),
        )?;
        read_execution_guest_identity_v1(journal, assignment, &specification)
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;

        let source_operation_commitment: [u8; 32] = Sha256::new()
            .chain_update(PUBLIC_REQUEST_DIGEST_DOMAIN)
            .chain_update(REQUEST_SCOPE)
            .chain_update(context.caller().as_bytes())
            .chain_update(context.project().as_bytes())
            .chain_update((context.canonical_request().len() as u64).to_be_bytes())
            .chain_update(context.canonical_request())
            .finalize()
            .into();
        Ok(Self {
            operation_id,
            projection_operation_id: operation_id,
            execution_id: *specification.execution().as_bytes(),
            action: ControllerExecutionActionV1::Authorize,
            specification: Some(specification),
            observation_specification_digest: None,
            source_operation_commitment,
        })
    }

    /// Derives a distinct Host Observe intent from an admitted Create intent.
    ///
    /// The caller must reserve and retain `observation_operation_id` under
    /// protected custody before requesting the Host effect. A completed
    /// Observe result is immutable, so each later observation needs a new ID.
    ///
    /// # Errors
    ///
    /// Rejects a source without its exact Create specification or a repeated
    /// Host operation identity.
    #[allow(dead_code)]
    pub(crate) fn observe_after_authorization(
        &self,
        observation_operation_id: OperationId,
    ) -> Result<Self, EffectFailure> {
        if self.action != ControllerExecutionActionV1::Authorize
            || observation_operation_id == self.operation_id
            || observation_operation_id.as_bytes() == &[0; 16]
        {
            return Err(EffectFailure::Permanent(
                "execution Observe has no distinct admitted Create source".to_owned(),
            ));
        }
        let specification = self.specification.as_ref().ok_or_else(|| {
            EffectFailure::Permanent("execution Observe has no retained specification".to_owned())
        })?;

        Ok(Self {
            operation_id: observation_operation_id,
            projection_operation_id: self.projection_operation_id,
            execution_id: self.execution_id,
            action: ControllerExecutionActionV1::Observe,
            specification: None,
            observation_specification_digest: Some(execution_spec_digest_v1(specification)),
            source_operation_commitment: self.source_operation_commitment,
        })
    }

    pub(crate) fn prepare_authorization(
        &self,
        kind: ExecutionAuthorizationKindV1,
        project: ProjectId,
        node: NodeId,
        journal: &mut Journal,
        signer: Option<&ControllerBrokerPlanSignerV1>,
    ) -> Result<BrokerAuthorizationArtifactsV1, EffectFailure> {
        let signer = signer.ok_or_else(|| {
            EffectFailure::Retryable("Host execution plan signer is unavailable".to_owned())
        })?;
        let projection = PublicProjectionStoreV1::new(journal)
            .get(PublicProjectionKindV1::Execution, self.execution_id)
            .map_err(retryable)?
            .ok_or_else(|| {
                EffectFailure::Retryable("protected execution projection is absent".to_owned())
            })?;
        if projection.project() != project {
            return Err(EffectFailure::Permanent(
                "execution projection crossed its admitted project".to_owned(),
            ));
        }
        let PublicProjectionResourceV1::Execution(execution) = projection.resource() else {
            return Err(EffectFailure::Permanent(
                "execution projection has another resource kind".to_owned(),
            ));
        };
        if self.action == ControllerExecutionActionV1::Observe
            && (self.observation_specification_digest.is_none()
                || (kind == ExecutionAuthorizationKindV1::Apply
                    && (projection.operation() != self.projection_operation_id
                        || !matches!(
                            execution.phase.as_known(),
                            Some(
                                ExecutionPhase::EXECUTION_PHASE_REQUESTED
                                    | ExecutionPhase::EXECUTION_PHASE_RUNNING
                            )
                        ))))
        {
            return Err(EffectFailure::Retryable(
                "execution Observe source is not current".to_owned(),
            ));
        }
        let sandbox_id: [u8; 16] = execution.sandbox_id.as_slice().try_into().map_err(|_| {
            EffectFailure::Permanent("execution sandbox identity is invalid".to_owned())
        })?;
        let sandbox = SandboxId::from_bytes(sandbox_id);
        let current = AuthorityPublicationStore::new(journal)
            .current(sandbox)
            .map_err(retryable)?
            .ok_or_else(|| {
                EffectFailure::Retryable("current execution authority is absent".to_owned())
            })?;
        let manifest = current.manifest();
        let assignment = manifest.broker_assignment().map_err(retryable)?;
        let lease_assignment = current.lease().lease().assignment();
        if manifest.manifest().project() != project
            || manifest.manifest().node() != node
            || execution.sandbox_incarnation_id.as_slice()
                != manifest.manifest().incarnation().as_bytes()
            || execution.assignment_epoch != manifest.manifest().epoch().get()
            || lease_assignment.sandbox() != assignment.sandbox()
            || lease_assignment.incarnation() != assignment.incarnation()
            || lease_assignment.epoch() != assignment.epoch()
            || lease_assignment.digest() != assignment.digest()
            || current.lease().lease().node() != node
        {
            return Err(EffectFailure::Retryable(
                "execution assignment is not current".to_owned(),
            ));
        }
        if let Some(specification) = &self.specification {
            if encode_execution_spec_v1(specification).len() > MAXIMUM_HOST_EXECUTION_SPEC_BYTES {
                return Err(EffectFailure::Retryable(
                    "execution specification exceeds the sealed Host content ceiling".to_owned(),
                ));
            }
            let target = specification.target();
            if target.sandbox() != manifest.manifest().sandbox()
                || target.incarnation() != manifest.manifest().incarnation()
                || target.assignment_epoch() != manifest.manifest().epoch()
                || target.assignment_digest() != manifest.digest()
                || target.namespace_generation() != manifest.manifest().namespace_generation()
                || specification.environment_descriptor() != manifest.manifest().environment()
                || specification.resources().parent_profile_commitment()
                    != manifest.manifest().resource_commitment()
                || specification.resources().output_bytes().assignment() != manifest
                || specification.execution().as_bytes() != &self.execution_id
            {
                return Err(EffectFailure::Retryable(
                    "execution specification is stale for current assignment".to_owned(),
                ));
            }
        }

        let semantics = match kind {
            ExecutionAuthorizationKindV1::Apply => host_execution_apply_grant_v1(
                assignment,
                *self.operation_id.as_bytes(),
                ExecutionId::from_bytes(self.execution_id),
                ObjectDigest::from_bytes(self.source_operation_commitment),
                self.action.effect_operation(),
                self.specification.as_ref(),
            ),
            ExecutionAuthorizationKindV1::Query => {
                let content = self.descriptor_content()?;
                host_execution_query_content_grant_v1(
                    assignment,
                    *self.operation_id.as_bytes(),
                    ExecutionId::from_bytes(self.execution_id),
                    ObjectDigest::from_bytes(self.source_operation_commitment),
                    HostExecutionSpecContentFieldsV1::for_grant(&content),
                )
            }
        }
        .map_err(retryable)?;
        let template = current
            .templates()
            .iter()
            .find(|candidate| candidate.audience() == BrokerAudience::Host)
            .ok_or_else(|| {
                EffectFailure::Retryable("current Host authority template is absent".to_owned())
            })?;
        let parent = template.plan();
        if parent.assignment() != assignment || parent.node() != node {
            return Err(EffectFailure::Retryable(
                "current Host template differs from execution assignment".to_owned(),
            ));
        }
        let now = crate::controller_ownership::sample_ownership_clock()
            .map_err(retryable)?
            .wall_seconds();
        let expires = now
            .checked_add(30)
            .map(|limit| {
                limit
                    .min(parent.expires_seconds())
                    .min(current.lease().lease().authority_expires_seconds())
            })
            .ok_or_else(|| EffectFailure::Retryable("execution clock overflowed".to_owned()))?;
        if now < parent.issued_seconds() || expires <= now {
            return Err(EffectFailure::Retryable(
                "current Host authority is outside its validity interval".to_owned(),
            ));
        }
        let grant = BrokerGrant::new(
            semantics.verb(),
            semantics.target(),
            semantics.commitment(),
            64 * 1024,
            0,
        )
        .map_err(retryable)?;
        let plan = BrokerAuthorizationPlan::new(
            BrokerAudience::Host,
            ProtocolId::HostBroker,
            ProtocolVersion::new(1, 0),
            assignment,
            node,
            parent.ownership_authority().clone(),
            vec![grant],
            parent.policy_commitment(),
            parent.revocation_scope(),
            now,
            expires,
            Vec::new(),
        )
        .map_err(retryable)?;
        let signed = signer.sign_plan(plan, now).map_err(retryable)?;
        Ok(BrokerAuthorizationArtifactsV1 {
            broker_plan: signed.canonical_plan().to_vec(),
            broker_plan_signature: signed.canonical_signature().to_vec(),
            ownership_lease: current.lease().canonical_lease().to_vec(),
            ownership_lease_signature: current.lease().canonical_signature().to_vec(),
            ..Default::default()
        })
    }

    fn envelope(
        &self,
        kind: ExecutionAuthorizationKindV1,
        coordinates: DormantBrokerRequestCoordinatesV1,
        authorization: &BrokerAuthorizationArtifactsV1,
        stable_content: HostExecutionSpecContentFieldsV1,
    ) -> BrokerRequestEnvelope {
        let header = RequestHeader {
            protocol_major: u32::from(coordinates.protocol_version().major()),
            protocol_minor: u32::from(coordinates.protocol_version().minor()),
            request_id: coordinates.request_id().to_vec(),
            audience: coordinates.audience().into(),
            deadline_boottime_nanoseconds: coordinates.deadline_boottime_nanoseconds(),
            maximum_response_bytes: coordinates.maximum_response_bytes(),
            ..Default::default()
        };
        let body = match kind {
            ExecutionAuthorizationKindV1::Apply => {
                let (action, terminal_rows, terminal_columns, signal_number) =
                    self.action.wire_fields();
                let content = stable_content.bind_attempt(
                    coordinates.request_id(),
                    *self.operation_id.as_bytes(),
                    ExecutionId::from_bytes(self.execution_id),
                    ObjectDigest::from_bytes(self.source_operation_commitment),
                    self.action.effect_operation(),
                );
                let request = ApplyHostExecutionRequestV1 {
                    header: Some(header).into(),
                    operation_id: self.operation_id.as_bytes().to_vec(),
                    execution_id: self.execution_id.to_vec(),
                    action: action.into(),
                    source_operation_commitment: self.source_operation_commitment.to_vec(),
                    terminal_rows,
                    terminal_columns,
                    signal_number,
                    spec_transfer_version: 1,
                    spec_content_bytes: content.bytes(),
                    spec_content_digest: content.digest().to_vec(),
                    spec_attempt_commitment: content.attempt_commitment().to_vec(),
                    ..Default::default()
                };
                request.encode_to_vec()
            }
            ExecutionAuthorizationKindV1::Query => {
                let content = stable_content.bind_query_attempt(
                    coordinates.request_id(),
                    *self.operation_id.as_bytes(),
                    ExecutionId::from_bytes(self.execution_id),
                    ObjectDigest::from_bytes(self.source_operation_commitment),
                );
                let request = QueryHostExecutionRequestV1 {
                    header: Some(header).into(),
                    operation_id: self.operation_id.as_bytes().to_vec(),
                    execution_id: self.execution_id.to_vec(),
                    source_operation_commitment: self.source_operation_commitment.to_vec(),
                    spec_content_bytes: content.bytes(),
                    spec_content_digest: content.digest().to_vec(),
                    spec_transfer_version: 1,
                    spec_attempt_commitment: content.attempt_commitment().to_vec(),
                    ..Default::default()
                };
                request.encode_to_vec()
            }
        };
        BrokerRequestEnvelope {
            method: kind.broker_method().into(),
            body,
            descriptors: if kind == ExecutionAuthorizationKindV1::Apply {
                vec![BrokerDescriptorEntry {
                    index: 0,
                    role: BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_HOST_EXECUTION_SPEC.into(),
                    ..Default::default()
                }]
            } else {
                Vec::new()
            },
            authorization: Some(authorization.clone()).into(),
            ..Default::default()
        }
    }
}

fn retryable(error: impl ToString) -> EffectFailure {
    EffectFailure::Retryable(error.to_string())
}

struct ExecutionExchangeContextV1 {
    intent: ControllerExecutionIntentV1,
    kind: ExecutionAuthorizationKindV1,
}

/// Retains the exact signed Host request across transport and commit ambiguity.
#[derive(Default)]
pub(crate) struct ControllerExecutionExchangeV1 {
    exchange: RetainedBrokerExchangeV1<ExecutionExchangeContextV1>,
}

impl ControllerExecutionExchangeV1 {
    pub(crate) const fn has_pending(&self) -> bool {
        self.exchange.has_pending()
    }

    pub(crate) const fn needs_fresh_authorization(&self) -> bool {
        !self.exchange.has_request() && !self.exchange.requires_reconnect()
    }

    pub(crate) const fn requires_reconnect(&self) -> bool {
        self.exchange.requires_reconnect()
    }

    pub(crate) fn query(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        intent: &ControllerExecutionIntentV1,
        authorization: Option<&BrokerAuthorizationArtifactsV1>,
    ) -> Result<ControllerExecutionObservationV1, EffectFailure> {
        let outcome = self.exchange(
            session,
            intent,
            ExecutionAuthorizationKindV1::Query,
            authorization,
        )?;
        let result = classify_outcome(intent, ExecutionAuthorizationKindV1::Query, &outcome);
        if matches!(&result, Err(EffectFailure::Permanent(_))) {
            self.exchange.mark_failed();
        }
        result
    }

    pub(crate) fn apply(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        intent: &ControllerExecutionIntentV1,
        authorization: Option<&BrokerAuthorizationArtifactsV1>,
    ) -> Result<ControllerExecutionCompletionV1, EffectFailure> {
        let outcome = self.exchange(
            session,
            intent,
            ExecutionAuthorizationKindV1::Apply,
            authorization,
        )?;
        let result = classify_outcome(intent, ExecutionAuthorizationKindV1::Apply, &outcome);
        if matches!(&result, Err(EffectFailure::Permanent(_))) {
            self.exchange.mark_failed();
        }
        match result? {
            ControllerExecutionObservationV1::Applied(completion) => Ok(completion),
            ControllerExecutionObservationV1::Absent => Err(EffectFailure::Retryable(
                "Host execution effect has not completed".to_owned(),
            )),
        }
    }

    fn exchange(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        intent: &ControllerExecutionIntentV1,
        kind: ExecutionAuthorizationKindV1,
        authorization: Option<&BrokerAuthorizationArtifactsV1>,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, EffectFailure> {
        // A canonical spec exists, but no cross-owner physical Storage and
        // live Host effect handoff proves its admission at this boundary.
        // An in-memory specification cannot substitute for that custody.
        if intent.action == ControllerExecutionActionV1::Authorize {
            return Err(EffectFailure::Retryable(
                "execution authorization requires protected cross-owner handoff".to_owned(),
            ));
        }
        if self.requires_reconnect() {
            return Err(EffectFailure::Retryable(SESSION_UNUSABLE.to_owned()));
        }
        if self
            .exchange
            .context()
            .is_some_and(|pending| pending.intent != *intent || pending.kind != kind)
        {
            return Err(EffectFailure::Retryable(
                "another exact execution exchange retains Host session custody".to_owned(),
            ));
        }
        if self.exchange.context().is_none() {
            let authorization = authorization.ok_or_else(|| {
                EffectFailure::Retryable(
                    "current Host execution authorization is unavailable".to_owned(),
                )
            })?;
            let context = ExecutionExchangeContextV1 {
                intent: intent.clone(),
                kind,
            };
            let content = intent.descriptor_content()?;
            let stable_content = HostExecutionSpecContentFieldsV1::for_grant(&content);
            if kind == ExecutionAuthorizationKindV1::Apply {
                let credential = SealedReadOnlyCredential::create(
                    "aos-host-execution-spec",
                    &content,
                    MAXIMUM_HOST_EXECUTION_SPEC_BYTES,
                )
                .map_err(retryable)?;
                let descriptor = rustix::io::dup(credential.as_fd()).map_err(retryable)?;
                let preparation = session
                    .prepare_authenticated_descriptor_request(
                        kind.broker_method(),
                        vec![descriptor],
                        |coordinates| {
                            intent.envelope(kind, coordinates, authorization, stable_content)
                        },
                    )
                    .map_err(|_| {
                        self.exchange.mark_failed();
                        EffectFailure::Retryable(
                            "execution descriptor could not enter protected Host session custody"
                                .to_owned(),
                        )
                    })?;
                self.exchange.start_descriptor(context, preparation);
            } else {
                let preparation = session
                    .prepare_authenticated_request(kind.broker_method(), |coordinates| {
                        intent.envelope(kind, coordinates, authorization, stable_content)
                    })
                    .map_err(|_| {
                        self.exchange.mark_failed();
                        EffectFailure::Retryable(
                            "execution request could not enter protected Host session custody"
                                .to_owned(),
                        )
                    })?;
                self.exchange.start(context, preparation);
            }
        }
        self.exchange
            .drive(session, &ERRORS)
            .map(|(_, outcome)| outcome)
    }
}

#[cfg(test)]
mod tests {
    use aos_sandbox::JournalLimits;

    use super::*;

    #[test]
    fn authorization_acknowledgment_cannot_publish_running() {
        for phase in [
            BackendExecutionPhaseV1::Authorized,
            BackendExecutionPhaseV1::Starting,
            BackendExecutionPhaseV1::Running,
        ] {
            assert_eq!(
                authorization_acknowledgment_phase(phase).unwrap(),
                BackendExecutionPhaseV1::Authorized
            );
        }
        for phase in [
            BackendExecutionPhaseV1::Exited,
            BackendExecutionPhaseV1::Canceled,
            BackendExecutionPhaseV1::Failed,
            BackendExecutionPhaseV1::Lost,
        ] {
            assert!(authorization_acknowledgment_phase(phase).is_err());
        }

        let receipt = EffectReceipt::new(vec![1]).unwrap();
        let completion = ControllerExecutionCompletionV1 {
            receipt,
            phase: BackendExecutionPhaseV1::Authorized,
            observation_sequence: 1,
            terminal: None,
        };
        assert!(matches!(
            completion.public_phase(),
            Err(EffectFailure::Retryable(_))
        ));
        assert!(!completion.is_terminal());

        let canceled = ControllerExecutionCompletionV1 {
            receipt: EffectReceipt::new(vec![2]).unwrap(),
            phase: BackendExecutionPhaseV1::Canceled,
            observation_sequence: 2,
            terminal: Some(HostExecutionTerminalResultV1::Canceled),
        };
        assert!(matches!(
            canceled.public_phase(),
            Err(EffectFailure::Retryable(_))
        ));

        let exited = ControllerExecutionCompletionV1 {
            receipt: EffectReceipt::new(vec![3]).unwrap(),
            phase: BackendExecutionPhaseV1::Exited,
            observation_sequence: 3,
            terminal: Some(HostExecutionTerminalResultV1::Exited(0)),
        };
        assert!(matches!(
            exited.public_phase(),
            Err(EffectFailure::Retryable(_))
        ));
        let missing_result = ControllerExecutionCompletionV1 {
            terminal: None,
            ..exited
        };
        assert!(matches!(
            missing_result.public_phase(),
            Err(EffectFailure::Retryable(_))
        ));

        let operation_id = OperationId::from_bytes([1; 16]);
        let intent = ControllerExecutionIntentV1 {
            operation_id,
            projection_operation_id: operation_id,
            execution_id: [2; 16],
            action: ControllerExecutionActionV1::Authorize,
            specification: None,
            observation_specification_digest: None,
            source_operation_commitment: [3; 32],
        };
        let directory = tempfile::tempdir().unwrap();
        let (mut journal, _) = Journal::open(
            directory.path().join("controller.journal"),
            JournalLimits::default(),
        )
        .unwrap();
        let error = intent
            .commit_control_projection(ProjectId::from_bytes([4; 16]), &mut journal, &completion)
            .unwrap_err();
        assert!(matches!(
            error,
            EffectFailure::Retryable(message) if message == "execution authorization cannot publish a public phase"
        ));
    }
}

fn authorization_acknowledgment_phase(
    observed_phase: BackendExecutionPhaseV1,
) -> Result<BackendExecutionPhaseV1, EffectFailure> {
    if !matches!(
        observed_phase,
        BackendExecutionPhaseV1::Authorized
            | BackendExecutionPhaseV1::Starting
            | BackendExecutionPhaseV1::Running
    ) {
        return Err(EffectFailure::Permanent(
            "Host authorization cannot settle a terminal execution".to_owned(),
        ));
    }
    // Authorization is an effect acknowledgment, not a public observation.
    Ok(BackendExecutionPhaseV1::Authorized)
}

fn classify_outcome(
    intent: &ControllerExecutionIntentV1,
    kind: ExecutionAuthorizationKindV1,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<ControllerExecutionObservationV1, EffectFailure> {
    if outcome.method() != kind.broker_method() || !request_matches_intent(intent, kind, outcome) {
        return Err(EffectFailure::Permanent(
            "Host execution outcome has the wrong signed request".to_owned(),
        ));
    }
    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
        return Err(EffectFailure::Retryable(
            "Host execution method is unavailable or rejected".to_owned(),
        ));
    };
    let body = decode_host_execution_outcome_v1(
        exact_body,
        *intent.operation_id.as_bytes(),
        ExecutionId::from_bytes(intent.execution_id),
        ObjectDigest::from_bytes(intent.source_operation_commitment),
    )
    .map_err(|_| {
        EffectFailure::Permanent("signed Host execution outcome is malformed".to_owned())
    })?;
    match body.phase.as_known() {
        Some(HostExecutionPhaseV1::HOST_EXECUTION_PHASE_COMPLETE) => {
            let effect_commitment: [u8; 32] =
                body.effect_commitment.as_slice().try_into().map_err(|_| {
                    EffectFailure::Permanent(
                        "Host execution effect commitment is invalid".to_owned(),
                    )
                })?;
            let completion_digest: [u8; 32] =
                body.completion_digest.as_slice().try_into().map_err(|_| {
                    EffectFailure::Permanent(
                        "Host execution completion digest is invalid".to_owned(),
                    )
                })?;
            if effect_commitment == [0; 32]
                || completion_digest == [0; 32]
                || body.completion_bytes.is_empty()
            {
                return Err(EffectFailure::Permanent(
                    "Host execution completion is incomplete".to_owned(),
                ));
            }
            if body.observation_sequence == 0 {
                return Err(EffectFailure::Permanent(
                    "Host execution completion has no observation sequence".to_owned(),
                ));
            }
            match body.completion_status.as_known() {
                Some(HostExecutionCompletionStatusV1::HOST_EXECUTION_COMPLETION_STATUS_SUCCEEDED) => {}
                Some(
                    HostExecutionCompletionStatusV1::HOST_EXECUTION_COMPLETION_STATUS_REJECTED_BEFORE_EFFECT
                    | HostExecutionCompletionStatusV1::HOST_EXECUTION_COMPLETION_STATUS_FAILED_PERMANENT,
                ) => {
                    return Err(EffectFailure::Permanent(
                        "Host execution effect completed without success".to_owned(),
                    ));
                }
                _ => {
                    return Err(EffectFailure::Permanent(
                        "Host execution completion status is invalid".to_owned(),
                    ));
                }
            }
            let (phase, terminal) = if intent.action == ControllerExecutionActionV1::Observe {
                let specification_digest =
                    intent.observation_specification_digest.ok_or_else(|| {
                        EffectFailure::Permanent(
                            "Host Observe has no retained specification binding".to_owned(),
                        )
                    })?;
                let phase = decode_observe_completion_phase_v1(
                    &body.completion_bytes,
                    *intent.operation_id.as_bytes(),
                    intent.source_operation_commitment,
                    intent.execution_id,
                    specification_digest,
                    body.observation_sequence,
                )
                .map_err(|error| match error {
                    RuntimeExecutionEvidenceError::PhaseMismatch => EffectFailure::Retryable(
                        "Host Observe has not established an observable execution phase".to_owned(),
                    ),
                    _ => EffectFailure::Permanent(
                        "Host Observe completion evidence is invalid".to_owned(),
                    ),
                })?;
                let terminal = match phase {
                    BackendExecutionPhaseV1::Running => None,
                    BackendExecutionPhaseV1::Exited | BackendExecutionPhaseV1::Canceled => {
                        let terminal =
                            decode_host_execution_terminal_result_v1(&body.terminal_guest_result)
                                .map_err(|_| {
                                EffectFailure::Permanent(
                                    "Host terminal Observe lacks an exact Guest result".to_owned(),
                                )
                            })?;
                        if !matches!(
                            (phase, terminal),
                            (
                                BackendExecutionPhaseV1::Exited,
                                HostExecutionTerminalResultV1::Exited(_)
                            ) | (
                                BackendExecutionPhaseV1::Canceled,
                                HostExecutionTerminalResultV1::Canceled
                            )
                        ) {
                            return Err(EffectFailure::Permanent(
                                "Host terminal Observe phase differs from Guest result".to_owned(),
                            ));
                        }
                        Some(terminal)
                    }
                    _ => {
                        return Err(EffectFailure::Retryable(
                            "Host Observe has no publishable execution result".to_owned(),
                        ));
                    }
                };
                (phase, terminal)
            } else if let Some(specification) = &intent.specification {
                let observed_phase = decode_authorize_completion_binding_v1(
                    &body.completion_bytes,
                    *intent.operation_id.as_bytes(),
                    intent.source_operation_commitment,
                    intent.execution_id,
                    execution_spec_digest_v1(specification),
                    body.observation_sequence,
                )
                .map_err(|_| {
                    EffectFailure::Permanent(
                        "Host authorization completion evidence is invalid".to_owned(),
                    )
                })?;
                (authorization_acknowledgment_phase(observed_phase)?, None)
            } else {
                let phase = decode_control_completion_phase_v1(
                    &body.completion_bytes,
                    intent.action.effect_operation(),
                    *intent.operation_id.as_bytes(),
                    intent.source_operation_commitment,
                    intent.execution_id,
                    body.observation_sequence,
                )
                .map_err(|_| {
                    EffectFailure::Permanent(
                        "Host control completion evidence is invalid".to_owned(),
                    )
                })?;
                (phase, None)
            };
            if intent.action == ControllerExecutionActionV1::Cancel
                && phase != BackendExecutionPhaseV1::Canceled
            {
                return Err(EffectFailure::Permanent(
                    "execution exited before cancellation was observed".to_owned(),
                ));
            }
            let mut receipt_hash = Sha256::new()
                .chain_update(EXECUTION_RECEIPT_DOMAIN)
                .chain_update(intent.operation_id.as_bytes())
                .chain_update(intent.execution_id)
                .chain_update(intent.source_operation_commitment)
                .chain_update(effect_commitment)
                .chain_update(completion_digest)
                .chain_update(body.observation_sequence.to_be_bytes())
                .chain_update(&body.completion_bytes);
            if terminal.is_some() {
                receipt_hash.update((body.terminal_guest_result.len() as u64).to_be_bytes());
                receipt_hash.update(&body.terminal_guest_result);
            }
            let digest: [u8; 32] = receipt_hash.finalize().into();
            let receipt = EffectReceipt::new([b"AOSEXE01".as_slice(), digest.as_slice()].concat())
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            Ok(ControllerExecutionObservationV1::Applied(
                ControllerExecutionCompletionV1 {
                    receipt,
                    phase,
                    observation_sequence: body.observation_sequence,
                    terminal,
                },
            ))
        }
        Some(HostExecutionPhaseV1::HOST_EXECUTION_PHASE_ABSENT)
            if kind == ExecutionAuthorizationKindV1::Query =>
        {
            Ok(ControllerExecutionObservationV1::Absent)
        }
        Some(
            HostExecutionPhaseV1::HOST_EXECUTION_PHASE_PENDING
            | HostExecutionPhaseV1::HOST_EXECUTION_PHASE_ISSUED
            | HostExecutionPhaseV1::HOST_EXECUTION_PHASE_INDETERMINATE,
        ) => Err(EffectFailure::Retryable(
            "Host execution effect is pending exact recovery".to_owned(),
        )),
        _ => Err(EffectFailure::Permanent(
            "signed Host execution outcome has an invalid phase".to_owned(),
        )),
    }
}

fn request_matches_intent(
    intent: &ControllerExecutionIntentV1,
    kind: ExecutionAuthorizationKindV1,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> bool {
    let exact_body = outcome.request().exact_body();
    match kind {
        ExecutionAuthorizationKindV1::Apply => {
            let Ok(request) = ApplyHostExecutionRequestV1::decode_from_slice(exact_body) else {
                return false;
            };
            let Some(request_id) = request
                .header
                .as_option()
                .and_then(|header| header.request_id.as_slice().try_into().ok())
            else {
                return false;
            };
            let Ok(content) = intent.descriptor_content() else {
                return false;
            };
            let fields = HostExecutionSpecContentFieldsV1::for_grant(&content).bind_attempt(
                request_id,
                *intent.operation_id.as_bytes(),
                ExecutionId::from_bytes(intent.execution_id),
                ObjectDigest::from_bytes(intent.source_operation_commitment),
                intent.action.effect_operation(),
            );
            let (action, rows, columns, signal_number) = intent.action.wire_fields();
            request.encode_to_vec() == exact_body
                && request.operation_id == intent.operation_id.as_bytes()
                && request.execution_id == intent.execution_id
                && request.source_operation_commitment == intent.source_operation_commitment
                && request.canonical_execution_spec.is_empty()
                && request.spec_transfer_version == 1
                && request.spec_content_bytes == fields.bytes()
                && request.spec_content_digest == fields.digest().to_vec()
                && request.spec_attempt_commitment == fields.attempt_commitment().to_vec()
                && request.action.as_known() == Some(action)
                && request.terminal_rows == rows
                && request.terminal_columns == columns
                && request.signal_number == signal_number
        }
        ExecutionAuthorizationKindV1::Query => {
            let Ok(request) = QueryHostExecutionRequestV1::decode_from_slice(exact_body) else {
                return false;
            };
            let Some(request_id) = request
                .header
                .as_option()
                .and_then(|header| header.request_id.as_slice().try_into().ok())
            else {
                return false;
            };
            let Ok(content) = intent.descriptor_content() else {
                return false;
            };
            let fields = HostExecutionSpecContentFieldsV1::for_grant(&content).bind_query_attempt(
                request_id,
                *intent.operation_id.as_bytes(),
                ExecutionId::from_bytes(intent.execution_id),
                ObjectDigest::from_bytes(intent.source_operation_commitment),
            );
            request.encode_to_vec() == exact_body
                && request.operation_id == intent.operation_id.as_bytes()
                && request.execution_id == intent.execution_id
                && request.source_operation_commitment == intent.source_operation_commitment
                && request.spec_content_bytes == fields.bytes()
                && request.spec_content_digest == fields.digest().to_vec()
                && request.spec_transfer_version == 1
                && request.spec_attempt_commitment == fields.attempt_commitment().to_vec()
        }
    }
}
