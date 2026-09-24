//! Protected-current construction and durable admission of execution specs.
//!
//! The producer joins distinct exclusive controller, environment, and runtime
//! owners while all three are held. Its admitted spec is immutable custody,
//! not Host effect authority or physical output-storage admission. Detached
//! capture can be specified only with two independently retained ceilings;
//! no captured byte may be written until physical Storage admission joins it.

use aos_proto::aos::sandbox::v1::{Command, ExecutionIoMode, ExecutionPhase};
use aos_sandbox_core::model::spec::{LimitDimension, LimitValue, ResourceProfile};
use aos_sandbox_core::runtime_backend::{
    AdmissionCommitError, AdmissionIdempotencyV1, BackendOperationIdV1, ExecutionAdmissionDraftV1,
    ExecutionAdmissionOutcomeV1, admit_execution,
};
use aos_sandbox_core::{
    AuditId, ExecutionAccessRouteV1, ExecutionCommandV1, ExecutionCredentialsV1,
    ExecutionDisconnectPolicyV1, ExecutionEndpointCapabilityV1, ExecutionEnvironmentEntry,
    ExecutionId, ExecutionIoV1, ExecutionOutputModeV1, ExecutionPublicKeyV1,
    ExecutionResourceAdmissionV1, ExecutionResourceRequestV1, ExecutionResourceRequestValueV1,
    ExecutionResourceSublimitV1, ExecutionResourceSublimitValueV1, ExecutionSpecV1,
    ExecutionTerminalModeV1, ExecutionTimeoutV1, InvalidExecutionSpec, ObjectDigest, OperationId,
    PathName, PrincipalId, RawPairedClockSample, RelativePath, encode_execution_spec_v1,
    execution_spec_digest_v1,
};
use aos_sandbox_protocol::host_execution::MAXIMUM_HOST_EXECUTION_SPEC_BYTES;
use sha2::{Digest as _, Sha256};
use ssh_key::PublicKey;

use super::{
    AuthenticatedRuntimeArgumentReadbackV1, DormantRuntimeExecutionClaimV1,
    DormantRuntimeExecutionOwnerErrorV1, ExecutionJournalRecoveryTokenV1,
};
use crate::Journal;
use crate::cli_model::DormantSandboxRequestKindV1;
use crate::controller_execution_argument_receipt::{
    AuthenticatedControllerHostArgumentObservationV1, ControllerExecutionArgumentReceiptErrorV1,
    revalidate_current_controller_host_argument_observation_v1,
};
use crate::controller_execution_output_settlement::{
    ControllerExecutionOutputSettlementErrorV1, read_current_controller_output_settlement_v1,
};
use crate::controller_service::public_projection::{
    PublicProjectionError, PublicProjectionKindV1, PublicProjectionResourceV1,
    PublicProjectionStoreV1,
};
use crate::create_holder_proof::{self, CreateHolderProofErrorV1};
use crate::environment::{
    EnvironmentExecutionErrorV1, EnvironmentExecutionSourceV1, EnvironmentProtectedJournalOwnerV1,
};
use crate::execution_guest_identity::{
    ExecutionGuestIdentityReadbackErrorV1, read_execution_guest_identity_v1,
};
use crate::execution_output_reservation::{
    DurableExecutionOutputReservationV1, ExecutionOutputReservationErrorV1, accepted_claim,
};
use crate::execution_parent_resource::{
    ExecutionParentResourceSourceErrorV1, ExecutionParentResourceSourceV1,
    revalidate_execution_parent_resource_from_journal_v1,
};
use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::reconciler::{ReconcilerError, accepted_create_execution_effect_from_journal_v1};
use crate::runtime_scope::{CurrentAssignmentTarget, CurrentRuntimeScopeError};
use crate::sandbox_spec_state::{self, SandboxSpecStateError};

/// Reports a missing or stale independent execution-specification input.
#[derive(Debug, thiserror::Error)]
pub enum ProtectedExecutionSpecProducerErrorV1 {
    /// The accepted request, projection, or exact signed assignment disagrees.
    #[error("accepted execution request or assignment is unavailable")]
    NotCurrent,
    /// The v1 spec cannot preserve this command's complete public semantics.
    #[error("execution command cannot be represented without losing semantics")]
    UnsupportedCommand,
    /// A finite execution child limit or policy-selected weight is unavailable.
    #[error("parent profile does not justify all execution child limits")]
    MissingSublimit,
    /// The protected current assignment or lease could not be rechecked.
    #[error(transparent)]
    Assignment(#[from] CurrentRuntimeScopeError),
    /// The accepted operation could not be replayed.
    #[error(transparent)]
    Operation(#[from] ReconcilerError),
    /// The accepted execution projection could not be replayed.
    #[error(transparent)]
    Projection(#[from] PublicProjectionError),
    /// The signed holder proof was invalid.
    #[error(transparent)]
    Holder(#[from] CreateHolderProofErrorV1),
    /// The current parent resource source changed.
    #[error(transparent)]
    Parent(#[from] ExecutionParentResourceSourceErrorV1),
    /// The environment lease, activation, or canonical bytes changed.
    #[error(transparent)]
    Environment(#[from] EnvironmentExecutionErrorV1),
    /// The retained explicit guest credential policy was unavailable.
    #[error(transparent)]
    GuestIdentity(#[from] ExecutionGuestIdentityReadbackErrorV1),
    /// The retained sandbox specification was unavailable.
    #[error(transparent)]
    SandboxSpec(#[from] SandboxSpecStateError),
    /// The fixed runtime owner, output claim, or fresh argument proof changed.
    #[error(transparent)]
    Runtime(#[from] DormantRuntimeExecutionOwnerErrorV1),
    /// The authenticated original Host output reservation is absent or stale.
    #[error(transparent)]
    HostOutput(#[from] ControllerExecutionOutputSettlementErrorV1),
    /// The signed Host argument receipt is missing or changed.
    #[error(transparent)]
    HostArgument(#[from] ControllerExecutionArgumentReceiptErrorV1),
    /// The accepted output claim cannot be reconstructed from current Create.
    #[error(transparent)]
    OutputClaim(#[from] ExecutionOutputReservationErrorV1),
    /// A canonical specification field or derived envelope is invalid.
    #[error(transparent)]
    Specification(#[from] InvalidExecutionSpec),
    /// The protected execution admission failed or requires recovery.
    #[error(transparent)]
    Admission(#[from] AdmissionCommitError),
}

/// Holds canonical execution bytes derived from current Controller sources.
///
/// This preview has no durable spec custody, physical Storage admission, or
/// Host effect authority. A future producer must revalidate every owner under
/// a held cross-process cut before appending the immutable specification.
pub struct ControllerExecutionSpecPreviewV1 {
    specification: ExecutionSpecV1,
    canonical_bytes: Vec<u8>,
    digest: ObjectDigest,
    accepted_request_digest: ObjectDigest,
    output_claim_digest: ObjectDigest,
    output_settlement_digest: ObjectDigest,
    argument_receipt_digest: ObjectDigest,
    source_heads: ControllerExecutionSpecSourceHeadsV1,
}

/// Records the independent protected heads observed while deriving one spec.
///
/// These values identify a Controller source cut for later audit. They do not
/// prove a Host/Storage cross-owner hold or confer effect authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerExecutionSpecSourceHeadsV1 {
    pub(crate) assignment_digest: ObjectDigest,
    pub(crate) assignment_epoch: u64,
    pub(crate) parent_binding: ObjectDigest,
    pub(crate) parent_projection: ObjectDigest,
    pub(crate) sandbox_spec_record: ObjectDigest,
    pub(crate) environment_activation: ObjectDigest,
    pub(crate) environment_manifest: ObjectDigest,
    pub(crate) environment_generation: u64,
    pub(crate) output_claim: ObjectDigest,
    pub(crate) output_settlement: ObjectDigest,
    pub(crate) argument_receipt: ObjectDigest,
    pub(crate) host_argument_custody: ObjectDigest,
    pub(crate) host_argument_sequence: u64,
}

impl ControllerExecutionSpecPreviewV1 {
    /// Borrows the complete canonical specification model.
    #[must_use]
    pub const fn specification(&self) -> &ExecutionSpecV1 {
        &self.specification
    }

    /// Borrows exact canonical bytes for a future sealed descriptor transfer.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the canonical execution-specification commitment.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    /// Returns the accepted Create request commitment.
    #[must_use]
    pub const fn accepted_request_digest(&self) -> ObjectDigest {
        self.accepted_request_digest
    }

    /// Returns the exact AOSEOR02 output claim commitment.
    #[must_use]
    pub const fn output_claim_digest(&self) -> ObjectDigest {
        self.output_claim_digest
    }

    /// Returns the Controller's protected AOSCIS01 settlement commitment.
    #[must_use]
    pub const fn output_settlement_digest(&self) -> ObjectDigest {
        self.output_settlement_digest
    }

    /// Returns the Controller's protected AOSCAF01 receipt commitment.
    #[must_use]
    pub const fn argument_receipt_digest(&self) -> ObjectDigest {
        self.argument_receipt_digest
    }

    /// Returns the independent source heads selected for this preview.
    #[must_use]
    pub const fn source_heads(&self) -> ControllerExecutionSpecSourceHeadsV1 {
        self.source_heads
    }
}

/// Joins protected Create, environment, policy, and live runtime evidence.
///
/// Stream and PTY requests always retain an explicit zero-byte output claim.
/// Detached capture retains the two exact, versioned public stream ceilings
/// whose checked sum equals its aggregate claim.
/// This function never issues a Host descriptor or effect grant. Ambiguous
/// admission returns the runtime store's opaque recovery token unchanged.
///
/// # Errors
///
/// Returns an error when any protected owner, current assignment, exact public
/// request, guest policy, resource sublimit, or fresh signed readback fails.
/// Admission errors include unresolved or ambiguous protected durability.
#[allow(clippy::too_many_arguments)]
pub fn admit_accepted_execution_spec_v1<T>(
    claim: &mut DormantRuntimeExecutionClaimV1<'_>,
    controller: &mut Journal,
    assignment: &CurrentAssignmentTarget,
    environment_owner: &mut EnvironmentProtectedJournalOwnerV1<'_, '_>,
    parent: &ExecutionParentResourceSourceV1,
    argument_readback: &AuthenticatedRuntimeArgumentReadbackV1,
    execution: ExecutionId,
    create_operation: OperationId,
    clock: &mut T,
) -> Result<
    ExecutionAdmissionOutcomeV1<ExecutionJournalRecoveryTokenV1>,
    ProtectedExecutionSpecProducerErrorV1,
>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    assignment.recheck(controller, clock)?;
    revalidate_execution_parent_resource_from_journal_v1(controller, parent)?;
    if assignment.binding().manifest() != parent.assignment()
        || argument_readback.execution() != execution
        || argument_readback.create_operation() != create_operation
    {
        return Err(ProtectedExecutionSpecProducerErrorV1::NotCurrent);
    }

    let source = read_controller_spec_inputs(
        controller,
        environment_owner,
        parent,
        execution,
        create_operation,
    )?;
    let output =
        claim.read_protected_accepted_output_v2(controller, create_operation, execution, parent)?;
    let host_output = read_current_controller_output_settlement_v1(
        controller,
        assignment,
        execution,
        create_operation,
        clock,
    )?
    .ok_or(ProtectedExecutionSpecProducerErrorV1::NotCurrent)?;
    if host_output.claim_digest() != output.reservation().record_digest() {
        return Err(ProtectedExecutionSpecProducerErrorV1::NotCurrent);
    }
    claim.revalidate_fresh_runtime_argument_readback_v1(argument_readback)?;
    let specification = build_specification(
        &source,
        parent,
        output.reservation(),
        argument_readback.evidence(),
        execution,
        create_operation,
    )?;
    read_execution_guest_identity_v1(controller, assignment, &specification)?;

    // Every independent owner remains exclusively held through this final
    // readback and the immutable spec admission append below.
    environment_owner.revalidate_execution_source(&source.environment)?;
    assignment.recheck(controller, clock)?;
    revalidate_execution_parent_resource_from_journal_v1(controller, parent)?;
    let current_output =
        claim.read_protected_accepted_output_v2(controller, create_operation, execution, parent)?;
    claim.revalidate_fresh_runtime_argument_readback_v1(argument_readback)?;
    if current_output.reservation() != output.reservation()
        || current_output.currentness() != output.currentness()
    {
        return Err(ProtectedExecutionSpecProducerErrorV1::NotCurrent);
    }
    let current_host_output = read_current_controller_output_settlement_v1(
        controller,
        assignment,
        execution,
        create_operation,
        clock,
    )?
    .ok_or(ProtectedExecutionSpecProducerErrorV1::NotCurrent)?;
    if current_host_output.record_digest() != host_output.record_digest()
        || current_host_output.claim_digest() != current_output.reservation().record_digest()
    {
        return Err(ProtectedExecutionSpecProducerErrorV1::NotCurrent);
    }
    let idempotency = AdmissionIdempotencyV1::new(
        BackendOperationIdV1::new(*create_operation.as_bytes())
            .map_err(|_| ProtectedExecutionSpecProducerErrorV1::NotCurrent)?,
        source.accepted_request_digest,
    )?;
    let draft =
        ExecutionAdmissionDraftV1::new(&specification, idempotency, output.currentness().clone())?;
    // The Host transfer is a sealed content descriptor, not a 64 KiB inline
    // broker body. Keep the durable canonical bytes within that exact bound.
    if !spec_fits_host_descriptor(draft.specification_bytes().len()) {
        return Err(ProtectedExecutionSpecProducerErrorV1::UnsupportedCommand);
    }
    admit_execution(claim, draft).map_err(Into::into)
}

/// Prepares canonical bytes from cross-process Host evidence and Controller sources.
///
/// This deliberately does not append spec admission or send a Host Apply. The
/// Host argument receipt is fresh only for this handoff; AOSEOR02 settlement
/// is checked against the exact accepted Create claim, while physical Storage
/// and a live Host handoff remain independent, unavailable authorities.
///
/// # Errors
///
/// Rejects stale accepted Create, assignment, environment, parent policy,
/// Host output settlement, guest credential policy, or argument evidence. It
/// also rejects a canonical spec beyond the sealed Host descriptor limit.
#[allow(clippy::too_many_arguments)]
pub fn prepare_controller_execution_spec_preview_v1<T>(
    controller: &mut Journal,
    assignment: &CurrentAssignmentTarget,
    environment_owner: &mut EnvironmentProtectedJournalOwnerV1<'_, '_>,
    parent: &ExecutionParentResourceSourceV1,
    argument_observation: &AuthenticatedControllerHostArgumentObservationV1,
    execution: ExecutionId,
    create_operation: OperationId,
    clock: &mut T,
) -> Result<ControllerExecutionSpecPreviewV1, ProtectedExecutionSpecProducerErrorV1>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    if argument_observation.execution() != execution
        || argument_observation.create_operation() != create_operation
        || assignment.binding().manifest() != parent.assignment()
    {
        return Err(ProtectedExecutionSpecProducerErrorV1::NotCurrent);
    }
    assignment.recheck(controller, clock)?;
    revalidate_execution_parent_resource_from_journal_v1(controller, parent)?;
    revalidate_current_controller_host_argument_observation_v1(
        controller,
        assignment,
        environment_owner,
        parent,
        argument_observation,
        clock,
    )?;

    let source = read_controller_spec_inputs(
        controller,
        environment_owner,
        parent,
        execution,
        create_operation,
    )?;
    let output = accepted_claim(controller, create_operation, execution, parent)?.record;
    let host_output = read_current_controller_output_settlement_v1(
        controller,
        assignment,
        execution,
        create_operation,
        clock,
    )?
    .ok_or(ProtectedExecutionSpecProducerErrorV1::NotCurrent)?;
    if host_output.claim_digest() != output.record_digest() {
        return Err(ProtectedExecutionSpecProducerErrorV1::NotCurrent);
    }

    let specification = build_specification(
        &source,
        parent,
        &output,
        argument_observation.evidence(),
        execution,
        create_operation,
    )?;
    read_execution_guest_identity_v1(controller, assignment, &specification)?;

    // These owners are held while the exact spec bytes are derived. A later
    // durable admission still needs a physical-Storage/Host effect cut.
    environment_owner.revalidate_execution_source(&source.environment)?;
    revalidate_current_controller_host_argument_observation_v1(
        controller,
        assignment,
        environment_owner,
        parent,
        argument_observation,
        clock,
    )?;
    revalidate_execution_parent_resource_from_journal_v1(controller, parent)?;
    let current_output = accepted_claim(controller, create_operation, execution, parent)?.record;
    let current_host_output = read_current_controller_output_settlement_v1(
        controller,
        assignment,
        execution,
        create_operation,
        clock,
    )?
    .ok_or(ProtectedExecutionSpecProducerErrorV1::NotCurrent)?;
    if current_output != output
        || current_host_output.record_digest() != host_output.record_digest()
        || current_host_output.claim_digest() != current_output.record_digest()
    {
        return Err(ProtectedExecutionSpecProducerErrorV1::NotCurrent);
    }

    let canonical_bytes = encode_execution_spec_v1(&specification);
    if !spec_fits_host_descriptor(canonical_bytes.len()) {
        return Err(ProtectedExecutionSpecProducerErrorV1::UnsupportedCommand);
    }
    let digest = execution_spec_digest_v1(&specification);
    assignment.recheck(controller, clock)?;
    Ok(ControllerExecutionSpecPreviewV1 {
        specification,
        canonical_bytes,
        digest,
        accepted_request_digest: source.accepted_request_digest,
        output_claim_digest: output.record_digest(),
        output_settlement_digest: host_output.record_digest(),
        argument_receipt_digest: argument_observation.record_digest(),
        source_heads: ControllerExecutionSpecSourceHeadsV1 {
            assignment_digest: parent.assignment().digest(),
            assignment_epoch: parent.assignment().manifest().epoch().get(),
            parent_binding: parent.binding_digest(),
            parent_projection: parent.projection_revision(),
            sandbox_spec_record: parent.specification_record_digest(),
            environment_activation: source.environment.activation_digest(),
            environment_manifest: source.environment.manifest().digest(),
            environment_generation: source.environment.generation().get(),
            output_claim: output.record_digest(),
            output_settlement: host_output.record_digest(),
            argument_receipt: argument_observation.record_digest(),
            host_argument_custody: argument_observation.host_custody_digest(),
            host_argument_sequence: argument_observation.host_custody_sequence(),
        },
    })
}

struct ControllerSpecSourceInputsV1 {
    command: Command,
    client_public_key: Vec<u8>,
    environment: EnvironmentExecutionSourceV1,
    credentials: ExecutionCredentialsV1,
    principal: PrincipalId,
    accepted_request_digest: ObjectDigest,
}

fn read_controller_spec_inputs(
    controller: &mut Journal,
    environment_owner: &mut EnvironmentProtectedJournalOwnerV1<'_, '_>,
    parent: &ExecutionParentResourceSourceV1,
    execution: ExecutionId,
    create_operation: OperationId,
) -> Result<ControllerSpecSourceInputsV1, ProtectedExecutionSpecProducerErrorV1> {
    let accepted = accepted_create_execution_effect_from_journal_v1(controller, create_operation)?
        .ok_or(ProtectedExecutionSpecProducerErrorV1::NotCurrent)?;
    let DormantSandboxRequestKindV1::Exec(request) = accepted.validated_request()? else {
        return Err(ProtectedExecutionSpecProducerErrorV1::NotCurrent);
    };
    create_holder_proof::verify_create_holder_proof_v1(&request)?;
    let command = request
        .command
        .as_option()
        .ok_or(ProtectedExecutionSpecProducerErrorV1::NotCurrent)?;
    let projection = PublicProjectionStoreV1::new(controller)
        .get(PublicProjectionKindV1::Execution, *execution.as_bytes())?
        .ok_or(ProtectedExecutionSpecProducerErrorV1::NotCurrent)?;
    let PublicProjectionResourceV1::Execution(projected) = projection.resource() else {
        return Err(ProtectedExecutionSpecProducerErrorV1::NotCurrent);
    };
    let manifest = parent.assignment().manifest();
    if accepted.project() != manifest.project()
        || request.sandbox_id != manifest.sandbox().as_bytes()
        || projection.project() != accepted.project()
        || projection.operation() != create_operation
        || projected.execution_id.as_slice() != execution.as_bytes()
        || projected.sandbox_id != request.sandbox_id
        || projected.sandbox_incarnation_id != manifest.incarnation().as_bytes()
        || projected.assignment_epoch != manifest.epoch().get()
        || projected.phase.as_known() != Some(ExecutionPhase::EXECUTION_PHASE_REQUESTED)
        || projected.audit_id != create_operation.as_bytes()
        || projected.command.as_option() != Some(command)
    {
        return Err(ProtectedExecutionSpecProducerErrorV1::NotCurrent);
    }

    let environment = environment_owner.current_execution_source(
        accepted.project(),
        parent.assignment().manifest().sandbox(),
        execution,
    )?;
    if environment.descriptor() != parent.assignment().manifest().environment() {
        return Err(ProtectedExecutionSpecProducerErrorV1::NotCurrent);
    }
    let retained = sandbox_spec_state::get(controller, parent.specification_descriptor())?
        .ok_or(ProtectedExecutionSpecProducerErrorV1::NotCurrent)?;
    if retained.record_digest() != parent.specification_record_digest() {
        return Err(ProtectedExecutionSpecProducerErrorV1::NotCurrent);
    }
    let policy = retained
        .spec()
        .guest_execution_identity()
        .ok_or(ProtectedExecutionSpecProducerErrorV1::NotCurrent)?;
    let credentials = ExecutionCredentialsV1::new(
        policy.user_id(),
        policy.primary_group_id(),
        policy.supplementary_group_ids().to_vec(),
    )?;
    Ok(ControllerSpecSourceInputsV1 {
        command: command.clone(),
        client_public_key: request.client_public_key.clone(),
        environment,
        credentials,
        principal: accepted.caller(),
        accepted_request_digest: ObjectDigest::from_bytes(
            Sha256::digest(accepted.canonical_request()).into(),
        ),
    })
}

fn build_specification(
    source: &ControllerSpecSourceInputsV1,
    parent: &ExecutionParentResourceSourceV1,
    output: &DurableExecutionOutputReservationV1,
    argument_limit: &aos_sandbox_core::ExecutionRuntimeArgumentLimitV1,
    execution: ExecutionId,
    create_operation: OperationId,
) -> Result<ExecutionSpecV1, ProtectedExecutionSpecProducerErrorV1> {
    let command = &source.command;
    Ok(ExecutionSpecV1::new(
        execution,
        argument_limit.target().clone(),
        source.environment.descriptor().clone(),
        source.environment.environment().clone(),
        source.environment.generation(),
        execution_command(command, source.credentials.clone())?,
        argument_limit.clone(),
        execution_resources(parent, output)?,
        execution_io(command, &source.client_public_key, output)?,
        ExecutionTimeoutV1::new(
            command
                .execution_timeout
                .as_option()
                .ok_or(ProtectedExecutionSpecProducerErrorV1::UnsupportedCommand)?
                .nanoseconds,
        )?,
        source.principal,
        AuditId::from_bytes(*create_operation.as_bytes()),
    )?)
}

fn spec_fits_host_descriptor(encoded_bytes: usize) -> bool {
    encoded_bytes != 0 && encoded_bytes <= MAXIMUM_HOST_EXECUTION_SPEC_BYTES
}

fn execution_command(
    public: &Command,
    credentials: ExecutionCredentialsV1,
) -> Result<ExecutionCommandV1, ProtectedExecutionSpecProducerErrorV1> {
    if !public.sandbox_shell.is_empty() {
        return Err(ProtectedExecutionSpecProducerErrorV1::UnsupportedCommand);
    }
    let components = if public.working_directory.is_empty() {
        Vec::new()
    } else {
        public
            .working_directory
            .split(|byte| *byte == b'/')
            .map(|bytes| {
                PathName::new(bytes.to_vec())
                    .map_err(|_| ProtectedExecutionSpecProducerErrorV1::UnsupportedCommand)
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    let directory = RelativePath::new(components)
        .map_err(|_| ProtectedExecutionSpecProducerErrorV1::UnsupportedCommand)?;
    let overlay = public
        .environment
        .iter()
        .map(|entry| ExecutionEnvironmentEntry::new(entry.name.clone(), entry.value.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    ExecutionCommandV1::new(public.arguments.clone(), overlay, directory, credentials)
        .map_err(Into::into)
}

fn execution_io(
    public: &Command,
    client_public_key: &[u8],
    output: &DurableExecutionOutputReservationV1,
) -> Result<ExecutionIoV1, ProtectedExecutionSpecProducerErrorV1> {
    let mode = public
        .io_mode
        .as_known()
        .ok_or(ProtectedExecutionSpecProducerErrorV1::UnsupportedCommand)?;
    let represented_features: &[&str] = match mode {
        ExecutionIoMode::EXECUTION_IO_MODE_STREAM => &[
            crate::controller_query::EXECUTION_STREAM_FEATURE_V1,
            crate::controller_query::EXECUTION_TIMEOUT_FEATURE_V1,
        ],
        ExecutionIoMode::EXECUTION_IO_MODE_PTY => &[
            crate::controller_query::EXECUTION_PTY_FEATURE_V1,
            crate::controller_query::EXECUTION_TIMEOUT_FEATURE_V1,
        ],
        ExecutionIoMode::EXECUTION_IO_MODE_DETACHED_CAPTURE => &[
            crate::controller_query::EXECUTION_DETACHED_CAPTURE_FEATURE_V1,
            crate::controller_query::EXECUTION_DETACHED_CAPTURE_STREAM_CEILINGS_FEATURE_V1,
            crate::controller_query::EXECUTION_TIMEOUT_FEATURE_V1,
        ],
        _ => return Err(ProtectedExecutionSpecProducerErrorV1::UnsupportedCommand),
    };
    if public
        .stream_features
        .iter()
        .any(|feature| !represented_features.contains(&feature.namespace.as_str()))
    {
        return Err(ProtectedExecutionSpecProducerErrorV1::UnsupportedCommand);
    }
    if mode == ExecutionIoMode::EXECUTION_IO_MODE_DETACHED_CAPTURE {
        let aggregate =
            crate::controller_query::portable_resource::checked_detached_capture_bytes(public)
                .ok_or(ProtectedExecutionSpecProducerErrorV1::UnsupportedCommand)?;
        let stdout = public
            .maximum_stdout_bytes
            .ok_or(ProtectedExecutionSpecProducerErrorV1::UnsupportedCommand)?;
        let stderr = public
            .maximum_stderr_bytes
            .ok_or(ProtectedExecutionSpecProducerErrorV1::UnsupportedCommand)?;
        if aggregate != output.output().admitted_bytes()
            || stdout != output.maximum_stdout_bytes()
            || stderr != output.maximum_stderr_bytes()
        {
            return Err(ProtectedExecutionSpecProducerErrorV1::NotCurrent);
        }
        return ExecutionIoV1::new(
            ExecutionTerminalModeV1::None,
            ExecutionOutputModeV1::Capture {
                maximum_stdout_bytes: stdout,
                maximum_stderr_bytes: stderr,
            },
            ExecutionDisconnectPolicyV1::Continue,
            ExecutionAccessRouteV1::Detached,
        )
        .map_err(Into::into);
    }
    let terminal = if mode == ExecutionIoMode::EXECUTION_IO_MODE_PTY {
        ExecutionTerminalModeV1::Pty
    } else {
        ExecutionTerminalModeV1::None
    };
    if public.detached_capture_bytes != 0
        || output.output().admitted_bytes() != 0
        || output.maximum_stdout_bytes() != 0
        || output.maximum_stderr_bytes() != 0
    {
        return Err(ProtectedExecutionSpecProducerErrorV1::NotCurrent);
    }
    let key_text = std::str::from_utf8(client_public_key)
        .map_err(|_| ProtectedExecutionSpecProducerErrorV1::UnsupportedCommand)?;
    let public_key = PublicKey::from_openssh(key_text)
        .map_err(|_| ProtectedExecutionSpecProducerErrorV1::UnsupportedCommand)?;
    let material = public_key
        .key_data()
        .ed25519()
        .ok_or(ProtectedExecutionSpecProducerErrorV1::UnsupportedCommand)?
        .0;
    let holder = ExecutionPublicKeyV1::new_ssh_ed25519(material)?;
    let mut capabilities = vec![
        ExecutionEndpointCapabilityV1::StandardInput,
        ExecutionEndpointCapabilityV1::StandardOutput,
        ExecutionEndpointCapabilityV1::StandardError,
    ];
    if terminal == ExecutionTerminalModeV1::Pty {
        capabilities.push(ExecutionEndpointCapabilityV1::TerminalResize);
    }
    let route = ExecutionAccessRouteV1::open_ssh(holder, capabilities)?;
    ExecutionIoV1::new(
        terminal,
        ExecutionOutputModeV1::Stream,
        ExecutionDisconnectPolicyV1::Cancel,
        route,
    )
    .map_err(Into::into)
}

fn execution_resources(
    parent: &ExecutionParentResourceSourceV1,
    output: &DurableExecutionOutputReservationV1,
) -> Result<ExecutionResourceAdmissionV1, ProtectedExecutionSpecProducerErrorV1> {
    let (requested, admitted) = inherited_child_limits(parent.profile())?;
    ExecutionResourceAdmissionV1::new(
        requested,
        admitted,
        parent.profile().clone(),
        parent.profile_commitment(),
        output.output().clone(),
    )
    .map_err(Into::into)
}

fn inherited_child_limits(
    profile: &ResourceProfile,
) -> Result<
    (
        Vec<ExecutionResourceRequestV1>,
        Vec<ExecutionResourceSublimitV1>,
    ),
    ProtectedExecutionSpecProducerErrorV1,
> {
    let dimensions = [
        LimitDimension::Processes,
        LimitDimension::Memory,
        LimitDimension::CpuWeight,
        LimitDimension::CpuQuota,
        LimitDimension::IoWeight,
        LimitDimension::IoBandwidth,
        LimitDimension::OpenFiles,
    ];
    let mut requested = Vec::with_capacity(dimensions.len());
    let mut admitted = Vec::with_capacity(dimensions.len());
    for dimension in dimensions {
        let limit = profile
            .limits()
            .iter()
            .find(|limit| limit.dimension() == dimension)
            .ok_or(ProtectedExecutionSpecProducerErrorV1::MissingSublimit)?;
        let LimitValue::Bounded(value) = limit.value() else {
            return Err(ProtectedExecutionSpecProducerErrorV1::MissingSublimit);
        };
        if matches!(
            dimension,
            LimitDimension::CpuWeight | LimitDimension::IoWeight
        ) {
            let weight = u16::try_from(value)
                .map_err(|_| ProtectedExecutionSpecProducerErrorV1::MissingSublimit)?;
            requested.push(ExecutionResourceRequestV1::new(
                dimension,
                ExecutionResourceRequestValueV1::RelativeWeight(weight),
            )?);
            admitted.push(ExecutionResourceSublimitV1::new(
                dimension,
                ExecutionResourceSublimitValueV1::RelativeWeight(weight),
            )?);
        } else {
            requested.push(ExecutionResourceRequestV1::new(
                dimension,
                ExecutionResourceRequestValueV1::Inherit,
            )?);
            admitted.push(ExecutionResourceSublimitV1::new(
                dimension,
                ExecutionResourceSublimitValueV1::Maximum(value),
            )?);
        }
    }
    Ok((requested, admitted))
}

#[cfg(test)]
mod tests {
    use aos_sandbox_core::FeatureRef;
    use aos_sandbox_core::model::spec::Limit;

    use super::*;

    #[test]
    fn canonical_spec_uses_full_sealed_host_transfer_bound() {
        assert!(!spec_fits_host_descriptor(0));
        assert!(spec_fits_host_descriptor(64 * 1_024 + 1));
        assert!(spec_fits_host_descriptor(MAXIMUM_HOST_EXECUTION_SPEC_BYTES));
        assert!(!spec_fits_host_descriptor(
            MAXIMUM_HOST_EXECUTION_SPEC_BYTES + 1
        ));
    }

    fn parent_profile() -> ResourceProfile {
        let cgroup = FeatureRef::new("aos.sandbox.enforcement.cgroup-v2", 1, 0).unwrap();
        let ledger = FeatureRef::new("aos.sandbox.enforcement.broker-ledger", 1, 0).unwrap();
        let limits = [
            (LimitDimension::Processes, 64, cgroup.clone()),
            (LimitDimension::Memory, 1_048_576, cgroup.clone()),
            (LimitDimension::CpuWeight, 100, cgroup.clone()),
            (LimitDimension::CpuQuota, 50_000, cgroup.clone()),
            (LimitDimension::IoWeight, 200, cgroup.clone()),
            (LimitDimension::IoBandwidth, 8_192, cgroup),
            (LimitDimension::OpenFiles, 256, ledger),
        ];
        ResourceProfile::new(
            limits
                .into_iter()
                .map(|(dimension, value, enforcement)| {
                    Limit::new(dimension, LimitValue::Bounded(value), enforcement)
                })
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn child_limits_are_exact_finite_parent_bounds_and_weights() {
        let (requested, admitted) = inherited_child_limits(&parent_profile()).unwrap();
        assert_eq!(requested.len(), 7);
        assert_eq!(admitted.len(), 7);
        assert_eq!(
            requested[0].value(),
            ExecutionResourceRequestValueV1::Inherit
        );
        assert_eq!(
            admitted[0].value(),
            ExecutionResourceSublimitValueV1::Maximum(64)
        );
        assert_eq!(
            requested[2].value(),
            ExecutionResourceRequestValueV1::RelativeWeight(100)
        );
        assert_eq!(
            admitted[4].value(),
            ExecutionResourceSublimitValueV1::RelativeWeight(200)
        );
    }

    #[test]
    fn child_limits_reject_missing_or_unbounded_parent_entries() {
        let mut limits = parent_profile().limits().to_vec();
        limits.retain(|limit| limit.dimension() != LimitDimension::IoWeight);
        assert!(matches!(
            inherited_child_limits(&ResourceProfile::new(limits).unwrap()),
            Err(ProtectedExecutionSpecProducerErrorV1::MissingSublimit)
        ));

        let mut limits = parent_profile().limits().to_vec();
        let index = limits
            .iter()
            .position(|limit| limit.dimension() == LimitDimension::Memory)
            .unwrap();
        limits[index] = Limit::new(
            LimitDimension::Memory,
            LimitValue::Inherited,
            FeatureRef::new("aos.sandbox.enforcement.cgroup-v2", 1, 0).unwrap(),
        );
        assert!(matches!(
            inherited_child_limits(&ResourceProfile::new(limits).unwrap()),
            Err(ProtectedExecutionSpecProducerErrorV1::MissingSublimit)
        ));
    }
}
