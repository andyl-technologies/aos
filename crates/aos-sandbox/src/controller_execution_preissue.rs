//! Nonrenewable Controller custody for an accepted execution source.
//!
//! AOSCIP01 is a provisional Controller record, not a Host grant. The source
//! commitment is derived under the sole Controller journal writer from the
//! accepted Create, current signed assignment, parent profile, environment,
//! and version-two guest identity policy. A later cross-owner protocol must
//! obtain exact Host AOSEOR02 and Storage AOSEOR03 receipts before signing an
//! AOSCAS01 grant. The preissue itself does not consume a Host challenge; that
//! needs a separate final Controller CAS. No Host journal is opened here.
//!
//! ```text
//! AOSCIP01 || execution:16 || create-operation:16 || source-digest:32
//!          || stdout-ceiling:u64be || stderr-ceiling:u64be
//!          || controller-source-sequence:u64be || host-boot-id:16
//!          || deadline-boottime-nanoseconds:u64be || issuer-nonce:32
//!          || SHA256("aos.sandbox.controller-execution-preissue.v1\0" || preceding):32
//! ```

use aos_proto::aos::sandbox::v1::{ExecutionIoMode, ExecutionPhase};
use aos_sandbox_core::model::spec::IdentityProfile;
use aos_sandbox_core::{ExecutionId, ObjectDigest, OperationId, RawPairedClockSample};
use rand::{TryRngCore as _, rngs::OsRng};
use sha2::{Digest as _, Sha256};

use crate::cli_model::DormantSandboxRequestKindV1;
use crate::controller_service::public_projection::{
    PublicProjectionError, PublicProjectionKindV1, PublicProjectionResourceV1,
    PublicProjectionStoreV1,
};
use crate::create_holder_proof::{self, CreateHolderProofErrorV1};
use crate::environment::{EnvironmentExecutionErrorV1, EnvironmentProtectedJournalOwnerV1};
use crate::execution_parent_resource::{
    ExecutionParentResourceSourceErrorV1, ExecutionParentResourceSourceV1,
    revalidate_execution_parent_resource_from_journal_v1,
};
use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::reconciler::{ReconcilerError, accepted_create_execution_effect_from_journal_v1};
use crate::runtime_scope::{CurrentAssignmentTarget, CurrentRuntimeScopeError};
use crate::sandbox_spec_state::{self, SandboxSpecStateError};
use crate::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};

mod reserve_source;

pub use reserve_source::{
    ControllerExecutionReserveSourceV1, EXECUTION_RESERVE_SOURCE_BYTES_V1,
    prepare_execution_reserve_source_v1,
};

const MAGIC: &[u8; 8] = b"AOSCIP01";
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.controller-execution-preissue.v1\0";
const SOURCE_DOMAIN: &[u8] = b"aos.sandbox.controller-execution-source.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.controller-execution-preissue-tx.v1\0";
const MAXIMUM_PREISSUE_WINDOW_NANOSECONDS: u64 = 30_000_000_000;
const RECORD_BYTES: usize = 8 + 16 + 16 + 32 + 8 + 8 + 8 + 16 + 8 + 32 + 32;

/// Reports a missing or stale protected provisional execution source.
#[derive(Debug, thiserror::Error)]
pub enum ControllerExecutionPreissueErrorV1 {
    /// The accepted Create or current owner graph disagrees.
    #[error("accepted execution source is not current")]
    NotCurrent,
    /// The public command cannot be represented by a future execution spec.
    #[error("accepted execution command is unsupported")]
    UnsupportedCommand,
    /// A prior one-shot source expired or belongs to another Host boot.
    #[error("execution preissue is expired and cannot be regenerated")]
    Expired,
    /// A protected append may have committed and requires cold replay.
    #[error("execution preissue durability is ambiguous; reopen the Controller journal")]
    OutcomeUnknown,
    /// The kernel did not provide a nonzero issuer nonce.
    #[error("execution preissue entropy is unavailable")]
    Entropy,
    /// The protected Controller journal is absent or corrupt.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The current signed assignment or lease is unavailable.
    #[error(transparent)]
    Assignment(#[from] CurrentRuntimeScopeError),
    /// The accepted public operation could not be replayed.
    #[error(transparent)]
    Operation(#[from] ReconcilerError),
    /// The exact public execution projection could not be replayed.
    #[error(transparent)]
    Projection(#[from] PublicProjectionError),
    /// The accepted client-holder proof is invalid.
    #[error(transparent)]
    Holder(#[from] CreateHolderProofErrorV1),
    /// The current parent profile is unavailable.
    #[error(transparent)]
    Parent(#[from] ExecutionParentResourceSourceErrorV1),
    /// The exact current environment source is unavailable.
    #[error(transparent)]
    Environment(#[from] EnvironmentExecutionErrorV1),
    /// The version-two sandbox spec or guest policy is unavailable.
    #[error(transparent)]
    SandboxSpec(#[from] SandboxSpecStateError),
}

/// Retains one immutable, nonauthorizing Controller preissue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerExecutionPreissueV1 {
    execution: ExecutionId,
    create_operation: OperationId,
    source_digest: ObjectDigest,
    maximum_stdout_bytes: u64,
    maximum_stderr_bytes: u64,
    controller_source_sequence: u64,
    host_boot_id: [u8; 16],
    deadline_boottime_nanoseconds: u64,
    issuer_nonce: [u8; 32],
    record_digest: ObjectDigest,
}

impl ControllerExecutionPreissueV1 {
    /// Returns the exact execution selected by accepted Create.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the exact accepted Create operation.
    #[must_use]
    pub const fn create_operation(&self) -> OperationId {
        self.create_operation
    }

    /// Returns the commitment to revalidated Controller-owned source facts.
    #[must_use]
    pub const fn source_digest(&self) -> ObjectDigest {
        self.source_digest
    }

    /// Returns the exact accepted standard-output ceiling.
    #[must_use]
    pub const fn maximum_stdout_bytes(&self) -> u64 {
        self.maximum_stdout_bytes
    }

    /// Returns the exact accepted standard-error ceiling.
    #[must_use]
    pub const fn maximum_stderr_bytes(&self) -> u64 {
        self.maximum_stderr_bytes
    }

    /// Returns the protected Controller source sequence captured before append.
    #[must_use]
    pub const fn controller_source_sequence(&self) -> u64 {
        self.controller_source_sequence
    }

    /// Returns the Host kernel boot bound to the provisional nonce.
    #[must_use]
    pub const fn host_boot_id(&self) -> [u8; 16] {
        self.host_boot_id
    }

    /// Returns the non-renewable monotonic deadline.
    #[must_use]
    pub const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.deadline_boottime_nanoseconds
    }

    /// Returns the nonrenewable issuer nonce, not a Guest challenge nonce.
    #[must_use]
    pub const fn issuer_nonce(&self) -> [u8; 32] {
        self.issuer_nonce
    }

    /// Returns the digest of the exact protected AOSCIP01 record.
    #[must_use]
    pub const fn record_digest(&self) -> ObjectDigest {
        self.record_digest
    }

    /// Returns the exact versioned record for a future signed provisional grant.
    ///
    /// The bytes alone are not a Controller signature or Host dispatch permit.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.encode()
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RECORD_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(self.execution.as_bytes());
        bytes.extend_from_slice(self.create_operation.as_bytes());
        bytes.extend_from_slice(self.source_digest.as_bytes());
        bytes.extend_from_slice(&self.maximum_stdout_bytes.to_be_bytes());
        bytes.extend_from_slice(&self.maximum_stderr_bytes.to_be_bytes());
        bytes.extend_from_slice(&self.controller_source_sequence.to_be_bytes());
        bytes.extend_from_slice(&self.host_boot_id);
        bytes.extend_from_slice(&self.deadline_boottime_nanoseconds.to_be_bytes());
        bytes.extend_from_slice(&self.issuer_nonce);
        bytes.extend_from_slice(self.record_digest.as_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, ControllerExecutionPreissueErrorV1> {
        if bytes.len() != RECORD_BYTES || bytes.get(..8) != Some(MAGIC.as_slice()) {
            return Err(ControllerExecutionPreissueErrorV1::NotCurrent);
        }
        let read_16 = |start| -> Result<[u8; 16], ControllerExecutionPreissueErrorV1> {
            bytes[start..start + 16]
                .try_into()
                .map_err(|_| ControllerExecutionPreissueErrorV1::NotCurrent)
        };
        let read_32 = |start| -> Result<[u8; 32], ControllerExecutionPreissueErrorV1> {
            bytes[start..start + 32]
                .try_into()
                .map_err(|_| ControllerExecutionPreissueErrorV1::NotCurrent)
        };
        let read_u64 = |start| -> Result<u64, ControllerExecutionPreissueErrorV1> {
            Ok(u64::from_be_bytes(
                bytes[start..start + 8]
                    .try_into()
                    .map_err(|_| ControllerExecutionPreissueErrorV1::NotCurrent)?,
            ))
        };
        let record = Self {
            execution: ExecutionId::from_bytes(read_16(8)?),
            create_operation: OperationId::from_bytes(read_16(24)?),
            source_digest: ObjectDigest::from_bytes(read_32(40)?),
            maximum_stdout_bytes: read_u64(72)?,
            maximum_stderr_bytes: read_u64(80)?,
            controller_source_sequence: read_u64(88)?,
            host_boot_id: read_16(96)?,
            deadline_boottime_nanoseconds: read_u64(112)?,
            issuer_nonce: read_32(120)?,
            record_digest: ObjectDigest::from_bytes(read_32(152)?),
        };
        if record.execution.as_bytes() == &[0; 16]
            || record.create_operation.as_bytes() == &[0; 16]
            || record.source_digest.as_bytes() == &[0; 32]
            || record.controller_source_sequence == 0
            || record.host_boot_id == [0; 16]
            || record.deadline_boottime_nanoseconds == 0
            || record.issuer_nonce == [0; 32]
            || record.record_digest != record_digest(&bytes[..152])
        {
            return Err(ControllerExecutionPreissueErrorV1::NotCurrent);
        }
        Ok(record)
    }
}

/// Starts or replays one Controller-local accepted-Create source.
///
/// A successful replay returns the original nonce and deadline only after all
/// Controller sources are revalidated. Expiration or a Host reboot quarantines
/// the record; this method never silently mints a replacement. This record is
/// not a signed Host/Storage grant or a physical output reservation.
///
/// # Errors
///
/// Rejects an unprotected journal, stale accepted Create/assignment/parent/
/// environment/policy, incompatible output split, expired prior record, or
/// unresolved append durability. `OutcomeUnknown` requires protected reopen.
#[allow(clippy::too_many_arguments)]
pub fn preissue_accepted_execution_source_v1<T>(
    controller: &mut Journal,
    assignment: &CurrentAssignmentTarget,
    environment_owner: &mut EnvironmentProtectedJournalOwnerV1<'_, '_>,
    parent: &ExecutionParentResourceSourceV1,
    execution: ExecutionId,
    create_operation: OperationId,
    clock: &mut T,
) -> Result<ControllerExecutionPreissueV1, ControllerExecutionPreissueErrorV1>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    controller.ensure_protected_authority()?;
    let (_, observed) = assignment.verified_plan_lease(controller, clock)?;
    let source = current_source(
        controller,
        assignment,
        environment_owner,
        parent,
        execution,
        create_operation,
    )?;
    let deadline = observed
        .boottime_nanoseconds()
        .checked_add(MAXIMUM_PREISSUE_WINDOW_NANOSECONDS)
        .map(|value| value.min(assignment.deadline_boottime_nanoseconds()))
        .filter(|value| *value > observed.boottime_nanoseconds())
        .ok_or(ControllerExecutionPreissueErrorV1::Expired)?;

    revalidate_execution_parent_resource_from_journal_v1(controller, parent)?;
    environment_owner.revalidate_execution_source(&source.environment)?;
    let (_, final_sample) = assignment.verified_plan_lease(controller, clock)?;
    if final_sample.host_boot_id() != observed.host_boot_id()
        || final_sample.boottime_nanoseconds() >= deadline
    {
        return Err(ControllerExecutionPreissueErrorV1::Expired);
    }
    controller.ensure_protected_authority()?;
    let existing = controller
        .get(
            RecordNamespace::ControllerExecutionPreissue,
            execution.as_bytes(),
        )
        .map(ControllerExecutionPreissueV1::decode)
        .transpose()?;
    if let Some(existing) = existing {
        return validate_existing(existing, source.identity(), final_sample);
    }

    let mut nonce = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| ControllerExecutionPreissueErrorV1::Entropy)?;
    if nonce == [0; 32] {
        return Err(ControllerExecutionPreissueErrorV1::Entropy);
    }
    let sequence = controller.snapshot_sequence();
    let mut record = ControllerExecutionPreissueV1 {
        execution,
        create_operation,
        source_digest: source.digest,
        maximum_stdout_bytes: source.stdout,
        maximum_stderr_bytes: source.stderr,
        controller_source_sequence: sequence,
        host_boot_id: observed.host_boot_id(),
        deadline_boottime_nanoseconds: deadline,
        issuer_nonce: nonce,
        record_digest: ObjectDigest::from_bytes([0; 32]),
    };
    let encoded = record.encode();
    record.record_digest = record_digest(&encoded[..152]);
    persist_preissue(controller, &record)?;
    Ok(record)
}

/// Rechecks a retained one-shot preissue under all current Controller owners.
///
/// This is a nonauthorizing source readback. A final signed AOSCAS01 grant
/// additionally needs exact authenticated Host AOSEOR02 and Storage AOSEOR03
/// receipts, live runtime/profile evidence, and an effect handoff barrier.
///
/// # Errors
///
/// Rejects absent, stale, expired, corrupt, or unprotected source custody.
#[allow(clippy::too_many_arguments)]
pub fn revalidate_accepted_execution_preissue_v1<T>(
    controller: &mut Journal,
    assignment: &CurrentAssignmentTarget,
    environment_owner: &mut EnvironmentProtectedJournalOwnerV1<'_, '_>,
    parent: &ExecutionParentResourceSourceV1,
    preissue: &ControllerExecutionPreissueV1,
    clock: &mut T,
) -> Result<(), ControllerExecutionPreissueErrorV1>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    controller.ensure_protected_authority()?;
    let (_, observed) = assignment.verified_plan_lease(controller, clock)?;
    let source = current_source(
        controller,
        assignment,
        environment_owner,
        parent,
        preissue.execution,
        preissue.create_operation,
    )?;
    revalidate_execution_parent_resource_from_journal_v1(controller, parent)?;
    environment_owner.revalidate_execution_source(&source.environment)?;
    let (_, final_sample) = assignment.verified_plan_lease(controller, clock)?;
    if final_sample.host_boot_id() != observed.host_boot_id() {
        return Err(ControllerExecutionPreissueErrorV1::Expired);
    }
    let stored = controller
        .get(
            RecordNamespace::ControllerExecutionPreissue,
            preissue.execution.as_bytes(),
        )
        .ok_or(ControllerExecutionPreissueErrorV1::NotCurrent)
        .and_then(ControllerExecutionPreissueV1::decode)?;
    if stored != *preissue {
        return Err(ControllerExecutionPreissueErrorV1::NotCurrent);
    }
    validate_existing(stored, source.identity(), final_sample).map(|_| ())
}

#[derive(Clone, Copy)]
struct SourceIdentityV1 {
    digest: ObjectDigest,
    stdout: u64,
    stderr: u64,
    execution: ExecutionId,
    create_operation: OperationId,
}

struct CurrentSourceV1 {
    digest: ObjectDigest,
    stdout: u64,
    stderr: u64,
    execution: ExecutionId,
    create_operation: OperationId,
    environment: crate::environment::EnvironmentExecutionSourceV1,
}

impl CurrentSourceV1 {
    fn identity(&self) -> SourceIdentityV1 {
        SourceIdentityV1 {
            digest: self.digest,
            stdout: self.stdout,
            stderr: self.stderr,
            execution: self.execution,
            create_operation: self.create_operation,
        }
    }
}

fn current_source(
    controller: &mut Journal,
    assignment: &CurrentAssignmentTarget,
    environment_owner: &mut EnvironmentProtectedJournalOwnerV1<'_, '_>,
    parent: &ExecutionParentResourceSourceV1,
    execution: ExecutionId,
    create_operation: OperationId,
) -> Result<CurrentSourceV1, ControllerExecutionPreissueErrorV1> {
    revalidate_execution_parent_resource_from_journal_v1(controller, parent)?;
    if assignment.binding().manifest() != parent.assignment() {
        return Err(ControllerExecutionPreissueErrorV1::NotCurrent);
    }
    let accepted = accepted_create_execution_effect_from_journal_v1(controller, create_operation)?
        .ok_or(ControllerExecutionPreissueErrorV1::NotCurrent)?;
    let DormantSandboxRequestKindV1::Exec(request) = accepted.validated_request()? else {
        return Err(ControllerExecutionPreissueErrorV1::NotCurrent);
    };
    create_holder_proof::verify_create_holder_proof_v1(&request)?;
    let command = request
        .command
        .as_option()
        .ok_or(ControllerExecutionPreissueErrorV1::NotCurrent)?;
    let (stdout, stderr) = accepted_stream_ceiling(command)?;
    let projection = PublicProjectionStoreV1::new(controller)
        .get(PublicProjectionKindV1::Execution, *execution.as_bytes())?
        .ok_or(ControllerExecutionPreissueErrorV1::NotCurrent)?;
    let PublicProjectionResourceV1::Execution(projected) = projection.resource() else {
        return Err(ControllerExecutionPreissueErrorV1::NotCurrent);
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
        || !command.sandbox_shell.is_empty()
    {
        return Err(ControllerExecutionPreissueErrorV1::NotCurrent);
    }
    let environment = environment_owner.current_execution_source(
        accepted.project(),
        manifest.sandbox(),
        execution,
    )?;
    if environment.descriptor() != manifest.environment() {
        return Err(ControllerExecutionPreissueErrorV1::NotCurrent);
    }
    let retained = sandbox_spec_state::get(controller, parent.specification_descriptor())?
        .ok_or(ControllerExecutionPreissueErrorV1::NotCurrent)?;
    if retained.record_digest() != parent.specification_record_digest() {
        return Err(ControllerExecutionPreissueErrorV1::NotCurrent);
    }
    let guest_policy = retained
        .spec()
        .guest_execution_identity()
        .ok_or(ControllerExecutionPreissueErrorV1::NotCurrent)?;
    let IdentityProfile::PrivateUserns { id_range_size, .. } = retained.spec().identity_profile()
    else {
        return Err(ControllerExecutionPreissueErrorV1::NotCurrent);
    };
    let id_range_size = id_range_size.get();
    if guest_policy.user_id() >= id_range_size
        || guest_policy.primary_group_id() >= id_range_size
        || guest_policy
            .supplementary_group_ids()
            .iter()
            .any(|group| *group >= id_range_size)
    {
        return Err(ControllerExecutionPreissueErrorV1::NotCurrent);
    }

    let mut hash = Sha256::new();
    hash.update(SOURCE_DOMAIN);
    hash.update(execution.as_bytes());
    hash.update(create_operation.as_bytes());
    hash.update(accepted.caller().as_bytes());
    hash.update(accepted.project().as_bytes());
    hash.update((accepted.canonical_request().len() as u64).to_be_bytes());
    hash.update(accepted.canonical_request());
    hash.update(parent.assignment().digest().as_bytes());
    hash.update(parent.binding_digest().as_bytes());
    hash.update(parent.projection_revision().as_bytes());
    hash.update(parent.profile_commitment().as_bytes());
    hash.update(parent.specification_record_digest().as_bytes());
    hash.update(environment.activation_digest().as_bytes());
    hash.update(environment.manifest().digest().as_bytes());
    hash.update(environment.generation().get().to_be_bytes());
    hash.update(environment.descriptor().media_type().as_str().as_bytes());
    hash.update(environment.descriptor().digest().as_bytes());
    hash.update(environment.descriptor().encoded_size().to_be_bytes());
    hash.update(Sha256::digest(environment.canonical_bytes()));
    hash.update(stdout.to_be_bytes());
    hash.update(stderr.to_be_bytes());
    Ok(CurrentSourceV1 {
        digest: ObjectDigest::from_bytes(hash.finalize().into()),
        stdout,
        stderr,
        execution,
        create_operation,
        environment,
    })
}

fn accepted_stream_ceiling(
    command: &aos_proto::aos::sandbox::v1::Command,
) -> Result<(u64, u64), ControllerExecutionPreissueErrorV1> {
    match command.io_mode.as_known() {
        Some(ExecutionIoMode::EXECUTION_IO_MODE_DETACHED_CAPTURE) => {
            let stdout = command
                .maximum_stdout_bytes
                .ok_or(ControllerExecutionPreissueErrorV1::UnsupportedCommand)?;
            let stderr = command
                .maximum_stderr_bytes
                .ok_or(ControllerExecutionPreissueErrorV1::UnsupportedCommand)?;
            if stdout.checked_add(stderr) != Some(command.detached_capture_bytes) {
                return Err(ControllerExecutionPreissueErrorV1::UnsupportedCommand);
            }
            Ok((stdout, stderr))
        }
        Some(
            ExecutionIoMode::EXECUTION_IO_MODE_STREAM | ExecutionIoMode::EXECUTION_IO_MODE_PTY,
        ) if command.detached_capture_bytes == 0
            && command.maximum_stdout_bytes.is_none()
            && command.maximum_stderr_bytes.is_none() =>
        {
            Ok((0, 0))
        }
        _ => Err(ControllerExecutionPreissueErrorV1::UnsupportedCommand),
    }
}

fn validate_existing(
    existing: ControllerExecutionPreissueV1,
    source: SourceIdentityV1,
    observed: RawPairedClockSample,
) -> Result<ControllerExecutionPreissueV1, ControllerExecutionPreissueErrorV1> {
    if existing.execution != source.execution
        || existing.create_operation != source.create_operation
        || existing.source_digest != source.digest
        || existing.maximum_stdout_bytes != source.stdout
        || existing.maximum_stderr_bytes != source.stderr
    {
        return Err(ControllerExecutionPreissueErrorV1::NotCurrent);
    }
    if existing.host_boot_id != observed.host_boot_id()
        || observed.boottime_nanoseconds() >= existing.deadline_boottime_nanoseconds
    {
        return Err(ControllerExecutionPreissueErrorV1::Expired);
    }
    Ok(existing)
}

fn persist_preissue(
    controller: &mut Journal,
    record: &ControllerExecutionPreissueV1,
) -> Result<(), ControllerExecutionPreissueErrorV1> {
    let transaction_hash: [u8; 32] = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(record.execution.as_bytes())
        .chain_update(record.create_operation.as_bytes())
        .finalize()
        .into();
    let transaction_id: [u8; 16] = transaction_hash[..16]
        .try_into()
        .map_err(|_| ControllerExecutionPreissueErrorV1::NotCurrent)?;
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::ControllerExecutionPreissue,
            record.execution.as_bytes().to_vec(),
            record.encode(),
        )],
    )?;
    controller
        .commit(&transaction)
        .map_err(|_| ControllerExecutionPreissueErrorV1::OutcomeUnknown)?;
    Ok(())
}

fn record_digest(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(RECORD_DOMAIN)
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}

#[cfg(test)]
mod tests {
    use std::fs::{self, Permissions};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use aos_proto::aos::sandbox::v1::Command;
    use aos_sandbox_core::RawClockProvenance;

    use crate::JournalLimits;

    use super::*;

    fn fixture_record() -> ControllerExecutionPreissueV1 {
        let mut record = ControllerExecutionPreissueV1 {
            execution: ExecutionId::from_bytes([1; 16]),
            create_operation: OperationId::from_bytes([2; 16]),
            source_digest: ObjectDigest::from_bytes([3; 32]),
            maximum_stdout_bytes: 5,
            maximum_stderr_bytes: 7,
            controller_source_sequence: 9,
            host_boot_id: [4; 16],
            deadline_boottime_nanoseconds: 100,
            issuer_nonce: [5; 32],
            record_digest: ObjectDigest::from_bytes([0; 32]),
        };
        record.record_digest = record_digest(&record.encode()[..152]);
        record
    }

    #[test]
    fn record_rejects_tampering_and_preserves_one_shot_identity() {
        let record = fixture_record();
        let bytes = record.encode();
        assert_eq!(
            ControllerExecutionPreissueV1::decode(&bytes).unwrap(),
            record
        );

        let mut tampered = bytes;
        tampered[80] ^= 1;
        assert!(ControllerExecutionPreissueV1::decode(&tampered).is_err());
    }

    #[test]
    fn protected_cold_replay_retains_exact_original_nonce() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let (mut journal, _) = Journal::open_protected_at_uid(
            directory.path(),
            "controller.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        let record = fixture_record();

        persist_preissue(&mut journal, &record).unwrap();
        drop(journal);

        let (reopened, _) = Journal::open_protected_at_uid(
            directory.path(),
            "controller.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        reopened.ensure_protected_authority().unwrap();
        let recovered = reopened
            .get(
                RecordNamespace::ControllerExecutionPreissue,
                record.execution.as_bytes(),
            )
            .and_then(|bytes| ControllerExecutionPreissueV1::decode(bytes).ok())
            .unwrap();
        assert_eq!(recovered, record);
        assert_eq!(recovered.issuer_nonce(), [5; 32]);
    }

    #[test]
    fn replay_rejects_expiry_reboot_and_foreign_source() {
        let record = fixture_record();
        let source = SourceIdentityV1 {
            digest: record.source_digest,
            stdout: record.maximum_stdout_bytes,
            stderr: record.maximum_stderr_bytes,
            execution: record.execution,
            create_operation: record.create_operation,
        };
        let provenance = RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap();
        let sample = |boot, boottime| {
            RawPairedClockSample::new_untrusted(provenance, boot, 1, boottime).unwrap()
        };

        assert_eq!(
            validate_existing(record.clone(), source, sample([4; 16], 99)).unwrap(),
            record
        );
        assert!(matches!(
            validate_existing(record.clone(), source, sample([4; 16], 100)),
            Err(ControllerExecutionPreissueErrorV1::Expired)
        ));
        assert!(matches!(
            validate_existing(record.clone(), source, sample([6; 16], 99)),
            Err(ControllerExecutionPreissueErrorV1::Expired)
        ));
        assert!(matches!(
            validate_existing(
                record,
                SourceIdentityV1 {
                    digest: ObjectDigest::from_bytes([9; 32]),
                    ..source
                },
                sample([4; 16], 99),
            ),
            Err(ControllerExecutionPreissueErrorV1::NotCurrent)
        ));
    }

    #[test]
    fn accepted_output_split_is_exact_and_never_inferred() {
        let detached = Command {
            io_mode: ExecutionIoMode::EXECUTION_IO_MODE_DETACHED_CAPTURE.into(),
            detached_capture_bytes: 9,
            maximum_stdout_bytes: Some(7),
            maximum_stderr_bytes: Some(2),
            ..Default::default()
        };
        assert_eq!(accepted_stream_ceiling(&detached).unwrap(), (7, 2));

        let missing_stderr = Command {
            maximum_stderr_bytes: None,
            ..detached.clone()
        };
        assert!(accepted_stream_ceiling(&missing_stderr).is_err());

        let wrong_sum = Command {
            maximum_stderr_bytes: Some(1),
            ..detached
        };
        assert!(accepted_stream_ceiling(&wrong_sum).is_err());

        let stream = Command {
            io_mode: ExecutionIoMode::EXECUTION_IO_MODE_STREAM.into(),
            ..Default::default()
        };
        assert_eq!(accepted_stream_ceiling(&stream).unwrap(), (0, 0));

        let nonzero_stream = Command {
            detached_capture_bytes: 1,
            ..stream
        };
        assert!(accepted_stream_ceiling(&nonzero_stream).is_err());
    }
}
