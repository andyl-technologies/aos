//! Protected, nonauthorizing Controller custody of one canonical execution spec.
//!
//! The AOSCSI01 attempt stores exact accepted-Create and independently observed
//! Controller, environment, output, and Host-argument heads with the canonical
//! specification. Its source producer holds Controller and environment writers
//! through append. Host output settlement and argument custody are historical
//! receipts; neither holds the Host or physical Storage head through a future
//! effect handoff. Reopen is audit and recovery input, never an Authorize grant.
//!
//! ```text
//! AOSCSI01 || execution:16 || Create-operation:16 || accepted-request-digest:32
//!          || source-heads:344 || Controller-sequence:u64be
//!          || spec-length:u32be || spec-digest:32 || canonical-spec
//!          || SHA256("aos.sandbox.controller-execution-spec-attempt.v1\0" || preceding):32
//! ```

use aos_sandbox_core::{
    DecodeLimits, ExecutionId, ExecutionSpecV1, ObjectDigest, OperationId, RawPairedClockSample,
    decode_execution_spec_v1, encode_execution_spec_v1, execution_spec_digest_v1,
};
use aos_sandbox_protocol::host_execution::MAXIMUM_HOST_EXECUTION_SPEC_BYTES;
use sha2::{Digest as _, Sha256};

use crate::controller_execution_argument_receipt::AuthenticatedControllerHostArgumentObservationV1;
use crate::environment::EnvironmentProtectedJournalOwnerV1;
use crate::execution_parent_resource::ExecutionParentResourceSourceV1;
use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::runtime_execution::{
    ControllerExecutionSpecPreviewV1, ControllerExecutionSpecSourceHeadsV1,
    ProtectedExecutionSpecProducerErrorV1, prepare_controller_execution_spec_preview_v1,
};
use crate::runtime_scope::CurrentAssignmentTarget;
use crate::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};

const MAGIC: &[u8; 8] = b"AOSCSI01";
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.controller-execution-spec-attempt.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.controller-execution-spec-attempt-tx.v1\0";
const SPEC_DOMAIN: &[u8] = b"aos-sandbox-execution-spec-v1\0";
const HEAD_BYTES: usize = 10 * 32 + 3 * 8;
const PREFIX_BYTES: usize = 8 + 16 + 16 + 32 + HEAD_BYTES + 8 + 4 + 32;
const MINIMUM_RECORD_BYTES: usize = PREFIX_BYTES + 1 + 32;
const MAXIMUM_RECORD_BYTES: usize = PREFIX_BYTES + MAXIMUM_HOST_EXECUTION_SPEC_BYTES + 32;

/// Reports stale, equivocal, corrupt, or ambiguous protected attempt custody.
#[derive(Debug, thiserror::Error)]
pub enum ControllerExecutionSpecAttemptErrorV1 {
    /// The exact source cut, record, or canonical spec bytes differ.
    #[error("execution specification attempt differs from its protected source")]
    Mismatch,
    /// A previous attempt exists for this execution and cannot be replaced.
    #[error("execution specification attempt already exists with another source")]
    Conflict,
    /// A protected append may have committed; reopen before any further work.
    #[error("execution specification attempt append is ambiguous; reopen Controller custody")]
    OutcomeUnknown,
    /// Current independent sources cannot produce an exact canonical spec.
    #[error(transparent)]
    Source(#[from] ProtectedExecutionSpecProducerErrorV1),
    /// The protected Controller journal is unavailable.
    #[error(transparent)]
    Journal(#[from] JournalError),
}

/// Retains exact canonical bytes and source heads for a single Create attempt.
///
/// This record is deliberately incapable of authorizing a Host effect. A later
/// admission owner must establish and retain all independent Host and Storage
/// holds under an ordered, recoverable barrier before signing a grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerExecutionSpecAttemptV1 {
    execution: ExecutionId,
    create_operation: OperationId,
    accepted_request_digest: ObjectDigest,
    source_heads: ControllerExecutionSpecSourceHeadsV1,
    controller_sequence: u64,
    specification_digest: ObjectDigest,
    specification_bytes: Vec<u8>,
    record_digest: ObjectDigest,
}

impl ControllerExecutionSpecAttemptV1 {
    /// Returns the exact execution identity.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the accepted Create operation.
    #[must_use]
    pub const fn create_operation(&self) -> OperationId {
        self.create_operation
    }

    /// Returns the exact accepted public request commitment.
    #[must_use]
    pub const fn accepted_request_digest(&self) -> ObjectDigest {
        self.accepted_request_digest
    }

    /// Returns the independent source heads observed for this attempt.
    #[must_use]
    pub const fn source_heads(&self) -> ControllerExecutionSpecSourceHeadsV1 {
        self.source_heads
    }

    /// Returns the Controller journal sequence before the attempt append.
    #[must_use]
    pub const fn controller_sequence(&self) -> u64 {
        self.controller_sequence
    }

    /// Returns the domain-separated canonical spec digest.
    #[must_use]
    pub const fn specification_digest(&self) -> ObjectDigest {
        self.specification_digest
    }

    /// Borrows the exact canonical specification retained by the Controller.
    #[must_use]
    pub fn specification_bytes(&self) -> &[u8] {
        &self.specification_bytes
    }

    /// Decodes the retained canonical spec and checks its attempt identity.
    ///
    /// The returned model is historical custody. Current assignment, Host,
    /// and Storage authority must be established separately before dispatch.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid canonical bytes or a spec that disagrees
    /// with the protected execution, Create operation, or source heads.
    pub fn decoded_specification(
        &self,
    ) -> Result<ExecutionSpecV1, ControllerExecutionSpecAttemptErrorV1> {
        let limits = DecodeLimits {
            maximum_bytes: MAXIMUM_HOST_EXECUTION_SPEC_BYTES,
            ..DecodeLimits::default()
        };
        let specification = decode_execution_spec_v1(&self.specification_bytes, limits)
            .map_err(|_| ControllerExecutionSpecAttemptErrorV1::Mismatch)?;
        if specification.execution() != self.execution
            || specification.audit().as_bytes() != self.create_operation.as_bytes()
            || specification.target().assignment_digest() != self.source_heads.assignment_digest
            || specification.target().assignment_epoch().get() != self.source_heads.assignment_epoch
            || specification.environment_generation().get()
                != self.source_heads.environment_generation
            || encode_execution_spec_v1(&specification) != self.specification_bytes
            || execution_spec_digest_v1(&specification) != self.specification_digest
        {
            return Err(ControllerExecutionSpecAttemptErrorV1::Mismatch);
        }
        Ok(specification)
    }

    /// Returns the complete immutable record commitment.
    #[must_use]
    pub const fn record_digest(&self) -> ObjectDigest {
        self.record_digest
    }

    fn from_preview(
        preview: &ControllerExecutionSpecPreviewV1,
        create_operation: OperationId,
        controller_sequence: u64,
    ) -> Result<Self, ControllerExecutionSpecAttemptErrorV1> {
        let specification = preview.specification();
        if specification.audit().as_bytes() != create_operation.as_bytes()
            || specification.execution().as_bytes() == &[0; 16]
            || create_operation.as_bytes() == &[0; 16]
            || controller_sequence == 0
            || !valid_spec_size(preview.canonical_bytes().len())
            || digest_spec(preview.canonical_bytes()) != preview.digest()
            || specification.target().assignment_digest()
                != preview.source_heads().assignment_digest
            || specification.target().assignment_epoch().get()
                != preview.source_heads().assignment_epoch
            || specification.environment_generation().get()
                != preview.source_heads().environment_generation
        {
            return Err(ControllerExecutionSpecAttemptErrorV1::Mismatch);
        }
        let mut record = Self {
            execution: specification.execution(),
            create_operation,
            accepted_request_digest: preview.accepted_request_digest(),
            source_heads: preview.source_heads(),
            controller_sequence,
            specification_digest: preview.digest(),
            specification_bytes: preview.canonical_bytes().to_vec(),
            record_digest: ObjectDigest::from_bytes([0; 32]),
        };
        record.record_digest = digest_record(&record.encode_without_digest());
        Ok(record)
    }

    fn matches_preview(&self, preview: &ControllerExecutionSpecPreviewV1) -> bool {
        self.execution == preview.specification().execution()
            && self.create_operation.as_bytes() == preview.specification().audit().as_bytes()
            && self.accepted_request_digest == preview.accepted_request_digest()
            && self.source_heads == preview.source_heads()
            && self.specification_digest == preview.digest()
            && self.specification_bytes == preview.canonical_bytes()
    }

    fn encode_without_digest(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PREFIX_BYTES + self.specification_bytes.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(self.execution.as_bytes());
        bytes.extend_from_slice(self.create_operation.as_bytes());
        bytes.extend_from_slice(self.accepted_request_digest.as_bytes());
        self.source_heads.encode_into(&mut bytes);
        bytes.extend_from_slice(&self.controller_sequence.to_be_bytes());
        bytes.extend_from_slice(&(self.specification_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.specification_digest.as_bytes());
        bytes.extend_from_slice(&self.specification_bytes);
        bytes
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = self.encode_without_digest();
        bytes.extend_from_slice(self.record_digest.as_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, ControllerExecutionSpecAttemptErrorV1> {
        if bytes.len() < MINIMUM_RECORD_BYTES
            || bytes.len() > MAXIMUM_RECORD_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
        {
            return Err(ControllerExecutionSpecAttemptErrorV1::Mismatch);
        }
        let mut cursor = 8;
        let execution = ExecutionId::from_bytes(read_array::<16>(bytes, &mut cursor)?);
        let create_operation = OperationId::from_bytes(read_array::<16>(bytes, &mut cursor)?);
        let accepted_request_digest = ObjectDigest::from_bytes(read_array(bytes, &mut cursor)?);
        let source_heads = ControllerExecutionSpecSourceHeadsV1::decode_from(bytes, &mut cursor)?;
        let controller_sequence = u64::from_be_bytes(read_array(bytes, &mut cursor)?);
        let specification_length =
            u32::from_be_bytes(read_array::<4>(bytes, &mut cursor)?) as usize;
        let specification_digest = ObjectDigest::from_bytes(read_array(bytes, &mut cursor)?);
        if !valid_spec_size(specification_length)
            || bytes.len() != PREFIX_BYTES + specification_length + 32
        {
            return Err(ControllerExecutionSpecAttemptErrorV1::Mismatch);
        }
        let specification_bytes = bytes[cursor..cursor + specification_length].to_vec();
        cursor += specification_length;
        let record_digest = ObjectDigest::from_bytes(read_array(bytes, &mut cursor)?);
        let record = Self {
            execution,
            create_operation,
            accepted_request_digest,
            source_heads,
            controller_sequence,
            specification_digest,
            specification_bytes,
            record_digest,
        };
        if cursor != bytes.len()
            || record.execution.as_bytes() == &[0; 16]
            || record.create_operation.as_bytes() == &[0; 16]
            || record.accepted_request_digest.as_bytes() == &[0; 32]
            || record.controller_sequence == 0
            || digest_spec(&record.specification_bytes) != record.specification_digest
            || digest_record(&bytes[..bytes.len() - 32]) != record.record_digest
        {
            return Err(ControllerExecutionSpecAttemptErrorV1::Mismatch);
        }
        record.decoded_specification()?;
        Ok(record)
    }
}

impl ControllerExecutionSpecSourceHeadsV1 {
    /// Encodes the independently named source heads in AOSCSI01 field order.
    ///
    /// These bytes are historical identifiers, not a cross-owner barrier.
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEAD_BYTES);
        self.encode_into(&mut bytes);
        bytes
    }

    fn encode_into(self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(self.assignment_digest.as_bytes());
        bytes.extend_from_slice(&self.assignment_epoch.to_be_bytes());
        bytes.extend_from_slice(self.parent_binding.as_bytes());
        bytes.extend_from_slice(self.parent_projection.as_bytes());
        bytes.extend_from_slice(self.sandbox_spec_record.as_bytes());
        bytes.extend_from_slice(self.environment_activation.as_bytes());
        bytes.extend_from_slice(self.environment_manifest.as_bytes());
        bytes.extend_from_slice(&self.environment_generation.to_be_bytes());
        bytes.extend_from_slice(self.output_claim.as_bytes());
        bytes.extend_from_slice(self.output_settlement.as_bytes());
        bytes.extend_from_slice(self.argument_receipt.as_bytes());
        bytes.extend_from_slice(self.host_argument_custody.as_bytes());
        bytes.extend_from_slice(&self.host_argument_sequence.to_be_bytes());
    }

    fn decode_from(
        bytes: &[u8],
        cursor: &mut usize,
    ) -> Result<Self, ControllerExecutionSpecAttemptErrorV1> {
        let read_digest =
            |cursor: &mut usize| read_array(bytes, cursor).map(ObjectDigest::from_bytes);
        let assignment_digest = read_digest(cursor)?;
        let assignment_epoch = u64::from_be_bytes(read_array(bytes, cursor)?);
        let parent_binding = read_digest(cursor)?;
        let parent_projection = read_digest(cursor)?;
        let sandbox_spec_record = read_digest(cursor)?;
        let environment_activation = read_digest(cursor)?;
        let environment_manifest = read_digest(cursor)?;
        let environment_generation = u64::from_be_bytes(read_array(bytes, cursor)?);
        let output_claim = read_digest(cursor)?;
        let output_settlement = read_digest(cursor)?;
        let argument_receipt = read_digest(cursor)?;
        let host_argument_custody = read_digest(cursor)?;
        let host_argument_sequence = u64::from_be_bytes(read_array(bytes, cursor)?);
        let heads = Self {
            assignment_digest,
            assignment_epoch,
            parent_binding,
            parent_projection,
            sandbox_spec_record,
            environment_activation,
            environment_manifest,
            environment_generation,
            output_claim,
            output_settlement,
            argument_receipt,
            host_argument_custody,
            host_argument_sequence,
        };
        if heads.assignment_epoch == 0
            || heads.environment_generation == 0
            || heads.host_argument_sequence == 0
            || [
                assignment_digest,
                parent_binding,
                parent_projection,
                sandbox_spec_record,
                environment_activation,
                environment_manifest,
                output_claim,
                output_settlement,
                argument_receipt,
                host_argument_custody,
            ]
            .iter()
            .any(|digest| digest.as_bytes() == &[0; 32])
        {
            return Err(ControllerExecutionSpecAttemptErrorV1::Mismatch);
        }
        Ok(heads)
    }
}

fn read_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], ControllerExecutionSpecAttemptErrorV1> {
    let end = cursor
        .checked_add(N)
        .ok_or(ControllerExecutionSpecAttemptErrorV1::Mismatch)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(ControllerExecutionSpecAttemptErrorV1::Mismatch)?
        .try_into()
        .map_err(|_| ControllerExecutionSpecAttemptErrorV1::Mismatch)?;
    *cursor = end;
    Ok(value)
}

fn valid_spec_size(size: usize) -> bool {
    size != 0 && size <= MAXIMUM_HOST_EXECUTION_SPEC_BYTES
}

fn digest_spec(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(SPEC_DOMAIN)
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}

fn digest_record(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(RECORD_DOMAIN)
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}

/// Constructs and durably retains one nonauthorizing spec attempt.
///
/// All Controller and environment sources are rechecked by the preview producer
/// while their writers remain held through the append. A duplicate can replay
/// only byte-identically; an ambiguous append requires protected cold reopen.
/// The stored heads do not hold Host or Storage authority for any later effect.
///
/// # Errors
///
/// Rejects stale source heads, changed replay, unprotected custody, oversized
/// specs, or unresolved append durability.
#[allow(clippy::too_many_arguments)]
pub fn retain_controller_execution_spec_attempt_v1<T>(
    controller: &mut Journal,
    assignment: &CurrentAssignmentTarget,
    environment_owner: &mut EnvironmentProtectedJournalOwnerV1<'_, '_>,
    parent: &ExecutionParentResourceSourceV1,
    argument_observation: &AuthenticatedControllerHostArgumentObservationV1,
    execution: ExecutionId,
    create_operation: OperationId,
    clock: &mut T,
) -> Result<ControllerExecutionSpecAttemptV1, ControllerExecutionSpecAttemptErrorV1>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    controller.ensure_protected_authority()?;
    let preview = prepare_controller_execution_spec_preview_v1(
        controller,
        assignment,
        environment_owner,
        parent,
        argument_observation,
        execution,
        create_operation,
        clock,
    )?;
    if let Some(existing) = load_controller_execution_spec_attempt_v1(controller, execution)? {
        return if existing.matches_preview(&preview) {
            Ok(existing)
        } else {
            Err(ControllerExecutionSpecAttemptErrorV1::Conflict)
        };
    }
    let attempt = ControllerExecutionSpecAttemptV1::from_preview(
        &preview,
        create_operation,
        controller.snapshot_sequence(),
    )?;
    append_attempt(controller, &attempt)?;
    Ok(attempt)
}

/// Reopens exact protected attempt custody for audit and recovery.
///
/// The returned historical record cannot restore fresh Host argument evidence
/// or confer cross-owner effect authority after transport loss or restart.
///
/// # Errors
///
/// Rejects unprotected custody, a corrupt record, or an identity mismatch.
pub fn load_controller_execution_spec_attempt_v1(
    controller: &Journal,
    execution: ExecutionId,
) -> Result<Option<ControllerExecutionSpecAttemptV1>, ControllerExecutionSpecAttemptErrorV1> {
    controller.ensure_protected_authority()?;
    controller
        .get(
            RecordNamespace::ControllerExecutionSpecAttempt,
            execution.as_bytes(),
        )
        .map(ControllerExecutionSpecAttemptV1::decode)
        .transpose()?
        .map(|attempt| {
            if attempt.execution == execution {
                Ok(attempt)
            } else {
                Err(ControllerExecutionSpecAttemptErrorV1::Mismatch)
            }
        })
        .transpose()
}

fn append_attempt(
    controller: &mut Journal,
    attempt: &ControllerExecutionSpecAttemptV1,
) -> Result<(), ControllerExecutionSpecAttemptErrorV1> {
    if let Some(existing) =
        load_controller_execution_spec_attempt_v1(controller, attempt.execution)?
    {
        return if existing == *attempt {
            Ok(())
        } else {
            Err(ControllerExecutionSpecAttemptErrorV1::Conflict)
        };
    }
    let transaction_hash: [u8; 32] = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(attempt.execution.as_bytes())
        .chain_update(attempt.create_operation.as_bytes())
        .finalize()
        .into();
    let transaction_id: [u8; 16] = transaction_hash[..16]
        .try_into()
        .map_err(|_| ControllerExecutionSpecAttemptErrorV1::Mismatch)?;
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::ControllerExecutionSpecAttempt,
            attempt.execution.as_bytes().to_vec(),
            attempt.encode(),
        )],
    )?;
    controller
        .commit(&transaction)
        .map(|_| ())
        .map_err(|_| ControllerExecutionSpecAttemptErrorV1::OutcomeUnknown)
}

#[cfg(test)]
mod tests {
    use std::fs::{self, Permissions};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use aos_sandbox_core::model::spec::ResourceProfile;
    use aos_sandbox_core::model::view::Environment;
    use aos_sandbox_core::model::{AssignmentManifestV1, SandboxAncestry};
    use aos_sandbox_core::{
        AssignmentEpoch, AuditId, DesiredGeneration, ExecutionAccessRouteV1, ExecutionCommandV1,
        ExecutionCredentialsV1, ExecutionDisconnectPolicyV1, ExecutionIoV1,
        ExecutionOutputByteAdmissionV1, ExecutionOutputModeV1, ExecutionResourceAdmissionV1,
        ExecutionResourceRequestV1, ExecutionResourceRequestValueV1, ExecutionResourceSublimitV1,
        ExecutionResourceSublimitValueV1, ExecutionRuntimeArgumentLimitV1, ExecutionTargetV1,
        ExecutionTerminalModeV1, ExecutionTimeoutV1, FeatureRef, IncarnationId, MediaType,
        NamespaceGeneration, NodeId, ObjectDescriptor, PayloadBootId, PortableMediaType,
        PrincipalId, ProjectId, RelativePath, ResourceDimension, ResourceVector, Revision,
        SandboxId, descriptor_for_bytes, resource_profile_digest_v1,
    };

    use crate::JournalLimits;

    use super::*;

    fn descriptor(kind: PortableMediaType, byte: u8) -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new(kind.as_str().to_owned()).unwrap(),
            ObjectDigest::from_bytes([byte; 32]),
            u64::from(byte),
        )
    }

    fn fixture_spec(argument_bytes: usize) -> ExecutionSpecV1 {
        let sandbox = SandboxId::from_bytes([1; 16]);
        let environment = Environment::new(vec![], vec![], vec![], vec![]).unwrap();
        let environment_descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::Environment.as_str().to_owned()).unwrap(),
            &aos_sandbox_core::format::encode_environment(&environment),
        );
        let profile = ResourceProfile::new(vec![]).unwrap();
        let profile_digest = resource_profile_digest_v1(&profile);
        let runtime_profile = FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0).unwrap();
        let assignment = aos_sandbox_core::CanonicalAssignmentManifestV1::new(
            AssignmentManifestV1::new(
                sandbox,
                ProjectId::from_bytes([2; 16]),
                SandboxAncestry::new(sandbox, vec![]).unwrap(),
                IncarnationId::from_bytes([3; 16]),
                NodeId::from_bytes([4; 16]),
                AssignmentEpoch::new(5),
                DesiredGeneration::new(6),
                NamespaceGeneration::new(7),
                descriptor(PortableMediaType::SandboxSpec, 8),
                descriptor(PortableMediaType::Policy, 9),
                environment_descriptor.clone(),
                descriptor(PortableMediaType::View, 10),
                vec![],
                profile_digest,
                ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, 4096),
                vec![runtime_profile.clone()],
            )
            .unwrap(),
        );
        let target = ExecutionTargetV1::new(
            sandbox,
            assignment.manifest().incarnation(),
            assignment.manifest().epoch(),
            assignment.digest(),
            assignment.manifest().namespace_generation(),
            PayloadBootId::new([11; 16]).unwrap(),
        )
        .unwrap();
        let argument_limit = ExecutionRuntimeArgumentLimitV1::new(
            runtime_profile,
            ObjectDigest::from_bytes([12; 32]),
            target.clone(),
            131_072,
        )
        .unwrap();
        let weights = [
            aos_sandbox_core::model::spec::LimitDimension::CpuWeight,
            aos_sandbox_core::model::spec::LimitDimension::IoWeight,
        ];
        let requested = weights
            .into_iter()
            .map(|dimension| {
                ExecutionResourceRequestV1::new(
                    dimension,
                    ExecutionResourceRequestValueV1::RelativeWeight(100),
                )
                .unwrap()
            })
            .collect();
        let admitted = weights
            .into_iter()
            .map(|dimension| {
                ExecutionResourceSublimitV1::new(
                    dimension,
                    ExecutionResourceSublimitValueV1::RelativeWeight(100),
                )
                .unwrap()
            })
            .collect();
        let resources = ExecutionResourceAdmissionV1::new(
            requested,
            admitted,
            profile,
            profile_digest,
            ExecutionOutputByteAdmissionV1::new(0, 0, assignment).unwrap(),
        )
        .unwrap();
        let command = ExecutionCommandV1::new(
            vec![b"/bin/true".to_vec(), vec![b'x'; argument_bytes]],
            vec![],
            RelativePath::new(vec![]).unwrap(),
            ExecutionCredentialsV1::new(1000, 1000, vec![]).unwrap(),
        )
        .unwrap();
        let io = ExecutionIoV1::new(
            ExecutionTerminalModeV1::None,
            ExecutionOutputModeV1::Capture {
                maximum_stdout_bytes: 0,
                maximum_stderr_bytes: 0,
            },
            ExecutionDisconnectPolicyV1::Continue,
            ExecutionAccessRouteV1::Detached,
        )
        .unwrap();
        ExecutionSpecV1::new(
            ExecutionId::from_bytes([1; 16]),
            target,
            environment_descriptor,
            environment,
            Revision::new(11),
            command,
            argument_limit,
            resources,
            io,
            ExecutionTimeoutV1::new(1_000_000_000).unwrap(),
            PrincipalId::from_bytes([13; 16]),
            AuditId::from_bytes([2; 16]),
        )
        .unwrap()
    }

    fn fixture_record(argument_bytes: usize) -> ControllerExecutionSpecAttemptV1 {
        let digest = |byte| ObjectDigest::from_bytes([byte; 32]);
        let specification = fixture_spec(argument_bytes);
        let specification_bytes = encode_execution_spec_v1(&specification);
        let mut record = ControllerExecutionSpecAttemptV1 {
            execution: ExecutionId::from_bytes([1; 16]),
            create_operation: OperationId::from_bytes([2; 16]),
            accepted_request_digest: digest(3),
            source_heads: ControllerExecutionSpecSourceHeadsV1 {
                assignment_digest: specification.target().assignment_digest(),
                assignment_epoch: 5,
                parent_binding: digest(6),
                parent_projection: digest(7),
                sandbox_spec_record: digest(8),
                environment_activation: digest(9),
                environment_manifest: digest(10),
                environment_generation: 11,
                output_claim: digest(12),
                output_settlement: digest(13),
                argument_receipt: digest(14),
                host_argument_custody: digest(15),
                host_argument_sequence: 16,
            },
            controller_sequence: 17,
            specification_digest: digest_spec(&specification_bytes),
            specification_bytes,
            record_digest: digest(0),
        };
        record.record_digest = digest_record(&record.encode_without_digest());
        record
    }

    fn protected_journal(path: &std::path::Path) -> Journal {
        fs::set_permissions(path, Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(path).unwrap().uid();
        Journal::open_protected_at_uid(path, "controller.journal", JournalLimits::default(), uid)
            .unwrap()
            .0
    }

    #[test]
    fn cold_replay_after_lost_response_preserves_exact_spec_and_heads() {
        let directory = tempfile::tempdir().unwrap();
        let mut journal = protected_journal(directory.path());
        let attempt = fixture_record(257);
        append_attempt(&mut journal, &attempt).unwrap();
        drop(journal);

        let mut reopened = protected_journal(directory.path());
        let recovered = load_controller_execution_spec_attempt_v1(&reopened, attempt.execution())
            .unwrap()
            .unwrap();
        assert_eq!(recovered, attempt);
        append_attempt(&mut reopened, &attempt).unwrap();

        let mut changed = attempt.clone();
        changed.source_heads.environment_generation += 1;
        changed.record_digest = digest_record(&changed.encode_without_digest());
        assert!(matches!(
            append_attempt(&mut reopened, &changed),
            Err(ControllerExecutionSpecAttemptErrorV1::Conflict)
        ));

        let mut changed = attempt.clone();
        changed.source_heads.assignment_digest = ObjectDigest::from_bytes([19; 32]);
        changed.record_digest = digest_record(&changed.encode_without_digest());
        assert!(matches!(
            append_attempt(&mut reopened, &changed),
            Err(ControllerExecutionSpecAttemptErrorV1::Conflict)
        ));

        let mut changed = attempt.clone();
        changed.source_heads.output_settlement = ObjectDigest::from_bytes([20; 32]);
        changed.record_digest = digest_record(&changed.encode_without_digest());
        assert!(matches!(
            append_attempt(&mut reopened, &changed),
            Err(ControllerExecutionSpecAttemptErrorV1::Conflict)
        ));

        let mut changed = attempt.clone();
        changed.source_heads.host_argument_custody = ObjectDigest::from_bytes([21; 32]);
        changed.record_digest = digest_record(&changed.encode_without_digest());
        assert!(matches!(
            append_attempt(&mut reopened, &changed),
            Err(ControllerExecutionSpecAttemptErrorV1::Conflict)
        ));
    }

    #[test]
    fn record_rejects_changed_heads_spec_and_trailing_bytes() {
        let record = fixture_record(17);
        let mut bytes = record.encode();
        bytes[100] ^= 1;
        assert!(ControllerExecutionSpecAttemptV1::decode(&bytes).is_err());
        let mut bytes = record.encode();
        bytes[PREFIX_BYTES] ^= 1;
        assert!(ControllerExecutionSpecAttemptV1::decode(&bytes).is_err());
        let mut bytes = record.encode();
        bytes.push(0);
        assert!(ControllerExecutionSpecAttemptV1::decode(&bytes).is_err());
    }

    #[test]
    fn record_rejects_digest_consistent_identity_and_source_substitution() {
        let original = fixture_record(17);
        assert_eq!(
            original.decoded_specification().unwrap().execution(),
            original.execution()
        );

        let mut changed = original.clone();
        changed.execution = ExecutionId::from_bytes([22; 16]);
        changed.record_digest = digest_record(&changed.encode_without_digest());
        assert!(ControllerExecutionSpecAttemptV1::decode(&changed.encode()).is_err());

        let mut changed = original.clone();
        changed.create_operation = OperationId::from_bytes([23; 16]);
        changed.record_digest = digest_record(&changed.encode_without_digest());
        assert!(ControllerExecutionSpecAttemptV1::decode(&changed.encode()).is_err());

        for mutate in [
            |record: &mut ControllerExecutionSpecAttemptV1| {
                record.source_heads.assignment_digest = ObjectDigest::from_bytes([24; 32]);
            },
            |record: &mut ControllerExecutionSpecAttemptV1| {
                record.source_heads.assignment_epoch += 1;
            },
            |record: &mut ControllerExecutionSpecAttemptV1| {
                record.source_heads.environment_generation += 1;
            },
        ] {
            let mut changed = original.clone();
            mutate(&mut changed);
            changed.record_digest = digest_record(&changed.encode_without_digest());
            assert!(ControllerExecutionSpecAttemptV1::decode(&changed.encode()).is_err());
        }
    }

    #[test]
    fn record_rejects_a_canonical_spec_for_another_create() {
        let mut changed = fixture_record(17);
        let mut canonical = encode_execution_spec_v1(&fixture_spec(18));
        let last = canonical.len() - 1;
        canonical[last] = 23;
        let substituted = decode_execution_spec_v1(&canonical, DecodeLimits::default()).unwrap();
        assert_ne!(
            substituted.audit().as_bytes(),
            changed.create_operation.as_bytes()
        );
        changed.specification_bytes = canonical;
        changed.specification_digest = digest_spec(&changed.specification_bytes);
        changed.record_digest = digest_record(&changed.encode_without_digest());
        assert!(ControllerExecutionSpecAttemptV1::decode(&changed.encode()).is_err());
    }
}
