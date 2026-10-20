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

use aos_sandbox_model::{
    DecodeLimits, ExecutionId, ExecutionSpecV1, ObjectDigest, OperationId, RawPairedClockSample,
    decode_execution_spec_v1, encode_execution_spec_v1, execution_spec_digest_v1,
};
use aos_sandbox_protocol::host_execution::MAXIMUM_HOST_EXECUTION_SPEC_BYTES;
use sha2::{Digest as _, Sha256};

use crate::controller_execution_argument_receipt::AuthenticatedControllerHostArgumentObservationV1;
use crate::environment::EnvironmentProtectedJournalOwnerV1;
use crate::execution_parent_resource::ExecutionParentResourceSourceV1;
use aos_sandbox_broker::paired_clock::ProtectedOwnershipClockError;
use crate::runtime_execution::{
    ControllerExecutionSpecPreviewV1, ControllerExecutionSpecSourceHeadsV1,
    ProtectedExecutionSpecProducerErrorV1, prepare_controller_execution_spec_preview_v1,
};
use crate::runtime_scope::CurrentAssignmentTarget;
use crate::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};

const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.controller-execution-spec-attempt-tx.v1\0";
use aos_sandbox_protocol::execution_spec_attempt::{
    ExecutionSpecAttemptFieldsV1, ExecutionSpecAttemptDataErrorV1,
    PREFIX_BYTES, MINIMUM_RECORD_BYTES, MAXIMUM_RECORD_BYTES,
    valid_spec_size, digest_spec, digest_record,
};
pub use aos_sandbox_protocol::execution_spec_attempt::execution_spec_attempt_request_digest_v1;

/// Reports stale, equivocal, corrupt, or ambiguous protected attempt custody.
#[derive(Debug, thiserror::Error)]
pub enum ControllerExecutionSpecAttemptErrorV1 {
    /// The genuine SAME18 scope refused the exact reached append requirement.
    #[error(transparent)]
    Receiving(#[from] crate::ResourceReservationErrorV1),
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

    /// Checks the exact accepted Create body retained with this attempt.
    #[must_use]
    pub fn matches_accepted_request(&self, canonical_request: &[u8]) -> bool {
        self.accepted_request_digest == execution_spec_attempt_request_digest_v1(canonical_request)
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
        self.fields_v1().decoded_specification().map_err(Into::into)
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

    fn fields_v1(&self) -> ExecutionSpecAttemptFieldsV1<'_> {
        ExecutionSpecAttemptFieldsV1 {
            execution: self.execution, create_operation: self.create_operation,
            accepted_request_digest: self.accepted_request_digest,
            source_heads: self.source_heads, controller_sequence: self.controller_sequence,
            specification_digest: self.specification_digest,
            specification_bytes: &self.specification_bytes, record_digest: self.record_digest,
        }
    }

    fn encode_without_digest(&self) -> Vec<u8> {
        self.fields_v1().encode_without_digest()
    }

    fn encode(&self) -> Vec<u8> {
        self.fields_v1().encode()
    }

    fn decode(bytes: &[u8]) -> Result<Self, ControllerExecutionSpecAttemptErrorV1> {
        let fields = ExecutionSpecAttemptFieldsV1::decode(bytes)?;
        Ok(Self {
            execution: fields.execution, create_operation: fields.create_operation,
            accepted_request_digest: fields.accepted_request_digest,
            source_heads: fields.source_heads, controller_sequence: fields.controller_sequence,
            specification_digest: fields.specification_digest,
            specification_bytes: fields.specification_bytes.to_vec(), record_digest: fields.record_digest,
        })
    }

    /// Encodes this historical record without granting Host admission.
    #[must_use]
    pub fn canonical_bytes_v1(&self) -> Vec<u8> {
        self.encode()
    }
}

impl From<ExecutionSpecAttemptDataErrorV1> for ControllerExecutionSpecAttemptErrorV1 {
    fn from(error: ExecutionSpecAttemptDataErrorV1) -> Self {
        match error {
            ExecutionSpecAttemptDataErrorV1::Mismatch => Self::Mismatch,
        }
    }
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
    receiving: &mut crate::controller_execution_operation::ControllerExecutionReadReceivingLoanV1<'_, '_>,
    bank: &crate::ControllerResourceBankOpeningV1,
    profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
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
    // The pure builder is bounded by the already admitted model/encoding
    // peak. Its actual canonical width now prices the SAME native writer
    // before record encoding, frame construction or append begins.
    let record_bytes = PREFIX_BYTES.checked_add(attempt.specification_bytes().len())
        .and_then(|bytes| bytes.checked_add(32))
        .ok_or(ControllerExecutionSpecAttemptErrorV1::Mismatch)?;
    receiving.admit_controller_append_v1(bank, controller, profile, std::iter::once(
        aos_sandbox_journal::geometry::RecordShape { key_bytes: attempt.execution().as_bytes().len(), value_bytes: Some(record_bytes) },
    ))?;
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
    ).map_err(JournalError::from)?;
    controller
        .commit(&transaction)
        .map(|_| ())
        .map_err(|_| ControllerExecutionSpecAttemptErrorV1::OutcomeUnknown)
}

#[cfg(test)]
mod tests {
    use std::fs::{self, Permissions};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use aos_sandbox_model::model::spec::ResourceProfile;
    use aos_sandbox_model::model::view::Environment;
    use aos_sandbox_model::model::{AssignmentManifestV1, SandboxAncestry};
    use aos_sandbox_model::{
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

    const ACCEPTED_REQUEST_FIXTURE: &[u8] = b"\x0a\x01\x01";

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
            &aos_sandbox_model::format::encode_environment(&environment),
        );
        let profile = ResourceProfile::new(vec![]).unwrap();
        let profile_digest = resource_profile_digest_v1(&profile);
        let runtime_profile = FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0).unwrap();
        let assignment = aos_sandbox_model::CanonicalAssignmentManifestV1::new(
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
            aos_sandbox_model::model::spec::LimitDimension::CpuWeight,
            aos_sandbox_model::model::spec::LimitDimension::IoWeight,
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
            accepted_request_digest: execution_spec_attempt_request_digest_v1(
                ACCEPTED_REQUEST_FIXTURE,
            ),
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
        assert!(recovered.matches_accepted_request(ACCEPTED_REQUEST_FIXTURE));
        assert!(!recovered.matches_accepted_request(b"\x0a\x01\x02"));
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
    fn attempt_request_digest_has_stable_canonical_body_semantics() {
        assert_eq!(
            *execution_spec_attempt_request_digest_v1(ACCEPTED_REQUEST_FIXTURE).as_bytes(),
            [
                0xe2, 0x70, 0xef, 0x6d, 0x30, 0x67, 0x3a, 0xbe, 0x7a, 0xfc, 0xa8, 0x05, 0x76, 0xc5,
                0x1b, 0xe1, 0x30, 0x51, 0x6f, 0x8d, 0xd1, 0x32, 0x4d, 0x7f, 0xc3, 0x6f, 0x6c, 0x10,
                0x6c, 0x5e, 0x1e, 0xba,
            ]
        );
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

    #[test]
    fn full_host_content_limit_fits_one_protected_record() {
        assert!(valid_spec_size(MAXIMUM_HOST_EXECUTION_SPEC_BYTES));
        assert!(!valid_spec_size(MAXIMUM_HOST_EXECUTION_SPEC_BYTES + 1));
        assert_eq!(
            MAXIMUM_RECORD_BYTES,
            PREFIX_BYTES + MAXIMUM_HOST_EXECUTION_SPEC_BYTES + 32
        );
        assert!(MAXIMUM_RECORD_BYTES + 7 + 16 < JournalLimits::default().maximum_record_bytes);
    }

    fn storage_registration_fixture(record: &ControllerExecutionSpecAttemptV1) -> Vec<u8> {
        use aos_sandbox_api::aos::sandbox::local::v1::StorageOutputRegistrationResponseV1;
        use buffa::Message as _;

        let mut row = vec![1; 177];
        row[..8].copy_from_slice(b"AOSEOR03");
        row[8..24].copy_from_slice(record.execution().as_bytes());
        row[24..40].copy_from_slice(record.create_operation().as_bytes());
        row[40..72].copy_from_slice(record.source_heads().assignment_digest.as_bytes());
        row[72..104].copy_from_slice(record.source_heads().output_claim.as_bytes());
        row[104..128].fill(0);
        row[128] = 1;
        row[129..145].fill(0);
        let mut marker = vec![2; 184];
        marker[..8].copy_from_slice(b"AOSEOS01");
        marker[24..40].copy_from_slice(&row[8..24]);
        marker[40..56].copy_from_slice(&row[24..40]);
        marker[120..152].copy_from_slice(&Sha256::digest(&row));
        StorageOutputRegistrationResponseV1 { canonical_reservation: row,
            canonical_original_marker: marker, ..Default::default() }.encode_to_vec()
    }

    #[test]
    fn versioned_host_content_rejects_another_exact_width_storage_claim() {
        use aos_sandbox_api::aos::sandbox::local::v1::StorageOutputRegistrationResponseV1;
        use aos_sandbox_protocol::host_execution::admission_content::HostExecutionAdmissionContentV5;
        use aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2;
        use buffa::Message as _;
        let mut record = fixture_record(257);
        let capture_source = physical_capture_source_fixture(&mut record);
        let capture_response = physical_capture_attempt_response_fixture(&capture_source);
        let capture_source = StorageCaptureGrantSourceV2::from_canonical_bytes_v2(&capture_source).unwrap();
        let attempt = record.canonical_bytes_v1();
        let mut storage = StorageOutputRegistrationResponseV1::decode_from_slice(&storage_registration_fixture(&record)).unwrap();
        storage.canonical_reservation[72..104].fill(99);
        storage.canonical_original_marker[120..152].copy_from_slice(&Sha256::digest(&storage.canonical_reservation));

        assert!(HostExecutionAdmissionContentV5::new_capture_v5(&attempt, &storage.encode_to_vec(), &capture_source, &capture_response).is_err());
    }

    #[test]
    fn versioned_host_content_rejects_changed_lengths_and_checksum() {
        use aos_sandbox_protocol::host_execution::admission_content::HostExecutionAdmissionContentV5;
        use aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2;
        let mut record = fixture_record(257);
        let capture_source = physical_capture_source_fixture(&mut record);
        let capture_response = physical_capture_attempt_response_fixture(&capture_source);
        let capture_source = StorageCaptureGrantSourceV2::from_canonical_bytes_v2(&capture_source).unwrap();
        let attempt = record.canonical_bytes_v1();
        let storage = storage_registration_fixture(&record);
        let original = HostExecutionAdmissionContentV5::new_capture_v5(&attempt, &storage, &capture_source, &capture_response).unwrap().encode().unwrap();
        let mut length = original.clone();
        length[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        let mut checksum = original;
        let last = checksum.len() - 1;
        checksum[last] ^= 1;

        assert!(HostExecutionAdmissionContentV5::decode(&length).is_err());
        assert!(HostExecutionAdmissionContentV5::decode(&checksum).is_err());
    }

    #[test]
    fn actual_host_apply_decoder_verifies_the_complete_version_five_descriptor() {
        use aos_sandbox_api::aos::sandbox::local::v1::{ApplyHostExecutionRequestV1,
            HostExecutionActionV1, RequestHeader, Audience};
        use aos_sandbox_protocol::host_execution::{HostExecutionSpecContentFieldsV1,
            decode_host_execution_apply_v1};
        use aos_sandbox_protocol::host_execution::admission_content::HostExecutionAdmissionContentV5;
        use aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2;
        use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};
        use buffa::Message as _;

        let mut record = fixture_record(70_000);
        let capture_source = physical_capture_source_fixture(&mut record);
        let capture_response = physical_capture_attempt_response_fixture(&capture_source);
        let capture_source = StorageCaptureGrantSourceV2::from_canonical_bytes_v2(&capture_source).unwrap();
        let attempt = record.canonical_bytes_v1();
        let storage = storage_registration_fixture(&record);
        let content = HostExecutionAdmissionContentV5::new_capture_v5(&attempt, &storage, &capture_source, &capture_response).unwrap().encode().unwrap();
        let source = ObjectDigest::from_bytes([91; 32]);
        let fields = HostExecutionSpecContentFieldsV1::for_grant(&content)
            .bind_lifetime_admission_attempt_v5([81; 16], *record.create_operation().as_bytes(),
                record.execution(), source);
        let request = ApplyHostExecutionRequestV1 {
            header: Some(RequestHeader { protocol_major: 1, request_id: vec![81; 16],
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: 100, maximum_response_bytes: 4096,
                ..Default::default() }).into(),
            operation_id: record.create_operation().as_bytes().to_vec(),
            execution_id: record.execution().as_bytes().to_vec(),
            action: HostExecutionActionV1::HOST_EXECUTION_ACTION_AUTHORIZE.into(),
            source_operation_commitment: source.as_bytes().to_vec(),
            spec_transfer_version: 5, spec_content_bytes: fields.bytes(),
            spec_content_digest: fields.digest().to_vec(),
            spec_attempt_commitment: fields.attempt_commitment().to_vec(),
            ..Default::default()
        };
        let peer = PeerCredentials { pid: Some(1), uid: 0, gid: 0 };
        let policy = PeerPolicy { uid: 0, gid: Some(0), audience: Audience::AUDIENCE_NODE_CONTROLLER };
        let mut decoded = decode_host_execution_apply_v1(&request.encode_to_vec(), peer, policy, 1).unwrap();
        decoded.verify_content(&content).unwrap();
        assert_eq!(decoded.content_version(), 5);
        assert_eq!(decoded.specification().unwrap(), &record.decoded_specification().unwrap());

        let mut relabeled = request;
        relabeled.spec_transfer_version = 1;
        assert!(decode_host_execution_apply_v1(&relabeled.encode_to_vec(), peer, policy, 1).is_err());
        let mut corrupt = content;
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(decoded.verify_content(&corrupt).is_err());
    }


    fn physical_capture_source_fixture(record: &mut ControllerExecutionSpecAttemptV1) -> [u8; 944] {
        use aos_sandbox_protocol::storage_capture_grant::ControllerOutputSettlementPreimageV1;
        let mut settlement = [9; 208];
        settlement[..8].copy_from_slice(b"AOSCIS01");
        settlement[8..24].copy_from_slice(record.execution.as_bytes());
        settlement[24..40].copy_from_slice(record.create_operation.as_bytes());
        settlement[104..112].copy_from_slice(&1_u64.to_be_bytes());
        let checksum = Sha256::new().chain_update(b"aos.sandbox.controller-output-settlement.v1\0")
            .chain_update(&settlement[..176]).finalize();
        settlement[176..].copy_from_slice(&checksum);
        record.source_heads.output_settlement = ControllerOutputSettlementPreimageV1::from_canonical_bytes(
            &settlement).unwrap().record_digest();
        record.record_digest = digest_record(&record.encode_without_digest());

        let specification = decode_execution_spec_v1(&record.specification_bytes,
            DecodeLimits::default()).unwrap();
        let assignment = specification.resources().output_bytes().assignment().broker_assignment().unwrap();
        let storage = aos_sandbox_protocol::storage_output_reserve::continuation
            ::decode_storage_output_registration_response_data_v1(&storage_registration_fixture(record)).unwrap();
        let mut source = [0; 512];
        source[..8].copy_from_slice(b"AOSSCG01");
        source[8..216].copy_from_slice(&settlement);
        source[216..248].copy_from_slice(&Sha256::digest(&storage.canonical_reservation));
        source[248..280].copy_from_slice(record.source_heads.output_claim.as_bytes());
        source[280..296].fill(3);
        source[296..312].copy_from_slice(assignment.sandbox().as_bytes());
        source[312..328].copy_from_slice(assignment.incarnation().as_bytes());
        source[328..336].copy_from_slice(&assignment.epoch().get().to_be_bytes());
        source[336..344].copy_from_slice(&assignment.desired_generation().get().to_be_bytes());
        source[344..376].copy_from_slice(assignment.digest().as_bytes());
        source[376..392].fill(4);
        source[392..408].fill(5);
        source[408..440].fill(6);
        // This is genuine typed zero-byte Capture, not a Stream surrogate.
        source[464..472].copy_from_slice(&4096_u64.to_be_bytes());
        source[472..480].copy_from_slice(&512_u64.to_be_bytes());
        source[480..488].copy_from_slice(&4096_u64.to_be_bytes());
        source[488..496].copy_from_slice(&1_000_000_000_u64.to_be_bytes());
        source[496..512].fill(7);
        use aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2;
        use aos_sandbox_protocol::storage_capture_lifetime::{StorageCaptureExecutionLifetimeDataV2,
            StorageCaptureLifetimeOriginsDataV2};
        use aos_sandbox_model::{RawClockProvenance, RawPairedClockSample};
        let sample = |boot| RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            [4; 16], 100, boot).unwrap();
        let target = sample(1);
        let lease_expiry = 1000;
        let plan_expiry = 900;
        let original_deadline = target.conservative_lease_expiry_deadline_data_v2(lease_expiry, 0).unwrap()
            .min(target.conservative_expiry_deadline_data_v1(plan_expiry).unwrap());
        let origins = StorageCaptureLifetimeOriginsDataV2 {
            original_target_clock: target,
            original_lease_digest: ObjectDigest::from_bytes([20; 32]),
            original_lease_generation: 1,
            original_lease_authority_expires_seconds: lease_expiry,
            original_lease_maximum_clock_skew_seconds: 0,
            original_root_plan_expires_seconds: Some(plan_expiry),
            original_residency_deadline_boottime_nanoseconds: original_deadline,
            first_pre_spawn_clock: sample(2),
            execution_parent_plan_expires_seconds: plan_expiry,
        };
        let lifetime = StorageCaptureExecutionLifetimeDataV2::from_pre_spawn_sources_data_v2(
            &specification, record.create_operation(), record.create_operation(),
            record.accepted_request_digest(), assignment, &origins).unwrap();
        let mut full = [0; 944];
        full[..8].copy_from_slice(b"AOSSCG02");
        full[8..520].copy_from_slice(&source);
        full[520..].copy_from_slice(lifetime.canonical_bytes_v2());
        *StorageCaptureGrantSourceV2::from_canonical_bytes_v2(&full).unwrap().canonical_bytes_v2()
    }

    fn physical_capture_attempt_response_fixture(source: &[u8]) -> Vec<u8> {
        use aos_sandbox_api::aos::sandbox::local::v1::{StorageExecutionCaptureAttemptV1,
            StorageExecutionCaptureAttemptStatusV1};
        use aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2;
        use buffa::Message as _;
        let source = StorageCaptureGrantSourceV2::from_canonical_bytes_v2(source).unwrap();
        let locator = source.locator_v2();
        StorageExecutionCaptureAttemptV1 {
            execution_id: locator.execution().as_bytes().to_vec(),
            create_operation_id: locator.create_operation().as_bytes().to_vec(),
            original_reserve_request_id: locator.original_reserve_request_id().to_vec(),
            grant_source_digest: locator.source_digest().as_bytes().to_vec(),
            output_record_digest: locator.output_record_digest().as_bytes().to_vec(),
            status: StorageExecutionCaptureAttemptStatusV1::STORAGE_EXECUTION_CAPTURE_ATTEMPT_STATUS_EFFECT_POSSIBLE.into(),
            attempt_id: vec![8; 16], durable_attempt_digest: vec![9; 32],
            effective_deadline_boottime_nanoseconds: source.effective_execution_deadline_v2(),
            ..Default::default()
        }.encode_to_vec()
    }

    #[test]
    fn physical_content_preserves_full_spec_and_zero_capture_without_ready_claim() {
        use aos_sandbox_protocol::host_execution::admission_content::HostExecutionAdmissionContentV5;
        use aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2;
        let mut record = fixture_record(70_000);
        let source = physical_capture_source_fixture(&mut record);
        let response = physical_capture_attempt_response_fixture(&source);
        let attempt = record.canonical_bytes_v1();
        let storage = storage_registration_fixture(&record);


        let source_data = StorageCaptureGrantSourceV2::from_canonical_bytes_v2(&source).unwrap();
        let bytes = HostExecutionAdmissionContentV5::new_capture_v5(&attempt, &storage, &source_data, &response)
            .unwrap().encode().unwrap();
        assert_eq!(aos_sandbox_protocol::host_execution::admission_content::capture_encoded_widths_v5(
            attempt.len(), storage.len(), response.len()), Some(bytes.len()));
        let decoded = HostExecutionAdmissionContentV5::decode(&bytes).unwrap();

        assert!(decoded.specification_bytes().unwrap().len() > 65_536);
        assert_eq!(decoded.attempt_bytes(), attempt);
        assert_eq!(decoded.storage_response_bytes(), storage);
        assert_eq!(decoded.specification_bytes().unwrap(), record.specification_bytes());
        assert_eq!(decoded.capture_source_v2().unwrap().canonical_bytes_v2(), &source);
        assert_eq!(decoded.capture_source_v2().unwrap().original_source_v1().output_limits(), (0, 0, 0));
        assert_eq!(decoded.capture_attempt_v1().unwrap().attempt(), Some([8; 16]));
        let mut changed = bytes;
        let last = changed.len() - 1;
        changed[last] ^= 1;
        assert!(HostExecutionAdmissionContentV5::decode(&changed).is_err());
    }

    #[test]
    fn physical_content_rejects_valid_but_foreign_source_or_attempt() {
        use aos_sandbox_protocol::host_execution::admission_content::HostExecutionAdmissionContentV5;
        use aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2;
        let mut record = fixture_record(32);
        let source = physical_capture_source_fixture(&mut record);
        let response = physical_capture_attempt_response_fixture(&source);
        let attempt = record.canonical_bytes_v1();
        let storage = storage_registration_fixture(&record);

        let mut changed = source;
        changed[8 + 216] ^= 1;
        let changed_response = physical_capture_attempt_response_fixture(&changed);
        let changed_data = StorageCaptureGrantSourceV2::from_canonical_bytes_v2(&changed).unwrap();
        assert!(HostExecutionAdmissionContentV5::new_capture_v5(&attempt, &storage, &changed_data, &changed_response).is_err());
        assert!(HostExecutionAdmissionContentV5::new_capture_v5(&attempt, &storage, &changed_data, &response).is_err());
        // Matching response, valid total and allocation still cannot change
        // the actual spec's per-stream Capture ceilings.
        changed = source;
        changed[8 + 440..8 + 448].copy_from_slice(&1_u64.to_be_bytes());
        changed[8 + 448..8 + 456].copy_from_slice(&1_u64.to_be_bytes());
        let changed_response = physical_capture_attempt_response_fixture(&changed);
        let changed_data = StorageCaptureGrantSourceV2::from_canonical_bytes_v2(&changed).unwrap();
        assert!(HostExecutionAdmissionContentV5::new_capture_v5(&attempt, &storage, &changed_data, &changed_response).is_err());
    }

}
