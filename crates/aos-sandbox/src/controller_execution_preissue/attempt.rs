//! Protected Controller custody of the original Host output-reserve attempt.
//!
//! AOSCIA01 freezes the signed method-35 request ID and exact source before
//! the authenticated session may send it. If either journal append is
//! ambiguous, cold recovery may query the original attempt but cannot issue
//! another reserve request for the execution. A Host ABSENT reply is evidence
//! of historical absence, not permission to regenerate this record.
//!
//! ```text
//! AOSCIA01 || AOSCIR01[688] || original-request-id[16]
//!          || signed-plan-digest[32] || semantic-request-digest[32]
//!          || request-deadline-boottime-nanoseconds:u64be
//!          || SHA256("aos.sandbox.controller-output-attempt.v1\0" || preceding)[32]
//! ```

use aos_sandbox_core::{
    AssignmentEpoch, BrokerAssignment, BrokerAudience, BrokerGrantTarget, BrokerVerb,
    DesiredGeneration, ExecutionId, ObjectDigest, OperationId, ProtocolId, ProtocolVersion,
};
use aos_sandbox_protocol::semantics::host_output_reserve_grant_v1;
use sha2::{Digest as _, Sha256};

use crate::{
    Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace, SignedBrokerPlan,
};

use super::{ControllerExecutionReserveSourceV1, EXECUTION_RESERVE_SOURCE_BYTES_V1};

const MAGIC: &[u8; 8] = b"AOSCIA01";
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.controller-output-attempt.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.controller-output-attempt-tx.v1\0";
const RECORD_BYTES: usize = 8 + EXECUTION_RESERVE_SOURCE_BYTES_V1 + 16 + 32 + 32 + 8 + 32;
const SOURCE_END: usize = 8 + EXECUTION_RESERVE_SOURCE_BYTES_V1;

/// Reports an unavailable or ambiguous original Host reserve attempt.
#[derive(Debug, thiserror::Error)]
pub enum ControllerExecutionOutputAttemptErrorV1 {
    /// The source, signed plan, or fixed record is malformed or mismatched.
    #[error("Controller execution output attempt is invalid")]
    Invalid,
    /// This execution already has an attempt; only cold query may continue.
    #[error("Controller execution output attempt already exists; query the original request")]
    AlreadyIssued,
    /// An append may have committed; reopen the Controller journal and query.
    #[error("Controller execution output attempt outcome is ambiguous; reopen and query")]
    OutcomeUnknown,
    /// The protected Controller journal is absent, corrupt, or poisoned.
    #[error(transparent)]
    Journal(#[from] JournalError),
}

/// Retains the immutable, nonauthorizing original Host reserve identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerExecutionOutputAttemptV1 {
    source: ControllerExecutionReserveSourceV1,
    original_request_id: [u8; 16],
    plan_digest: ObjectDigest,
    semantic_request_digest: ObjectDigest,
    request_deadline_boottime_nanoseconds: u64,
    record_digest: ObjectDigest,
}

impl ControllerExecutionOutputAttemptV1 {
    /// Borrows the exact Controller source frozen before the first Host send.
    #[must_use]
    pub const fn source(&self) -> &ControllerExecutionReserveSourceV1 {
        &self.source
    }

    /// Returns the sole original method-35 authenticated-session request ID.
    #[must_use]
    pub const fn original_request_id(&self) -> [u8; 16] {
        self.original_request_id
    }

    /// Returns the signed broker-plan digest Host must attest on completion.
    #[must_use]
    pub const fn plan_digest(&self) -> ObjectDigest {
        self.plan_digest
    }

    /// Returns the exact method-35 semantic commitment Host must attest.
    #[must_use]
    pub const fn semantic_request_digest(&self) -> ObjectDigest {
        self.semantic_request_digest
    }

    /// Returns the original signed request's BOOTTIME deadline.
    #[must_use]
    pub const fn request_deadline_boottime_nanoseconds(&self) -> u64 {
        self.request_deadline_boottime_nanoseconds
    }

    /// Returns the digest of the exact AOSCIA01 protected record.
    #[must_use]
    pub const fn record_digest(&self) -> ObjectDigest {
        self.record_digest
    }

    /// Returns the immutable original Controller attempt for a later signed
    /// Storage source. These bytes alone are not cross-process authority.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.encode().to_vec()
    }

    /// Returns the exact execution keyed by this one-shot attempt.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.source.preissue().execution()
    }

    /// Returns the accepted Create operation paired with the execution.
    #[must_use]
    pub const fn create_operation(&self) -> OperationId {
        self.source.preissue().create_operation()
    }

    fn encode(&self) -> [u8; RECORD_BYTES] {
        let mut bytes = [0_u8; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..SOURCE_END].copy_from_slice(&self.source.canonical_bytes());
        bytes[SOURCE_END..SOURCE_END + 16].copy_from_slice(&self.original_request_id);
        bytes[SOURCE_END + 16..SOURCE_END + 48].copy_from_slice(self.plan_digest.as_bytes());
        bytes[SOURCE_END + 48..SOURCE_END + 80]
            .copy_from_slice(self.semantic_request_digest.as_bytes());
        bytes[SOURCE_END + 80..SOURCE_END + 88]
            .copy_from_slice(&self.request_deadline_boottime_nanoseconds.to_be_bytes());
        bytes[RECORD_BYTES - 32..].copy_from_slice(self.record_digest.as_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, ControllerExecutionOutputAttemptErrorV1> {
        if bytes.len() != RECORD_BYTES || bytes.get(..8) != Some(MAGIC.as_slice()) {
            return Err(ControllerExecutionOutputAttemptErrorV1::Invalid);
        }
        let source = ControllerExecutionReserveSourceV1::decode_structural(&bytes[8..SOURCE_END])
            .map_err(|_| ControllerExecutionOutputAttemptErrorV1::Invalid)?;
        let original_request_id = bytes[SOURCE_END..SOURCE_END + 16]
            .try_into()
            .map_err(|_| ControllerExecutionOutputAttemptErrorV1::Invalid)?;
        let read_digest =
            |start: usize| -> Result<ObjectDigest, ControllerExecutionOutputAttemptErrorV1> {
                Ok(ObjectDigest::from_bytes(
                    bytes[start..start + 32]
                        .try_into()
                        .map_err(|_| ControllerExecutionOutputAttemptErrorV1::Invalid)?,
                ))
            };
        let plan_digest = read_digest(SOURCE_END + 16)?;
        let semantic_request_digest = read_digest(SOURCE_END + 48)?;
        let request_deadline_boottime_nanoseconds = u64::from_be_bytes(
            bytes[SOURCE_END + 80..SOURCE_END + 88]
                .try_into()
                .map_err(|_| ControllerExecutionOutputAttemptErrorV1::Invalid)?,
        );
        let record_digest = read_digest(RECORD_BYTES - 32)?;
        let record = Self {
            source,
            original_request_id,
            plan_digest,
            semantic_request_digest,
            request_deadline_boottime_nanoseconds,
            record_digest,
        };
        if !record.is_valid() || record.record_digest != digest_record(&bytes[..RECORD_BYTES - 32])
        {
            return Err(ControllerExecutionOutputAttemptErrorV1::Invalid);
        }
        Ok(record)
    }

    fn is_valid(&self) -> bool {
        self.original_request_id != [0; 16]
            && self.plan_digest.as_bytes() != &[0; 32]
            && self.semantic_request_digest.as_bytes() != &[0; 32]
            && self.request_deadline_boottime_nanoseconds != 0
            && self.request_deadline_boottime_nanoseconds
                <= self.source.preissue().deadline_boottime_nanoseconds()
            && semantic_request_digest(&self.source, self.original_request_id)
                == Some(self.semantic_request_digest)
    }
}

/// Freezes one original signed Host reserve attempt before its session send.
///
/// A prior record is never overwritten or renewed, even if its request never
/// reached Host. The caller must retain the same signed session request through
/// ambiguity; after restart only Query36 of the original ID is permitted.
/// This record itself does not authorize a Host effect.
///
/// # Errors
///
/// Rejects an unprotected Controller journal, a nonmatching signed Host plan,
/// a prior attempt, invalid deadline, or ambiguous protected append.
pub fn retain_controller_execution_output_attempt_v1(
    controller: &mut Journal,
    source: &ControllerExecutionReserveSourceV1,
    signed_plan: &SignedBrokerPlan,
    original_request_id: [u8; 16],
    request_deadline_boottime_nanoseconds: u64,
) -> Result<ControllerExecutionOutputAttemptV1, ControllerExecutionOutputAttemptErrorV1> {
    controller.ensure_protected_authority()?;
    let source_bytes = source.canonical_bytes();
    let assignment = signed_plan.plan().assignment();
    let semantics = host_output_reserve_grant_v1(assignment, original_request_id, &source_bytes)
        .map_err(|_| ControllerExecutionOutputAttemptErrorV1::Invalid)?;
    let plan = signed_plan.plan();
    let [grant] = plan.grants() else {
        return Err(ControllerExecutionOutputAttemptErrorV1::Invalid);
    };
    if plan.audience() != BrokerAudience::Host
        || plan.protocol() != ProtocolId::HostBroker
        || plan.protocol_version() != ProtocolVersion::new(1, 0)
        || plan.node() != source.node()
        || assignment.sandbox() != source.sandbox()
        || assignment.incarnation() != source.incarnation()
        || assignment.epoch().get() != source.assignment_epoch()
        || assignment.desired_generation().get() != source.desired_generation()
        || assignment.digest() != source.assignment_manifest_digest()
        || grant.verb() != BrokerVerb::HostReserveExecutionOutput
        || grant.target() != BrokerGrantTarget::Assignment
        || grant.argument_commitment() != semantics.commitment()
    {
        return Err(ControllerExecutionOutputAttemptErrorV1::Invalid);
    }

    let mut attempt = ControllerExecutionOutputAttemptV1 {
        source: source.clone(),
        original_request_id,
        plan_digest: signed_plan.digest(),
        semantic_request_digest: semantics.commitment().digest(),
        request_deadline_boottime_nanoseconds,
        record_digest: ObjectDigest::from_bytes([0; 32]),
    };
    if !attempt.is_valid() {
        return Err(ControllerExecutionOutputAttemptErrorV1::Invalid);
    }
    attempt.record_digest = digest_record(&attempt.encode()[..RECORD_BYTES - 32]);
    persist_attempt(controller, &attempt)?;
    Ok(attempt)
}

/// Replays the exact historical attempt from a protected Controller journal.
///
/// This readback does not renew the original request, attest Host completion,
/// or authorize a fresh Host reserve. A caller may use it only to construct an
/// authenticated query for the original ID under current Host assignment.
///
/// # Errors
///
/// Rejects unprotected, poisoned, or malformed Controller custody.
pub fn load_controller_execution_output_attempt_v1(
    controller: &Journal,
    execution: ExecutionId,
) -> Result<Option<ControllerExecutionOutputAttemptV1>, ControllerExecutionOutputAttemptErrorV1> {
    controller.ensure_protected_authority()?;
    controller
        .get(
            RecordNamespace::ControllerExecutionOutputAttempt,
            execution.as_bytes(),
        )
        .map(|bytes| {
            let attempt = ControllerExecutionOutputAttemptV1::decode(bytes)?;
            if attempt.execution() != execution {
                return Err(ControllerExecutionOutputAttemptErrorV1::Invalid);
            }
            Ok(attempt)
        })
        .transpose()
}

fn persist_attempt(
    controller: &mut Journal,
    attempt: &ControllerExecutionOutputAttemptV1,
) -> Result<(), ControllerExecutionOutputAttemptErrorV1> {
    controller.ensure_protected_authority()?;
    if !attempt.is_valid() {
        return Err(ControllerExecutionOutputAttemptErrorV1::Invalid);
    }
    if controller
        .get(
            RecordNamespace::ControllerExecutionOutputAttempt,
            attempt.execution().as_bytes(),
        )
        .is_some()
    {
        return Err(ControllerExecutionOutputAttemptErrorV1::AlreadyIssued);
    }
    let transaction_hash: [u8; 32] = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(attempt.execution().as_bytes())
        .chain_update(attempt.create_operation().as_bytes())
        .finalize()
        .into();
    let transaction_id = transaction_hash[..16]
        .try_into()
        .map_err(|_| ControllerExecutionOutputAttemptErrorV1::Invalid)?;
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::ControllerExecutionOutputAttempt,
            attempt.execution().as_bytes().to_vec(),
            attempt.encode().to_vec(),
        )],
    )?;
    controller
        .commit(&transaction)
        .map_err(|_| ControllerExecutionOutputAttemptErrorV1::OutcomeUnknown)?;
    Ok(())
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

fn semantic_request_digest(
    source: &ControllerExecutionReserveSourceV1,
    original_request_id: [u8; 16],
) -> Option<ObjectDigest> {
    let assignment = BrokerAssignment::new(
        source.sandbox(),
        source.incarnation(),
        AssignmentEpoch::new(source.assignment_epoch()),
        DesiredGeneration::new(source.desired_generation()),
        source.assignment_manifest_digest(),
    )
    .ok()?;
    let semantics =
        host_output_reserve_grant_v1(assignment, original_request_id, &source.canonical_bytes())
            .ok()?;
    Some(semantics.commitment().digest())
}

#[cfg(test)]
mod tests {
    use std::fs::{self, Permissions};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use crate::JournalLimits;

    use super::*;

    fn fixture() -> ControllerExecutionOutputAttemptV1 {
        let source = super::super::reserve_source::tests::fixture();
        let original_request_id = [11; 16];
        let semantic_request_digest =
            semantic_request_digest(&source, original_request_id).unwrap();
        let mut attempt = ControllerExecutionOutputAttemptV1 {
            source,
            original_request_id,
            plan_digest: ObjectDigest::from_bytes([12; 32]),
            semantic_request_digest,
            request_deadline_boottime_nanoseconds: 90,
            record_digest: ObjectDigest::from_bytes([0; 32]),
        };
        attempt.record_digest = digest_record(&attempt.encode()[..RECORD_BYTES - 32]);
        attempt
    }

    #[test]
    fn attempt_format_rejects_substitution_and_expired_request_deadline() {
        let attempt = fixture();
        let mut bytes = attempt.encode();
        assert_eq!(
            ControllerExecutionOutputAttemptV1::decode(&bytes).unwrap(),
            attempt
        );

        bytes[SOURCE_END] ^= 1;
        assert!(ControllerExecutionOutputAttemptV1::decode(&bytes).is_err());

        let mut substituted_semantics = fixture();
        substituted_semantics.semantic_request_digest = ObjectDigest::from_bytes([13; 32]);
        substituted_semantics.record_digest =
            digest_record(&substituted_semantics.encode()[..RECORD_BYTES - 32]);
        assert!(
            ControllerExecutionOutputAttemptV1::decode(&substituted_semantics.encode()).is_err()
        );

        let mut expired = fixture();
        expired.request_deadline_boottime_nanoseconds = 101;
        expired.record_digest = digest_record(&expired.encode()[..RECORD_BYTES - 32]);
        assert!(ControllerExecutionOutputAttemptV1::decode(&expired.encode()).is_err());
    }

    #[test]
    fn protected_cold_replay_keeps_original_id_and_refuses_reissue() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let (mut controller, _) = Journal::open_protected_at_uid(
            directory.path(),
            "controller.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        let attempt = fixture();

        persist_attempt(&mut controller, &attempt).unwrap();
        assert!(matches!(
            persist_attempt(&mut controller, &attempt),
            Err(ControllerExecutionOutputAttemptErrorV1::AlreadyIssued)
        ));
        drop(controller);

        let (reopened, _) = Journal::open_protected_at_uid(
            directory.path(),
            "controller.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        let recovered = load_controller_execution_output_attempt_v1(&reopened, attempt.execution())
            .unwrap()
            .unwrap();
        assert_eq!(recovered, attempt);
        assert_eq!(recovered.original_request_id(), [11; 16]);
    }

    #[test]
    fn unprotected_journal_cannot_claim_attempt_custody() {
        let directory = tempfile::tempdir().unwrap();
        let (mut ordinary, _) = Journal::open(
            directory.path().join("ordinary.journal"),
            JournalLimits::default(),
        )
        .unwrap();
        let attempt = fixture();

        assert!(matches!(
            persist_attempt(&mut ordinary, &attempt),
            Err(ControllerExecutionOutputAttemptErrorV1::Journal(
                JournalError::ProtectedBoundary
            ))
        ));
        assert!(
            load_controller_execution_output_attempt_v1(&ordinary, attempt.execution()).is_err()
        );
    }
}
