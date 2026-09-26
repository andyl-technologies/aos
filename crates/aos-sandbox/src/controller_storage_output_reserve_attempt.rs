//! Protected custody of one original Controller-signed Storage output reserve.
//!
//! This record freezes method 46 before any future session send. An ambiguous
//! append or send can only be investigated by a distinct historical query;
//! it never permits a regenerated reserve request. The record does not prove
//! same-session Host state or authorize an AOSEOR03 mutation.
//!
//! ```text
//! AOSCST01 || execution[16] || Create-operation[16] || request-id[16]
//!          || signed-plan-digest[32] || semantic-grant-digest[32]
//!          || body-length:u16be || canonical-method-46-body[body-length]
//!          || SHA256("aos.sandbox.controller-storage-output-attempt.v1\0"
//!             || preceding)[32]
//! ```

use aos_proto::aos::sandbox::local::v1::{
    ObserveHostStorageOutputRequestV1, QueryStorageExecutionOutputRequestV1, RequestHeader,
    ReserveStorageExecutionOutputRequestV1,
};
use aos_sandbox_core::{
    BrokerAudience, ExecutionId, ObjectDigest, OperationId, ProtocolId, ProtocolVersion,
};
use aos_sandbox_protocol::host_storage_output_readback::{
    ValidatedHostStorageOutputReadbackRequestV1, host_storage_output_readback_grant_v1,
};
use aos_sandbox_protocol::storage_output_reserve::{
    StorageOutputReserveRecordsV1, ValidatedStorageOutputQueryRequestV1,
    storage_output_query_grant_v1, storage_output_reserve_grant_v1,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::{
    Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace, SignedBrokerPlan,
};

const MAGIC: &[u8; 8] = b"AOSCST01";
const DOMAIN: &[u8] = b"aos.sandbox.controller-storage-output-attempt.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.controller-storage-output-attempt-tx.v1\0";
const FIXED_PREFIX_BYTES: usize = 8 + 16 + 16 + 16 + 32 + 32 + 2;
const MAXIMUM_BODY_BYTES: usize = 4 * 1_024;

/// Reports invalid or ambiguous original Storage reserve custody.
#[derive(Debug, thiserror::Error)]
pub enum ControllerStorageOutputReserveAttemptErrorV1 {
    /// The body, signed plan, or protected record is malformed or mismatched.
    #[error("Controller Storage output reserve attempt is invalid")]
    Invalid,
    /// Another original attempt already owns this execution; query it instead.
    #[error("Controller Storage output reserve attempt already exists; query the original")]
    AlreadyIssued,
    /// The append may have committed; reopen protected custody before query.
    #[error("Controller Storage output reserve attempt outcome is ambiguous")]
    OutcomeUnknown,
    /// The protected Controller journal is unavailable or poisoned.
    #[error(transparent)]
    Journal(#[from] JournalError),
}

/// Retains the immutable, nonauthorizing original method-46 identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerStorageOutputReserveAttemptV1 {
    execution: ExecutionId,
    create_operation: OperationId,
    original_request_id: [u8; 16],
    signed_plan_digest: ObjectDigest,
    semantic_digest: ObjectDigest,
    canonical_body: Vec<u8>,
    record_digest: ObjectDigest,
}

impl ControllerStorageOutputReserveAttemptV1 {
    /// Returns the execution that owns this sole Storage reserve attempt.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the original authenticated-session request ID.
    #[must_use]
    pub const fn original_request_id(&self) -> [u8; 16] {
        self.original_request_id
    }

    /// Borrows the exact method-46 request body frozen before send.
    #[must_use]
    pub fn canonical_body(&self) -> &[u8] {
        &self.canonical_body
    }

    /// Returns the digest of the original signed Storage plan.
    #[must_use]
    pub const fn signed_plan_digest(&self) -> ObjectDigest {
        self.signed_plan_digest
    }

    /// Returns the original method-46 semantic grant digest.
    #[must_use]
    pub const fn semantic_digest(&self) -> ObjectDigest {
        self.semantic_digest
    }

    /// Returns the deterministic digest of the protected AOSCST01 record.
    #[must_use]
    pub const fn record_digest(&self) -> ObjectDigest {
        self.record_digest
    }

    /// Builds a nonauthorizing Host readback body from this frozen attempt.
    ///
    /// A separate Controller-signed Host plan, Storage session, and protected
    /// Host reply remain required. The fresh request never replaces method 46.
    ///
    /// # Errors
    ///
    /// Rejects a reused request ID or malformed Storage-audience Host header.
    pub fn host_readback_body(
        &self,
        header: RequestHeader,
    ) -> Result<Vec<u8>, ControllerStorageOutputReserveAttemptErrorV1> {
        let request_id: [u8; 16] = header
            .request_id
            .as_slice()
            .try_into()
            .map_err(|_| ControllerStorageOutputReserveAttemptErrorV1::Invalid)?;
        let body = ObserveHostStorageOutputRequestV1 {
            header: Some(header).into(),
            canonical_original_storage_reserve_request: self.canonical_body.clone(),
            original_storage_signed_plan_digest: self.signed_plan_digest.as_bytes().to_vec(),
            original_storage_semantic_digest: self.semantic_digest.as_bytes().to_vec(),
            controller_storage_attempt_digest: self.record_digest.as_bytes().to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (_, records, _) = inspect_original(&self.canonical_body)?;
        host_storage_output_readback_grant_v1(records.assignment(), request_id, &body)
            .map_err(|_| ControllerStorageOutputReserveAttemptErrorV1::Invalid)?;
        Ok(body)
    }

    /// Checks every original field of a parsed Host readback request.
    #[must_use]
    pub fn matches_host_readback(
        &self,
        readback: &ValidatedHostStorageOutputReadbackRequestV1,
    ) -> bool {
        readback.original_storage_request_id() == self.original_request_id
            && readback.original_body() == self.canonical_body
            && readback.original_storage_plan_digest() == self.signed_plan_digest
            && readback.original_storage_semantic_digest() == self.semantic_digest
            && readback.controller_storage_attempt_digest() == self.record_digest
            && readback.records().host_locator().execution() == self.execution
            && readback.records().host_locator().create_operation() == self.create_operation
    }

    /// Builds a nonauthorizing cold-query body from the retained original.
    ///
    /// The caller must obtain a fresh authenticated-session header and a
    /// separate Controller-signed read-only query plan before any send.
    ///
    /// # Errors
    ///
    /// Rejects a reused original request ID or malformed query header.
    pub fn query_body(
        &self,
        header: RequestHeader,
    ) -> Result<Vec<u8>, ControllerStorageOutputReserveAttemptErrorV1> {
        let request_id: [u8; 16] = header
            .request_id
            .as_slice()
            .try_into()
            .map_err(|_| ControllerStorageOutputReserveAttemptErrorV1::Invalid)?;
        let query = QueryStorageExecutionOutputRequestV1 {
            header: Some(header).into(),
            canonical_original_reserve_request: self.canonical_body.clone(),
            original_signed_plan_digest: self.signed_plan_digest.as_bytes().to_vec(),
            original_semantic_request_digest: self.semantic_digest.as_bytes().to_vec(),
            ..Default::default()
        };
        let body = query.encode_to_vec();
        let (_, records, _) = inspect_original(&self.canonical_body)?;
        storage_output_query_grant_v1(records.assignment(), request_id, &body)
            .map_err(|_| ControllerStorageOutputReserveAttemptErrorV1::Invalid)?;
        Ok(body)
    }

    /// Checks a parsed cold query against every immutable original field.
    #[must_use]
    pub fn matches_query(&self, query: &ValidatedStorageOutputQueryRequestV1) -> bool {
        query.original_request_id() == self.original_request_id
            && query.original_body() == self.canonical_body
            && query.original_plan_digest() == self.signed_plan_digest
            && query.original_semantic_digest() == self.semantic_digest
            && query.records().host_locator().execution() == self.execution
            && query.records().host_locator().create_operation() == self.create_operation
    }

    fn from_original(
        body: &[u8],
        signed_plan_digest: ObjectDigest,
    ) -> Result<Self, ControllerStorageOutputReserveAttemptErrorV1> {
        let (request_id, records, semantic_digest) = inspect_original(body)?;
        if signed_plan_digest.as_bytes() == &[0; 32] {
            return Err(ControllerStorageOutputReserveAttemptErrorV1::Invalid);
        }
        let mut attempt = Self {
            execution: records.host_locator().execution(),
            create_operation: records.host_locator().create_operation(),
            original_request_id: request_id,
            signed_plan_digest,
            semantic_digest,
            canonical_body: body.to_vec(),
            record_digest: ObjectDigest::from_bytes([0; 32]),
        };
        attempt.record_digest = digest_record(&attempt.encode_prefix_and_body());
        Ok(attempt)
    }

    fn encode_prefix_and_body(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(FIXED_PREFIX_BYTES + self.canonical_body.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(self.execution.as_bytes());
        bytes.extend_from_slice(self.create_operation.as_bytes());
        bytes.extend_from_slice(&self.original_request_id);
        bytes.extend_from_slice(self.signed_plan_digest.as_bytes());
        bytes.extend_from_slice(self.semantic_digest.as_bytes());
        bytes.extend_from_slice(&(self.canonical_body.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.canonical_body);
        bytes
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = self.encode_prefix_and_body();
        bytes.extend_from_slice(self.record_digest.as_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, ControllerStorageOutputReserveAttemptErrorV1> {
        if bytes.len() < FIXED_PREFIX_BYTES + 32 || bytes.get(..8) != Some(MAGIC.as_slice()) {
            return Err(ControllerStorageOutputReserveAttemptErrorV1::Invalid);
        }
        let body_len = u16::from_be_bytes(
            bytes[FIXED_PREFIX_BYTES - 2..FIXED_PREFIX_BYTES]
                .try_into()
                .map_err(|_| ControllerStorageOutputReserveAttemptErrorV1::Invalid)?,
        ) as usize;
        if body_len == 0
            || body_len > MAXIMUM_BODY_BYTES
            || bytes.len() != FIXED_PREFIX_BYTES + body_len + 32
            || digest_record(&bytes[..bytes.len() - 32]).as_bytes() != &bytes[bytes.len() - 32..]
        {
            return Err(ControllerStorageOutputReserveAttemptErrorV1::Invalid);
        }
        let plan_digest = ObjectDigest::from_bytes(
            bytes[56..88]
                .try_into()
                .map_err(|_| ControllerStorageOutputReserveAttemptErrorV1::Invalid)?,
        );
        let rebuilt = Self::from_original(
            &bytes[FIXED_PREFIX_BYTES..FIXED_PREFIX_BYTES + body_len],
            plan_digest,
        )?;
        if rebuilt.encode() != bytes {
            return Err(ControllerStorageOutputReserveAttemptErrorV1::Invalid);
        }
        Ok(rebuilt)
    }
}

/// Freezes one original signed Storage reserve before any session send.
///
/// A prior attempt is never overwritten, even if Storage later says absent.
/// This record does not authorize Storage mutation.
///
/// # Errors
///
/// Rejects a nonprotected journal, nonmatching signed Storage plan, prior
/// attempt, or ambiguous protected append.
pub fn retain_controller_storage_output_reserve_attempt_v1(
    controller: &mut Journal,
    body: &[u8],
    signed_plan: &SignedBrokerPlan,
) -> Result<ControllerStorageOutputReserveAttemptV1, ControllerStorageOutputReserveAttemptErrorV1> {
    controller.ensure_protected_authority()?;
    let attempt =
        ControllerStorageOutputReserveAttemptV1::from_original(body, signed_plan.digest())?;
    let request = ReserveStorageExecutionOutputRequestV1::decode_from_slice(body)
        .map_err(|_| ControllerStorageOutputReserveAttemptErrorV1::Invalid)?;
    let records = StorageOutputReserveRecordsV1::from_canonical_records(
        &request.canonical_controller_attempt,
        &request.canonical_controller_settlement,
    )
    .map_err(|_| ControllerStorageOutputReserveAttemptErrorV1::Invalid)?;
    let plan = signed_plan.plan();
    let [grant] = plan.grants() else {
        return Err(ControllerStorageOutputReserveAttemptErrorV1::Invalid);
    };
    let expected_grant =
        storage_output_reserve_grant_v1(records.assignment(), attempt.original_request_id, body)
            .map_err(|_| ControllerStorageOutputReserveAttemptErrorV1::Invalid)?;
    if plan.audience() != BrokerAudience::Storage
        || plan.protocol() != ProtocolId::StorageBroker
        || plan.protocol_version() != ProtocolVersion::new(1, 0)
        || plan.assignment() != records.assignment()
        || plan.node().as_bytes() != &request.canonical_controller_attempt[8 + 584..8 + 600]
        || grant != &expected_grant
    {
        return Err(ControllerStorageOutputReserveAttemptErrorV1::Invalid);
    }
    persist_attempt(controller, &attempt)?;
    Ok(attempt)
}

/// Replays the original attempt from protected Controller custody only.
///
/// # Errors
///
/// Rejects an unprotected, poisoned, or malformed Controller journal.
pub fn load_controller_storage_output_reserve_attempt_v1(
    controller: &Journal,
    execution: ExecutionId,
) -> Result<
    Option<ControllerStorageOutputReserveAttemptV1>,
    ControllerStorageOutputReserveAttemptErrorV1,
> {
    controller.ensure_protected_authority()?;
    controller
        .get(
            RecordNamespace::ControllerStorageOutputReserveAttempt,
            execution.as_bytes(),
        )
        .map(|bytes| {
            let attempt = ControllerStorageOutputReserveAttemptV1::decode(bytes)?;
            if attempt.execution != execution {
                return Err(ControllerStorageOutputReserveAttemptErrorV1::Invalid);
            }
            Ok(attempt)
        })
        .transpose()
}

fn inspect_original(
    body: &[u8],
) -> Result<
    ([u8; 16], StorageOutputReserveRecordsV1, ObjectDigest),
    ControllerStorageOutputReserveAttemptErrorV1,
> {
    if body.is_empty() || body.len() > MAXIMUM_BODY_BYTES {
        return Err(ControllerStorageOutputReserveAttemptErrorV1::Invalid);
    }
    let request = ReserveStorageExecutionOutputRequestV1::decode_from_slice(body)
        .map_err(|_| ControllerStorageOutputReserveAttemptErrorV1::Invalid)?;
    let header = request
        .header
        .as_option()
        .ok_or(ControllerStorageOutputReserveAttemptErrorV1::Invalid)?;
    let request_id: [u8; 16] = header
        .request_id
        .as_slice()
        .try_into()
        .map_err(|_| ControllerStorageOutputReserveAttemptErrorV1::Invalid)?;
    let records = StorageOutputReserveRecordsV1::from_canonical_records(
        &request.canonical_controller_attempt,
        &request.canonical_controller_settlement,
    )
    .map_err(|_| ControllerStorageOutputReserveAttemptErrorV1::Invalid)?;
    let grant = storage_output_reserve_grant_v1(records.assignment(), request_id, body)
        .map_err(|_| ControllerStorageOutputReserveAttemptErrorV1::Invalid)?;
    Ok((request_id, records, grant.argument_commitment().digest()))
}

fn persist_attempt(
    controller: &mut Journal,
    attempt: &ControllerStorageOutputReserveAttemptV1,
) -> Result<(), ControllerStorageOutputReserveAttemptErrorV1> {
    controller.ensure_protected_authority()?;
    if !ControllerStorageOutputReserveAttemptV1::decode(&attempt.encode())
        .is_ok_and(|decoded| decoded == *attempt)
    {
        return Err(ControllerStorageOutputReserveAttemptErrorV1::Invalid);
    }
    if controller
        .get(
            RecordNamespace::ControllerStorageOutputReserveAttempt,
            attempt.execution.as_bytes(),
        )
        .is_some()
    {
        return Err(ControllerStorageOutputReserveAttemptErrorV1::AlreadyIssued);
    }
    let transaction_hash: [u8; 32] = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(attempt.execution.as_bytes())
        .chain_update(attempt.create_operation.as_bytes())
        .finalize()
        .into();
    let transaction_id = transaction_hash[..16]
        .try_into()
        .map_err(|_| ControllerStorageOutputReserveAttemptErrorV1::Invalid)?;
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::ControllerStorageOutputReserveAttempt,
            attempt.execution.as_bytes().to_vec(),
            attempt.encode(),
        )],
    )?;
    controller
        .commit(&transaction)
        .map_err(|_| ControllerStorageOutputReserveAttemptErrorV1::OutcomeUnknown)?;
    Ok(())
}

fn digest_record(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(DOMAIN)
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}

#[cfg(test)]
mod tests {
    use std::fs::{self, Permissions};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use aos_proto::aos::sandbox::local::v1::{Audience, RequestHeader};
    use aos_sandbox_core::{
        AssignmentEpoch, BrokerAssignment, DesiredGeneration, IncarnationId, SandboxId,
    };
    use aos_sandbox_protocol::host_storage_output_readback::decode_host_storage_output_readback_request_v1;
    use aos_sandbox_protocol::semantics::host_output_reserve_grant_v1;
    use aos_sandbox_protocol::storage_output_reserve::decode_storage_output_query_request_v1;
    use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};

    use crate::JournalLimits;

    use super::*;

    fn seal(domain: &[u8], bytes: &mut [u8], content_len: usize) {
        let digest = Sha256::new()
            .chain_update(domain)
            .chain_update(&bytes[..content_len])
            .finalize();
        bytes[content_len..content_len + 32].copy_from_slice(&digest);
    }

    fn original_body() -> Vec<u8> {
        let mut source = [0_u8; 688];
        source[..8].copy_from_slice(b"AOSCIR01");
        source[8..16].copy_from_slice(b"AOSCIP01");
        source[16..32].fill(1);
        source[32..48].fill(2);
        source[48..80].fill(3);
        source[96..104].copy_from_slice(&1_u64.to_be_bytes());
        source[104..120].fill(4);
        source[120..128].copy_from_slice(&1_000_u64.to_be_bytes());
        source[128..160].fill(5);
        let preissue_digest = Sha256::new()
            .chain_update(b"aos.sandbox.controller-execution-preissue.v1\0")
            .chain_update(&source[8..160])
            .finalize();
        source[160..192].copy_from_slice(&preissue_digest);

        source[192..200].copy_from_slice(b"AOSEOR02");
        source[200..216].fill(1);
        source[216..232].fill(2);
        for offset in [232, 264, 328, 360, 392, 456] {
            source[offset..offset + 32].fill(6);
        }
        source[296..328].fill(7);
        source[432..440].copy_from_slice(&100_u64.to_be_bytes());
        let claim_checksum = Sha256::digest(&source[192..488]);
        source[488..520].copy_from_slice(&claim_checksum);
        source[520..552].fill(8);
        source[552..568].fill(9);
        source[568..584].fill(10);
        source[584..600].fill(11);
        for offset in [600, 608, 616] {
            source[offset..offset + 8].copy_from_slice(&1_u64.to_be_bytes());
        }
        source[624..656].fill(7);
        seal(
            b"aos.sandbox.controller-execution-reserve-source.v1\0",
            &mut source,
            656,
        );

        let assignment = BrokerAssignment::new(
            SandboxId::from_bytes([9; 16]),
            IncarnationId::from_bytes([10; 16]),
            AssignmentEpoch::new(1),
            DesiredGeneration::new(1),
            ObjectDigest::from_bytes([7; 32]),
        )
        .unwrap();
        let host_grant = host_output_reserve_grant_v1(assignment, [12; 16], &source).unwrap();
        let mut attempt = [0_u8; 816];
        attempt[..8].copy_from_slice(b"AOSCIA01");
        attempt[8..696].copy_from_slice(&source);
        attempt[696..712].fill(12);
        attempt[712..744].fill(13);
        attempt[744..776].copy_from_slice(host_grant.commitment().digest().as_bytes());
        attempt[776..784].copy_from_slice(&900_u64.to_be_bytes());
        seal(
            b"aos.sandbox.controller-output-attempt.v1\0",
            &mut attempt,
            784,
        );

        let mut settlement = [0_u8; 208];
        settlement[..8].copy_from_slice(b"AOSCIS01");
        settlement[8..24].fill(1);
        settlement[24..40].fill(2);
        settlement[40..72].copy_from_slice(&attempt[784..816]);
        settlement[72..104].fill(15);
        settlement[104..112].copy_from_slice(&1_u64.to_be_bytes());
        settlement[112..144].fill(16);
        settlement[144..176].fill(17);
        seal(
            b"aos.sandbox.controller-output-settlement.v1\0",
            &mut settlement,
            176,
        );

        ReserveStorageExecutionOutputRequestV1 {
            header: Some(RequestHeader {
                protocol_major: 1,
                request_id: vec![18; 16],
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: 950,
                maximum_response_bytes: 4_096,
                ..Default::default()
            })
            .into(),
            canonical_controller_attempt: attempt.to_vec(),
            canonical_controller_settlement: settlement.to_vec(),
            ..Default::default()
        }
        .encode_to_vec()
    }

    #[test]
    fn protected_attempt_is_one_shot_and_cold_query_matches_exact_record() {
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
        let original = ControllerStorageOutputReserveAttemptV1::from_original(
            &original_body(),
            ObjectDigest::from_bytes([20; 32]),
        )
        .unwrap();
        let mut corrupted = original.encode();
        corrupted[56] ^= 1;
        assert!(ControllerStorageOutputReserveAttemptV1::decode(&corrupted).is_err());

        persist_attempt(&mut controller, &original).unwrap();
        assert!(matches!(
            persist_attempt(&mut controller, &original),
            Err(ControllerStorageOutputReserveAttemptErrorV1::AlreadyIssued)
        ));
        drop(controller);

        let (reopened, _) = Journal::open_protected_at_uid(
            directory.path(),
            "controller.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        let recovered =
            load_controller_storage_output_reserve_attempt_v1(&reopened, original.execution())
                .unwrap()
                .unwrap();
        assert_eq!(recovered, original);

        let query_body = recovered
            .query_body(RequestHeader {
                protocol_major: 1,
                request_id: vec![19; 16],
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: 1_100,
                maximum_response_bytes: 4_096,
                ..Default::default()
            })
            .unwrap();
        let peer = PeerCredentials {
            uid: 1,
            gid: 2,
            pid: None,
        };
        let policy = PeerPolicy {
            uid: 1,
            gid: Some(2),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        };
        let query =
            decode_storage_output_query_request_v1(&query_body, peer, policy, 1_000).unwrap();
        assert!(recovered.matches_query(&query));

        let mut substituted =
            QueryStorageExecutionOutputRequestV1::decode_from_slice(&query_body).unwrap();
        substituted.original_signed_plan_digest[0] ^= 1;
        let changed = decode_storage_output_query_request_v1(
            &substituted.encode_to_vec(),
            peer,
            policy,
            1_000,
        )
        .unwrap();
        assert!(!recovered.matches_query(&changed));
        let readback_body = recovered
            .host_readback_body(RequestHeader {
                protocol_major: 1,
                request_id: vec![20; 16],
                audience: Audience::AUDIENCE_STORAGE_BROKER.into(),
                deadline_boottime_nanoseconds: 1_100,
                maximum_response_bytes: 4_096,
                ..Default::default()
            })
            .unwrap();
        let readback = decode_host_storage_output_readback_request_v1(
            &readback_body,
            peer,
            PeerPolicy {
                audience: Audience::AUDIENCE_STORAGE_BROKER,
                ..policy
            },
            1_000,
        )
        .unwrap();
        assert!(recovered.matches_host_readback(&readback));
        assert_eq!(
            readback.controller_storage_attempt_digest(),
            recovered.record_digest()
        );
        assert!(
            recovered
                .host_readback_body(RequestHeader {
                    protocol_major: 1,
                    request_id: vec![18; 16],
                    audience: Audience::AUDIENCE_STORAGE_BROKER.into(),
                    deadline_boottime_nanoseconds: 1_100,
                    ..Default::default()
                })
                .is_err()
        );
        assert!(
            recovered
                .query_body(RequestHeader {
                    request_id: vec![18; 16],
                    protocol_major: 1,
                    audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                    deadline_boottime_nanoseconds: 1_100,
                    ..Default::default()
                })
                .is_err()
        );
    }

    #[test]
    fn ordinary_journal_cannot_claim_original_storage_attempt() {
        let directory = tempfile::tempdir().unwrap();
        let (mut ordinary, _) = Journal::open(
            directory.path().join("ordinary.journal"),
            JournalLimits::default(),
        )
        .unwrap();
        let original = ControllerStorageOutputReserveAttemptV1::from_original(
            &original_body(),
            ObjectDigest::from_bytes([20; 32]),
        )
        .unwrap();

        assert!(matches!(
            persist_attempt(&mut ordinary, &original),
            Err(ControllerStorageOutputReserveAttemptErrorV1::Journal(
                JournalError::ProtectedBoundary
            ))
        ));
        assert!(
            load_controller_storage_output_reserve_attempt_v1(&ordinary, original.execution())
                .is_err()
        );
    }
}
