//! Durable, accepted-Create-derived execution output-byte reservations.
//!
//! The runtime execution store owns one assignment-scoped v2 ledger in the
//! same protected journal as spec admission. The controller's accepted Create
//! projection fixes the byte count; callers cannot provide an independent
//! budget. Stream and PTY requests commit a zero-byte record so absence is
//! never mistaken for a reservation. Terminal exit does not release output.
//!
//! ```text
//! marker = AOSEOM01 || assignment[32] || parent-bytes:u64be
//! claim  = AOSEOR01 || execution[16] || create-operation[16]
//!          || accepted-resource-version[32] || projection[32] || assignment[32]
//!          || parent-profile[32] || parent-binding[32] || spec-record[32]
//!          || requested:u64be || parent-bytes:u64be || claim[32] || sha256[32]
//! ```
//!
//! The runtime store's protected-open provenance, exclusive claim, and
//! synchronous commit are the trust boundary. Record checksums detect torn or
//! noncanonical records, not forgery by an equally privileged writer. The
//! provisional claim and its later spec admission do not authorize Host Apply.
//! Historical standalone journals are not silently imported into this owner.

use aos_proto::aos::sandbox::v1::{Command, ExecutionIoMode, ExecutionPhase};
use aos_sandbox_core::{
    ExecutionId, ExecutionOutputByteAdmissionV1, ObjectDigest, OperationId, ResourceDimension,
};
use sha2::{Digest as _, Sha256};

use crate::Journal;
use crate::controller_service::public_projection::{
    PublicProjectionKindV1, PublicProjectionResourceV1, PublicProjectionStoreV1,
};
use crate::execution_parent_resource::{
    ExecutionParentResourceSourceV1, revalidate_execution_parent_resource_from_journal_v1,
};
use crate::journal::JournalError;

pub(crate) const MARKER_KEY: &[u8] = b"execution-output-owner-v1";
const MARKER_MAGIC: &[u8; 8] = b"AOSEOM01";
const CLAIM_MAGIC: &[u8; 8] = b"AOSEOR01";
pub(crate) const CLAIM_KEY_PREFIX: u8 = b'o';
const MARKER_BYTES: usize = 48;
pub(crate) const CLAIM_BYTES: usize = 312;

/// Reports absent accepted input, capacity exhaustion, or protected-ledger failure.
#[derive(Debug, thiserror::Error)]
pub enum ExecutionOutputReservationErrorV1 {
    /// The accepted Create projection or parent source is unavailable.
    #[error("accepted execution output source is not current")]
    NotCurrent,
    /// The accepted request does not fit its current parent output reservation.
    #[error("execution output-byte capacity is unavailable")]
    CapacityUnavailable,
    /// Existing protected output ledger bytes fail exact replay or ownership.
    #[error("protected execution output ledger is corrupt or belongs to another assignment")]
    CorruptLedger,
    /// The same execution has an incompatible prior reservation.
    #[error("execution output reservation conflicts with durable custody")]
    Conflict,
    /// Protected journal I/O, authority, or durability failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
}

/// Holds the exact durable output claim; it is not Host effect authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableExecutionOutputReservationV1 {
    execution: ExecutionId,
    create_operation: OperationId,
    accepted_resource_version: ObjectDigest,
    projection_revision: ObjectDigest,
    output: ExecutionOutputByteAdmissionV1,
    record_digest: ObjectDigest,
}

impl DurableExecutionOutputReservationV1 {
    /// Borrows the assignment-bound, accepted output-byte admission claim.
    #[must_use]
    pub const fn output(&self) -> &ExecutionOutputByteAdmissionV1 {
        &self.output
    }

    /// Returns the exact execution reserved by the protected ledger.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the accepted Create operation bound to this reservation.
    #[must_use]
    pub const fn create_operation(&self) -> OperationId {
        self.create_operation
    }

    /// Returns the complete durable record digest for later spec-custody joins.
    #[must_use]
    pub const fn record_digest(&self) -> ObjectDigest {
        self.record_digest
    }

    /// Returns the accepted Create projection's request-bound resource version.
    #[must_use]
    pub const fn accepted_resource_version(&self) -> ObjectDigest {
        self.accepted_resource_version
    }

    /// Returns the accepted requested projection's record revision.
    #[must_use]
    pub const fn projection_revision(&self) -> ObjectDigest {
        self.projection_revision
    }
}

/// Distinguishes a durable result from a possibly committed journal append.
#[must_use]
pub enum ExecutionOutputReservationCommitV1 {
    /// The exact claim was committed or replayed from protected storage.
    Committed(DurableExecutionOutputReservationV1),
    /// The caller must reopen the same protected ledger and resolve this token.
    RecoveryRequired(ExecutionOutputReservationRecoveryV1),
}

/// Retains exact recovery identity after an ambiguous append.
#[must_use = "an ambiguous output reservation must be resolved after protected reopen"]
pub struct ExecutionOutputReservationRecoveryV1 {
    pub(crate) store_binding: ObjectDigest,
    pub(crate) expected: DurableExecutionOutputReservationV1,
    pub(crate) expected_bytes: [u8; CLAIM_BYTES],
}

/// Reports definitive protected readback of an ambiguous reservation.
#[must_use]
pub enum ExecutionOutputReservationRecoveryResultV1 {
    /// The exact reservation committed; no second reservation is permitted.
    Committed(DurableExecutionOutputReservationV1),
    /// No reservation committed; a new current-source admission is required.
    NotCommitted,
}

pub(crate) struct ClaimDraft {
    pub(crate) record: DurableExecutionOutputReservationV1,
    pub(crate) bytes: [u8; CLAIM_BYTES],
    pub(crate) assignment: ObjectDigest,
    pub(crate) requested_bytes: u64,
    pub(crate) parent_bytes: u64,
}

pub(crate) fn accepted_claim(
    controller: &mut Journal,
    create_operation: OperationId,
    execution: ExecutionId,
    parent: &ExecutionParentResourceSourceV1,
) -> Result<ClaimDraft, ExecutionOutputReservationErrorV1> {
    controller.ensure_protected_authority()?;
    revalidate_execution_parent_resource_from_journal_v1(controller, parent)
        .map_err(|_| ExecutionOutputReservationErrorV1::NotCurrent)?;
    let projection = PublicProjectionStoreV1::new(controller)
        .get(PublicProjectionKindV1::Execution, *execution.as_bytes())
        .map_err(|_| ExecutionOutputReservationErrorV1::NotCurrent)?
        .ok_or(ExecutionOutputReservationErrorV1::NotCurrent)?;
    let PublicProjectionResourceV1::Execution(accepted) = projection.resource() else {
        return Err(ExecutionOutputReservationErrorV1::NotCurrent);
    };
    let manifest = parent.assignment().manifest();
    let command = accepted
        .command
        .as_option()
        .ok_or(ExecutionOutputReservationErrorV1::NotCurrent)?;
    if projection.project() != manifest.project()
        || projection.operation() != create_operation
        || accepted.phase.as_known() != Some(ExecutionPhase::EXECUTION_PHASE_REQUESTED)
        || accepted.audit_id != create_operation.as_bytes()
        || accepted.execution_id != execution.as_bytes()
        || accepted.sandbox_id != manifest.sandbox().as_bytes()
        || accepted.sandbox_incarnation_id != manifest.incarnation().as_bytes()
        || accepted.assignment_epoch != manifest.epoch().get()
        || accepted.resource_version.len() != 32
    {
        return Err(ExecutionOutputReservationErrorV1::NotCurrent);
    }
    let requested_bytes = requested_output_bytes(command)?;
    let output = ExecutionOutputByteAdmissionV1::new(
        requested_bytes,
        requested_bytes,
        parent.assignment().clone(),
    )
    .map_err(|_| ExecutionOutputReservationErrorV1::CapacityUnavailable)?;
    let accepted_resource_version = ObjectDigest::from_bytes(
        accepted
            .resource_version
            .as_slice()
            .try_into()
            .map_err(|_| ExecutionOutputReservationErrorV1::NotCurrent)?,
    );
    if accepted_resource_version.as_bytes() == &[0; 32] {
        return Err(ExecutionOutputReservationErrorV1::NotCurrent);
    }
    let parent_bytes = parent
        .parent_reservations()
        .get(ResourceDimension::OutputBytes);
    let mut bytes = [0_u8; CLAIM_BYTES];
    bytes[..8].copy_from_slice(CLAIM_MAGIC);
    bytes[8..24].copy_from_slice(execution.as_bytes());
    bytes[24..40].copy_from_slice(create_operation.as_bytes());
    bytes[40..72].copy_from_slice(accepted_resource_version.as_bytes());
    bytes[72..104].copy_from_slice(projection.revision().as_bytes());
    bytes[104..136].copy_from_slice(parent.assignment().digest().as_bytes());
    bytes[136..168].copy_from_slice(parent.profile_commitment().as_bytes());
    bytes[168..200].copy_from_slice(parent.binding_digest().as_bytes());
    bytes[200..232].copy_from_slice(parent.specification_record_digest().as_bytes());
    bytes[232..240].copy_from_slice(&requested_bytes.to_be_bytes());
    bytes[240..248].copy_from_slice(&parent_bytes.to_be_bytes());
    bytes[248..280].copy_from_slice(output.reservation_commitment().as_bytes());
    let checksum = Sha256::digest(&bytes[..280]);
    bytes[280..].copy_from_slice(&checksum);
    let record_digest = ObjectDigest::from_bytes(Sha256::digest(bytes).into());
    Ok(ClaimDraft {
        record: DurableExecutionOutputReservationV1 {
            execution,
            create_operation,
            accepted_resource_version,
            projection_revision: projection.revision(),
            output,
            record_digest,
        },
        bytes,
        assignment: parent.assignment().digest(),
        requested_bytes,
        parent_bytes,
    })
}

fn requested_output_bytes(command: &Command) -> Result<u64, ExecutionOutputReservationErrorV1> {
    match command.io_mode.as_known() {
        Some(
            ExecutionIoMode::EXECUTION_IO_MODE_STREAM | ExecutionIoMode::EXECUTION_IO_MODE_PTY,
        ) if command.detached_capture_bytes == 0 => Ok(0),
        Some(ExecutionIoMode::EXECUTION_IO_MODE_DETACHED_CAPTURE)
            if command.detached_capture_bytes > 0 =>
        {
            Ok(command.detached_capture_bytes)
        }
        _ => Err(ExecutionOutputReservationErrorV1::NotCurrent),
    }
}

pub(crate) fn admit_next(
    used: u64,
    requested: u64,
    parent: u64,
) -> Result<(), ExecutionOutputReservationErrorV1> {
    if used.checked_add(requested).is_none_or(|next| next > parent) {
        return Err(ExecutionOutputReservationErrorV1::CapacityUnavailable);
    }
    Ok(())
}

pub(crate) struct RetainedClaim {
    pub(crate) execution: [u8; 16],
    pub(crate) create_operation: [u8; 16],
    pub(crate) assignment: ObjectDigest,
    pub(crate) parent_profile: ObjectDigest,
    pub(crate) claim_commitment: ObjectDigest,
    pub(crate) requested_bytes: u64,
    pub(crate) parent_bytes: u64,
    pub(crate) record_digest: ObjectDigest,
}

pub(crate) fn decode_claim(
    bytes: &[u8],
) -> Result<RetainedClaim, ExecutionOutputReservationErrorV1> {
    let required_digests = [40, 72, 104, 136, 168, 200, 248];
    if bytes.len() != CLAIM_BYTES
        || bytes.get(..8) != Some(CLAIM_MAGIC.as_slice())
        || Sha256::digest(&bytes[..280]).as_slice() != &bytes[280..]
        || bytes[8..24] == [0; 16]
        || bytes[24..40] == [0; 16]
        || required_digests
            .iter()
            .any(|start| bytes[*start..*start + 32] == [0; 32])
    {
        return Err(ExecutionOutputReservationErrorV1::CorruptLedger);
    }
    let requested_bytes = u64::from_be_bytes(
        bytes[232..240]
            .try_into()
            .map_err(|_| ExecutionOutputReservationErrorV1::CorruptLedger)?,
    );
    let parent_bytes = u64::from_be_bytes(
        bytes[240..248]
            .try_into()
            .map_err(|_| ExecutionOutputReservationErrorV1::CorruptLedger)?,
    );
    if requested_bytes > parent_bytes {
        return Err(ExecutionOutputReservationErrorV1::CorruptLedger);
    }

    Ok(RetainedClaim {
        execution: bytes[8..24]
            .try_into()
            .map_err(|_| ExecutionOutputReservationErrorV1::CorruptLedger)?,
        create_operation: bytes[24..40]
            .try_into()
            .map_err(|_| ExecutionOutputReservationErrorV1::CorruptLedger)?,
        assignment: ObjectDigest::from_bytes(
            bytes[104..136]
                .try_into()
                .map_err(|_| ExecutionOutputReservationErrorV1::CorruptLedger)?,
        ),
        parent_profile: ObjectDigest::from_bytes(
            bytes[136..168]
                .try_into()
                .map_err(|_| ExecutionOutputReservationErrorV1::CorruptLedger)?,
        ),
        claim_commitment: ObjectDigest::from_bytes(
            bytes[248..280]
                .try_into()
                .map_err(|_| ExecutionOutputReservationErrorV1::CorruptLedger)?,
        ),
        requested_bytes,
        parent_bytes,
        record_digest: ObjectDigest::from_bytes(Sha256::digest(bytes).into()),
    })
}

pub(crate) fn marker_bytes(assignment: ObjectDigest, parent_bytes: u64) -> [u8; MARKER_BYTES] {
    let mut marker = [0_u8; MARKER_BYTES];
    marker[..8].copy_from_slice(MARKER_MAGIC);
    marker[8..40].copy_from_slice(assignment.as_bytes());
    marker[40..].copy_from_slice(&parent_bytes.to_be_bytes());
    marker
}

pub(crate) struct LedgerReadback {
    pub(crate) used: u64,
    pub(crate) marker_seen: bool,
    pub(crate) replay: bool,
}

pub(crate) fn replay_ledger<'record>(
    records: impl IntoIterator<Item = (&'record [u8], &'record [u8])>,
    assignment: ObjectDigest,
    parent_bytes: u64,
    expected_key: &[u8],
    expected_bytes: &[u8],
) -> Result<LedgerReadback, ExecutionOutputReservationErrorV1> {
    let marker = marker_bytes(assignment, parent_bytes);
    let mut readback = LedgerReadback {
        used: 0,
        marker_seen: false,
        replay: false,
    };
    let mut claims = 0_usize;

    for (key, value) in records {
        if key == MARKER_KEY {
            if readback.marker_seen || value != marker {
                return Err(ExecutionOutputReservationErrorV1::CorruptLedger);
            }
            readback.marker_seen = true;
            continue;
        }
        if key.len() != 17 || key[0] != CLAIM_KEY_PREFIX {
            return Err(ExecutionOutputReservationErrorV1::CorruptLedger);
        }
        let retained = decode_claim(value)?;
        if key[1..] != retained.execution
            || retained.assignment != assignment
            || retained.parent_bytes != parent_bytes
        {
            return Err(ExecutionOutputReservationErrorV1::CorruptLedger);
        }
        readback.used = readback
            .used
            .checked_add(retained.requested_bytes)
            .ok_or(ExecutionOutputReservationErrorV1::CorruptLedger)?;
        claims += 1;
        if key == expected_key {
            if value != expected_bytes {
                return Err(ExecutionOutputReservationErrorV1::Conflict);
            }
            readback.replay = true;
        }
    }
    if (readback.marker_seen != (claims > 0)) || readback.used > parent_bytes {
        return Err(ExecutionOutputReservationErrorV1::CorruptLedger);
    }
    Ok(readback)
}

pub(crate) fn claim_key(execution: ExecutionId) -> Vec<u8> {
    let mut key = Vec::with_capacity(17);
    key.push(CLAIM_KEY_PREFIX);
    key.extend_from_slice(execution.as_bytes());
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use crate::journal::{JournalRecord, JournalTransaction, RecordNamespace};

    fn replay_records(
        records: &[(Vec<u8>, Vec<u8>)],
        assignment: ObjectDigest,
        parent_bytes: u64,
        expected_key: &[u8],
        expected_bytes: &[u8],
    ) -> Result<LedgerReadback, ExecutionOutputReservationErrorV1> {
        replay_ledger(
            records
                .iter()
                .map(|(key, value)| (key.as_slice(), value.as_slice())),
            assignment,
            parent_bytes,
            expected_key,
            expected_bytes,
        )
    }

    fn command(mode: ExecutionIoMode, capture_bytes: u64) -> Command {
        Command {
            io_mode: mode.into(),
            detached_capture_bytes: capture_bytes,
            ..Default::default()
        }
    }

    fn retained_record(execution: u8, assignment: u8, requested: u64, parent: u64) -> Vec<u8> {
        let mut bytes = [0_u8; CLAIM_BYTES];
        bytes[..8].copy_from_slice(CLAIM_MAGIC);
        bytes[8..24].fill(execution);
        bytes[24..40].fill(3);
        for (index, start) in [40, 72, 104, 136, 168, 200, 248].into_iter().enumerate() {
            bytes[start..start + 32].fill(if start == 104 {
                assignment
            } else {
                index as u8 + 1
            });
        }
        bytes[232..240].copy_from_slice(&requested.to_be_bytes());
        bytes[240..248].copy_from_slice(&parent.to_be_bytes());
        let checksum = Sha256::digest(&bytes[..280]);
        bytes[280..].copy_from_slice(&checksum);
        bytes.to_vec()
    }

    #[test]
    fn accepted_io_shape_derives_zero_or_exact_capture_budget() {
        assert_eq!(
            requested_output_bytes(&command(ExecutionIoMode::EXECUTION_IO_MODE_STREAM, 0)).ok(),
            Some(0)
        );
        assert_eq!(
            requested_output_bytes(&command(ExecutionIoMode::EXECUTION_IO_MODE_PTY, 0)).ok(),
            Some(0)
        );
        assert_eq!(
            requested_output_bytes(&command(
                ExecutionIoMode::EXECUTION_IO_MODE_DETACHED_CAPTURE,
                79
            ))
            .ok(),
            Some(79)
        );
        assert!(
            requested_output_bytes(&command(ExecutionIoMode::EXECUTION_IO_MODE_STREAM, 1)).is_err()
        );
        assert!(
            requested_output_bytes(&command(
                ExecutionIoMode::EXECUTION_IO_MODE_DETACHED_CAPTURE,
                0
            ))
            .is_err()
        );
    }

    #[test]
    fn zero_byte_stream_is_durable_and_capacity_checks_overflow() {
        let assignment = ObjectDigest::from_bytes([9; 32]);
        let key = claim_key(ExecutionId::from_bytes([1; 16]));
        let claim = retained_record(1, 9, 0, 100);
        let records = vec![
            (MARKER_KEY.to_vec(), marker_bytes(assignment, 100).to_vec()),
            (key.clone(), claim.clone()),
        ];
        let readback =
            replay_records(&records, assignment, 100, &key, &claim).expect("exact replay");
        assert!(readback.replay);
        assert_eq!(readback.used, 0);

        assert!(admit_next(60, 40, 100).is_ok());
        assert!(matches!(
            admit_next(100, 1, 100),
            Err(ExecutionOutputReservationErrorV1::CapacityUnavailable)
        ));
        assert!(matches!(
            admit_next(u64::MAX, 1, u64::MAX),
            Err(ExecutionOutputReservationErrorV1::CapacityUnavailable)
        ));
    }

    #[test]
    fn replay_rejects_marker_loss_assignment_change_and_torn_record() {
        let assignment = ObjectDigest::from_bytes([9; 32]);
        let key = claim_key(ExecutionId::from_bytes([1; 16]));
        let claim = retained_record(1, 9, 20, 100);
        let marker = (MARKER_KEY.to_vec(), marker_bytes(assignment, 100).to_vec());
        assert!(matches!(
            replay_records(
                &[(key.clone(), claim.clone())],
                assignment,
                100,
                &key,
                &claim
            ),
            Err(ExecutionOutputReservationErrorV1::CorruptLedger)
        ));
        assert!(matches!(
            replay_records(
                &[marker.clone(), (key.clone(), claim.clone())],
                ObjectDigest::from_bytes([8; 32]),
                100,
                &key,
                &claim
            ),
            Err(ExecutionOutputReservationErrorV1::CorruptLedger)
        ));
        let mut torn = claim.clone();
        torn[232] ^= 1;
        assert!(matches!(
            replay_records(
                &[marker.clone(), (key.clone(), torn)],
                assignment,
                100,
                &key,
                &claim
            ),
            Err(ExecutionOutputReservationErrorV1::CorruptLedger)
        ));

        let substituted = retained_record(1, 9, 21, 100);
        assert!(matches!(
            replay_records(
                &[marker.clone(), (key.clone(), substituted)],
                assignment,
                100,
                &key,
                &claim
            ),
            Err(ExecutionOutputReservationErrorV1::Conflict)
        ));
        let other_key = claim_key(ExecutionId::from_bytes([2; 16]));
        let other_claim = retained_record(2, 9, 90, 100);
        assert!(matches!(
            replay_records(
                &[
                    marker,
                    (key.clone(), claim.clone()),
                    (other_key, other_claim)
                ],
                assignment,
                100,
                &key,
                &claim
            ),
            Err(ExecutionOutputReservationErrorV1::CorruptLedger)
        ));
    }

    #[test]
    fn protected_journal_reopen_retains_zero_byte_reservation() {
        let directory = tempfile::Builder::new()
            .prefix("aos-output-ledger-")
            .tempdir_in(std::env::current_dir().expect("current directory"))
            .expect("private test directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private protected directory");
        let uid = directory
            .path()
            .metadata()
            .expect("directory metadata")
            .uid();
        let assignment = ObjectDigest::from_bytes([9; 32]);
        let key = claim_key(ExecutionId::from_bytes([1; 16]));
        let claim = retained_record(1, 9, 0, 0);
        let marker = marker_bytes(assignment, 0);

        let (mut journal, _) = Journal::open_protected_at_uid(
            directory.path(),
            "ledger.journal",
            Default::default(),
            uid,
        )
        .expect("protected journal");
        let mut authority = journal
            .claim_protected_authority(RecordNamespace::Effect)
            .expect("exclusive protected claim");
        let transaction = JournalTransaction::new(
            [1; 16],
            vec![
                JournalRecord::put(
                    RecordNamespace::Effect,
                    MARKER_KEY.to_vec(),
                    marker.to_vec(),
                ),
                JournalRecord::put(RecordNamespace::Effect, key.clone(), claim.clone()),
            ],
        )
        .expect("canonical transaction");
        authority.commit(&transaction).expect("durable reservation");
        drop(authority);
        drop(journal);

        let (mut reopened, _) = Journal::open_protected_at_uid(
            directory.path(),
            "ledger.journal",
            Default::default(),
            uid,
        )
        .expect("protected cold replay");
        let authority = reopened
            .claim_protected_authority(RecordNamespace::Effect)
            .expect("reopened exclusive claim");
        let records = authority
            .records()
            .expect("protected records")
            .map(|(key, value)| (key.to_vec(), value.to_vec()))
            .collect::<Vec<_>>();
        let readback = replay_records(&records, assignment, 0, &key, &claim)
            .expect("exact zero-byte reservation");
        assert!(readback.replay);
        assert_eq!(readback.used, 0);
    }
}
