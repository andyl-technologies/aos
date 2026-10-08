//! Canonical legacy capacity-reservation DATA and closed purpose layouts.
//!
//! These values and hash identities carry no reserved capacity or owner custody.
//! Complete family selection, accounting, and protected admission remain upper.
//!
//! ```text
//! AOSJCR01 | version:u16be=1/2 | namespace:u8 | purpose:u8 | reserved:2 |
//! owner/operation/artifact/checkpoint/head commitments | terminal/poison bounds |
//! [V2 future-transactions:u32be] | admission-ID:16 | reservation-ID:32
//! ```

use aos_sandbox_core::RecordNamespace;
use sha2::{Digest as _, Sha256};

use super::JournalTransactionDataError;

/// Prefixes canonical reservation-identity keys.
const KEY_PREFIX: &[u8] = b"aos.journal.global-capacity-reservation.v1\0";
/// Separates V1 reservation-identity hashes.
pub const RECORD_DOMAIN: &[u8] = b"aos.sandbox.journal.global-capacity-reservation.v1\0";
/// Sizes the canonical V1 reservation representation.
pub const VALUE_BYTES_V1: usize = 262;
/// Sizes the canonical V2 reservation representation.
pub const VALUE_BYTES_V2: usize = 266;
/// Separates V2 reservation-identity hashes.
const RECORD_DOMAIN_V2: &[u8] = b"aos.sandbox.journal.global-capacity-reservation.v2\0";
/// Bounds the future-transaction count encoded by supported purposes.
pub const MAXIMUM_FUTURE_TRANSACTIONS: u32 = 3;

/// Selects one closed cross-namespace admission and settlement protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum GlobalCapacityReservationPurposeV1 {
    /// Publisher permit issuance and terminal publication settlement.
    PublisherCompletion = 1,
    /// Runtime execution admission and terminal effect settlement.
    RuntimeExecution = 2,
    /// Source-provider native admission and terminal settlement.
    SourceProviderNativeTerminal = 3,
    /// Root project intent, exact decision, and bounded history retirement.
    RootProjectAdmission = 4,
    /// Controller acceptance and exact Root-history retirement in one Effect.
    ControllerProjectAdmission = 5,
    /// Root-owned initial Source intent and exact semantic-floor settlement.
    RootSourceGenesisAnchor = 6,
    /// Non-authorizing Controller resource preparation and retained quarantine.
    ControllerConsumerResource = 7,
    /// Fixed Root first-successor settlement; generic capacity scopes refuse it.
    RootFirstSourceSuccessorAnchor = 8,
    /// Fixed Source first-successor ACK; generic capacity scopes refuse it.
    SourceFirstSourceSuccessorAck = 9,
    /// Fixed Controller first-successor completion; generic scopes refuse it.
    ControllerFirstSourceSuccessorComplete = 10,
}

impl GlobalCapacityReservationPurposeV1 {
    /// Returns the fixed DATA namespace associated with this closed purpose.
    pub const fn owner_namespace(self) -> RecordNamespace {
        match self {
            Self::PublisherCompletion => RecordNamespace::PublisherAuthority,
            Self::RuntimeExecution => RecordNamespace::Effect,
            Self::RootProjectAdmission => RecordNamespace::DesiredState,
            Self::SourceProviderNativeTerminal => RecordNamespace::SourceProviderAuthority,
            Self::ControllerProjectAdmission => RecordNamespace::Effect,
            Self::RootSourceGenesisAnchor => RecordNamespace::DesiredState,
            Self::ControllerConsumerResource => RecordNamespace::ControllerConsumerReadAttempt,
            Self::RootFirstSourceSuccessorAnchor
            | Self::SourceFirstSourceSuccessorAck
            | Self::ControllerFirstSourceSuccessorComplete => RecordNamespace::DesiredState,
        }
    }

    /// Reports membership in the closed purpose's namespace set.
    ///
    /// This DATA classification does not admit a write or grant namespace authority.
    pub const fn permits(self, namespace: RecordNamespace) -> bool {
        match self {
            Self::PublisherCompletion => matches!(
                namespace,
                RecordNamespace::PublisherAuthority
                    | RecordNamespace::AuthorityPublication
                    | RecordNamespace::Effect
                    | RecordNamespace::GlobalCapacityReservation
            ),
            Self::RuntimeExecution => matches!(
                namespace,
                RecordNamespace::Effect | RecordNamespace::GlobalCapacityReservation
            ),
            Self::RootProjectAdmission => matches!(
                namespace,
                RecordNamespace::DesiredState | RecordNamespace::GlobalCapacityReservation
            ),
            Self::SourceProviderNativeTerminal => matches!(
                namespace,
                RecordNamespace::SourceProviderAuthority
                    | RecordNamespace::GlobalCapacityReservation
            ),
            Self::ControllerProjectAdmission => matches!(
                namespace,
                RecordNamespace::Effect | RecordNamespace::GlobalCapacityReservation
            ),
            Self::RootSourceGenesisAnchor => matches!(
                namespace,
                RecordNamespace::DesiredState | RecordNamespace::GlobalCapacityReservation
            ),
            Self::ControllerConsumerResource => matches!(
                namespace,
                RecordNamespace::ControllerConsumerReadAttempt
                    | RecordNamespace::GlobalCapacityReservation
            ),
            Self::RootFirstSourceSuccessorAnchor
            | Self::SourceFirstSourceSuccessorAck
            | Self::ControllerFirstSourceSuccessorComplete => matches!(
                namespace,
                RecordNamespace::DesiredState | RecordNamespace::GlobalCapacityReservation
            ),
        }
    }

    /// Decodes one supported closed legacy-purpose discriminant.
    ///
    /// # Errors
    ///
    /// Rejects every unknown purpose byte.
    pub fn from_byte(value: u8) -> Result<Self, JournalTransactionDataError> {
        match value {
            1 => Ok(Self::PublisherCompletion),
            2 => Ok(Self::RuntimeExecution),
            3 => Ok(Self::SourceProviderNativeTerminal),
            4 => Ok(Self::RootProjectAdmission),
            5 => Ok(Self::ControllerProjectAdmission),
            6 => Ok(Self::RootSourceGenesisAnchor),
            7 => Ok(Self::ControllerConsumerResource),
            8 => Ok(Self::RootFirstSourceSuccessorAnchor),
            9 => Ok(Self::SourceFirstSourceSuccessorAck),
            10 => Ok(Self::ControllerFirstSourceSuccessorComplete),
            _ => Err(JournalTransactionDataError::MalformedRecord(
                "unknown global capacity reservation purpose",
            )),
        }
    }

    /// Reports whether the DATA purpose names a fixed first-Source-successor step.
    pub const fn is_first_source_successor(self) -> bool {
        matches!(
            self,
            Self::RootFirstSourceSuccessorAnchor
                | Self::SourceFirstSourceSuccessorAck
                | Self::ControllerFirstSourceSuccessorComplete
        )
    }
}

/// Describes one exact operation whose terminal capacity must remain available.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GlobalCapacityReservationRequestV1 {
    /// Closed transaction protocol that owns this reservation.
    pub purpose: GlobalCapacityReservationPurposeV1,
    /// Namespace that owns the terminal operation.
    pub owner_namespace: RecordNamespace,
    /// Stable owner identity within that namespace.
    pub owner_id: [u8; 32],
    /// Exact owner or permit commitment.
    pub owner_digest: [u8; 32],
    /// Stable operation identity.
    pub operation_id: [u8; 16],
    /// Exact admitted artifact commitment.
    pub artifact_digest: [u8; 32],
    /// Exact admission checkpoint commitment.
    pub checkpoint_digest: [u8; 32],
    /// Exact predecessor or chain-head commitment.
    pub chain_head_digest: [u8; 32],
    /// Maximum remaining durable transactions, including final settlement.
    /// Legacy reservations retain exactly one; ordered transfers decrease this
    /// count atomically with their remaining record and byte budgets.
    pub future_transactions: u32,
    /// Maximum records in the successful terminal transaction.
    pub terminal_records: u32,
    /// Maximum encoded bytes in the successful terminal transaction.
    pub terminal_bytes: u64,
    /// Maximum records in the poison terminal transaction.
    pub poison_records: u32,
    /// Maximum encoded bytes in the poison terminal transaction.
    pub poison_bytes: u64,
}

/// Identifies a replayed reservation without trusting its retained owner digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GlobalCapacityReservationRecoveryBindingV1 {
    /// Closed transaction protocol that owns this reservation.
    pub purpose: GlobalCapacityReservationPurposeV1,
    /// Stable operation identity.
    pub operation_id: [u8; 16],
    /// Exact admitted artifact commitment.
    pub artifact_digest: [u8; 32],
    /// Exact admission checkpoint commitment.
    pub checkpoint_digest: [u8; 32],
    /// Exact predecessor or chain-head commitment.
    pub chain_head_digest: [u8; 32],
    /// Exact remaining durable transaction budget.
    pub future_transactions: u32,
    /// Maximum successful terminal record count.
    pub terminal_records: u32,
    /// Maximum successful terminal byte count.
    pub terminal_bytes: u64,
    /// Maximum poison terminal record count.
    pub poison_records: u32,
    /// Maximum poison terminal byte count.
    pub poison_bytes: u64,
}

/// Encodes the exact canonical key for a reservation identity.
pub fn reservation_key(reservation_id: [u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(KEY_PREFIX.len() + reservation_id.len());
    key.extend_from_slice(KEY_PREFIX);
    key.extend_from_slice(&reservation_id);
    key
}

/// Derives a canonical reservation identity from the complete supplied DATA.
pub fn reservation_id(
    request: &GlobalCapacityReservationRequestV1,
    admission_transaction_id: [u8; 16],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(if uses_v2(request) {
        RECORD_DOMAIN_V2
    } else {
        RECORD_DOMAIN
    });
    hasher.update([request.purpose as u8]);
    hasher.update([request.owner_namespace as u8]);
    hasher.update(request.owner_id);
    hasher.update(request.owner_digest);
    hasher.update(request.operation_id);
    hasher.update(request.artifact_digest);
    hasher.update(request.checkpoint_digest);
    hasher.update(request.chain_head_digest);
    hasher.update(request.terminal_records.to_be_bytes());
    hasher.update(request.terminal_bytes.to_be_bytes());
    hasher.update(request.poison_records.to_be_bytes());
    hasher.update(request.poison_bytes.to_be_bytes());
    if uses_v2(request) {
        hasher.update(request.future_transactions.to_be_bytes());
    }
    hasher.update(admission_transaction_id);
    hasher.finalize().into()
}

/// Compares a candidate identity with the canonical reservation DATA hash.
pub fn capacity_reservation_identity_is_exact_v1(
    request: &GlobalCapacityReservationRequestV1,
    admission_transaction_id: [u8; 16],
    candidate_reservation_id: [u8; 32],
) -> bool {
    reservation_id(request, admission_transaction_id) == candidate_reservation_id
}

/// Encodes the supplied legacy reservation DATA without admitting it.
pub fn encode_reservation(
    request: &GlobalCapacityReservationRequestV1,
    admission_transaction_id: [u8; 16],
    reservation_id: [u8; 32],
) -> Vec<u8> {
    let v2 = uses_v2(request);
    let mut value = Vec::with_capacity(if v2 { VALUE_BYTES_V2 } else { VALUE_BYTES_V1 });
    value.extend_from_slice(b"AOSJCR01");
    value.extend_from_slice(&(if v2 { 2_u16 } else { 1_u16 }).to_be_bytes());
    value.push(request.owner_namespace as u8);
    value.push(request.purpose as u8);
    value.extend_from_slice(&[0; 2]);
    value.extend_from_slice(&request.owner_id);
    value.extend_from_slice(&request.owner_digest);
    value.extend_from_slice(&request.operation_id);
    value.extend_from_slice(&request.artifact_digest);
    value.extend_from_slice(&request.checkpoint_digest);
    value.extend_from_slice(&request.chain_head_digest);
    value.extend_from_slice(&request.terminal_records.to_be_bytes());
    value.extend_from_slice(&request.terminal_bytes.to_be_bytes());
    value.extend_from_slice(&request.poison_records.to_be_bytes());
    value.extend_from_slice(&request.poison_bytes.to_be_bytes());
    if v2 {
        value.extend_from_slice(&request.future_transactions.to_be_bytes());
    }
    value.extend_from_slice(&admission_transaction_id);
    value.extend_from_slice(&reservation_id);
    value
}

/// Decodes the exact legacy reservation layout as nonauthorizing DATA.
///
/// # Errors
///
/// Rejects framing, namespace, purpose, transaction-count, or trailing-byte violations.
pub fn decode_reservation(
    value: &[u8],
) -> Result<(GlobalCapacityReservationRequestV1, [u8; 16], [u8; 32]), JournalTransactionDataError> {
    let v2 =
        value.len() == VALUE_BYTES_V2 && value.get(8..10) == Some(2_u16.to_be_bytes().as_slice());
    let v1 =
        value.len() == VALUE_BYTES_V1 && value.get(8..10) == Some(1_u16.to_be_bytes().as_slice());
    if (!v1 && !v2) || &value[..8] != b"AOSJCR01" || value[12..14] != [0; 2] {
        return Err(JournalTransactionDataError::MalformedRecord(
            "invalid capacity reservation envelope",
        ));
    }
    let namespace = RecordNamespace::from_byte(value[10])?;
    let purpose = GlobalCapacityReservationPurposeV1::from_byte(value[11])?;
    let mut offset = 14;
    let owner_id = take::<32>(value, &mut offset);
    let owner_digest = take::<32>(value, &mut offset);
    let operation_id = take::<16>(value, &mut offset);
    let artifact_digest = take::<32>(value, &mut offset);
    let checkpoint_digest = take::<32>(value, &mut offset);
    let chain_head_digest = take::<32>(value, &mut offset);
    let terminal_records = u32::from_be_bytes(take::<4>(value, &mut offset));
    let terminal_bytes = u64::from_be_bytes(take::<8>(value, &mut offset));
    let poison_records = u32::from_be_bytes(take::<4>(value, &mut offset));
    let poison_bytes = u64::from_be_bytes(take::<8>(value, &mut offset));
    let future_transactions = if v2 {
        u32::from_be_bytes(take::<4>(value, &mut offset))
    } else {
        1
    };
    let admission_transaction_id = take::<16>(value, &mut offset);
    let reservation_id = take::<32>(value, &mut offset);
    if offset != value.len()
        || future_transactions == 0
        || future_transactions > MAXIMUM_FUTURE_TRANSACTIONS
        || !valid_future_transactions(purpose, future_transactions)
        || (purpose == GlobalCapacityReservationPurposeV1::ControllerProjectAdmission && !v2)
        || (v2
            && future_transactions == 1
            && purpose != GlobalCapacityReservationPurposeV1::ControllerProjectAdmission)
    {
        return Err(JournalTransactionDataError::MalformedRecord(
            "capacity reservation has trailing bytes",
        ));
    }
    Ok((
        GlobalCapacityReservationRequestV1 {
            purpose,
            owner_namespace: namespace,
            owner_id,
            owner_digest,
            operation_id,
            artifact_digest,
            checkpoint_digest,
            chain_head_digest,
            future_transactions,
            terminal_records,
            terminal_bytes,
            poison_records,
            poison_bytes,
        },
        admission_transaction_id,
        reservation_id,
    ))
}

/// Reports whether the supplied DATA requires the canonical V2 layout.
pub fn uses_v2(request: &GlobalCapacityReservationRequestV1) -> bool {
    request.future_transactions != 1
        || request.purpose == GlobalCapacityReservationPurposeV1::ControllerProjectAdmission
}

/// Reports whether a count matches the closed legacy-purpose DATA rule.
pub fn valid_future_transactions(purpose: GlobalCapacityReservationPurposeV1, count: u32) -> bool {
    match purpose {
        GlobalCapacityReservationPurposeV1::ControllerFirstSourceSuccessorComplete => count == 2,
        GlobalCapacityReservationPurposeV1::ControllerProjectAdmission => {
            (1..=MAXIMUM_FUTURE_TRANSACTIONS).contains(&count)
        }
        GlobalCapacityReservationPurposeV1::RootProjectAdmission => (1..=2).contains(&count),
        GlobalCapacityReservationPurposeV1::PublisherCompletion
        | GlobalCapacityReservationPurposeV1::RuntimeExecution
        | GlobalCapacityReservationPurposeV1::SourceProviderNativeTerminal
        | GlobalCapacityReservationPurposeV1::ControllerConsumerResource
        | GlobalCapacityReservationPurposeV1::RootFirstSourceSuccessorAnchor
        | GlobalCapacityReservationPurposeV1::SourceFirstSourceSuccessorAck
        | GlobalCapacityReservationPurposeV1::RootSourceGenesisAnchor => count == 1,
    }
}

fn take<const N: usize>(value: &[u8], offset: &mut usize) -> [u8; N] {
    let mut bytes = [0; N];
    bytes.copy_from_slice(&value[*offset..*offset + N]);
    *offset += N;
    bytes
}
