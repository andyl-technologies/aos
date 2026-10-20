//! Owns finite prepaid recipient history and exact predecessor CAS DATA.
//!
//! ```text
//! current = i || enrollment.node[16]
//! history = j || sha256(domain || enrollment96 || ordinal8)[..16]
//! row = AOSRRI03 || legacy-body[584] || allowance[176]
//!       || recipients:u64be || range-commitment[32] || checksum[32]
//! ```
//!
//! Native accepts these bytes only through the existing private launch owner.
//! Skipped ordinals remain fully charged; history records committed recipients,
//! not invented successful launches or a refund of uncommitted attempts.

use aos_sandbox_core::ResourceVector;
use sha2::{Digest as _, Sha256};

use super::{RecipientIncarnation, RecipientSuccessorMutation};
use super::super::{EnrollmentIdentity, ImageBootstrapPolicy, JournalRecord,
    JournalTransaction, RecordNamespace, ResourceBankDataError, State, codec, replay};

pub(in super::super) const HISTORY_PREFIX: u8 = b'j';

/// Specifies the complete canonical finite-range recipient row width.
pub const RECIPIENT_RANGE_INCARNATION_BYTES: usize = 840;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RecipientRange {
    pub(super) recipients: u64,
    pub(super) allowance: ResourceVector,
    pub(super) commitment: [u8; 32],
}

pub(super) fn seal_initial(mut row: RecipientIncarnation, policy: ImageBootstrapPolicy)
    -> Result<RecipientIncarnation, ResourceBankDataError>
{
    if let Some((recipients, allowance)) = policy.controller_recovery_range_v1() {
        row.range = Some(RecipientRange { recipients, allowance,
            commitment: codec::controller_recipient_range_commitment_v1(row.enrollment, policy)? });
    }
    Ok(row)
}

pub(super) fn require_policy(row: RecipientIncarnation, policy: ImageBootstrapPolicy)
    -> Result<(), ResourceBankDataError>
{
    match (row.range, policy.controller_recovery_range_v1()) {
        (None, None) => Ok(()),
        (Some(range), Some((recipients, allowance)))
            if range.recipients == recipients && range.allowance == allowance
                && range.commitment == codec::controller_recipient_range_commitment_v1(row.enrollment, policy)? => Ok(()),
        _ => Err(ResourceBankDataError::Conflict),
    }
}

pub(super) fn encode(row: RecipientIncarnation) -> Result<Vec<u8>, ResourceBankDataError> {
    codec::validate_enrollment(row.enrollment)?;
    let range = row.range.ok_or(ResourceBankDataError::CorruptLedger)?;
    super::super::require_recipient_range_v1(range.recipients, range.allowance, row.recovery)?;
    if row.generation > range.recipients || row.recipient == [0; 16]
        || row.normal == ResourceVector::ZERO || range.commitment == [0; 32]
        || (row.generation == 0 && (row.predecessor_recipient != [0; 16]
            || row.pid1_original_cut != [0; 32] || row.predecessor_bank != [0; 32]
            || row.predecessor_row != [0; 32]))
        || (row.generation > 0 && (row.predecessor_recipient == [0; 16]
            || row.predecessor_recipient == row.recipient || row.pid1_original_cut == [0; 32]
            || row.predecessor_bank == [0; 32] || row.predecessor_row == [0; 32]))
    { return Err(ResourceBankDataError::CorruptLedger); }
    row.normal.checked_add(row.recovery)?;
    let mut bytes = vec![0; RECIPIENT_RANGE_INCARNATION_BYTES];
    bytes[..8].copy_from_slice(b"AOSRRI03");
    codec::encode_enrollment(row.enrollment, &mut bytes[8..104]);
    bytes[104..112].copy_from_slice(&row.generation.to_be_bytes());
    bytes[112..128].copy_from_slice(&row.predecessor_recipient);
    bytes[128..144].copy_from_slice(&row.recipient);
    bytes[144..176].copy_from_slice(&row.pid1_original_cut);
    bytes[176..208].copy_from_slice(&row.predecessor_bank);
    bytes[208..240].copy_from_slice(&row.predecessor_row);
    codec::encode_vector(row.normal, &mut bytes[240..416]);
    codec::encode_vector(row.recovery, &mut bytes[416..592]);
    codec::encode_vector(range.allowance, &mut bytes[592..768]);
    bytes[768..776].copy_from_slice(&range.recipients.to_be_bytes());
    bytes[776..808].copy_from_slice(&range.commitment);
    let checksum = Sha256::digest(&bytes[..808]);
    bytes[808..].copy_from_slice(&checksum);
    Ok(bytes)
}

pub(super) fn decode(bytes: &[u8]) -> Result<RecipientIncarnation, ResourceBankDataError> {
    codec::require_record(bytes, RECIPIENT_RANGE_INCARNATION_BYTES, b"AOSRRI03")?;
    let row = RecipientIncarnation {
        enrollment: codec::decode_enrollment(&bytes[8..104])?,
        generation: u64::from_be_bytes(codec::fixed(&bytes[104..112])?),
        predecessor_recipient: codec::fixed(&bytes[112..128])?,
        recipient: codec::fixed(&bytes[128..144])?,
        pid1_original_cut: codec::fixed(&bytes[144..176])?,
        predecessor_bank: codec::fixed(&bytes[176..208])?,
        predecessor_row: codec::fixed(&bytes[208..240])?,
        normal: codec::decode_vector(&bytes[240..416])?,
        recovery: codec::decode_vector(&bytes[416..592])?,
        range: Some(RecipientRange {
            allowance: codec::decode_vector(&bytes[592..768])?,
            recipients: u64::from_be_bytes(codec::fixed(&bytes[768..776])?),
            commitment: codec::fixed(&bytes[776..808])?,
        }),
    };
    if encode(row)? != bytes { return Err(ResourceBankDataError::CorruptLedger); }
    Ok(row)
}

pub(in super::super) fn history_key(row: RecipientIncarnation) -> [u8; 17] {
    let mut identity = [0; 96];
    codec::encode_enrollment(row.enrollment, &mut identity);
    let hash = Sha256::new().chain_update(b"AOS-controller-recipient-history-v1\0")
        .chain_update(identity).chain_update(row.generation.to_be_bytes()).finalize();
    let mut key = [HISTORY_PREFIX; 17];
    key[1..].copy_from_slice(&hash[..16]);
    key
}

/// Resolves a funding row to its exact current or immutable historical recipient.
///
/// This passive lookup never makes an archived invocation current.
///
/// # Errors
/// Rejects malformed history, duplicate recipient identities or no matching row.
pub fn controller_recipient_for_invocation_v2(state: &State, enrollment: EnrollmentIdentity,
    invocation: [u8; 16]) -> Result<RecipientIncarnation, ResourceBankDataError>
{
    let mut selected = None;
    for ((namespace, key), value) in state {
        if *namespace != RecordNamespace::ControllerResourceReservation
            || !matches!(key.first(), Some(&super::PREFIX) | Some(&HISTORY_PREFIX)) { continue; }
        let row = super::decode(value)?;
        if row.enrollment == enrollment && row.recipient == invocation {
            if selected.replace(row).is_some() { return Err(ResourceBankDataError::CorruptLedger); }
        }
    }
    selected.ok_or(ResourceBankDataError::CorruptLedger)
}

impl RecipientSuccessorMutation {
    /// Prepares an exact range successor under comparison facts from Native.
    ///
    /// `confirmed_ordinal` and `confirmed_recipient` describe the actual PID1
    /// floor. Every intervening consumed ordinal must have been physically cut
    /// by that SAME retained PID1 range owner before the current child clone.
    /// This DATA constructor cannot establish that Native proof.
    ///
    /// # Errors
    /// Rejects changed enrollment/range, exhausted or repeated ordinal, a bank
    /// predecessor outside the native floor, or an existing archive key.
    pub fn new_range_v2(state: &State, enrollment: EnrollmentIdentity,
        recipient: [u8; 16], ordinal: u64, commitment: [u8; 32],
        confirmed_ordinal: u64, confirmed_recipient: [u8; 16],
        pid1_original_cut: [u8; 32]) -> Result<Self, ResourceBankDataError>
    {
        if replay::validate(state)? != Some(enrollment) { return Err(ResourceBankDataError::Conflict); }
        let previous = super::recipient_incarnation(state, enrollment)?
            .ok_or(ResourceBankDataError::EnrollmentUnavailable)?;
        let range = previous.range.ok_or(ResourceBankDataError::EnrollmentUnavailable)?;
        if commitment != range.commitment || ordinal > range.recipients
            || ordinal <= previous.generation || confirmed_ordinal > previous.generation
            || (confirmed_ordinal == previous.generation && confirmed_recipient != previous.recipient)
            || controller_recipient_for_invocation_v2(state, enrollment, recipient).is_ok()
        { return Err(ResourceBankDataError::Conflict); }
        // If the durable bank is ahead of PID1's confirmed floor, the floor
        // must still exist literally in the same immutable committed chain.
        let confirmed = controller_recipient_for_invocation_v2(state, enrollment, confirmed_recipient)?;
        if confirmed.generation != confirmed_ordinal { return Err(ResourceBankDataError::Conflict); }
        let archive_key = history_key(previous);
        if state.contains_key(&(RecordNamespace::ControllerResourceReservation, archive_key.to_vec())) {
            return Err(ResourceBankDataError::Conflict);
        }
        let before = super::bank_digest(state, None)?;
        let row = RecipientIncarnation { generation: ordinal,
            predecessor_recipient: previous.recipient, recipient, pid1_original_cut,
            predecessor_bank: before, predecessor_row: previous.commitment()?, ..previous };
        let encoded = encode(row)?;
        let archive = previous.to_bytes()?;
        let current_key = replay::key(super::PREFIX, enrollment.node);
        let after = super::bank_digest_two(state,
            Some((&current_key, &encoded)), Some((&archive_key, &archive)))?;
        Ok(Self { row, encoded, archive: Some((archive_key, archive)), before, after })
    }
}

pub(in super::super) fn require_chain(state: &State, current: RecipientIncarnation)
    -> Result<(), ResourceBankDataError>
{
    let range = current.range.ok_or(ResourceBankDataError::CorruptLedger)?;
    let mut count = 0_u64;
    for ((namespace, key), value) in state {
        if *namespace != RecordNamespace::ControllerResourceReservation || key.first() != Some(&HISTORY_PREFIX) { continue; }
        let row = decode(value)?;
        if key.as_slice() != history_key(row) || row.enrollment != current.enrollment
            || row.range != Some(range) || row.normal != current.normal || row.recovery != current.recovery
            || row.generation >= current.generation || row.recipient == current.recipient
        { return Err(ResourceBankDataError::CorruptLedger); }
        count = count.checked_add(1).ok_or(ResourceBankDataError::Conflict)?;
    }
    let mut cursor = current;
    let mut visited = 0_u64;
    while cursor.generation > 0 {
        let previous = controller_recipient_for_invocation_v2(state, current.enrollment, cursor.predecessor_recipient)?;
        if previous.generation >= cursor.generation || previous.commitment()? != cursor.predecessor_row {
            return Err(ResourceBankDataError::CorruptLedger);
        }
        visited = visited.checked_add(1).ok_or(ResourceBankDataError::Conflict)?;
        if visited > count { return Err(ResourceBankDataError::CorruptLedger); }
        cursor = previous;
    }
    if visited != count { return Err(ResourceBankDataError::CorruptLedger); }
    Ok(())
}

pub(super) fn validate_transaction(state: &State, transaction: &JournalTransaction)
    -> Result<(), ResourceBankDataError>
{
    let mut selected = None;
    for record in transaction.records() {
        if record.namespace() != RecordNamespace::ControllerResourceReservation || record.key().first() != Some(&super::PREFIX) { continue; }
        if selected.is_some() { return Err(ResourceBankDataError::CorruptLedger); }
        let row = decode(record.value().ok_or(ResourceBankDataError::CorruptLedger)?)?;
        if record.key() != replay::key(super::PREFIX, row.enrollment.node) { return Err(ResourceBankDataError::CorruptLedger); }
        selected = Some(row);
    }
    let row = selected.ok_or(ResourceBankDataError::CorruptLedger)?;
    let previous = super::recipient_incarnation(state, row.enrollment)?;
    if previous.is_none() && row.generation == 0 && replay::validate(state)?.is_none() {
        if transaction.records().iter().any(|record| record.namespace() == RecordNamespace::ControllerResourceReservation
            && record.key().first() == Some(&HISTORY_PREFIX)) { return Err(ResourceBankDataError::CorruptLedger); }
        return Ok(());
    }
    let previous = previous.ok_or(ResourceBankDataError::Conflict)?;
    let key = history_key(previous);
    let archive = previous.to_bytes()?;
    if previous.range != row.range || previous.normal != row.normal || previous.recovery != row.recovery
        || controller_recipient_for_invocation_v2(state, row.enrollment, row.recipient).is_ok()
        || row.generation <= previous.generation || row.predecessor_recipient != previous.recipient
        || row.predecessor_row != previous.commitment()? || row.predecessor_bank != super::bank_digest(state, None)?
        || state.contains_key(&(RecordNamespace::ControllerResourceReservation, key.to_vec()))
        || transaction.records().len() != 2
    { return Err(ResourceBankDataError::Conflict); }
    let records = [JournalRecord::put(RecordNamespace::ControllerResourceReservation, key.to_vec(), archive),
        JournalRecord::put(RecordNamespace::ControllerResourceReservation,
            replay::key(super::PREFIX, row.enrollment.node).to_vec(), encode(row)?)];
    if transaction.records() != records.as_slice() { return Err(ResourceBankDataError::Conflict); }
    Ok(())
}
