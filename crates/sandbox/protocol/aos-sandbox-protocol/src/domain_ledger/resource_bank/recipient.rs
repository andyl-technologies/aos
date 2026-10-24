//! Owns passive recipient succession without replacing any bank account.
//!
//! ```text
//! key = i || enrollment.node[16]
//! historical-row = AOSRRI02 || enrollment[96] || generation:u64be
//!       || predecessor-recipient[16] || recipient[16] || PID1-Offer-digest[32]
//!       || complete-predecessor-bank-digest[32] || predecessor-row-digest[32]
//!       || normal-precharge[22*u64be] || recovery-reserve[22*u64be]
//!       || sha256[32]
//! range-row = AOSRRI03 || historical-body[584] || allowance[176]
//!             || recipients:u64be || range-commitment[32] || sha256[32]
//! ```
//!
//! The historical row totals 624 bytes; the range row totals 840. V3 keeps the
//! initial current key and archives each exact committed predecessor under the
//! finite j-key history. Ordinals may skip physically contained attempts that
//! never committed, but a history row does not turn such an attempt into an ACK.
//!
//! These fields and comparisons are DATA. Native must retain the actual original
//! PID1 channel, authenticated Offer, predecessor/recipient, transaction identity,
//! returned commit, readback and final posts. Neither decoding nor preparing a
//! row authorizes replacement, re-enrollment, account reset or resource issuance.

use sha2::{Digest as _, Sha256};

use super::{
    EnrollmentIdentity, JournalRecord, JournalTransaction, RecordNamespace, ResourceBankDataError,
    State, codec, replay,
};

pub(super) const PREFIX: u8 = b'i';
const MAGIC: &[u8; 8] = b"AOSRRI02";
const STATE_DIGEST_DOMAIN: &[u8] = b"AOS-resource-bank-state-v1\0";

#[cfg(test)]
mod tests;

pub(super) mod range;
pub use range::{controller_recipient_for_invocation_v2, RECIPIENT_RANGE_INCARNATION_BYTES};

/// Specifies the historical V2 recipient DATA width, including checksum.
pub const RECIPIENT_INCARNATION_BYTES: usize = 624;

/// Retains one canonical recipient transition as comparison DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecipientIncarnation {
    enrollment: EnrollmentIdentity,
    generation: u64,
    predecessor_recipient: [u8; 16],
    recipient: [u8; 16],
    pid1_original_cut: [u8; 32],
    predecessor_bank: [u8; 32],
    predecessor_row: [u8; 32],
    normal: aos_sandbox_model::ResourceVector,
    recovery: aos_sandbox_model::ResourceVector,
    range: Option<range::RecipientRange>,
}

impl RecipientIncarnation {
    /// Decodes a complete canonical recipient row without granting authority.
    ///
    /// # Errors
    /// Rejects malformed framing, checksum, enrollment or transition fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, ResourceBankDataError> {
        decode(bytes)
    }

    /// Returns the historical enrollment comparison identity.
    pub const fn enrollment(self) -> EnrollmentIdentity {
        self.enrollment
    }

    /// Returns the historical recipient generation.
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the recorded predecessor invocation, without retaining PID1 custody.
    pub const fn predecessor_recipient(self) -> [u8; 16] {
        self.predecessor_recipient
    }

    /// Returns the recorded successor invocation, without accepting that process.
    pub const fn recipient(self) -> [u8; 16] {
        self.recipient
    }

    /// Returns the supplied exact authenticated PID1 Offer commitment DATA.
    pub const fn pid1_original_cut_digest(self) -> [u8; 32] {
        self.pid1_original_cut
    }

    /// Returns the complete historical predecessor bank commitment.
    pub const fn predecessor_bank_digest(self) -> [u8; 32] {
        self.predecessor_bank
    }

    /// Returns the predecessor-row hash, or zero for an initial or legacy V2 row.
    pub const fn predecessor_row_digest(self) -> [u8; 32] {
        self.predecessor_row
    }

    /// Returns the whole precharged normal envelope, including retained uncertainty.
    pub const fn normal_precharge_v1(self) -> aos_sandbox_model::ResourceVector { self.normal }

    /// Returns the image's prepaid recovery reserve inside the same baseline B.
    pub const fn recovery_reserve_v1(self) -> aos_sandbox_model::ResourceVector { self.recovery }

    /// Returns the finite image range, if this is a V11 recipient.
    pub fn prepaid_range_v2(self) -> Option<(u64, aos_sandbox_model::ResourceVector, [u8; 32])> {
        self.range.map(|range| (range.recipients, range.allowance, range.commitment))
    }

    /// Returns the permanently charged amount outside this recipient's allowance.
    ///
    /// # Errors
    /// Rejects invalid full baseline or subtraction arithmetic.
    pub fn outside_allowance_v2(self) -> Result<aos_sandbox_model::ResourceVector, ResourceBankDataError> {
        match self.range {
            Some(range) if self.generation > 0 => Ok(self.normal.checked_add(self.recovery)?.checked_sub(range.allowance)?),
            _ => Ok(self.normal),
        }
    }

    /// Returns the durable whole-envelope precharge at this recipient cut.
    ///
    /// # Errors
    /// Rejects checked N+R overflow. No plane is refunded after succession.
    pub fn charged_baseline_v1(self) -> Result<aos_sandbox_model::ResourceVector, ResourceBankDataError> {
        Ok(if self.generation == 0 { self.normal } else { self.normal.checked_add(self.recovery)? })
    }

    /// Compares the same image's B/N/R partition as passive DATA.
    ///
    /// # Errors
    /// Rejects an older image or a different normal/recovery partition.
    pub fn require_policy_v1(self, policy: super::ImageBootstrapPolicy) -> Result<(), ResourceBankDataError> {
        let (_, normal, recovery) = policy.controller_baseline_partition_v1()?;
        range::require_policy(self, policy)?;
        if self.normal != normal || self.recovery != recovery {
            return Err(ResourceBankDataError::Conflict);
        }
        Ok(())
    }

    /// Encodes the exact selected historical or finite-range row.
    ///
    /// # Errors
    /// Rejects invalid enrollment or transition fields.
    pub fn to_bytes(self) -> Result<Vec<u8>, ResourceBankDataError> {
        encode(self)
    }

    /// Hashes the complete canonical row for the actual owner's ACK comparison.
    ///
    /// # Errors
    /// Retains canonical row validation failures.
    pub fn commitment(self) -> Result<[u8; 32], ResourceBankDataError> {
        Ok(Sha256::digest(encode(self)?).into())
    }
}

/// Decodes the selected historical recipient row under a supplied enrollment.
///
/// This lookup does not replay the complete bank or authenticate a live process.
///
/// # Errors
/// Rejects malformed recipient DATA or an enrollment differing from the supplied one.
pub fn recipient_incarnation(
    state: &State,
    enrollment: EnrollmentIdentity,
) -> Result<Option<RecipientIncarnation>, ResourceBankDataError> {
    replay::record_bytes(state, PREFIX, enrollment.node)
        .map(|bytes| {
            let row = decode(bytes)?;
            if row.enrollment != enrollment {
                return Err(ResourceBankDataError::Conflict);
            }
            Ok(row)
        })
        .transpose()
}

/// Retains one exact passive replacement and whole-bank before/after comparisons.
///
/// Preparing these bytes does not retain a writer, accept PID1 or grant a permit.
/// The actual Native owner must bind its transaction identity and returned result.
pub struct RecipientSuccessorMutation {
    row: RecipientIncarnation,
    encoded: Vec<u8>,
    archive: Option<([u8; 17], Vec<u8>)>,
    before: [u8; 32],
    after: [u8; 32],
}

impl RecipientSuccessorMutation {
    /// Prepares one DATA row while leaving every account and claim unchanged.
    ///
    /// `expected_predecessor` and `pid1_original_cut` are comparison DATA supplied
    /// by the actual Native owner. The first successor requires the initial durable whole-N seal;
    /// its predecessor must still come from that owner's genuine PID1 channel.
    ///
    /// # Errors
    /// Rejects an absent/corrupt enrollment, differing predecessor, zero or equal
    /// recipients, zero Offer commitment, or checked generation/digest overflow.
    pub fn new(
        state: &State,
        enrollment: EnrollmentIdentity,
        expected_predecessor: [u8; 16],
        recipient: [u8; 16],
        pid1_original_cut: [u8; 32],
    ) -> Result<Self, ResourceBankDataError> {
        if replay::validate(state)? != Some(enrollment) {
            return Err(ResourceBankDataError::Conflict);
        }
        let previous = recipient_incarnation(state, enrollment)?;
        let previous = previous.ok_or(ResourceBankDataError::EnrollmentUnavailable)?;
        // One immutable R is available. A confirmed successor cannot issue a
        // second precharge; PID1 independently enforces this before clone.
        if previous.generation != 0 || previous.recipient != expected_predecessor || previous.range.is_some() {
            return Err(ResourceBankDataError::Conflict);
        }
        let generation = 1;
        let predecessor_row = previous.commitment()?;
        let before = bank_digest(state, None)?;
        let row = RecipientIncarnation {
            enrollment,
            generation,
            predecessor_recipient: expected_predecessor,
            recipient,
            pid1_original_cut,
            predecessor_bank: before,
            predecessor_row,
            normal: previous.normal,
            recovery: previous.recovery,
            range: None,
        };
        let encoded = encode(row)?;
        let key = replay::key(PREFIX, enrollment.node);
        let after = bank_digest(state, Some((&key, &encoded)))?;
        Ok(Self {
            row,
            encoded,
            archive: None,
            before,
            after,
        })
    }

    /// Returns the exact proposed historical row without establishing custody.
    pub const fn row(&self) -> RecipientIncarnation {
        self.row
    }

    /// Constructs the exact current Put and any immutable predecessor archive.
    ///
    /// # Errors
    /// Rejects a zero transaction identity. This constructs DATA, not a commit.
    pub fn transaction(&self, id: [u8; 16]) -> Result<JournalTransaction, ResourceBankDataError> {
        Ok(JournalTransaction::new(
            id,
            self.records(),
        )?)
    }

    fn records(&self) -> Vec<JournalRecord> {
        let mut records = Vec::with_capacity(if self.archive.is_some() { 2 } else { 1 });
        if let Some((key, value)) = &self.archive {
            records.push(JournalRecord::put(RecordNamespace::ControllerResourceReservation,
                key.to_vec(), value.clone()));
        }
        records.push(JournalRecord::put(
                RecordNamespace::ControllerResourceReservation,
                replay::key(PREFIX, self.row.enrollment.node).to_vec(),
                self.encoded.to_vec(),
            ));
        records
    }

    /// Checks the entire predecessor bank and exact proposed record sequence.
    ///
    /// The Native caller separately compares its actual transaction identity.
    ///
    /// # Errors
    /// Rejects corrupt replay, changed bank bytes or a differing transaction shape.
    pub fn require_exact(
        &self,
        state: &State,
        transaction: &JournalTransaction,
    ) -> Result<(), ResourceBankDataError> {
        if replay::validate(state)? != Some(self.row.enrollment)
            || bank_digest(state, None)? != self.before
            || transaction.id() == &[0; 16]
            || transaction.records() != self.records().as_slice()
        {
            return Err(ResourceBankDataError::Conflict);
        }
        Ok(())
    }

    /// Checks the complete expected bank and exact row after actual Native readback.
    ///
    /// This comparison does not locate a transaction or accept a returned commit.
    /// Later unrelated bank mutations are outside this immediate readback cut.
    ///
    /// # Errors
    /// Rejects corrupt replay, changed bank bytes, or an absent/differing row.
    pub fn require_returned_rows(&self, state: &State) -> Result<(), ResourceBankDataError> {
        if replay::validate(state)? != Some(self.row.enrollment)
            || bank_digest(state, None)? != self.after
            || replay::record_bytes(state, PREFIX, self.row.enrollment.node)
                != Some(self.encoded.as_slice())
        {
            return Err(ResourceBankDataError::Conflict);
        }
        Ok(())
    }
}

fn encode(
    row: RecipientIncarnation,
) -> Result<Vec<u8>, ResourceBankDataError> {
    if row.range.is_some() { return range::encode(row); }
    codec::validate_enrollment(row.enrollment)?;
    let initial = row.generation == 0;
    if row.generation > 1 || row.recipient == [0; 16]
        || (initial && (row.predecessor_recipient != [0; 16]
            || row.pid1_original_cut != [0; 32] || row.predecessor_bank != [0; 32]
            || row.predecessor_row != [0; 32]))
        || (!initial && (row.predecessor_recipient == [0; 16]
            || row.predecessor_recipient == row.recipient
            || row.pid1_original_cut == [0; 32] || row.predecessor_bank == [0; 32]
            || row.predecessor_row == [0; 32]))
        || row.normal == aos_sandbox_model::ResourceVector::ZERO
        || row.recovery == aos_sandbox_model::ResourceVector::ZERO
    {
        return Err(ResourceBankDataError::CorruptLedger);
    }
    row.normal.checked_add(row.recovery)?;
    let mut bytes = [0; RECIPIENT_INCARNATION_BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    codec::encode_enrollment(row.enrollment, &mut bytes[8..104]);
    bytes[104..112].copy_from_slice(&row.generation.to_be_bytes());
    bytes[112..128].copy_from_slice(&row.predecessor_recipient);
    bytes[128..144].copy_from_slice(&row.recipient);
    bytes[144..176].copy_from_slice(&row.pid1_original_cut);
    bytes[176..208].copy_from_slice(&row.predecessor_bank);
    bytes[208..240].copy_from_slice(&row.predecessor_row);
    codec::encode_vector(row.normal, &mut bytes[240..416]);
    codec::encode_vector(row.recovery, &mut bytes[416..592]);
    let checksum = Sha256::digest(&bytes[..592]);
    bytes[592..].copy_from_slice(&checksum);
    Ok(bytes.to_vec())
}

pub(super) fn decode(bytes: &[u8]) -> Result<RecipientIncarnation, ResourceBankDataError> {
    if bytes.get(..8) == Some(b"AOSRRI03") { return range::decode(bytes); }
    codec::require_record(bytes, RECIPIENT_INCARNATION_BYTES, MAGIC)?;
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
        range: None,
    };
    if encode(row)?.as_slice() != bytes {
        return Err(ResourceBankDataError::CorruptLedger);
    }
    Ok(row)
}

/// Prepares the initial whole-normal-envelope seal from the same image DATA.
///
/// Older images return no seal and cannot enter a V10 continuation. Native
/// requires the sealed generation-zero delivery and actual enrollment commit.
///
/// # Errors
/// Rejects invalid image partition or recipient identity.
pub fn initial_recipient_precharge_v1(enrollment: EnrollmentIdentity,
    policy: super::ImageBootstrapPolicy, recipient: [u8; 16])
    -> Result<Option<RecipientIncarnation>, ResourceBankDataError>
{
    if policy.bootstrap_provisions().controller_recovery.is_none() { return Ok(None); }
    let (_, normal, recovery) = policy.controller_baseline_partition_v1()?;
    let row = RecipientIncarnation { enrollment, generation: 0,
        predecessor_recipient: [0; 16], recipient, pid1_original_cut: [0; 32],
        predecessor_bank: [0; 32], predecessor_row: [0; 32], normal, recovery, range: None };
    let row = range::seal_initial(row, policy)?;
    encode(row)?;
    Ok(Some(row))
}

/// Validates a logical recipient transition before the same replay materializes it.
///
/// Compaction supplies the complete current map separately; it never renews a
/// precharge. A logical successor changes exactly the existing recipient key.
///
/// # Errors
/// Rejects deletion, repeated generation, altered partition, missing initial
/// seal or changed complete predecessor state/row commitment.
pub fn validate_recipient_transaction_v1(state: &State, transaction: &JournalTransaction)
    -> Result<(), ResourceBankDataError>
{
    if transaction.records().iter().any(|record| record.namespace() == RecordNamespace::ControllerResourceReservation
        && (record.key().first() == Some(&range::HISTORY_PREFIX)
            || record.value().is_some_and(|value| value.get(..8) == Some(b"AOSRRI03"))))
    { return range::validate_transaction(state, transaction); }
    let mut selected = None;
    for record in transaction.records() {
        if record.namespace() != RecordNamespace::ControllerResourceReservation
            || record.key().first() != Some(&PREFIX) { continue; }
        if selected.is_some() { return Err(ResourceBankDataError::CorruptLedger); }
        let row = decode(record.value().ok_or(ResourceBankDataError::CorruptLedger)?)?;
        if record.key() != replay::key(PREFIX, row.enrollment.node) {
            return Err(ResourceBankDataError::CorruptLedger);
        }
        selected = Some(row);
    }
    let Some(row) = selected else { return Ok(()); };
    match recipient_incarnation(state, row.enrollment)? {
        None if row.generation == 0 && replay::validate(state)?.is_none() => Ok(()),
        Some(previous) if previous.range.is_none() && previous.generation == 0 && row.generation == 1
            && transaction.records().len() == 1 && row.normal == previous.normal
            && row.recovery == previous.recovery && row.predecessor_recipient == previous.recipient
            && row.predecessor_row == previous.commitment()?
            && row.predecessor_bank == bank_digest(state, None)? => Ok(()),
        _ => Err(ResourceBankDataError::Conflict),
    }
}

pub(super) fn require_replayed_v1(state: &State, row: RecipientIncarnation)
    -> Result<(), ResourceBankDataError>
{
    let controller = replay::find_head(state,
        super::bootstrap::account_id(row.enrollment, b"controller"))?;
    if controller.kind != super::AccountKind::Controller
        || controller.enrollment != row.enrollment
        || controller.baseline != row.normal.checked_add(row.recovery)?
    {
        return Err(ResourceBankDataError::CorruptLedger);
    }
    if row.range.is_some() { range::require_chain(state, row)?; }
    Ok(())
}

// Both passes borrow the original sorted map. Substitution affects one fixed
// row; no full state, key set, account list or canonical buffer is cloned.
fn bank_digest(state: &State, replacement: Option<(&[u8], &[u8])>)
    -> Result<[u8; 32], ResourceBankDataError>
{
    bank_digest_two(state, replacement, None)
}

// The same canonical fold overlays at most the fixed current/archive pair.
// It borrows every existing row and never clones the complete protected bank.
fn bank_digest_two(state: &State, first: Option<(&[u8], &[u8])>,
    second: Option<(&[u8], &[u8])>) -> Result<[u8; 32], ResourceBankDataError>
{
    let mut replacements = [first, second];
    if replacements[0].is_none() || matches!((replacements[0], replacements[1]),
        (Some((left, _)), Some((right, _))) if left > right)
    { replacements.swap(0, 1); }
    if matches!((replacements[0], replacements[1]),
        (Some((left, _)), Some((right, _))) if left == right)
    { return Err(ResourceBankDataError::Conflict); }
    let mut count = 0_u64;
    for ((namespace, _), _) in state {
        if *namespace == RecordNamespace::ControllerResourceReservation {
            count = count.checked_add(1).ok_or(ResourceBankDataError::Conflict)?;
        }
    }
    for (key, _) in replacements.into_iter().flatten() {
        if !state.iter().any(|((namespace, actual), _)|
            *namespace == RecordNamespace::ControllerResourceReservation && actual.as_slice() == key)
        { count = count.checked_add(1).ok_or(ResourceBankDataError::Conflict)?; }
    }
    let mut hash = Sha256::new();
    hash.update(STATE_DIGEST_DOMAIN);
    hash.update(count.to_be_bytes());
    let mut inserted = [false; 2];
    for ((namespace, key), value) in state {
        if *namespace != RecordNamespace::ControllerResourceReservation { continue; }
        let mut replaced = false;
        for (index, replacement) in replacements.iter().enumerate() {
            if let Some((replacement_key, replacement_value)) = replacement {
                if !inserted[index] && *replacement_key <= key.as_slice() {
                    hash_row(&mut hash, replacement_key, replacement_value)?;
                    inserted[index] = true;
                }
                replaced |= key.as_slice() == *replacement_key;
            }
        }
        if !replaced { hash_row(&mut hash, key, value)?; }
    }
    for (index, replacement) in replacements.into_iter().enumerate() {
        if let Some((key, value)) = replacement.filter(|_| !inserted[index]) {
            hash_row(&mut hash, key, value)?;
        }
    }
    Ok(hash.finalize().into())
}

fn hash_row(hasher: &mut Sha256, key: &[u8], value: &[u8]) -> Result<(), ResourceBankDataError> {
    hasher.update([RecordNamespace::ControllerResourceReservation as u8]);
    hasher.update(
        u64::try_from(key.len())
            .map_err(|_| ResourceBankDataError::Conflict)?
            .to_be_bytes(),
    );
    hasher.update(key);
    hasher.update(
        u64::try_from(value.len())
            .map_err(|_| ResourceBankDataError::Conflict)?
            .to_be_bytes(),
    );
    hasher.update(value);
    Ok(())
}
