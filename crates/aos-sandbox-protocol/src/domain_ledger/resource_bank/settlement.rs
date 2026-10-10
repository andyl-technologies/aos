//! Owns complete terminal encoding and allocation-free physical-history replay.
//!
//! ```text
//! AOSRST01..02 | original16 | coissuance32 | transaction16 | names48 |
//! next8 | prior-end8 | Root-final32 | eight(id16,members32,sequence8,end8) | SHA32
//! ```

use std::collections::BTreeSet;
use sha2::{Digest as _, Sha256};

use super::{AccountHead, AccountMutation, Claim, ClaimState, CommitPosition, JournalTransaction, Origin, ProtectedJournalNamesV1, RecordNamespace, ResourceBankDataError, TerminalBinding as Binding, codec, matches_record, q04, replay};

pub(super) const PREFIX: u8 = b't';
const RECORD_BYTES: usize = 712;


// There is one exact successor today. Later operation/history events must be
// implemented as typed transitions, not a generation >= 1 replay exception.
pub(super) fn current_use(
    state: &replay::State,
    original: super::CoissuanceBinding,
) -> Result<(Claim, AccountHead), ResourceBankDataError> {
    let claim = q04::use_claim(original);
    let before = q04::child_head(original)?;
    let Some(bytes) = replay::record_bytes(state, PREFIX, q04::original_claim(original).id) else {
        return Ok((claim, before));
    };
    let terminal = decode(bytes)?;
    require_original(terminal, original)?;
    Ok((
        Claim { state: ClaimState::Committed, ..claim },
        AccountHead {
            generation: before.generation.checked_add(1)
                .ok_or(ResourceBankDataError::CorruptLedger)?,
            account: before.account.commit(claim.amount)?,
            ..before
        },
    ))
}

pub(super) fn require_predecessor(
    state: &replay::State,
    terminal: Binding,
    transition: &AccountMutation<'_>,
) -> Result<(), ResourceBankDataError> {
    let original = q04::decode(replay::record_bytes(state, q04::PREFIX, terminal.original)
        .ok_or(ResourceBankDataError::Conflict)?)?;
    require_original(terminal, original)?;
    q04::require_replayed(state, original)?;
    let claim = q04::use_claim(original);
    if replay::record_bytes(state, PREFIX, terminal.original).is_some()
        || (*transition.transaction_id) != terminal.transaction
        || (*transition.before) != q04::child_head(original)?
        || (*transition.previous_claim) != Some(claim)
        || (*transition.claim) != (Claim { state: ClaimState::Committed, ..claim })
    {
        return Err(ResourceBankDataError::Conflict);
    }
    Ok(())
}

fn require_original(terminal: Binding, original: super::CoissuanceBinding) -> Result<(), ResourceBankDataError> {
    if terminal.input_origin != q04::has_input_origin(original)
        || terminal.original != q04::original_claim(original).id
        || terminal.coissuance != <[u8; 32]>::from(Sha256::digest(q04::encode(original)?))
    {
        return Err(ResourceBankDataError::CorruptLedger);
    }
    Ok(())
}

pub(super) fn encode(binding: Binding) -> Result<[u8; RECORD_BYTES], ResourceBankDataError> {
    if binding.original == [0; 16] || binding.transaction == [0; 16]
        || binding.root_final == [0; 32] || binding.coissuance == [0; 32]
        || binding.next == 0 || binding.prior_end == 0
        || binding.origins[7].returned.commit_sequence.checked_add(1) != Some(binding.next)
        || binding.origins[7].returned.durable_bytes != binding.prior_end
    {
        return Err(ResourceBankDataError::CorruptLedger);
    }
    for (index, origin) in binding.origins.iter().enumerate() {
        if origin.id == [0; 16] || origin.id == binding.transaction || origin.members == [0; 32]
            || origin.returned.commit_sequence == 0 || origin.returned.durable_bytes == 0
            || binding.origins[..index].iter().any(|previous| previous.id == origin.id)
            || (index != 0 && (binding.origins[index - 1].returned.commit_sequence >= origin.returned.commit_sequence
                || binding.origins[index - 1].returned.durable_bytes >= origin.returned.durable_bytes))
        {
            return Err(ResourceBankDataError::CorruptLedger);
        }
    }
    let mut bytes = [0; RECORD_BYTES];
    bytes[..8].copy_from_slice(if binding.input_origin { b"AOSRST02" } else { b"AOSRST01" });
    bytes[8..24].copy_from_slice(&binding.original);
    bytes[24..56].copy_from_slice(&binding.coissuance);
    bytes[56..72].copy_from_slice(&binding.transaction);
    bytes[72..120].copy_from_slice(&binding.names.to_bytes());
    bytes[120..128].copy_from_slice(&binding.next.to_be_bytes());
    bytes[128..136].copy_from_slice(&binding.prior_end.to_be_bytes());
    bytes[136..168].copy_from_slice(&binding.root_final);
    for (index, origin) in binding.origins.iter().enumerate() {
        let start = 168 + index * 64;
        bytes[start..start + 16].copy_from_slice(&origin.id);
        bytes[start + 16..start + 48].copy_from_slice(&origin.members);
        bytes[start + 48..start + 56].copy_from_slice(&origin.returned.commit_sequence.to_be_bytes());
        bytes[start + 56..start + 64].copy_from_slice(&origin.returned.durable_bytes.to_be_bytes());
    }
    let checksum = Sha256::digest(&bytes[..680]);
    bytes[680..].copy_from_slice(&checksum);
    Ok(bytes)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Binding, ResourceBankDataError> {
    if bytes.len() != RECORD_BYTES || ![b"AOSRST01".as_slice(), b"AOSRST02".as_slice()]
        .contains(&bytes.get(..8).ok_or(ResourceBankDataError::CorruptLedger)?) {
        return Err(ResourceBankDataError::CorruptLedger);
    }
    let mut origins = [Origin {
        id: [0; 16], members: [0; 32],
        returned: CommitPosition { commit_sequence: 0, durable_bytes: 0 },
    }; 8];
    for (index, origin) in origins.iter_mut().enumerate() {
        let start = 168 + index * 64;
        *origin = Origin {
            id: fixed(&bytes[start..start + 16])?,
            members: fixed(&bytes[start + 16..start + 48])?,
            returned: CommitPosition {
                commit_sequence: u64::from_be_bytes(fixed(&bytes[start + 48..start + 56])?),
                durable_bytes: u64::from_be_bytes(fixed(&bytes[start + 56..start + 64])?),
            },
        };
    }
    let binding = Binding {
        input_origin: bytes[..8] == *b"AOSRST02",
        original: fixed(&bytes[8..24])?, coissuance: fixed(&bytes[24..56])?,
        transaction: fixed(&bytes[56..72])?,
        names: ProtectedJournalNamesV1::from_bytes(&bytes[72..120])
            .map_err(ResourceBankDataError::Names)?,
        next: u64::from_be_bytes(fixed(&bytes[120..128])?),
        prior_end: u64::from_be_bytes(fixed(&bytes[128..136])?),
        root_final: fixed(&bytes[136..168])?, origins,
    };
    if encode(binding)?.as_slice() != bytes {
        return Err(ResourceBankDataError::CorruptLedger);
    }
    Ok(binding)
}

/// Hashes the complete ordered historical transaction member transcript.
///
/// The transcript includes transaction identity, namespace, key, optional-value
/// tag and bytes. It allocates no record copies.
///
/// # Errors
///
/// Rejects record counts or key/value widths that cannot be represented as `u64`.
pub fn transaction_digest(transaction: &JournalTransaction) -> Result<[u8; 32], ResourceBankDataError> {
    let mut digest = Sha256::new().chain_update(b"AOS-Q04-TERMINAL-MEMBERS-V1\0")
        .chain_update(transaction.id());
    digest.update(u64::try_from(transaction.records().len())
        .map_err(|_| ResourceBankDataError::CorruptLedger)?.to_be_bytes());
    for record in transaction.records() {
        digest.update([record.namespace() as u8]);
        digest.update(u64::try_from(record.key().len())
            .map_err(|_| ResourceBankDataError::CorruptLedger)?.to_be_bytes());
        digest.update(record.key());
        match record.value() {
            Some(value) => {
                digest.update([1]);
                digest.update(u64::try_from(value.len())
                    .map_err(|_| ResourceBankDataError::CorruptLedger)?.to_be_bytes());
                digest.update(value);
            }
            None => digest.update([0]),
        }
    }
    Ok(digest.finalize().into())
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ResourceBankDataError> {
    bytes.try_into().map_err(|_| ResourceBankDataError::CorruptLedger)
}

/// Compares retained terminal rows with transactions supplied by the Native parser.
///
/// This allocation-free observer checks actual complete members and physical
/// chronology. It constructs no payment, current authority or retry permit.
pub struct PhysicalHistory<'state> {
    state: &'state replay::State,
    matched: usize,
}

impl<'state> PhysicalHistory<'state> {
    /// Selects the closed observer only when terminal history is present.
    pub fn new(state: &'state replay::State) -> Option<Self> {
        state.keys().any(|(namespace, key)| {
            *namespace == RecordNamespace::ControllerResourceReservation
                && key.first() == Some(&PREFIX)
        }).then_some(Self { state, matched: 0 })
    }

    /// Compares a complete transaction with retained origin and terminal chronology.
    ///
    /// The observer borrows the supplied state and counts matching terminal commits;
    /// it does not parse physical frames or establish that a transaction committed.
    /// The Native parser supplies its actual ordered positions and transaction.
    ///
    /// # Errors
    ///
    /// Rejects malformed or inconsistent retained records, differing member digests
    /// or positions, nonadjacent origins, invalid terminal members, and count overflow.
    pub fn observe(
        &mut self,
        transaction: &JournalTransaction,
        begin_sequence: u64,
        commit_sequence: u64,
        begin_offset: u64,
        end_offset: u64,
    ) -> Result<(), ResourceBankDataError> {
        for ((namespace, key), bytes) in self.state {
            if *namespace != RecordNamespace::ControllerResourceReservation
                || key.first() != Some(&PREFIX)
            {
                continue;
            }
            let terminal = decode(bytes)?;
            let original = q04::decode(replay::record_bytes(self.state, q04::PREFIX, terminal.original)
                .ok_or(ResourceBankDataError::CorruptLedger)?)?;
            require_original(terminal, original)?;
            for (index, origin) in terminal.origins.iter().enumerate() {
                if transaction.id() != &origin.id { continue; }
                let frames = u64::try_from(transaction.records().len())
                    .map_err(|_| ResourceBankDataError::CorruptLedger)?
                    .checked_add(2).ok_or(ResourceBankDataError::CorruptLedger)?;
                if transaction_digest(transaction)? != origin.members
                    || commit_sequence != origin.returned.commit_sequence
                    || end_offset != origin.returned.durable_bytes
                    || commit_sequence.checked_add(1).and_then(|next| next.checked_sub(frames)) != Some(begin_sequence)
                    || (index != 0 && (terminal.origins[index - 1].returned.commit_sequence.checked_add(1) != Some(begin_sequence)
                        || terminal.origins[index - 1].returned.durable_bytes != begin_offset))
                {
                    return Err(ResourceBankDataError::CorruptLedger);
                }
                if index == 0 && (transaction.records().len() != 3 + q04::BANK_MEMBERS + usize::from(q04::has_input_origin(original))
                    || !matches_record(&transaction.records()[8], q04::PREFIX,
                        terminal.original, q04::encode(original)?.as_slice())
                    || (q04::has_input_origin(original)
                        && !q04::matches_origin_record(original, &transaction.records()[9])?))
                {
                    return Err(ResourceBankDataError::CorruptLedger);
                }
            }
            if transaction.id() != &terminal.transaction { continue; }
            let (claim, head) = current_use(self.state, original)?;
            let records = transaction.records();
            if records.len() != 3 || begin_sequence != terminal.next || begin_offset != terminal.prior_end
                || !matches_record(&records[0], replay::HEAD_PREFIX, head.id, &codec::encode_head(head)?)
                || !matches_record(&records[1], replay::CLAIM_PREFIX, claim.id, &codec::encode_claim(claim)?)
                || !matches_record(&records[2], PREFIX, terminal.original, bytes)
            {
                return Err(ResourceBankDataError::CorruptLedger);
            }
            self.matched = self.matched.checked_add(1).ok_or(ResourceBankDataError::CorruptLedger)?;
        }
        Ok(())
    }

    /// Requires recorded origin and terminal identities in the supplied history.
    ///
    /// # Errors
    /// Refuses missing supplied identities, changed names or incomplete observation.
    pub fn finish(
        &self,
        ids: &BTreeSet<[u8; 16]>,
        names: ProtectedJournalNamesV1,
    ) -> Result<(), ResourceBankDataError> {
        let mut expected = 0_usize;
        for ((namespace, key), bytes) in self.state {
            if *namespace != RecordNamespace::ControllerResourceReservation
                || key.first() != Some(&PREFIX)
            {
                continue;
            }
            let terminal = decode(bytes).map_err(|_| ResourceBankDataError::CorruptLedger)?;
            if terminal.names != names || !ids.contains(&terminal.transaction)
                || terminal.origins.iter().any(|origin| !ids.contains(&origin.id))
            {
                return Err(ResourceBankDataError::CorruptLedger);
            }
            expected = expected.checked_add(1).ok_or(ResourceBankDataError::CorruptLedger)?;
        }
        if self.matched != expected { return Err(ResourceBankDataError::CorruptLedger); }
        Ok(())
    }
}
