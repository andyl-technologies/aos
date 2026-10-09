//! Records terminal Q04 retention without refunding unsupported owner costs.
//!
//! The original preparation and compound grant remain immutable history. One
//! exact terminal successor commits the original use and advances its Sandbox
//! head once. Legacy T01 keeps full C; T02 keeps the genuinely admitted U from
//! Q02 without refund. Neither row constructs new operation authority.
//! Source/Cache physical owners and remote retention lack a complete disposal
//! recipe, so every resource dimension remains charged at its original value.
//!
//! The private native format is fixed and uses the existing claim/head codecs:
//! ```text
//! AOSRST01 | original-id16 | co-issuance-sha32 | terminal-tx16
//!          | Controller-names48 | terminal-NEXT8 | prior-end8 | Root-final32
//!          | eight origins(id16, ordered-member-sha32, commit8, end8) | SHA32
//! AOSRST02 | same fixed712 layout, closed only with AOSRSQ02 co-issuance
//! ```
//! A row is replay DATA. The same original native parser must independently
//! verify its whole transaction, all eight origins and exact chronological cut.

use std::collections::BTreeSet;

use sha2::{Digest as _, Sha256};

use crate::journal::{CommitResult, ControllerQ04TransitionV1, ProtectedJournalNamesV1};
use crate::policy_compiler::create_q04::{
    CreateQ04ErrorV1, OriginalQ04FinalRootObservationV1,
};
use crate::{Journal, JournalTransaction, RecordNamespace};

use super::{
    AccountHead, AccountTransition, Claim, ClaimState, ResourceReservationErrorV1,
    codec, matches_record, q04, replay,
};

pub(super) const PREFIX: u8 = b't';
const RECORD_BYTES: usize = 712;

#[derive(Clone, Copy, Eq, PartialEq)]
struct NativeOrigin {
    id: [u8; 16],
    members: [u8; 32],
    returned: CommitResult,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct Binding {
    input_origin: bool,
    original: [u8; 16],
    coissuance: [u8; 32],
    transaction: [u8; 16],
    names: ProtectedJournalNamesV1,
    next: u64,
    prior_end: u64,
    root_final: [u8; 32],
    origins: [NativeOrigin; 8],
}

impl Binding {
    pub(super) fn original_id(self) -> [u8; 16] { self.original }

    pub(super) fn names(self) -> ProtectedJournalNamesV1 { self.names }
}

/// Owns a terminal mutation prepared under the genuine final Root borrower.
///
/// Construction is private to the completed original Q04 route. The value
/// preserves the old full charge; it is not a current-purpose allocation loan.
pub(crate) struct Q04TerminalDispositionV1 {
    pub(super) transition: AccountTransition,
}

impl Q04TerminalDispositionV1 {
    /// Prepares full-charge retention under all eight returned native origins.
    ///
    /// # Errors
    /// Refuses absent/failed outcomes, a changed original terminal borrower,
    /// nonmatching native membership or a changed account predecessor.
    pub(crate) fn prepare(
        journal: &Journal,
        root: &OriginalQ04FinalRootObservationV1<'_, '_, '_>,
        original: &super::Q04ResourceTransferV1,
        recipes: &[ControllerQ04TransitionV1<'_>],
        returned: &[Option<Result<CommitResult, CreateQ04ErrorV1>>; 8],
    ) -> Result<Self, CreateQ04ErrorV1> {
        root.recheck()?;
        if recipes.len() != 8 || original.crossing_failure().is_some()
            || !recipes.first().and_then(|recipe| recipe.resource_transfer())
                .is_some_and(|held| std::ptr::eq(held, original))
            || returned.iter().any(|result| !matches!(result, Some(Ok(_))))
            || recipes.iter().enumerate().any(|(index, recipe)| {
                !std::ptr::eq(recipe.identity(), root.identity())
                    || recipe.phase_number() as usize != index + 1
                    || !recipe.same_original_cut(&recipes[0])
            })
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        original.require_readback(journal).map_err(resource_error)?;
        original.require_last_clock().map_err(resource_error)?;
        journal.require_controller_resource_q04_prefix_v1(recipes)?;

        let mut origins = [NativeOrigin {
            id: [0; 16], members: [0; 32],
            returned: CommitResult { commit_sequence: 0, durable_bytes: 0 },
        }; 8];
        let mut next = recipes[0].ledger().original_next();
        let mut prior_end = 0;
        for (index, recipe) in recipes.iter().enumerate() {
            let result = returned[index].as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(CreateQ04ErrorV1::ChangedCut)?;
            let frames = u64::try_from(recipe.transaction().records().len())
                .map_err(|_| CreateQ04ErrorV1::Bounds)?
                .checked_add(2).ok_or(CreateQ04ErrorV1::Bounds)?;
            if result.commit_sequence.checked_add(1) != next.checked_add(frames)
                || (index != 0 && result.durable_bytes <= prior_end)
            {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            origins[index] = NativeOrigin {
                id: *recipe.transaction().id(),
                members: transaction_digest(recipe.transaction()).map_err(resource_error)?,
                returned: *result,
            };
            next = result.commit_sequence.checked_add(1).ok_or(CreateQ04ErrorV1::Bounds)?;
            prior_end = result.durable_bytes;
        }
        journal.require_q04_returned_commit_v1(&origins[7].returned)?;
        let state = journal.controller_resource_state_v1()?;
        let use_claim = q04::use_claim(original.binding);
        let before = replay::find_head(state, use_claim.account).map_err(resource_error)?;
        let mut transition = AccountTransition::settle(before, use_claim, true)
            .map_err(resource_error)?;
        transition.original_clock = Some(original.original_clock);
        let binding = Binding {
            input_origin: q04::has_input_origin(original.binding),
            original: q04::original_claim(original.binding).id,
            coissuance: Sha256::digest(q04::encode(original.binding).map_err(resource_error)?).into(),
            transaction: transition.transaction_id,
            names: journal.protected_writer_physical_names_v1()?,
            next, prior_end,
            root_final: *root.terminal_digest()?.as_bytes(),
            origins,
        };
        require_predecessor(state, binding, &transition).map_err(resource_error)?;
        transition.terminal = Some(binding);
        root.recheck()?;
        Ok(Self { transition })
    }
}

// There is one exact successor today. Later operation/history events must be
// implemented as typed transitions, not a generation >= 1 replay exception.
pub(super) fn current_use(
    state: &replay::State,
    original: q04::Binding,
) -> Result<(Claim, AccountHead), ResourceReservationErrorV1> {
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
                .ok_or(ResourceReservationErrorV1::CorruptLedger)?,
            account: before.account.commit(claim.amount)?,
            ..before
        },
    ))
}

pub(super) fn require_predecessor(
    state: &replay::State,
    terminal: Binding,
    transition: &AccountTransition,
) -> Result<(), ResourceReservationErrorV1> {
    let original = q04::decode(replay::record_bytes(state, q04::PREFIX, terminal.original)
        .ok_or(ResourceReservationErrorV1::Conflict)?)?;
    require_original(terminal, original)?;
    q04::require_replayed(state, original)?;
    let claim = q04::use_claim(original);
    if replay::record_bytes(state, PREFIX, terminal.original).is_some()
        || transition.transaction_id != terminal.transaction
        || transition.before != q04::child_head(original)?
        || transition.previous_claim != Some(claim)
        || transition.claim != (Claim { state: ClaimState::Committed, ..claim })
    {
        return Err(ResourceReservationErrorV1::Conflict);
    }
    Ok(())
}

fn require_original(terminal: Binding, original: q04::Binding) -> Result<(), ResourceReservationErrorV1> {
    if terminal.input_origin != q04::has_input_origin(original)
        || terminal.original != q04::original_claim(original).id
        || terminal.coissuance != <[u8; 32]>::from(Sha256::digest(q04::encode(original)?))
    {
        return Err(ResourceReservationErrorV1::CorruptLedger);
    }
    Ok(())
}

pub(super) fn encode(binding: Binding) -> Result<[u8; RECORD_BYTES], ResourceReservationErrorV1> {
    if binding.original == [0; 16] || binding.transaction == [0; 16]
        || binding.root_final == [0; 32] || binding.coissuance == [0; 32]
        || binding.next == 0 || binding.prior_end == 0
        || binding.origins[7].returned.commit_sequence.checked_add(1) != Some(binding.next)
        || binding.origins[7].returned.durable_bytes != binding.prior_end
    {
        return Err(ResourceReservationErrorV1::CorruptLedger);
    }
    for (index, origin) in binding.origins.iter().enumerate() {
        if origin.id == [0; 16] || origin.id == binding.transaction || origin.members == [0; 32]
            || origin.returned.commit_sequence == 0 || origin.returned.durable_bytes == 0
            || binding.origins[..index].iter().any(|previous| previous.id == origin.id)
            || (index != 0 && (binding.origins[index - 1].returned.commit_sequence >= origin.returned.commit_sequence
                || binding.origins[index - 1].returned.durable_bytes >= origin.returned.durable_bytes))
        {
            return Err(ResourceReservationErrorV1::CorruptLedger);
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

pub(super) fn decode(bytes: &[u8]) -> Result<Binding, ResourceReservationErrorV1> {
    if bytes.len() != RECORD_BYTES || ![b"AOSRST01".as_slice(), b"AOSRST02".as_slice()]
        .contains(&bytes.get(..8).ok_or(ResourceReservationErrorV1::CorruptLedger)?) {
        return Err(ResourceReservationErrorV1::CorruptLedger);
    }
    let mut origins = [NativeOrigin {
        id: [0; 16], members: [0; 32],
        returned: CommitResult { commit_sequence: 0, durable_bytes: 0 },
    }; 8];
    for (index, origin) in origins.iter_mut().enumerate() {
        let start = 168 + index * 64;
        *origin = NativeOrigin {
            id: fixed(&bytes[start..start + 16])?,
            members: fixed(&bytes[start + 16..start + 48])?,
            returned: CommitResult {
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
            .map_err(crate::journal::JournalError::from)?,
        next: u64::from_be_bytes(fixed(&bytes[120..128])?),
        prior_end: u64::from_be_bytes(fixed(&bytes[128..136])?),
        root_final: fixed(&bytes[136..168])?, origins,
    };
    if encode(binding)?.as_slice() != bytes {
        return Err(ResourceReservationErrorV1::CorruptLedger);
    }
    Ok(binding)
}

fn transaction_digest(transaction: &JournalTransaction) -> Result<[u8; 32], ResourceReservationErrorV1> {
    let mut digest = Sha256::new().chain_update(b"AOS-Q04-TERMINAL-MEMBERS-V1\0")
        .chain_update(transaction.id());
    digest.update(u64::try_from(transaction.records().len())
        .map_err(|_| ResourceReservationErrorV1::CorruptLedger)?.to_be_bytes());
    for record in transaction.records() {
        digest.update([record.namespace() as u8]);
        digest.update(u64::try_from(record.key().len())
            .map_err(|_| ResourceReservationErrorV1::CorruptLedger)?.to_be_bytes());
        digest.update(record.key());
        match record.value() {
            Some(value) => {
                digest.update([1]);
                digest.update(u64::try_from(value.len())
                    .map_err(|_| ResourceReservationErrorV1::CorruptLedger)?.to_be_bytes());
                digest.update(value);
            }
            None => digest.update([0]),
        }
    }
    Ok(digest.finalize().into())
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ResourceReservationErrorV1> {
    bytes.try_into().map_err(|_| ResourceReservationErrorV1::CorruptLedger)
}

fn resource_error(error: ResourceReservationErrorV1) -> CreateQ04ErrorV1 {
    CreateQ04ErrorV1::ResourceReservation(Box::new(error))
}

/// Audits retained terminal rows through the original native parser.
///
/// This allocation-free observer checks actual complete members and physical
/// chronology. It constructs no payment, current authority or retry permit.
pub(crate) struct NativeHistory<'state> {
    state: &'state replay::State,
    matched: usize,
}

impl<'state> NativeHistory<'state> {
    /// Selects the closed observer only when terminal history is present.
    pub(crate) fn new(state: &'state replay::State) -> Option<Self> {
        state.keys().any(|(namespace, key)| {
            *namespace == RecordNamespace::ControllerResourceReservation
                && key.first() == Some(&PREFIX)
        }).then_some(Self { state, matched: 0 })
    }

    /// Compares one actual native commit to every retained terminal origin.
    ///
    /// # Errors
    /// Refuses changed members, missing chronological adjacency or a foreign
    /// terminal transaction at the original physical boundary.
    pub(crate) fn observe(
        &mut self,
        transaction: &JournalTransaction,
        begin_sequence: u64,
        commit_sequence: u64,
        begin_offset: u64,
        end_offset: u64,
    ) -> Result<(), crate::JournalError> {
        self.observe_exact(transaction, begin_sequence, commit_sequence, begin_offset, end_offset)
            .map_err(|_| crate::JournalError::ProtectedBoundary)
    }

    fn observe_exact(
        &mut self,
        transaction: &JournalTransaction,
        begin_sequence: u64,
        commit_sequence: u64,
        begin_offset: u64,
        end_offset: u64,
    ) -> Result<(), ResourceReservationErrorV1> {
        for ((namespace, key), bytes) in self.state {
            if *namespace != RecordNamespace::ControllerResourceReservation
                || key.first() != Some(&PREFIX)
            {
                continue;
            }
            let terminal = decode(bytes)?;
            let original = q04::decode(replay::record_bytes(self.state, q04::PREFIX, terminal.original)
                .ok_or(ResourceReservationErrorV1::CorruptLedger)?)?;
            require_original(terminal, original)?;
            for (index, origin) in terminal.origins.iter().enumerate() {
                if transaction.id() != &origin.id { continue; }
                let frames = u64::try_from(transaction.records().len())
                    .map_err(|_| ResourceReservationErrorV1::CorruptLedger)?
                    .checked_add(2).ok_or(ResourceReservationErrorV1::CorruptLedger)?;
                if transaction_digest(transaction)? != origin.members
                    || commit_sequence != origin.returned.commit_sequence
                    || end_offset != origin.returned.durable_bytes
                    || commit_sequence.checked_add(1).and_then(|next| next.checked_sub(frames)) != Some(begin_sequence)
                    || (index != 0 && (terminal.origins[index - 1].returned.commit_sequence.checked_add(1) != Some(begin_sequence)
                        || terminal.origins[index - 1].returned.durable_bytes != begin_offset))
                {
                    return Err(ResourceReservationErrorV1::CorruptLedger);
                }
                if index == 0 && (transaction.records().len() != 3 + q04::BANK_MEMBERS + usize::from(q04::has_input_origin(original))
                    || !matches_record(&transaction.records()[8], q04::PREFIX,
                        terminal.original, q04::encode(original)?.as_slice())
                    || (q04::has_input_origin(original)
                        && !q04::matches_origin_record(original, &transaction.records()[9])?))
                {
                    return Err(ResourceReservationErrorV1::CorruptLedger);
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
                return Err(ResourceReservationErrorV1::CorruptLedger);
            }
            self.matched = self.matched.checked_add(1).ok_or(ResourceReservationErrorV1::CorruptLedger)?;
        }
        Ok(())
    }

    /// Requires all real origins and terminal transactions in complete replay.
    ///
    /// # Errors
    /// Refuses missing commits, changed physical names or incomplete observation.
    pub(crate) fn finish(
        &self,
        ids: &BTreeSet<[u8; 16]>,
        names: ProtectedJournalNamesV1,
    ) -> Result<(), crate::JournalError> {
        let mut expected = 0_usize;
        for ((namespace, key), bytes) in self.state {
            if *namespace != RecordNamespace::ControllerResourceReservation
                || key.first() != Some(&PREFIX)
            {
                continue;
            }
            let terminal = decode(bytes).map_err(|_| crate::JournalError::ProtectedBoundary)?;
            if terminal.names != names || !ids.contains(&terminal.transaction)
                || terminal.origins.iter().any(|origin| !ids.contains(&origin.id))
            {
                return Err(crate::JournalError::ProtectedBoundary);
            }
            expected = expected.checked_add(1).ok_or(crate::JournalError::ProtectedBoundary)?;
        }
        if self.matched != expected { return Err(crate::JournalError::ProtectedBoundary); }
        Ok(())
    }
}
