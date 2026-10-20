//! Binds one Create Storage use to its exact completed Q04 allocation.
//!
//! These immutable associations, mutations and replay comparisons are DATA.
//! They create no Ready loan, Root authorization, writer or resource permit.
//! The native issuer retains the real cut and appends through its closed loan.
//!
//! ```text
//! key = u | use-claim[16]
//! AOSRSU01 | original-Q04-claim[16] | coissuance-sha256[32] |
//! UseAuthorized-record[32] | RootValidated-record[32] | use-claim[16] | SHA256[32]
//! ```

use sha2::{Digest as _, Sha256};

use super::{
    AccountHead, AccountMutation, Claim, ClaimPurpose, ClaimState, CoissuanceBinding,
    JournalTransaction, ResourceBankDataError, codec, matches_record, q04, replay, settlement,
};

pub(super) const PREFIX: u8 = b'u';

// One canonical constructor serves the actual issuer and replay comparison.
// Field inheritance cannot be replaced by caller-supplied ancestry scalars.
pub(super) fn inherited_claim(
    original: CoissuanceBinding,
    id: [u8; 16],
    amount: aos_sandbox_core::ResourceVector,
) -> Result<Claim, ResourceBankDataError> {
    q04::encode(original)?;
    let preparation = q04::use_claim(original);
    let claim = Claim {
        id,
        purpose: ClaimPurpose::CreateStorageUse,
        amount,
        state: ClaimState::Reserved,
        ..preparation
    };
    if id == [0; 16]
        || [
            q04::original_claim(original).id,
            preparation.id,
            original.grant.id,
        ]
        .contains(&id)
        || amount == aos_sandbox_core::ResourceVector::ZERO
    {
        return Err(ResourceBankDataError::CorruptLedger);
    }
    codec::encode_claim(claim)?;
    Ok(claim)
}
/// Specifies the complete immutable Create use binding width.
pub const CREATE_STORAGE_USE_BINDING_BYTES_V1: usize = 168;

/// Retains immutable historical joins for exactly one Create Storage use.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateStorageUseBindingV1 {
    original: [u8; 16],
    coissuance: [u8; 32],
    use_authorized: [u8; 32],
    root_validated: [u8; 32],
    claim: [u8; 16],
}

impl CreateStorageUseBindingV1 {
    /// Constructs passive joins from the original allocation and proposed use.
    ///
    /// # Errors
    /// Rejects zero identities, noncanonical Q04 DATA or changed claim ancestry.
    pub fn new(
        original: CoissuanceBinding,
        use_authorized: [u8; 32],
        root_validated: [u8; 32],
        claim: Claim,
    ) -> Result<Self, ResourceBankDataError> {
        let binding = Self {
            original: q04::original_claim(original).id,
            coissuance: Sha256::digest(q04::encode(original)?).into(),
            use_authorized,
            root_validated,
            claim: claim.id,
        };
        binding.encode()?;
        binding.require_claim(original, claim)?;
        Ok(binding)
    }

    /// Decodes the exact immutable historical binding without native authority.
    ///
    /// # Errors
    /// Rejects changed width, magic, checksum or zero comparison identities.
    pub fn decode(bytes: &[u8]) -> Result<Self, ResourceBankDataError> {
        if bytes.len() != CREATE_STORAGE_USE_BINDING_BYTES_V1 || bytes[..8] != *b"AOSRSU01" {
            return Err(ResourceBankDataError::CorruptLedger);
        }
        let binding = Self {
            original: fixed(&bytes[8..24])?,
            coissuance: fixed(&bytes[24..56])?,
            use_authorized: fixed(&bytes[56..88])?,
            root_validated: fixed(&bytes[88..120])?,
            claim: fixed(&bytes[120..136])?,
        };
        if binding.encode()?.as_slice() != bytes {
            return Err(ResourceBankDataError::CorruptLedger);
        }
        Ok(binding)
    }

    /// Encodes the fixed binding using its sole canonical representation.
    ///
    /// # Errors
    /// Rejects unavailable or aliased original and use identities.
    pub fn encode(
        self,
    ) -> Result<[u8; CREATE_STORAGE_USE_BINDING_BYTES_V1], ResourceBankDataError> {
        if self.original == [0; 16]
            || self.claim == [0; 16]
            || self.original == self.claim
            || [self.coissuance, self.use_authorized, self.root_validated].contains(&[0; 32])
        {
            return Err(ResourceBankDataError::CorruptLedger);
        }
        let mut bytes = [0; CREATE_STORAGE_USE_BINDING_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSRSU01");
        bytes[8..24].copy_from_slice(&self.original);
        bytes[24..56].copy_from_slice(&self.coissuance);
        bytes[56..88].copy_from_slice(&self.use_authorized);
        bytes[88..120].copy_from_slice(&self.root_validated);
        bytes[120..136].copy_from_slice(&self.claim);
        let checksum = Sha256::digest(&bytes[..136]);
        bytes[136..].copy_from_slice(&checksum);
        Ok(bytes)
    }

    /// Returns the use identity that selects this immutable bank row.
    pub const fn claim_id(self) -> [u8; 16] {
        self.claim
    }

    /// Returns the original Q04 identity used by the saved association.
    pub const fn original_claim_id(self) -> [u8; 16] {
        self.original
    }

    /// Returns the exact Root UseAuthorized record commitment.
    pub const fn use_authorized_checksum(self) -> [u8; 32] {
        self.use_authorized
    }

    /// Returns the exact Controller RootValidated record commitment.
    pub const fn root_validated_checksum(self) -> [u8; 32] {
        self.root_validated
    }

    /// Derives the exact reserve transaction identity from the complete binding.
    ///
    /// # Errors
    /// Rejects invalid binding DATA or the reserved zero transaction sentinel.
    pub fn reserve_transaction_id(self) -> Result<[u8; 16], ResourceBankDataError> {
        self.transaction_id(b"aos.sandbox.create-storage.use-reserve.v1\0")
    }

    /// Derives the distinct positive-commit identity from the same binding.
    ///
    /// # Errors
    /// Rejects invalid binding DATA or the reserved zero transaction sentinel.
    pub fn commit_transaction_id(self) -> Result<[u8; 16], ResourceBankDataError> {
        self.transaction_id(b"aos.sandbox.create-storage.use-commit.v1\0")
    }

    fn transaction_id(self, domain: &[u8]) -> Result<[u8; 16], ResourceBankDataError> {
        let hash = Sha256::new()
            .chain_update(domain)
            .chain_update(self.encode()?)
            .finalize();
        let id = fixed(&hash[..16])?;
        if id == [0; 16] {
            return Err(ResourceBankDataError::CorruptLedger);
        }
        Ok(id)
    }

    fn require_original(self, original: CoissuanceBinding) -> Result<(), ResourceBankDataError> {
        if self.original != q04::original_claim(original).id
            || self.coissuance != <[u8; 32]>::from(Sha256::digest(q04::encode(original)?))
        {
            return Err(ResourceBankDataError::CorruptLedger);
        }
        Ok(())
    }

    fn require_claim(
        self,
        original: CoissuanceBinding,
        claim: Claim,
    ) -> Result<(), ResourceBankDataError> {
        self.require_original(original)?;
        if claim != inherited_claim(original, self.claim, claim.amount)? {
            return Err(ResourceBankDataError::CorruptLedger);
        }
        Ok(())
    }

    fn original(self, state: &replay::State) -> Result<CoissuanceBinding, ResourceBankDataError> {
        let original = q04::decode(
            replay::record_bytes(state, q04::PREFIX, self.original)
                .ok_or(ResourceBankDataError::CorruptLedger)?,
        )?;
        self.require_original(original)?;
        let terminal = settlement::decode(
            replay::record_bytes(state, settlement::PREFIX, self.original)
                .ok_or(ResourceBankDataError::CorruptLedger)?,
        )?;
        settlement::require_original(terminal, original)?;
        Ok(original)
    }

    fn pairs(
        self,
        original: CoissuanceBinding,
        claim: Claim,
    ) -> Result<(AccountHead, AccountHead, AccountHead), ResourceBankDataError> {
        self.require_claim(original, claim)?;
        let (_, terminal) = settlement::terminal_pair(original)?;
        let reserved = super::account::reserve_head(terminal, claim)?;
        let (committed, _) = super::account::settled_pair(reserved, claim, true)?;
        Ok((terminal, reserved, committed))
    }

    pub(super) fn require_replayed(
        self,
        state: &replay::State,
    ) -> Result<AccountHead, ResourceBankDataError> {
        if replay::record_bytes(state, PREFIX, self.claim) != Some(self.encode()?.as_slice()) {
            return Err(ResourceBankDataError::CorruptLedger);
        }
        let original = self.original(state)?;
        let claim = codec::decode_claim(
            replay::record_bytes(state, replay::CLAIM_PREFIX, self.claim)
                .ok_or(ResourceBankDataError::CorruptLedger)?,
        )?;
        let (_, reserved, committed) = self.pairs(
            original,
            Claim {
                state: ClaimState::Reserved,
                ..claim
            },
        )?;
        let head = match claim.state {
            ClaimState::Reserved => reserved,
            ClaimState::Committed => committed,
            ClaimState::Released => return Err(ResourceBankDataError::CorruptLedger),
        };
        if replay::find_head(state, claim.account)? != head {
            return Err(ResourceBankDataError::CorruptLedger);
        }
        Ok(head)
    }

    /// Bounds fixed replay locals and canonical encoder scratch before comparison.
    ///
    /// This prices DATA controls only; it reserves no account or native work.
    #[must_use]
    pub fn reserved_replay_receiving_bytes_v1() -> Option<usize> {
        std::mem::size_of::<(
            Self, CoissuanceBinding, Claim, super::ClaimFields,
            AccountHead, AccountHead, AccountHead, super::TerminalBinding,
            q04::EncodedBinding, [u8; codec::CLAIM_BYTES],
            [u8; CREATE_STORAGE_USE_BINDING_BYTES_V1], Sha256,
        )>()
        .checked_mul(2)?
        .checked_add(settlement::encoded_binding_receiving_bytes_v1()?)
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
            Result<(AccountHead, Claim), ResourceBankDataError>,
        >()))
    }

    /// Compares the exact current Reserved U and its immutable Q04 ancestry.
    ///
    /// # Errors
    /// Rejects changed binding, predecessor, inherited claim or current head,
    /// and rejects committed or released use claims.
    pub fn reserved_replayed_pair_v1(self, state: &replay::State)
        -> Result<(AccountHead, Claim), ResourceBankDataError> {
        let head = self.require_replayed(state)?;
        let claim = codec::decode_claim(
            replay::record_bytes(state, replay::CLAIM_PREFIX, self.claim)
                .ok_or(ResourceBankDataError::CorruptLedger)?,
        )?;
        if claim.state != ClaimState::Reserved {
            return Err(ResourceBankDataError::Conflict);
        }
        Ok((head, claim))
    }

    /// Borrows the validated actual positive U settlement as comparison DATA.
    ///
    /// # Errors
    /// Rejects a changed immutable binding, historical predecessor, head/claim
    /// relation or any state other than the actual committed claim.
    pub fn committed_replayed_pair_v1(self, state: &replay::State, reserved: Claim)
        -> Result<(AccountHead, Claim), ResourceBankDataError> {
        let head = self.require_replayed(state)?;
        let claim = codec::decode_claim(replay::record_bytes(state, replay::CLAIM_PREFIX, self.claim)
            .ok_or(ResourceBankDataError::CorruptLedger)?)?;
        if reserved.state != ClaimState::Reserved
            || claim != (Claim { state: ClaimState::Committed, ..reserved })
        { return Err(ResourceBankDataError::Conflict); }
        Ok((head, claim))
    }

    pub(super) fn require_transition(
        self,
        state: &replay::State,
        mutation: &AccountMutation<'_>,
    ) -> Result<(), ResourceBankDataError> {
        let original = self.original(state)?;
        q04::require_replayed(state, original)?;
        let claim = Claim {
            state: ClaimState::Reserved,
            ..*mutation.claim
        };
        let (terminal, reserved, committed) = self.pairs(original, claim)?;
        if mutation.child.is_some() || mutation.preparation.is_some() || mutation.terminal.is_some()
        {
            return Err(ResourceBankDataError::Conflict);
        }
        match *mutation.previous_claim {
            None if mutation.claim.state == ClaimState::Reserved
                && *mutation.before == terminal
                && *mutation.after == reserved
                && *mutation.transaction_id == self.reserve_transaction_id()?
                && binding_for_original(state, self.original)?.is_none() => {}
            Some(previous)
                if previous == claim
                    && mutation.claim.state == ClaimState::Committed
                    && *mutation.before == reserved
                    && *mutation.after == committed
                    && *mutation.transaction_id == self.commit_transaction_id()?
                    && replay::record_bytes(state, PREFIX, self.claim)
                        == Some(self.encode()?.as_slice()) => {}
            _ => return Err(ResourceBankDataError::Conflict),
        }
        Ok(())
    }
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ResourceBankDataError> {
    bytes
        .try_into()
        .map_err(|_| ResourceBankDataError::CorruptLedger)
}

fn binding_for_original(
    state: &replay::State,
    original: [u8; 16],
) -> Result<Option<CreateStorageUseBindingV1>, ResourceBankDataError> {
    let mut found = None;
    for ((namespace, key), bytes) in state {
        if *namespace != super::RecordNamespace::ControllerResourceReservation
            || key.first() != Some(&PREFIX)
        {
            continue;
        }
        let binding = CreateStorageUseBindingV1::decode(bytes)?;
        if key.as_slice() != replay::key(PREFIX, binding.claim) {
            return Err(ResourceBankDataError::CorruptLedger);
        }
        if binding.original == original {
            if found.replace(binding).is_some() {
                return Err(ResourceBankDataError::CorruptLedger);
            }
        }
    }
    Ok(found)
}

pub(super) fn current_child(
    state: &replay::State,
    original: CoissuanceBinding,
    terminal: AccountHead,
) -> Result<AccountHead, ResourceBankDataError> {
    match binding_for_original(state, q04::original_claim(original).id)? {
        Some(binding) => binding.require_replayed(state),
        None => Ok(terminal),
    }
}

pub(super) fn require_use_claim(
    state: &replay::State,
    claim: Claim,
) -> Result<(), ResourceBankDataError> {
    let binding = CreateStorageUseBindingV1::decode(
        replay::record_bytes(state, PREFIX, claim.id)
            .ok_or(ResourceBankDataError::CorruptLedger)?,
    )?;
    if binding.claim != claim.id {
        return Err(ResourceBankDataError::CorruptLedger);
    }
    binding.require_replayed(state).map(|_| ())
}

#[derive(Default)]
pub(super) struct UsePhysicalHistoryV1 {
    positions: Vec<UsePosition>,
}

struct UsePosition {
    claim: [u8; 16],
    next: u64,
    end: u64,
    committed: bool,
}

impl UsePhysicalHistoryV1 {
    pub(super) fn additional_demand(
        state: &replay::State,
    ) -> Result<aos_sandbox_core::ResourceVector, ResourceBankDataError> {
        let count = state
            .keys()
            .filter(|(namespace, key)| {
                *namespace == super::RecordNamespace::ControllerResourceReservation
                    && key.first() == Some(&PREFIX)
            })
            .count();
        Self::additional_demand_for_count(count)
    }

    pub(super) fn additional_demand_for_count(
        count: usize,
    ) -> Result<aos_sandbox_core::ResourceVector, ResourceBankDataError> {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

        if count == 0 {
            return Ok(ResourceVector::ZERO);
        }
        let bytes = count
            .max(4)
            .checked_mul(std::mem::size_of::<UsePosition>())
            .and_then(|bytes| bytes.checked_mul(3))
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<Self>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ResourceBankDataError::Conflict)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    pub(super) fn observe(
        &mut self,
        state: &replay::State,
        transaction: &JournalTransaction,
        begin_sequence: u64,
        commit_sequence: u64,
        begin_offset: u64,
        end_offset: u64,
    ) -> Result<(), ResourceBankDataError> {
        for ((namespace, key), bytes) in state {
            if *namespace != super::RecordNamespace::ControllerResourceReservation
                || key.first() != Some(&PREFIX)
            {
                continue;
            }
            let binding = CreateStorageUseBindingV1::decode(bytes)?;
            let reserve = transaction.id() == &binding.reserve_transaction_id()?;
            let commit = transaction.id() == &binding.commit_transaction_id()?;
            if !reserve && !commit {
                continue;
            }
            binding.require_replayed(state)?;
            let original = binding.original(state)?;
            let claim = codec::decode_claim(
                replay::record_bytes(state, replay::CLAIM_PREFIX, binding.claim)
                    .ok_or(ResourceBankDataError::CorruptLedger)?,
            )?;
            let reserved_claim = Claim {
                state: ClaimState::Reserved,
                ..claim
            };
            let (_, reserved_head, committed_head) = binding.pairs(original, reserved_claim)?;
            let records = transaction.records();
            let expected_head = if reserve {
                reserved_head
            } else {
                committed_head
            };
            let expected_claim = if reserve {
                reserved_claim
            } else {
                Claim {
                    state: ClaimState::Committed,
                    ..claim
                }
            };
            if records.len() != (if reserve { 3 } else { 2 })
                || !matches_record(
                    &records[0],
                    replay::HEAD_PREFIX,
                    expected_head.id,
                    &codec::encode_head(expected_head)?,
                )
                || !matches_record(
                    &records[1],
                    replay::CLAIM_PREFIX,
                    expected_claim.id,
                    &codec::encode_claim(expected_claim)?,
                )
                || (reserve
                    && !matches_record(&records[2], PREFIX, binding.claim, &binding.encode()?))
                || (!reserve && claim.state != ClaimState::Committed)
                || begin_sequence.checked_add(records.len() as u64 + 1) != Some(commit_sequence)
                || end_offset <= begin_offset
            {
                return Err(ResourceBankDataError::CorruptLedger);
            }
            let terminal = settlement::decode(
                replay::record_bytes(state, settlement::PREFIX, binding.original)
                    .ok_or(ResourceBankDataError::CorruptLedger)?,
            )?;
            // Q04's three-member terminal consumes five physical frames. A U
            // event cannot precede it or reuse its original byte boundary.
            if begin_sequence
                < terminal
                    .next
                    .checked_add(5)
                    .ok_or(ResourceBankDataError::CorruptLedger)?
                || begin_offset <= terminal.prior_end
            {
                return Err(ResourceBankDataError::CorruptLedger);
            }
            if reserve {
                if self
                    .positions
                    .iter()
                    .any(|position| position.claim == binding.claim)
                {
                    return Err(ResourceBankDataError::CorruptLedger);
                }
                self.positions
                    .try_reserve_exact(1)
                    .map_err(ResourceBankDataError::Representation)?;
                self.positions.push(UsePosition {
                    claim: binding.claim,
                    next: commit_sequence
                        .checked_add(1)
                        .ok_or(ResourceBankDataError::CorruptLedger)?,
                    end: end_offset,
                    committed: false,
                });
            } else {
                let position = self
                    .positions
                    .iter_mut()
                    .find(|position| position.claim == binding.claim)
                    .ok_or(ResourceBankDataError::CorruptLedger)?;
                if position.committed
                    || begin_sequence < position.next
                    || begin_offset < position.end
                {
                    return Err(ResourceBankDataError::CorruptLedger);
                }
                position.committed = true;
            }
        }
        Ok(())
    }

    pub(super) fn finish(
        &self,
        state: &replay::State,
        ids: &std::collections::BTreeSet<[u8; 16]>,
    ) -> Result<(), ResourceBankDataError> {
        let mut count = 0usize;
        for ((namespace, key), bytes) in state {
            if *namespace != super::RecordNamespace::ControllerResourceReservation
                || key.first() != Some(&PREFIX)
            {
                continue;
            }
            let binding = CreateStorageUseBindingV1::decode(bytes)?;
            binding.require_replayed(state)?;
            let claim = codec::decode_claim(
                replay::record_bytes(state, replay::CLAIM_PREFIX, binding.claim)
                    .ok_or(ResourceBankDataError::CorruptLedger)?,
            )?;
            let position = self
                .positions
                .iter()
                .find(|position| position.claim == binding.claim)
                .ok_or(ResourceBankDataError::CorruptLedger)?;
            if !ids.contains(&binding.reserve_transaction_id()?)
                || position.committed != (claim.state == ClaimState::Committed)
                || ids.contains(&binding.commit_transaction_id()?) != position.committed
            {
                return Err(ResourceBankDataError::CorruptLedger);
            }
            count = count
                .checked_add(1)
                .ok_or(ResourceBankDataError::CorruptLedger)?;
        }
        if count != self.positions.len() {
            return Err(ResourceBankDataError::CorruptLedger);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
