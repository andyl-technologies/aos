//! Durable Cache policy-state freeze for an inert Create binding cut.
//!
//! ```text
//! AOSCPH01 | version:u16 | phase:held|released | reserved:5 |
//! project:16 | partition:32 | cache-head:32 | binding:32 | epoch:u64 |
//! SHA-256(Cache-hold-domain || preceding 136 bytes):32
//! ```
//! V8 retirement also retains the prior held row's digest until Root records
//! the post-Controller settlement:
//!
//! ```text
//! AOSCPP08 | version=1 | phase=pending | reserved[5] |
//! binding[32] | epoch:u64 | SHA-256(held AOSCPH01)[32] |
//! SHA-256(released AOSCPH01)[32] |
//! SHA-256(Cache-V8-pending-domain || preceding 120 bytes)[32]
//! ```
//!
//! A separate protected journal lets Cache state and manifest commits hold its
//! writer lock through sync. The Cache clock may still advance its monotone
//! floor; it cannot change quota, domain, or replay head.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use aos_sandbox_core::{ObjectDigest, ProjectId};
use sha2::{Digest as _, Sha256};

use crate::policy_compiler::RootV8SettledGrantV1;

use super::{
    Journal, JournalError, JournalLimits, JournalRecord, JournalTransaction,
    ReadOnlyProtectedJournal, RecordNamespace,
};

mod retained;
pub(crate) use retained::{
    BorrowedCacheMutationGateV1, CacheMutationGateV1, HeldCacheMutationGateV1,
};

pub(crate) const NAME: &str = "policy-hold.journal";
const GENESIS_KEY: &[u8] = b"\0aos-cache-policy-hold-genesis-v1\0";
const HOLD_KEY: &[u8] = b"\0aos-cache-policy-hold-v1\0";
const V8_PENDING_KEY: &[u8] = b"\0aos-cache-policy-v8-pending-settlement-v1\0";
const GENESIS: &[u8] = b"AOSCPG01";
const MAGIC: &[u8; 8] = b"AOSCPH01";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.cache-policy-hold.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.cache-policy-hold-transaction.v1\0";
const V8_PENDING_MAGIC: &[u8; 8] = b"AOSCPP08";
const V8_PENDING_CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.cache-policy-v8-pending.v1\0";
const V8_RELEASE_TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.cache-policy-v8-release.v1\0";
const V8_SETTLEMENT_TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.cache-policy-v8-settlement.v1\0";
const V8_SETTLEMENT_PREFLIGHT_DOMAIN: &[u8] =
    b"aos.sandbox.cache-policy-v8-settlement-preflight.v1\0";
const RECORD_BYTES: usize = 168;
const V8_PENDING_RECORD_BYTES: usize = 152;

fn hold_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 16 * 1024 * 1024,
        maximum_record_bytes: 512,
        maximum_key_bytes: 128,
        maximum_records_per_transaction: 2,
        maximum_transaction_bytes: 1024,
        maximum_transactions: 50_000,
        maximum_materialized_bytes: 1024,
        maximum_materialized_records: 3,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CachePolicyV8PendingSettlementV1 {
    binding: ObjectDigest,
    epoch: u64,
    held_digest: ObjectDigest,
    released_digest: ObjectDigest,
}

impl CachePolicyV8PendingSettlementV1 {
    fn new(held: CachePolicyHoldV1, released: CachePolicyHoldV1) -> Result<Self, JournalError> {
        if !held.is_held()
            || released
                != (CachePolicyHoldV1 {
                    held: false,
                    ..held
                })
        {
            return Err(JournalError::ProtectedBoundary);
        }

        Ok(Self {
            binding: held.binding(),
            epoch: held.epoch(),
            held_digest: held.record_digest()?,
            released_digest: released.record_digest()?,
        })
    }

    fn validate_for(self, released: CachePolicyHoldV1) -> Result<(), JournalError> {
        if released.is_held()
            || self
                != Self::new(
                    CachePolicyHoldV1 {
                        held: true,
                        ..released
                    },
                    released,
                )?
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    fn encode(self) -> [u8; V8_PENDING_RECORD_BYTES] {
        let mut bytes = [0_u8; V8_PENDING_RECORD_BYTES];
        bytes[..8].copy_from_slice(V8_PENDING_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = 1;
        bytes[16..48].copy_from_slice(self.binding.as_bytes());
        bytes[48..56].copy_from_slice(&self.epoch.to_be_bytes());
        bytes[56..88].copy_from_slice(self.held_digest.as_bytes());
        bytes[88..120].copy_from_slice(self.released_digest.as_bytes());
        let checksum = Sha256::new()
            .chain_update(V8_PENDING_CHECKSUM_DOMAIN)
            .chain_update(&bytes[..120])
            .finalize();
        bytes[120..].copy_from_slice(&checksum);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        if bytes.len() != V8_PENDING_RECORD_BYTES
            || bytes.get(..8) != Some(V8_PENDING_MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[10] != 1
            || bytes[11..16] != [0; 5]
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let pending = Self {
            binding: ObjectDigest::from_bytes(
                bytes[16..48]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            epoch: u64::from_be_bytes(
                bytes[48..56]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            held_digest: ObjectDigest::from_bytes(
                bytes[56..88]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            released_digest: ObjectDigest::from_bytes(
                bytes[88..120]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
        };
        if pending.encode().as_slice() != bytes {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(pending)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct CachePolicyHoldStateV1 {
    hold: Option<CachePolicyHoldV1>,
    v8_pending: Option<CachePolicyV8PendingSettlementV1>,
}

/// Identifies one exact, nonauthorizing protected Cache policy hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CachePolicyHoldV1 {
    project: ProjectId,
    partition: ObjectDigest,
    cache_head: ObjectDigest,
    binding: ObjectDigest,
    epoch: u64,
    held: bool,
}

impl CachePolicyHoldV1 {
    /// Constructs the exact Cache cut to freeze before root submission.
    ///
    /// # Errors
    ///
    /// Rejects sentinel identities and a zero epoch.
    pub fn new(
        project: ProjectId,
        partition: ObjectDigest,
        cache_head: ObjectDigest,
        binding: ObjectDigest,
        epoch: u64,
    ) -> Result<Self, JournalError> {
        let hold = Self {
            project,
            partition,
            cache_head,
            binding,
            epoch,
            held: true,
        };
        hold.validate()?;
        Ok(hold)
    }

    /// Returns the held project.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the held physical partition digest.
    #[must_use]
    pub const fn partition(self) -> ObjectDigest {
        self.partition
    }

    /// Returns the exact protected Cache replay head.
    #[must_use]
    pub const fn cache_head(self) -> ObjectDigest {
        self.cache_head
    }

    /// Returns the proposed root binding digest.
    #[must_use]
    pub const fn binding(self) -> ObjectDigest {
        self.binding
    }

    /// Returns the proposed root handoff epoch.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Reports whether Cache policy state remains frozen.
    #[must_use]
    pub const fn is_held(self) -> bool {
        self.held
    }

    /// Returns the digest of the exact canonical held or released record.
    ///
    /// # Errors
    ///
    /// Rejects invalid Cache hold fields.
    pub fn record_digest(self) -> Result<ObjectDigest, JournalError> {
        Ok(ObjectDigest::from_bytes(
            Sha256::digest(self.encode()?).into(),
        ))
    }

    fn validate(self) -> Result<(), JournalError> {
        if self.project.as_bytes() == &[0; 16]
            || self.partition.as_bytes() == &[0; 32]
            || self.cache_head.as_bytes() == &[0; 32]
            || self.binding.as_bytes() == &[0; 32]
            || self.epoch == 0
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    fn encode(self) -> Result<[u8; RECORD_BYTES], JournalError> {
        self.validate()?;
        let mut bytes = [0_u8; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = if self.held { 1 } else { 2 };
        bytes[16..32].copy_from_slice(self.project.as_bytes());
        bytes[32..64].copy_from_slice(self.partition.as_bytes());
        bytes[64..96].copy_from_slice(self.cache_head.as_bytes());
        bytes[96..128].copy_from_slice(self.binding.as_bytes());
        bytes[128..136].copy_from_slice(&self.epoch.to_be_bytes());
        let checksum = Sha256::new()
            .chain_update(CHECKSUM_DOMAIN)
            .chain_update(&bytes[..136])
            .finalize();
        bytes[136..].copy_from_slice(&checksum);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        if bytes.len() != RECORD_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || !matches!(bytes[10], 1 | 2)
            || bytes[11..16] != [0; 5]
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let hold = Self {
            project: ProjectId::from_bytes(
                bytes[16..32]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            partition: ObjectDigest::from_bytes(
                bytes[32..64]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            cache_head: ObjectDigest::from_bytes(
                bytes[64..96]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            binding: ObjectDigest::from_bytes(
                bytes[96..128]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            epoch: u64::from_be_bytes(
                bytes[128..136]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            held: bytes[10] == 1,
        };
        if hold.encode()?.as_slice() != bytes {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(hold)
    }
}

fn transaction(key: &[u8], value: &[u8]) -> Result<JournalTransaction, JournalError> {
    let digest = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(key)
        .chain_update(value)
        .finalize();
    JournalTransaction::new(
        digest[..16]
            .try_into()
            .map_err(|_| JournalError::ProtectedBoundary)?,
        vec![JournalRecord::put(
            RecordNamespace::DesiredState,
            key.to_vec(),
            value.to_vec(),
        )],
    )
}

fn v8_release_transaction(
    released: CachePolicyHoldV1,
    pending: CachePolicyV8PendingSettlementV1,
) -> Result<JournalTransaction, JournalError> {
    pending.validate_for(released)?;
    let hold_bytes = released.encode()?;
    let pending_bytes = pending.encode();
    let digest = Sha256::new()
        .chain_update(V8_RELEASE_TRANSACTION_DOMAIN)
        .chain_update(hold_bytes)
        .chain_update(pending_bytes)
        .finalize();

    JournalTransaction::new(
        digest[..16]
            .try_into()
            .map_err(|_| JournalError::ProtectedBoundary)?,
        vec![
            JournalRecord::put(
                RecordNamespace::DesiredState,
                HOLD_KEY.to_vec(),
                hold_bytes.to_vec(),
            ),
            JournalRecord::put(
                RecordNamespace::DesiredState,
                V8_PENDING_KEY.to_vec(),
                pending_bytes.to_vec(),
            ),
        ],
    )
}

fn v8_settlement_transaction(
    grant: RootV8SettledGrantV1,
) -> Result<JournalTransaction, JournalError> {
    let digest = Sha256::new()
        .chain_update(V8_SETTLEMENT_TRANSACTION_DOMAIN)
        .chain_update(grant.predecessor().as_bytes())
        .chain_update(grant.epoch().to_be_bytes())
        .chain_update(grant.cache_released().as_bytes())
        .chain_update(grant.settlement().as_bytes())
        .finalize();

    JournalTransaction::new(
        digest[..16]
            .try_into()
            .map_err(|_| JournalError::ProtectedBoundary)?,
        vec![JournalRecord::delete(
            RecordNamespace::DesiredState,
            V8_PENDING_KEY.to_vec(),
        )],
    )
}

fn v8_settlement_preflight_transaction(
    released: CachePolicyHoldV1,
) -> Result<JournalTransaction, JournalError> {
    let digest = Sha256::new()
        .chain_update(V8_SETTLEMENT_PREFLIGHT_DOMAIN)
        .chain_update(released.encode()?)
        .finalize();

    JournalTransaction::new(
        digest[..16]
            .try_into()
            .map_err(|_| JournalError::ProtectedBoundary)?,
        vec![JournalRecord::delete(
            RecordNamespace::DesiredState,
            V8_PENDING_KEY.to_vec(),
        )],
    )
}

fn current_state(journal: &mut Journal) -> Result<CachePolicyHoldStateV1, JournalError> {
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    let mut records = authority.records()?;
    if records.next() != Some((GENESIS_KEY, GENESIS)) {
        return Err(JournalError::ProtectedBoundary);
    }
    let hold = match records.next() {
        Some((HOLD_KEY, value)) => Some(CachePolicyHoldV1::decode(value)?),
        Some(_) => return Err(JournalError::ProtectedBoundary),
        None => None,
    };
    let v8_pending = match records.next() {
        Some((V8_PENDING_KEY, value)) => Some(CachePolicyV8PendingSettlementV1::decode(value)?),
        Some(_) => return Err(JournalError::ProtectedBoundary),
        None => None,
    };
    if records.next().is_some() {
        return Err(JournalError::ProtectedBoundary);
    }
    if let Some(pending) = v8_pending {
        pending.validate_for(hold.ok_or(JournalError::ProtectedBoundary)?)?;
    }
    Ok(CachePolicyHoldStateV1 { hold, v8_pending })
}

fn current(journal: &mut Journal) -> Result<Option<CachePolicyHoldV1>, JournalError> {
    Ok(current_state(journal)?.hold)
}

fn v8_released_pair(
    state: CachePolicyHoldStateV1,
) -> Result<(CachePolicyHoldV1, CachePolicyHoldV1), JournalError> {
    let released = state.hold.ok_or(JournalError::ProtectedBoundary)?;
    let pending = state.v8_pending.ok_or(JournalError::ProtectedBoundary)?;
    pending.validate_for(released)?;
    Ok((
        CachePolicyHoldV1 {
            held: true,
            ..released
        },
        released,
    ))
}

pub(super) fn require_valid_compaction(journal: &mut Journal) -> Result<(), JournalError> {
    if journal
        .protected
        .as_ref()
        .is_some_and(|location| location.name == NAME)
    {
        current_state(journal)?;
    }
    Ok(())
}

impl ReadOnlyProtectedJournal {
    /// Returns only an active, canonical hold from the fixed read-only name.
    pub(crate) fn held_cache_policy_hold(&mut self) -> Result<CachePolicyHoldV1, JournalError> {
        if self.witness.name != NAME {
            return Err(JournalError::ProtectedBoundary);
        }
        current(&mut self.journal)?
            .filter(|hold| hold.is_held())
            .ok_or(JournalError::ProtectedBoundary)
    }
}

impl Journal {
    /// Reads an active Cache hold while retaining its protected writer lock.
    ///
    /// # Errors
    ///
    /// Rejects a foreign name, released or malformed hold, or lost named custody.
    pub(crate) fn held_cache_policy_hold_for_writer(
        &mut self,
    ) -> Result<CachePolicyHoldV1, JournalError> {
        self.cache_policy_hold_for_writer()?
            .filter(|hold| hold.is_held())
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn cache_policy_hold_for_writer(
        &mut self,
    ) -> Result<Option<CachePolicyHoldV1>, JournalError> {
        Ok(self.cache_policy_hold_state_for_writer()?.hold)
    }

    /// Reads an exact V8 pending release under retained writer custody.
    ///
    /// # Errors
    ///
    /// Rejects changed custody, a missing marker, or a mismatched released row.
    pub(crate) fn v8_pending_cache_policy_release_for_writer(
        &mut self,
    ) -> Result<(CachePolicyHoldV1, CachePolicyHoldV1), JournalError> {
        v8_released_pair(self.cache_policy_hold_state_for_writer()?)
    }

    /// Reads one released Cache row against an authenticated Root settlement.
    ///
    /// The marker's presence is returned so a retained writer can reject a
    /// change between its first observation and final postflight. Absence is
    /// accepted only when Root's exact released-row digest still matches.
    ///
    /// # Errors
    ///
    /// Rejects changed writer names, a held or different row, or malformed
    /// pending settlement evidence.
    pub(crate) fn v8_cache_policy_settlement_state_for_writer(
        &mut self,
        grant: RootV8SettledGrantV1,
    ) -> Result<(CachePolicyHoldV1, CachePolicyHoldV1, bool), JournalError> {
        let state = self.cache_policy_hold_state_for_writer()?;
        let released = state.hold.ok_or(JournalError::ProtectedBoundary)?;
        if released.is_held()
            || released.binding() != grant.predecessor()
            || released.epoch() != grant.epoch()
            || released.record_digest()? != grant.cache_released()
        {
            return Err(JournalError::ProtectedBoundary);
        }

        let held = CachePolicyHoldV1 {
            held: true,
            ..released
        };
        Ok((held, released, state.v8_pending.is_some()))
    }

    /// Clears only the pending V8 marker after an exact Root successor grant.
    ///
    /// The canonical released row remains durable. Replaying after a lost
    /// reply performs no second commit, but still checks that row and grant.
    ///
    /// # Errors
    ///
    /// Rejects a stale row or grant, or a failed durable deletion and readback.
    pub(crate) fn clear_v8_pending_cache_settlement_for_writer(
        &mut self,
        grant: RootV8SettledGrantV1,
    ) -> Result<CachePolicyHoldV1, JournalError> {
        let (_, released, pending) = self.v8_cache_policy_settlement_state_for_writer(grant)?;
        if pending {
            self.commit(&v8_settlement_transaction(grant)?)?;
        }
        let (_, readback, still_pending) =
            self.v8_cache_policy_settlement_state_for_writer(grant)?;
        if still_pending || readback != released {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(readback)
    }

    fn cache_policy_hold_state_for_writer(
        &mut self,
    ) -> Result<CachePolicyHoldStateV1, JournalError> {
        let location = self
            .protected
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if location.name != NAME {
            return Err(JournalError::ProtectedBoundary);
        }
        self.require_protected_names_current()?;
        current_state(self)
    }
}

fn open(directory: &Path, uid: u32) -> Result<Journal, JournalError> {
    #[cfg(test)]
    let opened = Journal::open_protected_at_uid(directory, NAME, hold_limits(), uid);
    #[cfg(not(test))]
    let opened = Journal::open_protected_at_for_uid(directory, NAME, hold_limits(), uid);
    opened.map(|(journal, _)| journal)
}

pub(crate) fn initialize_fresh(directory: &Path, uid: u32) -> Result<(), JournalError> {
    let hold_path = directory.join(NAME);
    let existing = match fs::symlink_metadata(&hold_path) {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(JournalError::Io(error)),
    };
    if !existing {
        for name in ["state.journal", "authority.journal", "clock.journal"] {
            for suffix in ["", ".lock", ".compact.tmp"] {
                match fs::symlink_metadata(directory.join(format!("{name}{suffix}"))) {
                    Ok(_) => return Err(JournalError::ProtectedBoundary),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(JournalError::Io(error)),
                }
            }
        }
    }
    let mut journal = open(directory, uid)?;
    if journal.all_records().next().is_none() && !existing {
        journal.commit(&transaction(GENESIS_KEY, GENESIS)?)?;
    }
    current(&mut journal)?;
    Ok(())
}

pub(super) fn check_unheld(journal: &Journal) -> Result<(), JournalError> {
    let _guard = mutation_guard(journal)?;
    Ok(())
}

pub(super) fn mutation_guard(journal: &Journal) -> Result<Option<Journal>, JournalError> {
    let Some((directory, uid)) = &journal.cache_policy_gate else {
        return Ok(None);
    };
    #[cfg(not(test))]
    journal.require_protected_location(
        directory,
        &journal
            .protected
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?
            .name,
        *uid,
        journal.limits,
    )?;
    let mut hold = open(directory, *uid)?;
    if current(&mut hold)?.is_some_and(CachePolicyHoldV1::is_held) {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(Some(hold))
}

impl Journal {
    /// Returns the fixed replay bounds for the protected Cache hold name.
    pub(crate) fn cache_policy_hold_limits() -> JournalLimits {
        hold_limits()
    }

    pub(crate) fn initialize_cache_policy_hold_at(
        directory: &Path,
        uid: u32,
    ) -> Result<(), JournalError> {
        initialize_fresh(directory, uid)
    }

    pub(crate) fn enable_cache_policy_hold_gate(
        &mut self,
        directory: &Path,
        uid: u32,
    ) -> Result<(), JournalError> {
        self.ensure_protected_authority()?;
        let location = self
            .protected
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if location.expected_uid != uid
            || !matches!(
                location.name.as_str(),
                "state.journal" | "authority.journal"
            )
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.cache_policy_gate = Some((PathBuf::from(directory), uid));
        Ok(())
    }

    pub(crate) fn read_cache_policy_hold_at(
        directory: &Path,
        uid: u32,
    ) -> Result<Option<CachePolicyHoldV1>, JournalError> {
        current(&mut open(directory, uid)?)
    }

    /// Recovers the exact held and released rows from a V8 pending marker.
    ///
    /// # Errors
    ///
    /// Rejects a missing marker, mismatched row, or stale protected name.
    pub(crate) fn read_v8_pending_cache_policy_release_at(
        directory: &Path,
        uid: u32,
    ) -> Result<(CachePolicyHoldV1, CachePolicyHoldV1), JournalError> {
        let state = current_state(&mut open(directory, uid)?)?;
        v8_released_pair(state)
    }

    pub(crate) fn acquire_cache_policy_hold_at(
        directory: &Path,
        uid: u32,
        hold: CachePolicyHoldV1,
    ) -> Result<(), JournalError> {
        if !hold.held {
            return Err(JournalError::ProtectedBoundary);
        }
        let mut journal = open(directory, uid)?;
        journal.acquire_cache_policy_hold_for_writer(hold)
    }

    fn acquire_cache_policy_hold_for_writer(
        &mut self,
        hold: CachePolicyHoldV1,
    ) -> Result<(), JournalError> {
        if !hold.held {
            return Err(JournalError::ProtectedBoundary);
        }
        let state = self.cache_policy_hold_state_for_writer()?;
        if state.hold.is_some_and(CachePolicyHoldV1::is_held) || state.v8_pending.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        let acquire = transaction(HOLD_KEY, &hold.encode()?)?;
        let released = CachePolicyHoldV1 {
            held: false,
            ..hold
        };
        let legacy_release = transaction(HOLD_KEY, &released.encode()?)?;
        let v8_pending = CachePolicyV8PendingSettlementV1::new(hold, released)?;
        let v8_release = v8_release_transaction(released, v8_pending)?;
        let v8_clear = v8_settlement_preflight_transaction(released)?;
        self.preflight_transactions(&[acquire.clone(), legacy_release])?;
        // The pending marker must be clearable without depending on future
        // compaction, even when this acquire reaches the journal capacity edge.
        self.preflight_transactions(&[acquire.clone(), v8_release, v8_clear])?;
        self.commit(&acquire)?;
        if current(self)? != Some(hold) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn release_cache_policy_hold_if_at<E>(
        directory: &Path,
        uid: u32,
        expected: CachePolicyHoldV1,
        verify_root: impl FnOnce() -> Result<(), E>,
    ) -> Result<(), E>
    where
        E: From<JournalError>,
    {
        let mut journal = open(directory, uid)?;
        if !expected.held || current(&mut journal)? != Some(expected) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        // No state or manifest writer can cross this check: each commit must
        // borrow this same hold-journal lock until its durable sync completes.
        verify_root()?;
        let released = CachePolicyHoldV1 {
            held: false,
            ..expected
        };
        journal.commit(&transaction(HOLD_KEY, &released.encode()?)?)?;
        if current(&mut journal)? != Some(released) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        Ok(())
    }

    /// Retires an exact Cache hold through its already retained writer.
    ///
    /// The caller must retain the other Cache writers and physical owner until
    /// its final cross-owner checks have completed. Opening this journal again
    /// would contend with the writer held by that same callback. The returned
    /// canonical released row is read back from this writer after durable sync;
    /// an exact cold replay returns the same row without another commit.
    ///
    /// # Errors
    ///
    /// Rejects foreign or stale writer custody, a different hold, or failed
    /// durable commit and readback.
    pub(crate) fn release_held_cache_policy_hold_for_writer(
        &mut self,
        expected: CachePolicyHoldV1,
    ) -> Result<CachePolicyHoldV1, JournalError> {
        if !expected.is_held() {
            return Err(JournalError::ProtectedBoundary);
        }

        let released = CachePolicyHoldV1 {
            held: false,
            ..expected
        };
        match self.cache_policy_hold_state_for_writer()? {
            CachePolicyHoldStateV1 {
                hold: Some(current),
                v8_pending: None,
            } if current == expected => {
                self.commit(&transaction(HOLD_KEY, &released.encode()?)?)?;
            }
            CachePolicyHoldStateV1 {
                hold: Some(current),
                v8_pending: None,
            } if current == released => {}
            _ => return Err(JournalError::ProtectedBoundary),
        }

        let readback = self
            .cache_policy_hold_for_writer()?
            .ok_or(JournalError::ProtectedBoundary)?;
        if readback != released {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(readback)
    }

    /// Retires a V8 Cache hold with its pending settlement in one transaction.
    ///
    /// The marker retains both canonical row digests until a future trusted
    /// Root successor settlement permits clearing it. Replaying the exact
    /// released pair through this writer performs no second commit.
    ///
    /// # Errors
    ///
    /// Rejects changed custody, a different row, a missing marker on replay,
    /// or a failed durable transaction or readback.
    pub(crate) fn release_v8_held_cache_policy_hold_for_writer(
        &mut self,
        expected: CachePolicyHoldV1,
    ) -> Result<CachePolicyHoldV1, JournalError> {
        if !expected.is_held() {
            return Err(JournalError::ProtectedBoundary);
        }
        let released = CachePolicyHoldV1 {
            held: false,
            ..expected
        };
        let pending = CachePolicyV8PendingSettlementV1::new(expected, released)?;
        let state = self.cache_policy_hold_state_for_writer()?;
        match state {
            CachePolicyHoldStateV1 {
                hold: Some(current),
                v8_pending: None,
            } if current == expected => {
                self.commit(&v8_release_transaction(released, pending)?)?;
            }
            CachePolicyHoldStateV1 {
                hold: Some(current),
                v8_pending: Some(current_pending),
            } if current == released && current_pending == pending => {}
            _ => return Err(JournalError::ProtectedBoundary),
        }

        let (held_readback, released_readback) =
            v8_released_pair(self.cache_policy_hold_state_for_writer()?)?;
        if held_readback != expected || released_readback != released {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(released_readback)
    }

    /// Retains the exact hold writer through a non-mutating local observation.
    ///
    /// The caller must already retain clock, authority, and state writers in
    /// that order. In particular, this is not a policy publication capability.
    pub(crate) fn with_held_cache_policy_hold_at<R, E>(
        directory: &Path,
        uid: u32,
        expected: CachePolicyHoldV1,
        observe: impl FnOnce() -> Result<R, E>,
    ) -> Result<R, E>
    where
        E: From<JournalError>,
    {
        let mut journal = open(directory, uid)?;
        if !expected.is_held() || current(&mut journal)? != Some(expected) {
            return Err(JournalError::ProtectedBoundary.into());
        }

        let result = observe()?;
        if current(&mut journal)? != Some(expected) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        #[cfg(test)]
        journal.require_protected_names_current_for_test()?;
        #[cfg(not(test))]
        journal.require_protected_named_location(directory, NAME, uid, hold_limits())?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use super::*;

    fn fixture() -> (tempfile::TempDir, u32) {
        let directory = tempfile::tempdir().expect("private Cache fixture");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory mode");
        let uid = fs::metadata(directory.path())
            .expect("directory metadata")
            .uid();
        (directory, uid)
    }

    fn open_gated(directory: &Path, uid: u32, name: &str) -> Journal {
        let (mut journal, _) =
            Journal::open_protected_at_uid(directory, name, JournalLimits::default(), uid)
                .expect("protected Cache journal");
        journal
            .enable_cache_policy_hold_gate(directory, uid)
            .expect("Cache gate");
        journal
    }

    fn put(id: u8) -> JournalTransaction {
        JournalTransaction::new(
            [id; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                vec![id],
                vec![id],
            )],
        )
        .expect("test transaction")
    }

    fn hold() -> CachePolicyHoldV1 {
        CachePolicyHoldV1::new(
            ProjectId::from_bytes([1; 16]),
            ObjectDigest::from_bytes([2; 32]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
            5,
        )
        .expect("Cache hold")
    }

    fn settled_grant(released: CachePolicyHoldV1) -> RootV8SettledGrantV1 {
        let mut bytes = [0_u8; 256];
        bytes[..8].copy_from_slice(b"AOSPC88S");
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[16..48].copy_from_slice(released.binding().as_bytes());
        bytes[48..56].copy_from_slice(&released.epoch().to_be_bytes());
        bytes[56..64].copy_from_slice(&(released.epoch() + 1).to_be_bytes());
        for (offset, value) in [(64, 6), (96, 7), (160, 8), (192, 9)] {
            bytes[offset..offset + 32].fill(value);
        }
        bytes[128..160].copy_from_slice(released.record_digest().unwrap().as_bytes());
        let checksum = Sha256::new()
            .chain_update(b"aos.sandbox.policy-compiler.root-v8-successor-settlement.v1\0")
            .chain_update(&bytes[..224])
            .finalize();
        bytes[224..].copy_from_slice(&checksum);
        RootV8SettledGrantV1::from_record_bytes_for_test(&bytes)
            .expect("canonical settled Root grant")
    }

    #[test]
    fn held_cache_cuts_survive_reopen_and_fence_state_and_manifest_writes() {
        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).expect("fresh hold genesis");
        let mut state = open_gated(directory.path(), uid, "state.journal");
        let mut authority = open_gated(directory.path(), uid, "authority.journal");
        state.commit(&put(10)).expect("state before hold");

        Journal::acquire_cache_policy_hold_at(directory.path(), uid, hold())
            .expect("durable Cache freeze");
        assert_eq!(
            Journal::read_cache_policy_hold_at(directory.path(), uid).unwrap(),
            Some(hold())
        );
        assert!(matches!(
            state.commit(&put(11)),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(matches!(
            authority.commit(&put(12)),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(matches!(
            state.compact(),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(matches!(
            authority.preflight_transactions(&[put(13)]),
            Err(JournalError::ProtectedBoundary)
        ));
        drop(state);
        drop(authority);

        let mut reopened = open_gated(directory.path(), uid, "state.journal");
        assert!(matches!(
            reopened.commit(&put(14)),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(Journal::acquire_cache_policy_hold_at(directory.path(), uid, hold()).is_err());
        assert!(
            Journal::release_cache_policy_hold_if_at::<JournalError>(
                directory.path(),
                uid,
                hold(),
                || Err(JournalError::ProtectedBoundary)
            )
            .is_err()
        );
        assert_eq!(
            Journal::read_cache_policy_hold_at(directory.path(), uid).unwrap(),
            Some(hold())
        );

        let wrong = CachePolicyHoldV1::new(
            hold().project(),
            hold().partition(),
            hold().cache_head(),
            ObjectDigest::from_bytes([9; 32]),
            hold().epoch(),
        )
        .expect("different root binding");
        assert!(
            Journal::release_cache_policy_hold_if_at::<JournalError>(
                directory.path(),
                uid,
                wrong,
                || Ok(())
            )
            .is_err()
        );
        Journal::release_cache_policy_hold_if_at::<JournalError>(
            directory.path(),
            uid,
            hold(),
            || Ok(()),
        )
        .expect("exact cold release");
        reopened.commit(&put(15)).expect("state after release");
        assert!(
            !Journal::read_cache_policy_hold_at(directory.path(), uid)
                .unwrap()
                .expect("released record")
                .is_held()
        );
    }

    #[test]
    fn retained_admission_denies_active_and_v8_pending_without_changing_ordinary_mutation() {
        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).unwrap();
        let mut state = open_gated(directory.path(), uid, "state.journal");
        let authority = open_gated(directory.path(), uid, "authority.journal");
        let mut gate = open(directory.path(), uid).unwrap();
        gate.acquire_cache_policy_hold_for_writer(hold()).unwrap();
        drop(gate);
        assert!(Journal::retain_cache_read_mutation_gate_v1(&state, &authority).is_err());
        assert!(state.commit(&put(81)).is_err());

        let mut gate = open(directory.path(), uid).unwrap();
        gate.release_v8_held_cache_policy_hold_for_writer(hold())
            .unwrap();
        drop(gate);
        assert!(Journal::retain_cache_read_mutation_gate_v1(&state, &authority).is_err());
        state
            .commit(&put(82))
            .expect("ordinary released+pending mutation remains allowed");
    }

    #[test]
    fn retained_writer_releases_only_its_exact_hold_and_replays_the_release() {
        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).expect("fresh hold genesis");
        Journal::acquire_cache_policy_hold_at(directory.path(), uid, hold())
            .expect("durable Cache freeze");

        let mut writer = open(directory.path(), uid).expect("retained hold writer");
        let wrong = CachePolicyHoldV1::new(
            hold().project(),
            hold().partition(),
            hold().cache_head(),
            ObjectDigest::from_bytes([9; 32]),
            hold().epoch(),
        )
        .expect("different binding");
        assert!(matches!(
            writer.release_held_cache_policy_hold_for_writer(wrong),
            Err(JournalError::ProtectedBoundary)
        ));
        assert_eq!(writer.held_cache_policy_hold_for_writer().unwrap(), hold());

        let first = writer
            .release_held_cache_policy_hold_for_writer(hold())
            .expect("exact release through retained writer");
        assert!(!first.is_held());
        assert_eq!(first.project(), hold().project());
        assert_eq!(first.partition(), hold().partition());
        assert_eq!(first.cache_head(), hold().cache_head());
        assert_eq!(first.binding(), hold().binding());
        assert_eq!(first.epoch(), hold().epoch());
        assert_ne!(
            first.record_digest().unwrap(),
            hold().record_digest().unwrap()
        );
        assert!(writer.held_cache_policy_hold_for_writer().is_err());
        drop(writer);

        let mut reopened = open(directory.path(), uid).expect("cold retained writer");
        let released = reopened
            .release_held_cache_policy_hold_for_writer(hold())
            .expect("exact cold release replay");
        assert_eq!(released, first);

        let changed = [
            CachePolicyHoldV1::new(
                ProjectId::from_bytes([9; 16]),
                hold().partition(),
                hold().cache_head(),
                hold().binding(),
                hold().epoch(),
            ),
            CachePolicyHoldV1::new(
                hold().project(),
                ObjectDigest::from_bytes([9; 32]),
                hold().cache_head(),
                hold().binding(),
                hold().epoch(),
            ),
            CachePolicyHoldV1::new(
                hold().project(),
                hold().partition(),
                ObjectDigest::from_bytes([9; 32]),
                hold().binding(),
                hold().epoch(),
            ),
            CachePolicyHoldV1::new(
                hold().project(),
                hold().partition(),
                hold().cache_head(),
                ObjectDigest::from_bytes([9; 32]),
                hold().epoch(),
            ),
            CachePolicyHoldV1::new(
                hold().project(),
                hold().partition(),
                hold().cache_head(),
                hold().binding(),
                hold().epoch() + 1,
            ),
        ];
        for mismatched in changed {
            assert!(matches!(
                reopened.release_held_cache_policy_hold_for_writer(mismatched.unwrap()),
                Err(JournalError::ProtectedBoundary)
            ));
        }
        assert!(matches!(
            reopened.release_held_cache_policy_hold_for_writer(released),
            Err(JournalError::ProtectedBoundary)
        ));
        drop(reopened);

        let replayed = Journal::read_cache_policy_hold_at(directory.path(), uid)
            .expect("cold replay")
            .expect("released record");
        assert_eq!(replayed, released);
        assert_eq!(
            replayed.record_digest().unwrap(),
            first.record_digest().unwrap()
        );
    }

    #[test]
    fn v8_pending_settlement_survives_compaction_and_fences_new_holds() {
        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).expect("fresh genesis");
        Journal::acquire_cache_policy_hold_at(directory.path(), uid, hold()).expect("held cut");

        let mut writer = open(directory.path(), uid).expect("retained Cache writer");
        let released = writer
            .release_v8_held_cache_policy_hold_for_writer(hold())
            .expect("atomic V8 release");
        assert!(!released.is_held());
        assert_eq!(
            writer
                .release_v8_held_cache_policy_hold_for_writer(hold())
                .expect("exact retained replay"),
            released
        );
        writer.compact().expect("validated compaction");
        drop(writer);

        assert_eq!(
            Journal::read_v8_pending_cache_policy_release_at(directory.path(), uid)
                .expect("cold V8 row pair"),
            (hold(), released)
        );
        assert_eq!(
            Journal::read_cache_policy_hold_at(directory.path(), uid)
                .expect("ordinary typed readback"),
            Some(released)
        );
        assert!(matches!(
            Journal::acquire_cache_policy_hold_at(directory.path(), uid, hold()),
            Err(JournalError::ProtectedBoundary)
        ));

        let mut reopened = open(directory.path(), uid).expect("cold writer");
        assert_eq!(
            reopened
                .release_v8_held_cache_policy_hold_for_writer(hold())
                .expect("cold exact replay"),
            released
        );
        assert!(matches!(
            reopened.release_held_cache_policy_hold_for_writer(hold()),
            Err(JournalError::ProtectedBoundary)
        ));
    }

    #[test]
    fn cache_acquire_reserves_capacity_for_v8_marker_clear() {
        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).expect("fresh genesis");

        let insufficient = JournalLimits {
            maximum_transactions: 3,
            ..hold_limits()
        };
        let (mut writer, _) =
            Journal::open_protected_at_uid(directory.path(), NAME, insufficient, uid)
                .expect("small Cache journal");
        assert!(matches!(
            writer.acquire_cache_policy_hold_for_writer(hold()),
            Err(JournalError::LimitExceeded(_))
        ));
        assert_eq!(writer.cache_policy_hold_for_writer().unwrap(), None);
        drop(writer);

        let exact = JournalLimits {
            maximum_transactions: 4,
            ..hold_limits()
        };
        let (mut writer, _) = Journal::open_protected_at_uid(directory.path(), NAME, exact, uid)
            .expect("four-transaction Cache journal");
        writer
            .acquire_cache_policy_hold_for_writer(hold())
            .expect("acquire reserves release and clear");
        let released = writer
            .release_v8_held_cache_policy_hold_for_writer(hold())
            .expect("reserved V8 release");
        let grant = settled_grant(released);
        assert_eq!(
            writer
                .clear_v8_pending_cache_settlement_for_writer(grant)
                .expect("reserved marker clear"),
            released
        );
        assert_eq!(
            writer.cache_policy_hold_for_writer().unwrap(),
            Some(released)
        );
    }

    #[test]
    fn v8_settlement_clears_only_matching_marker_and_replays_after_reopen() {
        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).expect("fresh genesis");
        Journal::acquire_cache_policy_hold_at(directory.path(), uid, hold()).expect("held cut");

        let mut writer = open(directory.path(), uid).expect("retained Cache writer");
        let released = writer
            .release_v8_held_cache_policy_hold_for_writer(hold())
            .expect("atomic V8 release");
        let grant = settled_grant(released);
        let wrong_rows = [
            CachePolicyHoldV1 {
                cache_head: ObjectDigest::from_bytes([9; 32]),
                ..released
            },
            CachePolicyHoldV1 {
                binding: ObjectDigest::from_bytes([9; 32]),
                ..released
            },
            CachePolicyHoldV1 {
                epoch: released.epoch() + 1,
                ..released
            },
        ];
        for wrong in wrong_rows {
            assert!(matches!(
                writer.clear_v8_pending_cache_settlement_for_writer(settled_grant(wrong)),
                Err(JournalError::ProtectedBoundary)
            ));
        }
        assert_eq!(
            writer.v8_pending_cache_policy_release_for_writer().unwrap(),
            (hold(), released)
        );

        assert_eq!(
            writer
                .clear_v8_pending_cache_settlement_for_writer(grant)
                .expect("Root settlement clears Cache fence"),
            released
        );
        assert!(writer.v8_pending_cache_policy_release_for_writer().is_err());
        assert_eq!(
            writer.cache_policy_hold_for_writer().unwrap(),
            Some(released)
        );
        writer.compact().expect("compaction preserves settled row");
        drop(writer);

        let mut reopened = open(directory.path(), uid).expect("cold Cache writer");
        assert_eq!(
            reopened
                .clear_v8_pending_cache_settlement_for_writer(grant)
                .expect("exact cold replay"),
            released
        );
        for wrong in wrong_rows {
            assert!(matches!(
                reopened.clear_v8_pending_cache_settlement_for_writer(settled_grant(wrong)),
                Err(JournalError::ProtectedBoundary)
            ));
        }
        drop(reopened);

        let next = CachePolicyHoldV1::new(
            hold().project(),
            hold().partition(),
            hold().cache_head(),
            ObjectDigest::from_bytes([10; 32]),
            hold().epoch() + 1,
        )
        .expect("next Cache hold");
        Journal::acquire_cache_policy_hold_at(directory.path(), uid, next)
            .expect("settled marker no longer fences next hold");
        let mut next_writer = open(directory.path(), uid).expect("next retained writer");
        assert!(matches!(
            next_writer.clear_v8_pending_cache_settlement_for_writer(grant),
            Err(JournalError::ProtectedBoundary)
        ));
    }

    #[test]
    fn v8_pending_settlement_rejects_orphan_and_mismatched_rows() {
        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).expect("fresh genesis");
        let released = CachePolicyHoldV1 {
            held: false,
            ..hold()
        };
        let pending =
            CachePolicyV8PendingSettlementV1::new(hold(), released).expect("canonical pending row");
        let mut writer = open(directory.path(), uid).expect("Cache writer");
        writer
            .commit(&transaction(V8_PENDING_KEY, &pending.encode()).expect("orphan marker"))
            .expect("fixture orphan commit");
        assert!(matches!(
            current_state(&mut writer),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(matches!(
            writer.compact(),
            Err(JournalError::ProtectedBoundary)
        ));
        drop(writer);
        assert!(matches!(
            Journal::read_cache_policy_hold_at(directory.path(), uid),
            Err(JournalError::ProtectedBoundary)
        ));

        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).expect("fresh genesis");
        Journal::acquire_cache_policy_hold_at(directory.path(), uid, hold()).expect("held cut");
        let mut writer = open(directory.path(), uid).expect("Cache writer");
        writer
            .release_v8_held_cache_policy_hold_for_writer(hold())
            .expect("V8 release");
        let mut changed = pending;
        changed.held_digest = ObjectDigest::from_bytes([9; 32]);
        writer
            .commit(&transaction(V8_PENDING_KEY, &changed.encode()).expect("changed marker"))
            .expect("fixture mismatch commit");
        assert!(matches!(
            current_state(&mut writer),
            Err(JournalError::ProtectedBoundary)
        ));
        drop(writer);
        assert!(matches!(
            Journal::read_v8_pending_cache_policy_release_at(directory.path(), uid),
            Err(JournalError::ProtectedBoundary)
        ));
    }

    #[test]
    fn torn_v8_release_retains_held_row_without_pending_marker() {
        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).expect("fresh genesis");
        Journal::acquire_cache_policy_hold_at(directory.path(), uid, hold()).expect("held cut");
        let path = directory.path().join(NAME);
        let before = fs::metadata(&path).expect("held journal length").len();

        let mut writer = open(directory.path(), uid).expect("Cache writer");
        writer
            .release_v8_held_cache_policy_hold_for_writer(hold())
            .expect("complete V8 release fixture");
        drop(writer);
        let after = fs::metadata(&path).expect("release journal length").len();
        assert!(after > before + 8);
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open fixture journal")
            .set_len(after - 8)
            .expect("tear final commit frame");

        assert_eq!(
            Journal::read_cache_policy_hold_at(directory.path(), uid)
                .expect("replay torn transaction"),
            Some(hold())
        );
        assert!(matches!(
            Journal::read_v8_pending_cache_policy_release_at(directory.path(), uid),
            Err(JournalError::ProtectedBoundary)
        ));
    }

    #[test]
    fn legacy_release_remains_reacquirable_without_v8_marker() {
        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).expect("fresh genesis");
        Journal::acquire_cache_policy_hold_at(directory.path(), uid, hold()).expect("held cut");
        let mut writer = open(directory.path(), uid).expect("Cache writer");
        writer
            .release_held_cache_policy_hold_for_writer(hold())
            .expect("legacy release");
        drop(writer);

        assert!(matches!(
            Journal::read_v8_pending_cache_policy_release_at(directory.path(), uid),
            Err(JournalError::ProtectedBoundary)
        ));
        let next = CachePolicyHoldV1::new(
            hold().project(),
            hold().partition(),
            hold().cache_head(),
            ObjectDigest::from_bytes([9; 32]),
            hold().epoch() + 1,
        )
        .expect("next hold");
        Journal::acquire_cache_policy_hold_at(directory.path(), uid, next)
            .expect("legacy released row permits next hold");
    }

    #[test]
    fn missing_hold_custody_never_reinitializes_existing_cache() {
        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).expect("fresh genesis");
        let mut state = open_gated(directory.path(), uid, "state.journal");
        state.commit(&put(20)).expect("Cache history");
        drop(state);
        fs::remove_file(directory.path().join(NAME)).expect("remove fixture hold");

        assert!(matches!(
            initialize_fresh(directory.path(), uid),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(matches!(
            open_gated(directory.path(), uid, "state.journal").commit(&put(21)),
            Err(JournalError::ProtectedBoundary)
        ));
    }

    #[test]
    fn malformed_hold_custody_fails_before_any_cache_mutation() {
        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).expect("fresh genesis");
        let mut state = open_gated(directory.path(), uid, "state.journal");
        let mut hold_journal = open(directory.path(), uid).expect("hold journal");
        hold_journal
            .commit(&transaction(HOLD_KEY, b"invalid").expect("malformed transaction"))
            .expect("fixture corruption");
        drop(hold_journal);

        assert!(matches!(
            state.commit(&put(22)),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(matches!(
            initialize_fresh(directory.path(), uid),
            Err(JournalError::ProtectedBoundary)
        ));
    }

    #[test]
    fn cache_commit_waits_for_the_same_lock_used_by_freeze() {
        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).expect("fresh genesis");
        let mut state = open_gated(directory.path(), uid, "state.journal");
        let hold_writer = open(directory.path(), uid).expect("held freeze lock");

        assert!(matches!(
            state.commit(&put(30)),
            Err(JournalError::AlreadyLocked)
        ));
        drop(hold_writer);
        state
            .commit(&put(30))
            .expect("commit after freeze lock release");
    }
}
