//! Source-domain-wide custody for one closed policy-binding proposal.
//!
//! ```text
//! AOSSDH01 | version=1 | phase=held|released | reserved[5]=0 |
//! operation[16] | sandbox[16] | controller-source[32] | ancestry[32] |
//! binding[32] | epoch[8] | SHA-256[32]
//! ```
//!
//! V8 retirement also retains a fixed pending-settlement record:
//!
//! ```text
//! AOSSDP08 | version=1 | phase=pending | reserved[5]=0 |
//! binding[32] | epoch[8] | SHA-256(held AOSSDH01)[32] |
//! SHA-256(released AOSSDH01)[32] | SHA-256[32]
//! ```
//!
//! The one protected source-domain journal owns hierarchy, environment, Git,
//! and lifecycle records. This hold freezes all of their writes after process
//! death; the V8 pending marker preserves that freeze until Root settlement.
//! Neither record grants publication or effect authority.

use std::collections::BTreeMap;

use aos_sandbox_core::{ObjectDigest, OperationId, SandboxId};
use sha2::{Digest as _, Sha256};

use super::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};

#[cfg(target_os = "linux")]
use crate::policy_compiler::create_q04::{
    Q04CutIdentityV1, Q04PendingOwnerV1, Q04PendingRecordV1, Q04TransactionOwnerV1,
    SOURCE_PENDING_KEY,
};

const KEY: &[u8] = b"\0aos-source-domain-policy-hold-v1\0";
const V8_PENDING_KEY: &[u8] = b"\0aos-source-domain-policy-v8-pending-settlement-v1\0";
const MAGIC: &[u8; 8] = b"AOSSDH01";
const V8_PENDING_MAGIC: &[u8; 8] = b"AOSSDP08";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.source-domain-policy-hold.v1\0";
const V8_PENDING_CHECKSUM_DOMAIN: &[u8] =
    b"aos.sandbox.source-domain-policy-v8-pending-settlement.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.source-domain-policy-hold-transaction.v1\0";
const V8_PENDING_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.source-domain-policy-v8-retirement-transaction.v1\0";
const V8_CLEAR_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.source-domain-policy-v8-settlement-clear-transaction.v1\0";
const RECORD_BYTES: usize = 184;
const V8_PENDING_RECORD_BYTES: usize = 152;
const JOURNAL_NAME: &str = "source-domains-v1.journal";

/// Identifies one exact, nonauthorizing source-domain policy hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceDomainPolicyHoldV1 {
    operation: OperationId,
    sandbox: SandboxId,
    controller_source: ObjectDigest,
    ancestry: ObjectDigest,
    binding: ObjectDigest,
    epoch: u64,
    held: bool,
}

impl SourceDomainPolicyHoldV1 {
    /// Constructs custody for the exact ancestry used in a closed proposal.
    ///
    /// # Errors
    ///
    /// Rejects a zero identity, commitment, or epoch.
    pub fn new(
        operation: OperationId,
        sandbox: SandboxId,
        controller_source: ObjectDigest,
        ancestry: ObjectDigest,
        binding: ObjectDigest,
        epoch: u64,
    ) -> Result<Self, JournalError> {
        let hold = Self {
            operation,
            sandbox,
            controller_source,
            ancestry,
            binding,
            epoch,
            held: true,
        };
        hold.validate()?;
        Ok(hold)
    }

    /// Returns the accepted Create operation fixed by this hold.
    #[must_use]
    pub const fn operation(self) -> OperationId {
        self.operation
    }

    /// Returns the accepted Create sandbox fixed by this hold.
    #[must_use]
    pub const fn sandbox(self) -> SandboxId {
        self.sandbox
    }

    /// Returns the Controller source commitment observed under its writer.
    #[must_use]
    pub const fn controller_source(self) -> ObjectDigest {
        self.controller_source
    }

    /// Returns the exact hierarchy ancestry head held for this Create.
    #[must_use]
    pub const fn ancestry(self) -> ObjectDigest {
        self.ancestry
    }

    /// Returns the root binding digest fixed before Q04 submission.
    #[must_use]
    pub const fn binding(self) -> ObjectDigest {
        self.binding
    }

    /// Returns the root handoff epoch fixed before Q04 submission.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Reports whether source-domain writers remain frozen.
    #[must_use]
    pub const fn is_held(self) -> bool {
        self.held
    }

    /// Returns the digest of the exact canonical held or released record.
    ///
    /// # Errors
    ///
    /// Rejects an invalid Source hold.
    pub fn record_digest(self) -> Result<ObjectDigest, JournalError> {
        Ok(ObjectDigest::from_bytes(
            Sha256::digest(self.encode()?).into(),
        ))
    }

    // This reuses the sole record encoder for equality DATA. It supplies no
    // Source writer, observed release, settlement permission or authority.
    #[cfg(target_os = "linux")]
    pub(crate) fn q04_released_record_digest(self) -> Result<ObjectDigest, JournalError> {
        Self { held: false, ..self }.record_digest()
    }

    fn validate(self) -> Result<(), JournalError> {
        if self.operation.as_bytes() == &[0; 16]
            || self.sandbox.as_bytes() == &[0; 16]
            || self.controller_source.as_bytes() == &[0; 32]
            || self.ancestry.as_bytes() == &[0; 32]
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
        bytes[16..32].copy_from_slice(self.operation.as_bytes());
        bytes[32..48].copy_from_slice(self.sandbox.as_bytes());
        bytes[48..80].copy_from_slice(self.controller_source.as_bytes());
        bytes[80..112].copy_from_slice(self.ancestry.as_bytes());
        bytes[112..144].copy_from_slice(self.binding.as_bytes());
        bytes[144..152].copy_from_slice(&self.epoch.to_be_bytes());
        let checksum = Sha256::new()
            .chain_update(CHECKSUM_DOMAIN)
            .chain_update(&bytes[..152])
            .finalize();
        bytes[152..].copy_from_slice(&checksum);
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
            operation: OperationId::from_bytes(
                bytes[16..32]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            sandbox: SandboxId::from_bytes(
                bytes[32..48]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            controller_source: ObjectDigest::from_bytes(
                bytes[48..80]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            ancestry: ObjectDigest::from_bytes(
                bytes[80..112]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            binding: ObjectDigest::from_bytes(
                bytes[112..144]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            epoch: u64::from_be_bytes(
                bytes[144..152]
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

/// Retains exact V8 Source release evidence until Root successor settlement.
///
/// This owner-local marker is not a Controller or Root release authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceDomainPolicyV8PendingSettlementV1 {
    binding: ObjectDigest,
    epoch: u64,
    held_record: ObjectDigest,
    released_record: ObjectDigest,
}

impl SourceDomainPolicyV8PendingSettlementV1 {
    fn new(expected: SourceDomainPolicyHoldV1) -> Result<Self, JournalError> {
        if !expected.is_held() {
            return Err(JournalError::ProtectedBoundary);
        }
        let released = SourceDomainPolicyHoldV1 {
            held: false,
            ..expected
        };
        Ok(Self {
            binding: expected.binding(),
            epoch: expected.epoch(),
            held_record: expected.record_digest()?,
            released_record: released.record_digest()?,
        })
    }

    /// Returns the binding whose released Source record remains protected.
    #[must_use]
    pub const fn binding(self) -> ObjectDigest {
        self.binding
    }

    /// Returns the protected binding's handoff epoch.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Returns the digest of the canonical prior held Source record.
    #[must_use]
    pub const fn held_record_digest(self) -> ObjectDigest {
        self.held_record
    }

    /// Returns the digest of the canonical released Source record.
    #[must_use]
    pub const fn released_record_digest(self) -> ObjectDigest {
        self.released_record
    }

    fn matches_released(self, released: SourceDomainPolicyHoldV1) -> Result<bool, JournalError> {
        if released.is_held()
            || self.binding != released.binding()
            || self.epoch != released.epoch()
        {
            return Ok(false);
        }
        let held = SourceDomainPolicyHoldV1 {
            held: true,
            ..released
        };
        Ok(self.held_record == held.record_digest()?
            && self.released_record == released.record_digest()?)
    }

    fn encode(self) -> Result<[u8; V8_PENDING_RECORD_BYTES], JournalError> {
        if self.binding.as_bytes() == &[0; 32]
            || self.epoch == 0
            || self.held_record.as_bytes() == &[0; 32]
            || self.released_record.as_bytes() == &[0; 32]
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let mut bytes = [0; V8_PENDING_RECORD_BYTES];
        bytes[..8].copy_from_slice(V8_PENDING_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = 1;
        bytes[16..48].copy_from_slice(self.binding.as_bytes());
        bytes[48..56].copy_from_slice(&self.epoch.to_be_bytes());
        bytes[56..88].copy_from_slice(self.held_record.as_bytes());
        bytes[88..120].copy_from_slice(self.released_record.as_bytes());
        let checksum = Sha256::new()
            .chain_update(V8_PENDING_CHECKSUM_DOMAIN)
            .chain_update(&bytes[..120])
            .finalize();
        bytes[120..].copy_from_slice(&checksum);
        Ok(bytes)
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
        let marker = Self {
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
            held_record: ObjectDigest::from_bytes(
                bytes[56..88]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            released_record: ObjectDigest::from_bytes(
                bytes[88..120]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
        };
        if marker.encode()?.as_slice() != bytes {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(marker)
    }
}

fn current(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<SourceDomainPolicyHoldV1>, JournalError> {
    current_state(state).map(|readback| readback.hold)
}

fn current_with_v8_pending(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<
    (
        Option<SourceDomainPolicyHoldV1>,
        Option<SourceDomainPolicyV8PendingSettlementV1>,
    ),
    JournalError,
> {
    let readback = current_state(state)?;
    #[cfg(target_os = "linux")]
    if readback.q04_pending.is_some() {
        // A Q04 marker is never interpreted as a legacy/V8 release proof.
        return Err(JournalError::ProtectedBoundary);
    }
    Ok((readback.hold, readback.v8_pending))
}

struct SourceDomainPolicyHoldStateV1 {
    hold: Option<SourceDomainPolicyHoldV1>,
    v8_pending: Option<SourceDomainPolicyV8PendingSettlementV1>,
    #[cfg(target_os = "linux")]
    q04_pending: Option<Q04PendingRecordV1>,
}

fn current_state(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<SourceDomainPolicyHoldStateV1, JournalError> {
    let mut records = state
        .range((RecordNamespace::SourceDomainPolicyHold, Vec::new())..)
        .take_while(|((namespace, _), _)| *namespace == RecordNamespace::SourceDomainPolicyHold);
    let mut hold = None;
    let mut pending = None;
    #[cfg(target_os = "linux")]
    let mut q04_pending = None;
    for ((_, key), value) in &mut records {
        match key.as_slice() {
            KEY if hold.is_none() => hold = Some(SourceDomainPolicyHoldV1::decode(value)?),
            V8_PENDING_KEY if pending.is_none() => {
                pending = Some(SourceDomainPolicyV8PendingSettlementV1::decode(value)?)
            }
            #[cfg(target_os = "linux")]
            SOURCE_PENDING_KEY if q04_pending.is_none() => {
                q04_pending = Some(Q04PendingRecordV1::decode(Q04PendingOwnerV1::Source, value)?);
            }
            _ => return Err(JournalError::ProtectedBoundary),
        }
    }
    if let Some(marker) = pending {
        match hold {
            Some(released) if marker.matches_released(released)? => {}
            _ => return Err(JournalError::ProtectedBoundary),
        }
    }
    #[cfg(target_os = "linux")]
    if let Some(marker) = &q04_pending {
        let row = hold.ok_or(JournalError::ProtectedBoundary)?;
        if pending.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        require_q04_marker_row(marker, row)?;
    }
    Ok(SourceDomainPolicyHoldStateV1 {
        hold,
        v8_pending: pending,
        #[cfg(target_os = "linux")]
        q04_pending,
    })
}

#[cfg(target_os = "linux")]
fn require_q04_marker_row(
    marker: &Q04PendingRecordV1,
    row: SourceDomainPolicyHoldV1,
) -> Result<(), JournalError> {
    let held = SourceDomainPolicyHoldV1 { held: true, ..row };
    let released = SourceDomainPolicyHoldV1 { held: false, ..row };
    if marker.is_held() != row.is_held()
        || marker.bytes()[64..96] != *row.binding().as_bytes()
        || marker.bytes()[96..104] != row.epoch().to_be_bytes()
        || marker.bytes()[104..136] != *held.record_digest()?.as_bytes()
        || marker.bytes()[136..168] != *released.record_digest()?.as_bytes()
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

pub(super) fn require_no_mutation(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    let readback = current_state(state)?;
    #[cfg(target_os = "linux")]
    if readback.q04_pending.is_some() {
        return Err(JournalError::ProtectedBoundary);
    }
    if readback.hold.is_some_and(SourceDomainPolicyHoldV1::is_held)
        || readback.v8_pending.is_some()
        || transaction
            .records()
            .iter()
            .any(|record| record.namespace() == RecordNamespace::SourceDomainPolicyHold)
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn require_q04_ordinary_boundary(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    // Old private hold/V8 flags do not waive this new purpose. Its marker
    // freezes all Source writes until the exact retained transition clears it.
    let writes_marker = transaction.records().iter().any(|record| {
            record.namespace() == RecordNamespace::SourceDomainPolicyHold
                && record.key() == SOURCE_PENDING_KEY
        });
    let has_marker = state.keys().any(|(namespace, key)| {
        *namespace == RecordNamespace::SourceDomainPolicyHold && key == SOURCE_PENDING_KEY
    });
    if !has_marker
        && !writes_marker
    {
        // No new-purpose byte means no additional legacy parse or reordered
        // ordinary error. The existing validators retain their old positions.
        return Ok(());
    }
    current_state(state)?;
    Err(JournalError::ProtectedBoundary)
}

// These are inert complete transaction recipes, not a Source writer lease or
// a Root release proof. The installed coordinator retains the real owner and
// repeats its gen1/native/named/clock joins before selecting any append.
#[cfg(target_os = "linux")]
pub(crate) struct SourceQ04TransactionRecipesV1<'cut> {
    identity: &'cut Q04CutIdentityV1,
    names: super::ProtectedJournalNamesV1,
    original_next: u64,
    release_authorization: Option<ObjectDigest>,
    prior: Option<SourceDomainPolicyHoldV1>,
    held: SourceDomainPolicyHoldV1,
    held_marker: Q04PendingRecordV1,
    released_marker: Q04PendingRecordV1,
    transactions: [JournalTransaction; 3],
}

#[cfg(target_os = "linux")]
impl<'cut> SourceQ04TransactionRecipesV1<'cut> {
    pub(crate) fn capture(
        source: &mut crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1,
        ledger: &crate::reconciler::OriginalQ04ControllerLedgerV1,
        identity: &'cut Q04CutIdentityV1,
    ) -> Result<Self, crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        use crate::policy_compiler::create_q04::CreateQ04ErrorV1;

        ledger.require_identity(identity)?;
        source.require_fixed_named_writer_v1()?;
        if source.journal().protected_owner_uid()? != identity.source_uid() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let before = current_state(&source.journal().state)?;
        if before.hold.is_some_and(SourceDomainPolicyHoldV1::is_held)
            || before.v8_pending.is_some()
            || before.q04_pending.is_some()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let names = source.fixed_physical_names_v1()?;
        let original_next = source.journal().snapshot_sequence();
        let held = SourceDomainPolicyHoldV1::new(
            identity.operation(),
            identity.sandbox(),
            ledger.source_commitment(),
            identity.ancestry(),
            identity.binding(),
            identity.epoch(),
        )?;
        // Only uncommitted release/clear shapes use this nonissuing value.
        // Acquisition bytes do not depend on a future Root response.
        let bodies = q04_hold_recipe_bodies(
            identity, names, held,
            crate::policy_compiler::create_q04::lower_release_capacity_shape(identity),
        )?;
        source.require_fixed_named_writer_v1()?;
        if source.fixed_physical_names_v1()? != names {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        Ok(Self {
            identity,
            names,
            original_next,
            release_authorization: None,
            prior: before.hold,
            held,
            held_marker: bodies.held_marker,
            released_marker: bodies.released_marker,
            transactions: bodies.transactions,
        })
    }

    pub(crate) fn transactions(&self) -> &[JournalTransaction; 3] {
        &self.transactions
    }

    pub(crate) fn identity(&self) -> &Q04CutIdentityV1 {
        self.identity
    }

    pub(crate) fn original_next(&self) -> u64 {
        self.original_next
    }

    pub(crate) fn release_authorization(&self) -> Option<ObjectDigest> {
        self.release_authorization
    }

    pub(crate) fn terminal_pair_data(
        &self,
    ) -> Result<[ObjectDigest; 2], crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        Ok([self.held.record_digest()?, self.held.q04_released_record_digest()?])
    }

    pub(crate) fn bind_observed_release(
        &mut self,
        source: &mut crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1,
        root: &crate::policy_compiler::create_q04::OriginalQ04RootCacheLoanV1<'_, '_, '_>,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        use crate::policy_compiler::create_q04::CreateQ04ErrorV1;

        if self.release_authorization.is_some() || !std::ptr::eq(self.identity, root.identity()) {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let release = root.release_phase()?.digest();
        root.require_lower_transition(1, Some(release))?;
        self.require_named_owner(source)?;
        self.require_prefix(&source.journal().state, 1)?;
        source.journal().require_q04_native_recipe_prefix_v1(
            &self.transactions[..1], self.original_next,
        )?;
        let bodies = q04_hold_recipe_bodies(self.identity, self.names, self.held, release)?;
        if bodies.held_marker != self.held_marker || bodies.transactions[0] != self.transactions[0] {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.released_marker = bodies.released_marker;
        self.transactions = bodies.transactions;
        self.release_authorization = Some(release);
        source.journal().preflight_source_q04_remaining_v1(self, 1)?;
        self.require_named_owner(source)?;
        root.require_lower_transition(1, Some(release))
    }

    pub(crate) fn clear_recipe_digest(
        &self,
    ) -> Result<ObjectDigest, crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        if self.release_authorization.is_none() {
            return Err(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut);
        }
        super::q04_lower_clear_native_digest_v1(
            self.identity, Q04TransactionOwnerV1::Source, self.names,
            self.original_next.checked_add(8).ok_or(JournalError::SequenceExhausted)?,
            &self.transactions[2],
        )
    }

    pub(crate) fn require_fixed_journal(&self, journal: &Journal) -> Result<(), JournalError> {
        journal.require_protected_named_location(
            std::path::Path::new(crate::lifecycle::protected_journal_join::PROTECTED_SOURCE_DOMAIN_ROOT),
            JOURNAL_NAME,
            self.identity.source_uid(),
            crate::lifecycle::protected_journal_join::source_domain_journal_limits(),
        )?;
        if journal.protected_writer_physical_names_v1()? != self.names {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn require_named_owner(
        &self,
        source: &mut crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), JournalError> {
        source.require_fixed_named_writer_v1()?;
        if source.journal().protected_owner_uid()? != self.identity.source_uid()
            || source.fixed_physical_names_v1()? != self.names
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn require_prefix(
        &self,
        state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        committed: usize,
    ) -> Result<(), JournalError> {
        let readback = current_state(state)?;
        if readback.v8_pending.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        let released = SourceDomainPolicyHoldV1 { held: false, ..self.held };
        let matches = match committed {
            0 => readback.hold == self.prior && readback.q04_pending.is_none(),
            1 => readback.hold == Some(self.held)
                && readback.q04_pending.as_ref() == Some(&self.held_marker),
            2 => readback.hold == Some(released)
                && readback.q04_pending.as_ref() == Some(&self.released_marker),
            3 => readback.hold == Some(released) && readback.q04_pending.is_none(),
            _ => false,
        };
        if !matches {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
struct Q04SourceHoldRecipeBodiesV1 {
    held_marker: Q04PendingRecordV1,
    released_marker: Q04PendingRecordV1,
    transactions: [JournalTransaction; 3],
}

// This is the sole Source Q04 record/transaction recipe. Root calls the same
// DATA builder only after authenticating the original fields independently.
#[cfg(target_os = "linux")]
fn q04_hold_recipe_bodies(
    identity: &Q04CutIdentityV1,
    names: super::ProtectedJournalNamesV1,
    held: SourceDomainPolicyHoldV1,
    release_authorization: ObjectDigest,
) -> Result<Q04SourceHoldRecipeBodiesV1, crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
    use crate::policy_compiler::create_q04::{CreateQ04ErrorV1, PENDING_BYTES};

    if !held.is_held() || held.operation() != identity.operation()
        || held.sandbox() != identity.sandbox() || held.binding() != identity.binding()
        || held.epoch() != identity.epoch() || held.ancestry() != identity.ancestry()
        || release_authorization.as_bytes() == &[0; 32]
    {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    let released = SourceDomainPolicyHoldV1 { held: false, ..held };
    let owner_recipe = ObjectDigest::from_bytes(Sha256::new()
        .chain_update(b"aos.sandbox.create-q04.source-before-owner-recipe.v1\0")
        .chain_update(names.to_bytes())
        .chain_update(held.encode()?)
        .chain_update(released.encode()?)
        .finalize().into());
    let mut body = [0; PENDING_BYTES];
    body[16..48].copy_from_slice(identity.digest().as_bytes());
    body[48..64].copy_from_slice(&identity.nonce());
    body[64..96].copy_from_slice(identity.binding().as_bytes());
    body[96..104].copy_from_slice(&identity.epoch().to_be_bytes());
    body[104..136].copy_from_slice(held.record_digest()?.as_bytes());
    body[136..168].copy_from_slice(released.record_digest()?.as_bytes());
    body[200..232].copy_from_slice(owner_recipe.as_bytes());
    let held_marker = Q04PendingRecordV1::from_body(Q04PendingOwnerV1::Source, 1, body)?;
    body[168..200].copy_from_slice(release_authorization.as_bytes());
    let released_marker = Q04PendingRecordV1::from_body(Q04PendingOwnerV1::Source, 2, body)?;
    released_marker.require_release_of(&held_marker)?;

    let acquire = q04_transaction(identity, 1, owner_recipe, vec![
        JournalRecord::put(RecordNamespace::SourceDomainPolicyHold, KEY.to_vec(), held.encode()?.to_vec()),
        JournalRecord::put(RecordNamespace::SourceDomainPolicyHold, SOURCE_PENDING_KEY.to_vec(), held_marker.bytes().to_vec()),
    ])?;
    let release = q04_transaction(identity, 2, held_marker.digest(), vec![
        JournalRecord::put(RecordNamespace::SourceDomainPolicyHold, KEY.to_vec(), released.encode()?.to_vec()),
        JournalRecord::put(RecordNamespace::SourceDomainPolicyHold, SOURCE_PENDING_KEY.to_vec(), released_marker.bytes().to_vec()),
    ])?;
    let clear = q04_transaction(identity, 3, released_marker.digest(), vec![
        JournalRecord::delete(RecordNamespace::SourceDomainPolicyHold, SOURCE_PENDING_KEY.to_vec()),
    ])?;
    Ok(Q04SourceHoldRecipeBodiesV1 {
        held_marker, released_marker, transactions: [acquire, release, clear],
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn q04_clear_recipe_digest_data(
    identity: &Q04CutIdentityV1,
    names: super::ProtectedJournalNamesV1,
    original_next: u64,
    held: SourceDomainPolicyHoldV1,
    release_authorization: ObjectDigest,
) -> Result<ObjectDigest, crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
    let bodies = q04_hold_recipe_bodies(identity, names, held, release_authorization)?;
    super::q04_lower_clear_native_digest_v1(
        identity, Q04TransactionOwnerV1::Source, names,
        original_next.checked_add(8).ok_or(JournalError::SequenceExhausted)?,
        &bodies.transactions[2],
    )
}

#[cfg(target_os = "linux")]
pub(super) fn require_q04_transition(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    recipes: &SourceQ04TransactionRecipesV1<'_>,
    index: usize,
) -> Result<(), JournalError> {
    if recipes.transactions().get(index) != Some(transaction) {
        return Err(JournalError::ProtectedBoundary);
    }
    recipes.require_prefix(state, index)
}

#[cfg(target_os = "linux")]
fn q04_transaction(
    identity: &Q04CutIdentityV1,
    phase: u8,
    predecessor: ObjectDigest,
    records: Vec<JournalRecord>,
) -> Result<JournalTransaction, JournalError> {
    JournalTransaction::new(
        Q04TransactionOwnerV1::Source.transaction_id(identity, phase, predecessor)?,
        records,
    )
}

pub(super) fn require_no_compaction(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<(), JournalError> {
    // The typed parser validates the released row and marker together before
    // generic compaction materializes every current record.
    let readback = current_state(state)?;
    #[cfg(target_os = "linux")]
    if readback.q04_pending.is_some() {
        return Err(JournalError::ProtectedBoundary);
    }
    if readback.hold.is_some_and(SourceDomainPolicyHoldV1::is_held) {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn transaction(hold: SourceDomainPolicyHoldV1) -> Result<JournalTransaction, JournalError> {
    let bytes = hold.encode()?;
    let digest = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(bytes)
        .finalize();
    let id: [u8; 16] = digest[..16]
        .try_into()
        .map_err(|_| JournalError::ProtectedBoundary)?;
    JournalTransaction::new(
        id,
        vec![JournalRecord::put(
            RecordNamespace::SourceDomainPolicyHold,
            KEY.to_vec(),
            bytes.to_vec(),
        )],
    )
}

pub(super) fn release_transaction(
    expected: SourceDomainPolicyHoldV1,
) -> Result<JournalTransaction, JournalError> {
    if !expected.is_held() {
        return Err(JournalError::ProtectedBoundary);
    }
    transaction(SourceDomainPolicyHoldV1 {
        held: false,
        ..expected
    })
}

fn v8_retirement_transaction(
    expected: SourceDomainPolicyHoldV1,
) -> Result<JournalTransaction, JournalError> {
    let marker = SourceDomainPolicyV8PendingSettlementV1::new(expected)?;
    let released = SourceDomainPolicyHoldV1 {
        held: false,
        ..expected
    };
    let released_bytes = released.encode()?;
    let marker_bytes = marker.encode()?;
    let digest = Sha256::new()
        .chain_update(V8_PENDING_TRANSACTION_DOMAIN)
        .chain_update(released_bytes)
        .chain_update(marker_bytes)
        .finalize();
    let id: [u8; 16] = digest[..16]
        .try_into()
        .map_err(|_| JournalError::ProtectedBoundary)?;
    JournalTransaction::new(
        id,
        vec![
            JournalRecord::put(
                RecordNamespace::SourceDomainPolicyHold,
                KEY.to_vec(),
                released_bytes.to_vec(),
            ),
            JournalRecord::put(
                RecordNamespace::SourceDomainPolicyHold,
                V8_PENDING_KEY.to_vec(),
                marker_bytes.to_vec(),
            ),
        ],
    )
}

fn v8_clear_transaction(
    released: SourceDomainPolicyHoldV1,
) -> Result<JournalTransaction, JournalError> {
    if released.is_held() {
        return Err(JournalError::ProtectedBoundary);
    }
    let held = SourceDomainPolicyHoldV1 {
        held: true,
        ..released
    };
    let marker = SourceDomainPolicyV8PendingSettlementV1::new(held)?;
    let digest = Sha256::new()
        .chain_update(V8_CLEAR_TRANSACTION_DOMAIN)
        .chain_update(released.encode()?)
        .chain_update(marker.encode()?)
        .finalize();
    let id: [u8; 16] = digest[..16]
        .try_into()
        .map_err(|_| JournalError::ProtectedBoundary)?;
    JournalTransaction::new(
        id,
        vec![JournalRecord::delete(
            RecordNamespace::SourceDomainPolicyHold,
            V8_PENDING_KEY.to_vec(),
        )],
    )
}

pub(super) fn v8_retirement_and_clear_transactions(
    held: SourceDomainPolicyHoldV1,
) -> Result<[JournalTransaction; 2], JournalError> {
    Ok([
        v8_retirement_transaction(held)?,
        v8_clear_transaction(SourceDomainPolicyHoldV1 {
            held: false,
            ..held
        })?,
    ])
}

pub(super) fn ensure_source_domain(journal: &Journal) -> Result<(), JournalError> {
    journal.ensure_protected_authority()?;
    if journal
        .protected
        .as_ref()
        .map(|location| location.name.as_str())
        != Some(JOURNAL_NAME)
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

impl Journal {
    /// Durably freezes the fixed source-domain writer before Q04 submission.
    ///
    /// The exact held record survives transport loss or process death. Its
    /// release needs privileged root cold readback and a held Controller writer.
    ///
    /// # Errors
    ///
    /// Rejects non-source storage, an existing hold, a non-held candidate,
    /// invalid fields, or insufficient capacity for eventual exact release.
    pub(crate) fn acquire_source_domain_policy_hold_v1(
        &mut self,
        hold: SourceDomainPolicyHoldV1,
    ) -> Result<(), JournalError> {
        ensure_source_domain(self)?;
        let (current_hold, pending) = current_with_v8_pending(self.native.state())?;
        if !hold.held
            || current_hold.is_some_and(SourceDomainPolicyHoldV1::is_held)
            || pending.is_some()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let acquire = transaction(hold)?;
        let legacy_release = release_transaction(hold)?;
        let [v8_release, v8_clear] = v8_retirement_and_clear_transactions(hold)?;
        // No ordinary source-domain commit can race after acquisition.
        self.preflight_transactions_with_capacity_scope(
            &[acquire.clone(), legacy_release],
            None,
            false,
            true,
        )?;
        self.preflight_transactions_with_capacity_scope(
            &[acquire.clone(), v8_release, v8_clear],
            None,
            false,
            true,
        )?;
        self.commit_with_capacity_scope(&acquire, None, false, true, false, false, false)?;
        if current(self.native.state())? != Some(hold) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Reads exact source-domain custody under its protected writer.
    ///
    /// # Errors
    ///
    /// Rejects non-source storage or malformed custody.
    pub(crate) fn source_domain_policy_hold_v1(
        &self,
    ) -> Result<Option<SourceDomainPolicyHoldV1>, JournalError> {
        ensure_source_domain(self)?;
        current(self.native.state())
    }

    /// Reads the V8 pending marker under the retained protected Source writer.
    ///
    /// # Errors
    ///
    /// Rejects non-Source storage or an orphan, mismatched, or malformed marker.
    pub(crate) fn source_domain_policy_v8_pending_settlement_v1(
        &self,
    ) -> Result<Option<SourceDomainPolicyV8PendingSettlementV1>, JournalError> {
        ensure_source_domain(self)?;
        current_with_v8_pending(self.native.state()).map(|(_, pending)| pending)
    }

    /// Reads the marker-anchored held predecessor and current released row.
    ///
    /// # Errors
    ///
    /// Rejects foreign custody or a missing, malformed, or mismatched V8 marker.
    pub(crate) fn source_domain_policy_v8_release_pair_v1(
        &self,
    ) -> Result<(SourceDomainPolicyHoldV1, SourceDomainPolicyHoldV1), JournalError> {
        ensure_source_domain(self)?;
        let (Some(released), Some(_)) = current_with_v8_pending(self.native.state())? else {
            return Err(JournalError::ProtectedBoundary);
        };
        let held = SourceDomainPolicyHoldV1 {
            held: true,
            ..released
        };
        Ok((held, released))
    }

    pub(crate) fn release_source_domain_policy_hold_after_root_readback_v1(
        &mut self,
        expected: SourceDomainPolicyHoldV1,
    ) -> Result<(), JournalError> {
        ensure_source_domain(self)?;
        if !expected.held || current(self.native.state())? != Some(expected) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.commit_released_source_domain_policy_hold(expected)
    }

    /// Records an exact V8 Source release after higher-level owner verification.
    ///
    /// This journal transition does not verify Root or Cache release. It must
    /// remain unreachable from public Create until a held cross-owner caller
    /// supplies that evidence. An exact cold replay is idempotent so a lost
    /// response after durable sync cannot strand the Source writer.
    ///
    /// # Errors
    ///
    /// Rejects non-source custody, a non-held expected record, a different
    /// current hold, or failed durable release and readback.
    pub(crate) fn retire_source_domain_policy_hold_v8(
        &mut self,
        expected: SourceDomainPolicyHoldV1,
    ) -> Result<(), JournalError> {
        ensure_source_domain(self)?;
        if !expected.held {
            return Err(JournalError::ProtectedBoundary);
        }
        let released = SourceDomainPolicyHoldV1 {
            held: false,
            ..expected
        };

        let marker = SourceDomainPolicyV8PendingSettlementV1::new(expected)?;
        match current_with_v8_pending(self.native.state())? {
            (Some(current), None) if current == expected => {
                self.commit_with_capacity_scope(
                    &v8_retirement_transaction(expected)?,
                    None,
                    false,
                    true,
                    false,
                    false,
                    false,
                )?;
                if current_with_v8_pending(self.native.state())? != (Some(released), Some(marker)) {
                    return Err(JournalError::ProtectedBoundary);
                }
                Ok(())
            }
            (Some(current), Some(current_marker))
                if current == released && current_marker == marker =>
            {
                Ok(())
            }
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    /// Clears only the pending V8 marker after the caller verifies Root
    /// settlement and Cache clearance under the retained owner writers.
    ///
    /// Exact replay may observe an absent marker after an ambiguous commit.
    /// The caller must still supply the same authenticated Root grant and
    /// Cache-clear proof; this local journal row grants neither authority.
    ///
    /// # Errors
    ///
    /// Rejects changed Source custody, malformed release evidence, or failed
    /// durable deletion and readback.
    pub(crate) fn clear_source_domain_policy_v8_pending_settlement_v1(
        &mut self,
        expected_released: SourceDomainPolicyHoldV1,
    ) -> Result<(), JournalError> {
        ensure_source_domain(self)?;
        if expected_released.is_held() {
            return Err(JournalError::ProtectedBoundary);
        }
        match current_with_v8_pending(self.native.state())? {
            (Some(current), Some(_)) if current == expected_released => {
                self.commit_with_capacity_scope(
                    &v8_clear_transaction(expected_released)?,
                    None,
                    false,
                    true,
                    false,
                    false,
                    false,
                )?;
            }
            (Some(current), None) if current == expected_released => {}
            _ => return Err(JournalError::ProtectedBoundary),
        }
        if current_with_v8_pending(self.native.state())? != (Some(expected_released), None) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    fn commit_released_source_domain_policy_hold(
        &mut self,
        expected: SourceDomainPolicyHoldV1,
    ) -> Result<(), JournalError> {
        let released = SourceDomainPolicyHoldV1 {
            held: false,
            ..expected
        };
        self.commit_with_capacity_scope(
            &release_transaction(expected)?,
            None,
            false,
            true,
            false,
            false,
            false,
        )?;
        if current(self.native.state())? != Some(released) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::PathBuf;

    use super::*;
    use crate::hierarchy::protected_journal::HierarchyProtectedJournalOwnerV1;
    use crate::journal::JournalLimits;
    use crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "aos-source-domain-policy-hold-{}-{}",
                std::process::id(),
                OperationId::new()
            ));
            fs::create_dir(&path).expect("test directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("protected directory mode");
            Self(path)
        }

        fn open(&self) -> Journal {
            let uid = fs::metadata(&self.0).expect("directory metadata").uid();
            Journal::open_protected_at_uid(&self.0, JOURNAL_NAME, JournalLimits::default(), uid)
                .expect("protected source-domain reopen")
                .0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn hold() -> SourceDomainPolicyHoldV1 {
        SourceDomainPolicyHoldV1::new(
            OperationId::from_bytes([1; 16]),
            SandboxId::from_bytes([2; 16]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
            ObjectDigest::from_bytes([5; 32]),
            7,
        )
        .expect("valid source-domain hold")
    }

    fn ordinary_transaction(namespace: RecordNamespace, id: u8) -> JournalTransaction {
        JournalTransaction::new(
            [id; 16],
            vec![JournalRecord::put(
                namespace,
                b"ordinary".to_vec(),
                b"value".to_vec(),
            )],
        )
        .expect("ordinary transaction")
    }

    #[test]
    fn lost_reply_freezes_all_source_domain_writers_after_reopen() {
        let directory = TestDirectory::new();
        let mut source_domains = directory.open();
        let expected = hold();
        assert!(
            source_domains
                .acquire_source_domain_policy_hold_v1(SourceDomainPolicyHoldV1 {
                    held: false,
                    ..expected
                })
                .is_err()
        );
        source_domains
            .acquire_source_domain_policy_hold_v1(expected)
            .expect("durable source-domain hold before root submit");
        drop(source_domains);

        let mut reopened = directory.open();
        assert_eq!(
            reopened.source_domain_policy_hold_v1().unwrap(),
            Some(expected)
        );
        for (index, namespace) in [
            RecordNamespace::DesiredState,
            RecordNamespace::Operation,
            RecordNamespace::Effect,
            RecordNamespace::PublisherPolicy,
        ]
        .into_iter()
        .enumerate()
        {
            let transaction = ordinary_transaction(namespace, index as u8 + 10);
            assert!(matches!(
                reopened.commit(&transaction),
                Err(JournalError::ProtectedBoundary)
            ));
            assert!(matches!(
                reopened.preflight_transactions(&[transaction]),
                Err(JournalError::ProtectedBoundary)
            ));
        }
        assert!(matches!(
            reopened.compact(),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(
            reopened
                .acquire_source_domain_policy_hold_v1(expected)
                .is_err()
        );
    }

    #[test]
    fn exact_cold_release_restores_writes_and_wrong_binding_does_not() {
        let directory = TestDirectory::new();
        let expected = hold();
        directory
            .open()
            .acquire_source_domain_policy_hold_v1(expected)
            .unwrap();

        let mut reopened = directory.open();
        let wrong_binding = SourceDomainPolicyHoldV1 {
            binding: ObjectDigest::from_bytes([6; 32]),
            ..expected
        };
        assert!(
            reopened
                .release_source_domain_policy_hold_after_root_readback_v1(wrong_binding)
                .is_err()
        );
        assert!(
            reopened
                .commit(&ordinary_transaction(RecordNamespace::DesiredState, 9))
                .is_err()
        );
        reopened
            .release_source_domain_policy_hold_after_root_readback_v1(expected)
            .expect("exact root readback checked by caller");
        assert!(
            !reopened
                .source_domain_policy_hold_v1()
                .unwrap()
                .unwrap()
                .is_held()
        );
        reopened
            .commit(&ordinary_transaction(RecordNamespace::DesiredState, 9))
            .expect("source-domain writes restored");
    }

    #[test]
    fn v8_retirement_replays_exact_released_source_after_reopen() {
        let directory = TestDirectory::new();
        let expected = hold();
        let mut source = ProtectedSourceDomainJournalOwnerV1::from_test_journal(directory.open());
        source
            .acquire_closed_policy_source_hold_v1(expected)
            .expect("held Source custody");

        source
            .retire_closed_policy_source_hold_v8(expected)
            .expect("exact V8 retirement transition");
        drop(source);

        let mut reopened = ProtectedSourceDomainJournalOwnerV1::from_test_journal(directory.open());
        assert_eq!(
            reopened.closed_policy_source_hold_v1().unwrap(),
            Some(SourceDomainPolicyHoldV1 {
                held: false,
                ..expected
            })
        );
        let marker = reopened
            .pending_closed_policy_source_v8_settlement_v1()
            .unwrap()
            .expect("V8 release remains pending settlement");
        assert_eq!(marker.binding(), expected.binding());
        assert_eq!(marker.epoch(), expected.epoch());
        assert_eq!(
            marker.held_record_digest(),
            expected.record_digest().unwrap()
        );
        assert_eq!(
            marker.released_record_digest(),
            SourceDomainPolicyHoldV1 {
                held: false,
                ..expected
            }
            .record_digest()
            .unwrap()
        );
        assert_eq!(
            reopened.closed_policy_source_v8_release_pair_v1().unwrap(),
            (
                expected,
                SourceDomainPolicyHoldV1 {
                    held: false,
                    ..expected
                }
            )
        );
        reopened
            .retire_closed_policy_source_hold_v8(expected)
            .expect("exact released replay is idempotent");
        assert!(
            reopened
                .acquire_closed_policy_source_hold_v1(expected)
                .is_err()
        );
        let erase_marker = JournalTransaction::new(
            [18; 16],
            vec![JournalRecord::delete(
                RecordNamespace::SourceDomainPolicyHold,
                V8_PENDING_KEY.to_vec(),
            )],
        )
        .unwrap();
        assert!(matches!(
            reopened.journal().commit(&erase_marker),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(matches!(
            reopened
                .journal()
                .commit(&ordinary_transaction(RecordNamespace::DesiredState, 9)),
            Err(JournalError::ProtectedBoundary)
        ));
        reopened.journal().compact().expect("typed pair compacts");
        drop(reopened);

        let reopened = ProtectedSourceDomainJournalOwnerV1::from_test_journal(directory.open());
        assert_eq!(
            reopened.closed_policy_source_hold_v1().unwrap(),
            Some(SourceDomainPolicyHoldV1 {
                held: false,
                ..expected
            })
        );
        assert_eq!(
            reopened
                .pending_closed_policy_source_v8_settlement_v1()
                .unwrap(),
            Some(marker)
        );
        assert_eq!(
            reopened
                .closed_policy_source_v8_release_pair_v1()
                .unwrap()
                .0,
            expected,
            "compaction retains the typed historical predecessor"
        );
    }

    #[test]
    fn v8_settlement_clear_survives_reopen_and_rejects_stale_replay() {
        let directory = TestDirectory::new();
        let expected = hold();
        let released = SourceDomainPolicyHoldV1 {
            held: false,
            ..expected
        };
        let wrong = SourceDomainPolicyHoldV1 {
            ancestry: ObjectDigest::from_bytes([9; 32]),
            ..released
        };
        let mut source = directory.open();
        source
            .acquire_source_domain_policy_hold_v1(expected)
            .unwrap();
        source
            .retire_source_domain_policy_hold_v8(expected)
            .unwrap();
        drop(source);

        let mut recovered = directory.open();
        assert!(
            recovered
                .clear_source_domain_policy_v8_pending_settlement_v1(wrong)
                .is_err()
        );
        assert!(
            recovered
                .source_domain_policy_v8_pending_settlement_v1()
                .unwrap()
                .is_some()
        );
        recovered
            .clear_source_domain_policy_v8_pending_settlement_v1(released)
            .unwrap();
        recovered
            .commit(&ordinary_transaction(RecordNamespace::DesiredState, 9))
            .expect("Source writes resume only after settlement");
        drop(recovered);

        let mut recovered = directory.open();
        assert_eq!(
            recovered.source_domain_policy_hold_v1().unwrap(),
            Some(released)
        );
        assert_eq!(
            recovered
                .source_domain_policy_v8_pending_settlement_v1()
                .unwrap(),
            None
        );
        recovered
            .clear_source_domain_policy_v8_pending_settlement_v1(released)
            .expect("same released Source row replays after an ambiguous clear");
        recovered
            .compact()
            .expect("settled Source journal compacts");
        drop(recovered);

        let mut recovered = directory.open();
        recovered
            .clear_source_domain_policy_v8_pending_settlement_v1(released)
            .expect("exact replay survives compaction");
        let successor = SourceDomainPolicyHoldV1 {
            binding: ObjectDigest::from_bytes([6; 32]),
            epoch: expected.epoch() + 1,
            held: true,
            ..expected
        };
        recovered
            .acquire_source_domain_policy_hold_v1(successor)
            .expect("settled Source permits the successor");
        assert!(
            recovered
                .clear_source_domain_policy_v8_pending_settlement_v1(released)
                .is_err()
        );
    }

    #[test]
    fn v8_retirement_rejects_wrong_identity_and_phase() {
        let directory = TestDirectory::new();
        let expected = hold();
        let mut source = directory.open();
        assert!(
            source
                .retire_source_domain_policy_hold_v8(expected)
                .is_err()
        );
        source
            .acquire_source_domain_policy_hold_v1(expected)
            .expect("held Source custody");

        let wrong_binding = SourceDomainPolicyHoldV1 {
            binding: ObjectDigest::from_bytes([6; 32]),
            ..expected
        };
        let released_argument = SourceDomainPolicyHoldV1 {
            held: false,
            ..expected
        };
        assert!(
            source
                .retire_source_domain_policy_hold_v8(wrong_binding)
                .is_err()
        );
        assert!(
            source
                .retire_source_domain_policy_hold_v8(released_argument)
                .is_err()
        );
        assert_eq!(
            source.source_domain_policy_hold_v1().unwrap(),
            Some(expected)
        );

        source
            .retire_source_domain_policy_hold_v8(expected)
            .expect("exact V8 retirement transition");
        assert!(
            source
                .retire_source_domain_policy_hold_v8(wrong_binding)
                .is_err()
        );
        assert!(
            source
                .retire_source_domain_policy_hold_v8(released_argument)
                .is_err()
        );
    }

    #[test]
    fn format_rejects_noncanonical_or_corrupt_custody() {
        let expected = hold();
        let mut bytes = expected.encode().unwrap();
        assert_eq!(SourceDomainPolicyHoldV1::decode(&bytes).unwrap(), expected);
        bytes[11] = 1;
        assert!(SourceDomainPolicyHoldV1::decode(&bytes).is_err());
        bytes = expected.encode().unwrap();
        bytes[183] ^= 1;
        assert!(SourceDomainPolicyHoldV1::decode(&bytes).is_err());
    }

    #[test]
    fn v8_pending_marker_rejects_orphan_mismatch_and_noncanonical_bytes() {
        let expected = hold();
        let released = SourceDomainPolicyHoldV1 {
            held: false,
            ..expected
        };
        let marker = SourceDomainPolicyV8PendingSettlementV1::new(expected).unwrap();
        let mut state = BTreeMap::new();
        state.insert(
            (
                RecordNamespace::SourceDomainPolicyHold,
                V8_PENDING_KEY.to_vec(),
            ),
            marker.encode().unwrap().to_vec(),
        );
        assert!(current_with_v8_pending(&state).is_err());

        state.insert(
            (RecordNamespace::SourceDomainPolicyHold, KEY.to_vec()),
            expected.encode().unwrap().to_vec(),
        );
        assert!(current_with_v8_pending(&state).is_err());

        state.insert(
            (RecordNamespace::SourceDomainPolicyHold, KEY.to_vec()),
            released.encode().unwrap().to_vec(),
        );
        assert_eq!(
            current_with_v8_pending(&state).unwrap(),
            (Some(released), Some(marker))
        );

        let changed = SourceDomainPolicyHoldV1 {
            ancestry: ObjectDigest::from_bytes([9; 32]),
            ..released
        };
        state.insert(
            (RecordNamespace::SourceDomainPolicyHold, KEY.to_vec()),
            changed.encode().unwrap().to_vec(),
        );
        assert!(current_with_v8_pending(&state).is_err());

        let mut noncanonical = marker.encode().unwrap();
        noncanonical[11] = 1;
        assert!(SourceDomainPolicyV8PendingSettlementV1::decode(&noncanonical).is_err());
        noncanonical = marker.encode().unwrap();
        noncanonical[151] ^= 1;
        assert!(SourceDomainPolicyV8PendingSettlementV1::decode(&noncanonical).is_err());
    }

    #[test]
    fn legacy_release_stays_reusable_and_cannot_replay_as_v8() {
        let directory = TestDirectory::new();
        let expected = hold();
        let mut source = directory.open();
        source
            .acquire_source_domain_policy_hold_v1(expected)
            .unwrap();
        source
            .release_source_domain_policy_hold_after_root_readback_v1(expected)
            .unwrap();
        drop(source);

        let mut reopened = directory.open();
        assert_eq!(
            reopened
                .source_domain_policy_v8_pending_settlement_v1()
                .unwrap(),
            None
        );
        assert!(
            reopened
                .retire_source_domain_policy_hold_v8(expected)
                .is_err()
        );
        assert!(reopened.source_domain_policy_v8_release_pair_v1().is_err());
        let successor = SourceDomainPolicyHoldV1 {
            binding: ObjectDigest::from_bytes([6; 32]),
            epoch: expected.epoch() + 1,
            ..expected
        };
        reopened
            .acquire_source_domain_policy_hold_v1(successor)
            .unwrap();
        assert_eq!(
            reopened.source_domain_policy_hold_v1().unwrap(),
            Some(successor)
        );
    }

    #[test]
    fn acquisition_reserves_capacity_for_cold_release() {
        let directory = TestDirectory::new();
        let uid = fs::metadata(&directory.0).unwrap().uid();
        let limits = JournalLimits {
            maximum_transactions: 1,
            ..JournalLimits::default()
        };
        let (mut journal, _) =
            Journal::open_protected_at_uid(&directory.0, JOURNAL_NAME, limits, uid).unwrap();
        assert!(
            journal
                .acquire_source_domain_policy_hold_v1(hold())
                .is_err()
        );
        assert_eq!(journal.source_domain_policy_hold_v1().unwrap(), None);
    }

    #[test]
    fn acquisition_reserves_two_record_v8_retirement() {
        let directory = TestDirectory::new();
        let uid = fs::metadata(&directory.0).unwrap().uid();
        let limits = JournalLimits {
            maximum_records_per_transaction: 1,
            ..JournalLimits::default()
        };
        let (mut journal, _) =
            Journal::open_protected_at_uid(&directory.0, JOURNAL_NAME, limits, uid).unwrap();
        assert!(
            journal
                .acquire_source_domain_policy_hold_v1(hold())
                .is_err()
        );
        assert_eq!(journal.source_domain_policy_hold_v1().unwrap(), None);
    }

    #[test]
    fn acquisition_reserves_v8_marker_clear_after_release() {
        let directory = TestDirectory::new();
        let uid = fs::metadata(&directory.0).unwrap().uid();
        let limits = JournalLimits {
            maximum_transactions: 2,
            ..JournalLimits::default()
        };
        let (mut journal, _) =
            Journal::open_protected_at_uid(&directory.0, JOURNAL_NAME, limits, uid).unwrap();
        assert!(
            journal
                .acquire_source_domain_policy_hold_v1(hold())
                .is_err()
        );
        assert_eq!(journal.source_domain_policy_hold_v1().unwrap(), None);
    }

    #[test]
    fn hold_cannot_be_redirected_to_another_protected_journal() {
        let directory = TestDirectory::new();
        let uid = fs::metadata(&directory.0).unwrap().uid();
        let (mut other, _) = Journal::open_protected_at_uid(
            &directory.0,
            "not-source-domains.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();

        assert!(matches!(
            other.acquire_source_domain_policy_hold_v1(hold()),
            Err(JournalError::ProtectedBoundary)
        ));
    }

    #[test]
    fn held_record_does_not_displace_typed_hierarchy_replay() {
        let directory = TestDirectory::new();
        let mut owner = ProtectedSourceDomainJournalOwnerV1::from_test_journal(directory.open());
        owner.acquire_closed_policy_source_hold_v1(hold()).unwrap();
        drop(owner);

        let mut reopened = ProtectedSourceDomainJournalOwnerV1::from_test_journal(directory.open());
        HierarchyProtectedJournalOwnerV1::claim(&mut reopened)
            .expect("typed hierarchy replay ignores the distinct hold namespace");
        assert!(
            reopened
                .closed_policy_source_hold_v1()
                .unwrap()
                .unwrap()
                .is_held()
        );
    }
}
