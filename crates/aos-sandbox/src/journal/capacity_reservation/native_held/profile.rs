//! Complete native suffix measurement over exact canonical owner mutations.
//!
//! Owner reducers, not this module, establish the meaning of those bytes. The
//! closed step names bound the native append schedule; no measurement proves
//! that a writer cut, original descriptor, or protected claim is retained.

use std::collections::BTreeMap;

use super::super::super::{
    JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
    encoded_transaction_append_bytes, encoded_transaction_record_bytes, validate_transaction,
};
use super::super::reservation_key;
use super::{NATIVE_HELD_CAPACITY_VALUE_BYTES_V3, NativeHeldCapacityPurposeV3, invalid};

mod original_source;
mod v2;

pub(in crate::journal) use original_source::{
    OriginalSourceGeometryDataV5, OriginalSourceMeasuredAlternativeV5,
    check_original_source_candidate_spend_v5, derive_original_source_geometry_v5,
};

pub use v2::{
    NativeHeldCapacityAppendV2, NativeHeldCapacityStepV2, NativeHeldCapacitySuffixV2,
    provider_native_capacity_transition_v2,
};

/// Names one native append slot without authorizing its owner transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeHeldCapacityStepV3 {
    /// Root stores its first signed preparation.
    RootPreparedStored,
    /// Root stores the received Provider-held offer.
    RootHeldStored,
    /// Root performs the original response CAS with all namespace-40 companions.
    RootDispositionCas,
    /// Root stores its irreversible Accepted-or-Closed assertion and preparation.
    RootDispositionPrepared,
    /// Root stores its signed disposition before escape.
    RootDispositionStored,
    /// Root stores the terminal proof and unsigned terminal acknowledgement.
    RootTerminalProofStored,
    /// Root stores the signed terminal acknowledgement or exact mode-3 proof.
    RootTerminalAckStored,
    /// Provider checkpoints original challenge issuance.
    ProviderChallengeIssued,
    /// Provider stores the original Storage preparation.
    ProviderStoragePrepared,
    /// Provider checkpoints spending the original challenge.
    ProviderChallengeSpent,
    /// Provider completes exactly the actual six owner rows.
    ProviderSixRowComplete,
    /// Provider stores its unsigned held offer.
    ProviderHeldPrepared,
    /// Provider stores its signed held offer before escape.
    ProviderHeldStored,
    /// Provider stores Root's disposition and unsigned Storage relay.
    ProviderRootDispositionPrepared,
    /// Provider stores the signed Storage relay before escape.
    ProviderRelayStored,
    /// Provider stores the original Storage settlement assertion.
    ProviderStorageSettlement,
    /// Provider prepares its terminal settled assertion.
    ProviderSettledPrepared,
    /// Provider stores its signed terminal assertion before escape.
    ProviderSettledStored,
    /// Provider stores the first exact Root recovery proof.
    ProviderRootRecoveryStored,
    /// Provider prepares the original Storage recovery relay.
    ProviderRecoveryRelayPrepared,
    /// Provider stores that signed relay before escape.
    ProviderRecoveryRelayStored,
    /// Provider stores the first exact Storage recovery state.
    ProviderStorageRecoveryStored,
    /// Provider prepares the first terminal recovery state.
    ProviderRecoveryTerminalPrepared,
    /// Provider stores the signed terminal recovery state before escape.
    ProviderRecoveryTerminalStored,
    /// Provider stores Root's exact terminal proof, without releasing cleanup capacity.
    ProviderRootTerminalStored,
    /// Provider performs the independently legitimate maximal lifecycle cleanup/fault.
    ProviderLifecycleCleanup,
}

impl NativeHeldCapacityStepV3 {
    fn owner_and_slot(self) -> (NativeHeldCapacityPurposeV3, u8) {
        use NativeHeldCapacityPurposeV3::{Provider, Root};
        use NativeHeldCapacityStepV3::*;
        match self {
            RootPreparedStored => (Root, 1),
            RootHeldStored => (Root, 2),
            RootDispositionCas => (Root, 3),
            RootDispositionPrepared => (Root, 4),
            RootDispositionStored => (Root, 5),
            RootTerminalProofStored => (Root, 6),
            RootTerminalAckStored => (Root, 7),
            ProviderChallengeIssued => (Provider, 1),
            ProviderStoragePrepared => (Provider, 2),
            ProviderChallengeSpent => (Provider, 3),
            ProviderSixRowComplete => (Provider, 4),
            ProviderHeldPrepared => (Provider, 5),
            ProviderHeldStored => (Provider, 6),
            ProviderRootDispositionPrepared => (Provider, 7),
            ProviderRelayStored => (Provider, 8),
            ProviderStorageSettlement => (Provider, 9),
            ProviderSettledPrepared => (Provider, 10),
            ProviderSettledStored => (Provider, 11),
            ProviderRootRecoveryStored => (Provider, 12),
            ProviderRecoveryRelayPrepared => (Provider, 13),
            ProviderRecoveryRelayStored => (Provider, 14),
            ProviderStorageRecoveryStored => (Provider, 15),
            ProviderRecoveryTerminalPrepared => (Provider, 16),
            ProviderRecoveryTerminalStored => (Provider, 17),
            ProviderRootTerminalStored => (Provider, 18),
            ProviderLifecycleCleanup => (Provider, 19),
        }
    }

    fn is_final(self) -> bool {
        matches!(
            self,
            Self::RootTerminalAckStored | Self::ProviderLifecycleCleanup
        )
    }
}

/// Carries one exact owner before/after image solely for byte accounting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHeldCapacityChangeV3 {
    key: Vec<u8>,
    before: Option<Vec<u8>>,
    after: Option<Vec<u8>>,
}

impl NativeHeldCapacityChangeV3 {
    /// Constructs one change from an actual owner's canonical proposal bytes.
    ///
    /// # Errors
    ///
    /// Rejects an empty/unrepresentable key or an unchanged before/after pair.
    /// It does not decode or approve the owner records.
    pub fn new(
        key: Vec<u8>,
        before: Option<Vec<u8>>,
        after: Option<Vec<u8>>,
    ) -> Result<Self, JournalError> {
        if key.is_empty() || key.len() > u16::MAX as usize || before == after {
            return Err(invalid("invalid native capacity before/after change"));
        }
        Ok(Self { key, before, after })
    }
}

/// Describes one owner append, excluding its mechanically derived capacity rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHeldCapacityAppendV3 {
    step: NativeHeldCapacityStepV3,
    transaction_id: [u8; 16],
    changes: Vec<NativeHeldCapacityChangeV3>,
}

impl NativeHeldCapacityAppendV3 {
    pub(super) fn purpose(&self) -> NativeHeldCapacityPurposeV3 {
        self.step.owner_and_slot().0
    }

    pub(super) const fn transaction_id(&self) -> [u8; 16] {
        self.transaction_id
    }

    pub(super) fn is_cleanup(&self) -> bool {
        self.step == NativeHeldCapacityStepV3::ProviderLifecycleCleanup
    }

    pub(super) fn owner_records(&self) -> Vec<JournalRecord> {
        let namespace = self.purpose().owner_namespace();
        self.changes
            .iter()
            .map(|change| match &change.after {
                Some(value) => JournalRecord::put(namespace, change.key.clone(), value.clone()),
                None => JournalRecord::delete(namespace, change.key.clone()),
            })
            .collect()
    }

    /// Joins exact owner mutations to a closed native append slot.
    ///
    /// # Errors
    ///
    /// Rejects a zero transaction ID, empty mutations, or repeated logical keys.
    /// The actual owner must independently validate its complete row graph.
    pub fn new(
        step: NativeHeldCapacityStepV3,
        transaction_id: [u8; 16],
        changes: Vec<NativeHeldCapacityChangeV3>,
    ) -> Result<Self, JournalError> {
        require_changes(transaction_id, &changes)?;
        require_owner_shape(step, &changes)?;
        Ok(Self {
            step,
            transaction_id,
            changes,
        })
    }
}

fn require_changes(
    transaction_id: [u8; 16],
    changes: &[NativeHeldCapacityChangeV3],
) -> Result<(), JournalError> {
    if transaction_id == [0; 16] || changes.is_empty() {
        return Err(JournalError::InvalidTransaction);
    }
    let mut keys = std::collections::BTreeSet::new();
    if changes
        .iter()
        .any(|change| !keys.insert(change.key.as_slice()))
    {
        return Err(JournalError::DuplicateRecordKey);
    }
    Ok(())
}

fn require_owner_shape(
    step: NativeHeldCapacityStepV3,
    changes: &[NativeHeldCapacityChangeV3],
) -> Result<(), JournalError> {
    use NativeHeldCapacityStepV3::*;
    let mut widths = changes
        .iter()
        .map(|change| change.key.len())
        .collect::<Vec<_>>();
    widths.sort_unstable();
    let matches = match step {
        RootDispositionCas => widths == [64, 66, 68, 75],
        RootPreparedStored
        | RootHeldStored
        | RootDispositionPrepared
        | RootDispositionStored
        | RootTerminalProofStored
        | RootTerminalAckStored => widths == [68],
        ProviderSixRowComplete => widths == [40, 49, 63, 96, 99, 103],
        ProviderLifecycleCleanup => {
            !widths.is_empty()
                && widths.len() <= 6
                && widths
                    .iter()
                    .all(|width| [40, 49, 63, 96, 99, 103].contains(width))
        }
        _ => widths == [40],
    };
    if !matches {
        return Err(invalid("native capacity concrete owner row shape"));
    }
    Ok(())
}

/// Fixes which native continuation is being measured, not its validity as authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeHeldCapacityPathV3 {
    /// Remaining ordinary durable stages through the owner's final reserved floor.
    Normal,
    /// Cold irreversible Closed stages; excluded positive stages cannot reappear.
    ColdClosed,
    /// Exact first-proof recovery continuation, never arbitrary query history.
    Recovery,
}

/// Retains one bounded complete native continuation as plain accounting data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHeldCapacitySuffixV3 {
    purpose: NativeHeldCapacityPurposeV3,
    path: NativeHeldCapacityPathV3,
    appends: Vec<NativeHeldCapacityAppendV3>,
}

impl NativeHeldCapacitySuffixV3 {
    /// Constructs a complete ordered suffix, including its reserved final append.
    ///
    /// # Errors
    ///
    /// Rejects empty/oversize paths, foreign or repeated slots/transaction IDs,
    /// reverse chronology, omitted final retirement, or a normal-stage gap.
    /// Cold/recovery paths may exclude skipped stages only after the owner reducer
    /// has proved the irreversible closed transition; this type is not that proof.
    pub fn new(
        purpose: NativeHeldCapacityPurposeV3,
        path: NativeHeldCapacityPathV3,
        appends: Vec<NativeHeldCapacityAppendV3>,
    ) -> Result<Self, JournalError> {
        if appends.is_empty() || appends.len() > purpose.maximum_future_transactions() as usize {
            return Err(invalid("native capacity suffix count"));
        }
        let mut previous = None;
        let mut ids = std::collections::BTreeSet::new();
        for append in &appends {
            let (owner, slot) = append.step.owner_and_slot();
            if owner != purpose
                || !ids.insert(append.transaction_id)
                || previous.is_some_and(|old| slot <= old)
                || (path == NativeHeldCapacityPathV3::Normal
                    && previous.is_some_and(|old| !normal_successor(purpose, old, slot)))
            {
                return Err(invalid("native capacity suffix chronology"));
            }
            previous = Some(slot);
        }
        if !appends.last().is_some_and(|append| append.step.is_final()) {
            return Err(invalid("native capacity suffix lacks retirement"));
        }
        if path == NativeHeldCapacityPathV3::Normal
            && purpose == NativeHeldCapacityPurposeV3::Provider
            && appends
                .iter()
                .any(|append| (12..=17).contains(&append.step.owner_and_slot().1))
        {
            return Err(invalid("recovery slot in normal native suffix"));
        }
        let slots = appends
            .iter()
            .map(|append| append.step.owner_and_slot().1)
            .collect::<Vec<_>>();
        if !closed_path_shape(purpose, path, &slots) {
            return Err(invalid("native capacity closed continuation shape"));
        }
        Ok(Self {
            purpose,
            path,
            appends,
        })
    }

    /// Returns the fixed native journal owner described by this measurement.
    #[must_use]
    pub const fn purpose(&self) -> NativeHeldCapacityPurposeV3 {
        self.purpose
    }

    /// Returns the bounded continuation class, not proof of an owner transition.
    #[must_use]
    pub const fn path(&self) -> NativeHeldCapacityPathV3 {
        self.path
    }

    /// Measures every complete append and exact relative retained growth.
    ///
    /// # Errors
    ///
    /// Rejects inconsistent repeated before-images, arithmetic overflow, or any
    /// individual transaction outside the supplied unchanged journal ceilings.
    /// Aggregate admission and all outstanding reservations remain separate.
    pub fn measure(
        &self,
        limits: JournalLimits,
    ) -> Result<NativeHeldCapacityGeometryV3, JournalError> {
        measure_appends(
            self.purpose,
            self.appends.iter().map(|append| MeasurementAppend {
                transaction_id: append.transaction_id,
                changes: &append.changes,
                final_append: append.step.is_final(),
            }),
            limits,
            NATIVE_HELD_CAPACITY_VALUE_BYTES_V3,
        )
    }
}

struct MeasurementAppend<'a> {
    transaction_id: [u8; 16],
    changes: &'a [NativeHeldCapacityChangeV3],
    final_append: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RetainedPrefix {
    owner_bytes: i128,
    owner_records: i64,
    final_append: bool,
}

struct MeasuredAppends {
    geometry: NativeHeldCapacityGeometryV3,
    prefixes: Vec<RetainedPrefix>,
    maximum_key_bytes: usize,
    maximum_record_payload_bytes: usize,
}

// Both profiles use identical before-image, retained-growth and journal framing
// arithmetic. Owner chronology is validated separately before reaching here.
fn measure_appends<'a>(
    purpose: NativeHeldCapacityPurposeV3,
    appends: impl IntoIterator<Item = MeasurementAppend<'a>>,
    limits: JournalLimits,
    floor_value_bytes: usize,
) -> Result<NativeHeldCapacityGeometryV3, JournalError> {
    Ok(measure_appends_with_prefixes(purpose, appends, limits, floor_value_bytes)?.geometry)
}

// The old owner-only result and the original Source coupled view consume this
// single retained accumulation pass. Extra observations do not change framing,
// before-image chronology, conservative headroom or any old returned field.
fn measure_appends_with_prefixes<'a>(
    purpose: NativeHeldCapacityPurposeV3,
    appends: impl IntoIterator<Item = MeasurementAppend<'a>>,
    limits: JournalLimits,
    floor_value_bytes: usize,
) -> Result<MeasuredAppends, JournalError> {
    let namespace = purpose.owner_namespace();
    let mut states = BTreeMap::<Vec<u8>, Option<Vec<u8>>>::new();
    let mut original_bytes = 0_u64;
    let mut current_bytes = 0_u64;
    let mut original_records = 0_u32;
    let mut current_records = 0_u32;
    let mut geometry = NativeHeldCapacityGeometryV3::default();
    let mut prefixes = Vec::new();
    let mut maximum_key_bytes = 0;
    let mut maximum_record_payload_bytes = 0;

    for append in appends {
        let mut records = Vec::with_capacity(append.changes.len() + 2);
        for change in append.changes {
            if let Some(current) = states.get(&change.key) {
                if current != &change.before {
                    return Err(invalid("native capacity inconsistent before image"));
                }
            } else {
                let (bytes, count) = retained(&change.key, change.before.as_deref())?;
                original_bytes = add(original_bytes, bytes)?;
                current_bytes = add(current_bytes, bytes)?;
                original_records = add_records(original_records, count)?;
                current_records = add_records(current_records, count)?;
            }
            let (before_bytes, before_count) = retained(&change.key, change.before.as_deref())?;
            let (after_bytes, after_count) = retained(&change.key, change.after.as_deref())?;
            current_bytes = add(
                current_bytes
                    .checked_sub(before_bytes)
                    .ok_or(JournalError::InvalidTransaction)?,
                after_bytes,
            )?;
            current_records = add_records(
                current_records
                    .checked_sub(before_count)
                    .ok_or(JournalError::InvalidTransaction)?,
                after_count,
            )?;
            states.insert(change.key.clone(), change.after.clone());
            records.push(match &change.after {
                Some(value) => JournalRecord::put(namespace, change.key.clone(), value.clone()),
                None => JournalRecord::delete(namespace, change.key.clone()),
            });
        }

        // Private width-only templates are never returned, decoded, or used
        // as authority. Each nonfinal transfer deletes the old key and puts
        // a distinct fixed-width successor; final retirement deletes only.
        records.push(JournalRecord::delete(
            RecordNamespace::GlobalCapacityReservation,
            reservation_key([1; 32]),
        ));
        if !append.final_append {
            records.push(JournalRecord::put(
                RecordNamespace::GlobalCapacityReservation,
                reservation_key([2; 32]),
                vec![0; floor_value_bytes],
            ));
        }
        let transaction = JournalTransaction::new(append.transaction_id, records)?;
        validate_transaction(&transaction, limits)?;
        for record in transaction.records() {
            maximum_key_bytes = maximum_key_bytes.max(record.key().len());
            maximum_record_payload_bytes =
                maximum_record_payload_bytes.max(crate::journal::encode_record(record)?.len());
        }
        let append_bytes = encoded_transaction_append_bytes(&transaction)?;
        let record_bytes = encoded_transaction_record_bytes(&transaction)?;
        let record_count = u32::try_from(transaction.records().len())
            .map_err(|_| JournalError::LimitExceeded("native suffix records"))?;

        geometry.transactions = add_records(geometry.transactions, 1)?;
        geometry.records = add_records(geometry.records, record_count)?;
        geometry.append_bytes = add(geometry.append_bytes, append_bytes)?;
        geometry.maximum_transaction_records =
            geometry.maximum_transaction_records.max(record_count);
        geometry.maximum_transaction_record_bytes =
            geometry.maximum_transaction_record_bytes.max(record_bytes);
        geometry.maximum_retained_growth_bytes = geometry
            .maximum_retained_growth_bytes
            .max(current_bytes.saturating_sub(original_bytes));
        geometry.maximum_retained_growth_records = geometry
            .maximum_retained_growth_records
            .max(current_records.saturating_sub(original_records));
        prefixes.push(RetainedPrefix {
            owner_bytes: i128::from(current_bytes) - i128::from(original_bytes),
            owner_records: i64::from(current_records) - i64::from(original_records),
            final_append: append.final_append,
        });
    }
    geometry.require_headroom(limits, NativeHeldCapacityUsageV3::default())?;
    Ok(MeasuredAppends {
        geometry,
        prefixes,
        maximum_key_bytes,
        maximum_record_payload_bytes,
    })
}

fn normal_successor(purpose: NativeHeldCapacityPurposeV3, before: u8, after: u8) -> bool {
    if purpose == NativeHeldCapacityPurposeV3::Provider && before == 11 {
        after == 18
    } else {
        after == before + 1
    }
}

fn closed_path_shape(
    purpose: NativeHeldCapacityPurposeV3,
    path: NativeHeldCapacityPathV3,
    slots: &[u8],
) -> bool {
    use NativeHeldCapacityPathV3::{ColdClosed, Normal, Recovery};
    use NativeHeldCapacityPurposeV3::{Provider, Root};
    match (purpose, path) {
        (_, Normal) => true,
        (Root, ColdClosed) => matches!(slots, [4, 5, 6, 7] | [4, 6, 7] | [5, 6, 7] | [6, 7] | [7]),
        (Root, Recovery) => matches!(slots, [6, 7] | [7]),
        (Provider, Recovery) => provider_recovery_shape(slots),
        (Provider, ColdClosed) => provider_closed_shape(slots),
    }
}

fn provider_recovery_shape(slots: &[u8]) -> bool {
    // These are the actual possible durable prefix endpoints, not permission
    // to skip arbitrary writes. In particular endpoint 5 is unescaped3 and
    // endpoint 7 is unescaped5. Their first9 write respectively clears3 or
    // preserves5; the already-reserved unsigned11 write replaces only5.
    // Endpoint 0 is genuine Requested-only Closed recovery. The owner reducer
    // still must prove every original graph, preparation and archive predicate.
    const PREFIX: [u8; 11] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    const ENDPOINTS: [usize; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    const RECOVERY: [u8; 8] = [12, 13, 14, 15, 16, 17, 18, 19];
    ENDPOINTS
        .iter()
        .any(|end| suffix_of_join(slots, &PREFIX[..*end], &RECOVERY))
}

fn provider_closed_shape(slots: &[u8]) -> bool {
    // No cold continuation introduces challenge, Complete or a positive held
    // offer. A genuine direct Closed disposition starts at slot7; recovery may
    // replace the unescaped relay or terminal carrier at their exact endpoint.
    const CLOSED: [u8; 5] = [7, 8, 9, 10, 11];
    const HOT_TERMINAL: [u8; 2] = [18, 19];
    const RECOVERY: [u8; 8] = [12, 13, 14, 15, 16, 17, 18, 19];
    suffix_of_join(slots, &CLOSED, &HOT_TERMINAL)
        || [0, 1, 2, 3, 4, 5]
            .iter()
            .any(|end| suffix_of_join(slots, &CLOSED[..*end], &RECOVERY))
}

fn suffix_of_join(slots: &[u8], prefix: &[u8], terminal: &[u8]) -> bool {
    let mut complete = Vec::with_capacity(prefix.len() + terminal.len());
    complete.extend_from_slice(prefix);
    complete.extend_from_slice(terminal);
    complete.ends_with(slots)
}

/// Reports conservative complete-suffix accounting without reserving any space.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NativeHeldCapacityGeometryV3 {
    /// Complete remaining appends, including terminal cleanup or retirement.
    pub transactions: u32,
    /// Aggregate record frames, including all capacity deletes and successors.
    pub records: u32,
    /// Aggregate actual begin/record/commit framed bytes.
    pub append_bytes: u64,
    /// Largest individual transaction's record count.
    pub maximum_transaction_records: u32,
    /// Largest individual transaction's canonical record payload bytes.
    pub maximum_transaction_record_bytes: u64,
    /// Maximum positive key/value growth relative to the original before-images.
    pub maximum_retained_growth_bytes: u64,
    /// Maximum positive logical entry growth relative to the original before-images.
    pub maximum_retained_growth_records: u32,
}

/// Describes diagnostic existing usage and all already retained reservation floors.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NativeHeldCapacityUsageV3 {
    /// Existing fully framed durable journal length.
    pub journal_bytes: u64,
    /// Existing committed transaction count.
    pub transactions: u64,
    /// Existing materialized key/value bytes, including reservation rows.
    pub materialized_bytes: u64,
    /// Existing materialized logical entries, including reservation rows.
    pub materialized_records: u64,
    /// Complete append/materialized byte floors of every other pending reservation.
    pub reserved_bytes: u64,
    /// Aggregate record floors of every other pending reservation.
    pub reserved_records: u64,
    /// Remaining append counts of every other pending reservation.
    pub reserved_transactions: u64,
}

impl NativeHeldCapacityGeometryV3 {
    /// Checks complete aggregate floors against unchanged opened journal ceilings.
    ///
    /// The record and byte aggregates conservatively cover retained growth just
    /// as existing reservation accounting does. An actual protected owner must
    /// derive usage under its held writer before any admission; caller-provided
    /// diagnostics cannot reserve space or establish a current snapshot.
    ///
    /// # Errors
    ///
    /// Rejects overflow, any per-transaction ceiling, or aggregate journal,
    /// materialized, record-count, or committed-transaction exhaustion.
    pub fn require_headroom(
        &self,
        limits: JournalLimits,
        usage: NativeHeldCapacityUsageV3,
    ) -> Result<(), JournalError> {
        let bytes = add(usage.reserved_bytes, self.append_bytes)?;
        let records = add(usage.reserved_records, u64::from(self.records))?;
        let transactions = add(usage.reserved_transactions, u64::from(self.transactions))?;
        if self.maximum_transaction_records as usize > limits.maximum_records_per_transaction
            || self.maximum_transaction_record_bytes > limits.maximum_transaction_bytes as u64
            || add(usage.journal_bytes, bytes)? > limits.maximum_journal_bytes
            || add(usage.materialized_bytes, bytes)? > limits.maximum_materialized_bytes as u64
            || add(usage.materialized_records, records)?
                > limits.maximum_materialized_records as u64
            || add(usage.transactions, transactions)? > limits.maximum_transactions as u64
        {
            return Err(JournalError::LimitExceeded(
                "complete native capacity suffix",
            ));
        }
        Ok(())
    }
}

fn retained(key: &[u8], value: Option<&[u8]>) -> Result<(u64, u32), JournalError> {
    match value {
        Some(value) => Ok((add(key.len() as u64, value.len() as u64)?, 1)),
        None => Ok((0, 0)),
    }
}

fn add(left: u64, right: u64) -> Result<u64, JournalError> {
    left.checked_add(right).ok_or(JournalError::JournalTooLarge)
}

fn add_records(left: u32, right: u32) -> Result<u32, JournalError> {
    left.checked_add(right)
        .ok_or(JournalError::LimitExceeded("native suffix records"))
}
