//! Exact borrowed Broker HEAD and purpose-closed transaction/hash geometry.
//!
//! Host complete-map HEADs remain solely in Core's original comparison engine.
//! These hashes and sequence estimates are DATA, not persistence or capacity
//! tokens. The private purpose selector accepts no caller domain or namespace.

use std::collections::BTreeSet;

use aos_sandbox_controller_domain::{JournalTransaction, RecordNamespace};
use sha2::{Digest as _, Sha256};

use super::{FloorCutV1, FloorErrorV1, RecordPurposeDataV1};

const HEAD_DOMAIN: &[u8] = b"aos.sandbox.broker-session.tpm-floor.head.v1\0";

/// Hashes the original sorted complete namespace-47 map without packet copies.
///
/// # Errors
///
/// Rejects empty/nonascending keys, count overflow and invalid cut sentinels.
pub(crate) fn broker_cut_from_records_v1<'a>(
    sequence: u64,
    records: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Result<FloorCutV1, FloorErrorV1> {
    cut_from_records_v1(RecordPurposeDataV1::BrokerV1, [0; 32], sequence, records)
}

/// Hashes the complete ONLINE map, including its entire immutable signed seed.
///
/// # Errors
/// Preserves key/order, count and sequence sentinel rejection. The profile's
/// scope is DATA until joined to the original authenticated purpose owner.
pub(crate) fn online_cut_from_records_v1<'a>(
    profile: super::OnlineFloorProfileV1,
    sequence: u64,
    records: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Result<FloorCutV1, FloorErrorV1> {
    cut_from_records_v1(RecordPurposeDataV1::OnlineNixV1, profile.scope(), sequence, records)
}

macro_rules! cut_step_v3 {
    (Ordinary, digest $original:ident) => { Sha256::new() };
    (Retained, digest $original:ident) => {{
        $original.digest = Some(Sha256::new());
        $original.digest.as_mut().ok_or(FloorErrorV1::Encoding)?
    }};
    (Ordinary, initialize $original:ident, $previous:ident, $count:ident) => {
        let mut $previous: Option<&[u8]> = None;
        let mut $count = 0_u64;
    };
    (Retained, initialize $original:ident, $previous:ident, $count:ident) => {};
    (Ordinary, previous $original:ident, $previous:ident, $key:ident) => {
        $previous.is_some_and(|old| old >= $key)
    };
    (Retained, previous $original:ident, $previous:ident, $key:ident) => {
        $original.predecessor.as_deref().is_some_and(|old| old >= $key)
    };
    (Ordinary, advance $original:ident, $previous:ident, $count:ident, $key:ident) => {
        $count = $count.checked_add(1).ok_or(FloorErrorV1::Encoding)?;
        $previous = Some($key);
    };
    (Retained, advance $original:ident, $previous:ident, $count:ident, $key:ident) => {
        $original.count = $original.count.checked_add(1).ok_or(FloorErrorV1::Encoding)?;
        $original.predecessor = Some($key.to_vec());
    };
    (Ordinary, count $original:ident, $count:ident) => { $count };
    (Retained, count $original:ident, $count:ident) => { $original.count };
    (Ordinary, finish $original:ident, $digest:ident, $sequence:ident) => {
        FloorCutV1::new($sequence, $digest.finalize().into())
    };
    (Retained, finish $original:ident, $digest:ident, $sequence:ident) => {
        FloorCutV1::new($sequence,
            $original.digest.take().ok_or(FloorErrorV1::Encoding)?.finalize().into())
    };
}

macro_rules! cut_recipe_v3 {
    ($mode:ident, $original:ident, $purpose:ident, $scope:ident, $sequence:ident, $records:ident) => {{
        (|| {
            let mut digest = cut_step_v3!($mode, digest $original);
            match $purpose {
                RecordPurposeDataV1::OnlineNixV1 => {
                    digest.update(b"aos.sandbox.nix.online-floor.head.v1\0");
                    digest.update($scope);
                }
                _ => digest.update(HEAD_DOMAIN),
            }
            digest.update([RecordNamespace::BrokerSessionTraffic as u8]);
            digest.update($sequence.to_be_bytes());
            cut_step_v3!($mode, initialize $original, predecessor, count);
            for (key, value) in $records {
                if key.is_empty() || cut_step_v3!($mode, previous $original, predecessor, key) {
                    return Err(FloorErrorV1::Encoding);
                }
                update_bytes(&mut digest, key)?;
                update_bytes(&mut digest, value)?;
                cut_step_v3!($mode, advance $original, predecessor, count, key);
            }
            digest.update(cut_step_v3!($mode, count $original, count).to_be_bytes());
            cut_step_v3!($mode, finish $original, digest, $sequence)
        })()
    }};
}

fn cut_from_records_v1<'a>(
    purpose: RecordPurposeDataV1,
    scope: [u8; 32],
    sequence: u64,
    records: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Result<FloorCutV1, FloorErrorV1> {
    cut_recipe_v3!(Ordinary, unused, purpose, scope, sequence, records)
}

/// Retains the canonical complete-map hash and reached ordering prefix.
pub(crate) struct FloorHeadCutOriginalV3 {
    digest: Option<Sha256>,
    predecessor: Option<Vec<u8>>,
    count: u64,
    returned: Option<Result<FloorCutV1, FloorErrorV1>>,
    entered: bool,
    reentry: Option<FloorErrorV1>,
}

impl FloorHeadCutOriginalV3 {
    /// Creates inert destinations without allocating or hashing input.
    pub(crate) const fn new() -> Self {
        Self { digest: None, predecessor: None, count: 0, returned: None,
            entered: false, reentry: None }
    }

    /// Prices the hash state and overlapping old/new predecessor-key backing.
    ///
    /// The key is an ordering carrier, not another map or Metadata entry.
    pub(crate) fn receiving_demand_v3(maximum_key_bytes: usize)
        -> Option<aos_sandbox_model::ResourceVector>
    {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(maximum_key_bytes.checked_mul(2)?)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?))
    }

    /// Runs the same complete Broker map hash once into retained destinations.
    ///
    /// # Errors
    /// Preserves empty/order, length/count and cut-sentinel failures. Reentry
    /// keeps the first actual hash/model prefix and refuses replacement.
    pub(crate) fn observe_broker_once_v3<'a>(&mut self, sequence: u64,
        records: impl IntoIterator<Item = (&'a [u8], &'a [u8])>)
        -> Result<FloorCutV1, FloorErrorV1>
    {
        if self.entered {
            self.reentry.get_or_insert(FloorErrorV1::Encoding);
            return Err(FloorErrorV1::Encoding);
        }
        self.entered = true;
        let purpose = RecordPurposeDataV1::BrokerV1;
        let scope = [0; 32];
        self.returned = Some(cut_recipe_v3!(Retained, self, purpose, scope, sequence, records));
        self.returned.as_ref().copied().unwrap_or(Err(FloorErrorV1::Encoding))
    }

    /// Borrows the original hash refusal without discarding reached DATA.
    pub(crate) fn failure(&self) -> Option<&FloorErrorV1> {
        self.returned.as_ref().and_then(|value| value.as_ref().err()).or(self.reentry.as_ref())
    }
}

/// Hashes exact ordered Broker records under the unchanged fixed domain.
///
/// # Errors
///
/// Rejects foreign namespaces, empty/duplicate keys and unrepresentable lengths.
pub(crate) fn broker_transaction_digest_v1(
    transaction: &JournalTransaction,
) -> Result<[u8; 32], FloorErrorV1> {
    transaction_digest_v1(RecordPurposeDataV1::BrokerV1, [0; 32], transaction)
}

/// Walks the exact ONLINE transaction using the existing ordered codec inputs.
pub(crate) fn online_transaction_digest_v1(
    profile: super::OnlineFloorProfileV1,
    transaction: &JournalTransaction,
) -> Result<[u8; 32], FloorErrorV1> {
    transaction_digest_v1(RecordPurposeDataV1::OnlineNixV1, profile.scope(), transaction)
}

// Keeps the actual hash state and owning key index through a later refusal.
#[derive(Default)]
pub(super) struct FloorTransactionDigestOriginalV1 {
    digest: Option<Sha256>,
    keys: BTreeSet<Vec<u8>>,
    current: Option<Vec<u8>>,
    returned: Option<Result<[u8; 32], FloorErrorV1>>,
    entered: bool,
    reentry: Option<FloorErrorV1>,
}

/// Restricts a retained transaction hash to the existing Broker HEAD purpose.
pub(crate) struct FloorHeadTransactionOriginalV3 {
    original: FloorTransactionDigestOriginalV1,
}

impl FloorHeadTransactionOriginalV3 {
    /// Creates inert hash/index destinations without allocating input DATA.
    pub(crate) fn new() -> Self {
        Self { original: FloorTransactionDigestOriginalV1::new() }
    }

    /// Prices the actual existing owning transaction-key index.
    pub(crate) fn receiving_demand_v3(transaction: &JournalTransaction)
        -> Option<aos_sandbox_model::ResourceVector>
    {
        FloorTransactionDigestOriginalV1::actual_transaction_receiving_demand_v3(transaction)
    }

    /// Hashes the existing Broker transaction once through its canonical engine.
    ///
    /// # Errors
    /// Retains namespace, empty/duplicate-key, width and repeated-entry failure.
    pub(crate) fn observe_broker_once_v3(&mut self, transaction: &JournalTransaction)
        -> Result<(), FloorErrorV1>
    {
        self.original.observe_once(RecordPurposeDataV1::BrokerV1, [0; 32], transaction).map(|_| ())
    }

    /// Borrows the actual retained hash/index refusal.
    pub(crate) fn failure(&self) -> Option<&FloorErrorV1> { self.original.failure() }
}

macro_rules! digest_step {
    (Ordinary, digest $original:ident) => { Sha256::new() };
    (Retained, digest $original:ident) => {{
        $original.digest = Some(Sha256::new());
        $original.digest.as_mut().ok_or(FloorErrorV1::Encoding)?
    }};
    (Ordinary, keys $original:ident, $keys:ident) => { let mut $keys = BTreeSet::new(); };
    (Retained, keys $original:ident, $keys:ident) => {};
    (Ordinary, insert $original:ident, $keys:ident, $key:expr) => { $keys.insert($key) };
    (Retained, insert $original:ident, $keys:ident, $key:expr) => {{
        // The stored counterpart owns bytes rather than borrowing a sibling's
        // transaction. Keep a duplicate's actual new key before refusal.
        $original.current = Some($key.to_vec());
        let current = $original.current.as_ref().ok_or(FloorErrorV1::Encoding)?;
        if $original.keys.contains(current.as_slice()) {
            false
        } else {
            $original.keys.insert($original.current.take().ok_or(FloorErrorV1::Encoding)?)
        }
    }};
    (Ordinary, finish $original:ident, $digest:ident) => { Ok($digest.finalize().into()) };
    (Retained, finish $original:ident, $digest:ident) => {
        Ok($original.digest.take().ok_or(FloorErrorV1::Encoding)?.finalize().into())
    };
}

macro_rules! transaction_digest_recipe {
    ($mode:ident, $original:ident, $purpose:ident, $scope:ident, $transaction:ident) => {{
        (|| {
            let mut digest = digest_step!($mode, digest $original);
            digest.update($purpose.transaction_domain());
            if $purpose != RecordPurposeDataV1::BrokerV1 {
                digest.update($scope);
            }
            digest.update($transaction.id());
            digest.update(
                u64::try_from($transaction.records().len())
                    .map_err(|_| FloorErrorV1::Encoding)?
                    .to_be_bytes(),
            );
            digest_step!($mode, keys $original, keys);
            for record in $transaction.records() {
                if record.namespace() != $purpose.namespace()
                    || record.key().is_empty()
                    || !digest_step!($mode, insert $original, keys, record.key())
                {
                    return Err(FloorErrorV1::Encoding);
                }
                digest.update([record.namespace() as u8, u8::from(record.value().is_some())]);
                update_bytes(&mut digest, record.key())?;
                update_bytes(&mut digest, record.value().unwrap_or_default())?;
            }
            digest_step!($mode, finish $original, digest)
        })()
    }};
}

/// Walks exact ordered records using only a closed purpose's DATA domain.
///
/// # Errors
/// Rejects foreign namespaces, empty/duplicate keys and unrepresentable lengths.
pub(super) fn transaction_digest_v1(
    purpose: RecordPurposeDataV1,
    scope: [u8; 32],
    transaction: &JournalTransaction,
) -> Result<[u8; 32], FloorErrorV1> {
    transaction_digest_recipe!(Ordinary, original, purpose, scope, transaction)
}

impl FloorTransactionDigestOriginalV1 {
    pub(super) fn new() -> Self { Self::default() }

    pub(super) fn observe_once(&mut self, purpose: RecordPurposeDataV1,
        scope: [u8; 32], transaction: &JournalTransaction) -> Result<[u8; 32], FloorErrorV1>
    {
        if self.entered {
            self.reentry.get_or_insert(FloorErrorV1::Encoding);
            return Err(FloorErrorV1::Encoding);
        }
        self.entered = true;
        self.returned = Some(transaction_digest_recipe!(Retained, self, purpose, scope, transaction));
        match self.returned.as_ref() {
            Some(Ok(value)) => Ok(*value),
            Some(Err(cause)) => Err(*cause),
            None => Err(FloorErrorV1::Encoding),
        }
    }

    pub(super) fn failure(&self) -> Option<&FloorErrorV1> {
        self.returned.as_ref().and_then(|result| result.as_ref().err())
            .or(self.reentry.as_ref())
    }

    /// Prices this digest's actual owning key index without schema validation.
    ///
    /// The constructor still checks successor sequence before entering the
    /// digest. This passive forecast inspects only allocated input lengths and
    /// never moves a later transaction/namespace rejection ahead of that check.
    pub(super) fn actual_transaction_receiving_demand_v3(
        transaction: &JournalTransaction,
    ) -> Option<aos_sandbox_model::ResourceVector> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

        let mut keys = 0usize;
        let mut largest_key = 0usize;
        for record in transaction.records() {
            keys = keys.checked_add(record.key().len())?;
            largest_key = largest_key.max(record.key().len());
        }

        let rows = transaction.records().len();
        let index = aos_sandbox_journal::geometry::
            conservative_btree_node_bytes_v1::<Vec<u8>, ()>(rows)?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(index)?.checked_add(keys)?.checked_add(largest_key)?;
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::MetadataEntries, u64::try_from(rows).ok()?))
    }

    fn key_bound_v2(encoded_bytes: usize, limits: aos_sandbox_controller_domain::JournalLimits) -> usize {
        (encoded_bytes.saturating_sub(32) / 12).min(limits.maximum_records_per_transaction)
    }

    pub(super) fn receiving_named_entries_v2(encoded_bytes: usize, limits: aos_sandbox_controller_domain::JournalLimits)
        -> usize
    {
        Self::key_bound_v2(encoded_bytes, limits)
    }

    pub(super) fn receiving_obligations_v1(encoded_bytes: usize, limits: aos_sandbox_controller_domain::JournalLimits)
        -> Option<(usize, usize)>
    {
        let rows = Self::key_bound_v2(encoded_bytes, limits);
        let nodes = aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1::<Vec<u8>, ()>(rows)?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?.checked_add(nodes)?
            .checked_add(encoded_bytes)?.checked_add(encoded_bytes.min(limits.maximum_key_bytes))?;
        // Owner6; purpose/scope/TX/digest/record/count/key/return/framing10;
        // current-key borrow/contains/insertion and original borrow4. Each
        // owning key has Vec/node namespaces2. Payload bytes are separate.
        Some((bytes, 6usize.checked_add(14)?.checked_add(rows.checked_mul(2)?)?))
    }
}

fn update_bytes(digest: &mut Sha256, bytes: &[u8]) -> Result<(), FloorErrorV1> {
    digest.update(
        u64::try_from(bytes.len())
            .map_err(|_| FloorErrorV1::Encoding)?
            .to_be_bytes(),
    );
    digest.update(bytes);
    Ok(())
}

/// Computes the original exact native frame successor without reserving it.
///
/// # Errors
///
/// Rejects count/sequence overflow and the exhausted sequence sentinel.
pub(crate) fn successor_sequence(
    sequence: u64,
    transaction: &JournalTransaction,
) -> Result<u64, FloorErrorV1> {
    let frames = u64::try_from(transaction.records().len())
        .ok()
        .and_then(|records| records.checked_add(2))
        .ok_or(FloorErrorV1::Successor)?;
    sequence
        .checked_add(frames)
        .filter(|next| *next != u64::MAX)
        .ok_or(FloorErrorV1::Successor)
}

/// Computes fixed prepare/finalize sidecar geometry without proving its history.
///
/// # Errors
///
/// Rejects ordinal zero, arithmetic overflow and the exhausted sequence sentinel.
pub(crate) fn sidecar_sequence_v1(ordinal: u64, pending: bool) -> Result<u64, FloorErrorV1> {
    ordinal
        .checked_sub(1)
        .and_then(|count| count.checked_mul(9))
        .and_then(|frames| frames.checked_add(if pending { 8 } else { 4 }))
        .filter(|sequence| *sequence != u64::MAX)
        .ok_or(FloorErrorV1::Encoding)
}

/// Hashes only byte DATA; closed callers retain their fixed domain constants.
pub(crate) fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    for part in parts {
        digest.update(part);
    }
    digest.finalize().into()
}

#[cfg(test)]
mod retained_head_cut_tests {
    use super::*;

    #[test]
    fn retained_head_hash_matches_the_existing_complete_map_recipe() {
        let rows = [(b"a".as_slice(), b"one".as_slice()),
            (b"b".as_slice(), b"two".as_slice())];
        let expected = broker_cut_from_records_v1(7, rows).unwrap();
        let mut original = FloorHeadCutOriginalV3::new();

        let actual = original.observe_broker_once_v3(7, rows).unwrap();

        assert_eq!(actual, expected);
        assert_eq!(original.count, 2);
        assert!(original.digest.is_none());
        assert!(original.failure().is_none());
    }

    #[test]
    fn later_order_refusal_retains_the_actual_hash_and_first_key_after_reentry() {
        let rows = [(b"a".as_slice(), b"one".as_slice()),
            (b"a".as_slice(), b"two".as_slice())];
        let mut original = FloorHeadCutOriginalV3::new();

        assert_eq!(original.observe_broker_once_v3(7, rows), Err(FloorErrorV1::Encoding));

        assert!(original.digest.is_some());
        assert_eq!(original.predecessor.as_deref(), Some(b"a".as_slice()));
        assert_eq!(original.count, 1);
        let first = original.failure().unwrap() as *const FloorErrorV1;
        assert!(original.observe_broker_once_v3(8, []).is_err());
        assert!(std::ptr::eq(first, original.failure().unwrap()));
        assert!(original.digest.is_some());
        assert_eq!(original.count, 1);
    }
}

#[cfg(test)]
mod retained_transaction_tests {
    use super::*;
    use aos_sandbox_controller_domain::JournalRecord;

    fn transaction(second_namespace: RecordNamespace, second_key: &[u8]) -> JournalTransaction {
        JournalTransaction::new([1; 16], vec![
            JournalRecord::put(RecordNamespace::BrokerSessionTraffic, b"a".to_vec(), vec![1]),
            JournalRecord::put(second_namespace, second_key.to_vec(), vec![2]),
        ]).unwrap()
    }

    #[test]
    fn foreign_later_record_keeps_actual_hash_and_owning_earlier_key() {
        let transaction = transaction(RecordNamespace::DesiredState, b"b");
        let mut original = FloorTransactionDigestOriginalV1::new();

        assert!(matches!(original.observe_once(RecordPurposeDataV1::BrokerV1, [0; 32],
            &transaction), Err(FloorErrorV1::Encoding)));
        assert!(original.digest.is_some());
        assert_eq!(original.keys.len(), 1);
        assert!(original.keys.contains(b"a".as_slice()));
        let cause = original.failure().unwrap() as *const FloorErrorV1;
        assert!(original.observe_once(RecordPurposeDataV1::BrokerV1, [0; 32],
            &transaction).is_err());

        assert_eq!(original.failure().unwrap() as *const FloorErrorV1, cause);
        assert_eq!(original.keys.len(), 1);
        assert!(original.digest.is_some());
    }

    #[test]
    fn duplicate_keeps_new_key_and_original_index_without_self_references() {
        let transaction = transaction(RecordNamespace::BrokerSessionTraffic, b"a");
        let mut original = FloorTransactionDigestOriginalV1::new();

        assert!(original.observe_once(RecordPurposeDataV1::BrokerV1, [0; 32], &transaction).is_err());

        assert_eq!(original.current.as_deref(), Some(b"a".as_slice()));
        assert_eq!(original.keys.len(), 1);
        assert!(original.keys.contains(b"a".as_slice()));
        assert!(original.digest.is_some());
    }

    #[test]
    fn positive_digest_matches_the_same_ordinary_recipe() {
        let transaction = transaction(RecordNamespace::BrokerSessionTraffic, b"b");
        let expected = transaction_digest_v1(RecordPurposeDataV1::BrokerV1,
            [0; 32], &transaction).unwrap();
        let mut original = FloorTransactionDigestOriginalV1::new();

        let actual = original.observe_once(RecordPurposeDataV1::BrokerV1,
            [0; 32], &transaction).unwrap();

        assert_eq!(actual, expected);
        assert_eq!(original.keys.len(), 2);
        assert!(original.digest.is_none());
        assert!(original.failure().is_none());
    }
}
