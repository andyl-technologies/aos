//! Compares passive Create Storage materialized record/head readback DATA.
//!
//! These carriers and the lexical comparison perform no IO and grant no
//! native owner, phase, resource, receiving, or currentness authority. Actual
//! role owners retain their original map, NEXT and append outcome.

use super::HEAD_BYTES;

/// Holds copied comparison DATA after the caller's actual pair readback.
pub struct HistoryPairReadbackDataV1<const RECORD: usize> {
    /// Contains the exact observed fixed record bytes.
    pub record: [u8; RECORD],
    /// Contains the exact observed latest-head bytes.
    pub head: [u8; HEAD_BYTES],
    /// Contains the observed native NEXT.
    pub next: u64,
}

/// Borrows the exact observed record with copied head and NEXT DATA.
pub struct HistoryPairReadbackBytesDataV1<'journal> {
    /// Borrows the original materialized record without copying its allocation.
    pub record: &'journal [u8],
    /// Contains the exact observed latest-head bytes.
    pub head: [u8; HEAD_BYTES],
    /// Contains the observed native NEXT.
    pub next: u64,
}

/// Expands the sole pair comparison in the actual role's existing helper frame.
///
/// The inputs are existing lexical bindings. This introduces no callback,
/// argument carrier, allocation, native observation or owned return hop. The
/// caller's native owner remains responsible for names, full suffix, admission
/// and independent posts. A successful comparison grants no effect authority.
#[macro_export]
macro_rules! readback_create_storage_history_pair_bytes_data_v1 {
    (
        journal: $journal:ident,
        transaction: $transaction:ident,
        record: $record:ident,
        head: $head:ident,
        before_next: $before_next:ident,
        committed: $committed:ident,
        namespace: $namespace:path,
        boundary: $boundary:expr,
        result: $result:ident,
    ) => {{
        let [member, latest] = $transaction.records() else {
            return Err($boundary);
        };
        if member.namespace() != $namespace
            || latest.namespace() != $namespace
            || member.value() != Some($record)
            || latest.value() != Some($head.as_slice())
        {
            return Err($boundary);
        }
        let observed_record = $journal.get($namespace, member.key())
            .ok_or($boundary)?;
        let observed_head: [u8; $crate::domain_ledger::create_storage_history::HEAD_BYTES] = $journal.get($namespace, latest.key())
            .ok_or($boundary)?
            .try_into().map_err(|_| $boundary)?;
        let next = $journal.snapshot_sequence();
        if observed_record != $record || &observed_head != $head
            || $committed.commit_sequence.checked_add(1) != Some(next)
            || $before_next.checked_add(4) != Some(next)
        {
            return Err($boundary);
        }
        Ok($result { record: observed_record, head: observed_head, next })

    }};
}
