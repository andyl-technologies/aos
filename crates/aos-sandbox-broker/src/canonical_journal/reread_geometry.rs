//! Shares the existing physical-prefix replay byte arithmetic.
//!
//! These three terms describe logical native work only. They do not price an
//! owning role's current state, Source cache, challenge history or complete
//! constructor, and supply neither allocation policy nor native authority.

use aos_sandbox_journal::framing::HEADER_BYTES;

use super::{JournalLimits, JournalRecord};

/// Describes the existing canonical parser's three logical byte terms.
pub struct CanonicalRereadWireWorkDataV1 {
    /// Covers replay/prospective maps, IDs, namespaces and the private index.
    pub replay_indexes: usize,
    /// Covers reached pending record headers within the actual physical prefix.
    pub pending_records: usize,
    /// Covers simultaneous frame growth and the canonical fixed read scratch.
    pub frame_payload: usize,
}

/// Computes the existing ordinary reread recipe from its physical prefix.
///
/// Returns None on checked arithmetic or canonical frame-bound failure.
/// This is nonauthorizing DATA; complete role, semantic and retained-owner
/// costs remain with the actual caller before it enters its existing parser.
#[must_use]
pub fn ordinary_reread_wire_work_data_v1(
    physical: usize,
    limits: JournalLimits,
) -> Option<CanonicalRereadWireWorkDataV1> {
    let historical_frames = physical / HEADER_BYTES;
    let historical_rows = historical_frames.min(limits.maximum_materialized_records);
    let historical_transactions = historical_frames.min(limits.maximum_transactions);
    let map_entry = std::mem::size_of::<((aos_sandbox_core::RecordNamespace, Vec<u8>), Vec<u8>)>();
    let idempotency_entry = std::mem::size_of::<(
        Vec<u8>,
        aos_sandbox_protocol::domain_ledger::readonly::IdempotencyDecisionV1,
    )>();

    let replay_indexes = physical
        .checked_mul(3)
        .and_then(|bytes| {
            bytes.checked_add(historical_rows.checked_mul(map_entry)?.checked_mul(2)?)
        })
        .and_then(|bytes| bytes.checked_add(historical_rows.checked_mul(idempotency_entry)?))
        .and_then(|bytes| bytes.checked_add(historical_transactions.checked_mul(16)?))
        .and_then(|bytes| {
            bytes.checked_add(
                historical_frames
                    .checked_mul(std::mem::size_of::<aos_sandbox_core::RecordNamespace>())?,
            )
        })?;
    let pending_records = historical_frames
        .min(limits.maximum_records_per_transaction)
        .checked_mul(std::mem::size_of::<JournalRecord>())?;
    let advertised_payload = limits.maximum_record_bytes.checked_add(7)?;
    let frame_payload = aos_sandbox_journal::framing::reached_frame_read_memory_bound_v1(
        advertised_payload,
        physical,
    )
    .ok()?;

    Some(CanonicalRereadWireWorkDataV1 {
        replay_indexes,
        pending_records,
        frame_payload,
    })
}
