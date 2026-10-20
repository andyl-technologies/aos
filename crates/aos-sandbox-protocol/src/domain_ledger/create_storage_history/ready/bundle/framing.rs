//! Compiles the complete fixed framing invocation roster of the Ready codec.
//!
//! Counts conservatively include all reached fixed calls, even mutually
//! exclusive/completed ones. Each call reserves argument, local, return and
//! caller-comparison planes; one additional whole roster covers Result/return
//! construction. No count derives from hostile announced lengths. Quota rows
//! stream through the existing borrowed iterator and allocate no row model.

use std::mem::size_of;

use aos_sandbox_core::{ResourceDimension as D, ResourceVector, bounded_codec::BoundedReader};
use super::super::super::{HistoryErrorV1, KeyV1, LatestHeadV1, RecordEnvelopeV1};
use super::super::super::association::AcceptedAssociationDataV1;
use super::super::super::assignment_planned::AssignmentPlannedBodyDataV1;
use super::super::super::cache_held::{CacheHeldBodyDataV1, CacheHeldReceiptDataV1,
    CacheJournalDataV1, CachePhysicalDataV1};
use super::super::super::controller_intent::ControllerIntentBodyDataV1;
use super::super::super::source_held::{SourceHeldBodyDataV1, SourceHeldReceiptDataV1};
use super::{IntentNativeReceiptDataV1, ReadyBundleDataV1};
use crate::cache_state::complete_node_quotas::CompleteNodeQuotaRowsDataV1;
use crate::domain_ledger::{protected_names::ProtectedJournalNamesV1,
    resource_bank::{AccountHead, ResourceBankDataError}};

// Complete decode -> encoded_bytes -> require_history_association roster:
// eleven record decodes; three each Source/Cache body decodes; seven latest
// heads; fifteen Cache journal and three physical subdecodes. Reader upper64
// includes every one of those plus top/Intent/receipts/associations/assignment.
// Four per-call planes cover arguments, locals, return and outer comparison.
const PLANES: usize = 4;
const RECORD_CALLS: usize = 11;
const SOURCE_BODY_CALLS: usize = 3;
const CACHE_BODY_CALLS: usize = 3;
const HEAD_CALLS: usize = 7;
const CACHE_JOURNAL_CALLS: usize = 15;
const CACHE_PHYSICAL_CALLS: usize = 3;
const READER_CALLS: usize = 64;

#[allow(dead_code)]
struct FixedFramingInvocationRosterV1 {
    ready: [ReadyBundleDataV1<'static>; PLANES],
    fields: [[&'static [u8]; 25]; 2],
    intent: [ControllerIntentBodyDataV1<'static>; PLANES],
    intent_fields: [[&'static [u8]; 11]; 2],
    native: [IntentNativeReceiptDataV1; PLANES],
    records: [RecordEnvelopeV1<'static>; PLANES * RECORD_CALLS],
    keys: [KeyV1; PLANES * 32],
    heads: [LatestHeadV1; PLANES * HEAD_CALLS],
    source_receipts: [SourceHeldReceiptDataV1<'static>; PLANES],
    source_bodies: [SourceHeldBodyDataV1; PLANES * SOURCE_BODY_CALLS],
    cache_receipts: [CacheHeldReceiptDataV1<'static>; PLANES],
    cache_bodies: [CacheHeldBodyDataV1; PLANES * CACHE_BODY_CALLS],
    cache_journals: [CacheJournalDataV1; PLANES * CACHE_JOURNAL_CALLS],
    cache_physical: [CachePhysicalDataV1; PLANES * CACHE_PHYSICAL_CALLS],
    associations: [AcceptedAssociationDataV1; PLANES * 16],
    association_encoded: [[u8; 192]; PLANES * 4],
    named: [ProtectedJournalNamesV1; PLANES * 32],
    name_encoded: [[u8; 48]; PLANES * 32],
    planned: [AssignmentPlannedBodyDataV1<'static>; PLANES],
    bank: [Result<AccountHead, ResourceBankDataError>; PLANES],
    vectors: [ResourceVector; PLANES * 8],
    quotas: [CompleteNodeQuotaRowsDataV1<'static>; PLANES],
    quota_iterator: [std::slice::ChunksExact<'static, u8>; PLANES],
    readers: [BoundedReader<'static, HistoryErrorV1>; PLANES * READER_CALLS],
    hashes: [sha2::Sha256; PLANES * 4],
    digest_return: [[u8; 32]; PLANES * 8],
    results: [Result<(), HistoryErrorV1>; PLANES * 64],
}

pub(super) fn receiving_demand_v1() -> Option<ResourceVector> {
    let memory = size_of::<FixedFramingInvocationRosterV1>().checked_mul(2)?;
    // These borrowed framing views and fixed codec temporaries create no
    // resident namespace entries. Their complete byte peak remains prepaid.
    Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).ok()?))
}
