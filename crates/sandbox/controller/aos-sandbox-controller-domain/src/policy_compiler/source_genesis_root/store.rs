//! Exercises the sole retained Root receipt comparison with real Source fixtures.
//!
//! Live fixed Authority opening, native pins/history/currentness and all Root
//! mutations now belong to the actual Policy native owner. These tests retain
//! the existing Source append/receipt/ACK fixture engine in its original crate.

use aos_sandbox_model::ObjectDigest;
use aos_sandbox_ledger_replay::genesis::SourceTreeGenesisReceiptV1;
use aos_sandbox_ledger_replay::replay::root_genesis_records::{RootSourceGenesisIntentRecordV1, SourceHierarchyFloorRecordV1};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;

fn require_receipt_matches_retained_root(
    receipt: &SourceTreeGenesisReceiptV1,
    intent: Option<&RootSourceGenesisIntentRecordV1>,
    floor: Option<&SourceHierarchyFloorRecordV1>,
    roles: ObjectDigest,
) -> Result<(), SourceGenesisErrorV1> {
    aos_sandbox_ledger_replay::replay::root_genesis_records::require_receipt_matches_retained_root_v1(
        receipt, intent, floor, roles,
    ).map_err(SourceGenesisErrorV1::from)
}

#[cfg(test)]
mod tests;
