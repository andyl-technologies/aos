//! Bounds native error projections around the canonical Source phase decoder.

use std::mem::size_of;
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use aos_sandbox_ledger_replay::replay::phase_records::{
    SourceFirstSuccessorPendingV2, SourceFirstSuccessorReceiptV2,
    SourceFirstSuccessorAckV2, RootFirstSourceSuccessorFloorV2,
    ControllerFirstSourceSuccessorAnchoredV2,
};

pub(crate) fn first_source_successor_fixed_codec_peak_bytes_v1() -> Option<usize> {
    let native_results = size_of::<Result<SourceFirstSuccessorPendingV2, SourceGenesisErrorV1>>()
        .checked_add(size_of::<Result<SourceFirstSuccessorReceiptV2, SourceGenesisErrorV1>>())?
        .checked_add(size_of::<Result<SourceFirstSuccessorAckV2, SourceGenesisErrorV1>>())?
        .checked_add(size_of::<Result<RootFirstSourceSuccessorFloorV2, SourceGenesisErrorV1>>())?
        .checked_add(size_of::<Result<ControllerFirstSourceSuccessorAnchoredV2, SourceGenesisErrorV1>>())?;
    aos_sandbox_ledger_replay::replay::phase_records::first_source_successor_fixed_codec_peak_bytes_v1()?
        .checked_add(native_results.checked_mul(2)?)
}
