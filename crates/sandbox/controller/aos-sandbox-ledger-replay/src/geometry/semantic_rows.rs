//! Retains the existing all-family row and encoded representation recipe.

use std::mem::size_of;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::framing::HEADER_BYTES;
use aos_sandbox_protocol::domain_ledger::capacity_family::family::CanonicalCapacityFamily;
use aos_sandbox_protocol::mount_source_acquisition_state::{
    StoredRecordV2, InventoryCorrelationV2, ProjectionEntryV2, ProviderAttemptStateV2,
    native_held_completion::{RootNativeHeldSidecarV1, RootNativeHeldSidecarV2,
                            RootNativeReconstructedCutV1},
};
use aos_sandbox_source_provider_protocol::native_held_completion::{
    MAXIMUM_NATIVE_HELD_RETAINED_CONTROLS_V1,
    frame::{NativeHeldSectionV1, SignedNativeHeldControlV1},
};

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as JournalError;
use crate::replay::phase_records::{
    RootFirstSourceSuccessorIntentV2, RootFirstSourceSuccessorFloorV2, SourceFirstSuccessorReceiptV2, SourceFirstSuccessorPendingV2, SourceFirstSuccessorAckV2,
};
use crate::replay::root_genesis_records::{
    RootSourceGenesisIntentRecordV1, SourceHierarchyFloorRecordV1,
};


/// Returns the original closed list of actual canonical row widths.
///
/// # Errors
/// Refuses overflow in nested native-history archive representation.
pub fn native_semantic_row_widths_v1() -> Result<[usize; 8], JournalError> {
    let invalid = || JournalError::LimitExceeded("native semantic row geometry");
    let sections = 3usize.checked_mul(size_of::<NativeHeldSectionV1>()).ok_or_else(invalid)?;
    let controls = MAXIMUM_NATIVE_HELD_RETAINED_CONTROLS_V1.checked_mul(
        size_of::<SignedNativeHeldControlV1>().checked_add(sections).ok_or_else(invalid)?,
    ).ok_or_else(invalid)?;
    let sidecars = size_of::<RootNativeHeldSidecarV1>()
        .checked_add(size_of::<RootNativeHeldSidecarV2>())
        .and_then(|bytes| bytes.checked_add(controls)).ok_or_else(invalid)?;
    let cut = size_of::<RootNativeReconstructedCutV1>()
        .checked_add(4usize.checked_mul(size_of::<StoredRecordV2>()).ok_or_else(invalid)?)
        .ok_or_else(invalid)?;
    let genesis = size_of::<RootSourceGenesisIntentRecordV1>()
        .checked_add(size_of::<SourceHierarchyFloorRecordV1>())
        .and_then(|bytes| bytes.checked_add(size_of::<crate::replay::source_tree_genesis::SourceGenesisPendingV1>()))
        .and_then(|bytes| bytes.checked_add(size_of::<crate::replay::source_tree_genesis::SourceGenesisAckV1>()))
        .and_then(|bytes| bytes.checked_add(size_of::<crate::genesis::SourceTreeGenesisReceiptV1>()))
        .ok_or_else(invalid)?;
    let successor = size_of::<RootFirstSourceSuccessorIntentV2>()
        .checked_add(size_of::<RootFirstSourceSuccessorFloorV2>())
        .and_then(|bytes| bytes.checked_add(size_of::<SourceFirstSuccessorReceiptV2>()))
        .and_then(|bytes| bytes.checked_add(size_of::<SourceFirstSuccessorPendingV2>()))
        .and_then(|bytes| bytes.checked_add(size_of::<SourceFirstSuccessorAckV2>()))
        .ok_or_else(invalid)?;
    Ok([
        size_of::<CanonicalCapacityFamily>(),
        size_of::<StoredRecordV2>(),
        sidecars,
        cut,
        genesis,
        successor,
        size_of::<crate::replay::controller_source_successor_issuance::RetainedIssuanceDataV2>(),
        size_of::<InventoryCorrelationV2>() + size_of::<ProjectionEntryV2>()
            + size_of::<ProviderAttemptStateV2>(),
    ])
}

/// Bounds the original matching map planes and encoded backing.
///
/// # Errors
/// Refuses checked representation arithmetic overflow.
pub fn semantic_representation_demand_v1(
    encoded: usize,
    rows: usize,
) -> Result<ResourceVector, JournalError> {
    let invalid = || JournalError::LimitExceeded("native semantic receiving demand");
    let mut row = 0usize;
    for width in native_semantic_row_widths_v1()? {
        row = row.max(width);
    }
    let links = size_of::<([u8; 32], Vec<u8>, Vec<u8>, [usize; 3])>();
    let cells = rows.checked_mul(32).ok_or_else(invalid)?;
    let memory = row.checked_add(links)
        .and_then(|width| cells.checked_mul(width))
        .and_then(|bytes| bytes.checked_add(encoded.checked_mul(128)?))
        .and_then(|bytes| bytes.checked_add(
            aos_sandbox_protocol::public_api::projection::dependencies::
                // Proposed Execution and one current Attachment coexist in
                // the shared assignment-consumer barrier. Both complete typed
                // decoders fit the same actual full-prefix byte upper bound.
                projection_dependencies_receiving_bytes_v2(encoded)?.checked_mul(2)?,
        ))
        .and_then(|bytes| bytes.checked_add(
            aos_sandbox_protocol::domain_ledger::provisioning_resources::
                provisioning_links_decoding_receiving_bytes_v1(encoded)?,
        ))
        .ok_or_else(invalid)?;
    Ok(ResourceVector::ZERO
        .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| invalid())?)
        .with(D::MetadataEntries, u64::try_from(cells).map_err(|_| invalid())?))
}
