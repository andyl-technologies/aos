//! Prices the shared canonical catalog source before retained model growth.
//!
//! Both Start and periodic maintenance use the same history, canonical decoder
//! and sealed transfer recipe. The caller contributes its actual compiled
//! inline layouts as DATA; only its genuine native loan can admit the result.

use super::*;
use crate::ResourceReservationErrorV1;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::immutable_file::SealedReadOnlyCredentialCreateOriginalsV1;

const TRANSFER_NAME: &str = "aos-host-catalog";

pub(super) fn canonical_source_receiving_demand_v2(
    controller: &Journal,
    catalog_bytes: usize,
    inline_bytes: usize,
) -> Result<ResourceVector, ResourceReservationErrorV1> {
    canonical_source_history_receiving_demand_v2(controller, inline_bytes)?
        .checked_add(canonical_source_output_receiving_demand_v2(catalog_bytes)?)
        .map_err(|_| ResourceReservationErrorV1::Conflict)
}

pub(super) fn canonical_source_history_receiving_demand_v2(
    controller: &Journal,
    inline_bytes: usize,
) -> Result<ResourceVector, ResourceReservationErrorV1> {
    let closed = || ResourceReservationErrorV1::Conflict;
    let decode = aos_sandbox_protocol::host_catalog_snapshot::host_catalog_canonical_decode_receiving_bytes_v2;
    let history = controller
        .records(RecordNamespace::HostCatalogReconciliation)
        .try_fold(0_usize, |total, (key, value)| {
            let models = decode(value.len())
                .and_then(|bytes| bytes.checked_mul(4))
                .and_then(|bytes| bytes.checked_add(value.len().checked_mul(4)?))
                .and_then(|bytes| bytes.checked_add(key.len().checked_mul(2)?))
                .ok_or_else(closed)?;
            total.checked_add(models).ok_or_else(closed)
        })?;
    let memory = inline_bytes
        .checked_add(history)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(closed)?;
    controller
        .create_storage_semantic_append_demand_v1()?
        .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, memory))
        .map_err(Into::into)
}

// The caller measures the existing canonical writer only after its projection
// and counting carriers are admitted. Output, decoder/readback, draft and the
// one actual sealed transfer are then admitted before those allocations/IO.
pub(super) fn canonical_source_output_receiving_demand_v2(
    catalog_bytes: usize,
) -> Result<ResourceVector, ResourceReservationErrorV1> {
    let closed = || ResourceReservationErrorV1::Conflict;
    let decode = aos_sandbox_protocol::host_catalog_snapshot::host_catalog_canonical_decode_receiving_bytes_v2;
    let seal = SealedReadOnlyCredentialCreateOriginalsV1::receiving_footprint_v1(
        TRANSFER_NAME.len(),
        catalog_bytes,
    )
    .ok_or_else(closed)?;
    let memory = decode(catalog_bytes)
        .and_then(|bytes| bytes.checked_mul(4))
        .and_then(|bytes| {
            bytes.checked_add(
                catalog_bytes
                    .checked_add(FIXED_RECORD_BYTES)?
                    .checked_mul(12)?,
            )
        })
        .and_then(|bytes| bytes.checked_add(seal.memory_bytes))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(closed)?;
    let files = u64::try_from(seal.open_files).map_err(|_| closed())?;
    Ok(ResourceVector::ZERO
        .with(D::MemoryBytes, memory)
        .with(D::OpenFiles, files))
}

// This pays the complete ordinary projection, including nonempty attachment
// handle vectors. The existing Start recipe uses the same model engine for its
// closed no-slot profile; real current C semantic histories are separately
// joined by that same supplier before any validation or row collection.
pub(super) fn maintenance_projection_receiving_demand_v2(
    controller: &Journal,
    storage: &ValidatedStorageInventory,
    network: &ValidatedNetworkInventory,
    mounts: &ValidatedMountInventory,
    destinations: &ValidatedDestinationSlotInventory,
) -> Result<ResourceVector, JournalError> {
    let common = super::start_projection::start_projection_receiving_demand_data_v2(
        controller,
        storage,
        network,
        destinations,
    )?;
    let handles = mounts
        .mounts()
        .len()
        .checked_mul(std::mem::size_of::<[u8; 32]>())
        .and_then(|bytes| bytes.checked_mul(8))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(JournalError::JournalTooLarge)?;
    common
        .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, handles))
        .map_err(JournalError::ReceivingAccounting)
}

pub(super) fn maintenance_no_slots_projection_receiving_demand_v2(
    controller: &Journal,
    storage: &ValidatedStorageInventory,
    network: &ValidatedNetworkInventory,
    destinations: &ValidatedDestinationSlotInventory,
) -> Result<ResourceVector, JournalError> {
    let counting =
        aos_sandbox_protocol::host_catalog_snapshot::host_catalog_counting_carrier_bytes_v2()
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
    super::start_projection::start_projection_receiving_demand_data_v2(
        controller,
        storage,
        network,
        destinations,
    )?
    .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, counting))
    .map_err(JournalError::ReceivingAccounting)
}
