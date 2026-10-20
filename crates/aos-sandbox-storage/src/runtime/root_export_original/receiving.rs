//! Prices the actual saved catalog and compiled root-export custody.
//!
//! This arithmetic performs no IO, parser growth, authority acquisition or
//! ledger mutation. The real same-original lender consumes it before the upper
//! header allocation and before fixed Host capture, accept or native preview.

use super::*;
use aos_sandbox_core::{AccountingError, ResourceDimension as D};

pub(in crate::runtime) struct RootExportRepresentationV2 {
    pub(in crate::runtime) upper_bytes: usize,
    pub(in crate::runtime) saved_catalog_bytes: usize,
    pub(in crate::runtime) catalog_entries: usize,
    pub(in crate::runtime) catalog_native_files: usize,
}

impl RootExportRepresentationV2 {
    pub(in crate::runtime) fn from_runtime_v2(runtime: &StorageBrokerRuntime)
        -> Result<Self, AccountingError>
    {
        let overflow = || AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes };
        let catalog = runtime.inventory_retention_demand_v1()?;
        // Both before/after inventories and their rooted publication readbacks
        // survive until the descriptor send and all independent posts finish.
        // The existing sole supplier includes the actual saved State/workspace
        // row model and marker/file bound; it is not a raw-prefix multiplier.
        let saved_catalog_bytes = usize::try_from(catalog.get(D::MemoryBytes))
            .map_err(|_| overflow())?.checked_mul(2).ok_or_else(overflow)?;
        // Before/after inventory models describe the same actual catalog
        // keyspace. Their overlapping copies are byte/native costs below,
        // not additional namespace entries.
        let catalog_entries = usize::try_from(catalog.get(D::MetadataEntries))
            .map_err(|_| overflow())?;
        let native_files = usize::try_from(catalog.get(D::OpenFiles))
            .map_err(|_| overflow())?.checked_mul(2).ok_or_else(overflow)?;
        let catalog_native_files = native_files.checked_add(
            Pair::MAXIMUM_RETAINED_FILES_V1.checked_mul(4).ok_or_else(overflow)?,
        ).ok_or_else(overflow)?;
        // Include body, constructor/result carriers, Box allocation header and
        // alignment, all four actual retained paired-clock reservoirs, and the
        // fixed kernel/protocol diagnostic/control scratch before construction.
        let upper_bytes = std::mem::size_of::<RootExportOriginalV2>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<Box<RootExportOriginalV2>>()))
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<usize>()))
            .and_then(|bytes| bytes.checked_add(std::mem::align_of::<RootExportOriginalV2>()))
            .and_then(|bytes| bytes.checked_add(Pair::dominant_requested_bytes_v1()?.checked_mul(4)?))
            .and_then(|bytes| bytes.checked_add(64 * 1024))
            .ok_or_else(overflow)?;
        Ok(Self { upper_bytes, saved_catalog_bytes, catalog_entries, catalog_native_files })
    }
}
