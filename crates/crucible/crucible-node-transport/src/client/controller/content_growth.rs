//! Projects internal content growth from the actual retained Controller custody.
//!
//! The projection preserves local quotas and separately admits its enclosing
//! counter. Existing owners and the rest of SDK exchange work remain separate.

use super::*;
use crate::client::{ClientContent, OriginalClientContentGrowthStorageData};
use std::mem::size_of;

impl CnpController {
    /// Quotes internal content growth at this Controller's actual local ceilings.
    ///
    /// Reads its original private content custody without copying a store or
    /// replacing its quotas with negotiated limits. The result prices borrowed
    /// installation and incoming transfer growth, including this defining quote's
    /// fixed counter. Existing content, caller-owned input buffers and reference
    /// strings, wire decoding, typed DTOs, journals, correlation and whole-Source
    /// observation growth still require independent funding.
    ///
    /// This DATA authenticates no Source, live registration, current checkpoint
    /// or phase, and issues no grant. It remains available for a fenced owner's
    /// sticky partials. The enclosing original Source/Core action must admit this
    /// counter before entry and retain its complete reservation independently.
    ///
    /// # Errors
    /// Refuses unsupported layouts, checked overflow or a complete content
    /// retained/transient/scratch row above the independent supplied restriction.
    pub fn original_content_internal_growth_storage_data(
        &self,
        maximum: usize,
    ) -> Result<OriginalClientContentGrowthStorageData, ProviderError> {
        self.custody
            .content()
            .original_internal_growth_storage_data(maximum)?
            .with_additional_counter_storage_data(wrapper_counter_scratch_data(), maximum)
    }

    /// Names the actual content and enclosing Controller quote's fixed headers.
    pub fn original_content_internal_growth_counter_scratch_data() -> usize {
        ClientContent::original_internal_growth_counter_scratch_data()
            + wrapper_counter_scratch_data()
    }
}

fn wrapper_counter_scratch_data() -> usize {
    size_of::<&CnpController>()
        + size_of::<&ClientCustody>()
        + 2 * size_of::<OriginalClientContentGrowthStorageData>()
        + 2 * size_of::<Result<OriginalClientContentGrowthStorageData, ProviderError>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<&[usize]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<[usize; 8]>()
}
