//! Supplies actual private native owner layouts to the inert shared report.
//!
//! Private compiled layouts remain in their defining CompleteBirth supplier.
//! The three calls retain their original order and failures; moving their
//! numeric reports supplies no admission, Source or native constructor rights.

use crate::ProviderError;
use crucible_source_birth_data::profile::reference_packet::service::native_startup::fixed_layout::NativeBirthFixedOwnerLayoutData;
use std::mem::size_of;

pub(super) fn project(maximum: usize) -> Result<NativeBirthFixedOwnerLayoutData, ProviderError> {
    let shared_headers_bytes =
        super::super::super::server::complete::birth::original_native_birth_shared_layout_bytes()?;
    let phase_headers_bytes =
        super::super::super::server::complete::birth::original_native_birth_phase_layout_bytes()?;
    let context_bank_bytes = super::sum(
        &super::super::super::ack_emitter::ORIGINAL_ACK_CONTEXT_BANK_BYTES,
        maximum,
    )?;

    Ok(NativeBirthFixedOwnerLayoutData {
        shared_headers_bytes,
        phase_headers_bytes,
        context_bank_bytes,
    })
}

// Only this new fixed adapter's actual payload and return headers are added.
// Existing private-layout calculations and their old controls remain upper.
pub(super) const fn counter_scratch_data() -> usize {
    // The supplier initializes the payload, then returns its actual Result.
    size_of::<NativeBirthFixedOwnerLayoutData>()
        + size_of::<Result<NativeBirthFixedOwnerLayoutData, ProviderError>>()
        // The real caller receives the Result and retains its successful data.
        + size_of::<Result<NativeBirthFixedOwnerLayoutData, ProviderError>>()
        + size_of::<NativeBirthFixedOwnerLayoutData>()
}

#[cfg(test)]
#[path = "fixed_layout/tests.rs"]
mod tests;
