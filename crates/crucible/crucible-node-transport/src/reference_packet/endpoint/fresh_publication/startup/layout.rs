//! Supplies actual Fresh headers without moving owner queries or admissions.
//!
//! Only the infallible sizeof facts are grouped. The real retained-attempt query
//! remains first in the original retained sum, and the defining fixed counter
//! remains after that sum. No private native definition moves into DATA.

use super::*;
use crucible_source_birth_data::profile::reference_packet::service::native_startup::fresh_publication_layout::FreshPublicationFixedLayoutData;

pub(super) const fn project() -> FreshPublicationFixedLayoutData {
    FreshPublicationFixedLayoutData {
        received_frame_bytes: size_of::<ReceivedFrame>(),
        request_body_bytes: size_of::<RequestBody>(),
        observe_result_bytes: size_of::<ObserveResult>(),
        control_reply_bytes: size_of::<super::super::super::super::control::PacketControlReply>(),
        content_slot_bytes: size_of::<(ContentRef, Vec<u8>)>(),
    }
}

pub(super) fn owner_bytes_data() -> usize {
    super::super::super::fresh_restore::original_fresh_report_owner_layout_data()
}

pub(super) fn counter_output_data() -> usize {
    original_fresh_report_startup_publication_counter_scratch_data()
}

// Every original defining counter term remains. These name only actual newly
// introduced windows; they are not allocation requests or compiler frame sizes.
pub(super) const fn counter_scratch_data() -> usize {
    // Supplier initializer, supplier owned return and caller-owned binding.
    size_of::<FreshPublicationFixedLayoutData>()
        + size_of::<FreshPublicationFixedLayoutData>()
        + size_of::<FreshPublicationFixedLayoutData>()
        // Retained-attempt and final-counter forwarding return values.
        + size_of::<usize>()
        + size_of::<usize>()
}

#[cfg(test)]
mod original;

#[cfg(test)]
mod tests;
