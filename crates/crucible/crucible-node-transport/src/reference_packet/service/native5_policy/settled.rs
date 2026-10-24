//! Preserves the complete native immutable policy as historical DATA.
//!
//! The new representation uses explicit nulls for every absent selected owner.
//! Existing selected policy fields are not inferred from a profile label, and
//! historical private policy bytes never install a fresh registrar or boot.

use super::*;
use crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes;
use serde::{Serialize, Serializer, ser::SerializeStruct};

struct PolicyHistory<'a>(&'a Native5Policy);

impl Serialize for PolicyHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let Native5PolicyData {
            selection,
            coordinator,
            definition,
            connected,
            capture_profile,
            confirmation_selection,
            confirmation_definition,
            ack_emitter_selection,
            ack_emitter_definition,
            native_codec_metadata_extent,
            protocol_metadata_limits,
            complete_restore_selection,
            complete_restore_definitions,
            complete_restore_transfer_definitions,
            restore_input_emitter_selection,
            restore_input_emitter_definition,
            capture_allocation_selection,
            capture_allocation_definitions,
            fresh_restore_allocation_selection,
            fresh_restore_allocation_definitions,
        } = &self.0.data;
        let mut state = serializer.serialize_struct("NativePolicyHistory17", 21)?;
        state.serialize_field(
            "schema",
            "source-private.native5-policy-restored-settled/17",
        )?;
        state.serialize_field("selection", selection)?;
        state.serialize_field(
            "coordinator",
            &(
                &coordinator.reference,
                coordinator.bytes.allocation_capacity(),
                BorrowedCompactBytes::new(coordinator.bytes.as_slice()),
            ),
        )?;
        state.serialize_field("definition", definition)?;
        state.serialize_field("connected", connected)?;
        state.serialize_field("capture_profile", capture_profile)?;
        state.serialize_field("confirmation_selection", confirmation_selection)?;
        state.serialize_field("confirmation_definition", confirmation_definition)?;
        state.serialize_field("ack_emitter_selection", ack_emitter_selection)?;
        state.serialize_field("ack_emitter_definition", ack_emitter_definition)?;
        state.serialize_field("native_codec_metadata_extent", native_codec_metadata_extent)?;
        state.serialize_field("protocol_metadata_limits", protocol_metadata_limits)?;
        state.serialize_field("complete_restore_selection", complete_restore_selection)?;
        state.serialize_field("complete_restore_definitions", complete_restore_definitions)?;
        state.serialize_field(
            "complete_restore_transfer_definitions",
            complete_restore_transfer_definitions,
        )?;
        state.serialize_field(
            "restore_input_emitter_selection",
            restore_input_emitter_selection,
        )?;
        state.serialize_field(
            "restore_input_emitter_definition",
            restore_input_emitter_definition,
        )?;
        state.serialize_field("capture_allocation_selection", capture_allocation_selection)?;
        state.serialize_field(
            "capture_allocation_definitions",
            capture_allocation_definitions,
        )?;
        state.serialize_field(
            "fresh_restore_allocation_selection",
            fresh_restore_allocation_selection,
        )?;
        state.serialize_field(
            "fresh_restore_allocation_definitions",
            fresh_restore_allocation_definitions,
        )?;
        state.end()
    }
}

impl Native5Policy {
    /// Borrows the complete immutable policy without authenticating a live route.
    pub(crate) fn borrowed_settled_history_data(&self) -> impl Serialize + '_ {
        PolicyHistory(self)
    }

    /// Counts defining fixed native policy serializer headers.
    pub(crate) const fn settled_history_counter_scratch_data() -> usize {
        std::mem::size_of::<PolicyHistory<'static>>()
            + BorrowedCompactBytes::requested_serialization_scratch_bytes()
            + std::mem::size_of::<Result<(), ProviderError>>()
    }
}
