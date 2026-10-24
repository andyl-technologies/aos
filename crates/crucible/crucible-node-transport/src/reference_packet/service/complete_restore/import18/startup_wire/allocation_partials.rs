//! Names the unchanged native allocation row's actual three decoder fields.
//!
//! Shared new18 parser companions select this one implementation. Its real
//! U64 field DAG supplies layout and diagnostics DATA, never native allowance.

use crate::reference_packet::continuation_models::serde_partials::decoder_struct;
use crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow;

decoder_struct!(PacketNativeStartupAllocationRow {
    retained_requested_bytes,
    maximum_simultaneous_transient_bytes,
    declared_counter_scratch_bytes,
});
