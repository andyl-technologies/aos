//! Shared original resource custody and typed artifact encoding and decoding.
//!
//! The storage substrate owns the finite account used by campaign and compact
//! scenario codecs. This facade adds scoped JSON visitors, borrowed-seed CBOR
//! decoding, and bounded output adapters without giving storage a dependency
//! on model formats or serialization libraries. Format-specific parser and
//! custom-visitor allocations still require their own original purposes.

pub use crucible_cas::owned_decode::{
    DecodeAdmissionError, DecodeBudget, DecodeCustody, DecodeDescriptorLoan,
    DecodeResourceAuthority, DecodeScope, DecodeScratch, ResourceLoan, ResourceLoanSlot,
    charge_array, charge_btree_entry, charge_btree_set_entry, charge_bytes, current_budget,
    current_child_budget, current_custody, reserve_vec,
};

mod bounded_visitors;
pub use bounded_visitors::{deserialize_prepaid_map, deserialize_prepaid_sequence};

mod serde_budget;
pub use serde_budget::deserialize_with_budget;
pub use serde_budget::{from_json_slice, from_json_slice_closed};

/// Owns the sealed controlled service JSON schemas.
pub mod json_profiles;

mod json_diagnostic;
pub use json_diagnostic::{ClosedJsonError, JsonProfileRefusal, PaidJsonError};

mod cbor_encode;
pub use cbor_encode::{CborEncodeError, to_cbor_vec_prefixed};

mod cbor_decode;
pub use cbor_decode::{from_cbor_slice, from_cbor_slice_with_seed};

mod json_encode;
pub use json_encode::{to_json_vec, to_json_vec_bounded};

mod output_scope;
pub use output_scope::{require_current_child_budget, require_current_custody};

mod text_encode;
pub use text_encode::display_string;

#[cfg(test)]
mod tests;

mod retained_vec;
pub use retained_vec::grow_retained_vec;

#[cfg(feature = "test-support")]
#[doc(hidden)]
pub use json_diagnostic::closed_json_diagnostic_extent_for_test;
