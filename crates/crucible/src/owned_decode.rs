//! Shared original resource custody and typed JSON artifact decoding.
//!
//! The storage substrate owns the finite account used by campaign and compact
//! scenario codecs. This facade adds the serde visitor adapter without giving
//! storage a dependency on model formats or JSON.

pub use crucible_cas::owned_decode::{
    DecodeAdmissionError, DecodeBudget, DecodeCustody, DecodeDescriptorLoan,
    DecodeResourceAuthority, DecodeScope, DecodeScratch, ResourceLoan, ResourceLoanSlot,
    charge_array, charge_btree_entry, charge_btree_set_entry, charge_bytes, current_budget,
    current_child_budget, current_custody, reserve_vec,
};

mod serde_budget;
pub use serde_budget::deserialize_with_budget;
pub use serde_budget::from_json_slice;

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
