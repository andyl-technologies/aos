//! Reports the original generic issuer decoder's actual compiled layout facts.
//!
//! These numbers describe typed slots and tree entries, never population caps,
//! complete requested-storage rows, native authority or a parsing permission.
//! The defining private Control/model types and their layout query remain upper.

/// Separates the three actual compiled layouts used by generic issuer decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IssuerDecodeLayoutData {
    /// Bounds one actual typed value/array slot across the owning decoders.
    pub maximum_typed_slot_bytes: usize,
    /// Bounds key-plus-value storage across their concrete decoder tree maps.
    pub maximum_tree_key_value_bytes: usize,
    /// Reports the largest actual alignment of those map keys and values.
    pub maximum_tree_entry_alignment: usize,
}
