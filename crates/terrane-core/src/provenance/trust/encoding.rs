//! Serializes borrowed context fields after the caller checks the immutable view.
//!
//! ```text
//! [1, view, domain, selector-bytes, baseline-or-null, min-chunk-size]
//! [2, view, domain, selector-bytes, baseline-or-null, min-chunk-size,
//!     selected-evidence-bytes]
//! ```

use crate::{cbor, identity::Digest};
use alloc::vec::Vec;

#[cfg(test)]
mod tests;

/// Borrows ordinary encoding fields, without constructing a trust evaluator.
pub(super) struct ContextFields<'a> {
    /// Selected immutable commit identity.
    pub(super) view: &'a Digest,
    /// Guard-selected effective disclosure domain.
    pub(super) domain: &'a str,
    /// Complete canonical selector bytes.
    pub(super) selector: &'a [u8],
    /// Optional configured baseline, retaining an empty present value.
    pub(super) baseline: Option<&'a str>,
    /// History's configured minimum chunk size.
    pub(super) minimum: u64,
    /// Complete canonical selected rows, or empty bytes to select v1.
    pub(super) selected: &'a [u8],
}

/// Encodes the exact v1 or v2 projection selected by evidence presence.
pub(super) fn encode(fields: ContextFields<'_>) -> Vec<u8> {
    let has_selected = !fields.selected.is_empty();
    let mut bytes = Vec::new();
    cbor::write_array(&mut bytes, if has_selected { 7 } else { 6 });
    cbor::write_uint(&mut bytes, if has_selected { 2 } else { 1 });
    cbor::write_bytes(&mut bytes, fields.view);
    cbor::write_text(&mut bytes, fields.domain);
    cbor::write_bytes(&mut bytes, fields.selector);
    if let Some(baseline) = fields.baseline {
        cbor::write_text(&mut bytes, baseline);
    } else {
        bytes.push(0xf6);
    }
    cbor::write_uint(&mut bytes, fields.minimum);
    if has_selected {
        cbor::write_bytes(&mut bytes, fields.selected);
    }
    bytes
}
