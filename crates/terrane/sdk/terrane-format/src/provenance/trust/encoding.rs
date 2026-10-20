//! Serializes legacy fields and explicit ordinary recorded interpretation claims.
//!
//! ```text
//! [1, view, domain, selector-bytes, baseline-or-null, min-chunk-size]
//! [2, view, domain, selector-bytes, baseline-or-null, min-chunk-size,
//!     selected-evidence-bytes]
//! [3, view, domain, selector-bytes, baseline-or-null, min-chunk-size,
//!     selected-evidence-bytes-or-null,
//!     [original-view-root, property-revision, behavioral-names, later-names]]
//! ```

use crate::{cbor, identity::Digest};
use alloc::vec::Vec;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod recorded_tests;

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

/// Borrows explicit ordinary recorded claims without creating an evaluator.
pub(super) struct RecordedContextFields<'a> {
    /// Existing context fields; empty selected bytes mean absence.
    pub(super) context: ContextFields<'a>,
    /// Original immutable view root before fold preprocessing.
    pub(super) root: &'a Digest,
    /// Registered property semantic revision.
    pub(super) revision: u64,
    /// Exact sorted behavioral vocabulary.
    pub(super) behavioral: &'a [&'a str],
    /// Sorted disjoint claimed preservation vocabulary.
    pub(super) later: &'a [&'a str],
}

/// Encodes the mandatory v3 tuple for an explicitly recorded interpretation.
///
/// This checks structural claims only; callers independently establish the
/// selected root association and trusted later registration.
///
/// # Errors
/// Rejects malformed selectors, unsupported revisions, invalid vocabularies,
/// oversized fences or inconsistent selected evidence.
pub(super) fn encode_recorded(
    fields: RecordedContextFields<'_>,
) -> Result<Vec<u8>, super::Rejected> {
    if fields.behavioral.len() > 35 || fields.later.len() > 65536 {
        return Err(super::Rejected);
    }
    for (names, limit) in [(fields.behavioral, 35 * 255), (fields.later, 65536)] {
        let mut total = 0usize;
        for (index, name) in names.iter().enumerate() {
            total = total.checked_add(name.len()).ok_or(super::Rejected)?;
            if name.is_empty()
                || name.len() > 255
                || total > limit
                || index > 0 && names[index - 1].as_bytes() >= name.as_bytes()
            {
                return Err(super::Rejected);
            }
        }
    }
    let legacy = encode(fields.context);
    let decoded = super::context::decode(&legacy)?;
    let mut bytes = Vec::new();
    cbor::write_array(&mut bytes, 8);
    cbor::write_uint(&mut bytes, 3);
    // Both legacy tuple prefixes use one-byte array and version headers.
    // Reuse only the common five fields, excluding optional side evidence.
    let mut prefix = encode(ContextFields {
        view: decoded.view.try_into().map_err(|_| super::Rejected)?,
        domain: decoded.domain,
        selector: decoded.selector,
        baseline: decoded.baseline,
        minimum: decoded.minimum,
        selected: &[],
    });
    bytes.extend_from_slice(&prefix.split_off(2));
    if let Some(selected) = decoded.selected {
        cbor::write_bytes(&mut bytes, selected);
    } else {
        bytes.push(0xf6);
    }
    cbor::write_array(&mut bytes, 4);
    cbor::write_bytes(&mut bytes, fields.root);
    cbor::write_uint(&mut bytes, fields.revision);
    for names in [fields.behavioral, fields.later] {
        cbor::write_array(&mut bytes, names.len());
        for name in names {
            cbor::write_text(&mut bytes, name);
        }
    }
    super::context::validate(&bytes)?;
    Ok(bytes)
}
