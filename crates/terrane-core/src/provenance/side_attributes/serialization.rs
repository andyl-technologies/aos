//! Serializes selected rows and borrowed side-evidence fields without authority.
//!
//! ```text
//! row = [view-location, name, domain, full-view-path, evidence]
//! evidence = [record, object, name, function, version, value-bytes,
//!             producer, witness-location, [producer-domain, full-path]]
//! ```

use super::{EntryLocation, SideAttributeKey};
use crate::{cbor, identity::Digest};
use alloc::vec::Vec;

#[cfg(test)]
mod tests;

/// Borrows ordinary wire fields extracted by the checked evidence holder.
pub(super) struct EvidenceFields<'a> {
    /// Exact canonical attribute-record identity.
    pub(super) record: &'a [u8],
    /// Object identity named by the attribute record.
    pub(super) object: &'a Digest,
    /// Registered attribute name.
    pub(super) name: &'a str,
    /// Record's producing function name.
    pub(super) function: &'a str,
    /// Record's producing function version.
    pub(super) version: &'a str,
    /// Complete canonical attribute value, retained inside a byte string.
    pub(super) value: &'a [u8],
    /// Originating producer commit identity.
    pub(super) producer: &'a Digest,
    /// Checked carrying witness, which may differ from an unsigned producer.
    pub(super) location: &'a EntryLocation,
    /// Effective domain of the producer's witness.
    pub(super) producer_domain: &'a str,
    /// Full path of the producer's witness.
    pub(super) producer_path: &'a [u8],
}

/// Serializes matching rows from the caller's sorted unique map iteration.
///
/// The private caller supplies a `BTreeMap` iterator, so filtering retains the
/// registered tuple ordering without an additional sort or copied key strings.
pub(super) fn selected<'a, T: 'a>(
    rows: impl IntoIterator<Item = (&'a SideAttributeKey, &'a T)>,
    view: Digest,
    domain: &str,
    path: impl Fn(&'a T) -> &'a [u8],
    encode: impl Fn(&mut Vec<u8>, &'a T),
) -> Vec<u8> {
    let selected: Vec<_> = rows
        .into_iter()
        .filter(|((location, _, selected_domain), _)| {
            location.commit == view && selected_domain == domain
        })
        .collect();
    if selected.is_empty() {
        return Vec::new();
    }

    let mut bytes = Vec::new();
    cbor::write_array(&mut bytes, selected.len());
    for ((location, name, domain), value) in selected {
        cbor::write_array(&mut bytes, 5);
        encode_location(&mut bytes, location);
        cbor::write_text(&mut bytes, name);
        cbor::write_text(&mut bytes, domain);
        cbor::write_bytes(&mut bytes, path(value));
        encode(&mut bytes, value);
    }
    bytes
}

fn encode_location(output: &mut Vec<u8>, location: &EntryLocation) {
    cbor::write_array(output, 3);
    cbor::write_bytes(output, &location.commit);
    cbor::write_bytes(output, &location.root);
    cbor::write_bytes(output, &location.path);
}

/// Encodes all nine evidence fields, including the independent carrying witness.
pub(super) fn encode_evidence(output: &mut Vec<u8>, fields: EvidenceFields<'_>) {
    cbor::write_array(output, 9);
    cbor::write_bytes(output, fields.record);
    cbor::write_bytes(output, fields.object);
    cbor::write_text(output, fields.name);
    cbor::write_text(output, fields.function);
    cbor::write_text(output, fields.version);
    cbor::write_bytes(output, fields.value);
    cbor::write_bytes(output, fields.producer);
    encode_location(output, fields.location);
    cbor::write_array(output, 2);
    cbor::write_text(output, fields.producer_domain);
    cbor::write_bytes(output, fields.producer_path);
}
