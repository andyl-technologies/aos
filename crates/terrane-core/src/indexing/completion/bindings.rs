//! Validates selected names and merges exact owner-local binding bytes.

use alloc::{collections::BTreeMap, vec::Vec};

use super::{Error, Selection, Work, add};
use crate::{
    cbor,
    indexing::{IndexEvaluationRecipe, IndexRoots, maintenance::ByteArena},
    tree_builder::Tree,
    tree_format::Property,
};

fn key(name: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_text(&mut bytes, name);
    bytes
}

/// Validates a nonempty selection batch and orders it by encoded attribute keys.
///
/// # Errors
/// Rejects empty batches, unregistered attribute names and duplicate selections.
pub(super) fn ordered<'input>(
    selections: &[Selection<'input>],
) -> Result<Vec<Selection<'input>>, Error> {
    if selections.is_empty() {
        return Err(Error::EmptySelection);
    }
    let mut ordered = BTreeMap::new();
    for selection in selections {
        IndexEvaluationRecipe::new([0; 32], selection.attribute).map_err(Error::Binding)?;
        if ordered
            .insert(key(selection.attribute), *selection)
            .is_some()
        {
            return Err(Error::DuplicateSelection);
        }
    }
    Ok(ordered.into_values().collect())
}

/// Merges selected index identities into validated owner-local bindings.
///
/// Replaces selected bindings while preserving unselected bindings and other
/// properties. The caller validates selections and their index closures first.
/// An unchanged binding reuses its payload; a changed binding is copied into
/// the arena, with properties returned in encoded-key order.
///
/// # Errors
/// Rejects malformed existing noninherited wrappers or merged binding values,
/// binding codec size limits, encoding-count overflow, and arena payload-limit
/// or allocation refusal. Work counters may be updated before an error.
pub(super) fn merge<'value>(
    owner: &Tree<'value>,
    selections: &[Selection<'_>],
    arena: &'value ByteArena,
    work: &mut Work,
) -> Result<Vec<Property<'value>>, Error> {
    let properties = owner.props().unwrap_or_default();
    let existing = properties
        .iter()
        .find(|property| property.name == "index-roots");
    let mut bindings = BTreeMap::new();
    if let Some(existing) = existing {
        let roots = IndexRoots::decode_binding(existing.value).map_err(Error::Binding)?;
        work.binding_bytes_decoded = existing.value.len();
        for binding in roots.as_bindings() {
            bindings.insert(key(binding.attribute), (binding.attribute, binding.node));
        }
    }
    for selection in selections {
        bindings.insert(
            key(selection.attribute),
            (selection.attribute, selection.data.root),
        );
    }
    let mut value = Vec::new();
    cbor::write_map(&mut value, bindings.len());
    for (attribute, node) in bindings.values() {
        cbor::write_text(&mut value, attribute);
        cbor::write_argument(&mut value, 3, 64);
        for byte in node {
            value.push(b"0123456789abcdef"[usize::from(byte >> 4)]);
            value.push(b"0123456789abcdef"[usize::from(byte & 15)]);
        }
    }
    let roots = IndexRoots::decode_value(&value).map_err(Error::Binding)?;
    let bytes = roots.encode_binding().map_err(Error::Binding)?;
    work.binding_value_bytes_encoded = value.len();
    // encode_binding also encodes its value internally; both operations count.
    work.binding_bytes_encoded = bytes.len();
    add(&mut work.binding_bytes_encoded, value.len())?;
    let stored = match existing {
        Some(existing) if existing.value == bytes => return Ok(properties.to_vec()),
        _ => {
            let stored = arena.copy(&bytes).map_err(Error::Arena)?;
            work.arena_bytes_copied = bytes.len();
            stored
        }
    };
    let mut result: Vec<_> = properties
        .iter()
        .filter(|property| property.name != "index-roots")
        .copied()
        .collect();
    result.push(Property {
        name: "index-roots",
        value: stored,
    });
    result.sort_by_cached_key(|property| key(property.name));
    Ok(result)
}
