//! Shares authoritative JCS object ordering with borrowed enclosing codecs.

use super::*;

type BorrowedEntry<'a> = fn((&'a String, &'a Value)) -> (&'a str, &'a Value);
type JsonFields<'a> = std::iter::Map<serde_json::map::Iter<'a>, BorrowedEntry<'a>>;
type TreeFields<'a> =
    std::iter::Map<std::collections::btree_map::Iter<'a, String, Value>, BorrowedEntry<'a>>;

fn borrowed_entry<'a>((key, value): (&'a String, &'a Value)) -> (&'a str, &'a Value) {
    (key.as_str(), value)
}

/// Writes a borrowed object at its actual position in an enclosing JSON value.
///
/// `depth` counts enclosing containers, with zero for a root object. The object
/// uses the same UTF-16 ordering, string escaping, scalar formatting and depth
/// limit as [`canonical_json_to_writer`]. No owning Value wrapper is constructed;
/// canonical ordering and formatter allocations remain caller-funded work.
///
/// # Errors
/// Rejects a 65th container, excessive arrays, unsupported numeric values or
/// sink errors. Partial output remains in the caller's original sink.
pub fn canonical_json_object_to_writer_at_depth(
    values: &Map<String, Value>,
    output: &mut impl std::io::Write,
    depth: usize,
) -> Result<(), ContractError> {
    let fields: JsonFields<'_> = values.iter().map(borrowed_entry as BorrowedEntry<'_>);
    write_object_fields(fields, output, depth)
}

/// Writes a borrowed BTreeMap object at its actual enclosing JSON depth.
///
/// This shares the authoritative object writer with
/// [`canonical_json_object_to_writer_at_depth`]. Input UTF-8 key order does not
/// replace JCS UTF-16 order, including for extension maps with non-ASCII keys.
/// Canonical ordering and formatter allocations remain caller-funded work.
///
/// # Errors
/// Rejects the same nesting, array, numeric and sink failures as
/// [`canonical_json_to_writer`]. Partial output remains in the original sink.
pub fn canonical_json_btree_object_to_writer_at_depth(
    values: &BTreeMap<String, Value>,
    output: &mut impl std::io::Write,
    depth: usize,
) -> Result<(), ContractError> {
    let fields: TreeFields<'_> = values.iter().map(borrowed_entry as BorrowedEntry<'_>);
    write_object_fields(fields, output, depth)
}

// Both public collections guarantee unique keys before this iterator is formed.
fn write_object_fields<'a>(
    fields: impl Iterator<Item = (&'a str, &'a Value)>,
    output: &mut impl std::io::Write,
    depth: usize,
) -> Result<(), ContractError> {
    if depth >= 64 {
        return Err(invalid("json_depth", CANONICAL_DEPTH_REASON));
    }
    let ordered: BTreeMap<Vec<u16>, (&str, &Value)> = fields
        .map(|(key, value)| (key.encode_utf16().collect(), (key, value)))
        .collect();
    output.write_all(b"{").map_err(serde_json::Error::io)?;
    for (index, (key, value)) in ordered.values().enumerate() {
        if index != 0 {
            output.write_all(b",").map_err(serde_json::Error::io)?;
        }
        output
            .write_all(serde_json::to_string(key)?.as_bytes())
            .map_err(serde_json::Error::io)?;
        output.write_all(b":").map_err(serde_json::Error::io)?;
        write_canonical(value, output, depth + 1)?;
    }
    output.write_all(b"}").map_err(serde_json::Error::io)?;
    Ok(())
}

// Names the new collection adapters and call operands beside the original
// authoritative ordering states. The actual function-pointer maps are named
// above, so their closure representation is not guessed by another module.
pub(super) fn counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<JsonFields<'static>>()
        + size_of::<TreeFields<'static>>()
        + size_of::<BorrowedEntry<'static>>()
        + size_of::<&Map<String, Value>>()
        + size_of::<&BTreeMap<String, Value>>()
        + size_of::<&mut Vec<u8>>() * 2
        + size_of::<usize>() * 2
        + size_of::<&String>()
        + size_of::<&str>()
        + size_of::<&Value>()
        + size_of::<Result<(), ContractError>>() * 2
}
