//! Counts only the closed Source binding's actual unchanged external children.
//!
//! The native allocation row cannot be used to enlarge the census that admits
//! that row. This fixed borrowed cursor selects exactly the nine immutable base
//! fields. Their same literal values survive Binding6..14. The named successor
//! fields are counted once by the closed compiled projection, using quoted-U64
//! width bounds, so recomputing after finalization cannot count its row twice.

use crate::decoded_occurrences as decoded;
use crate::errors::ProviderError;
use crate::selected_decode::selected_value_decode_storage_data as decode_value;
use std::mem::{align_of, size_of};

const BASE: [&[u8]; 9] = [
    b"selection",
    b"program",
    b"coordinator",
    b"limits",
    b"storage",
    b"capture_profile",
    b"confirmation_selection",
    b"ack_emitter_selection",
    b"codec_metadata_extent",
];
const EXTRA: [&[u8]; 9] = [
    b"schema",
    b"native_codec_metadata_extent",
    b"protocol_metadata_limits",
    b"complete_restore_selection",
    b"restore_input_emitter_selection",
    b"capture_allocation_selection",
    b"fresh_restore_allocation_selection",
    b"report_startup_allocation",
    b"native_startup_allocation",
];

/// Reports the original nine external base-value occurrence banks.
///
/// Allocation rows and successor payloads cannot enlarge their own census.
/// This record grants no binding, parsing, Source or native authority.
pub struct SourceBindingStorage {
    /// Counts the canonical outer keys, delimiters and exact selected values.
    pub base_encoded_bytes: usize,
    /// Counts the independent generic Value decode and canonical phases.
    pub base_decoded_bytes: usize,
    /// Counts the original native Value backing and outer root entries.
    pub base_value_backing_bytes: usize,
}

// The Source's actual constructor already emits canonical JSON. This cursor
// refuses aliases/escapes in the closed top-level keys and retains no values.
// Full raw JSON grammar, typed schema validation and byte identity are separate
// mandatory consumers before any native constructor or semantic use.
fn value_end(bytes: &[u8], start: usize) -> Result<usize, ProviderError> {
    let mut cursor = start;
    let mut stack = [0u8; 64];
    let mut depth = 0usize;
    let mut string = false;
    while let Some(&byte) = bytes.get(cursor) {
        if string {
            match byte {
                b'\\' => {
                    cursor = cursor.checked_add(1).ok_or_else(refused)?;
                    bytes.get(cursor).ok_or_else(refused)?;
                }
                b'"' => {
                    string = false;
                    if depth == 0 {
                        return Ok(cursor + 1);
                    }
                }
                0..=31 => return Err(refused()),
                _ => {}
            }
        } else {
            match byte {
                b'"' => string = true,
                b'{' | b'[' => {
                    let slot = stack.get_mut(depth).ok_or_else(refused)?;
                    *slot = if byte == b'{' { b'}' } else { b']' };
                    depth += 1;
                }
                b'}' | b']' => {
                    if depth == 0 {
                        return if cursor > start {
                            Ok(cursor)
                        } else {
                            Err(refused())
                        };
                    }
                    depth -= 1;
                    if stack[depth] != byte {
                        return Err(refused());
                    }
                    if depth == 0 {
                        return Ok(cursor + 1);
                    }
                }
                b',' if depth == 0 => {
                    return if cursor > start {
                        Ok(cursor)
                    } else {
                        Err(refused())
                    };
                }
                b' ' | b'\t' | b'\r' | b'\n' => return Err(refused()),
                _ => {}
            }
        }
        cursor = cursor.checked_add(1).ok_or_else(refused)?;
    }
    Err(refused())
}

fn fields(bytes: &[u8]) -> Result<[&[u8]; 9], ProviderError> {
    fields_inner(bytes, false)
}

fn fields_inner(bytes: &[u8], invocation: bool) -> Result<[&[u8]; 9], ProviderError> {
    if bytes.first() != Some(&b'{') {
        return Err(refused());
    }
    let mut selected = [None; 9];
    let mut extras = [false; 9];
    let mut saw_invocation = false;
    let mut selected_schema = false;
    let mut cursor = 1usize;
    loop {
        if bytes.get(cursor) == Some(&b'}') {
            cursor += 1;
            if cursor != bytes.len() {
                return Err(refused());
            }
            break;
        }
        if bytes.get(cursor) != Some(&b'"') {
            return Err(refused());
        }
        let start = cursor + 1;
        cursor = start;
        while bytes.get(cursor).is_some_and(|byte| *byte != b'"') {
            let byte = bytes[cursor];
            if !(32..=126).contains(&byte) || byte == b'\\' {
                return Err(refused());
            }
            cursor += 1;
        }
        let key = bytes.get(start..cursor).ok_or_else(refused)?;
        if bytes.get(cursor) != Some(&b'"') || bytes.get(cursor + 1) != Some(&b':') {
            return Err(refused());
        }
        let value_start = cursor + 2;
        let end = value_end(bytes, value_start)?;
        if let Some(index) = BASE.iter().position(|name| *name == key) {
            if selected[index]
                .replace(bytes.get(value_start..end).ok_or_else(refused)?)
                .is_some()
            {
                return Err(refused());
            }
        } else if invocation && key == b"invocation" {
            if std::mem::replace(&mut saw_invocation, true) {
                return Err(refused());
            }
        } else if let Some(index) = EXTRA.iter().position(|name| *name == key) {
            if invocation && key == b"schema" {
                selected_schema = bytes.get(value_start..end)
                    == Some(b"\"source-owned.packet-canonical-ack-source-binding/15\"");
            }
            if std::mem::replace(&mut extras[index], true) {
                return Err(refused());
            }
        } else {
            return Err(refused());
        }
        cursor = end;
        match bytes.get(cursor) {
            Some(b',') => cursor += 1,
            Some(b'}') => {}
            _ => return Err(refused()),
        }
    }
    if invocation && (!saw_invocation || !selected_schema || extras.iter().any(|seen| !seen)) {
        return Err(refused());
    }
    let [a, b, c, d, e, f, g, h, i] = selected;
    Ok([
        a.ok_or_else(refused)?,
        b.ok_or_else(refused)?,
        c.ok_or_else(refused)?,
        d.ok_or_else(refused)?,
        e.ok_or_else(refused)?,
        f.ok_or_else(refused)?,
        g.ok_or_else(refused)?,
        h.ok_or_else(refused)?,
        i.ok_or_else(refused)?,
    ])
}

/// Quotes the original closed Binding6–14 nine-base-field occurrence bank.
///
/// # Errors
/// Refuses the original closed framing/roster errors, excessive depth, arithmetic
/// overflow or an original requested component above maximum.
pub fn project(bytes: &[u8], maximum: usize) -> Result<SourceBindingStorage, ProviderError> {
    project_values(fields(bytes)?, maximum)
}

/// Quotes the closed Binding15 base values while excluding its announced rows.
///
/// The actual caller separately authenticates purpose, original private channel,
/// complete raw grammar and typed schema. Numeric success is not that proof.
///
/// # Errors
/// Refuses missing, duplicate or unknown top-level fields, a schema other than
/// Binding15, original framing/depth errors, overflow or the original ceiling.
pub fn project_invocation(
    bytes: &[u8],
    maximum: usize,
) -> Result<SourceBindingStorage, ProviderError> {
    project_values(fields_inner(bytes, true)?, maximum)
}

fn project_values(
    values: [&[u8]; 9],
    maximum: usize,
) -> Result<SourceBindingStorage, ProviderError> {
    // Each actual field retains its exact complete nested value occurrences.
    // Nine keys, colons, eight commas and the outer braces are separately named.
    let mut encoded = 2usize + 8 + 9;
    let mut decoded = 0usize;
    let mut backing = 0usize;
    for (key, value) in BASE.into_iter().zip(values) {
        encoded = sum(&[encoded, key.len() + 2, value.len()], maximum)?;
        backing = sum(
            &[
                backing,
                decoded::quote(
                    value,
                    size_of::<serde_json::Value>(),
                    size_of::<serde_json::Value>(),
                    maximum,
                )?
                .value_backing,
                key.len(),
            ],
            maximum,
        )?;
        decoded = sum(
            &[decoded, decode_value(value, maximum)?, key.len()],
            maximum,
        )?;
    }
    let roots = crate::profile::requested_storage::tree_storage_data(
        1,
        9,
        size_of::<(String, serde_json::Value)>(),
        align_of::<(String, serde_json::Value)>(),
    )?;
    decoded = sum(&[decoded, roots, size_of::<serde_json::Value>()], maximum)?;
    Ok(SourceBindingStorage {
        base_encoded_bytes: encoded,
        base_decoded_bytes: decoded,
        base_value_backing_bytes: sum(&[backing, roots, size_of::<serde_json::Value>()], maximum)?,
    })
}

fn sum(values: &[usize], maximum: usize) -> Result<usize, ProviderError> {
    values.iter().try_fold(0usize, |total, bytes| {
        total
            .checked_add(*bytes)
            .filter(|total| *total <= maximum)
            .ok_or_else(refused)
    })
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("native baseline requested storage")
}
