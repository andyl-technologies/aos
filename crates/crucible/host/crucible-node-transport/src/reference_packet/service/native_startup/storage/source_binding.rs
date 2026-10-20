//! Counts only the closed Source binding's actual unchanged external children.
//!
//! The native allocation row cannot be used to enlarge the census that admits
//! that row. This fixed borrowed cursor selects exactly the nine immutable base
//! fields. Their same literal values survive Binding6..14. The named successor
//! fields are counted once by the closed compiled projection, using quoted-U64
//! width bounds, so recomputing after finalization cannot count its row twice.

use super::*;

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

pub(super) struct SourceBindingStorage {
    pub(super) base_encoded_bytes: usize,
    pub(super) base_decoded_bytes: usize,
    pub(super) base_value_backing_bytes: usize,
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

pub(super) fn project(bytes: &[u8], maximum: usize) -> Result<SourceBindingStorage, ProviderError> {
    project_values(fields(bytes)?, maximum)
}

// This data-only sibling preserves the legacy closed roster. Its caller must
// authenticate the actual Source15 purpose and original private channel first.
pub(super) fn project_invocation(
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
    let roots = crate::retained_metadata::requested_storage::tree_storage_data(
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

#[cfg(test)]
mod invocation_tests {
    use super::*;
    use crucible_node_format::canonical;
    use serde_json::json;

    // Closed inert field occurrences exercise the census, not a typed launch,
    // Source member, parser authority or semantic binding.
    fn source(schema: &str) -> serde_json::Value {
        let mut value = serde_json::Map::new();
        for name in BASE.into_iter().chain(EXTRA) {
            value.insert(
                std::str::from_utf8(name).unwrap().into(),
                serde_json::Value::Null,
            );
        }
        value.insert("schema".into(), json!(schema));
        serde_json::Value::Object(value)
    }

    #[test]
    fn invocation_source_census_keeps_legacy_roster_and_exact_unchanged_base() {
        let old = source("source-owned.packet-canonical-ack-source-binding/14");
        let old = canonical::canonical_json(&old).unwrap();
        let legacy = project(&old, usize::MAX).unwrap();
        assert!(project_invocation(&old, usize::MAX).is_err());

        let mut current = source("source-owned.packet-canonical-ack-source-binding/15");
        current["invocation"] = json!({"inert_occurrence":true});
        let encoded = canonical::canonical_json(&current).unwrap();
        let selected = project_invocation(&encoded, usize::MAX).unwrap();
        assert_eq!(selected.base_encoded_bytes, legacy.base_encoded_bytes);
        assert_eq!(selected.base_decoded_bytes, legacy.base_decoded_bytes);
        assert_eq!(
            selected.base_value_backing_bytes,
            legacy.base_value_backing_bytes
        );
        assert!(project(&encoded, usize::MAX).is_err());

        for name in [
            "invocation",
            "schema",
            "native_startup_allocation",
            "selection",
        ] {
            let mut changed = current.clone();
            changed.as_object_mut().unwrap().remove(name);
            assert!(
                project_invocation(&canonical::canonical_json(&changed).unwrap(), usize::MAX)
                    .is_err()
            );
        }
        current["foreign"] = json!(null);
        assert!(
            project_invocation(&canonical::canonical_json(&current).unwrap(), usize::MAX).is_err()
        );
    }
}
