//! Shares the original generic selected decoder occurrence calculations.
//!
//! These banks preserve the original owner projector's separate DOM, typed and
//! canonical phase multipliers. They are distinct from native launch occurrence
//! geometry. Framing observations and numeric rows grant no parser, Source,
//! restoration, member, reservation or native authority.

use crate::errors::ProviderError;
use serde_json::Value;
use std::mem::{align_of, size_of};

/// Retains the original scalar occurrence banks before phase multiplication.
///
/// No decoded owner, allocation or authority is retained by this numeric record.
#[derive(Default)]
pub struct Credit {
    strings: usize,
    values: usize,
    /// Counts each object occurrence, including independent empty roots.
    /// Value/DTO phases charge these separately; legacy requested() stays exact.
    pub object_roots: usize,
    typed: usize,
    canonical: usize,
}

/// Names independently simultaneous DOM, typed and canonical phases.
pub struct Phases {
    /// Multiplies actual string and Value occurrence banks.
    pub dom: usize,
    /// Multiplies the supplied actual typed-layout occurrence bank.
    pub typed: usize,
    /// Multiplies actual canonical output and ordering work.
    pub canonical: usize,
}

impl Credit {
    /// Returns the original string-occurrence backing before phase multiplication.
    pub const fn string_backing_bytes_data(&self) -> usize {
        self.strings
    }

    /// Sums the original independently multiplied phase banks.
    ///
    /// # Errors
    /// Refuses arithmetic overflow with the original storage error.
    pub fn requested(&self, phases: &Phases) -> Result<usize, ProviderError> {
        sum(&[
            mul(self.strings, phases.dom)?,
            mul(self.values, phases.dom)?,
            mul(self.typed, phases.typed)?,
            mul(self.canonical, phases.canonical)?,
        ])
    }
}

/// Scans raw selected input with the original fixed 64-level framing walk.
///
/// This is requested-layout DATA, not full JSON validation. The maximum bounds
/// input length; phase callers separately preserve their original result bounds.
///
/// # Errors
/// Refuses empty or oversized input, zero supplied layouts, excessive nesting,
/// malformed framing or checked arithmetic overflow with the original errors.
pub fn scan(
    bytes: &[u8],
    maximum: usize,
    typed_slot: usize,
    typed_node: usize,
) -> Result<Credit, ProviderError> {
    if bytes.is_empty() || bytes.len() > maximum || typed_slot == 0 || typed_node == 0 {
        return Err(exhausted());
    }
    let value_node = map_node(
        size_of::<String>() + size_of::<Value>(),
        align_of::<Value>(),
    )?;
    let ordered_node = map_node(
        size_of::<Vec<u16>>() + size_of::<(&str, &Value)>(),
        align_of::<Vec<u16>>().max(align_of::<(&str, &Value)>()),
    )?;
    let mut credit = Credit {
        canonical: growth(bytes.len(), 8)?,
        ..Credit::default()
    };
    let mut stack = [0u8; 64];
    let mut depth = 0usize;
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b' ' | b'\n' | b'\r' | b'\t' | b':' | b',' => cursor += 1,
            b'{' | b'[' => {
                let delimiter = bytes[cursor];
                let slot = stack.get_mut(depth).ok_or_else(exhausted)?;
                *slot = delimiter;
                depth += 1;
                if delimiter == b'{' {
                    // Count occurrences without introducing a new node-width
                    // overflow into the unchanged legacy quote paths.
                    add(&mut credit.object_roots, 1)?;
                }
                add(&mut credit.typed, mul(4, typed_slot)?)?;
                if delimiter == b'[' {
                    add(&mut credit.values, mul(4, size_of::<Value>())?)?;
                    add(&mut credit.typed, mul(4, typed_slot)?)?;
                }
                cursor += 1;
            }
            b'}' | b']' => {
                let expected = if bytes[cursor] == b'}' { b'{' } else { b'[' };
                depth = depth.checked_sub(1).ok_or_else(malformed)?;
                if stack[depth] != expected {
                    return Err(malformed());
                }
                cursor += 1;
            }
            b'"' => {
                cursor += 1;
                let start = cursor;
                let mut closed = false;
                while cursor < bytes.len() {
                    let byte = bytes[cursor];
                    cursor += 1;
                    if byte == b'\\' {
                        cursor = cursor.checked_add(1).ok_or_else(exhausted)?;
                        if cursor > bytes.len() {
                            return Err(malformed());
                        }
                    } else if byte == b'"' {
                        closed = true;
                        break;
                    }
                }
                if !closed {
                    return Err(malformed());
                }
                let encoded = cursor - start - 1;
                add(&mut credit.strings, growth(encoded, 8)?)?;
                add(&mut credit.strings, encoded)?;
                add(&mut credit.typed, encoded)?;
                add(
                    &mut credit.canonical,
                    growth(sum(&[mul(encoded, 6)?, 2])?, 256)?,
                )?;
                let mut next = cursor;
                while bytes.get(next).is_some_and(u8::is_ascii_whitespace) {
                    next += 1;
                }
                if bytes.get(next) == Some(&b':') {
                    add(&mut credit.values, value_node)?;
                    add(&mut credit.typed, typed_node)?;
                    add(&mut credit.canonical, ordered_node)?;
                    add(&mut credit.canonical, sum(&[mul(encoded, 8)?, 16])?)?;
                }
                add(&mut credit.values, mul(4, size_of::<Value>())?)?;
                add(&mut credit.typed, mul(4, typed_slot)?)?;
            }
            _ => {
                let start = cursor;
                while cursor < bytes.len() && !b" \n\r\t,:]}".contains(&bytes[cursor]) {
                    cursor += 1;
                }
                if cursor == start {
                    return Err(malformed());
                }
                add(&mut credit.values, mul(4, size_of::<Value>())?)?;
                add(&mut credit.typed, mul(4, typed_slot)?)?;
            }
        }
    }
    if depth != 0 {
        return Err(malformed());
    }
    add(&mut credit.typed, typed_slot)?;
    Ok(credit)
}

// Source-pinned Rust 1.98 B=6 upper layout: eleven key/value slots, twelve
// edges and eight alignment boundaries. This is requested storage, not an ABI.
/// Calculates the source-pinned requested tree node bound.
///
/// # Errors
/// Refuses invalid alignment or arithmetic overflow with the original storage error.
pub fn map_node(key_value: usize, alignment: usize) -> Result<usize, ProviderError> {
    let alignment = alignment.max(align_of::<usize>());
    std::alloc::Layout::from_size_align(0, alignment).map_err(|_| exhausted())?;
    sum(&[
        size_of::<usize>(),
        2 * size_of::<u16>(),
        12 * size_of::<usize>(),
        mul(11, key_value)?,
        mul(8, alignment - 1)?,
    ])
}

/// Sums the original checked requested-layout components.
///
/// # Errors
/// Refuses arithmetic overflow with the original storage error.
pub fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values.iter().try_fold(0usize, |total, value| {
        total.checked_add(*value).ok_or_else(exhausted)
    })
}
/// Multiplies the original checked requested-layout components.
///
/// # Errors
/// Refuses arithmetic overflow with the original storage error.
pub fn mul(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(exhausted)
}
fn add(total: &mut usize, value: usize) -> Result<(), ProviderError> {
    *total = sum(&[*total, value])?;
    Ok(())
}
/// Calculates the original checked growth component.
///
/// # Errors
/// Refuses arithmetic overflow with the original storage error.
pub fn growth(length: usize, minimum: usize) -> Result<usize, ProviderError> {
    sum(&[mul(length, 4)?, minimum])
}
/// Returns the original selected native owner storage refusal.
pub fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("selected native owner validation storage")
}
fn malformed() -> ProviderError {
    ProviderError::Frame("selected native owner validation framing")
}

/// Counts a closed native DTO roster without importing restore/model layouts.
///
/// The caller supplies the compiled maximum of every actual nested DTO/Vec
/// element; portable extension maps remain String-to-Value. Two complete DOMs
/// cover parser/borrowed decoding and container rebuilds independently.
///
/// # Errors
/// Refuses the original scanner failures, arithmetic overflow or a result above maximum.
pub fn selected_native_dto_decode_storage_data(
    bytes: &[u8],
    typed_slot: usize,
    maximum: usize,
) -> Result<usize, ProviderError> {
    let value_node = map_node(
        size_of::<String>() + size_of::<Value>(),
        align_of::<Value>(),
    )?;
    let credit = scan(bytes, maximum, typed_slot, value_node)?;
    let requested = sum(&[
        credit.requested(&Phases {
            dom: 2,
            typed: 1,
            canonical: 1,
        })?,
        // Metadata facts include one possible tree root for every object,
        // independently of its entries, including empty nested objects.
        mul(2, mul(credit.object_roots, value_node)?)?,
        mul(2, size_of::<Value>())?,
    ])?;
    if requested > maximum {
        return Err(exhausted());
    }
    Ok(requested)
}

/// Counts actual raw Value-only parsing, cloning and canonical work.
///
/// Native Source and registration children have no Control/model DTO per raw
/// token. Two complete DOMs conservatively cover parser and borrowed/owned
/// Value-deserialization container rebuilding; strings remain double-counted.
/// This uses the existing selected-issuer fixed scanner scratch, admitted by
/// the original native counter before entry. Strict validation stays separate.
///
/// # Errors
/// Refuses the original scanner failures, arithmetic overflow or a result above maximum.
pub fn selected_value_decode_storage_data(
    bytes: &[u8],
    maximum: usize,
) -> Result<usize, ProviderError> {
    let value_node = map_node(
        size_of::<String>() + size_of::<Value>(),
        align_of::<Value>(),
    )?;
    let credit = scan(bytes, maximum, size_of::<Value>(), value_node)?;
    // scan stores the root inline header in its typed term. This Value-only
    // phase must name both independent root headers explicitly, including {}.
    let requested = sum(&[
        credit.requested(&Phases {
            dom: 2,
            typed: 0,
            canonical: 1,
        })?,
        // Metadata facts include one possible tree root for every object,
        // independently of its entries, including empty nested objects.
        mul(2, mul(credit.object_roots, value_node)?)?,
        mul(2, size_of::<Value>())?,
    ])?;
    if requested > maximum {
        return Err(exhausted());
    }
    Ok(requested)
}

#[cfg(test)]
mod tests;
