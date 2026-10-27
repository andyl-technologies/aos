//! Counts actual raw and projected JSON occurrences with one native algorithm.
//!
//! The original raw scanner remains a layout prewalk, not a JSON validator.
//! Projected callers serialize real borrowed fields into the same accumulator;
//! opaque token/path strings contribute exact extents without placeholder bytes.
//! These requested-layout rows grant no parsing, Source or native authority.

use crate::errors::ProviderError;
use serde_json::Value;
use std::mem::{align_of, size_of};

mod projected;

pub use projected::{
    ProjectedLaunchStorage, projected_counter_scratch_data, projected_issuer_counter_scratch_data,
    quote_projected_launch, quote_projected_launch_with_issuer,
};

/// Separates the actual native decoded backing and complete construction work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedStorage {
    /// Reports independently retained decoded Value backing, including empty roots.
    pub value_backing: usize,
    /// Reports typed root/array element and independently retained string backing.
    pub typed_backing: usize,
    /// Reports the original complete simultaneous decode/canonical/sort phase.
    pub work: usize,
}

impl DecodedStorage {
    /// Sums the original three independently required components.
    ///
    /// # Errors
    /// Refuses overflow or a complete requested sum above the supplied ceiling.
    pub fn total(self, maximum: usize) -> Result<usize, ProviderError> {
        sum(
            &[self.value_backing, self.typed_backing, self.work],
            maximum,
        )
    }
}

fn sum(values: &[usize], maximum: usize) -> Result<usize, ProviderError> {
    values.iter().try_fold(0usize, |total, bytes| {
        total
            .checked_add(*bytes)
            .filter(|n| *n <= maximum)
            .ok_or_else(refused)
    })
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("native baseline requested storage")
}

fn tree_node() -> Result<usize, ProviderError> {
    crate::profile::serialization_storage::original_serialization_tree_node_requested_bytes_data::<
        String,
        Value,
    >()
}

struct Counter {
    strings: usize,
    maps: usize,
    slots: usize,
    canonical: usize,
    sort_node: usize,
}

impl Counter {
    fn new(encoded: usize) -> Result<Self, ProviderError> {
        let sort_node = crate::profile::serialization_storage::original_serialization_tree_node_requested_bytes_data::<Vec<u16>, (&str, &Value)>()?;
        let sort_slot = size_of::<(Vec<u16>, (&str, &Value))>();
        if size_of::<usize>() != 8 || sort_slot.checked_mul(5).ok_or_else(refused)? > sort_node {
            return Err(refused());
        }
        let mut counter = Self {
            strings: 0,
            maps: 0,
            slots: 0,
            canonical: 0,
            sort_node,
        };
        counter.encoded(encoded)?;
        Ok(counter)
    }

    fn encoded(&mut self, bytes: usize) -> Result<(), ProviderError> {
        self.canonical = self
            .canonical
            .checked_add(bytes.checked_mul(8).ok_or_else(refused)?)
            .ok_or_else(refused)?;
        Ok(())
    }

    fn array_value(&mut self) -> Result<(), ProviderError> {
        self.slots = self.slots.checked_add(4).ok_or_else(refused)?;
        Ok(())
    }

    fn container(&mut self, byte: u8) -> Result<(), ProviderError> {
        if byte == b'{' {
            self.maps = self.maps.checked_add(1).ok_or_else(refused)?;
        } else {
            self.array_value()?;
        }
        Ok(())
    }

    fn string(&mut self, encoded: usize, key: bool, maximum: usize) -> Result<(), ProviderError> {
        // The same original string and UTF16-key/sort accounting applies to raw
        // bytes and actual serializer output; Bytes is still one encoded string.
        self.strings = sum(
            &[
                self.strings,
                encoded.checked_mul(8).ok_or_else(refused)?,
                32,
            ],
            maximum,
        )?;
        if key {
            self.maps = self.maps.checked_add(1).ok_or_else(refused)?;
            self.canonical = sum(
                &[
                    self.canonical,
                    encoded.checked_mul(8).ok_or_else(refused)?,
                    self.sort_node.checked_mul(2).ok_or_else(refused)?,
                    16,
                ],
                maximum,
            )?;
        }
        self.canonical = sum(
            &[
                self.canonical,
                encoded.checked_mul(24).ok_or_else(refused)?,
                264,
            ],
            maximum,
        )?;
        Ok(())
    }

    fn finish(
        self,
        root: usize,
        element: usize,
        maximum: usize,
    ) -> Result<DecodedStorage, ProviderError> {
        let sort_slot = size_of::<(Vec<u16>, (&str, &Value))>();
        let map_backing = self.maps.checked_mul(tree_node()?).ok_or_else(refused)?;
        let value_backing = sum(
            &[
                self.strings,
                map_backing,
                self.slots
                    .checked_mul(size_of::<Value>())
                    .ok_or_else(refused)?,
                size_of::<Value>(),
            ],
            maximum,
        )?;
        let typed_backing = sum(
            &[
                self.strings,
                map_backing,
                self.slots.checked_mul(element).ok_or_else(refused)?,
                root,
            ],
            maximum,
        )?;
        // Container rebuilding from owned Value can coexist with the original
        // subtree. Keep both DOMs; canonical sorting/output is separate work.
        // These are explicit standard-library local banks, not compiler frames.
        // A single sort owns one aligned4096 workspace,66 one-word run records,
        //66 desired-depth bytes, insertion temporary/CopyOnDrop and heap header.
        let sort_alignment = align_of::<(Vec<u16>, (&str, &Value))>();
        let sort_workspace = ((4096 + sort_alignment - 1) & !(sort_alignment - 1))
            + size_of::<[usize; 66]>()
            + size_of::<[u8; 66]>()
            + sort_slot
            + 3 * size_of::<usize>()
            + size_of::<Vec<(Vec<u16>, (&str, &Value))>>();
        let work = sum(
            &[
                value_backing,
                value_backing,
                typed_backing,
                self.canonical,
                sort_workspace,
            ],
            maximum,
        )?;
        let result = DecodedStorage {
            value_backing,
            typed_backing,
            work,
        };
        result.total(maximum)?;
        Ok(result)
    }
}

/// Quotes the original native raw occurrence walk before any DTO cardinality check.
///
/// This retains the original malformed-input behavior and hard scanner stack.
/// It creates no JSON/typed owner and supplies no grammar or native acceptance.
///
/// # Errors
/// Refuses empty/oversized input, zero layouts, malformed scanner structure,
/// unsupported compiled layout, arithmetic overflow or the unchanged ceiling.
pub fn quote(
    bytes: &[u8],
    root: usize,
    element: usize,
    maximum: usize,
) -> Result<DecodedStorage, ProviderError> {
    if bytes.is_empty() || bytes.len() > maximum || root == 0 || element == 0 {
        return Err(refused());
    }
    let mut stack = [0u8; 64];
    let mut depth = 0usize;
    let mut cursor = 0usize;
    let mut counter = Counter::new(bytes.len())?;
    while let Some(&byte) = bytes.get(cursor) {
        if b" \t\r\n,:".contains(&byte) {
            cursor += 1;
            continue;
        }
        let closes = byte == b'}' || byte == b']';
        if !closes && depth > 0 && stack[depth - 1] == b'[' {
            counter.array_value()?;
        }
        match byte {
            b'{' | b'[' => {
                *stack.get_mut(depth).ok_or_else(refused)? = byte;
                depth += 1;
                counter.container(byte)?;
                cursor += 1;
            }
            b'}' | b']' => {
                depth = depth.checked_sub(1).ok_or_else(refused)?;
                if stack[depth] != if byte == b'}' { b'{' } else { b'[' } {
                    return Err(refused());
                }
                cursor += 1;
            }
            b'"' => {
                cursor += 1;
                let start = cursor;
                loop {
                    let next = *bytes.get(cursor).ok_or_else(refused)?;
                    cursor += 1;
                    if next == b'\\' {
                        bytes.get(cursor).ok_or_else(refused)?;
                        cursor += 1;
                    } else if next == b'"' {
                        break;
                    }
                }
                let encoded = cursor - start - 1;
                let mut next = cursor;
                while bytes.get(next).is_some_and(u8::is_ascii_whitespace) {
                    next += 1;
                }
                counter.string(encoded, bytes.get(next) == Some(&b':'), maximum)?;
            }
            _ => {
                let start = cursor;
                while bytes
                    .get(cursor)
                    .is_some_and(|byte| !b" \t\r\n,:]}".contains(byte))
                {
                    cursor += 1;
                }
                if cursor == start {
                    return Err(refused());
                }
            }
        }
    }
    if depth != 0 {
        return Err(refused());
    }
    counter.finish(root, element, maximum)
}

/// Names original raw-scan controls plus the actual shared accumulator adapters.
///
/// The old complete control terms remain; additional typed accumulator/input/
/// return views are explicit rather than described as spare old row capacity.
/// Compiler/recursive frames and allocator resources remain separate.
pub const fn counter_scratch_data() -> usize {
    size_of::<[u8; 64]>()
        + size_of::<DecodedStorage>()
        + size_of::<[usize; 6]>()
        + size_of::<[usize; 7]>()
        + size_of::<[usize; 6]>()
        + size_of::<[usize; 4]>()
        + size_of::<&[u8]>()
        + size_of::<&[usize]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<Counter>()
        + size_of::<Result<Counter, ProviderError>>()
        + size_of::<&mut Counter>()
        + size_of::<Result<(), ProviderError>>()
}

#[cfg(test)]
mod original;
#[cfg(test)]
mod tests;
