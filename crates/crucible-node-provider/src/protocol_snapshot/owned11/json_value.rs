//! Checks borrowed historical JSON before rebuilding its final data owners.
//!
//! Capacity rows follow the source metadata walk: a String row, a Vector row
//! before array children, or a Tree row before ordered key/value pairs. Primitive
//! values consume no row. This helper preserves requested String/Vec capacities;
//! tree populations do not describe hidden map nodes or allocator geometry.
//! The selected serde_json build must omit arbitrary_precision and preserve_order.
//! Numbers preserve actual captured serializer roundtrips. This is not arbitrary
//! numeric-token parity with serde_json's optional or default float parsers.
//! No decoded data creates a live source association or restoration permission.

use std::mem::size_of;

use serde_json::{Map, Number, Value};

use crate::ProviderError;
use crate::retained_metadata::records::{
    MetadataCapacityRecord, MetadataRecordKind, MetadataRecordRows,
};

mod native17_build;
pub(crate) use native17_build::{HistoricalJsonBuildAttempt, HistoricalStringBuildAttempt};

const MAXIMUM_DEPTH: usize = 64;
const MAXIMUM_NUMBER_BYTES: usize = 32;

/// Bounds logical parsing work and requested String/Vec backing independently.
#[derive(Clone, Copy, Debug)]
pub struct HistoricalJsonLimits {
    /// Bounds the complete borrowed JSON input, including whitespace.
    pub maximum_input_bytes: usize,
    /// Bounds visited values and object keys.
    pub maximum_nodes: usize,
    /// Bounds value nesting; the selected limit cannot exceed 64.
    pub maximum_depth: usize,
    /// Bounds summed requested String and Vec backing, excluding map nodes.
    pub maximum_owned_backing_bytes: usize,
    /// Bounds total initialized object entries, without inferring node geometry.
    pub maximum_tree_entries: usize,
}

/// Borrows a fully checked input and the exact capacity-row prefix it consumes.
///
/// Validation uses a fixed traversal stack and borrowed string tokens. No owned
/// JSON tree or decoded String is constructed before the full preflight succeeds.
/// Rebuilding is data-only: hidden tree nodes, allocation rounding and compiler
/// stack geometry require separate admission by the whole-owner caller.
pub struct ValidatedHistoricalJson<'input, 'records> {
    input: &'input [u8],
    original_records: MetadataRecordRows<'records>,
    remaining: MetadataRecordRows<'records>,
    consumed: usize,
}

impl<'input, 'records> ValidatedHistoricalJson<'input, 'records> {
    /// Validates grammar, ordering, layouts and capacity rows without ownership copies.
    ///
    /// The row prefix is checked completely; subsequent typed fields remain in
    /// [`Self::remaining_records`]. Object keys must be strictly ordered by their
    /// decoded UTF-8 contents, matching the selected original BTreeMap walk.
    ///
    /// # Errors
    /// Refuses malformed UTF-8/JSON, trailing data, invalid numbers or escapes,
    /// excessive work/depth/backing, mismatched rows/layouts and small capacities.
    pub fn validate(
        input: &'input [u8],
        records: MetadataRecordRows<'records>,
        limits: HistoricalJsonLimits,
    ) -> Result<Self, ProviderError> {
        if input.len() > limits.maximum_input_bytes
            || limits.maximum_depth == 0
            || limits.maximum_depth > MAXIMUM_DEPTH
        {
            return Err(credit());
        }
        std::str::from_utf8(input).map_err(|_| invalid())?;

        let mut cursor = Cursor::new(input);
        let mut ledger = Ledger::new(records.clone(), limits);
        let mut frames = [None; MAXIMUM_DEPTH];
        let mut depth = 0usize;

        loop {
            ledger.node()?;
            if depth >= limits.maximum_depth {
                return Err(credit());
            }
            cursor.whitespace();
            match cursor.peek() {
                Some(b'[') | Some(b'{') => {
                    let object = cursor.peek() == Some(b'{');
                    cursor.advance()?;
                    let kind = if object {
                        MetadataRecordKind::Tree
                    } else {
                        MetadataRecordKind::Vector
                    };
                    let layout = if object {
                        size_of::<String>() + size_of::<Value>()
                    } else {
                        size_of::<Value>()
                    };
                    let row = ledger.row(kind, layout)?;
                    let mut frame = ValidationFrame {
                        object,
                        extent: row.extent,
                        entries: 0,
                        previous_key: None,
                    };
                    cursor.whitespace();
                    if cursor.peek() == Some(frame.closing()) {
                        cursor.advance()?;
                        frame.finish()?;
                    } else {
                        if object {
                            frame.key(&mut cursor, &mut ledger)?;
                        }
                        frames[depth] = Some(frame);
                        depth += 1;
                        continue;
                    }
                }
                Some(b'"') => {
                    let token = cursor.string()?;
                    ledger.string(token.decoded_bytes)?;
                }
                Some(b'n') => cursor.literal(b"null")?,
                Some(b't') => cursor.literal(b"true")?,
                Some(b'f') => cursor.literal(b"false")?,
                Some(b'-' | b'0'..=b'9') => {
                    cursor.number()?;
                }
                _ => return Err(invalid()),
            }

            loop {
                cursor.whitespace();
                if depth == 0 {
                    if cursor.position != input.len() {
                        return Err(invalid());
                    }
                    return Ok(Self {
                        input,
                        original_records: records,
                        remaining: ledger.records,
                        consumed: ledger.consumed,
                    });
                }
                let frame = frames[depth - 1].as_mut().ok_or_else(invalid)?;
                frame.entries = frame.entries.checked_add(1).ok_or_else(credit)?;
                if frame.entries > frame.extent {
                    return Err(invalid());
                }
                if cursor.peek() == Some(frame.closing()) {
                    cursor.advance()?;
                    frame.finish()?;
                    frames[depth - 1] = None;
                    depth -= 1;
                    continue;
                }
                cursor.literal(b",")?;
                if frame.object {
                    frame.key(&mut cursor, &mut ledger)?;
                }
                break;
            }
        }
    }

    /// Reports exactly how many metadata prefix rows this input consumes.
    #[must_use]
    pub const fn consumed_record_count(&self) -> usize {
        self.consumed
    }

    /// Borrows the advanced row iterator for subsequent typed fields.
    #[must_use]
    pub fn remaining_records(&self) -> MetadataRecordRows<'records> {
        self.remaining.clone()
    }

    /// Rebuilds the final JSON data directly from the checked immutable input.
    ///
    /// Each String/Vec is reserved once at its recorded capacity before filling.
    /// No temporary DOM, serde string scratch or second owned key is introduced.
    /// BTreeMap insertion has no fallible node reservation API; logical entry
    /// bounds are not a physical allocation guarantee. The whole-owner live gate
    /// must remain refused without independent tree/stack/allocator admission.
    ///
    /// # Errors
    /// Refuses failed String/Vec reservation, capacity disagreement or a changed
    /// selected layout. Borrowed inputs and records are never mutated.
    pub fn reconstruct(&self) -> Result<Value, ProviderError> {
        let mut cursor = Cursor::new(self.input);
        let mut records = self.original_records.clone();
        let value = reconstruct_value(&mut cursor, &mut records)?;
        cursor.whitespace();
        if cursor.position != self.input.len() {
            return Err(invalid());
        }
        Ok(value)
    }

    /// Rebuilds an object directly into its final contract extensions tree.
    ///
    /// Root keys and child owners are constructed once. No temporary root
    /// serde_json Map/Value or second tree is created. Nested objects retain
    /// their final Value owners. Logical Tree rows still do not qualify hidden
    /// map nodes, control blocks, compiler stack or restoration authority.
    ///
    /// # Errors
    /// Refuses a non-object root before copying ownership, failed String/Vec
    /// reservation or capacity/layout disagreement. Inputs remain borrowed.
    pub fn reconstruct_extensions(
        &self,
    ) -> Result<crucible_node_contract::Extensions, ProviderError> {
        let mut cursor = Cursor::new(self.input);
        cursor.whitespace();
        cursor.literal(b"{")?;
        let mut records = self.original_records.clone();
        let root = next_row(&mut records)?;
        if root.kind != MetadataRecordKind::Tree
            || root.element_bytes != size_of::<String>() + size_of::<Value>()
            || root.alignment != std::mem::align_of::<String>().max(std::mem::align_of::<Value>())
        {
            return Err(invalid());
        }
        let mut extensions = crucible_node_contract::Extensions::new();
        cursor.whitespace();
        if cursor.peek() != Some(b'}') {
            loop {
                let key = owned_string(&mut cursor, &mut records)?;
                cursor.whitespace();
                cursor.literal(b":")?;
                let value = reconstruct_value(&mut cursor, &mut records)?;
                if extensions.insert(key, value).is_some() {
                    return Err(invalid());
                }
                cursor.whitespace();
                if cursor.peek() == Some(b'}') {
                    break;
                }
                cursor.literal(b",")?;
                cursor.whitespace();
            }
        }
        cursor.literal(b"}")?;
        cursor.whitespace();
        if cursor.position != self.input.len() || extensions.len() != root.extent {
            return Err(invalid());
        }
        Ok(extensions)
    }
}

// Returns one final child and advances the same borrowed cursor/row prefix.
// Both public entry points already checked their complete immutable grammar.
fn reconstruct_value(
    cursor: &mut Cursor<'_>,
    records: &mut MetadataRecordRows<'_>,
) -> Result<Value, ProviderError> {
    let mut frames: [Option<OwnedFrame>; MAXIMUM_DEPTH] = std::array::from_fn(|_| None);
    let mut depth = 0usize;

    loop {
        cursor.whitespace();
        let mut value = match cursor.peek() {
            Some(b'[') | Some(b'{') => {
                let object = cursor.peek() == Some(b'{');
                cursor.advance()?;
                let row = next_row(records)?;
                let mut frame = if object {
                    OwnedFrame::Object(Map::new(), None)
                } else {
                    let mut values = Vec::new();
                    values.try_reserve_exact(row.extent).map_err(|_| credit())?;
                    if values.capacity() != row.extent {
                        return Err(credit());
                    }
                    OwnedFrame::Array(values)
                };
                cursor.whitespace();
                if cursor.peek() == Some(frame.closing()) {
                    cursor.advance()?;
                    frame.into_value()
                } else {
                    frame.key(cursor, records)?;
                    if depth >= MAXIMUM_DEPTH {
                        return Err(invalid());
                    }
                    frames[depth] = Some(frame);
                    depth += 1;
                    continue;
                }
            }
            Some(b'"') => Value::String(owned_string(cursor, records)?),
            Some(b'n') => {
                cursor.literal(b"null")?;
                Value::Null
            }
            Some(b't') => {
                cursor.literal(b"true")?;
                Value::Bool(true)
            }
            Some(b'f') => {
                cursor.literal(b"false")?;
                Value::Bool(false)
            }
            Some(b'-' | b'0'..=b'9') => Value::Number(cursor.number()?),
            _ => return Err(invalid()),
        };

        loop {
            cursor.whitespace();
            if depth == 0 {
                return Ok(value);
            }
            let frame = frames[depth - 1].as_mut().ok_or_else(invalid)?;
            frame.append(value)?;
            if cursor.peek() == Some(frame.closing()) {
                cursor.advance()?;
                value = frames[depth - 1].take().ok_or_else(invalid)?.into_value();
                depth -= 1;
                continue;
            }
            cursor.literal(b",")?;
            frame.key(cursor, records)?;
            break;
        }
    }
}

struct Ledger<'records> {
    records: MetadataRecordRows<'records>,
    limits: HistoricalJsonLimits,
    consumed: usize,
    nodes: usize,
    backing: usize,
    trees: usize,
}

impl<'records> Ledger<'records> {
    fn new(records: MetadataRecordRows<'records>, limits: HistoricalJsonLimits) -> Self {
        Self {
            records,
            limits,
            consumed: 0,
            nodes: 0,
            backing: 0,
            trees: 0,
        }
    }

    fn node(&mut self) -> Result<(), ProviderError> {
        self.nodes = self.nodes.checked_add(1).ok_or_else(credit)?;
        if self.nodes > self.limits.maximum_nodes {
            return Err(credit());
        }
        Ok(())
    }

    fn row(
        &mut self,
        kind: MetadataRecordKind,
        layout: usize,
    ) -> Result<MetadataCapacityRecord, ProviderError> {
        let row = next_row(&mut self.records)?;
        let expected_alignment = match kind {
            MetadataRecordKind::String => 1,
            MetadataRecordKind::Vector => std::mem::align_of::<Value>(),
            MetadataRecordKind::Tree => {
                std::mem::align_of::<String>().max(std::mem::align_of::<Value>())
            }
            _ => return Err(invalid()),
        };
        if row.kind != kind || row.element_bytes != layout || row.alignment != expected_alignment {
            return Err(invalid());
        }
        self.consumed = self.consumed.checked_add(1).ok_or_else(credit)?;
        if kind == MetadataRecordKind::Tree {
            self.trees = self.trees.checked_add(row.extent).ok_or_else(credit)?;
            if self.trees > self.limits.maximum_tree_entries {
                return Err(credit());
            }
        } else {
            let bytes = row.extent.checked_mul(layout).ok_or_else(credit)?;
            self.backing = self.backing.checked_add(bytes).ok_or_else(credit)?;
            if self.backing > self.limits.maximum_owned_backing_bytes {
                return Err(credit());
            }
        }
        Ok(row)
    }

    fn string(&mut self, length: usize) -> Result<(), ProviderError> {
        if self.row(MetadataRecordKind::String, 1)?.extent < length {
            return Err(invalid());
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct ValidationFrame<'input> {
    object: bool,
    extent: usize,
    entries: usize,
    previous_key: Option<StringToken<'input>>,
}

impl<'input> ValidationFrame<'input> {
    fn closing(self) -> u8 {
        if self.object { b'}' } else { b']' }
    }

    fn finish(self) -> Result<(), ProviderError> {
        if self.object && self.entries != self.extent {
            return Err(invalid());
        }
        Ok(())
    }

    fn key(
        &mut self,
        cursor: &mut Cursor<'input>,
        ledger: &mut Ledger<'_>,
    ) -> Result<(), ProviderError> {
        ledger.node()?;
        cursor.whitespace();
        let key = cursor.string()?;
        ledger.string(key.decoded_bytes)?;
        if let Some(previous) = self.previous_key
            && !previous.strictly_before(key)?
        {
            return Err(invalid());
        }
        self.previous_key = Some(key);
        cursor.whitespace();
        cursor.literal(b":")
    }
}

enum OwnedFrame {
    Array(Vec<Value>),
    Object(Map<String, Value>, Option<String>),
}

impl OwnedFrame {
    fn closing(&self) -> u8 {
        match self {
            Self::Array(_) => b']',
            Self::Object(_, _) => b'}',
        }
    }

    fn key(
        &mut self,
        cursor: &mut Cursor<'_>,
        records: &mut MetadataRecordRows<'_>,
    ) -> Result<(), ProviderError> {
        if let Self::Object(_, pending) = self {
            cursor.whitespace();
            *pending = Some(owned_string(cursor, records)?);
            cursor.whitespace();
            cursor.literal(b":")?;
        }
        Ok(())
    }

    fn append(&mut self, value: Value) -> Result<(), ProviderError> {
        match self {
            Self::Array(values) => {
                if values.len() == values.capacity() {
                    return Err(invalid());
                }
                values.push(value);
            }
            Self::Object(values, pending) => {
                let key = pending.take().ok_or_else(invalid)?;
                if values.insert(key, value).is_some() {
                    return Err(invalid());
                }
            }
        }
        Ok(())
    }

    fn into_value(self) -> Value {
        match self {
            Self::Array(values) => Value::Array(values),
            Self::Object(values, _) => Value::Object(values),
        }
    }
}

fn next_row(records: &mut MetadataRecordRows<'_>) -> Result<MetadataCapacityRecord, ProviderError> {
    records.next().ok_or_else(invalid)?
}

fn owned_string(
    cursor: &mut Cursor<'_>,
    records: &mut MetadataRecordRows<'_>,
) -> Result<String, ProviderError> {
    let token = cursor.string()?;
    let row = next_row(records)?;
    let mut value = String::new();
    value.try_reserve_exact(row.extent).map_err(|_| credit())?;
    if value.capacity() != row.extent {
        return Err(credit());
    }
    let mut decoder = Cursor::new(token.encoded);
    while decoder.position < token.encoded.len() {
        value.push(decoder.character()?);
    }
    Ok(value)
}

#[derive(Clone, Copy)]
struct StringToken<'input> {
    encoded: &'input [u8],
    decoded_bytes: usize,
}

impl StringToken<'_> {
    fn strictly_before(self, other: Self) -> Result<bool, ProviderError> {
        let mut left = Cursor::new(self.encoded);
        let mut right = Cursor::new(other.encoded);
        while left.position < self.encoded.len() && right.position < other.encoded.len() {
            let a = left.character()?;
            let b = right.character()?;
            if a != b {
                return Ok(a < b);
            }
        }
        Ok(left.position == self.encoded.len() && right.position < other.encoded.len())
    }
}

struct Cursor<'input> {
    input: &'input [u8],
    position: usize,
}

impl<'input> Cursor<'input> {
    fn new(input: &'input [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.position).copied()
    }

    fn advance(&mut self) -> Result<u8, ProviderError> {
        let byte = self.peek().ok_or_else(invalid)?;
        self.position += 1;
        Ok(byte)
    }

    fn whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.position += 1;
        }
    }

    fn literal(&mut self, bytes: &[u8]) -> Result<(), ProviderError> {
        let end = self.position.checked_add(bytes.len()).ok_or_else(invalid)?;
        if self.input.get(self.position..end) != Some(bytes) {
            return Err(invalid());
        }
        self.position = end;
        Ok(())
    }

    fn string(&mut self) -> Result<StringToken<'input>, ProviderError> {
        self.literal(b"\"")?;
        let start = self.position;
        let mut decoded_bytes = 0usize;
        while self.peek() != Some(b'"') {
            decoded_bytes = decoded_bytes
                .checked_add(self.character()?.len_utf8())
                .ok_or_else(credit)?;
        }
        let end = self.position;
        self.advance()?;
        Ok(StringToken {
            encoded: &self.input[start..end],
            decoded_bytes,
        })
    }

    fn character(&mut self) -> Result<char, ProviderError> {
        let byte = self.advance()?;
        if byte < 0x20 {
            return Err(invalid());
        }
        if byte != b'\\' {
            // Inspect only one scalar. Rechecking the complete remaining input
            // for every character would make large strings quadratic.
            let width = match byte {
                0x20..=0x7f => 1,
                0xc2..=0xdf => 2,
                0xe0..=0xef => 3,
                0xf0..=0xf4 => 4,
                _ => return Err(invalid()),
            };
            let start = self.position - 1;
            let end = start.checked_add(width).ok_or_else(invalid)?;
            let bytes = self.input.get(start..end).ok_or_else(invalid)?;
            let scalar = std::str::from_utf8(bytes).map_err(|_| invalid())?;
            let value = scalar.chars().next().ok_or_else(invalid)?;
            self.position = end;
            return Ok(value);
        }
        match self.advance()? {
            b'"' => Ok('"'),
            b'\\' => Ok('\\'),
            b'/' => Ok('/'),
            b'b' => Ok('\u{8}'),
            b'f' => Ok('\u{c}'),
            b'n' => Ok('\n'),
            b'r' => Ok('\r'),
            b't' => Ok('\t'),
            b'u' => {
                let first = self.hex_quad()?;
                let point = if (0xd800..=0xdbff).contains(&first) {
                    self.literal(b"\\u")?;
                    let second = self.hex_quad()?;
                    if !(0xdc00..=0xdfff).contains(&second) {
                        return Err(invalid());
                    }
                    0x10000 + ((first - 0xd800) << 10) + second - 0xdc00
                } else {
                    first
                };
                char::from_u32(point).ok_or_else(invalid)
            }
            _ => Err(invalid()),
        }
    }

    fn hex_quad(&mut self) -> Result<u32, ProviderError> {
        let mut value = 0u32;
        for _ in 0..4 {
            let digit = self.advance()?;
            let digit = match digit {
                b'0'..=b'9' => u32::from(digit - b'0'),
                b'a'..=b'f' => u32::from(digit - b'a' + 10),
                b'A'..=b'F' => u32::from(digit - b'A' + 10),
                _ => return Err(invalid()),
            };
            value = value * 16 + digit;
        }
        Ok(value)
    }

    fn number(&mut self) -> Result<Number, ProviderError> {
        let start = self.position;
        if self.peek() == Some(b'-') {
            self.advance()?;
        }
        match self.advance()? {
            b'0' => {}
            b'1'..=b'9' => {
                while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                    self.advance()?;
                }
            }
            _ => return Err(invalid()),
        }
        if self.peek() == Some(b'.') {
            self.advance()?;
            self.digits()?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.advance()?;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.advance()?;
            }
            self.digits()?;
        }
        if self.position - start > MAXIMUM_NUMBER_BYTES
            || !matches!(
                self.peek(),
                None | Some(b' ' | b'\n' | b'\r' | b'\t' | b',' | b']' | b'}')
            )
        {
            return Err(invalid());
        }
        let text = std::str::from_utf8(&self.input[start..self.position]).map_err(|_| invalid())?;
        // serde_json's Number parser boxes errors, including overflow errors.
        // Keep failed preflight allocation-free and preserve the original
        // serializer's exact finite float roundtrip instead of using that parser.
        if !text.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E')) {
            if text.starts_with('-') {
                if let Ok(value) = text.parse::<i64>()
                    && value != 0
                {
                    return Ok(Number::from(value));
                }
            } else if let Ok(value) = text.parse::<u64>() {
                return Ok(Number::from(value));
            }
        }
        let value = text.parse::<f64>().map_err(|_| invalid())?;
        Number::from_f64(value).ok_or_else(invalid)
    }

    fn digits(&mut self) -> Result<(), ProviderError> {
        if !self.advance()?.is_ascii_digit() {
            return Err(invalid());
        }
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.advance()?;
        }
        Ok(())
    }
}

fn invalid() -> ProviderError {
    ProviderError::Frame("owned historical JSON grammar or capacities")
}

fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("owned historical JSON extent")
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "historical data fixtures fail at their original capacity or grammar assertion"
)]
mod tests {
    use super::*;
    use crate::retained_metadata::records::{MetadataRecordBank, ValidatedMetadataRecords};

    fn limits() -> HistoricalJsonLimits {
        HistoricalJsonLimits {
            maximum_input_bytes: 16 * 1024,
            maximum_nodes: 256,
            maximum_depth: 64,
            maximum_owned_backing_bytes: 16 * 1024,
            maximum_tree_entries: 64,
        }
    }

    fn rows(bytes: &[u8]) -> MetadataRecordRows<'_> {
        ValidatedMetadataRecords::validate(bytes, 256, 16 * 1024)
            .unwrap()
            .rows()
    }

    fn string(capacity: usize) -> MetadataCapacityRecord {
        MetadataCapacityRecord {
            kind: MetadataRecordKind::String,
            extent: capacity,
            element_bytes: 1,
            alignment: 1,
        }
    }

    fn vector(capacity: usize) -> MetadataCapacityRecord {
        MetadataCapacityRecord {
            kind: MetadataRecordKind::Vector,
            extent: capacity,
            element_bytes: size_of::<Value>(),
            alignment: std::mem::align_of::<Value>(),
        }
    }

    fn tree(entries: usize) -> MetadataCapacityRecord {
        MetadataCapacityRecord {
            kind: MetadataRecordKind::Tree,
            extent: entries,
            element_bytes: size_of::<String>() + size_of::<Value>(),
            alignment: std::mem::align_of::<String>().max(std::mem::align_of::<Value>()),
        }
    }

    fn capture(value: &Value, bank: &mut MetadataRecordBank) {
        match value {
            Value::String(text) => bank.append(string(text.capacity())).unwrap(),
            Value::Array(values) => {
                bank.append(vector(values.capacity())).unwrap();
                for child in values {
                    capture(child, bank);
                }
            }
            Value::Object(values) => {
                bank.append(tree(values.len())).unwrap();
                for (key, child) in values {
                    bank.append(string(key.capacity())).unwrap();
                    capture(child, bank);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    fn same_capacities(original: &Value, restored: &Value) {
        assert_eq!(original, restored);
        match (original, restored) {
            (Value::String(a), Value::String(b)) => assert_eq!(a.capacity(), b.capacity()),
            (Value::Array(a), Value::Array(b)) => {
                assert_eq!(a.capacity(), b.capacity());
                for (x, y) in a.iter().zip(b) {
                    same_capacities(x, y);
                }
            }
            (Value::Object(a), Value::Object(b)) => {
                assert_eq!(a.len(), b.len());
                for ((ak, av), (bk, bv)) in a.iter().zip(b) {
                    assert_eq!(ak.capacity(), bk.capacity());
                    same_capacities(av, bv);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn original_nested_strings_arrays_and_keys_keep_spare_capacities() {
        let mut text = String::with_capacity(47);
        text.push_str("quoted \" \\ newline\n café 😀");
        let empty = String::with_capacity(31);
        let mut children = Vec::with_capacity(9);
        children.push(Value::String(text));
        children.push(Value::String(empty));
        children.push(Value::Array(Vec::with_capacity(7)));
        children.push(Value::Bool(false));
        let mut key = String::with_capacity(53);
        key.push_str("original");
        let mut object = Map::new();
        object.insert(key, Value::Array(children));
        let original = Value::Object(object);
        let mut bank = MetadataRecordBank::reserve(32).unwrap();
        capture(&original, &mut bank);
        let bytes = serde_json::to_vec(&original).unwrap();
        let recorded = serde_json::to_vec(&bank).unwrap();

        let plan = ValidatedHistoricalJson::validate(&bytes, rows(&recorded), limits()).unwrap();
        assert_eq!(plan.consumed_record_count(), bank.rows().len());
        assert!(plan.remaining_records().next().is_none());
        let restored = plan.reconstruct().unwrap();

        same_capacities(&original, &restored);
        assert_eq!(serde_json::to_vec(&restored).unwrap(), bytes);
    }

    #[test]
    fn contract_extensions_are_built_directly_with_original_child_capacities() {
        let mut key = String::with_capacity(43);
        key.push_str("original/extension");
        let mut text = String::with_capacity(29);
        text.push_str("nested café");
        let mut values = Vec::with_capacity(8);
        values.push(Value::String(text));
        values.push(Value::Array(Vec::with_capacity(7)));
        let mut nested = Map::new();
        nested.insert(String::from("nested"), Value::Array(values));
        let mut original = crucible_node_contract::Extensions::new();
        original.insert(key, Value::Object(nested));
        let mut bank = MetadataRecordBank::reserve(32).unwrap();
        bank.append(tree(original.len())).unwrap();
        for (key, value) in &original {
            bank.append(string(key.capacity())).unwrap();
            capture(value, &mut bank);
        }
        let input = serde_json::to_vec(&original).unwrap();
        let recorded = serde_json::to_vec(&bank).unwrap();

        let plan = ValidatedHistoricalJson::validate(&input, rows(&recorded), limits()).unwrap();
        let restored = plan.reconstruct_extensions().unwrap();

        assert_eq!(restored, original);
        assert_eq!(serde_json::to_vec(&restored).unwrap(), input);
        for ((original_key, original_value), (restored_key, restored_value)) in
            original.iter().zip(&restored)
        {
            assert_eq!(original_key.capacity(), restored_key.capacity());
            same_capacities(original_value, restored_value);
        }
        let empty = serde_json::to_vec(&[tree(0)]).unwrap();
        let plan = ValidatedHistoricalJson::validate(b"{}", rows(&empty), limits()).unwrap();
        assert!(plan.reconstruct_extensions().unwrap().is_empty());
        for input in [b"null".as_slice(), b"true", b"1"] {
            let plan = ValidatedHistoricalJson::validate(input, rows(b"[]"), limits()).unwrap();
            assert!(plan.reconstruct_extensions().is_err());
        }
    }

    #[test]
    fn primitive_rows_are_absent_and_remaining_typed_rows_stay_borrowed() {
        let recorded = br#"[["string",19,1,1],["boxed",7,1,1]]"#;
        for input in [
            b"null".as_slice(),
            b"true",
            b"false",
            b"0",
            b"-0",
            b"-12",
            b"1.25e+2",
            b"18446744073709551615",
        ] {
            let plan = ValidatedHistoricalJson::validate(input, rows(recorded), limits()).unwrap();
            assert_eq!(plan.consumed_record_count(), 0);
            assert_eq!(
                plan.remaining_records().next().unwrap().unwrap(),
                string(19)
            );
            assert_eq!(
                plan.reconstruct().unwrap(),
                serde_json::from_slice::<Value>(input).unwrap()
            );
        }
        let plan =
            ValidatedHistoricalJson::validate(br#""borrowed""#, rows(recorded), limits()).unwrap();
        assert_eq!(plan.consumed_record_count(), 1);
        assert_eq!(
            plan.remaining_records().next().unwrap().unwrap().kind,
            MetadataRecordKind::Boxed
        );
    }

    #[test]
    fn escapes_surrogates_and_decoded_key_order_are_checked_without_dom() {
        let recorded = serde_json::to_vec(&[tree(2), string(8), string(8)]).unwrap();
        let input = br#"{"\u0061":null,"\ud83d\ude00":true}"#;
        let plan = ValidatedHistoricalJson::validate(input, rows(&recorded), limits()).unwrap();
        assert_eq!(
            plan.reconstruct().unwrap(),
            serde_json::from_slice::<Value>(input).unwrap()
        );
        for input in [
            br#"{"a":null,"\u0061":true}"#.as_slice(),
            br#"{"z":null,"a":true}"#,
        ] {
            assert!(ValidatedHistoricalJson::validate(input, rows(&recorded), limits()).is_err());
        }
        for input in [
            br#""\ud800""#.as_slice(),
            br#""\udc00""#,
            br#""\ud800\u0041""#,
            br#""\u0x00""#,
            br#""\q""#,
            b"\"line\nfeed\"",
        ] {
            assert!(
                ValidatedHistoricalJson::validate(input, rows(br#"[["string",32,1,1]]"#), limits())
                    .is_err()
            );
        }
    }

    #[test]
    fn malformed_trailing_nonfinite_and_oversized_tokens_refuse_preflight() {
        for input in [
            b"".as_slice(),
            b"[1,]",
            b"{\"a\":1,}",
            b"null false",
            b"01",
            b"-01",
            b"+1",
            b"1.",
            b"1e",
            b"1e+",
            b"1e400",
            b"12345678901234567890123456789012345",
            b"\"unterminated",
            b"\"\xff\"",
            b"[}",
        ] {
            let recorded = serde_json::to_vec(&[vector(4), string(32)]).unwrap();
            assert!(ValidatedHistoricalJson::validate(input, rows(&recorded), limits()).is_err());
        }
    }

    #[test]
    fn capacity_layout_population_and_work_ceilings_precede_reconstruction() {
        let input = br#"["large"]"#;
        let correct = serde_json::to_vec(&[vector(3), string(17)]).unwrap();
        assert!(ValidatedHistoricalJson::validate(input, rows(&correct), limits()).is_ok());
        for records in [
            vec![vector(0), string(17)],
            vec![vector(3), string(4)],
            vec![string(3), string(17)],
            vec![vector(3)],
            vec![
                MetadataCapacityRecord {
                    element_bytes: 1,
                    ..vector(3)
                },
                string(17),
            ],
        ] {
            let recorded = serde_json::to_vec(&records).unwrap();
            assert!(ValidatedHistoricalJson::validate(input, rows(&recorded), limits()).is_err());
        }
        for bounded in [
            HistoricalJsonLimits {
                maximum_input_bytes: input.len() - 1,
                ..limits()
            },
            HistoricalJsonLimits {
                maximum_nodes: 1,
                ..limits()
            },
            HistoricalJsonLimits {
                maximum_depth: 1,
                ..limits()
            },
            HistoricalJsonLimits {
                maximum_depth: 65,
                ..limits()
            },
            HistoricalJsonLimits {
                maximum_owned_backing_bytes: 1,
                ..limits()
            },
        ] {
            assert!(ValidatedHistoricalJson::validate(input, rows(&correct), bounded).is_err());
        }
        let object = br#"{"a":null}"#;
        for entries in [0, 2] {
            let recorded = serde_json::to_vec(&[tree(entries), string(4)]).unwrap();
            assert!(ValidatedHistoricalJson::validate(object, rows(&recorded), limits()).is_err());
        }
        let recorded = serde_json::to_vec(&[tree(1), string(4)]).unwrap();
        let bounded = HistoricalJsonLimits {
            maximum_tree_entries: 0,
            ..limits()
        };
        assert!(ValidatedHistoricalJson::validate(object, rows(&recorded), bounded).is_err());
    }

    #[test]
    fn fixed_stack_accepts_depth_boundary_and_refuses_the_next_value() {
        let allowed = format!("{}null{}", "[".repeat(63), "]".repeat(63));
        let denied = format!("{}null{}", "[".repeat(64), "]".repeat(64));
        let recorded = serde_json::to_vec(&vec![vector(1); 64]).unwrap();

        let plan = ValidatedHistoricalJson::validate(allowed.as_bytes(), rows(&recorded), limits())
            .unwrap();
        assert_eq!(plan.consumed_record_count(), 63);
        assert!(plan.reconstruct().is_ok());
        assert!(
            ValidatedHistoricalJson::validate(denied.as_bytes(), rows(&recorded), limits())
                .is_err()
        );
    }

    #[test]
    fn captured_floats_round_trip_original_bits_at_numeric_boundaries() {
        for original in [
            0.0f64,
            -0.0,
            1.0,
            f64::from_bits(1),
            -f64::from_bits(1),
            f64::MIN_POSITIVE,
            f64::MAX,
            -f64::MAX,
            0.1,
            f64::from_bits(0.1f64.to_bits() - 1),
            f64::from_bits(0.1f64.to_bits() + 1),
            9_007_199_254_740_991.0,
            9_007_199_254_740_992.0,
            9_007_199_254_740_994.0,
        ] {
            let captured = Number::from_f64(original).unwrap();
            let input = serde_json::to_vec(&captured).unwrap();
            let plan = ValidatedHistoricalJson::validate(&input, rows(b"[]"), limits()).unwrap();
            let restored = plan.reconstruct().unwrap();

            let Value::Number(restored) = restored else {
                panic!("captured numeric value changed type");
            };
            assert!(restored.is_f64());
            assert_eq!(restored, captured);
            assert_eq!(restored.as_f64().unwrap().to_bits(), original.to_bits());
            assert_eq!(serde_json::to_vec(&restored).unwrap(), input);
        }
        let integer = ValidatedHistoricalJson::validate(b"1", rows(b"[]"), limits())
            .unwrap()
            .reconstruct()
            .unwrap();
        let Value::Number(integer) = integer else {
            panic!("captured integer changed type");
        };
        assert!(integer.is_u64());
        assert!(!integer.is_f64());
        assert_eq!(integer, Number::from(1u64));

        let negative_zero = ValidatedHistoricalJson::validate(b"-0", rows(b"[]"), limits())
            .unwrap()
            .reconstruct()
            .unwrap();
        assert_eq!(
            negative_zero.as_f64().unwrap().to_bits(),
            (-0.0f64).to_bits()
        );
    }
}

/// Reports the declared fixed traversal arrays of this source-bound decoder.
///
/// Compiler frames and thread-stack peak remain independent of these explicit
/// arrays. No archive field can change their actual element layouts.
pub(crate) fn original_reconstruction_stack_bytes() -> usize {
    std::mem::size_of::<[Option<ValidationFrame<'static>>; MAXIMUM_DEPTH]>()
        + std::mem::size_of::<[Option<OwnedFrame>; MAXIMUM_DEPTH]>()
}

/// Compares one complete JSON string with borrowed decoded text without allocation.
///
/// This uses the same bounded escape/UTF-8/surrogate decoder as the historical
/// reader. It creates no String, Value, metadata row or reconstruction authority.
///
/// # Errors
/// Refuses invalid JSON string framing, escapes, Unicode or trailing bytes.
pub(crate) fn borrowed_json_string_matches_data(
    input: &[u8],
    expected: &str,
) -> Result<bool, ProviderError> {
    let mut cursor = Cursor::new(input);
    let token = cursor.string()?;
    if cursor.position != input.len() {
        return Err(invalid());
    }
    let mut decoder = Cursor::new(token.encoded);
    let mut actual = expected.chars();
    while decoder.position < token.encoded.len() {
        if actual.next() != Some(decoder.character()?) {
            return Ok(false);
        }
    }
    Ok(actual.next().is_none())
}

/// Names the borrowed string comparator's actual fixed cursor/character views.
pub(crate) const fn borrowed_json_string_comparison_counter_scratch_data() -> usize {
    std::mem::size_of::<[Cursor<'static>; 2]>()
        + std::mem::size_of::<StringToken<'static>>()
        + std::mem::size_of::<std::str::Chars<'static>>()
        + std::mem::size_of::<Option<char>>()
        + std::mem::size_of::<Result<char, ProviderError>>()
        + std::mem::size_of::<Result<bool, ProviderError>>()
        + std::mem::size_of::<[u32; 3]>()
        + std::mem::size_of::<[usize; 3]>()
}

#[cfg(test)]
mod borrowed_string_comparison_tests {
    use super::*;

    #[test]
    fn borrowed_comparison_decodes_controls_quotes_unicode_and_surrogate_pairs() {
        for (encoded, decoded) in [
            (
                r#""application/quote\"slash\\""#,
                "application/quote\"slash\\",
            ),
            (r#""domain\n\u0000""#, "domain\n\0"),
            (r#""\ud83d\ude00""#, "😀"),
            (r#""é/δ""#, "é/δ"),
        ] {
            assert!(borrowed_json_string_matches_data(encoded.as_bytes(), decoded).unwrap());
            assert!(!borrowed_json_string_matches_data(encoded.as_bytes(), "different").unwrap());
        }
        for malformed in [
            br#""\ud83d""#.as_slice(),
            br#""\x""#.as_slice(),
            br#""ok"0"#.as_slice(),
        ] {
            assert!(borrowed_json_string_matches_data(malformed, "anything").is_err());
        }
    }
}
