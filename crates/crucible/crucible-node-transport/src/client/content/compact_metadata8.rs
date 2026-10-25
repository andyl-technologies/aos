//! Validates edition-eight metadata capacities around unchanged content seven.
//!
//! The explicit wrapper preserves the entire checked byte/alias grammar and adds
//! independently admitted capacities for every owned row key and ContentRef string.
//! It neither changes edition seven nor issues native installation authority.
//!
//! ```json
//! ["source-private.client-content/8", ["source-private.client-content/7",1,1,1,0,[],[]], [], []]
//! ```

use super::{
    ClientContent,
    compact_cursor::{CompactContentLimits, ValidatedCompactContent},
};
use crate::ProviderError;
use crucible_node_format::ContentRef;
use serde::{
    Serialize, Serializer,
    ser::{SerializeSeq, SerializeTuple},
};

const TAG: &[u8] = b"[\"source-private.client-content/8\",";

/// Bounds original byte groups and separately retained metadata backing buffers.
#[derive(Clone, Copy, Debug)]
pub struct CompactMetadata8Limits {
    /// Admits the unchanged inner content-seven byte and alias data.
    pub content: CompactContentLimits,
    /// Bounds the sum of all original key and reference String capacities.
    pub maximum_metadata_capacity_bytes: usize,
}

/// Retains a checked immutable edition-eight data plan without allocating owners.
pub struct ValidatedCompactMetadata8<'a> {
    data: ValidatedCompactContent<'a>,
    transfers: &'a [u8],
    objects: &'a [u8],
    metadata_capacity_bytes: usize,
}

impl<'a> ValidatedCompactMetadata8<'a> {
    /// Admits full framing, original data and all metadata capacities before copies.
    ///
    /// The caller precharges the original cursor's fixed summary/parser scratch
    /// and this wrapper's fixed cursor/plan state plus compiler/thread stack.
    ///
    /// # Errors
    /// Refuses malformed/trailing framing, changed inner data, capacity smaller
    /// than its decoded field, overflow, roster mismatch or insufficient credit.
    pub fn validate(
        input: &'a [u8],
        limits: CompactMetadata8Limits,
    ) -> Result<Self, ProviderError> {
        if input.len() > limits.content.max_input_bytes {
            return Err(credit());
        }
        let mut cursor = Cursor::new(input);
        cursor.literal(TAG)?;
        let encoded = cursor.array()?;
        cursor.literal(b",")?;
        let transfers = cursor.array()?;
        cursor.literal(b",")?;
        let objects = cursor.array()?;
        cursor.literal(b"]")?;
        if cursor.position != input.len() {
            return Err(invalid());
        }

        let data = ValidatedCompactContent::validate(encoded, limits.content)?;
        let mut total = 0usize;
        validate_rows(
            data.transfers(),
            transfers,
            &mut total,
            limits.maximum_metadata_capacity_bytes,
        )?;
        validate_rows(
            data.objects(),
            objects,
            &mut total,
            limits.maximum_metadata_capacity_bytes,
        )?;
        Ok(Self {
            data,
            transfers,
            objects,
            metadata_capacity_bytes: total,
        })
    }

    /// Checks the complete aligned content8 prefix for compact-custody18.
    ///
    /// # Errors
    /// Refuses changed capacities, entry layouts, alignments or missing rows.
    pub(crate) fn validate_compact_custody18_capacity_rows<'records>(
        &self,
        records: crate::retained_metadata::records::MetadataRecordRows<'records>,
    ) -> Result<crate::retained_metadata::records::MetadataRecordRows<'records>, ProviderError>
    {
        use crate::retained_metadata::records::MetadataRecordKind;
        use std::mem::align_of;

        let remaining = self.validate_owned11_capacity_rows(records.clone())?;
        let mut aligned = records;
        for (entries, tree_alignment) in [
            (
                self.data.transfer_count(),
                align_of::<crucible_node_format::Id>().max(align_of::<super::Transfer>()),
            ),
            (
                self.data.object_count(),
                align_of::<String>().max(align_of::<(ContentRef, std::rc::Rc<Vec<u8>>)>()),
            ),
        ] {
            if aligned.next().ok_or_else(invalid)??.alignment != tree_alignment {
                return Err(invalid());
            }
            for _ in 0..entries {
                for _ in 0..7 {
                    let row = aligned.next().ok_or_else(invalid)??;
                    let expected = if row.kind == MetadataRecordKind::Shared {
                        align_of::<Vec<u8>>()
                    } else {
                        1
                    };
                    if row.alignment != expected {
                        return Err(invalid());
                    }
                }
            }
        }
        Ok(remaining)
    }

    pub(crate) fn validate_owned11_capacity_rows<'records>(
        &self,
        mut records: crate::retained_metadata::records::MetadataRecordRows<'records>,
    ) -> Result<crate::retained_metadata::records::MetadataRecordRows<'records>, ProviderError>
    {
        use crate::retained_metadata::records::MetadataRecordKind;
        expect_owned_row(
            &mut records,
            MetadataRecordKind::Tree,
            self.data.transfer_count(),
            std::mem::size_of::<crucible_node_format::Id>()
                + std::mem::size_of::<super::Transfer>(),
        )?;
        for (row, capacities) in self.data.transfers().zip(self.transfer_metadata()) {
            let row = row?;
            for capacity in capacities? {
                expect_owned_row(&mut records, MetadataRecordKind::String, capacity, 1)?;
            }
            expect_owned_row(
                &mut records,
                MetadataRecordKind::Shared,
                std::mem::size_of::<Vec<u8>>(),
                1,
            )?;
            expect_owned_row(&mut records, MetadataRecordKind::Vector, row.capacity, 1)?;
        }
        expect_owned_row(
            &mut records,
            MetadataRecordKind::Tree,
            self.data.object_count(),
            std::mem::size_of::<String>()
                + std::mem::size_of::<(ContentRef, std::rc::Rc<Vec<u8>>)>(),
        )?;
        for (row, capacities) in self.data.objects().zip(self.object_metadata()) {
            let row = row?;
            for capacity in capacities? {
                expect_owned_row(&mut records, MetadataRecordKind::String, capacity, 1)?;
            }
            expect_owned_row(
                &mut records,
                MetadataRecordKind::Shared,
                std::mem::size_of::<Vec<u8>>(),
                1,
            )?;
            expect_owned_row(&mut records, MetadataRecordKind::Vector, row.capacity, 1)?;
        }
        Ok(records)
    }

    /// Borrows the original checked byte-group and alias data.
    pub fn data(&self) -> &ValidatedCompactContent<'a> {
        &self.data
    }

    /// Reports the admitted sum of actual original metadata String capacities.
    pub fn metadata_capacity_bytes(&self) -> usize {
        self.metadata_capacity_bytes
    }

    /// Replays checked transfer metadata capacities in original row order.
    pub fn transfer_metadata(&self) -> MetadataCapacityRows<'a> {
        MetadataCapacityRows::new(self.transfers)
    }

    /// Replays checked object metadata capacities in original row order.
    pub fn object_metadata(&self) -> MetadataCapacityRows<'a> {
        MetadataCapacityRows::new(self.objects)
    }
}

/// Replays five checked key/algorithm/domain/digest/media capacities per row.
pub struct MetadataCapacityRows<'a> {
    cursor: Cursor<'a>,
    first: bool,
    finished: bool,
}

impl<'a> MetadataCapacityRows<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            cursor: Cursor { input, position: 1 },
            first: true,
            finished: false,
        }
    }
}

impl Iterator for MetadataCapacityRows<'_> {
    type Item = Result<[usize; 5], ProviderError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        if self.cursor.peek() == Some(b']') {
            self.finished = true;
            self.cursor.position += 1;
            return if self.cursor.position == self.cursor.input.len() {
                None
            } else {
                Some(Err(invalid()))
            };
        }
        let result = (|| {
            if !self.first {
                self.cursor.literal(b",")?;
            }
            self.first = false;
            self.cursor.literal(b"[")?;
            let mut fields = [0usize; 5];
            for (index, field) in fields.iter_mut().enumerate() {
                if index != 0 {
                    self.cursor.literal(b",")?;
                }
                *field = self.cursor.integer()?;
            }
            self.cursor.literal(b"]")?;
            Ok(fields)
        })();
        if result.is_err() {
            self.finished = true;
        }
        Some(result)
    }
}

fn validate_rows<'a>(
    rows: impl Iterator<Item = Result<super::compact_cursor::BorrowedContentRow<'a>, ProviderError>>,
    encoded: &[u8],
    total: &mut usize,
    maximum: usize,
) -> Result<(), ProviderError> {
    let mut capacities = MetadataCapacityRows::new(encoded);
    for row in rows {
        let row = row?;
        let actual = capacities.next().ok_or(invalid())??;
        let minimum = [
            row.key.len(),
            "blake3-256".len(),
            "cnp.blob.v1".len(),
            row.reference.digest().len(),
            row.reference.media_type_length(),
        ];
        for (capacity, length) in actual.into_iter().zip(minimum) {
            if capacity < length {
                return Err(invalid());
            }
            *total = total.checked_add(capacity).ok_or(credit())?;
            if *total > maximum {
                return Err(credit());
            }
        }
    }
    if capacities.next().is_some() {
        return Err(invalid());
    }
    Ok(())
}

fn invalid() -> ProviderError {
    ProviderError::Frame("invalid compact metadata8 data")
}

fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("compact metadata8 capacity credit")
}

struct Cursor<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.position).copied()
    }

    fn literal(&mut self, expected: &[u8]) -> Result<(), ProviderError> {
        let end = self.position.checked_add(expected.len()).ok_or(invalid())?;
        if self.input.get(self.position..end) != Some(expected) {
            return Err(invalid());
        }
        self.position = end;
        Ok(())
    }

    fn integer(&mut self) -> Result<usize, ProviderError> {
        let start = self.position;
        let mut value = 0usize;
        while let Some(byte @ b'0'..=b'9') = self.peek() {
            if self.position > start && self.input[start] == b'0' {
                return Err(invalid());
            }
            value = value
                .checked_mul(10)
                .and_then(|value| value.checked_add(usize::from(byte - b'0')))
                .ok_or(credit())?;
            self.position += 1;
        }
        if self.position == start {
            return Err(invalid());
        }
        Ok(value)
    }

    // Finds one bounded immutable array span; the two closed grammar parsers
    // subsequently validate every token. This scanner never decodes strings.
    fn array(&mut self) -> Result<&'a [u8], ProviderError> {
        if self.peek() != Some(b'[') {
            return Err(invalid());
        }
        let start = self.position;
        let mut stack = [0u8; 64];
        let mut depth = 0usize;
        let mut quoted = false;
        let mut escaped = false;
        while let Some(byte) = self.peek() {
            self.position += 1;
            if quoted {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    quoted = false;
                }
                continue;
            }
            match byte {
                b'"' => quoted = true,
                b'[' | b'{' => {
                    let slot = stack.get_mut(depth).ok_or(invalid())?;
                    *slot = byte;
                    depth += 1;
                }
                b']' | b'}' => {
                    depth = depth.checked_sub(1).ok_or(invalid())?;
                    let expected = if byte == b']' { b'[' } else { b'{' };
                    if stack[depth] != expected {
                        return Err(invalid());
                    }
                    if depth == 0 {
                        return Ok(&self.input[start..self.position]);
                    }
                }
                _ => {}
            }
        }
        Err(invalid())
    }
}

impl ClientContent {
    /// Borrows an explicit edition-eight value preserving original metadata capacities.
    ///
    /// This data serializer grants no source/native capture or installation
    /// rights. Existing edition-seven serializers and selection stay unchanged.
    pub fn original_compact_metadata8_view(&self) -> impl Serialize + '_ {
        Metadata8View(self)
    }
}

struct Metadata8View<'a>(&'a ClientContent);

impl Serialize for Metadata8View<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut tuple = serializer.serialize_tuple(4)?;
        tuple.serialize_element("source-private.client-content/8")?;
        tuple.serialize_element(&self.0.original_compact_protocol_view())?;
        tuple.serialize_element(&MetadataRowsView {
            content: self.0,
            transfers: true,
        })?;
        tuple.serialize_element(&MetadataRowsView {
            content: self.0,
            transfers: false,
        })?;
        tuple.end()
    }
}

struct MetadataRowsView<'a> {
    content: &'a ClientContent,
    transfers: bool,
}

impl Serialize for MetadataRowsView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut rows = serializer.serialize_seq(Some(if self.transfers {
            self.content.transfers.len()
        } else {
            self.content.objects.len()
        }))?;
        if self.transfers {
            for (id, transfer) in &self.content.transfers {
                rows.serialize_element(&capacities(id.allocated_capacity(), &transfer.reference))?;
            }
        } else {
            for (key, (reference, _)) in &self.content.objects {
                rows.serialize_element(&capacities(key.capacity(), reference))?;
            }
        }
        rows.end()
    }
}

fn capacities(key: usize, reference: &ContentRef) -> [usize; 5] {
    [
        key,
        reference.hash.algorithm.capacity(),
        reference.hash.domain.capacity(),
        reference.hash.digest.capacity(),
        reference.media_type.capacity(),
    ]
}

fn expect_owned_row(
    records: &mut crate::retained_metadata::records::MetadataRecordRows<'_>,
    kind: crate::retained_metadata::records::MetadataRecordKind,
    extent: usize,
    element_bytes: usize,
) -> Result<(), ProviderError> {
    let row = records.next().ok_or_else(invalid)??;
    if row.kind != kind || row.extent != extent || row.element_bytes != element_bytes {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::client::content::Transfer;
    use crucible_node_format::{Id, canonical};
    use std::rc::Rc;

    fn string(value: &str, capacity: usize) -> String {
        let mut owned = String::with_capacity(capacity);
        owned.push_str(value);
        owned
    }

    fn reference(bytes: &[u8], extra: usize) -> ContentRef {
        let mut reference = canonical::content_ref(bytes, "application/octet-stream").unwrap();
        reference.hash.algorithm = string(&reference.hash.algorithm, 16 + extra);
        reference.hash.domain = string(&reference.hash.domain, 24 + extra);
        reference.hash.digest = string(&reference.hash.digest, 96 + extra);
        reference.media_type = string(&reference.media_type, 48 + extra);
        reference
    }

    fn fixture() -> ClientContent {
        let mut first = Vec::with_capacity(64);
        first.extend_from_slice(b"same");
        let first = Rc::new(first);
        let mut second = Vec::with_capacity(96);
        second.extend_from_slice(b"same");
        let mut content = ClientContent::new(1024, 8, 256).unwrap();
        content.reserved = 12;
        content.transfers.insert(
            Id::new(string("first", 32)).unwrap(),
            Transfer {
                reference: reference(b"same", 0),
                bytes: first.clone(),
                complete: true,
            },
        );
        content.transfers.insert(
            Id::new(string("second", 48)).unwrap(),
            Transfer {
                reference: reference(b"same", 16),
                bytes: Rc::new(second),
                complete: true,
            },
        );
        let alias = reference(b"same", 32);
        content
            .objects
            .insert(string(&alias.hash.digest, 160), (alias, first));
        let empty = reference(b"", 48);
        content.objects.insert(
            string(&empty.hash.digest, 192),
            (empty, Rc::new(Vec::with_capacity(32))),
        );
        content
    }

    fn limits(input: &[u8], metadata: usize) -> CompactMetadata8Limits {
        CompactMetadata8Limits {
            content: CompactContentLimits {
                max_input_bytes: input.len(),
                max_rows: 4,
                max_groups: 3,
                max_first_group_capacity_bytes: 192,
            },
            maximum_metadata_capacity_bytes: metadata,
        }
    }

    #[test]
    fn explicit_metadata8_preserves_all_original_string_and_byte_capacities() {
        let original = fixture();
        let encoded = serde_json::to_vec(&original.original_compact_metadata8_view()).unwrap();
        let plan =
            ValidatedCompactMetadata8::validate(&encoded, limits(&encoded, usize::MAX)).unwrap();
        let exact = plan.metadata_capacity_bytes();

        let restored =
            ClientContent::decode_compact_metadata8_data(&encoded, limits(&encoded, exact))
                .unwrap();

        assert_eq!(
            serde_json::to_vec(&restored.original_compact_metadata8_view()).unwrap(),
            encoded
        );
        assert_eq!(restored.reserved, 12);
        let first = &restored.transfers[&Id::new("first").unwrap()];
        let second = &restored.transfers[&Id::new("second").unwrap()];
        let alias = &restored.objects[&first.reference.hash.digest];
        assert!(Rc::ptr_eq(&first.bytes, &alias.1));
        assert!(!Rc::ptr_eq(&first.bytes, &second.bytes));
        assert_eq!(first.bytes.capacity(), 64);
        assert_eq!(second.bytes.capacity(), 96);
        assert_eq!(
            restored
                .transfers
                .keys()
                .next()
                .unwrap()
                .allocated_capacity(),
            32
        );
        assert!(
            restored
                .objects
                .values()
                .any(|(_, bytes)| bytes.is_empty() && bytes.capacity() == 32)
        );
        assert!(
            ClientContent::decode_compact_metadata8_data(&encoded, limits(&encoded, exact - 1))
                .is_err()
        );
        assert!(
            ClientContent::decode_compact_protocol_data(&encoded, limits(&encoded, exact).content)
                .is_err()
        );
    }

    #[test]
    fn metadata8_rejects_incomplete_rosters_and_capacity_smaller_than_original_field() {
        let encoded = serde_json::to_vec(&fixture().original_compact_metadata8_view()).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        value[2][0][0] = serde_json::json!(0);
        let too_small = serde_json::to_vec(&value).unwrap();
        assert!(
            ValidatedCompactMetadata8::validate(&too_small, limits(&too_small, usize::MAX))
                .is_err()
        );
        value[2] = serde_json::json!([]);
        let missing = serde_json::to_vec(&value).unwrap();
        assert!(
            ValidatedCompactMetadata8::validate(&missing, limits(&missing, usize::MAX)).is_err()
        );
        value[2] =
            serde_json::json!([[32, 16, 24, 96, 48], [48, 32, 40, 112, 64], [0, 0, 0, 0, 0]]);
        let extra = serde_json::to_vec(&value).unwrap();
        assert!(ValidatedCompactMetadata8::validate(&extra, limits(&extra, usize::MAX)).is_err());
    }

    #[test]
    fn metadata8_rejects_escaped_numeric_and_trailing_nested_tokens_without_serde() {
        let inner = serde_json::to_vec(&fixture().original_compact_protocol_view()).unwrap();
        let prefix = format!(
            "[\"source-private.client-content/8\",{},",
            std::str::from_utf8(&inner).unwrap()
        );
        for tail in [
            format!("[[\"{}\",16,24,96,48]],[]]", "\\u0030".repeat(1024)),
            "[[184467440737095516159999,16,24,96,48]],[]]".to_owned(),
            "[],[],{\"unexpected\":[[[true]]]}]".to_owned(),
            "[[01,16,24,96,48]],[]]".to_owned(),
        ] {
            let encoded = format!("{prefix}{tail}").into_bytes();
            assert!(ValidatedCompactMetadata8::validate(&encoded, limits(&encoded, 16)).is_err());
        }
    }
}
