//! Validates borrowed ClientContent7 byte groups and historical alias edges.
//!
//! The canonical format is a closed, whitespace-free JSON tuple:
//!
//! ```text
//! ["source-private.client-content/7",maxBytes,maxObjects,maxChunk,reserved,
//!  [[id,reference,["transfer",firstIndex],capacity,complete,payload]],
//!  [[digest,reference,[kind,firstIndex],capacity,payload]]]
//! ```
//!
//! Each first group carries a compact-byte tuple; aliases carry `null` and name
//! that first group. Equal bytes never establish an alias. Validation allocates
//! nothing and uses a fixed summary bank, whose declared storage must be charged
//! before invocation. This data format omits original metadata String capacities
//! and supplies neither complete allocation restoration nor source, hash,
//! Capture, adoption or native execution authority.

use crate::ProviderError;
use crate::protocol_snapshot::compact_bytes::ValidatedCompactBytes;

const ROSTER_LIMIT: usize = 4096;
const TOTAL_ROW_LIMIT: usize = 2 * ROSTER_LIMIT;

/// Bounds encoded input, actual row population and original byte capacities.
///
/// These caller-selected data allowances are independent of the serialized
/// logical content limits. They do not reserve storage or authenticate custody.
#[derive(Clone, Copy, Debug)]
pub struct CompactContentLimits {
    /// Maximum complete canonical input extent in bytes.
    pub max_input_bytes: usize,
    /// Maximum combined transfer and object rows, at most 8192.
    pub max_rows: usize,
    /// Maximum payload-bearing first groups, at most 8192.
    pub max_groups: usize,
    /// Maximum checked sum of first groups' original Vec capacities in bytes.
    pub max_first_group_capacity_bytes: usize,
}

impl CompactContentLimits {
    /// Returns the existing decoder's compiled combined transfer/object ceiling.
    ///
    /// This constant DATA neither admits those rows nor alters their signed
    /// limits. The actual decoder retains its independent checks on both rosters.
    pub(crate) const fn maximum_supported_combined_rows_data() -> usize {
        TOTAL_ROW_LIMIT
    }
}

/// Retains the original logical limits without normalizing historical credit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredContentLimits {
    /// Original logical maximum bytes; distinct from spare allocation capacity.
    pub maximum_bytes: usize,
    /// Original logical maximum objects; distinct from decoder row admission.
    pub maximum_objects: usize,
    /// Original maximum content chunk extent.
    pub maximum_chunk: usize,
}

/// Identifies the roster containing a first original byte group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentGroupKind {
    /// A first payload-bearing transfer row.
    Transfer,
    /// A first payload-bearing object row.
    Object,
}

/// Names a historical first group without authenticating a native allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContentGroupEdge {
    /// Roster containing the first group.
    pub kind: ContentGroupKind,
    /// Zero-based ordinal of the first payload-bearing row in that roster.
    pub index: usize,
}

/// Borrows a checked ContentRef representation and its bounded scalar fields.
#[derive(Clone, Copy, Debug)]
pub struct BorrowedContentReference<'a> {
    raw: &'a [u8],
    digest: &'a str,
    length: u64,
    media: &'a [u8],
    media_length: usize,
}

impl<'a> BorrowedContentReference<'a> {
    /// Returns the entire original canonical ContentRef JSON slice.
    pub fn encoded(&self) -> &'a [u8] {
        self.raw
    }

    /// Returns the checked lowercase digest; no payload hash is verified here.
    pub fn digest(&self) -> &'a str {
        self.digest
    }

    /// Returns the original declared U64 length.
    pub fn length(&self) -> u64 {
        self.length
    }

    /// Returns the printable ASCII media type's unescaped length.
    pub fn media_type_length(&self) -> usize {
        self.media_length
    }

    /// Iterates the bounded media bytes, unescaping only quote and backslash.
    pub fn media_type_bytes(&self) -> impl Iterator<Item = u8> + 'a {
        MediaBytes {
            remaining: self.media,
        }
    }
}

/// Borrows one fully framed row and its optional original first-group payload.
///
/// Metadata String capacities are absent from edition7. Hash verification and
/// owning reconstruction remain the caller's separate responsibilities.
pub struct BorrowedContentRow<'a> {
    /// Original Id for a transfer, or exact digest key for an object.
    pub key: &'a str,
    /// Entire checked original reference and its bounded fields.
    pub reference: BorrowedContentReference<'a>,
    /// Checked first-group ordinal and roster kind.
    pub edge: ContentGroupEdge,
    /// Original Vec allocation capacity, including empty spare capacity.
    pub capacity: usize,
    /// Original transfer completion flag; absent for object rows.
    pub complete: Option<bool>,
    /// Borrowed validated payload for a first group; aliases retain `None`.
    pub payload: Option<ValidatedCompactBytes<'a>>,
}

#[derive(Clone, Copy)]
struct GroupSummary<'a> {
    digest: &'a str,
    declared_length: u64,
    capacity: usize,
    decoded_length: usize,
}

struct SummaryBank<'a> {
    transfers: [Option<GroupSummary<'a>>; ROSTER_LIMIT],
    objects: [Option<GroupSummary<'a>>; ROSTER_LIMIT],
}

/// Reports the exact declared fixed summary bank size for decoder admission.
///
/// The caller must precharge this temporary storage before validation. This is
/// `size_of` of the two bounded summary arrays, not compiler stack spills,
/// thread-stack reservation or the owning/native executor's complete peak.
pub const fn compact_content_summary_bank_bytes() -> usize {
    size_of::<SummaryBank<'static>>()
}

/// Reports declared parser cursor, row and stored-header scratch sizes.
///
/// These named data structures supplement the summary bank. This quantity does
/// not claim complete physical stack/ABI/compiler temporary geometry; the
/// owning source must separately account that implementation's remaining peak.
pub const fn compact_content_parser_scratch_bytes() -> usize {
    size_of::<Cursor<'static>>()
        + size_of::<BorrowedContentRow<'static>>()
        + size_of::<StoredContentLimits>()
}

/// Borrows a completely validated representation without owning decoded bytes.
///
/// Validation checks all rows, capacities, aliases and trailing bytes before
/// any owning reconstruction. Private fields prevent bypassing validation.
pub struct ValidatedCompactContent<'a> {
    limits: StoredContentLimits,
    reserved: usize,
    transfers: &'a [u8],
    objects: &'a [u8],
    transfer_count: usize,
    object_count: usize,
    group_count: usize,
    group_capacity: usize,
}

impl<'a> ValidatedCompactContent<'a> {
    /// Validates the entire closed tuple using bounded fixed scratch only.
    ///
    /// Each roster is limited to 4096 rows. The caller must admit the declared
    /// summary-bank/parser scratch before invoking this method, independently
    /// of original byte capacities. Row counts are independent of the stored
    /// logical `maximum_objects`; historical credit is retained unchanged.
    ///
    /// # Errors
    /// Rejects unsupported grammar, overflow, invalid fields, aliases to
    /// nonfirst/future groups, changed alias capacities/references, inconsistent
    /// payload lengths, trailing bytes, or exceeded caller allowances.
    pub fn validate(input: &'a [u8], limits: CompactContentLimits) -> Result<Self, ProviderError> {
        if input.len() > limits.max_input_bytes
            || limits.max_rows > TOTAL_ROW_LIMIT
            || limits.max_groups > TOTAL_ROW_LIMIT
        {
            return Err(allowance_error());
        }

        let mut cursor = Cursor::new(input);
        cursor.literal(b"[\"source-private.client-content/7\",")?;
        let stored = StoredContentLimits {
            maximum_bytes: cursor.usize()?,
            maximum_objects: cursor.comma_usize()?,
            maximum_chunk: cursor.comma_usize()?,
        };
        let reserved = cursor.comma_usize()?;
        if stored.maximum_bytes == 0
            || !(1..=ROSTER_LIMIT).contains(&stored.maximum_objects)
            || !(1..=1024 * 1024).contains(&stored.maximum_chunk)
            || reserved > stored.maximum_bytes
        {
            return Err(grammar_error());
        }

        validate_rosters(cursor, stored, reserved, limits)
    }

    /// Returns the exact stored logical limits.
    pub fn stored_limits(&self) -> StoredContentLimits {
        self.limits
    }

    /// Returns original reserved credit without refund or recomputation.
    pub fn reserved(&self) -> usize {
        self.reserved
    }

    /// Returns the admitted transfer row count.
    pub fn transfer_count(&self) -> usize {
        self.transfer_count
    }

    /// Returns the admitted object row count.
    pub fn object_count(&self) -> usize {
        self.object_count
    }

    /// Returns the number of distinct payload-bearing first groups.
    pub fn first_group_count(&self) -> usize {
        self.group_count
    }

    /// Returns the checked sum of first groups' original byte capacities.
    pub fn first_group_capacity_bytes(&self) -> usize {
        self.group_capacity
    }

    /// Iterates borrowed transfer rows without allocations or byte copies.
    ///
    /// Each result retains the original payload plan/reference. Immutable input
    /// already passed complete validation; iterator errors are explicit rather
    /// than panics or silent truncation if an internal invariant changes.
    pub fn transfers(&self) -> CompactContentRows<'a> {
        CompactContentRows::new(self.transfers, ContentGroupKind::Transfer)
    }

    /// Iterates borrowed object rows without allocations or byte copies.
    pub fn objects(&self) -> CompactContentRows<'a> {
        CompactContentRows::new(self.objects, ContentGroupKind::Object)
    }
}

/// Reparses one validated roster sequentially without retaining a tree.
pub struct CompactContentRows<'a> {
    cursor: Cursor<'a>,
    kind: ContentGroupKind,
    finished: bool,
}

impl<'a> CompactContentRows<'a> {
    fn new(input: &'a [u8], kind: ContentGroupKind) -> Self {
        Self {
            cursor: Cursor::new(input),
            kind,
            finished: false,
        }
    }
}

impl<'a> Iterator for CompactContentRows<'a> {
    type Item = Result<BorrowedContentRow<'a>, ProviderError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished || self.cursor.at_end() {
            return None;
        }
        let result = self.cursor.row(self.kind).and_then(|row| {
            if !self.cursor.at_end() {
                self.cursor.literal(b",")?;
            }
            Ok(row)
        });
        if result.is_err() {
            self.finished = true;
        }
        Some(result)
    }
}

fn validate_rosters<'a>(
    mut cursor: Cursor<'a>,
    stored: StoredContentLimits,
    reserved: usize,
    limits: CompactContentLimits,
) -> Result<ValidatedCompactContent<'a>, ProviderError> {
    let mut bank = SummaryBank {
        transfers: [None; ROSTER_LIMIT],
        objects: [None; ROSTER_LIMIT],
    };
    let mut counts = [0_usize; 2];
    let mut spans = [&[][..]; 2];
    let mut group_count = 0_usize;
    let mut group_capacity = 0_usize;

    for (roster, kind) in [ContentGroupKind::Transfer, ContentGroupKind::Object]
        .into_iter()
        .enumerate()
    {
        cursor.literal(b",[")?;
        let start = cursor.position;
        let mut previous_key: Option<&str> = None;
        while cursor.peek() != Some(b']') {
            let index = counts[roster];
            if index >= ROSTER_LIMIT || counts[0] + counts[1] >= limits.max_rows {
                return Err(allowance_error());
            }
            let row = cursor.row(kind)?;
            if previous_key.is_some_and(|previous| previous >= row.key) {
                return Err(grammar_error());
            }
            previous_key = Some(row.key);

            let summary = if let Some(payload) = &row.payload {
                if row.edge != (ContentGroupEdge { kind, index }) {
                    return Err(grammar_error());
                }
                group_count = group_count.checked_add(1).ok_or_else(grammar_error)?;
                group_capacity = group_capacity
                    .checked_add(row.capacity)
                    .ok_or_else(grammar_error)?;
                if group_count > limits.max_groups
                    || group_capacity > limits.max_first_group_capacity_bytes
                {
                    return Err(allowance_error());
                }
                Some(GroupSummary {
                    digest: row.reference.digest,
                    declared_length: row.reference.length,
                    capacity: row.capacity,
                    decoded_length: payload.decoded_length(),
                })
            } else {
                let target = match row.edge.kind {
                    ContentGroupKind::Transfer if row.edge.index < counts[0] => {
                        bank.transfers[row.edge.index]
                    }
                    ContentGroupKind::Object
                        if kind == ContentGroupKind::Object && row.edge.index < index =>
                    {
                        bank.objects[row.edge.index]
                    }
                    _ => None,
                }
                .ok_or_else(grammar_error)?;
                if target.capacity != row.capacity
                    || target.digest != row.reference.digest
                    || target.declared_length != row.reference.length
                {
                    return Err(grammar_error());
                }
                validate_payload_length(target.decoded_length, row.reference.length, row.complete)?;
                None
            };
            match kind {
                ContentGroupKind::Transfer => bank.transfers[index] = summary,
                ContentGroupKind::Object => bank.objects[index] = summary,
            }
            counts[roster] += 1;
            if cursor.peek() == Some(b',') {
                cursor.literal(b",")?;
                if cursor.peek() == Some(b']') {
                    return Err(grammar_error());
                }
            } else if cursor.peek() != Some(b']') {
                return Err(grammar_error());
            }
        }
        spans[roster] = &cursor.input[start..cursor.position];
        cursor.literal(b"]")?;
    }
    cursor.literal(b"]")?;
    if !cursor.at_end() {
        return Err(grammar_error());
    }
    Ok(ValidatedCompactContent {
        limits: stored,
        reserved,
        transfers: spans[0],
        objects: spans[1],
        transfer_count: counts[0],
        object_count: counts[1],
        group_count,
        group_capacity,
    })
}

fn validate_payload_length(
    decoded: usize,
    declared: u64,
    complete: Option<bool>,
) -> Result<(), ProviderError> {
    let decoded = u64::try_from(decoded).map_err(|_| grammar_error())?;
    if decoded > declared || (complete != Some(false) && decoded != declared) {
        return Err(grammar_error());
    }
    Ok(())
}

struct Cursor<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn at_end(&self) -> bool {
        self.position == self.input.len()
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.position).copied()
    }

    fn literal(&mut self, value: &[u8]) -> Result<(), ProviderError> {
        let end = self
            .position
            .checked_add(value.len())
            .ok_or_else(grammar_error)?;
        if self.input.get(self.position..end) != Some(value) {
            return Err(grammar_error());
        }
        self.position = end;
        Ok(())
    }

    fn number(&mut self) -> Result<u64, ProviderError> {
        let start = self.position;
        let mut value = 0_u64;
        while let Some(digit @ b'0'..=b'9') = self.peek() {
            value = value
                .checked_mul(10)
                .and_then(|n| n.checked_add(u64::from(digit - b'0')))
                .ok_or_else(grammar_error)?;
            self.position += 1;
        }
        if self.position == start || (self.position - start > 1 && self.input[start] == b'0') {
            return Err(grammar_error());
        }
        Ok(value)
    }

    fn usize(&mut self) -> Result<usize, ProviderError> {
        usize::try_from(self.number()?).map_err(|_| grammar_error())
    }

    fn comma_usize(&mut self) -> Result<usize, ProviderError> {
        self.literal(b",")?;
        self.usize()
    }

    fn ascii_string(
        &mut self,
        maximum: usize,
        escapes: bool,
    ) -> Result<(&'a [u8], usize), ProviderError> {
        self.literal(b"\"")?;
        let start = self.position;
        let mut length = 0;
        loop {
            match self.peek() {
                Some(b'"') => break,
                Some(b'\\') if escapes => {
                    self.position += 1;
                    if !matches!(self.peek(), Some(b'"' | b'\\')) {
                        return Err(grammar_error());
                    }
                    self.position += 1;
                }
                Some(b' '..=b'~') if self.peek() != Some(b'\\') => self.position += 1,
                _ => return Err(grammar_error()),
            }
            length += 1;
            if length > maximum {
                return Err(grammar_error());
            }
        }
        if length == 0 {
            return Err(grammar_error());
        }
        let raw = &self.input[start..self.position];
        self.literal(b"\"")?;
        Ok((raw, length))
    }

    fn reference(&mut self) -> Result<BorrowedContentReference<'a>, ProviderError> {
        let start = self.position;
        self.literal(
            b"{\"hash\":{\"algorithm\":\"blake3-256\",\"domain\":\"cnp.blob.v1\",\"digest\":",
        )?;
        let (digest, _) = self.ascii_string(64, false)?;
        validate_digest(digest)?;
        self.literal(b"},\"length\":\"")?;
        let length = self.number()?;
        self.literal(b"\",\"media_type\":")?;
        let (media, media_length) = self.ascii_string(128, true)?;
        self.literal(b"}")?;
        Ok(BorrowedContentReference {
            raw: &self.input[start..self.position],
            digest: ascii(digest)?,
            length,
            media,
            media_length,
        })
    }

    fn row(&mut self, kind: ContentGroupKind) -> Result<BorrowedContentRow<'a>, ProviderError> {
        self.literal(b"[")?;
        let (key, _) = self.ascii_string(128, false)?;
        match kind {
            ContentGroupKind::Transfer => validate_id(key)?,
            ContentGroupKind::Object => validate_digest(key)?,
        }
        self.literal(b",")?;
        let reference = self.reference()?;
        if kind == ContentGroupKind::Object && key != reference.digest.as_bytes() {
            return Err(grammar_error());
        }
        self.literal(b",[")?;
        let edge_kind = if self.input[self.position..].starts_with(b"\"transfer\",") {
            self.literal(b"\"transfer\",")?;
            ContentGroupKind::Transfer
        } else {
            self.literal(b"\"object\",")?;
            ContentGroupKind::Object
        };
        let index = self.usize()?;
        self.literal(b"]")?;
        let capacity = self.comma_usize()?;
        self.literal(b",")?;
        let complete = if kind == ContentGroupKind::Transfer {
            let value = if self.input[self.position..].starts_with(b"true") {
                self.literal(b"true")?;
                true
            } else {
                self.literal(b"false")?;
                false
            };
            self.literal(b",")?;
            Some(value)
        } else {
            None
        };
        let payload = if self.input[self.position..].starts_with(b"null") {
            self.literal(b"null")?;
            None
        } else {
            let raw = self.payload_span()?;
            let plan = ValidatedCompactBytes::validate(raw, raw.len(), capacity)?;
            validate_payload_length(plan.decoded_length(), reference.length, complete)?;
            Some(plan)
        };
        self.literal(b"]")?;
        Ok(BorrowedContentRow {
            key: ascii(key)?,
            reference,
            edge: ContentGroupEdge {
                kind: edge_kind,
                index,
            },
            capacity,
            complete,
            payload,
        })
    }

    // Only the compact leaf's two array levels are recognized. The complete
    // extracted span still passes its own strict grammar/pad-bit validator.
    fn payload_span(&mut self) -> Result<&'a [u8], ProviderError> {
        let start = self.position;
        self.literal(b"[")?;
        let mut depth = 1;
        let mut string = false;
        while let Some(byte) = self.peek() {
            self.position += 1;
            if byte == b'"' {
                string = !string;
            } else if string {
                if byte == b'\\' || !byte.is_ascii_graphic() {
                    return Err(grammar_error());
                }
            } else if byte == b'[' {
                depth += 1;
                if depth > 2 {
                    return Err(grammar_error());
                }
            } else if byte == b']' {
                depth -= 1;
                if depth == 0 {
                    return Ok(&self.input[start..self.position]);
                }
            }
        }
        Err(grammar_error())
    }
}

struct MediaBytes<'a> {
    remaining: &'a [u8],
}

impl Iterator for MediaBytes<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let (&first, rest) = self.remaining.split_first()?;
        if first == b'\\' {
            let (&escaped, rest) = rest.split_first()?;
            self.remaining = rest;
            Some(escaped)
        } else {
            self.remaining = rest;
            Some(first)
        }
    }
}

fn ascii(bytes: &[u8]) -> Result<&str, ProviderError> {
    std::str::from_utf8(bytes).map_err(|_| grammar_error())
}

fn validate_digest(bytes: &[u8]) -> Result<(), ProviderError> {
    if bytes.len() != 64
        || !bytes
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(grammar_error());
    }
    Ok(())
}

fn validate_id(bytes: &[u8]) -> Result<(), ProviderError> {
    if !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        || !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(b))
    {
        return Err(grammar_error());
    }
    Ok(())
}

fn grammar_error() -> ProviderError {
    ProviderError::Frame("noncanonical compact content or alias geometry")
}

fn allowance_error() -> ProviderError {
    ProviderError::ResourceExhausted("compact content data allowance")
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "Malformed-format controls use panic as their assertion signal"
)]
mod tests {
    use super::*;
    use crate::client::content::{ClientContent, Transfer};
    use crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes;
    use crucible_node_format::{Id, canonical};
    use serde_json::{Value, json};
    use std::rc::Rc;

    fn limits() -> CompactContentLimits {
        CompactContentLimits {
            max_input_bytes: 32 * 1024 * 1024,
            max_rows: 8192,
            max_groups: 8192,
            max_first_group_capacity_bytes: 1024 * 1024,
        }
    }

    fn payload(bytes: &[u8]) -> Value {
        serde_json::to_value(BorrowedCompactBytes::new(bytes)).unwrap()
    }

    fn reference(bytes: &[u8]) -> Value {
        serde_json::to_value(canonical::content_ref(bytes, "application/octet-stream").unwrap())
            .unwrap()
    }

    fn transfer(id: &str, index: usize, capacity: usize, bytes: &[u8]) -> Value {
        json!([
            id,
            reference(bytes),
            ["transfer", index],
            capacity,
            true,
            payload(bytes)
        ])
    }

    fn document(transfers: Vec<Value>, objects: Vec<Value>) -> Value {
        json!([
            "source-private.client-content/7",
            1024,
            8,
            256,
            0,
            transfers,
            objects
        ])
    }

    // Reference objects must retain the source encoder's struct field order;
    // serde_json::Value's default map sorts keys, so render them explicitly.
    fn encoded(value: &Value) -> Vec<u8> {
        let mut output = String::new();
        render(value, &mut output);
        output.into_bytes()
    }

    fn render(value: &Value, output: &mut String) {
        if let Value::Object(fields) = value {
            let names: &[&str] = if fields.contains_key("hash") {
                &["hash", "length", "media_type"]
            } else {
                &["algorithm", "domain", "digest"]
            };
            output.push('{');
            for (index, name) in names.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push_str(&serde_json::to_string(name).unwrap());
                output.push(':');
                render(&fields[*name], output);
            }
            output.push('}');
        } else if let Value::Array(values) = value {
            output.push('[');
            for (index, item) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                render(item, output);
            }
            output.push(']');
        } else {
            output.push_str(&serde_json::to_string(value).unwrap());
        }
    }

    fn accepts(value: &Value) -> bool {
        ValidatedCompactContent::validate(&encoded(value), limits()).is_ok()
    }

    #[test]
    fn actual_encoder_aliases_equal_distinct_groups_and_empty_spare_are_borrowed() {
        let mut first = Vec::with_capacity(64);
        first.extend_from_slice(b"same");
        let mut distinct = Vec::with_capacity(96);
        distinct.extend_from_slice(b"same");
        let first = Rc::new(first);
        let distinct = Rc::new(distinct);
        let empty = Rc::new(Vec::with_capacity(32));
        let reference = canonical::content_ref(b"same", "application/octet-stream").unwrap();
        let mut content = ClientContent::new(1024, 8, 256).unwrap();
        content.reserved = 8;
        for (name, bytes) in [
            ("first", first.clone()),
            ("first-alias", first.clone()),
            ("second", distinct.clone()),
        ] {
            content.transfers.insert(
                Id::new(name).unwrap(),
                Transfer {
                    reference: reference.clone(),
                    bytes,
                    complete: true,
                },
            );
        }
        content
            .objects
            .insert(reference.hash.digest.clone(), (reference, first.clone()));
        let empty_reference = canonical::content_ref(b"", "application/octet-stream").unwrap();
        content.objects.insert(
            empty_reference.hash.digest.clone(),
            (empty_reference, empty.clone()),
        );
        let input = serde_json::to_vec(&content.original_compact_protocol_view()).unwrap();

        let plan = ValidatedCompactContent::validate(&input, limits()).unwrap();
        let rows = plan.transfers().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(plan.transfer_count(), 3);
        assert_eq!(plan.object_count(), 2);
        assert_eq!(plan.first_group_count(), 3);
        assert_eq!(
            plan.first_group_capacity_bytes(),
            first.capacity() + distinct.capacity() + empty.capacity()
        );
        assert_eq!(plan.reserved(), 8);
        assert!(rows[0].payload.is_some());
        assert!(rows[1].payload.is_none());
        assert_eq!(rows[1].edge.index, 0);
        assert!(rows[2].payload.is_some());
        assert_eq!(rows[2].edge.index, 2);
        for row in plan.objects() {
            let row = row.unwrap();
            if let Some(payload) = row.payload {
                let mut original = Vec::with_capacity(row.capacity);
                let pointer = original.as_ptr();
                payload.fill_preowned(&mut original).unwrap();
                assert!(original.is_empty());
                assert_eq!(original.as_ptr(), pointer);
                assert_eq!(original.capacity(), empty.capacity());
            } else {
                assert_eq!(row.edge.kind, ContentGroupKind::Transfer);
                assert_eq!(row.capacity, first.capacity());
            }
        }
    }

    #[test]
    fn empty_rosters_preserve_credit_and_report_declared_scratch() {
        let mut value = document(vec![], vec![]);
        value[4] = json!(17);
        let input = encoded(&value);
        let mut allowance = limits();
        allowance.max_rows = 0;
        allowance.max_groups = 0;
        allowance.max_first_group_capacity_bytes = 0;
        let plan = ValidatedCompactContent::validate(&input, allowance).unwrap();

        assert_eq!(plan.reserved(), 17);
        assert_eq!(plan.first_group_capacity_bytes(), 0);
        assert!(plan.transfers().next().is_none());
        assert!(plan.objects().next().is_none());
        assert_eq!(
            compact_content_summary_bank_bytes(),
            size_of::<[Option<GroupSummary<'_>>; 8192]>()
        );
        assert_eq!(
            compact_content_parser_scratch_bytes(),
            size_of::<Cursor<'_>>()
                + size_of::<BorrowedContentRow<'_>>()
                + size_of::<StoredContentLimits>()
        );
    }

    #[test]
    fn aliases_require_backward_first_group_and_exact_capacity_reference() {
        let first = transfer("a", 0, 64, b"same");
        let mut alias = transfer("b", 0, 64, b"same");
        alias[5] = Value::Null;
        let good = document(vec![first, alias], vec![]);
        assert!(accepts(&good));

        for replacement in [
            json!(["transfer", 1]),
            json!(["transfer", 2]),
            json!(["object", 0]),
        ] {
            let mut wrong = good.clone();
            wrong[5][1][2] = replacement;
            assert!(!accepts(&wrong));
        }
        let mut wrong = good.clone();
        wrong[5][1][3] = json!(65);
        assert!(!accepts(&wrong));
        wrong = good.clone();
        wrong[5][1][1]["hash"]["digest"] = json!("f".repeat(64));
        assert!(!accepts(&wrong));
        wrong = good.clone();
        wrong[5][1][1]["length"] = json!("5");
        assert!(!accepts(&wrong));
        wrong = good.clone();
        wrong[5][1][1]["media_type"] = json!("different/type");
        assert!(accepts(&wrong));
        let mut third = wrong[5][1].clone();
        third[0] = json!("c");
        third[2] = json!(["transfer", 1]);
        wrong[5].as_array_mut().unwrap().push(third);
        assert!(!accepts(&wrong));
    }

    #[test]
    fn object_edges_reject_forward_alias_chains_and_key_drift() {
        let r = reference(b"same");
        let key = r["hash"]["digest"].clone();
        let object = json!([key, r, ["transfer", 0], 64, null]);
        let good = document(vec![transfer("a", 0, 64, b"same")], vec![object]);
        assert!(accepts(&good));
        for edge in [
            json!(["object", 0]),
            json!(["object", 1]),
            json!(["transfer", 1]),
        ] {
            let mut wrong = good.clone();
            wrong[6][0][2] = edge;
            assert!(!accepts(&wrong));
        }
        let mut wrong = good.clone();
        wrong[6][0][0] = json!("0".repeat(64));
        assert!(!accepts(&wrong));

        let first = json!([
            "0".repeat(64),
            reference(b""),
            ["object", 0],
            32,
            payload(b"")
        ]);
        let mut first = first;
        first[1]["hash"]["digest"] = first[0].clone();
        let mut alias = first.clone();
        alias[0] = json!("1".repeat(64));
        alias[1]["hash"]["digest"] = alias[0].clone();
        alias[2] = json!(["object", 0]);
        alias[4] = Value::Null;
        // Changed digest already refuses; even unchanged digest would collide
        // with the unique object key, so object aliases cannot fabricate rows.
        assert!(!accepts(&document(vec![], vec![first, alias])));
    }

    #[test]
    fn sorted_unique_ids_and_object_keys_are_required() {
        let rows = vec![transfer("a", 0, 8, b"x"), transfer("b", 1, 8, b"x")];
        let good = document(rows, vec![]);
        assert!(accepts(&good));
        for id in ["a", "0", "-bad", "bad space", "a\\b", "é", ""] {
            let mut wrong = good.clone();
            wrong[5][1][0] = json!(id);
            assert!(!accepts(&wrong));
        }
        let mut wrong = good.clone();
        wrong[5][1][0] = json!("x".repeat(129));
        assert!(!accepts(&wrong));
        wrong = good;
        wrong[5].as_array_mut().unwrap().swap(0, 1);
        assert!(!accepts(&wrong));
    }

    #[test]
    fn media_unescapes_only_bounded_printable_quote_and_backslash() {
        let mut value = document(vec![transfer("a", 0, 8, b"x")], vec![]);
        value[5][0][1]["media_type"] = json!("a\"b\\c /d");
        let input = encoded(&value);
        let plan = ValidatedCompactContent::validate(&input, limits()).unwrap();
        let row = plan.transfers().next().unwrap().unwrap();
        assert_eq!(
            row.reference.media_type_bytes().collect::<Vec<_>>(),
            b"a\"b\\c /d"
        );
        assert_eq!(row.reference.media_type_length(), 8);
        assert!(
            input
                .windows(row.reference.encoded().len())
                .any(|bytes| bytes == row.reference.encoded())
        );

        for media in ["", "\n", "é"] {
            value[5][0][1]["media_type"] = json!(media);
            assert!(!accepts(&value));
        }
        value[5][0][1]["media_type"] = json!("a".repeat(128));
        assert!(accepts(&value));
        value[5][0][1]["media_type"] = json!("a".repeat(129));
        assert!(!accepts(&value));
        let valid = String::from_utf8(input).unwrap();
        for replacement in ["\\u0061", "\\/", "\\t"] {
            let wrong = valid.replace("a\\\"b\\\\c /d", replacement);
            assert!(ValidatedCompactContent::validate(wrong.as_bytes(), limits()).is_err());
        }
    }

    #[test]
    fn reference_field_order_hash_literals_and_u64_are_closed() {
        let input =
            String::from_utf8(encoded(&document(vec![transfer("a", 0, 8, b"x")], vec![]))).unwrap();
        for (old, new) in [
            ("blake3-256", "sha256"),
            ("cnp.blob.v1", "cnp.other"),
            ("\"length\":\"1\"", "\"length\":\"01\""),
            ("\"length\":\"1\"", "\"length\":\"18446744073709551616\""),
            ("\"length\":\"1\"", "\"length\":1"),
            ("\"media_type\":", "\"extra\":0,\"media_type\":"),
            ("\"algorithm\":", "\"algorithm\":null,\"algorithm\":"),
        ] {
            let wrong = input.replace(old, new);
            assert!(
                ValidatedCompactContent::validate(wrong.as_bytes(), limits()).is_err(),
                "{new}"
            );
        }
        let mut value = document(vec![transfer("a", 0, 8, b"x")], vec![]);
        for digest in ["F".repeat(64), "a".repeat(63), "g".repeat(64)] {
            value[5][0][1]["hash"]["digest"] = json!(digest);
            assert!(!accepts(&value));
        }
    }

    #[test]
    fn partial_transfers_and_aliases_preserve_declared_length() {
        let mut first = transfer("a", 0, 64, b"part");
        first[1]["length"] = json!("10");
        first[4] = json!(false);
        let mut alias = first.clone();
        alias[0] = json!("b");
        alias[5] = Value::Null;
        let good = document(vec![first, alias], vec![]);
        assert!(accepts(&good));
        let mut wrong = good.clone();
        wrong[5][0][4] = json!(true);
        assert!(!accepts(&wrong));
        wrong = good.clone();
        wrong[5][1][4] = json!(true);
        assert!(!accepts(&wrong));
        wrong = good.clone();
        wrong[5][0][1]["length"] = json!("3");
        assert!(!accepts(&wrong));
        let row = &good[5][0];
        let object = json!([row[1]["hash"]["digest"], row[1], ["transfer", 0], 64, null]);
        wrong = good;
        wrong[6] = json!([object]);
        assert!(!accepts(&wrong));
    }

    #[test]
    fn physical_capacity_and_rows_are_independent_of_logical_limits() {
        let mut value = document(
            vec![transfer("a", 0, 8192, b"x"), transfer("b", 1, 4096, b"x")],
            vec![],
        );
        value[1] = json!(1);
        value[2] = json!(1);
        value[4] = json!(1);
        let input = encoded(&value);
        let mut allowance = limits();
        allowance.max_rows = 2;
        allowance.max_groups = 2;
        allowance.max_first_group_capacity_bytes = 12288;
        let plan = ValidatedCompactContent::validate(&input, allowance).unwrap();
        assert_eq!(plan.stored_limits().maximum_objects, 1);
        assert_eq!(plan.first_group_capacity_bytes(), 12288);
        for changed in 0..4 {
            let mut insufficient = allowance;
            match changed {
                0 => insufficient.max_input_bytes = input.len() - 1,
                1 => insufficient.max_rows = 1,
                2 => insufficient.max_groups = 1,
                _ => insufficient.max_first_group_capacity_bytes = 12287,
            }
            assert!(ValidatedCompactContent::validate(&input, insufficient).is_err());
        }
    }

    #[test]
    fn aggregate_capacity_overflow_and_short_payload_bank_refuse() {
        let value = document(
            vec![transfer("a", 0, usize::MAX, b""), transfer("b", 1, 1, b"")],
            vec![],
        );
        let mut allowance = limits();
        allowance.max_first_group_capacity_bytes = usize::MAX;
        assert!(ValidatedCompactContent::validate(&encoded(&value), allowance).is_err());
        assert!(!accepts(&document(vec![transfer("a", 0, 0, b"x")], vec![])));
        let input = String::from_utf8(encoded(&document(vec![], vec![]))).unwrap();
        let wrong = input.replace(",1024,", ",18446744073709551616,");
        assert!(ValidatedCompactContent::validate(wrong.as_bytes(), allowance).is_err());
    }

    #[test]
    fn malformed_leaf_and_full_trailing_refuse_before_caller_reservation() {
        let input =
            String::from_utf8(encoded(&document(vec![transfer("a", 0, 8, b"x")], vec![]))).unwrap();
        let mut caller_allocations = 0;
        for wrong in [
            input.clone() + " ",
            input.clone() + "[]",
            input.replace("eA==", "eB=="),
            input.replace(
                "source-private.compact-bytes/7",
                "source-private.compact-bytes/6",
            ),
            input.replace(",1024,", ",01024,"),
            input.replace(",1024,", ", 1024,"),
        ] {
            if let Ok(plan) = ValidatedCompactContent::validate(wrong.as_bytes(), limits()) {
                caller_allocations += 1;
                let _target = Vec::<u8>::with_capacity(plan.first_group_capacity_bytes());
            }
        }
        assert_eq!(caller_allocations, 0);
    }

    #[test]
    fn header_and_payload_null_geometry_are_exact() {
        let good = document(vec![transfer("a", 0, 8, b"x")], vec![]);
        for (field, value) in [
            (1, json!(0)),
            (2, json!(0)),
            (2, json!(4097)),
            (3, json!(0)),
            (3, json!(1048577)),
            (4, json!(1025)),
        ] {
            let mut wrong = good.clone();
            wrong[field] = value;
            assert!(!accepts(&wrong));
        }
        let mut wrong = good.clone();
        wrong[5][0][5] = Value::Null;
        assert!(!accepts(&wrong));
        wrong = good.clone();
        wrong[5][0][2] = json!(["transfer", 1]);
        assert!(!accepts(&wrong));
        let mut allowance = limits();
        allowance.max_rows = 8193;
        assert!(ValidatedCompactContent::validate(&encoded(&good), allowance).is_err());
        allowance = limits();
        allowance.max_groups = 8193;
        assert!(ValidatedCompactContent::validate(&encoded(&good), allowance).is_err());
    }

    #[test]
    fn maximum_fixed_rosters_validate_with_single_pass_alias_tables() {
        let transfers = (0..4096)
            .map(|index| transfer(&format!("t{index:04}"), index, 1, b""))
            .collect();
        let objects = (0..4096)
            .map(|index| {
                let key = format!("{index:064x}");
                let mut r = reference(b"");
                r["hash"]["digest"] = json!(key);
                json!([key, r, ["object", index], 1, payload(b"")])
            })
            .collect();
        let input = encoded(&document(transfers, objects));
        let plan = ValidatedCompactContent::validate(&input, limits()).unwrap();
        assert_eq!(plan.transfer_count(), 4096);
        assert_eq!(plan.object_count(), 4096);
        assert_eq!(plan.first_group_count(), 8192);
        assert_eq!(plan.first_group_capacity_bytes(), 8192);
        assert_eq!(plan.transfers().count(), 4096);
        assert_eq!(plan.objects().count(), 4096);
    }
}
