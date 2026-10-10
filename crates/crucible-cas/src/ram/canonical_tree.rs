//! Borrowed canonical envelope framing for fixed binary catalog nodes.
//!
//! Decoding allocates no envelope, strings, child table, or body copy. The
//! caller retains the borrowed bytes through its actual checked EOF and cleanup.
//!
//! ```text
//! envelope: "CRUCOBJE" | format:u32be | schema:u16be+bytes | version:u32be
//!           | children:u32be | (role:u16be+bytes, id:u16be+bytes)*
//!           | body-length:u64be | body
//! tree body: kind:u8 | digest:32bytes | height:u32be | pages:u64be | kind fields
//! ```

use super::RamStoreError;
use super::codec::{TreeChild as Child, TreeNode, TreeRef, validate_tree_parts};
use crate::content_envelope::ContentEnvelopeError;
use crate::content_store::{ContentId, ObjectKind, StoreError};

#[derive(Clone, Copy)]
struct Envelope<'a> {
    schema: &'a str,
    version: u32,
    children: [Option<Child<'a>>; 2],
    body: &'a [u8],
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ContentEnvelopeError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ContentEnvelopeError::Truncated)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ContentEnvelopeError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn field<const N: usize>(&mut self) -> Result<[u8; N], ContentEnvelopeError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ContentEnvelopeError::Truncated)
    }

    fn text(
        &mut self,
        maximum: usize,
        limit: &'static str,
    ) -> Result<&'a str, ContentEnvelopeError> {
        let length = usize::from(u16::from_be_bytes(self.field()?));
        if length > maximum {
            return Err(ContentEnvelopeError::LimitExceeded { limit });
        }
        std::str::from_utf8(self.take(length)?).map_err(|_| ContentEnvelopeError::InvalidIdentifier)
    }

    fn finish(self) -> Result<(), ContentEnvelopeError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(ContentEnvelopeError::TrailingBytes)
        }
    }
}

fn identifier(value: &str) -> Result<(), ContentEnvelopeError> {
    if !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':')
        })
    {
        Ok(())
    } else {
        Err(ContentEnvelopeError::InvalidIdentifier)
    }
}

fn envelope(bytes: &[u8], maximum_children: usize) -> Result<Envelope<'_>, ContentEnvelopeError> {
    let mut cursor = Cursor::new(bytes);
    if cursor.take(8)? != b"CRUCOBJE" || u32::from_be_bytes(cursor.field()?) != 1 {
        return Err(ContentEnvelopeError::Incompatible);
    }
    let schema = cursor.text(128, "schema-name-bytes")?;
    let version = u32::from_be_bytes(cursor.field()?);
    let count = u32::from_be_bytes(cursor.field()?) as usize;
    if count > maximum_children {
        return Err(ContentEnvelopeError::LimitExceeded {
            limit: "child-count",
        });
    }

    let mut children = [None; 2];
    let mut previous: Option<Child<'_>> = None;
    for index in 0..count {
        let role = cursor.text(256, "child-role-bytes")?;
        let text = cursor.text(160, "content-id-bytes")?;
        let id = ContentId::parse(text).map_err(|_| ContentEnvelopeError::InvalidContentId)?;
        // Content ID decoding precedes role validation in the canonical grammar.
        identifier(role)?;
        if previous.is_some_and(|prior| (prior.role, prior.id) >= (role, id)) {
            return Err(ContentEnvelopeError::NonCanonicalChildren);
        }
        let child = Child { role, id };
        if let Some(slot) = children.get_mut(index) {
            *slot = Some(child);
        }
        previous = Some(child);
    }

    let length = usize::try_from(u64::from_be_bytes(cursor.field()?)).map_err(|_| {
        ContentEnvelopeError::LimitExceeded {
            limit: "body-byte-count",
        }
    })?;
    let body = cursor.take(length)?;
    cursor.finish()?;
    // Construction validates the schema only after complete envelope framing.
    identifier(schema)?;
    if version == 0 {
        return Err(ContentEnvelopeError::Incompatible);
    }

    Ok(Envelope {
        schema,
        version,
        children,
        body,
    })
}

pub(super) fn read_tree_canonical(
    bytes: &[u8],
    expected: TreeRef,
) -> Result<TreeNode, RamStoreError> {
    preflight(bytes, expected)?;
    let envelope = envelope(bytes, 2)?;
    if envelope.version != 1 {
        return Err(RamStoreError::Invalid("RAM envelope schema"));
    }
    let count = envelope
        .children
        .iter()
        .filter(|child| child.is_some())
        .count();
    validate_tree_parts(
        envelope.schema,
        envelope.body,
        count,
        |index| envelope.children.get(index).copied().flatten(),
        expected,
    )
}

// The single-record route postpones allocating decoding until native closure.
// This shared grammar retains the existing framing/identifier error priority.
pub(super) fn validate_envelope_canonical(
    bytes: &[u8],
    maximum_children: usize,
) -> Result<(), ContentEnvelopeError> {
    envelope(bytes, maximum_children).map(|_| ())
}

pub(super) fn preflight(bytes: &[u8], expected: TreeRef) -> Result<(), RamStoreError> {
    if expected.id.kind() != ObjectKind::RamTree {
        return Err(RamStoreError::Invalid("tree object kind"));
    }
    if expected.id.schema_version() != 1 {
        return Err(RamStoreError::Invalid("RAM storage schema"));
    }
    if bytes.len() > 4096 {
        return Err(RamStoreError::Limit("single canonical object"));
    }
    if !expected.id.authenticates(bytes) {
        return Err(StoreError::Corrupt { id: expected.id }.into());
    }
    Ok(())
}
