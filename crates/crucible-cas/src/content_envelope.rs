//! Canonical child-bearing content-object envelopes.
//!
//! This format sits below campaign semantics so storage, transfer, retention,
//! and garbage collection can authenticate and walk object closures without a
//! dependency on a campaign runtime.
//!
//! ```text
//! "CRUCOBJE" | envelope-version:u32
//! schema-name-length:u16 | schema-name:utf8 | schema-version:u32
//! child-count:u32 | (role-length:u16 | role:utf8 | content-id-length:u16 | content-id:utf8)*
//! body-length:u64 | body
//! ```

use std::collections::BTreeSet;

use thiserror::Error;

use crate::content_store::{ContentId, ObjectKind};

const MAGIC: &[u8; 8] = b"CRUCOBJE";
const ENVELOPE_VERSION: u32 = 1;
const MAX_ENVELOPE_BYTES: usize = 64 * 1024 * 1024;
const MAX_SCHEMA_NAME_BYTES: usize = 128;
const MAX_CHILD_ROLE_BYTES: usize = 256;
const MAX_CONTENT_ID_BYTES: usize = 160;
const MAX_CHILDREN: usize = 65_536;

/// Stable error while constructing or decoding a generic content envelope.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ContentEnvelopeError {
    /// The input ended before its declared value was complete.
    #[error("content envelope is truncated")]
    Truncated,
    /// Bytes remained after the one canonical envelope.
    #[error("content envelope contains trailing bytes")]
    TrailingBytes,
    /// Magic or envelope version is unsupported.
    #[error("content envelope framing is incompatible")]
    Incompatible,
    /// A schema name or child role is invalid.
    #[error("content envelope identifier is invalid")]
    InvalidIdentifier,
    /// A child content identity is malformed or noncanonical.
    #[error("content envelope child id is invalid")]
    InvalidContentId,
    /// Children were duplicated or not in canonical order.
    #[error("content envelope child table is not a canonical set")]
    NonCanonicalChildren,
    /// The envelope or one of its dimensions exceeded a hard bound.
    #[error("content envelope exceeds the {limit} limit")]
    LimitExceeded {
        /// Stable limit category.
        limit: &'static str,
    },
    /// Re-encoding did not reproduce the exact input bytes.
    #[error("content envelope is not canonically encoded")]
    NonCanonical,
}

/// One role-tagged content reference visible to generic closure walkers.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentChild {
    role: String,
    id: ContentId,
}

impl ContentChild {
    /// Builds a bounded child reference.
    ///
    /// # Errors
    ///
    /// Returns [`ContentEnvelopeError::InvalidIdentifier`] for an invalid role.
    pub fn new(role: impl Into<String>, id: ContentId) -> Result<Self, ContentEnvelopeError> {
        let role = role.into();
        validate_identifier(&role, MAX_CHILD_ROLE_BYTES)?;
        Ok(Self { role, id })
    }

    /// Returns the stable semantic role within the parent record.
    #[must_use]
    pub fn role(&self) -> &str {
        &self.role
    }

    /// Returns the referenced immutable content identity.
    #[must_use]
    pub const fn id(&self) -> ContentId {
        self.id
    }
}

/// Canonical generic envelope around one record-specific body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentEnvelope {
    schema_name: String,
    schema_version: u32,
    children: BTreeSet<ContentChild>,
    body: Vec<u8>,
}

impl ContentEnvelope {
    /// Builds a valid-by-construction bounded canonical envelope.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid schema name, zero version, too many
    /// children, or a total encoded size above 64 MiB.
    pub fn new(
        schema_name: impl Into<String>,
        schema_version: u32,
        children: BTreeSet<ContentChild>,
        body: Vec<u8>,
    ) -> Result<Self, ContentEnvelopeError> {
        let schema_name = schema_name.into();
        validate_identifier(&schema_name, MAX_SCHEMA_NAME_BYTES)?;
        if schema_version == 0 {
            return Err(ContentEnvelopeError::Incompatible);
        }
        if children.len() > MAX_CHILDREN {
            return Err(ContentEnvelopeError::LimitExceeded {
                limit: "child-count",
            });
        }
        let envelope = Self {
            schema_name,
            schema_version,
            children,
            body,
        };
        if envelope.encoded_len()? > MAX_ENVELOPE_BYTES {
            return Err(ContentEnvelopeError::LimitExceeded {
                limit: "encoded-byte-count",
            });
        }
        Ok(envelope)
    }

    /// Returns the record-specific schema name.
    #[must_use]
    pub fn schema_name(&self) -> &str {
        &self.schema_name
    }

    /// Returns the record-specific canonical schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Returns the complete sorted child-reference table.
    #[must_use]
    pub fn children(&self) -> &BTreeSet<ContentChild> {
        &self.children
    }

    /// Returns the opaque record-specific canonical body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Returns canonical envelope bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len().unwrap_or(0));
        bytes.extend_from_slice(MAGIC);
        put_u32(&mut bytes, ENVELOPE_VERSION);
        put_short_bytes(&mut bytes, self.schema_name.as_bytes());
        put_u32(&mut bytes, self.schema_version);
        put_u32(&mut bytes, self.children.len() as u32);
        for child in &self.children {
            put_short_bytes(&mut bytes, child.role.as_bytes());
            put_short_bytes(&mut bytes, child.id.encode().as_bytes());
        }
        put_u64(&mut bytes, self.body.len() as u64);
        bytes.extend_from_slice(&self.body);
        bytes
    }

    /// Computes the logical content identity for this exact envelope.
    #[must_use]
    pub fn content_id(&self, kind: ObjectKind) -> ContentId {
        ContentId::for_bytes(kind, self.schema_version, &self.canonical_bytes())
    }

    /// Decodes one strict bounded canonical envelope.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed framing, invalid identifiers/child IDs,
    /// excessive sizes, duplicate or unsorted children, or alternate encoding.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ContentEnvelopeError> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(ContentEnvelopeError::LimitExceeded {
                limit: "encoded-byte-count",
            });
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(MAGIC.len())? != MAGIC || decoder.u32()? != ENVELOPE_VERSION {
            return Err(ContentEnvelopeError::Incompatible);
        }
        let schema_name = decoder.string(MAX_SCHEMA_NAME_BYTES, "schema-name-bytes")?;
        let schema_version = decoder.u32()?;
        let child_count = decoder.u32()? as usize;
        if child_count > MAX_CHILDREN {
            return Err(ContentEnvelopeError::LimitExceeded {
                limit: "child-count",
            });
        }
        let mut children = BTreeSet::new();
        let mut previous: Option<ContentChild> = None;
        for _ in 0..child_count {
            let role = decoder.string(MAX_CHILD_ROLE_BYTES, "child-role-bytes")?;
            let encoded_id = decoder.string(MAX_CONTENT_ID_BYTES, "content-id-bytes")?;
            let id = ContentId::parse(&encoded_id)
                .map_err(|_| ContentEnvelopeError::InvalidContentId)?;
            let child = ContentChild::new(role, id)?;
            if previous.as_ref().is_some_and(|prior| prior >= &child)
                || !children.insert(child.clone())
            {
                return Err(ContentEnvelopeError::NonCanonicalChildren);
            }
            previous = Some(child);
        }
        let body_len =
            usize::try_from(decoder.u64()?).map_err(|_| ContentEnvelopeError::LimitExceeded {
                limit: "body-byte-count",
            })?;
        let body_bytes = decoder.take(body_len)?;
        let mut body = Vec::new();
        body.try_reserve_exact(body_len)
            .map_err(|_| ContentEnvelopeError::LimitExceeded {
                limit: "body-allocation",
            })?;
        body.extend_from_slice(body_bytes);
        decoder.finish()?;

        let envelope = Self::new(schema_name, schema_version, children, body)?;
        if envelope.canonical_bytes() != bytes {
            return Err(ContentEnvelopeError::NonCanonical);
        }
        Ok(envelope)
    }

    fn encoded_len(&self) -> Result<usize, ContentEnvelopeError> {
        let mut length = MAGIC
            .len()
            .checked_add(4)
            .and_then(|value| value.checked_add(2 + self.schema_name.len()))
            .and_then(|value| value.checked_add(4 + 4))
            .ok_or(limit("encoded-byte-count"))?;
        for child in &self.children {
            length = length
                .checked_add(2 + child.role.len())
                .and_then(|value| value.checked_add(2 + child.id.encode().len()))
                .ok_or(limit("encoded-byte-count"))?;
        }
        length
            .checked_add(8)
            .and_then(|value| value.checked_add(self.body.len()))
            .ok_or(limit("encoded-byte-count"))
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ContentEnvelopeError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(ContentEnvelopeError::Truncated)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(ContentEnvelopeError::Truncated)?;
        self.cursor = end;
        Ok(value)
    }

    fn u32(&mut self) -> Result<u32, ContentEnvelopeError> {
        self.take(4)?
            .try_into()
            .map(u32::from_be_bytes)
            .map_err(|_| ContentEnvelopeError::Truncated)
    }

    fn u64(&mut self) -> Result<u64, ContentEnvelopeError> {
        self.take(8)?
            .try_into()
            .map(u64::from_be_bytes)
            .map_err(|_| ContentEnvelopeError::Truncated)
    }

    fn string(
        &mut self,
        maximum: usize,
        limit_name: &'static str,
    ) -> Result<String, ContentEnvelopeError> {
        let length = u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| ContentEnvelopeError::Truncated)?,
        ) as usize;
        if length > maximum {
            return Err(limit(limit_name));
        }
        let value = std::str::from_utf8(self.take(length)?)
            .map_err(|_| ContentEnvelopeError::InvalidIdentifier)?;
        Ok(value.to_owned())
    }

    fn finish(self) -> Result<(), ContentEnvelopeError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(ContentEnvelopeError::TrailingBytes)
        }
    }
}

fn validate_identifier(value: &str, maximum: usize) -> Result<(), ContentEnvelopeError> {
    let valid = !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':')
        });
    if valid {
        Ok(())
    } else {
        Err(ContentEnvelopeError::InvalidIdentifier)
    }
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_short_bytes(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
    bytes.extend_from_slice(value);
}

const fn limit(limit: &'static str) -> ContentEnvelopeError {
    ContentEnvelopeError::LimitExceeded { limit }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn content(name: &str) -> ContentId {
        ContentId::for_bytes(ObjectKind::CampaignFact, 1, name.as_bytes())
    }

    #[test]
    fn envelope_round_trip_is_strict_and_children_are_walkable() {
        let envelope = ContentEnvelope::new(
            "crucible.test-record",
            3,
            BTreeSet::from([
                ContentChild::new("left", content("left")).expect("left"),
                ContentChild::new("right", content("right")).expect("right"),
            ]),
            b"canonical body".to_vec(),
        )
        .expect("envelope");
        let bytes = envelope.canonical_bytes();
        assert_eq!(
            ContentEnvelope::from_canonical_bytes(&bytes).expect("decode"),
            envelope
        );
        assert_eq!(envelope.children().len(), 2);
        assert_eq!(
            envelope
                .content_id(ObjectKind::CampaignFact)
                .schema_version(),
            3
        );
    }

    #[test]
    fn envelope_rejects_trailing_and_truncated_input() {
        let envelope = ContentEnvelope::new(
            "crucible.test-record",
            1,
            BTreeSet::from([ContentChild::new("child", content("child")).expect("child")]),
            Vec::new(),
        )
        .expect("envelope");
        let bytes = envelope.canonical_bytes();
        assert_eq!(
            ContentEnvelope::from_canonical_bytes(&bytes[..bytes.len() - 1]),
            Err(ContentEnvelopeError::Truncated)
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            ContentEnvelope::from_canonical_bytes(&trailing),
            Err(ContentEnvelopeError::TrailingBytes)
        );
    }

    #[test]
    fn envelope_rejects_unsorted_and_duplicate_child_tables() {
        fn raw(children: &[(&str, ContentId)]) -> Vec<u8> {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(MAGIC);
            put_u32(&mut bytes, ENVELOPE_VERSION);
            put_short_bytes(&mut bytes, b"crucible.test-record");
            put_u32(&mut bytes, 1);
            put_u32(&mut bytes, children.len() as u32);
            for (role, id) in children {
                put_short_bytes(&mut bytes, role.as_bytes());
                put_short_bytes(&mut bytes, id.encode().as_bytes());
            }
            put_u64(&mut bytes, 0);
            bytes
        }

        let left = ("left", content("left"));
        let right = ("right", content("right"));
        assert_eq!(
            ContentEnvelope::from_canonical_bytes(&raw(&[right, left])),
            Err(ContentEnvelopeError::NonCanonicalChildren)
        );
        assert_eq!(
            ContentEnvelope::from_canonical_bytes(&raw(&[left, left])),
            Err(ContentEnvelopeError::NonCanonicalChildren)
        );
    }
}
