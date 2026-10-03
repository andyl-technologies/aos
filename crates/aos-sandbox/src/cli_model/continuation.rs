//! CLI-safe continuation frames for authenticated public API state.
//!
//! A list continuation is encoded as:
//!
//! ```text
//! AOSLPC01 | query-binding:224 | revision-len:u32be | token-len:u32be |
//! revision | server-token | sha256:32
//! ```
//!
//! The frame digest prevents accidental local field substitution. It is not a
//! server authenticator and grants no authority; the public endpoint still
//! authenticates the opaque token and returns the current query binding.

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::controller_query::{
    CheckedWatchEventV1, MAXIMUM_OPAQUE_RESPONSE_BYTES, QUERY_BINDING_TRANSPORT_BYTES,
    QueryBindingV1,
};

const LIST_CONTINUATION_MAGIC_V1: &[u8; 8] = b"AOSLPC01";
const LIST_CONTINUATION_HEADER_BYTES_V1: usize =
    LIST_CONTINUATION_MAGIC_V1.len() + QUERY_BINDING_TRANSPORT_BYTES + 8;
const LIST_CONTINUATION_DIGEST_BYTES_V1: usize = 32;
const WATCH_CONTINUATION_MAGIC_V1: &[u8; 8] = b"AOSLWC01";
const WATCH_CONTINUATION_HEADER_BYTES_V1: usize =
    WATCH_CONTINUATION_MAGIC_V1.len() + QUERY_BINDING_TRANSPORT_BYTES + 8 + 4;
const WATCH_CONTINUATION_DIGEST_BYTES_V1: usize = 32;

/// Maximum encoded bytes in one CLI list continuation frame.
pub const MAXIMUM_LIST_CONTINUATION_BYTES_V1: usize = LIST_CONTINUATION_HEADER_BYTES_V1
    + (2 * MAXIMUM_OPAQUE_RESPONSE_BYTES)
    + LIST_CONTINUATION_DIGEST_BYTES_V1;
/// Maximum encoded bytes in one CLI watch continuation frame.
pub const MAXIMUM_WATCH_CONTINUATION_BYTES_V1: usize = WATCH_CONTINUATION_HEADER_BYTES_V1
    + MAXIMUM_OPAQUE_RESPONSE_BYTES
    + WATCH_CONTINUATION_DIGEST_BYTES_V1;

/// Reports a malformed or noncanonical CLI list continuation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidListContinuationV1 {
    /// The frame shape, digest, binding, or opaque values are invalid.
    #[error("list continuation is invalid")]
    Invalid,
}

/// Reports a malformed or noncanonical CLI watch continuation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidWatchContinuationV1 {
    /// The frame shape, digest, binding, sequence, or cursor is invalid.
    #[error("watch continuation is invalid")]
    Invalid,
}

/// Retains a query-bound immutable-list continuation for CLI transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DormantListContinuationV1 {
    binding: QueryBindingV1,
    immutable_revision: Vec<u8>,
    server_page_token: Vec<u8>,
}

impl DormantListContinuationV1 {
    /// Constructs a continuation from one authenticated response page.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidListContinuationV1`] when either opaque value is empty
    /// or exceeds the public response ceiling.
    pub fn from_authenticated_page(
        binding: QueryBindingV1,
        immutable_revision: Vec<u8>,
        server_page_token: Vec<u8>,
    ) -> Result<Self, InvalidListContinuationV1> {
        if immutable_revision.is_empty()
            || immutable_revision.len() > MAXIMUM_OPAQUE_RESPONSE_BYTES
            || server_page_token.is_empty()
            || server_page_token.len() > MAXIMUM_OPAQUE_RESPONSE_BYTES
        {
            return Err(InvalidListContinuationV1::Invalid);
        }
        Ok(Self {
            binding,
            immutable_revision,
            server_page_token,
        })
    }

    /// Decodes one exact canonical CLI continuation frame.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidListContinuationV1`] for an invalid magic, length,
    /// binding, digest, or opaque field.
    pub fn decode(encoded: &[u8]) -> Result<Self, InvalidListContinuationV1> {
        if encoded.len() < LIST_CONTINUATION_HEADER_BYTES_V1 + LIST_CONTINUATION_DIGEST_BYTES_V1
            || encoded.len() > MAXIMUM_LIST_CONTINUATION_BYTES_V1
            || encoded.get(..8) != Some(LIST_CONTINUATION_MAGIC_V1.as_slice())
        {
            return Err(InvalidListContinuationV1::Invalid);
        }
        let binding_end = 8 + QUERY_BINDING_TRANSPORT_BYTES;
        let binding = QueryBindingV1::from_transport_bytes(&encoded[8..binding_end])
            .map_err(|_| InvalidListContinuationV1::Invalid)?;
        let revision_length = u32::from_be_bytes(
            encoded[binding_end..binding_end + 4]
                .try_into()
                .map_err(|_| InvalidListContinuationV1::Invalid)?,
        ) as usize;
        let token_length = u32::from_be_bytes(
            encoded[binding_end + 4..binding_end + 8]
                .try_into()
                .map_err(|_| InvalidListContinuationV1::Invalid)?,
        ) as usize;
        let revision_end = LIST_CONTINUATION_HEADER_BYTES_V1
            .checked_add(revision_length)
            .ok_or(InvalidListContinuationV1::Invalid)?;
        let token_end = revision_end
            .checked_add(token_length)
            .ok_or(InvalidListContinuationV1::Invalid)?;
        let frame_end = token_end
            .checked_add(LIST_CONTINUATION_DIGEST_BYTES_V1)
            .ok_or(InvalidListContinuationV1::Invalid)?;
        if frame_end != encoded.len() {
            return Err(InvalidListContinuationV1::Invalid);
        }
        let expected_digest = continuation_digest(&encoded[..token_end]);
        if encoded[token_end..] != expected_digest.as_bytes()[..] {
            return Err(InvalidListContinuationV1::Invalid);
        }

        Self::from_authenticated_page(
            binding,
            encoded[LIST_CONTINUATION_HEADER_BYTES_V1..revision_end].to_vec(),
            encoded[revision_end..token_end].to_vec(),
        )
    }

    /// Encodes the exact canonical CLI continuation frame.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(
            LIST_CONTINUATION_HEADER_BYTES_V1
                + self.immutable_revision.len()
                + self.server_page_token.len()
                + LIST_CONTINUATION_DIGEST_BYTES_V1,
        );
        encoded.extend_from_slice(LIST_CONTINUATION_MAGIC_V1);
        encoded.extend_from_slice(&self.binding.to_transport_bytes());
        encoded.extend_from_slice(&(self.immutable_revision.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&(self.server_page_token.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&self.immutable_revision);
        encoded.extend_from_slice(&self.server_page_token);
        let digest = continuation_digest(&encoded);
        encoded.extend_from_slice(digest.as_bytes());
        encoded
    }

    /// Returns the complete retained query binding.
    #[must_use]
    pub const fn binding(&self) -> QueryBindingV1 {
        self.binding
    }

    /// Returns the retained immutable revision bytes.
    #[must_use]
    pub fn immutable_revision(&self) -> &[u8] {
        &self.immutable_revision
    }

    /// Returns the opaque server page token.
    #[must_use]
    pub fn server_page_token(&self) -> &[u8] {
        &self.server_page_token
    }
}

/// Retains a query-bound watch cursor and its fully applied sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DormantWatchContinuationV1 {
    binding: QueryBindingV1,
    sequence: u64,
    server_cursor: Vec<u8>,
}

impl DormantWatchContinuationV1 {
    /// Constructs a continuation from a fully checked watch event.
    #[must_use]
    pub fn from_checked_event(event: &CheckedWatchEventV1) -> Self {
        Self {
            binding: event.cursor().binding(),
            sequence: event.sequence(),
            server_cursor: event.cursor().as_bytes().to_vec(),
        }
    }

    /// Constructs a continuation from one fully checked watch event.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidWatchContinuationV1`] for a zero sequence or an empty
    /// or oversized cursor.
    pub fn from_authenticated_event(
        binding: QueryBindingV1,
        sequence: u64,
        server_cursor: Vec<u8>,
    ) -> Result<Self, InvalidWatchContinuationV1> {
        if sequence == 0
            || server_cursor.is_empty()
            || server_cursor.len() > MAXIMUM_OPAQUE_RESPONSE_BYTES
        {
            return Err(InvalidWatchContinuationV1::Invalid);
        }
        Ok(Self {
            binding,
            sequence,
            server_cursor,
        })
    }

    /// Decodes one exact canonical CLI watch continuation frame.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidWatchContinuationV1`] for an invalid magic, length,
    /// binding, sequence, cursor, or digest.
    pub fn decode(encoded: &[u8]) -> Result<Self, InvalidWatchContinuationV1> {
        if encoded.len() < WATCH_CONTINUATION_HEADER_BYTES_V1 + WATCH_CONTINUATION_DIGEST_BYTES_V1
            || encoded.len() > MAXIMUM_WATCH_CONTINUATION_BYTES_V1
            || encoded.get(..8) != Some(WATCH_CONTINUATION_MAGIC_V1.as_slice())
        {
            return Err(InvalidWatchContinuationV1::Invalid);
        }
        let binding_end = 8 + QUERY_BINDING_TRANSPORT_BYTES;
        let binding = QueryBindingV1::from_transport_bytes(&encoded[8..binding_end])
            .map_err(|_| InvalidWatchContinuationV1::Invalid)?;
        let sequence = u64::from_be_bytes(
            encoded[binding_end..binding_end + 8]
                .try_into()
                .map_err(|_| InvalidWatchContinuationV1::Invalid)?,
        );
        let cursor_length = u32::from_be_bytes(
            encoded[binding_end + 8..binding_end + 12]
                .try_into()
                .map_err(|_| InvalidWatchContinuationV1::Invalid)?,
        ) as usize;
        let cursor_end = WATCH_CONTINUATION_HEADER_BYTES_V1
            .checked_add(cursor_length)
            .ok_or(InvalidWatchContinuationV1::Invalid)?;
        let frame_end = cursor_end
            .checked_add(WATCH_CONTINUATION_DIGEST_BYTES_V1)
            .ok_or(InvalidWatchContinuationV1::Invalid)?;
        if frame_end != encoded.len() {
            return Err(InvalidWatchContinuationV1::Invalid);
        }
        let expected_digest = watch_continuation_digest(&encoded[..cursor_end]);
        if encoded[cursor_end..] != expected_digest.as_bytes()[..] {
            return Err(InvalidWatchContinuationV1::Invalid);
        }

        Self::from_authenticated_event(
            binding,
            sequence,
            encoded[WATCH_CONTINUATION_HEADER_BYTES_V1..cursor_end].to_vec(),
        )
    }

    /// Encodes the exact canonical CLI watch continuation frame.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(
            WATCH_CONTINUATION_HEADER_BYTES_V1
                + self.server_cursor.len()
                + WATCH_CONTINUATION_DIGEST_BYTES_V1,
        );
        encoded.extend_from_slice(WATCH_CONTINUATION_MAGIC_V1);
        encoded.extend_from_slice(&self.binding.to_transport_bytes());
        encoded.extend_from_slice(&self.sequence.to_be_bytes());
        encoded.extend_from_slice(&(self.server_cursor.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&self.server_cursor);
        let digest = watch_continuation_digest(&encoded);
        encoded.extend_from_slice(digest.as_bytes());
        encoded
    }

    /// Returns the complete retained query binding.
    #[must_use]
    pub const fn binding(&self) -> QueryBindingV1 {
        self.binding
    }

    /// Returns the last fully applied stream sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the opaque server cursor.
    #[must_use]
    pub fn server_cursor(&self) -> &[u8] {
        &self.server_cursor
    }
}

fn continuation_digest(encoded: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.cli.list-continuation.v1\0")
            .chain_update(encoded)
            .finalize()
            .into(),
    )
}

fn watch_continuation_digest(encoded: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.cli.watch-continuation.v1\0")
            .chain_update(encoded)
            .finalize()
            .into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller_query::{
        AuthorizationRevisionDigestV1, NormalizedQueryDigestV1, ObservationSchemaDigestV1,
        QueryFilterDigestV1, QueryPrincipalDigestV1, QuerySortDigestV1, QueryVisibilityDigestV1,
    };

    fn binding() -> QueryBindingV1 {
        QueryBindingV1::new(
            NormalizedQueryDigestV1::commit(b"query"),
            QueryFilterDigestV1::commit(b"filters"),
            QuerySortDigestV1::commit(b"sort"),
            QueryPrincipalDigestV1::commit(b"principal"),
            QueryVisibilityDigestV1::commit(b"visibility"),
            AuthorizationRevisionDigestV1::commit(b"authorization"),
            ObservationSchemaDigestV1::commit(b"schema"),
        )
    }

    #[test]
    fn list_continuation_round_trips_and_detects_substitution() {
        let continuation = DormantListContinuationV1::from_authenticated_page(
            binding(),
            b"revision".to_vec(),
            b"token".to_vec(),
        )
        .unwrap();
        let encoded = continuation.encode();
        assert_eq!(
            DormantListContinuationV1::decode(&encoded).unwrap(),
            continuation
        );

        let mut changed = encoded;
        changed[12] ^= 1;
        assert_eq!(
            DormantListContinuationV1::decode(&changed),
            Err(InvalidListContinuationV1::Invalid)
        );
    }

    #[test]
    fn watch_continuation_round_trips_and_detects_substitution() {
        let continuation =
            DormantWatchContinuationV1::from_authenticated_event(binding(), 42, b"cursor".to_vec())
                .unwrap();
        let encoded = continuation.encode();
        assert_eq!(
            DormantWatchContinuationV1::decode(&encoded).unwrap(),
            continuation
        );

        let mut changed = encoded;
        changed[20] ^= 1;
        assert_eq!(
            DormantWatchContinuationV1::decode(&changed),
            Err(InvalidWatchContinuationV1::Invalid)
        );
    }
}
