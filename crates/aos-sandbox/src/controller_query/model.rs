//! Query-binding commitments and bounded response primitives.
//!
//! Pagination tokens, immutable revisions, and watch cursors are intentionally
//! not raw byte strings. Their client-state wrappers retain the complete
//! normalized query, principal, authorization, visibility, and observation
//! schema binding that was active when the server value was received.

use std::fmt;

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

/// Maximum bytes in one server-issued opaque token, revision, or cursor.
pub const MAXIMUM_OPAQUE_RESPONSE_BYTES: usize = 4 * 1024;
/// Maximum encoded bytes in one checked public API resource.
pub const MAXIMUM_PUBLIC_RESOURCE_BYTES: usize = 4 * 1024 * 1024;

/// Reports invalid query bindings or response primitives.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidQueryModel {
    /// A commitment uses the all-zero sentinel.
    #[error("query binding contains an unspecified commitment")]
    UnspecifiedCommitment,
    /// A server-issued opaque value is empty or exceeds its compiled ceiling.
    #[error("server-issued opaque value is invalid")]
    InvalidOpaqueValue,
    /// A response value was reused under another normalized query binding.
    #[error("response value does not match the normalized query binding")]
    BindingMismatch,
    /// An encoded item exceeds the per-resource allocation ceiling.
    #[error("public resource exceeds its encoded byte ceiling")]
    ResourceTooLarge,
}

macro_rules! define_binding_commitment {
    ($name:ident, $summary:literal, $domain:literal) => {
        #[doc = $summary]
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(ObjectDigest);

        impl $name {
            /// Commits normalized bytes in this binding component's domain.
            #[must_use]
            pub fn commit(bytes: &[u8]) -> Self {
                Self(ObjectDigest::from_bytes(
                    Sha256::new()
                        .chain_update($domain)
                        .chain_update(bytes)
                        .finalize()
                        .into(),
                ))
            }

            /// Returns the purpose-specific commitment.
            #[must_use]
            pub const fn digest(self) -> ObjectDigest {
                self.0
            }

            pub(crate) const fn from_digest(digest: ObjectDigest) -> Self {
                Self(digest)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

define_binding_commitment!(
    NormalizedQueryDigestV1,
    "Commits the normalized resource query independently of its filters.",
    b"aos.sandbox.client.normalized-query.v1\0"
);
define_binding_commitment!(
    QueryFilterDigestV1,
    "Commits the complete normalized query filter set.",
    b"aos.sandbox.client.query-filter.v1\0"
);
define_binding_commitment!(
    QuerySortDigestV1,
    "Commits the normalized result ordering.",
    b"aos.sandbox.client.query-sort.v1\0"
);
define_binding_commitment!(
    QueryPrincipalDigestV1,
    "Commits the authenticated principal and holder binding.",
    b"aos.sandbox.client.query-principal.v1\0"
);
define_binding_commitment!(
    QueryVisibilityDigestV1,
    "Commits the requested and authorized disclosure surface.",
    b"aos.sandbox.client.query-visibility.v1\0"
);
define_binding_commitment!(
    AuthorizationRevisionDigestV1,
    "Commits the authorization scope and exact authorization revision.",
    b"aos.sandbox.client.authorization-revision.v1\0"
);
define_binding_commitment!(
    ObservationSchemaDigestV1,
    "Commits negotiated observation schemas and required feature versions.",
    b"aos.sandbox.client.observation-schema.v1\0"
);
define_binding_commitment!(
    WatchRequestCommitmentV1,
    "Commits normalized watch semantics excluding the separately typed continuation cursor.",
    b"aos.sandbox.client.watch-request.v1\0"
);

/// Binds an opaque response value to every semantic authorization dimension.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct QueryBindingV1 {
    query: NormalizedQueryDigestV1,
    filters: QueryFilterDigestV1,
    sort: QuerySortDigestV1,
    principal: QueryPrincipalDigestV1,
    visibility: QueryVisibilityDigestV1,
    authorization: AuthorizationRevisionDigestV1,
    schema: ObservationSchemaDigestV1,
}

impl fmt::Debug for QueryBindingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("QueryBindingV1(<redacted>)")
    }
}

impl QueryBindingV1 {
    /// Constructs one complete local binding for pagination or watch state.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        query: NormalizedQueryDigestV1,
        filters: QueryFilterDigestV1,
        sort: QuerySortDigestV1,
        principal: QueryPrincipalDigestV1,
        visibility: QueryVisibilityDigestV1,
        authorization: AuthorizationRevisionDigestV1,
        schema: ObservationSchemaDigestV1,
    ) -> Self {
        Self {
            query,
            filters,
            sort,
            principal,
            visibility,
            authorization,
            schema,
        }
    }

    /// Returns the normalized query commitment.
    #[must_use]
    pub const fn query(self) -> NormalizedQueryDigestV1 {
        self.query
    }

    /// Returns the normalized filter commitment.
    #[must_use]
    pub const fn filters(self) -> QueryFilterDigestV1 {
        self.filters
    }

    /// Returns the normalized sort commitment.
    #[must_use]
    pub const fn sort(self) -> QuerySortDigestV1 {
        self.sort
    }

    /// Returns the authenticated principal commitment.
    #[must_use]
    pub const fn principal(self) -> QueryPrincipalDigestV1 {
        self.principal
    }

    /// Returns the visibility commitment.
    #[must_use]
    pub const fn visibility(self) -> QueryVisibilityDigestV1 {
        self.visibility
    }

    /// Returns the authorization revision commitment.
    #[must_use]
    pub const fn authorization(self) -> AuthorizationRevisionDigestV1 {
        self.authorization
    }

    /// Returns the negotiated observation-schema commitment.
    #[must_use]
    pub const fn schema(self) -> ObservationSchemaDigestV1 {
        self.schema
    }
}

/// Identifies the semantic role of bounded opaque response bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum OpaqueResponseKindV1 {
    PageToken,
    ImmutableListRevision,
    WatchCursor,
    WatchWatermark,
    ResourceVersion,
}

/// Stores bounded server-issued bytes without exposing an arbitrary constructor.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OpaqueResponseBytesV1 {
    bytes: Vec<u8>,
    kind: OpaqueResponseKindV1,
}

impl OpaqueResponseBytesV1 {
    pub(crate) fn from_response(
        bytes: Vec<u8>,
        kind: OpaqueResponseKindV1,
    ) -> Result<Self, InvalidQueryModel> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_OPAQUE_RESPONSE_BYTES {
            Err(InvalidQueryModel::InvalidOpaqueValue)
        } else {
            Ok(Self { bytes, kind })
        }
    }

    /// Returns the exact server-issued bytes for the matching transport field.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for OpaqueResponseBytesV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueResponseBytesV1")
            .field("kind", &self.kind)
            .field("length", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// Supplies a checked encoded byte cost for generic client-state items.
pub trait ClientStateItem: super::client_state_sealed::Sealed {
    /// Returns the exact protobuf encoded size used for accumulation bounds.
    fn encoded_byte_cost(&self) -> usize;
}

pub(crate) fn checked_item_cost<T: ClientStateItem>(item: &T) -> Result<usize, InvalidQueryModel> {
    let cost = item.encoded_byte_cost();
    if cost > MAXIMUM_PUBLIC_RESOURCE_BYTES {
        Err(InvalidQueryModel::ResourceTooLarge)
    } else {
        Ok(cost)
    }
}
