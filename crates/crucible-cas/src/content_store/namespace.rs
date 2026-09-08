//! Deployment-namespace authorization for immutable store graphs.
//!
//! A namespaced graph node binds one non-secret namespace identifier into the
//! graph configuration while resolving the corresponding authorization
//! capability separately at construction. The capability remains operational:
//! its policy and credentials do not enter content or graph identity.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::sync::Arc;

use super::{
    BackendCapabilities, BlobHandle, ByteRange, ContentId, ImmutableBlobBackend, PutReceipt,
    StoreError,
};

const MAX_NAMESPACE_ID_BYTES: usize = 512;
const MAX_NAMESPACE_SEGMENT_BYTES: usize = 255;

/// Validated non-secret identifier for one store authorization namespace.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StoreNamespaceId(String);

impl StoreNamespaceId {
    /// Validates one bounded slash-separated namespace identifier.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidComposition`] when the value is empty,
    /// exceeds 512 bytes, contains an empty, `.` or `..` segment, has a segment
    /// longer than 255 bytes, or uses characters outside ASCII letters,
    /// digits, `.`, `_`, and `-`.
    pub fn new(value: impl Into<String>) -> Result<Self, StoreError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_NAMESPACE_ID_BYTES
            && value.split('/').all(|segment| {
                !segment.is_empty()
                    && segment.len() <= MAX_NAMESPACE_SEGMENT_BYTES
                    && segment != "."
                    && segment != ".."
                    && segment.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
            });
        if !valid {
            return Err(StoreError::InvalidComposition {
                reason: "store authorization namespace identifier is invalid",
            });
        }
        Ok(Self(value))
    }

    /// Returns the validated namespace spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Closed immutable-store operation presented to a namespace authorizer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreNamespaceOperation {
    /// Tests whether an exact logical object exists.
    Contains,
    /// Reads an exact logical object or authenticated range.
    Read,
    /// Conditionally places an exact logical object.
    Put,
}

/// Operational authorization capability for one exact store namespace.
///
/// Implementations may consult credentials or policy state, but must not use
/// modeled time or mutate canonical content. Authorization is checked before
/// the child store can observe the requested object identity.
pub trait StoreNamespaceAuthorizer: Send + Sync {
    /// Authorizes one operation on one exact logical object.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Unauthorized`] for a stable denial or another
    /// backend error when authorization cannot be decided safely.
    fn authorize(
        &self,
        operation: StoreNamespaceOperation,
        id: ContentId,
    ) -> Result<(), StoreError>;
}

/// External namespace capabilities used while constructing a store graph.
#[derive(Default)]
pub struct StoreGraphNamespaceAuthorizers {
    authorizers: BTreeMap<StoreNamespaceId, Arc<dyn StoreNamespaceAuthorizer>>,
}

impl StoreGraphNamespaceAuthorizers {
    /// Creates an empty namespace-capability collection.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            authorizers: BTreeMap::new(),
        }
    }

    /// Inserts the capability for one exact namespace.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidComposition`] when the namespace already
    /// has a capability in this collection.
    pub fn insert(
        &mut self,
        namespace: StoreNamespaceId,
        authorizer: Arc<dyn StoreNamespaceAuthorizer>,
    ) -> Result<(), StoreError> {
        match self.authorizers.entry(namespace) {
            Entry::Vacant(entry) => {
                entry.insert(authorizer);
                Ok(())
            }
            Entry::Occupied(_) => Err(StoreError::InvalidComposition {
                reason: "store namespace capability collection contains a duplicate identifier",
            }),
        }
    }

    pub(super) fn resolve(
        &self,
        namespace: &StoreNamespaceId,
    ) -> Result<Arc<dyn StoreNamespaceAuthorizer>, StoreError> {
        self.authorizers
            .get(namespace)
            .cloned()
            .ok_or(StoreError::Unauthorized)
    }
}

/// Authorization facade bound to one exact deployment namespace.
pub(super) struct NamespacedStore {
    name: String,
    child: Arc<dyn ImmutableBlobBackend>,
    authorizer: Arc<dyn StoreNamespaceAuthorizer>,
}

impl NamespacedStore {
    pub(super) fn new(
        name: impl Into<String>,
        child: Arc<dyn ImmutableBlobBackend>,
        authorizer: Arc<dyn StoreNamespaceAuthorizer>,
    ) -> Self {
        Self {
            name: name.into(),
            child,
            authorizer,
        }
    }

    fn authorize(
        &self,
        operation: StoreNamespaceOperation,
        id: ContentId,
    ) -> Result<(), StoreError> {
        self.authorizer.authorize(operation, id)
    }
}

impl ImmutableBlobBackend for NamespacedStore {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.child.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.authorize(StoreNamespaceOperation::Contains, id)?;
        self.child.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.authorize(StoreNamespaceOperation::Read, id)?;
        self.child.read(id, range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.authorize(StoreNamespaceOperation::Put, id)?;
        self.child.put_if_absent(id, source)
    }
}
