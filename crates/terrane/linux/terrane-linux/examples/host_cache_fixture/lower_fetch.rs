//! Supplies read-only lower-tier content without constructing native authority.
//!
//! The confined native owner and independent supervisor provide every physical
//! observation. This provider supplies only ordinary encoded bytes through the
//! frozen ContentStore interface and records actual get dispatches.

use std::sync::atomic::{AtomicUsize, Ordering};
use terrane_format::identity::Identity;
use terrane_sdk::store::{
    ByteRange, Capabilities, CapabilityReport, ContentStore, ContentUpload, Durability,
    IdentityPrefix, RangeCapability, RefCapability, StoreErrorKind, StoreFailure,
};

/// Retains untrusted lower bytes and the actual provider dispatch counter.
pub(super) struct LowerChunk {
    identity: Identity,
    encoded: Vec<u8>,
    calls: AtomicUsize,
    capabilities: Capabilities,
}

impl LowerChunk {
    /// Retains one ordinary lower-tier body without granting local cache custody.
    pub(super) fn new(identity: Identity, encoded: Vec<u8>) -> Self {
        Self {
            identity,
            encoded,
            calls: AtomicUsize::new(0),
            capabilities: Capabilities {
                refs: RefCapability::None,
                ranges: RangeCapability::WholeObjectOnly,
                presign: false,
                locality: Default::default(),
                durability: Durability::Local,
                sealed: false,
            },
        }
    }

    /// Returns the actual number of lower-tier get calls.
    pub(super) fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

impl CapabilityReport for LowerChunk {
    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
}

#[async_trait::async_trait]
impl ContentStore for LowerChunk {
    async fn put(&self, _: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        Err(StoreFailure::new(StoreErrorKind::ReadOnly))
    }

    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if identity != &self.identity {
            return Err(StoreFailure::new(StoreErrorKind::Absent(identity.clone())));
        }
        if range.is_some() {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        Ok(self.encoded.clone())
    }

    async fn has(&self, identities: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        Ok(identities
            .iter()
            .map(|identity| identity == &self.identity)
            .collect())
    }

    async fn list(&self, _: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        Err(StoreFailure::new(StoreErrorKind::Unsupported))
    }
}
