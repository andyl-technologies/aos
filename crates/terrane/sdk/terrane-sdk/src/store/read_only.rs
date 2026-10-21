//! Composes a read-only content cache with the original reference authority.
//!
//! Reads retain the authority backend rather than copying its ref records.
//! Resident-only caches can fall back to that backend's verified content.
//! Complete content drivers instead own all content routing and failure policy.
//! Mutations are refused before either child is called. This adapter performs
//! no admission, creates no ref authority and cannot transfer original ownership.

use super::{
    ByteRange, Capabilities, CapabilityReport, ContentStore, ContentUpload, IdentityPrefix,
    RefCapability, RefCasOutcome, RefLogAppendOutcome, RefStore, StoreErrorKind, StoreFailure,
};
use crate::bucket::BucketBinding;
use terrane_format::{
    identity::Identity,
    refs::{RefLogRecord, RefRecord},
};

/// Supplies cached reads while preserving the original backend for current refs.
///
/// Cache and authority bindings come from trusted composition for the same
/// disclosure domain. Repository guards must authorize every operation before
/// invoking this raw store. Every child remains responsible for complete content
/// verification under its own immutable profile. [`Self::new`] allows eligible
/// resident failures to use the original content backend. [`Self::with_driver`]
/// delegates complete content routing and preserves every driver failure.
///
/// Ref reads and watches always reach the original authority. Content writes,
/// ref CAS and log appends always return `ReadOnly` without child effects.
pub struct ReadOnlyStore<L, R> {
    local: L,
    authority: R,
    capabilities: Capabilities,
    retry_authority: bool,
}

impl<L: ContentStore, R: RefStore> ReadOnlyStore<L, R> {
    /// Retains both trusted bindings without reading or modifying either child.
    pub fn new(local: L, authority: R) -> Self {
        let mut capabilities = local.capabilities().clone();
        capabilities.refs = RefCapability::None;
        capabilities.presign = false;
        Self {
            local,
            authority,
            capabilities,
            retry_authority: true,
        }
    }

    /// Retains a complete content driver and the original reference authority.
    ///
    /// The trusted driver owns all resident, lower-tier, circuit and admission
    /// behavior. A failed driver read is returned unchanged; this adapter never
    /// makes an additional authority-content request around that policy.
    pub fn with_driver(driver: L, authority: R) -> Self {
        let mut store = Self::new(driver, authority);
        store.retry_authority = false;
        store
    }
}

impl<L, R> CapabilityReport for ReadOnlyStore<L, R> {
    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<L, R> ContentStore for ReadOnlyStore<L, R>
where
    L: ContentStore + BucketBinding,
    R: ContentStore + RefStore + BucketBinding,
{
    async fn put(&self, _: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        Err(read_only())
    }

    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        match self.local.get(identity, range).await {
            Ok(bytes) => Ok(bytes),
            Err(error)
                if self.retry_authority
                    && matches!(
                        error.kind(),
                        StoreErrorKind::Absent(_)
                            | StoreErrorKind::Corrupt(_)
                            | StoreErrorKind::Unavailable { .. }
                            | StoreErrorKind::Capacity
                    ) =>
            {
                self.authority.get(identity, range).await
            }
            Err(error) => Err(error),
        }
    }

    async fn has(&self, identities: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        let mut present = Vec::with_capacity(identities.len());
        for identity in identities {
            match self.get(identity, None).await {
                Ok(_) => present.push(true),
                Err(error) if matches!(error.kind(), StoreErrorKind::Absent(_)) => {
                    present.push(false)
                }
                Err(error) => return Err(error),
            }
        }
        Ok(present)
    }

    async fn list(&self, prefix: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        // Listing is advisory. A complete driver's policy also owns this lower
        // read; a resident-only cache uses original authority candidates.
        if self.retry_authority {
            self.authority.list(prefix).await
        } else {
            self.local.list(prefix).await
        }
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<L, R> RefStore for ReadOnlyStore<L, R>
where
    L: BucketBinding,
    R: RefStore + BucketBinding,
{
    type Watch = R::Watch;

    async fn ref_get(&self, name: &str) -> Result<Option<RefRecord>, StoreFailure> {
        self.authority.ref_get(name).await
    }

    async fn ref_cas(
        &self,
        _: &str,
        _: Option<&RefRecord>,
        _: &RefRecord,
    ) -> Result<RefCasOutcome, StoreFailure> {
        Err(read_only())
    }

    async fn ref_log_append(
        &self,
        _: &str,
        _: u64,
        _: &RefLogRecord,
    ) -> Result<RefLogAppendOutcome, StoreFailure> {
        Err(read_only())
    }

    async fn ref_log_read(
        &self,
        name: &str,
        from_seq: u64,
    ) -> Result<Vec<RefLogRecord>, StoreFailure> {
        self.authority.ref_log_read(name, from_seq).await
    }

    async fn ref_watch(&self, name: &str, from_seq: u64) -> Result<Self::Watch, StoreFailure> {
        self.authority.ref_watch(name, from_seq).await
    }
}

fn read_only() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::ReadOnly)
}
