//! Routes all canonical held owning-history content through one actual read ledger.
//!
//! Ref observations remain genuine reads of the held backend. This adapter
//! supplies no mutation methods and cannot outlive its actual namespace holder.

use crate::bucket::BucketBinding;
use crate::bucket::held::{CurrentNodeReads, HeldBucket};
use crate::store::{
    ByteRange, Capabilities, CapabilityReport, Clock, ContentStore, ContentUpload,
    ContentValidator, IdentityPrefix, LocalFs, RefCasOutcome, RefLogAppendOutcome, RefStore,
    StoreErrorKind, StoreFailure,
};
use terrane_format::identity::Identity;
use terrane_format::refs::{RefLogRecord, RefRecord};

/// Borrows a genuine held backend and the same sealed held authorization invocation reader.
pub(in crate::guard) struct HeldHistoryStore<'scope, 'held, F: LocalFs, B, V> {
    held: &'scope HeldBucket<'held, F, B, V, false>,
    reads: &'scope dyn CurrentNodeReads,
}

impl<'scope, 'held, F, B, V> HeldHistoryStore<'scope, 'held, F, B, V>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    /// Requires the reader to belong to this actual retained namespace.
    ///
    /// # Errors
    /// Refuses a foreign or unavailable actual holder before canonical reads.
    pub(in crate::guard) fn new(
        held: &'scope HeldBucket<'held, F, B, V, false>,
        reads: &'scope dyn CurrentNodeReads,
    ) -> Result<Self, StoreFailure> {
        reads.check_holder(&held.identity_proof())?;
        Ok(Self { held, reads })
    }
}

impl<F: LocalFs, B, V> CapabilityReport for HeldHistoryStore<'_, '_, F, B, V> {
    fn capabilities(&self) -> &Capabilities {
        self.held.capabilities()
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<F, B, V> ContentStore for HeldHistoryStore<'_, '_, F, B, V>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    async fn put(&self, _upload: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        Err(StoreFailure::new(StoreErrorKind::ReadOnly))
    }

    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        self.reads.get(identity, range).await
    }

    async fn has(&self, identities: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        self.held.has(identities).await
    }

    async fn list(&self, prefix: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        self.held.list(prefix).await
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<F, B, V> RefStore for HeldHistoryStore<'_, '_, F, B, V>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    type Watch = crate::bucket::held::HeldWatch;

    async fn ref_get(&self, name: &str) -> Result<Option<RefRecord>, StoreFailure> {
        self.held.ref_get(name).await
    }

    async fn ref_cas(
        &self,
        _name: &str,
        _expect: Option<&RefRecord>,
        _new: &RefRecord,
    ) -> Result<RefCasOutcome, StoreFailure> {
        Err(StoreFailure::new(StoreErrorKind::ReadOnly))
    }

    async fn ref_log_append(
        &self,
        _name: &str,
        _seq: u64,
        _record: &RefLogRecord,
    ) -> Result<RefLogAppendOutcome, StoreFailure> {
        Err(StoreFailure::new(StoreErrorKind::ReadOnly))
    }

    async fn ref_log_read(
        &self,
        name: &str,
        from_seq: u64,
    ) -> Result<Vec<RefLogRecord>, StoreFailure> {
        self.held.ref_log_read(name, from_seq).await
    }

    async fn ref_watch(&self, name: &str, from_seq: u64) -> Result<Self::Watch, StoreFailure> {
        self.held.ref_watch(name, from_seq).await
    }
}
