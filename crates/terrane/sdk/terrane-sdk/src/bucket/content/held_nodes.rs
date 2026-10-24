//! Shares actual held catalog and pack data during one relationship verification.
//!
//! The loader still checks every contextual Node occurrence. This private reader
//! retains ordinary bytes only; history completion requires its independent fresh
//! closing check before any view promotion or publication receipt is constructed.

use super::*;
use crate::bucket::catalog::CatalogReads;
use crate::bucket::held::HeldBucket;
use crate::bucket::publication::{SelectedObservation, receipts::RecordRead};
use crate::pack::IndexEntry;
use crate::store::{Capabilities, CapabilityReport};
use std::future::poll_fn;
use std::sync::{Arc, Mutex};
use std::task::{Poll, Waker};

#[cfg(all(test, feature = "tokio", unix))]
mod tests;

mod sealed {
    /// Prevents arbitrary data stores from supplying a successful closing check.
    pub trait Sealed {}
}

/// Supplies operation-local Node data with a mandatory genuine closing check.
///
/// Only an actual held backend reader implements this sealed private interface.
#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
pub(crate) trait NodeReads: ContentStore + BucketBinding + sealed::Sealed {
    /// Binds the data reader to the actual holder used by owning history checks.
    ///
    /// # Errors
    /// Rejects a missing, foreign or substituted physical namespace.
    fn check_holder(
        &self,
        held: &crate::bucket::held::HeldIdentity<'_>,
    ) -> Result<(), StoreFailure>;

    /// Requires the same actual selected observation borrowed by this reader.
    ///
    /// # Errors
    /// Rejects a separately captured, foreign or substituted selection.
    fn check_selection(&self, selected: &SelectedObservation<'_>) -> Result<(), StoreFailure>;

    /// Freezes new data reads and returns every actual original payload recipe.
    ///
    /// # Errors
    /// Rejects incomplete, failed, repeated or unavailable closing attempts.
    fn begin_closing(&self) -> Result<Vec<RecordRead>, StoreFailure>;

    /// Completes only the same scope closed by the genuine native producer.
    ///
    /// # Errors
    /// Refuses incomplete closure, mismatched inputs and changed current checks.
    #[cfg(all(feature = "tokio", unix))]
    fn complete_closing(
        &self,
        checked: &crate::store::native_publication_effects::CheckedHistoryInputs<'_, '_, '_>,
    ) -> Result<(), StoreFailure>;

    /// Rechecks actual catalog/container reads and their complete held selection.
    ///
    /// This data closure grants no history authority. The owning verifier must
    /// also close every actual Original/control input before promoting a view.
    ///
    /// # Errors
    /// Rejects changed selection, physical evidence or unavailable fresh reads.
    #[cfg(all(test, feature = "tokio", unix))]
    async fn finish(&self) -> Result<(), StoreFailure>;
}

/// Borrows one actual selected namespace while sharing only immutable payload data.
pub(crate) struct HeldNodeReads<'read, 'held, F: LocalFs, C, V> {
    bucket: &'read FileBucket<F, C, V>,
    selected: &'read SelectedObservation<'held>,
    catalog: Catalog,
    artifacts: RetainedArtifacts<'read, F, C, V>,
    cache: Mutex<Cache>,
}

/// Keeps original actual physical recipes for every consumed direct artifact.
struct RetainedArtifacts<'read, F: LocalFs, C, V> {
    bucket: &'read FileBucket<F, C, V>,
    final_check: crate::selected_bridge::OwnedFinalCheck,
    reads: Mutex<Vec<RecordRead>>,
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<F, C, V> CatalogReads for RetainedArtifacts<'_, F, C, V>
where
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    async fn read_artifact(
        &self,
        key: &terrane_format::bucket::BucketKey,
    ) -> Result<RecordRead, StoreFailure> {
        self.final_check.recheck()?;
        let read = self.bucket.read_optional_retained(key).await?;
        self.final_check.recheck()?;
        self.reads
            .lock()
            .map_err(|_| unavailable())?
            .push(read.clone());
        Ok(read)
    }
}

impl<'held, F, C, V, const WRITABLE: bool> HeldBucket<'held, F, C, V, WRITABLE>
where
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    /// Starts data sharing beneath the actual freshly checked held selection.
    ///
    /// # Errors
    /// Refuses unsupported retention, mismatched actual holders, changed selected
    /// authority and every ordinary complete catalog or physical read failure.
    pub(crate) async fn held_node_reads<'read, 'selection>(
        &'read self,
        selected: &'read SelectedObservation<'selection>,
        final_check: crate::selected_bridge::OwnedFinalCheck,
    ) -> Result<HeldNodeReads<'read, 'selection, F, C, V>, StoreFailure> {
        self.identity_proof().retained_namespace()?;
        if selected.identity().root() != self.root()
            || selected.identity().physical_identity() != self.physical_identity()
            || self.bucket().publication_operator_uid() != Some(selected.configured_operator_uid())
        {
            return Err(files::layout_corrupt());
        }
        final_check.recheck()?;
        selected.revalidate_physical_reads(self.fs()).await?;
        final_check.recheck()?;
        let artifacts = RetainedArtifacts {
            bucket: self.bucket(),
            final_check,
            reads: Mutex::new(Vec::new()),
        };
        let catalog = self
            .bucket()
            .catalog_observed_with_reads(selected, &artifacts)
            .await?;
        selected.revalidate_physical_reads(self.fs()).await?;
        artifacts.final_check.recheck()?;
        Ok(HeldNodeReads {
            bucket: self.bucket(),
            selected,
            catalog,
            artifacts,
            cache: Mutex::new(Cache::default()),
        })
    }
}

/// Retains containing packs requested during this operation's loader traversal.
#[derive(Default)]
struct Cache {
    packs: BTreeMap<PackId, PackState>,
    phase: ReadPhase,
}

#[derive(Default, Eq, PartialEq)]
enum ReadPhase {
    #[default]
    Open,
    Closing,
    Complete,
}

enum PackState {
    Reading(Vec<Waker>),
    Ready(Arc<VerifiedPack>),
    Failed(Arc<StoreFailure>),
}

/// Keeps the actual whole pack/index reads separate from contextual Node use.
struct VerifiedPack {
    pack: RecordRead,
    entries: Vec<IndexEntry>,
}

enum PackAction {
    Read,
    Ready(Arc<VerifiedPack>),
}

/// Removes an unfinished single-flight read and wakes waiters on cancellation.
struct Flight<'cache> {
    cache: &'cache Mutex<Cache>,
    id: PackId,
    completed: bool,
}

fn unavailable() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Unavailable { retry_after: None })
}

/// Preserves the original typed outcome and diagnostic for every waiting subject.
#[derive(Debug)]
struct SharedFailure(Arc<StoreFailure>);

impl std::fmt::Display for SharedFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, formatter)
    }
}

impl std::error::Error for SharedFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

fn shared_failure(error: &Arc<StoreFailure>) -> StoreFailure {
    StoreFailure::with_source(error.kind().clone(), SharedFailure(Arc::clone(error)))
}

impl Flight<'_> {
    fn complete(
        mut self,
        outcome: Result<VerifiedPack, StoreFailure>,
    ) -> Result<Arc<VerifiedPack>, StoreFailure> {
        let outcome = outcome.map(Arc::new).map_err(Arc::new);
        let waiters = {
            let mut cache = self.cache.lock().map_err(|_| unavailable())?;
            let state = match &outcome {
                Ok(pack) => PackState::Ready(Arc::clone(pack)),
                Err(error) => PackState::Failed(Arc::clone(error)),
            };
            match cache.packs.insert(self.id, state) {
                Some(PackState::Reading(waiters)) => waiters,
                _ => return Err(unavailable()),
            }
        };
        self.completed = true;
        for waiter in waiters {
            waiter.wake();
        }
        outcome.map_err(|error| shared_failure(&error))
    }
}

impl Drop for Flight<'_> {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        let waiters = match self.cache.lock() {
            Ok(mut cache) => match cache.packs.remove(&self.id) {
                Some(PackState::Reading(waiters)) => waiters,
                _ => Vec::new(),
            },
            Err(_) => Vec::new(),
        };
        for waiter in waiters {
            waiter.wake();
        }
    }
}

impl<F, C, V> HeldNodeReads<'_, '_, F, C, V>
where
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    /// Returns ordinary consumed recipes only after the actual closing check.
    ///
    /// These data still require fresh checks at every later effect and ACK.
    ///
    /// # Errors
    /// Rejects incomplete or failed closure and unavailable read synchronization.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(crate) fn completed_reads(&self) -> Result<Vec<RecordRead>, StoreFailure> {
        if self.cache.lock().map_err(|_| unavailable())?.phase != ReadPhase::Complete {
            return Err(unavailable());
        }
        Ok(self
            .artifacts
            .reads
            .lock()
            .map_err(|_| unavailable())?
            .clone())
    }

    async fn containing_pack(&self, id: PackId) -> Result<Arc<VerifiedPack>, StoreFailure> {
        let action = poll_fn(|context| {
            let mut cache = match self.cache.lock() {
                Ok(cache) => cache,
                Err(_) => return Poll::Ready(Err(unavailable())),
            };
            if cache.phase != ReadPhase::Open {
                return Poll::Ready(Err(unavailable()));
            }
            match cache.packs.get_mut(&id) {
                Some(PackState::Ready(pack)) => {
                    Poll::Ready(Ok(PackAction::Ready(Arc::clone(pack))))
                }
                Some(PackState::Failed(error)) => Poll::Ready(Err(shared_failure(error))),
                Some(PackState::Reading(waiters)) => {
                    if !waiters
                        .iter()
                        .any(|waiter| waiter.will_wake(context.waker()))
                    {
                        waiters.push(context.waker().clone());
                    }
                    Poll::Pending
                }
                None => {
                    cache.packs.insert(id, PackState::Reading(Vec::new()));
                    Poll::Ready(Ok(PackAction::Read))
                }
            }
        })
        .await?;
        match action {
            PackAction::Ready(pack) => Ok(pack),
            PackAction::Read => {
                let flight = Flight {
                    cache: &self.cache,
                    id,
                    completed: false,
                };
                flight.complete(self.read_pack(id).await)
            }
        }
    }

    async fn read_pack(&self, id: PackId) -> Result<VerifiedPack, StoreFailure> {
        // Full physical read retention is supplied by the closed held reader;
        // the ordinary containing-pack checks remain identical to encoded_body.
        let pack = self
            .artifacts
            .read_artifact(&registered(&id.pack_key())?)
            .await?;
        let index = self
            .artifacts
            .read_artifact(&registered(&id.index_key())?)
            .await?;
        let bytes = pack.bytes().ok_or_else(files::layout_corrupt)?;
        let index_bytes = index.bytes().ok_or_else(files::layout_corrupt)?;
        let inventory = self
            .catalog
            .inventory
            .as_ref()
            .and_then(|entries| entries.iter().find(|entry| entry.pack_id == *id.as_bytes()));
        let (pack_identity, index_identity) = if let Some(inventory) = inventory {
            (
                TERRANE_V1.from_digest(IdentityKind::Pack, &inventory.pack_hash),
                TERRANE_V1.from_digest(IdentityKind::Index, &inventory.index_hash),
            )
        } else {
            // Legacy inventory absence does not grant body authority. These
            // computed identities name only the actual artifacts in diagnostics.
            (
                TERRANE_V1.calculate(IdentityKind::Pack, bytes),
                TERRANE_V1.calculate(IdentityKind::Index, index_bytes),
            )
        };
        let pack_identity = pack_identity.map_err(|_| files::layout_corrupt())?;
        let index_identity = index_identity.map_err(|_| files::layout_corrupt())?;
        if let Some(inventory) = inventory {
            if bytes.len() as u64 != inventory.pack_size
                || index_bytes.len() as u64 != inventory.index_size
            {
                return Err(corrupt(&pack_identity));
            }
            for (identity, body) in [(&pack_identity, bytes), (&index_identity, index_bytes)] {
                TERRANE_V1
                    .verify(identity, body)
                    .map_err(|_| corrupt(identity))?;
            }
        }
        let reader = PackReader::open(bytes).map_err(|_| corrupt(&pack_identity))?;
        if reader.header().id() != id {
            return Err(corrupt(&pack_identity));
        }
        reader
            .check_index_object(index_bytes)
            .map_err(|_| corrupt(&index_identity))?;
        let entries = reader.entries().to_vec();
        Ok(VerifiedPack { pack, entries })
    }
}

impl<F: LocalFs, C, V> sealed::Sealed for HeldNodeReads<'_, '_, F, C, V> {}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<F, C, V> NodeReads for HeldNodeReads<'_, '_, F, C, V>
where
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    fn check_holder(
        &self,
        held: &crate::bucket::held::HeldIdentity<'_>,
    ) -> Result<(), StoreFailure> {
        if held.root() != self.selected.identity().root()
            || held.physical_identity() != self.selected.identity().physical_identity()
        {
            return Err(files::layout_corrupt());
        }
        held.retained_namespace()?;
        Ok(())
    }

    fn check_selection(&self, selected: &SelectedObservation<'_>) -> Result<(), StoreFailure> {
        // The observation's lifetime is invariant. Address comparison requires
        // the same actual borrowed object without unifying its holder lifetimes.
        let actual = std::ptr::from_ref(self.selected).cast::<()>();
        let requested = std::ptr::from_ref(selected).cast::<()>();
        if !std::ptr::addr_eq(actual, requested) {
            return Err(files::layout_corrupt());
        }
        Ok(())
    }

    fn begin_closing(&self) -> Result<Vec<RecordRead>, StoreFailure> {
        self.artifacts.final_check.recheck()?;
        {
            let mut cache = self.cache.lock().map_err(|_| unavailable())?;
            if cache.phase != ReadPhase::Open {
                return Err(unavailable());
            }
            for pack in cache.packs.values() {
                match pack {
                    PackState::Reading(_) => return Err(unavailable()),
                    PackState::Failed(error) => return Err(shared_failure(error)),
                    PackState::Ready(_) => {}
                }
            }
            cache.phase = ReadPhase::Closing;
        }
        Ok(self
            .artifacts
            .reads
            .lock()
            .map_err(|_| unavailable())?
            .clone())
    }

    #[cfg(all(feature = "tokio", unix))]
    fn complete_closing(
        &self,
        checked: &crate::store::native_publication_effects::CheckedHistoryInputs<'_, '_, '_>,
    ) -> Result<(), StoreFailure> {
        checked.check_reader_scope(self)?;
        self.artifacts.final_check.recheck()?;
        let mut cache = self.cache.lock().map_err(|_| unavailable())?;
        if cache.phase != ReadPhase::Closing {
            return Err(unavailable());
        }
        cache.phase = ReadPhase::Complete;
        Ok(())
    }

    #[cfg(all(test, feature = "tokio", unix))]
    async fn finish(&self) -> Result<(), StoreFailure> {
        let reads = self.begin_closing()?;
        self.selected
            .revalidate_physical_reads(self.bucket.fs())
            .await?;
        self.artifacts.final_check.recheck()?;
        for read in &reads {
            self.artifacts.final_check.recheck()?;
            read.revalidate_retained(self.bucket.fs()).await?;
            self.artifacts.final_check.recheck()?;
        }
        self.selected
            .revalidate_physical_reads(self.bucket.fs())
            .await?;
        self.artifacts.final_check.recheck()?;
        self.cache.lock().map_err(|_| unavailable())?.phase = ReadPhase::Complete;
        Ok(())
    }
}

impl<F: LocalFs, C, V> CapabilityReport for HeldNodeReads<'_, '_, F, C, V> {
    fn capabilities(&self) -> &Capabilities {
        self.bucket.capabilities()
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<F, C, V> ContentStore for HeldNodeReads<'_, '_, F, C, V>
where
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
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
        #[cfg(all(test, feature = "tokio", unix))]
        self.bucket.inner.content_observation.get(identity.kind());

        self.artifacts.final_check.recheck()?;
        if self.cache.lock().map_err(|_| unavailable())?.phase != ReadPhase::Open {
            return Err(unavailable());
        }
        if identity.kind() != IdentityKind::Node || range.is_some() {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        if self.bucket.is_excluded(&self.catalog, identity)? {
            return Err(StoreFailure::new(StoreErrorKind::Absent(identity.clone())));
        }
        let location = self.bucket.location(&self.catalog, identity)?;
        let pack = self.containing_pack(location.pack()).await?;
        self.artifacts.final_check.recheck()?;
        let position = pack
            .entries
            .binary_search_by_key(location.entry().hash(), |entry| *entry.hash())
            .map_err(|_| corrupt(identity))?;
        let entry = &pack.entries[position];
        if entry != location.entry() {
            return Err(corrupt(identity));
        }
        let start = usize::try_from(entry.offset()).map_err(|_| corrupt(identity))?;
        let end = start
            .checked_add(entry.body_len() as usize)
            .ok_or_else(|| corrupt(identity))?;
        let body = pack
            .pack
            .bytes()
            .and_then(|bytes| bytes.get(start..end))
            .ok_or_else(|| corrupt(identity))?;
        if entry.plaintext_len() as usize != body.len() {
            return Err(corrupt(identity));
        }
        let upload = MetaUpload::new(IdentityKind::Node, body).map_err(|_| corrupt(identity))?;
        self.bucket
            .inner
            .validator
            .validate_meta(&upload)
            .map_err(|_| corrupt(identity))?;
        TERRANE_V1
            .verify(identity, body)
            .map_err(|_| corrupt(identity))?;
        self.artifacts.final_check.recheck()?;
        Ok(body.to_vec())
    }

    async fn has(&self, _identities: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        Err(StoreFailure::new(StoreErrorKind::Unsupported))
    }

    async fn list(&self, _prefix: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        Err(StoreFailure::new(StoreErrorKind::Unsupported))
    }
}
