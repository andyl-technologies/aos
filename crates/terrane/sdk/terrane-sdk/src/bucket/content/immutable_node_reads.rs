//! Shares immutable Commit and Node DATA during one distinct immutable history walk.
//!
//! Every occurrence still validates its own canonical identity and context. The
//! actual original DATA recipes close separately from protected authority inputs;
//! no history or ACL decision can consume this reader before genuine closure.

use super::*;
use crate::bucket::catalog::CatalogReads;
use crate::bucket::held::HeldBucket;
use crate::bucket::publication::{SelectedObservation, receipts::RecordRead};
use crate::pack::IndexEntry;
use crate::store::{Capabilities, CapabilityReport};
use std::future::poll_fn;
use std::sync::{Arc, Mutex};
use std::task::{Poll, Waker};

/// Retains a distinct opaque immutable invocation without granting current rights.
#[derive(Clone)]
pub(crate) enum ImmutableReadCheck {
    /// Preserves the existing ordinary direct purpose.
    Direct(crate::guard::direct_history::DirectReadCheck),
    /// Preserves one genuinely borrowed overlay purpose.
    Overlay(crate::guard::overlay_history::OverlayReadCheck),
}

impl ImmutableReadCheck {
    /// Rechecks the actual registration inventory for this exact invocation.
    ///
    /// # Errors
    /// Preserves missing or contradictory retained control failures.
    pub(crate) fn recheck(&self) -> Result<(), StoreFailure> {
        match self {
            Self::Direct(check) => check.recheck(),
            Self::Overlay(check) => check.recheck(),
        }
    }

    fn check_direct(
        &self,
        requested: &crate::guard::direct_history::DirectReadCheck,
    ) -> Result<(), StoreFailure> {
        match self {
            Self::Direct(check) => check.same_invocation(requested),
            Self::Overlay(_) => Err(files::layout_corrupt()),
        }
    }

    fn check_overlay(
        &self,
        requested: &crate::guard::overlay_history::OverlayReadCheck,
    ) -> Result<(), StoreFailure> {
        match self {
            Self::Overlay(check) => check.same_invocation(requested),
            Self::Direct(_) => Err(files::layout_corrupt()),
        }
    }
}

/// Borrows one actual selected namespace while sharing only immutable payload data.
pub(crate) struct HeldImmutableNodeReads<'read, 'held, F: LocalFs, C, V> {
    bucket: &'read FileBucket<F, C, V>,
    selected: &'read SelectedObservation<'held>,
    catalog: Catalog,
    artifacts: RetainedArtifacts<'read, F, C, V>,
    cache: Mutex<Cache>,
}

/// Keeps original actual physical recipes for every consumed immutable artifact.
struct RetainedArtifacts<'read, F: LocalFs, C, V> {
    bucket: &'read FileBucket<F, C, V>,
    read_check: ImmutableReadCheck,
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
        self.read_check.recheck()?;
        let ordinary = self.bucket.read_optional_ordinary_retained(key).await?;
        let read = if ordinary.bytes().is_some() {
            ordinary
        } else {
            // Missing ordinary reads carry no retained recipe. The independently
            // captured protected absence must still be absent before use.
            let absent = self.bucket.read_optional_retained(key).await?;
            if absent.bytes().is_some() {
                return Err(files::layout_corrupt());
            }
            absent
        };
        self.read_check.recheck()?;
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
    pub(super) async fn immutable_node_reads<'read, 'selection>(
        &'read self,
        selected: &'read SelectedObservation<'selection>,
        read_check: ImmutableReadCheck,
    ) -> Result<HeldImmutableNodeReads<'read, 'selection, F, C, V>, StoreFailure> {
        self.identity_proof().retained_namespace()?;
        if selected.identity().root() != self.root()
            || selected.identity().physical_identity() != self.physical_identity()
            || self.bucket().publication_operator_uid() != Some(selected.configured_operator_uid())
            || !std::ptr::eq(
                self.identity_proof().retained_namespace()?,
                selected.identity().retained_namespace()?,
            )
        {
            return Err(files::layout_corrupt());
        }
        read_check.recheck()?;
        selected.revalidate_physical_reads(self.fs()).await?;
        read_check.recheck()?;
        let artifacts = RetainedArtifacts {
            bucket: self.bucket(),
            read_check: read_check.clone(),
            reads: Mutex::new(Vec::new()),
        };
        let catalog = self
            .bucket()
            .catalog_observed_with_reads(selected, &artifacts)
            .await?;
        selected.revalidate_physical_reads(self.fs()).await?;
        artifacts.read_check.recheck()?;
        Ok(HeldImmutableNodeReads {
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
    active_consumers: usize,
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

/// Keeps actual whole pack/index reads separate from each contextual metadata use.
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

/// Prevents closing while any get, including a ready-pack hit, is in flight.
struct ActiveConsumer<'cache> {
    cache: &'cache Mutex<Cache>,
}

impl<'cache> ActiveConsumer<'cache> {
    fn acquire(cache: &'cache Mutex<Cache>) -> Result<Self, StoreFailure> {
        let mut state = cache.lock().map_err(|_| unavailable())?;
        if state.phase != ReadPhase::Open {
            return Err(unavailable());
        }
        state.active_consumers = state
            .active_consumers
            .checked_add(1)
            .ok_or_else(unavailable)?;
        Ok(Self { cache })
    }
}

impl Drop for ActiveConsumer<'_> {
    fn drop(&mut self) {
        if let Ok(mut cache) = self.cache.lock() {
            // Every guard is constructed only after its checked increment.
            cache.active_consumers -= 1;
        }
    }
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

impl<F, C, V> HeldImmutableNodeReads<'_, '_, F, C, V>
where
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
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

impl<F: LocalFs, C, V> super::direct_node_reads::sealed::Sealed
    for HeldImmutableNodeReads<'_, '_, F, C, V>
{
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<F, C, V> super::direct_node_reads::DirectNodeReads for HeldImmutableNodeReads<'_, '_, F, C, V>
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
            || !std::ptr::eq(
                held.retained_namespace()?,
                self.selected.identity().retained_namespace()?,
            )
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

    fn check_direct(
        &self,
        direct: &crate::guard::direct_history::DirectReadCheck,
    ) -> Result<(), StoreFailure> {
        self.artifacts.read_check.check_direct(direct)
    }

    fn begin_closing(&self) -> Result<Vec<RecordRead>, StoreFailure> {
        self.artifacts.read_check.recheck()?;
        {
            let mut cache = self.cache.lock().map_err(|_| unavailable())?;
            if cache.phase != ReadPhase::Open || cache.active_consumers != 0 {
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
    fn complete_direct_closing(
        &self,
        checked: &crate::guard::direct_history::CheckedDirectHistoryInputs<'_, '_, '_>,
    ) -> Result<(), StoreFailure> {
        checked.check_reader_scope(self)?;
        self.artifacts.read_check.recheck()?;
        let mut cache = self.cache.lock().map_err(|_| unavailable())?;
        if cache.phase != ReadPhase::Closing || cache.active_consumers != 0 {
            return Err(unavailable());
        }
        cache.phase = ReadPhase::Complete;
        Ok(())
    }
}

impl<F: LocalFs, C, V> super::overlay_node_reads::sealed::Sealed
    for HeldImmutableNodeReads<'_, '_, F, C, V>
{
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<F, C, V> super::overlay_node_reads::OverlayNodeReads
    for HeldImmutableNodeReads<'_, '_, F, C, V>
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
            || !std::ptr::eq(
                held.retained_namespace()?,
                self.selected.identity().retained_namespace()?,
            )
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

    fn check_overlay(
        &self,
        overlay: &crate::guard::overlay_history::OverlayReadCheck,
    ) -> Result<(), StoreFailure> {
        self.artifacts.read_check.check_overlay(overlay)
    }

    fn begin_closing(&self) -> Result<Vec<RecordRead>, StoreFailure> {
        self.artifacts.read_check.recheck()?;
        {
            let mut cache = self.cache.lock().map_err(|_| unavailable())?;
            if cache.phase != ReadPhase::Open || cache.active_consumers != 0 {
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
    fn complete_overlay_closing(
        &self,
        checked: &crate::guard::overlay_history::CheckedOverlayHistoryInputs<'_, '_, '_>,
    ) -> Result<(), StoreFailure> {
        checked.check_reader_scope(self)?;
        self.artifacts.read_check.recheck()?;
        let mut cache = self.cache.lock().map_err(|_| unavailable())?;
        if cache.phase != ReadPhase::Closing || cache.active_consumers != 0 {
            return Err(unavailable());
        }
        cache.phase = ReadPhase::Complete;
        Ok(())
    }
}

impl<F: LocalFs, C, V> CapabilityReport for HeldImmutableNodeReads<'_, '_, F, C, V> {
    fn capabilities(&self) -> &Capabilities {
        self.bucket.capabilities()
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<F, C, V> ContentStore for HeldImmutableNodeReads<'_, '_, F, C, V>
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

        self.artifacts.read_check.recheck()?;
        let _consumer = ActiveConsumer::acquire(&self.cache)?;
        if !matches!(identity.kind(), IdentityKind::Commit | IdentityKind::Node) || range.is_some()
        {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        if self.bucket.is_excluded(&self.catalog, identity)? {
            return Err(StoreFailure::new(StoreErrorKind::Absent(identity.clone())));
        }
        let location = self.bucket.location(&self.catalog, identity)?;
        let pack = self.containing_pack(location.pack()).await?;
        self.artifacts.read_check.recheck()?;
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
        let upload = MetaUpload::new(identity.kind(), body).map_err(|_| corrupt(identity))?;
        self.bucket
            .inner
            .validator
            .validate_meta(&upload)
            .map_err(|_| corrupt(identity))?;
        TERRANE_V1
            .verify(identity, body)
            .map_err(|_| corrupt(identity))?;
        self.artifacts.read_check.recheck()?;
        Ok(body.to_vec())
    }

    async fn has(&self, _identities: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        Err(StoreFailure::new(StoreErrorKind::Unsupported))
    }

    async fn list(&self, _prefix: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        Err(StoreFailure::new(StoreErrorKind::Unsupported))
    }
}
