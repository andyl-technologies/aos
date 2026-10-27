//! Authenticated disk-addressable RAM images with bounded traversal memory.
//!
//! Logical RAM digests belong to `crucible-ram`. This module persists their
//! immutable realizations as ordinary child-bearing CAS objects. A root contains
//! the canonical logical root record and one catalog reference per selected
//! region; page lookup reads only its binary path. Initial capture streams pages,
//! and subsequent updates replace only changed paths. Neither operation builds
//! an in-memory catalog proportional to the number of guest pages.
//!
//! ```text
//! exact-manifest@ram-root.1 -> region catalog roots
//! ram-tree@ram-tree.1   -> left/right catalogs or one page object
//! ram-extent@ram-page.1    -> valid-length, logical digest, canonical page bytes
//! ```
//!
//! Root leases are supplied by the surrounding retention owner. The caller must
//! integrate that owner with its GC journal; a content digest or open backend
//! does not itself prevent collection. Physical packing remains a backend
//! property, and never changes the canonical plaintext object identities.

use std::sync::Arc;

use crucible_ram::{NodeDigest, RamRootDigest, RegionDescriptor, RootRecord};
use thiserror::Error;

use crate::content_envelope::{ContentEnvelope, ContentEnvelopeError};
use crate::content_store::{
    BlobHandle, ContentId, DurabilityRequirement, ImmutableBlobBackend, StoreError,
};

mod backing;
mod bounded_read;
mod canonical_tree;
mod difference;
pub use bounded_read::BoundedReadRequest;
#[cfg(test)]
pub(crate) use bounded_read::{
    read_tree_for_test, with_failed_work_for_test, with_pending_validation_for_test,
};
mod codec;
mod codec_ownership;
mod record_account;
mod root_publication;
pub use backing::maximum_encoded_ram_graph_bytes;
mod failure_cause;
pub use failure_cause::{
    PreparedRamFailure, RamFailureAdmission, RamFailureCause, RamOperationFailure,
};
mod inventory;
mod metadata;
pub use metadata::AdmittedRamRootMetadata;
mod restore;
pub use restore::RamPageVisitor;
mod retention;
pub use retention::{FencedRamRetention, RamRetentionAuthority};
mod object_source;
mod page_read;
pub use page_read::{RamPageBytes, RamPageRead};
mod read_failure;
mod receive;
pub use read_failure::{RamReadContinuation, RamReadValidation};
mod response;
mod send;
mod store_boundary;
mod transfer;
mod tree;
pub use store_boundary::RamBoundaryRefusal;

#[cfg(test)]
mod tests;

pub use crucible_qemu_protocol::ram_transfer::RamTransferCodecError;
pub use object_source::{RamObjectCoordinate, RamObjectRecord};
pub use receive::{RamTransferReceiver, RamTransferStep};
pub use response::RamTransferResponse;
pub use send::RamTransferSender;
pub use transfer::{RamClosureStored, RamTransferReport};
pub use tree::{RamPageChange, RamPageReader, RamVerificationReport};

/// Maximum canonical bytes in a single RAM metadata or page object.
pub const MAX_RAM_OBJECT_BYTES: u64 = 4 * 1024 * 1024;

/// Bounds allocation payloads before opening retained RAM root metadata.
///
/// The bound covers authenticated envelope input, child catalogs, canonical
/// re-encoding, the portable root decoder and retained tree references. All
/// RAM envelope decoders reject more than the portable region limit before
/// allocating child tables. Allocator and process overhead need additional
/// independently admitted resident headroom.
///
/// # Errors
/// Returns an error if the codec bounds cannot be composed without overflow.
pub fn maximum_ram_root_decoding_bytes() -> Result<u64, RamStoreError> {
    let limits = crucible_ram::Limits::default();
    let envelope = ContentEnvelope::decoding_memory_bound(
        usize::try_from(MAX_RAM_OBJECT_BYTES)
            .map_err(|_| RamStoreError::Limit("root allocation"))?,
        limits.max_regions,
    )?;
    let record = RootRecord::decoding_memory_bound(limits).map_err(logical)?;
    let catalogs = limits
        .max_regions
        .checked_mul(std::mem::size_of::<codec::TreeRef>())
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(RamStoreError::Limit("root allocation"))?;
    envelope
        .checked_add(record)
        .and_then(|bytes| bytes.checked_add(catalogs))
        .ok_or(RamStoreError::Limit("root allocation"))
}

/// Hard resource bounds for one RAM operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RamStoreLimits {
    /// Maximum aggregate logical bytes in the selected image.
    pub maximum_logical_bytes: u64,
    /// Maximum logical pages, counting repeated contents by position.
    pub maximum_pages: u64,
    /// Maximum metadata/page visits, including repeated references.
    pub maximum_object_visits: u64,
    /// Maximum authenticated canonical bytes read or written in one operation.
    pub maximum_io_bytes: u64,
}

impl Default for RamStoreLimits {
    fn default() -> Self {
        Self {
            maximum_logical_bytes: 64 * 1024 * 1024 * 1024,
            maximum_pages: 16 * 1024 * 1024 + 4096,
            maximum_object_visits: 128 * 1024 * 1024,
            maximum_io_bytes: 256 * 1024 * 1024 * 1024,
        }
    }
}

/// Error while capturing, looking up, updating, or transferring paged RAM.
#[derive(Debug, Error)]
pub enum RamStoreError {
    /// A checked boundary failed with complete original storage cleanup retained.
    #[error(transparent)]
    Boundary(RamFailureCause<RamStoreError>),
    /// The immutable content backend rejected an operation.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Canonical RAM or CAS metadata was malformed.
    #[error("RAM catalog validation failed: {0}")]
    Invalid(&'static str),
    /// The logical format rejected a descriptor, digest, or geometry.
    #[error("logical RAM validation failed: {0}")]
    Logical(String),
    /// An owned logical validation cause is retained without formatting it.
    #[error("logical RAM validation failed: {0}")]
    LogicalValidation(#[source] crucible_ram::RamError),
    /// A bounded CAS envelope failed validation.
    #[error(transparent)]
    Envelope(#[from] ContentEnvelopeError),
    /// The operation exhausted a declared resource dimension.
    #[error("RAM operation exceeds {0}")]
    Limit(&'static str),
    /// The operational owner canceled this work.
    #[error("RAM operation canceled")]
    Canceled,
    /// Retention could not establish or preserve required ownership.
    #[error("RAM retention failed: {0}")]
    Retention(String),
    /// A bounded transfer control or transport rejected a message.
    #[error(transparent)]
    Transfer(#[from] crucible_qemu_protocol::ram_transfer::RamTransferCodecError),
}

impl RamStoreError {
    /// Retains a typed admission refusal with its already existing account.
    ///
    /// This inline bridge requests no additional loan or shared allocation. It
    /// does not prepay the incoming refusal's own independently created payload.
    #[must_use]
    pub fn from_admission(
        original: &crate::owned_decode::DecodeBudget,
        source: crate::owned_decode::DecodeAdmissionError,
    ) -> Self {
        crate::content_store::batch::admission_under(original, source).into()
    }
}

/// Runs checked store work under an existing RAM operation boundary.
///
/// The adapter prepays the failure carriers before invoking the callback. A
/// boundary refusal remains the first typed [`RamStoreError`] while any later
/// storage or cleanup failure stays attached to the same original operation.
/// The callback receives a store-shaped boundary for checked content-store
/// APIs and must not retain it beyond the call.
///
/// # Errors
///
/// Returns original-account admission, the first boundary refusal, or the
/// checked store operation's error with its retained cleanup outcome.
pub fn with_store_operation_boundary<T>(
    original: &crate::owned_decode::DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
    operation: impl FnOnce(&mut dyn FnMut() -> Result<(), StoreError>) -> Result<T, StoreError>,
) -> Result<T, RamStoreError> {
    let mut account = store_boundary::WorkAccount::new(original)?;
    account.checked(boundary, |_, checked_boundary| operation(checked_boundary))
}

/// Retention capability keeping one immutable root and its descendants readable.
///
/// Implementations must register the root with the same authority used by GC.
/// Dropping a lease releases only this owner's claim; independently retained
/// checkpoints, templates, or transfers continue to protect their claims.
pub trait RamRootLease: Send + Sync {
    /// Returns the exact root covered by this retention capability.
    fn root(&self) -> ContentId;
}

/// Journal and GC owner for immutable RAM publication and discovery.
///
/// A publication session must keep GC exclusion or equivalent retention active
/// while new immutable objects are persisted and until `retain_root` installs
/// successor ownership. A validated catalog can precede its descendants; only
/// the complete closure permits root ownership. Unnamed partial progress may
/// become collectable after the operation closes. Implementations cannot
/// substitute advisory TTLs for live claims.
pub trait RamRetention: Send + Sync {
    /// Retains an object discovered or persisted within this operation.
    ///
    /// # Errors
    ///
    /// Returns an error if GC-safe operation ownership cannot be established.
    fn retain_object(&self, id: ContentId) -> Result<(), RamStoreError>;

    /// Establishes an independent root lease before operation retention ends.
    ///
    /// # Errors
    ///
    /// Returns an error if the root and all descendants cannot remain readable.
    fn retain_root(&self, root: ContentId) -> Result<Arc<dyn RamRootLease>, RamStoreError>;
}

/// Authenticated root metadata together with its live storage-retention owner.
#[derive(Clone)]
pub struct LeasedRamRoot {
    record: Arc<RootRecord>,
    regions: Arc<[codec::TreeRef]>,
    // A destination transfer shares the original metadata's storage retention.
    metadata_custody: Arc<dyn RamRootLease>,
    lease: Arc<dyn RamRootLease>,
    // Declared last so all shared metadata and retention controls close before
    // refundable financial credit. Transfers clone the same terminal loan.
    metadata_resources: crate::owned_decode::ResourceLoanSlot,
}

impl std::fmt::Debug for LeasedRamRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeasedRamRoot")
            .field("object", &self.object_id())
            .field("regions", &self.regions.len())
            .finish_non_exhaustive()
    }
}

impl LeasedRamRoot {
    /// Returns the storage identity of the complete RAM root object.
    #[must_use]
    pub fn object_id(&self) -> ContentId {
        self.lease.root()
    }

    /// Returns the decoded canonical logical root record.
    #[must_use]
    pub fn record(&self) -> &RootRecord {
        &self.record
    }

    /// Returns the representation-independent logical RAM digest.
    #[must_use]
    pub fn logical_digest(&self) -> RamRootDigest {
        self.record.digest()
    }
}

/// Immutable RAM store operating over a separately admitted content backend.
#[derive(Clone)]
pub struct RamStore {
    backend: Arc<dyn ImmutableBlobBackend>,
    durability: DurabilityRequirement,
    limits: RamStoreLimits,
}

impl RamStore {
    /// Admits an authenticated, streaming, durable content backend.
    ///
    /// Admission of each publication also checks the actual topology against
    /// authoritative writable-leaf object headroom. A streaming interface alone
    /// does not establish that a backend index can hold a dense RAM graph.
    ///
    /// # Errors
    ///
    /// Returns an error for zero limits or unsupported durability/streaming.
    pub fn new(
        backend: Arc<dyn ImmutableBlobBackend>,
        durability: DurabilityRequirement,
        limits: RamStoreLimits,
    ) -> Result<Self, RamStoreError> {
        if limits.maximum_logical_bytes == 0
            || limits.maximum_pages == 0
            || limits.maximum_object_visits == 0
            || limits.maximum_io_bytes == 0
        {
            return Err(RamStoreError::Limit("nonzero operation bounds"));
        }

        let capabilities = backend.capabilities();
        if !capabilities.durable
            || !capabilities.streaming_read
            || !capabilities.streaming_put
            || !capabilities.conditional_create
            || (capabilities.deferred_write && !durability.allows_deferred_write())
        {
            return Err(RamStoreError::Invalid("backend capability contract"));
        }

        Ok(Self {
            backend,
            durability,
            limits,
        })
    }
}

struct Work<'a> {
    pending: Option<PendingBatch>,
    canonical_session: Option<crate::content_store::PackedCanonicalSession>,
    canonical_session_enabled: bool,
    limits: RamStoreLimits,
    visits: u64,
    io_bytes: u64,
    boundary: &'a mut dyn FnMut() -> Result<(), RamStoreError>,
    account: store_boundary::WorkAccount<'a>,
    destination: Option<store_boundary::WorkAccount<'a>>,
}

struct PendingPublication {
    id: ContentId,
    source: BlobHandle,
    envelope: codec_ownership::PendingEnvelope,
}

// Element storage closes before its original scratch receipt. A flush drops
// this entire old batch before admitting a replacement array.
struct PendingBatch {
    objects: Vec<PendingPublication>,
    sorted_positions: [u16; codec::MAX_PUBLICATION_BATCH_OBJECTS],
    #[cfg(test)]
    identity_comparisons: std::cell::Cell<u64>,
    encoded_bytes: u64,
    _credit: crate::owned_decode::DecodeScratch,
}

impl std::ops::Deref for PendingBatch {
    type Target = Vec<PendingPublication>;

    fn deref(&self) -> &Self::Target {
        &self.objects
    }
}

enum PendingLookup<'a> {
    Occupied(&'a PendingPublication),
    Vacant(usize),
}

impl PendingBatch {
    fn object_at(&self, position: usize) -> Result<Option<&PendingPublication>, RamStoreError> {
        if position >= self.objects.len() {
            return Ok(None);
        }
        let slot = self
            .sorted_positions
            .get(position)
            .copied()
            .ok_or(RamStoreError::Invalid("RAM publication index position"))?;
        self.objects
            .get(usize::from(slot))
            .map(Some)
            .ok_or(RamStoreError::Invalid("RAM publication index slot"))
    }

    fn compare_id(&self, left: &ContentId, right: &ContentId) -> std::cmp::Ordering {
        #[cfg(test)]
        self.identity_comparisons
            .set(self.identity_comparisons.get() + 1);
        left.cmp(right)
    }

    fn lookup(&self, id: ContentId) -> Result<PendingLookup<'_>, RamStoreError> {
        // Shared/zero pages commonly repeat the first input. Preserve that
        // constant-time path without moving objects out of publication order.
        if let Some(first) = self.objects.first() {
            #[cfg(test)]
            self.identity_comparisons
                .set(self.identity_comparisons.get() + 1);
            if first.id == id {
                return Ok(PendingLookup::Occupied(first));
            }
        }
        let mut lower = 0;
        let mut upper = self.objects.len();
        while lower < upper {
            let middle = lower + (upper - lower) / 2;
            let candidate = self
                .object_at(middle)?
                .ok_or(RamStoreError::Invalid("RAM publication index entry"))?;
            if self.compare_id(&candidate.id, &id).is_lt() {
                lower = middle + 1;
            } else {
                upper = middle;
            }
        }
        if let Some(candidate) = self.object_at(lower)?
            && self.compare_id(&candidate.id, &id).is_eq()
        {
            return Ok(PendingLookup::Occupied(candidate));
        }
        Ok(PendingLookup::Vacant(lower))
    }

    fn push_at(
        &mut self,
        position: usize,
        object: PendingPublication,
    ) -> Result<(), RamStoreError> {
        let length = self.objects.len();
        if length >= self.objects.capacity() || length >= self.sorted_positions.len() {
            return Err(RamStoreError::Limit("RAM publication batch capacity"));
        }
        if position > length
            || (position != 0
                && self
                    .object_at(position - 1)?
                    .is_some_and(|prior| !self.compare_id(&prior.id, &object.id).is_lt()))
            || self
                .object_at(position)?
                .is_some_and(|next| !self.compare_id(&next.id, &object.id).is_gt())
        {
            return Err(RamStoreError::Invalid("RAM publication insertion position"));
        }
        let slot = u16::try_from(length)
            .map_err(|_| RamStoreError::Limit("RAM publication index slot"))?;
        let positions = self
            .sorted_positions
            .get_mut(position..=length)
            .ok_or(RamStoreError::Invalid("RAM publication insertion range"))?;
        // The checked inclusive range always contains at least one slot.
        // Shift only compact positions; the actual sources keep their order.
        positions.copy_within(..positions.len() - 1, 1);
        positions[0] = slot;
        // Capacity and all fallible index validation precede either mutation.
        // This push cannot allocate; the paid original array retains its order.
        self.objects.push(object);
        Ok(())
    }
}

impl<'a> IntoIterator for &'a PendingBatch {
    type Item = &'a PendingPublication;
    type IntoIter = std::slice::Iter<'a, PendingPublication>;

    fn into_iter(self) -> Self::IntoIter {
        self.objects.iter()
    }
}

impl<'a> Work<'a> {
    fn new(
        limits: RamStoreLimits,
        original: &'a crate::owned_decode::DecodeBudget,
        boundary: &'a mut dyn FnMut() -> Result<(), RamStoreError>,
    ) -> Result<Self, RamStoreError> {
        let account = store_boundary::WorkAccount::new(original)?;
        Ok(Self {
            pending: None,
            canonical_session: None,
            canonical_session_enabled: false,
            limits,
            visits: 0,
            io_bytes: 0,
            boundary,
            account,
            destination: None,
        })
    }

    fn from_retained(
        limits: RamStoreLimits,
        original: &'a crate::owned_decode::DecodeBudget,
        boundary: &'a mut dyn FnMut() -> Result<(), RamStoreError>,
        state: store_boundary::RetainedReadState,
        visits: u64,
        io_bytes: u64,
    ) -> Self {
        Self {
            pending: None,
            canonical_session: None,
            canonical_session_enabled: false,
            limits,
            visits,
            io_bytes,
            boundary,
            account: store_boundary::WorkAccount::from_retained(original, state),
            destination: None,
        }
    }

    fn destination(
        &mut self,
        original: &'a crate::owned_decode::DecodeBudget,
    ) -> Result<(), RamStoreError> {
        self.destination = Some(store_boundary::WorkAccount::new(original)?);
        Ok(())
    }

    fn with_destination<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, RamStoreError>,
    ) -> Result<T, RamStoreError> {
        let destination = self
            .destination
            .take()
            .ok_or(RamStoreError::Invalid("destination operation account"))?;
        let source = std::mem::replace(&mut self.account, destination);
        let result = operation(self);
        self.destination = Some(std::mem::replace(&mut self.account, source));
        result
    }

    fn visit(&mut self, bytes: u64) -> Result<(), RamStoreError> {
        (self.boundary)()?;
        self.visit_accounting(bytes)
    }

    // The prepaid small-record reader relocates its existing second poll.
    // All other visitors retain their original poll-before-accounting order.
    fn visit_accounting(&mut self, bytes: u64) -> Result<(), RamStoreError> {
        self.visits = self
            .visits
            .checked_add(1)
            .ok_or(RamStoreError::Limit("object visits"))?;
        self.io_bytes = self
            .io_bytes
            .checked_add(bytes)
            .ok_or(RamStoreError::Limit("I/O bytes"))?;
        if self.visits > self.limits.maximum_object_visits {
            return Err(RamStoreError::Limit("object visits"));
        }
        if self.io_bytes > self.limits.maximum_io_bytes {
            return Err(RamStoreError::Limit("I/O bytes"));
        }
        Ok(())
    }
}

fn logical(error: crucible_ram::RamError) -> RamStoreError {
    RamStoreError::LogicalValidation(error)
}

fn page_count(length: u64) -> u64 {
    1 + (length - 1) / 4096
}

fn height(count: u64) -> u32 {
    64 - (count - 1).leading_zeros()
}

fn valid_length(region: &RegionDescriptor, page: u64) -> Result<usize, RamStoreError> {
    let offset = page
        .checked_mul(4096)
        .ok_or(RamStoreError::Invalid("page offset overflow"))?;
    let remaining = region
        .logical_length()
        .checked_sub(offset)
        .filter(|remaining| *remaining != 0)
        .ok_or(RamStoreError::Invalid("page outside region"))?;
    usize::try_from(remaining.min(4096)).map_err(|_| RamStoreError::Invalid("page length"))
}

fn empty_node(level: u32) -> Result<NodeDigest, RamStoreError> {
    let mut digest = crucible_ram::empty_leaf_digest();
    for h in 1..=level {
        digest = crucible_ram::inner_digest(h, digest, digest).map_err(logical)?;
    }
    Ok(digest)
}
