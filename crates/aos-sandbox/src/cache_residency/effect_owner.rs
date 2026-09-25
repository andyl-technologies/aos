//! Dormant bounded memory and disk cache effect ownership.
//!
//! This fixed-root owner is a concrete node-local companion to the protected
//! residency reducers. It verifies immutable bytes before positive insertion,
//! scopes negative entries to an authorized lookup key, durably records disk
//! residency and pin obligations, and evicts only zero-pin LRU entries. It is
//! not opened by any service or installed profile.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use aos_sandbox_core::{MediaType, ObjectDescriptor, ObjectDigest};
use aos_sandbox_linux::immutable_file::{
    FsVerityDigest, FsVerityMapping, FsVerityPublicationRoot, MaterializationCallbacks,
    PublicationName,
};
use aos_sandbox_linux::path::BeneathRoot;
use rustix::fs::{AtFlags, FileType, FlockOperation, Mode, OFlags, RenameFlags};
use sha2::{Digest as _, Sha256};

use super::owner_readback::{
    CLOSED_CACHE_OWNER_READBACK_BYTES_V1, CacheOwnerReadbackChallengeV1, CacheOwnerReadbackErrorV1,
    CacheOwnerReadbackFieldsV1, cache_owner_limits_digest_v1, sign_closed_cache_owner_readback_v1,
};
use super::{
    AuthorizedLookupKey, CacheAuthorityOwner, CachePinId, CacheReservationV1,
    CurrentReadAuthorityV1, ImmutableAdmissionPlanV1, PhysicalPartitionId, SealProfileV1,
    ValidatedCacheResidencyPostcommitV1, VerifiedCacheCapabilityV1,
};

pub(crate) const FIXED_CACHE_ROOT: &str = "/var/lib/aos/sandbox/cache-residency-objects";
const LEGACY_CACHE_ROOT: &str = "/var/lib/aos/sandbox/cache-residency";
const MANIFEST_NAME: &str = "owner-state";
const MANIFEST_MAGIC: &[u8; 8] = b"AOSCOO01";
const MANIFEST_VERSION: u32 = 3;
const MAXIMUM_MANIFEST_BYTES: usize = 16 * 1024 * 1024;

mod signer_view;

pub(crate) use signer_view::SIGNER_OBJECT_VIEW;
pub(crate) use signer_view::{CacheSignerObjectReadbackV1, read_fixed_signer_cache_object_view_v1};

/// Bounds every retained positive, negative, and pin resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheOwnerLimitsV1 {
    /// Maximum heap bytes retained by positive memory entries.
    pub maximum_memory_bytes: u64,
    /// Maximum committed positive disk bytes.
    pub maximum_disk_bytes: u64,
    /// Disk usage below which an eviction pass stops.
    pub disk_low_water_bytes: u64,
    /// Maximum positive entries across both tiers.
    pub maximum_positive_entries: usize,
    /// Maximum authority-scoped negative entries.
    pub maximum_negative_entries: usize,
    /// Maximum simultaneous pins.
    pub maximum_pins: usize,
    /// Maximum aggregate bytes covered by pins.
    pub maximum_pinned_bytes: u64,
}

impl CacheOwnerLimitsV1 {
    /// Derives one node-global physical owner envelope from protected quotas.
    ///
    /// The caller supplies only the separate heap-tier ceiling. Physical bytes,
    /// resident entries, and pin obligations come from the complete protected
    /// partition set. The negative cache is advisory and shares the resident
    /// entry ceiling; it cannot expand correctness authority.
    ///
    /// # Errors
    ///
    /// Returns [`CacheOwnerErrorV1::InvalidLimits`] for absent, duplicate,
    /// cross-node, invalid, or unrepresentable partition quotas.
    pub fn from_node_quotas(
        maximum_memory_bytes: u64,
        quotas: impl IntoIterator<Item = super::NodeCacheQuotaV1>,
    ) -> Result<Self, CacheOwnerErrorV1> {
        let mut partitions = BTreeSet::new();
        let mut node = None;
        let mut maximum_disk_bytes = 0_u64;
        let mut disk_low_water_bytes = 0_u64;
        let mut maximum_positive_entries = 0_u64;
        let mut maximum_pins = 0_u64;
        let mut maximum_pinned_bytes = 0_u64;

        for quota in quotas {
            quota
                .validate()
                .map_err(|_| CacheOwnerErrorV1::InvalidLimits)?;
            if !partitions.insert(*quota.partition.digest().as_bytes())
                || node.is_some_and(|current| current != *quota.partition.node().as_bytes())
            {
                return Err(CacheOwnerErrorV1::InvalidLimits);
            }
            node = Some(*quota.partition.node().as_bytes());

            let partition_pins = quota
                .maximum_logical_pins
                .checked_add(quota.maximum_source_retentions)
                .and_then(|count| count.checked_add(quota.maximum_kernel_references))
                .and_then(|count| count.checked_add(quota.maximum_backing_registrations))
                .ok_or(CacheOwnerErrorV1::InvalidLimits)?;
            maximum_disk_bytes = maximum_disk_bytes
                .checked_add(quota.maximum_physical_bytes)
                .ok_or(CacheOwnerErrorV1::InvalidLimits)?;
            disk_low_water_bytes = disk_low_water_bytes
                .checked_add(quota.low_water_bytes)
                .ok_or(CacheOwnerErrorV1::InvalidLimits)?;
            maximum_positive_entries = maximum_positive_entries
                .checked_add(quota.maximum_resident_objects)
                .ok_or(CacheOwnerErrorV1::InvalidLimits)?;
            maximum_pins = maximum_pins
                .checked_add(partition_pins)
                .ok_or(CacheOwnerErrorV1::InvalidLimits)?;
            // Each pin charges its object's bytes independently. Saturation
            // keeps the owner bound representable without rejecting valid
            // large protected quotas; checked runtime accounting still fails
            // before u64 overflow.
            maximum_pinned_bytes = maximum_pinned_bytes
                .saturating_add(quota.maximum_physical_bytes.saturating_mul(partition_pins));
        }

        if partitions.is_empty() {
            return Err(CacheOwnerErrorV1::InvalidLimits);
        }
        Self {
            maximum_memory_bytes,
            maximum_disk_bytes,
            disk_low_water_bytes,
            maximum_positive_entries: usize::try_from(maximum_positive_entries)
                .map_err(|_| CacheOwnerErrorV1::InvalidLimits)?,
            maximum_negative_entries: usize::try_from(maximum_positive_entries)
                .map_err(|_| CacheOwnerErrorV1::InvalidLimits)?,
            maximum_pins: usize::try_from(maximum_pins)
                .map_err(|_| CacheOwnerErrorV1::InvalidLimits)?,
            maximum_pinned_bytes,
        }
        .validate()
    }

    /// Matches the entire physical envelope to protected node quotas.
    pub(crate) fn matches_node_quotas(self, quotas: &[super::NodeCacheQuotaV1]) -> bool {
        Self::from_node_quotas(self.maximum_memory_bytes, quotas.iter().copied())
            .is_ok_and(|derived| derived == self)
    }

    fn validate(self) -> Result<Self, CacheOwnerErrorV1> {
        if self.maximum_memory_bytes == 0
            || self.maximum_disk_bytes == 0
            || self.disk_low_water_bytes > self.maximum_disk_bytes
            || self.maximum_positive_entries == 0
            || self.maximum_negative_entries == 0
            || self.maximum_pins == 0
            || self.maximum_pinned_bytes == 0
        {
            return Err(CacheOwnerErrorV1::InvalidLimits);
        }
        Ok(self)
    }
}

/// Identifies one owner-local durable correctness pin.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CacheOwnerPinIdV1([u8; 16]);

impl CacheOwnerPinIdV1 {
    /// Derives an owner-global identity for a partition-local protected pin.
    ///
    /// # Errors
    ///
    /// Returns [`CacheOwnerErrorV1::InvalidPin`] if the truncated commitment is
    /// the reserved zero identity.
    pub fn for_cache_pin(
        partition: PhysicalPartitionId,
        pin: CachePinId,
    ) -> Result<Self, CacheOwnerErrorV1> {
        let digest = Sha256::new()
            .chain_update(b"aos.sandbox.cache.owner-pin-id.v1\0")
            .chain_update(partition.digest().as_bytes())
            .chain_update(pin.as_bytes())
            .finalize();
        let mut id = [0; 16];
        id.copy_from_slice(&digest[..16]);
        Self::from_bytes(id)
    }

    /// Constructs a nonzero owner-local pin identity.
    ///
    /// # Errors
    ///
    /// Returns [`CacheOwnerErrorV1::InvalidPin`] for the zero sentinel.
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, CacheOwnerErrorV1> {
        if bytes == [0; 16] {
            return Err(CacheOwnerErrorV1::InvalidPin);
        }
        Ok(Self(bytes))
    }

    /// Borrows the exact pin bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Proves which complete durable owner manifest was current.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheOwnerCurrentnessV1 {
    generation: u64,
    digest: ObjectDigest,
}

impl CacheOwnerCurrentnessV1 {
    /// Returns the durable owner generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the complete manifest digest.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.digest
    }
}

/// Reports one sealed owner effect and its resulting currentness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheEffectObservationV1 {
    effect: ObjectDigest,
    current: CacheOwnerCurrentnessV1,
}

impl CacheEffectObservationV1 {
    /// Returns the complete domain-separated effect commitment.
    #[must_use]
    pub const fn effect(self) -> ObjectDigest {
        self.effect
    }

    /// Returns the durable manifest current after the effect.
    #[must_use]
    pub const fn currentness(self) -> CacheOwnerCurrentnessV1 {
        self.current
    }
}

/// Describes an evicted immutable disk object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvictedCacheObjectV1 {
    /// Physical cache partition that owned the file.
    pub partition: ObjectDigest,
    /// Exact evicted object descriptor.
    pub descriptor: ObjectDescriptor,
    /// Bytes removed from owner accounting.
    pub bytes: u64,
}

/// Returns one authorization-scoped cache lookup result.
pub enum CacheLookupV1<'owner> {
    /// Verified bytes retained in the bounded heap tier.
    Memory(&'owner [u8]),
    /// Open descriptor for exact verified immutable disk bytes.
    Disk(File),
    /// A still-live negative entry for this exact authority scope.
    Negative { valid_until: u64 },
    /// No positive or authorized negative entry exists.
    Miss,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ObjectKey {
    partition: ObjectDigest,
    descriptor: ObjectDescriptor,
}

struct MemoryEntry {
    bytes: Vec<u8>,
    last_used: u64,
}

#[derive(Clone)]
struct DiskEntry {
    file_name: String,
    staging_name: Option<String>,
    deleting_name: Option<String>,
    bytes: u64,
    device: u64,
    inode: u64,
    verity: [u8; 32],
    canonical_name: ObjectDigest,
    root_custody: ObjectDigest,
    last_used: u64,
    pins: BTreeSet<CacheOwnerPinIdV1>,
}

#[derive(Clone, Copy)]
struct NegativeEntry {
    valid_until: u64,
    last_used: u64,
}

struct OrphanEntry {
    name: String,
    device: u64,
    inode: u64,
    bytes: u64,
}

/// Owns bounded node-local cache state beneath the fixed dormant root.
pub struct DormantCacheOwnerV1 {
    root: OwnedFd,
    _owner_lock: OwnedFd,
    root_identity: RootIdentity,
    publication_root: FsVerityPublicationRoot,
    mapping_root: BeneathRoot,
    limits: CacheOwnerLimitsV1,
    generation: u64,
    manifest_digest: ObjectDigest,
    memory: BTreeMap<ObjectKey, MemoryEntry>,
    disk: BTreeMap<ObjectKey, DiskEntry>,
    negatives: BTreeMap<AuthorizedLookupKey, NegativeEntry>,
    pin_index: BTreeMap<CacheOwnerPinIdV1, ObjectKey>,
    memory_bytes: u64,
    disk_bytes: u64,
    pinned_bytes: u64,
    orphans: BTreeMap<ObjectDigest, OrphanEntry>,
    fenced: bool,
    // A manifest with unknown durability must be resolved before any other effect.
    pending_manifest: Option<ObjectDigest>,
}

/// Borrows one replayable Cache head while its physical owner keeps the flock.
///
/// The descriptors remain borrowed from the owner, so this value cannot
/// release or transfer local ownership. A remote process must independently
/// authenticate the fixed paths, lock, and manifest from received descriptors;
/// these getters are not a publication or effect capability.
#[must_use = "revalidate before handing borrowed descriptors to another owner"]
pub struct CacheOwnerHeldSnapshotV1<'owner> {
    owner: &'owner DormantCacheOwnerV1,
    root_identity: RootIdentity,
    lock_identity: LockIdentity,
    manifest_identity: Option<ManifestIdentity>,
    current: CacheOwnerCurrentnessV1,
}

impl CacheOwnerHeldSnapshotV1<'_> {
    /// Returns the UID of the retained physical root and lock.
    #[must_use]
    pub const fn owner_uid(&self) -> u32 {
        self.root_identity.uid
    }

    /// Borrows the root and lock descriptors after a fresh local recheck.
    ///
    /// The first descriptor is the fixed root; the second is its held flock.
    /// A receiver must independently authenticate and replay both.
    ///
    /// # Errors
    ///
    /// Rejects a lost flock, changed fixed identity, or stale manifest.
    pub fn borrow_descriptors(
        &self,
    ) -> Result<(BorrowedFd<'_>, BorrowedFd<'_>), CacheOwnerErrorV1> {
        self.revalidate()?;
        Ok((self.owner.root.as_fd(), self.owner._owner_lock.as_fd()))
    }

    /// Returns the locally replayed durable head, not remote authority.
    #[must_use]
    pub const fn currentness(&self) -> CacheOwnerCurrentnessV1 {
        self.current
    }

    /// Rechecks the exact fixed descriptors and manifest while ownership holds.
    ///
    /// # Errors
    ///
    /// Rejects a lost flock, changed fixed path or inode, non-replayable
    /// volatile state, or changed or malformed durable manifest.
    pub fn revalidate(&self) -> Result<(), CacheOwnerErrorV1> {
        self.owner.validate_held_snapshot(
            self.root_identity,
            self.lock_identity,
            self.manifest_identity,
            self.current,
        )
    }

    /// Signs one closed fixed-name readback while the owner retains its flock.
    ///
    /// The caller must obtain a distinct Cache-purpose seed from protected
    /// deployment custody. The signing key and generation do not become
    /// authority merely because this method was invoked. No production path
    /// currently loads that seed or accepts the resulting statement.
    ///
    /// # Errors
    ///
    /// Rejects a lost flock, changed fixed names or durable head, malformed
    /// owner envelope, or zero signer generation.
    pub fn sign_closed_readback(
        &self,
        challenge: CacheOwnerReadbackChallengeV1,
        signer_generation: u64,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<[u8; CLOSED_CACHE_OWNER_READBACK_BYTES_V1], CacheOwnerReadbackErrorV1> {
        self.revalidate()?;
        let fields = self.readback_fields()?;
        let bytes =
            sign_closed_cache_owner_readback_v1(fields, challenge, signer_generation, signing_key)?;
        self.revalidate()?;
        Ok(bytes)
    }

    fn readback_fields(&self) -> Result<CacheOwnerReadbackFieldsV1, CacheOwnerReadbackErrorV1> {
        Ok(CacheOwnerReadbackFieldsV1 {
            root_device: self.root_identity.device,
            root_inode: self.root_identity.inode,
            root_uid: self.root_identity.uid,
            root_mode: self.root_identity.mode,
            lock_device: self.lock_identity.device,
            lock_inode: self.lock_identity.inode,
            manifest_generation: self.current.generation(),
            manifest_digest: self.current.digest(),
            limits_digest: cache_owner_limits_digest_v1(self.owner.limits)?,
        })
    }
}

/// Retains the exact fixed-root Cache identity across an ordered owner reopen.
///
/// This is not an effect admission or a held-lock proof. The Cache lock is
/// released while the ticket exists; `reopen` must reacquire it and independently
/// replay the same durable head before a caller may use the new owner.
#[must_use = "reopen and validate this Cache owner before using it"]
pub struct CacheOwnerReopenTicketV1 {
    root_identity: RootIdentity,
    lock_identity: LockIdentity,
    limits: CacheOwnerLimitsV1,
    current: CacheOwnerCurrentnessV1,
}

impl CacheOwnerReopenTicketV1 {
    /// Reacquires the fixed owner and rejects any root, lock, or head change.
    ///
    /// # Errors
    ///
    /// Returns an error if protected ownership cannot be reacquired, replay
    /// fails, or another actor changed the exact identity or durable head.
    pub fn reopen(self) -> Result<DormantCacheOwnerV1, CacheOwnerErrorV1> {
        let owner = DormantCacheOwnerV1::open_fixed(self.limits)?;
        if owner.root_identity != self.root_identity
            || inspect_lock(&owner.root, &owner._owner_lock)? != self.lock_identity
            || owner.currentness() != self.current
            || !owner.replayable_after_release()
        {
            return Err(CacheOwnerErrorV1::Stale);
        }
        owner.validate_current(self.current)?;
        Ok(owner)
    }
}

/// Retains Cache ownership when an ordered release cannot safely proceed.
#[must_use = "retain the owner for exact recovery after a refused release"]
pub struct CacheOwnerReleaseFailureV1 {
    owner: DormantCacheOwnerV1,
    source: CacheOwnerErrorV1,
}

impl CacheOwnerReleaseFailureV1 {
    /// Returns the still-held owner and the reason release was refused.
    #[must_use]
    pub fn into_parts(self) -> (DormantCacheOwnerV1, CacheOwnerErrorV1) {
        (self.owner, self.source)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RootIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LockIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ManifestIdentity {
    device: u64,
    inode: u64,
}

/// Retains the exact manifest generation after a replacement became ambiguous.
#[derive(Debug)]
#[must_use = "recover this exact manifest replacement before issuing another effect"]
pub struct CacheOwnerOutcomeUnknownV1 {
    generation: u64,
    predecessor: CacheOwnerCurrentnessV1,
    expected: Vec<u8>,
    temporary_name: String,
    effect: ObjectDigest,
}

/// Retains exact manifest-replacement custody after any failed recovery step.
#[derive(Debug)]
pub struct CacheOwnerRecoveryFailureV1 {
    pending: CacheOwnerOutcomeUnknownV1,
    source: CacheOwnerErrorV1,
}

impl CacheOwnerRecoveryFailureV1 {
    /// Returns the retained manifest token and latest recovery failure.
    #[must_use]
    pub fn into_parts(self) -> (CacheOwnerOutcomeUnknownV1, CacheOwnerErrorV1) {
        (self.pending, self.source)
    }
}

/// Retains exact cleanup custody for one failed fresh private inode.
#[derive(Debug)]
#[must_use = "recover or remove the exact retained private inode before retry"]
pub struct CacheMaterializationOutcomeV1 {
    name: String,
    device: u64,
    inode: u64,
}

/// Retains exact failed-materialization custody after any cleanup failure.
#[derive(Debug)]
pub struct CacheMaterializationRecoveryFailureV1 {
    pending: CacheMaterializationOutcomeV1,
    source: CacheOwnerErrorV1,
}

/// Classifies orphan cleanup as before-effect or exact recovery custody.
#[must_use = "recover pending cleanup or reclaim its unconsumed admission"]
pub enum CacheOrphanResolutionFailureV1 {
    /// No exact orphan was selected, so the admission remains unconsumed.
    BeforeEffect {
        /// Original one-shot admission, unchanged and reusable by its owner.
        admission: CacheOwnerAdmissionV1,
        /// Before-effect terminal classification.
        source: CacheOwnerErrorV1,
    },
    /// Cleanup started and must resume from exact inode/manifest custody.
    Pending(CacheOrphanResolutionPendingV1),
}

/// Retains one-shot admission, inode facts, and optional manifest ambiguity.
#[must_use = "resume this exact cleanup before attempting another admission"]
pub struct CacheOrphanResolutionPendingV1 {
    admission: CacheOwnerAdmissionV1,
    name: String,
    device: u64,
    inode: u64,
    bytes: u64,
    manifest: Option<CacheOwnerOutcomeUnknownV1>,
    last_error: Option<CacheOwnerErrorV1>,
}

impl CacheOrphanResolutionFailureV1 {
    /// Separates a before-effect admission from exact pending recovery custody.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> Result<CacheOrphanResolutionPendingV1, (CacheOwnerAdmissionV1, CacheOwnerErrorV1)> {
        match self {
            Self::BeforeEffect { admission, source } => Err((admission, source)),
            Self::Pending(pending) => Ok(pending),
        }
    }

    /// Returns exact pending custody, preserving a before-effect failure intact.
    pub fn into_pending(self) -> Result<CacheOrphanResolutionPendingV1, Self> {
        match self {
            Self::Pending(pending) => Ok(pending),
            before_effect => Err(before_effect),
        }
    }
}

impl CacheOrphanResolutionPendingV1 {
    /// Reports whether manifest replacement must be resolved before cleanup retry.
    #[must_use]
    pub const fn has_manifest_outcome_unknown(&self) -> bool {
        self.manifest.is_some()
    }

    /// Returns the most recent non-manifest recovery error, when one exists.
    #[must_use]
    pub const fn last_error(&self) -> Option<&CacheOwnerErrorV1> {
        self.last_error.as_ref()
    }
}

impl CacheMaterializationRecoveryFailureV1 {
    /// Returns the retained inode custody and latest cleanup failure.
    #[must_use]
    pub fn into_parts(self) -> (CacheMaterializationOutcomeV1, CacheOwnerErrorV1) {
        (self.pending, self.source)
    }
}

/// Carries one reserve-before-allocation admission issued by protected replay.
#[must_use = "the protected reservation must be consumed by one insertion attempt"]
pub struct CacheOwnerAdmissionV1 {
    transaction: ObjectDigest,
    plan: ImmutableAdmissionPlanV1,
    reservation: CacheReservationV1,
}

/// Carries one protected, single-use pin-state transition authority.
#[must_use = "the protected pin transition must be consumed exactly once"]
pub struct CacheOwnerPinAdmissionV1 {
    transaction: ObjectDigest,
    action: CacheOwnerPinActionV1,
    id: CacheOwnerPinIdV1,
    partition: PhysicalPartitionId,
    descriptor: ObjectDescriptor,
    predecessor: CacheOwnerCurrentnessV1,
    maximum_pins: usize,
    maximum_pinned_bytes: u64,
}

/// Carries one protected, single-use eviction transition authority.
#[must_use = "the protected eviction transition must be consumed exactly once"]
pub struct CacheOwnerEvictionAdmissionV1 {
    transaction: ObjectDigest,
    predecessor: CacheOwnerCurrentnessV1,
    target_reclaim_bytes: u64,
    victims: Vec<CacheEvictionVictimV1>,
}

struct CacheEvictionVictimV1 {
    partition: PhysicalPartitionId,
    key: ObjectKey,
    physical_bytes: u64,
    last_use_generation: u64,
    canonical_name: ObjectDigest,
    root_custody: ObjectDigest,
}

/// Selects the exact protected pin transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheOwnerPinActionV1 {
    /// Acquires the protected pin.
    Acquire,
    /// Releases the protected pin.
    Release,
}

/// Reports whether one exact owner-local pin is present in the current manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheOwnerPinPresenceV1 {
    /// The exact partition and object retain this pin.
    Present,
    /// No durable owner entry retains this pin identity.
    Absent,
}

/// Reports the durable physical result of one current protected pin event.
#[must_use = "public completion must account for the exact physical pin result"]
pub enum CacheOwnerPinSettlementV1 {
    /// The owner durably acquired or released the exact protected pin.
    Changed(CacheEffectObservationV1),
    /// A renewal retained its one already-present physical pin.
    Retained(CacheOwnerCurrentnessV1),
}

/// Describes whether exact physical reconciliation changed the owner manifest.
#[must_use = "cold pin recovery must account for the exact physical result"]
pub enum CacheOwnerPinReconciliationStateV1 {
    /// The missing physical action changed the durable owner manifest.
    Changed(CacheEffectObservationV1),
    /// The exact pin was already in the protected event's desired state.
    AlreadySettled(CacheOwnerCurrentnessV1),
}

/// Binds cold physical reconciliation to the protected pin action.
#[must_use = "cold pin recovery must account for the protected action"]
pub enum CacheOwnerPinReconciliationV1 {
    /// The protected acquisition has one present physical pin.
    Acquired(CacheOwnerPinReconciliationStateV1),
    /// The protected release has no remaining physical pin.
    Released(CacheOwnerPinReconciliationStateV1),
    /// A renewal retained its one already-present physical pin.
    Retained(CacheOwnerCurrentnessV1),
}

/// Reports a failed protected-to-physical Cache pin handoff.
#[derive(Debug, thiserror::Error)]
pub enum CacheOwnerPinSettlementErrorV1 {
    /// The protected postcommit proof is stale or cannot authorize this effect.
    #[error("protected Cache pin handoff failed: {0}")]
    Protected(#[from] super::CacheResidencyProtectedJournalErrorV1),
    /// Physical owner admission or durable observation failed.
    #[error("physical Cache pin handoff failed: {0}")]
    Owner(#[from] CacheOwnerErrorV1),
}

/// Borrows one validated, owner-locked durable manifest for batch pin observation.
pub struct CacheOwnerPinSnapshotV1<'owner> {
    owner: &'owner DormantCacheOwnerV1,
}

impl CacheOwnerPinSnapshotV1<'_> {
    /// Observes one exact pin without reopening the already-validated manifest.
    ///
    /// # Errors
    ///
    /// Returns an error for a conflicting identity or inconsistent pin index.
    pub fn observe_pin(
        &self,
        id: CacheOwnerPinIdV1,
        partition: PhysicalPartitionId,
        descriptor: &ObjectDescriptor,
    ) -> Result<CacheOwnerPinPresenceV1, CacheOwnerErrorV1> {
        let key = ObjectKey {
            partition: partition.digest(),
            descriptor: descriptor.clone(),
        };
        match self.owner.pin_index.get(&id) {
            Some(existing) if existing == &key => {
                let entry = self
                    .owner
                    .disk
                    .get(existing)
                    .ok_or(CacheOwnerErrorV1::RecoveryMismatch)?;
                if !entry.pins.contains(&id) {
                    return Err(CacheOwnerErrorV1::RecoveryMismatch);
                }
                Ok(CacheOwnerPinPresenceV1::Present)
            }
            Some(_) => Err(CacheOwnerErrorV1::InvalidPin),
            None if self
                .owner
                .disk
                .get(&key)
                .is_some_and(|entry| entry.pins.contains(&id)) =>
            {
                Err(CacheOwnerErrorV1::RecoveryMismatch)
            }
            None => Ok(CacheOwnerPinPresenceV1::Absent),
        }
    }
}

impl CacheOwnerPinAdmissionV1 {
    pub(crate) fn from_verified(
        transaction: ObjectDigest,
        action: CacheOwnerPinActionV1,
        id: CacheOwnerPinIdV1,
        partition: PhysicalPartitionId,
        descriptor: ObjectDescriptor,
        predecessor: CacheOwnerCurrentnessV1,
        maximum_pins: usize,
        maximum_pinned_bytes: u64,
    ) -> Self {
        Self {
            transaction,
            action,
            id,
            partition,
            descriptor,
            predecessor,
            maximum_pins,
            maximum_pinned_bytes,
        }
    }
}

impl CacheOwnerEvictionAdmissionV1 {
    pub(crate) fn from_verified(
        transaction: ObjectDigest,
        predecessor: CacheOwnerCurrentnessV1,
        target_reclaim_bytes: u64,
        victims: Vec<(
            PhysicalPartitionId,
            ObjectDescriptor,
            u64,
            u64,
            ObjectDigest,
            ObjectDigest,
        )>,
    ) -> Self {
        Self {
            transaction,
            predecessor,
            target_reclaim_bytes,
            victims: victims
                .into_iter()
                .map(
                    |(
                        partition,
                        descriptor,
                        physical_bytes,
                        last_use_generation,
                        canonical_name,
                        root_custody,
                    )| CacheEvictionVictimV1 {
                        partition,
                        key: ObjectKey {
                            partition: partition.digest(),
                            descriptor,
                        },
                        physical_bytes,
                        last_use_generation,
                        canonical_name,
                        root_custody,
                    },
                )
                .collect(),
        }
    }
}

impl CacheOwnerAdmissionV1 {
    pub(crate) fn from_verified(
        current: ValidatedCacheResidencyPostcommitV1<'_>,
        plan: ImmutableAdmissionPlanV1,
        reservation: CacheReservationV1,
    ) -> Self {
        Self {
            transaction: current.transaction_digest(),
            plan,
            reservation,
        }
    }
}

impl DormantCacheOwnerV1 {
    pub(crate) fn pin_grant_context(&self) -> (CacheOwnerCurrentnessV1, usize, u64) {
        (
            self.currentness(),
            self.limits.maximum_pins,
            self.limits.maximum_pinned_bytes,
        )
    }

    pub(crate) fn eviction_grant_predecessor(&self) -> CacheOwnerCurrentnessV1 {
        self.currentness()
    }

    /// Opens or initializes the fixed cache owner and recovers exact disk state.
    ///
    /// This call is the dormant effect boundary; no production component calls
    /// it. Recovery verifies every manifest-named file and restores an
    /// interrupted pre-manifest eviction rename when possible.
    ///
    /// # Errors
    ///
    /// Returns [`CacheOwnerErrorV1`] for invalid limits, malformed durable
    /// state, missing/corrupt immutable bytes, or filesystem failure.
    pub fn open_fixed(limits: CacheOwnerLimitsV1) -> Result<Self, CacheOwnerErrorV1> {
        let limits = limits.validate()?;
        reject_legacy_object_root()?;
        let root = rustix::fs::open(
            FIXED_CACHE_ROOT,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let root_identity = inspect_root(&root)?;
        let owner_lock = open_owner_lock(&root)?;
        let publication_root =
            FsVerityPublicationRoot::from_protected_absolute_path(Path::new(FIXED_CACHE_ROOT))?;
        if publication_root.device() != root_identity.device
            || publication_root.inode() != root_identity.inode
        {
            return Err(CacheOwnerErrorV1::RootChanged);
        }
        let mapping_root = BeneathRoot::from_owned(rustix::io::dup(&root)?)?;
        let bytes = match read_bounded_at(&root, MANIFEST_NAME, MAXIMUM_MANIFEST_BYTES) {
            Ok(bytes) => bytes,
            Err(CacheOwnerErrorV1::Rustix(error)) if error == rustix::io::Errno::NOENT => {
                let mut owner = Self::empty(
                    root,
                    owner_lock,
                    root_identity,
                    publication_root,
                    mapping_root,
                    limits,
                );
                owner.quarantine_orphan_staging()?;
                return Ok(owner);
            }
            Err(error) => return Err(error),
        };
        let (generation, disk, negatives) = decode_manifest(&bytes, limits)?;
        let manifest_digest = ObjectDigest::from_bytes(Sha256::digest(&bytes).into());
        let mut owner = Self {
            root,
            _owner_lock: owner_lock,
            root_identity,
            publication_root,
            mapping_root,
            limits,
            generation,
            manifest_digest,
            memory: BTreeMap::new(),
            disk,
            negatives,
            pin_index: BTreeMap::new(),
            memory_bytes: 0,
            disk_bytes: 0,
            pinned_bytes: 0,
            orphans: BTreeMap::new(),
            fenced: false,
            pending_manifest: None,
        };
        owner.recover_and_verify()?;
        owner.quarantine_orphan_staging()?;
        Ok(owner)
    }

    fn empty(
        root: OwnedFd,
        owner_lock: OwnedFd,
        root_identity: RootIdentity,
        publication_root: FsVerityPublicationRoot,
        mapping_root: BeneathRoot,
        limits: CacheOwnerLimitsV1,
    ) -> Self {
        Self {
            root,
            _owner_lock: owner_lock,
            root_identity,
            publication_root,
            mapping_root,
            limits,
            generation: 0,
            manifest_digest: ObjectDigest::from_bytes([0; 32]),
            memory: BTreeMap::new(),
            disk: BTreeMap::new(),
            negatives: BTreeMap::new(),
            pin_index: BTreeMap::new(),
            memory_bytes: 0,
            disk_bytes: 0,
            pinned_bytes: 0,
            orphans: BTreeMap::new(),
            fenced: false,
            pending_manifest: None,
        }
    }

    /// Returns the exact durable owner head.
    #[must_use]
    pub const fn currentness(&self) -> CacheOwnerCurrentnessV1 {
        CacheOwnerCurrentnessV1 {
            generation: self.generation,
            digest: self.manifest_digest,
        }
    }

    /// Borrows a replayable Cache head and its held fixed-root descriptors.
    ///
    /// This local snapshot prevents mutation through this owner for its
    /// lifetime. It does not prove Controller/source currentness or authorize
    /// a remote root CAS; a receiver must replay and validate the descriptors
    /// independently before it may rely on physical Cache evidence.
    ///
    /// # Errors
    ///
    /// Returns an error for volatile or unresolved state, changed fixed
    /// identity, lost exclusive lock, or failed durable manifest readback.
    pub fn held_snapshot(&self) -> Result<CacheOwnerHeldSnapshotV1<'_>, CacheOwnerErrorV1> {
        let current = self.currentness();
        let lock_identity = inspect_lock(&self.root, &self._owner_lock)?;
        let manifest_identity = inspect_manifest_identity(&self.root)?;
        self.validate_held_snapshot(
            self.root_identity,
            lock_identity,
            manifest_identity,
            current,
        )?;
        Ok(CacheOwnerHeldSnapshotV1 {
            owner: self,
            root_identity: self.root_identity,
            lock_identity,
            manifest_identity,
            current,
        })
    }

    /// Returns the envelope retained by this physical owner's flock.
    #[must_use]
    pub const fn limits(&self) -> CacheOwnerLimitsV1 {
        self.limits
    }

    fn validate_held_snapshot(
        &self,
        root_identity: RootIdentity,
        lock_identity: LockIdentity,
        manifest_identity: Option<ManifestIdentity>,
        current: CacheOwnerCurrentnessV1,
    ) -> Result<(), CacheOwnerErrorV1> {
        if !self.replayable_after_release() {
            return Err(CacheOwnerErrorV1::UnsafeRelease);
        }
        self.recheck_root()?;
        if self.root_identity != root_identity
            || inspect_lock(&self.root, &self._owner_lock)? != lock_identity
        {
            return Err(CacheOwnerErrorV1::RootChanged);
        }
        ensure_held_lock(&self.root, &self._owner_lock)?;
        if inspect_manifest_identity(&self.root)? != manifest_identity
            || replayed_manifest_head(&self.root, self.limits)? != current
            || inspect_manifest_identity(&self.root)? != manifest_identity
        {
            return Err(CacheOwnerErrorV1::Stale);
        }
        self.validate_current(current)
    }

    /// Releases a fully replayable owner for controller-to-source-to-Cache order.
    ///
    /// Memory entries, quarantined orphans, interrupted disk stages, and
    /// ambiguous manifest writes cannot be reconstructed by `open_fixed`.
    /// Refusal retains the original owner and its lock for exact recovery.
    /// Neither this ticket nor a later reopened owner proves another owner's
    /// head; publication still needs one held cross-owner cut.
    ///
    /// # Errors
    ///
    /// Returns the still-held owner if volatile state is present or fixed-root
    /// readback no longer matches the current durable manifest.
    pub fn release_for_ordered_reopen(
        self,
    ) -> Result<CacheOwnerReopenTicketV1, CacheOwnerReleaseFailureV1> {
        let result = (|| {
            if !self.replayable_after_release() {
                return Err(CacheOwnerErrorV1::UnsafeRelease);
            }
            self.validate_current(self.currentness())?;
            let lock_identity = inspect_lock(&self.root, &self._owner_lock)?;
            Ok(CacheOwnerReopenTicketV1 {
                root_identity: self.root_identity,
                lock_identity,
                limits: self.limits,
                current: self.currentness(),
            })
        })();
        result.map_err(|source| CacheOwnerReleaseFailureV1 {
            owner: self,
            source,
        })
    }

    fn replayable_after_release(&self) -> bool {
        !self.fenced
            && self.pending_manifest.is_none()
            && self.memory.is_empty()
            && self.memory_bytes == 0
            && self.orphans.is_empty()
            && self
                .disk
                .values()
                .all(|entry| entry.staging_name.is_none() && entry.deleting_name.is_none())
    }

    /// Reopens the manifest and validates an effect-time currentness proof.
    ///
    /// # Errors
    ///
    /// Returns [`CacheOwnerErrorV1::Stale`] after any durable replacement.
    pub fn validate_current(
        &self,
        expected: CacheOwnerCurrentnessV1,
    ) -> Result<(), CacheOwnerErrorV1> {
        self.validate_durable_head(expected)
    }

    /// Observes one exact physical pin against the current durable manifest.
    ///
    /// A missing pin is distinct from an identity bound to another object;
    /// the latter is a conflict, never a successful no-effect release.
    ///
    /// # Errors
    ///
    /// Returns an error when the owner is fenced, the manifest changed, or
    /// retained pin indexing disagrees with the exact object and partition.
    pub fn observe_pin(
        &self,
        id: CacheOwnerPinIdV1,
        partition: PhysicalPartitionId,
        descriptor: &ObjectDescriptor,
    ) -> Result<CacheOwnerPinPresenceV1, CacheOwnerErrorV1> {
        self.pin_snapshot()?.observe_pin(id, partition, descriptor)
    }

    /// Validates and borrows one owner-locked manifest for bounded pin scans.
    ///
    /// # Errors
    ///
    /// Returns an error when the owner is fenced or its durable head changed.
    pub fn pin_snapshot(&self) -> Result<CacheOwnerPinSnapshotV1<'_>, CacheOwnerErrorV1> {
        self.ensure_unfenced()?;
        self.validate_durable_head(self.currentness())?;
        Ok(CacheOwnerPinSnapshotV1 { owner: self })
    }

    fn validate_durable_head(
        &self,
        expected: CacheOwnerCurrentnessV1,
    ) -> Result<(), CacheOwnerErrorV1> {
        self.recheck_root()?;
        let bytes = match read_bounded_at(&self.root, MANIFEST_NAME, MAXIMUM_MANIFEST_BYTES) {
            Err(CacheOwnerErrorV1::Rustix(error))
                if error == rustix::io::Errno::NOENT && expected.generation == 0 =>
            {
                return if expected.digest.as_bytes() == &[0; 32] {
                    Ok(())
                } else {
                    Err(CacheOwnerErrorV1::Stale)
                };
            }
            outcome => outcome?,
        };
        let actual = CacheOwnerCurrentnessV1 {
            generation: decode_generation(&bytes)?,
            digest: ObjectDigest::from_bytes(Sha256::digest(&bytes).into()),
        };
        if actual != expected {
            return Err(CacheOwnerErrorV1::Stale);
        }
        Ok(())
    }

    /// Consumes one protected reservation before allocating memory or disk.
    ///
    /// # Errors
    ///
    /// Returns an error for descriptor mismatch, exhausted capacity, clock
    /// regression, allocation refusal, or durable filesystem failure.
    pub fn insert_verified(
        &mut self,
        admission: CacheOwnerAdmissionV1,
        source: OwnedFd,
        prefer_memory: bool,
        now: u64,
    ) -> Result<CacheEffectObservationV1, CacheOwnerErrorV1> {
        self.ensure_unfenced()?;
        validate_now(now)?;
        self.recheck_root()?;
        let descriptor = admission.plan.descriptor.clone();
        let partition = admission.plan.partition;
        if self.orphans.contains_key(&admission.transaction) {
            return Err(CacheOwnerErrorV1::Materialization);
        }
        if admission.reservation.reserved_bytes < descriptor.encoded_size()
            || admission.plan.reserved_bytes < descriptor.encoded_size()
        {
            return Err(CacheOwnerErrorV1::CapacityExhausted);
        }
        let key = ObjectKey {
            partition: partition.digest(),
            descriptor,
        };
        if let Some(entry) = self.disk.get_mut(&key) {
            entry.last_used = now;
            return self.persist(b"touch-existing", key.descriptor.digest().as_bytes());
        }
        if let Some(entry) = self.memory.get_mut(&key) {
            entry.last_used = now;
            return self.persist(b"memory-touch", admission.transaction.as_bytes());
        }
        if self.disk.len() + self.memory.len() >= self.limits.maximum_positive_entries {
            return Err(CacheOwnerErrorV1::CapacityExhausted);
        }
        let length = key.descriptor.encoded_size();
        if prefer_memory && length <= self.limits.maximum_memory_bytes {
            while self
                .memory_bytes
                .checked_add(length)
                .is_none_or(|value| value > self.limits.maximum_memory_bytes)
            {
                let oldest = self
                    .memory
                    .iter()
                    .min_by_key(|(_, entry)| entry.last_used)
                    .map(|(candidate, _)| candidate.clone())
                    .ok_or(CacheOwnerErrorV1::CapacityExhausted)?;
                let removed = self
                    .memory
                    .remove(&oldest)
                    .ok_or(CacheOwnerErrorV1::RecoveryMismatch)?;
                self.memory_bytes = self
                    .memory_bytes
                    .checked_sub(removed.bytes.len() as u64)
                    .ok_or(CacheOwnerErrorV1::RecoveryMismatch)?;
            }
            let length_usize =
                usize::try_from(length).map_err(|_| CacheOwnerErrorV1::CapacityExhausted)?;
            let mut owned = Vec::new();
            owned
                .try_reserve_exact(length_usize)
                .map_err(|_| CacheOwnerErrorV1::AllocationRefused)?;
            owned.resize(length_usize, 0);
            let mut source = File::from(source);
            source.read_exact(&mut owned)?;
            let mut trailing = [0_u8; 1];
            if source.read(&mut trailing)? != 0 {
                return Err(CacheOwnerErrorV1::IntegrityFailure);
            }
            verify_bytes(&key.descriptor, &owned)?;
            self.memory.insert(
                key.clone(),
                MemoryEntry {
                    bytes: owned,
                    last_used: now,
                },
            );
            self.memory_bytes += length;
            return self.persist(b"memory-insert", admission.transaction.as_bytes());
        }
        if self
            .disk_bytes
            .checked_add(length)
            .is_none_or(|value| value > self.limits.maximum_disk_bytes)
        {
            return Err(CacheOwnerErrorV1::CapacityExhausted);
        }
        let file_name = object_file_name(&key);
        validate_basename(&file_name)?;
        let staging_generation = self
            .generation
            .checked_add(1)
            .ok_or(CacheOwnerErrorV1::GenerationExhausted)?;
        let temporary_name = format!(
            ".admit-{}-{}.tmp",
            staging_generation,
            hex(admission.transaction.as_bytes())
        );
        let mut verifier = DescriptorVerifier::new(&key.descriptor);
        let sealed = match self.publication_root.materialize_and_seal_exact_mode(
            source,
            PublicationName::new(OsStr::new(&temporary_name))?,
            admission.reservation.reserved_bytes,
            &mut verifier,
        ) {
            Ok(sealed) => sealed,
            Err(error) => {
                let (_, retained) = error.into_parts();
                let pending = retained.and_then(|artifact| {
                    Some(CacheMaterializationOutcomeV1 {
                        name: artifact.name().as_os_str().to_str()?.to_owned(),
                        device: artifact.device()?,
                        inode: artifact.inode()?,
                    })
                });
                return match pending {
                    Some(pending) => Err(CacheOwnerErrorV1::MaterializationRetained(pending)),
                    None => {
                        self.fenced = true;
                        Err(CacheOwnerErrorV1::Materialization)
                    }
                };
            }
        };
        let retained_sealed = CacheMaterializationOutcomeV1 {
            name: temporary_name.clone(),
            device: sealed.device(),
            inode: sealed.inode(),
        };
        let FsVerityDigest::Sha256(verity) = sealed.verity_digest() else {
            return Err(CacheOwnerErrorV1::MaterializationRetained(retained_sealed));
        };
        if admission.plan.expected_seal.profile != SealProfileV1::FsVeritySha256
            || admission.plan.expected_seal.measurement.as_bytes() != &verity
        {
            return Err(CacheOwnerErrorV1::MaterializationRetained(retained_sealed));
        }
        let device = sealed.device();
        let inode = sealed.inode();
        self.disk.insert(
            key.clone(),
            DiskEntry {
                file_name,
                staging_name: Some(temporary_name.clone()),
                deleting_name: None,
                bytes: length,
                device,
                inode,
                verity,
                canonical_name: super::canonical_name_digest(
                    admission.plan.partition,
                    &admission.plan.descriptor,
                ),
                root_custody: admission.plan.root_custody,
                last_used: now,
                pins: BTreeSet::new(),
            },
        );
        self.disk_bytes += length;
        self.persist(b"admission-staged", key.descriptor.digest().as_bytes())?;
        let final_name = self
            .disk
            .get(&key)
            .ok_or(CacheOwnerErrorV1::RecoveryMismatch)?
            .file_name
            .clone();
        self.validate_durable_head(self.currentness())?;
        if rustix::fs::renameat_with(
            &self.root,
            temporary_name.as_str(),
            &self.root,
            final_name.as_str(),
            RenameFlags::NOREPLACE,
        )
        .is_err()
            || rustix::fs::fsync(&self.root).is_err()
            || self
                .verify_disk_name(&key, &final_name, device, inode, verity)
                .is_err()
        {
            return Err(CacheOwnerErrorV1::AdmissionOutcomeUnknown {
                staging_current: self.currentness(),
            });
        }
        self.disk
            .get_mut(&key)
            .ok_or(CacheOwnerErrorV1::RecoveryMismatch)?
            .staging_name = None;
        self.persist(b"disk-insert", key.descriptor.digest().as_bytes())
    }

    /// Completes any manifest-retained admission or eviction stage after reopen.
    ///
    /// # Errors
    ///
    /// Returns an error unless every staged name identifies the exact retained
    /// fs-verity inode and the resulting manifest reaches exact readback.
    pub fn recover_staged_effects(&mut self) -> Result<(), CacheOwnerErrorV1> {
        self.ensure_unfenced()?;
        self.disk_bytes = 0;
        self.pinned_bytes = 0;
        self.pin_index.clear();
        self.recover_and_verify()
    }

    /// Removes only the exact failed fresh inode retained by materialization.
    ///
    /// # Errors
    ///
    /// Returns an error if the protected basename now names a different inode
    /// or cleanup cannot be durably synchronized.
    pub fn recover_failed_materialization(
        &mut self,
        pending: CacheMaterializationOutcomeV1,
    ) -> Result<(), CacheMaterializationRecoveryFailureV1> {
        match self.recover_failed_materialization_inner(&pending) {
            Ok(()) => Ok(()),
            Err(source) => Err(CacheMaterializationRecoveryFailureV1 { pending, source }),
        }
    }

    fn recover_failed_materialization_inner(
        &mut self,
        pending: &CacheMaterializationOutcomeV1,
    ) -> Result<(), CacheOwnerErrorV1> {
        self.ensure_unfenced()?;
        self.recheck_root()?;
        validate_basename(&pending.name)?;
        if pending.device == 0 || pending.inode == 0 {
            return Err(CacheOwnerErrorV1::RecoveryMismatch);
        }
        let transaction = orphan_transaction(&pending.name)?;
        match rustix::fs::statat(&self.root, pending.name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat)
                if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
                    && stat.st_dev == pending.device
                    && stat.st_ino == pending.inode
                    && stat.st_uid == rustix::process::geteuid().as_raw()
                    && stat.st_nlink == 1 =>
            {
                self.validate_durable_head(self.currentness())?;
                rustix::fs::unlinkat(&self.root, pending.name.as_str(), AtFlags::empty())?;
            }
            Err(error) if error == rustix::io::Errno::NOENT => {
                // Reopen may either observe completed unlink or have moved the
                // same inode into its deterministic orphan quarantine.
                let quarantine = format!(
                    ".orphan-{}-{:016x}-{:016x}",
                    hex(transaction.as_bytes()),
                    pending.device,
                    pending.inode
                );
                match rustix::fs::statat(&self.root, quarantine.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                {
                    Ok(stat)
                        if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
                            && stat.st_dev == pending.device
                            && stat.st_ino == pending.inode
                            && stat.st_uid == rustix::process::geteuid().as_raw()
                            && stat.st_nlink == 1 =>
                    {
                        self.validate_durable_head(self.currentness())?;
                        rustix::fs::unlinkat(&self.root, quarantine.as_str(), AtFlags::empty())?;
                    }
                    Err(error) if error == rustix::io::Errno::NOENT => {}
                    Ok(_) => return Err(CacheOwnerErrorV1::RecoveryMismatch),
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(_) => return Err(CacheOwnerErrorV1::RecoveryMismatch),
            Err(error) => return Err(error.into()),
        }
        self.validate_durable_head(self.currentness())?;
        rustix::fs::fsync(&self.root)?;
        if let Some(orphan) = self.orphans.get(&transaction) {
            if orphan.device != pending.device || orphan.inode != pending.inode {
                return Err(CacheOwnerErrorV1::RecoveryMismatch);
            }
            let bytes = orphan.bytes;
            self.orphans.remove(&transaction);
            self.disk_bytes = self
                .disk_bytes
                .checked_sub(bytes)
                .ok_or(CacheOwnerErrorV1::RecoveryMismatch)?;
        }
        self.recheck_root()
    }

    /// Removes one bounded orphan only under its original protected reservation.
    ///
    /// # Errors
    ///
    /// Returns an error unless the admission transaction and reserved byte
    /// ceiling match the exact quarantined inode.
    pub fn resolve_orphaned_admission(
        &mut self,
        admission: CacheOwnerAdmissionV1,
    ) -> Result<CacheEffectObservationV1, CacheOrphanResolutionFailureV1> {
        let transaction = admission.transaction;
        let custody = self.orphans.get(&transaction).map(|orphan| {
            (
                orphan.name.clone(),
                orphan.device,
                orphan.inode,
                orphan.bytes,
            )
        });
        let Some((name, device, inode, bytes)) = custody else {
            return Err(CacheOrphanResolutionFailureV1::BeforeEffect {
                admission,
                source: CacheOwnerErrorV1::NotResident,
            });
        };
        self.resolve_orphan_inner(admission, name, device, inode, bytes)
    }

    /// Recovers exact orphan cleanup after live or cold ambiguity.
    ///
    /// # Errors
    ///
    /// Returns refreshed admission and inode custody on every failure.
    pub fn recover_orphaned_admission(
        &mut self,
        mut pending: CacheOrphanResolutionPendingV1,
    ) -> Result<CacheEffectObservationV1, CacheOrphanResolutionFailureV1> {
        if let Some(manifest) = pending.manifest.take() {
            return match self.recover_outcome_unknown(manifest) {
                Ok(observation) => Ok(observation),
                Err(failure) => {
                    let (manifest, source) = failure.into_parts();
                    pending.manifest = Some(manifest);
                    pending.last_error = Some(source);
                    Err(CacheOrphanResolutionFailureV1::Pending(pending))
                }
            };
        }
        self.resolve_orphan_inner(
            pending.admission,
            pending.name,
            pending.device,
            pending.inode,
            pending.bytes,
        )
    }

    fn resolve_orphan_inner(
        &mut self,
        admission: CacheOwnerAdmissionV1,
        name: String,
        device: u64,
        inode: u64,
        bytes: u64,
    ) -> Result<CacheEffectObservationV1, CacheOrphanResolutionFailureV1> {
        match self.resolve_orphan_exact(&admission, &name, device, inode, bytes) {
            Ok(observation) => Ok(observation),
            Err(CacheOwnerErrorV1::OutcomeUnknown(manifest)) => Err(
                CacheOrphanResolutionFailureV1::Pending(CacheOrphanResolutionPendingV1 {
                    admission,
                    name,
                    device,
                    inode,
                    bytes,
                    manifest: Some(manifest),
                    last_error: None,
                }),
            ),
            Err(source) => Err(CacheOrphanResolutionFailureV1::Pending(
                CacheOrphanResolutionPendingV1 {
                    admission,
                    name,
                    device,
                    inode,
                    bytes,
                    manifest: None,
                    last_error: Some(source),
                },
            )),
        }
    }

    fn resolve_orphan_exact(
        &mut self,
        admission: &CacheOwnerAdmissionV1,
        name: &str,
        device: u64,
        inode: u64,
        bytes: u64,
    ) -> Result<CacheEffectObservationV1, CacheOwnerErrorV1> {
        self.ensure_unfenced()?;
        validate_basename(name)?;
        if device == 0 || inode == 0 || bytes == 0 || bytes > admission.reservation.reserved_bytes {
            return Err(CacheOwnerErrorV1::RecoveryMismatch);
        }
        match rustix::fs::statat(&self.root, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat)
                if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
                    && stat.st_dev == device
                    && stat.st_ino == inode
                    && stat.st_uid == rustix::process::geteuid().as_raw()
                    && stat.st_nlink == 1 =>
            {
                self.validate_durable_head(self.currentness())?;
                rustix::fs::unlinkat(&self.root, name, AtFlags::empty())?;
            }
            Err(error) if error == rustix::io::Errno::NOENT => {
                // The exact unlink may have completed before directory fsync.
            }
            Ok(_) => return Err(CacheOwnerErrorV1::RecoveryMismatch),
            Err(error) => return Err(error.into()),
        }
        self.validate_durable_head(self.currentness())?;
        rustix::fs::fsync(&self.root)?;
        if let Some(orphan) = self.orphans.get(&admission.transaction) {
            if orphan.name != name
                || orphan.device != device
                || orphan.inode != inode
                || orphan.bytes != bytes
            {
                return Err(CacheOwnerErrorV1::RecoveryMismatch);
            }
            self.orphans.remove(&admission.transaction);
            self.disk_bytes = self
                .disk_bytes
                .checked_sub(bytes)
                .ok_or(CacheOwnerErrorV1::RecoveryMismatch)?;
        }
        self.persist(b"orphan-cleanup", admission.transaction.as_bytes())
    }

    /// Records or refreshes one authorization-scoped negative result.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid time, exhausted negative capacity, or
    /// durable replacement failure.
    pub fn record_negative(
        &mut self,
        authority: &CurrentReadAuthorityV1,
        authority_owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
    ) -> Result<CacheEffectObservationV1, CacheOwnerErrorV1> {
        self.ensure_unfenced()?;
        let now = protected_now()?;
        let (_, _, key, valid_until) =
            authority.revalidate_cache_lookup(authority_owner, capability, now)?;
        if valid_until <= now {
            return Err(CacheOwnerErrorV1::InvalidTime);
        }
        self.prune_negatives(now);
        if !self.negatives.contains_key(&key)
            && self.negatives.len() >= self.limits.maximum_negative_entries
        {
            let oldest = self
                .negatives
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| *key)
                .ok_or(CacheOwnerErrorV1::CapacityExhausted)?;
            self.negatives.remove(&oldest);
        }
        let now = protected_now()?;
        let (_, _, current_key, current_valid_until) =
            authority.revalidate_cache_lookup(authority_owner, capability, now)?;
        if current_key != key || current_valid_until != valid_until {
            return Err(CacheOwnerErrorV1::Stale);
        }
        self.negatives.insert(
            key,
            NegativeEntry {
                valid_until,
                last_used: now,
            },
        );
        self.persist(b"negative", key.digest().as_bytes())
    }

    /// Looks up positive bytes or a negative memo only after authority supplied its key.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid time, descriptor mismatch in recovered
    /// state, or filesystem failure.
    pub fn lookup<'owner>(
        &'owner mut self,
        authority: &CurrentReadAuthorityV1,
        authority_owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
    ) -> Result<CacheLookupV1<'owner>, CacheOwnerErrorV1> {
        self.ensure_unfenced()?;
        let now = protected_now()?;
        let (partition, descriptor, authorized_negative, _) =
            authority.revalidate_cache_lookup(authority_owner, capability, now)?;
        let key = ObjectKey {
            partition: partition.digest(),
            descriptor: descriptor.clone(),
        };
        if self.memory.contains_key(&key) {
            let entry = self.memory.get_mut(&key).ok_or(CacheOwnerErrorV1::Stale)?;
            entry.last_used = now;
            return Ok(CacheLookupV1::Memory(&entry.bytes));
        }
        if let Some(entry) = self.disk.get_mut(&key) {
            entry.last_used = now;
            let (file_name, device, inode, verity) = (
                entry.file_name.clone(),
                entry.device,
                entry.inode,
                entry.verity,
            );
            let _ = entry;
            let _ = self.persist(b"lookup-touch", key.descriptor.digest().as_bytes())?;
            let file = self.verify_disk_name(&key, &file_name, device, inode, verity)?;
            let now = protected_now()?;
            let (current_partition, current_descriptor, current_key, _) =
                authority.revalidate_cache_lookup(authority_owner, capability, now)?;
            if current_partition != partition
                || current_descriptor != descriptor
                || current_key != authorized_negative
            {
                return Err(CacheOwnerErrorV1::Stale);
            }
            return Ok(CacheLookupV1::Disk(file));
        }
        if let Some(entry) = self.negatives.get_mut(&authorized_negative) {
            if entry.valid_until > now {
                entry.last_used = now;
                let valid_until = entry.valid_until;
                let _ = entry;
                let _ = self.persist(b"negative-touch", authorized_negative.digest().as_bytes())?;
                let now = protected_now()?;
                let (_, _, current_key, current_valid_until) =
                    authority.revalidate_cache_lookup(authority_owner, capability, now)?;
                if current_key != authorized_negative || current_valid_until != valid_until {
                    return Err(CacheOwnerErrorV1::Stale);
                }
                return Ok(CacheLookupV1::Negative { valid_until });
            }
            self.negatives.remove(&authorized_negative);
        }
        Ok(CacheLookupV1::Miss)
    }

    pub(crate) fn observe_lifecycle_availability(
        &mut self,
        descriptor: &ObjectDescriptor,
    ) -> Result<CacheEffectObservationV1, CacheOwnerErrorV1> {
        self.ensure_unfenced()?;
        self.recheck_root()?;
        if self
            .memory
            .keys()
            .any(|candidate| &candidate.descriptor == descriptor)
        {
            return Err(CacheOwnerErrorV1::Stale);
        }
        let Some((key, entry)) = self
            .disk
            .iter()
            .find(|(candidate, _)| &candidate.descriptor == descriptor)
        else {
            return Err(CacheOwnerErrorV1::Stale);
        };
        let key = key.clone();
        let (file_name, device, inode, verity) = (
            entry.file_name.clone(),
            entry.device,
            entry.inode,
            entry.verity,
        );
        self.verify_disk_name(&key, &file_name, device, inode, verity)?;
        let current = self.currentness();
        Ok(CacheEffectObservationV1 {
            effect: cache_lifecycle_availability_effect_v1(descriptor, current),
            current,
        })
    }

    /// Applies the exact physical pin action sealed by a protected transaction.
    ///
    /// The admission supplies its own action, owner-local identity, partition,
    /// and object. A caller cannot redirect it to another physical pin.
    ///
    /// # Errors
    ///
    /// Returns an error for stale owner state, absent residency, pin conflict,
    /// exhausted budgets, or a failed durable manifest update.
    pub fn apply_pin_change(
        &mut self,
        admission: CacheOwnerPinAdmissionV1,
    ) -> Result<CacheEffectObservationV1, CacheOwnerErrorV1> {
        match admission.action {
            CacheOwnerPinActionV1::Acquire => self.acquire_pin(admission),
            CacheOwnerPinActionV1::Release => self.release_pin(admission),
        }
    }

    /// Acquires one durable pin within both count and byte budgets.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate/unknown pins or exhausted budgets.
    fn acquire_pin(
        &mut self,
        admission: CacheOwnerPinAdmissionV1,
    ) -> Result<CacheEffectObservationV1, CacheOwnerErrorV1> {
        self.ensure_unfenced()?;
        let id = admission.id;
        let partition = admission.partition;
        let descriptor = &admission.descriptor;
        if admission.action != CacheOwnerPinActionV1::Acquire
            || admission.predecessor != self.currentness()
            || admission.maximum_pins != self.limits.maximum_pins
            || admission.maximum_pinned_bytes != self.limits.maximum_pinned_bytes
        {
            return Err(CacheOwnerErrorV1::Stale);
        }
        if self.pin_index.contains_key(&id) || self.pin_index.len() >= self.limits.maximum_pins {
            return Err(CacheOwnerErrorV1::InvalidPin);
        }
        let key = ObjectKey {
            partition: partition.digest(),
            descriptor: descriptor.clone(),
        };
        let entry = self
            .disk
            .get_mut(&key)
            .ok_or(CacheOwnerErrorV1::NotResident)?;
        if entry.pins.contains(&id) {
            return Err(CacheOwnerErrorV1::InvalidPin);
        }
        let next = self
            .pinned_bytes
            .checked_add(entry.bytes)
            .ok_or(CacheOwnerErrorV1::CapacityExhausted)?;
        if next > self.limits.maximum_pinned_bytes {
            return Err(CacheOwnerErrorV1::CapacityExhausted);
        }
        entry.pins.insert(id);
        self.pin_index.insert(id, key.clone());
        self.pinned_bytes = next;
        self.persist(b"pin", id.as_bytes())
    }

    /// Releases one exact durable pin.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown or inconsistent pin identity.
    fn release_pin(
        &mut self,
        admission: CacheOwnerPinAdmissionV1,
    ) -> Result<CacheEffectObservationV1, CacheOwnerErrorV1> {
        self.ensure_unfenced()?;
        let id = admission.id;
        let key = self
            .pin_index
            .get(&id)
            .ok_or(CacheOwnerErrorV1::InvalidPin)?
            .clone();
        if admission.action != CacheOwnerPinActionV1::Release
            || admission.partition.digest() != key.partition
            || admission.descriptor != key.descriptor
            || admission.predecessor != self.currentness()
            || admission.maximum_pins != self.limits.maximum_pins
            || admission.maximum_pinned_bytes != self.limits.maximum_pinned_bytes
        {
            return Err(CacheOwnerErrorV1::Stale);
        }
        let entry = self.disk.get(&key).ok_or(CacheOwnerErrorV1::InvalidPin)?;
        if !entry.pins.contains(&id) {
            return Err(CacheOwnerErrorV1::InvalidPin);
        }
        let remaining_pinned_bytes = self
            .pinned_bytes
            .checked_sub(entry.bytes)
            .ok_or(CacheOwnerErrorV1::InvalidPin)?;

        let entry = self
            .disk
            .get_mut(&key)
            .ok_or(CacheOwnerErrorV1::InvalidPin)?;

        // All fallible consistency checks precede the coupled mutation.
        // A failed persist fences the owner until recovery or reopen.
        let _ = entry.pins.remove(&id);
        let _ = self.pin_index.remove(&id);
        self.pinned_bytes = remaining_pinned_bytes;
        self.persist(b"unpin", id.as_bytes())
    }

    /// Evicts zero-pin disk entries in least-recently-used order to low water.
    ///
    /// # Errors
    ///
    /// Returns an error when insufficient eligible bytes exist or a durable
    /// rename, manifest replacement, unlink, or directory sync fails.
    pub fn evict_to_low_water(
        &mut self,
        admission: CacheOwnerEvictionAdmissionV1,
    ) -> Result<(Vec<EvictedCacheObjectV1>, CacheEffectObservationV1), CacheOwnerErrorV1> {
        self.ensure_unfenced()?;
        self.validate_durable_head(admission.predecessor)?;
        if admission.predecessor != self.currentness()
            || admission.victims.is_empty()
            || admission.target_reclaim_bytes == 0
        {
            return Err(CacheOwnerErrorV1::Stale);
        }
        let mut reclaimable = 0_u64;
        let mut exact_victims = BTreeSet::new();
        for victim in &admission.victims {
            if !exact_victims.insert(victim.key.clone()) {
                return Err(CacheOwnerErrorV1::Stale);
            }
            let entry = self
                .disk
                .get(&victim.key)
                .ok_or(CacheOwnerErrorV1::RecoveryMismatch)?;
            if !entry.pins.is_empty()
                || entry.bytes != victim.physical_bytes
                || entry.last_used != victim.last_use_generation
                || entry.canonical_name != victim.canonical_name
                || entry.root_custody != victim.root_custody
                || super::canonical_name_digest(victim.partition, &victim.key.descriptor)
                    != victim.canonical_name
            {
                return Err(CacheOwnerErrorV1::Stale);
            }
            reclaimable = reclaimable
                .checked_add(entry.bytes)
                .ok_or(CacheOwnerErrorV1::CapacityExhausted)?;
        }
        if reclaimable < admission.target_reclaim_bytes
            || self
                .disk_bytes
                .checked_sub(reclaimable)
                .is_none_or(|remaining| remaining > self.limits.disk_low_water_bytes)
        {
            return Err(CacheOwnerErrorV1::CapacityExhausted);
        }
        let mut evicted = Vec::new();
        for victim in &admission.victims {
            let key = victim.key.clone();
            self.validate_durable_head(self.currentness())?;
            let entry = self
                .disk
                .get(&key)
                .ok_or(CacheOwnerErrorV1::RecoveryMismatch)?;
            if !entry.pins.is_empty() {
                return Err(CacheOwnerErrorV1::InvalidPin);
            }
            let file_name = entry.file_name.clone();
            let entry_bytes = entry.bytes;
            let deleting_generation = self
                .generation
                .checked_add(1)
                .ok_or(CacheOwnerErrorV1::GenerationExhausted)?;
            let deleting = format!(".deleting-{deleting_generation}-{file_name}");
            validate_basename(&deleting)?;
            self.validate_durable_head(self.currentness())?;
            rustix::fs::renameat(&self.root, file_name.as_str(), &self.root, &deleting)?;
            if rustix::fs::fsync(&self.root).is_err() {
                return Err(CacheOwnerErrorV1::EvictionOutcomeUnknown {
                    deleting_current: self.currentness(),
                });
            }
            self.disk
                .get_mut(&key)
                .ok_or(CacheOwnerErrorV1::RecoveryMismatch)?
                .deleting_name = Some(deleting.clone());
            self.persist(b"eviction-selected", key.descriptor.digest().as_bytes())?;
            self.validate_durable_head(self.currentness())?;
            if rustix::fs::unlinkat(&self.root, deleting.as_str(), AtFlags::empty()).is_err()
                || rustix::fs::fsync(&self.root).is_err()
            {
                return Err(CacheOwnerErrorV1::EvictionOutcomeUnknown {
                    deleting_current: self.currentness(),
                });
            }
            let entry = self
                .disk
                .remove(&key)
                .ok_or(CacheOwnerErrorV1::RecoveryMismatch)?;
            self.disk_bytes = self
                .disk_bytes
                .checked_sub(entry.bytes)
                .ok_or(CacheOwnerErrorV1::RecoveryMismatch)?;
            let observation =
                self.persist(b"eviction-unlinked", key.descriptor.digest().as_bytes())?;
            evicted.push(EvictedCacheObjectV1 {
                partition: key.partition,
                descriptor: key.descriptor,
                bytes: entry_bytes,
            });
            let _ = observation;
        }
        if self.disk_bytes > self.limits.disk_low_water_bytes {
            return Err(CacheOwnerErrorV1::CapacityExhausted);
        }
        let observation = self.persist(b"eviction-complete", admission.transaction.as_bytes())?;
        Ok((evicted, observation))
    }

    fn recover_and_verify(&mut self) -> Result<(), CacheOwnerErrorV1> {
        self.disk_bytes = 0;
        self.pinned_bytes = 0;
        self.pin_index.clear();
        let staging: Vec<_> = self
            .disk
            .iter()
            .filter_map(|(key, entry)| {
                entry
                    .staging_name
                    .as_ref()
                    .map(|name| (key.clone(), name.clone()))
            })
            .collect();
        let recovered_admission = !staging.is_empty();
        for (key, name) in staging {
            let entry = self
                .disk
                .get(&key)
                .ok_or(CacheOwnerErrorV1::RecoveryMismatch)?;
            let final_verified = self
                .verify_disk_name(
                    &key,
                    &entry.file_name,
                    entry.device,
                    entry.inode,
                    entry.verity,
                )
                .is_ok();
            if !final_verified {
                self.verify_disk_name(&key, &name, entry.device, entry.inode, entry.verity)?;
                self.validate_durable_head(self.currentness())?;
                rustix::fs::renameat_with(
                    &self.root,
                    name.as_str(),
                    &self.root,
                    entry.file_name.as_str(),
                    RenameFlags::NOREPLACE,
                )?;
                rustix::fs::fsync(&self.root)?;
                self.verify_disk_name(
                    &key,
                    &entry.file_name,
                    entry.device,
                    entry.inode,
                    entry.verity,
                )?;
            }
            self.disk
                .get_mut(&key)
                .ok_or(CacheOwnerErrorV1::RecoveryMismatch)?
                .staging_name = None;
        }
        let deleting: Vec<_> = self
            .disk
            .iter()
            .filter_map(|(key, entry)| {
                entry
                    .deleting_name
                    .as_ref()
                    .map(|name| (key.clone(), name.clone()))
            })
            .collect();
        let recovered_deletion = !deleting.is_empty();
        for (key, name) in deleting {
            let entry = self
                .disk
                .get(&key)
                .ok_or(CacheOwnerErrorV1::RecoveryMismatch)?;
            match self.verify_disk_name(&key, &name, entry.device, entry.inode, entry.verity) {
                Ok(_) => {
                    self.validate_durable_head(self.currentness())?;
                    rustix::fs::unlinkat(&self.root, name.as_str(), AtFlags::empty())?;
                }
                Err(CacheOwnerErrorV1::Rustix(error)) if error == rustix::io::Errno::NOENT => {
                    // The unlink may have succeeded before its parent fsync failed.
                    // The durable deleting manifest is the exact authority to
                    // accept absence and finish the same reclamation only.
                }
                Err(error) => return Err(error),
            }
            rustix::fs::fsync(&self.root)?;
            self.disk.remove(&key);
        }
        for (key, entry) in &self.disk {
            validate_basename(&entry.file_name)?;
            let verification = self.verify_disk_name(
                key,
                &entry.file_name,
                entry.device,
                entry.inode,
                entry.verity,
            );
            if matches!(
                &verification,
                Err(CacheOwnerErrorV1::Rustix(error)) if *error == rustix::io::Errno::NOENT
            ) {
                let interrupted = format!(
                    ".deleting-{}-{}",
                    self.generation
                        .checked_add(1)
                        .ok_or(CacheOwnerErrorV1::GenerationExhausted)?,
                    entry.file_name
                );
                self.verify_disk_name(key, &interrupted, entry.device, entry.inode, entry.verity)?;
                self.validate_durable_head(self.currentness())?;
                rustix::fs::renameat(
                    &self.root,
                    interrupted.as_str(),
                    &self.root,
                    entry.file_name.as_str(),
                )?;
                rustix::fs::fsync(&self.root)?;
                self.verify_disk_name(
                    key,
                    &entry.file_name,
                    entry.device,
                    entry.inode,
                    entry.verity,
                )?;
            } else {
                verification?;
            }
            self.disk_bytes = self
                .disk_bytes
                .checked_add(entry.bytes)
                .ok_or(CacheOwnerErrorV1::CapacityExhausted)?;
            for pin in &entry.pins {
                if self.pin_index.insert(*pin, key.clone()).is_some() {
                    return Err(CacheOwnerErrorV1::RecoveryMismatch);
                }
                self.pinned_bytes = self
                    .pinned_bytes
                    .checked_add(entry.bytes)
                    .ok_or(CacheOwnerErrorV1::CapacityExhausted)?;
            }
        }
        self.disk_bytes = self
            .orphans
            .values()
            .try_fold(self.disk_bytes, |total, orphan| {
                total
                    .checked_add(orphan.bytes)
                    .ok_or(CacheOwnerErrorV1::CapacityExhausted)
            })?;
        if self.disk_bytes > self.limits.maximum_disk_bytes
            || self.pin_index.len() > self.limits.maximum_pins
            || self.pinned_bytes > self.limits.maximum_pinned_bytes
        {
            return Err(CacheOwnerErrorV1::CapacityExhausted);
        }
        if recovered_admission || recovered_deletion {
            let kind: &[u8] = if recovered_deletion {
                b"eviction-recovered"
            } else {
                b"admission-recovered"
            };
            let _ = self.persist(kind, &[0; 32])?;
        }
        Ok(())
    }

    fn verify_disk_name(
        &self,
        key: &ObjectKey,
        name: &str,
        device: u64,
        inode: u64,
        verity: [u8; 32],
    ) -> Result<File, CacheOwnerErrorV1> {
        validate_basename(name)?;
        self.recheck_root()?;
        let descriptor = FsVerityMapping::open_verified_beneath(
            &self.mapping_root,
            Path::new(name),
            FsVerityDigest::Sha256(verity),
            key.descriptor.encoded_size(),
        )?;
        let stat = rustix::fs::fstat(&descriptor)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_dev != device
            || stat.st_ino != inode
            || stat.st_nlink != 1
            || stat.st_uid != rustix::process::geteuid().as_raw()
            || stat.st_size < 0
            || stat.st_size as u64 != key.descriptor.encoded_size()
        {
            return Err(CacheOwnerErrorV1::RecoveryMismatch);
        }
        self.recheck_root()?;
        Ok(File::from(descriptor))
    }

    fn recheck_root(&self) -> Result<(), CacheOwnerErrorV1> {
        if inspect_root(&self.root)? != self.root_identity {
            return Err(CacheOwnerErrorV1::RootChanged);
        }
        inspect_lock(&self.root, &self._owner_lock)?;
        self.publication_root.recheck_protected_path()?;
        Ok(())
    }

    fn ensure_unfenced(&self) -> Result<(), CacheOwnerErrorV1> {
        if self.fenced || self.pending_manifest.is_some() {
            return Err(CacheOwnerErrorV1::Fenced);
        }
        Ok(())
    }

    fn quarantine_orphan_staging(&mut self) -> Result<(), CacheOwnerErrorV1> {
        self.recheck_root()?;
        let readable = rustix::fs::openat(
            &self.root,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let entries = rustix::fs::Dir::read_from(&readable)?;
        let mut inspected = 0_usize;
        for entry in entries {
            let entry = entry?;
            let name_bytes = entry.file_name().to_bytes();
            if (!name_bytes.starts_with(b".admit-") || !name_bytes.ends_with(b".tmp"))
                && !name_bytes.starts_with(b".orphan-")
            {
                continue;
            }
            inspected = inspected
                .checked_add(1)
                .ok_or(CacheOwnerErrorV1::CapacityExhausted)?;
            if inspected > self.limits.maximum_positive_entries {
                return Err(CacheOwnerErrorV1::CapacityExhausted);
            }
            let name =
                std::str::from_utf8(name_bytes).map_err(|_| CacheOwnerErrorV1::UnsafeName)?;
            validate_basename(name)?;
            if name.starts_with(".admit-")
                && self
                    .disk
                    .values()
                    .any(|record| record.staging_name.as_deref() == Some(name))
            {
                continue;
            }
            let stat = rustix::fs::statat(&self.root, name, AtFlags::SYMLINK_NOFOLLOW)?;
            if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                || stat.st_uid != rustix::process::geteuid().as_raw()
                || stat.st_nlink != 1
            {
                return Err(CacheOwnerErrorV1::RecoveryMismatch);
            }
            let transaction = orphan_transaction(name)?;
            let quarantine = format!(
                ".orphan-{}-{:016x}-{:016x}",
                hex(transaction.as_bytes()),
                stat.st_dev,
                stat.st_ino
            );
            if name != quarantine {
                self.validate_durable_head(self.currentness())?;
                rustix::fs::renameat_with(
                    &self.root,
                    name,
                    &self.root,
                    quarantine.as_str(),
                    RenameFlags::NOREPLACE,
                )?;
            }
            let after =
                rustix::fs::statat(&self.root, quarantine.as_str(), AtFlags::SYMLINK_NOFOLLOW)?;
            if after.st_dev != stat.st_dev || after.st_ino != stat.st_ino {
                return Err(CacheOwnerErrorV1::RecoveryMismatch);
            }
            rustix::fs::fsync(&self.root)?;
            let bytes =
                u64::try_from(after.st_size).map_err(|_| CacheOwnerErrorV1::RecoveryMismatch)?;
            self.disk_bytes = self
                .disk_bytes
                .checked_add(bytes)
                .ok_or(CacheOwnerErrorV1::CapacityExhausted)?;
            if self.disk_bytes > self.limits.maximum_disk_bytes
                || self
                    .orphans
                    .insert(
                        transaction,
                        OrphanEntry {
                            name: quarantine,
                            device: after.st_dev,
                            inode: after.st_ino,
                            bytes,
                        },
                    )
                    .is_some()
            {
                return Err(CacheOwnerErrorV1::CapacityExhausted);
            }
        }
        self.recheck_root()
    }

    fn prune_negatives(&mut self, now: u64) {
        self.negatives.retain(|_, entry| entry.valid_until > now);
    }

    fn persist(
        &mut self,
        kind: &[u8],
        subject: &[u8],
    ) -> Result<CacheEffectObservationV1, CacheOwnerErrorV1> {
        let result = self.persist_inner(kind, subject);

        // Callers may have already changed memory; only exact recovery or reopen
        // can reconcile a failed durable write with those tentative changes.
        match &result {
            Ok(_) => {}
            Err(CacheOwnerErrorV1::OutcomeUnknown(pending)) => {
                self.pending_manifest = Some(pending.effect);
            }
            Err(_) => self.fenced = true,
        }
        result
    }

    fn persist_inner(
        &mut self,
        kind: &[u8],
        subject: &[u8],
    ) -> Result<CacheEffectObservationV1, CacheOwnerErrorV1> {
        self.recheck_root()?;
        let predecessor = self.currentness();
        self.validate_durable_head(predecessor)?;
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(CacheOwnerErrorV1::GenerationExhausted)?;
        let bytes = encode_manifest(generation, &self.disk, &self.negatives)?;
        let temporary_name = format!(".{MANIFEST_NAME}-{generation}.tmp");
        let digest = ObjectDigest::from_bytes(Sha256::digest(&bytes).into());
        let current = CacheOwnerCurrentnessV1 { generation, digest };
        let effect = cache_owner_effect_commitment_v1(kind, subject, current);
        let pending = || CacheOwnerOutcomeUnknownV1 {
            generation,
            predecessor,
            expected: bytes.clone(),
            temporary_name: temporary_name.clone(),
            effect,
        };
        let stage_result = (|| -> Result<(), CacheOwnerErrorV1> {
            remove_exact_temporary(&self.root, &temporary_name, &bytes)?;
            let descriptor = rustix::fs::openat(
                &self.root,
                temporary_name.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )?;
            let mut file = File::from(descriptor);
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            if read_bounded_at(&self.root, &temporary_name, MAXIMUM_MANIFEST_BYTES)? != bytes {
                return Err(CacheOwnerErrorV1::InvalidManifest);
            }
            Ok(())
        })();
        if stage_result.is_err() {
            return Err(CacheOwnerErrorV1::OutcomeUnknown(pending()));
        }
        if self.validate_durable_head(predecessor).is_err() {
            return Err(CacheOwnerErrorV1::OutcomeUnknown(pending()));
        }
        if rustix::fs::renameat(
            &self.root,
            temporary_name.as_str(),
            &self.root,
            MANIFEST_NAME,
        )
        .is_err()
            || rustix::fs::fsync(&self.root).is_err()
        {
            return Err(CacheOwnerErrorV1::OutcomeUnknown(pending()));
        }
        let readback = read_bounded_at(&self.root, MANIFEST_NAME, MAXIMUM_MANIFEST_BYTES);
        if !readback.as_ref().is_ok_and(|observed| observed == &bytes)
            || self.recheck_root().is_err()
        {
            return Err(CacheOwnerErrorV1::OutcomeUnknown(pending()));
        }
        self.generation = generation;
        self.manifest_digest = digest;
        Ok(CacheEffectObservationV1 { effect, current })
    }

    /// Reopens and resolves one exact manifest replacement without broad retry.
    ///
    /// # Errors
    ///
    /// Returns [`CacheOwnerRecoveryFailureV1`] with the original exact token
    /// when readback is foreign, remains ambiguous, or cannot be synchronized.
    pub fn recover_outcome_unknown(
        &mut self,
        pending: CacheOwnerOutcomeUnknownV1,
    ) -> Result<CacheEffectObservationV1, CacheOwnerRecoveryFailureV1> {
        match self.recover_outcome_unknown_inner(&pending) {
            Ok(observation) => Ok(observation),
            Err(source) => Err(CacheOwnerRecoveryFailureV1 { pending, source }),
        }
    }

    fn recover_outcome_unknown_inner(
        &mut self,
        pending: &CacheOwnerOutcomeUnknownV1,
    ) -> Result<CacheEffectObservationV1, CacheOwnerErrorV1> {
        if self.fenced {
            return Err(CacheOwnerErrorV1::Fenced);
        }
        // A cold reopen has no volatile marker; the durable comparison below
        // still authenticates the exact recovery token.
        if self
            .pending_manifest
            .is_some_and(|effect| effect != pending.effect)
        {
            return Err(CacheOwnerErrorV1::Stale);
        }
        self.recheck_root()?;
        if decode_generation(&pending.expected)? != pending.generation {
            return Err(CacheOwnerErrorV1::InvalidManifest);
        }
        let observed = read_bounded_at(&self.root, MANIFEST_NAME, MAXIMUM_MANIFEST_BYTES);
        if observed
            .as_ref()
            .is_ok_and(|bytes| bytes == &pending.expected)
        {
            rustix::fs::fsync(&self.root)?;
            remove_exact_temporary(&self.root, &pending.temporary_name, &pending.expected)?;
            self.adopt_manifest(&pending.expected)?;
            self.pending_manifest = None;
            return Ok(CacheEffectObservationV1 {
                effect: pending.effect,
                current: self.currentness(),
            });
        }
        let predecessor_matches = match observed {
            Ok(bytes) => {
                decode_generation(&bytes)? == pending.predecessor.generation
                    && ObjectDigest::from_bytes(Sha256::digest(&bytes).into())
                        == pending.predecessor.digest
            }
            Err(CacheOwnerErrorV1::Rustix(error)) if error == rustix::io::Errno::NOENT => {
                pending.predecessor.generation == 0
                    && pending.predecessor.digest.as_bytes() == &[0; 32]
            }
            Err(error) => return Err(error),
        };
        if !predecessor_matches {
            return Err(CacheOwnerErrorV1::Stale);
        }
        let recreate_temporary =
            match read_bounded_at(&self.root, &pending.temporary_name, MAXIMUM_MANIFEST_BYTES) {
                Ok(bytes) if bytes == pending.expected => false,
                Err(CacheOwnerErrorV1::Rustix(error)) if error == rustix::io::Errno::NOENT => true,
                Ok(_) => {
                    let stat = rustix::fs::statat(
                        &self.root,
                        pending.temporary_name.as_str(),
                        AtFlags::SYMLINK_NOFOLLOW,
                    )?;
                    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                        || stat.st_uid != rustix::process::geteuid().as_raw()
                        || stat.st_nlink != 1
                    {
                        return Err(CacheOwnerErrorV1::RecoveryMismatch);
                    }
                    rustix::fs::unlinkat(
                        &self.root,
                        pending.temporary_name.as_str(),
                        AtFlags::empty(),
                    )?;
                    rustix::fs::fsync(&self.root)?;
                    true
                }
                Err(error) => return Err(error),
            };
        if recreate_temporary {
            let descriptor = rustix::fs::openat(
                &self.root,
                pending.temporary_name.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )?;
            let mut file = File::from(descriptor);
            file.write_all(&pending.expected)?;
            file.sync_all()?;
            drop(file);
            if read_bounded_at(&self.root, &pending.temporary_name, MAXIMUM_MANIFEST_BYTES)?
                != pending.expected
            {
                return Err(CacheOwnerErrorV1::RecoveryMismatch);
            }
        }
        if rustix::fs::renameat(
            &self.root,
            pending.temporary_name.as_str(),
            &self.root,
            MANIFEST_NAME,
        )
        .is_err()
            || rustix::fs::fsync(&self.root).is_err()
            || !read_bounded_at(&self.root, MANIFEST_NAME, MAXIMUM_MANIFEST_BYTES)
                .as_ref()
                .is_ok_and(|bytes| bytes == &pending.expected)
        {
            return Err(CacheOwnerErrorV1::RecoveryMismatch);
        }
        self.adopt_manifest(&pending.expected)?;
        self.pending_manifest = None;
        Ok(CacheEffectObservationV1 {
            effect: pending.effect,
            current: self.currentness(),
        })
    }

    fn adopt_manifest(&mut self, bytes: &[u8]) -> Result<(), CacheOwnerErrorV1> {
        let (generation, disk, negatives) = decode_manifest(bytes, self.limits)?;
        self.generation = generation;
        self.manifest_digest = ObjectDigest::from_bytes(Sha256::digest(bytes).into());
        self.disk = disk;
        self.negatives = negatives;
        self.pin_index.clear();
        self.disk_bytes = 0;
        self.pinned_bytes = 0;
        self.recover_and_verify()
    }
}

fn reject_legacy_object_root() -> Result<(), CacheOwnerErrorV1> {
    reject_legacy_object_root_at(Path::new(LEGACY_CACHE_ROOT))
}

fn reject_legacy_object_root_at(legacy: &Path) -> Result<(), CacheOwnerErrorV1> {
    match std::fs::symlink_metadata(legacy) {
        Ok(_) => return Err(CacheOwnerErrorV1::RootChanged),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
}

#[cfg(test)]
mod legacy_path_tests {
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn old_parent_name_fails_closed() {
        let directory = tempfile::tempdir().expect("private legacy fixture");
        let old = directory.path().join("cache-residency");
        assert!(reject_legacy_object_root_at(&old).is_ok());

        std::fs::create_dir(&old).expect("empty old parent");
        assert!(matches!(
            reject_legacy_object_root_at(&old),
            Err(CacheOwnerErrorV1::RootChanged)
        ));
    }

    #[test]
    fn old_alias_fails_closed() {
        let directory = tempfile::tempdir().expect("private legacy fixture");
        let old = directory.path().join("cache-residency");
        symlink(directory.path(), &old).expect("old path alias");
        assert!(matches!(
            reject_legacy_object_root_at(&old),
            Err(CacheOwnerErrorV1::RootChanged)
        ));
    }
}

fn protected_now() -> Result<u64, CacheOwnerErrorV1> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CacheOwnerErrorV1::InvalidTime)?
        .as_secs();
    validate_now(now)?;
    Ok(now)
}

pub(crate) fn cache_lifecycle_availability_effect_v1(
    descriptor: &ObjectDescriptor,
    current: CacheOwnerCurrentnessV1,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.cache.lifecycle-availability.v1\0")
            .chain_update(descriptor.digest().as_bytes())
            .chain_update(descriptor.encoded_size().to_be_bytes())
            .chain_update(current.generation.to_be_bytes())
            .chain_update(current.digest.as_bytes())
            .finalize()
            .into(),
    )
}

pub(crate) fn cache_owner_effect_commitment_v1(
    kind: &[u8],
    subject: &[u8],
    current: CacheOwnerCurrentnessV1,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.cache.owner-effect.v1\0")
            .chain_update((kind.len() as u16).to_be_bytes())
            .chain_update(kind)
            .chain_update((subject.len() as u16).to_be_bytes())
            .chain_update(subject)
            .chain_update(current.generation.to_be_bytes())
            .chain_update(current.digest.as_bytes())
            .finalize()
            .into(),
    )
}

fn encode_manifest(
    generation: u64,
    disk: &BTreeMap<ObjectKey, DiskEntry>,
    negatives: &BTreeMap<AuthorizedLookupKey, NegativeEntry>,
) -> Result<Vec<u8>, CacheOwnerErrorV1> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MANIFEST_MAGIC);
    bytes.extend_from_slice(&MANIFEST_VERSION.to_be_bytes());
    bytes.extend_from_slice(&generation.to_be_bytes());
    put_u32(&mut bytes, disk.len())?;
    for (key, entry) in disk {
        bytes.extend_from_slice(key.partition.as_bytes());
        put_descriptor(&mut bytes, &key.descriptor)?;
        put_string(&mut bytes, &entry.file_name)?;
        put_string(&mut bytes, entry.staging_name.as_deref().unwrap_or(""))?;
        put_string(&mut bytes, entry.deleting_name.as_deref().unwrap_or(""))?;
        bytes.extend_from_slice(&entry.bytes.to_be_bytes());
        bytes.extend_from_slice(&entry.device.to_be_bytes());
        bytes.extend_from_slice(&entry.inode.to_be_bytes());
        bytes.extend_from_slice(&entry.verity);
        bytes.extend_from_slice(entry.canonical_name.as_bytes());
        bytes.extend_from_slice(entry.root_custody.as_bytes());
        bytes.extend_from_slice(&entry.last_used.to_be_bytes());
        put_u32(&mut bytes, entry.pins.len())?;
        for pin in &entry.pins {
            bytes.extend_from_slice(pin.as_bytes());
        }
    }
    put_u32(&mut bytes, negatives.len())?;
    for (key, entry) in negatives {
        bytes.extend_from_slice(key.digest().as_bytes());
        bytes.extend_from_slice(&entry.valid_until.to_be_bytes());
        bytes.extend_from_slice(&entry.last_used.to_be_bytes());
    }
    let checksum: [u8; 32] = Sha256::digest(&bytes).into();
    bytes.extend_from_slice(&checksum);
    if bytes.len() > MAXIMUM_MANIFEST_BYTES {
        return Err(CacheOwnerErrorV1::CapacityExhausted);
    }
    Ok(bytes)
}

fn decode_manifest(
    bytes: &[u8],
    limits: CacheOwnerLimitsV1,
) -> Result<
    (
        u64,
        BTreeMap<ObjectKey, DiskEntry>,
        BTreeMap<AuthorizedLookupKey, NegativeEntry>,
    ),
    CacheOwnerErrorV1,
> {
    if bytes.len() < 56 || bytes.len() > MAXIMUM_MANIFEST_BYTES {
        return Err(CacheOwnerErrorV1::InvalidManifest);
    }
    let (payload, checksum) = bytes.split_at(bytes.len() - 32);
    if Sha256::digest(payload).as_slice() != checksum {
        return Err(CacheOwnerErrorV1::InvalidManifest);
    }
    let mut cursor = Cursor::new(payload);
    if cursor.take(8)? != MANIFEST_MAGIC || cursor.u32()? != MANIFEST_VERSION {
        return Err(CacheOwnerErrorV1::InvalidManifest);
    }
    let generation = cursor.u64()?;
    if generation == 0 {
        return Err(CacheOwnerErrorV1::InvalidManifest);
    }
    let count = cursor.u32()? as usize;
    if count > limits.maximum_positive_entries {
        return Err(CacheOwnerErrorV1::CapacityExhausted);
    }
    let mut disk = BTreeMap::new();
    for _ in 0..count {
        let key = ObjectKey {
            partition: ObjectDigest::from_bytes(cursor.array()?),
            descriptor: cursor.descriptor()?,
        };
        let file_name = cursor.string()?;
        validate_basename(&file_name)?;
        let staging_name = match cursor.string()? {
            name if name.is_empty() => None,
            name => {
                validate_basename(&name)?;
                Some(name)
            }
        };
        let deleting_name = match cursor.string()? {
            name if name.is_empty() => None,
            name => {
                validate_basename(&name)?;
                Some(name)
            }
        };
        if staging_name.is_some() && deleting_name.is_some() {
            return Err(CacheOwnerErrorV1::InvalidManifest);
        }
        let bytes = cursor.u64()?;
        let device = cursor.u64()?;
        let inode = cursor.u64()?;
        let verity = cursor.array()?;
        let canonical_name = ObjectDigest::from_bytes(cursor.array()?);
        let root_custody = ObjectDigest::from_bytes(cursor.array()?);
        let last_used = cursor.u64()?;
        let pin_count = cursor.u32()? as usize;
        if bytes == 0
            || device == 0
            || inode == 0
            || verity == [0; 32]
            || canonical_name.as_bytes() == &[0; 32]
            || root_custody.as_bytes() == &[0; 32]
            || last_used == 0
            || pin_count > limits.maximum_pins
        {
            return Err(CacheOwnerErrorV1::InvalidManifest);
        }
        let mut pins = BTreeSet::new();
        for _ in 0..pin_count {
            if !pins.insert(CacheOwnerPinIdV1::from_bytes(cursor.array()?)?) {
                return Err(CacheOwnerErrorV1::InvalidManifest);
            }
        }
        if disk
            .insert(
                key,
                DiskEntry {
                    file_name,
                    staging_name,
                    deleting_name,
                    bytes,
                    device,
                    inode,
                    verity,
                    canonical_name,
                    root_custody,
                    last_used,
                    pins,
                },
            )
            .is_some()
        {
            return Err(CacheOwnerErrorV1::InvalidManifest);
        }
    }
    let negative_count = cursor.u32()? as usize;
    if negative_count > limits.maximum_negative_entries {
        return Err(CacheOwnerErrorV1::CapacityExhausted);
    }
    let mut negatives = BTreeMap::new();
    for _ in 0..negative_count {
        let key = AuthorizedLookupKey::from_digest(ObjectDigest::from_bytes(cursor.array()?))
            .map_err(|_| CacheOwnerErrorV1::InvalidManifest)?;
        let entry = NegativeEntry {
            valid_until: cursor.u64()?,
            last_used: cursor.u64()?,
        };
        if entry.valid_until == 0 || entry.last_used == 0 || negatives.insert(key, entry).is_some()
        {
            return Err(CacheOwnerErrorV1::InvalidManifest);
        }
    }
    if !cursor.remaining().is_empty() {
        return Err(CacheOwnerErrorV1::InvalidManifest);
    }
    Ok((generation, disk, negatives))
}

fn decode_generation(bytes: &[u8]) -> Result<u64, CacheOwnerErrorV1> {
    if bytes.len() < 20
        || &bytes[..8] != MANIFEST_MAGIC
        || bytes[8..12] != MANIFEST_VERSION.to_be_bytes()
    {
        return Err(CacheOwnerErrorV1::InvalidManifest);
    }
    Ok(u64::from_be_bytes(
        bytes[12..20]
            .try_into()
            .map_err(|_| CacheOwnerErrorV1::InvalidManifest)?,
    ))
}
fn put_u32(bytes: &mut Vec<u8>, value: usize) -> Result<(), CacheOwnerErrorV1> {
    bytes.extend_from_slice(
        &u32::try_from(value)
            .map_err(|_| CacheOwnerErrorV1::CapacityExhausted)?
            .to_be_bytes(),
    );
    Ok(())
}
fn put_string(bytes: &mut Vec<u8>, value: &str) -> Result<(), CacheOwnerErrorV1> {
    let length = u16::try_from(value.len()).map_err(|_| CacheOwnerErrorV1::InvalidManifest)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}
fn put_descriptor(
    bytes: &mut Vec<u8>,
    descriptor: &ObjectDescriptor,
) -> Result<(), CacheOwnerErrorV1> {
    put_string(bytes, descriptor.media_type().as_str())?;
    bytes.extend_from_slice(descriptor.digest().as_bytes());
    bytes.extend_from_slice(&descriptor.encoded_size().to_be_bytes());
    Ok(())
}
fn object_file_name(key: &ObjectKey) -> String {
    format!(
        "{}-{}",
        hex(key.partition.as_bytes()),
        hex(key.descriptor.digest().as_bytes())
    )
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(DIGITS[(byte >> 4) as usize] as char);
        value.push(DIGITS[(byte & 0xf) as usize] as char);
    }
    value
}

fn orphan_transaction(name: &str) -> Result<ObjectDigest, CacheOwnerErrorV1> {
    let encoded = if let Some(staging) = name
        .strip_prefix(".admit-")
        .and_then(|value| value.strip_suffix(".tmp"))
    {
        staging.rsplit_once('-').map(|(_, digest)| digest)
    } else {
        name.strip_prefix(".orphan-")
            .and_then(|value| value.split_once('-').map(|(digest, _)| digest))
    }
    .ok_or(CacheOwnerErrorV1::UnsafeName)?;
    if encoded.len() != 64 {
        return Err(CacheOwnerErrorV1::UnsafeName);
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_value(pair[0]).ok_or(CacheOwnerErrorV1::UnsafeName)?;
        let low = hex_value(pair[1]).ok_or(CacheOwnerErrorV1::UnsafeName)?;
        bytes[index] = (high << 4) | low;
    }
    let digest = ObjectDigest::from_bytes(bytes);
    if digest.as_bytes() == &[0; 32] {
        return Err(CacheOwnerErrorV1::UnsafeName);
    }
    Ok(digest)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}
fn validate_now(now: u64) -> Result<(), CacheOwnerErrorV1> {
    if now == 0 {
        Err(CacheOwnerErrorV1::InvalidTime)
    } else {
        Ok(())
    }
}
fn read_bounded_at(
    root: &OwnedFd,
    name: &str,
    maximum: usize,
) -> Result<Vec<u8>, CacheOwnerErrorV1> {
    validate_basename(name)?;
    let descriptor = rustix::fs::openat(
        root,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let stat = rustix::fs::fstat(&descriptor)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile || stat.st_nlink != 1 {
        return Err(CacheOwnerErrorV1::InvalidManifest);
    }
    let mut file = File::from(descriptor);
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(CacheOwnerErrorV1::InvalidManifest);
    }
    Ok(bytes)
}

fn remove_exact_temporary(
    root: &OwnedFd,
    name: &str,
    expected: &[u8],
) -> Result<(), CacheOwnerErrorV1> {
    match rustix::fs::statat(root, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => {
            if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                || stat.st_uid != rustix::process::geteuid().as_raw()
                || stat.st_nlink != 1
                || read_bounded_at(root, name, MAXIMUM_MANIFEST_BYTES)? != expected
            {
                return Err(CacheOwnerErrorV1::ForeignTemporary);
            }
            rustix::fs::unlinkat(root, name, AtFlags::empty())?;
            rustix::fs::fsync(root)?;
            Ok(())
        }
        Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn validate_basename(name: &str) -> Result<(), CacheOwnerErrorV1> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 255
        || bytes == b"."
        || bytes == b".."
        || bytes.contains(&b'/')
        || bytes.contains(&0)
        || Path::new(name).is_absolute()
        || Path::new(name).components().count() != 1
    {
        return Err(CacheOwnerErrorV1::UnsafeName);
    }
    Ok(())
}

fn inspect_root(root: &OwnedFd) -> Result<RootIdentity, CacheOwnerErrorV1> {
    let stat = rustix::fs::fstat(root)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o700
    {
        return Err(CacheOwnerErrorV1::RootChanged);
    }
    Ok(RootIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
        uid: stat.st_uid,
        mode: stat.st_mode & 0o7777,
    })
}

fn open_owner_lock(root: &OwnedFd) -> Result<OwnedFd, CacheOwnerErrorV1> {
    let create_flags =
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let (lock, created) =
        match rustix::fs::openat(root, ".owner.lock", create_flags, Mode::RUSR | Mode::WUSR) {
            Ok(lock) => (lock, true),
            Err(rustix::io::Errno::EXIST) => (
                rustix::fs::openat(
                    root,
                    ".owner.lock",
                    OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )?,
                false,
            ),
            Err(error) => return Err(error.into()),
        };

    rustix::fs::flock(&lock, FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| CacheOwnerErrorV1::OwnerBusy)?;
    if created {
        // Normalize a fresh lock independently of the caller's umask.
        rustix::fs::fchmod(&lock, Mode::RUSR | Mode::WUSR)?;
    }
    let stat = rustix::fs::fstat(&lock)?;
    let named = rustix::fs::statat(root, ".owner.lock", AtFlags::SYMLINK_NOFOLLOW)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
        || named.st_dev != stat.st_dev
        || named.st_ino != stat.st_ino
        || named.st_mode != stat.st_mode
    {
        return Err(CacheOwnerErrorV1::RootChanged);
    }
    rustix::fs::fsync(&lock)?;
    rustix::fs::fsync(root)?;
    Ok(lock)
}

fn inspect_lock(root: &OwnedFd, lock: &OwnedFd) -> Result<LockIdentity, CacheOwnerErrorV1> {
    let stat = rustix::fs::fstat(lock)?;
    let named = rustix::fs::statat(root, ".owner.lock", AtFlags::SYMLINK_NOFOLLOW)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
        || named.st_dev != stat.st_dev
        || named.st_ino != stat.st_ino
        || named.st_mode != stat.st_mode
    {
        return Err(CacheOwnerErrorV1::RootChanged);
    }
    Ok(LockIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
    })
}

fn ensure_held_lock(root: &OwnedFd, lock: &OwnedFd) -> Result<(), CacheOwnerErrorV1> {
    inspect_lock(root, lock)?;
    rustix::fs::flock(lock, FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| CacheOwnerErrorV1::OwnerLockNotHeld)?;
    let independent = rustix::fs::openat(
        root,
        ".owner.lock",
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    match rustix::fs::flock(&independent, FlockOperation::NonBlockingLockExclusive) {
        Err(rustix::io::Errno::WOULDBLOCK) => Ok(()),
        Ok(()) => Err(CacheOwnerErrorV1::OwnerLockNotHeld),
        Err(error) => Err(error.into()),
    }
}

fn inspect_manifest_identity(
    root: &OwnedFd,
) -> Result<Option<ManifestIdentity>, CacheOwnerErrorV1> {
    let named = match rustix::fs::statat(root, MANIFEST_NAME, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(named) => named,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if FileType::from_raw_mode(named.st_mode) != FileType::RegularFile
        || named.st_uid != rustix::process::geteuid().as_raw()
        || named.st_mode & 0o7777 != 0o600
        || named.st_nlink != 1
    {
        return Err(CacheOwnerErrorV1::InvalidManifest);
    }
    Ok(Some(ManifestIdentity {
        device: named.st_dev,
        inode: named.st_ino,
    }))
}

fn replayed_manifest_head(
    root: &OwnedFd,
    limits: CacheOwnerLimitsV1,
) -> Result<CacheOwnerCurrentnessV1, CacheOwnerErrorV1> {
    let bytes = match read_bounded_at(root, MANIFEST_NAME, MAXIMUM_MANIFEST_BYTES) {
        Ok(bytes) => bytes,
        Err(CacheOwnerErrorV1::Rustix(rustix::io::Errno::NOENT)) => {
            return Ok(CacheOwnerCurrentnessV1 {
                generation: 0,
                digest: ObjectDigest::from_bytes([0; 32]),
            });
        }
        Err(error) => return Err(error),
    };
    let (generation, disk, _) = decode_manifest(&bytes, limits)?;
    if disk
        .values()
        .any(|entry| entry.staging_name.is_some() || entry.deleting_name.is_some())
    {
        return Err(CacheOwnerErrorV1::UnsafeRelease);
    }
    Ok(CacheOwnerCurrentnessV1 {
        generation,
        digest: ObjectDigest::from_bytes(Sha256::digest(&bytes).into()),
    })
}

fn verify_bytes(descriptor: &ObjectDescriptor, bytes: &[u8]) -> Result<(), CacheOwnerErrorV1> {
    if bytes.len() as u64 != descriptor.encoded_size()
        || Sha256::digest(bytes).as_slice() != descriptor.digest().as_bytes()
    {
        return Err(CacheOwnerErrorV1::IntegrityFailure);
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
#[error("materialized bytes differ from the protected admission descriptor")]
/// Reports a streaming mismatch against the protected admission descriptor.
struct DescriptorVerificationError;

struct DescriptorVerifier<'descriptor> {
    descriptor: &'descriptor ObjectDescriptor,
    bytes: u64,
    hasher: Sha256,
}

impl<'descriptor> DescriptorVerifier<'descriptor> {
    fn new(descriptor: &'descriptor ObjectDescriptor) -> Self {
        Self {
            descriptor,
            bytes: 0,
            hasher: Sha256::new(),
        }
    }
}

impl MaterializationCallbacks for DescriptorVerifier<'_> {
    type Error = DescriptorVerificationError;

    fn checkpoint(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn verify_chunk(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .ok_or(DescriptorVerificationError)?;
        if self.bytes > self.descriptor.encoded_size() {
            return Err(DescriptorVerificationError);
        }
        self.hasher.update(bytes);
        Ok(())
    }

    fn finish_verification(&mut self) -> Result<(), Self::Error> {
        if self.bytes != self.descriptor.encoded_size()
            || self.hasher.clone().finalize().as_slice() != self.descriptor.digest().as_bytes()
        {
            return Err(DescriptorVerificationError);
        }
        Ok(())
    }
}

struct Cursor<'a> {
    remaining: &'a [u8],
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }
    fn remaining(&self) -> &'a [u8] {
        self.remaining
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], CacheOwnerErrorV1> {
        let (head, tail) = self
            .remaining
            .split_at_checked(length)
            .ok_or(CacheOwnerErrorV1::InvalidManifest)?;
        self.remaining = tail;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], CacheOwnerErrorV1> {
        self.take(N)?
            .try_into()
            .map_err(|_| CacheOwnerErrorV1::InvalidManifest)
    }
    fn u16(&mut self) -> Result<u16, CacheOwnerErrorV1> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, CacheOwnerErrorV1> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, CacheOwnerErrorV1> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn string(&mut self) -> Result<String, CacheOwnerErrorV1> {
        let length = self.u16()? as usize;
        let value = std::str::from_utf8(self.take(length)?)
            .map_err(|_| CacheOwnerErrorV1::InvalidManifest)?;
        Ok(value.to_owned())
    }
    fn descriptor(&mut self) -> Result<ObjectDescriptor, CacheOwnerErrorV1> {
        let media =
            MediaType::new(self.string()?).map_err(|_| CacheOwnerErrorV1::InvalidManifest)?;
        Ok(ObjectDescriptor::new(
            media,
            ObjectDigest::from_bytes(self.array()?),
            self.u64()?,
        ))
    }
}

/// Reports bounded cache ownership, durability, or integrity failure.
#[derive(Debug, thiserror::Error)]
pub enum CacheOwnerErrorV1 {
    /// Protected read authority is stale, expired, or does not bind this object.
    #[error("cache owner rejected protected read authority: {0}")]
    ReadAuthority(#[from] super::ReadAuthorityError),
    /// A failed effect or ambiguous manifest requires exact recovery or owner reopen.
    #[error("cache owner is fenced until its durable state is recovered")]
    Fenced,
    /// Volatile or unresolved state cannot be replayed after releasing the lock.
    #[error("cache owner has non-replayable state and cannot release ownership")]
    UnsafeRelease,
    /// One or more hard owner bounds are zero or inconsistent.
    #[error("invalid cache owner limits")]
    InvalidLimits,
    /// Trusted clock input is zero or an expiry is not in the future.
    #[error("invalid cache owner time")]
    InvalidTime,
    /// Immutable bytes do not match their exact descriptor.
    #[error("cache object integrity validation failed")]
    IntegrityFailure,
    /// Memory, disk, entry, or pin budget is exhausted.
    #[error("cache owner capacity exhausted")]
    CapacityExhausted,
    /// Exact allocation was refused.
    #[error("cache owner allocation refused")]
    AllocationRefused,
    /// Pin identity is zero, duplicate, absent, or inconsistent.
    #[error("invalid cache owner pin")]
    InvalidPin,
    /// The exact object is not durably resident.
    #[error("cache object is not resident")]
    NotResident,
    /// Durable manifest bytes are malformed or corrupt.
    #[error("invalid cache owner manifest")]
    InvalidManifest,
    /// Recovered files, pins, or accounting differ from the durable manifest.
    #[error("cache owner recovery inventory mismatch")]
    RecoveryMismatch,
    /// Effect-time currentness differs from fixed-root readback.
    #[error("cache owner currentness is stale")]
    Stale,
    /// The durable generation space is exhausted.
    #[error("cache owner generation exhausted")]
    GenerationExhausted,
    /// A persisted name was absolute, traversing, or not one ordinary basename.
    #[error("unsafe cache owner basename")]
    UnsafeName,
    /// A deterministic retry temporary did not match the exact expected inode.
    #[error("cache owner retry temporary is foreign")]
    ForeignTemporary,
    /// The retained protected root changed identity or protection metadata.
    #[error("cache owner protected root changed")]
    RootChanged,
    /// Another independently opened owner already holds the protected head lock.
    #[error("cache owner protected head is already claimed")]
    OwnerBusy,
    /// The fixed lock is not exclusively held by this owner description.
    #[error("cache owner fixed lock is not held by this descriptor")]
    OwnerLockNotHeld,
    /// Exact manifest replacement requires reopen/readback recovery.
    #[error("cache owner manifest replacement outcome is unknown")]
    OutcomeUnknown(CacheOwnerOutcomeUnknownV1),
    /// A protected staged-admission manifest owns exact rename recovery.
    #[error("cache admission rename outcome is unknown and retained by staged currentness")]
    AdmissionOutcomeUnknown {
        /// Exact durable staged manifest that must be reopened and recovered.
        staging_current: CacheOwnerCurrentnessV1,
    },
    /// A protected deleting manifest owns exact unlink recovery.
    #[error("cache eviction unlink outcome is unknown and retained by deleting currentness")]
    EvictionOutcomeUnknown {
        /// Exact durable deleting manifest that must be reopened and recovered.
        deleting_current: CacheOwnerCurrentnessV1,
    },
    /// Linux descriptor-relative operation failed.
    #[error("cache owner descriptor operation failed: {0}")]
    Rustix(#[from] rustix::io::Errno),
    /// Protected fs-verity publication-root admission failed.
    #[error("cache owner fs-verity root failed: {0}")]
    PublicationRoot(#[from] aos_sandbox_linux::immutable_file::PublicationRootError),
    /// Immutable mapping validation failed.
    #[error("cache owner immutable mapping failed: {0}")]
    ImmutableMapping(#[from] aos_sandbox_linux::immutable_file::ImmutableFileError),
    /// Beneath-root adoption failed.
    #[error("cache owner beneath-root adoption failed: {0}")]
    BeneathRoot(#[from] aos_sandbox_linux::Error),
    /// Publication basename validation failed.
    #[error("cache owner publication name failed: {0}")]
    PublicationName(#[from] aos_sandbox_linux::immutable_file::InvalidPublicationName),
    /// Fresh-inode fs-verity materialization failed and retained its recovery name.
    #[error("cache owner immutable materialization failed; exact private name is retained")]
    Materialization,
    /// Fresh materialization failed after creating an exactly identified inode.
    #[error("cache owner immutable materialization retained an exact private inode")]
    MaterializationRetained(CacheMaterializationOutcomeV1),
    /// Fixed-root filesystem operation failed.
    #[error("cache owner filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt as _;

    use super::{
        CacheOwnerErrorV1, CacheOwnerLimitsV1, MANIFEST_NAME, encode_manifest, ensure_held_lock,
        inspect_lock, inspect_manifest_identity, open_owner_lock, replayed_manifest_head,
    };
    use rustix::fs::{FlockOperation, Mode, OFlags};

    fn fixture_limits() -> CacheOwnerLimitsV1 {
        CacheOwnerLimitsV1 {
            maximum_memory_bytes: 1024,
            maximum_disk_bytes: 1024,
            disk_low_water_bytes: 0,
            maximum_positive_entries: 4,
            maximum_negative_entries: 4,
            maximum_pins: 4,
            maximum_pinned_bytes: 1024,
        }
    }

    #[test]
    fn held_lock_rejects_replaced_fixed_name() {
        let directory = tempfile::tempdir().expect("temporary owner root");
        let root = rustix::fs::open(
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open temporary owner root");
        let lock = open_owner_lock(&root).expect("hold owner lock");
        let original = inspect_lock(&root, &lock).expect("current held lock");

        std::fs::remove_file(directory.path().join(".owner.lock"))
            .expect("replace fixed lock name");
        std::fs::write(directory.path().join(".owner.lock"), [])
            .expect("install different lock inode");

        assert!(matches!(
            inspect_lock(&root, &lock),
            Err(CacheOwnerErrorV1::RootChanged)
        ));
        assert_ne!(original.inode, 0);
    }

    #[test]
    fn borrowed_lock_rejects_competing_open_file_description() {
        let directory = tempfile::tempdir().expect("temporary owner root");
        let root = rustix::fs::open(
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open temporary owner root");
        let lock = open_owner_lock(&root).expect("hold owner lock");
        ensure_held_lock(&root, &lock).expect("original description holds the flock");

        let competing = rustix::fs::openat(
            &root,
            ".owner.lock",
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("independent lock description");
        rustix::fs::flock(&lock, FlockOperation::Unlock).expect("release original flock");
        rustix::fs::flock(&competing, FlockOperation::NonBlockingLockExclusive)
            .expect("competing description holds flock");

        assert!(matches!(
            ensure_held_lock(&root, &lock),
            Err(CacheOwnerErrorV1::OwnerLockNotHeld)
        ));
    }

    #[test]
    fn borrowed_manifest_head_replays_and_rejects_malformed_replacement() {
        let directory = tempfile::tempdir().expect("temporary owner root");
        let root = rustix::fs::open(
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open temporary owner root");
        let limits = fixture_limits();
        assert_eq!(
            replayed_manifest_head(&root, limits)
                .expect("absent genesis manifest")
                .generation(),
            0
        );

        let manifest =
            encode_manifest(1, &BTreeMap::new(), &BTreeMap::new()).expect("valid empty manifest");
        std::fs::write(directory.path().join(MANIFEST_NAME), manifest)
            .expect("install durable manifest");
        let original = replayed_manifest_head(&root, limits).expect("replayed manifest");
        assert_eq!(original.generation(), 1);

        let replacement =
            encode_manifest(2, &BTreeMap::new(), &BTreeMap::new()).expect("replacement manifest");
        std::fs::write(directory.path().join(MANIFEST_NAME), replacement)
            .expect("replace durable manifest");
        let changed = replayed_manifest_head(&root, limits).expect("replayed replacement");
        assert_ne!(changed, original);
        assert_eq!(changed.generation(), 2);

        std::fs::write(directory.path().join(MANIFEST_NAME), b"not-a-manifest")
            .expect("replace manifest bytes");
        assert!(matches!(
            replayed_manifest_head(&root, limits),
            Err(CacheOwnerErrorV1::InvalidManifest)
        ));
    }

    #[test]
    fn named_manifest_identity_rejects_identical_byte_replacement() {
        let directory = tempfile::tempdir().expect("temporary owner root");
        let root = rustix::fs::open(
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open temporary owner root");
        let manifest =
            encode_manifest(1, &BTreeMap::new(), &BTreeMap::new()).expect("valid empty manifest");
        let named = directory.path().join(MANIFEST_NAME);
        std::fs::write(&named, &manifest).expect("install manifest");
        std::fs::set_permissions(&named, std::fs::Permissions::from_mode(0o600))
            .expect("private manifest");
        let identity = inspect_manifest_identity(&root).expect("named manifest");
        let head = replayed_manifest_head(&root, fixture_limits()).expect("durable manifest");

        let retained = directory.path().join("owner-state.retained");
        std::fs::rename(&named, &retained).expect("retain old manifest inode");
        std::fs::copy(&retained, &named).expect("install identical replacement bytes");

        assert_eq!(
            replayed_manifest_head(&root, fixture_limits()).expect("same head"),
            head
        );
        assert_ne!(
            inspect_manifest_identity(&root).expect("new named inode"),
            identity
        );
    }
}
