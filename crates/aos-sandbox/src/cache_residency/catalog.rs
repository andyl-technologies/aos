//! Immutable residency catalog and authorization-scoped lookup memoization.
//!
//! A canonical name is not visibility.  Only a committed catalog entry can be
//! considered for a hit, and even that hit is returned only through a current
//! independently authorized lookup.  Negative observations and in-flight
//! coalescing use the same authority-scoped key as positive observations.

use std::collections::{BTreeMap, VecDeque};

use aos_sandbox_core::{ObjectDescriptor, ObjectDigest, OperationId};

use super::accounting::CacheReservationId;
use super::domain::{
    AuthorizedLookupKey, CacheIsolationPolicyV1, PhysicalPartitionId, validate_object_descriptor,
};

/// Identifies an immutable publisher-verified seal.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ImmutableSealV1 {
    /// Closed seal implementation profile.
    pub profile: SealProfileV1,
    /// Measurement of the exact sealed destination inode or snapshot.
    pub measurement: ObjectDigest,
}

impl ImmutableSealV1 {
    /// Validates a non-sentinel immutable seal.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError::InvalidEntry`] for an absent measurement.
    pub fn validate(self) -> Result<Self, CatalogError> {
        if self.measurement.as_bytes() == &[0; 32] {
            return Err(CatalogError::InvalidEntry);
        }
        Ok(self)
    }
}

/// Selects the closed immutable backing profile.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum SealProfileV1 {
    /// A fresh destination inode protected by fs-verity SHA-256.
    FsVeritySha256 = 1,
    /// An already-created, held, read-only ZFS snapshot GUID.
    ReadOnlyZfsSnapshot = 2,
}

/// Opaque identity of a backing object beneath a protected cache root.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BackingObjectIdentityV1([u8; 32]);

impl BackingObjectIdentityV1 {
    /// Constructs a nonzero identity from protected root-relative observation.
    ///
    /// The bytes are an opaque digest of root custody and stable filesystem
    /// identity. They are not a path, file descriptor, device number, or inode
    /// scalar usable as authority.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError::InvalidEntry`] for the zero sentinel.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, CatalogError> {
        if bytes == [0; 32] {
            return Err(CatalogError::InvalidEntry);
        }
        Ok(Self(bytes))
    }

    /// Borrows the opaque identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Describes the durable reachability state of one immutable object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CatalogPresenceV1 {
    /// The object is committed and may be considered by authorized readers.
    Committed = 1,
    /// The canonical name has moved into a private deleting namespace.
    Deleting = 2,
    /// Validation failed and the backing object is isolated from readers.
    Quarantined = 3,
    /// Physical reclamation was proved; only the durable tombstone remains.
    Evicted = 4,
}

/// Stores one immutable physical-residency catalog entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogEntryV1 {
    /// Physical cache partition containing the object.
    pub partition: PhysicalPartitionId,
    /// Complete immutable portable object identity.
    pub descriptor: ObjectDescriptor,
    /// Independently measured immutable backing seal.
    pub seal: ImmutableSealV1,
    /// Opaque protected-root-relative backing identity.
    pub backing: BackingObjectIdentityV1,
    /// Exact allocated bytes independently observed for this backing.
    pub allocated_bytes: u64,
    /// Exact protected root custody generation digest.
    pub root_custody: ObjectDigest,
    /// Exact protected root generation observed at publication.
    pub root_generation: u64,
    /// Deterministic canonical-name commitment within the protected root.
    pub canonical_name: ObjectDigest,
    /// Publication operation that committed the canonical entry.
    pub publication: OperationId,
    /// Capacity reservation converted into this residency.
    pub reservation: CacheReservationId,
    /// Current catalog reachability state.
    pub presence: CatalogPresenceV1,
    /// Monotone catalog generation.
    pub generation: u64,
    /// Digest of the preceding generation, absent only at generation one.
    pub predecessor: Option<ObjectDigest>,
    /// Digest of this complete entry.
    pub digest: ObjectDigest,
}

impl CatalogEntryV1 {
    /// Validates closed catalog invariants and the derived entry digest.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError::InvalidEntry`] for sentinel, chain, or digest
    /// inconsistencies.
    pub fn validate(self) -> Result<Self, CatalogError> {
        self.seal.validate()?;
        if validate_object_descriptor(&self.descriptor).is_err()
            || self.allocated_bytes == 0
            || self.root_custody.as_bytes() == &[0; 32]
            || self.root_generation == 0
            || self.canonical_name != canonical_name_digest(self.partition, &self.descriptor)
            || self.publication.as_bytes() == &[0; 16]
            || self.generation == 0
            || (self.generation == 1) != self.predecessor.is_none()
            || self.digest != catalog_digest(&self)
        {
            return Err(CatalogError::InvalidEntry);
        }
        Ok(self)
    }

    /// Constructs a first committed generation after immutable publication.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError::InvalidEntry`] for malformed facts.
    pub fn committed(
        partition: PhysicalPartitionId,
        descriptor: ObjectDescriptor,
        seal: ImmutableSealV1,
        backing: BackingObjectIdentityV1,
        allocated_bytes: u64,
        root_custody: ObjectDigest,
        root_generation: u64,
        publication: OperationId,
        reservation: CacheReservationId,
    ) -> Result<Self, CatalogError> {
        let canonical_name = canonical_name_digest(partition, &descriptor);
        let mut entry = Self {
            partition,
            descriptor,
            seal,
            backing,
            allocated_bytes,
            root_custody,
            root_generation,
            canonical_name,
            publication,
            reservation,
            presence: CatalogPresenceV1::Committed,
            generation: 1,
            predecessor: None,
            digest: ObjectDigest::from_bytes([0; 32]),
        };
        entry.digest = catalog_digest(&entry);
        entry.validate()
    }

    /// Produces the checked immediate reachability successor.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError`] if the transition is illegal or the generation
    /// counter is exhausted.
    pub fn transition(&self, presence: CatalogPresenceV1) -> Result<Self, CatalogError> {
        let legal = matches!(
            (self.presence, presence),
            (CatalogPresenceV1::Committed, CatalogPresenceV1::Deleting)
                | (CatalogPresenceV1::Committed, CatalogPresenceV1::Quarantined)
                | (CatalogPresenceV1::Deleting, CatalogPresenceV1::Committed)
                | (CatalogPresenceV1::Deleting, CatalogPresenceV1::Quarantined)
                | (CatalogPresenceV1::Deleting, CatalogPresenceV1::Evicted)
                | (CatalogPresenceV1::Quarantined, CatalogPresenceV1::Deleting)
                | (CatalogPresenceV1::Quarantined, CatalogPresenceV1::Committed)
        );
        if !legal {
            return Err(CatalogError::InvalidTransition);
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(CatalogError::GenerationExhausted)?;
        let mut next = Self {
            partition: self.partition,
            descriptor: self.descriptor.clone(),
            seal: self.seal,
            backing: self.backing,
            allocated_bytes: self.allocated_bytes,
            root_custody: self.root_custody,
            root_generation: self.root_generation,
            canonical_name: self.canonical_name,
            publication: self.publication,
            reservation: self.reservation,
            presence,
            generation,
            predecessor: Some(self.digest),
            digest: ObjectDigest::from_bytes([0; 32]),
        };
        next.digest = catalog_digest(&next);
        Ok(next)
    }
}

/// Bounds lookup retention, coalescing, and caller-visible backpressure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LookupMemoLimitsV1 {
    /// Maximum retained positive and negative entries together.
    pub maximum_entries: usize,
    /// Maximum simultaneous coalesced misses.
    pub maximum_in_flight: usize,
    /// Maximum aggregate byte permits retained by in-flight lookups.
    pub maximum_in_flight_bytes: u64,
    /// Maximum waiters admitted for one exact lookup.
    pub maximum_waiters_per_lookup: u32,
    /// Maximum generation span for a negative result.
    pub maximum_negative_span: u64,
}

impl LookupMemoLimitsV1 {
    /// Validates bounded memoization limits.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError::InvalidLimits`] for zero or excessive limits.
    pub fn validate(self) -> Result<Self, CatalogError> {
        if self.maximum_entries == 0
            || self.maximum_entries > 1_000_000
            || self.maximum_in_flight == 0
            || self.maximum_in_flight > 65_536
            || self.maximum_in_flight_bytes == 0
            || self.maximum_waiters_per_lookup == 0
            || self.maximum_waiters_per_lookup > 65_536
            || self.maximum_negative_span == 0
        {
            return Err(CatalogError::InvalidLimits);
        }
        Ok(self)
    }
}

/// Records one authority-scoped lookup result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LookupMemoValueV1 {
    /// An exact committed catalog digest was visible under this authority.
    Positive { catalog_digest: ObjectDigest },
    /// Absence was observed until the bounded catalog-generation horizon.
    Negative { valid_through_generation: u64 },
}

/// Reports whether a miss became the fetch leader or joined bounded work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoalescingOutcomeV1 {
    /// The caller owns the new fetch attempt.
    Leader,
    /// The caller joined the exact same authority-scoped lookup.
    Joined { waiter_ordinal: u32 },
}

/// Maintains bounded, authority-scoped lookup observations.
#[derive(Clone, Debug)]
pub struct LookupMemoV1 {
    limits: LookupMemoLimitsV1,
    entries: BTreeMap<AuthorizedLookupKey, LookupMemoValueV1>,
    order: VecDeque<AuthorizedLookupKey>,
    in_flight: BTreeMap<AuthorizedLookupKey, InFlightLookupV1>,
    in_flight_bytes: u64,
    coalescing_enabled: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InFlightLookupV1 {
    waiters: u32,
    reserved_bytes: u64,
}

impl LookupMemoV1 {
    /// Constructs an empty bounded lookup memo.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError::InvalidLimits`] for invalid limits.
    pub fn new(
        limits: LookupMemoLimitsV1,
        isolation: CacheIsolationPolicyV1,
    ) -> Result<Self, CatalogError> {
        let isolation = isolation
            .validate()
            .map_err(|_| CatalogError::InvalidLimits)?;
        Ok(Self {
            limits: limits.validate()?,
            entries: BTreeMap::new(),
            order: VecDeque::new(),
            in_flight: BTreeMap::new(),
            in_flight_bytes: 0,
            coalescing_enabled: isolation.fetch_coalescing,
        })
    }

    /// Reads a memo only when its retained generation remains current.
    #[must_use]
    pub fn get(
        &self,
        key: AuthorizedLookupKey,
        current_catalog_generation: u64,
    ) -> Option<LookupMemoValueV1> {
        match self.entries.get(&key).copied() {
            Some(LookupMemoValueV1::Negative {
                valid_through_generation,
            }) if current_catalog_generation > valid_through_generation => None,
            value => value,
        }
    }

    /// Begins or joins one bounded authority-scoped miss.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError::Backpressure`] when either the global in-flight
    /// bound or per-key waiter bound is exhausted.
    pub fn begin_miss(
        &mut self,
        key: AuthorizedLookupKey,
        reserved_bytes: u64,
    ) -> Result<CoalescingOutcomeV1, CatalogError> {
        if reserved_bytes == 0 {
            return Err(CatalogError::Backpressure);
        }
        let next_total = self
            .in_flight_bytes
            .checked_add(reserved_bytes)
            .ok_or(CatalogError::Backpressure)?;
        if next_total > self.limits.maximum_in_flight_bytes {
            return Err(CatalogError::Backpressure);
        }
        if let Some(in_flight) = self.in_flight.get_mut(&key) {
            if !self.coalescing_enabled {
                return Err(CatalogError::Backpressure);
            }
            if in_flight.waiters >= self.limits.maximum_waiters_per_lookup {
                return Err(CatalogError::Backpressure);
            }
            in_flight.waiters += 1;
            in_flight.reserved_bytes = in_flight
                .reserved_bytes
                .checked_add(reserved_bytes)
                .ok_or(CatalogError::Backpressure)?;
            self.in_flight_bytes = next_total;
            return Ok(CoalescingOutcomeV1::Joined {
                waiter_ordinal: in_flight.waiters,
            });
        }
        if self.in_flight.len() >= self.limits.maximum_in_flight {
            return Err(CatalogError::Backpressure);
        }
        self.in_flight.insert(
            key,
            InFlightLookupV1 {
                waiters: 0,
                reserved_bytes,
            },
        );
        self.in_flight_bytes = next_total;
        Ok(CoalescingOutcomeV1::Leader)
    }

    /// Completes coalesced work and retains a bounded result.
    pub fn complete(
        &mut self,
        key: AuthorizedLookupKey,
        value: LookupMemoValueV1,
        current_catalog_generation: u64,
    ) {
        if let Some(in_flight) = self.in_flight.remove(&key) {
            self.in_flight_bytes = self
                .in_flight_bytes
                .saturating_sub(in_flight.reserved_bytes);
        }
        let bounded_value = match value {
            LookupMemoValueV1::Negative {
                valid_through_generation,
            } => LookupMemoValueV1::Negative {
                valid_through_generation: valid_through_generation.min(
                    current_catalog_generation.saturating_add(self.limits.maximum_negative_span),
                ),
            },
            positive => positive,
        };
        if self.entries.insert(key, bounded_value).is_none() {
            self.order.push_back(key);
        }
        while self.entries.len() > self.limits.maximum_entries {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            } else {
                break;
            }
        }
    }

    /// Removes one in-flight miss without installing a presence observation.
    ///
    /// This is used after a proved pre-fetch failure or during bounded recovery;
    /// it does not create a negative cache entry.
    #[must_use]
    pub fn abort_miss(&mut self, key: AuthorizedLookupKey) -> bool {
        let Some(in_flight) = self.in_flight.remove(&key) else {
            return false;
        };
        self.in_flight_bytes = self
            .in_flight_bytes
            .saturating_sub(in_flight.reserved_bytes);
        true
    }
}

/// Reports invalid catalog state or bounded lookup exhaustion.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CatalogError {
    /// An entry, seal, backing identity, or chain commitment is malformed.
    #[error("cache catalog entry is invalid")]
    InvalidEntry,
    /// A reachability transition is outside the closed state machine.
    #[error("cache catalog transition is invalid")]
    InvalidTransition,
    /// A generation counter is exhausted.
    #[error("cache catalog generation is exhausted")]
    GenerationExhausted,
    /// Lookup memo limits are invalid.
    #[error("cache lookup memo limits are invalid")]
    InvalidLimits,
    /// Bounded miss coalescing or request admission is full.
    #[error("cache lookup is backpressured")]
    Backpressure,
}

pub(crate) fn catalog_digest(entry: &CatalogEntryV1) -> ObjectDigest {
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest as _;
    hasher.update(b"aos.sandbox.cache.catalog-entry.v1\0");
    hasher.update(entry.partition.digest().as_bytes());
    let media = entry.descriptor.media_type().as_str().as_bytes();
    hasher.update((media.len() as u16).to_be_bytes());
    hasher.update(media);
    hasher.update(entry.descriptor.digest().as_bytes());
    hasher.update(entry.descriptor.encoded_size().to_be_bytes());
    hasher.update([entry.seal.profile as u8]);
    hasher.update(entry.seal.measurement.as_bytes());
    hasher.update(entry.backing.as_bytes());
    hasher.update(entry.allocated_bytes.to_be_bytes());
    hasher.update(entry.root_custody.as_bytes());
    hasher.update(entry.root_generation.to_be_bytes());
    hasher.update(entry.canonical_name.as_bytes());
    hasher.update(entry.publication.as_bytes());
    hasher.update(entry.reservation.as_bytes());
    hasher.update([entry.presence as u8]);
    hasher.update(entry.generation.to_be_bytes());
    hasher.update(
        entry
            .predecessor
            .map_or([0; 32], |digest| *digest.as_bytes()),
    );
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Derives the only canonical name commitment for an object in one partition.
#[must_use]
pub fn canonical_name_digest(
    partition: PhysicalPartitionId,
    descriptor: &ObjectDescriptor,
) -> ObjectDigest {
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest as _;
    hasher.update(b"aos.sandbox.cache.canonical-name.v1\0");
    hasher.update(partition.digest().as_bytes());
    let media = descriptor.media_type().as_str().as_bytes();
    hasher.update((media.len() as u16).to_be_bytes());
    hasher.update(media);
    hasher.update(descriptor.digest().as_bytes());
    hasher.update(descriptor.encoded_size().to_be_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}
