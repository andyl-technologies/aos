//! Overflow-safe resource admission and ancestry reservation accounting.
//!
//! Portable accounting is a pure transaction over explicit resource vectors.
//! It does not rely on cgroup hierarchy because logical sandbox ancestry may
//! cross nodes. Kernel and service limits enforce each assigned sandbox while
//! controller reservations enforce aggregate ancestor envelopes.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

/// Identifies one independently accounted hard resource.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[repr(u8)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceDimension {
    /// CPU quota in microseconds within the policy's fixed period.
    CpuMicrosPerPeriod,
    /// Payload and charged helper memory in bytes.
    MemoryBytes,
    /// Payload task count.
    Pids,
    /// Conservative aggregate open-file envelope.
    OpenFiles,
    /// Brokered and statically configured mount count.
    Mounts,
    /// Reserved logical descendants.
    Descendants,
    /// Persistent writable storage in bytes.
    StorageBytes,
    /// Memory-backed filesystem bytes, also charged to memory.
    TmpfsBytes,
    /// Cache capacity promised before allocation.
    CacheReservationBytes,
    /// Correctness-pinned immutable bytes.
    PinnedBytes,
    /// Resident namespace metadata entries.
    MetadataEntries,
    /// Node-local mapped index bytes.
    MappedIndexBytes,
    /// Bytes admitted for concurrent remote fetch.
    InflightFetchBytes,
    /// Bytes admitted for concurrent decompression.
    InflightDecompressedBytes,
    /// Unpublished transactional staging bytes.
    PublicationStagingBytes,
    /// Kernel-held FUSE backing-file registrations.
    BackingRegistrations,
    /// Desired or realized attachment edges.
    AttachmentEdges,
    /// Concurrent admitted executions.
    Executions,
    /// Network bytes reserved for an out-of-payload operation.
    NetworkBytes,
    /// Diagnostic log bytes reserved for an operation.
    LogBytes,
    /// Result bytes reserved for an operation.
    OutputBytes,
    /// Concurrent out-of-payload operations.
    ConcurrentOperations,
}

impl ResourceDimension {
    /// Number of registered resource dimensions.
    pub const COUNT: usize = 22;

    /// Dimensions in their stable accounting order.
    pub const ALL: [Self; Self::COUNT] = [
        Self::CpuMicrosPerPeriod,
        Self::MemoryBytes,
        Self::Pids,
        Self::OpenFiles,
        Self::Mounts,
        Self::Descendants,
        Self::StorageBytes,
        Self::TmpfsBytes,
        Self::CacheReservationBytes,
        Self::PinnedBytes,
        Self::MetadataEntries,
        Self::MappedIndexBytes,
        Self::InflightFetchBytes,
        Self::InflightDecompressedBytes,
        Self::PublicationStagingBytes,
        Self::BackingRegistrations,
        Self::AttachmentEdges,
        Self::Executions,
        Self::NetworkBytes,
        Self::LogBytes,
        Self::OutputBytes,
        Self::ConcurrentOperations,
    ];

    const fn index(self) -> usize {
        self as usize
    }

    /// Returns the stable kebab-case diagnostic name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CpuMicrosPerPeriod => "cpu-micros-per-period",
            Self::MemoryBytes => "memory-bytes",
            Self::Pids => "pids",
            Self::OpenFiles => "open-files",
            Self::Mounts => "mounts",
            Self::Descendants => "descendants",
            Self::StorageBytes => "storage-bytes",
            Self::TmpfsBytes => "tmpfs-bytes",
            Self::CacheReservationBytes => "cache-reservation-bytes",
            Self::PinnedBytes => "pinned-bytes",
            Self::MetadataEntries => "metadata-entries",
            Self::MappedIndexBytes => "mapped-index-bytes",
            Self::InflightFetchBytes => "inflight-fetch-bytes",
            Self::InflightDecompressedBytes => "inflight-decompressed-bytes",
            Self::PublicationStagingBytes => "publication-staging-bytes",
            Self::BackingRegistrations => "backing-registrations",
            Self::AttachmentEdges => "attachment-edges",
            Self::Executions => "executions",
            Self::NetworkBytes => "network-bytes",
            Self::LogBytes => "log-bytes",
            Self::OutputBytes => "output-bytes",
            Self::ConcurrentOperations => "concurrent-operations",
        }
    }
}

impl fmt::Display for ResourceDimension {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Stores one amount for every registered resource dimension.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ResourceVector([u64; ResourceDimension::COUNT]);

impl ResourceVector {
    /// The vector containing zero in every dimension.
    pub const ZERO: Self = Self([0; ResourceDimension::COUNT]);

    /// Constructs a vector from values in [`ResourceDimension::ALL`] order.
    #[must_use]
    pub const fn new(values: [u64; ResourceDimension::COUNT]) -> Self {
        Self(values)
    }

    /// Returns the amount charged in `dimension`.
    #[must_use]
    pub const fn get(self, dimension: ResourceDimension) -> u64 {
        self.0[dimension.index()]
    }

    /// Returns a copy with one dimension replaced by an explicit amount.
    #[must_use]
    pub const fn with(mut self, dimension: ResourceDimension, amount: u64) -> Self {
        self.0[dimension.index()] = amount;
        self
    }

    /// Adds corresponding dimensions without permitting wraparound.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::ArithmeticOverflow`] naming the first
    /// dimension whose sum exceeds [`u64::MAX`].
    pub fn checked_add(self, other: Self) -> Result<Self, AccountingError> {
        let mut result = self;
        for dimension in ResourceDimension::ALL {
            let Some(sum) = self.get(dimension).checked_add(other.get(dimension)) else {
                return Err(AccountingError::ArithmeticOverflow { dimension });
            };
            result.0[dimension.index()] = sum;
        }
        Ok(result)
    }

    /// Subtracts corresponding dimensions without permitting underflow.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::InsufficientAmount`] naming the first
    /// dimension for which `other` exceeds this vector.
    pub fn checked_sub(self, other: Self) -> Result<Self, AccountingError> {
        let mut result = self;
        for dimension in ResourceDimension::ALL {
            let Some(difference) = self.get(dimension).checked_sub(other.get(dimension)) else {
                return Err(AccountingError::InsufficientAmount {
                    dimension,
                    available: self.get(dimension),
                    requested: other.get(dimension),
                });
            };
            result.0[dimension.index()] = difference;
        }
        Ok(result)
    }

    /// Reports whether every amount is at most the corresponding `ceiling`.
    #[must_use]
    pub fn is_within(self, ceiling: Self) -> bool {
        ResourceDimension::ALL
            .into_iter()
            .all(|dimension| self.get(dimension) <= ceiling.get(dimension))
    }
}

/// Defines one resolved hard ceiling without using numeric sentinels.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "value")]
pub enum ResourceLimit {
    /// Rejects any total above the explicit value, including when it is zero.
    Bounded(u64),
    /// Carries prior proof of separately authorized unlimited use.
    Unlimited,
}

impl ResourceLimit {
    const fn intersect(self, other: Self) -> Self {
        match (self, other) {
            (Self::Bounded(left), Self::Bounded(right)) => {
                Self::Bounded(if left < right { left } else { right })
            }
            (Self::Bounded(value), Self::Unlimited) | (Self::Unlimited, Self::Bounded(value)) => {
                Self::Bounded(value)
            }
            (Self::Unlimited, Self::Unlimited) => Self::Unlimited,
        }
    }
}

/// Stores the resolved ceiling for every resource dimension.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ResourceCeilings([ResourceLimit; ResourceDimension::COUNT]);

impl ResourceCeilings {
    /// Constructs explicit per-dimension ceilings in stable registry order.
    #[must_use]
    pub const fn new(values: [ResourceLimit; ResourceDimension::COUNT]) -> Self {
        Self(values)
    }

    /// Constructs a finite ceiling from one resource vector.
    #[must_use]
    pub const fn bounded(values: ResourceVector) -> Self {
        let mut limits = [ResourceLimit::Bounded(0); ResourceDimension::COUNT];
        let mut index = 0;
        while index < ResourceDimension::COUNT {
            limits[index] = ResourceLimit::Bounded(values.0[index]);
            index += 1;
        }
        Self(limits)
    }

    /// Constructs ceilings that are explicitly unlimited in every dimension.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self([ResourceLimit::Unlimited; ResourceDimension::COUNT])
    }

    /// Returns the resolved limit for one dimension.
    #[must_use]
    pub const fn get(self, dimension: ResourceDimension) -> ResourceLimit {
        self.0[dimension.index()]
    }

    /// Returns a copy with one dimension replaced by an explicit limit.
    #[must_use]
    pub const fn with(mut self, dimension: ResourceDimension, limit: ResourceLimit) -> Self {
        self.0[dimension.index()] = limit;
        self
    }

    /// Intersects two ceiling layers component by component.
    #[must_use]
    pub fn intersect(self, other: Self) -> Self {
        let mut result = self;
        for dimension in ResourceDimension::ALL {
            result.0[dimension.index()] = self.get(dimension).intersect(other.get(dimension));
        }
        result
    }

    fn validate(self, total: ResourceVector) -> Result<(), AccountingError> {
        for dimension in ResourceDimension::ALL {
            if let ResourceLimit::Bounded(limit) = self.get(dimension) {
                let attempted = total.get(dimension);
                if attempted > limit {
                    return Err(AccountingError::LimitExceeded {
                        dimension,
                        limit,
                        attempted,
                    });
                }
            }
        }
        Ok(())
    }
}

/// Reports a fail-closed arithmetic or admission failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AccountingError {
    /// Addition would wrap in the named dimension.
    #[error("resource arithmetic overflow in {dimension}")]
    ArithmeticOverflow {
        /// Dimension whose arithmetic overflowed.
        dimension: ResourceDimension,
    },
    /// A release or commit exceeds the accounted source amount.
    #[error("insufficient {dimension}: requested {requested}, but only {available} is accounted")]
    InsufficientAmount {
        /// Dimension whose source amount was insufficient.
        dimension: ResourceDimension,
        /// Amount currently accounted.
        available: u64,
        /// Amount requested by the operation.
        requested: u64,
    },
    /// The post-transaction total exceeds a finite resolved ceiling.
    #[error("{dimension} total {attempted} exceeds hard limit {limit}")]
    LimitExceeded {
        /// Dimension whose ceiling rejected admission.
        dimension: ResourceDimension,
        /// Effective finite ceiling.
        limit: u64,
        /// Total that would result from the transaction.
        attempted: u64,
    },
}

/// Holds committed use and promised capacity under one resolved ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ResourceAccount {
    ceilings: ResourceCeilings,
    committed: ResourceVector,
    reserved: ResourceVector,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceAccountWire {
    ceilings: ResourceCeilings,
    committed: ResourceVector,
    reserved: ResourceVector,
}

impl<'de> Deserialize<'de> for ResourceAccount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ResourceAccountWire::deserialize(deserializer)?;
        Self::from_usage(wire.ceilings, wire.committed, wire.reserved)
            .map_err(serde::de::Error::custom)
    }
}

impl ResourceAccount {
    /// Creates an empty account beneath explicit resolved ceilings.
    #[must_use]
    pub const fn new(ceilings: ResourceCeilings) -> Self {
        Self {
            ceilings,
            committed: ResourceVector::ZERO,
            reserved: ResourceVector::ZERO,
        }
    }

    /// Reconstructs an account after validating its persisted totals.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError`] if addition overflows or the reconstructed
    /// total exceeds any finite ceiling.
    pub fn from_usage(
        ceilings: ResourceCeilings,
        committed: ResourceVector,
        reserved: ResourceVector,
    ) -> Result<Self, AccountingError> {
        ceilings.validate(committed.checked_add(reserved)?)?;
        Ok(Self {
            ceilings,
            committed,
            reserved,
        })
    }

    /// Returns the account's resolved ceilings.
    #[must_use]
    pub const fn ceilings(self) -> ResourceCeilings {
        self.ceilings
    }

    /// Returns resources whose effects have committed.
    #[must_use]
    pub const fn committed(self) -> ResourceVector {
        self.committed
    }

    /// Returns capacity promised before effect allocation.
    #[must_use]
    pub const fn reserved(self) -> ResourceVector {
        self.reserved
    }

    /// Returns the complete charged and promised total.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::ArithmeticOverflow`] if persisted state is
    /// corrupt and cannot be represented.
    pub fn total(self) -> Result<ResourceVector, AccountingError> {
        self.committed.checked_add(self.reserved)
    }

    /// Returns a new account with `amount` atomically reserved.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError`] on arithmetic overflow or ceiling excess.
    pub fn reserve(self, amount: ResourceVector) -> Result<Self, AccountingError> {
        let reserved = self.reserved.checked_add(amount)?;
        self.ceilings
            .validate(self.committed.checked_add(reserved)?)?;
        Ok(Self { reserved, ..self })
    }

    /// Converts an existing reservation into committed use without changing
    /// the total charge.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError`] if the reservation is insufficient or
    /// committed arithmetic overflows.
    pub fn commit(self, amount: ResourceVector) -> Result<Self, AccountingError> {
        let reserved = self.reserved.checked_sub(amount)?;
        let committed = self.committed.checked_add(amount)?;
        Ok(Self {
            committed,
            reserved,
            ..self
        })
    }

    /// Releases capacity that was reserved but never committed.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError`] if `amount` exceeds the reservation.
    pub fn release_reservation(self, amount: ResourceVector) -> Result<Self, AccountingError> {
        Ok(Self {
            reserved: self.reserved.checked_sub(amount)?,
            ..self
        })
    }

    /// Releases committed use after authoritative effect cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError`] if `amount` exceeds committed use.
    pub fn release_committed(self, amount: ResourceVector) -> Result<Self, AccountingError> {
        Ok(Self {
            committed: self.committed.checked_sub(amount)?,
            ..self
        })
    }
}

/// Selects the isolated capacity pool charged by a reservation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReservationClass {
    /// Capacity necessary for admitted semantics or correctness.
    Hard,
    /// Cancelable optimization capacity that can never expand hard admission.
    Advisory,
}

/// Keeps correctness reservations independent from cancelable advisory work.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceBudget {
    hard: ResourceAccount,
    advisory: ResourceAccount,
}

impl ResourceBudget {
    /// Creates independent empty hard and advisory accounts.
    #[must_use]
    pub const fn new(hard: ResourceCeilings, advisory: ResourceCeilings) -> Self {
        Self {
            hard: ResourceAccount::new(hard),
            advisory: ResourceAccount::new(advisory),
        }
    }

    /// Returns the account for `class`.
    #[must_use]
    pub const fn account(self, class: ReservationClass) -> ResourceAccount {
        match class {
            ReservationClass::Hard => self.hard,
            ReservationClass::Advisory => self.advisory,
        }
    }

    /// Returns a new budget with capacity reserved only in the selected pool.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError`] if that pool rejects the reservation.
    pub fn reserve(
        self,
        class: ReservationClass,
        amount: ResourceVector,
    ) -> Result<Self, AccountingError> {
        match class {
            ReservationClass::Hard => Ok(Self {
                hard: self.hard.reserve(amount)?,
                ..self
            }),
            ReservationClass::Advisory => Ok(Self {
                advisory: self.advisory.reserve(amount)?,
                ..self
            }),
        }
    }

    /// Converts a reservation in the selected pool into committed use.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError`] if the selected pool has insufficient
    /// reservation or committed arithmetic overflows.
    pub fn commit(
        self,
        class: ReservationClass,
        amount: ResourceVector,
    ) -> Result<Self, AccountingError> {
        match class {
            ReservationClass::Hard => Ok(Self {
                hard: self.hard.commit(amount)?,
                ..self
            }),
            ReservationClass::Advisory => Ok(Self {
                advisory: self.advisory.commit(amount)?,
                ..self
            }),
        }
    }

    /// Releases an uncommitted reservation from the selected pool.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError`] if the selected reservation is
    /// insufficient.
    pub fn release_reservation(
        self,
        class: ReservationClass,
        amount: ResourceVector,
    ) -> Result<Self, AccountingError> {
        match class {
            ReservationClass::Hard => Ok(Self {
                hard: self.hard.release_reservation(amount)?,
                ..self
            }),
            ReservationClass::Advisory => Ok(Self {
                advisory: self.advisory.release_reservation(amount)?,
                ..self
            }),
        }
    }

    /// Releases committed use after authoritative cleanup in the selected pool.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError`] if committed use is insufficient.
    pub fn release_committed(
        self,
        class: ReservationClass,
        amount: ResourceVector,
    ) -> Result<Self, AccountingError> {
        match class {
            ReservationClass::Hard => Ok(Self {
                hard: self.hard.release_committed(amount)?,
                ..self
            }),
            ReservationClass::Advisory => Ok(Self {
                advisory: self.advisory.release_committed(amount)?,
                ..self
            }),
        }
    }
}

/// Reports which ancestor rejected an otherwise atomic reservation proposal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AncestryAdmissionError {
    /// The proposed self-to-root path did not even contain the subject account.
    #[error("ancestry accounting path must contain at least the subject account")]
    EmptyPath,
    /// One account rejected the proposed transaction.
    #[error("ancestor account {ancestor_index} rejected reservation: {source}")]
    Rejected {
        /// Zero-based position in the supplied self-to-root account path.
        ancestor_index: usize,
        /// Concrete arithmetic or ceiling failure at that ancestor.
        #[source]
        source: AccountingError,
    },
}

impl AncestryAdmissionError {
    /// Returns the rejecting ancestor index, or `None` for an empty path.
    #[must_use]
    pub const fn ancestor_index(self) -> Option<usize> {
        match self {
            Self::EmptyPath => None,
            Self::Rejected { ancestor_index, .. } => Some(ancestor_index),
        }
    }
}

/// Prepares an all-or-nothing reservation across a self-to-root ancestry path.
///
/// The input is never mutated. Success returns replacement budgets for a
/// caller to persist in one compare-and-swap transaction. A descendant's
/// reservation therefore consumes every inclusive ancestor envelope even when
/// those ancestors reside on different nodes.
///
/// # Errors
///
/// Returns [`AncestryAdmissionError`] naming the first ancestor whose selected
/// pool overflows or exceeds its resolved ceiling.
pub fn reserve_across_ancestry(
    accounts: &[ResourceBudget],
    class: ReservationClass,
    amount: ResourceVector,
) -> Result<Vec<ResourceBudget>, AncestryAdmissionError> {
    if accounts.is_empty() {
        return Err(AncestryAdmissionError::EmptyPath);
    }

    accounts
        .iter()
        .copied()
        .enumerate()
        .map(|(ancestor_index, account)| {
            account
                .reserve(class, amount)
                .map_err(|source| AncestryAdmissionError::Rejected {
                    ancestor_index,
                    source,
                })
        })
        .collect()
}

/// Commits an existing reservation across a complete ancestry path.
///
/// Like [`reserve_across_ancestry`], this returns replacement values and never
/// partially mutates input state.
///
/// # Errors
///
/// Returns [`AncestryAdmissionError`] naming the first account with
/// insufficient reservation or overflowed committed use.
pub fn commit_across_ancestry(
    accounts: &[ResourceBudget],
    class: ReservationClass,
    amount: ResourceVector,
) -> Result<Vec<ResourceBudget>, AncestryAdmissionError> {
    if accounts.is_empty() {
        return Err(AncestryAdmissionError::EmptyPath);
    }

    accounts
        .iter()
        .copied()
        .enumerate()
        .map(|(ancestor_index, account)| {
            account
                .commit(class, amount)
                .map_err(|source| AncestryAdmissionError::Rejected {
                    ancestor_index,
                    source,
                })
        })
        .collect()
}

/// Releases a pre-commit reservation across a complete ancestry path.
///
/// # Errors
///
/// Returns [`AncestryAdmissionError`] naming the first account with an
/// insufficient reservation. Callers must treat such a failure as ledger
/// corruption and leave persisted state unchanged.
pub fn release_reservation_across_ancestry(
    accounts: &[ResourceBudget],
    class: ReservationClass,
    amount: ResourceVector,
) -> Result<Vec<ResourceBudget>, AncestryAdmissionError> {
    if accounts.is_empty() {
        return Err(AncestryAdmissionError::EmptyPath);
    }

    accounts
        .iter()
        .copied()
        .enumerate()
        .map(|(ancestor_index, account)| {
            account
                .release_reservation(class, amount)
                .map_err(|source| AncestryAdmissionError::Rejected {
                    ancestor_index,
                    source,
                })
        })
        .collect()
}

/// Releases committed use across a complete ancestry path after cleanup.
///
/// # Errors
///
/// Returns [`AncestryAdmissionError`] naming the first account with
/// insufficient committed use. Callers must leave persisted state unchanged.
pub fn release_committed_across_ancestry(
    accounts: &[ResourceBudget],
    class: ReservationClass,
    amount: ResourceVector,
) -> Result<Vec<ResourceBudget>, AncestryAdmissionError> {
    if accounts.is_empty() {
        return Err(AncestryAdmissionError::EmptyPath);
    }

    accounts
        .iter()
        .copied()
        .enumerate()
        .map(|(ancestor_index, account)| {
            account.release_committed(class, amount).map_err(|source| {
                AncestryAdmissionError::Rejected {
                    ancestor_index,
                    source,
                }
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        AccountingError, ReservationClass, ResourceBudget, ResourceCeilings, ResourceDimension,
        ResourceLimit, ResourceVector, reserve_across_ancestry,
    };

    fn memory(bytes: u64) -> ResourceVector {
        ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, bytes)
    }

    fn bounded_memory(bytes: u64) -> ResourceCeilings {
        ResourceCeilings::unlimited().with(
            ResourceDimension::MemoryBytes,
            ResourceLimit::Bounded(bytes),
        )
    }

    #[test]
    fn zero_is_an_explicit_finite_ceiling() {
        let account = super::ResourceAccount::new(bounded_memory(0));
        assert_eq!(
            account.reserve(memory(1)),
            Err(AccountingError::LimitExceeded {
                dimension: ResourceDimension::MemoryBytes,
                limit: 0,
                attempted: 1,
            })
        );
    }

    #[test]
    fn arithmetic_overflow_fails_before_limit_comparison() {
        let account = super::ResourceAccount::from_usage(
            ResourceCeilings::unlimited(),
            memory(u64::MAX),
            ResourceVector::ZERO,
        );
        let result = account.and_then(|value| value.reserve(memory(1)));

        assert_eq!(
            result,
            Err(AccountingError::ArithmeticOverflow {
                dimension: ResourceDimension::MemoryBytes,
            })
        );
    }

    #[test]
    fn commit_moves_but_does_not_increase_the_total() {
        let reserved = super::ResourceAccount::new(bounded_memory(100)).reserve(memory(40));
        let committed = reserved.and_then(|account| account.commit(memory(25)));

        assert_eq!(
            committed.map(|account| (
                account.committed().get(ResourceDimension::MemoryBytes),
                account.reserved().get(ResourceDimension::MemoryBytes),
                account
                    .total()
                    .map(|total| total.get(ResourceDimension::MemoryBytes)),
            )),
            Ok((25, 15, Ok(40)))
        );
    }

    #[test]
    fn ancestry_reservation_is_all_or_nothing() {
        let child = ResourceBudget::new(bounded_memory(100), bounded_memory(100));
        let parent = ResourceBudget::new(bounded_memory(50), bounded_memory(100));
        let original = [child, parent];
        let result = reserve_across_ancestry(&original, ReservationClass::Hard, memory(60));

        assert_eq!(
            result.err().and_then(|error| error.ancestor_index()),
            Some(1)
        );
        assert_eq!(
            original[0]
                .account(ReservationClass::Hard)
                .reserved()
                .get(ResourceDimension::MemoryBytes),
            0
        );
    }

    #[test]
    fn ancestry_path_must_include_the_subject() {
        let result = reserve_across_ancestry(&[], ReservationClass::Hard, ResourceVector::ZERO);

        assert_eq!(result, Err(super::AncestryAdmissionError::EmptyPath));
    }

    #[test]
    fn advisory_exhaustion_does_not_consume_hard_capacity() {
        let budget = ResourceBudget::new(bounded_memory(100), bounded_memory(10));
        let result = budget.reserve(ReservationClass::Advisory, memory(11));

        assert!(result.is_err());
        assert_eq!(
            budget
                .account(ReservationClass::Hard)
                .reserved()
                .get(ResourceDimension::MemoryBytes),
            0
        );
    }

    #[test]
    fn ceiling_intersection_never_widens_a_finite_layer() {
        let finite = bounded_memory(64);
        let intersected = finite.intersect(ResourceCeilings::unlimited());

        assert_eq!(
            intersected.get(ResourceDimension::MemoryBytes),
            ResourceLimit::Bounded(64)
        );
    }

    #[test]
    fn deserialization_revalidates_account_totals() {
        let invalid = super::ResourceAccount {
            ceilings: bounded_memory(0),
            committed: memory(1),
            reserved: ResourceVector::ZERO,
        };
        let encoded = serde_json::to_string(&invalid);
        let decoded = encoded
            .as_deref()
            .map(serde_json::from_str::<super::ResourceAccount>);

        assert!(matches!(decoded, Ok(Err(_))));
    }
}
