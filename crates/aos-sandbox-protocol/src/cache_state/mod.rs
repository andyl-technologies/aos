//! Pure Cache accounting, catalog, and physical-partition state.
//!
//! `accounting` owns complete checked quota and reservation projections;
//! `catalog` owns immutable catalog records and reachability successors;
//! `partition` owns physical identity and isolation-policy commitments. These
//! DATA reducers retain no keys, operating-system descriptors, native causes,
//! clocks, or live loans, and grant no admission, durability, currentness, or
//! effect authority.

pub mod accounting;
pub mod catalog;
pub mod partition;

pub use accounting::{
    AccountingError, AccountingLimitsV1, CacheAccountingV1, CacheReservationId, CacheReservationV1,
    CacheUsageV1, NodeCacheQuotaV1, ProjectCacheQuotaV1, ReservationStateV1,
    validate_quota_totals_v1,
};
pub use catalog::{
    BackingObjectIdentityV1, CatalogEntryV1, CatalogError, CatalogPresenceV1, ImmutableSealV1,
    LookupMemoValueV1, SealProfileV1, canonical_name_digest, hash_descriptor_fields_u16_v1,
};
pub use partition::{
    BackingIsolationV1, CacheDomainError, CacheIsolationPolicyV1, CacheNodeIdV1,
    PhysicalPartitionId, ProtectedBackingIdentityV1, ResidencyEnforcementV1, cache_domain_code,
    object_descriptor_commitment, validate_object_descriptor,
};
