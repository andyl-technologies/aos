//! Pure Cache accounting, catalog, and physical-partition state.
//!
//! `accounting` owns complete checked quota and reservation projections;
//! `catalog` owns immutable catalog records and reachability successors;
//! `partition` owns physical identity and isolation-policy commitments. These
//! DATA reducers retain no keys, operating-system descriptors, native causes,
//! clocks, or live loans, and grant no admission, durability, currentness, or
//! effect authority.

pub mod accounting;
pub mod admission_progress;
pub mod admission_data;
pub mod authority_record;
pub mod catalog;
pub mod complete_node_quotas;
pub mod durable_format;
pub mod eviction_data;
pub mod handoff_data;
pub mod partition;
pub mod physical_manifest;
pub mod pin_data;
pub mod pin_floor;
pub mod pin_ledger;
pub mod scrub_data;

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

/// Shares the compiled existing Cache fixed-journal comparison recipes.
pub mod fixed_journals;

/// Shares complete historical replay manifests and Bootstrap validation.
pub mod replay_evidence;

/// Canonical historical Cache models, codecs and complete recovery folds.
pub mod recovery;

/// Canonical protected Cache envelope/family historical DATA validation.
pub mod protected_replay;

/// Canonical historical Cache replay-manifest and partition envelope DATA.
pub mod replay_envelope;

/// Shares exact historical Cache project selection and replay-head DATA.
pub mod current_selection;

/// Shares the complete historical fixed HOLD grammar without a live claim.
pub mod hold_state;

/// Shares canonical historical Cache clock-floor bytes without clock authority.
pub mod clock_floor;
