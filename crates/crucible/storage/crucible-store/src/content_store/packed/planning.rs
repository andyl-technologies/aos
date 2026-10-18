//! Immutable repack plans, identifiers, reports, and physical accounting.

use super::*;

/// Checked logical and physical accounting for one packed leaf generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackedStorageAccounting {
    pub(super) generation: u64,
    pub(super) logical_objects: u64,
    pub(super) logical_bytes: u64,
    pub(super) packs: u64,
    pub(super) physical_bytes: u64,
}

impl PackedStorageAccounting {
    /// Returns the monotonic index generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the indexed logical-object count.
    #[must_use]
    pub const fn logical_objects(self) -> u64 {
        self.logical_objects
    }

    /// Returns the checked sum of indexed logical bytes.
    #[must_use]
    pub const fn logical_bytes(self) -> u64 {
        self.logical_bytes
    }

    /// Returns the number of physical packs referenced by the index.
    #[must_use]
    pub const fn packs(self) -> u64 {
        self.packs
    }

    /// Returns the checked sum of referenced physical pack bytes.
    #[must_use]
    pub const fn physical_bytes(self) -> u64 {
        self.physical_bytes
    }
}

/// Result of one deterministic replacement-pack publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackedRepackReport {
    pub(super) plan: PackedRepackPlanId,
    pub(super) before: PackedStorageAccounting,
    pub(super) after: PackedStorageAccounting,
    pub(super) removed_packs: u64,
    pub(super) replayed: bool,
}

impl PackedRepackReport {
    /// Returns the exact applied or replayed plan identity.
    #[must_use]
    pub const fn plan(self) -> PackedRepackPlanId {
        self.plan
    }

    /// Returns accounting before the index-generation switch.
    #[must_use]
    pub const fn before(self) -> PackedStorageAccounting {
        self.before
    }

    /// Returns accounting after replacement publication and cleanup.
    #[must_use]
    pub const fn after(self) -> PackedStorageAccounting {
        self.after
    }

    /// Returns the number of superseded pack names removed durably.
    #[must_use]
    pub const fn removed_packs(self) -> u64 {
        self.removed_packs
    }

    /// Returns whether the index switch had already committed before this call.
    #[must_use]
    pub const fn replayed(self) -> bool {
        self.replayed
    }
}

/// Content-derived identity of one exact packed-index repack plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PackedRepackPlanId(pub(super) [u8; 32]);

impl PackedRepackPlanId {
    /// Returns the raw plan digest.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Canonical exact-generation plan for deterministic replacement packing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackedRepackPlan {
    pub(super) id: PackedRepackPlanId,
    pub(super) configuration: [u8; 32],
    pub(super) instance: [u8; 32],
    pub(super) generation: u64,
    pub(super) index_digest: [u8; 32],
    pub(super) before: PackedStorageAccounting,
}

impl PackedRepackPlan {
    /// Returns the content-derived plan identity.
    #[must_use]
    pub const fn id(&self) -> PackedRepackPlanId {
        self.id
    }

    /// Returns the exact pre-apply storage accounting captured by the plan.
    #[must_use]
    pub const fn before(&self) -> PackedStorageAccounting {
        self.before
    }

    /// Returns canonical bytes suitable for an external maintenance journal.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode_repack_plan(self)
    }

    /// Strictly decodes one canonical v1 plan.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Incompatible`] for truncation, trailing bytes,
    /// checksum failure, or invalid accounting.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        decode_repack_plan(bytes)
    }
}
