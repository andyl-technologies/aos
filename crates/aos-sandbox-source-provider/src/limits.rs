//! Explicit memory, journal, and retention bounds for AOSSPL01.

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

pub use aos_sandbox_source_provider_ledger::limits::{
    MAXIMUM_ACTIVE_ACQUISITIONS_PER_HOLDER, MAXIMUM_APPLY_TEMPLATE_BYTES,
    MAXIMUM_BACKEND_EVIDENCE_PAYLOAD_BYTES, MAXIMUM_HOLDERS, MAXIMUM_INVENTORY_ENTRIES_PER_HOLDER,
    MAXIMUM_INVENTORY_TOMBSTONES_PER_HOLDER, MAXIMUM_LEASE_HISTORY_PER_ACQUISITION,
    MAXIMUM_LOGICAL_BINDING_BYTES, MAXIMUM_RETAINED_CATALOG_HEADS, MAXIMUM_RETAINED_IDENTITIES,
    MAXIMUM_SIGNED_HELLO_BYTES, MAXIMUM_SIGNED_LEASE_BYTES, MAXIMUM_SIGNED_RELEASE_RECEIPT_BYTES,
    MAXIMUM_SIGNED_REQUEST_OR_RESPONSE_BYTES, MAXIMUM_TRANSACTION_BYTES,
    MAXIMUM_TRANSACTION_RECORDS,
};
/// Conservative journal capacity required before an Acquire backend effect.
pub(crate) const MAXIMUM_ACQUIRE_COMPLETION_BYTES: usize = 3 * 1024 * 1024;
/// Conservative journal capacity required before a Release backend effect.
pub(crate) const MAXIMUM_RELEASE_COMPLETION_BYTES: usize = 3 * 1024 * 1024;
/// Conservative journal capacity required before signing an Inventory result.
pub(crate) const MAXIMUM_INVENTORY_COMPLETION_BYTES: usize = 5 * 1024 * 1024 / 2;
const _: () = assert!(MAXIMUM_ACQUIRE_COMPLETION_BYTES <= MAXIMUM_TRANSACTION_BYTES);
const _: () = assert!(MAXIMUM_RELEASE_COMPLETION_BYTES <= MAXIMUM_TRANSACTION_BYTES);
const _: () = assert!(MAXIMUM_INVENTORY_COMPLETION_BYTES <= MAXIMUM_TRANSACTION_BYTES);

/// Describes deployment ceilings below the protocol maxima.
///
/// AOSSPL01 version 3 admits only [`Self::default`] so recovery has an exact
/// format-defined limit policy. The constructor reserves an explicit typed
/// boundary for a future ledger version that durably commits custom ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderLedgerLimits {
    maximum_holders: usize,
    maximum_active_acquisitions_per_holder: usize,
    maximum_inventory_entries_per_holder: usize,
    maximum_retained_identities: usize,
    maximum_inventory_tombstones_per_holder: usize,
}

impl ProviderLedgerLimits {
    /// Constructs bounded ledger limits.
    ///
    /// # Errors
    ///
    /// Returns `LimitExceeded` when any value is zero or exceeds its hard cap.
    pub fn new(
        maximum_holders: usize,
        maximum_active_acquisitions_per_holder: usize,
        maximum_inventory_entries_per_holder: usize,
        maximum_retained_identities: usize,
        maximum_inventory_tombstones_per_holder: usize,
    ) -> Result<Self, crate::ProviderLedgerError> {
        let within_bounds = maximum_holders > 0
            && maximum_holders <= MAXIMUM_HOLDERS
            && maximum_active_acquisitions_per_holder > 0
            && maximum_active_acquisitions_per_holder <= MAXIMUM_ACTIVE_ACQUISITIONS_PER_HOLDER
            && maximum_inventory_entries_per_holder > 0
            && maximum_inventory_entries_per_holder <= MAXIMUM_INVENTORY_ENTRIES_PER_HOLDER
            && maximum_retained_identities > 0
            && maximum_retained_identities <= MAXIMUM_RETAINED_IDENTITIES
            && maximum_inventory_tombstones_per_holder <= MAXIMUM_INVENTORY_TOMBSTONES_PER_HOLDER;
        if !within_bounds {
            return Err(crate::ProviderLedgerError::LimitExceeded(
                "configured SourceProvider ledger limits",
            ));
        }
        Ok(Self {
            maximum_holders,
            maximum_active_acquisitions_per_holder,
            maximum_inventory_entries_per_holder,
            maximum_retained_identities,
            maximum_inventory_tombstones_per_holder,
        })
    }

    pub(crate) const fn maximum_holders(self) -> usize {
        self.maximum_holders
    }

    pub(crate) const fn maximum_active_acquisitions_per_holder(self) -> usize {
        self.maximum_active_acquisitions_per_holder
    }

    pub(crate) const fn maximum_inventory_entries_per_holder(self) -> usize {
        self.maximum_inventory_entries_per_holder
    }

    pub(crate) const fn maximum_retained_identities(self) -> usize {
        self.maximum_retained_identities
    }

    pub(crate) const fn maximum_inventory_tombstones_per_holder(self) -> usize {
        self.maximum_inventory_tombstones_per_holder
    }

    pub(crate) fn deployment_digest(self) -> ObjectDigest {
        let mut hasher = Sha256::new();
        hasher.update(b"aos.sandbox.source-provider.deployment-limits.v1\0");
        hasher.update((self.maximum_holders as u64).to_be_bytes());
        hasher.update((self.maximum_active_acquisitions_per_holder as u64).to_be_bytes());
        hasher.update((self.maximum_inventory_entries_per_holder as u64).to_be_bytes());
        hasher.update((self.maximum_retained_identities as u64).to_be_bytes());
        hasher.update((self.maximum_inventory_tombstones_per_holder as u64).to_be_bytes());
        ObjectDigest::from_bytes(hasher.finalize().into())
    }
}

impl Default for ProviderLedgerLimits {
    fn default() -> Self {
        Self {
            maximum_holders: MAXIMUM_HOLDERS,
            maximum_active_acquisitions_per_holder: MAXIMUM_ACTIVE_ACQUISITIONS_PER_HOLDER,
            maximum_inventory_entries_per_holder: MAXIMUM_INVENTORY_ENTRIES_PER_HOLDER,
            maximum_retained_identities: MAXIMUM_RETAINED_IDENTITIES,
            maximum_inventory_tombstones_per_holder: MAXIMUM_INVENTORY_TOMBSTONES_PER_HOLDER,
        }
    }
}
