//! Retains durable manifest pin custody after an exclusive recovery turn ends.
//!
//! Only consuming an actual phase-bound receipt through its effect guard creates
//! this value. Read-only accessors perform no embedded-store or publisher lock.

use super::*;

/// Owns actual synced manifest/source/pin custody without borrowing the executor.
///
/// This value contains no live phase authority and cannot authorize adoption,
/// publication, Resume or ordinary retention currentness. Backing readers keep
/// it by value with the independently adopted object. Its destruction does not
/// clear durable pins/holds or the physical executor's source registry.
pub(crate) struct RecoveryManifestBackingRetention {
    retained: RetainedManifest,
    measurement: Option<super::reconcile::EffectMeasurement>,
}

impl RecoveryManifestBackingRetention {
    /// Borrows actual metadata registration for acknowledged retirement cleanup.
    ///
    /// This does not clone an ordinary receipt or restore its former recovery
    /// phase. The caller must retain the original verified body and Running
    /// barrier, and require the typed final-removal reply before releasing it.
    pub(in crate::host_cache::owner) fn retirement_metadata(&self) -> &RetainedManifest {
        &self.retained
    }

    /// Transfers durable custody from a genuine consumed phase-bound receipt.
    ///
    /// Only the effect guard calls this after reconciliation or explicit failure.
    /// It accepts no ordinary receipt, raw descriptor, ID or caller-selected file.
    pub(super) fn from_phase<'phase, 'executor>(
        receipt: RecoveryRetainedManifest<'phase, 'executor>,
        measurement: Option<super::reconcile::EffectMeasurement>,
    ) -> (Self, &'phase mut LiveManifestRecoveryContext<'executor>) {
        let RecoveryRetainedManifest { retained, live } = receipt;
        (
            Self {
                retained,
                measurement,
            },
            live,
        )
    }

    /// Checks actual durable registration while the physical owner holds custody.
    ///
    /// This does not check a client context or grant ordinary currentness. The
    /// caller must separately verify the retained original recovery barrier.
    ///
    /// # Errors
    /// Refuses changed source or missing/foreign durable pin, lease and hold rows.
    pub(in crate::host_cache::owner) fn check_recovery_registration(
        &self,
        owner: &Custody,
    ) -> io::Result<()> {
        self.retained.check_registration(owner)
    }

    /// Returns scoped synchronized source/backing inode blocks after successful reconciliation.
    ///
    /// Absence denotes unresolved effects, not zero allocation. This excludes
    /// policy/private binding allocation and is not full project quota usage.
    pub(crate) fn synchronized_source_and_body_bytes(&self) -> Option<u64> {
        self.measurement
            .as_ref()
            .map(|measurement| measurement.retained_source_and_body_bytes)
    }

    /// Returns separate fresh owner quota charge after successful reconciliation.
    pub(crate) fn charged_reserved_bytes(&self) -> Option<u64> {
        self.measurement
            .as_ref()
            .map(|measurement| measurement.charged_reserved_bytes)
    }

    /// Borrows the independently verified canonical manifest claim.
    pub(crate) fn claim(&self) -> &PublicationClaim {
        self.retained.claim()
    }

    /// Borrows the actual retained metadata pack without consulting state.
    pub(crate) fn metadata_file(&self) -> &File {
        self.retained.metadata_file()
    }

    /// Returns the verified canonical manifest range in that actual pack.
    pub(crate) fn manifest_range(&self) -> ByteRange {
        self.retained.manifest_range()
    }

    /// Borrows actual retained domain/root/profile custody without a state lock.
    pub(crate) fn layout(&self) -> &Arc<NativeHostLayout<HostDomainLocation>> {
        self.retained.layout()
    }

    /// Borrows the independently verified metadata-pack identity.
    pub(crate) fn pack_identity(&self) -> &Identity {
        self.retained.pack_identity()
    }

    /// Borrows the actual durable retention registration identifier.
    pub(crate) fn retention_id(&self) -> &[u8; 16] {
        self.retained.retention_id()
    }

    /// Borrows the original actual cache incarnation.
    pub(crate) fn cache_incarnation(&self) -> &[u8; 16] {
        self.retained.cache_incarnation()
    }
}
