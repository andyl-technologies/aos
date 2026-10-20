//! Retains one finite catalog-maintenance native interval on the actual B.
//!
//! The same baseline ledger, names and private Producer engine remain active.
//! This original grants no Ready, operation or semantic replay. The upper
//! owner supplies fresh paid clocks, Source, all four real Sessions and signed
//! inventories. Any Storage31 effect requires its separate typed authority.

use super::*;

use crate::controller_receiving::bank_launch::ControllerNativePostOriginalV1;

const APPEND_SLOTS: usize = 8;

/// Retains only the identity of one already-paid maintenance native interval.
///
/// The strong references borrow existing unique owners without allocating a
/// second token. Keeping the native turn alive prevents address reuse from
/// making a later interval compare equal. This identity grants no currentness,
/// Session association, append, observation or effect authority.
#[must_use = "retain the same identity with its canonical Source owner"]
pub struct ControllerCatalogMaintenanceIdentityV2 {
    original: Arc<ControllerReceivingOriginalV1>,
    turn: Arc<std::sync::atomic::AtomicBool>,
}

/// Retains one finite ordinary catalog-maintenance native interval.
#[must_use = "retain every maintenance prefix through all independently owed posts"]
pub struct ControllerCatalogMaintenanceReceivingV2 {
    native: ControllerCreateProvisioningReceivingV1,
    append_entries: [Option<Result<(), ControllerBankLaunchErrorV1>>; APPEND_SLOTS],
    next_append: usize,
    append_selected: Option<usize>,
    append_exhausted: Option<ControllerBankLaunchErrorV1>,
}

impl ControllerCatalogMaintenanceReceivingV2 {
    /// Prices two complete carriers, the native interval and all eight C posts.
    ///
    /// Permanent Session/context residents remain intrinsically summed by B;
    /// the upper complete bound adds only newly retained owners and traffic.
    ///
    /// # Errors
    /// Returns checked compiled-layout or native supplier overflow.
    pub fn receiving_demand_v2(profile: &ControllerSelfProfileOriginalV1)
        -> Result<ResourceVector, ControllerBankLaunchErrorV1>
    {
        let extra = std::mem::size_of::<Self>()
            .checked_sub(std::mem::size_of::<ControllerCreateProvisioningReceivingV1>())
            .and_then(|bytes| bytes.checked_mul(2))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let mut demand = ControllerCreateProvisioningReceivingV1::receiving_demand_v1(profile)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, extra))?;
        for _ in 0..APPEND_SLOTS {
            demand = demand.checked_add(ControllerNativePostOriginalV1::receiving_demand_v1()?)?;
        }
        Ok(demand)
    }

    /// Rejoins the actual active maintenance and same C/profile/launch.
    ///
    /// # Errors
    /// Refuses another owner, failed entry, completion or purpose.
    pub fn require_current_v2<P>(&self, writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.append_selected.is_some() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.native.require_current_v1(writer, launch, profile)?;
        let base = *self.native.entry.as_ref().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
        self.native.original.require_catalog_maintenance_active_v2(base).map_err(Into::into)
    }

    /// Borrows the unique identity of this actual current maintenance interval.
    ///
    /// No new token or ordinal is allocated. The opaque result retains only
    /// strong references to the native interval's already-paid originals.
    ///
    /// # Errors
    /// Refuses any failed, completed, foreign or unentered native interval.
    pub fn identity_current_v2<P>(
        &self,
        writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<ControllerCatalogMaintenanceIdentityV2, ControllerBankLaunchErrorV1> {
        self.require_current_v2(writer, launch, profile)?;
        let turn = self.native.turn_identity.as_ref()
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        Ok(ControllerCatalogMaintenanceIdentityV2 {
            original: Arc::clone(&self.native.original),
            turn: Arc::clone(turn),
        })
    }

    /// Rejoins a retained Source identity to this same current native interval.
    ///
    /// # Errors
    /// Refuses ordinary native currentness failures or another actual interval.
    pub fn require_identity_current_v2<P>(
        &self,
        identity: &ControllerCatalogMaintenanceIdentityV2,
        writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_current_v2(writer, launch, profile)?;
        if !self.matches_identity_data_v2(identity) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(())
    }

    /// Compares original affinity after short loans and owed posts have ended.
    ///
    /// This passive equality supplies neither positive native currentness nor
    /// completion. Its caller must separately hold the genuine completed owner.
    #[must_use]
    pub fn matches_identity_data_v2(
        &self,
        identity: &ControllerCatalogMaintenanceIdentityV2,
    ) -> bool {
        Arc::ptr_eq(&self.native.original, &identity.original)
            && self.native.turn_identity.as_ref()
                .is_some_and(|turn| Arc::ptr_eq(turn, &identity.turn))
    }

    /// Raises new maintenance representation on the same cumulative B ledger.
    ///
    /// # Errors
    /// Retains geometry, currentness or genuine same-ledger refusal.
    pub fn require_complete_representation_v2<P>(&mut self,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1, complete: ResourceVector,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_current_v2(writer, launch, profile)?;
        self.native.require_complete_representation_v1(writer, launch, profile, complete)
    }

    /// Joins this active maintenance to its actual completed ordinary receiver.
    ///
    /// The upper completed-native borrower independently holds this receiver's
    /// exact protected Main and endpoint custody, and SDK verifies the actual
    /// Session/socket/transcript. This comparison adopts none of those DATA.
    /// Initial receivers require actual ordinal zero; a genuine nonzero range
    /// recipient requires the new ordinary representation and all four actual
    /// completion markers.
    /// Readonly Recover receivers never satisfy this purpose.
    ///
    /// # Errors
    /// Refuses another C/profile/role, old funding, failed receiver or unfinished
    /// before/after/endpoint custody. No IO, debit or new receiver is produced.
    pub fn require_completed_session_original_v2<P>(&self,
        actual: &crate::controller_receiving::ControllerInitialSessionReceivingOriginalV1,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        role: crate::controller_receiving::ControllerInitialBrokerSessionRoleV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_current_v2(writer, launch, profile)?;
        actual.require_completed_maintenance_original_v2(&self.native.original, role)
            .map_err(Into::into)
    }

    /// Requires the paid receipt for independent upper after observations.
    ///
    /// This negative-capable comparison performs no debit or healthy-body check.
    ///
    /// # Errors
    /// Refuses failed fixed geometry, native conjunction or initial debit.
    pub fn require_prepaid_owed_observation_v2(&self)
        -> Result<(), ControllerBankLaunchErrorV1> {
        if self.native.fixed.is_err()
            || self.native.conjunction.is_err() || self.native.entry.is_err() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(())
    }

    /// Arms the next independent C post from eight already-paid destinations.
    ///
    /// The canonical upper append still prepays actual RecordShapes, frames,
    /// indexes and future prefixes. Replay without a write consumes no slot.
    /// Existing writer finish/dispose methods retain this SAME native original.
    ///
    /// # Errors
    /// Retains the actual first entry refusal; rejects a ninth append.
    pub fn begin_append_post_once_v2<P>(&mut self,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<ControllerNativePostOriginalV1, ControllerBankLaunchErrorV1> {
        let index = self.next_append;
        if index >= APPEND_SLOTS {
            if self.append_exhausted.is_none() {
                self.append_exhausted = Some(ControllerBankLaunchErrorV1::Conflict);
            }
            if self.native.failure().is_none() { self.append_selected.get_or_insert(APPEND_SLOTS); }
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.next_append += 1;
        self.append_entries[index] = Some(self.require_current_v2(writer, launch, profile));
        if !matches!(self.append_entries[index], Some(Ok(()))) {
            if self.native.failure().is_none() { self.append_selected.get_or_insert(index); }
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        match writer.begin_independent_native_post_retaining_v2() {
            Ok(post) => {
                if post.failure().is_some() {
                    self.append_entries[index] = Some(Err(ControllerBankLaunchErrorV1::Conflict));
                    self.append_selected.get_or_insert(index);
                }
                // A failed prearm still returns its entire actual native
                // original. Its caller owes finish and retains its first cause.
                Ok(post)
            },
            Err(cause) => {
                self.append_entries[index] = Some(Err(cause));
                self.append_selected.get_or_insert(index);
                Err(ControllerBankLaunchErrorV1::Conflict)
            }
        }
    }

    /// Attempts all prearmed native posts independently of upper body refusal.
    ///
    /// # Errors
    /// Retains the original name, profile, recipient or disposal failure.
    pub fn finish_native_once_v2<P>(&mut self, writer: &mut ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        let result = self.native.finish_native_once(writer, launch, profile);
        if self.append_selected.is_some() {
            writer.fixed.fence();
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        result
    }

    /// Requires actual positive native disposal and current ordinary context.
    ///
    /// This comparison proves no catalog, Source or fresh clock success.
    ///
    /// # Errors
    /// Refuses unfinished native custody, changed C or a failed append admission.
    pub fn require_completed_original_v2<P>(&self, writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.append_selected.is_some() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.native.require_completed_original_v1(writer, launch, profile)?;
        self.native.original.require_catalog_maintenance_context_v2().map_err(Into::into)
    }

    pub(crate) fn require_source_original_v2<P>(&self,
        source: &crate::controller_receiving::ControllerSourceOriginalRefV1,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_current_v2(writer, launch, profile)?;
        self.native.require_source_original_v1(source, writer, launch, profile)
    }

    pub(crate) fn require_completed_source_original_v2(&self,
        source: &crate::controller_receiving::ControllerSourceOriginalRefV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.native.require_completed_source_original_v1(source)
    }

    /// Borrows the private profile failure only when it was the selected source.
    #[must_use]
    pub fn profile_failure_view_v2(&self)
        -> Option<crate::controller_receiving::profile::ControllerProfileFailureViewV1<'_>> {
        if self.append_selected.is_some() { return None; }
        self.native.profile_failure_view_v1()
    }

    /// Borrows the first actual native or append refusal without cloning.
    #[must_use]
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(index) = self.append_selected {
            if index == APPEND_SLOTS {
                return self.append_exhausted.as_ref().map(|cause| cause as _);
            }
            return self.append_entries[index].as_ref()
                .and_then(|returned| returned.as_ref().err()).map(|cause| cause as _);
        }
        self.native.failure()
    }
}

impl<P> ControllerCoordinatorWriterV1<P> {
    /// Begins a finite maintenance native interval on the actual current B.
    ///
    /// This supplies no clock horizon, Source success or Storage31 authority.
    #[must_use]
    pub fn begin_catalog_maintenance_receiving_v2(&mut self,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
        complete: ResourceVector,
    ) -> ControllerCatalogMaintenanceReceivingV2 {
        let native = ControllerCreateProvisioningReceivingV1::begin_purpose_v1(
            self, launch, profile, complete, ContinuationReceivingPurposeV1::CatalogMaintenance,
        );
        ControllerCatalogMaintenanceReceivingV2 {
            native, append_entries: std::array::from_fn(|_| None), next_append: 0,
            append_selected: None, append_exhausted: None,
        }
    }
}
