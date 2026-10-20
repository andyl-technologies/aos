//! Receives four fresh ordinary Sessions after actual recovered enrollment.
//!
//! The constructor borrows the completed native enrollment association on the
//! same C/Launch/profile. It permanently prices the entire four-slot carrier
//! before entry. Each role then uses the sole native continuation engine for a
//! fresh before and independently owed after. Its Session representation and
//! native prefix remain resident after that role's positive native disposal.
//! This owner supplies no reconciliation, clock renewal, Ready or TLS grant.

use super::*;
use crate::controller_receiving::initial_session::{
    ControllerInitialBrokerSessionRoleV1 as Role, ControllerInitialSessionReceivingOriginalV1,
};
use super::recovered_enrollment::RecoveredEnrollmentAssociationV1;

#[derive(Clone, Copy)]
enum First {
    Association,
    Entry,
    Reentry,
    RoleEntry(usize),
    Geometry(usize),
    Native(usize),
    Representation(usize),
    After(usize),
    Completion(usize),
}

#[derive(Default)]
struct Slot {
    entry: Option<Result<(), ControllerBankLaunchErrorV1>>,
    geometry: Option<Result<ResourceVector, ControllerBankLaunchErrorV1>>,
    native: Option<ControllerCreateProvisioningReceivingV1>,
    representation: Option<Result<Arc<ControllerSessionRepresentationV3>, ControllerBankLaunchErrorV1>>,
    after: Option<Result<(), ControllerBankLaunchErrorV1>>,
    completion: Option<Result<(), ControllerBankLaunchErrorV1>>,
}

/// Retains the actual recovered enrollment and four once-owned Session turns.
///
/// Every failed native prefix stays in its original slot. The caller retains
/// each returned whole Session receiver. No old initial or read-only Session
/// claim, prefix, traffic or highwater is reused or reset.
#[doc(hidden)]
#[must_use]
pub struct ControllerRecoveredOrdinarySessionsOriginalV2 {
    original: Arc<ControllerReceivingOriginalV1>,
    identity: Arc<ControllerWriterIdentityV1>,
    association: Result<RecoveredEnrollmentAssociationV1, ControllerBankLaunchErrorV1>,
    entry: Result<(), ControllerReceivingErrorV1>,
    slots: [Slot; Role::COUNT],
    reentry: Option<ControllerBankLaunchErrorV1>,
    first: Option<First>,
}

impl ControllerRecoveredOrdinarySessionsOriginalV2 {
    /// Prices the full fixed four-slot carrier before its genuine construction.
    ///
    /// # Errors
    /// Refuses unrepresentable actual compiled owner/lock construction sizes.
    pub fn receiving_demand_v2() -> Result<ResourceVector, ControllerBankLaunchErrorV1> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(ControllerReceivingOriginalV1::initial_session_current_temporary_shape_v1().0))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    // The context's two whole copies cover all four inline native slots and
    // their sequential constructor overlap. Keep the same native supplier's
    // actual names, profile producers and dynamic buffers; count its inline
    // Self once through that already-paid carrier, rather than again per role.
    pub(super) fn role_native_demand_v2(profile: &ControllerSelfProfileOriginalV1)
        -> Result<ResourceVector, ControllerBankLaunchErrorV1>
    {
        let covered = std::mem::size_of::<ControllerCreateProvisioningReceivingV1>()
            .checked_mul(2).and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        ControllerCreateProvisioningReceivingV1::receiving_demand_v1(profile)?
            .checked_sub(ResourceVector::ZERO.with(D::MemoryBytes, covered)).map_err(Into::into)
    }

    /// Requires the actual same C, confirmed successor and completed association.
    ///
    /// # Errors
    /// Refuses prior entry/refusal, foreign current owners or another recipient.
    pub fn require_current_v2<P>(&self, writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.first.is_some() || self.entry.is_err()
            || !writer.fixed.has_original(&self.original)
            || !Arc::ptr_eq(writer.fixed.identity(), &self.identity)
            || !profile.has_same_baseline_original(&self.original)
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.original.require_recovered_sessions_context_current_v2()?;
        self.association.as_ref().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?
            .require_same_v1(&self.original, &self.identity)?;
        launch.require_operator_recover_current_v1(writer)
    }

    /// Begins one new ordinary role with real native before/owed-after custody.
    ///
    /// The supplied complete Session shape comes from the existing fixed/native
    /// receiver supplier; it can only add debt on the same B. Geometry and the
    /// shared representation helper are paid before allocation or Session IO.
    ///
    /// # Errors
    /// Retains repeated/out-of-order entry, foreign current owners, exhausted
    /// residual, native/profile failure or actual representation refusal.
    pub fn begin_session_receiving_once_v2<P>(&mut self,
        writer: &mut ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1, role: Role, session_fixed: ResourceVector,
    ) -> Result<ControllerInitialSessionReceivingOriginalV1, ControllerBankLaunchErrorV1> {
        let index = role.index();
        if self.slots[index].entry.is_some() {
            self.reentry.get_or_insert(ControllerBankLaunchErrorV1::Conflict);
            self.first.get_or_insert(First::Reentry);
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let current = self.require_current_v2(writer, launch, profile);
        self.slots[index].entry = Some(current.and_then(|()| {
            if self.slots.iter().enumerate().any(|(other, slot)| other != index
                && slot.entry.is_some() && !matches!(slot.completion, Some(Ok(()))))
            {
                return Err(ControllerBankLaunchErrorV1::Conflict);
            }
            Ok(())
        }));
        if !matches!(self.slots[index].entry, Some(Ok(()))) {
            self.first.get_or_insert(First::RoleEntry(index));
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.slots[index].geometry = Some(ControllerSessionRepresentationV3::demand_v1()
            .and_then(|helper| helper.checked_add(session_fixed).map_err(Into::into)));
        let complete = match self.slots[index].geometry.as_ref() {
            Some(Ok(complete)) => *complete,
            _ => {
                self.first.get_or_insert(First::Geometry(index));
                return Err(ControllerBankLaunchErrorV1::Conflict);
            }
        };
        self.slots[index].native = Some(ControllerCreateProvisioningReceivingV1::begin_purpose_v1(
            writer, launch, profile, complete, ContinuationReceivingPurposeV1::RecoveredOrdinarySession(role),
        ));
        let slot = &mut self.slots[index];
        let native = slot.native.as_ref().ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        if native.failure().is_some() {
            self.first.get_or_insert(First::Native(index));
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        slot.representation = Some(ControllerSessionRepresentationV3::from_recovered_ordinary_native_v2(
            native, profile, role, session_fixed,
        ).map(Arc::new));
        match slot.representation.as_ref() {
            Some(Ok(representation)) => Ok(ControllerInitialSessionReceivingOriginalV1::from_recovered_ordinary_v2(
                Arc::clone(&self.original), profile, Arc::clone(representation),
            )),
            _ => {
                self.first.get_or_insert(First::Representation(index));
                Err(ControllerBankLaunchErrorV1::Conflict)
            }
        }
    }

    /// Attempts the entered role's native after without a new healthy debit.
    ///
    /// This performs native disposal only. The caller independently requires
    /// its same whole SDK Session result before proceeding to another role.
    ///
    /// # Errors
    /// Retains missing/repeated entry and all independent name/profile/native
    /// post results; an earlier selected cause remains the original primary.
    pub fn finish_session_native_once_v2<P>(&mut self,
        writer: &mut ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1, role: Role,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        let index = role.index();
        let slot = &mut self.slots[index];
        if slot.after.is_some() || slot.native.is_none() {
            self.reentry.get_or_insert(ControllerBankLaunchErrorV1::Conflict);
            self.first.get_or_insert(First::Reentry);
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let native = slot.native.as_mut().ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        if native.entry.is_err() {
            // Nothing native was entered when the fixed debit refused.
            // Keep the failed envelope intact without inventing an owed IO.
            slot.after = Some(Err(ControllerBankLaunchErrorV1::Conflict));
            self.first.get_or_insert(First::Native(index));
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        slot.after = Some(native.finish_native_once(writer, launch, profile));
        if !matches!(slot.after, Some(Ok(()))) {
            self.first.get_or_insert(First::After(index));
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        slot.completion = Some((|| {
            native.require_completed_original_v1(writer, launch, profile)?;
            if !matches!(slot.representation, Some(Ok(_))) {
                return Err(ControllerBankLaunchErrorV1::Conflict);
            }
            self.original.complete_recovered_session_native_v2(role)?;
            slot.representation.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ControllerBankLaunchErrorV1::Conflict)?.require_current_v1()?;
            Ok(())
        })());
        if !matches!(slot.completion, Some(Ok(()))) {
            self.first.get_or_insert(First::Completion(index));
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(())
    }

    /// Requires all four positive native disposals on this same current context.
    ///
    /// # Errors
    /// Refuses a failed, absent or incomplete role or changed C/Launch/profile.
    pub fn require_completed_v2<P>(&self, writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_current_v2(writer, launch, profile)?;
        for slot in &self.slots {
            if !matches!(slot.completion, Some(Ok(()))) {
                return Err(ControllerBankLaunchErrorV1::Conflict);
            }
            slot.native.as_ref().ok_or(ControllerBankLaunchErrorV1::Conflict)?
                .require_completed_original_v1(writer, launch, profile)?;
            slot.representation.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ControllerBankLaunchErrorV1::Conflict)?.require_current_v1()?;
        }
        Ok(())
    }

    /// Compares the same actual role receiver without adopting a decoded model.
    ///
    /// # Errors
    /// Refuses another original, role, association or current financial owner.
    pub fn require_session_original_v2<P>(&self, actual: &ControllerInitialSessionReceivingOriginalV1,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1, role: Role,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_current_v2(writer, launch, profile)?;
        let representation = self.slots[role.index()].representation.as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        if !actual.matches_recovered_ordinary_original_v2(representation, &self.original, role) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        representation.require_current_v1().map_err(Into::into)
    }

    /// Joins historical positive four-role disposal to the same current receiver.
    ///
    /// Saved completions are actual owned results. A new finite operation may
    /// occupy the shared native profile slots, so this lender checks those
    /// historical results and the actual receiver's retained endpoint prefix,
    /// then the new context's current C/recipient/ledger association. It never
    /// presents an old profile sample as a fresh observation.
    ///
    /// # Errors
    /// Refuses any unfinished or failed role, foreign receiver, incomplete
    /// endpoint custody or changed current C/Launch/profile/funding.
    pub fn require_completed_session_original_v2<P>(&self,
        actual: &ControllerInitialSessionReceivingOriginalV1,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1, role: Role,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_current_v2(writer, launch, profile)?;
        if self.slots.iter().any(|slot| !matches!(slot.completion, Some(Ok(())))) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let representation = self.slots[role.index()].representation.as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        actual.require_completed_recovered_ordinary_v2(representation, &self.original, role)
            .map_err(Into::into)
    }

    /// Borrows a rich native profile cause only at its original selected site.
    #[must_use]
    pub fn profile_failure_view_v2(&self)
        -> Option<crate::controller_receiving::profile::ControllerProfileFailureViewV1<'_>>
    {
        let index = match self.first? {
            First::Native(index) | First::After(index) => index,
            _ => return None,
        };
        self.slots[index].native.as_ref()?.profile_failure_view_v1()
    }

    /// Borrows only the first retained native or financial failure.
    #[must_use]
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Association => self.association.as_ref().err().map(|cause| cause as _),
            First::Entry => self.entry.as_ref().err().map(|cause| cause as _),
            First::Reentry => self.reentry.as_ref().map(|cause| cause as _),
            First::RoleEntry(index) => cause(&self.slots[index].entry),
            First::Geometry(index) => cause(&self.slots[index].geometry),
            First::Native(index) => self.slots[index].native.as_ref()?.failure(),
            First::Representation(index) => cause(&self.slots[index].representation),
            First::After(index) => self.slots[index].native.as_ref()?.failure()
                .or_else(|| cause(&self.slots[index].after)),
            First::Completion(index) => cause(&self.slots[index].completion),
        }
    }
}

impl<P> ControllerCoordinatorWriterV1<P> {
    /// Constructs the finite four-role context from actual completed enrollment.
    ///
    /// # Errors
    /// The whole returned owner retains association or same-B entry refusal.
    /// This native constructor proves no Source/clock/reconciliation semantics.
    #[must_use]
    pub fn begin_recovered_ordinary_sessions_once_v2(&self,
        enrolled: &ControllerRecoveredEnrollmentReceivingV2,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
    ) -> ControllerRecoveredOrdinarySessionsOriginalV2 {
        let association = enrolled.completed_association_v1(self, launch, profile);
        let entry = (|| {
            association.as_ref().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
            let complete = ControllerRecoveredOrdinarySessionsOriginalV2::receiving_demand_v2()
                .map_err(|_| ControllerReceivingErrorV1::Conflict)?;
            self.fixed.original().begin_recovered_sessions_context_v2(complete)
        })();
        let first = if association.is_err() { Some(First::Association) }
            else { entry.is_err().then_some(First::Entry) };
        ControllerRecoveredOrdinarySessionsOriginalV2 {
            original: Arc::clone(self.fixed.original()), identity: Arc::clone(self.fixed.identity()),
            association, entry, slots: std::array::from_fn(|_| Slot::default()), reentry: None, first,
        }
    }
}

fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_context_prepays_all_four_native_slots_and_sequential_constructor_overlap() {
        let context = std::mem::size_of::<ControllerRecoveredOrdinarySessionsOriginalV2>();
        let native = std::mem::size_of::<ControllerCreateProvisioningReceivingV1>();
        assert!(context >= Role::COUNT * native);
        assert!(2 * context >= context + 2 * native);
        assert!(ControllerRecoveredOrdinarySessionsOriginalV2::receiving_demand_v2().unwrap()
            .get(D::MemoryBytes) >= u64::try_from(2 * context).unwrap());
    }
}
