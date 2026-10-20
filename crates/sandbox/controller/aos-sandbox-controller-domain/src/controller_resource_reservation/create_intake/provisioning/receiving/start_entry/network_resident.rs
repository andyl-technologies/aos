//! Keeps completed Network Session representation in the same Start's next turn.
//!
//! This handoff records accounting DATA after the actual opening, C and Root
//! posts. It grants no request or receiving authority. The next genuine native
//! entry must pay the resulting complete resident base before further IO.

use super::*;
use super::network_opening::StartResourceSessionOpeningOriginalV2;
use crate::normal_root::RootHostLaunchClientOriginalV1;

/// Names the actual completed SDK Session's non-traffic resident shape.
///
/// The sole Runtime caller obtains these three values from that SDK owner's
/// completed_receiving_demand_v4 after the same native association has closed.
/// They exclude HELLO traffic and Output; no prior charge becomes a credit.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct StartResourceSessionResidentShapeDataV4 {
    /// Actual retained SDK model/native byte backing with conservative peaks.
    pub memory_bytes: u64,
    /// Actual retained native descriptors or their conservative fixed peak.
    pub open_files: u64,
    /// Actual named endpoint, proc, socket and initialization entries.
    pub namespace_entries: u64,
}

impl AcceptedStartEntryOriginalV1 {
    /// Retains the same completed Session's cost before entering the next IO turn.
    ///
    /// The actual final held-Journal sample and Domain completion owners supply
    /// their own native/semantic/schema planes intrinsically. The SDK argument
    /// supplies only its private surviving model and native planes. This method
    /// performs no IO, parser work, new debit or deadline renewal.
    ///
    /// # Errors
    /// Retains reentry, missing real SDK/native disposal, changed Start/Root/C
    /// association, incomplete independent posts or checked geometry overflow.
    pub fn retain_completed_network_session_once_v4(
        &mut self,
        opening: &StartResourceSessionOpeningOriginalV2,
        root: &RootHostLaunchClientOriginalV1,
        controller: &Journal,
        sdk: StartResourceSessionResidentShapeDataV4,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.retain_completed_resource_session_once_v4(resource_state::StartResourceKindV2::Network,
            opening, root, controller, sdk)
    }

    /// Retains the actual Mount Session after its separate four-purpose opening posts.
    ///
    /// # Errors
    /// Refuses changed purpose, missing native completion, reentry or overflow.
    pub fn retain_completed_mount_session_once_v4(
        &mut self,
        opening: &StartResourceSessionOpeningOriginalV2,
        root: &RootHostLaunchClientOriginalV1,
        controller: &Journal,
        sdk: StartResourceSessionResidentShapeDataV4,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.retain_completed_resource_session_once_v4(resource_state::StartResourceKindV2::Mount,
            opening, root, controller, sdk)
    }

    fn retain_completed_resource_session_once_v4(
        &mut self,
        kind: resource_state::StartResourceKindV2,
        opening: &StartResourceSessionOpeningOriginalV2,
        root: &RootHostLaunchClientOriginalV1,
        controller: &Journal,
        sdk: StartResourceSessionResidentShapeDataV4,
    ) -> Result<(), ResourceReservationErrorV1> {
        if opening.actual_role_v2() != kind.role_v2() { return Err(CLOSED); }
        let state = self.native_state.as_ref().ok_or(CLOSED)?;
        if state.resources.member_v2(kind).session_resident.is_some() {
            return Err(CLOSED);
        }
        let parent = self.body.plan_v1()?.operation_id();
        let native_turn = state.native_turn;
        let complete: Result<ResourceVector, ResourceReservationErrorV1> = (|| {
            root.require_completed_resource_opening_v4(kind.purpose_v2(), self, controller, parent, native_turn)?;
            let identity = self.identity.as_ref().map_err(|_| CLOSED)?;
            let sdk = ResourceVector::ZERO
                .with(D::MemoryBytes, sdk.memory_bytes)
                .with(D::OpenFiles, sdk.open_files)
                .with(D::MetadataEntries, sdk.namespace_entries);
            let resident = opening.completed_resident_receiving_demand_v4(
                identity, parent, native_turn, &state.profile, sdk,
            )?;
            Ok(resident)
        })();

        let state = self.native_state.as_mut().ok_or(CLOSED)?;
        state.resources.member_mut_v2(kind).session_resident = Some(complete);
        let Some(Ok(_)) = state.resources.member_v2(kind).session_resident.as_ref() else {
            state.first.get_or_insert(FirstV1::ResourceSessionResident(kind));
            return Err(CLOSED);
        };
        Ok(())
    }
}

const CLOSED: ResourceReservationErrorV1 = ResourceReservationErrorV1::Conflict;
