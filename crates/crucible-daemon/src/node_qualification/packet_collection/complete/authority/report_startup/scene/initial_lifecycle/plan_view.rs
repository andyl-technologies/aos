//! Checks one original plan view between complete outer file measurements.
//!
//! The borrowed interval has no callback entry point and grants no execution
//! permission. It owns only this installed authority's two fixed currentness
//! bodies and concrete plan comparisons. All original Source/Host checks remain
//! in order; the two interior boundaries omit only their duplicate file reads.

use super::*;
use std::{cell::Ref, mem::size_of};

/// Borrows the authority after its actual selector and complete entry read.
struct OriginalPlanViewInterval<'a> {
    authority: &'a InstalledPacketCompleteCollectionAuthority,
    holder: Ref<'a, PacketCompleteReportStartupHolder>,
}

impl InstalledPacketCompleteCollectionAuthority {
    /// Reauthenticates a concrete plan view within one selected original callback.
    ///
    /// The enclosing original host/runtime/fresh construction admission includes
    /// this module's controls through `original_initial_callback_transient_data`
    /// before any callback work. This method issues no admission of its own.
    ///
    /// # Errors
    /// Preserves the first selector, currentness or plan mismatch diagnostic.
    /// Always reads terminal file currency after an entered body, including on
    /// failure; a terminal refusal is returned only after the body succeeds.
    /// File drift at an omitted interior read is observed at the outer terminal
    /// read. A plan mismatch then remains primary even if the old interior read
    /// might have detected that concurrent drift before the comparison.
    pub(in crate::node_qualification::packet_collection::complete::authority) fn authenticate_original_plan_view_interval_data(
        &self,
        plan: ConformancePlanEvidence<'_>,
    ) -> Result<(), EvidenceError> {
        if !self.original_initial_callback_active.get() {
            return Err(evidence_error(refused()));
        }
        let original = self
            .report_startup_holder
            .get()
            .and_then(std::rc::Weak::upgrade)
            .ok_or_else(|| evidence_error(refused()))?;
        let holder = original
            .try_borrow()
            .map_err(|_| evidence_error(refused()))?;
        let interval = OriginalPlanViewInterval::begin(self, holder)?;
        let checked = interval.authenticate_body_data(plan);
        interval.finish(checked)
    }
}

impl<'a> OriginalPlanViewInterval<'a> {
    fn begin(
        authority: &'a InstalledPacketCompleteCollectionAuthority,
        holder: Ref<'a, PacketCompleteReportStartupHolder>,
    ) -> Result<Self, EvidenceError> {
        authenticate_selection_data(&holder).map_err(evidence_error)?;
        authority
            .graph_policy
            .read_original_initial_callback_data()
            .map_err(callback_error)?;
        Ok(Self { authority, holder })
    }

    fn authenticate_body_data(
        &self,
        plan: ConformancePlanEvidence<'_>,
    ) -> Result<(), EvidenceError> {
        let authority = self.authority;
        authority
            .authenticate_original_initial_callback_body_data()
            .map_err(callback_error)?;
        // This is the first currentness call's former terminal boundary. Keep
        // its parent guards even though the outer terminal read measures files.
        authority
            .graph_policy
            .authenticate_original_initial_callback_parents_data()
            .map_err(callback_error)?;

        let original = authority.plan_evidence();
        if plan.plan_ref != original.plan_ref
            || plan.plan_bytes != original.plan_bytes
            || plan.refused_ref != original.refused_ref
            || plan.refused_bytes != original.refused_bytes
            || plan.world != original.world
            || plan.sources != original.sources
        {
            return Err(evidence_error(refused()));
        }

        // The fixed comparison above invokes no callbacks. Repeat the actual
        // second selector/origin check; this borrow is not a reusable permission.
        if !authority.original_initial_callback_active.get() {
            return Err(evidence_error(refused()));
        }
        let original = authority
            .report_startup_holder
            .get()
            .and_then(std::rc::Weak::upgrade)
            .ok_or_else(|| evidence_error(refused()))?;
        let held = original
            .try_borrow()
            .map_err(|_| evidence_error(refused()))?;
        authenticate_selection_data(&held).map_err(evidence_error)?;
        // This is the second currentness call's former entry boundary.
        authority
            .graph_policy
            .authenticate_original_initial_callback_parents_data()
            .map_err(callback_error)?;
        authority
            .authenticate_original_initial_callback_body_data()
            .map_err(callback_error)
    }

    fn finish(self, checked: Result<(), EvidenceError>) -> Result<(), EvidenceError> {
        let terminal = self
            .authority
            .graph_policy
            .read_original_initial_callback_data();
        // The original shared holder loan remains live through the terminal
        // read; only then may the final diagnostic be returned to its caller.
        drop(self.holder);
        match checked {
            Err(error) => Err(error),
            Ok(()) => terminal.map_err(callback_error),
        }
    }
}

fn authenticate_selection_data(
    held: &PacketCompleteReportStartupHolder,
) -> Result<(), QualificationError> {
    let selected = held.runtime_in_flight.get().is_some()
        || held
            .host_initial_lifecycle_in_flight_data()
            .map_err(|_| refused())?;
    if !selected {
        return Err(refused());
    }
    held.authenticate_native_origin_data()
        .map_err(|_| refused())
}

fn callback_error(_: RuntimeError) -> EvidenceError {
    evidence_error(QualificationError::Refused(INITIAL_CALLBACK_REFUSAL))
}

/// Names concrete controls additional to the complete currentness producer row.
///
/// The outer holder borrow spans the complete interval; the second selector's
/// own shared borrow can coexist with it. Both actual views are named below.
/// The original diagnostic row funds one primary String.
/// A failed body retains that same EvidenceError while the terminal raw status
/// is observed and dropped; no secondary diagnostic bank is constructed.
pub(super) const fn counter_scratch_data() -> usize {
    size_of::<OriginalPlanViewInterval<'_>>()
        + size_of::<OriginalPlanViewInterval<'_>>()
        + size_of::<Result<OriginalPlanViewInterval<'_>, EvidenceError>>()
        + size_of::<&InstalledPacketCompleteCollectionAuthority>()
        + size_of::<&InstalledPacketCompleteCollectionAuthority>()
        + size_of::<&OriginalPlanViewInterval<'_>>()
        + size_of::<ConformancePlanEvidence<'_>>()
        + size_of::<ConformancePlanEvidence<'_>>()
        + size_of::<ConformancePlanEvidence<'_>>()
        + size_of::<&ContentRef>()
        + size_of::<&ContentRef>()
        + size_of::<&[u8]>()
        + size_of::<&[u8]>()
        + size_of::<&HashRef>()
        + size_of::<&HashRef>()
        + size_of::<&[ContentRef]>()
        + size_of::<&[ContentRef]>()
        // Fixed body return, retained checked local, finish argument/output,
        // selected caller return, and concrete plan-view delegation return.
        + size_of::<Result<(), EvidenceError>>()
        + size_of::<Result<(), EvidenceError>>()
        + size_of::<Result<(), EvidenceError>>()
        + size_of::<Result<(), EvidenceError>>()
        + size_of::<Result<(), EvidenceError>>()
        + size_of::<Result<(), EvidenceError>>()
        // Both fixed bodies, their parent boundary returns, and terminal status
        // use these sequential raw controls; the final raw status can coexist
        // with the retained first diagnostic.
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<RuntimeError>()
        + size_of::<EvidenceError>()
        + size_of::<Result<(), QualificationError>>()
        + size_of::<QualificationError>()
        // Both selectors use the same transient borrowed Weak views in
        // sequence. The outer original Rc/Ref remain live during the second
        // upgrade and borrow, so both locals and actual mapped results follow.
        + size_of::<Option<&std::rc::Weak<RefCell<PacketCompleteReportStartupHolder>>>>()
        + size_of::<&std::rc::Weak<RefCell<PacketCompleteReportStartupHolder>>>()
        + size_of::<Option<Rc<RefCell<PacketCompleteReportStartupHolder>>>>()
        + size_of::<Rc<RefCell<PacketCompleteReportStartupHolder>>>()
        + size_of::<Result<Rc<RefCell<PacketCompleteReportStartupHolder>>, EvidenceError>>()
        + size_of::<Option<Rc<RefCell<PacketCompleteReportStartupHolder>>>>()
        + size_of::<Rc<RefCell<PacketCompleteReportStartupHolder>>>()
        + size_of::<Result<Rc<RefCell<PacketCompleteReportStartupHolder>>, EvidenceError>>()
        + size_of::<Ref<'_, PacketCompleteReportStartupHolder>>()
        + size_of::<Result<Ref<'_, PacketCompleteReportStartupHolder>, std::cell::BorrowError>>()
        + size_of::<Result<Ref<'_, PacketCompleteReportStartupHolder>, EvidenceError>>()
        + size_of::<Ref<'_, PacketCompleteReportStartupHolder>>()
        + size_of::<Result<Ref<'_, PacketCompleteReportStartupHolder>, std::cell::BorrowError>>()
        + size_of::<Result<Ref<'_, PacketCompleteReportStartupHolder>, EvidenceError>>()
        + size_of::<&PacketCompleteReportStartupHolder>()
        + size_of::<&Ref<'_, PacketCompleteReportStartupHolder>>()
        + size_of::<std::cell::BorrowError>()
        + size_of::<bool>()
        + size_of::<Result<bool, RuntimeError>>()
        + size_of::<Result<bool, QualificationError>>()
        + size_of::<Option<crucible::node_admission::OriginalRuntimeConstructionPhase>>()
        // Own defining counter return and its addition to the enclosing row.
        + size_of::<usize>()
        + size_of::<usize>()
        + size_of::<[usize; 5]>()
        + size_of::<std::array::IntoIter<usize, 5>>()
        + size_of::<Result<usize, RuntimeError>>()
}

#[cfg(test)]
mod tests;
