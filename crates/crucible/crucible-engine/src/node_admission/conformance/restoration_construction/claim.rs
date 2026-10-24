//! Borrows one actual installed restoration phase without a final context.
//!
//! The private constructor belongs to the genuine installed window. A claim
//! is consumed by one Source operation; dropping it cannot reset the window's
//! spent phase or the original archive's target transaction ledger.

use super::*;
use crucible_node_transport::{
    client::OriginalFreshRestoreQuery, protocol_snapshot::PreparedArchivedProtocolMapping,
    reference_packet::service::complete_restore::transfer::PacketCompleteRestoreInputAllocation,
};

/// Names the three ordered effects of one original once-only transaction.
pub(crate) enum OriginalRestorationTransactionPhase {
    Prepare,
    Inputs,
    Commit,
}

/// Borrows the authenticated originals for Source-derived request construction.
///
/// This view is returned only by an opaque claim after its member check. It is
/// not publicly constructible, portable, Clone, a MAC, an installed grant or a
/// final lineage context. The journal is the actual owned cold group's journal.
pub(crate) struct OriginalRestorationSigningInputs<'a> {
    pub(crate) source: &'a Rc<PacketCompleteSemanticSource>,
    pub(crate) archive: &'a CompleteOriginalRestorationSource,
    pub(crate) ticket: &'a CompleteOriginalNativeTicket,
    pub(crate) plan: &'a InstalledConformancePlan,
    pub(crate) activation: &'a ActivationRecord,
    pub(crate) journal: &'a crate::node_adapters::cnp::PacketCompleteSettledJournal,
    pub(crate) journal_reference: &'a ContentRef,
    pub(crate) capture_terminal: &'a crucible_node_transport::envelope::Envelope,
    pub(crate) mapping: &'a PreparedArchivedProtocolMapping,
    pub(crate) native_allocation: &'a PacketCompleteRestoreInputAllocation,
    pub(crate) prepare_id: &'a Id,
    pub(crate) commit_id: &'a Id,
    // The actual window's observation precedes the Source association loan.
    // This bound includes all other retained owners and prepaid phase growth;
    // the archive constructor independently recounts its own captured owners.
    pub(crate) maximum_record_bytes: usize,
    pub(crate) observed_other_retained_bytes: usize,
}

/// Borrows the genuine completed cold owners before a future mapping exists.
pub(crate) struct OriginalRestorationMappingInputs<'a> {
    pub(crate) source: &'a Rc<PacketCompleteSemanticSource>,
    pub(crate) plan: &'a InstalledConformancePlan,
    pub(crate) host: &'a crucible_node_transport::protocol_snapshot::owned11::outer::SealedHistoricalControllerState,
    pub(crate) native: std::cell::Ref<'a, crucible_node_transport::protocol_snapshot::owned11::native::outer::SealedHistoricalNativeState>,
    pub(crate) host_reference: &'a ContentRef,
    pub(crate) native_reference: &'a ContentRef,
}

/// Lends one already-admitted, once-started phase on its same actual target.
///
/// There is no public constructor, deserializer, Clone, bool conversion or
/// final-context conversion. Core's private window retains all partial owners
/// and consumes the phase before creating this loan. Query is deliberately not
/// a field: its sole frontier is checked before Prepare only; later phases
/// authenticate the actual retained Prepare pair and Source receipt instead.
#[must_use = "consume the original phase through its same Source and node"]
pub(crate) struct OriginalRestorationTransactionClaim<'a> {
    window: &'a CompleteOriginalRestorationWindow,
    target: &'a CompleteOriginalRestorationTransactionTarget,
    source: &'a Rc<PacketCompleteSemanticSource>,
    plan: &'a InstalledConformancePlan,
    activation: &'a ActivationRecord,
    phase: OriginalRestorationTransactionPhase,
}

impl<'a> OriginalRestorationTransactionClaim<'a> {
    pub(super) fn from_original_window(
        window: &'a CompleteOriginalRestorationWindow,
        target: &'a CompleteOriginalRestorationTransactionTarget,
        source: &'a Rc<PacketCompleteSemanticSource>,
        plan: &'a InstalledConformancePlan,
        activation: &'a ActivationRecord,
        phase: OriginalRestorationTransactionPhase,
    ) -> Self {
        Self {
            window,
            target,
            source,
            plan,
            activation,
            phase,
        }
    }

    pub(crate) fn original_source_data(&self) -> &'a Rc<PacketCompleteSemanticSource> {
        self.source
    }

    pub(crate) fn original_target_data(&self) -> &'a CompleteOriginalRestorationTransactionTarget {
        self.target
    }

    pub(crate) fn original_window_data(&self) -> &'a CompleteOriginalRestorationWindow {
        self.window
    }

    pub(crate) fn original_plan_data(&self) -> &'a InstalledConformancePlan {
        self.plan
    }

    pub(crate) fn original_activation_data(&self) -> &'a ActivationRecord {
        self.activation
    }
}

impl OriginalRestorationTransactionClaim<'_> {
    /// Repeats the actual bank-free installed member and terminal live fence.
    ///
    /// The concrete member callback runs before the final scheduler check, so
    /// revocation followed by Ok cannot disarm the currentness guard. Source
    /// consumers additionally keep their SAME bounded SourceRead guard armed
    /// through this check and final kernel/executable/source-MAC checks.
    pub(crate) fn authenticate_current(&self) -> Result<(), RuntimeError> {
        self.window.authenticate_original_phase_member_data(
            self.target,
            self.source,
            self.plan,
            self.activation,
            &self.phase,
        )?;
        self.window
            .authenticate_original_runtime_member_current_data(&self.activation.world_binding_hash)
    }

    pub(crate) fn phase(&self) -> &OriginalRestorationTransactionPhase {
        &self.phase
    }

    pub(crate) fn original_inputs_data(
        &self,
    ) -> Result<OriginalRestorationSigningInputs<'_>, RuntimeError> {
        self.authenticate_current()?;
        self.window.original_signing_inputs_data(
            self.target,
            self.source,
            self.plan,
            self.activation,
        )
    }

    /// Claims the one prospective mapping step within this genuine Prepare phase.
    pub(crate) fn begin_original_mapping_data(&self) -> Result<(), RuntimeError> {
        if !matches!(self.phase, OriginalRestorationTransactionPhase::Prepare) {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.authenticate_current()?;
        self.target.begin_original_mapping_data()?;
        self.authenticate_current()
    }

    /// Borrows genuine sealed mapping inputs without requiring a future mapping.
    pub(crate) fn original_mapping_inputs_data(
        &self,
    ) -> Result<OriginalRestorationMappingInputs<'_>, RuntimeError> {
        if !matches!(self.phase, OriginalRestorationTransactionPhase::Prepare) {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.authenticate_current()?;
        self.window
            .original_mapping_inputs_data(self.target, self.source, self.plan)
    }

    /// Borrows the actual five archived banks and target-owned mapping bank.
    ///
    /// Only the Inputs phase may obtain this effect-bearing loan. The window
    /// checks the same actual ticket/journal/mapping/assigned Prepare identity;
    /// Source and SDK still verify keyed Prepare receipt and all six references
    /// before publication. No caller byte slice supplies an input role.
    pub(crate) fn original_input_bodies_data(&self) -> Result<[&[u8]; 6], RuntimeError> {
        if !matches!(self.phase, OriginalRestorationTransactionPhase::Inputs) {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.authenticate_current()?;
        self.window.original_input_bodies_data(self.target)
    }

    /// Checks the actual sole completed Query before any Prepare traffic.
    pub(crate) fn authenticate_original_prepare_query_data(
        &self,
        controller: &crucible_node_transport::client::CnpController,
        emitter: &crucible_node_transport::client::OriginalCanonicalBlobAckEmitter,
        query: &OriginalFreshRestoreQuery,
    ) -> Result<(), RuntimeError> {
        if !matches!(self.phase, OriginalRestorationTransactionPhase::Prepare) {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.authenticate_current()?;
        self.window.authenticate_original_prepare_query_data(
            self.target,
            controller,
            emitter,
            query,
        )?;
        self.authenticate_current()
    }
}
