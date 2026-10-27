//! Issues and completes one phase against the same retained target and node.
//!
//! The claim is a private loan of an already-funded installed window. A phase
//! is spent before its member callback or Source operation. Completion consumes
//! opaque Source evidence while the same SourceRead fence remains armed through
//! the concrete bank-free member callback and final native currentness check.

use super::*;
use crate::node_adapters::cnp::{
    OriginalSourceRestoreSignerConstructionData, OriginalSourceRestoreVerifiedPhase,
    OriginalSourceRestoreVerifiedPhaseKind,
};
use crucible_node_transport::client::OriginalCompleteRestoreInputUpload;

// A closure passed to Source borrows only this fixed scope. Its callback never
// opens the runtime/node, SDK, preparation, cold, or Source association banks.
struct PhaseCompletionCurrency<'a> {
    window: &'a CompleteOriginalRestorationWindow,
    target: &'a CompleteOriginalRestorationTransactionTarget,
    source: &'a Rc<PacketCompleteSemanticSource>,
    plan: &'a InstalledConformancePlan,
    activation: &'a ActivationRecord,
}

impl PhaseCompletionCurrency<'_> {
    fn authenticate_current(&self) -> Result<(), RuntimeError> {
        self.window.authenticate_registered_target_member(
            self.target,
            self.source,
            self.plan,
            self.activation,
        )
    }
}

impl CompleteOriginalRestorationWindow {
    /// Spends a single ordered phase before returning its private Source claim.
    ///
    /// No public caller can construct or clone the returned loan. All three
    /// targets must retain the original group before the first protocol effect.
    /// A callback failure, refusal, dropped claim or unwind leaves this phase
    /// spent; only real verified evidence permits the next phase.
    pub(crate) fn begin_original_phase_claim<'a>(
        &'a self,
        plan: &'a InstalledConformancePlan,
        activation: &'a ActivationRecord,
        selected: usize,
        phase: OriginalRestorationTransactionPhase,
    ) -> Result<OriginalRestorationTransactionClaim<'a>, RuntimeError> {
        if self.targets.iter().any(|slot| slot.get().is_none()) {
            return Err(RuntimeError::OwnerUnavailable);
        }
        let target = self
            .targets
            .get(selected)
            .and_then(OnceCell::get)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let source = self
            .sources
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        self.authenticate_registered_target_identity(target, source, plan, activation)?;
        self.authenticate_producer_publication_before_prepare_data(&phase)?;
        target.begin_original_phase_data(&phase)?;
        self.authenticate_original_phase_member_data(target, source, plan, activation, &phase)?;
        Ok(OriginalRestorationTransactionClaim::from_original_window(
            self, target, source, plan, activation, phase,
        ))
    }

    pub(crate) fn original_source_signer_data<'a>(
        &'a self,
        target: &CompleteOriginalRestorationTransactionTarget,
    ) -> Result<&'a OriginalSourceRestoreSignerConstructionData, RuntimeError> {
        self.origin()?;
        let selected = target.selected_data();
        if !self
            .targets
            .get(selected)
            .and_then(OnceCell::get)
            .is_some_and(|original| std::ptr::eq(original, target))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.node_rows
            .get()
            .and_then(|rows| rows.get(selected))
            .and_then(|row| row.signer.as_ref())
            .ok_or(RuntimeError::OwnerUnavailable)
    }

    /// Advances the spent phase only from its actual opaque Source evidence.
    ///
    /// ResponseBody, a completed transport flag or a caller phase label cannot
    /// create this evidence. Source repeats the same original SDK pairs, keyed
    /// receipts, mapping, uploader ACK chain and SourceRead checks, keeping that
    /// fence armed through the currency callback. No erased callback follows
    /// its return before the fixed phase transition below.
    pub(crate) fn complete_original_verified_phase(
        &self,
        plan: &InstalledConformancePlan,
        activation: &ActivationRecord,
        target: &CompleteOriginalRestorationTransactionTarget,
        expected: &OriginalRestorationTransactionPhase,
        evidence: &OriginalSourceRestoreVerifiedPhase<'_>,
        uploaded: Option<&OriginalCompleteRestoreInputUpload>,
    ) -> Result<(), RuntimeError> {
        let source = self
            .sources
            .get(target.selected_data())
            .ok_or(RuntimeError::ForeignAuthority)?;
        self.authenticate_original_phase_member_data(target, source, plan, activation, expected)?;
        let inputs = self.original_signing_inputs_data(target, source, plan, activation)?;
        let row = self.original_source_signer_data(target)?;
        let currency = PhaseCompletionCurrency {
            window: self,
            target,
            source,
            plan,
            activation,
        };
        let actual = evidence
            .authenticate_current(&inputs, row, uploaded, || currency.authenticate_current())?;
        match (expected, actual) {
            (
                OriginalRestorationTransactionPhase::Prepare,
                OriginalSourceRestoreVerifiedPhaseKind::Prepare,
            )
            | (
                OriginalRestorationTransactionPhase::Inputs,
                OriginalSourceRestoreVerifiedPhaseKind::Inputs,
            )
            | (
                OriginalRestorationTransactionPhase::Commit,
                OriginalSourceRestoreVerifiedPhaseKind::Commit,
            ) => {}
            _ => return Err(RuntimeError::InvalidReceipt),
        }
        target.finish_original_verified_phase_data(expected)
    }

    pub(super) fn phase_counter_scratch_data() -> usize {
        size_of::<PhaseCompletionCurrency<'static>>()
            + size_of::<&PhaseCompletionCurrency<'static>>()
            + size_of::<OriginalRestorationTransactionClaim<'static>>()
            + size_of::<OriginalRestorationSigningInputs<'static>>()
            + size_of::<OriginalRestorationTransactionPhase>()
            + size_of::<OriginalSourceRestoreVerifiedPhase<'static>>()
            + size_of::<OriginalSourceRestoreVerifiedPhaseKind>()
            + size_of::<Result<OriginalSourceRestoreVerifiedPhaseKind, RuntimeError>>()
            + size_of::<Option<&OriginalCompleteRestoreInputUpload>>()
            + size_of::<Result<OriginalRestorationTransactionClaim<'static>, RuntimeError>>()
            + size_of::<Result<OriginalRestorationSigningInputs<'static>, RuntimeError>>()
            + size_of::<
                std::slice::Iter<'static, OnceCell<CompleteOriginalRestorationTransactionTarget>>,
            >()
    }
}
