//! Lends separately admitted activation originals beneath a real complete context.
//!
//! Claims own only a weak association to the same retained Window. Issuance
//! spends a closed phase before any Source effect. A Source-produced evidence
//! loan, not a response DTO or success flag, must authenticate the actual
//! original/terminal pair before Core advances the retained phase ledger.

use super::*;
use crate::node_adapters::cnp::{
    OriginalSourceRestorationActivationConstructionData,
    OriginalSourceRestoreSignerConstructionData,
};
use crate::node_contract::OriginalLineageNativeScope;
use crucible_node_transport::{
    client::OriginalCompleteRestoreInputUpload,
    reference_packet::service::complete_restore::{
        PacketNativeRestoredCommitHold,
        activation::OriginalInstalledRestorationActivationConstructionData,
    },
};
use std::{mem::size_of, thread::ThreadId};

/// Names one separately admitted effect of an installed restoration.
///
/// The value classifies a phase. It cannot issue a claim or authenticate an
/// original, native held state, completed world, scope proof or resource row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginalInstalledRestorationActivationPhase {
    /// Arms the actual restored node while its physical gate remains held.
    Arm,
    /// Publishes the actual held-false continuation before releasing its gate.
    WorldActivate,
}

/// Retains one once-started activation beneath its actual complete Window.
///
/// There is no public constructor, Clone, deserializer or portable authority
/// representation. Dropping a claim cannot reset its Window's spent phase.
/// The registered holder keeps the original Window and partial native/Source
/// owners alive through cleanup; a weak association never extends that lifetime.
#[must_use = "retain the same Window and partial activation owners through failure"]
pub struct OriginalInstalledRestorationActivationClaim {
    process: u32,
    thread: ThreadId,
    window: Weak<CompleteOriginalRestorationWindow>,
    selected: usize,
    phase: OriginalInstalledRestorationActivationPhase,
    proof_identity: [u8; 32],
}

/// Lends actual pre-Prepare originals for a prospective Source-only quote.
///
/// The future scope reference is priced from its compiled ContentRef grammar;
/// no fabricated scope or future proof is a field of this DATA view. Neither
/// the existing transfer inputs nor the independently quoted activation row
/// admits allocation, signing, parsing, native effects or context issuance.
pub(crate) struct OriginalInstalledRestorationActivationSigningConstructionInputs<'a> {
    pub(crate) transfer: &'a OriginalRestorationSigningConstructionInputs<'a>,
    pub(crate) activation_data: &'a OriginalInstalledRestorationActivationConstructionData,
    pub(crate) request_ids: [&'a Id; 2],
    pub(crate) signer: &'a OriginalSourceRestoreSignerConstructionData,
    pub(crate) coordinator: &'a OriginalRestorationCoordinatorConstructionData,
}

/// Lends genuine completed originals within one unit-valued Window callback.
///
/// This view cannot escape the callback or retain a Window/Controller owner.
/// Source first authenticates the real completed Commit/Hold in an immutable
/// Controller loan, drops that loan, and only then prepares its mutable send.
pub(crate) struct OriginalInstalledRestorationActivationSigningInputs<'a> {
    pub(crate) transfer: OriginalRestorationSigningInputs<'a>,
    pub(crate) inspection: OriginalRestorationTransactionInspection<'a>,
    pub(crate) signer: &'a OriginalSourceRestoreSignerConstructionData,
    pub(crate) uploaded: &'a OriginalCompleteRestoreInputUpload,
    pub(crate) scope: &'a OriginalLineageNativeScope,
    pub(crate) scope_proof: &'a ContentRef,
    pub(crate) scope_proof_body: &'a [u8],
    pub(crate) activation_data: &'a OriginalInstalledRestorationActivationConstructionData,
    pub(crate) source_construction: &'a OriginalSourceRestorationActivationConstructionData,
    pub(crate) phase: OriginalInstalledRestorationActivationPhase,
    pub(crate) request_id: &'a Id,
    pub(crate) world: Option<&'a crate::node_contract::WorldActivation>,
    pub(super) window: &'a CompleteOriginalRestorationWindow,
    pub(super) selected: usize,
}

impl OriginalInstalledRestorationActivationSigningInputs<'_> {
    /// Compares actual reauthenticated held evidence with the fourth-owner proof.
    ///
    /// Source separately checks its full keyed Commit, captured references,
    /// target and context under SourceRead before invoking this comparison.
    pub(crate) fn authenticate_original_activation_hold_data(
        &self,
        held: &PacketNativeRestoredCommitHold,
        reference: &ContentRef,
    ) -> Result<(), RuntimeError> {
        self.window.authenticate_original_activation_hold_data(
            self.selected,
            self.scope,
            held,
            reference,
        )
    }
}

impl OriginalInstalledRestorationActivationClaim {
    pub(super) fn from_original_window(
        window: &Rc<CompleteOriginalRestorationWindow>,
        selected: usize,
        phase: OriginalInstalledRestorationActivationPhase,
        proof_identity: [u8; 32],
    ) -> Self {
        Self {
            process: std::process::id(),
            thread: std::thread::current().id(),
            window: Rc::downgrade(window),
            selected,
            phase,
            proof_identity,
        }
    }

    fn origin(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(crate) fn phase_data(&self) -> OriginalInstalledRestorationActivationPhase {
        self.phase
    }

    /// Checks only actual registered identities and the terminal live member.
    ///
    /// This deliberately opens no Source association, Controller or node bank.
    /// Source must keep its ReadCall armed across this callback and repeat its
    /// native kernel/registrar fence afterward. It authenticates the actual
    /// Controller/Commit itself; this method never accepts copied evidence.
    pub(crate) fn authenticate_current(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        let window = self
            .window
            .upgrade()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        window.authenticate_original_activation_member_data(
            self.selected,
            source,
            self.phase,
            self.proof_identity,
        )
    }

    /// Lends same-Window signing originals without returning an extractable owner.
    pub(crate) fn with_original_activation_signing_inputs_data(
        &self,
        source: &PacketCompleteSemanticSource,
        inspect: impl FnOnce(
            &OriginalInstalledRestorationActivationSigningInputs<'_>,
        ) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        self.authenticate_current(source)?;
        let window = self
            .window
            .upgrade()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        window.with_original_activation_signing_inputs_data(
            self.selected,
            source,
            self.phase,
            self.proof_identity,
            inspect,
        )?;
        self.authenticate_current(source)
    }

    pub(crate) fn counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<Rc<CompleteOriginalRestorationWindow>>()
            + size_of::<Option<Rc<CompleteOriginalRestorationWindow>>>()
            + size_of::<Result<Rc<CompleteOriginalRestorationWindow>, RuntimeError>>()
            + size_of::<OriginalInstalledRestorationActivationSigningInputs<'static>>()
            + size_of::<OriginalInstalledRestorationActivationSigningConstructionInputs<'static>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Result<OriginalInstalledRestorationActivationPhase, RuntimeError>>()
            + size_of::<OriginalSourceRestorationActivationConstructionData>()
            + size_of::<Result<OriginalSourceRestorationActivationConstructionData, RuntimeError>>()
            + size_of::<Result<&OriginalSourceRestorationActivationConstructionData, RuntimeError>>(
            )
            + size_of::<Result<OriginalInstalledRestorationActivationClaim, RuntimeError>>()
            + size_of::<Option<&crate::node_contract::WorldActivation>>()
            + size_of::<Result<&crate::node_contract::WorldActivation, RuntimeError>>()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ActivationStage {
    Unissued,
    ArmStarted,
    ArmVerified,
    WorldStarted,
    WorldVerified,
    Failed,
}

pub(super) struct OriginalInstalledRestorationActivationLedger(std::cell::Cell<ActivationStage>);

impl OriginalInstalledRestorationActivationLedger {
    pub(super) fn new() -> Self {
        Self(std::cell::Cell::new(ActivationStage::Unissued))
    }

    pub(super) fn begin(
        &self,
        phase: OriginalInstalledRestorationActivationPhase,
    ) -> Result<(), RuntimeError> {
        let (expected, started) = match phase {
            OriginalInstalledRestorationActivationPhase::Arm => {
                (ActivationStage::Unissued, ActivationStage::ArmStarted)
            }
            OriginalInstalledRestorationActivationPhase::WorldActivate => {
                (ActivationStage::ArmVerified, ActivationStage::WorldStarted)
            }
        };
        if self.0.replace(ActivationStage::Failed) != expected {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.0.set(started);
        Ok(())
    }

    pub(super) fn verified_phase_data(
        &self,
    ) -> Result<Option<OriginalInstalledRestorationActivationPhase>, RuntimeError> {
        match self.0.get() {
            ActivationStage::Unissued => Ok(None),
            ActivationStage::ArmVerified => {
                Ok(Some(OriginalInstalledRestorationActivationPhase::Arm))
            }
            ActivationStage::WorldVerified => Ok(Some(
                OriginalInstalledRestorationActivationPhase::WorldActivate,
            )),
            ActivationStage::ArmStarted
            | ActivationStage::WorldStarted
            | ActivationStage::Failed => Err(RuntimeError::OutstandingObligations),
        }
    }

    pub(super) fn authenticate_retained_phase_data(
        &self,
        phase: OriginalInstalledRestorationActivationPhase,
    ) -> Result<(), RuntimeError> {
        let matches = match phase {
            OriginalInstalledRestorationActivationPhase::Arm => matches!(
                self.0.get(),
                ActivationStage::ArmStarted | ActivationStage::ArmVerified
            ),
            OriginalInstalledRestorationActivationPhase::WorldActivate => matches!(
                self.0.get(),
                ActivationStage::WorldStarted | ActivationStage::WorldVerified
            ),
        };
        if !matches {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    pub(super) fn is_verified(&self, phase: OriginalInstalledRestorationActivationPhase) -> bool {
        matches!(
            (self.0.get(), phase),
            (
                ActivationStage::ArmVerified,
                OriginalInstalledRestorationActivationPhase::Arm
            ) | (
                ActivationStage::WorldVerified,
                OriginalInstalledRestorationActivationPhase::WorldActivate
            )
        )
    }

    pub(super) fn authenticate_started(
        &self,
        phase: OriginalInstalledRestorationActivationPhase,
    ) -> Result<(), RuntimeError> {
        let expected = match phase {
            OriginalInstalledRestorationActivationPhase::Arm => ActivationStage::ArmStarted,
            OriginalInstalledRestorationActivationPhase::WorldActivate => {
                ActivationStage::WorldStarted
            }
        };
        if self.0.get() != expected {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    // Only the Window's opaque Source-evidence consumer calls this transition.
    // No erased callback or allocation follows the terminal SourceRead fence.
    pub(super) fn complete_verified(
        &self,
        phase: OriginalInstalledRestorationActivationPhase,
    ) -> Result<(), RuntimeError> {
        self.authenticate_started(phase)?;
        self.0.set(match phase {
            OriginalInstalledRestorationActivationPhase::Arm => ActivationStage::ArmVerified,
            OriginalInstalledRestorationActivationPhase::WorldActivate => {
                ActivationStage::WorldVerified
            }
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_arm_or_swallowed_duplicate_cannot_issue_world_activation() {
        let missing = OriginalInstalledRestorationActivationLedger::new();
        assert!(
            missing
                .begin(OriginalInstalledRestorationActivationPhase::WorldActivate)
                .is_err()
        );
        assert!(
            missing
                .begin(OriginalInstalledRestorationActivationPhase::Arm)
                .is_err()
        );

        let interrupted = OriginalInstalledRestorationActivationLedger::new();
        interrupted
            .begin(OriginalInstalledRestorationActivationPhase::Arm)
            .unwrap();
        assert!(
            interrupted
                .begin(OriginalInstalledRestorationActivationPhase::Arm)
                .is_err()
        );
        assert!(
            interrupted
                .complete_verified(OriginalInstalledRestorationActivationPhase::Arm)
                .is_err()
        );
        assert!(
            interrupted
                .begin(OriginalInstalledRestorationActivationPhase::WorldActivate)
                .is_err()
        );
    }

    #[test]
    fn exact_verified_phase_completion_does_not_renew_a_spent_claim() {
        let phase = OriginalInstalledRestorationActivationLedger::new();
        phase
            .begin(OriginalInstalledRestorationActivationPhase::Arm)
            .unwrap();
        assert!(
            phase
                .complete_verified(OriginalInstalledRestorationActivationPhase::WorldActivate)
                .is_err()
        );
        phase
            .complete_verified(OriginalInstalledRestorationActivationPhase::Arm)
            .unwrap();
        phase
            .begin(OriginalInstalledRestorationActivationPhase::WorldActivate)
            .unwrap();
        phase
            .complete_verified(OriginalInstalledRestorationActivationPhase::WorldActivate)
            .unwrap();
        assert!(
            phase
                .begin(OriginalInstalledRestorationActivationPhase::WorldActivate)
                .is_err()
        );
    }
}
