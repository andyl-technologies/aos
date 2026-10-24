//! Lends one separately funded observation after the actual restored world.
//!
//! A claim spends the same Window's per-node observation ledger. The existing
//! World evidence establishes chronology; it supplies no observation budget.
//! Source must authenticate the newly assigned Observe and terminal under its
//! owning read fence before Core can complete the observation ledger.

use super::*;
use crate::node_adapters::cnp::{
    OriginalSourceRestorationActivationConstructionData,
    OriginalSourceRestorationObservationConstructionData,
};
use crucible_node_transport::reference_packet::service::complete_restore::restoration_observe::OriginalInstalledRestorationObservationConstructionData;
use std::{
    cell::{Cell, OnceCell},
    mem::size_of,
    thread::ThreadId,
};

/// Retains one once-started observation beneath its actual complete Window.
///
/// There is no public constructor, Clone, deserializer or portable authority.
/// Dropping the claim leaves its phase spent. The registered holder retains the
/// Window and every partial Source, SDK and native owner through failure.
#[must_use = "retain the same Window and partial observation owners through failure"]
pub struct OriginalInstalledRestorationObservationClaim {
    process: u32,
    thread: ThreadId,
    window: Weak<CompleteOriginalRestorationWindow>,
    selected: usize,
    proof_identity: [u8; 32],
}

/// Borrows actual pre-Prepare inputs for an independent observation quote.
///
/// These references do not construct a future World, scope artifact or response.
/// The previous activation row is an input to a new independent validation
/// bound; its earlier allocation credit is never reused for observation.
pub(crate) struct OriginalInstalledRestorationObservationSigningConstructionInputs<'a> {
    pub(crate) activation:
        &'a super::activation::OriginalInstalledRestorationActivationSigningConstructionInputs<'a>,
    pub(crate) activation_source: &'a OriginalSourceRestorationActivationConstructionData,
    pub(crate) observation_data: &'a OriginalInstalledRestorationObservationConstructionData,
    pub(crate) request_id: &'a Id,
}

/// Borrows the same completed World and separately admitted observation rows.
///
/// Source authenticates the actual completed World pair in an immutable
/// Controller loan, ends that loan, and only then assigns the new Observe.
/// This unit callback retains no Controller or Window owner in Source.
pub(crate) struct OriginalInstalledRestorationObservationSigningInputs<'a> {
    pub(crate) activation:
        &'a super::activation::OriginalInstalledRestorationActivationSigningInputs<'a>,
    pub(crate) observation_data: &'a OriginalInstalledRestorationObservationConstructionData,
    pub(crate) source_construction: &'a OriginalSourceRestorationObservationConstructionData,
    pub(crate) request_id: &'a Id,
}

impl Drop for OriginalInstalledRestorationObservationClaim {
    fn drop(&mut self) {
        // Destruction revokes only an unfinished attempt. It performs no erased
        // callback, Source/SDK loan, serialization or restoration action.
        if self.process == std::process::id()
            && self.thread == std::thread::current().id()
            && let Some(window) = self.window.upgrade()
        {
            window.interrupt_original_observation_data(self.selected);
        }
    }
}

impl OriginalInstalledRestorationObservationSigningInputs<'_> {
    /// Repeats the original full archived predicates inside Source's read fence.
    ///
    /// Source first authenticates its actual Observe/World/Commit chain and
    /// current native proof. The saved independent validation row bounds the
    /// temporary semantic and model owners; none escape to the Node callback.
    pub(crate) fn authenticate_original_observation_hold_data(
        &self,
        held: &crucible_node_transport::reference_packet::service::complete_restore::PacketNativeRestoredCommitHold,
        reference: &ContentRef,
    ) -> Result<(), RuntimeError> {
        self.activation
            .window
            .authenticate_original_observed_hold_data(
                self.activation.selected,
                self.activation.scope,
                held,
                reference,
            )
    }
}

impl OriginalInstalledRestorationObservationClaim {
    pub(super) fn from_original_window(
        window: &Rc<CompleteOriginalRestorationWindow>,
        selected: usize,
        proof_identity: [u8; 32],
    ) -> Self {
        Self {
            process: std::process::id(),
            thread: std::thread::current().id(),
            window: Rc::downgrade(window),
            selected,
            proof_identity,
        }
    }

    fn original_window(&self) -> Result<Rc<CompleteOriginalRestorationWindow>, RuntimeError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.window.upgrade().ok_or(RuntimeError::OwnerUnavailable)
    }

    /// Rechecks only the actual registered member and bank-free live fence.
    ///
    /// Source keeps its ReadCall armed across this callback, then repeats the
    /// actual kernel and registrar checks. No Source or Controller bank opens.
    pub(crate) fn authenticate_current(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(), RuntimeError> {
        self.original_window()?
            .authenticate_original_observation_member_data(
                self.selected,
                source,
                self.proof_identity,
            )
    }

    pub(crate) fn with_original_observation_signing_inputs_data(
        &self,
        source: &PacketCompleteSemanticSource,
        inspect: impl FnOnce(
            &OriginalInstalledRestorationObservationSigningInputs<'_>,
        ) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        self.authenticate_current(source)?;
        self.original_window()?
            .with_original_observation_signing_inputs_data(
                self.selected,
                source,
                self.proof_identity,
                inspect,
            )?;
        self.authenticate_current(source)
    }

    pub(super) fn authenticate_original_handoff_data(
        &self,
        original: &CompleteOriginalRestorationWindow,
        selected: usize,
        source: &PacketCompleteSemanticSource,
        proof: [u8; 32],
    ) -> Result<(), RuntimeError> {
        let window = self.original_window()?;
        if !std::ptr::eq(window.as_ref(), original)
            || self.selected != selected
            || self.proof_identity != proof
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        // This is the same nonconstructible guard born at begin. Its terminal
        // member recheck remains bank-free; Source's later fenced callback
        // repeats actual native/SDK proof before any Node copy is accepted.
        self.authenticate_current(source)
    }

    pub(crate) fn counter_scratch_data() -> Result<usize, RuntimeError> {
        let terms: [usize; 53] = [
            size_of::<Self>(),
            size_of::<&Self>(),
            size_of::<Result<&Self, RuntimeError>>(),
            size_of::<&mut Self>(),
            size_of::<Option<Self>>(),
            size_of::<&crate::node_scheduling::NativeSchedulingObservation>(),
            size_of::<&crucible_node_transport::reference_packet::service::complete_restore::PacketNativeRestoredCommitHold>(),
            size_of::<&ContentRef>(),

            size_of::<Weak<CompleteOriginalRestorationWindow>>(),
            size_of::<Rc<CompleteOriginalRestorationWindow>>(),
            size_of::<Option<Rc<CompleteOriginalRestorationWindow>>>(),
            size_of::<Result<Rc<CompleteOriginalRestorationWindow>, RuntimeError>>(),
            size_of::<OriginalInstalledRestorationObservationSigningConstructionInputs<'static>>(),
            size_of::<OriginalInstalledRestorationObservationSigningInputs<'static>>(),
            size_of::<OriginalInstalledRestorationObservationLedger>(),
            size_of::<&OriginalInstalledRestorationObservationLedger>(),
            size_of::<Option<&OriginalInstalledRestorationObservationLedger>>(),
            size_of::<Result<&OriginalInstalledRestorationObservationLedger, RuntimeError>>(),
            size_of::<OriginalSourceRestorationObservationConstructionData>(),
            size_of::<Option<OriginalSourceRestorationObservationConstructionData>>(),
            size_of::<&OriginalSourceRestorationObservationConstructionData>(),
            size_of::<&OriginalInstalledRestorationObservationSigningConstructionInputs<'static>>(),
            size_of::<&OriginalInstalledRestorationObservationSigningInputs<'static>>(),
            size_of::<ObservationStage>(),
            size_of::<std::slice::Iter<'static, OriginalInstalledRestorationObservationLedger>>(),
            size_of::<&[OriginalInstalledRestorationObservationLedger; 3]>(),
            size_of::<Result<OriginalSourceRestorationObservationConstructionData, RuntimeError>>(),
            size_of::<Result<&OriginalSourceRestorationObservationConstructionData, RuntimeError>>(
            ),
            size_of::<OriginalInstalledRestorationObservationConstructionData>(),
            size_of::<Option<&OriginalInstalledRestorationObservationConstructionData>>(),
            size_of::<Result<&OriginalInstalledRestorationObservationConstructionData, RuntimeError>>(
            ),
            size_of::<
                crate::node_adapters::cnp::OriginalSourceRestorationObservationVerifiedPhase<
                    'static,
                >,
            >(),
            size_of::<
                Result<
                    crate::node_adapters::cnp::OriginalSourceRestorationObservationVerifiedPhase<
                        'static,
                    >,
                    RuntimeError,
                >,
            >(),
            size_of::<Result<OriginalInstalledRestorationObservationClaim, RuntimeError>>(),
            size_of::<Option<&crate::node_contract::WorldActivation>>(),
            size_of::<Result<&crate::node_contract::WorldActivation, RuntimeError>>(),
            size_of::<Result<(), RuntimeError>>(),
            size_of::<Result<usize, RuntimeError>>(),
            size_of::<Option<usize>>(),
            size_of::<Option<bool>>(),
            size_of::<Result<bool, RuntimeError>>(),
            size_of::<Option<&OriginalRestorationNodeConstructionData>>(),
            size_of::<Result<&OriginalRestorationNodeConstructionData, RuntimeError>>(),
            size_of::<Option<&[OriginalRestorationNodeConstructionData; 3]>>(),
            size_of::<Option<&OnceCell<Id>>>(),
            size_of::<
                Option<
                    &crate::node_adapters::cnp::OriginalInstalledRestorationCustodyConstructionData,
                >,
            >(),
            size_of::<Option<&OriginalSourceRestorationObservationConstructionData>>(),
            size_of::<Option<&Id>>(),
            size_of::<Result<&Id, RuntimeError>>(),
            size_of::<&[super::activation::OriginalInstalledRestorationActivationLedger; 3]>(),
            size_of::<
                std::slice::Iter<
                    'static,
                    super::activation::OriginalInstalledRestorationActivationLedger,
                >,
            >(),
            size_of::<[usize; 53]>(),
            size_of::<std::array::IntoIter<usize, 53>>(),
        ];
        terms.into_iter().try_fold(0usize, |sum, term| {
            sum.checked_add(term).ok_or(RuntimeError::ResourceLimit)
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ObservationStage {
    Unissued,
    Started,
    Verified,
    Failed,
}

pub(super) struct OriginalInstalledRestorationObservationLedger(Cell<ObservationStage>);

pub(super) fn authenticate_original_observation_worlds_data(
    phases: &[super::activation::OriginalInstalledRestorationActivationLedger; 3],
) -> Result<(), RuntimeError> {
    if !phases.iter().all(|phase| {
        phase.is_verified(
            super::activation::OriginalInstalledRestorationActivationPhase::WorldActivate,
        )
    }) {
        return Err(RuntimeError::OutstandingObligations);
    }
    Ok(())
}

impl OriginalInstalledRestorationObservationLedger {
    pub(super) fn new() -> Self {
        Self(Cell::new(ObservationStage::Unissued))
    }

    pub(super) fn begin(&self) -> Result<(), RuntimeError> {
        // A repeated or reentrant issue poisons the earlier phase permanently.
        if self.0.replace(ObservationStage::Failed) != ObservationStage::Unissued {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.0.set(ObservationStage::Started);
        Ok(())
    }

    pub(super) fn authenticate_started(&self) -> Result<(), RuntimeError> {
        if self.0.get() != ObservationStage::Started {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    pub(super) fn complete_verified(&self) -> Result<(), RuntimeError> {
        self.authenticate_started()?;
        self.0.set(ObservationStage::Verified);
        Ok(())
    }

    pub(super) fn authenticate_retained(&self) -> Result<(), RuntimeError> {
        if !matches!(
            self.0.get(),
            ObservationStage::Started | ObservationStage::Verified
        ) {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    pub(super) fn interrupt_started(&self) -> bool {
        match self.0.get() {
            ObservationStage::Started | ObservationStage::Failed => {
                self.0.set(ObservationStage::Failed);
                true
            }
            ObservationStage::Unissued | ObservationStage::Verified => false,
        }
    }

    pub(super) fn is_verified(&self) -> bool {
        self.0.get() == ObservationStage::Verified
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupted_attempts_fail_but_completed_evidence_stays_readable() {
        let phase = OriginalInstalledRestorationObservationLedger::new();
        assert!(phase.authenticate_retained().is_err());
        assert!(!phase.interrupt_started());
        phase.begin().unwrap();
        phase.authenticate_retained().unwrap();
        assert!(phase.interrupt_started());
        assert!(phase.authenticate_retained().is_err());
        assert!(phase.complete_verified().is_err());

        let complete = OriginalInstalledRestorationObservationLedger::new();
        complete.begin().unwrap();
        complete.complete_verified().unwrap();
        complete.authenticate_retained().unwrap();
        assert!(!complete.interrupt_started());
        assert!(complete.is_verified());
        assert!(complete.authenticate_started().is_err());
    }

    #[test]
    fn an_unissued_or_reentered_observation_cannot_complete() {
        let unissued = OriginalInstalledRestorationObservationLedger::new();
        assert!(unissued.complete_verified().is_err());
        assert!(!unissued.is_verified());

        let reentered = OriginalInstalledRestorationObservationLedger::new();
        reentered.begin().unwrap();
        assert!(reentered.begin().is_err());
        assert!(reentered.complete_verified().is_err());
        assert!(reentered.begin().is_err());
    }

    #[test]
    fn a_verified_observation_cannot_issue_a_second_original() {
        let ledger = OriginalInstalledRestorationObservationLedger::new();
        ledger.begin().unwrap();
        ledger.complete_verified().unwrap();
        assert!(ledger.is_verified());

        assert!(ledger.begin().is_err());
        assert!(ledger.complete_verified().is_err());
        assert!(!ledger.is_verified());
    }

    #[test]
    fn every_real_world_phase_must_complete_before_first_observation() {
        use super::super::activation::{
            OriginalInstalledRestorationActivationLedger,
            OriginalInstalledRestorationActivationPhase::{Arm, WorldActivate},
        };

        let worlds: [_; 3] =
            std::array::from_fn(|_| OriginalInstalledRestorationActivationLedger::new());
        assert!(authenticate_original_observation_worlds_data(&worlds).is_err());

        for index in 0..3 {
            let ledger = &worlds[index];
            ledger.begin(Arm).unwrap();
            ledger.complete_verified(Arm).unwrap();
            ledger.begin(WorldActivate).unwrap();
            assert!(authenticate_original_observation_worlds_data(&worlds).is_err());
            ledger.complete_verified(WorldActivate).unwrap();
            if index < 2 {
                assert!(authenticate_original_observation_worlds_data(&worlds).is_err());
            }
        }
        assert!(authenticate_original_observation_worlds_data(&worlds).is_ok());

        assert!(worlds[1].begin(WorldActivate).is_err());
        assert!(authenticate_original_observation_worlds_data(&worlds).is_err());
    }
}
