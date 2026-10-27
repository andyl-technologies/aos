//! Retains a distinct first-current checkpoint after all three initial Observes.
//!
//! Imported Runtime7 ancestry and the once-Observe evidence remain immutable.
//! This seed admits no operation or input and cannot advance a native cursor.
//! A later continuation must supply its own signed original, terminal and live
//! native proof before replacing the current checkpoint.

use super::*;
use crate::node_adapters::cnp::{
    CnpSemanticSource, OriginalSourceRestorationObservationConstructionData,
};
use crate::node_contract::WorldActivation;
use crucible_node_format::Position;
use crucible_node_transport::client::CnpController;

/// Contains fixed prospective DATA for one independently fenced seed inspection.
#[derive(Clone, Copy)]
pub(crate) struct OriginalRestoredSuffixConstructionData {
    pub(crate) process: u32,
    pub(crate) thread: ThreadId,
    pub(crate) source: *const PacketCompleteSemanticSource,
    pub(crate) controller: *const CnpController,
    pub(crate) observation: OriginalSourceRestorationObservationConstructionData,
    pub(crate) requested: usize,
    pub(crate) scratch: usize,
    pub(crate) maximum: usize,
}

impl OriginalRestoredSuffixConstructionData {
    /// Checks the actual creator and Source/Controller row correspondence.
    ///
    /// # Errors
    /// Refuses foreign origin or identity and an incoherent admitted bound.
    pub(crate) fn authenticate_original_data(
        &self,
        source: &PacketCompleteSemanticSource,
        controller: &CnpController,
    ) -> Result<(), RuntimeError> {
        if self.process != std::process::id()
            || self.thread != std::thread::current().id()
            || !std::ptr::eq(self.source, source)
            || !std::ptr::eq(self.controller, controller)
            || self.requested > self.maximum
        {
            return Err(RuntimeError::ForeignAuthority);
        }

        Ok(())
    }

    /// Returns the independently summed prospective seed validation extent.
    pub(crate) fn requested_bytes_data(&self) -> usize {
        self.requested
    }

    /// Names fixed claim, ledger and borrowed Window counter views.
    pub(crate) fn counter_scratch_data() -> usize {
        size_of::<Self>()
            + super::current_observation::OriginalRestoredSchedulingObservationConstructionData::counter_scratch_data()
            + crate::node_contract::OriginalRuntimeOperationDispatch::counter_scratch_data()
            + 2 * size_of::<&Self>()
            + size_of::<Option<Self>>()
            + size_of::<Result<Self, RuntimeError>>()
            + size_of::<Option<Result<Self, RuntimeError>>>()
            + size_of::<Result<Option<Self>, RuntimeError>>()
            + size_of::<Option<&OriginalSourceRestorationObservationConstructionData>>()
            + size_of::<OriginalRestoredSuffixSeedClaim<'static>>()
            + size_of::<&OriginalRestoredSuffixSeedClaim<'static>>()
            + size_of::<SuffixAttemptGuard<'static>>()
            + size_of::<std::slice::Iter<'static, SuffixLedger>>()
            + size_of::<&[SuffixLedger; 3]>()
            + size_of::<&Cell<bool>>()
            + size_of::<&observation::OriginalRestorationWholeObservation>()
            + size_of::<SuffixLedger>()
            + size_of::<[SuffixLedger; 3]>()
            + size_of::<
                std::slice::Iter<
                    'static,
                    super::super::observation::OriginalInstalledRestorationObservationLedger,
                >,
            >()
            + size_of::<&CompleteOriginalRestorationWindow>()
            + size_of::<&PacketCompleteSemanticSource>()
            + size_of::<&dyn CnpSemanticSource>()
            + size_of::<&CnpController>()
            + size_of::<&WorldActivation>()
            + size_of::<*const ()>()
            + size_of::<[u8; 32]>()
            + size_of::<Option<&Self>>()
            + size_of::<Result<&Self, RuntimeError>>()
            + size_of::<Option<&OriginalRestorationNodeConstructionData>>()
            + size_of::<Result<&OriginalRestorationNodeConstructionData, RuntimeError>>()
            + size_of::<Option<&[OriginalRestorationNodeConstructionData; 3]>>()
            + size_of::<Result<&[OriginalRestorationNodeConstructionData; 3], RuntimeError>>()
            + size_of::<std::slice::Iter<'static, OriginalRestorationNodeConstructionData>>()
            + size_of::<std::slice::Iter<'static, Rc<PacketCompleteSemanticSource>>>()
            + size_of::<Rc<PacketCompleteSemanticSource>>()
            + size_of::<Option<&Rc<PacketCompleteSemanticSource>>>()
            + size_of::<Result<&Rc<PacketCompleteSemanticSource>, RuntimeError>>()
            + size_of::<Option<&SuffixLedger>>()
            + size_of::<Result<&SuffixLedger, RuntimeError>>()
            + size_of::<Option<&WorldActivation>>()
            + size_of::<Option<&super::scope_owner::OriginalRestorationScopeOwner>>()
            + size_of::<Result<&super::scope_owner::OriginalRestorationScopeOwner, RuntimeError>>()
            + size_of::<
                &super::super::observation::OriginalInstalledRestorationObservationSigningInputs<
                    'static,
                >,
            >()
            + size_of::<(
                &OriginalRestoredSuffixSeedClaim<'static>,
                &OriginalRestoredSuffixConstructionData,
            )>()
            + size_of::<&crate::node_contract::OriginalRuntimeOperationDispatch<'static>>()
            + size_of::<&crate::node_contract::OperationAdmission>()
            + size_of::<&crate::node_contract::NodeRoute>()
            + size_of::<&crate::node_contract::OwnerIdentity>()
            + size_of::<&[crate::node_contract::OwnerIdentity]>()
            + size_of::<&crate::node_contract::ActivationRecord>()
            + size_of::<&crate::node_contract::OperationToken>()
            + size_of::<std::slice::Iter<'static, crate::node_contract::OwnerIdentity>>()
            + size_of::<Option<&crate::node_contract::OwnerIdentity>>()
            + size_of::<&crate::node_adapters::cnp::CnpSemanticInstallation>()
            + size_of::<Result<(), RuntimeError>>()
    }
}

/// Describes a retained checkpoint without carrying permission or owned history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OriginalRestoredSuffixCheckpointData {
    pub(crate) restoration_proof: [u8; 32],
    pub(crate) native_binding: [u8; 32],
    pub(crate) observation_binding: [u8; 32],
    pub(crate) reached: Position,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SeedStage {
    Empty,
    Started,
    Verified,
    Failed,
}

pub(super) struct SuffixLedger(Cell<SeedStage>);

impl SuffixLedger {
    pub(super) fn new() -> Self {
        Self(Cell::new(SeedStage::Empty))
    }

    fn begin(&self) -> Result<(), RuntimeError> {
        match self.0.get() {
            SeedStage::Empty => {
                self.0.set(SeedStage::Started);
                Ok(())
            }
            SeedStage::Started => {
                self.0.set(SeedStage::Failed);
                Err(RuntimeError::OutstandingObligations)
            }
            SeedStage::Verified | SeedStage::Failed => Err(RuntimeError::OutstandingObligations),
        }
    }

    pub(super) fn authenticate(&self, expected: SeedStage) -> Result<(), RuntimeError> {
        if self.0.get() != expected {
            return Err(RuntimeError::OutstandingObligations);
        }

        Ok(())
    }
}

fn begin_suffix_attempt_data(
    selected: usize,
    ledgers: &[SuffixLedger; 3],
    in_flight: &Cell<bool>,
    whole: &observation::OriginalRestorationWholeObservation,
) -> Result<(), RuntimeError> {
    let selected = ledgers
        .get(selected)
        .ok_or(RuntimeError::ForeignAuthority)?;
    if in_flight.get() {
        // A swallowed reentrant error must not let the original callback tail
        // complete. Revoke the actual outstanding seed, including another peer.
        for ledger in ledgers {
            if ledger.0.get() == SeedStage::Started {
                ledger.0.set(SeedStage::Failed);
            }
        }
        whole.require_observation();
        return Err(RuntimeError::OwnerBusy);
    }
    selected.begin()?;
    in_flight.set(true);
    Ok(())
}

struct SuffixAttemptGuard<'a> {
    ledger: &'a SuffixLedger,
    whole: &'a observation::OriginalRestorationWholeObservation,
    in_flight: &'a Cell<bool>,
}

impl Drop for SuffixAttemptGuard<'_> {
    fn drop(&mut self) {
        if self.ledger.0.get() == SeedStage::Started {
            self.ledger.0.set(SeedStage::Failed);
        }
        self.whole.require_observation();
        self.in_flight.set(false);
    }
}

/// Borrows the genuine Window only for the current seed's fenced callback.
///
/// There is no constructor, Clone, decoder, operation permit or DTO conversion.
/// The same Window lends this scope only after its real whole-owner observation.
pub(crate) struct OriginalRestoredSuffixSeedClaim<'a> {
    window: &'a CompleteOriginalRestorationWindow,
    selected: usize,
    source: &'a PacketCompleteSemanticSource,
    controller: &'a CnpController,
    read_owner: *const (),
    world: &'a WorldActivation,
    proof: [u8; 32],
    expected: SeedStage,
}

impl OriginalRestoredSuffixSeedClaim<'_> {
    /// Rechecks actual fixed Window, runtime, World, Source and spent seed identity.
    ///
    /// # Errors
    /// Refuses an incomplete roster, changed original identity or wrong once phase.
    pub(crate) fn authenticate_current_data(
        &self,
        source: &PacketCompleteSemanticSource,
        controller: &CnpController,
    ) -> Result<(), RuntimeError> {
        if !std::ptr::eq(self.source, source) || !std::ptr::eq(self.controller, controller) {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.window.authenticate_suffix_identity_data(
            self.selected,
            source,
            self.read_owner,
            self.world,
            self.proof,
        )?;
        if self.window.suffix_in_flight.get() != (self.expected == SeedStage::Started) {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.window
            .node_rows
            .get()
            .and_then(|rows| rows.get(self.selected))
            .and_then(|row| row.restored_suffix.as_ref())
            .ok_or(RuntimeError::OwnerUnavailable)?
            .authenticate_original_data(source, controller)?;
        self.window.suffix_seeds[self.selected].authenticate(self.expected)
    }

    /// Borrows the already authenticated immutable restoration identity as DATA.
    pub(crate) fn restoration_proof_data(&self) -> [u8; 32] {
        self.proof
    }

    /// Runs the actual member callback inside the caller's owning SourceRead.
    ///
    /// # Errors
    /// Refuses changed original identity, unavailable plan or member revocation.
    pub(crate) fn authenticate_terminal_member_data(&self) -> Result<(), RuntimeError> {
        self.authenticate_current_data(self.source, self.controller)?;
        let plan = self
            .window
            .plan
            .upgrade()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let scope = self
            .window
            .complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .scope_data()?;
        // This concrete member callback runs inside SourceRead. The bank-free
        // identity path above never invokes an erased authority callback.
        self.window
            .authenticate_original_complete_member_data(&plan, scope)?;
        self.authenticate_current_data(self.source, self.controller)
    }
}

impl CompleteOriginalRestorationWindow {
    pub(super) fn authenticate_suffix_identity_data(
        &self,
        selected: usize,
        source: &PacketCompleteSemanticSource,
        read_owner: *const (),
        world: &WorldActivation,
        proof: [u8; 32],
    ) -> Result<(), RuntimeError> {
        self.authenticate_original_retained_observation_identity_data(selected, source, proof)?;
        if !self
            .observation_phases
            .iter()
            .all(|phase| phase.is_verified())
            || !self
                .activation_world
                .get()
                .is_some_and(|actual| actual.same_authority(world))
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let original = self
            .sources
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        self.node_rows
            .get()
            .and_then(|rows| rows.get(selected))
            .ok_or(RuntimeError::OwnerUnavailable)?
            .authenticate_original_owner_data(original, read_owner)
    }

    /// Signs one separate initial current checkpoint after complete observation.
    ///
    /// # Errors
    /// Refuses missing independent credit, pending census, foreign originals,
    /// repeated attempts and every Source/member/native-fence failure.
    pub(crate) fn seed_original_restored_suffix_data(
        &self,
        selected: usize,
        source: &dyn CnpSemanticSource,
        controller: &CnpController,
        read_owner: *const (),
        world: &WorldActivation,
    ) -> Result<(), RuntimeError> {
        if self.original_installed_source_index_data(source)? != selected {
            return Err(RuntimeError::ForeignAuthority);
        }
        let source = self
            .sources
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?
            .as_ref();
        let proof = self.original_complete_scope_proof_identity_data()?;
        self.authenticate_suffix_identity_data(selected, source, read_owner, world, proof)?;
        let row = self
            .node_rows
            .get()
            .and_then(|rows| rows.get(selected))
            .and_then(|row| row.restored_suffix.as_ref())
            .ok_or(RuntimeError::OwnerUnavailable)?;
        row.authenticate_original_data(source, controller)?;
        self.whole_observation.authenticate_dispatch_data()?;
        let ledger = self
            .suffix_seeds
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        begin_suffix_attempt_data(
            selected,
            &self.suffix_seeds,
            &self.suffix_in_flight,
            &self.whole_observation,
        )?;

        let _attempt = SuffixAttemptGuard {
            ledger,
            whole: &self.whole_observation,
            in_flight: &self.suffix_in_flight,
        };
        let claim = OriginalRestoredSuffixSeedClaim {
            window: self,
            selected,
            source,
            controller,
            read_owner,
            world,
            proof,
            expected: SeedStage::Started,
        };

        self.with_original_observation_signing_inputs_data(selected, source, proof, |inputs| {
            source.seed_original_restored_suffix_data(controller, inputs, row, &claim)
        })?;
        claim.authenticate_current_data(source, controller)?;
        ledger.0.set(SeedStage::Verified);

        Ok(())
    }

    /// Lends the retained seed after reauthenticating its actual initial producer.
    ///
    /// # Errors
    /// Refuses a missing/failed seed, changed identity, pending census, callback
    /// failure or any old initial Observe/World/Hold/currentness mismatch.
    pub(crate) fn with_original_restored_suffix_seed_data(
        &self,
        selected: usize,
        source: &dyn CnpSemanticSource,
        controller: &CnpController,
        read_owner: *const (),
        world: &WorldActivation,
        inspect: impl FnOnce(&OriginalRestoredSuffixCheckpointData) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        if self.original_installed_source_index_data(source)? != selected {
            return Err(RuntimeError::ForeignAuthority);
        }
        let source = self
            .sources
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?
            .as_ref();
        let proof = self.original_complete_scope_proof_identity_data()?;
        self.authenticate_suffix_identity_data(selected, source, read_owner, world, proof)?;
        self.suffix_seeds[selected].authenticate(SeedStage::Verified)?;
        self.whole_observation.authenticate_dispatch_data()?;
        let claim = OriginalRestoredSuffixSeedClaim {
            window: self,
            selected,
            source,
            controller,
            read_owner,
            world,
            proof,
            expected: SeedStage::Verified,
        };

        self.with_original_observation_signing_inputs_data(selected, source, proof, |inputs| {
            let row = self
                .node_rows
                .get()
                .and_then(|rows| rows.get(selected))
                .and_then(|row| row.restored_suffix.as_ref())
                .ok_or(RuntimeError::OwnerUnavailable)?;
            source.with_original_restored_suffix_seed_data(controller, inputs, row, &claim, inspect)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reentrant_seed_cannot_complete_or_reopen_the_original_attempt() {
        let ledgers = std::array::from_fn(|_| SuffixLedger::new());
        let in_flight = Cell::new(false);
        let whole = observation::OriginalRestorationWholeObservation::new_pending();
        whole.complete_observation();
        begin_suffix_attempt_data(0, &ledgers, &in_flight, &whole).expect("actual first gate");

        // A reentrant attempt through another genuine roster slot must revoke
        // the first active seed, even if its caller swallows the returned error.
        assert!(begin_suffix_attempt_data(1, &ledgers, &in_flight, &whole).is_err());
        assert!(ledgers[0].authenticate(SeedStage::Started).is_err());
        assert!(ledgers[0].authenticate(SeedStage::Failed).is_ok());
        assert!(whole.authenticate_dispatch_data().is_err());
        assert!(ledgers[0].begin().is_err());
    }

    #[test]
    fn failed_seed_keeps_the_whole_owner_observation_pending() {
        let ledger = SuffixLedger::new();
        let whole = observation::OriginalRestorationWholeObservation::new_pending();
        let in_flight = Cell::new(true);
        whole.complete_observation();
        ledger.begin().expect("first attempt");
        {
            let _attempt = SuffixAttemptGuard {
                ledger: &ledger,
                whole: &whole,
                in_flight: &in_flight,
            };
        }

        assert!(!in_flight.get());
        assert!(ledger.authenticate(SeedStage::Failed).is_ok());
        assert!(whole.authenticate_dispatch_data().is_err());

        assert!(ledger.begin().is_err());
    }
}

impl CompleteOriginalRestorationWindow {
    /// Authenticates pending Runtime admission against the actual restored seed.
    ///
    /// This bank-free correspondence check creates no action claim, allocates
    /// nothing and invokes no erased authority callback. A later issuer must
    /// retain/admit its independent complete future row and observe all current
    /// owners before opening SourceRead or publishing a fresh original.
    ///
    /// # Errors
    /// Refuses a copied/foreign admission, another actual World/Source/node or
    /// owner, unverified first observations/seed, or changed retained provenance.
    pub(crate) fn authenticate_original_suffix_runtime_dispatch_data(
        &self,
        selected: usize,
        source: &dyn crate::node_adapters::cnp::CnpSemanticSource,
        controller: &CnpController,
        read_owner: *const (),
        dispatch: &crate::node_contract::OriginalRuntimeOperationDispatch<'_>,
    ) -> Result<(), RuntimeError> {
        if self.original_installed_source_index_data(source)? != selected {
            return Err(RuntimeError::ForeignAuthority);
        }
        let source = self
            .sources
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?
            .as_ref();
        let admission = dispatch.admission_data();
        let world = admission.activation();
        let route = admission.token().route();
        dispatch.authenticate_original_data(admission, world, route)?;
        let [owner] = route.owners.as_slice() else {
            return Err(RuntimeError::UnsupportedFacet);
        };
        let installation = source.installation();
        if route.node != installation.binding.compatibility.node_id
            || owner.owner != installation.owner.owner.id
            || !world.record().owners.iter().any(|actual| actual == owner)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let proof = self.original_complete_scope_proof_identity_data()?;
        self.authenticate_suffix_identity_data(selected, source, read_owner, world, proof)?;
        self.suffix_seeds
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?
            .authenticate(SeedStage::Verified)?;
        self.node_rows
            .get()
            .and_then(|rows| rows.get(selected))
            .and_then(|row| row.restored_suffix.as_ref())
            .ok_or(RuntimeError::OwnerUnavailable)?
            .authenticate_original_data(source, controller)
    }
}
