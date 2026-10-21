//! Retains the real non-Q04 mutation crossings beside their entered originals.
//!
//! Only the genuine ordinary Genesis owner constructs these finite borrowers.
//! The append engine receives the same transaction borrow that its owner has
//! already preflighted. The final native checks run after semantic model work;
//! failures stay with the actual mutation reservoir before a boundary marker.

use std::error::Error;
use std::sync::OnceLock;
use std::time::Instant;

use aos_sandbox_model::RawPairedClockSample;
use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;

use crate::native::PolicyNativeJournalErrorV1;
use crate::native::journal::RootPolicyJournalV1;

use super::super::RootAuthorityErrorV1;
use super::super::names::{RootAuthorityNameRecipeV1, RootAuthorityNamesOriginalV1};

// Each actual mutation reservoir owns its samplers and rich cause before the
// append engine is entered. A callee-local cut cannot drop a failed native graph.
pub(super) struct RootGenesisNativeCrossingOriginalV1 {
    pub(super) shape_owner: RootAuthorityNamesOriginalV1,
    pub(super) family_owner: RootAuthorityNamesOriginalV1,
    pin_owner: RootAuthorityNamesOriginalV1,
    parsed_owner: RootAuthorityNamesOriginalV1,
    initialized_pins: super::super::pins::RootAuthorityPinsOriginalV1,
    owner: RootAuthorityNamesOriginalV1,
    physical: RootAuthorityNamesOriginalV1,
    failure: OnceLock<RootAuthorityErrorV1>,
}

impl RootGenesisNativeCrossingOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            shape_owner: RootAuthorityNamesOriginalV1::new(),
            family_owner: RootAuthorityNamesOriginalV1::new(),
            pin_owner: RootAuthorityNamesOriginalV1::new(),
            parsed_owner: RootAuthorityNamesOriginalV1::new(),
            initialized_pins: super::super::pins::RootAuthorityPinsOriginalV1::new(),
            owner: RootAuthorityNamesOriginalV1::new(),
            physical: RootAuthorityNamesOriginalV1::new(),
            failure: OnceLock::new(),
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.shape_owner
            .failure()
            .or_else(|| self.family_owner.failure())
            .or_else(|| self.pin_owner.failure())
            .or_else(|| self.initialized_pins.failure())
            .or_else(|| self.parsed_owner.failure())
            .or_else(|| self.owner.failure())
            .or_else(|| self.physical.failure())
            .or_else(|| self.failure.get().map(|cause| cause as _))
    }

    pub(super) fn retain(&self, cause: RootAuthorityErrorV1) -> PolicyNativeJournalErrorV1 {
        if let Err(_still_owned) = self.failure.set(cause) {
            // An entered failed original cannot silently discard a second
            // unreturned failure. Keep both causes alive until process death.
            std::process::abort();
        }
        PolicyNativeJournalErrorV1::boundary()
    }
}

impl Default for RootGenesisNativeCrossingOriginalV1 {
    fn default() -> Self {
        Self::new()
    }
}

// Each phase borrows its actual prepared or recovered original. There is no
// public phase setter, supplied reservation DATA or generic capacity grant.
pub(super) enum RootGenesisCapacityBorrowV1<'original> {
    Initialize,
    Prepared(&'original super::capacity::PreparedRootGenesisCapacityOriginalV1),
    Anchor(&'original super::capacity::RootGenesisCapacityOriginalV1),
}

/// Copies accounting coordinates only from the real private mutation borrower.
pub(in crate::native) struct RootGenesisCapacityCutDataV1 {
    pub(in crate::native) allow_capacity_records: bool,
    pub(in crate::native) settling_reservation: Option<[u8; 32]>,
}

// The same actual Root capacity/native guard is shared once. The private
// surrounding borrowers retain the distinct legacy, resource and project final
// recipes; a missing clock never chooses a fallback native purpose.
pub(super) struct RootGenesisMutationScopeV1<'original> {
    pub(super) capacity: RootGenesisCapacityBorrowV1<'original>,
    pub(super) transaction: &'original JournalTransaction,
    pub(super) native: &'original mut RootGenesisNativeCrossingOriginalV1,
}

impl RootGenesisMutationScopeV1<'_> {
    pub(in crate::native) fn require_before_models_v1(
        &self,
        journal: &RootPolicyJournalV1,
        transactions: &[JournalTransaction],
    ) -> Result<(), PolicyNativeJournalErrorV1> {
        journal.require_native_original()?;
        if transactions.len() != 1 || transactions[0] != *self.transaction {
            return Err(PolicyNativeJournalErrorV1::boundary());
        }
        match &self.capacity {
            RootGenesisCapacityBorrowV1::Initialize => {
                // Native owner and credential capture stay at the actual
                // live Root-genesis slot, before prospective model growth.
                if self.transaction.records().len() != 2 {
                    return Err(PolicyNativeJournalErrorV1::boundary());
                }
            }
            RootGenesisCapacityBorrowV1::Prepared(prepared) => {
                prepared.require_admission_v1(journal, self.transaction)?;
                if prepared.data()?.request.purpose != aos_sandbox_protocol::domain_ledger::capacity::
                    GlobalCapacityReservationPurposeV1::RootSourceGenesisAnchor
                {
                    return Err(PolicyNativeJournalErrorV1::boundary());
                }
            }
            RootGenesisCapacityBorrowV1::Anchor(reservation) => {
                if reservation.request().purpose != aos_sandbox_protocol::domain_ledger::capacity::
                    GlobalCapacityReservationPurposeV1::RootSourceGenesisAnchor
                    || reservation.request().future_transactions != 1
                {
                    return Err(PolicyNativeJournalErrorV1::boundary());
                }
            }
        }
        Ok(())
    }

    pub(in crate::native) fn capacity_data_v1(&self) -> RootGenesisCapacityCutDataV1 {
        match &self.capacity {
            RootGenesisCapacityBorrowV1::Initialize => RootGenesisCapacityCutDataV1 {
                allow_capacity_records: false,
                settling_reservation: None,
            },
            RootGenesisCapacityBorrowV1::Prepared(_) => RootGenesisCapacityCutDataV1 {
                allow_capacity_records: true,
                settling_reservation: None,
            },
            RootGenesisCapacityBorrowV1::Anchor(reservation) => RootGenesisCapacityCutDataV1 {
                allow_capacity_records: true,
                settling_reservation: Some(reservation.reservation_id()),
            },
        }
    }

    pub(in crate::native) fn require_root_genesis_mutation_v1(
        &mut self,
        journal: &RootPolicyJournalV1,
        transaction: &JournalTransaction,
    ) -> Result<(), PolicyNativeJournalErrorV1> {
        if transaction != self.transaction {
            return Err(PolicyNativeJournalErrorV1::boundary());
        }
        let returned = (|| {
            self.native
                .shape_owner
                .observe_transient_once_v1(journal, RootAuthorityNameRecipeV1::Owner)
                .map_err(|()| RootAuthorityErrorV1::Stale)?;
            let rows = journal.read_view().historical_view();
            match &self.capacity {
                RootGenesisCapacityBorrowV1::Initialize => {
                    let instance = aos_sandbox_ledger_replay::replay::root_genesis_capacity::
                        require_initialization_shape_v1(rows, transaction)?;
                    self.native
                        .pin_owner
                        .observe_transient_once_v1(journal, RootAuthorityNameRecipeV1::Owner)
                        .map_err(|()| RootAuthorityErrorV1::Stale)?;
                    self.native.initialized_pins.capture_once(journal);
                    if !self.native.initialized_pins.has_positive_capture_v1() {
                        return Err(RootAuthorityErrorV1::Stale);
                    }
                    self.native
                        .parsed_owner
                        .observe_transient_once_v1(journal, RootAuthorityNameRecipeV1::Owner)
                        .map_err(|()| RootAuthorityErrorV1::Stale)?;
                    self.native.initialized_pins.finish_once();
                    if !self.native.initialized_pins.ready() {
                        return Err(RootAuthorityErrorV1::Stale);
                    }
                    aos_sandbox_ledger_replay::replay::root_genesis_capacity::
                        require_initialization_pins_v1(transaction, instance,
                            self.native.initialized_pins.record_bytes()?)?;
                }
                RootGenesisCapacityBorrowV1::Prepared(prepared) => {
                    aos_sandbox_ledger_replay::replay::root_genesis_capacity::validate_admission(
                        rows,
                        transaction,
                        &prepared.data()?.request,
                    )?;
                }
                RootGenesisCapacityBorrowV1::Anchor(reservation) => {
                    aos_sandbox_ledger_replay::replay::root_genesis_capacity::validate_settlement(
                        rows,
                        transaction,
                        &reservation.request(),
                        reservation.reservation_id(),
                    )?;
                }
            }
            Ok(())
        })();
        returned.map_err(|cause| self.native.retain(cause))
    }
}

// Private fields preserve the real fixed writer purpose, original preflighted
// transaction and original server clock. No raw floor or tag creates this cut.
pub(in crate::native) struct GlobalRootGenesisNativeCutV2<'original> {
    pub(super) scope: RootGenesisMutationScopeV1<'original>,
    pub(super) names: ProtectedJournalNamesV1,
    pub(super) original: &'original RawPairedClockSample,
    pub(super) deadline: Instant,
}

impl GlobalRootGenesisNativeCutV2<'_> {
    pub(in crate::native) fn require_before_models_v1(
        &self,
        journal: &RootPolicyJournalV1,
        transactions: &[JournalTransaction],
    ) -> Result<(), PolicyNativeJournalErrorV1> {
        self.scope.require_before_models_v1(journal, transactions)
    }

    pub(in crate::native) fn capacity_data_v1(&self) -> RootGenesisCapacityCutDataV1 {
        self.scope.capacity_data_v1()
    }

    pub(in crate::native) fn require_root_genesis_mutation_v1(
        &mut self,
        journal: &RootPolicyJournalV1,
        transaction: &JournalTransaction,
    ) -> Result<(), PolicyNativeJournalErrorV1> {
        self.scope
            .require_root_genesis_mutation_v1(journal, transaction)
    }

    // The append owner calls this at its old Root-genesis live guard slot,
    // after consumer admission and before the common semantic boundaries.

    pub(in crate::native) fn final_crossing_v1(
        &mut self,
        journal: &RootPolicyJournalV1,
        transaction: &JournalTransaction,
    ) -> Result<(), PolicyNativeJournalErrorV1> {
        if transaction != self.scope.transaction {
            return Err(PolicyNativeJournalErrorV1::boundary());
        }
        let returned = (|| {
            self.scope
                .native
                .owner
                .observe_transient_once_v1(journal, RootAuthorityNameRecipeV1::Owner)
                .map_err(|_| RootAuthorityErrorV1::Stale)?;
            self.scope
                .native
                .physical
                .observe_transient_once_v1(journal, RootAuthorityNameRecipeV1::Physical)
                .map_err(|_| RootAuthorityErrorV1::Stale)?;
            if self.scope.native.physical.names() != Some(self.names) {
                return Err(RootAuthorityErrorV1::Stale);
            }
            let expiry = match &self.scope.capacity {
                RootGenesisCapacityBorrowV1::Initialize
                | RootGenesisCapacityBorrowV1::Prepared(_) => {
                    Some(super::deployment::require_current_deployment(journal)?)
                }
                RootGenesisCapacityBorrowV1::Anchor(_) => None,
            };
            // All model, name and deployment work precedes this actual sample.
            let current = super::clock::observe_original_clock(Some(*self.original))?;
            if Instant::now() >= self.deadline
                || expiry.is_some_and(|expires| current.wall_seconds() >= expires)
            {
                return Err(RootAuthorityErrorV1::Stale);
            }
            Ok(())
        })();
        returned.map_err(|cause| self.scope.native.retain(cause))
    }
}

// Mixed Root successor commits repeat the full native join at their final
// frontier. The old strict recipe remains distinct and has no such late clock.
pub(in crate::native) struct RootSuccessorNativeServerCutV3<'original> {
    pub(super) pins: &'original super::super::pins::RootAuthorityPinsOriginalV1,
    pub(super) current: &'original super::super::currentness::RootAuthorityCurrentCustodyV1,
    pub(super) names: ProtectedJournalNamesV1,
    pub(super) context: &'original aos_sandbox_ledger_replay::replay::phase_records::RootFirstSourceSuccessorIntentV2,
    pub(super) phase: aos_sandbox_ledger_replay::replay::source_tree_successor::FirstSourceSuccessorNativePhaseV2,
    pub(super) transaction: &'original JournalTransaction,
    pub(super) original: &'original RawPairedClockSample,
    pub(super) deadline: &'original Instant,
    pub(super) native: &'original mut RootGenesisNativeCrossingOriginalV1,
}

impl RootSuccessorNativeServerCutV3<'_> {
    pub(in crate::native) fn first_phase_data_v1(
        &self,
    ) -> aos_sandbox_ledger_replay::replay::source_tree_successor::FirstSourceSuccessorNativePhaseV2
    {
        self.phase
    }

    pub(in crate::native) fn require_source_transition_v1(
        &self,
        state: &std::collections::BTreeMap<(aos_sandbox_model::RecordNamespace, Vec<u8>), Vec<u8>>,
        transaction: &JournalTransaction,
    ) -> Result<Option<[u8; 32]>, PolicyNativeJournalErrorV1> {
        aos_sandbox_ledger_replay::replay::source_tree_successor::require_transition::<
            aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1,
            aos_sandbox_protocol::domain_ledger::DomainLedgerDataError,
            aos_sandbox_ledger_replay::genesis::SourceGenesisReceiptDataErrorV1,
        >(state, transaction, Some(self.phase))
        .map_err(PolicyNativeJournalErrorV1::from)
    }

    pub(in crate::native) fn require_phase_owner_before_v1(
        &mut self,
        journal: &RootPolicyJournalV1,
    ) -> Result<(), PolicyNativeJournalErrorV1> {
        self.native
            .family_owner
            .observe_transient_once_v1(journal, RootAuthorityNameRecipeV1::Owner)
            .map_err(|()| PolicyNativeJournalErrorV1::boundary())
    }

    pub(in crate::native) fn require_phase_owner_after_v1(
        &mut self,
        journal: &RootPolicyJournalV1,
    ) -> Result<(), PolicyNativeJournalErrorV1> {
        self.native
            .shape_owner
            .observe_transient_once_v1(journal, RootAuthorityNameRecipeV1::Owner)
            .map_err(|()| PolicyNativeJournalErrorV1::boundary())
    }

    pub(in crate::native) fn require_before_models_v1(
        &self,
        journal: &RootPolicyJournalV1,
        transactions: &[JournalTransaction],
    ) -> Result<(), PolicyNativeJournalErrorV1> {
        if transactions.len() != 1 || transactions[0] != *self.transaction {
            return Err(PolicyNativeJournalErrorV1::boundary());
        }
        use aos_sandbox_ledger_replay::replay::source_tree_successor::FirstSourceSuccessorNativePhaseV2 as Phase;
        if !matches!(
            self.phase,
            Phase::RootPrepared
                | Phase::RootAnchor
                | Phase::MixedRootPrepared
                | Phase::MixedRootAnchor
        ) {
            return Err(PolicyNativeJournalErrorV1::boundary());
        }
        // The constructor is private to the actual native session. The full
        // transition and its capacity family run at their original slots,
        // after their original semantic predecessors, rather than being
        // decoded a second time before model construction.
        if self.transaction.id()
            != &aos_sandbox_ledger_replay::replay::source_tree_successor::transaction_id(
                self.context.approval(),
                self.phase.canonical(),
            )
        {
            return Err(PolicyNativeJournalErrorV1::boundary());
        }
        journal.ensure_healthy()
    }

    pub(in crate::native) fn final_crossing_v1(
        &mut self,
        journal: &RootPolicyJournalV1,
        transaction: &JournalTransaction,
    ) -> Result<(), PolicyNativeJournalErrorV1> {
        use aos_sandbox_ledger_replay::replay::phase_records::RootFirstSourceSuccessorIntentV2;
        use aos_sandbox_ledger_replay::replay::root_successor::{
            self, RootFirstSourceSuccessorArchiveV2,
        };
        use aos_sandbox_ledger_replay::replay::source_tree_successor::FirstSourceSuccessorNativePhaseV2 as Phase;

        if transaction != self.transaction {
            return Err(PolicyNativeJournalErrorV1::boundary());
        }
        if matches!(self.phase, Phase::RootPrepared | Phase::RootAnchor) {
            return Ok(());
        }
        let returned = (|| {
            // The shared driver preserves owner→pins→physical names→complete
            // saved-history order and retains every reached native failure.
            super::super::currentness::require_current_v1(
                journal,
                self.pins,
                self.names,
                self.current,
            )?;
            if self.context.roles() != self.pins.digest()? {
                return Err(RootAuthorityErrorV1::Stale);
            }
            let retained = root_successor::project_rows_v3(
                journal.read_view().state(),
                Some(self.context.project()),
            )?;
            let value = transaction
                .records()
                .first()
                .and_then(|record| record.value())
                .ok_or(RootAuthorityErrorV1::Conflict)?;
            let deployment_expiry = match self.phase {
                Phase::MixedRootPrepared => {
                    if retained.intent.is_some()
                        || retained.archives.contains_key(&self.context.project())
                        || RootFirstSourceSuccessorIntentV2::decode(value)? != *self.context
                    {
                        return Err(RootAuthorityErrorV1::Conflict);
                    }
                    Some(super::deployment::require_current_deployment(journal)?)
                }
                Phase::MixedRootAnchor => {
                    if retained.intent.as_ref() != Some(self.context)
                        || RootFirstSourceSuccessorArchiveV2::decode(value)?.original
                            != *self.context
                    {
                        return Err(RootAuthorityErrorV1::Conflict);
                    }
                    None
                }
                _ => return Err(RootAuthorityErrorV1::Conflict),
            };
            drop(retained);

            let current = super::clock::observe_original_clock(Some(*self.original))?;
            if Instant::now() >= *self.deadline {
                return Err(RootAuthorityErrorV1::Stale);
            }
            if deployment_expiry.is_some_and(|expiry| current.wall_seconds() >= expiry) {
                return Err(RootAuthorityErrorV1::AdmissionClosed);
            }
            if self.phase == Phase::MixedRootPrepared {
                crate::controller_successor_data::require_approval_clock(
                    self.context.approval_packet(),
                    current,
                )?;
                if current.host_boot_id() != self.context.boot()
                    || current.boottime_nanoseconds() >= self.context.boottime_deadline()
                    || u64::try_from(current.wall_seconds())
                        .map_err(|_| RootAuthorityErrorV1::AdmissionClosed)?
                        >= self.context.expires_wall()
                {
                    return Err(RootAuthorityErrorV1::AdmissionClosed);
                }
            }
            Ok(())
        })();
        returned.map_err(|cause| self.native.retain(cause))
    }
}

// Initial project genesis uses the same actual capacity originals but keeps its
// distinct native owner/family check and late AdmissionClosed clock category.
pub(in crate::native) struct RootProjectGenesisNativeCutV3<'original> {
    pub(super) global: GlobalRootGenesisNativeCutV2<'original>,
    pub(super) project: aos_sandbox_model::ProjectId,
}

impl RootProjectGenesisNativeCutV3<'_> {
    pub(in crate::native) fn require_before_models_v1(
        &self,
        journal: &RootPolicyJournalV1,
        transactions: &[JournalTransaction],
    ) -> Result<(), PolicyNativeJournalErrorV1> {
        if matches!(
            self.global.scope.capacity,
            RootGenesisCapacityBorrowV1::Initialize
        ) {
            return Err(PolicyNativeJournalErrorV1::boundary());
        }
        self.global.require_before_models_v1(journal, transactions)
    }

    pub(in crate::native) fn capacity_data_v1(&self) -> RootGenesisCapacityCutDataV1 {
        self.global.scope.capacity_data_v1()
    }

    pub(in crate::native) fn require_root_genesis_mutation_v1(
        &mut self,
        journal: &RootPolicyJournalV1,
        transaction: &JournalTransaction,
    ) -> Result<(), PolicyNativeJournalErrorV1> {
        self.global
            .require_root_genesis_mutation_v1(journal, transaction)
    }

    pub(in crate::native) fn project_phase_data_v1(
        &self,
    ) -> Result<
        aos_sandbox_ledger_replay::replay::source_tree_successor::ProjectGenesisNativePhaseV3,
        PolicyNativeJournalErrorV1,
    > {
        use aos_sandbox_ledger_replay::replay::source_tree_successor::ProjectGenesisNativePhaseV3 as Phase;
        match self.global.scope.capacity {
            RootGenesisCapacityBorrowV1::Prepared(_) => Ok(Phase::RootPrepared(self.project)),
            RootGenesisCapacityBorrowV1::Anchor(_) => Ok(Phase::RootAnchor(self.project)),
            RootGenesisCapacityBorrowV1::Initialize => Err(PolicyNativeJournalErrorV1::boundary()),
        }
    }

    pub(in crate::native) fn require_project_family_v1(
        &mut self,
        journal: &RootPolicyJournalV1,
        state: &std::collections::BTreeMap<(aos_sandbox_model::RecordNamespace, Vec<u8>), Vec<u8>>,
        transaction: &JournalTransaction,
    ) -> Result<(), PolicyNativeJournalErrorV1> {
        let phase = self.project_phase_data_v1()?;
        self.global
            .scope
            .native
            .family_owner
            .observe_transient_once_v1(journal, RootAuthorityNameRecipeV1::Owner)
            .map_err(|()| PolicyNativeJournalErrorV1::boundary())?;
        aos_sandbox_ledger_replay::replay::source_tree_successor::require_project_genesis_family_v3(
            state,
            transaction,
            phase,
        )
        .map_err(PolicyNativeJournalErrorV1::from)
    }

    pub(in crate::native) fn final_crossing_v1(
        &mut self,
        journal: &RootPolicyJournalV1,
        transaction: &JournalTransaction,
    ) -> Result<(), PolicyNativeJournalErrorV1> {
        if transaction != self.global.scope.transaction {
            return Err(PolicyNativeJournalErrorV1::boundary());
        }
        let returned = (|| {
            self.global
                .scope
                .native
                .owner
                .observe_transient_once_v1(journal, RootAuthorityNameRecipeV1::Owner)
                .map_err(|()| RootAuthorityErrorV1::Stale)?;
            let expiry = if matches!(
                self.global.scope.capacity,
                RootGenesisCapacityBorrowV1::Prepared(_)
            ) {
                Some(super::deployment::require_current_deployment(journal)?)
            } else {
                None
            };
            let current = super::clock::observe_original_clock(Some(*self.global.original))?;
            if expiry.is_some_and(|expiry| current.wall_seconds() >= expiry) {
                return Err(RootAuthorityErrorV1::AdmissionClosed);
            }
            if Instant::now() >= self.global.deadline {
                return Err(RootAuthorityErrorV1::Stale);
            }
            Ok(())
        })();
        returned.map_err(|cause| self.global.scope.native.retain(cause))
    }
}

// The existing legacy strict route has no late GlobalV2 clock/deployment arm.
// Actual admission and all Root capacity checks still use the same scope.
pub(in crate::native) struct RootStrictGenesisNativeCutV1<'original> {
    pub(super) scope: RootGenesisMutationScopeV1<'original>,
}

impl RootStrictGenesisNativeCutV1<'_> {
    pub(in crate::native) fn require_before_models_v1(
        &self,
        journal: &RootPolicyJournalV1,
        transactions: &[JournalTransaction],
    ) -> Result<(), PolicyNativeJournalErrorV1> {
        self.scope.require_before_models_v1(journal, transactions)
    }

    pub(in crate::native) fn capacity_data_v1(&self) -> RootGenesisCapacityCutDataV1 {
        self.scope.capacity_data_v1()
    }

    pub(in crate::native) fn require_root_genesis_mutation_v1(
        &mut self,
        journal: &RootPolicyJournalV1,
        transaction: &JournalTransaction,
    ) -> Result<(), PolicyNativeJournalErrorV1> {
        self.scope
            .require_root_genesis_mutation_v1(journal, transaction)
    }

    pub(in crate::native) fn final_crossing_v1(
        &mut self,
        journal: &RootPolicyJournalV1,
        transaction: &JournalTransaction,
    ) -> Result<(), PolicyNativeJournalErrorV1> {
        if transaction != self.scope.transaction {
            return Err(PolicyNativeJournalErrorV1::boundary());
        }
        journal.require_healthy_native()
    }
}
