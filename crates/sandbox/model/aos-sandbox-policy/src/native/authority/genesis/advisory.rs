//! Preserves the distinct advisory preludes of real Root-genesis mutations.
//!
//! These private borrowers carry actual prepared or recovered originals. Their
//! successful comparisons neither append nor renew the actual server deadline.
//! Live Root-genesis mutation guards remain separate from advisory preflight.

use std::collections::BTreeMap;

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as Mechanical;
use aos_sandbox_model::{ProjectId, RecordNamespace};
use aos_sandbox_ledger_replay::replay::root_genesis_capacity as canonical;
use aos_sandbox_ledger_replay::replay::source_tree_successor::{
    ProjectGenesisNativePhaseV3, require_project_genesis_family_v3,
};
use aos_sandbox_protocol::domain_ledger::capacity::GlobalCapacityReservationPurposeV1;
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;

use crate::native::{PolicyNativeJournalErrorV1, journal::RootPolicyJournalV1};

use super::super::RootAuthorityErrorV1;
use super::super::names::RootAuthorityNameRecipeV1;
use super::capacity::{PreparedRootGenesisCapacityOriginalV1, RootGenesisCapacityOriginalV1};
use super::native_cut::{RootGenesisCapacityCutDataV1, RootGenesisNativeCrossingOriginalV1};

// Only actual Genesis methods create this finite recipe, borrowing their same
// entered capacity destination. It is not an arbitrary forecast-mode setter.
pub(super) enum RootGenesisAdvisoryRecipeV1<'original> {
    GlobalPrepared(&'original PreparedRootGenesisCapacityOriginalV1),
    GlobalAnchor(&'original RootGenesisCapacityOriginalV1),
    ProjectPrepared(ProjectId, &'original PreparedRootGenesisCapacityOriginalV1),
    ProjectAnchor(ProjectId, &'original RootGenesisCapacityOriginalV1),
}

pub(in crate::native) struct RootGenesisAdvisoryCutV1<'original> {
    pub(super) recipe: RootGenesisAdvisoryRecipeV1<'original>,
    pub(super) transaction: &'original JournalTransaction,
    pub(super) native: &'original mut RootGenesisNativeCrossingOriginalV1,
}

impl RootGenesisAdvisoryCutV1<'_> {
    pub(in crate::native) fn require_before_models_v1(
        &mut self,
        journal: &RootPolicyJournalV1,
        transactions: &[JournalTransaction],
    ) -> Result<(), PolicyNativeJournalErrorV1> {
        if transactions.len() != 1 || transactions[0] != *self.transaction {
            return Err(PolicyNativeJournalErrorV1::boundary());
        }
        let returned = (|| {
            match &self.recipe {
                RootGenesisAdvisoryRecipeV1::GlobalPrepared(prepared) => {
                    // The original capacity claim precedes its envelope check.
                    journal.require_native_original()?;
                    prepared.require_admission_v1(journal, self.transaction)?;
                }
                RootGenesisAdvisoryRecipeV1::ProjectPrepared(_, prepared) => {
                    // Project's original preflight checks the Root-specific
                    // admission before comparing the prepared capacity tuple.
                    self.native
                        .shape_owner
                        .observe_transient_once_v1(journal, RootAuthorityNameRecipeV1::Owner)
                        .map_err(|()| RootAuthorityErrorV1::Stale)?;
                    canonical::validate_admission(
                        journal.read_view().historical_view(),
                        self.transaction,
                        &prepared.data()?.request,
                    )?;
                    prepared.require_admission_v1(journal, self.transaction)?;
                }
                RootGenesisAdvisoryRecipeV1::GlobalAnchor(reservation)
                | RootGenesisAdvisoryRecipeV1::ProjectAnchor(_, reservation) => {
                    if matches!(self.recipe, RootGenesisAdvisoryRecipeV1::GlobalAnchor(_)) {
                        journal.require_native_original()?;
                        super::capacity::require_claim_v1(journal, self.transaction)?;
                    }
                    if reservation.request().purpose
                        != GlobalCapacityReservationPurposeV1::RootSourceGenesisAnchor
                    {
                        return Err(Mechanical::ProtectedBoundary.into());
                    }
                    let _comparison = reservation.compare_terminal_v1(journal, self.transaction)?;
                    self.native
                        .shape_owner
                        .observe_transient_once_v1(journal, RootAuthorityNameRecipeV1::Owner)
                        .map_err(|()| RootAuthorityErrorV1::Stale)?;
                    canonical::validate_settlement(
                        journal.read_view().historical_view(),
                        self.transaction,
                        &reservation.request(),
                        reservation.reservation_id(),
                    )?;
                }
            }
            Ok(())
        })();
        returned.map_err(|cause| self.native.retain(cause))
    }

    pub(in crate::native) fn capacity_data_v1(&self) -> RootGenesisCapacityCutDataV1 {
        RootGenesisCapacityCutDataV1 {
            allow_capacity_records: true,
            settling_reservation: match &self.recipe {
                RootGenesisAdvisoryRecipeV1::GlobalAnchor(reservation)
                | RootGenesisAdvisoryRecipeV1::ProjectAnchor(_, reservation) => {
                    Some(reservation.reservation_id())
                }
                _ => None,
            },
        }
    }

    pub(in crate::native) fn project_phase_data_v1(&self) -> Option<ProjectGenesisNativePhaseV3> {
        match self.recipe {
            RootGenesisAdvisoryRecipeV1::ProjectPrepared(project, _) => {
                Some(ProjectGenesisNativePhaseV3::RootPrepared(project))
            }
            RootGenesisAdvisoryRecipeV1::ProjectAnchor(project, _) => {
                Some(ProjectGenesisNativePhaseV3::RootAnchor(project))
            }
            _ => None,
        }
    }

    pub(in crate::native) fn require_project_family_v1(
        &mut self,
        journal: &RootPolicyJournalV1,
        state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        transaction: &JournalTransaction,
    ) -> Result<(), PolicyNativeJournalErrorV1> {
        let Some(phase) = self.project_phase_data_v1() else {
            return Err(PolicyNativeJournalErrorV1::boundary());
        };
        // The advisory loop has a separate genuine owner observation, after
        // prospective clone, before the full Source family comparison.
        self.native
            .family_owner
            .observe_transient_once_v1(journal, RootAuthorityNameRecipeV1::Owner)
            .map_err(|()| PolicyNativeJournalErrorV1::boundary())?;
        require_project_genesis_family_v3(state, transaction, phase)
            .map_err(PolicyNativeJournalErrorV1::from)
    }
}
