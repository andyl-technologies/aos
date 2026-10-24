//! Connects actual Genesis originals to the sole native append engine.
//!
//! Every constructor below is private to the owning Genesis tree. Advisory and
//! mutation borrowers retain distinct native destinations. The actual journal
//! remains uniquely borrowed through each complete native operation; no public
//! transaction adapter or supplied preflight stamp enters this boundary.

use std::time::Instant;

use aos_sandbox_broker::canonical_journal::CommitResult;
use aos_sandbox_model::{ProjectId, RawPairedClockSample};
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;

use crate::native::PolicyNativeJournalErrorV1;
use crate::native::append::PolicyMutationGateV1;

use super::RootSourceGenesisAuthorityV1;
use super::advisory::{RootGenesisAdvisoryCutV1, RootGenesisAdvisoryRecipeV1};
use super::native_cut::{
    GlobalRootGenesisNativeCutV2, RootGenesisCapacityBorrowV1, RootGenesisMutationScopeV1,
    RootGenesisNativeCrossingOriginalV1, RootProjectGenesisNativeCutV3,
    RootStrictGenesisNativeCutV1,
};

impl RootSourceGenesisAuthorityV1 {
    pub(super) fn preflight_genesis_v1(
        &self,
        transaction: &JournalTransaction,
        recipe: RootGenesisAdvisoryRecipeV1<'_>,
        native: &mut RootGenesisNativeCrossingOriginalV1,
    ) -> Result<(), PolicyNativeJournalErrorV1> {
        let mut original = RootGenesisAdvisoryCutV1 {
            recipe,
            transaction,
            native,
        };
        self.authority
            .journal
            .preflight_genesis_advisory_v1(std::slice::from_ref(transaction), &mut original)
    }

    pub(super) fn commit_global_genesis_v2(
        &mut self,
        transaction: &JournalTransaction,
        capacity: RootGenesisCapacityBorrowV1<'_>,
        original: &RawPairedClockSample,
        deadline: Instant,
        native: &mut RootGenesisNativeCrossingOriginalV1,
        advisory: &mut RootGenesisNativeCrossingOriginalV1,
    ) -> Result<CommitResult, PolicyNativeJournalErrorV1> {
        // This is the exact old GlobalV2 crossing construction frontier. It
        // rechecks the real accepted resource-bearing owner before advisory IO.
        self.require_global_native_cut_v2()
            .map_err(|cause| native.retain(cause))?;
        match &capacity {
            RootGenesisCapacityBorrowV1::Initialize => self
                .authority
                .journal
                .preflight_transactions(std::slice::from_ref(transaction))?,
            RootGenesisCapacityBorrowV1::Prepared(prepared) => self.preflight_genesis_v1(
                transaction,
                RootGenesisAdvisoryRecipeV1::GlobalPrepared(prepared),
                advisory,
            )?,
            RootGenesisCapacityBorrowV1::Anchor(reservation) => self.preflight_genesis_v1(
                transaction,
                RootGenesisAdvisoryRecipeV1::GlobalAnchor(reservation),
                advisory,
            )?,
        }
        let cut = GlobalRootGenesisNativeCutV2 {
            scope: RootGenesisMutationScopeV1 {
                capacity,
                transaction,
                native,
            },
            names: self.authority.names,
            original,
            deadline,
        };
        self.authority
            .journal
            .commit_with_role_gate_v1(transaction, PolicyMutationGateV1::GenesisGlobal(cut))
    }

    pub(super) fn commit_project_genesis_v3(
        &mut self,
        transaction: &JournalTransaction,
        capacity: RootGenesisCapacityBorrowV1<'_>,
        project: ProjectId,
        original: &RawPairedClockSample,
        deadline: Instant,
        native: &mut RootGenesisNativeCrossingOriginalV1,
        advisory: &mut RootGenesisNativeCrossingOriginalV1,
    ) -> Result<CommitResult, PolicyNativeJournalErrorV1> {
        match &capacity {
            RootGenesisCapacityBorrowV1::Initialize => {
                return Err(PolicyNativeJournalErrorV1::boundary());
            }
            RootGenesisCapacityBorrowV1::Prepared(prepared) => self.preflight_genesis_v1(
                transaction,
                RootGenesisAdvisoryRecipeV1::ProjectPrepared(project, prepared),
                advisory,
            )?,
            RootGenesisCapacityBorrowV1::Anchor(reservation) => self.preflight_genesis_v1(
                transaction,
                RootGenesisAdvisoryRecipeV1::ProjectAnchor(project, reservation),
                advisory,
            )?,
        }
        let cut = RootProjectGenesisNativeCutV3 {
            global: GlobalRootGenesisNativeCutV2 {
                scope: RootGenesisMutationScopeV1 {
                    capacity,
                    transaction,
                    native,
                },
                names: self.authority.names,
                original,
                deadline,
            },
            project,
        };
        self.authority
            .journal
            .commit_with_role_gate_v1(transaction, PolicyMutationGateV1::GenesisProject(cut))
    }

    pub(super) fn commit_strict_genesis_v1(
        &mut self,
        transaction: &JournalTransaction,
        capacity: RootGenesisCapacityBorrowV1<'_>,
        native: &mut RootGenesisNativeCrossingOriginalV1,
    ) -> Result<CommitResult, PolicyNativeJournalErrorV1> {
        // The actual strict owner already performed its original advisory cut;
        // unlike GlobalV2 it has no late deployment/kernel-clock recipe.
        let cut = RootStrictGenesisNativeCutV1 {
            scope: RootGenesisMutationScopeV1 {
                capacity,
                transaction,
                native,
            },
        };
        self.authority
            .journal
            .commit_with_role_gate_v1(transaction, PolicyMutationGateV1::GenesisStrict(cut))
    }
    pub(super) fn commit_successor_v1(
        &mut self,
        transaction: &JournalTransaction,
        context: &aos_sandbox_ledger_replay::replay::phase_records::RootFirstSourceSuccessorIntentV2,
        phase: aos_sandbox_ledger_replay::replay::source_tree_successor::FirstSourceSuccessorNativePhaseV2,
        original: &RawPairedClockSample,
        deadline: &Instant,
        native: &mut RootGenesisNativeCrossingOriginalV1,
    ) -> Result<CommitResult, PolicyNativeJournalErrorV1> {
        let cut = super::native_cut::RootSuccessorNativeServerCutV3 {
            pins: &self.authority.pins,
            current: &self.authority.current,
            names: self.authority.names,
            context,
            phase,
            transaction,
            original,
            deadline,
            native,
        };
        self.authority
            .journal
            .commit_with_role_gate_v1(transaction, PolicyMutationGateV1::GenesisSuccessor(cut))
    }
}
