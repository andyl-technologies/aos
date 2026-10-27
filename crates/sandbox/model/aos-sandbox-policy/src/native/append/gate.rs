//! Keeps the actual finite Policy mutation loans at the final native crossing.
//!
//! These variants are private to the real role implementation. Publication
//! retains its genuine verifier/Gen1/Origin lifetimes. Authority retains its
//! own private history and same-flight Input borrower. No DATA constructs either
//! variant, and no callback or externally implementable trait supplies a gate.

use crate::native::authority::AuthorityAppendGateV1;
use crate::native::target::RootCurrentInputVerifierV1;
use crate::native::{PolicyNativeJournalErrorV1 as ErrorV1, journal::RootPolicyJournalV1};
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;

pub(in crate::native) enum PolicyMutationGateV1<'gate, 'flight, 'origin, 'packet, 'startup> {
    Ordinary,
    RootOpen(&'gate mut crate::native::root_current::RootInitialOpenAppendGateV1<'flight, 'startup>),
    StartupCredential(crate::native::startup::StartupCredentialAppendGateV1<'gate, 'startup>),
    GenesisStrict(crate::native::authority::RootStrictGenesisNativeCutV1<'gate>),
    GenesisGlobal(crate::native::authority::GlobalRootGenesisNativeCutV2<'gate>),
    GenesisProject(crate::native::authority::RootProjectGenesisNativeCutV3<'gate>),
    GenesisSuccessor(crate::native::authority::RootSuccessorNativeServerCutV3<'gate>),
    Publication(&'gate RootCurrentInputVerifierV1<'gate, 'flight, 'origin, 'packet, 'startup>),
    Authority(AuthorityAppendGateV1<'gate, 'gate, 'origin, 'startup>),
}

impl PolicyMutationGateV1<'_, '_, '_, '_, '_> {
    pub(in crate::native) fn preflight(
        &mut self,
        journal: &RootPolicyJournalV1,
        transactions: &[JournalTransaction],
    ) -> Result<(), ErrorV1> {
        journal.preflight_with_role_gate_v1(transactions, self)
    }

    pub(in crate::native) fn commit(
        self,
        journal: &mut RootPolicyJournalV1,
        transaction: &JournalTransaction,
    ) -> Result<aos_sandbox_broker::canonical_journal::CommitResult, ErrorV1> {
        journal.commit_with_role_gate_v1(transaction, self)
    }

    pub(super) fn require_before_models_v1(
        &mut self,
        journal: &RootPolicyJournalV1,
        transactions: &[JournalTransaction],
    ) -> Result<(), ErrorV1> {
        match self {
            Self::Ordinary | Self::RootOpen(_) => journal.ensure_healthy(),
            Self::StartupCredential(original) => {
                original.require_same_journal_v1(journal)?;
                journal.ensure_healthy()
            },
            Self::GenesisStrict(original) => {
                original.require_before_models_v1(journal, transactions)
            }
            Self::GenesisGlobal(original) => {
                original.require_before_models_v1(journal, transactions)
            }
            Self::GenesisProject(original) => {
                original.require_before_models_v1(journal, transactions)
            }
            Self::GenesisSuccessor(original) => {
                original.require_before_models_v1(journal, transactions)
            }
            Self::Publication(current) => current
                .require_actual_append_current_v1()
                .map_err(|()| ErrorV1::boundary()),
            Self::Authority(original) => original.preflight_v1(journal, transactions),
        }
    }

    pub(super) fn require_q04_transition_v1(
        &self,
        state: &std::collections::BTreeMap<(aos_sandbox_model::RecordNamespace, Vec<u8>), Vec<u8>>,
        transaction: &JournalTransaction,
        index: usize,
    ) -> Result<(), ErrorV1> {
        match self {
            Self::Ordinary
            | Self::RootOpen(_)
            | Self::StartupCredential(_)
            | Self::Publication(_)
            | Self::GenesisStrict(_)
            | Self::GenesisGlobal(_)
            | Self::GenesisProject(_)
            | Self::GenesisSuccessor(_) => {
                aos_sandbox_ledger_replay::ordinary_mutation::require_no_root_q04_mutation_v1(
                    state,
                    transaction,
                )
                .map_err(ErrorV1::from)
            }
            Self::Authority(original) => {
                original.require_q04_transition_v1(state, transaction, index)
            }
        }
    }

    pub(super) fn final_crossing_v1(
        &mut self,
        journal: &RootPolicyJournalV1,
        transaction: &JournalTransaction,
    ) -> Result<(), ErrorV1> {
        match self {
            Self::Ordinary => journal.ensure_healthy(),
            Self::RootOpen(original) => original.final_crossing(journal),
            Self::StartupCredential(original) => {
                original.require_same_journal_v1(journal)?;
                journal.ensure_healthy()
            },
            Self::GenesisStrict(original) => original.final_crossing_v1(journal, transaction),
            Self::GenesisGlobal(original) => original.final_crossing_v1(journal, transaction),
            Self::GenesisProject(original) => original.final_crossing_v1(journal, transaction),
            Self::GenesisSuccessor(original) => {
                original.require_phase_owner_after_v1(journal)?;
                original.final_crossing_v1(journal, transaction)
            }
            Self::Publication(current) => current
                .require_actual_append_current_v1()
                .map_err(|()| ErrorV1::boundary()),
            Self::Authority(original) => original.final_crossing_v1(journal, transaction),
        }
    }
}
