//! Dispatches finite genuine Genesis borrowers at the original shared slots.
//!
//! The passive capacity coordinate comes from the same actual Source transition
//! or the genuine retained reservation. It stays local to this one native or
//! prospective call and neither constructs a borrower nor authorizes an append.

use std::collections::BTreeMap;

use aos_sandbox_model::RecordNamespace;
use aos_sandbox_ledger_replay::replay::source_tree_successor;
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;

use crate::native::authority::{
    RootGenesisAdvisoryCutV1, RootGenesisCapacityCutDataV1, RootProjectGenesisNativeCutV3,
    RootSuccessorAdvisoryCutV1, RootSuccessorNativeServerCutV3,
};

use super::preflight::PolicyPreflightGateV1;
use super::{ErrorV1, Mechanical, PolicyMutationGateV1, RootPolicyJournalV1};

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

// Only the finite real borrower below supplies these comparison values. The
// common native encoder/pressure recipe does not accept caller-supplied values.
pub(super) struct CapacityCoordinatesV1 {
    allow_capacity_records: bool,
    pub(super) settling_reservation: Option<[u8; 32]>,
}

impl CapacityCoordinatesV1 {
    pub(super) fn ordinary() -> Self {
        Self {
            allow_capacity_records: false,
            settling_reservation: None,
        }
    }

    fn from_genesis(data: RootGenesisCapacityCutDataV1) -> Self {
        Self {
            allow_capacity_records: data.allow_capacity_records,
            settling_reservation: data.settling_reservation,
        }
    }

    pub(super) fn require_presence_v1(
        &self,
        transaction: &JournalTransaction,
    ) -> Result<(), ErrorV1> {
        let present = transaction
            .records()
            .iter()
            .any(|record| record.namespace() == RecordNamespace::GlobalCapacityReservation);
        if present != self.allow_capacity_records {
            return Err(ErrorV1::boundary());
        }
        Ok(())
    }

    pub(super) fn require_consumer_v1(
        &self,
        state: &State,
        transaction: &JournalTransaction,
    ) -> Result<(), ErrorV1> {
        aos_sandbox_ledger_replay::ordinary_mutation::require_no_consumer_resource_transition_v1(
            state,
            transaction,
            self.allow_capacity_records,
        )
        .map_err(ErrorV1::from)
    }
}

// Both schedule kinds borrow the actual private owners. This closed sum shares
// only the semantic slot, without an externally implementable gate or callback.
pub(super) enum GenesisSourceBorrowV1<'borrow, 'original> {
    Ordinary,
    Project(&'borrow mut RootProjectGenesisNativeCutV3<'original>),
    Successor(&'borrow mut RootSuccessorNativeServerCutV3<'original>),
    ProjectAdvisory(&'borrow mut RootGenesisAdvisoryCutV1<'original>),
    SuccessorAdvisory(&'borrow mut RootSuccessorAdvisoryCutV1<'original>),
}

impl GenesisSourceBorrowV1<'_, '_> {
    pub(super) fn require_transition_v1(
        self,
        journal: &RootPolicyJournalV1,
        state: &State,
        transaction: &JournalTransaction,
    ) -> Result<Option<[u8; 32]>, ErrorV1> {
        match self {
            Self::Ordinary => source_tree_successor::require_transition::<
                Mechanical,
                aos_sandbox_protocol::domain_ledger::DomainLedgerDataError,
                aos_sandbox_ledger_replay::genesis::SourceGenesisReceiptDataErrorV1,
            >(state, transaction, None)
            .map_err(ErrorV1::from),
            Self::Project(original) => {
                original.require_project_family_v1(journal, state, transaction)?;
                Ok(None)
            }
            Self::ProjectAdvisory(original) => {
                original.require_project_family_v1(journal, state, transaction)?;
                Ok(None)
            }
            Self::Successor(original) => {
                let settling = original.require_source_transition_v1(state, transaction)?;
                original.require_phase_owner_before_v1(journal)?;
                source_tree_successor::require_capacity_records_data_v1(
                    journal.limits(),
                    transaction,
                )?;
                Ok(settling)
            }
            Self::SuccessorAdvisory(original) => {
                let settling = original.require_source_transition_v1(state, transaction)?;
                original.require_family_owner_v1(journal)?;
                source_tree_successor::require_capacity_records_data_v1(
                    journal.limits(),
                    transaction,
                )?;
                Ok(settling)
            }
        }
    }
}

impl<'gate, 'flight, 'origin, 'packet, 'startup>
    PolicyMutationGateV1<'gate, 'flight, 'origin, 'packet, 'startup>
{
    pub(super) fn source_borrow_v1(&mut self) -> GenesisSourceBorrowV1<'_, 'gate> {
        match self {
            Self::GenesisProject(original) => GenesisSourceBorrowV1::Project(original),
            Self::GenesisSuccessor(original) => GenesisSourceBorrowV1::Successor(original),
            _ => GenesisSourceBorrowV1::Ordinary,
        }
    }

    pub(super) fn capacity_coordinates_v1(
        &self,
        source_settling: Option<[u8; 32]>,
    ) -> CapacityCoordinatesV1 {
        match self {
            Self::GenesisStrict(original) => {
                CapacityCoordinatesV1::from_genesis(original.capacity_data_v1())
            }
            Self::GenesisGlobal(original) => {
                CapacityCoordinatesV1::from_genesis(original.capacity_data_v1())
            }
            Self::GenesisProject(original) => {
                CapacityCoordinatesV1::from_genesis(original.capacity_data_v1())
            }
            Self::GenesisSuccessor(original) => CapacityCoordinatesV1 {
                allow_capacity_records: original.first_phase_data_v1().has_capacity_records(),
                settling_reservation: source_settling,
            },
            _ => CapacityCoordinatesV1::ordinary(),
        }
    }

    pub(super) fn require_root_genesis_v1(
        &mut self,
        journal: &RootPolicyJournalV1,
        transaction: &JournalTransaction,
    ) -> Result<(), ErrorV1> {
        match self {
            Self::GenesisStrict(original) => {
                original.require_root_genesis_mutation_v1(journal, transaction)
            }
            Self::GenesisGlobal(original) => {
                original.require_root_genesis_mutation_v1(journal, transaction)
            }
            Self::GenesisProject(original) => {
                original.require_root_genesis_mutation_v1(journal, transaction)
            }
            _ => aos_sandbox_ledger_replay::replay::root_genesis_capacity::require_no_mutation_v1(
                transaction,
            )
            .map_err(ErrorV1::from),
        }
    }

    pub(super) fn has_successor_v1(&self) -> bool {
        matches!(self, Self::GenesisSuccessor(_))
    }
}

impl<'borrow, 'gate, 'flight, 'origin, 'packet, 'startup>
    PolicyPreflightGateV1<'borrow, 'gate, 'flight, 'origin, 'packet, 'startup>
{
    pub(super) fn source_borrow_v1(&mut self) -> GenesisSourceBorrowV1<'_, 'gate> {
        match self {
            Self::Mutation(gate) => gate.source_borrow_v1(),
            Self::Genesis(original) if original.project_phase_data_v1().is_some() => {
                GenesisSourceBorrowV1::ProjectAdvisory(original)
            }
            Self::Successor(original) => GenesisSourceBorrowV1::SuccessorAdvisory(original),
            _ => GenesisSourceBorrowV1::Ordinary,
        }
    }

    pub(super) fn capacity_coordinates_v1(
        &self,
        source_settling: Option<[u8; 32]>,
    ) -> CapacityCoordinatesV1 {
        match self {
            Self::Mutation(gate) => gate.capacity_coordinates_v1(source_settling),
            Self::Genesis(original) => {
                CapacityCoordinatesV1::from_genesis(original.capacity_data_v1())
            }
            Self::Successor(original) => CapacityCoordinatesV1 {
                allow_capacity_records: original.first_phase_data_v1().has_capacity_records(),
                settling_reservation: source_settling,
            },
            Self::Forecast(_) => CapacityCoordinatesV1::ordinary(),
        }
    }

    pub(super) fn has_successor_v1(&self) -> bool {
        match self {
            Self::Mutation(gate) => gate.has_successor_v1(),
            Self::Successor(_) => true,
            _ => false,
        }
    }
}
