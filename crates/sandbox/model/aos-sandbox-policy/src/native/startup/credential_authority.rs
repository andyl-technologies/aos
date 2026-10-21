//! Reborrows the actual startup Authority through its five fixed admissions.
//!
//! This private scope preserves the old DesiredState claim/read/mutation gates.
//! It is never exported as a generic Journal, supplied writer, or purpose grant.

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as Mechanical;
use aos_sandbox_broker::receiving::RootJournalFinancialBorrowV1;
use aos_sandbox_model::RecordNamespace;
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;

use super::super::PolicyNativeJournalErrorV1 as ErrorV1;
use super::super::journal::RootPolicyJournalV1;
use super::{
    RootStartupJournalErrorV1, RootStartupJournalOriginalV1, StartupCredentialAppendGateV1,
};

pub(super) struct StartupCredentialAuthorityV1<'journal, 'borrow, 'initial> {
    journal: &'journal mut RootPolicyJournalV1,
    gate: Option<StartupCredentialAuthorityGateV1<'borrow, 'initial>>,
}

enum StartupCredentialAuthorityGateV1<'borrow, 'initial> {
    Selected(StartupCredentialAppendGateV1<'borrow, 'initial>),
    Ordinary,
}

impl RootStartupJournalOriginalV1 {
    // Native fixed credential methods alone can create this actual scope
    // after their single names entry and original encode/decode frontier.
    // Its return cannot outlive the same mutable startup Journal borrow.
    pub(super) fn credential_authority_after_entry_v1<'journal, 'borrow, 'initial>(
        &'journal mut self,
        original: Option<&'borrow RootJournalFinancialBorrowV1<'initial>>,
    ) -> Result<StartupCredentialAuthorityV1<'journal, 'borrow, 'initial>, RootStartupJournalErrorV1>
    {
        let gate = match (&self.storage, original) {
            (super::StartupJournalStorageV1::Selected(selected), Some(original)) => {
                StartupCredentialAuthorityGateV1::Selected(
                    selected.credential_append_gate_v1(original)?,
                )
            }
            (super::StartupJournalStorageV1::Ordinary(_), None) => {
                StartupCredentialAuthorityGateV1::Ordinary
            }
            _ => return Err(RootStartupJournalErrorV1::Closed),
        };
        let journal = self
            .journal_after_entry_mut_v1()
            .ok_or(RootStartupJournalErrorV1::Closed)?;
        StartupCredentialAuthorityV1::claim_after_entry_v1(journal, Some(gate))
    }

    // Precredential read has its own actual entry and namespace claim. It
    // cannot mint a mutation gate from an absent financial original.
    pub(super) fn binding_read_authority_after_entry_v1(
        &mut self,
    ) -> Result<StartupCredentialAuthorityV1<'_, 'static, 'static>, RootStartupJournalErrorV1> {
        let journal = self
            .journal_after_entry_mut_v1()
            .ok_or(RootStartupJournalErrorV1::Closed)?;
        StartupCredentialAuthorityV1::claim_after_entry_v1(journal, None)
    }
}

impl<'journal, 'borrow, 'initial> StartupCredentialAuthorityV1<'journal, 'borrow, 'initial> {
    fn claim_after_entry_v1(
        journal: &'journal mut RootPolicyJournalV1,
        gate: Option<StartupCredentialAuthorityGateV1<'borrow, 'initial>>,
    ) -> Result<Self, RootStartupJournalErrorV1> {
        journal.ensure_protected_authority()?;
        let read = journal.read_view();
        let state = read.state();
        aos_sandbox_protocol::domain_ledger::capacity_family::family::require_legacy_reservations(
            state,
        )
        .map_err(Mechanical::from)
        .map_err(ErrorV1::from)?;
        let namespace = RecordNamespace::DesiredState;
        let has_foreign_history = read.committed_namespaces().iter().any(|committed| {
            *committed != namespace && *committed != RecordNamespace::GlobalCapacityReservation
        });
        let has_foreign_state = state.keys().any(|(record_namespace, _)| {
            *record_namespace != namespace
                && *record_namespace != RecordNamespace::GlobalCapacityReservation
        });
        if has_foreign_history
            || has_foreign_state
            || !aos_sandbox_protocol::domain_ledger::capacity_family::all_reservations_owned_by(
                state, namespace,
            )
            .map_err(Mechanical::from)
            .map_err(ErrorV1::from)?
        {
            return Err(ErrorV1::Mechanical(Mechanical::ForeignAuthorityNamespace).into());
        }
        Ok(StartupCredentialAuthorityV1 { journal, gate })
    }

    pub(super) fn get(&self, key: &[u8]) -> Result<Option<&[u8]>, ErrorV1> {
        self.journal.ensure_protected_authority()?;
        Ok(self.journal.get(RecordNamespace::DesiredState, key))
    }

    pub(super) fn records(&self) -> Result<impl Iterator<Item = (&[u8], &[u8])>, ErrorV1> {
        self.journal.ensure_protected_authority()?;
        Ok(self.journal.records(RecordNamespace::DesiredState))
    }

    pub(super) fn is_materialized_empty(&self) -> Result<bool, ErrorV1> {
        self.journal.ensure_protected_authority()?;
        Ok(self.journal.read_view().state().is_empty())
    }

    pub(super) fn commit(
        &mut self,
        transaction: &JournalTransaction,
    ) -> Result<aos_sandbox_broker::canonical_journal::CommitResult, ErrorV1> {
        self.journal.ensure_protected_authority()?;
        if transaction
            .records()
            .iter()
            .any(|record| record.namespace() != RecordNamespace::DesiredState)
        {
            return Err(Mechanical::ForeignAuthorityNamespace.into());
        }
        let gate = self.gate.as_ref().ok_or_else(ErrorV1::boundary)?;
        // This is the old credential current check BEFORE any common commit
        // semantics fee/model work; it must not move into the final crossing.
        if let StartupCredentialAuthorityGateV1::Selected(gate) = gate {
            gate.require_initial_current_v1(self.journal)?;
        }
        let gate = match self.gate.take().ok_or_else(ErrorV1::boundary)? {
            StartupCredentialAuthorityGateV1::Selected(gate) => {
                crate::native::append::PolicyMutationGateV1::StartupCredential(gate)
            }
            StartupCredentialAuthorityGateV1::Ordinary => {
                crate::native::append::PolicyMutationGateV1::Ordinary
            }
        };
        self.journal.commit_with_role_gate_v1(transaction, gate)
    }
}

pub(super) fn control_bytes_v1() -> Option<usize> {
    use std::mem::size_of;
    records_control_bytes_v1(RootPolicyJournalV1::records)?
        .checked_add(
            size_of::<(
                &mut RootPolicyJournalV1,
                Option<StartupCredentialAuthorityGateV1<'_, '_>>,
            )>()
            .checked_mul(3)?,
        )?
        .checked_add(size_of::<&mut RootStartupJournalOriginalV1>().checked_mul(3)?)?
        .checked_add(
            size_of::<
                Result<
                    StartupCredentialAuthorityV1<'_, 'static, 'static>,
                    RootStartupJournalErrorV1,
                >,
            >()
            .checked_mul(6)?,
        )?
        .checked_add(super::credentials::binding_read_control_bytes_v1()?)?
        .checked_add(size_of::<StartupCredentialAuthorityGateV1<'_, '_>>().checked_mul(3)?)?
        .checked_add(size_of::<Option<&RootJournalFinancialBorrowV1<'_>>>().checked_mul(3)?)?
        .checked_add(
            size_of::<std::collections::btree_set::Iter<'_, RecordNamespace>>().checked_mul(3)?,
        )?
        .checked_add(
            size_of::<std::collections::btree_map::Keys<'_, (RecordNamespace, Vec<u8>), Vec<u8>>>()
                .checked_mul(3)?,
        )?
        .checked_add(size_of::<StartupCredentialAuthorityV1<'_, '_, '_>>().checked_mul(3)?)?
        .checked_add(
            size_of::<Result<StartupCredentialAuthorityV1<'_, '_, '_>, RootStartupJournalErrorV1>>(
            )
            .checked_mul(3)?,
        )?
        .checked_add(
            size_of::<(
                &mut RootStartupJournalOriginalV1,
                &RootJournalFinancialBorrowV1<'_>,
            )>()
            .checked_mul(3)?,
        )?
        .checked_add(
            size_of::<(&StartupCredentialAuthorityV1<'_, '_, '_>, &[u8])>().checked_mul(3)?,
        )?
        .checked_add(size_of::<Result<Option<&[u8]>, ErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<bool, ErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), ErrorV1>>().checked_mul(6)?)?
        .checked_add(
            size_of::<Result<aos_sandbox_broker::canonical_journal::CommitResult, ErrorV1>>()
                .checked_mul(3)?,
        )?
        .checked_add(size_of::<Option<StartupCredentialAuthorityGateV1<'_, '_>>>().checked_mul(3)?)?
        .checked_add(
            size_of::<(
                &mut StartupCredentialAuthorityV1<'_, '_, '_>,
                &JournalTransaction,
            )>()
            .checked_mul(3)?,
        )?
        .checked_add(size_of::<(&RecordNamespace, &RecordNamespace)>().checked_mul(3)?)?
        .checked_add(size_of::<bool>().checked_mul(6)?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
}

// Type inference measures the actual opaque borrowed iterator returned by the
// sole existing native view method. The method is never invoked: no synthetic
// state, native owner, callback observation, or successful result is created.
fn records_control_bytes_v1<'rows, Records>(
    _method: fn(&'rows RootPolicyJournalV1, RecordNamespace) -> Records,
) -> Option<usize>
where
    Records: Iterator<Item = (&'rows [u8], &'rows [u8])>,
{
    std::mem::size_of::<Records>()
        .checked_mul(3)?
        .checked_add(std::mem::size_of::<Result<Records, ErrorV1>>().checked_mul(3)?)?
        .checked_add(
            std::mem::size_of::<fn(&'rows RootPolicyJournalV1, RecordNamespace) -> Records>()
                .checked_mul(3)?,
        )?
        .checked_add(std::mem::size_of::<Option<usize>>().checked_mul(3)?)
}
