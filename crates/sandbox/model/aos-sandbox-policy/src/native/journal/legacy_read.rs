//! Keeps the fixed legacy verifier's original DesiredState read-only scope.
//!
//! The ordinary fixed owner uses this private borrow to authenticate retained
//! legacy DATA. It grants no current Q04 publication: the legacy verifier still
//! refuses every nonempty legacy or V2 binding set. Root's actual selected
//! gen1/current-flight owner has its own independent native and financial gates.

use std::sync::Arc;

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as Mechanical;
use aos_sandbox_model::RecordNamespace;
use aos_sandbox_protocol::domain_ledger::capacity_family::{all_reservations_owned_by, family};

use super::super::PolicyNativeJournalErrorV1 as ErrorV1;
use super::{PolicyJournalInstanceV1, PolicyJournalStorageV1, RootPolicyJournalV1};

/// Retains the same real ordinary fixed writer through the legacy read scope.
pub(in crate::native) struct PolicyLegacyDesiredReadV1<'journal> {
    journal: &'journal mut RootPolicyJournalV1,
}

/// Retains the actual fixed instance and original sequence for one read scope.
pub(in crate::native) struct PolicyLegacyDesiredSnapshotV1 {
    instance: Arc<PolicyJournalInstanceV1>,
    sequence: u64,
}

impl RootPolicyJournalV1 {
    pub(in crate::native) fn claim_legacy_desired_read_v1(
        &mut self,
    ) -> Result<PolicyLegacyDesiredReadV1<'_>, ErrorV1> {
        // The selected current-flight owner never enters this legacy route.
        if !matches!(self.storage, PolicyJournalStorageV1::Ordinary { .. }) {
            return Err(ErrorV1::boundary());
        }
        self.require_healthy_native()?;
        let read = self.read_view();
        if read.protected_view().is_none() {
            return Err(ErrorV1::boundary());
        }
        let namespace = RecordNamespace::DesiredState;
        family::require_legacy_reservations(read.state())
            .map_err(Mechanical::from)
            .map_err(ErrorV1::from)?;
        let has_foreign_history = read
            .committed_namespaces()
            .iter()
            .any(|committed_namespace| {
                *committed_namespace != namespace
                    && *committed_namespace != RecordNamespace::GlobalCapacityReservation
            });
        let has_foreign_state = read.state().keys().any(|(record_namespace, _)| {
            *record_namespace != namespace
                && *record_namespace != RecordNamespace::GlobalCapacityReservation
        });
        if has_foreign_history
            || has_foreign_state
            || !all_reservations_owned_by(read.state(), namespace)
                .map_err(Mechanical::from)
                .map_err(ErrorV1::from)?
        {
            return Err(Mechanical::ForeignAuthorityNamespace.into());
        }
        Ok(PolicyLegacyDesiredReadV1 { journal: self })
    }
}

impl PolicyLegacyDesiredReadV1<'_> {
    fn require_same_fixed_read_v1(&self) -> Result<(), ErrorV1> {
        self.journal.require_healthy_native()?;
        if !matches!(
            self.journal.storage,
            PolicyJournalStorageV1::Ordinary { .. }
        ) || self.journal.read_view().protected_view().is_none()
        {
            return Err(ErrorV1::boundary());
        }
        Ok(())
    }

    pub(in crate::native) fn get(&self, key: &[u8]) -> Result<Option<&[u8]>, ErrorV1> {
        self.require_same_fixed_read_v1()?;
        Ok(self.journal.get(RecordNamespace::DesiredState, key))
    }

    pub(in crate::native) fn records(
        &self,
    ) -> Result<impl Iterator<Item = (&[u8], &[u8])>, ErrorV1> {
        self.require_same_fixed_read_v1()?;
        Ok(self.journal.records(RecordNamespace::DesiredState))
    }

    pub(in crate::native) fn snapshot(&self) -> Result<PolicyLegacyDesiredSnapshotV1, ErrorV1> {
        self.require_same_fixed_read_v1()?;
        Ok(PolicyLegacyDesiredSnapshotV1 {
            instance: Arc::clone(&self.journal.instance),
            sequence: self.journal.next_sequence(),
        })
    }

    pub(in crate::native) fn validate_snapshot_for_effect(
        &self,
        snapshot: &PolicyLegacyDesiredSnapshotV1,
    ) -> Result<(), ErrorV1> {
        self.require_same_fixed_read_v1()?;
        if !Arc::ptr_eq(&snapshot.instance, &self.journal.instance)
            || snapshot.sequence != self.journal.next_sequence()
        {
            return Err(Mechanical::StaleAuthoritySnapshot.into());
        }
        Ok(())
    }
}
