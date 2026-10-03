//! Same-writer fixed Source observations without append or settlement authority.
//!
//! The complete floor syntax and physical custody are checked here. Source owns
//! the separate full ledger codec/configuration checks; this derivative grants
//! neither live archive eligibility nor an original native admission.

use super::{
    FixedSourceProviderJournalHandoffV1, Journal, JournalError, JournalRecord,
    ProtectedAuthorityScope, ProtectedJournalAuthority, ProtectedJournalSnapshot, RecordNamespace,
    capacity_reservation,
};

/// Borrows the actual fixed Source writer for immutable mixed-profile readback.
///
/// The raw view is immutable and its purpose scope rejects generic mutation,
/// legacy capacity grants and effect snapshots. No append or DELETE is exposed.
pub struct SourceProviderHeldReadOnlyJournalAuthorityV1<'journal> {
    authority: ProtectedJournalAuthority<'journal>,
}

impl Journal {
    /// Claims observation-only custody of the fixed Source journal and floors.
    ///
    /// # Errors
    ///
    /// Rejects changed physical names/inodes, unprotected or unhealthy custody,
    /// foreign committed history/state, and malformed or foreign floor families.
    pub fn claim_source_provider_held_readonly_v1(
        &mut self,
    ) -> Result<SourceProviderHeldReadOnlyJournalAuthorityV1<'_>, JournalError> {
        self.ensure_protected_authority()?;
        let authority = SourceProviderHeldReadOnlyJournalAuthorityV1 {
            authority: ProtectedJournalAuthority {
                journal: self,
                namespace: RecordNamespace::SourceProviderAuthority,
                scope: ProtectedAuthorityScope::SourceProviderHeldReadOnly,
            },
        };
        authority.require_current()?;
        Ok(authority)
    }
}

impl<'journal> SourceProviderHeldReadOnlyJournalAuthorityV1<'journal> {
    fn require_current(&self) -> Result<(), JournalError> {
        validate_current_authority(&self.authority)
    }

    /// Rechecks custody and borrows immutable rows for Security observations only.
    ///
    /// Legacy Source/effect/capacity factory purpose checks reject this scope.
    ///
    /// # Errors
    ///
    /// Rejects stale physical custody, unhealthy state or malformed/foreign floors.
    pub fn security_view(&self) -> Result<&ProtectedJournalAuthority<'journal>, JournalError> {
        self.require_current()?;
        Ok(&self.authority)
    }

    /// Captures the actual mixed read scope, instance and sequence.
    ///
    /// # Errors
    ///
    /// Rejects stale physical custody, unhealthy state or invalid floor union syntax.
    pub fn snapshot(&self) -> Result<ProtectedJournalSnapshot, JournalError> {
        self.require_current()?;
        self.authority.snapshot()
    }

    /// Rechecks the exact physical read snapshot without granting an effect.
    ///
    /// # Errors
    ///
    /// Rejects changed names, instance, scope, sequence, health or floor syntax.
    pub fn validate_snapshot(
        &self,
        snapshot: &ProtectedJournalSnapshot,
    ) -> Result<(), JournalError> {
        self.require_current()?;
        self.authority.validate_snapshot(snapshot)
    }

    /// Borrows a fixed handoff for the genuine completed Security handshake.
    ///
    /// # Errors
    ///
    /// Rejects changed physical custody, unhealthy state or malformed floors.
    pub fn session_handoff(
        &self,
    ) -> Result<FixedSourceProviderJournalHandoffV1<'_, 'journal>, JournalError> {
        self.require_current()?;
        Ok(FixedSourceProviderJournalHandoffV1 {
            authority: &self.authority,
            sequence: self.authority.journal.next_sequence,
        })
    }

    /// Returns canonical complete namespace46 observations, never settlement grants.
    ///
    /// # Errors
    ///
    /// Rejects changed physical custody, malformed/unknown or foreign floor rows.
    pub fn capacity_records(&self) -> Result<Vec<JournalRecord>, JournalError> {
        self.require_current()?;
        Ok(self
            .authority
            .journal
            .records(RecordNamespace::GlobalCapacityReservation)
            .map(|(key, value)| {
                JournalRecord::put(
                    RecordNamespace::GlobalCapacityReservation,
                    key.to_vec(),
                    value.to_vec(),
                )
            })
            .collect())
    }
}

pub(super) fn validate_current_authority(
    authority: &ProtectedJournalAuthority<'_>,
) -> Result<(), JournalError> {
    let journal = &authority.journal;
    journal.ensure_protected_authority()?;
    if authority.namespace != RecordNamespace::SourceProviderAuthority
        || authority.scope != ProtectedAuthorityScope::SourceProviderHeldReadOnly
    {
        return Err(JournalError::ForeignAuthorityNamespace);
    }
    authority.validate_held_root_owned_at("/var/lib/aos/source-provider", "provider.journal")?;
    let namespace = RecordNamespace::SourceProviderAuthority;
    if journal.committed_namespaces.iter().any(|value| {
        !matches!(
            value,
            RecordNamespace::SourceProviderAuthority | RecordNamespace::GlobalCapacityReservation
        )
    }) || journal.state.keys().any(|(value, _)| {
        !matches!(
            value,
            RecordNamespace::SourceProviderAuthority | RecordNamespace::GlobalCapacityReservation
        )
    }) || !capacity_reservation::all_reservations_owned_by(&journal.state, namespace)?
    {
        return Err(JournalError::ForeignAuthorityNamespace);
    }
    Ok(())
}
