//! Constructs only Source's existing protected namespace and terminal scopes.
//!
//! Every claim borrows its actual held journal. Complete committed history and
//! current rows are checked together; deletion cannot hide a foreign namespace.
//! Original and readonly claims remain in their distinct native owner modules.

use aos_sandbox_protocol::domain_ledger::capacity_family::{
    all_reservations_owned_by, family::require_legacy_reservations,
};

use super::{
    Journal, JournalError, ProtectedAuthorityScope, ProtectedJournalAuthority, RecordNamespace,
};

impl Journal {
    /// Claims the actual Source namespace without a terminal-capacity grant.
    ///
    /// This fixed-role owner rejects every other namespace. Namespace DATA
    /// cannot select another service's native role or construct an original.
    ///
    /// # Errors
    /// Refuses another namespace, unprotected/poisoned custody, malformed floors
    /// or any foreign committed history, current row or reservation owner.
    pub fn claim_protected_authority(
        &mut self,
        namespace: RecordNamespace,
    ) -> Result<ProtectedJournalAuthority<'_>, JournalError> {
        self.ensure_protected_authority()?;
        if namespace != RecordNamespace::SourceProviderAuthority {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        require_legacy_reservations(self.native_view().state())?;
        self.require_source_namespace_history_v1()?;
        Ok(ProtectedJournalAuthority {
            journal: self,
            namespace,
            scope: ProtectedAuthorityScope::SingleNamespace,
        })
    }

    /// Claims Source's exact legacy native-terminal capacity protocol.
    ///
    /// The full original and readonly purposes have distinct claim paths. No
    /// caller-selected global purpose or copied floor can create this borrower.
    ///
    /// # Errors
    /// Refuses unprotected/poisoned custody, malformed floors, or foreign
    /// committed history, current rows or retained reservation ownership.
    pub fn claim_source_provider_native_terminal_authority_v1(
        &mut self,
    ) -> Result<ProtectedJournalAuthority<'_>, JournalError> {
        self.ensure_protected_authority()?;
        require_legacy_reservations(self.native_view().state())?;
        self.require_source_namespace_history_v1()?;

        // Preserve the closed capacity-claim comparison after the complete
        // namespace join, without exposing the old multi-role purpose selector.
        self.ensure_protected_authority()?;
        require_legacy_reservations(self.native_view().state())?;
        Ok(ProtectedJournalAuthority {
            journal: self,
            namespace: RecordNamespace::SourceProviderAuthority,
            scope: ProtectedAuthorityScope::SourceProviderNativeTerminal,
        })
    }

    fn require_source_namespace_history_v1(&self) -> Result<(), JournalError> {
        let native = self.native_view();
        let namespace = RecordNamespace::SourceProviderAuthority;
        let has_foreign_history = native.committed_namespaces().iter().any(|value| {
            *value != namespace && *value != RecordNamespace::GlobalCapacityReservation
        });
        let has_foreign_state = native.state().keys().any(|(value, _)| {
            *value != namespace && *value != RecordNamespace::GlobalCapacityReservation
        });
        if has_foreign_history
            || has_foreign_state
            || !all_reservations_owned_by(native.state(), namespace)?
        {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        Ok(())
    }
}
