//! Retains receiving aliases until their original World physically returns.
//!
//! One inline value moves from the caller to the existing Main control cell,
//! then into its existing Service phase. No new receiver count is registered.

use crate::imported_checkpoint::{
    ImportedCheckpointBasis, ImportedCheckpointMaintenance, ImportedCheckpointReturn,
    RetainedImportedCheckpoint,
};
use crate::lifecycle_cleanup::{ServiceMainPreclaim, ServiceMainReceiver};

/// Owns actual replay or maintenance aliases and their existing output receiver.
///
/// The Main's configured slot sizeof pays this inline value before Service
/// birth. The separate actual Loop returns through its original carrier; this
/// value cannot construct or expose a World.
pub(crate) struct ServiceRetirementInput {
    aliases: Option<RetirementAliases>,
    returned: Option<ImportedCheckpointReturn>,
    receiver: Option<ServiceMainReceiver>,
    semantic_shutdown: Option<crucible::SchedulerError>,
    aliases_destroyed: bool,
    receiver_return_attempted: bool,
    receiver_return_refused: bool,
}

enum RetirementAliases {
    Basis(ImportedCheckpointBasis),
    Maintenance(RetainedImportedCheckpoint),
}

impl ServiceRetirementInput {
    pub(crate) fn from_maintenance(
        basis: ImportedCheckpointBasis,
        maintenance: ImportedCheckpointMaintenance<'_>,
        receiver: ServiceMainReceiver,
        semantic_shutdown: Option<crucible::SchedulerError>,
    ) -> Self {
        Self {
            aliases: Some(RetirementAliases::Maintenance(
                maintenance.into_cleanup_custody(basis),
            )),
            returned: None,
            receiver: Some(receiver),
            semantic_shutdown,
            aliases_destroyed: false,
            receiver_return_attempted: false,
            receiver_return_refused: false,
        }
    }

    /// Retains only actual replay basis aliases; no maintenance Original exists.
    pub(crate) fn from_imported_basis(
        basis: ImportedCheckpointBasis,
        receiver: ServiceMainReceiver,
    ) -> Self {
        Self {
            aliases: Some(RetirementAliases::Basis(basis)),
            returned: None,
            receiver: Some(receiver),
            semantic_shutdown: None,
            aliases_destroyed: false,
            receiver_return_attempted: false,
            receiver_return_refused: false,
        }
    }

    /// Corroborates the saved receiver's original role without issuing it.
    pub(crate) fn matches_main_role(&self, key: &ServiceMainPreclaim) -> bool {
        self.receiver
            .as_ref()
            .is_some_and(|receiver| receiver.matches_main_role(key))
    }

    /// Borrows the caller's actual semantic shutdown refusal independently.
    ///
    /// This is history, never a native body/World return or receiver ACK fact.
    pub(crate) fn semantic_shutdown_failure(&self) -> Option<&crucible::SchedulerError> {
        self.semantic_shutdown.as_ref()
    }

    pub(super) fn retry_after_world_cleanup(&mut self) -> bool {
        if let Some(aliases) = self.aliases.take() {
            match aliases {
                RetirementAliases::Basis(basis) => drop(basis),
                RetirementAliases::Maintenance(imported) => {
                    self.returned = Some(imported.retire_unpublished());
                }
            }
            self.aliases_destroyed = true;
        }
        if !self.aliases_destroyed {
            return false;
        }
        if let Some(returned) = &mut self.returned {
            if !returned.retry_parent_return() {
                return false;
            }
        }
        if let Some(receiver) = self.receiver.take() {
            self.receiver_return_attempted = true;
            if let Err(receiver) = receiver.return_after_alias_destruction() {
                self.receiver_return_refused = true;
                self.receiver = Some(receiver);
                return false;
            }
        }
        self.is_returned()
    }

    pub(super) fn is_returned(&self) -> bool {
        self.aliases_destroyed
            && self.aliases.is_none()
            && self.receiver.is_none()
            && self
                .returned
                .as_ref()
                .is_none_or(|returned| returned.parent_returned())
    }

    pub(super) fn returned(&self) -> Option<&ImportedCheckpointReturn> {
        self.returned.as_ref()
    }
}

impl std::fmt::Debug for ServiceRetirementInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServiceRetirementInput")
            .field("aliases_destroyed", &self.aliases_destroyed)
            .field("receiver_return_attempted", &self.receiver_return_attempted)
            .field("receiver_return_refused", &self.receiver_return_refused)
            .field("returned", &self.returned)
            .field("semantic_shutdown", &self.semantic_shutdown)
            .finish_non_exhaustive()
    }
}
