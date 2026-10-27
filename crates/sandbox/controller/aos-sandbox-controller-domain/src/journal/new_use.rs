//! Applies the shared typed-target refusal to the actual protected Controller map.
//!
//! A successful negative check supplies no operation grant. Callers retain their
//! original currentness/funding interval and repeat this check before effects.

use aos_sandbox_model::ProjectId;
use aos_sandbox_model::model::ViewSource;
use aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1;
use aos_sandbox_protocol::domain_ledger::delete_batch::new_use::{
    require_public_mutation_targets_live_data_v2, require_view_source_live_data_v2,
};
use super::{Journal, JournalError, RecordNamespace};

impl Journal {
    /// Rejects a tombstoned LiveExport owner from the producer's decoded View.
    ///
    /// The genuine producer retains its existing object integrity, Source,
    /// financial and native checks independently. No descriptor hash is treated
    /// as an owner identity, and this negative check grants no new use.
    ///
    /// # Errors
    /// Refuses unhealthy/unprotected storage, malformed typed owner/tombstone
    /// DATA, and an exact project/LiveExport-owner tombstone match.
    #[doc(hidden)]
    pub fn require_view_source_live_v2(
        &self, project: ProjectId, source: &ViewSource,
    ) -> Result<(), JournalError> {
        self.ensure_protected_authority()?;
        require_view_source_live_data_v2(project, source,
            self.records(RecordNamespace::DesiredState)).map_err(JournalError::NewUseTombstone)
    }

    /// Rejects concrete new uses covered by this protected journal's tombstones.
    ///
    /// Callers must first pay the canonical fixed new-use scratch supplier and
    /// hold the genuine current C interval; this comparison does no native IO.
    /// It neither reauthorizes accepted work nor permits a diagnostic map to
    /// substitute for independently retained native currentness.
    ///
    /// # Errors
    /// Refuses unhealthy/unprotected storage, malformed target/tombstone DATA,
    /// and an exact typed tombstoned target in the supplied authorized project.
    #[doc(hidden)]
    pub fn require_public_mutation_targets_live_v2(
        &self, project: ProjectId, request: &DormantSandboxRequestKindV1,
    ) -> Result<(), JournalError> {
        self.ensure_protected_authority()?;
        require_public_mutation_targets_live_data_v2(project, request,
            self.records(RecordNamespace::DesiredState)).map_err(JournalError::NewUseTombstone)
    }
}
