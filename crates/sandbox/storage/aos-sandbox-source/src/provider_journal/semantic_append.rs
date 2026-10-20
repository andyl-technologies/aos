//! Coordinates the Source-only policy around the same native append stages.
//!
//! The actual common holder projects, encodes, appends, applies and publishes.
//! This private Source coordinator retains the existing complete original-floor
//! checks between those steps. It exposes no callback, supplied native state,
//! generic role gate, signer, financial loan or Source original constructor.

use aos_sandbox_broker::canonical_journal::coordinator::{
    CanonicalCoordinatorAppendDataV1, CanonicalCoordinatorAppendV1,
};

use super::{CommitResult, Journal, JournalError, JournalTransaction};

mod policy;
mod preflight;

/// Selects only the existing private Source-original comparison branch.
#[derive(Clone, Copy)]
pub(super) enum SourceOwnerEdge {
    SourceOriginal,
}

/// Carries private comparison selectors without granting native authority.
#[derive(Clone, Copy, Default)]
pub(super) struct AppendScope {
    pub(super) settling_reservation: Option<[u8; 32]>,
    pub(super) allow_capacity_records: bool,
    pub(super) root_local_edge: Option<SourceOwnerEdge>,
}

pub(super) type PreflightScope = AppendScope;

impl Journal {
    /// Appends ordinary Source rows without selecting an original owner edge.
    ///
    /// # Errors
    /// Refuses protected original/floor mutations, malformed or duplicate input,
    /// actual opened bounds, or the original native append/publication failure.
    pub fn commit(
        &mut self,
        transaction: &JournalTransaction,
    ) -> Result<CommitResult, JournalError> {
        self.commit_in_scope(transaction, AppendScope::default())
    }

    pub(super) fn commit_in_scope(
        &mut self,
        transaction: &JournalTransaction,
        scope: AppendScope,
    ) -> Result<CommitResult, JournalError> {
        let scope = policy::validate_before_projection(self, transaction, scope)?;

        let mut stage = self
            .held
            .prepare_append_once(transaction)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let primary = (|| {
            let materialized_bytes = stage
                .projected_materialized_bytes()
                .ok_or(JournalError::ProtectedBoundary)?;
            let (commit_sequence, following_sequence) = self
                .held
                .append_coordinates_once(&mut stage)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            policy::validate_after_coordinates(self, transaction, scope, following_sequence)?;

            let expected_length = self
                .held
                .expected_append_length_once(&mut stage)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            policy::validate_after_expected_length(
                self,
                transaction,
                scope,
                materialized_bytes,
                expected_length,
            )?;

            // The actual held original performs the same final native append;
            // the private comparison selector cannot replace this ownership.
            let durable_bytes = self
                .held
                .append_prepared_once(&mut stage)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            while self
                .held
                .apply_next_record_once(&mut stage)
                .map_err(|_| JournalError::ProtectedBoundary)?
            {}
            self.held
                .publish_append_once(&mut stage)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            self.held
                .finish_append_after_posts_once(&mut stage)
                .map_err(|_| JournalError::ProtectedBoundary)?;

            Ok(CommitResult {
                commit_sequence,
                durable_bytes,
            })
        })();

        // The Provider path is the existing ordinary allocation/disposal mode.
        // Extract its precise lower cause only after its original stage-local
        // disposal; semantic errors stay first when no lower operation failed.
        match primary {
            Ok(completed) => Ok(completed),
            Err(primary) => match stage.take_ordinary_error_v1() {
                Ok(Some(native)) => Err(JournalError::from(native)),
                _ => Err(primary),
            },
        }
    }
}
