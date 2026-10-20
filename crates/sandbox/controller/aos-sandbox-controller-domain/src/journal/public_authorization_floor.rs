//! Routes the sole canonical retained public-authorization floor recipe.
//!
//! The private recipe is minted beside the existing floor encoder. It is DATA,
//! not a payer or mutation capability. Purpose-specific native scope owners
//! must be retained independently; this ordinary endpoint preserves the existing
//! protected semantic/native engine and all its fences.

use super::{CommitResult, Journal, JournalError, JournalTransaction};
use crate::cli_model::authorization_adapter::PublicAuthorizationFloorRecipeV1;

impl Journal {
    pub(crate) fn commit_retained_public_authorization_floor_v1(
        &mut self, transaction: &JournalTransaction,
        recipe: &PublicAuthorizationFloorRecipeV1<'_>,
    ) -> Result<CommitResult, JournalError> {
        recipe.require_exact_v1(transaction)?;
        if self.execution_admission.is_some() {
            return self.commit_execution_authorization_floor_v2(transaction, recipe);
        }
        if self.operator_recovery.is_some() {
            return self.commit_operator_recover_floor_v1(transaction, recipe);
        }
        if self.start_admission.is_some() {
            return self.commit_start_authorization_floor_v1(transaction, recipe);
        }
        self.commit(transaction)
    }
}
