//! Selects the exact first-local Storage cleanup from Root's held fresh models.
//!
//! Selection borrows the same completed full graph, four Session cuts and current
//! assignment owner. Its fixed Copy result is retained inline in the already-paid
//! pending Root owner. It allocates no model, opens no native resource and grants
//! no signature, catalog preparation, acceptance or destruction authority.

use aos_sandbox_model::OperationId;
use crate::journal::JournalError;
pub(super) use crate::lifecycle::SelectedDeleteStoragePreparationDataV2 as SelectedPreparationDataV2;
use crate::lifecycle::{select_first_local_delete_storage_preparation_data_v2,
    DeleteStorageSelectionErrorV2};
use super::{RootDeleteChallengeOriginalsV1, RootDeleteCleanupInputsOriginalV2,
    RootDeleteControllerCurrentOriginalV1, RootDeleteErrorV1, RootDeleteGraphComparisonOriginalV2};

#[derive(Default)]
pub(crate) struct RootDeleteResourceSelectionOriginalV2 {
    selection: Option<Result<SelectedPreparationDataV2, JournalError>>,
    helper: Option<Result<SelectedPreparationDataV2, DeleteStorageSelectionErrorV2>>,
    closed: Option<JournalError>,
}

impl RootDeleteResourceSelectionOriginalV2 {
    pub(super) fn select_once_v2(&mut self, challenge: &RootDeleteChallengeOriginalsV1,
        inputs: &RootDeleteCleanupInputsOriginalV2, controller: &RootDeleteControllerCurrentOriginalV1,
        comparison: &RootDeleteGraphComparisonOriginalV2,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.selection.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(RootDeleteErrorV1::Original);
        }
        self.selection = Some(self.select_v2(challenge, inputs, controller, comparison));
        self.selected_v2().map(|_| ())
    }

    fn select_v2(&mut self, challenge: &RootDeleteChallengeOriginalsV1,
        inputs: &RootDeleteCleanupInputsOriginalV2, controller: &RootDeleteControllerCurrentOriginalV1,
        comparison: &RootDeleteGraphComparisonOriginalV2,
    ) -> Result<SelectedPreparationDataV2, JournalError> {
        let invalid = || JournalError::ProtectedBoundary;
        let selection = comparison.selection_data_v2().map_err(|_| invalid())?;
        let manifest = inputs.manifest_v2().map_err(|_| invalid())?;
        let inventory = controller.current_storage_inventory_data_v2().map_err(|_| invalid())?;
        let lifecycle = controller.current_storage_lifecycle_data_v2().map_err(|_| invalid())?;
        let query = challenge.source_query_v1().map_err(|_| invalid())?;
        self.helper = Some(select_first_local_delete_storage_preparation_data_v2(selection.root,
            &selection.resources, manifest, inventory, lifecycle, OperationId::from_bytes(query.operation),
            query.nonce, query.cutoff));
        self.helper.as_ref().and_then(|value| value.as_ref().ok()).copied().ok_or_else(invalid)
    }

    pub(crate) fn require_selected_v2(&self) -> Result<(), RootDeleteErrorV1> {
        self.selected_v2().map(|_| ())
    }

    pub(super) fn selected_v2(&self) -> Result<SelectedPreparationDataV2, RootDeleteErrorV1> {
        if self.closed.is_some() { return Err(RootDeleteErrorV1::Original); }
        self.selection.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(RootDeleteErrorV1::Original)
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.helper.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.selection.as_ref().and_then(|value| value.as_ref().err())
                .or(self.closed.as_ref()).map(|cause| cause as _))
    }
}
