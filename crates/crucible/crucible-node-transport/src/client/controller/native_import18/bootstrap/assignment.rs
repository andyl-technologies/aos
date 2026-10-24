//! Installs unsigned assignment beneath the same retained Controller and Hello.
//!
//! Neither quote nor construction renews time, reserves an SDK original or
//! authenticates Source proof. The caller admits the whole holder independently.

use super::*;
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::{
    PacketNativeImport18BootstrapAssignmentRowData,
    native_import18_bootstrap_assignment_counter_scratch_data,
    native_import18_bootstrap_assignment_into_data,
    native_import18_bootstrap_assignment_quote_data,
};

impl CnpController {
    /// Quotes unsigned construction beside the actual retained typed owner.
    ///
    /// The caller retains this row, ends all live loans and admits its demand
    /// beside the complete Source/Controller/Hello holder before construction.
    ///
    /// # Errors
    /// Refuses a spent/failed owner, changed Controller/Hello/inputs or short bound.
    pub fn quote_original_native_import18_bootstrap_assignment_data(
        &self,
        hello: &OriginalHelloJournal,
        owner: &OriginalNativeImport18Bootstrap,
        maximum: usize,
    ) -> Result<PacketNativeImport18BootstrapAssignmentRowData, ProviderError> {
        authenticate_unassigned(self, hello, owner)?;
        let cut = self.session.original_bootstrap_hello_cut_data()?;
        let result = native_import18_bootstrap_assignment_quote_data(maximum);
        let terminal = self
            .session
            .authenticate_original_bootstrap_effect_cut_data(cut, 2);
        let row = result?;
        terminal?;
        Ok(row)
    }

    /// Installs the actual unsigned assignment under the unrenewed original cut.
    ///
    /// The same owner keeps its typed inputs, cut and every constructed prefix
    /// after refusal. The attempt cannot be restarted. All three assignment IDs
    /// have independent backing, while the original moved input ID stays retained.
    /// SDK reservation and Source signing are separate, later operations.
    ///
    /// # Errors
    /// Refuses occupied/spent state, changed original ownership or Hello, expired
    /// cut, malformed typed inputs or independently admitted component demand.
    pub fn assign_original_native_import18_bootstrap_data(
        &self,
        hello: &OriginalHelloJournal,
        owner: &mut OriginalNativeImport18Bootstrap,
        row: &PacketNativeImport18BootstrapAssignmentRowData,
        maximum: usize,
    ) -> Result<(), ProviderError> {
        if owner.assignment.is_some() || owner.cut.is_some() || !owner.retained || owner.failed {
            return Err(invalid());
        }
        // Spend the attempt before authentication, including a stale quote or
        // clock refusal that prevents the first allocation from taking place.
        owner.failed = true;
        authenticate_inputs(self, hello, owner)?;
        let cut = self.session.original_bootstrap_hello_cut_data()?;
        owner.cut = Some(cut);

        let result = native_import18_bootstrap_assignment_into_data(
            [
                self.authority().session_id(),
                self.authority().incarnation_id(),
                owner.request_id.as_ref().ok_or_else(invalid)?,
            ],
            owner.request.as_ref().ok_or_else(invalid)?,
            row,
            maximum,
            &mut owner.assignment,
        );
        // Evaluate the terminal cut after either constructor result, before
        // propagating its error. No replacement deadline or fresh budget exists.
        let census = check_retained(owner, row);
        let terminal = self
            .session
            .authenticate_original_bootstrap_effect_cut_data(cut, 2);
        result?;
        census?;
        terminal?;
        owner.failed = false;
        Ok(())
    }

    /// Names both defining quote/constructor and original-cut control layouts.
    pub fn original_native_import18_bootstrap_assignment_counter_scratch_data() -> usize {
        Self::original_native_import18_bootstrap_counter_scratch_data()
            + crate::client::ClientSession::original_bootstrap_effect_cut_counter_scratch_data()
            + native_import18_bootstrap_assignment_counter_scratch_data()
            + size_of::<&OriginalNativeImport18Bootstrap>()
            + size_of::<&mut OriginalNativeImport18Bootstrap>()
            + size_of::<&PacketNativeImport18BootstrapAssignmentRowData>()
            + size_of::<[OperationalDeadline; 2]>()
            + size_of::<Result<OperationalDeadline, ProviderError>>()
            + size_of::<Result<RetainedProtocolMetadataFacts, ProviderError>>()
            + size_of::<[usize; 3]>()
            + size_of::<Result<(), ProviderError>>() * 2
    }
}

fn check_retained(
    owner: &OriginalNativeImport18Bootstrap,
    row: &PacketNativeImport18BootstrapAssignmentRowData,
) -> Result<(), ProviderError> {
    let actual = owner.retained_metadata_data()?;
    let requested = size_of::<OriginalNativeImport18Bootstrap>()
        .checked_add(requested_metadata_backing_storage_data(&actual)?)
        .ok_or_else(credit)?;
    let retained = owner.row.axes[0]
        .checked_add(row.requested_storage_data()[0])
        .ok_or_else(credit)?;
    if requested > retained {
        return Err(credit());
    }
    Ok(())
}

fn authenticate_unassigned(
    controller: &CnpController,
    hello: &OriginalHelloJournal,
    owner: &OriginalNativeImport18Bootstrap,
) -> Result<(), ProviderError> {
    if !owner.retained || owner.failed || owner.assignment.is_some() || owner.cut.is_some() {
        return Err(invalid());
    }
    authenticate_inputs(controller, hello, owner)
}

fn authenticate_inputs(
    controller: &CnpController,
    hello: &OriginalHelloJournal,
    owner: &OriginalNativeImport18Bootstrap,
) -> Result<(), ProviderError> {
    owner.row.authenticate_data(
        controller,
        &OriginalNativeImport18BootstrapBirthInputs {
            hello,
            recipe: &owner.row.recipe,
            initial: &owner.row.initial,
        },
        owner.request_id.as_ref().ok_or_else(invalid)?,
        owner.request.as_ref().ok_or_else(invalid)?,
        storage::checked_sum_data(&owner.row.axes)?,
    )
}
