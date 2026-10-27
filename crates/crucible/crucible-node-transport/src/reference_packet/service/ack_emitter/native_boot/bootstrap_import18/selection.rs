//! Checks the complete selected import definitions in original native custody.
//!
//! Compiled definition factories run sequentially under the independently
//! reconstructed initial row. Their result is immutable correspondence DATA;
//! it installs no model, policy issuer, bootstrap ACK or restoration permission.

use super::*;
use crate::reference_packet::service::complete_restore::import18::{
    PacketNativeImport18Selection, native_import18_selection_construction_storage_data,
    native_import18_selection_prewalk_data,
};

/// Observes the actual original owner around selected-definition construction.
pub(in super::super) trait OriginalImport18SelectionAdmission {
    /// Admits the independently priced sequential compiled definition factories.
    ///
    /// # Errors
    /// Refuses unavailable original credit or changed enclosing custody.
    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        construction: [usize; 3],
    ) -> Result<(), ProviderError>;

    /// Observes the same surviving original owner after either factory outcome.
    ///
    /// # Errors
    /// Refuses unavailable original credit or incomplete whole-owner observation.
    fn finish_data(&self, original: &OriginalImport18RawBootstrap) -> Result<(), ProviderError>;
}

impl OriginalImport18RawBootstrap {
    /// Checks full selected definitions once under reconstructed initial custody.
    ///
    /// This checks complete provider and binding SchemaRefs and exact feature
    /// membership. No old native policy constructor or eager model is invoked.
    /// Failed attempts remain spent with their original raw/typed owners intact.
    ///
    /// # Errors
    /// Refuses re-entry, incomplete initial custody, stale raw/typed operands,
    /// insufficient admission, changed definitions/features or terminal guards.
    pub(in super::super) fn authenticate_selection_data(
        &mut self,
        admission: &dyn OriginalImport18SelectionAdmission,
    ) -> Result<(), ProviderError> {
        if self.selection_started {
            return Err(refused());
        }
        self.selection_started = true;

        let outcome = self.authenticate_current_selection(admission);
        let terminal = self.typed_bodies_data().map(|_| ());
        outcome?;
        terminal?;
        self.selection_authenticated = true;
        Ok(())
    }

    fn authenticate_current_selection(
        &mut self,
        admission: &dyn OriginalImport18SelectionAdmission,
    ) -> Result<(), ProviderError> {
        if !self.initial_reconstructed {
            return Err(refused());
        }
        self.typed_bodies_data()?;
        // The already reconstructed row funds the allocation-free prewalk too.
        // A later factory quote cannot back-fund its own computation.
        self.admit_source_row(self.initial_construction.as_ref().ok_or_else(refused)?.row)?;
        let construction = construction_data(self.bounds.requested_peak)?;
        self.selection_construction_row = Some(construction);
        admission.construct_data(self, construction)?;
        self.typed_bodies_data()?;

        let launch = self.typed_bodies_data()?.launch.launch_data();
        let outcome =
            PacketNativeImport18Selection::SourceSignedImport18.authenticate_launch_data(launch);
        let terminal = admission.finish_data(self);
        outcome?;
        terminal
    }
}

/// Quotes the same sequential full-definition checks before any private receipt.
///
/// # Errors
/// Refuses checked construction overflow or an insufficient independent bound.
pub(in crate::reference_packet::service) fn construction_data(
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    let (temporary, scratch) = native_import18_selection_construction_storage_data(maximum)?;
    let scratch = scratch
        .checked_add(counter_scratch_data())
        .ok_or_else(exhausted)?;
    if temporary
        .checked_add(scratch)
        .is_none_or(|peak| peak > maximum)
    {
        return Err(exhausted());
    }
    Ok([0, temporary, scratch])
}

/// Names the prewalk, actual original loans and terminal result controls.
pub(in crate::reference_packet::service) fn counter_scratch_data() -> usize {
    native_import18_selection_prewalk_data()
        + size_of::<&OriginalImport18RawBootstrap>()
        + size_of::<&mut OriginalImport18RawBootstrap>()
        + size_of::<&dyn OriginalImport18SelectionAdmission>()
        + size_of::<&crate::reference_packet::service::PacketNative5SourceLaunch>()
        + size_of::<PacketNativeImport18Selection>()
        + size_of::<[usize; 3]>()
        + size_of::<Result<[usize; 3], ProviderError>>()
        + size_of::<(usize, usize)>()
        + size_of::<Result<(usize, usize), ProviderError>>()
        + size_of::<Result<(), ProviderError>>() * 4
}
