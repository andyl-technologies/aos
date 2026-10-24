//! Retains the native Hello roster under original initial bootstrap custody.
//!
//! This constructor uses the defining immutable launch declaration and retained
//! roster builder. It constructs no model, negotiation, bootstrap ACK or phase
//! permission; full launch/definition validation and actual Hello remain separate.

use super::*;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crate::reference_packet::service::complete_restore::import18::hello::{
    PacketNativeImport18HelloDeclarationData, PacketNativeImport18HelloSelectionData,
    native_import18_hello_declaration_data,
};
use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};

/// Observes the same enclosing owner before and after native roster construction.
pub(in super::super) trait OriginalImport18HelloSelectionAdmission {
    /// Admits the actual stored selection row before its allocating constructor.
    ///
    /// # Errors
    /// Refuses unavailable original credit, changed custody or incomplete census.
    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        selection: [usize; 3],
    ) -> Result<(), ProviderError>;

    /// Observes actual surviving selection backing after either constructor result.
    ///
    /// # Errors
    /// Refuses stale custody or actual whole-owner demand beyond original credit.
    fn finish_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        actual_selection_backing: usize,
    ) -> Result<(), ProviderError>;
}

impl OriginalImport18RawBootstrap {
    /// Constructs the native feature/key roster once after initial correspondence.
    ///
    /// The enclosing actual owner and admission retain every partial selection.
    /// The shared initial formula independently prices these exact fields and
    /// constructor before any original private body is received. No model or
    /// ordinary Realize/Admit/Ready flag is initialized here.
    ///
    /// # Errors
    /// Refuses re-entry, unchecked full definitions, incomplete/stale original
    /// initial custody, declaration
    /// or quote failure, short original credit/admission, allocation or terminal
    /// guard failure. Initialized declaration and roster partials stay retained.
    pub(in super::super) fn construct_hello_selection_data(
        &mut self,
        admission: &dyn OriginalImport18HelloSelectionAdmission,
    ) -> Result<(), ProviderError> {
        if self.hello_started {
            return Err(refused());
        }
        self.hello_started = true;
        let outcome = self.construct_current_hello_selection(admission);
        let terminal = self.typed_bodies_data().map(|_| ());
        outcome?;
        terminal?;
        self.hello_complete = true;
        Ok(())
    }

    fn construct_current_hello_selection(
        &mut self,
        admission: &dyn OriginalImport18HelloSelectionAdmission,
    ) -> Result<(), ProviderError> {
        if !self.initial_reconstructed || !self.selection_authenticated {
            return Err(refused());
        }
        // Existing independent initial funding admits fixed quote controls.
        // The later declaration/selection rows cannot back-fund this operation.
        self.typed_bodies_data()?;
        self.admit_source_row(self.initial_construction.as_ref().ok_or_else(refused)?.row)?;
        let launch = self.typed_bodies_data()?.launch.launch_data();
        self.hello_declaration = Some(native_import18_hello_declaration_data(launch)?);
        let row = construction_data(self.typed_bodies_data()?.launch.launch_data())?;
        self.hello_construction_row = Some(row);
        admission.construct_data(self, row)?;
        self.typed_bodies_data()?;

        let declaration = self.hello_declaration.as_ref().ok_or_else(refused)?;
        let outcome = declaration.retain_selection_into_data(&mut self.hello_selection);
        let actual = self.hello_selection_backing_data();
        let terminal = actual.and_then(|actual| admission.finish_data(self, actual));
        outcome?;
        terminal
    }

    /// Lends this same completed roster while original bootstrap guards hold.
    ///
    /// The caller independently admits its callback's work. Only Copy DATA may
    /// return; a negotiation or live native issuer is not created by this loan.
    ///
    /// # Errors
    /// Refuses incomplete/refused construction, absent output, stale original
    /// custody, callback refusal or terminal guards after the callback.
    pub(in super::super) fn with_hello_selection_data<R: Copy>(
        &self,
        inspect: impl FnOnce(&PacketNativeImport18HelloSelectionData) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        if !self.hello_complete {
            return Err(refused());
        }
        self.typed_bodies_data()?;
        let outcome = inspect(self.hello_selection.as_ref().ok_or_else(refused)?);
        let terminal = self.typed_bodies_data().map(|_| ());
        let output = outcome?;
        terminal?;
        Ok(output)
    }

    /// Names the separate completed-roster loan and actual Copy return controls.
    pub(in super::super) fn hello_selection_loan_counter_scratch_data<R: Copy>() -> usize {
        counter_scratch_data()
            + private_body_owner_counter_scratch_data()
            + native_import18_private_prefix_counter_scratch_data()
            + size_of::<R>()
            + size_of::<Result<R, ProviderError>>()
    }

    /// Counts actual feature/key backing, including incomplete construction.
    ///
    /// # Errors
    /// Refuses metadata population or checked backing-layout overflow.
    pub(super) fn hello_selection_backing_data(&self) -> Result<usize, ProviderError> {
        let mut observer = MetadataObserver::new();
        observer.observe(&self.hello_selection)?;
        requested_metadata_backing_storage_data(&observer.finish())
    }
}

/// Quotes the actual roster constructor without creating its output or a policy.
///
/// # Errors
/// Refuses malformed actual launch selectors or checked construction overflow.
pub(in crate::reference_packet::service) fn construction_data(
    launch: &PacketNative5SourceLaunch,
) -> Result<[usize; 3], ProviderError> {
    let declaration = native_import18_hello_declaration_data(launch)?;
    let mut row = declaration.selection_construction_storage_data()?;
    row[1] = row[1]
        .checked_add(size_of::<PacketNativeImport18HelloDeclarationData>())
        .and_then(|n| {
            n.checked_add(size_of::<
                Result<PacketNativeImport18HelloDeclarationData, ProviderError>,
            >())
        })
        .ok_or_else(exhausted)?;
    row[2] = row[2]
        .checked_add(counter_scratch_data())
        .ok_or_else(exhausted)?;
    Ok(row)
}

/// Names original roster construction, actual census and guarded-loan controls.
pub(in crate::reference_packet::service) fn counter_scratch_data() -> usize {
    PacketNativeImport18HelloDeclarationData::declaration_counter_scratch_data()
        + size_of::<&OriginalImport18RawBootstrap>()
        + size_of::<&mut OriginalImport18RawBootstrap>()
        + size_of::<&dyn OriginalImport18HelloSelectionAdmission>()
        + size_of::<PacketNativeImport18HelloDeclarationData>()
        + size_of::<Option<&PacketNativeImport18HelloDeclarationData>>()
        + size_of::<&PacketNativeImport18HelloSelectionData>()
        + size_of::<Option<&PacketNativeImport18HelloSelectionData>>()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<MetadataObserver<'static>>()
        + size_of::<[usize; 3]>() * 2
        + size_of::<Result<[usize; 3], ProviderError>>()
        + size_of::<usize>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<(), ProviderError>>() * 4
}
