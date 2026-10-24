//! Retains immutable model-absent import18 policy DATA from the original launch.
//!
//! This owner shares the actual decoded selected9 allocation and stores only
//! fixed correspondence beside it. It owns no Control, runtime model, effect
//! socket, physical Hold or old Native5Policy. Original SDK/Birth/funding and
//! phase provenance remain in the enclosing bootstrap and eventual live owner.

use super::service::PacketNative5SourceLaunch;
use super::service::complete_restore::import18::{
    NATIVE_IMPORT18_EXTENSION, NATIVE_IMPORT18_RESTORED_RECORD_SCHEMA,
    NATIVE_IMPORT18_STAGE_SELECTION, PacketNativeImport18SelectedLaunchWireData,
};
use crate::ProviderError;
use crate::hello_frames::OriginalHelloFrameDigests;
use crucible_node_format::SchemaRef;
use std::{
    mem::{align_of, size_of},
    rc::Rc,
};

/// Retains original immutable launch and full-definition correspondence without a model.
pub(crate) struct NativeImport18PolicyData {
    launch: Rc<PacketNativeImport18SelectedLaunchWireData>,
    recipe_identity: [u8; 32],
    hello: OriginalHelloFrameDigests,
    definitions: [usize; 3],
}

impl NativeImport18PolicyData {
    /// Constructs policy DATA only after independently admitted original checks.
    ///
    /// The actual bootstrap separately proves full launch/definition validation,
    /// original SDK and literal publication, same recipe, custody and funding.
    /// This constructor indexes existing full definitions; it does not authenticate
    /// their factory bodies or install any issuer, policy verifier or permission.
    ///
    /// # Errors
    /// Refuses absent or duplicate selected definition names in the same launch.
    pub(in crate::reference_packet) fn from_original_data(
        launch: Rc<PacketNativeImport18SelectedLaunchWireData>,
        recipe_identity: [u8; 32],
        hello: OriginalHelloFrameDigests,
    ) -> Result<Self, ProviderError> {
        let mut definitions = [None; 3];
        for (index, schema) in launch
            .launch_data()
            .selection
            .provider
            .implementation
            .formats
            .iter()
            .enumerate()
        {
            for (role, name) in definition_names().into_iter().enumerate() {
                if schema.id.as_str() == name && definitions[role].replace(index).is_some() {
                    return Err(refused());
                }
            }
        }
        let [import, stage, record] = definitions;
        Ok(Self {
            launch,
            recipe_identity,
            hello,
            definitions: [
                import.ok_or_else(refused)?,
                stage.ok_or_else(refused)?,
                record.ok_or_else(refused)?,
            ],
        })
    }

    /// Borrows the original program/configuration DATA without constructing a model.
    pub(crate) fn launch_data(&self) -> &PacketNative5SourceLaunch {
        self.launch.launch_data()
    }

    /// Borrows all three complete references from the original immutable roster.
    ///
    /// # Errors
    /// Refuses an inconsistent original definition index.
    pub(crate) fn definitions_data(&self) -> Result<[&SchemaRef; 3], ProviderError> {
        let formats = &self.launch_data().selection.provider.implementation.formats;
        let [import, stage, record] = self.definitions;
        Ok([
            formats.get(import).ok_or_else(refused)?,
            formats.get(stage).ok_or_else(refused)?,
            formats.get(record).ok_or_else(refused)?,
        ])
    }

    /// Borrows the same announced identity already joined by the original bootstrap.
    pub(crate) fn recipe_identity_data(&self) -> &[u8; 32] {
        &self.recipe_identity
    }

    /// Returns correspondence from the original completed literal Hello pair.
    pub(crate) fn hello_data(&self) -> OriginalHelloFrameDigests {
        self.hello
    }

    /// Authenticates the shared edge before discounting original launch backing.
    ///
    /// Equal DTOs in different allocations do not satisfy this comparison.
    ///
    /// # Errors
    /// Refuses a different original shared allocation.
    pub(in crate::reference_packet) fn authenticate_original_data(
        &self,
        launch: &Rc<PacketNativeImport18SelectedLaunchWireData>,
    ) -> Result<(), ProviderError> {
        if !Rc::ptr_eq(&self.launch, launch) {
            return Err(refused());
        }
        Ok(())
    }

    /// Quotes only this additional shared owner and fixed construction controls.
    ///
    /// Original launch backing is counted by its real decoder. This quote is valid
    /// only with the exact shared edge above; all enclosing custody and SDK guards
    /// are separately priced by their defining bootstrap transition.
    ///
    /// # Errors
    /// Refuses shared-layout arithmetic or an independently short restriction.
    pub(in crate::reference_packet) fn construction_data(
        maximum: usize,
    ) -> Result<[usize; 3], ProviderError> {
        let retained = Self::shared_backing_data()?;
        let transient = size_of::<Self>() * 3
            + size_of::<Rc<Self>>() * 2
            + size_of::<Rc<PacketNativeImport18SelectedLaunchWireData>>() * 2;
        let scratch = Self::counter_scratch_data();
        if retained
            .checked_add(transient)
            .and_then(|n| n.checked_add(scratch))
            .is_none_or(|n| n > maximum)
        {
            return Err(refused());
        }
        Ok([retained, transient, scratch])
    }

    /// Counts the defining shared header and policy payload without original graph copies.
    ///
    /// # Errors
    /// Refuses unsupported shared header geometry or checked overflow.
    pub(in crate::reference_packet) fn shared_backing_data() -> Result<usize, ProviderError> {
        crate::retained_metadata::requested_storage::shared_header_storage_data(
            1,
            align_of::<Self>(),
        )?
        .checked_add(size_of::<Self>())
        .ok_or_else(refused)
    }

    /// Names the actual definition indexing, shared-edge and returned row controls.
    pub(in crate::reference_packet) fn counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<Self>()
            + size_of::<Result<Self, ProviderError>>()
            + size_of::<Rc<Self>>() * 2
            + size_of::<&Rc<PacketNativeImport18SelectedLaunchWireData>>() * 2
            + size_of::<Rc<PacketNativeImport18SelectedLaunchWireData>>() * 2
            + size_of::<[u8; 32]>() * 2
            + size_of::<OriginalHelloFrameDigests>() * 2
            + size_of::<[Option<usize>; 3]>()
            + size_of::<[usize; 3]>() * 3
            + size_of::<[&str; 3]>()
            + size_of::<std::array::IntoIter<&str, 3>>()
            + size_of::<std::iter::Enumerate<std::array::IntoIter<&str, 3>>>()
            + size_of::<std::iter::Enumerate<std::slice::Iter<'static, SchemaRef>>>()
            + size_of::<&Vec<SchemaRef>>()
            + size_of::<[&SchemaRef; 3]>()
            + size_of::<Result<[&SchemaRef; 3], ProviderError>>()
            + size_of::<Option<&SchemaRef>>()
            + size_of::<Option<usize>>() * 4
            + size_of::<Result<[usize; 3], ProviderError>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<usize>() * 6
            + size_of::<std::alloc::Layout>()
            + size_of::<Result<std::alloc::Layout, std::alloc::LayoutError>>()
    }
}

fn definition_names() -> [&'static str; 3] {
    [
        NATIVE_IMPORT18_EXTENSION,
        NATIVE_IMPORT18_STAGE_SELECTION,
        NATIVE_IMPORT18_RESTORED_RECORD_SCHEMA,
    ]
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original model-absent import18 policy DATA")
}
