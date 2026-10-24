//! Borrows the actual immutable archive graph without serializing its descriptor.
//!
//! The authenticated index and manifest are historical values. Shared allocation
//! edges refer to the enclosing writer's same finite alias bank. A directory
//! role records retained ownership; it never reconstructs or opens a descriptor.

use super::*;
use crate::node_contract::restored_owner_history::{
    OriginalRestoredOwnerCapacityAliases, OriginalRestoredOwnerCapacityRow,
    OriginalRestoredOwnerCapacityRows, OriginalRestoredOwnerCapacityWalk,
};
use crate::node_contract::{NativeCaptureLimits, RuntimeError};
use serde::Serializer;
use std::cell::RefCell;

pub(crate) struct ArchiveHistory<'a> {
    archive: &'a NativeArchiveRecord,
}

impl NativeArchiveRecord {
    pub(crate) fn borrowed_settled_archive_history_data(
        &self,
    ) -> Result<ArchiveHistory<'_>, RuntimeError> {
        self.authenticate_complete_load_admission()?;
        Ok(ArchiveHistory { archive: self })
    }
}

impl<'a> ArchiveHistory<'a> {
    pub(crate) fn with_aliases<'view>(
        &'view self,
        aliases: &'view RefCell<OriginalRestoredOwnerCapacityAliases>,
    ) -> impl Serialize + 'view {
        ArchiveHistoryView {
            archive: self.archive,
            aliases,
        }
    }

    pub(crate) fn metadata_demand_data(&self) -> Result<(usize, usize), RuntimeError> {
        let index = OriginalRestoredOwnerCapacityRows(self.archive.index.as_ref())
            .metadata_demand_data()?;
        let manifest =
            OriginalRestoredOwnerCapacityRows(&self.archive.manifest).metadata_demand_data()?;
        Ok((
            index
                .0
                .checked_add(manifest.0)
                .and_then(|n| n.checked_add(2))
                .ok_or(RuntimeError::ResourceLimit)?,
            index
                .1
                .checked_add(manifest.1)
                .and_then(|n| n.checked_add(2))
                .ok_or(RuntimeError::ResourceLimit)?,
        ))
    }
}

struct ArchiveHistoryView<'a> {
    archive: &'a NativeArchiveRecord,
    aliases: &'a RefCell<OriginalRestoredOwnerCapacityAliases>,
}

impl Serialize for ArchiveHistoryView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{Error, SerializeStruct};

        let NativeArchiveRecord {
            complete_load,
            index,
            manifest,
            directory,
            limits,
        } = self.archive;
        self.archive
            .authenticate_complete_load_admission()
            .map_err(S::Error::custom)?;
        let admission = complete_load
            .as_ref()
            .ok_or_else(|| S::Error::custom(RuntimeError::ForeignAuthority))?;
        let index_edge = self
            .aliases
            .try_borrow_mut()
            .map_err(|_| S::Error::custom(RuntimeError::OwnerBusy))?
            .shared_arc_owner_data(index)
            .map_err(S::Error::custom)?;
        let directory_edge = self
            .aliases
            .try_borrow_mut()
            .map_err(|_| S::Error::custom(RuntimeError::OwnerBusy))?
            .shared_arc_owner_data(directory)
            .map_err(S::Error::custom)?;
        OriginalRestoredOwnerCapacityRows(index.as_ref())
            .metadata_demand_data()
            .map_err(S::Error::custom)?;
        OriginalRestoredOwnerCapacityRows(manifest)
            .metadata_demand_data()
            .map_err(S::Error::custom)?;

        let mut value = serializer.serialize_struct("CompleteOriginalArchiveHistory", 9)?;
        value.serialize_field(
            "schema",
            "source-private.complete-original-archive-history/1",
        )?;
        value.serialize_field("index_edge", &index_edge)?;
        value.serialize_field("index", index.as_ref())?;
        value.serialize_field(
            "index_capacities",
            &OriginalRestoredOwnerCapacityRows(index.as_ref()),
        )?;
        value.serialize_field("manifest", manifest)?;
        value.serialize_field(
            "manifest_capacities",
            &OriginalRestoredOwnerCapacityRows(manifest),
        )?;
        value.serialize_field("directory_edge", &directory_edge)?;
        value.serialize_field("limits", &ArchiveLimitsHistory(limits))?;
        value.serialize_field("load_admission", &admission.borrowed_settled_history_data())?;
        let completed = value.end()?;
        self.archive
            .authenticate_complete_load_admission()
            .map_err(S::Error::custom)?;
        Ok(completed)
    }
}

impl OriginalRestoredOwnerCapacityWalk for Index {
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn FnMut(OriginalRestoredOwnerCapacityRow) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        let Self {
            schema_version: _,
            artifact,
            objects,
            owners,
            selected_extensions,
            original_capture_journal,
        } = self;
        artifact.capacities(depth, sink)?;
        objects.capacities(depth, sink)?;
        owners.capacities(depth, sink)?;
        selected_extensions.capacities(depth, sink)?;
        original_capture_journal.capacities(depth, sink)
    }
}

impl OriginalRestoredOwnerCapacityWalk for Object {
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn FnMut(OriginalRestoredOwnerCapacityRow) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        let Self {
            reference,
            dependencies,
        } = self;
        reference.capacities(depth, sink)?;
        dependencies.capacities(depth, sink)
    }
}

impl OriginalRestoredOwnerCapacityWalk for NativeOwnerState {
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn FnMut(OriginalRestoredOwnerCapacityRow) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        let Self {
            owner,
            participants,
            key,
            cut: _,
            state,
            evidence,
            artifacts,
        } = self;
        owner.capacities(depth, sink)?;
        participants.capacities(depth, sink)?;
        key.capacities(depth, sink)?;
        state.capacities(depth, sink)?;
        evidence.capacities(depth, sink)?;
        artifacts.capacities(depth, sink)
    }
}

impl OriginalRestoredOwnerCapacityWalk for NativeArtifactState {
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn FnMut(OriginalRestoredOwnerCapacityRow) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        let Self {
            role,
            name,
            content,
        } = self;
        role.capacities(depth, sink)?;
        name.capacities(depth, sink)?;
        content.capacities(depth, sink)
    }
}

struct ArchiveLimitsHistory<'a>(&'a NativeArchiveLimits);
struct StateLimitsHistory<'a>(&'a crate::node_state::StateLimits);
struct NativeLimitsHistory<'a>(&'a NativeCaptureLimits);

impl Serialize for ArchiveLimitsHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let NativeArchiveLimits { state, native } = self.0;
        let mut value = serializer.serialize_struct("NativeArchiveLimitsHistory", 2)?;
        value.serialize_field("state", &StateLimitsHistory(state))?;
        value.serialize_field("native", &NativeLimitsHistory(native))?;
        value.end()
    }
}

macro_rules! scalar_fields {
    ($wrapper:ident, $ty:path, $($field:ident),+ $(,)?) => {
        impl Serialize for $wrapper<'_> {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                use serde::ser::SerializeStruct;
                let $ty { $($field,)+ } = self.0;
                let mut value = serializer.serialize_struct(stringify!($wrapper), [$(stringify!($field)),+].len())?;
                $(value.serialize_field(stringify!($field), $field)?;)+
                value.end()
            }
        }
    };
}

scalar_fields!(
    StateLimitsHistory,
    crate::node_state::StateLimits,
    maximum_record_bytes,
    maximum_owners_or_domains,
    maximum_content_bytes,
    maximum_total_content_bytes,
    maximum_content_objects,
    maximum_dependency_edges,
    maximum_dependency_depth,
    maximum_native_memory_bytes,
    maximum_native_writable_bytes,
    maximum_native_processes,
    maximum_native_descriptors
);
scalar_fields!(
    NativeLimitsHistory,
    NativeCaptureLimits,
    maximum_record_bytes,
    maximum_total_record_bytes,
    maximum_objects,
    maximum_artifact_bytes,
    maximum_total_artifact_bytes
);

impl NativeArchiveRecord {
    /// Names direct historical views; output and serializer work stay separate.
    pub(crate) fn settled_history_counter_scratch_data() -> usize {
        let terms = [
            std::mem::size_of::<ArchiveHistory<'static>>(),
            std::mem::size_of::<Result<ArchiveHistory<'static>, RuntimeError>>(),
            std::mem::size_of::<ArchiveHistoryView<'static>>(),
            std::mem::size_of::<ArchiveLimitsHistory<'static>>(),
            std::mem::size_of::<StateLimitsHistory<'static>>(),
            std::mem::size_of::<NativeLimitsHistory<'static>>(),
            std::mem::size_of::<&NativeArchiveRecord>(),
            std::mem::size_of::<&Index>(),
            std::mem::size_of::<&CaptureManifest>(),
            std::mem::size_of::<&OriginalRestoredOwnerCapacityAliases>(),
            std::mem::size_of::<std::cell::RefMut<'static, OriginalRestoredOwnerCapacityAliases>>(),
            std::mem::size_of::<
                Result<
                    std::cell::RefMut<'static, OriginalRestoredOwnerCapacityAliases>,
                    std::cell::BorrowMutError,
                >,
            >(),
            std::mem::size_of::<OriginalRestoredOwnerCapacityRow>(),
            std::mem::size_of::<Result<OriginalRestoredOwnerCapacityRow, RuntimeError>>(),
            std::mem::size_of::<OriginalRestoredOwnerCapacityRows<'static, Index>>(),
            std::mem::size_of::<OriginalRestoredOwnerCapacityRows<'static, CaptureManifest>>(),
            std::mem::size_of::<Option<&super::complete_original_loader::CompleteLoadAdmission>>(),
            std::mem::size_of::<&super::complete_original_loader::CompleteLoadAdmission>(),
            std::mem::size_of::<(
                &Option<super::complete_original_loader::CompleteLoadAdmission>,
                &Arc<Index>,
                &CaptureManifest,
                &Arc<File>,
                &NativeArchiveLimits,
            )>(),
            std::mem::size_of::<(
                &u16,
                &ContentRef,
                &Vec<Object>,
                &Vec<NativeOwnerState>,
                &Option<ContentRef>,
                &Option<ContentRef>,
            )>(),
            std::mem::size_of::<(&ContentRef, &Vec<ContentRef>)>(),
            std::mem::size_of::<(
                &Id,
                &Vec<Id>,
                &NativeStateKey,
                &Position,
                &ContentRef,
                &Vec<ContentRef>,
                &Vec<NativeArtifactState>,
            )>(),
            std::mem::size_of::<(&Id, &String, &ContentRef)>(),
            std::mem::size_of::<std::slice::Iter<'static, Object>>(),
            std::mem::size_of::<std::slice::Iter<'static, NativeOwnerState>>(),
            std::mem::size_of::<std::slice::Iter<'static, NativeArtifactState>>(),
            std::mem::size_of::<(&u32, &str, &usize, &str, &str)>(),
            std::mem::size_of::<(&crate::node_state::StateLimits, &NativeCaptureLimits)>(),
            std::mem::size_of::<(
                &usize,
                &usize,
                &usize,
                &usize,
                &usize,
                &usize,
                &usize,
                &u64,
                &u64,
                &u64,
                &u64,
            )>(),
            std::mem::size_of::<(&usize, &usize, &usize, &u64, &u64)>(),
            std::mem::size_of::<(usize, usize)>(),
            std::mem::size_of::<Result<(usize, usize), RuntimeError>>(),
        ];
        let array_bytes = std::mem::size_of_val(&terms);
        let mut iterator = terms.into_iter();
        let iterator_bytes = std::mem::size_of_val(&iterator);
        array_bytes
            .checked_add(iterator_bytes)
            .and_then(|initial| iterator.try_fold(initial, usize::checked_add))
            .unwrap_or(usize::MAX)
    }
}
