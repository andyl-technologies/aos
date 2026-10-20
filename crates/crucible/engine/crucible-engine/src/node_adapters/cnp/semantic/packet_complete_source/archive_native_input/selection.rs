//! Lends original immutable native-history selection without issuing authority.
//!
//! The live variant keeps the existing same-Source checks. The archived variant
//! is available only inside the strictly constructed inert initial15 holder;
//! its parent-scope loan never becomes a Source, key or restoration permission.

use super::super::archive_owner::initial15::OriginalInitial15ArchivedSelection;
use super::*;

pub(in crate::node_adapters::cnp::semantic::packet_complete_source) enum NativeInputSelection<'a> {
    Live(&'a PacketCompleteSemanticSource),
    Archived(&'a OriginalInitial15ArchivedSelection<'a>),
}

impl NativeInputSelection<'_> {
    pub(super) fn authenticate_same_source_data(
        &self,
        expected: &PacketCompleteSemanticSource,
    ) -> Result<(), OperationFailure> {
        match self {
            Self::Live(actual) if std::ptr::eq(*actual, expected) => actual.ensure_origin(),
            Self::Live(_) | Self::Archived(_) => Err(refused(
                "native history view belongs to another original Source",
            )),
        }
    }

    pub(super) fn authenticate_origin_data(&self) -> Result<(), OperationFailure> {
        match self {
            Self::Live(source) => source.ensure_origin(),
            Self::Archived(selection) => selection.authenticate_origin_data(),
        }
    }

    pub(super) fn node_data(&self) -> Result<&Id, OperationFailure> {
        self.authenticate_origin_data()?;
        Ok(match self {
            Self::Live(source) => &source.installation().descriptor.id,
            Self::Archived(selection) => selection.node_data(),
        })
    }

    pub(super) fn reactive_definition_data(
        &self,
    ) -> Result<Option<&PacketConnectedDefinition>, OperationFailure> {
        self.authenticate_origin_data()?;
        match self {
            Self::Live(source) => source.complete_reactive_definition_data(),
            Self::Archived(selection) => Ok(selection.reactive_definition_data()),
        }
    }

    pub(super) fn storage_data(&self) -> Result<&PacketNative5StorageSelection, OperationFailure> {
        self.authenticate_origin_data()?;
        match self {
            Self::Live(source) => source.selected_storage_selection(),
            Self::Archived(selection) => Ok(selection.storage_data()),
        }
    }

    pub(super) fn maximum_authorization_bytes_data(&self) -> Result<usize, OperationFailure> {
        self.authenticate_origin_data()?;
        Ok(match self {
            Self::Live(source) => source.installation().maximum_authorization_bytes,
            Self::Archived(selection) => selection.maximum_authorization_bytes_data(),
        })
    }
}
