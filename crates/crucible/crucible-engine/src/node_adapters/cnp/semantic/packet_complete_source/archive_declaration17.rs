//! Compares immutable archived program DATA to the actual installed code model.
//!
//! This reads only the installed producer/reactive declaration. Archived PIDs,
//! secrets, paths and per-Boot budgets stay authenticated historical DATA and are
//! never tested as live resources or substituted for fresh admission.

use super::*;
use crate::node_contract::RuntimeError;
use crucible_node_transport::reference_packet::{
    connected::PacketConnectedDefinition, coordinator::PacketNative5CoordinatorInstallation,
    service::PacketConnectedSourceProgram,
};

type ReactiveDeclaration17<'a> = (
    &'a PacketConnectedDefinition,
    &'a PacketNative5CoordinatorInstallation,
    &'a crate::node_contract::SavedRuntimeActivation,
);

type CoordinatorDeclaration17<'a> = (
    &'a PacketNative5CoordinatorInstallation,
    &'a crate::node_contract::SavedRuntimeActivation,
);

impl PacketCompleteSemanticSource {
    pub(crate) fn authenticate_archived_program17_data(
        &self,
        program: &PacketConnectedSourceProgram,
    ) -> Result<(), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        match (&self.original, program) {
            (
                CompletePacketOriginal::Producer(source),
                PacketConnectedSourceProgram::Producer { program },
            ) => {
                if source.original_program_data() != program {
                    return Err(RuntimeError::ForeignAuthority);
                }
            }
            (
                CompletePacketOriginal::Reactive(source),
                PacketConnectedSourceProgram::Reactive { program },
            ) => {
                let (actual, _, _) =
                    source.complete_retained_declaration_parts_with_error::<RuntimeError>()?;
                if actual != program {
                    return Err(RuntimeError::ForeignAuthority);
                }
            }
            _ => return Err(RuntimeError::ForeignAuthority),
        }
        self.storage_origin_with_error::<RuntimeError>()
    }

    pub(crate) fn archived_program17_counter_scratch_data() -> usize {
        std::mem::size_of::<&Self>()
            + std::mem::size_of::<&PacketConnectedSourceProgram>()
            + std::mem::size_of::<Result<(), RuntimeError>>()
            + std::mem::size_of::<ReactiveDeclaration17<'static>>()
            + std::mem::size_of::<Result<ReactiveDeclaration17<'static>, RuntimeError>>()
            + std::mem::size_of::<CoordinatorDeclaration17<'static>>()
            + std::mem::size_of::<Result<CoordinatorDeclaration17<'static>, RuntimeError>>()
    }
}
