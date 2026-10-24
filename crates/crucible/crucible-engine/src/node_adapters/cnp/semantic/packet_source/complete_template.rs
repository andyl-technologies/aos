//! Constructs fresh producer state from immutable validated code declarations.
//!
//! The caller funds the clone row before entry. This copies no live native read
//! or selected runtime codec: actual fresh launch binding remains separate.

use super::*;

impl PacketSemanticSource {
    pub(in crate::node_adapters::cnp::semantic) fn complete_template_constructor_transient_data()
    -> usize {
        world::PacketWorldSourceScope::complete_template_constructor_transient_data()
            + std::mem::size_of::<PacketProgramDefinition>()
            + std::mem::size_of::<
                crucible_node_transport::reference_packet::control::PacketNative5StorageSelection,
            >()
    }

    pub(in crate::node_adapters::cnp::semantic) fn cloned_complete_template_data(
        &self,
        installation: CnpSemanticInstallation,
    ) -> Result<Self, RuntimeError> {
        if !self.complete_preparation_unbound_with_error::<RuntimeError>()? {
            return Err(RuntimeError::OutstandingObligations);
        }
        let storage = self
            .complete_storage
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?;
        let world = self
            .world_scope
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?
            .cloned_complete_template_data()?;
        Ok(Self {
            installation,
            program: self.program.clone(),
            world_scope: Some(world),
            current_native: RefCell::new(None),
            complete_confirmation_selection: None,
            complete_capture_profile: None,
            complete_capture_allocation_selection: None,
            complete_storage: Some(storage.clone()),
        })
    }
}
