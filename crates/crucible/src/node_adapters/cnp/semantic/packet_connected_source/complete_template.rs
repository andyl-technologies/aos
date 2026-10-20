//! Constructs fresh reactive state from immutable validated code declarations.
//!
//! Lineage reservation occurs only after the new enclosing Source is retained.
//! A failed allocation therefore leaves its actual capacity in the same output.
//! No current read, input lineage, static rows or codec binding is copied.

use super::*;
use std::mem::size_of;

impl PacketConnectedSemanticSource {
    pub(in crate::node_adapters::cnp::semantic) fn complete_template_constructor_transient_data()
    -> usize {
        world::PacketConnectedWorldScope::complete_template_constructor_transient_data()
            + std::mem::size_of::<PacketConnectedDefinition>()
            + std::mem::size_of::<
                crucible_node_provider::reference_packet::control::PacketNative5StorageSelection,
            >()
    }

    pub(in crate::node_adapters::cnp::semantic) fn complete_template_lineage_bytes_data(
        &self,
    ) -> Result<usize, RuntimeError> {
        self.installation
            .maximum_operations
            .checked_mul(size_of::<OriginalInputLineage>())
            .ok_or(RuntimeError::ResourceLimit)
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
        let world = self.world.cloned_complete_template_data()?;
        Ok(Self {
            installation,
            definition: self.definition.clone(),
            world,
            input_lineage: RefCell::new(Vec::new()),
            complete_input_static: RefCell::new(None),
            process: std::process::id(),
            thread: std::thread::current().id(),
            current_native: RefCell::new(None),
            complete_confirmation_selection: None,
            complete_capture_profile: None,
            complete_capture_allocation_selection: None,
            complete_storage: Some(storage.clone()),
        })
    }

    pub(in crate::node_adapters::cnp::semantic) fn complete_template_retained_lineage_bytes_data(
        &mut self,
    ) -> Result<usize, RuntimeError> {
        self.input_lineage
            .get_mut()
            .capacity()
            .checked_mul(size_of::<OriginalInputLineage>())
            .ok_or(RuntimeError::ResourceLimit)
    }

    pub(in crate::node_adapters::cnp::semantic) fn reserve_complete_template_lineage_data(
        &mut self,
    ) -> Result<(), RuntimeError> {
        let maximum = self.installation.maximum_operations;
        let lineage = self.input_lineage.get_mut();
        if !lineage.is_empty() || lineage.capacity() != 0 {
            return Err(RuntimeError::DuplicateOperation);
        }
        lineage
            .try_reserve_exact(maximum)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if lineage.capacity() > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(())
    }
}
