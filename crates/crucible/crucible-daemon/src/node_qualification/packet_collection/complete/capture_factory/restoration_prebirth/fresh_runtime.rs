//! Observes and retires the actual fresh runtime without extracting its owner.
//!
//! Construction observers require the same issued archive and bound graph.
//! Cleanup checks creator identity only, so revocation cannot strand custody.

use super::*;
use crucible_engine::node_contract::{ActivationRecord, RuntimeError};
use std::mem::size_of;

impl PacketCompleteRestorationPrebirth {
    pub(in crate::node_qualification::packet_collection::complete) fn original_fresh_construction_callback_transient_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.construction_origin_data()?;
        // Binding and runtime constructors reauthenticate the DISTINCT code
        // authority as well as the fresh target. Neither callback borrows the
        // other's credit even when immutable selections happen to match.
        let authority = &self.factory.inner.authority;
        let mut bytes = authority.original_initial_callback_transient_data()?;
        bytes = bytes
            .checked_add(
                InstalledConformancePlan::original_runtime_constructor_serialization_storage_data(
                    authority.world(),
                    maximum,
                )?,
            )
            .filter(|total| *total <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        for source in &authority.roster().sources {
            let selected = source.installation();
            for amount in [
                source.original_collecting_validation_storage_data(maximum)?,
                InstalledConformancePlan::original_runtime_constructor_serialization_storage_data(
                    &selected.descriptor,
                    maximum,
                )?,
                InstalledConformancePlan::original_runtime_constructor_serialization_storage_data(
                    &selected.binding,
                    maximum,
                )?,
                InstalledConformancePlan::original_runtime_constructor_serialization_storage_data(
                    &selected.owner,
                    maximum,
                )?,
            ] {
                bytes = bytes
                    .checked_add(amount)
                    .filter(|total| *total <= maximum)
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
        }
        self.construction_origin_data()?;
        Ok(bytes)
    }

    pub(in crate::node_qualification::packet_collection::complete) fn retained_fresh_construction_runtime_descriptor_data(
        &self,
        target: &ActivationRecord,
    ) -> Result<usize, RuntimeError> {
        self.construction_origin_data()?;
        if self.failed_runtime.is_some() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let graph = self
            .fresh_graph
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let runtime = self.runtime_data()?;
        self.source
            .retained_original_construction_runtime_descriptor_data(&runtime, graph, target)
    }

    pub(in crate::node_qualification::packet_collection::complete) fn retained_fresh_construction_descriptor_data(
        &self,
        target: &ActivationRecord,
    ) -> Result<usize, RuntimeError> {
        self.construction_origin_data()?;
        let mut count = self
            .factory
            .inner
            .authority
            .capture_graph_policy()
            .original_initial_retained_descriptors_data()?;
        if let Some(factory) = &self.fresh_factory {
            count = count
                .checked_add(factory.original_unobserved_restoration_descriptor_data()?)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        if self.runtime.is_some() {
            count = count
                .checked_add(self.retained_fresh_construction_runtime_descriptor_data(target)?)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        if self.failed_runtime.is_some() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        Ok(count)
    }

    pub(in crate::node_qualification::packet_collection::complete) fn retire_retained_fresh_runtime_data(
        &mut self,
    ) -> Result<(), RuntimeError> {
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        if let Some(runtime) = &mut self.runtime {
            runtime.get_mut().retire_original()?;
        }
        if let Some(failure) = &mut self.failed_runtime {
            failure.retire_original()?;
        }
        Ok(())
    }

    pub(in crate::node_qualification::packet_collection::complete) fn fresh_runtime_custody_counter_scratch_data()
    -> usize {
        Self::runtime_owner_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&mut Self>()
            + size_of::<&Rc<PacketCompleteCaptureFactory>>()
            + size_of::<[usize; 4]>()
            + size_of::<std::array::IntoIter<usize, 4>>()
            + size_of::<[Rc<crucible_engine::node_adapters::cnp::PacketCompleteSemanticSource>; 3]>(
            )
            + size_of::<
                std::slice::Iter<
                    '_,
                    Rc<crucible_engine::node_adapters::cnp::PacketCompleteSemanticSource>,
                >,
            >()
            + size_of::<&ActivationRecord>()
            + size_of::<Option<&Rc<ConformanceGraph>>>()
            + size_of::<Result<&Rc<ConformanceGraph>, RuntimeError>>()
            + size_of::<&ConformanceRuntime>()
            + size_of::<Option<&ConformanceRuntime>>()
            + size_of::<Result<&ConformanceRuntime, RuntimeError>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
    }
}
