//! Selects Host dependency and key families from all three actual Sources.
//!
//! The original two-format Host stays unchanged. Current17 selection is explicit
//! immutable declaration data and remains separate from Scope/current authority.

use super::*;
use crucible::node_contract::{HostCaptureDependencyLookupData, HostCaptureDependencyStorageData};

pub(super) const fn selection_counter_scratch_data() -> usize {
    size_of::<Option<bool>>()
        + size_of::<bool>()
        + size_of::<Result<bool, crucible::node_contract::RuntimeError>>()
        + size_of::<Result<bool, StateError>>()
        + size_of::<
            std::slice::Iter<
                'static,
                Rc<crucible::node_adapters::cnp::PacketCompleteSemanticSource>,
            >,
        >()
}

impl PacketCompleteCaptureFactory {
    pub(super) fn selected_host_capture17_data(&self) -> Result<bool, StateError> {
        let mut selected = None;
        for source in &self.authority.roster().sources {
            let current = source
                .requires_restored_capture17_scope_data()
                .map_err(error)?;
            if selected.is_some_and(|previous| previous != current) {
                return Err(refused("complete Host capture declarations are mixed"));
            }
            selected = Some(current);
        }
        selected.ok_or_else(|| refused("complete Host capture declaration roster is absent"))
    }

    pub(super) fn host_capture_dependency_preflight_data(
        &self,
        runtime: &ContentRef,
    ) -> Result<HostCaptureDependencyStorageData, StateError> {
        if self.selected_host_capture17_data()? {
            self.host
                .restored_complete_capture_dependency_preflight17_data(runtime)
                .map_err(error)
        } else {
            self.host
                .original_complete_capture_dependency_preflight_data(runtime)
                .map_err(error)
        }
    }

    pub(super) fn host_capture_dependency_lookup_data(
        &self,
        reference: &ContentRef,
        maximum_objects: usize,
    ) -> Result<Option<HostCaptureDependencyLookupData>, StateError> {
        if self.selected_host_capture17_data()? {
            self.host
                .restored_complete_capture_dependency_lookup17_data(reference, maximum_objects)
                .map_err(error)
        } else {
            self.host
                .original_complete_capture_dependency_lookup_data(reference, maximum_objects)
                .map_err(error)
        }
    }

    pub(super) fn host_capture_dependencies_data(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        maximum_objects: usize,
        maximum_scratch: usize,
    ) -> Result<Option<Vec<ContentRef>>, StateError> {
        if self.selected_host_capture17_data()? {
            self.host
                .restored_complete_capture_dependencies17_data(
                    reference,
                    bytes,
                    maximum_objects,
                    maximum_scratch,
                )
                .map_err(error)
        } else {
            self.host
                .original_complete_capture_dependencies_data(
                    reference,
                    bytes,
                    maximum_objects,
                    maximum_scratch,
                )
                .map_err(error)
        }
    }
}
