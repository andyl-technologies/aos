//! Connects genuine Initial15 node associations to the selected Capture17 rows.
//!
//! Upgrading the retained Window is an identity loan. The Window independently
//! authenticates its current member, sealed boundary and admitted bank phase;
//! this module never constructs a Capture claim or imports a settled17 context.

use super::*;
use crate::node_adapters::cnp::OriginalRestoredSettledNodeHistoryView;
use crate::node_admission::OriginalRestoredCaptureRequestData;
use crucible_node_transport::reference_packet::service::PacketNative5SourceLaunch;

impl OriginalInstalledRestorationNodeAssociation {
    /// Reports fixed identity and callback frames used by this bridge.
    pub(crate) fn original_capture17_bridge_counter_scratch_data() -> usize {
        size_of::<(Rc<CompleteOriginalRestorationWindow>, usize)>()
            + size_of::<Result<(Rc<CompleteOriginalRestorationWindow>, usize), RuntimeError>>()
            + size_of::<&crate::node_adapters::cnp::PacketCompleteSemanticSource>()
            + size_of::<
                Result<&crate::node_adapters::cnp::PacketCompleteSemanticSource, RuntimeError>,
            >()
            + size_of::<&OriginalRestoredSettledNodeHistoryView<'static>>()
            + size_of::<Result<(usize, usize, usize), RuntimeError>>()
            + size_of::<crate::node_adapters::cnp::OriginalSourceRestoredCaptureConstructionData>()
            + size_of::<
                Result<
                    crate::node_adapters::cnp::OriginalSourceRestoredCaptureConstructionData,
                    RuntimeError,
                >,
            >()
            + Self::counter_scratch_data()
    }

    /// Borrows the original Window identity without granting a new action.
    ///
    /// # Errors
    /// Refuses a foreign creator, lost Window, changed proof or different Source.
    pub(crate) fn original_capture17_window_data(
        &self,
        source: &dyn CnpSemanticSource,
    ) -> Result<(Rc<CompleteOriginalRestorationWindow>, usize), RuntimeError> {
        self.origin()?;
        let window = self
            .window
            .upgrade()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if window.original_complete_scope_proof_identity_data()? != self.proof_identity
            || window.original_installed_source_index_data(source)? != self.selected
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok((window, self.selected))
    }

    pub(crate) fn quote_original_restored_capture_prequote_data(
        &self,
        erased: &dyn CnpSemanticSource,
        controller: &CnpController,
        read_owner: *const (),
        launch: &PacketNative5SourceLaunch,
        raw5: &[u8],
        request: &OriginalRestoredCaptureRequestData<'_>,
        node_history: &OriginalRestoredSettledNodeHistoryView<'_>,
        maximum: usize,
    ) -> Result<(usize, usize, usize), RuntimeError> {
        let (window, selected) = self.original_capture17_window_data(erased)?;
        let source = window.original_restored_capture_source_data(selected, erased)?;
        window.with_original_restored_capture_signing_inputs_data(
            selected,
            source,
            self.proof_identity,
            |inputs| {
                source.original_restored_capture_prequote_storage_data(
                    controller,
                    read_owner,
                    launch,
                    raw5,
                    inputs,
                    request,
                    node_history,
                    maximum,
                )
            },
        )
    }

    pub(crate) fn reserve_original_restored_capture_counting_banks_data(
        &self,
        erased: &dyn CnpSemanticSource,
        read_owner: *const (),
        launch: &PacketNative5SourceLaunch,
        raw5: &[u8],
        request: &OriginalRestoredCaptureRequestData<'_>,
        node_history: &OriginalRestoredSettledNodeHistoryView<'_>,
        maximum: usize,
    ) -> Result<(), RuntimeError> {
        let (window, selected) = self.original_capture17_window_data(erased)?;
        let source = window.original_restored_capture_source_data(selected, erased)?;
        source.authenticate_original_restored_settled_source17_launch_data(launch, raw5)?;
        window.reserve_restored_capture_counting_banks_data(
            selected,
            erased,
            read_owner,
            request,
            node_history,
            maximum,
        )?;
        source.authenticate_original_restored_settled_source17_launch_data(launch, raw5)
    }

    pub(crate) fn quote_original_restored_capture_construction_data(
        &self,
        erased: &dyn CnpSemanticSource,
        controller: &CnpController,
        read_owner: *const (),
        launch: &PacketNative5SourceLaunch,
        raw5: &[u8],
        request: &OriginalRestoredCaptureRequestData<'_>,
        node_history: &OriginalRestoredSettledNodeHistoryView<'_>,
        maximum: usize,
    ) -> Result<
        crate::node_adapters::cnp::OriginalSourceRestoredCaptureConstructionData,
        RuntimeError,
    > {
        let (window, selected) = self.original_capture17_window_data(erased)?;
        let source = window.original_restored_capture_source_data(selected, erased)?;
        window.with_original_restored_capture_signing_inputs_data(
            selected,
            source,
            self.proof_identity,
            |inputs| {
                window.with_restored_capture_quote_banks_data(
                    selected,
                    source,
                    controller,
                    inputs,
                    node_history,
                    maximum,
                    |quote| {
                        source.original_restored_capture_construction_data(
                            controller,
                            read_owner,
                            launch,
                            raw5,
                            inputs,
                            request,
                            node_history,
                            quote,
                            maximum,
                        )
                    },
                )
            },
        )
    }
}
