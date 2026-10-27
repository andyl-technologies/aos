//! Constructs Source-owned Capture output banks under the original Core action.
//!
//! The construction row is a private host-side addition to native startup, not a
//! native row14 allowance, Report grant or Capture permission. The same opaque
//! member is retained by the Source before this child requests any new storage.

use super::*;
use crucible_node_transport::reference_packet::service::{
    capture_allocation::PacketNative5CaptureAllocationSelection,
    complete_restore::{
        PacketNative5CompleteRestoreSelection, PacketNative5RestoreInputEmitterSelection,
    },
};

impl PacketCompleteSemanticSource {
    pub(super) fn original_native_source_capture_construction_data(
        &self,
        launch: &PacketNative5SourceLaunch,
        maximum: usize,
    ) -> Result<(usize, usize, usize), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        // Same-source/launch correspondence is checked by the enclosing quote.
        // Old installations retain their original no-construction path.
        if launch.complete_restore_selection
            != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        {
            return Ok((0, 0, 0));
        }
        if launch.capture_allocation_selection
            != Some(PacketNative5CaptureAllocationSelection::OriginalObserve12)
            || launch.restore_input_emitter_selection
                != Some(PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12)
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        if self
            .capture_execution
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .is_some()
        {
            return Err(RuntimeError::DuplicateOperation);
        }
        let backend = match &launch.capture_profile {
            PacketNative5CaptureProfile::OwnedProtocol11 {
                host_protocol_bytes,
                ..
            } => usize::try_from(host_protocol_bytes.get())
                .map_err(|_| RuntimeError::ResourceLimit)?,
            _ => return Err(RuntimeError::UnsupportedFacet),
        };
        let requested = self.original_complete_capture_execution_reservation_requested_data_with_error::<RuntimeError>(backend)?;
        let scratch = Self::original_complete_capture_execution_counter_scratch_data();
        retained_values::sum_with_error::<RuntimeError, _>([requested, scratch], maximum)?;
        Ok((backend, requested, scratch))
    }

    pub(super) fn reserve_original_native_source_capture_construction_data(
        &self,
        member: &OriginalNativeStartupMember,
        launch: &PacketNative5SourceLaunch,
    ) -> Result<(), RuntimeError> {
        // Do not call member.authenticate here: the caller holds this same
        // birth's mutable loan after storing the already authenticated member.
        // No arbitrary callback lies between that check, storage and this call.
        let (backend, requested, scratch) = self
            .original_native_source_capture_construction_data(launch, member.finalization_bytes)?;
        if backend != member.source_capture_backend_bytes
            || requested > member.source_capture_execution_bytes
            || scratch > member.source_capture_execution_scratch
        {
            return Err(RuntimeError::ResourceLimit);
        }
        if backend != 0 {
            self.reserve_original_complete_capture_execution_with_error::<RuntimeError>(
                backend,
                member.source_capture_execution_bytes,
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_adapters::cnp::semantic::packet_complete_source::tests::{
        coordinator, installation, producer, storage_selection,
    };
    use crucible_node_format::Bytes;
    use crucible_node_transport::{
        reference_packet::service::PacketConnectedSourceProgram,
        reference_service::InstalledContent,
    };

    // Inert launch DATA supports component refusal checks only. It does not
    // pass the enclosing launch correspondence check or install a member.
    fn originals() -> (PacketCompleteSemanticSource, PacketNative5SourceLaunch) {
        let coordinator = coordinator();
        let installed = installation(&coordinator, 0);
        let selection = coordinator.participants[0].clone();
        let controller_executable = installed.provider.implementation.artifacts[0]
            .content
            .clone();
        let storage = storage_selection();
        let source = PacketCompleteSemanticSource::new_producer_for_collecting_world(
            installed,
            producer(),
            coordinator,
            storage.clone(),
        )
        .unwrap();
        let launch = PacketNative5SourceLaunch {
            schema_version: 5,
            selection,
            program: PacketConnectedSourceProgram::Producer {
                program: producer(),
            },
            controller_pid: U64::new(u64::from(std::process::id())),
            controller_uid: U64::new(u64::from(rustix::process::geteuid().as_raw())),
            initial_coordinator: InstalledContent {
                reference: controller_executable.clone(),
                bytes: Bytes::new(Vec::new()),
            },
            controller_executable,
            admission_token: Bytes::new(Vec::new()),
            limits: storage.limits,
            storage: storage.storage,
            capture_profile: PacketNative5CaptureProfile::OwnedProtocol11 {
                native_before_protocol_bytes: U64::new(1024),
                native_after_protocol_bytes: U64::new(1024),
                host_protocol_bytes: U64::new(4096),
            },
            confirmation_selection: None,
            ack_emitter_selection: None,
            native_codec_metadata_extent: None,
            protocol_metadata_limits: None,
            complete_restore_selection: None,
            restore_input_emitter_selection: None,
            capture_allocation_selection: None,
            fresh_restore_allocation_selection: None,
            effects: std::path::PathBuf::new(),
        };
        (source, launch)
    }

    #[test]
    fn original_capture_construction_old_selection_keeps_empty_owner() {
        let (source, launch) = originals();
        assert_eq!(
            source.original_native_source_capture_construction_data(&launch, 0),
            Ok((0, 0, 0))
        );
        assert!(source.capture_execution.borrow().is_none());
        assert!(!source.complete_bytes_launch_reserved.get());
        assert!(source.authenticate_current_native().is_err());
    }

    #[test]
    fn original_capture_construction_missing_tuple_refuses_before_bank_loan() {
        let (source, mut launch) = originals();
        launch.complete_restore_selection =
            Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12);
        let busy = source.capture_execution.borrow_mut();
        assert_eq!(
            source.original_native_source_capture_construction_data(&launch, usize::MAX),
            Err(RuntimeError::UnsupportedFacet)
        );
        launch.capture_allocation_selection =
            Some(PacketNative5CaptureAllocationSelection::OriginalObserve12);
        assert_eq!(
            source.original_native_source_capture_construction_data(&launch, usize::MAX),
            Err(RuntimeError::UnsupportedFacet)
        );
        assert!(busy.is_none());
        assert!(!source.complete_bytes_launch_reserved.get());
    }

    #[test]
    fn original_capture_construction_creator_precedes_empty_selection_and_busy_bank() {
        let (mut source, launch) = originals();
        source.process = source.process.wrapping_add(1);
        let busy = source.capture_execution.borrow_mut();
        assert_eq!(
            source.original_native_source_capture_construction_data(&launch, usize::MAX),
            Err(RuntimeError::ForeignAuthority)
        );
        assert!(busy.is_none());
    }
}
