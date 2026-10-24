//! Retains a preconstruction association from the original realized source.
//!
//! The original source, native read and allocated banks remain independent of
//! later active Runtime7 capture geometry. This association grants no Arm,
//! capture, archive signing or fresh restoration permission by itself.

use super::*;
use crate::node_adapters::cnp::CnpSemanticSourceRead;
use crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError;
use crucible_node_transport::protocol_snapshot::OriginalProtocolStorageFacts;

pub(super) struct OriginalCompletePreconstruction {
    native: CnpSemanticSourceRead,
    source_banks: PacketCompleteCaptureBankFacts,
    controller_bank: OriginalProtocolStorageFacts,
}

impl PacketCompleteSemanticSource {
    /// Retains the original realized native and allocated source-bank association.
    ///
    /// The collecting authority calls this only with its original realization
    /// loan. A later installed factory must independently retain the same source
    /// allocation and genuine complete Host2 preparation source. This method
    /// never reads active capture geometry or qualifies a dormant graph.
    ///
    /// # Errors
    /// Refuses foreign or revoked source/native custody, absent preallocated
    /// banks, a changed original storage/profile tuple, incomplete physical I/O,
    /// or an earlier preconstruction association.
    pub fn record_original_preconstruction(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
    ) -> Result<(), OperationFailure> {
        self.authenticate_realization(*scope)?;
        self.authenticate_witness_scope(scope)?;
        let source_banks = self.original_capture_bank_facts()?;
        let selected = self.selected_storage_selection()?;
        scope
            .controller
            .authenticate_native5_source_codec()
            .map_err(unknown)?;
        self.authenticate_preconstruction_controller(scope)?;
        let controller_bank = scope
            .controller
            .original_native5_storage_facts()
            .map_err(unknown)?;
        if !controller_bank.all_io_complete
            || controller_bank.maximum_frame_bytes as u64 != selected.limits.frame_bytes.get()
            || controller_bank.maximum_history_bytes as u64
                != selected.storage.frame_bank_bytes.get()
            || controller_bank.maximum_frames_per_direction as u64
                != selected.storage.frames_per_direction.get()
        {
            return Err(refused(
                "preconstruction controller allocation differs from original selection",
            ));
        }
        let native = scope.native.original_source_read().map_err(unknown)?;
        native.ensure_current().map_err(unknown)?;
        self.authenticate_witness_scope(scope)?;

        let mut original = self
            .preconstruction
            .try_borrow_mut()
            .map_err(|_| refused("original preconstruction association is busy"))?;
        if original.is_some() {
            return Err(refused(
                "original preconstruction association is already retained",
            ));
        }
        *original = Some(OriginalCompletePreconstruction {
            native,
            source_banks,
            controller_bank,
        });
        Ok(())
    }

    /// Reauthenticates the same original preconstruction association.
    ///
    /// The retained bank counts describe that original allocation, never current
    /// lifetime journal credit. Capture obtains fresh owning-controller facts
    /// through its separate readonly runtime loan immediately before dispatch.
    ///
    /// # Errors
    /// Refuses foreign origin, an absent/busy association, revoked native custody,
    /// changed actual source bank capacities or an inconsistent original bank.
    pub fn authenticate_original_preconstruction(&self) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        let original = self
            .preconstruction
            .try_borrow()
            .map_err(|_| refused("original preconstruction association is busy"))?;
        let original = original
            .as_ref()
            .ok_or_else(|| refused("original preconstruction association is absent"))?;
        original.native.ensure_current().map_err(unknown)?;
        if self.original_capture_bank_facts()? != original.source_banks {
            return Err(refused("original preconstruction bank allocation changed"));
        }
        let selected = self.selected_storage_selection()?;
        if original.controller_bank.maximum_frame_bytes as u64 != selected.limits.frame_bytes.get()
            || original.controller_bank.maximum_history_bytes as u64
                != selected.storage.frame_bank_bytes.get()
            || original.controller_bank.maximum_frames_per_direction as u64
                != selected.storage.frames_per_direction.get()
        {
            return Err(refused("original preconstruction selected bank changed"));
        }
        original.native.ensure_current().map_err(unknown)
    }
}

impl PacketCompleteSemanticSource {
    /// Retains or rechecks original preconstruction only when actual banks were selected.
    ///
    /// The original realization callback supplies this same owning scope. A
    /// preparation-only source with no banks remains supported. A bank-backed
    /// source records one original association and rechecks that association on
    /// later callbacks; it never reissues it or derives active capture geometry.
    ///
    /// # Errors
    /// Refuses foreign or changed realization custody, busy source slots, a
    /// changed installed codec/profile/host extent, or revoked retained reads.
    pub fn authenticate_realized_preconstruction(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        self.authenticate_realization(*scope)?;
        self.authenticate_witness_scope(scope)?;
        let selected = self
            .capture_banks
            .try_borrow()
            .map_err(|_| refused("original preconstruction banks are busy"))?
            .is_some();
        if !selected {
            return Ok(());
        }

        let retained = self
            .preconstruction
            .try_borrow()
            .map_err(|_| refused("original preconstruction association is busy"))?
            .is_some();
        if retained {
            self.authenticate_original_preconstruction()?;
            self.authenticate_preconstruction_controller(scope)?;
            self.authenticate_witness_scope(scope)
        } else {
            self.record_original_preconstruction(scope)
        }
    }

    fn authenticate_preconstruction_controller(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        let selected = self.selected_capture_profile()?;
        if scope
            .controller
            .original_native5_capture_profile()
            .map_err(unknown)?
            != selected
        {
            return Err(refused(
                "preconstruction controller capture profile differs",
            ));
        }
        self.authenticate_preconstruction_protocol_bound(selected)
    }
}

impl PacketCompleteSemanticSource {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn authenticate_original_preconstruction_native(
        &self,
        expected: &crate::node_adapters::cnp::CnpSemanticSourceRead,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        self.authenticate_original_preconstruction()?;
        let original = self
            .preconstruction
            .try_borrow()
            .map_err(|_| refused("complete mechanism preconstruction busy"))?;
        let original = original
            .as_ref()
            .ok_or_else(|| refused("complete mechanism preconstruction absent"))?;
        original.native.ensure_current().map_err(unknown)?;
        expected.ensure_current().map_err(unknown)?;
        if !original.native.same_original(expected) {
            return Err(refused(
                "complete mechanism native differs from actual preconstruction",
            ));
        }
        original.native.ensure_current().map_err(unknown)
    }
}

impl OriginalCompletePreconstruction {
    pub(in crate::node_adapters::cnp::semantic) fn retained_native_read_storage_data_with_error<
        E: StorageError,
    >(
        &self,
        maximum: usize,
    ) -> Result<super::super::retained_storage::CnpRetainedStorageReport, E> {
        E::read(&self.native, maximum)
    }
}
