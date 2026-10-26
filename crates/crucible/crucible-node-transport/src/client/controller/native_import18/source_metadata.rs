//! Observes the closed roster of actual SDK owners retained by Source18 phases.
//!
//! The same defining field walks produce facts and append physical rows. These
//! borrowed DATA views never construct an SDK owner, certify phase completion or
//! grant admission. Every opaque SDK variant preserves its creator-origin check.

use super::*;
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::{
    PacketNativeImport18BootstrapRetainedData,
    native_import18_bootstrap_retention_counter_scratch_data,
};
use crate::retained_metadata::records::PacketRuntimeMetadataRecordBank;
use std::mem::size_of;

/// Borrows one actual member of the Source18 phase metadata roster.
#[derive(Clone, Copy)]
pub enum NativeImport18SourceMetadataData<'a> {
    /// Borrows the saved bootstrap construction row and its Controller association.
    BootstrapConstruction(&'a OriginalNativeImport18BootstrapConstructionData),
    /// Borrows every initialized bootstrap SDK partial, including failed phases.
    Bootstrap(&'a OriginalNativeImport18Bootstrap),
    /// Borrows the saved assignment row and its Controller association.
    AssignmentStorage(&'a OriginalNativeImport18AssignmentStorageData),
    /// Borrows every initialized assignment and input-upload SDK partial.
    Assignment(&'a OriginalNativeImport18Assignment),
    /// Borrows independent Source-retained inputs without checking DTO eligibility.
    SourceInputs {
        /// Borrows the assigned request identifier when retained.
        request_id: Option<&'a Id>,
        /// Borrows the independent Begin baseline when retained.
        baseline: Option<&'a BeginRequest>,
        /// Borrows the Prepare input when retained.
        prepare: Option<&'a PacketCompleteRestorePrepareRequest>,
        /// Borrows the Commit input when retained.
        commit: Option<&'a PacketCompleteRestoreCommitRequest>,
        /// Borrows the native binding when retained.
        binding: Option<&'a PacketNativeImport18Binding>,
    },
    /// Borrows a bootstrap DTO, including invalid and incomplete fields.
    BootstrapDto(PacketNativeImport18BootstrapRetainedData<'a>),
}

impl NativeImport18SourceMetadataData<'_> {
    /// Reports the actual typed geometry without copying or reconstructing owners.
    ///
    /// Callers admit [`Self::counter_scratch_data`] and each actual SDK owner's
    /// dynamic metadata-counter requirement before walking. Source origin, phase
    /// admission and native permissions remain the enclosing owner's obligations.
    ///
    /// # Errors
    /// Refuses a foreign SDK creator, checked overflow or traversal exhaustion.
    pub fn retained_metadata_data(self) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = MetadataObserver::new();
        self.observe_into(&mut observer)?;
        Ok(observer.finish())
    }

    /// Appends the same typed geometry without clearing earlier physical rows.
    ///
    /// The caller independently admits the bank and the same counters required
    /// by [`Self::retained_metadata_data`]. Failure preserves every initialized
    /// row; a ready bank or successful component walk proves no Source completion.
    ///
    /// # Errors
    /// Refuses foreign SDK creation, unready or exhausted physical backing,
    /// checked overflow or traversal exhaustion. Earlier rows remain retained.
    pub fn record_retained_metadata_data(
        self,
        bank: &mut PacketRuntimeMetadataRecordBank,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = MetadataObserver::appending(bank.recording_bank_data()?);
        self.observe_into(&mut observer)?;
        Ok(observer.finish())
    }

    /// Names fixed dispatch, borrowed-bank and defining typed-visitor controls.
    ///
    /// Actual SDK owners separately quote their dynamic JSON traversal controls;
    /// this fixed declaration does not replace those origin-checked prewalks.
    pub fn counter_scratch_data() -> usize {
        OriginalNativeImport18Assignment::source_input_metadata_counter_scratch_data()
            + CnpController::original_native_import18_bootstrap_counter_scratch_data()
            + native_import18_bootstrap_retention_counter_scratch_data()
            + size_of::<Self>()
            + size_of::<MetadataObserver<'static>>()
            + size_of::<&mut MetadataObserver<'static>>()
            + size_of::<&mut PacketRuntimeMetadataRecordBank>()
            + size_of::<
                Result<&mut crate::retained_metadata::records::MetadataRecordBank, ProviderError>,
            >()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<Result<RetainedProtocolMetadataFacts, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
    }

    fn observe_into(self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        match self {
            Self::BootstrapConstruction(owner) => owner.observe_source_metadata_data(observer),
            Self::Bootstrap(owner) => owner.observe_source_metadata_data(observer),
            Self::AssignmentStorage(owner) => owner.observe_source_metadata_data(observer),
            Self::Assignment(owner) => owner.observe_actual_history_data(observer),
            Self::SourceInputs {
                request_id,
                baseline,
                prepare,
                commit,
                binding,
            } => OriginalNativeImport18Assignment::observe_source_inputs_data(
                request_id, baseline, prepare, commit, binding, observer,
            ),
            Self::BootstrapDto(dto) => dto.observe_data(observer),
        }
    }
}
