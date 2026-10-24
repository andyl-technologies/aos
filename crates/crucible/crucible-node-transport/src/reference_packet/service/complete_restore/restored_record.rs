//! Defines restored native evidence without rewriting captured model gates.
//!
//! A portable record is data. The original source witness independently checks
//! its current child, original controller, actual installed restoration receipt
//! and exact Core target before accepting its physical gate association.
//!
//! ```text
//! restored-native/12 -> unchanged receipt/5 -> unchanged native/2 or native/4
//!                   -> exact original COMMIT request and response full refs
//! ```

pub use crucible_source_birth_data::profile::reference_packet::service::complete_restore::{
    PACKET_NATIVE_RESTORED_RECORD_FEATURE, native_restored_record_contract,
    native_restored_record_schema,
};

use super::*;
use crate::reference_packet::control::PacketNative5Record;

/// Retains both literal logical inventory and a distinct fresh physical gate.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeRestoredRecord {
    /// Names the exact separately registered proof grammar.
    pub schema: String,
    /// Retains the unchanged full live receipt and its native model proof ref.
    pub native_receipt: PacketNative5Record,
    /// Names the exact source-signed original pending native snapshot.
    pub captured_owner_state: ContentRef,
    /// Names its source-verified full Capture/after/fourth-Poll journal.
    pub captured_journal: ContentRef,
    /// Names the exact sealed historical mapping retained by the fresh installer.
    pub mapping: ContentRef,
    /// Names the actual complete assigned COMMIT envelope including its proof.
    pub restore_commit: ContentRef,
    /// Names the actual correlated post-sequence response including its receipt.
    pub restore_response: ContentRef,
    /// Binds the actual verified complete COMMIT context, 32 decoded bytes.
    pub context_digest: Bytes,
    /// Reports the independent fresh physical gate; logical inventory stays literal.
    pub physical_gate_held: bool,
}

impl PacketNativeRestoredRecord {
    /// Checks bounded closed record data without admitting a physical gate.
    ///
    /// The source additionally verifies the underlying full native record and
    /// original COMMIT pair, the genuine current child/controller and installed
    /// restoration association. This method creates none of those owners.
    ///
    /// # Errors
    /// Refuses another grammar/selection, missing owned-protocol birth, invalid
    /// full references, wrong digest width or an oversized evidence body.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != PACKET_NATIVE_RESTORED_RECORD_FEATURE
            || self.native_receipt.schema != "source-owned.packet-receipt/5"
            || self.native_receipt.native_pid.get() == 0
            || self.native_receipt.complete_restore_selection
                != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
            || !matches!(
                self.native_receipt.capture_profile,
                super::super::PacketNative5CaptureProfile::OwnedProtocol11 { .. }
            )
            || self.native_receipt.protocol_metadata_limits.is_none()
            || self.native_receipt.protocol_metadata_birth_facts.is_none()
            || self.context_digest.as_slice().len() != 32
            || self.restore_commit == self.restore_response
        {
            return Err(ProviderError::Correlation("restored native record grammar"));
        }
        for reference in [
            &self.captured_owner_state,
            &self.captured_journal,
            &self.mapping,
            &self.restore_commit,
            &self.restore_response,
            &self.native_receipt.native_record,
        ] {
            reference.validate()?;
        }
        crate::connection::serialized_credit(self, 65_536)?;
        Ok(())
    }
}

impl crate::retained_metadata::ObserveMetadata for PacketNativeRestoredRecord {
    fn observe_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        use crate::protocol_snapshot::restored_settled17::current_contracts::CurrentContract17;

        let Self {
            schema,
            native_receipt,
            captured_owner_state,
            captured_journal,
            mapping,
            restore_commit,
            restore_response,
            context_digest,
            physical_gate_held,
        } = self;

        observer.observe(schema)?;
        native_receipt.observe_current(observer)?;
        observer.observe(captured_owner_state)?;
        observer.observe(captured_journal)?;
        observer.observe(mapping)?;
        observer.observe(restore_commit)?;
        observer.observe(restore_response)?;
        observer.observe(context_digest)?;
        observer.observe(physical_gate_held)
    }
}

// One borrowed compiled roster drives BOTH the existing canonical definition
// and its prospective DOM/canonical counter. No schema bytes or field values
// are regenerated independently in the admission calculation.

pub(crate) use crucible_source_birth_data::profile::reference_packet::service::native_startup::schema_shapes::contracts::native_restored_record_contract_storage_data;
