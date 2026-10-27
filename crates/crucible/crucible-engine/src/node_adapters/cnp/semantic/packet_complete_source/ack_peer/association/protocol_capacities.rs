//! Observes the ACK association's original protocol and native-read component.
//!
//! Restored attempt, history, transfer and Capture owners remain independent
//! census components. This projection cannot stand in for their owning rosters
//! or establish whole-Source traversal work, publication or restoration rights.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::{
    record_value_capacity_data_with_error, value_capacity_counter_scratch_data,
};
use crate::node_contract::{
    RuntimeError, restored_owner_history::OriginalOwnerCapacityMetadataData,
};
use crucible_node_transport::retained_metadata::{
    RetainedCaptureProtocolData, RetainedProtocolMetadataFacts,
    records::PacketRuntimeMetadataRecordBank,
};
use std::{
    cell::{BorrowError, Ref},
    mem::size_of,
};

impl OriginalAckPeerAssociation {
    /// Records original raw/normalized bodies, context and protocol associations.
    ///
    /// Restored execution/history owners are separate components; their fields
    /// are named here so additions force a fresh ownership decision.
    ///
    /// # Errors
    /// Refuses foreign or busy child custody, unsupported executable backing,
    /// private JSON depth, exhausted rows and checked metadata/physical bounds.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn record_protocol_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            restore: _,
            restore_transfer_banks: _,
            restoration_activation: _,
            restoration_observation: _,
            current_observations: _,
            producer_progress: _,
            restored_capture: _,
            restored_observations17: _,
            restored_inputs: _,
            restored_suffix: _,
            emitter,
            restore_input_emitter,
            native,
            hello,
            banks,
            normalized,
            context,
            proof,
            attempted,
            ready,
            failed,
            signing_attempted,
            sealed,
            publication_attempted,
            completed_mechanism,
        } = self;
        census.observe_inline_data(attempted)?;
        census.observe_inline_data(ready)?;
        census.observe_inline_data(failed)?;
        census.observe_inline_data(signing_attempted)?;
        census.observe_inline_data(sealed)?;
        census.observe_inline_data(publication_attempted)?;
        census.observe_inline_data(&completed_mechanism.get())?;
        for bank in banks {
            census.observe(bank)?;
        }
        for value in normalized.iter().chain(std::iter::once(proof)).flatten() {
            record_value_capacity_data_with_error::<RuntimeError>(value, 0, census)?;
        }
        if let Some(context) = context {
            let PacketCanonicalAckAdmissionContext {
                schema,
                algorithm,
                source_birth,
                kernel_binding,
                policy_binding,
                host_registration,
                native_registration,
                hello_request,
                hello_response,
                assigned_admit,
            } = context;
            census.observe(schema)?;
            census.observe(algorithm)?;
            for bytes in [
                source_birth,
                kernel_binding,
                policy_binding,
                host_registration,
                native_registration,
                hello_request,
                hello_response,
                assigned_admit,
            ] {
                census.observe(bytes)?;
            }
        }
        if let Some(emitter) = emitter {
            census
                .observe_capture_protocol_data(RetainedCaptureProtocolData::AckEmitter(emitter))?;
        }
        if let Some(emitter) = restore_input_emitter {
            census.observe_capture_protocol_data(
                RetainedCaptureProtocolData::RestoreInputEmitter(emitter),
            )?;
        }
        if let Some(hello) = hello {
            census
                .observe_capture_protocol_data(RetainedCaptureProtocolData::HelloJournal(hello))?;
        }
        if let Some(native) = native {
            native.record_capacity_data(census)?;
        }
        Ok(())
    }
}

impl PacketCompleteSemanticSource {
    /// Reports retained ACK protocol bodies and original SDK/native associations.
    ///
    /// The original Source owns the inline association header. Its restored
    /// execution, transfer, observation and Capture histories require separate
    /// defining census components. This DATA remains observable after protocol
    /// revocation and does not authenticate a completed or publishable Admit.
    ///
    /// # Errors
    /// Refuses foreign creator processes/threads, a busy association or child,
    /// unsupported backing, private JSON depth or checked row/layout bounds.
    pub fn original_ack_protocol_capacity_data(
        &self,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let maximum = bank.as_ref().map_or(usize::MAX, |bank| bank.maximum_rows());
        let mut census = OriginalOwnerCapacityMetadataData::new(maximum, bank);
        if let Some(association) = association.as_ref() {
            association.record_protocol_capacity_data(&mut census)?;
        }
        self.storage_origin_with_error::<RuntimeError>()?;
        Ok(census.finish())
    }

    /// Names the concrete ACK protocol projection and borrowed observation controls.
    pub fn original_ack_protocol_capacity_counter_scratch_data() -> usize {
        type Values = std::iter::Flatten<
            std::iter::Chain<
                std::slice::Iter<'static, Option<serde_json::Value>>,
                std::iter::Once<&'static Option<serde_json::Value>>,
            >,
        >;
        type ProtocolFields = (
            &'static Option<OriginalCanonicalBlobAckEmitter>,
            &'static Option<OriginalCanonicalRestoreInputEmitter>,
            &'static Option<CnpSemanticSourceRead>,
            &'static Option<OriginalHelloJournal>,
            &'static [Vec<u8>; 5],
            &'static [Option<serde_json::Value>; 5],
            &'static Option<PacketCanonicalAckAdmissionContext>,
            &'static Option<serde_json::Value>,
            &'static bool,
            &'static bool,
            &'static bool,
            &'static bool,
            &'static bool,
            &'static bool,
            &'static std::cell::Cell<bool>,
        );
        OriginalOwnerCapacityMetadataData::counter_scratch_data()
            + RetainedCaptureProtocolData::capacity_counter_scratch_data()
            + CnpSemanticSourceRead::retained_capacity_counter_scratch_data()
            + value_capacity_counter_scratch_data()
            + size_of::<ProtocolFields>()
            + size_of::<Option<&mut PacketRuntimeMetadataRecordBank>>()
            + size_of::<&mut OriginalOwnerCapacityMetadataData<'_>>()
            + size_of::<usize>()
            + size_of::<bool>()
            + size_of::<&Self>()
            + size_of::<&OriginalAckPeerAssociation>()
            + size_of::<Ref<'_, Option<OriginalAckPeerAssociation>>>()
            + size_of::<Result<Ref<'_, Option<OriginalAckPeerAssociation>>, BorrowError>>()
            + size_of::<std::slice::Iter<'_, Vec<u8>>>()
            + size_of::<Values>()
            + size_of::<[&crucible_node_format::Bytes; 8]>()
            + size_of::<std::array::IntoIter<&crucible_node_format::Bytes, 8>>()
            + size_of::<(
                &String,
                &String,
                &crucible_node_format::Bytes,
                &crucible_node_format::Bytes,
                &crucible_node_format::Bytes,
                &crucible_node_format::Bytes,
                &crucible_node_format::Bytes,
                &crucible_node_format::Bytes,
                &crucible_node_format::Bytes,
                &crucible_node_format::Bytes,
            )>()
            + size_of::<&PacketCanonicalAckAdmissionContext>()
            + size_of::<Option<&PacketCanonicalAckAdmissionContext>>()
            + size_of::<Result<RetainedProtocolMetadataFacts, RuntimeError>>()
    }
}

#[cfg(test)]
#[path = "protocol_capacities/tests.rs"]
mod tests;
