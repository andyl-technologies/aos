//! Defines immutable complete packet preservation contracts separately from execution.
//!
//! The specifications bind the concrete Native5 and independent Host2 codecs.
//! Encoding, decoding or hashing these bytes issues no capture ticket, native
//! association, readiness, restoration permission or qualification evidence.
//!
//! ```text
//! {"schema":"source-owned.packet-semantic-contract/5", "closure":{...}}
//! ```

use crucible_source_birth_data::profile::reference_packet::continuation_contracts::{
    CompleteHostContinuationValue, CompleteHostDefinitionValue, CompletePacketContractValue,
};

pub(super) use crucible_source_birth_data::profile::reference_packet::continuation_contracts::{
    complete_host_continuation_schema, complete_host_definition,
};

pub use crucible_source_birth_data::profile::reference_packet::continuation_contracts::{
    PACKET_COMPLETE_LINEAGE_FEATURE, PACKET_COMPLETE_LINEAGE_PROFILE,
    PACKET_NATIVE5_COORDINATOR_SCHEMA, PACKET_NATIVE5_IMPLEMENTATION, complete_ingress_contract,
    complete_packet_continuation_schema, complete_packet_contract, complete_packet_ingress_schema,
    complete_packet_receipt_schema,
};

use crucible_node_format::SchemaRef;

use crate::ProviderError;

mod confirmation;
pub use confirmation::{
    PacketNative5ConfirmationDeclaration, complete_packet_confirmation_declaration,
};
mod ack_emitter;
pub use ack_emitter::{
    PacketNative5AckEmitterDeclaration, complete_packet_ack_emitter_declaration,
};

mod complete_restore;
mod fresh_restore;
pub use complete_restore::{
    PacketNative5CompleteRestoreDeclaration, complete_packet_capture_allocation_declaration,
    complete_packet_restore_declaration, complete_packet_restore_input_emitter_declaration,
};
pub use fresh_restore::complete_packet_fresh_restore_allocation_declaration;

// One borrowed compiled roster drives BOTH the existing canonical definition
// and its prospective DOM/canonical counter. No schema bytes or field values
// are regenerated independently in the admission calculation.

pub(crate) use crucible_source_birth_data::profile::reference_packet::service::native_startup::schema_shapes::contracts::complete_ingress_contract_storage_data;

// The same immutable rosters drive ordinary encoding and prospective counting.

/// Counts all static contract generators called by one complete coordinator validator.
///
/// Each native validation retains receipt/continuation/ingress references while
/// another definition is encoded. Summing the complete phases for all3 peers
/// and the independent Host validators is conservative; no schema DOM is made.
pub(crate) fn complete_coordinator_contract_storage_data(
    maximum: usize,
) -> Result<usize, ProviderError> {
    use crate::retained_metadata::{
        RetainedProtocolMetadataFacts, serialization_storage::actual_serialization_storage_data,
    };
    let packet = actual_serialization_storage_data(
        &CompletePacketContractValue,
        RetainedProtocolMetadataFacts::default(),
        maximum,
    )?
    .requested_total()?;
    let ingress = complete_ingress_contract_storage_data(maximum)?.requested_total()?;
    let host_definition = actual_serialization_storage_data(
        &CompleteHostDefinitionValue,
        RetainedProtocolMetadataFacts::default(),
        maximum,
    )?
    .requested_total()?;
    let host_continuation = actual_serialization_storage_data(
        &CompleteHostContinuationValue,
        RetainedProtocolMetadataFacts::default(),
        maximum,
    )?
    .requested_total()?;
    // Three native validators each call receipt + continuation + ingress;
    // Host validation and host_configuration independently build the definition.
    [
        packet,
        packet,
        ingress,
        packet,
        packet,
        ingress,
        packet,
        packet,
        ingress,
        host_definition,
        host_definition,
        host_continuation,
        // Nine native SchemaRefs and five Host definition/configuration/schema
        // refs remain independent. SchemaRef includes ContentRef inline; Id
        // grammar supplies its finite128-byte dynamic child bound.
        14 * (std::mem::size_of::<SchemaRef>()
            + 128
            + "blake3-256".len()
            + "cnp.blob.v1".len()
            + 64
            + "application/json".len()),
    ]
    .into_iter()
    .try_fold(0usize, |sum, bytes| {
        sum.checked_add(bytes)
            .filter(|total| *total <= maximum)
            .ok_or(ProviderError::ResourceExhausted(
                "complete coordinator contract storage",
            ))
    })
}

#[cfg(test)]
#[path = "continuation_contracts/precision_tests.rs"]
mod precision_tests;

#[path = "continuation_contracts/initial15.rs"]
mod initial15;
pub use initial15::complete_packet_contract_history_data;

/// Projects the same four fixed rosters reached by complete coordinator validation.
///
/// This allocation-free DATA companion does not run a schema factory. The actual
/// validator calls packet (six), ingress (three), Host definition (two) and Host continuation (one);
/// its caller separately prices each returned reference and constructor phase.
pub(crate) fn complete_coordinator_contract_projections_data(
    maximum: usize,
) -> Result<
    [crate::retained_metadata::serialization_storage::OriginalSerializationStorageData; 4],
    ProviderError,
> {
    use crate::retained_metadata::{
        RetainedProtocolMetadataFacts, serialization_storage::actual_serialization_storage_data,
    };
    Ok([
        actual_serialization_storage_data(
            &CompletePacketContractValue,
            RetainedProtocolMetadataFacts::default(),
            maximum,
        )?,
        complete_ingress_contract_storage_data(maximum)?,
        actual_serialization_storage_data(
            &CompleteHostDefinitionValue,
            RetainedProtocolMetadataFacts::default(),
            maximum,
        )?,
        actual_serialization_storage_data(
            &CompleteHostContinuationValue,
            RetainedProtocolMetadataFacts::default(),
            maximum,
        )?,
    ])
}
