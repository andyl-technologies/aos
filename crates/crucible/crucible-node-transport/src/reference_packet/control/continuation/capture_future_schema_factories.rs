//! Quotes the fixed schema factories reached by the unchanged Control validator.
//!
//! Same borrowed compiled rosters drive counting and actual factory encoding.
//! This adds no factory query, schema cache, decoder branch or live permission.
//! Input-dependent coordinator data, validation errors and outer owners remain
//! separate from these fixed definitions and generated reference children.

use super::*;
use crate::reference_packet::{
    continuation_contracts,
    continuation_models::canonical_value_writer_frame_data,
    service::{
        ack_emitter, capture_allocation,
        complete_restore::{self, transfer},
        confirmation,
        native_startup::contract_value::ContractValue,
    },
};
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData as Shape, original_serialization_counter_scratch_data,
    original_serialization_frame_counter_scratch_data,
};
use std::mem::size_of;

type Axes = (usize, usize);

impl PacketDecodedCaptureFutureControlData {
    /// Names fixed controls before projecting the actual compiled definitions.
    ///
    /// The caller admits these controls before invoking the allocation-free
    /// quote. It separately admits the returned constructor T/S before decode.
    /// The existing counter rejects a 65th container before descending, so its
    /// actual borrowed Serialize call profile has at most 65 activations.
    pub fn decoder_validation_schema_quote_counter_scratch_data() -> usize {
        original_serialization_counter_scratch_data()
            + 65 * (contract_frame_data() + original_serialization_frame_counter_scratch_data())
            + size_of::<[Shape; 11]>()
            + size_of::<[Shape; 4]>()
            + size_of::<Result<[Shape; 4], ProviderError>>()
            + size_of::<[(usize, Shape); 11]>()
            + size_of::<std::array::IntoIter<(usize, Shape), 11>>()
            + size_of::<(usize, Shape)>()
            + 2 * size_of::<[&str; 26]>()
            + size_of::<std::array::IntoIter<&str, 26>>()
            + size_of::<&str>()
            // maximum/transient/nodes/calls/count/heap/scratch, reference
            // identifiers_bytes/reference, and sum total/left/right operands.
            + size_of::<usize>() * 12
            + size_of::<&[usize]>()
            + size_of::<std::slice::Iter<'static, usize>>()
            + size_of::<&usize>()
            + size_of::<[usize; 4]>()
            + size_of::<std::array::IntoIter<usize, 4>>()
            + size_of::<Option<usize>>()
            + size_of::<Axes>()
            + size_of::<Result<Axes, ProviderError>>()
            + size_of::<Result<Shape, ProviderError>>()
            + size_of::<Result<usize, ProviderError>>()
    }

    /// Projects independent temporary and fixed constructor demand for schemas.
    ///
    /// Every potentially selected factory branch is summed conservatively:
    /// allocation (two), canonical inputs (one), transfer (six) plus record
    /// (one), restoration (three), ACK (one),
    /// confirmation (one) and the exact complete-coordinator factory roster. Each
    /// call uses its defining immutable borrowed Serialize roster. No schema
    /// factory or temporary JSON owner is executed to discover the demand.
    ///
    /// Actual Control/World/model DTOs, variable coordinator identity/configuration
    /// work, validation-error backing and the caller's retained failure owner
    /// remain separate. The result is no allocation allowance or capability.
    ///
    /// # Errors
    /// Refuses checked arithmetic or a complete independent T/S sum above
    /// `maximum`, including an insufficient quotation window.
    pub fn decoder_validation_schema_construction_data(
        maximum: usize,
    ) -> Result<(usize, usize), ProviderError> {
        let [packet, ingress, host_definition, host_continuation] =
            continuation_contracts::complete_coordinator_contract_projections_data(maximum)?;
        let contracts = [
            (
                2,
                capture_allocation::capture_allocation_contract_storage_data(maximum)?,
            ),
            (
                1,
                complete_restore::canonical_restore_inputs_contract_storage_data(maximum)?,
            ),
            (
                6,
                transfer::complete_restore_transfer_contract_storage_data(maximum)?,
            ),
            (
                1,
                complete_restore::native_restored_record_contract_storage_data(maximum)?,
            ),
            (
                3,
                complete_restore::complete_restore_contract_storage_data(maximum)?,
            ),
            (
                1,
                ack_emitter::native_canonical_blob_ack_contract_storage_data(maximum)?,
            ),
            (
                1,
                confirmation::native_after_confirmation_contract_storage_data(maximum)?,
            ),
            (6, packet),
            (3, ingress),
            (2, host_definition),
            (1, host_continuation),
        ];
        let mut transient = 0usize;
        let mut nodes = 0usize;
        let mut calls = 0usize;
        for (count, shape) in contracts {
            // Requested-total includes the quotation's fixed S. Keep that axis
            // separate here; actual factory controls are independently below.
            let heap = sum(&[
                shape.dom_and_canonical_scratch_bytes,
                shape.projected_parser_requested_bytes,
                shape.canonical_output_requested_bytes,
                shape.serializer_temporary_requested_bytes,
            ])?;
            transient = add(transient, mul(count, heap)?)?;
            nodes = add(nodes, mul(count, shape.serialized_value_nodes)?)?;
            calls = add(calls, count)?;
        }
        transient = add(transient, reference_children_data()?)?;

        // Each actual JSON node bounds one Serialize/JCS activation. Complete
        // independent ordering controls belong to every canonical factory call;
        // none receives credit from the quotation or a retained input graph.
        let scratch = sum(&[
            Self::decoder_validation_schema_quote_counter_scratch_data(),
            mul(
                nodes,
                add(contract_frame_data(), canonical_value_writer_frame_data())?,
            )?,
            mul(
                calls,
                canonical::canonical_json_counter_scratch_bytes_data(),
            )?,
            reference_constructor_counter_scratch_data(),
        ])?;
        if add(transient, scratch)? > maximum {
            return Err(exhausted());
        }
        Ok((transient, scratch))
    }
}

fn reference_children_data() -> Result<usize, ProviderError> {
    // These are the actual schema constructors' identifier leaves. Complete
    // coordinator validation has three peers with receipt/continuation/ingress each,
    // one Host continuation and one preparation Id. Its remaining three references
    // are ContentRef-only (two definitions and the configuration); preparation
    // additionally owns its cloned definition. Total: 29 independent fullrefs.
    let identifiers = schema_identifiers_data();
    let mut identifiers_bytes = 0usize;
    for identifier in identifiers {
        identifiers_bytes = add(identifiers_bytes, identifier.len())?;
    }
    // Static to_owned fields request their exact lengths. The hex Display
    // String has a separate cumulative RawVec growth envelope 4L + 16, with L = 64
    // fixed by the actual BLAKE3 hex result. It is not a body-size multiplier.
    let reference = sum(&[
        "blake3-256".len(),
        "cnp.blob.v1".len(),
        "application/json".len(),
        add(mul(4, 64)?, 16)?,
    ])?;
    add(identifiers_bytes, mul(29, reference)?)
}

fn schema_identifiers_data() -> [&'static str; 26] {
    use transfer::PacketCompleteRestoreTransferPhase::{Commit, Prepare};
    [
        capture_allocation::PACKET_NATIVE_CAPTURE_ALLOCATION_REPORT,
        capture_allocation::PACKET_NATIVE_CAPTURE_ALLOCATION_RECORD,
        complete_restore::PACKET_CANONICAL_RESTORE_INPUTS_FEATURE,
        Prepare.request_extension(),
        Prepare.proof_extension(),
        Prepare.receipt_extension(),
        Commit.request_extension(),
        Commit.proof_extension(),
        Commit.receipt_extension(),
        complete_restore::PACKET_NATIVE_RESTORED_RECORD_FEATURE,
        complete_restore::PACKET_COMPLETE_RESTORE_FEATURE,
        complete_restore::PACKET_COMPLETE_RESTORE_PROOF_EXTENSION,
        complete_restore::PACKET_COMPLETE_RESTORE_RECEIPT_EXTENSION,
        ack_emitter::PACKET_NATIVE_CANONICAL_ACK_FEATURE,
        "source-owned.packet-native-after-confirmation/5",
        "source-owned.packet-receipt/5",
        "source-owned.packet-native-continuation/5",
        "source-owned.packet-ingress/5",
        "source-owned.packet-receipt/5",
        "source-owned.packet-native-continuation/5",
        "source-owned.packet-ingress/5",
        "source-owned.packet-receipt/5",
        "source-owned.packet-native-continuation/5",
        "source-owned.packet-ingress/5",
        "source-owned.host-scheduling-continuation/2",
        "source-owned.host-scheduling-complete-preparation/2",
    ]
}

fn contract_frame_data() -> usize {
    // Typed Serialize and its generic Container element/key loans coexist.
    2 * size_of::<&ContractValue<'static>>()
        + 2 * size_of::<&&str>()
        + size_of::<&str>()
        + size_of::<&&[ContractValue<'static>]>()
        + size_of::<&&[(&str, ContractValue<'static>)]>()
        + size_of::<std::slice::Iter<'static, ContractValue<'static>>>()
        + size_of::<std::slice::Iter<'static, (&str, ContractValue<'static>)>>()
        + size_of::<Option<&ContractValue<'static>>>()
        + size_of::<Option<&(&str, ContractValue<'static>)>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<Value, serde_json::Error>>()
}

fn reference_constructor_counter_scratch_data() -> usize {
    size_of::<SchemaRef>() * 29
        + size_of::<transfer::PacketCompleteRestoreTransferPhase>()
        + size_of::<transfer::PacketCompleteRestoreTransferSchema>()
        + size_of::<Result<SchemaRef, ProviderError>>()
        + size_of::<[SchemaRef; 2]>()
        + size_of::<Result<[SchemaRef; 2], ProviderError>>()
        + size_of::<std::array::IntoIter<SchemaRef, 2>>()
        + size_of::<[SchemaRef; 3]>()
        + size_of::<Result<[SchemaRef; 3], ProviderError>>()
        + size_of::<std::array::IntoIter<SchemaRef, 3>>()
        + size_of::<[SchemaRef; 7]>()
        + size_of::<Result<[SchemaRef; 7], ProviderError>>()
        + size_of::<std::array::IntoIter<SchemaRef, 7>>()
        + size_of::<ContentRef>()
        + size_of::<Result<ContentRef, ContractError>>()
        + size_of::<HashRef>()
        + size_of::<Result<HashRef, ContractError>>()
        + size_of::<Id>()
        + size_of::<Result<Id, ContractError>>()
        + size_of::<Result<Id, crucible_node_format::IdFromOwnedError>>()
        + crucible_node_format::IdFromOwnedError::construction_transient_bytes_data()
        + crucible_node_format::IdFromOwnedError::construction_counter_scratch_bytes_data()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + returned_size(blake3::Hash::to_hex)
        + size_of::<[u8; 4]>()
        + size_of::<[u8; 8]>()
        + size_of::<String>()
        + size_of::<&[u8]>()
        + size_of::<&str>()
        + size_of::<std::str::Bytes<'static>>()
        + size_of::<Result<u32, std::num::TryFromIntError>>()
        + size_of::<Result<u64, std::num::TryFromIntError>>()
        + size_of::<std::fmt::Arguments<'static>>()
        + size_of::<std::fmt::Formatter<'static>>()
        + size_of::<std::fmt::Result>()
}

fn returned_size<T>(_: fn(&blake3::Hash) -> T) -> usize {
    size_of::<T>()
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("independent Control schema factory constructor")
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(exhausted)
}

fn mul(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(exhausted)
}

fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values.iter().try_fold(0, |total, next| add(total, *next))
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn actual_factory_identifiers_match_closed_allocation_roster() -> TestResult {
        let mut schemas = vec![
            capture_allocation::capture_allocation_schema()?,
            capture_allocation::capture_allocation_record_schema()?,
            complete_restore::canonical_restore_inputs_schema()?,
        ];
        schemas
            .extend(crate::reference_packet::Native5Policy::complete_restore_transfer_schemas()?);
        schemas.extend([
            complete_restore::complete_restore_request_schema()?,
            complete_restore::complete_restore_proof_schema()?,
            complete_restore::complete_restore_receipt_schema()?,
            ack_emitter::native_canonical_blob_ack_schema()?,
            confirmation::native_after_confirmation_schema()?,
        ]);
        for _ in 0..3 {
            schemas.extend([
                continuation_contracts::complete_packet_receipt_schema()?,
                continuation_contracts::complete_packet_continuation_schema()?,
                continuation_contracts::complete_packet_ingress_schema()?,
            ]);
        }
        schemas.push(continuation_contracts::complete_host_continuation_schema()?);
        let identifiers = schema_identifiers_data();
        assert_eq!(schemas.len(), 25);
        for (actual, expected) in schemas.iter().zip(&identifiers[..25]) {
            assert_eq!(actual.id.as_str(), *expected);
        }
        // Preparation's inline SchemaRef is defined by validate_host, rather
        // than a public factory. Its independent definition clone is priced.
        assert_eq!(
            identifiers[25],
            "source-owned.host-scheduling-complete-preparation/2"
        );
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        for schema in &schemas {
            observer.observe(schema)?;
        }
        let actual =
            crate::retained_metadata::requested_metadata_backing_storage_data(&observer.finish())?;
        let (transient, _) =
            PacketDecodedCaptureFutureControlData::decoder_validation_schema_construction_data(
                usize::MAX,
            )?;
        assert!(transient >= actual);
        Ok(())
    }

    #[test]
    fn complete_fixed_factory_axes_preserve_exact_boundary_without_issuing_owner() -> TestResult {
        let actual =
            PacketDecodedCaptureFutureControlData::decoder_validation_schema_construction_data(
                usize::MAX,
            )?;
        assert!(actual.0 > 0 && actual.1 > 0);
        let total = actual.0.checked_add(actual.1).ok_or_else(exhausted)?;
        assert_eq!(
            PacketDecodedCaptureFutureControlData::decoder_validation_schema_construction_data(
                total
            )?,
            actual
        );
        assert!(
            PacketDecodedCaptureFutureControlData::decoder_validation_schema_construction_data(
                total - 1
            )
            .is_err()
        );
        assert!(
            PacketDecodedCaptureFutureControlData::decoder_validation_schema_construction_data(0)
                .is_err()
        );
        Ok(())
    }
}
