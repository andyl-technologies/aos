//! Names actual stage work and observes every retained partial child.
//!
//! Rows limit each axis independently. The installer admits the checked whole
//! holder plus cumulative retained requests, new retained requests, transient
//! work and fixed scratch before invoking a constructor. These numbers issue no
//! private key, allocation grant, startup member or native permission.

use super::*;
use crate::node_adapters::cnp::semantic::initial_lifecycle_diagnostics::OriginalInitialLifecycleDiagnostics;
use crucible_node_format::{ExtensionSelection, HashRef};
use crucible_node_transport::reference_packet::control::PacketDecodedCaptureFutureControlData;
use crucible_node_transport::reference_packet::service::PacketNative5CoordinatorConstructionStorage;
use crucible_node_transport::reference_packet::service::PacketNative5LaunchValidationStorage;
use crucible_node_transport::reference_packet::service::complete_restore::import18::hello::{
    PacketNativeImport18HelloDeclarationData, PacketNativeImport18ProspectiveHostRegistrationData,
    native_import18_registration_counter_scratch_data,
};
use crucible_node_transport::retained_metadata::RetainedProtocolMetadataFacts;
use std::{cell::Ref, mem::size_of};

/// Measures only real Bytes leaves of this pre-report SourceBirth view.
///
/// The closed declaration contains selection/portable coordinator fields,
/// generic Values, scalar limits and program configuration. Generic Value
/// serialization never invokes Bytes deserialization or a reserved raw reset.
/// The producer's event payloads are the only custom Bytes serialization leaves;
/// the reactive configuration declares connections/endpoints, not reactions.
/// These exhaustive field patterns keep that fact tied to the defining types.
pub(super) fn source_formatter_storage_data(
    launch: &PacketNative5SourceLaunch,
) -> Result<usize, RuntimeError> {
    use crucible_node_transport::reference_packet::service::PacketConnectedSourceProgram;
    use crucible_node_transport::reference_packet::{
        PacketEvent, PacketProgramDefinition, connected::PacketConnectedDefinition,
    };
    match &launch.program {
        PacketConnectedSourceProgram::Producer { program } => {
            let PacketProgramDefinition { schema: _, events } = program;
            let mut maximum = 0;
            for PacketEvent {
                id: _,
                evaluation: _,
                completion: _,
                payload,
            } in events
            {
                if let Some(payload) = payload {
                    maximum = maximum.max(
                        crucible_node_format::Bytes::borrowed_serialization_temporary_bytes_data(
                            payload.as_slice(),
                        )
                        .map_err(|_| RuntimeError::ResourceLimit)?,
                    );
                }
            }
            Ok(maximum)
        }
        PacketConnectedSourceProgram::Reactive { program } => {
            let PacketConnectedDefinition {
                schema: _,
                connections: _,
                output: _,
            } = program;
            Ok(0)
        }
    }
}

/// Quotes the actual one-time retained owner and its constructor occurrences.
pub(super) fn initialize_storage_data(maximum: usize) -> Result<[usize; 3], RuntimeError> {
    let private_attempt_return =
        NativeImport18PrivateBirthAttempt::new_construction_transient_data();
    let worker_initializer = size_of::<NativeImport18BirthConstruction>();
    let box_owning_argument = size_of::<NativeImport18BirthConstruction>();
    let box_return = size_of::<Box<NativeImport18BirthConstruction>>();
    let destination_assignment = size_of::<Option<Box<NativeImport18BirthConstruction>>>();
    let transient = sum(&[
        private_attempt_return,
        worker_initializer,
        box_owning_argument,
        box_return,
        destination_assignment,
        // take/replace return, old local and owned None/write inputs are
        // distinct header roles; their same heap remains retained exactly once.
        size_of::<Option<Id>>() * 5,
        size_of::<Option<PacketCompleteAckHostRegistrationPlan>>() * 5,
    ])?;
    bounded(
        [
            size_of::<NativeImport18BirthConstruction>(),
            transient,
            counter_scratch_data(),
        ],
        maximum,
    )
}

fn initial_operand_take_counter_scratch_data<T>() -> usize {
    // Option::take and mem::replace borrow the same slot through distinct
    // receivers; ptr::read/write expose their own source/destination controls.
    size_of::<&mut Option<T>>() * 2 + size_of::<*const Option<T>>() + size_of::<*mut Option<T>>()
}

pub(super) fn sum(values: &[usize]) -> Result<usize, RuntimeError> {
    values.iter().try_fold(0usize, |sum, value| {
        sum.checked_add(*value).ok_or(RuntimeError::ResourceLimit)
    })
}

pub(super) fn bounded(row: [usize; 3], maximum: usize) -> Result<[usize; 3], RuntimeError> {
    if row.into_iter().any(|value| value > maximum) {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(row)
}

pub(super) fn world_refusal_storage_data() -> usize {
    // The actual Producer/Reactive world comparators only borrow these labels.
    // Both the ordinary and selected initial diagnostic mode are included.
    [
        "packet complete original coordinator changed",
        "complete packet original coordinator changed",
        "complete producer world absent",
    ]
    .into_iter()
    .map(|text| {
        OriginalInitialLifecycleDiagnostics::borrowed_refusal_requested_storage_data(text.len())
    })
    .max()
    .unwrap_or(0)
}

pub(super) fn canonical_error_storage_data() -> Result<usize, RuntimeError> {
    // These retained Values passed the unchanged constructor depth checks. The
    // fixed canonical errors have no user-controlled Message body. The neutral
    // public component supplies only the actual serde ErrorImpl allocation.
    let text = "nesting exceeds 64 containers"
        .len()
        .max("not a finite JCS number".len())
        .max("exceeds 65536 elements".len());
    let string = text
        .checked_mul(4)
        .and_then(|v| v.checked_add(8))
        .ok_or(RuntimeError::ResourceLimit)?;
    sum(&[
        string,
        string,
        PacketDecodedCaptureFutureControlData::decoder_error_impl_allocation_upper_bytes_data(),
    ])
}

pub(super) fn registration_storage(
    plan: &PacketCompleteAckHostRegistrationPlan,
) -> Result<usize, RuntimeError> {
    let mut census =
        crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData::new(
            usize::MAX,
            None,
        );
    super::metadata::record_registration_capacity_data(plan, &mut census)?;
    PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
        &census.finish(),
        usize::MAX,
    )
}

/// Names the real quote, source facade, typed view and partial-census controls.
///
/// The pending defining coordinator facade supplies its decode/validator AND
/// retained observation scratch. No unrelated large DTO is a size donor.
/// Caller-specific admission callbacks remain independent work.
pub(super) fn counter_scratch_data() -> usize {
    let controls = super::metadata::counter_scratch_data()
        + size_of::<NativeImport18BirthConstruction>()
        + size_of::<Option<Box<NativeImport18BirthConstruction>>>()
        + size_of::<Box<NativeImport18BirthConstruction>>()
        + size_of::<NativeImport18BirthConstructionQuote>()
        + size_of::<Result<NativeImport18BirthConstructionQuote, RuntimeError>>()
        + size_of::<Identity>()
        + size_of::<Result<Identity, RuntimeError>>()
        + size_of::<&crucible_node_format::RealizationManifest>()
        + size_of::<&crucible_node_format::OwnerRef>()
        + size_of::<std::slice::Iter<'static, crucible_node_format::OwnerRef>>()
        + size_of::<[&crucible_node_format::IdSet; 2]>()
        + size_of::<std::array::IntoIter<&'static crucible_node_format::IdSet, 2>>()
        + size_of::<std::collections::btree_map::Iter<'static, String, Value>>()
        + size_of::<Option<i64>>() + size_of::<Option<u64>>() + size_of::<Option<f64>>()
        + size_of::<i64>() + size_of::<u64>() + size_of::<f64>()
        + size_of::<Stage>()
        + size_of::<&PacketCompleteSemanticSource>()
        + size_of::<&mut PacketCompleteSemanticSource>()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<&PacketNative5CoordinatorInstallation>()
        + size_of::<&NativeImport18BirthConstruction>()
        + size_of::<&mut NativeImport18BirthConstruction>()
        + size_of::<&NativeImport18BirthConstructionQuote>()
        + size_of::<Result<&NativeImport18BirthConstruction, RuntimeError>>()
        + size_of::<&PacketCompleteAckHostRegistrationPlan>()
        + size_of::<Option<PacketCompleteAckHostRegistrationPlan>>()
        + size_of::<&mut Option<PacketCompleteAckHostRegistrationPlan>>()
        + size_of::<Option<Id>>()
        + size_of::<&mut Option<Id>>()
        + size_of::<Ref<'static, Option<OriginalAckPeerBirth>>>()
        + size_of::<Ref<'static, Option<OriginalAckPeerAssociation>>>()
        + size_of::<Ref<'static, Option<crate::node_adapters::cnp::semantic::packet_complete_source::preconstruction::OriginalCompletePreconstruction>>>()
        + size_of::<std::cell::BorrowError>()
        + size_of::<Result<Ref<'static, Option<OriginalAckPeerBirth>>, std::cell::BorrowError>>()
        + size_of::<Result<Ref<'static, Option<OriginalAckPeerAssociation>>, std::cell::BorrowError>>()
        // The shared source view now owns the actual nonsecret field header.
        // Existing view/tuple/Result sizeof terms below follow its larger type;
        // These terms distinguish the initialized projection and its returned
        // result before it enters that view.
        + size_of::<PacketNative5LaunchValidationFields<'static>>() // initialized field view
        + size_of::<PacketNative5LaunchValidationFields<'static>>()
        + size_of::<&PacketNative5LaunchValidationFields<'static>>()
        + size_of::<views::SourceBirthView<'static>>()
        + size_of::<views::RegistrationView<'static>>()
        + size_of::<(
            views::SourceBirthView<'static>,
            views::RegistrationView<'static>,
        )>()
        + size_of::<
            Result<
                (
                    views::SourceBirthView<'static>,
                    views::RegistrationView<'static>,
                ),
                RuntimeError,
            >,
        >()
        + size_of::<Option<PacketNative5CoordinatorInstallation>>()
        + size_of::<PacketNative5CoordinatorInstallation>()
        + size_of::<
            Result<PacketNative5CoordinatorInstallation, crucible_node_transport::ProviderError>,
        >()
        + size_of::<Value>()
        + size_of::<Option<Value>>()
        + size_of::<Result<Value, serde_json::Error>>()
        + size_of::<ReservedWriter<'static>>()
        + size_of::<std::io::ErrorKind>()
        + size_of::<std::io::Result<usize>>()
        + size_of::<std::io::Result<()>>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<Result<(), OperationFailure>>()
        + size_of::<Result<(), crucible_node_transport::ProviderError>>()
        + size_of::<Result<usize, RuntimeError>>()
        + size_of::<[usize; 3]>()
        + size_of::<Result<[usize; 3], RuntimeError>>()
        + size_of::<(usize, usize)>()
        + size_of::<Result<(usize, usize), RuntimeError>>()
        + size_of::<[usize; 2]>()
        + size_of::<[usize; 8]>()
        + size_of::<[(&mut Option<Vec<u8>>, usize); 2]>()
        + size_of::<std::array::IntoIter<(&'static mut Option<Vec<u8>>, usize), 2>>()
        + size_of::<(&mut Option<Vec<u8>>, usize)>()
        + size_of::<&mut Vec<u8>>()
        + size_of::<&[usize]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<Option<usize>>()
        + size_of::<&usize>()
        + size_of::<usize>() * 12
        + size_of::<bool>() * 3
        + size_of::<&crucible_node_transport::reference_packet::service::PacketConnectedSourceProgram>()
        + size_of::<&crucible_node_transport::reference_packet::PacketProgramDefinition>()
        + size_of::<&crucible_node_transport::reference_packet::connected::PacketConnectedDefinition>()
        + size_of::<std::slice::Iter<'static, crucible_node_transport::reference_packet::PacketEvent>>()
        + size_of::<&crucible_node_transport::reference_packet::PacketEvent>()
        + size_of::<Option<&crucible_node_format::Bytes>>()
        + size_of::<&crucible_node_format::Bytes>()
        + size_of::<[u8; 20]>()
        + size_of::<Result<usize, crucible_node_format::ContractError>>()
        + size_of::<[&[u8]; 3]>()
        + size_of::<std::array::IntoIter<&'static [u8], 3>>()
        + size_of::<[&ContentRef; 2]>()
        + size_of::<std::array::IntoIter<&'static ContentRef, 2>>()
        + size_of::<[&String; 4]>()
        + size_of::<std::array::IntoIter<&'static String, 4>>()
        + size_of::<&ContentRef>()
        + size_of::<&HashRef>()
        + size_of::<&String>()
        + size_of::<&Id>()
        + size_of::<&str>()
        + size_of::<&[u8]>()
        + size_of::<[u8; 32]>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<RetainedProtocolMetadataFacts>()
        + size_of::<&RetainedProtocolMetadataFacts>()
        + size_of::<Result<RetainedProtocolMetadataFacts, crucible_node_transport::ProviderError>>()
        + size_of::<std::slice::Iter<'static, Id>>()
        + size_of::<std::slice::Iter<'static, String>>()
        + size_of::<std::slice::Iter<'static, ExtensionSelection>>()
        + size_of::<&ExtensionSelection>()
        + size_of::<[&Option<Value>; 2]>()
        + size_of::<std::array::IntoIter<&'static Option<Value>, 2>>()
        + size_of::<std::iter::Flatten<std::array::IntoIter<&'static Option<Value>, 2>>>()
        + size_of::<[&str; 3]>()
        + size_of::<std::array::IntoIter<&'static str, 3>>()
        + size_of::<Option<usize>>()
        + size_of::<std::alloc::Layout>()
        + size_of::<Result<std::alloc::Layout, std::alloc::LayoutError>>();
    let value_frame = size_of::<&Value>()
        + size_of::<std::slice::Iter<'static, Value>>()
        + size_of::<serde_json::map::Iter<'static>>()
        + size_of::<(&String, &Value)>()
        + size_of::<Result<usize, RuntimeError>>()
        + size_of::<[usize; 5]>()
        + size_of::<[usize; 3]>()
        + size_of::<std::array::IntoIter<usize, 3>>()
        + size_of::<usize>() * 4;
    let serializer_frame = size_of::<serde_json::value::Serializer>()
        + size_of::<<serde_json::value::Serializer as serde::Serializer>::SerializeSeq>()
        + size_of::<<serde_json::value::Serializer as serde::Serializer>::SerializeMap>()
        + size_of::<<serde_json::value::Serializer as serde::Serializer>::SerializeStruct>()
        + size_of::<&Value>()
        + size_of::<std::slice::Iter<'static, Value>>()
        + size_of::<serde_json::map::Iter<'static>>()
        + size_of::<(&String, &Value)>()
        + size_of::<Value>()
        + size_of::<Result<Value, serde_json::Error>>();
    crate::node_adapters::cnp::semantic::packet_complete_source::template18::MECHANISM_GATE_CONTROLS
        + controls
        + 65 * value_frame
        + 128 * serializer_frame
        + size_of::<&mut NativeImport18BirthConstruction>()
        + size_of::<&mut Option<Id>>()
        + size_of::<&mut Option<PacketCompleteAckHostRegistrationPlan>>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<bool>()
        + size_of::<[usize; 7]>()
        + initial_operand_take_counter_scratch_data::<Id>().max(
            initial_operand_take_counter_scratch_data::<PacketCompleteAckHostRegistrationPlan>(),
        )
        + 128 * NodeRuntime::capture_serialization_counter_scratch_data()
        + NativeImport18PrivateBirthAttempt::counter_scratch_data()
        + PacketNative5SourceLaunch::validation_construction_counter_scratch_data()
        + crucible_node_transport::reference_packet::service::original_import18_serialized_credit_failure_counter_scratch_data()
        + CREDIT_FAILURE_QUOTE_ADAPTER_CONTROLS
        + PacketCompleteSemanticSource::native_import18_declaration_counter_scratch_data()
        + PacketNative5CoordinatorInstallation::decode_construction_counter_scratch_data()
        + PacketCompleteSemanticSource::retained_metadata_conversion_counter_scratch_data()
        + canonical::canonical_json_counter_scratch_bytes_data()
        + OriginalInitialLifecycleDiagnostics::counter_scratch_bytes()
        + crucible_node_format::Bytes::serialization_counter_scratch_data()
        + crucible_node_format::Bytes::borrowed_serialization_counter_scratch_data()
        + native_import18_registration_counter_scratch_data()
        + size_of::<PacketNativeImport18HelloDeclarationData>()
        + size_of::<
            Result<
                PacketNativeImport18HelloDeclarationData,
                crucible_node_transport::ProviderError,
            >,
        >()
        + size_of::<
            Result<
                PacketNativeImport18ProspectiveHostRegistrationData,
                crucible_node_transport::ProviderError,
            >,
        >()
}

// Owns only the new credit-component call's actual Source-side adapter.
// Producer envelopes, bindings, constructor operands and FnOnce/Try arguments
// are distinct roles. All terms are const and admitted before either quote.
type CreditPair = (usize, usize);
type CreditResidual = Result<std::convert::Infallible, RuntimeError>;
type CreditFlow = std::ops::ControlFlow<CreditResidual, CreditPair>;

const CREDIT_FAILURE_QUOTE_ADAPTER_CONTROLS: usize = size_of::<usize>() * 2 // new coexisting locals
    + size_of::<CreditPair>() // caller ? Continue output binding
    + size_of::<[usize; 2]>() // actual new transient sum
    + size_of::<[usize; 3]>() // actual enlarged scratch sum
    + size_of::<Result<CreditPair, crucible_node_transport::ProviderError>>() // map_err self
    + size_of::<CreditPair>() * 2 // map_err Ok binding / Ok owned input
    + size_of::<crucible_node_transport::ProviderError>() // map_err Err binding
    + size_of::<crucible_node_transport::ProviderError>() // callback argument -> FnOnce tuple field input
    + size_of::<(crucible_node_transport::ProviderError,)>() // callback tuple initializer
    + size_of::<(crucible_node_transport::ProviderError,)>() // actual FnOnce args
    + size_of::<crucible_node_transport::ProviderError>() // closure's owned argument binding
    + size_of::<()>() // capture-free closure initializer
    + size_of::<()>() // map_err op owned operand
    + size_of::<()>() // FnOnce owned callable receiver
    + size_of::<RuntimeError>() // actual ResourceLimit initializer
    + size_of::<RuntimeError>() // mapper return
    + size_of::<RuntimeError>() // mapped Err owned input
    + size_of::<Result<CreditPair, RuntimeError>>() * 2 // mapper Result initializer / return
    + size_of::<Result<CreditPair, RuntimeError>>() // actual Try::branch self
    + size_of::<CreditPair>() * 2 // Try Ok binding / Continue owned input
    + size_of::<CreditFlow>() * 2 // branch initializer / return
    + size_of::<RuntimeError>() // Try Err binding
    + size_of::<RuntimeError>() // residual Err owned input
    + size_of::<CreditResidual>() // residual initializer
    + size_of::<CreditResidual>() // Break owned input
    + size_of::<CreditResidual>() // caller ? Break residual binding
    + size_of::<CreditResidual>() // FromResidual owned input
    + size_of::<RuntimeError>() // FromResidual Err binding
    + size_of::<RuntimeError>() // actual identity From owned input
    + size_of::<RuntimeError>() // identity From return (no Into edge)
    + size_of::<RuntimeError>() // enclosing Err owned input
    + size_of::<Result<NativeImport18BirthConstructionQuote, RuntimeError>>() // Err initializer
    + size_of::<Result<NativeImport18BirthConstructionQuote, RuntimeError>>(); // FromResidual return
