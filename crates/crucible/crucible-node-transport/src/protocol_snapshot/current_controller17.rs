//! Retains and validates current Controller17 logical DATA beside immutable ancestry.
//!
//! No decoded field can construct a live Controller, registrar, deadline, Source
//! claim or native permit. Owning parsing starts only after the independent new
//! decoder row is admitted. Exact input and a partial DOM remain retained on a
//! later grammar failure; immutable parent provenance is a separate outer check.

use super::{
    current_connection17::ConnectionSettledHistory17StructuralPlan,
    owned11::{OriginalOwned11Fields as Fields, original_owned11_plain_string as plain},
};
use crate::{ProviderError, bodies::*, envelope::Envelope};
use crucible_node_format::{ContentRef, HashRef, Id, U64, Validate};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};
use std::mem::size_of;

#[path = "current_controller17/typed_layouts.rs"]
mod typed_layouts;
use typed_layouts::{typed_layout_bytes, typed_result_views};

const SCHEMA: &str = "source-private.host-state-restored-settled/17";
const ROOT: [&str; 18] = [
    "ack_admit",
    "activation",
    "budget_nanoseconds",
    "budget_seconds",
    "capture",
    "complete_restore",
    "custody",
    "execution_owner",
    "fenced",
    "node",
    "observation",
    "protocol_owner_role",
    "restore_commit",
    "restore_prepare",
    "schema",
    "session",
    "supervisor",
    "uploads",
];

/// Reports independent raw/DOM retention, validation temporaries and fixed views.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerSettledHistory17ConstructionData {
    retained: usize,
    transient: usize,
    scratch: usize,
    total: usize,
}

impl ControllerSettledHistory17ConstructionData {
    /// Returns exact-input plus chosen inert DOM owner demand.
    pub const fn retained_requested_bytes_data(&self) -> usize {
        self.retained
    }

    /// Returns independent parser, canonical and typed-validation work.
    pub const fn maximum_simultaneous_transient_bytes_data(&self) -> usize {
        self.transient
    }

    /// Returns the defining fixed reader/header demand.
    pub const fn counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }

    /// Returns the checked whole new decoder demand, never admission authority.
    pub const fn requested_bytes_data(&self) -> usize {
        self.total
    }
}

/// Borrows a closed Controller17 root before owning decoding has been admitted.
pub struct ControllerSettledHistory17DecodePlan<'a> {
    input: &'a [u8],
    maximum: usize,
    demand: ControllerSettledHistory17ConstructionData,
}

/// Owns exact current logical bytes and an inert parsed component.
///
/// The private verified bit only records completion of this closed DATA reader.
/// It does not authenticate the enclosing archive, current World or fresh target.
pub struct ValidatedControllerSettledHistory17 {
    original: Vec<u8>,
    parsed: Option<Value>,
    verified: bool,
}

impl<'a> ControllerSettledHistory17DecodePlan<'a> {
    /// Checks the canonical root roster and prices the actual selected decoder.
    ///
    /// # Errors
    /// Refuses another family, unknown/missing root, size limit or checked overflow.
    pub fn validate(
        input: &'a [u8],
        maximum_input: usize,
        maximum_requested: usize,
    ) -> Result<Self, ProviderError> {
        if input.is_empty() || input.len() > maximum_input {
            return Err(invalid());
        }
        let mut fields = Fields::object(input)?;
        for name in ROOT {
            let value = fields.named(name)?;
            if name == "schema" && plain(value)? != SCHEMA {
                return Err(invalid());
            }
            if name == "session" {
                validate_session_boundary(value)?;
            }
        }
        fields.finish()?;
        let extent=crate::retained_metadata::serialization_storage::original_json_value_storage_extent_data(input.len())?;
        let retained = input
            .len()
            .checked_add(extent.value_dom_requested_bytes)
            .ok_or_else(invalid)?;
        // Only one typed child validation is live at once. The explicit sum of
        // all closed typed layouts conservatively bounds the largest child node;
        // the defining DOM bound independently covers its owned text/map backing.
        let transient = current_connection17_validation_transient_bytes_data(input.len())?;
        let scratch = current_controller17_counter_scratch_data();
        let total = retained
            .checked_add(transient)
            .and_then(|n| n.checked_add(scratch))
            .ok_or_else(invalid)?;
        if total > maximum_requested {
            return Err(invalid());
        }
        Ok(Self {
            input,
            maximum: maximum_input,
            demand: ControllerSettledHistory17ConstructionData {
                retained,
                transient,
                scratch,
                total,
            },
        })
    }

    /// Returns the independent construction DATA; the real caller admits it.
    pub const fn demand_data(&self) -> &ControllerSettledHistory17ConstructionData {
        &self.demand
    }

    /// Retains a partial output before the first owning allocation or parse.
    ///
    /// # Errors
    /// Refuses another output, unequal admitted row, allocation or any closed
    /// logical grammar/counter/namespace mismatch. The partial owner stays put.
    pub fn reconstruct_into(
        &self,
        admitted: &ControllerSettledHistory17ConstructionData,
        output: &mut Option<ValidatedControllerSettledHistory17>,
    ) -> Result<(), ProviderError> {
        if output.is_some() || admitted != &self.demand {
            return Err(invalid());
        }
        *output = Some(ValidatedControllerSettledHistory17 {
            original: Vec::new(),
            parsed: None,
            verified: false,
        });
        let slot = output.as_mut().ok_or_else(invalid)?;
        slot.original
            .try_reserve_exact(self.input.len())
            .map_err(|_| invalid())?;
        slot.original.extend_from_slice(self.input);
        slot.parsed = Some(crucible_node_format::canonical::parse_json(
            self.input,
            self.maximum,
        )?);
        validate_controller(slot.parsed.as_ref().ok_or_else(invalid)?)?;
        slot.verified = true;
        Ok(())
    }
}

impl ValidatedControllerSettledHistory17 {
    /// Returns exact bytes, including when later logical validation failed.
    pub fn original_bytes_data(&self) -> &[u8] {
        &self.original
    }

    /// Counts actual retained raw and parsed backing, including failed outputs.
    ///
    /// The enclosing owner separately counts this type's inline header. This
    /// walk does not substitute the prospective row or serialized length for
    /// actual Vec, String, array and map allocations.
    ///
    /// # Errors
    /// Refuses metadata/layout arithmetic overflow or the supplied ceiling.
    pub fn retained_requested_storage_data(&self, maximum: usize) -> Result<usize, ProviderError> {
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        observer.observe(&self.original)?;
        observer.observe(&self.parsed)?;
        let requested =
            crate::retained_metadata::requested_metadata_backing_storage_data(&observer.finish())?;
        if requested > maximum {
            return Err(invalid());
        }
        Ok(requested)
    }

    /// Borrows the complete inert logical component after strict DATA validation.
    ///
    /// No field is a live target owner or permission; outer provenance and actual
    /// fresh construction remain required independently.
    ///
    /// # Errors
    /// Refuses a retained partial whose closed validation did not finish.
    pub fn parts_data(&self) -> Result<&Value, ProviderError> {
        if !self.verified {
            return Err(invalid());
        }
        self.parsed.as_ref().ok_or_else(invalid)
    }
}

fn validate_session_boundary(input: &[u8]) -> Result<(), ProviderError> {
    let mut fields = Fields::object(input)?;
    fields.named("authority")?;
    let connection = fields.named("connection")?;
    ConnectionSettledHistory17StructuralPlan::validate(connection)?
        .authenticate_host_branch_data()?;
    fields.named("hello")?;
    if plain(fields.named("operational_cut")?)? != "same-stream-historical-nonrenewable-cut" {
        return Err(invalid());
    }
    fields.named("peer_executable")?;
    fields.named("peer_pid")?;
    if plain(fields.named("schema")?)? != "source-private.client-session-restored-settled/17" {
        return Err(invalid());
    }
    fields.named("sequence")?;
    fields.finish()
}

fn validate_controller(value: &Value) -> Result<(), ProviderError> {
    let value = object(value, &ROOT)?;
    text(field(value, "schema")?, SCHEMA)?;
    typed::<Id>(field(value, "node")?)?;
    typed::<Id>(field(value, "execution_owner")?)?;
    number(field(value, "budget_seconds")?)?;
    if number(field(value, "budget_nanoseconds")?)? >= 1_000_000_000 {
        return Err(invalid());
    }
    boolean(field(value, "fenced")?)?;
    text(
        field(value, "protocol_owner_role")?,
        "same-current-controller-actor",
    )?;
    session(field(value, "session")?)?;
    custody(field(value, "custody")?)?;
    optional(field(value, "ack_admit")?, |value| assigned(value, false))?;
    for name in ["complete_restore", "restore_prepare", "restore_commit"] {
        optional(field(value, name)?, |value| assigned(value, true))?;
    }
    for value in tuple(field(value, "activation")?, 2)? {
        optional(value, activation)?;
    }
    for value in tuple(field(value, "uploads")?, 2)? {
        optional(value, upload)?;
    }
    optional(field(value, "observation")?, observation)?;
    optional(
        field(value, "capture")?,
        super::current_sdk_capture17::validate_capture_data,
    )?;
    supervisor(field(value, "supervisor")?)
}

fn session(value: &Value) -> Result<(), ProviderError> {
    let value = object(
        value,
        &[
            "schema",
            "connection",
            "authority",
            "sequence",
            "peer_pid",
            "peer_executable",
            "hello",
            "operational_cut",
        ],
    )?;
    text(
        field(value, "schema")?,
        "source-private.client-session-restored-settled/17",
    )?;
    text(
        field(value, "operational_cut")?,
        "same-stream-historical-nonrenewable-cut",
    )?;
    number(field(value, "peer_pid")?)?;
    typed::<U64>(field(value, "sequence")?)?;
    typed::<ContentRef>(field(value, "peer_executable")?)?;
    authority(field(value, "authority")?)?;
    connection(field(value, "connection")?)?;
    if field(
        object(field(value, "connection")?, &CONNECTION)?,
        "authority",
    )? != field(value, "authority")?
    {
        return Err(invalid());
    }
    optional(field(value, "hello")?, frame_bank)
}

const CONNECTION: [&str; 17] = [
    "schema",
    "authority",
    "correlations",
    "codec",
    "blobs",
    "restore_inputs",
    "restore_responses",
    "complete_restoration",
    "canonical_ack_admission",
    "frames",
    "reader",
    "packet_schema",
    "connected_packet_schema",
    "fenced",
    "role",
    "protocol_owner_role",
    "supervisor_role",
];

fn connection(value: &Value) -> Result<(), ProviderError> {
    let value = object(value, &CONNECTION)?;
    text(
        field(value, "schema")?,
        "source-private.connection-restored-settled/17",
    )?;
    text(field(value, "role")?, "controller")?;
    text(
        field(value, "protocol_owner_role")?,
        "same-current-connection-actor",
    )?;
    text(
        field(value, "supervisor_role")?,
        "actual-retained-host-supervisor",
    )?;
    boolean(field(value, "fenced")?)?;
    for name in [
        "restore_inputs",
        "complete_restoration",
        "canonical_ack_admission",
    ] {
        if !field(value, name)?.is_null() {
            return Err(invalid());
        }
    }
    for response in tuple(field(value, "restore_responses")?, 2)? {
        if !response.is_null() {
            return Err(invalid());
        }
    }
    authority(field(value, "authority")?)?;
    super::current_transport17::validate_correlations_data(field(value, "correlations")?)?;
    super::current_transport17::validate_controller_codec_data(field(value, "codec")?)?;
    optional(
        field(value, "blobs")?,
        super::current_transport17::validate_blob_data,
    )?;
    frame_bank(field(value, "frames")?)?;
    let reader = object(
        field(value, "reader")?,
        &[
            "maximum_bytes",
            "maximum_nesting",
            "failed",
            "last_original_slot",
        ],
    )?;
    if number(field(reader, "maximum_bytes")?)? == 0
        || number(field(reader, "maximum_bytes")?)? > crate::transport::MAX_FRAME_BYTES as u64
        || number(field(reader, "maximum_nesting")?)? == 0
        || number(field(reader, "maximum_nesting")?)? > crate::transport::MAX_NESTING as u64
    {
        return Err(invalid());
    }
    boolean(field(reader, "failed")?)?;
    optional(field(reader, "last_original_slot")?, |v| {
        number(v).map(|_| ())
    })?;
    boolean(field(value, "packet_schema")?)?;
    boolean(field(value, "connected_packet_schema")?)?;
    connection_parent_data(value)
}

pub(super) fn authority(value: &Value) -> Result<(), ProviderError> {
    let value = object(
        value,
        &[
            "schema",
            "gate_role",
            "epoch_role",
            "saved_epoch",
            "observed_epoch",
            "gate_poisoned",
            "connection",
            "session",
            "incarnation",
            "limits",
            "features",
            "envelope_extensions",
            "extensions",
        ],
    )?;
    text(
        field(value, "schema")?,
        "source-private.connection-authority/17",
    )?;
    text(field(value, "gate_role")?, "registrar-gate")?;
    text(field(value, "epoch_role")?, "registrar-epoch")?;
    number(field(value, "saved_epoch")?)?;
    number(field(value, "observed_epoch")?)?;
    boolean(field(value, "gate_poisoned")?)?;
    for name in ["connection", "session", "incarnation"] {
        typed::<Id>(field(value, name)?)?;
    }
    let limits: crate::handshake::Limits = read(field(value, "limits")?)?;
    limits.validate()?;
    let features: Vec<Id> = read(field(value, "features")?)?;
    features.validate()?;
    let extensions = field(value, "envelope_extensions")?
        .as_array()
        .ok_or_else(invalid)?;
    let mut previous: Option<&str> = None;
    for extension in extensions {
        let extension = extension.as_str().ok_or_else(invalid)?;
        if previous.is_some_and(|old| old >= extension) {
            return Err(invalid());
        }
        previous = Some(extension);
    }
    optional(
        field(value, "extensions")?,
        typed::<Vec<crucible_node_format::ExtensionSelection>>,
    )
}

pub(super) fn connection_parent_data(value: &Map<String, Value>) -> Result<(), ProviderError> {
    let authority = field(value, "authority")?.as_object().ok_or_else(invalid)?;
    let correlations = tuple(field(value, "correlations")?, 12)?;
    let limits: crate::handshake::Limits = read(field(authority, "limits")?)?;
    let reader = field(value, "reader")?.as_object().ok_or_else(invalid)?;
    if &correlations[1] != field(authority, "session")?
        || &correlations[2] != field(authority, "incarnation")?
        || number(&correlations[5])? != limits.requests.get()
        || number(field(reader, "maximum_bytes")?)? != limits.frame_bytes.get()
        || number(field(reader, "maximum_nesting")?)? != limits.nesting.get()
    {
        return Err(invalid());
    }
    Ok(())
}

fn custody(value: &Value) -> Result<(), ProviderError> {
    let value = tuple(value, 6)?;
    let maximum = number(&value[0])?;
    if number(&value[2])? > number(&value[1])? {
        return Err(invalid());
    }
    for journal in [&value[3], &value[4]] {
        let journal = journal.as_object().ok_or_else(invalid)?;
        if journal.len() as u64 > maximum {
            return Err(invalid());
        }
        for (id, entry) in journal {
            Id::new(id.clone()).map_err(ProviderError::from)?;
            let entry = object(entry, &["request", "identity", "response"])?;
            let request: Envelope = read(field(entry, "request")?)?;
            if request.request_id.0.as_ref().map(Id::as_str) != Some(id.as_str()) {
                return Err(invalid());
            }
            typed::<HashRef>(field(entry, "identity")?)?;
            optional(field(entry, "response")?, typed::<Envelope>)?;
        }
    }
    super::current_transport17::validate_content_data(&value[5])
}

fn assigned(value: &Value, restore: bool) -> Result<(), ProviderError> {
    let value = tuple(value, if restore { 11 } else { 8 })?;
    text(
        &value[0],
        if restore {
            "source-private.sdk-assigned-restore-current/17"
        } else {
            "source-private.sdk-assigned-admit-current/17"
        },
    )?;
    typed::<Envelope>(&value[1])?;
    compact(&value[2], Some(number(&value[3])?))?;
    optional(&value[4], |v| number(v).map(|_| ()))?;
    phase(
        &value[5],
        &["unsigned", "sealing", "sealed", "publishing", "complete"],
    )?;
    optional(&value[6], typed::<Envelope>)?;
    text(&value[7], "historical-nonrenewable-operational-cut")?;
    if restore {
        typed::<ContentRef>(&value[8])?;
        typed::<[u8; 32]>(&value[9])?;
        text(&value[10], "same-prepared-mapping-identity")?;
    }
    Ok(())
}

fn activation(value: &Value) -> Result<(), ProviderError> {
    let value = tuple(value, 11)?;
    text(&value[0], "source-private.sdk-activation-current/17")?;
    super::current_transport17::validate_activation_command_data(&value[1])?;
    super::current_transport17::validate_activation_request_data(&value[2])?;
    optional(&value[3], typed::<Value>)?;
    optional(&value[4], typed::<Envelope>)?;
    compact(&value[5], Some(number(&value[6])?))?;
    optional(&value[7], |v| number(v).map(|_| ()))?;
    phase(
        &value[8],
        &[
            "preparing",
            "unsigned",
            "sealing",
            "sealed",
            "publishing",
            "complete",
        ],
    )?;
    optional(&value[9], typed::<Envelope>)?;
    text(&value[10], "historical-nonrenewable-operational-cut")
}

fn observation(value: &Value) -> Result<(), ProviderError> {
    let value = tuple(value, 13)?;
    text(&value[0], "source-private.sdk-first-observation-current/17")?;
    typed::<ObserveRequest>(&value[1])?;
    super::current_transport17::validate_observation_request_data(&value[2])?;
    optional(&value[3], typed::<Value>)?;
    optional(&value[4], typed::<Envelope>)?;
    compact(&value[5], Some(number(&value[6])?))?;
    optional(&value[7], |v| number(v).map(|_| ()))?;
    phase(
        &value[8],
        &[
            "preparing",
            "unsigned",
            "sealing",
            "sealed",
            "publishing",
            "complete",
        ],
    )?;
    optional(&value[9], typed::<Envelope>)?;
    optional(&value[10], response)?;
    text(&value[11], "historical-nonrenewable-operational-cut")?;
    optional(&value[12], typed::<U64>)?;
    if (value[8].as_str() == Some("complete")) != !value[12].is_null() {
        return Err(invalid());
    }
    Ok(())
}

fn upload(value: &Value) -> Result<(), ProviderError> {
    super::current_transport17::validate_upload_data(value)
}

fn frame_bank(value: &Value) -> Result<(), ProviderError> {
    super::current_transport17::validate_frame_bank_data(value)
}

fn supervisor(value: &Value) -> Result<(), ProviderError> {
    super::current_transport17::validate_supervisor_data(value)
}

pub(super) fn response(value: &Value) -> Result<(), ProviderError> {
    let value = object(value, &["shape", "result"])?;
    typed::<ResponseShape>(field(value, "shape")?)?;
    optional(field(value, "result")?, |value| {
        let value = object(value, &["kind", "data"])?;
        let body = field(value, "data")?;
        match field(value, "kind")?.as_str().ok_or_else(invalid)? {
            "admit" => typed::<AdmitResult>(body),
            "activate" => typed::<ActivateResult>(body),
            "world_activate" => typed::<WorldActivateResult>(body),
            "prepare_restore" => typed::<PrepareRestoreResult>(body),
            "capture" => typed::<CaptureResult>(body),
            "begin_accepted" => typed::<BeginAccepted>(body),
            "input" => typed::<InputResult>(body),
            "observe" => typed::<ObserveResult>(body),
            "poll" => typed::<PollResult>(body),
            "exact_run" | "boundary_settle" => typed::<ExactRunResult>(body),
            "retire" => typed::<RetireResult>(body),
            "blob_begin" => typed::<BlobBeginResult>(body),
            "blob_chunk" => typed::<BlobChunkResult>(body),
            "blob_finish" => typed::<BlobFinishResult>(body),
            _ => Err(invalid()),
        }
    })
}

pub(super) fn object<'a>(
    value: &'a Value,
    keys: &[&str],
) -> Result<&'a Map<String, Value>, ProviderError> {
    let value = value.as_object().ok_or_else(invalid)?;
    if value.len() != keys.len() || keys.iter().any(|key| !value.contains_key(*key)) {
        return Err(invalid());
    }
    Ok(value)
}

pub(super) fn field<'a>(
    value: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a Value, ProviderError> {
    value.get(key).ok_or_else(invalid)
}
pub(super) fn tuple(value: &Value, length: usize) -> Result<&[Value], ProviderError> {
    let value = value.as_array().ok_or_else(invalid)?;
    if value.len() != length {
        return Err(invalid());
    }
    Ok(value)
}
pub(super) fn text(value: &Value, expected: &str) -> Result<(), ProviderError> {
    if value.as_str() == Some(expected) {
        Ok(())
    } else {
        Err(invalid())
    }
}
pub(super) fn number(value: &Value) -> Result<u64, ProviderError> {
    value.as_u64().ok_or_else(invalid)
}
pub(super) fn boolean(value: &Value) -> Result<(), ProviderError> {
    value.as_bool().ok_or_else(invalid).map(|_| ())
}
pub(super) fn optional(
    value: &Value,
    validate: impl FnOnce(&Value) -> Result<(), ProviderError>,
) -> Result<(), ProviderError> {
    if value.is_null() {
        Ok(())
    } else {
        validate(value)
    }
}
pub(super) fn phase(value: &Value, allowed: &[&str]) -> Result<(), ProviderError> {
    if value.as_str().is_some_and(|v| allowed.contains(&v)) {
        Ok(())
    } else {
        Err(invalid())
    }
}
pub(super) fn read<T: DeserializeOwned>(value: &Value) -> Result<T, ProviderError> {
    T::deserialize(value)
        .map_err(crucible_node_format::ContractError::from)
        .map_err(ProviderError::from)
}
pub(super) fn typed<T: DeserializeOwned>(value: &Value) -> Result<(), ProviderError> {
    read::<T>(value).map(|_| ())
}
pub(super) fn compact(value: &Value, capacity: Option<u64>) -> Result<(), ProviderError> {
    let encoded = serde_json::to_vec(value).map_err(crucible_node_format::ContractError::from)?;
    let compact =
        super::compact_bytes::ValidatedCompactBytes::validate(&encoded, encoded.len(), usize::MAX)?;
    if capacity.is_some_and(|capacity| compact.decoded_length() as u64 > capacity) {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn verify_compact_reference_data(
    reference: &ContentRef,
    value: &Value,
) -> Result<(), ProviderError> {
    let encoded = serde_json::to_vec(value).map_err(crucible_node_format::ContractError::from)?;
    let payload =
        super::compact_bytes::ValidatedCompactBytes::validate(&encoded, encoded.len(), usize::MAX)?;
    verify_compact_payload_data(reference, &payload)
}

pub(super) fn verify_compact_payload_data(
    reference: &ContentRef,
    payload: &super::compact_bytes::ValidatedCompactBytes<'_>,
) -> Result<(), ProviderError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(payload.decoded_length())
        .map_err(|_| invalid())?;
    payload.fill_preowned(&mut bytes)?;
    reference.verify(&bytes)?;
    Ok(())
}

fn retained_reader_counter_scratch_data() -> usize {
    size_of::<crate::retained_metadata::MetadataObserver<'static>>()
        + size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
        + size_of::<Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError>>(
        )
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Option<&str>>()
        + size_of::<std::slice::Iter<'static, Value>>()
        + size_of::<&ContentRef>()
        + size_of::<&super::compact_bytes::ValidatedCompactBytes<'static>>()
        + size_of::<Result<super::compact_bytes::ValidatedCompactBytes<'static>, ProviderError>>()
        + size_of::<Vec<u8>>()
        + size_of::<&mut Vec<u8>>()
        + size_of::<Result<(), std::collections::TryReserveError>>()
        + size_of::<Result<(), crucible_node_format::ContractError>>()
        + crate::client::compact_cursor::compact_content_summary_bank_bytes()
        + crate::client::compact_cursor::compact_content_parser_scratch_bytes()
}

/// Names every defining fixed structural/owning reader view.
pub fn current_controller17_counter_scratch_data() -> usize {
    retained_reader_counter_scratch_data()
        + size_of::<ControllerSettledHistory17ConstructionData>()
        + size_of::<ControllerSettledHistory17DecodePlan<'static>>()
        + size_of::<ValidatedControllerSettledHistory17>()
        + size_of::<Option<ValidatedControllerSettledHistory17>>()
        + size_of::<&mut Option<ValidatedControllerSettledHistory17>>()
        + size_of::<Result<ControllerSettledHistory17DecodePlan<'static>,ProviderError>>()
        + size_of::<Result<(),ProviderError>>()
        + size_of::<Result<Value,crucible_node_format::ContractError>>()
        + size_of::<Result<Value,serde_json::Error>>()
        + size_of::<Result<Vec<u8>,serde_json::Error>>()
        + size_of::<Result<(),std::collections::TryReserveError>>()
        + size_of::<Fields<'static>>()
        + size_of::<Result<Fields<'static>,ProviderError>>()
        + size_of::<Result<&Value,ProviderError>>()
        + size_of::<Result<&Map<String,Value>,ProviderError>>()
        + size_of::<Result<&[Value],ProviderError>>()
        + size_of::<Result<u64,ProviderError>>()
        + size_of::<[&str;18]>()
        + size_of::<std::array::IntoIter<&str,18>>()
        + crate::retained_metadata::serialization_storage::original_json_value_storage_extent_counter_scratch_data()
        + typed_layout_bytes()
        + typed_result_views()
        + super::current_connection17::current_connection17_counter_scratch_data()
        + super::current_sdk_capture17::counter_scratch_data()
        + super::current_transport17::counter_scratch_data()
        + super::current_native_connection17::counter_scratch_data()
}

pub(super) fn invalid() -> ProviderError {
    ProviderError::Correlation("current Controller17 logical history differs")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn incomplete_data() -> Value {
        let mut component: Map<String, Value> = ROOT
            .into_iter()
            .map(|key| (key.to_owned(), Value::Null))
            .collect();
        component.insert("schema".into(), json!(SCHEMA));
        component.insert("node".into(), json!("reader/node"));
        component.insert("execution_owner".into(), json!("reader/owner"));
        component.insert("budget_seconds".into(), json!(1));
        component.insert("budget_nanoseconds".into(), json!(0));
        component.insert("fenced".into(), json!(false));
        component.insert(
            "protocol_owner_role".into(),
            json!("same-current-controller-actor"),
        );
        // All structural fields are present, but the Authority is deliberately
        // incomplete. A structural root is never whole logical acceptance.
        component.insert(
            "session".into(),
            json!({
                "schema":"source-private.client-session-restored-settled/17",
                "connection":super::super::current_connection17::tests::connection(false),
                "authority":{},"sequence":"2","peer_pid":1,
                "peer_executable":null,"hello":null,
                "operational_cut":"same-stream-historical-nonrenewable-cut",
            }),
        );
        Value::Object(component)
    }

    #[test]
    fn short_admission_keeps_output_empty_and_decode_failure_retains_exact_partial() {
        let input = serde_json::to_vec(&incomplete_data()).unwrap();
        let plan = ControllerSettledHistory17DecodePlan::validate(&input, input.len(), usize::MAX)
            .unwrap();
        let mut short = *plan.demand_data();
        short.retained -= 1;
        let mut output = None;
        assert!(plan.reconstruct_into(&short, &mut output).is_err());
        assert!(output.is_none());

        assert!(
            plan.reconstruct_into(plan.demand_data(), &mut output)
                .is_err()
        );
        let output = output.as_ref().unwrap();
        assert_eq!(output.original_bytes_data(), input.as_slice());
        assert!(output.parsed.is_some());
        assert!(output.parts_data().is_err());
    }

    #[test]
    fn unknown_root_and_old_family_refuse_before_owning_decode() {
        let mut value = incomplete_data();
        value["schema"] = json!("source-private.host-state-owned/11");
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(
            ControllerSettledHistory17DecodePlan::validate(&bytes, bytes.len(), usize::MAX)
                .is_err()
        );

        value["schema"] = json!(SCHEMA);
        value["unknown_owner"] = json!({"unaccounted":true});
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(
            ControllerSettledHistory17DecodePlan::validate(&bytes, bytes.len(), usize::MAX)
                .is_err()
        );
    }
}

/// Quotes the common/native logical validators' independent transient work.
///
/// The whole native reader supplies its genuinely selected encoded component
/// bound and separately funds exact raw/DOM retention and native private children.
/// This DATA getter is not a Source/Window/native allocation permission.
///
/// # Errors
/// Refuses zero extent or checked lexical/typed/canonical arithmetic overflow.
pub fn current_connection17_validation_transient_bytes_data(
    maximum_encoded: usize,
) -> Result<usize, ProviderError> {
    let extent =
        crate::retained_metadata::serialization_storage::original_json_value_storage_extent_data(
            maximum_encoded,
        )?;
    let typed = extent
        .maximum_value_nodes
        .checked_mul(typed_layout_bytes())
        .and_then(|n| n.checked_add(extent.value_dom_requested_bytes))
        .ok_or_else(invalid)?;
    extent
        .canonical_pass_requested_bytes()?
        .checked_mul(3)
        .and_then(|n| n.checked_add(typed))
        .ok_or_else(invalid)
}

#[path = "current_controller17/suffix_pair.rs"]
mod suffix_pair;
pub use suffix_pair::{
    ValidatedHistoricalRestoredSuffixPair, historical_restored_suffix_pair_counter_scratch_data,
    historical_restored_suffix_pair_validation_transient_bytes_data,
};

#[path = "current_controller17/first_observation.rs"]
mod first_observation;
pub use first_observation::ValidatedHistoricalFirstRestorationObservation17;

#[path = "current_controller17/capture.rs"]
mod capture;
pub use capture::{
    ValidatedHistoricalRestoredSettledCapture17,
    historical_restored_settled_capture17_counter_scratch_data,
    historical_restored_settled_capture17_retained_construction_bytes_data,
    historical_restored_settled_capture17_selected_counter_scratch_data,
    historical_restored_settled_capture17_selected_retained_construction_bytes_data,
    historical_restored_settled_capture17_selected_validation_transient_bytes_data,
    historical_restored_settled_capture17_validation_transient_bytes_data,
};

mod restoration_association;
pub use restoration_association::{
    ValidatedHistoricalRestorationAssociation17,
    historical_restoration_association17_counter_scratch_data,
    historical_restoration_association17_selected_counter_scratch_data,
    historical_restoration_association17_validation_transient_bytes_data,
    historical_restoration_association17_validation_transient_for_controller_data,
};
