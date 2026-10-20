//! Projects a signed Observe17 from closed borrowed field views.
//!
//! A prospective original is geometry, not an Envelope, assigned sequence, MAC
//! or native grant. Actual and prospective model encoders share the same exact
//! inventory field visitor. No arbitrary Serialize implementation is accepted.

use super::*;
use crate::reference_packet::connected::{
    PacketConnectedInventory, observation17_inventory_counter_scratch_data,
    project_original_observation17_inventory_data,
};
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection,
};
use std::mem::size_of;

type Projection = OriginalSerializationStorageProjection;

#[path = "observation_geometry/source_typed_storage.rs"]
mod source_typed_storage;
pub use source_typed_storage::{
    PacketRestoredObservation17SourceComponentStorageData,
    PacketRestoredObservation17SourceTypedStorageData,
    quote_restored_observation17_current_wrapper_storage_data,
    quote_restored_observation17_source_typed_storage_data,
};

/// Borrows the actual fields that determine one prospective signed Observe.
///
/// The owning Source independently authenticates these loans against its same
/// current checkpoint, first observation and SDK frontier. Public construction
/// supplies DATA only and cannot assign or spend any request.
pub struct PacketRestoredObservation17ProspectiveData<'a> {
    /// Borrows the actual current restoration and World correspondence.
    pub scope: &'a PacketRestorationActivationScope,
    /// Borrows the actual unchanged baseline observation body.
    pub observe: &'a ObserveRequest,
    /// Borrows this current generation's genuinely completed first observation.
    pub first_observation: &'a ContentRef,
    /// Borrows the uniquely latest authenticated restored proof reference.
    pub current_record: &'a ContentRef,
    /// Borrows that proof's complete current Reactive model reference.
    pub current_model: &'a ContentRef,
    /// Gives the actual SDK saved completed frontier before assignment.
    pub frontier: U64,
    /// Gives the actual next Source-owned observation ordinal.
    pub ordinal: u64,
}

/// Selects actual wire fields or the one closed prospective observation grammar.
pub(crate) enum Observation17OriginalData<'a> {
    Actual(&'a Envelope),
    Prospective(&'a PacketRestoredObservation17ProspectiveData<'a>),
}

/// Reports the independently owned expected output DOMs and canonical banks.
///
/// This fixed DATA is produced by the closed future-Observe inventory and
/// actual current wrapper visitors. It authenticates no Source, bank or row.
pub struct PacketRestoredObservation17OutputStorageData {
    model: OriginalSerializationStorageData,
    restored: OriginalSerializationStorageData,
}

impl PacketRestoredObservation17OutputStorageData {
    /// Returns the complete expected model's canonical wire-length bound.
    pub fn maximum_model_bytes_data(&self) -> usize {
        self.model.maximum_encoded_bytes
    }

    /// Returns the complete expected restored proof's canonical wire-length bound.
    pub fn maximum_restored_bytes_data(&self) -> usize {
        self.restored.maximum_encoded_bytes
    }

    /// Returns independently bounded full-model serialization and hashing work.
    ///
    /// A separate inventory-only hash phase may use this full-tree upper bound;
    /// its work is charged again rather than sharing another phase's credit.
    ///
    /// # Errors
    /// Refuses checked serialization-work overflow.
    pub fn model_serialization_work_bytes_data(&self) -> Result<usize, ProviderError> {
        self.model.requested_total()
    }

    /// Returns independently bounded restored-proof serialization work.
    ///
    /// # Errors
    /// Refuses checked serialization-work overflow.
    pub fn restored_serialization_work_bytes_data(&self) -> Result<usize, ProviderError> {
        self.restored.requested_total()
    }

    /// Reports the expected output DOM and canonical-bank retained growth.
    ///
    /// Typed Source clones, SDK custody, prefix transport and native work remain
    /// separate independently admitted owners.
    ///
    /// # Errors
    /// Refuses checked summation or a requested-storage representation overflow.
    pub fn expected_state_row_data(
        &self,
    ) -> Result<super::super::native_startup::PacketNativeStartupAllocationRow, ProviderError> {
        let sum = |terms: &[usize]| {
            terms.iter().try_fold(0usize, |sum, term| {
                sum.checked_add(*term).ok_or_else(exhausted)
            })
        };
        let quantity = |value| u64::try_from(value).map(U64::new).map_err(|_| exhausted());
        Ok(
            super::super::native_startup::PacketNativeStartupAllocationRow {
                retained_requested_bytes: quantity(sum(&[
                    self.model.retained_value_backing_bytes,
                    self.restored.retained_value_backing_bytes,
                    self.model.canonical_output_requested_bytes,
                    self.restored.canonical_output_requested_bytes,
                ])?)?,
                maximum_simultaneous_transient_bytes: quantity(sum(&[
                    self.model.requested_total()?,
                    self.restored.requested_total()?,
                ])?)?,
                declared_counter_scratch_bytes: quantity(sum(&[
                    restored_observation17_output_counter_scratch_data(),
                    self.model.declared_counter_scratch_bytes,
                    self.restored.declared_counter_scratch_bytes,
                ])?)?,
            },
        )
    }
}

/// Quotes the prospective Source outputs from actual borrowed current geometry.
///
/// The caller separately authenticates the immutable current wrapper bank and
/// exact Source-held Reactive inventory. The native producer uses the same
/// visitors with its actual stopped inventory and actual assigned original.
/// Neither a successful quote nor equal geometry creates a current-proof loan.
///
/// # Errors
/// Refuses unsupported closed fields, grants/oversized inventory, malformed
/// retained wrapper JSON, overflow or a component exceeding `maximum`.
pub fn quote_restored_observation17_output_storage_data(
    prospective: &PacketRestoredObservation17ProspectiveData<'_>,
    native_pid: U64,
    inventory: &PacketConnectedInventory,
    current_wrapper: &[u8],
    maximum: usize,
) -> Result<PacketRestoredObservation17OutputStorageData, ProviderError> {
    let original = Observation17OriginalData::Prospective(prospective);
    let mut projection = Projection::new(maximum)?;
    model(&mut projection, native_pid, &original, inventory)?;
    let mut model = projection.finish(maximum)?;
    model.serializer_temporary_requested_bytes = crate::reference_packet::connected::original_observation17_inventory_formatter_storage_data(inventory)?;
    let mut projection = Projection::new(maximum)?;
    restored_from_current_bytes(&mut projection, current_wrapper, &original)?;
    let mut restored = projection.finish(maximum)?;
    restored.serializer_temporary_requested_bytes = restored
        .serializer_temporary_requested_bytes
        .checked_add(43)
        .ok_or_else(exhausted)?;
    if model.requested_total()? > maximum || restored.requested_total()? > maximum {
        return Err(exhausted());
    }
    Ok(PacketRestoredObservation17OutputStorageData { model, restored })
}

/// Names the complete output visitor's fixed borrowed headers before its walk.
///
/// This DATA includes the inventory and bounded current-wrapper field cursors.
/// It grants no allocation or current-checkpoint authority.
pub fn restored_observation17_output_counter_scratch_data() -> usize {
    counter_scratch_data()
        + size_of::<PacketRestoredObservation17OutputStorageData>()
        + size_of::<Result<PacketRestoredObservation17OutputStorageData, ProviderError>>()
}

/// Names the closed Source typed-owner visitor's fixed headers before its walk.
///
/// The independent SDK and expected-output counters remain separate components.
pub fn restored_observation17_source_typed_counter_scratch_data() -> usize {
    prospective_counter_scratch_data() + source_typed_storage::counter_scratch_data()
}

pub(crate) fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("signed Observe17 prospective field geometry")
}

pub(crate) fn object(out: &mut Projection, names: &[&str]) -> Result<(), ProviderError> {
    out.add_object()?;
    for name in names {
        out.add_field(name)?;
    }
    Ok(())
}

pub(crate) fn json_reference(out: &mut Projection) -> Result<(), ProviderError> {
    object(out, &["hash", "length", "media_type"])?;
    hash(out, "cnp.blob.v1")?;
    out.add_unescaped_ascii_extent(20)?;
    out.add_string("application/json")
}

pub(crate) fn hash(out: &mut Projection, domain: &str) -> Result<(), ProviderError> {
    object(out, &["algorithm", "domain", "digest"])?;
    out.add_string("blake3-256")?;
    out.add_string(domain)?;
    out.add_unescaped_ascii_extent(64)
}

fn decimal(out: &mut Projection, value: U64) -> Result<(), ProviderError> {
    let digits = value.get().checked_ilog10().unwrap_or(0) as usize + 1;
    out.add_unescaped_ascii_extent(digits)
}

fn crate_reference(out: &mut Projection, value: &ContentRef) -> Result<(), ProviderError> {
    object(out, &["hash", "length", "media_type"])?;
    out.add_value(&value.hash)?;
    decimal(out, value.length)?;
    out.add_string(&value.media_type)
}

fn observe(out: &mut Projection, value: &ObserveRequest) -> Result<(), ProviderError> {
    if !value.extensions.is_empty() {
        return Err(exhausted());
    }
    object(
        out,
        &[
            "binding_hash",
            "owner_generation",
            "after_observation_sequence",
            "maximum_items",
            "extensions",
        ],
    )?;
    out.add_value(&value.binding_hash)?;
    decimal(out, value.owner_generation)?;
    decimal(out, value.after_observation_sequence)?;
    decimal(out, value.maximum_items)?;
    out.add_value(&value.extensions)
}

pub(crate) fn scope(
    out: &mut Projection,
    value: &PacketRestorationActivationScope,
) -> Result<(), ProviderError> {
    let PacketRestorationActivationScope {
        source_birth,
        source_runtime,
        scope_proof,
        target,
        restoration,
    } = value;
    let super::super::complete_restore::activation::PacketRestorationActivationTarget {
        native_pid,
        session,
        incarnation,
        node,
        owner,
        owner_generation,
        binding_hash,
        world,
        activation,
        generation,
        prepared_token,
        gate,
        admission,
        transaction,
    } = target;
    let super::super::complete_restore::activation::PacketRestorationActivationOriginals {
        captured_owner_state,
        captured_control,
        captured_journal,
        mapping,
        commit_request,
        commit_response,
        context_digest,
    } = restoration;
    object(
        out,
        &[
            "source_birth",
            "source_runtime",
            "scope_proof",
            "target",
            "restoration",
        ],
    )?;
    crate_reference(out, source_birth)?;
    crate_reference(out, source_runtime)?;
    crate_reference(out, scope_proof)?;
    object(
        out,
        &[
            "native_pid",
            "session",
            "incarnation",
            "node",
            "owner",
            "owner_generation",
            "binding_hash",
            "world",
            "activation",
            "generation",
            "prepared_token",
            "gate",
            "admission",
            "transaction",
        ],
    )?;
    decimal(out, *native_pid)?;
    out.add_value(session)?;
    out.add_value(incarnation)?;
    out.add_value(node)?;
    out.add_value(owner)?;
    decimal(out, *owner_generation)?;
    out.add_value(binding_hash)?;
    out.add_value(world)?;
    out.add_value(activation)?;
    decimal(out, *generation)?;
    out.add_value(prepared_token)?;
    out.add_value(gate)?;
    out.add_value(admission)?;
    out.add_value(transaction)?;
    object(
        out,
        &[
            "captured_owner_state",
            "captured_control",
            "captured_journal",
            "mapping",
            "commit_request",
            "commit_response",
            "context_digest",
        ],
    )?;
    for reference in [
        captured_owner_state,
        captured_control,
        captured_journal,
        mapping,
        commit_request,
        commit_response,
    ] {
        crate_reference(out, reference)?;
    }
    if context_digest.as_slice().len() != 32 {
        return Err(exhausted());
    }
    out.add_unescaped_ascii_extent(43)
}

impl PacketRestoredObservation17ProspectiveData<'_> {
    pub(crate) fn request(&self, out: &mut Projection) -> Result<(), ProviderError> {
        if self.ordinal == 0
            || self.frontier.get() == 0
            || self.observe.after_observation_sequence != U64::new(0)
            || self.observe.maximum_items != U64::new(1)
            || !self.observe.extensions.is_empty()
            || self.observe.binding_hash != self.scope.target.binding_hash
            || self.observe.owner_generation != self.scope.target.owner_generation
        {
            return Err(exhausted());
        }
        object(
            out,
            &[
                "schema",
                "command",
                "scope",
                "first_observation",
                "current_record",
                "current_model",
                "history_prefix",
                "history_next_sequence",
                "native_allocation",
            ],
        )?;
        out.add_string(REQUEST_SCHEMA)?;
        object(out, &["action"])?;
        out.add_string("observe")?;
        scope(out, self.scope)?;
        crate_reference(out, self.first_observation)?;
        crate_reference(out, self.current_record)?;
        crate_reference(out, self.current_model)?;
        json_reference(out)?;
        decimal(out, self.frontier)?;
        object(
            out,
            &[
                "retained_requested_bytes",
                "maximum_simultaneous_transient_bytes",
                "declared_counter_scratch_bytes",
            ],
        )?;
        for _ in 0..3 {
            out.add_unescaped_ascii_extent(20)?;
        }
        Ok(())
    }

    pub(crate) fn artifact(&self, out: &mut Projection) -> Result<(), ProviderError> {
        object(out, &["request", "proof"])?;
        self.request(out)?;
        object(out, &["schema", "algorithm", "context_digest", "mac"])?;
        out.add_string(PROOF_SCHEMA)?;
        out.add_string("blake3-256-mac")?;
        out.add_unescaped_ascii_extent(43)?;
        out.add_unescaped_ascii_extent(43)
    }

    pub(crate) fn context(&self, out: &mut Projection) -> Result<(), ProviderError> {
        object(out, &["schema", "request", "assigned_request"])?;
        out.add_string(CONTEXT_SCHEMA)?;
        self.request(out)?;
        out.add_unescaped_ascii_extent(43)
    }
}

impl Observation17OriginalData<'_> {
    pub(crate) fn project(&self, out: &mut Projection) -> Result<(), ProviderError> {
        match self {
            Self::Actual(original) => {
                object(
                    out,
                    &[
                        "protocol",
                        "message",
                        "session_id",
                        "incarnation_id",
                        "node_id",
                        "execution_owner_id",
                        "capture_owner_id",
                        "request_id",
                        "operation_id",
                        "sequence",
                        "method",
                        "body",
                        "extensions",
                    ],
                )?;
                out.add_string(&original.protocol)?;
                out.add_value(&original.message)?;
                out.add_value(&original.session_id)?;
                out.add_value(&original.incarnation_id)?;
                out.add_value(&original.node_id)?;
                out.add_value(&original.execution_owner_id)?;
                out.add_value(&original.capture_owner_id)?;
                out.add_value(&original.request_id)?;
                out.add_value(&original.operation_id)?;
                decimal(out, original.sequence)?;
                out.add_value(&original.method)?;
                out.add_value(&original.body)?;
                out.add_value(&original.extensions)
            }
            Self::Prospective(value) => {
                object(
                    out,
                    &[
                        "protocol",
                        "message",
                        "session_id",
                        "incarnation_id",
                        "node_id",
                        "execution_owner_id",
                        "capture_owner_id",
                        "request_id",
                        "operation_id",
                        "sequence",
                        "method",
                        "body",
                        "extensions",
                    ],
                )?;
                out.add_string("CNP/1")?;
                out.add_string("request")?;
                out.add_value(&value.scope.target.session)?;
                out.add_value(&value.scope.target.incarnation)?;
                out.add_value(&value.scope.target.node)?;
                out.add_value(&value.scope.target.owner)?;
                out.add_value(&Option::<()>::None)?;
                out.add_unescaped_ascii_extent("cnp-restored-current17-".len() + 20)?;
                out.add_value(&Option::<()>::None)?;
                decimal(out, value.frontier)?;
                out.add_string("observe")?;
                observe(out, value.observe)?;
                object(out, &[RESTORED_INPUT_REACTIVE17_FEATURE])?;
                value.artifact(out)
            }
        }
    }
}

pub(crate) fn model(
    out: &mut Projection,
    native_pid: U64,
    original: &Observation17OriginalData<'_>,
    inventory: &PacketConnectedInventory,
) -> Result<(), ProviderError> {
    model_header(out, native_pid, original)?;
    project_original_observation17_inventory_data(inventory, out)?;
    out.add_value(&Option::<()>::None)
}

pub(crate) fn model_header(
    out: &mut Projection,
    native_pid: U64,
    original: &Observation17OriginalData<'_>,
) -> Result<(), ProviderError> {
    object(
        out,
        &["schema", "native_pid", "original", "inventory", "grant"],
    )?;
    out.add_string("source-owned.packet-native/4")?;
    decimal(out, native_pid)?;
    original.project(out)
}

/// Projects the immutable current wrapper while replacing only its proof pair.
///
/// Callers lend the actual hash-verified current ContentStore bank after its
/// owning private cache/current-proof check. This walker supplies geometry only;
/// even an equal projection cannot authenticate that bank or grant an action.
pub(crate) fn restored_from_current_bytes(
    out: &mut Projection,
    input: &[u8],
    original: &Observation17OriginalData<'_>,
) -> Result<(), ProviderError> {
    use crate::protocol_snapshot::owned11::typed::{Fields, plain_string};

    let mut fields = Fields::object(input)?;
    out.add_object()?;
    let mut seen = 0u16;
    let mut previous: Option<&str> = None;
    while let Some((key, value)) = fields.pair()? {
        let key = plain_string(key)?;
        if previous.is_some_and(|previous| previous >= key) {
            return Err(exhausted());
        }
        previous = Some(key);
        let index = match key {
            "schema" => 0,
            "native_receipt" => 1,
            "captured_owner_state" => 2,
            "captured_journal" => 3,
            "mapping" => 4,
            "restore_commit" => 5,
            "restore_response" => 6,
            "context_digest" => 7,
            "physical_gate_held" if value == b"false" => 8,
            _ => return Err(exhausted()),
        };
        seen |= 1 << index;
        out.add_field(key)?;
        if key == "native_receipt" {
            receipt_from_current_bytes(out, value, original)?;
        } else {
            retained_json_value(out, value, 0)?;
        }
    }
    if seen != (1 << 9) - 1 {
        return Err(exhausted());
    }
    Ok(())
}

fn receipt_from_current_bytes(
    out: &mut Projection,
    input: &[u8],
    original: &Observation17OriginalData<'_>,
) -> Result<(), ProviderError> {
    use crate::protocol_snapshot::owned11::typed::{Fields, plain_string};

    let mut fields = Fields::object(input)?;
    out.add_object()?;
    let mut seen = 0u32;
    let mut previous: Option<&str> = None;
    while let Some((key, value)) = fields.pair()? {
        let key = plain_string(key)?;
        if previous.is_some_and(|previous| previous >= key) {
            return Err(exhausted());
        }
        previous = Some(key);
        let index = match key {
            "schema" => 0,
            "native_pid" => 1,
            "original" => 2,
            "binding_hash" => 3,
            "session" => 4,
            "incarnation" => 5,
            "node" => 6,
            "owner" => 7,
            "owner_generation" => 8,
            "input_epoch" => 9,
            "world" => 10,
            "native_record" => 11,
            "storage_selection" => 12,
            "capture_profile" => 13,
            "confirmation_selection" => 14,
            "ack_emitter_selection" => 15,
            "complete_restore_selection" => 16,
            "protocol_metadata_limits" => 17,
            "protocol_metadata_birth_facts" => 18,
            "restore_input_emitter_selection" => 19,
            _ => return Err(exhausted()),
        };
        seen |= 1 << index;
        out.add_field(key)?;
        match key {
            "original" => original.project(out)?,
            "native_record" => json_reference(out)?,
            _ => retained_json_value(out, value, 0)?,
        }
    }
    if seen & ((1 << 13) - 1) != (1 << 13) - 1 {
        return Err(exhausted());
    }
    Ok(())
}

// The retained bank is a defining producer's complete canonical JSON. Closed
// receipt metadata may also contain signed/floating JSON extension leaves. No
// custom U64/Bytes serializer, DOM decoder or formatter is invoked.
fn retained_json_value(
    out: &mut Projection,
    input: &[u8],
    depth: usize,
) -> Result<(), ProviderError> {
    use crate::protocol_snapshot::owned11::typed::Fields;

    if depth >= 64 {
        return Err(exhausted());
    }
    match input.first() {
        Some(b'{') => {
            out.add_object()?;
            let mut fields = Fields::object(input)?;
            while let Some((key, value)) = fields.pair()? {
                if let Ok(key) = crate::protocol_snapshot::owned11::typed::plain_string(key) {
                    out.add_field(key)?;
                } else {
                    let (decoded, _) = crate::protocol_snapshot::owned11::json_value::borrowed_json_string_storage_data(key)?;
                    // The owning private cache validates exact canonical fields.
                    // Escaped extension keys need their decoded String length;
                    // this extent conservatively preserves their sort backing.
                    out.add_field_extent(decoded)?;
                }
                retained_json_value(out, value, depth + 1)?;
            }
            Ok(())
        }
        Some(b'[') => {
            let count = {
                let mut fields = Fields::array(input)?;
                let mut count = 0usize;
                while fields.next()?.is_some() {
                    count = count.checked_add(1).ok_or_else(exhausted)?;
                }
                count
            };
            out.add_array_extent(count)?;
            let mut fields = Fields::array(input)?;
            while let Some(value) = fields.next()? {
                retained_json_value(out, value, depth + 1)?;
            }
            Ok(())
        }
        Some(b'"') => {
            let (decoded, encoded) =
                crate::protocol_snapshot::owned11::json_value::borrowed_json_string_storage_data(
                    input,
                )?;
            out.add_verified_json_string_extent_data(decoded, encoded)
        }
        Some(b't') if input == b"true" => out.add_value(&true),
        Some(b'f') if input == b"false" => out.add_value(&false),
        Some(b'n') if input == b"null" => out.add_value(&Option::<()>::None),
        Some(b'-' | b'0'..=b'9') => out.add_value(
            &crate::protocol_snapshot::owned11::json_value::borrowed_json_number_data(input)?,
        ),
        _ => Err(exhausted()),
    }
}

pub(crate) fn inventory_storage(
    inventory: &PacketConnectedInventory,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let mut out = Projection::new(maximum)?;
    project_original_observation17_inventory_data(inventory, &mut out)?;
    out.finish(maximum)
}

/// Names only the prospective request/context/artifact/original fixed visitors.
///
/// This excludes inventory and borrowed current-wrapper recursion, which are
/// independently named by the complete expected-output counter below.
pub(crate) fn prospective_counter_scratch_data() -> usize {
    size_of::<PacketRestoredObservation17ProspectiveData<'static>>()
        + size_of::<Observation17OriginalData<'static>>()
        + size_of::<Projection>()
        + size_of::<OriginalSerializationStorageData>()
        + size_of::<Result<OriginalSerializationStorageData, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<[&'static str; 14]>()
        + size_of::<[&'static str; 13]>()
        + size_of::<[&'static str; 10]>()
        + size_of::<[&'static str; 7]>()
        + size_of::<[&'static str; 5]>()
        + size_of::<[&'static str; 4]>()
        + size_of::<[&'static str; 3]>()
        + size_of::<[&'static str; 2]>()
        + size_of::<[&ContentRef; 6]>()
        + size_of::<std::array::IntoIter<&'static ContentRef, 6>>()
        + size_of::<std::slice::Iter<'static, &'static str>>()
        + size_of::<&PacketRestorationActivationScope>()
        + size_of::<&crate::reference_packet::service::complete_restore::activation::PacketRestorationActivationTarget>()
        + size_of::<&ObserveRequest>()
        + size_of::<&Envelope>()
        + size_of::<[usize; 4]>()
        + size_of::<U64>()
}

pub(crate) fn counter_scratch_data() -> usize {
    prospective_counter_scratch_data()
        + size_of::<PacketRestoredObservation17ProspectiveData<'static>>()
        + size_of::<Observation17OriginalData<'static>>()
        + size_of::<Projection>()
        + size_of::<OriginalSerializationStorageData>()
        + size_of::<Result<OriginalSerializationStorageData, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<[usize; 6]>()
        + 4 * size_of::<&ContentRef>()
        + size_of::<U64>()
        + size_of::<serde_json::Number>()
        + size_of::<Result<serde_json::Number, ProviderError>>()
        + observation17_inventory_counter_scratch_data()
        + crate::protocol_snapshot::owned11::json_value::borrowed_json_string_storage_counter_scratch_data()
        // The wrapper and receipt each retain their outer field cursor while
        // the bounded child walk runs. Fields::span's delimiter bank is named
        // independently of its enclosing immutable cursor headers.
        + 2 * (size_of::<crate::protocol_snapshot::owned11::typed::Fields<'static>>()
            + size_of::<[u8; 128]>()
            + size_of::<Option<&'static str>>()
            + size_of::<Option<(&'static [u8], &'static [u8])>>()
            + size_of::<[usize; 3]>()
            + size_of::<u32>())
        // Each bounded borrowed JSON recursion owns one Fields cursor after
        // the array counting cursor has left scope. No heap is used.
        + 64 * (size_of::<crate::protocol_snapshot::owned11::typed::Fields<'static>>()
            + size_of::<[u8; 128]>()
            + size_of::<Option<&'static str>>()
            + size_of::<Option<(&'static [u8], &'static [u8])>>()
            + size_of::<[usize; 3]>()
            + size_of::<u32>()
            + size_of::<U64>())
}

// crucible-lint: allow panic-shortcut -- verifies DATA geometry against defining requested layouts.
#[cfg(test)]
mod output_row_tests {
    use super::*;

    #[test]
    fn source_retained_row_funds_both_growable_canonical_banks() {
        let project = |text: &str| {
            let mut out = Projection::new(usize::MAX).unwrap();
            out.add_string(text).unwrap();
            out.finish(usize::MAX).unwrap()
        };
        let model = project("model owned bank");
        let restored = project("restored owned bank");
        let retained = model.retained_value_backing_bytes
            + restored.retained_value_backing_bytes
            + model.canonical_output_requested_bytes
            + restored.canonical_output_requested_bytes;
        let wire_only = model.retained_value_backing_bytes
            + restored.retained_value_backing_bytes
            + model.maximum_encoded_bytes
            + restored.maximum_encoded_bytes;
        let transient = model.requested_total().unwrap() + restored.requested_total().unwrap();
        let storage = PacketRestoredObservation17OutputStorageData { model, restored };
        let row = storage.expected_state_row_data().unwrap();

        assert_eq!(row.retained_requested_bytes.get(), retained as u64);
        assert!(retained > wire_only);
        assert_eq!(
            row.maximum_simultaneous_transient_bytes.get(),
            transient as u64
        );
        assert!(
            row.declared_counter_scratch_bytes.get()
                >= restored_observation17_output_counter_scratch_data() as u64
        );
    }
}
