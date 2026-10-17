//! Retains actual native consumption for independent installed source adoption.
//!
//! ```json
//! {"schema":"crucible.reference.consumption-relation.v1","input_batch":{},
//!  "native_receipt":{},"entries":[],"previous_closed":null}
//! ```
//!
//! The relation preserves original producer-local identifiers. It does not
//! convert quantized earlier inputs into the baseline same-time parent set.
//! Installed source adoption and coordinator event association remain separate.

use crucible_node_contract::{ContentRef, Endpoint, Id, InputBatch, U64, canonical};
use serde::Serialize;

use crate::ProviderError;

use super::{LineageStage, NativeConsumedBatch, protocol::MAX_FRAME_BYTES};

const RELATION_MEDIA: &str = "application/vnd.crucible.reference-consumption-relation+json";
const WIRE_MEDIA: &str = "application/vnd.crucible.reference-native-wire";
const MAX_RELATION_OBJECTS: usize = 72;
const MAX_RELATION_BYTES: usize = 600 * 1024;

/// Retains one complete original evidence body under its unchanged typed role.
pub struct ConsumptionEvidence {
    reference: ContentRef,
    bytes: Vec<u8>,
    dependencies: Vec<ContentRef>,
}

impl ConsumptionEvidence {
    /// Returns the complete typed identity of these original bytes.
    pub fn reference(&self) -> &ContentRef {
        &self.reference
    }

    /// Returns the explicit selected codec dependencies of this exact typed role.
    ///
    /// Parent proof bodies and preceding closures must still come from authentic
    /// source custody. Absence from the local inventory never makes them leaves.
    pub fn dependencies(&self) -> &[ContentRef] {
        &self.dependencies
    }

    /// Returns original bytes, including length prefixes for native wire roles.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Reserves complete relation geometry before the original native stage executes.
///
/// This reservation grants no execution or source authority. Its staged identity
/// prevents using another window's reservation for an actual consumed receipt.
pub struct ConsumptionRelationCredit {
    stage: ContentRef,
    objects: Vec<ConsumptionEvidence>,
    remaining_bytes: usize,
    maximum_objects: usize,
    entries: Vec<ConsumedEvent>,
}

impl ConsumptionRelationCredit {
    /// Reserves bounded slots for input, events, raw commands and native receipts.
    ///
    /// # Errors
    /// Refuses malformed stages, excessive entries, serialization limits, or
    /// unavailable allocation credit before any native effect is permitted.
    pub fn reserve(stage: &LineageStage, original_bytes: &[u8]) -> Result<Self, ProviderError> {
        Self::reserve_inner(stage, original_bytes, None)
    }

    /// Reserves exact original input copying for the separately selected reader.
    ///
    /// # Errors
    /// Refuses changed original selection/frame/scope or finite body/slot credit
    /// before native Stage or activation. Installation remains independently required.
    pub fn reserve_reader(
        stage: &LineageStage,
        original_bytes: &[u8],
        definition: &super::InputLineageDefinition,
    ) -> Result<Self, ProviderError> {
        Self::reserve_inner(stage, original_bytes, Some(definition))
    }

    fn reserve_inner(
        stage: &LineageStage,
        original_bytes: &[u8],
        input_reader: Option<&super::InputLineageDefinition>,
    ) -> Result<Self, ProviderError> {
        if original_bytes.is_empty() || original_bytes.len() > MAX_FRAME_BYTES {
            return Err(ProviderError::ResourceExhausted(
                "consumption original input frame",
            ));
        }
        let identity = stage.identity()?;
        stage.original_batch.verify(original_bytes)?;
        let value = canonical::parse_json(original_bytes, MAX_FRAME_BYTES)?;
        if canonical::canonical_json(&value)? != original_bytes {
            return Err(ProviderError::Correlation(
                "consumption input bytes changed",
            ));
        }
        let input: InputBatch = serde_json::from_value(value)
            .map_err(|_| ProviderError::Frame("consumption original input format"))?;
        super::association::validate_original_batch_selected(&input, stage, input_reader)?;
        let count = stage
            .entries
            .len()
            .checked_add(8)
            .ok_or(ProviderError::ResourceExhausted(
                "consumption relation object count",
            ))?;
        if count > MAX_RELATION_OBJECTS {
            return Err(ProviderError::ResourceExhausted(
                "consumption relation object credit",
            ));
        }
        let mut objects = Vec::new();
        objects.try_reserve_exact(count).map_err(|_| {
            ProviderError::ResourceExhausted("consumption relation slot allocation")
        })?;
        let mut credit = Self {
            stage: identity,
            objects,
            remaining_bytes: MAX_RELATION_BYTES,
            maximum_objects: count,
            entries: Vec::new(),
        };
        credit.retain(stage.original_batch.clone(), original_bytes)?;
        credit.retain(credit.stage.clone(), &canonical_bytes(stage)?)?;
        credit
            .entries
            .try_reserve_exact(input.events.len())
            .map_err(|_| {
                ProviderError::ResourceExhausted("consumption relation entry allocation")
            })?;
        for (index, (event, entry)) in input.events.iter().zip(&stage.entries).enumerate() {
            let original_event =
                credit.retain_bytes(&canonical_bytes(event)?, "application/json")?;
            credit.entries.push(ConsumedEvent {
                original_index: U64::new(index as u64),
                original_event,
                producer: event.source.clone(),
                event_id: event.id.clone(),
                native_sequence: event.source_sequence,
                byte_start: entry.byte_start,
                byte_end: entry.byte_end,
                checksum_after: U64::new(u64::MAX),
                zero_byte_consumed: entry.byte_start == entry.byte_end,
            });
        }
        credit.check_relation_envelope(stage)?;
        Ok(credit)
    }

    fn retain(&mut self, reference: ContentRef, bytes: &[u8]) -> Result<(), ProviderError> {
        reference.verify(bytes)?;
        if bytes.len() > MAX_FRAME_BYTES + 4
            || self.objects.len() >= self.maximum_objects
            || bytes.len() > self.remaining_bytes
        {
            return Err(ProviderError::ResourceExhausted(
                "consumption relation reserved body credit",
            ));
        }
        let mut retained = Vec::new();
        retained.try_reserve_exact(bytes.len()).map_err(|_| {
            ProviderError::ResourceExhausted("consumption relation body allocation")
        })?;
        retained.extend_from_slice(bytes);
        self.remaining_bytes -= bytes.len();
        self.objects.push(ConsumptionEvidence {
            reference,
            bytes: retained,
            dependencies: Vec::new(),
        });
        Ok(())
    }

    fn retain_bytes(&mut self, bytes: &[u8], media: &str) -> Result<ContentRef, ProviderError> {
        let reference = canonical::content_ref(bytes, media)?;
        self.retain(reference.clone(), bytes)?;
        Ok(reference)
    }

    fn check_relation_envelope(&mut self, stage: &LineageStage) -> Result<(), ProviderError> {
        // Every source-dependent field is already exact. Remaining native refs
        // use maximum decimal extent widths, and null ancestry is shorter than
        // the retained preceding receipt. No effect can outrun frame credit.
        let json = extent_placeholder("application/json")?;
        let wire = extent_placeholder(WIRE_MEDIA)?;
        let receipt = extent_placeholder(super::protocol::RECEIPT_MEDIA)?;
        let record = Relation {
            schema: "crucible.reference.consumption-relation.v1",
            owner: stage.grant.owner_id.clone(),
            incarnation: stage.grant.incarnation_id.clone(),
            owner_generation: stage.grant.generation,
            original_kernel_pid: U64::new(u64::MAX),
            original_kernel_start_ticks: U64::new(u64::MAX),
            native_window: stage.grant.window_id.clone(),
            input_batch: stage.original_batch.clone(),
            native_stage: self.stage.clone(),
            native_receipt: receipt.clone(),
            initialize_request: json.clone(),
            initialize_response_wire: wire.clone(),
            close_request: json,
            close_response_wire: wire,
            previous_closed: Some(receipt),
            preceding_publication_acknowledged: false,
            complete_consumed_prefix: U64::new(self.entries.len() as u64),
            measured_host_ns: U64::new(u64::MAX),
            entries: std::mem::take(&mut self.entries),
        };
        let checked = canonical_bytes(&record);
        self.entries = record.entries;
        checked?;
        Ok(())
    }
}

#[derive(Serialize)]
struct ConsumedEvent {
    original_index: U64,
    original_event: ContentRef,
    producer: Endpoint,
    event_id: Id,
    native_sequence: U64,
    byte_start: U64,
    byte_end: U64,
    checksum_after: U64,
    zero_byte_consumed: bool,
}

#[derive(Serialize)]
struct Relation {
    schema: &'static str,
    owner: Id,
    incarnation: Id,
    owner_generation: U64,
    original_kernel_pid: U64,
    original_kernel_start_ticks: U64,
    native_window: Id,
    input_batch: ContentRef,
    native_stage: ContentRef,
    native_receipt: ContentRef,
    initialize_request: ContentRef,
    initialize_response_wire: ContentRef,
    close_request: ContentRef,
    close_response_wire: ContentRef,
    previous_closed: Option<ContentRef>,
    preceding_publication_acknowledged: bool,
    complete_consumed_prefix: U64,
    measured_host_ns: U64,
    entries: Vec<ConsumedEvent>,
}

/// Owns actual native evidence pending independent installed source adoption.
///
/// Only a borrowed owning-driver consumption view can create this object. The
/// source provider must still authenticate its actual accepted public input and
/// installed implementation. This object grants no common-runtime publication,
/// parent identity, readiness, preservation, or replay capability.
pub struct NativeConsumptionRelation {
    relation: ContentRef,
    objects: Vec<ConsumptionEvidence>,
}

impl NativeConsumptionRelation {
    /// Copies exact original evidence without acknowledging native publication.
    ///
    /// Credit must have been reserved before native execution. A copy refusal
    /// leaves the borrowed driver's original Close, output and ACK custody
    /// unchanged; the source must retain that driver until disposition succeeds.
    ///
    /// # Errors
    /// Refuses another stage's reservation, incomplete native evidence,
    /// unavailable original physical measurement, or exceeded body/allocation
    /// credit. Failed copying does not authorize retrying native execution.
    pub fn collect(
        native: &NativeConsumedBatch<'_>,
        mut credit: ConsumptionRelationCredit,
    ) -> Result<Self, ProviderError> {
        let stage = native.window().stage();
        if credit.stage != stage.identity()? {
            return Err(ProviderError::Correlation(
                "consumption relation reservation names another native stage",
            ));
        }
        let native_bytes = canonical_bytes(native.receipt())?;
        let native_receipt = native.receipt().identity()?;
        credit.retain(native_receipt.clone(), &native_bytes)?;

        let origin = native.origin();
        let initialize_request =
            credit.retain_bytes(origin.initialization().request_bytes(), "application/json")?;
        let initialize_response_wire =
            credit.retain_bytes(origin.initialization().response_wire_bytes(), WIRE_MEDIA)?;
        let close_request =
            credit.retain_bytes(native.close_command().request_bytes(), "application/json")?;
        let close_response_wire =
            credit.retain_bytes(native.close_command().response_wire_bytes(), WIRE_MEDIA)?;

        for (entry, consumed) in credit.entries.iter_mut().zip(&native.receipt().consumed) {
            entry.checksum_after = consumed.checksum_after;
        }
        if credit.entries.len() != native.receipt().consumed.len() {
            return Err(ProviderError::Correlation(
                "native consumed prefix is incomplete",
            ));
        }
        let record = Relation {
            schema: "crucible.reference.consumption-relation.v1",
            owner: origin.owner().clone(),
            incarnation: origin.incarnation().clone(),
            owner_generation: origin.generation(),
            original_kernel_pid: U64::new(u64::from(origin.child_pid())),
            original_kernel_start_ticks: origin.start_ticks(),
            native_window: native.receipt().grant.window_id.clone(),
            input_batch: native.original_batch_ref().clone(),
            native_stage: credit.stage.clone(),
            native_receipt,
            initialize_request,
            initialize_response_wire,
            close_request,
            close_response_wire,
            previous_closed: native.receipt().previous_closed.clone(),
            preceding_publication_acknowledged: native
                .predecessor()
                .is_some_and(|p| p.acknowledged()),
            complete_consumed_prefix: native.complete_prefix(),
            measured_host_ns: native.window().measured_host_ns().ok_or(
                ProviderError::Correlation("original native physical measurement missing"),
            )?,
            entries: std::mem::take(&mut credit.entries),
        };
        let bytes = canonical_bytes(&record)?;
        let relation = credit.retain_bytes(&bytes, RELATION_MEDIA)?;
        // These rows come from the actual selected native and original input
        // codecs, not a scan of arbitrary payload bytes or hash-only aliases.
        let mut input_dependencies: Vec<_> = record
            .entries
            .iter()
            .map(|entry| entry.original_event.clone())
            .collect();
        if let Some(manifest) = native.input_manifest()? {
            input_dependencies.push(manifest);
        }
        let stage_dependencies = std::iter::once(record.input_batch.clone())
            .chain(stage.entries.iter().map(|entry| entry.payload.clone()))
            .collect();
        let native_dependencies = std::iter::once(record.native_stage.clone())
            .chain(record.previous_closed.iter().cloned())
            .collect();
        let relation_dependencies = credit
            .objects
            .iter()
            .filter(|object| object.reference != relation)
            .map(|object| object.reference.clone())
            .chain(record.previous_closed.iter().cloned())
            .collect();
        set_dependencies(&mut credit.objects, &record.input_batch, input_dependencies)?;
        set_dependencies(
            &mut credit.objects,
            &record.native_stage,
            stage_dependencies,
        )?;
        set_dependencies(
            &mut credit.objects,
            &record.native_receipt,
            native_dependencies,
        )?;
        set_dependencies(
            &mut credit.objects,
            &record.close_response_wire,
            vec![record.native_receipt.clone()],
        )?;
        for (entry, event) in record.entries.iter().zip(&native.original().events) {
            set_dependencies(
                &mut credit.objects,
                &entry.original_event,
                vec![event.payload.clone(), event.provenance_ref.clone()],
            )?;
        }
        set_dependencies(&mut credit.objects, &relation, relation_dependencies)?;
        Ok(Self {
            relation,
            objects: credit.objects,
        })
    }

    /// Returns the separate typed relation root, without changing original events.
    pub fn reference(&self) -> &ContentRef {
        &self.relation
    }

    /// Returns retained original objects for an installed codec's exact lookup.
    ///
    /// Parent payload/provenance and preceding receipt closures remain separate
    /// source obligations; this inventory does not claim their availability.
    pub fn evidence(&self) -> &[ConsumptionEvidence] {
        &self.objects
    }
}

fn set_dependencies(
    objects: &mut [ConsumptionEvidence],
    reference: &ContentRef,
    dependencies: Vec<ContentRef>,
) -> Result<(), ProviderError> {
    let object = objects
        .iter_mut()
        .find(|object| &object.reference == reference)
        .ok_or(ProviderError::Correlation(
            "native relation role has no original body",
        ))?;
    if dependencies.len() > MAX_RELATION_OBJECTS {
        return Err(ProviderError::ResourceExhausted(
            "native relation dependency row",
        ));
    }
    object.dependencies = dependencies;
    Ok(())
}

fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>, ProviderError> {
    let value = serde_json::to_value(value).map_err(crucible_node_contract::ContractError::from)?;
    let bytes = canonical::canonical_json(&value)?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProviderError::ResourceExhausted(
            "consumption relation frame",
        ));
    }
    Ok(bytes)
}

fn extent_placeholder(media: &str) -> Result<ContentRef, ProviderError> {
    let mut reference = canonical::content_ref(&[], media)?;
    reference.length = U64::new(u64::MAX);
    Ok(reference)
}
