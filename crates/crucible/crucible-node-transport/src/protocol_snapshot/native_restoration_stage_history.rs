//! Preserves exact activation/upload/first-Observe owners without live rights.
//!
//! The separate native class17 reader must join this component to the complete
//! boot/Commit/mapping/connection/Control history and authenticated parent DAG.
//! Component validation alone grants no Capture or restoration permission.

use crate::ProviderError;
use crate::bodies::ObserveRequest;
use crate::envelope::{Envelope, Method};
use crate::protocol_snapshot::compact_bytes::ValidatedCompactBytes;
use crate::reference_packet::service::complete_restore::activation::{
    PacketRestorationActivationArtifact, PacketRestorationActivationContext,
    PacketRestorationActivationPhase,
    upload::{PacketRestorationActivationUploadArtifact, PacketRestorationActivationUploadContext},
};
use crate::reference_packet::service::complete_restore::restoration_observe::{
    PacketRestorationObservationArtifact, PacketRestorationObservationContext,
};
use crate::retained_metadata::{
    records::ValidatedMetadataRecords,
    serialization_storage::original_json_value_storage_extent_data,
};
use crucible_node_format::{ActivationManifest, Id};
use serde::Deserialize;
use serde_json::Value;

/// Names only the complete restoration-stage component, never a whole native class.
pub const NATIVE_RESTORATION_STAGES_SCHEMA: &str = "source-private.native-restoration-stages/1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Activation {
    schema: String,
    creator: u32,
    thread: String,
    phase: PacketRestorationActivationPhase,
    original: Option<Envelope>,
    incoming_slot: Option<usize>,
    artifact: Option<PacketRestorationActivationArtifact>,
    context: Option<PacketRestorationActivationContext>,
    coordinator: Option<Value>,
    manifest: Option<ActivationManifest>,
    terminal: Option<Envelope>,
    verified: bool,
    dispatched: bool,
    published: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Upload {
    schema: String,
    creator: u32,
    thread: String,
    ordinal: usize,
    original: Option<Envelope>,
    artifact: Option<PacketRestorationActivationUploadArtifact>,
    context: Option<PacketRestorationActivationUploadContext>,
    pending: Option<Envelope>,
    terminal: Option<Envelope>,
    seen: Vec<Id>,
    seen_capacity: usize,
    bytes: Value,
    bytes_capacity: usize,
    content_attempted: bool,
    next_offset: usize,
    published_requests: usize,
    verified: bool,
    begun: bool,
    complete: bool,
    next_progress: Option<(usize, bool)>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FirstObservation {
    schema: String,
    creator: u32,
    thread: String,
    original: Option<Envelope>,
    body: Option<ObserveRequest>,
    artifact: Option<PacketRestorationObservationArtifact>,
    context: Option<PacketRestorationObservationContext>,
    terminal: Option<Envelope>,
    received: bool,
    verified: bool,
    dispatched: bool,
    published: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stages {
    aliases: Vec<(String, usize)>,
    alias_allocation: AliasAllocation,
    schema: String,
    activation: [Option<Activation>; 2],
    uploads: [Option<Upload>; 2],
    first_observation: Option<FirstObservation>,
    capacities: Vec<(String, usize, usize, usize)>,
    capacity_rows: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AliasAllocation {
    maximum_rows: usize,
    row_capacity: usize,
    lookup_capacity: usize,
    retained_rows: usize,
    row_bytes: usize,
    lookup_bytes: usize,
}

/// Names independent owning phases, without serving as allocation authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeRestorationStagesConstructionData {
    retained: usize,
    transient: usize,
    scratch: usize,
    total: usize,
}

impl NativeRestorationStagesConstructionData {
    /// Returns every new raw/DOM/typed retained owner.
    pub const fn retained_requested_bytes_data(&self) -> usize {
        self.retained
    }

    /// Returns full simultaneous decoding and correspondence work.
    pub const fn maximum_simultaneous_transient_bytes_data(&self) -> usize {
        self.transient
    }

    /// Returns exact declared fixed parser/result headers.
    pub const fn counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }

    /// Returns the checked whole construction demand.
    pub const fn requested_bytes_data(&self) -> usize {
        self.total
    }
}

/// Retains literal bytes and every constructed partial before later checks.
pub struct HistoricalNativeRestorationStages {
    original: Vec<u8>,
    parsed: Option<Value>,
    data: Option<Stages>,
}

/// Borrows the exact new family and bounds complete owning work before decode.
pub struct NativeRestorationStagesDecodePlan<'a> {
    input: &'a [u8],
    maximum: usize,
    demand: NativeRestorationStagesConstructionData,
}

impl<'a> NativeRestorationStagesDecodePlan<'a> {
    /// Checks the closed component roster and all prospective decode phases.
    ///
    /// # Errors
    /// Refuses another family, unknown/missing fields, excessive raw extent or overflow.
    pub fn validate(
        input: &'a [u8],
        maximum_input: usize,
        maximum_requested: usize,
    ) -> Result<Self, ProviderError> {
        if input.is_empty() || input.len() > maximum_input {
            return Err(invalid());
        }
        let mut fields = super::owned11::OriginalOwned11Fields::object(input)?;
        for key in [
            "activation",
            "alias_allocation",
            "aliases",
            "capacities",
            "capacity_rows",
            "first_observation",
            "schema",
            "uploads",
        ] {
            let value = fields.named(key)?;
            if key == "schema"
                && super::owned11::original_owned11_plain_string(value)?
                    != NATIVE_RESTORATION_STAGES_SCHEMA
            {
                return Err(invalid());
            }
        }
        fields.finish()?;
        let extent = original_json_value_storage_extent_data(input.len())?;
        // Lexical occurrences bound malformed repeated DTO/ID children using
        // their defining layouts. Raw bytes never stand in for typed heap.
        let typed = extent
            .maximum_value_nodes
            .checked_mul(
                std::mem::size_of::<Activation>()
                    .checked_add(std::mem::size_of::<Upload>())
                    .and_then(|n| n.checked_add(std::mem::size_of::<FirstObservation>()))
                    .and_then(|n| {
                        n.checked_add(std::mem::size_of::<
                            super::owned11::aliases::HistoricalAliasSummary,
                        >())
                    })
                    .ok_or_else(invalid)?,
            )
            .ok_or_else(invalid)?;
        let retained = input
            .len()
            .checked_add(
                extent
                    .value_dom_requested_bytes
                    .checked_mul(3)
                    .ok_or_else(invalid)?,
            )
            .and_then(|n| n.checked_add(typed))
            .ok_or_else(invalid)?;
        let transient = extent
            .canonical_pass_requested_bytes()?
            .checked_mul(4)
            .and_then(|n| n.checked_add(typed))
            .ok_or_else(invalid)?;
        let scratch = native_restoration_stages_counter_scratch_data();
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
            demand: NativeRestorationStagesConstructionData {
                retained,
                transient,
                scratch,
                total,
            },
        })
    }

    /// Returns this exact raw component's independent decode demand.
    pub const fn demand_data(&self) -> &NativeRestorationStagesConstructionData {
        &self.demand
    }

    /// Retains raw and parsed owners before typed decode or final correspondence.
    ///
    /// The genuine caller separately admits the whole row. This returns only
    /// historical DATA and cannot manufacture an actor, Scope or Capture seal.
    ///
    /// # Errors
    /// Refuses a reused output, short/different row, malformed children, duplicate
    /// keys, wrong phases, contradictory flags or incomplete published originals.
    pub fn reconstruct_into(
        &self,
        admitted: &NativeRestorationStagesConstructionData,
        output: &mut Option<HistoricalNativeRestorationStages>,
    ) -> Result<(), ProviderError> {
        if admitted != &self.demand || output.is_some() {
            return Err(invalid());
        }
        *output = Some(HistoricalNativeRestorationStages {
            original: Vec::new(),
            parsed: None,
            data: None,
        });
        let owner = output.as_mut().ok_or_else(invalid)?;
        owner
            .original
            .try_reserve_exact(self.input.len())
            .map_err(|_| invalid())?;
        owner.original.extend_from_slice(self.input);
        owner.parsed = Some(crucible_node_format::canonical::parse_json(
            self.input,
            self.maximum,
        )?);
        owner.data = Some(
            serde_json::from_value(owner.parsed.as_ref().ok_or_else(invalid)?.clone())
                .map_err(crucible_node_format::ContractError::from)?,
        );
        owner.authenticate_data()
    }
}

impl HistoricalNativeRestorationStages {
    /// Borrows every exact original byte, including rejected historical content.
    pub fn original_bytes_data(&self) -> &[u8] {
        &self.original
    }

    /// Checks only historical component correspondence; it supplies no native right.
    ///
    /// # Errors
    /// Refuses partial decode, invalid role/capacity/phase relationships or changed literals.
    pub fn authenticate_data(&self) -> Result<(), ProviderError> {
        let data = self.data.as_ref().ok_or_else(invalid)?;
        if data.schema != NATIVE_RESTORATION_STAGES_SCHEMA
            || data.capacity_rows != data.capacities.len()
        {
            return Err(invalid());
        }
        authenticate_stage_aliases(data)?;
        let capacities = canonical_value(&data.capacities)?;
        ValidatedMetadataRecords::validate(&capacities, data.capacity_rows, usize::MAX)?;
        for (index, activation) in data.activation.iter().enumerate() {
            let Some(stage) = activation else {
                continue;
            };
            origin(stage.creator, &stage.thread)?;
            if stage.schema != "source-private.native-restoration-activation-history/1"
                || stage.phase
                    != if index == 0 {
                        PacketRestorationActivationPhase::Arm
                    } else {
                        PacketRestorationActivationPhase::WorldActivate
                    }
                || stage.published
                    && (!stage.verified
                        || !stage.dispatched
                        || stage.artifact.is_none()
                        || stage.context.is_none())
                || stage.dispatched && !stage.verified
            {
                return Err(invalid());
            }
            pair(
                &stage.original,
                &stage.terminal,
                stage.published,
                stage.phase.method(),
            )?;
            // All unfinished fields remain data. The complete class17 reader
            // additionally authenticates Commit/World/MAC/literal edges.
            let _ = (&stage.incoming_slot, &stage.coordinator, &stage.manifest);
        }
        for (index, upload) in data.uploads.iter().enumerate() {
            let Some(stage) = upload else {
                continue;
            };
            origin(stage.creator, &stage.thread)?;
            if stage.schema != "source-private.native-restoration-upload-history/1"
                || stage.ordinal != index
                || stage.seen.len() > stage.seen_capacity
                || stage.seen.len() > 4096
                || stage.published_requests > stage.seen.len()
                || stage.complete
                    && (!stage.verified
                        || !stage.begun
                        || stage.content_attempted
                        || stage.pending.is_some()
                        || stage.next_progress.is_some())
                || stage.begun && !stage.verified
            {
                return Err(invalid());
            }
            let bytes = canonical_value(&stage.bytes)?;
            let bank = ValidatedCompactBytes::validate(&bytes, bytes.len(), stage.bytes_capacity)?;
            if stage.next_offset > bank.decoded_length() {
                return Err(invalid());
            }
            for (slot, request) in stage.seen.iter().enumerate() {
                if stage.seen[..slot].contains(request) {
                    return Err(invalid());
                }
            }
            if let Some(original) = &stage.original
                && original.method != Method::BlobBegin
            {
                return Err(invalid());
            }
            if stage.complete
                && (stage.artifact.is_none() || stage.context.is_none() || stage.terminal.is_none())
            {
                return Err(invalid());
            }
            let _ = (&stage.pending, &stage.next_progress);
        }
        if let Some(stage) = &data.first_observation {
            origin(stage.creator, &stage.thread)?;
            if stage.schema != "source-private.native-restoration-observation-history/1"
                || stage.published
                    && (!stage.received
                        || !stage.verified
                        || !stage.dispatched
                        || stage.artifact.is_none()
                        || stage.context.is_none())
                || stage.dispatched && !stage.verified
                || stage.verified && !stage.received
            {
                return Err(invalid());
            }
            pair(
                &stage.original,
                &stage.terminal,
                stage.published,
                Method::Observe,
            )?;
            if let (Some(original), Some(body)) = (&stage.original, &stage.body)
                && serde_json::to_value(body).map_err(crucible_node_format::ContractError::from)?
                    != Value::Object(original.body.clone())
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

struct StageAliasCursor<'a> {
    aliases: &'a [(String, usize)],
    index: usize,
}

impl StageAliasCursor<'_> {
    fn next(&mut self, present: bool, kind: &str) -> Result<(), ProviderError> {
        if present {
            let (actual, group) = self.aliases.get(self.index).ok_or_else(invalid)?;
            if actual != kind || *group != self.index {
                return Err(invalid());
            }
            self.index = self.index.checked_add(1).ok_or_else(invalid)?;
        }
        Ok(())
    }
}

fn authenticate_stage_aliases(data: &Stages) -> Result<(), ProviderError> {
    let facts = &data.alias_allocation;
    if facts.maximum_rows == 0
        || facts.maximum_rows > 131_072
        || facts.retained_rows != data.aliases.len()
        || facts.retained_rows > facts.maximum_rows
        || facts.retained_rows > facts.row_capacity
        || facts.retained_rows > facts.lookup_capacity
        || facts.row_bytes.checked_add(facts.lookup_bytes).is_none()
    {
        return Err(invalid());
    }
    let mut cursor = StageAliasCursor {
        aliases: &data.aliases,
        index: 0,
    };
    // Distinct signed phases/ordinals imply distinct live attempt allocations;
    // their actual recorder emits exactly one edge per present root in this order.
    for stage in &data.activation {
        cursor.next(stage.is_some(), "native-restoration-activation-attempt")?;
    }
    for stage in &data.uploads {
        cursor.next(stage.is_some(), "native-restoration-upload-attempt")?;
    }
    cursor.next(
        data.first_observation.is_some(),
        "native-restoration-observation-attempt",
    )?;
    if cursor.index != data.aliases.len() {
        return Err(invalid());
    }
    Ok(())
}

fn origin(creator: u32, thread: &str) -> Result<(), ProviderError> {
    if creator == 0 || thread != "same-original-thread-history-only" {
        return Err(invalid());
    }
    Ok(())
}

fn pair(
    original: &Option<Envelope>,
    terminal: &Option<Envelope>,
    published: bool,
    method: Method,
) -> Result<(), ProviderError> {
    if let Some(original) = original
        && original.method != method
    {
        return Err(invalid());
    }
    if published {
        original
            .as_ref()
            .ok_or_else(invalid)?
            .matches_response(terminal.as_ref().ok_or_else(invalid)?)?;
    }
    Ok(())
}

fn canonical_value(value: &impl serde::Serialize) -> Result<Vec<u8>, ProviderError> {
    let value = serde_json::to_value(value).map_err(crucible_node_format::ContractError::from)?;
    Ok(crucible_node_format::canonical::canonical_json(&value)?)
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("native restoration-stage historical codec differs")
}

/// Names exact new reader and typed-partial/result/cursor headers.
pub fn native_restoration_stages_counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<StageAliasCursor<'static>>()
        + size_of::<Option<&'static (String, usize)>>()
        + size_of::<Result<&'static (String, usize), ProviderError>>()
        + size_of::<Activation>()
        + size_of::<Upload>()
        + size_of::<FirstObservation>()
        + size_of::<Stages>()
        + size_of::<Result<Stages, serde_json::Error>>()
        + size_of::<HistoricalNativeRestorationStages>()
        + size_of::<Option<HistoricalNativeRestorationStages>>()
        + size_of::<NativeRestorationStagesDecodePlan<'static>>()
        + size_of::<Result<NativeRestorationStagesDecodePlan<'static>, ProviderError>>()
        + size_of::<NativeRestorationStagesConstructionData>()
        + size_of::<Value>() * 3
        + size_of::<Result<Value, serde_json::Error>>()
        + size_of::<Result<Value, crucible_node_format::ContractError>>()
        + size_of::<Result<Vec<u8>, ProviderError>>()
        + size_of::<Result<Vec<u8>, crucible_node_format::ContractError>>()
        + size_of::<ValidatedCompactBytes<'static>>()
        + size_of::<Result<ValidatedCompactBytes<'static>, ProviderError>>()
        + size_of::<ValidatedMetadataRecords<'static>>()
        + size_of::<Result<ValidatedMetadataRecords<'static>, ProviderError>>()
        + size_of::<std::slice::Iter<'static, Option<Activation>>>()
        + size_of::<std::slice::Iter<'static, Option<Upload>>>()
        + size_of::<std::slice::Iter<'static, Id>>()
        + size_of::<AliasAllocation>()
        + size_of::<Vec<super::owned11::aliases::HistoricalAliasSummary>>()
        + size_of::<super::owned11::aliases::ValidatedHistoricalAliases<'static, 'static>>()
        + size_of::<
            Result<
                super::owned11::aliases::ValidatedHistoricalAliases<'static, 'static>,
                ProviderError,
            >,
        >()
        + size_of::<Result<(), ProviderError>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_history() -> Value {
        serde_json::json!({
            "schema": NATIVE_RESTORATION_STAGES_SCHEMA,
            "activation": [null, null], "uploads": [null, null],
            "first_observation": null, "capacities": [], "capacity_rows": 0,
            "aliases": [], "alias_allocation": {
                "maximum_rows": 1, "row_capacity": 0, "lookup_capacity": 0,
                "retained_rows": 0, "row_bytes": 0, "lookup_bytes": 0
            }
        })
    }

    #[test]
    fn historical_stage_reader_keeps_partial_raw_and_refuses_unknown_or_alias_growth() {
        let mut value = empty_history();
        value["unexpected"] = Value::Null;
        let bytes = canonical_value(&value).unwrap();
        assert!(
            NativeRestorationStagesDecodePlan::validate(&bytes, bytes.len(), usize::MAX).is_err()
        );

        value.as_object_mut().unwrap().remove("unexpected");
        value["aliases"] = serde_json::json!([["native-restoration-upload-attempt", 0]]);
        let bytes = canonical_value(&value).unwrap();
        let plan =
            NativeRestorationStagesDecodePlan::validate(&bytes, bytes.len(), usize::MAX).unwrap();
        let mut partial = None;
        assert!(
            plan.reconstruct_into(plan.demand_data(), &mut partial)
                .is_err()
        );
        assert_eq!(partial.as_ref().unwrap().original_bytes_data(), bytes);
        assert!(partial.as_ref().unwrap().authenticate_data().is_err());
        assert!(
            plan.reconstruct_into(plan.demand_data(), &mut partial)
                .is_err()
        );
    }

    #[test]
    fn historical_stage_reader_requires_complete_correspondence_before_publication() {
        let mut value = empty_history();
        value["first_observation"] = serde_json::json!({
            "schema": "source-private.native-restoration-observation-history/1",
            "creator": 1, "thread": "same-original-thread-history-only",
            "original": null, "body": null, "artifact": null, "context": null,
            "terminal": null, "received": false, "verified": false,
            "dispatched": false, "published": false
        });
        value["aliases"] = serde_json::json!([["native-restoration-observation-attempt", 0]]);
        value["alias_allocation"]["retained_rows"] = serde_json::json!(1);
        value["alias_allocation"]["row_capacity"] = serde_json::json!(1);
        value["alias_allocation"]["lookup_capacity"] = serde_json::json!(1);
        let bytes = canonical_value(&value).unwrap();
        let plan =
            NativeRestorationStagesDecodePlan::validate(&bytes, bytes.len(), usize::MAX).unwrap();
        let mut owner = None;
        plan.reconstruct_into(plan.demand_data(), &mut owner)
            .unwrap();
        owner.as_ref().unwrap().authenticate_data().unwrap();

        value["first_observation"]["published"] = Value::Bool(true);
        let bytes = canonical_value(&value).unwrap();
        let plan =
            NativeRestorationStagesDecodePlan::validate(&bytes, bytes.len(), usize::MAX).unwrap();
        let mut refused = None;
        assert!(
            plan.reconstruct_into(plan.demand_data(), &mut refused)
                .is_err()
        );
        assert!(refused.is_some());
    }
}
