//! Owns original stopped producer receipts for the selected RateClock/Script pair.
//!
//! The native edition preserves complete receipt associations. Readers borrow
//! only previously retained bodies under the current opaque world authority;
//! they never reconstruct historical children from a later native state.
//!
//! ```text
//! Host native envelope 8 adds a required producer_observations array.
//! Each row stores objects in the exact order [root, native model, causal child].
//! Each object retains its complete ContentRef and original numeric byte array.
//! Missing, null, duplicate, oversized or unrelated associations are refused.
//! ```

use super::*;
use crate::node_scheduling::{InputPayload, RuntimeInputBatch};
use crucible_node_contract::{Extensions, SchemaRef, U64};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub(super) const MAXIMUM_OBSERVATIONS: usize = 64;
pub(super) const MAXIMUM_RECEIPT_BYTES: usize = 128 * 1024;

/// Defines the separate complete producer-evidence continuation policy.
pub const RATE_ALARM_PRODUCER_SPECIFICATION: &str = "host rate/alarm producer native envelope8 v2: fixed RateClock and finite kind4 Script pair; original Runtime1/coordinator1 only; complete exact stopped root/native/causes associations retained before producer observation; original operations and input/output/ACK bodies preserved; maximum64 observation associations,64 original operation records,64 input staging records and64 total original input deliveries;128KiB per three-role receipt; authentic fresh activation required for every reader; no original-lineage Runtime7, selected extensions, CPU, wall clock or guest IRQ authority";

/// Returns the selected original producer-evidence native schema.
///
/// # Errors
/// Refuses invalid authored schema identifiers or content identities.
pub fn host_rate_alarm_producer_schema() -> Result<SchemaRef, OperationFailure> {
    Ok(SchemaRef {
        id: Id::new("host/rate-alarm-producer-native-v2")
            .map_err(|error| failure(&error.to_string()))?,
        version: 2,
        definition: canonical::content_ref(
            RATE_ALARM_PRODUCER_SPECIFICATION.as_bytes(),
            "text/plain",
        )
        .map_err(|error| failure(&error.to_string()))?,
        extensions: Extensions::new(),
    })
}

pub(super) fn selected(binding: &NodeBinding) -> bool {
    host_rate_alarm_producer_schema().is_ok_and(|schema| {
        binding
            .compatibility
            .implementation
            .formats
            .contains(&schema)
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema_version: u16,
    profile: String,
    node: Id,
    owners: Vec<OwnerIdentity>,
    boundary: Position,
    native: ContentRef,
    native_sequence: U64,
    #[serde(deserialize_with = "required_input")]
    input: Option<(Id, ContentRef, U64)>,
    pending_causes: ContentRef,
}

// The key is mandatory even when no input delivery caused this receipt.
fn required_input<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<(Id, ContentRef, U64)>, D::Error> {
    Option::deserialize(deserializer)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Causes {
    schema: String,
    causes: Vec<Cause>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cause {
    time_ps: U64,
    source: u32,
    sequence: u32,
    parents: Vec<Position>,
}

/// Stores three original declared roles without a recursive prior capture.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OriginalReceipt {
    pub(super) objects: [InputPayload; 3],
}

/// Decodes the required selected roster without constructing excess rows.
///
/// # Errors
/// Refuses null or invalid rows, unavailable allocation or more than 64 rows.
pub(super) fn present_originals<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<OriginalReceipt>>, D::Error> {
    struct OriginalObservations;

    impl<'de> serde::de::Visitor<'de> for OriginalObservations {
        type Value = Vec<OriginalReceipt>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("at most 64 original producer receipt associations")
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> Result<Self::Value, A::Error> {
            let mut originals = Vec::new();
            for _ in 0..MAXIMUM_OBSERVATIONS {
                let Some(original) = sequence.next_element::<OriginalReceipt>()? else {
                    return Ok(originals);
                };
                originals.try_reserve(1).map_err(|_| {
                    serde::de::Error::custom("producer association reservation unavailable")
                })?;
                originals.push(original);
            }
            // Probe excess rows without constructing their typed payload arrays.
            if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom(
                    "producer association count exceeds selected credit",
                ));
            }
            Ok(originals)
        }
    }

    deserializer.deserialize_seq(OriginalObservations).map(Some)
}

impl OriginalReceipt {
    fn size(&self) -> Result<usize, OperationFailure> {
        self.objects.iter().try_fold(0usize, |size, object| {
            size.checked_add(object.bytes.len())
                .ok_or_else(|| failure("clock producer receipt geometry overflowed"))
        })
    }

    fn checked(&self, node: &Id) -> Result<Receipt, OperationFailure> {
        if self.size()? > MAXIMUM_RECEIPT_BYTES {
            return Err(failure(
                "clock producer receipt exceeds complete role credit",
            ));
        }
        for (object, media) in self.objects.iter().zip([
            "application/octet-stream",
            "application/octet-stream",
            "application/json",
        ]) {
            if object.reference.media_type != media
                || canonical::content_ref(&object.bytes, media)
                    .map_err(|error| failure(&error.to_string()))?
                    != object.reference
            {
                return Err(failure("clock producer original full content role differs"));
            }
        }
        let root: Receipt = serde_json::from_slice(&self.objects[0].bytes)
            .map_err(|error| failure(&error.to_string()))?;
        if root.schema_version != 1
            || root.profile != HOST_EXACT_PROFILE
            || &root.node != node
            || root.owners.len() != 1
            || root.native != self.objects[1].reference
            || root.pending_causes != self.objects[2].reference
        {
            return Err(failure(
                "clock producer original declared receipt roles differ",
            ));
        }
        let causes: Causes = serde_json::from_slice(&self.objects[2].bytes)
            .map_err(|error| failure(&error.to_string()))?;
        if causes.schema != "crucible.host-pending-causes.v1" || causes.causes.len() > 64 {
            return Err(failure("clock producer causal child codec differs"));
        }
        let mut pending = BTreeMap::new();
        for cause in causes.causes {
            if cause.parents.len() != 1
                || pending
                    .insert(
                        (cause.time_ps.get(), cause.source, cause.sequence),
                        cause.parents,
                    )
                    .is_some()
            {
                return Err(failure("clock producer original causal rows differ"));
            }
        }
        let native = &self.objects[1].bytes;
        if let Some(rest) = native.strip_prefix(b"crucible.scripted-cursor.v1\0") {
            let length = rest
                .get(..8)
                .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
                .map(u64::from_le_bytes)
                .and_then(|length| usize::try_from(length).ok())
                .ok_or_else(|| failure("clock producer original script geometry differs"))?;
            let script = rest
                .get(8..)
                .and_then(|bytes| bytes.get(..length))
                .ok_or_else(|| failure("clock producer original script truncated"))?;
            let source = super::super::ScriptedSource::from_continuation(script, native)?;
            if source.kind() != super::super::ScriptedRequestKind::RateAlarmClock
                || source.time_ps() != root.boundary.time_ps.get()
                || source.cursor() as u64 != root.native_sequence.get()
                || !pending.is_empty()
                || root.input.is_some()
            {
                return Err(failure("clock producer original script receipt differs"));
            }
        } else {
            let clock = super::super::rate_alarm_clock::RateAlarmClock::validate_native(native)?;
            if clock.position() != root.boundary
                || clock.issued().len() as u64 != root.native_sequence.get()
            {
                return Err(failure("clock producer original clock receipt differs"));
            }
            clock.validate_pending_causes(&pending)?;
        }
        // Reading the complete typed header also retains its original counters,
        // input commitment and boundary. These fields are data, never permission.
        let _ = (&root.native_sequence, &root.input);
        Ok(root)
    }
}

pub(super) fn validate_originals(
    originals: &[OriginalReceipt],
    source: &RuntimeSnapshot,
    node: &Id,
    binding: &NodeBinding,
    current_native: &[u8],
    limits: HostModelResources,
) -> Result<usize, OperationFailure> {
    if originals.len() > MAXIMUM_OBSERVATIONS {
        return Err(failure(
            "clock producer observation count exceeds selected credit",
        ));
    }
    let current_script = script_body(current_native)?;
    let current_clock = if current_script.is_none() {
        Some(super::super::rate_alarm_clock::RateAlarmClock::validate_native(current_native)?)
    } else {
        None
    };
    let mut total = 0usize;
    let mut roots = BTreeSet::new();
    for original in originals {
        total = total
            .checked_add(original.size()?)
            .ok_or_else(|| failure("clock producer original aggregate overflowed"))?;
        if total > limits.maximum_capture_bytes {
            return Err(failure(
                "clock producer original aggregate credit exhausted",
            ));
        }
        let root = original.checked(node)?;
        let historical_script = script_body(&original.objects[1].bytes)?;
        match (&current_script, &current_clock, historical_script) {
            (Some(current), None, Some(original)) if *current == original => {}
            (None, Some(current), None) => {
                let historical = super::super::rate_alarm_clock::RateAlarmClock::validate_native(
                    &original.objects[1].bytes,
                )?;
                if historical.definition() != current.definition() {
                    return Err(failure(
                        "clock producer original immutable counter policy changed",
                    ));
                }
            }
            _ => {
                return Err(failure(
                    "clock producer original native model identity differs",
                ));
            }
        }
        if root.owners[0].owner != binding.compatibility.execution_owner.id
            || root.owners[0].generation.get() == 0
            || root.boundary > source.capture_cut
            || !roots.insert(original.objects[0].reference.clone())
            || !source.owners.iter().any(|owner| {
                owner.identity.owner == root.owners[0].owner
                    && root.owners[0].generation <= source.source_activation.generation
            })
        {
            return Err(failure(
                "clock producer historical owner, cut or association differs",
            ));
        }
    }
    Ok(total)
}

fn script_body(native: &[u8]) -> Result<Option<&[u8]>, OperationFailure> {
    let Some(rest) = native.strip_prefix(b"crucible.scripted-cursor.v1\0") else {
        return Ok(None);
    };
    let length = rest
        .get(..8)
        .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
        .map(u64::from_le_bytes)
        .and_then(|length| usize::try_from(length).ok())
        .ok_or_else(|| failure("clock producer script length differs"))?;
    rest.get(8..)
        .and_then(|bytes| bytes.get(..length))
        .map(Some)
        .ok_or_else(|| failure("clock producer script body truncated"))
}

impl HostModelNode {
    pub(super) fn check_producer_effect_credit(&self) -> Result<(), OperationFailure> {
        if !selected(&self.binding) {
            return Ok(());
        }
        if self
            .completed
            .len()
            .checked_add(self.failed.len())
            .is_none_or(|count| count >= MAXIMUM_OBSERVATIONS)
            || self.producer_observations.len() >= MAXIMUM_OBSERVATIONS
        {
            return Err(failure(
                "clock producer original history credit exhausted before effects",
            ));
        }
        let retained = self
            .producer_observations
            .iter()
            .try_fold(0usize, |size, original| {
                size.checked_add(original.size()?)
                    .ok_or_else(|| failure("clock producer retained-byte overflowed"))
            })?;
        let completed = self
            .completed
            .values()
            .flat_map(|operation| &operation.evidence)
            .try_fold(retained, |size, object| {
                size.checked_add(object.bytes.len())
                    .ok_or_else(|| failure("clock producer operation credit overflowed"))
            })?;
        // Decimal byte arrays take at most four encoded bytes per octet. This
        // conservative pre-effect bound covers the complete retained children
        // and the next receipt; metadata and unchanged native state retain the
        // other half of the existing envelope ceiling.
        if completed
            .checked_add(MAXIMUM_RECEIPT_BYTES)
            .and_then(|size| size.checked_mul(4))
            .is_none_or(|size| size > self.limits.maximum_capture_bytes / 2)
        {
            return Err(failure(
                "clock producer complete receipt credit unavailable before effects",
            ));
        }
        Ok(())
    }

    pub(super) fn check_producer_input_credit(
        &self,
        batch: &RuntimeInputBatch,
    ) -> Result<(), OperationFailure> {
        if !selected(&self.binding) {
            return Ok(());
        }
        self.check_producer_effect_credit()?;
        let count = self
            .input_history
            .len()
            .checked_add(usize::from(self.staged.is_some()))
            .ok_or_else(|| failure("clock producer staging count overflowed"))?;
        let deliveries = self
            .input_history
            .values()
            .chain(self.staged.iter())
            .try_fold(batch.deliveries().len(), |count, input| {
                count.checked_add(input.original.deliveries().len())
            })
            .ok_or_else(|| failure("clock producer delivery count overflowed"))?;
        if count >= MAXIMUM_OBSERVATIONS
            || deliveries > super::super::rate_alarm_clock::MAXIMUM_CLOCK_REQUESTS
        {
            return Err(failure(
                "clock producer original input credit unavailable before staging",
            ));
        }
        Ok(())
    }

    pub(super) fn retain_producer_observation(
        &mut self,
        objects: [InputPayload; 3],
    ) -> Result<ContentRef, OperationFailure> {
        let reference = objects[0].reference.clone();
        if let Some(original) = self
            .producer_observations
            .iter()
            .find(|original| original.objects[0].reference == reference)
        {
            if original.objects != objects {
                return Err(failure("clock producer original body changed"));
            }
            return Ok(reference);
        }
        if self.producer_observations.len() >= MAXIMUM_OBSERVATIONS {
            return Err(failure("clock producer observation credit exhausted"));
        }
        let original = OriginalReceipt { objects };
        original.checked(&self.route.node)?;
        self.check_producer_effect_credit()?;
        self.producer_observations
            .try_reserve_exact(1)
            .map_err(|_| failure("clock producer association reservation unavailable"))?;
        self.producer_observations.push(original);
        Ok(reference)
    }

    fn producer_receipt(
        &self,
        activation: &WorldActivation,
        root: &ContentRef,
    ) -> Result<[&InputPayload; 3], OperationFailure> {
        if !selected(&self.binding)
            || !self.same_world(activation)
            || self.quarantined
            || self.model.is_none()
            || self
                .activation_authority
                .as_ref()
                .is_none_or(|authority| !Rc::ptr_eq(authority, &activation.authority))
        {
            return Err(failure(
                "clock producer original active custody unavailable",
            ));
        }
        if let Some(original) = self
            .producer_observations
            .iter()
            .find(|original| &original.objects[0].reference == root)
        {
            return Ok([
                &original.objects[0],
                &original.objects[1],
                &original.objects[2],
            ]);
        }
        for completed in self.completed.values() {
            if completed
                .outcome
                .scheduling
                .as_ref()
                .is_some_and(|observation| &observation.proof_ref == root)
            {
                let receipt = completed
                    .evidence
                    .iter()
                    .find(|object| &object.reference == root)
                    .ok_or_else(|| failure("clock original operation receipt absent"))?;
                let header: Receipt = serde_json::from_slice(&receipt.bytes)
                    .map_err(|error| failure(&error.to_string()))?;
                let native = completed
                    .evidence
                    .iter()
                    .find(|object| object.reference == header.native)
                    .ok_or_else(|| failure("clock original native child absent"))?;
                let causes = completed
                    .evidence
                    .iter()
                    .find(|object| object.reference == header.pending_causes)
                    .ok_or_else(|| failure("clock original causes child absent"))?;
                return Ok([receipt, native, causes]);
            }
        }
        Err(failure("clock producer historical original receipt absent"))
    }

    pub(super) fn producer_dependencies(
        &self,
        activation: &WorldActivation,
        root: &ContentRef,
        limits: InputProvenanceLimits,
    ) -> Result<Vec<ContentRef>, OperationFailure> {
        let objects = self.producer_receipt(activation, root)?;
        let total = objects
            .iter()
            .try_fold(0usize, |size, object| size.checked_add(object.bytes.len()))
            .ok_or_else(|| failure("clock producer complete dependency geometry overflowed"))?;
        if limits.maximum_objects < 3 || total > limits.maximum_bytes {
            return Err(failure(
                "clock producer complete dependency credit exhausted",
            ));
        }
        Ok(objects[1..]
            .iter()
            .map(|object| object.reference.clone())
            .collect())
    }

    pub(super) fn read_producer_evidence(
        &self,
        activation: &WorldActivation,
        references: &[ContentRef],
        maximum_bytes: usize,
    ) -> Result<Vec<InputPayload>, OperationFailure> {
        if !selected(&self.binding)
            || !self.same_world(activation)
            || self.quarantined
            || self.model.is_none()
            || self
                .activation_authority
                .as_ref()
                .is_none_or(|authority| !Rc::ptr_eq(authority, &activation.authority))
        {
            return Err(failure(
                "clock producer reader lacks current opaque authority",
            ));
        }
        if references.len() > MAXIMUM_OBSERVATIONS * 3
            || references.iter().collect::<BTreeSet<_>>().len() != references.len()
        {
            return Err(failure("clock producer requested role credit differs"));
        }
        let mut borrowed = Vec::new();
        borrowed
            .try_reserve_exact(references.len())
            .map_err(|_| failure("clock producer borrowed role reservation unavailable"))?;
        let mut total = 0usize;
        for reference in references {
            let mut found = None;
            for root in self
                .producer_observations
                .iter()
                .map(|row| &row.objects[0].reference)
                .chain(self.completed.values().filter_map(|operation| {
                    operation
                        .outcome
                        .scheduling
                        .as_ref()
                        .map(|observation| &observation.proof_ref)
                }))
            {
                if let Some(object) = self
                    .producer_receipt(activation, root)?
                    .into_iter()
                    .find(|object| &object.reference == reference)
                {
                    if found.is_some_and(|previous: &InputPayload| previous != object) {
                        return Err(failure("clock producer retained content conflict"));
                    }
                    found = Some(object);
                }
            }
            let object =
                found.ok_or_else(|| failure("clock producer requested original body absent"))?;
            total = total
                .checked_add(object.bytes.len())
                .ok_or_else(|| failure("clock producer expanded role credit overflowed"))?;
            if total > maximum_bytes {
                return Err(failure("clock producer expanded role credit exhausted"));
            }
            borrowed.push(object);
        }
        let mut output = Vec::new();
        output
            .try_reserve_exact(borrowed.len())
            .map_err(|_| failure("clock producer output role reservation unavailable"))?;
        for object in borrowed {
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(object.bytes.len())
                .map_err(|_| failure("clock producer output byte reservation unavailable"))?;
            bytes.extend_from_slice(&object.bytes);
            output.push(InputPayload {
                reference: object.reference.clone(),
                bytes,
            });
        }
        Ok(output)
    }
}

#[cfg(test)]
#[path = "host_rate_alarm_evidence/receipt_tests.rs"]
mod receipt_tests;
