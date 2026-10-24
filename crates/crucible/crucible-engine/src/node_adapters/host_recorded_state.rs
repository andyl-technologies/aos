//! Distinct recorded Block cursor codec within the complete native Host ledger.
//!
//! The source document is data. A restored cursor additionally requires the
//! authenticated runtime input and consumed native ledger, original activation
//! proof bodies and independently installed source qualification.

use serde::{Deserialize, Serialize};

use super::*;
use crate::node_adapters::host_ingress::{RecordedIngressCustody, RecordedIngressDefinition};

pub(super) const FORMAT: &str = "host/native-recorded-block-v1";
const MAXIMUM_HISTORIES: usize = 16;

/// Retains one actual activation and its immutable owned-prefix proof bodies.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProofHistory {
    activation: crate::node_contract::SavedRuntimeActivation,
    /// Retains only the original prefix visible under this historical activation.
    pub(crate) proofs: Vec<InputPayload>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecordedCursor {
    version: u16,
    definition: Vec<InputPayload>,
    consumed: U64,
    histories: Vec<ProofHistory>,
}

pub(crate) fn selected(binding: &NodeBinding) -> bool {
    binding
        .compatibility
        .implementation
        .formats
        .iter()
        .any(|format| format.id.as_str() == FORMAT && format.version == 1)
}

fn proof(
    definition: &RecordedIngressDefinition,
    activation: &crate::node_contract::SavedRuntimeActivation,
    consumed: usize,
) -> Result<InputPayload, OperationFailure> {
    let bytes = canonical::canonical_json(&serde_json::json!({
        "format":"crucible.recorded-input-owned-prefix","version":1,
        "activation":{"id":activation.activation_id,"generation":activation.generation,
            "world":activation.world_binding_hash,"owners":activation.owners,
            "boundary":activation.boundary},"root":definition.root(),
        "consumed_prefix":U64::new(consumed as u64)
    }))
    .map_err(|error| failure(&error.to_string()))?;
    let reference = canonical::content_ref(&bytes, "application/json")
        .map_err(|error| failure(&error.to_string()))?;
    Ok(InputPayload { reference, bytes })
}

pub(super) fn capture(
    ingress: &RecordedIngressCustody,
) -> Result<RecordedCursor, OperationFailure> {
    let activation = ingress
        .activation
        .as_ref()
        .ok_or_else(|| failure("recorded capture has no actual activation custody"))?;
    if ingress.historical_proofs.len() >= MAXIMUM_HISTORIES
        || ingress.definition.objects().len() != 4
        || ingress.cursor > ingress.definition.source().inputs.len()
        || ingress.proofs.len() != ingress.definition.source().inputs.len() + 1
        || activation.owners.len() != 1
        || ingress.historical_proofs.iter().any(|history| {
            history.activation.owners.len() != 1
                || history.proofs.is_empty()
                || history.proofs.len() > ingress.cursor + 1
        })
    {
        return Err(failure("recorded complete original history credit differs"));
    }
    let mut histories = Vec::new();
    histories
        .try_reserve_exact(ingress.historical_proofs.len() + 1)
        .map_err(|_| failure("recorded history allocation refused"))?;
    for original in &ingress.historical_proofs {
        histories.push(ProofHistory {
            activation: original.activation.clone(),
            proofs: copy_objects(&original.proofs)?,
        });
    }
    histories.push(ProofHistory {
        activation: activation.into(),
        proofs: copy_objects(&ingress.proofs[..=ingress.cursor])?,
    });
    Ok(RecordedCursor {
        version: 1,
        definition: copy_objects(ingress.definition.objects())?,
        consumed: U64::new(ingress.cursor as u64),
        histories,
    })
}

pub(super) fn restore(
    cursor: &RecordedCursor,
    captured: &Captured,
    source: &RuntimeSnapshot,
    binding: &NodeBinding,
) -> Result<RecordedIngressCustody, OperationFailure> {
    if !selected(binding)
        || cursor.version != 1
        || cursor.definition.len() != 4
        || cursor.histories.is_empty()
        || cursor.histories.len() > MAXIMUM_HISTORIES
    {
        return Err(failure(
            "recorded cursor edition or complete source inventory differs",
        ));
    }
    let definition = RecordedIngressDefinition::new(
        cursor.definition[0].clone(),
        cursor.definition[1].clone(),
        cursor.definition[2].clone(),
    )?;
    if definition.objects() != cursor.definition.as_slice()
        || definition.source().endpoint.node_id != binding.compatibility.node_id
        || cursor.consumed.get() > definition.source().inputs.len() as u64
    {
        return Err(failure(
            "recorded cursor original source, owner or prefix differs",
        ));
    }
    let consumed = cursor.consumed.get() as usize;
    let mut previous = None;
    let mut previous_prefix = 0;
    let mut incarnations = std::collections::BTreeSet::new();
    for history in &cursor.histories {
        // Older rows are retained facts imported only from an authenticated
        // archive lineage; their self-consistent hashes never issue authority.
        // Every row must keep this single selected logical owner and its own
        // original positive generation and unique physical incarnation.
        if history.activation.world_binding_hash != source.source_activation.world_binding_hash
            || history.activation.owners.len() != 1
            || history.activation.owners[0].owner != binding.compatibility.execution_owner.id
            || history.activation.owners[0].generation != history.activation.generation
            || history.activation.generation.get() == 0
            || !incarnations.insert(&history.activation.owners[0].incarnation)
            || history.proofs.len() < previous_prefix
            || history.proofs.is_empty()
            || history.proofs.len() > consumed + 1
            || previous.is_some_and(|generation| generation >= history.activation.generation)
        {
            return Err(failure(
                "recorded cursor original activation history differs",
            ));
        }
        for (index, original) in history.proofs.iter().enumerate() {
            if original != &proof(&definition, &history.activation, index)? {
                return Err(failure("recorded cursor original proof body differs"));
            }
        }
        previous = Some(history.activation.generation);
        previous_prefix = history.proofs.len();
    }
    let current = cursor
        .histories
        .last()
        .ok_or_else(|| failure("recorded cursor current proof absent"))?;
    if current.activation != source.source_activation || current.proofs.len() != consumed + 1 {
        return Err(failure(
            "recorded cursor source activation or owned proof prefix differs",
        ));
    }

    // Every native accepted request must be the exact original external event.
    // Native consumption determines the cursor; an immutable source or supplied
    // cursor scalar alone cannot retire an arrival.
    let mut delivered = std::collections::BTreeSet::new();
    let mut actually_consumed = std::collections::BTreeSet::new();
    let mut checker = RecordedIngressCustody::new(definition.clone());
    for input in captured.input_history.iter().chain(captured.staged.iter()) {
        for (offset, delivery) in input.deliveries.iter().enumerate() {
            let index = definition
                .source()
                .inputs
                .iter()
                .position(|original| original.event == delivery.publication_id)
                .ok_or_else(|| failure("recorded native input has no original FIFO identity"))?;
            checker.cursor = index;
            checker.validate_delivery(delivery, 0)?;
            if !delivered.insert(index) {
                return Err(failure("recorded original input was staged more than once"));
            }
            if offset < input.consumed.get() as usize {
                actually_consumed.insert(index);
            }
        }
    }
    if actually_consumed.iter().copied().ne(0..consumed) {
        return Err(failure(
            "recorded cursor differs from actual original native consumed prefix",
        ));
    }
    let mut restored = RecordedIngressCustody::new(definition);
    restored.cursor = consumed;
    restored.preserved = true;
    restored
        .historical_proofs
        .try_reserve_exact(cursor.histories.len())
        .map_err(|_| failure("recorded retained history slots unavailable"))?;
    for original in &cursor.histories {
        restored.historical_proofs.push(ProofHistory {
            activation: original.activation.clone(),
            proofs: copy_objects(&original.proofs)?,
        });
    }
    // Current target proofs are allocated by the genuine closed-gate arm.
    // Original historical proof bodies remain separate and byte-exact.
    Ok(restored)
}

// The old edition omits this field. Explicit null is never a selected cursor.
pub(super) fn present_cursor<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<RecordedCursor>, D::Error> {
    RecordedCursor::deserialize(deserializer).map(Some)
}

/// Counts native receipt roles separately from authenticated original source bodies.
pub(super) fn native_receipt_count(
    cursor: Option<&RecordedCursor>,
    evidence: &[InputPayload],
) -> Result<usize, OperationFailure> {
    let Some(cursor) = cursor else {
        return Ok(evidence.len());
    };
    let mut native = 0;
    for object in evidence {
        let original = cursor
            .definition
            .iter()
            .chain(cursor.histories.iter().flat_map(|history| &history.proofs))
            .find(|original| original.reference == object.reference);
        match original {
            Some(original) if original != object => {
                return Err(failure("recorded original receipt source body changed"));
            }
            Some(_) => {}
            None => native += 1,
        }
    }
    Ok(native)
}

fn copy_objects(original: &[InputPayload]) -> Result<Vec<InputPayload>, OperationFailure> {
    let mut copied = Vec::new();
    copied
        .try_reserve_exact(original.len())
        .map_err(|_| failure("recorded original object slots unavailable"))?;
    for object in original {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(object.bytes.len())
            .map_err(|_| failure("recorded original object byte credit unavailable"))?;
        bytes.extend_from_slice(&object.bytes);
        copied.push(InputPayload {
            reference: object.reference.clone(),
            bytes,
        });
    }
    Ok(copied)
}
