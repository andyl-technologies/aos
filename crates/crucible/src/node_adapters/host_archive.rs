//! Bounded inspection of the selected complete host native capture edition.
//!
//! Structural validation preserves the original ledger identities. Installed
//! archive authentication remains mandatory before these bytes establish any
//! provenance, fidelity or native restoration authority.

use super::*;

/// Describes verified structural contents of the selected host capture edition.
///
/// This inventory does not authenticate the archive or issue operational
/// authority. A trusted installed archive adapter must independently verify
/// source provenance, selected implementation and immutable model artifacts.
pub struct HostContinuationInventory {
    /// Identifies the original component represented by the complete envelope.
    pub node: Id,
    /// Preserves the original whole-world capture boundary.
    pub boundary: Position,
    /// Contains the embedded unchanged native model codec and its commitment.
    pub native_model: InputPayload,
    /// Contains the original immutable native receipt and publication objects.
    pub evidence: Vec<InputPayload>,
    /// Lists the complete component's original operation identities.
    pub operations: Vec<Id>,
    /// Describes the checked original source and actual native consumed FIFO prefix.
    /// This remains data until the complete signed source is authenticated.
    pub recorded_input: Option<(crate::node_adapters::RecordedIngressDefinition, U64)>,
    /// Lists the complete original staged input inventory commitments.
    pub input_inventories: Vec<ContentRef>,
}

/// Validates a complete host envelope against its original runtime ledger.
///
/// The function has no native effects and requires no fresh activation. It
/// checks the selected edition, complete original request/result/input custody,
/// content integrity, consumption prefixes and causal queue provenance. The
/// result remains structurally validated data until an installed archive
/// authority authenticates the complete source and immutable artifact closure.
///
/// # Errors
/// Rejects oversized bytes or ledgers, unsupported capture editions, changed
/// original operations, incomplete input or receipt objects, changed payloads,
/// invalid consumed prefixes and inconsistent native publication counters.
pub fn validate_host_continuation(
    bytes: &[u8],
    source: &RuntimeSnapshot,
    descriptor: &NodeDescriptor,
    binding: &NodeBinding,
    limits: HostModelResources,
) -> Result<HostContinuationInventory, OperationFailure> {
    let node = &descriptor.id;
    if bytes.len() > limits.maximum_capture_bytes
        || limits.maximum_capture_bytes == 0
        || limits.maximum_operations == 0
        || binding.compatibility.node_id != *node
        || descriptor
            .identity()
            .map_err(|error| failure(&error.to_string()))?
            != binding.compatibility.descriptor_hash
        || !binding
            .compatibility
            .operating_contract
            .facets
            .iter()
            .any(|facet| facet.id.as_str() == HOST_EXACT_PROFILE && facet.version == 1)
        || binding.compatibility.execution_owner != binding.compatibility.capture_owner
        || binding
            .compatibility
            .execution_owner
            .participant_ids
            .as_slice()
            != std::slice::from_ref(node)
    {
        return Err(failure(
            "host archive bytes, node or exclusive ownership contract differs",
        ));
    }
    SourceScope::checked(source, node, limits)?;
    let captured: Captured =
        serde_json::from_slice(bytes).map_err(|error| failure(&error.to_string()))?;
    let terminal_semantic = binding
        .compatibility
        .implementation
        .formats
        .iter()
        .any(|schema| {
            schema.id.as_str() == "host/native-semantic-continuation-v2" && schema.version == 2
        });
    let controlled_fault = binding
        .compatibility
        .implementation
        .formats
        .iter()
        .any(|schema| {
            schema.id.as_str() == "host/native-controlled-fault-link-v1" && schema.version == 1
        });
    let recorded = super::recorded::selected(binding);
    if captured.schema_version
        != if recorded {
            5
        } else if controlled_fault {
            3
        } else if terminal_semantic {
            2
        } else {
            1
        }
        || (controlled_fault && source.schema_version != 4)
        || (recorded && source.schema_version != 2)
        || captured.profile != HOST_EXACT_PROFILE
        || captured.boundary != source.capture_cut
        || captured.operations.len() > limits.maximum_operations
        || captured.pending_causes.len() > limits.maximum_operations
        || captured
            .input_history
            .len()
            .checked_add(usize::from(captured.staged.is_some()))
            .is_none_or(|count| count > limits.maximum_operations)
    {
        return Err(failure(
            "host archive edition, cut or record ceiling differs",
        ));
    }
    match (&captured.recorded_ingress, recorded) {
        (Some(cursor), true) => {
            super::recorded::restore(cursor, &captured, source, binding)?;
        }
        (None, false) => {}
        _ => {
            return Err(failure(
                "recorded cursor codec does not match selected installed format",
            ));
        }
    }
    let mut expected = BTreeMap::new();
    for saved in source
        .operations
        .iter()
        .filter(|operation| &operation.route.node == node)
    {
        let outcome = match &saved.result {
            SavedRuntimeResult::Complete(outcome) | SavedRuntimeResult::Acknowledged(outcome) => {
                outcome
            }
            _ => {
                return Err(failure(
                    "host archive contains unsupported pending or failed original operation",
                ));
            }
        };
        if expected
            .insert(&saved.operation, (saved, outcome))
            .is_some()
        {
            return Err(failure("host archive original operation identity repeats"));
        }
    }
    if expected.len() != captured.operations.len() {
        return Err(failure(
            "host archive original operation inventory is incomplete",
        ));
    }
    let mut previous = None;
    let mut evidence = BTreeMap::new();
    let mut maximum_sequence = None::<u64>;
    for operation in &captured.operations {
        let (saved, outcome) = expected
            .get(&operation.operation)
            .ok_or_else(|| failure("host archive contains a foreign original operation"))?;
        if previous.is_some_and(|id| id >= &operation.operation)
            || saved.request != operation.request
            || **outcome != operation.outcome
            || operation.acknowledged != matches!(saved.result, SavedRuntimeResult::Acknowledged(_))
        {
            return Err(failure(
                "host archive original request, outcome or ACK knowledge changed",
            ));
        }
        previous = Some(&operation.operation);
        let maximum_objects = operation.outcome.scheduling.as_ref().map_or_else(
            || match &operation.outcome.progress {
                ProgressEvidence::AssertionsFinalized { .. } => 2,
                _ => 1,
            },
            |observation| observation.publications.len().saturating_add(3),
        );
        if super::recorded::native_receipt_count(
            captured.recorded_ingress.as_ref(),
            &operation.evidence,
        )? > maximum_objects
        {
            return Err(failure(
                "host archive original receipt object ceiling exceeded",
            ));
        }
        let mut references = std::collections::BTreeSet::new();
        for object in &operation.evidence {
            if !references.insert(&object.reference)
                || canonical::content_ref(&object.bytes, &object.reference.media_type)
                    .map_err(|error| failure(&error.to_string()))?
                    != object.reference
                || evidence
                    .get(&object.reference)
                    .is_some_and(|bytes| bytes != &object.bytes)
            {
                return Err(failure("host archive original receipt integrity changed"));
            }
            evidence
                .entry(object.reference.clone())
                .or_insert_with(|| object.bytes.clone());
        }
        if let ProgressEvidence::AssertionsFinalized {
            barrier, report, ..
        } = &operation.outcome.progress
        {
            // The new semantic codec retains both original terminal objects;
            // legacy model codecs cannot silently acquire this custody shape.
            if captured.schema_version != 2
                || source.schema_version != 3
                || operation.outcome.scheduling.is_some()
                || references.len() != 2
                || !references.contains(barrier)
                || !references.contains(report)
            {
                return Err(failure(
                    "host archive original terminal evidence is incomplete",
                ));
            }
        }
        if let Some(observation) = &operation.outcome.scheduling {
            if observation.node != *node
                || !references.contains(&observation.proof_ref)
                || observation
                    .bounds
                    .iter()
                    .any(|bound| !references.contains(&bound.proof_ref))
                || observation
                    .input_progress
                    .as_ref()
                    .is_some_and(|progress| !references.contains(&progress.proof_ref))
                || observation.publications.iter().any(|publication| {
                    evidence.get(&publication.payload) != Some(&publication.payload_bytes)
                })
            {
                return Err(failure(
                    "host archive original scheduling evidence is incomplete",
                ));
            }
            for publication in &observation.publications {
                maximum_sequence = Some(
                    maximum_sequence.map_or(publication.native_sequence.get(), |old| {
                        old.max(publication.native_sequence.get())
                    }),
                );
            }
        }
    }
    let expected_sequence = maximum_sequence
        .map(|sequence| {
            sequence
                .checked_add(1)
                .ok_or_else(|| failure("host archive publication sequence exhausted"))
        })
        .transpose()?
        .unwrap_or(0);
    if captured.native_sequence.get() != expected_sequence {
        return Err(failure(
            "host archive publication counter differs from original receipts",
        ));
    }

    let mut input_ids = std::collections::BTreeSet::new();
    for input in captured.input_history.iter().chain(captured.staged.iter()) {
        let saved = source
            .inputs
            .iter()
            .find(|saved| &saved.node == node && saved.stage_operation == input.stage_operation)
            .ok_or_else(|| failure("host archive contains foreign original input custody"))?;
        let consumed = captured
            .operations
            .iter()
            .filter_map(|operation| operation.outcome.scheduling.as_ref())
            .filter_map(|observation| observation.input_progress.as_ref())
            .filter(|progress| progress.batch == input.batch)
            .max_by_key(|progress| progress.consumed.len());
        let prefix = consumed.map_or(0, |progress| progress.consumed.len());
        if !input_ids.insert(&input.stage_operation)
            || saved.failure.is_some()
            || saved.batch != input.batch
            || saved.cutoff != input.cutoff
            || saved.inventory != input.inventory
            || saved.deliveries != input.deliveries
            || saved.payloads != input.payloads
            || saved.acknowledgement.as_ref() != Some(&input.acknowledgement)
            || input.consumed.get() != prefix as u64
            || prefix > input.deliveries.len()
            || captured.input_history.iter().any(|old| {
                old.stage_operation == input.stage_operation && prefix != input.deliveries.len()
            })
            || consumed.is_some_and(|progress| {
                progress
                    .consumed
                    .iter()
                    .zip(&input.deliveries)
                    .any(|(identity, delivery)| {
                        identity.producer != delivery.producer
                            || identity.source_sequence != delivery.source_sequence
                    })
            })
        {
            return Err(failure(
                "host archive original input bytes, ACK or consumed prefix changed",
            ));
        }
        for payload in &input.payloads {
            if canonical::content_ref(&payload.bytes, &payload.reference.media_type)
                .map_err(|error| failure(&error.to_string()))?
                != payload.reference
            {
                return Err(failure(
                    "host archive original staged payload integrity changed",
                ));
            }
            evidence
                .entry(payload.reference.clone())
                .or_insert_with(|| payload.bytes.clone());
        }
        if input.acknowledgement_body.reference != input.acknowledgement.proof_ref
            || canonical::content_ref(
                &input.acknowledgement_body.bytes,
                &input.acknowledgement_body.reference.media_type,
            )
            .map_err(|error| failure(&error.to_string()))?
                != input.acknowledgement_body.reference
        {
            return Err(failure(
                "host archive original staging ACK body is incomplete",
            ));
        }
        evidence
            .entry(input.acknowledgement_body.reference.clone())
            .or_insert_with(|| input.acknowledgement_body.bytes.clone());
        let inventory_bytes = canonical::canonical_json(
            &serde_json::to_value(&input.deliveries)
                .map_err(|error| failure(&error.to_string()))?,
        )
        .map_err(|error| failure(&error.to_string()))?;
        if canonical::content_ref(&inventory_bytes, &input.inventory.media_type)
            .map_err(|error| failure(&error.to_string()))?
            != input.inventory
        {
            return Err(failure(
                "host archive canonical original input inventory differs",
            ));
        }
        evidence
            .entry(input.inventory.clone())
            .or_insert(inventory_bytes);
    }
    if source
        .inputs
        .iter()
        .filter(|input| &input.node == node)
        .any(|input| {
            input.failure.is_some()
                || input.acknowledgement.is_none()
                || !input_ids.contains(&input.stage_operation)
        })
    {
        return Err(failure("host archive original input custody is incomplete"));
    }
    let mut causal_keys = std::collections::BTreeSet::new();
    for cause in &captured.pending_causes {
        if !causal_keys.insert((cause.time_ps, cause.source, cause.sequence))
            || cause.parents.len() > limits.maximum_operations
            || cause.parents.iter().any(|parent| {
                parent.time_ps >= cause.time_ps
                    || !captured
                        .input_history
                        .iter()
                        .chain(captured.staged.iter())
                        .any(|input| {
                            input
                                .deliveries
                                .iter()
                                .take(input.consumed.get() as usize)
                                .any(|delivery| delivery.delivery == *parent)
                        })
            })
        {
            return Err(failure(
                "host archive pending causal lineage differs from original consumed inputs",
            ));
        }
    }
    let recorded_input = captured
        .recorded_ingress
        .as_ref()
        .map(|cursor| {
            let custody = super::recorded::restore(cursor, &captured, source, binding)?;
            Ok((custody.definition, U64::new(custody.cursor as u64)))
        })
        .transpose()?;
    let native_reference = canonical::content_ref(&captured.native, "application/octet-stream")
        .map_err(|error| failure(&error.to_string()))?;
    Ok(HostContinuationInventory {
        recorded_input,
        node: node.clone(),
        boundary: captured.boundary,
        native_model: InputPayload {
            reference: native_reference,
            bytes: captured.native,
        },
        evidence: evidence
            .into_iter()
            .map(|(reference, bytes)| InputPayload { reference, bytes })
            .collect(),
        operations: captured
            .operations
            .into_iter()
            .map(|operation| operation.operation)
            .collect(),
        input_inventories: captured
            .input_history
            .into_iter()
            .chain(captured.staged)
            .map(|input| input.inventory)
            .collect(),
    })
}
