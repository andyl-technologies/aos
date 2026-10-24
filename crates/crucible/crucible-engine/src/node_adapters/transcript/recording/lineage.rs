//! Records owning original lineage callbacks before native custody is released.

use super::*;
use crate::node_adapters::transcript::tape2::{RecordedLineage, RecordedTape2, bounded_metadata};
use serde::{Serialize, Serializer, ser::SerializeSeq};

impl RecordingNode {
    fn lineage_record_limit(&self) -> Result<usize, OperationFailure> {
        let state = self.state.0.borrow();
        let capture = state
            .capture
            .as_ref()
            .ok_or_else(|| failure("original lineage capture is closed", EffectKnowledge::None))?;
        usize::try_from(capture.maximum_record_bytes())
            .map_err(|_| failure("original lineage record extent", EffectKnowledge::None))
    }

    pub(super) fn capture_input_lineage(
        &self,
        batch: &RuntimeInputBatch,
        lineage: Option<&OriginalInputLineage>,
    ) -> Result<Vec<InputPayload>, OperationFailure> {
        let Some(lineage) = lineage else {
            if self.inner.requires_original_input_lineage(batch) {
                return Err(failure(
                    "original lineage recording input is missing",
                    EffectKnowledge::None,
                ));
            }
            return Ok(Vec::new());
        };
        if !self.original_lineage
            || lineage.original().node() != batch.node()
            || lineage.original().stage_operation() != batch.stage_operation()
            || lineage.original().batch() != batch.batch()
            || lineage.original().inventory() != batch.inventory()
            || !Rc::ptr_eq(
                &lineage.original().activation().authority,
                &batch.activation().authority,
            )
        {
            return Err(failure(
                "original lineage recording scope changed",
                EffectKnowledge::None,
            ));
        }
        let maximum = self.lineage_record_limit()?;
        bounded_metadata(
            &TapeView {
                schema_version: 2,
                source_capture: &self.origin.activation,
                node: &self.origin.route.node,
                interaction: batch.stage_operation(),
                lineage: LineageView::Input {
                    input: InputView {
                        schema_version: 1,
                        source: lineage.source_scope(),
                        publications: Publications(lineage.publications()),
                    },
                },
            },
            maximum,
        )
        .map_err(|error| failure(error, EffectKnowledge::None))?;
        let saved = lineage
            .saved_reference_view(OriginalInputLineageLimits::default())
            .map_err(|error| failure(error, EffectKnowledge::None))?;
        let metadata = RecordedTape2::capture(
            &self.origin,
            batch.stage_operation().clone(),
            RecordedLineage::Input {
                input: Box::new(saved),
            },
            maximum,
        )
        .map_err(|error| failure(error, EffectKnowledge::None))?;
        let mut evidence = Vec::new();
        for claim in lineage.publications() {
            append_originals(&mut evidence, &claim.objects, maximum)?;
        }
        append_originals(&mut evidence, &[metadata], maximum)?;
        Ok(evidence)
    }

    pub(super) fn capture_publication_lineage(
        &self,
        admission: &OperationAdmission,
        outcome: &OperationOutcome,
        evidence: &mut Vec<InputPayload>,
    ) -> Result<(), OperationFailure> {
        if !self.original_lineage {
            return Ok(());
        }
        let maximum = self.lineage_record_limit()?;
        let mut remaining = OriginalInputLineageLimits::default();
        if let Some(observation) = &outcome.scheduling {
            for publication in &observation.publications {
                let claim = self.inner.original_publication_lineage(
                    admission,
                    outcome,
                    publication,
                    remaining,
                )?;
                self.inner.validate_original_publication_lineage(
                    admission,
                    outcome,
                    publication,
                    &claim,
                )?;
                if claim.origin.measurement != observation.proof_ref
                    || claim.event.id != publication.publication_id
                    || claim.event.source != publication.endpoint
                    || claim.event.source_sequence != publication.native_sequence
                    || claim.event.publication_position != publication.publication
                    || claim.event.payload != publication.payload
                {
                    return Err(failure(
                        "recorded original publication tuple differs",
                        EffectKnowledge::None,
                    ));
                }
                // Count the complete outer record through borrowed views before
                // allocating any owned reference or dependency-row metadata.
                bounded_metadata(
                    &TapeView {
                        schema_version: 2,
                        source_capture: &self.origin.activation,
                        node: &self.origin.route.node,
                        interaction: admission.token().operation(),
                        lineage: LineageView::Publication {
                            publication: PublicationView::from(&claim),
                        },
                    },
                    maximum,
                )
                .map_err(|error| failure(error, EffectKnowledge::None))?;
                let mut objects = reserve(claim.objects.len())?;
                objects.extend(claim.objects.iter().map(|object| object.reference.clone()));
                let mut rows = reserve(claim.rows.len())?;
                for row in &claim.rows {
                    let mut dependencies = reserve(row.dependencies.len())?;
                    dependencies.extend(row.dependencies.iter().cloned());
                    rows.push(OriginalLineageRow {
                        object: row.object.clone(),
                        dependencies,
                    });
                }
                let saved = SavedOriginalPublication {
                    origin: claim.origin.clone(),
                    published: claim.published.clone(),
                    objects,
                    rows,
                };
                let derived = saved
                    .validate_recorded_bodies(remaining, |reference| {
                        claim
                            .objects
                            .iter()
                            .find(|object| object.reference == *reference)
                            .map(|object| object.bytes.as_slice())
                    })
                    .map_err(|error| failure(error, EffectKnowledge::None))?;
                let direct = claim
                    .rows
                    .iter()
                    .try_fold(0usize, |total, row| {
                        total.checked_add(row.dependencies.len())
                    })
                    .ok_or_else(|| {
                        failure("original publication edge extent", EffectKnowledge::None)
                    })?;
                remaining.maximum_objects = remaining
                    .maximum_objects
                    .checked_sub(claim.objects.len())
                    .ok_or_else(|| {
                        failure("original publication role credit", EffectKnowledge::None)
                    })?;
                for object in &claim.objects {
                    remaining.maximum_bytes = remaining
                        .maximum_bytes
                        .checked_sub(object.bytes.len())
                        .ok_or_else(|| {
                            failure("original publication body credit", EffectKnowledge::None)
                        })?;
                }
                remaining.maximum_edges = remaining
                    .maximum_edges
                    .checked_sub(direct.max(derived))
                    .ok_or_else(|| {
                        failure("original publication edge credit", EffectKnowledge::None)
                    })?;
                let metadata = RecordedTape2::capture(
                    &self.origin,
                    admission.token().operation().clone(),
                    RecordedLineage::Publication {
                        publication: Box::new(saved),
                    },
                    maximum,
                )
                .map_err(|error| failure(error, EffectKnowledge::None))?;
                append_originals(evidence, &claim.objects, maximum)?;
                append_originals(evidence, &[metadata], maximum)?;
                self.inner.validate_original_publication_lineage(
                    admission,
                    outcome,
                    publication,
                    &claim,
                )?;
            }
        }
        Ok(())
    }
}

fn append_originals(
    evidence: &mut Vec<InputPayload>,
    originals: &[InputPayload],
    maximum_bytes: usize,
) -> Result<(), OperationFailure> {
    let count = evidence
        .len()
        .checked_add(originals.len())
        .filter(|count| *count <= 4096)
        .ok_or_else(|| failure("original Tape2 evidence role credit", EffectKnowledge::None))?;
    let mut selected = Vec::new();
    selected
        .try_reserve_exact(count)
        .map_err(|_| failure("original Tape2 evidence allocation", EffectKnowledge::None))?;
    selected.extend(evidence.iter());
    for object in originals {
        object
            .reference
            .verify(&object.bytes)
            .map_err(|error| failure(error, EffectKnowledge::None))?;
        if let Some(previous) = selected
            .iter()
            .find(|old| old.reference == object.reference)
        {
            if *previous != object {
                return Err(failure(
                    "original Tape2 evidence body changed",
                    EffectKnowledge::None,
                ));
            }
        } else {
            selected.push(object);
        }
    }
    bounded_metadata(&selected, maximum_bytes)
        .map_err(|error| failure(error, EffectKnowledge::None))?;
    let additional = selected.len().saturating_sub(evidence.len());
    drop(selected);
    evidence
        .try_reserve_exact(additional)
        .map_err(|_| failure("original Tape2 evidence reservation", EffectKnowledge::None))?;
    for original in originals {
        if !evidence
            .iter()
            .any(|object| object.reference == original.reference)
        {
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(original.bytes.len())
                .map_err(|_| failure("original Tape2 body reservation", EffectKnowledge::None))?;
            bytes.extend_from_slice(&original.bytes);
            evidence.push(InputPayload {
                reference: original.reference.clone(),
                bytes,
            });
        }
    }
    Ok(())
}

/// Mirrors the closed Tape2 metadata without copying original references.
#[derive(Serialize)]
struct TapeView<'a> {
    schema_version: u16,
    source_capture: &'a SavedRuntimeActivation,
    node: &'a Id,
    interaction: &'a Id,
    lineage: LineageView<'a>,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum LineageView<'a> {
    Publication { publication: PublicationView<'a> },
    Input { input: InputView<'a> },
}

#[derive(Serialize)]
struct InputView<'a> {
    schema_version: u16,
    source: &'a SavedOriginalInputScope,
    publications: Publications<'a>,
}

#[derive(Serialize)]
struct PublicationView<'a> {
    origin: &'a OriginalPublicationOrigin,
    published: &'a ContentRef,
    objects: ObjectReferences<'a>,
    rows: &'a [OriginalLineageRow],
}

impl<'a> From<&'a OriginalPublicationClaim> for PublicationView<'a> {
    fn from(claim: &'a OriginalPublicationClaim) -> Self {
        Self {
            origin: &claim.origin,
            published: &claim.published,
            objects: ObjectReferences(&claim.objects),
            rows: &claim.rows,
        }
    }
}

struct ObjectReferences<'a>(&'a [InputPayload]);

impl Serialize for ObjectReferences<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for object in self.0 {
            sequence.serialize_element(&object.reference)?;
        }
        sequence.end()
    }
}

struct Publications<'a>(&'a [OriginalPublicationClaim]);

impl Serialize for Publications<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for claim in self.0 {
            sequence.serialize_element(&PublicationView::from(claim))?;
        }
        sequence.end()
    }
}

fn reserve<T>(count: usize) -> Result<Vec<T>, OperationFailure> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| failure("original Tape2 metadata reservation", EffectKnowledge::None))?;
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_adapters::transcript::{codec::TranscriptError, tests::origin};

    #[test]
    fn borrowed_tape2_metadata_matches_complete_owned_encoding() -> Result<(), TranscriptError> {
        let origin = origin();
        let interaction = origin.route.node.clone();
        let scope = SavedOriginalInputScope {
            source_activation: origin.activation.clone(),
            node: origin.route.node.clone(),
            stage_operation: interaction.clone(),
            batch: origin.route.node.clone(),
            owners: origin.route.owners.clone(),
            cutoff: origin.activation.boundary,
            inventory: origin.context[0].reference.clone(),
        };
        let view = TapeView {
            schema_version: 2,
            source_capture: &origin.activation,
            node: &origin.route.node,
            interaction: &interaction,
            lineage: LineageView::Input {
                input: InputView {
                    schema_version: 1,
                    source: &scope,
                    publications: Publications(&[]),
                },
            },
        };
        let bytes = encode(&view)?;
        assert!(bounded_metadata(&view, bytes.len() - 1).is_err());
        bounded_metadata(&view, bytes.len())?;

        let captured = RecordedTape2::capture(
            &origin,
            interaction.clone(),
            RecordedLineage::Input {
                input: Box::new(SavedOriginalInputLineage {
                    schema_version: 1,
                    source: scope.clone(),
                    publications: Vec::new(),
                }),
            },
            bytes.len(),
        )?;
        assert_eq!(captured.bytes, bytes);
        Ok(())
    }
}
