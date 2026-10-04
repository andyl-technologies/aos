//! Canonical replay-record indexing, encoding, and materialization.

use super::*;

pub(super) fn validate_recorded_replays(
    value: &PreparedCrucibleFindingCandidate,
) -> Result<(), PreparedSemanticResultCodecError> {
    let configurations = indexed_by_id(
        &value.replay_records.configurations,
        |record| record.id(),
        ConfigurationArtifact::canonical_bytes,
    )?;
    let measurements = indexed_by_id(
        &value.replay_records.measurements,
        |record| record.id(),
        MeasurementSet::canonical_bytes,
    )?;
    let properties = indexed_by_id(
        &value.replay_records.properties,
        |record| record.id(),
        PropertyVerdictSet::canonical_bytes,
    )?;
    let coverage = indexed_by_id(
        &value.replay_records.coverage,
        |record| record.id(),
        CoverageProjection::canonical_bytes,
    )?;
    let declarations = indexed_by_id(
        &value.replay_records.declarations,
        |record| record.id(),
        SelectableDeclaration::canonical_bytes,
    )?;
    let domains = indexed_by_id(
        &value.replay_records.domains,
        |record| record.id(),
        ChoiceDomain::canonical_bytes,
    )?;
    let opportunities = indexed_by_id(
        &value.replay_records.opportunities,
        |record| record.id(),
        ChoiceOpportunity::canonical_bytes,
    )?;
    let selections = indexed_by_id(
        &value.replay_records.selections,
        |record| record.id(),
        Selection::canonical_bytes,
    )?;

    // A compact journal may refer to one large record from every replay. Bound
    // that repeated copy work before reconstructing any owned evidence values.
    let mut referenced_bytes = 0usize;
    let mut reference_count = 0usize;
    for replay in value
        .minimization_replays
        .iter()
        .chain(&value.verification_replays)
    {
        charge_reference(
            &configurations,
            &replay.configuration(),
            &mut referenced_bytes,
            &mut reference_count,
            "finding replay configuration",
        )?;
        let Some((measurement_id, property_id, coverage_id, opportunity_ids, selection_ids)) =
            replay.observed_components()
        else {
            continue;
        };
        charge_reference(
            &measurements,
            &measurement_id,
            &mut referenced_bytes,
            &mut reference_count,
            "finding replay measurements",
        )?;
        charge_reference(
            &properties,
            &property_id,
            &mut referenced_bytes,
            &mut reference_count,
            "finding replay properties",
        )?;
        charge_reference(
            &coverage,
            &coverage_id,
            &mut referenced_bytes,
            &mut reference_count,
            "finding replay coverage",
        )?;
        for opportunity_id in opportunity_ids {
            let (opportunity, _) = charge_reference(
                &opportunities,
                opportunity_id,
                &mut referenced_bytes,
                &mut reference_count,
                "finding replay opportunity",
            )?;
            charge_reference(
                &declarations,
                &opportunity.declaration(),
                &mut referenced_bytes,
                &mut reference_count,
                "finding replay declaration",
            )?;
            charge_reference(
                &domains,
                &opportunity.domain(),
                &mut referenced_bytes,
                &mut reference_count,
                "finding replay domain",
            )?;
        }
        for selection_id in selection_ids {
            charge_reference(
                &selections,
                selection_id,
                &mut referenced_bytes,
                &mut reference_count,
                "finding replay selection",
            )?;
        }
    }

    for replay in value
        .minimization_replays
        .iter()
        .chain(&value.verification_replays)
    {
        let (configuration, _) = configurations.get(&replay.configuration()).ok_or(
            PreparedSemanticResultCodecError::Inconsistent {
                component: "finding replay configuration",
            },
        )?;
        let Some((measurement_id, property_id, coverage_id, opportunity_ids, selection_ids)) =
            replay.observed_components()
        else {
            continue;
        };
        let (measurement, _) = measurements.get(&measurement_id).ok_or(
            PreparedSemanticResultCodecError::Inconsistent {
                component: "finding replay measurements",
            },
        )?;
        let (property, _) =
            properties
                .get(&property_id)
                .ok_or(PreparedSemanticResultCodecError::Inconsistent {
                    component: "finding replay properties",
                })?;
        let (projection, _) =
            coverage
                .get(&coverage_id)
                .ok_or(PreparedSemanticResultCodecError::Inconsistent {
                    component: "finding replay coverage",
                })?;
        let mut discoveries = Vec::with_capacity(opportunity_ids.len());
        for opportunity_id in opportunity_ids {
            let (opportunity, _) = opportunities.get(opportunity_id).ok_or(
                PreparedSemanticResultCodecError::Inconsistent {
                    component: "finding replay opportunity",
                },
            )?;
            let (declaration, _) = declarations.get(&opportunity.declaration()).ok_or(
                PreparedSemanticResultCodecError::Inconsistent {
                    component: "finding replay declaration",
                },
            )?;
            let (domain, _) = domains.get(&opportunity.domain()).ok_or(
                PreparedSemanticResultCodecError::Inconsistent {
                    component: "finding replay domain",
                },
            )?;
            discoveries.push(ChoiceDiscovery::new(
                (*declaration).clone(),
                (*domain).clone(),
                (*opportunity).clone(),
            )?);
        }
        let replay_selections = selection_ids
            .iter()
            .map(|id| {
                selections
                    .get(id)
                    .map(|(record, _)| (*record).clone())
                    .ok_or(PreparedSemanticResultCodecError::Inconsistent {
                        component: "finding replay selection",
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let reconstructed = crate::CrucibleFindingReplayEvidence::new(
            replay.signature().cloned(),
            (*configuration).clone(),
            (*measurement).clone(),
            (*property).clone(),
            (*projection).clone(),
            discoveries,
            replay_selections,
        )?;
        if reconstructed.configuration().id()? != replay.configuration()
            || reconstructed.signature() != replay.signature()
        {
            return Err(PreparedSemanticResultCodecError::Inconsistent {
                component: "finding replay reconstruction",
            });
        }
    }
    Ok(())
}

fn indexed_by_id<T, I: Ord>(
    records: &[T],
    mut id: impl FnMut(&T) -> Result<I, CampaignCodecError>,
    canonical_bytes: impl Fn(&T) -> Vec<u8>,
) -> Result<BTreeMap<I, (&T, usize)>, PreparedSemanticResultCodecError> {
    let mut indexed = BTreeMap::new();
    for record in records {
        if indexed
            .insert(id(record)?, (record, canonical_bytes(record).len()))
            .is_some()
        {
            return Err(PreparedSemanticResultCodecError::Inconsistent {
                component: "duplicate finding replay record",
            });
        }
    }
    Ok(indexed)
}

fn charge_reference<'a, T, I: Ord>(
    records: &'a BTreeMap<I, (&'a T, usize)>,
    id: &I,
    referenced_bytes: &mut usize,
    reference_count: &mut usize,
    component: &'static str,
) -> Result<(&'a T, usize), PreparedSemanticResultCodecError> {
    let &(record, bytes) = records
        .get(id)
        .ok_or(PreparedSemanticResultCodecError::Inconsistent { component })?;
    *reference_count = reference_count
        .checked_add(1)
        .ok_or(PreparedSemanticResultCodecError::LimitExceeded)?;
    *referenced_bytes = referenced_bytes
        .checked_add(bytes)
        .ok_or(PreparedSemanticResultCodecError::LimitExceeded)?;
    if *reference_count > MAX_REPLAY_VALIDATION_REFERENCES
        || *referenced_bytes > MAX_CRUCIBLE_FINDING_REPLAY_BYTES
    {
        return Err(PreparedSemanticResultCodecError::LimitExceeded);
    }
    Ok((record, bytes))
}

pub(super) fn encode_replays(
    encoder: &mut Encoder,
    value: &PreparedCrucibleFindingCandidate,
) -> Result<(), PreparedSemanticResultCodecError> {
    let records = &value.replay_records;
    let configurations = content_positions(&records.configurations, |record| record.id())?;
    let measurements = content_positions(&records.measurements, |record| record.id())?;
    let properties = content_positions(&records.properties, |record| record.id())?;
    let coverage = content_positions(&records.coverage, |record| record.id())?;
    let opportunities = content_positions(&records.opportunities, |record| record.id())?;
    let selections = content_positions(&records.selections, |record| record.id())?;
    let indexes = ReplayRecordIndexes {
        configurations,
        measurements,
        properties,
        coverage,
        opportunities,
        selections,
    };
    encode_replay_pass(encoder, &value.minimization_replays, &indexes)?;
    encode_replay_pass(encoder, &value.verification_replays, &indexes)
}

fn content_positions<T, I>(
    records: &[T],
    mut id: impl FnMut(&T) -> Result<I, CampaignCodecError>,
) -> Result<BTreeMap<crucible_cas::content_store::ContentId, usize>, PreparedSemanticResultCodecError>
where
    I: ContentIdentity,
{
    let mut positions = BTreeMap::new();
    for (index, record) in records.iter().enumerate() {
        if positions.insert(id(record)?.content_id(), index).is_some() {
            return Err(PreparedSemanticResultCodecError::Inconsistent {
                component: "duplicate finding replay record",
            });
        }
    }
    Ok(positions)
}

trait ContentIdentity {
    fn content_id(self) -> crucible_cas::content_store::ContentId;
}

macro_rules! content_identity {
    ($($type:ty),+ $(,)?) => {$(
        impl ContentIdentity for $type {
            fn content_id(self) -> crucible_cas::content_store::ContentId {
                self.content_id()
            }
        }
    )+};
}

content_identity!(
    crucible_campaign::ConfigurationArtifactId,
    crucible_campaign::MeasurementSetId,
    crucible_campaign::PropertyVerdictSetId,
    crucible_campaign::CoverageProjectionId,
    crucible_campaign::ChoiceOpportunityId,
    crucible_campaign::SelectionId,
);

struct ReplayRecordIndexes {
    configurations: BTreeMap<crucible_cas::content_store::ContentId, usize>,
    measurements: BTreeMap<crucible_cas::content_store::ContentId, usize>,
    properties: BTreeMap<crucible_cas::content_store::ContentId, usize>,
    coverage: BTreeMap<crucible_cas::content_store::ContentId, usize>,
    opportunities: BTreeMap<crucible_cas::content_store::ContentId, usize>,
    selections: BTreeMap<crucible_cas::content_store::ContentId, usize>,
}

fn encode_replay_pass(
    encoder: &mut Encoder,
    replays: &[RecordedFindingReplay],
    indexes: &ReplayRecordIndexes,
) -> Result<(), PreparedSemanticResultCodecError> {
    encoder.count(replays.len())?;
    for replay in replays {
        encoder.byte(if replay.incompatibility().is_some() {
            1
        } else {
            0
        })?;
        encoder.index(find_index(
            &indexes.configurations,
            replay.configuration().content_id(),
        )?)?;
        if let Some(reason) = replay.incompatibility() {
            encoder.byte(incompatibility_tag(reason))?;
            continue;
        }
        let Some((measurements, properties, coverage, opportunities, selections)) =
            replay.observed_components()
        else {
            return Err(inconsistent("finding replay outcome"));
        };
        encoder.index(find_index(
            &indexes.measurements,
            measurements.content_id(),
        )?)?;
        encoder.index(find_index(&indexes.properties, properties.content_id())?)?;
        encoder.index(find_index(&indexes.coverage, coverage.content_id())?)?;
        encoder.count(opportunities.len())?;
        for opportunity in opportunities {
            encoder.index(find_index(
                &indexes.opportunities,
                opportunity.content_id(),
            )?)?;
        }
        encoder.count(selections.len())?;
        for selection in selections {
            encoder.index(find_index(&indexes.selections, selection.content_id())?)?;
        }
    }
    Ok(())
}

pub(super) fn find_index(
    indexes: &BTreeMap<crucible_cas::content_store::ContentId, usize>,
    id: crucible_cas::content_store::ContentId,
) -> Result<usize, PreparedSemanticResultCodecError> {
    indexes
        .get(&id)
        .copied()
        .ok_or(PreparedSemanticResultCodecError::Inconsistent {
            component: "finding replay record index",
        })
}

#[derive(Clone, Debug)]
pub(super) enum ReplayIndexes {
    Observed {
        configuration: usize,
        measurements: usize,
        properties: usize,
        coverage: usize,
        opportunities: Vec<usize>,
        selections: Vec<usize>,
    },
    DeterministicallyIncompatible {
        configuration: usize,
        reason: FindingReplayIncompatibility,
    },
}

pub(super) fn decode_replay_indexes(
    decoder: &mut Decoder<'_>,
    validation_references: &mut usize,
) -> Result<Vec<ReplayIndexes>, PreparedSemanticResultCodecError> {
    let count = decoder.count_bounded(MAX_CRUCIBLE_FINDING_REPLAY_RECORDS)?;
    charge_validation_references(validation_references, count, 4)?;
    // tag + configuration index + closed incompatibility reason
    let minimum_entry_bytes = 2 + size_of::<u32>();
    decoder.preflight_collection(count, minimum_entry_bytes)?;
    let mut replays = Vec::with_capacity(count);
    for _ in 0..count {
        let incompatible = match decoder.byte()? {
            0 => false,
            1 => true,
            _ => return Err(PreparedSemanticResultCodecError::InvalidTag),
        };
        let configuration = decoder.index()?;
        if incompatible {
            replays.push(ReplayIndexes::DeterministicallyIncompatible {
                configuration,
                reason: incompatibility_from_tag(decoder.byte()?)?,
            });
            continue;
        }
        let measurements = decoder.index()?;
        let properties = decoder.index()?;
        let coverage = decoder.index()?;
        let opportunity_count = decoder.count_bounded(MAX_CRUCIBLE_FINDING_REPLAY_RECORDS)?;
        charge_validation_references(validation_references, opportunity_count, 3)?;
        decoder.preflight_collection(opportunity_count, size_of::<u32>())?;
        let mut opportunities = Vec::with_capacity(opportunity_count);
        for _ in 0..opportunity_count {
            opportunities.push(decoder.index()?);
        }
        let selection_count = decoder.count_bounded(MAX_CRUCIBLE_FINDING_REPLAY_RECORDS)?;
        charge_validation_references(validation_references, selection_count, 1)?;
        decoder.preflight_collection(selection_count, size_of::<u32>())?;
        let mut selections = Vec::with_capacity(selection_count);
        for _ in 0..selection_count {
            selections.push(decoder.index()?);
        }
        replays.push(ReplayIndexes::Observed {
            configuration,
            measurements,
            properties,
            coverage,
            opportunities,
            selections,
        });
    }
    Ok(replays)
}

const fn incompatibility_tag(reason: FindingReplayIncompatibility) -> u8 {
    match reason {
        FindingReplayIncompatibility::PrefixDiverged => 0,
        FindingReplayIncompatibility::PrefixTerminated => 1,
        FindingReplayIncompatibility::SelectionMismatch => 2,
    }
}

pub(super) fn incompatibility_from_tag(
    tag: u8,
) -> Result<FindingReplayIncompatibility, PreparedSemanticResultCodecError> {
    match tag {
        0 => Ok(FindingReplayIncompatibility::PrefixDiverged),
        1 => Ok(FindingReplayIncompatibility::PrefixTerminated),
        2 => Ok(FindingReplayIncompatibility::SelectionMismatch),
        _ => Err(PreparedSemanticResultCodecError::InvalidTag),
    }
}

pub(super) fn charge_validation_references(
    current: &mut usize,
    records: usize,
    references_per_record: usize,
) -> Result<(), PreparedSemanticResultCodecError> {
    *current = records
        .checked_mul(references_per_record)
        .and_then(|additional| current.checked_add(additional))
        .ok_or(PreparedSemanticResultCodecError::LimitExceeded)?;
    if *current > MAX_REPLAY_VALIDATION_REFERENCES {
        return Err(PreparedSemanticResultCodecError::LimitExceeded);
    }
    Ok(())
}

pub(super) struct ReplayMaterialTables<'a> {
    pub(super) signatures: &'a [Option<crucible_campaign::FindingSignature>],
    pub(super) configurations: &'a [crucible_campaign::ConfigurationArtifactId],
    pub(super) measurements: &'a [crucible_campaign::MeasurementSetId],
    pub(super) properties: &'a [crucible_campaign::PropertyVerdictSetId],
    pub(super) coverage: &'a [crucible_campaign::CoverageProjectionId],
    pub(super) opportunities: &'a [crucible_campaign::ChoiceOpportunityId],
    pub(super) selections: &'a [crucible_campaign::SelectionId],
}

pub(super) fn materialize_replays(
    indexes: &[ReplayIndexes],
    tables: ReplayMaterialTables<'_>,
) -> Result<Vec<RecordedFindingReplay>, PreparedSemanticResultCodecError> {
    if indexes.len() != tables.signatures.len() {
        return Err(PreparedSemanticResultCodecError::Inconsistent {
            component: "finding replay signature count",
        });
    }
    indexes
        .iter()
        .zip(tables.signatures)
        .map(|(indexes, signature)| match indexes {
            ReplayIndexes::Observed {
                configuration,
                measurements: measurement,
                properties: property,
                coverage: projection,
                opportunities: opportunity_indexes,
                selections: selection_indexes,
            } => Ok(RecordedFindingReplay::Observed {
                signature: signature.clone().map(Box::new),
                configuration: *indexed(tables.configurations, *configuration)?,
                measurements: *indexed(tables.measurements, *measurement)?,
                properties: *indexed(tables.properties, *property)?,
                coverage: *indexed(tables.coverage, *projection)?,
                opportunities: opportunity_indexes
                    .iter()
                    .map(|index| indexed(tables.opportunities, *index).copied())
                    .collect::<Result<Vec<_>, PreparedSemanticResultCodecError>>()?,
                selections: selection_indexes
                    .iter()
                    .map(|index| indexed(tables.selections, *index).copied())
                    .collect::<Result<Vec<_>, PreparedSemanticResultCodecError>>()?,
            }),
            ReplayIndexes::DeterministicallyIncompatible {
                configuration,
                reason,
            } => {
                if signature.is_some() {
                    return Err(inconsistent("incompatible replay signature"));
                }
                Ok(RecordedFindingReplay::DeterministicallyIncompatible {
                    configuration: *indexed(tables.configurations, *configuration)?,
                    reason: *reason,
                })
            }
        })
        .collect()
}

pub(super) fn record_ids<T, I>(
    records: &[T],
    mut id: impl FnMut(&T) -> Result<I, CampaignCodecError>,
) -> Result<Vec<I>, PreparedSemanticResultCodecError> {
    records
        .iter()
        .map(|record| id(record).map_err(Into::into))
        .collect()
}

fn indexed<T>(records: &[T], index: usize) -> Result<&T, PreparedSemanticResultCodecError> {
    records
        .get(index)
        .ok_or(PreparedSemanticResultCodecError::Inconsistent {
            component: "finding replay record index",
        })
}

pub(super) const fn discovery_path_tag(path: crucible::FindingDiscoveryPath) -> u8 {
    match path {
        crucible::FindingDiscoveryPath::CampaignFork => 0,
        crucible::FindingDiscoveryPath::StateSpaceSearch => 1,
        crucible::FindingDiscoveryPath::CoverageGuidedFuzzing => 2,
        crucible::FindingDiscoveryPath::RetainedCorpusEntry => 3,
    }
}

pub(super) fn discovery_path_from_tag(
    tag: u8,
) -> Result<crucible::FindingDiscoveryPath, PreparedSemanticResultCodecError> {
    match tag {
        0 => Ok(crucible::FindingDiscoveryPath::CampaignFork),
        1 => Ok(crucible::FindingDiscoveryPath::StateSpaceSearch),
        2 => Ok(crucible::FindingDiscoveryPath::CoverageGuidedFuzzing),
        3 => Ok(crucible::FindingDiscoveryPath::RetainedCorpusEntry),
        _ => Err(PreparedSemanticResultCodecError::InvalidTag),
    }
}

pub(super) struct ReplayRecordTables<'a> {
    pub(super) configurations: &'a [ConfigurationArtifact],
    pub(super) measurements: &'a [MeasurementSet],
    pub(super) properties: &'a [PropertyVerdictSet],
    pub(super) coverage: &'a [CoverageProjection],
    pub(super) declarations: &'a [SelectableDeclaration],
    pub(super) domains: &'a [ChoiceDomain],
    pub(super) opportunities: &'a [ChoiceOpportunity],
    pub(super) selections: &'a [Selection],
}

pub(super) fn replay_record_totals(
    tables: ReplayRecordTables<'_>,
    bundle: &FindingCandidateBundle,
) -> Result<(usize, usize), PreparedSemanticResultCodecError> {
    let mut identities = BTreeSet::new();
    let mut bytes = 0usize;
    macro_rules! charge {
        ($records:expr, $id:ident) => {
            for record in $records {
                if !identities.insert(record.$id()?.content_id()) {
                    return Err(PreparedSemanticResultCodecError::Inconsistent {
                        component: "duplicate finding replay record",
                    });
                }
                bytes = bytes
                    .checked_add(record.canonical_bytes().len())
                    .ok_or(PreparedSemanticResultCodecError::LimitExceeded)?;
            }
        };
    }
    charge!(tables.configurations, id);
    charge!(tables.measurements, id);
    charge!(tables.properties, id);
    charge!(tables.coverage, id);
    charge!(tables.declarations, id);
    charge!(tables.domains, id);
    charge!(tables.opportunities, id);
    charge!(tables.selections, id);
    for signature in bundle
        .signature_minimization()
        .minimization_pass()
        .iter()
        .chain(bundle.signature_minimization().verification_pass().iter())
        .flatten()
    {
        bytes = bytes
            .checked_add(signature.canonical_bytes().len())
            .ok_or(PreparedSemanticResultCodecError::LimitExceeded)?;
    }
    if identities.len() > MAX_CRUCIBLE_FINDING_REPLAY_RECORDS
        || bytes > MAX_CRUCIBLE_FINDING_REPLAY_BYTES
    {
        return Err(PreparedSemanticResultCodecError::LimitExceeded);
    }
    Ok((identities.len(), bytes))
}

pub(super) fn encode_records<T>(
    encoder: &mut Encoder,
    records: &[T],
    encode: fn(&T) -> Vec<u8>,
) -> Result<(), PreparedSemanticResultCodecError> {
    encoder.count(records.len())?;
    for record in records {
        encoder.record(&encode(record))?;
    }
    Ok(())
}

pub(super) struct Encoder {
    bytes: Vec<u8>,
    records: usize,
    maximum_bytes: usize,
}

impl Encoder {
    pub(super) fn new(maximum_bytes: usize) -> Self {
        Self {
            bytes: Vec::new(),
            records: 0,
            maximum_bytes,
        }
    }

    pub(super) fn finish(self) -> Result<Vec<u8>, PreparedSemanticResultCodecError> {
        if self.bytes.len() > self.maximum_bytes {
            Err(PreparedSemanticResultCodecError::LimitExceeded)
        } else {
            Ok(self.bytes)
        }
    }

    pub(super) fn raw(&mut self, bytes: &[u8]) -> Result<(), PreparedSemanticResultCodecError> {
        self.reserve(bytes.len())?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    pub(super) fn byte(&mut self, value: u8) -> Result<(), PreparedSemanticResultCodecError> {
        self.raw(&[value])
    }

    pub(super) fn count(&mut self, count: usize) -> Result<(), PreparedSemanticResultCodecError> {
        let count =
            u32::try_from(count).map_err(|_| PreparedSemanticResultCodecError::LimitExceeded)?;
        self.raw(&count.to_be_bytes())
    }

    pub(super) fn index(&mut self, index: usize) -> Result<(), PreparedSemanticResultCodecError> {
        let index =
            u32::try_from(index).map_err(|_| PreparedSemanticResultCodecError::LimitExceeded)?;
        self.raw(&index.to_be_bytes())
    }

    pub(super) fn record(&mut self, record: &[u8]) -> Result<(), PreparedSemanticResultCodecError> {
        if record.len() > MAX_RECORD_BYTES || self.records == MAX_PREPARED_RESULT_RECORDS {
            return Err(PreparedSemanticResultCodecError::LimitExceeded);
        }
        self.records += 1;
        let length = u32::try_from(record.len())
            .map_err(|_| PreparedSemanticResultCodecError::LimitExceeded)?;
        self.raw(&length.to_be_bytes())?;
        self.raw(record)
    }

    pub(super) fn reserve(
        &mut self,
        additional: usize,
    ) -> Result<(), PreparedSemanticResultCodecError> {
        if self
            .bytes
            .len()
            .checked_add(additional)
            .is_none_or(|length| length > self.maximum_bytes)
        {
            return Err(PreparedSemanticResultCodecError::LimitExceeded);
        }
        self.bytes.reserve(additional);
        Ok(())
    }
}

pub(super) struct Decoder<'a> {
    remaining: &'a [u8],
    records: usize,
}

impl<'a> Decoder<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self {
            remaining: bytes,
            records: 0,
        }
    }

    pub(super) fn finish(self) -> Result<(), PreparedSemanticResultCodecError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(PreparedSemanticResultCodecError::TrailingBytes)
        }
    }

    pub(super) fn magic(
        &mut self,
        expected: &[u8],
    ) -> Result<(), PreparedSemanticResultCodecError> {
        if self.take(expected.len())? == expected {
            Ok(())
        } else {
            Err(PreparedSemanticResultCodecError::NonCanonical)
        }
    }

    pub(super) fn byte(&mut self) -> Result<u8, PreparedSemanticResultCodecError> {
        Ok(self.take(1)?[0])
    }

    pub(super) fn count(&mut self) -> Result<usize, PreparedSemanticResultCodecError> {
        let count = u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| PreparedSemanticResultCodecError::Truncated)?,
        ) as usize;
        if count > MAX_PREPARED_RESULT_RECORDS.saturating_sub(self.records) {
            return Err(PreparedSemanticResultCodecError::LimitExceeded);
        }
        Ok(count)
    }

    pub(super) fn count_bounded(
        &mut self,
        maximum: usize,
    ) -> Result<usize, PreparedSemanticResultCodecError> {
        let count = self.count()?;
        if count > maximum {
            return Err(PreparedSemanticResultCodecError::LimitExceeded);
        }
        Ok(count)
    }

    pub(super) fn index(&mut self) -> Result<usize, PreparedSemanticResultCodecError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| PreparedSemanticResultCodecError::Truncated)?,
        ) as usize)
    }

    pub(super) fn record(&mut self) -> Result<&'a [u8], PreparedSemanticResultCodecError> {
        if self.records == MAX_PREPARED_RESULT_RECORDS {
            return Err(PreparedSemanticResultCodecError::LimitExceeded);
        }
        self.records += 1;
        let length = u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| PreparedSemanticResultCodecError::Truncated)?,
        ) as usize;
        if length > MAX_RECORD_BYTES {
            return Err(PreparedSemanticResultCodecError::LimitExceeded);
        }
        self.take(length)
    }

    pub(super) fn decode_record<T>(
        &mut self,
        decode: fn(&[u8]) -> Result<T, CampaignCodecError>,
    ) -> Result<T, PreparedSemanticResultCodecError> {
        decode(self.record()?).map_err(Into::into)
    }

    pub(super) fn decode_replay_records<T>(
        &mut self,
        decode: fn(&[u8]) -> Result<T, CampaignCodecError>,
        aggregate_count: &mut usize,
        aggregate_bytes: &mut usize,
    ) -> Result<Vec<T>, PreparedSemanticResultCodecError> {
        let remaining = MAX_CRUCIBLE_FINDING_REPLAY_RECORDS
            .checked_sub(*aggregate_count)
            .ok_or(PreparedSemanticResultCodecError::LimitExceeded)?;
        let count = self.count_bounded(remaining)?;
        *aggregate_count += count;
        self.preflight_collection(count, size_of::<u32>())?;

        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let bytes = self.record()?;
            *aggregate_bytes = aggregate_bytes
                .checked_add(bytes.len())
                .ok_or(PreparedSemanticResultCodecError::LimitExceeded)?;
            if *aggregate_bytes > MAX_CRUCIBLE_FINDING_REPLAY_BYTES {
                return Err(PreparedSemanticResultCodecError::LimitExceeded);
            }
            records.push(decode(bytes)?);
        }
        Ok(records)
    }

    pub(super) fn preflight_collection(
        &self,
        count: usize,
        minimum_entry_bytes: usize,
    ) -> Result<(), PreparedSemanticResultCodecError> {
        let minimum_bytes = count
            .checked_mul(minimum_entry_bytes)
            .ok_or(PreparedSemanticResultCodecError::LimitExceeded)?;
        if minimum_bytes > self.remaining.len() {
            return Err(PreparedSemanticResultCodecError::Truncated);
        }
        Ok(())
    }

    pub(super) fn take(
        &mut self,
        length: usize,
    ) -> Result<&'a [u8], PreparedSemanticResultCodecError> {
        if self.remaining.len() < length {
            return Err(PreparedSemanticResultCodecError::Truncated);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }
}
