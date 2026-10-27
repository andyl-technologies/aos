//! Canonical replay-record indexing, encoding, and materialization.
//!
//! Retained replay records live in a record store and are named here only by
//! identity. Validation reads each record when it is needed and drops it
//! afterwards, so no pass holds more than one replay's records at once.

use super::*;
use crate::{ReplayRecord, load_replay_record_by_content};
use crucible_campaign::{ChoiceDomainId, ChoiceOpportunityId, SelectableId};
use crucible_store::content_store::ContentId;

/// Canonical byte length of every retained record, by identity.
///
/// Building the index reads and authenticates each record once. Only
/// identities, lengths, and each opportunity's two references stay resident.
struct ReplayRecordIndex {
    lengths: BTreeMap<ContentId, usize>,
    opportunity_references: BTreeMap<ChoiceOpportunityId, (SelectableId, ChoiceDomainId)>,
}

impl ReplayRecordIndex {
    fn build(
        records: &PreparedFindingReplayRecords,
    ) -> Result<Self, PreparedSemanticResultCodecError> {
        let mut index = Self {
            lengths: BTreeMap::new(),
            opportunity_references: BTreeMap::new(),
        };
        let ids = &records.ids;
        index.measure::<ConfigurationArtifact>(records, &ids.configurations)?;
        index.measure::<MeasurementSet>(records, &ids.measurements)?;
        index.measure::<PropertyVerdictSet>(records, &ids.properties)?;
        index.measure::<CoverageProjection>(records, &ids.coverage)?;
        index.measure::<SelectableDeclaration>(records, &ids.declarations)?;
        index.measure::<ChoiceDomain>(records, &ids.domains)?;
        index.measure::<Selection>(records, &ids.selections)?;
        for id in &ids.opportunities {
            let (opportunity, length) = load_replay_record::<ChoiceOpportunity>(records, *id)?;
            index.insert(id.content_id(), length)?;
            index
                .opportunity_references
                .insert(*id, (opportunity.declaration(), opportunity.domain()));
        }
        Ok(index)
    }

    fn measure<T: ReplayRecord>(
        &mut self,
        records: &PreparedFindingReplayRecords,
        ids: &[T::Id],
    ) -> Result<(), PreparedSemanticResultCodecError> {
        for id in ids {
            let (_, length) = load_replay_record::<T>(records, *id)?;
            self.insert(T::content_id(*id), length)?;
        }
        Ok(())
    }

    fn insert(
        &mut self,
        id: ContentId,
        length: usize,
    ) -> Result<(), PreparedSemanticResultCodecError> {
        if self.lengths.insert(id, length).is_some() {
            return Err(inconsistent("duplicate finding replay record"));
        }
        Ok(())
    }
}

/// Reads one record and its canonical length through the prepared sources.
fn load_replay_record<T: ReplayRecord>(
    records: &PreparedFindingReplayRecords,
    id: T::Id,
) -> Result<(T, usize), PreparedSemanticResultCodecError> {
    crate::load_replay_record::<T>(&records.sources, id).map_err(Into::into)
}

/// Repeated-reference budget for one journal's replay reconstruction.
///
/// A compact journal may refer to one large record from every replay, so the
/// copy work of reconstruction is charged per reference before it starts.
struct ReferenceCharge<'a> {
    index: &'a ReplayRecordIndex,
    bytes: u64,
    count: usize,
}

impl ReferenceCharge<'_> {
    fn charge(
        &mut self,
        id: ContentId,
        component: &'static str,
    ) -> Result<(), PreparedSemanticResultCodecError> {
        let length = self
            .index
            .lengths
            .get(&id)
            .ok_or(PreparedSemanticResultCodecError::Inconsistent { component })?;
        self.count = self
            .count
            .checked_add(1)
            .ok_or(PreparedSemanticResultCodecError::LimitExceeded)?;
        self.bytes = self.bytes.saturating_add(*length as u64);
        if self.count > MAX_REPLAY_VALIDATION_REFERENCES
            || self.bytes > MAX_CRUCIBLE_FINDING_REPLAY_BYTES
        {
            return Err(PreparedSemanticResultCodecError::LimitExceeded);
        }
        Ok(())
    }
}

pub(super) fn validate_recorded_replays(
    value: &PreparedCrucibleFindingCandidate,
) -> Result<(), PreparedSemanticResultCodecError> {
    let records = &value.replay_records;
    let index = ReplayRecordIndex::build(records)?;
    let replays = || {
        value
            .minimization_replays
            .iter()
            .chain(&value.verification_replays)
    };

    // Charge every reference before reconstructing any owned evidence value.
    let mut charge = ReferenceCharge {
        index: &index,
        bytes: 0,
        count: 0,
    };
    for replay in replays() {
        charge.charge(
            replay.configuration().content_id(),
            "finding replay configuration",
        )?;
        let Some((measurement_id, property_id, coverage_id, opportunity_ids, selection_ids)) =
            replay.observed_components()
        else {
            continue;
        };
        charge.charge(measurement_id.content_id(), "finding replay measurements")?;
        charge.charge(property_id.content_id(), "finding replay properties")?;
        charge.charge(coverage_id.content_id(), "finding replay coverage")?;
        for opportunity_id in opportunity_ids {
            charge.charge(opportunity_id.content_id(), "finding replay opportunity")?;
            let (declaration, domain) = index
                .opportunity_references
                .get(opportunity_id)
                .ok_or_else(|| inconsistent("finding replay opportunity"))?;
            charge.charge(declaration.content_id(), "finding replay declaration")?;
            charge.charge(domain.content_id(), "finding replay domain")?;
        }
        for selection_id in selection_ids {
            charge.charge(selection_id.content_id(), "finding replay selection")?;
        }
    }

    // Reconstruct one replay at a time; its records drop before the next.
    for replay in replays() {
        let Some((measurement_id, property_id, coverage_id, opportunity_ids, selection_ids)) =
            replay.observed_components()
        else {
            continue;
        };
        let (configuration, _) =
            load_replay_record::<ConfigurationArtifact>(records, replay.configuration())?;
        let (measurement, _) = load_replay_record::<MeasurementSet>(records, measurement_id)?;
        let (property, _) = load_replay_record::<PropertyVerdictSet>(records, property_id)?;
        let (projection, _) = load_replay_record::<CoverageProjection>(records, coverage_id)?;

        let mut discoveries = Vec::with_capacity(opportunity_ids.len());
        for opportunity_id in opportunity_ids {
            let (opportunity, _) =
                load_replay_record::<ChoiceOpportunity>(records, *opportunity_id)?;
            let (declaration, _) =
                load_replay_record::<SelectableDeclaration>(records, opportunity.declaration())?;
            let (domain, _) = load_replay_record::<ChoiceDomain>(records, opportunity.domain())?;
            discoveries.push(ChoiceDiscovery::new(declaration, domain, opportunity)?);
        }
        let replay_selections = selection_ids
            .iter()
            .map(|id| load_replay_record::<Selection>(records, *id).map(|(record, _)| record))
            .collect::<Result<Vec<_>, _>>()?;

        let reconstructed = crate::CrucibleFindingReplayEvidence::new(
            replay.signature().cloned(),
            configuration,
            measurement,
            property,
            projection,
            discoveries,
            replay_selections,
        )?;
        if reconstructed.configuration().id()? != replay.configuration()
            || reconstructed.signature() != replay.signature()
        {
            return Err(inconsistent("finding replay reconstruction"));
        }
    }
    Ok(())
}

/// Encodes the eight identity tables in canonical table order.
pub(super) fn encode_record_ids(
    encoder: &mut Encoder,
    ids: &ReplayRecordIds,
) -> Result<(), PreparedSemanticResultCodecError> {
    encode_id_table(encoder, &ids.configurations, |id| id.content_id())?;
    encode_id_table(encoder, &ids.measurements, |id| id.content_id())?;
    encode_id_table(encoder, &ids.properties, |id| id.content_id())?;
    encode_id_table(encoder, &ids.coverage, |id| id.content_id())?;
    encode_id_table(encoder, &ids.declarations, |id| id.content_id())?;
    encode_id_table(encoder, &ids.domains, |id| id.content_id())?;
    encode_id_table(encoder, &ids.opportunities, |id| id.content_id())?;
    encode_id_table(encoder, &ids.selections, |id| id.content_id())
}

fn encode_id_table<I: Copy>(
    encoder: &mut Encoder,
    ids: &[I],
    content_id: impl Fn(I) -> ContentId,
) -> Result<(), PreparedSemanticResultCodecError> {
    encoder.count(ids.len())?;
    for id in ids {
        encoder.content_id(content_id(*id))?;
    }
    Ok(())
}

/// Decodes the eight identity tables and types each identity by its record.
///
/// Every named record is read from `sources` once and authenticated, which
/// also yields its typed identity and canonical length. Returns the tables
/// with the distinct record count and aggregate canonical bytes.
pub(super) fn decode_record_ids(
    decoder: &mut Decoder<'_>,
    sources: &crate::ReplayRecordSources,
) -> Result<(ReplayRecordIds, usize, u64), PreparedSemanticResultCodecError> {
    let mut tally = RecordTally {
        sources,
        seen: BTreeSet::new(),
        bytes: 0,
    };
    let ids = ReplayRecordIds {
        configurations: tally.table::<ConfigurationArtifact>(decoder)?,
        measurements: tally.table::<MeasurementSet>(decoder)?,
        properties: tally.table::<PropertyVerdictSet>(decoder)?,
        coverage: tally.table::<CoverageProjection>(decoder)?,
        declarations: tally.table::<SelectableDeclaration>(decoder)?,
        domains: tally.table::<ChoiceDomain>(decoder)?,
        opportunities: tally.table::<ChoiceOpportunity>(decoder)?,
        selections: tally.table::<Selection>(decoder)?,
    };
    Ok((ids, tally.seen.len(), tally.bytes))
}

/// Distinct identities and canonical bytes of the tables decoded so far.
struct RecordTally<'a> {
    sources: &'a crate::ReplayRecordSources,
    seen: BTreeSet<ContentId>,
    bytes: u64,
}

impl RecordTally<'_> {
    fn table<T: ReplayRecord>(
        &mut self,
        decoder: &mut Decoder<'_>,
    ) -> Result<Vec<T::Id>, PreparedSemanticResultCodecError> {
        let remaining = MAX_CRUCIBLE_FINDING_REPLAY_RECORDS - self.seen.len();
        let count = decoder.index_count(remaining)?;
        decoder.preflight_collection(count, 1)?;

        let mut ids = Vec::with_capacity(count);
        for _ in 0..count {
            let content = decoder.content_id()?;
            if !self.seen.insert(content) {
                return Err(inconsistent("duplicate finding replay record"));
            }
            let (id, length) = load_replay_record_by_content::<T>(self.sources, content)?;
            self.bytes = self.bytes.saturating_add(length as u64);
            ids.push(id);
        }
        Ok(ids)
    }
}

pub(super) fn encode_replays(
    encoder: &mut Encoder,
    value: &PreparedCrucibleFindingCandidate,
) -> Result<(), PreparedSemanticResultCodecError> {
    let ids = &value.replay_records.ids;
    let configurations = content_positions(&ids.configurations)?;
    let measurements = content_positions(&ids.measurements)?;
    let properties = content_positions(&ids.properties)?;
    let coverage = content_positions(&ids.coverage)?;
    let opportunities = content_positions(&ids.opportunities)?;
    let selections = content_positions(&ids.selections)?;
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

fn content_positions<I>(
    ids: &[I],
) -> Result<
    BTreeMap<crucible_store::content_store::ContentId, usize>,
    PreparedSemanticResultCodecError,
>
where
    I: ContentIdentity + Copy,
{
    let mut positions = BTreeMap::new();
    for (index, id) in ids.iter().enumerate() {
        if positions.insert(id.content_id(), index).is_some() {
            return Err(PreparedSemanticResultCodecError::Inconsistent {
                component: "duplicate finding replay record",
            });
        }
    }
    Ok(positions)
}

trait ContentIdentity {
    fn content_id(self) -> crucible_store::content_store::ContentId;
}

macro_rules! content_identity {
    ($($type:ty),+ $(,)?) => {$(
        impl ContentIdentity for $type {
            fn content_id(self) -> crucible_store::content_store::ContentId {
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
    configurations: BTreeMap<crucible_store::content_store::ContentId, usize>,
    measurements: BTreeMap<crucible_store::content_store::ContentId, usize>,
    properties: BTreeMap<crucible_store::content_store::ContentId, usize>,
    coverage: BTreeMap<crucible_store::content_store::ContentId, usize>,
    opportunities: BTreeMap<crucible_store::content_store::ContentId, usize>,
    selections: BTreeMap<crucible_store::content_store::ContentId, usize>,
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
    indexes: &BTreeMap<crucible_store::content_store::ContentId, usize>,
    id: crucible_store::content_store::ContentId,
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
    let count = decoder.index_count(MAX_CRUCIBLE_FINDING_REPLAYS_PER_PASS)?;
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
        let opportunity_count = decoder.index_count(MAX_REPLAY_VALIDATION_REFERENCES)?;
        charge_validation_references(validation_references, opportunity_count, 3)?;
        decoder.preflight_collection(opportunity_count, size_of::<u32>())?;
        let mut opportunities = Vec::with_capacity(opportunity_count);
        for _ in 0..opportunity_count {
            opportunities.push(decoder.index()?);
        }
        let selection_count = decoder.index_count(MAX_REPLAY_VALIDATION_REFERENCES)?;
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

fn indexed<T>(records: &[T], index: usize) -> Result<&T, PreparedSemanticResultCodecError> {
    records
        .get(index)
        .ok_or(PreparedSemanticResultCodecError::Inconsistent {
            component: "finding replay record index",
        })
}

pub(super) const fn discovery_path_tag(path: crucible_engine::FindingDiscoveryPath) -> u8 {
    match path {
        crucible_engine::FindingDiscoveryPath::CampaignFork => 0,
        crucible_engine::FindingDiscoveryPath::StateSpaceSearch => 1,
        crucible_engine::FindingDiscoveryPath::CoverageGuidedFuzzing => 2,
        crucible_engine::FindingDiscoveryPath::RetainedCorpusEntry => 3,
    }
}

pub(super) fn discovery_path_from_tag(
    tag: u8,
) -> Result<crucible_engine::FindingDiscoveryPath, PreparedSemanticResultCodecError> {
    match tag {
        0 => Ok(crucible_engine::FindingDiscoveryPath::CampaignFork),
        1 => Ok(crucible_engine::FindingDiscoveryPath::StateSpaceSearch),
        2 => Ok(crucible_engine::FindingDiscoveryPath::CoverageGuidedFuzzing),
        3 => Ok(crucible_engine::FindingDiscoveryPath::RetainedCorpusEntry),
        _ => Err(PreparedSemanticResultCodecError::InvalidTag),
    }
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

    /// Writes one content identity as a u8-length-prefixed canonical string.
    pub(super) fn content_id(
        &mut self,
        id: crucible_store::content_store::ContentId,
    ) -> Result<(), PreparedSemanticResultCodecError> {
        let encoded = id.encode();
        let length = u8::try_from(encoded.len())
            .map_err(|_| PreparedSemanticResultCodecError::LimitExceeded)?;
        self.byte(length)?;
        self.raw(encoded.as_bytes())
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

    /// Reads the length of an identity or index list.
    ///
    /// Identity lists hold no payload records, so they are bounded by
    /// `maximum` rather than by the payload record count.
    pub(super) fn index_count(
        &mut self,
        maximum: usize,
    ) -> Result<usize, PreparedSemanticResultCodecError> {
        let count = u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| PreparedSemanticResultCodecError::Truncated)?,
        ) as usize;
        if count > maximum {
            return Err(PreparedSemanticResultCodecError::LimitExceeded);
        }
        Ok(count)
    }

    /// Reads one content identity written by [`Encoder::content_id`].
    pub(super) fn content_id(
        &mut self,
    ) -> Result<crucible_store::content_store::ContentId, PreparedSemanticResultCodecError> {
        let length = usize::from(self.byte()?);
        let encoded = std::str::from_utf8(self.take(length)?)
            .map_err(|_| PreparedSemanticResultCodecError::NonCanonical)?;
        crucible_store::content_store::ContentId::parse(encoded)
            .map_err(|_| PreparedSemanticResultCodecError::NonCanonical)
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
