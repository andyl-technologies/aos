//! Per-finding evidence records and their occurrence chunks.
//!
//! A findings ledger names one evidence record per finding. The record lists
//! the finding-level exchanges by content address, the report projection blob,
//! and the occurrence chunks in order:
//!
//! ```text
//! crucible.failure-triage.finding-evidence.v2
//! campaign=nightly-search
//! snapshot=crucible-campaign-snapshot:...
//! finding=crucible-campaign-finding:...
//! membership=<request hash> <response hash>
//! observation=<request hash> <response hash>
//! reproduction=<request hash> <response hash>
//! reproduction_segments=<hash>
//! minimized=<request hash> <response hash>
//! minimized_segments=<hash>
//! report=<hash>
//! occurrence_count=1
//! occurrence_chunk_count=1
//! occurrence_chunk.0=<hash>
//! ```
//!
//! A `*_segments` hash names the segment list of that reproduction's payload
//! segment exchanges (see the `reproduction` module). `minimized=none` and
//! `minimized_segments=none` record a finding without a minimized
//! reproduction. Each chunk holds at most [`MAX_OCCURRENCES_PER_CHUNK`]
//! consecutive occurrences. An occurrence names its page exchange, its three
//! object exchanges, both reproductions' segment lists, and, when its bundle
//! carries triage evidence, the ordered segment exchanges of all four replay
//! roles, each followed by the segment list of the attempt-log segments that
//! role's record names (see the `triage_segments` module):
//!
//! ```text
//! crucible.failure-triage.finding-occurrences.v3
//! first_occurrence=0
//! occurrence_count=1
//! occurrence.0.page=<request hash> <response hash>
//! occurrence.0.observation=<request hash> <response hash>
//! occurrence.0.reproduction=<request hash> <response hash>
//! occurrence.0.reproduction_segments=<hash>
//! occurrence.0.minimized=<request hash> <response hash>
//! occurrence.0.minimized_segments=<hash>
//! occurrence.0.triage=present
//! occurrence.0.minimization_original.segment_count=1
//! occurrence.0.minimization_original.segment.0=<request hash> <response hash>
//! occurrence.0.minimization_original.log_segments=<hash>
//! ...
//! ```
//!
//! `occurrence.N.triage=none` omits the role lines. Both formats are strict:
//! every line appears in this order exactly once, numbers use their shortest
//! decimal spelling, and the text ends with one line feed. Parsing therefore
//! accepts exactly the bytes the encoder writes, so equal evidence always has
//! one record identity.

use super::store::{
    CampaignExchangeRef, parse_evidence_hash, put_evidence_blob, read_evidence_blob,
};
use super::*;

/// Schema line of one finding's evidence record.
pub(super) const FINDING_EVIDENCE_SCHEMA: &str = "crucible.failure-triage.finding-evidence.v2";

/// Schema line of one occurrence chunk.
pub(super) const FINDING_OCCURRENCES_SCHEMA: &str =
    "crucible.failure-triage.finding-occurrences.v3";

/// Largest number of occurrences one chunk holds.
///
/// With every role at its segment bound, a full chunk stays below
/// [`MAX_OCCURRENCE_CHUNK_BYTES`].
pub(super) const MAX_OCCURRENCES_PER_CHUNK: u64 = 1024;

/// Largest segment transcript accepted for one triage replay role.
pub(super) const MAX_TRIAGE_REPLAY_SEGMENTS: usize = 8;

/// Record bound: fixed fields plus one chunk line per 1,024 of the at most
/// [`crucible_campaign::MAX_FINDING_OCCURRENCES`] occurrences.
const MAX_FINDING_EVIDENCE_RECORD_BYTES: usize = 128 * 1024;

/// Chunk bound: 1,024 occurrences of at most 47 lines below 200 bytes each.
const MAX_OCCURRENCE_CHUNK_BYTES: usize = 8 * 1024 * 1024;

/// Replay roles in the canonical order the bundle names them.
pub(super) const TRIAGE_REPLAY_ROLES: [(crucible_campaign::CampaignFindingTriageReplayRole, &str);
    4] = [
    (
        crucible_campaign::CampaignFindingTriageReplayRole::MinimizationOriginal,
        "minimization_original",
    ),
    (
        crucible_campaign::CampaignFindingTriageReplayRole::MinimizationSelected,
        "minimization_selected",
    ),
    (
        crucible_campaign::CampaignFindingTriageReplayRole::VerificationOriginal,
        "verification_original",
    ),
    (
        crucible_campaign::CampaignFindingTriageReplayRole::VerificationSelected,
        "verification_selected",
    ),
];

/// One finding's evidence record: exchange references and occurrence chunks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CampaignFindingEvidenceRecord {
    pub(super) campaign: crucible_campaign::CampaignName,
    pub(super) snapshot: crucible_campaign::CampaignSnapshotId,
    pub(super) finding: crucible_campaign::FindingId,
    pub(super) membership: CampaignExchangeRef,
    pub(super) observation: CampaignExchangeRef,
    pub(super) reproduction: CampaignExchangeRef,
    /// Segment list of the reproduction's payload segment exchanges.
    pub(super) reproduction_segments: crucible_engine::ContentHash,
    pub(super) minimized: Option<CampaignExchangeRef>,
    /// Segment list of the minimized reproduction, present with it.
    pub(super) minimized_segments: Option<crucible_engine::ContentHash>,
    /// Single-finding reproduction-ledger projection of the report evidence.
    pub(super) report: crucible_engine::ContentHash,
    pub(super) occurrence_count: u64,
    pub(super) chunks: Vec<crucible_engine::ContentHash>,
}

/// Exchange references that resolve one retained candidate occurrence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CampaignOccurrenceExchanges {
    pub(super) page: CampaignExchangeRef,
    pub(super) observation: CampaignExchangeRef,
    pub(super) reproduction: CampaignExchangeRef,
    /// Segment list of the reproduction's payload segment exchanges.
    pub(super) reproduction_segments: crucible_engine::ContentHash,
    pub(super) minimized: CampaignExchangeRef,
    /// Segment list of the minimized reproduction's payload segment exchanges.
    pub(super) minimized_segments: crucible_engine::ContentHash,
    /// Replay exchanges in [`TRIAGE_REPLAY_ROLES`] order.
    pub(super) triage: Option<[CampaignTriageRoleExchanges; 4]>,
}

/// Exchange references that resolve one triage replay role.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CampaignTriageRoleExchanges {
    /// Ordered storage-segment exchanges of the replay record.
    pub(super) segments: Vec<CampaignExchangeRef>,
    /// Segment list of the attempt-log segment exchanges the record names.
    pub(super) log_segments: crucible_engine::ContentHash,
}

impl CampaignFindingEvidenceRecord {
    /// Encodes the canonical record text.
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut lines = vec![
            String::from(FINDING_EVIDENCE_SCHEMA),
            format!("campaign={}", self.campaign.as_str()),
            format!("snapshot={}", self.snapshot.to_text()),
            format!("finding={}", self.finding.to_text()),
            format!("membership={}", self.membership.encode()),
            format!("observation={}", self.observation.encode()),
            format!("reproduction={}", self.reproduction.encode()),
            format!(
                "reproduction_segments={}",
                self.reproduction_segments.to_hex()
            ),
            format!(
                "minimized={}",
                self.minimized
                    .map_or_else(|| String::from("none"), CampaignExchangeRef::encode)
            ),
            format!(
                "minimized_segments={}",
                self.minimized_segments
                    .map_or_else(|| String::from("none"), |segments| segments.to_hex())
            ),
            format!("report={}", self.report.to_hex()),
            format!("occurrence_count={}", self.occurrence_count),
            format!("occurrence_chunk_count={}", self.chunks.len()),
        ];
        lines.extend(
            self.chunks
                .iter()
                .enumerate()
                .map(|(index, chunk)| format!("occurrence_chunk.{index}={}", chunk.to_hex())),
        );
        canonical_text(lines)
    }

    /// Parses one strict canonical record.
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, CliError> {
        let mut lines = StrictLines::new(bytes, "finding evidence record")?;
        lines.expect_line(FINDING_EVIDENCE_SCHEMA)?;
        let campaign = crucible_campaign::CampaignName::new(lines.field("campaign")?)
            .map_err(|error| artifact_error(format!("evidence campaign is invalid: {error}")))?;
        let snapshot = crucible_campaign::CampaignSnapshotId::parse(lines.field("snapshot")?)
            .map_err(|error| artifact_error(format!("evidence snapshot is invalid: {error}")))?;
        let finding = crucible_campaign::FindingId::parse(lines.field("finding")?)
            .map_err(|error| artifact_error(format!("evidence finding is invalid: {error}")))?;
        let membership = lines.exchange("membership")?;
        let observation = lines.exchange("observation")?;
        let reproduction = lines.exchange("reproduction")?;
        let reproduction_segments = parse_evidence_hash(
            "reproduction_segments",
            lines.field("reproduction_segments")?,
        )?;
        let minimized = match lines.field("minimized")? {
            "none" => None,
            value => Some(CampaignExchangeRef::parse("minimized", value)?),
        };
        let minimized_segments = match lines.field("minimized_segments")? {
            "none" => None,
            value => Some(parse_evidence_hash("minimized_segments", value)?),
        };
        if minimized.is_some() != minimized_segments.is_some() {
            return Err(artifact_error(
                "evidence minimized reproduction and its segment list disagree",
            ));
        }
        let report = parse_evidence_hash("report", lines.field("report")?)?;
        let occurrence_count = lines.number("occurrence_count")?;
        if occurrence_count > u64::from(crucible_campaign::MAX_FINDING_OCCURRENCES) {
            return Err(artifact_error(
                "evidence occurrence count exceeds the campaign bound",
            ));
        }
        let chunk_count = lines.number("occurrence_chunk_count")?;
        if chunk_count != occurrence_count.div_ceil(MAX_OCCURRENCES_PER_CHUNK) {
            return Err(artifact_error(
                "evidence occurrence chunk count disagrees with its occurrence count",
            ));
        }
        let mut chunks = Vec::new();
        for index in 0..chunk_count {
            chunks.push(parse_evidence_hash(
                "occurrence_chunk",
                lines.field(&format!("occurrence_chunk.{index}"))?,
            )?);
        }
        lines.finish()?;

        Ok(Self {
            campaign,
            snapshot,
            finding,
            membership,
            observation,
            reproduction,
            reproduction_segments,
            minimized,
            minimized_segments,
            report,
            occurrence_count,
            chunks,
        })
    }

    /// Stores the record and returns its content address.
    pub(super) fn put(
        &self,
        store: &crucible_engine::LocalDagStore,
    ) -> Result<crucible_engine::ContentHash, CliError> {
        let bytes = self.encode();
        if bytes.len() > MAX_FINDING_EVIDENCE_RECORD_BYTES {
            return Err(artifact_error(format!(
                "finding evidence record exceeds {MAX_FINDING_EVIDENCE_RECORD_BYTES} bytes"
            )));
        }
        put_evidence_blob(store, &bytes)
    }

    /// Reads and parses one stored record.
    pub(super) fn read(
        store: &crucible_engine::LocalDagStore,
        key: crucible_engine::ContentHash,
    ) -> Result<Self, CliError> {
        Self::parse(&read_evidence_blob(
            store,
            key,
            MAX_FINDING_EVIDENCE_RECORD_BYTES,
            "finding evidence record",
        )?)
    }

    /// Reads the chunk holding `occurrence` and returns that occurrence.
    pub(super) fn read_occurrence(
        &self,
        store: &crucible_engine::LocalDagStore,
        occurrence: u64,
    ) -> Result<CampaignOccurrenceExchanges, CliError> {
        let chunk_index = occurrence / MAX_OCCURRENCES_PER_CHUNK;
        let chunk = usize::try_from(chunk_index)
            .ok()
            .and_then(|index| self.chunks.get(index))
            .ok_or_else(|| artifact_error("evidence occurrence is outside its record"))?;
        let first = chunk_index * MAX_OCCURRENCES_PER_CHUNK;
        let offset = usize::try_from(occurrence - first)
            .map_err(|_| artifact_error("evidence occurrence offset is invalid"))?;
        read_occurrence_chunk(store, *chunk, first, self.chunk_len(chunk_index)?)?
            .into_iter()
            .nth(offset)
            .ok_or_else(|| artifact_error("evidence occurrence is outside its chunk"))
    }

    /// Returns how many occurrences chunk `chunk_index` must hold.
    pub(super) fn chunk_len(&self, chunk_index: u64) -> Result<u64, CliError> {
        let first = chunk_index
            .checked_mul(MAX_OCCURRENCES_PER_CHUNK)
            .filter(|first| *first < self.occurrence_count)
            .ok_or_else(|| artifact_error("evidence occurrence chunk is outside its record"))?;
        Ok((self.occurrence_count - first).min(MAX_OCCURRENCES_PER_CHUNK))
    }
}

/// Buffers occurrences during capture and stores each full chunk at once.
pub(super) struct CampaignOccurrenceChunkWriter<'a> {
    store: &'a crucible_engine::LocalDagStore,
    pending: Vec<CampaignOccurrenceExchanges>,
    written: u64,
    chunks: Vec<crucible_engine::ContentHash>,
}

impl<'a> CampaignOccurrenceChunkWriter<'a> {
    /// Starts an empty chunk sequence in `store`.
    pub(super) fn new(store: &'a crucible_engine::LocalDagStore) -> Self {
        Self {
            store,
            pending: Vec::new(),
            written: 0,
            chunks: Vec::new(),
        }
    }

    /// Appends one occurrence, storing the current chunk when it fills.
    pub(super) fn push(&mut self, occurrence: CampaignOccurrenceExchanges) -> Result<(), CliError> {
        self.pending.push(occurrence);
        if self.pending.len() as u64 == MAX_OCCURRENCES_PER_CHUNK {
            self.flush()?;
        }
        Ok(())
    }

    /// Stores the partial final chunk and returns the occurrence count and chunk keys.
    pub(super) fn finish(mut self) -> Result<(u64, Vec<crucible_engine::ContentHash>), CliError> {
        if !self.pending.is_empty() {
            self.flush()?;
        }
        Ok((self.written, self.chunks))
    }

    fn flush(&mut self) -> Result<(), CliError> {
        let bytes = encode_occurrence_chunk(self.written, &self.pending);
        if bytes.len() > MAX_OCCURRENCE_CHUNK_BYTES {
            return Err(artifact_error(format!(
                "finding occurrence chunk exceeds {MAX_OCCURRENCE_CHUNK_BYTES} bytes"
            )));
        }
        self.chunks.push(put_evidence_blob(self.store, &bytes)?);
        self.written += self.pending.len() as u64;
        self.pending.clear();
        Ok(())
    }
}

/// Encodes the canonical chunk text for consecutive occurrences from `first`.
pub(super) fn encode_occurrence_chunk(
    first: u64,
    occurrences: &[CampaignOccurrenceExchanges],
) -> Vec<u8> {
    let mut lines = vec![
        String::from(FINDING_OCCURRENCES_SCHEMA),
        format!("first_occurrence={first}"),
        format!("occurrence_count={}", occurrences.len()),
    ];
    for (offset, occurrence) in occurrences.iter().enumerate() {
        let prefix = format!("occurrence.{}", first + offset as u64);
        lines.push(format!("{prefix}.page={}", occurrence.page.encode()));
        lines.push(format!(
            "{prefix}.observation={}",
            occurrence.observation.encode()
        ));
        lines.push(format!(
            "{prefix}.reproduction={}",
            occurrence.reproduction.encode()
        ));
        lines.push(format!(
            "{prefix}.reproduction_segments={}",
            occurrence.reproduction_segments.to_hex()
        ));
        lines.push(format!(
            "{prefix}.minimized={}",
            occurrence.minimized.encode()
        ));
        lines.push(format!(
            "{prefix}.minimized_segments={}",
            occurrence.minimized_segments.to_hex()
        ));
        let Some(triage) = &occurrence.triage else {
            lines.push(format!("{prefix}.triage=none"));
            continue;
        };
        lines.push(format!("{prefix}.triage=present"));
        for ((_, label), role) in TRIAGE_REPLAY_ROLES.iter().zip(triage) {
            lines.push(format!(
                "{prefix}.{label}.segment_count={}",
                role.segments.len()
            ));
            lines.extend(role.segments.iter().enumerate().map(|(segment, exchange)| {
                format!("{prefix}.{label}.segment.{segment}={}", exchange.encode())
            }));
            lines.push(format!(
                "{prefix}.{label}.log_segments={}",
                role.log_segments.to_hex()
            ));
        }
    }
    canonical_text(lines)
}

/// Reads one chunk and checks that it holds occurrences `first..first + count`.
pub(super) fn read_occurrence_chunk(
    store: &crucible_engine::LocalDagStore,
    key: crucible_engine::ContentHash,
    first: u64,
    count: u64,
) -> Result<Vec<CampaignOccurrenceExchanges>, CliError> {
    let bytes = read_evidence_blob(
        store,
        key,
        MAX_OCCURRENCE_CHUNK_BYTES,
        "finding occurrence chunk",
    )?;
    parse_occurrence_chunk(&bytes, first, count)
}

/// Parses one strict canonical chunk.
pub(super) fn parse_occurrence_chunk(
    bytes: &[u8],
    first: u64,
    count: u64,
) -> Result<Vec<CampaignOccurrenceExchanges>, CliError> {
    let mut lines = StrictLines::new(bytes, "finding occurrence chunk")?;
    lines.expect_line(FINDING_OCCURRENCES_SCHEMA)?;
    if lines.number("first_occurrence")? != first || lines.number("occurrence_count")? != count {
        return Err(artifact_error(
            "finding occurrence chunk is out of place in its record",
        ));
    }

    let mut occurrences = Vec::new();
    for occurrence in first..first + count {
        let prefix = format!("occurrence.{occurrence}");
        let page = lines.exchange(&format!("{prefix}.page"))?;
        let observation = lines.exchange(&format!("{prefix}.observation"))?;
        let reproduction = lines.exchange(&format!("{prefix}.reproduction"))?;
        let reproduction_segments = lines.hash(&format!("{prefix}.reproduction_segments"))?;
        let minimized = lines.exchange(&format!("{prefix}.minimized"))?;
        let minimized_segments = lines.hash(&format!("{prefix}.minimized_segments"))?;
        let triage = match lines.field(&format!("{prefix}.triage"))? {
            "none" => None,
            "present" => {
                let mut roles: [CampaignTriageRoleExchanges; 4] = Default::default();
                for ((_, label), role) in TRIAGE_REPLAY_ROLES.iter().zip(&mut roles) {
                    let segment_count = lines.number(&format!("{prefix}.{label}.segment_count"))?;
                    if segment_count == 0 || segment_count > MAX_TRIAGE_REPLAY_SEGMENTS as u64 {
                        return Err(artifact_error(format!(
                            "occurrence {occurrence} {label} segment count exceeds its bound"
                        )));
                    }
                    for segment in 0..segment_count {
                        role.segments
                            .push(lines.exchange(&format!("{prefix}.{label}.segment.{segment}"))?);
                    }
                    role.log_segments = lines.hash(&format!("{prefix}.{label}.log_segments"))?;
                }
                Some(roles)
            }
            _ => {
                return Err(artifact_error(format!(
                    "occurrence {occurrence} triage marker is malformed"
                )));
            }
        };
        occurrences.push(CampaignOccurrenceExchanges {
            page,
            observation,
            reproduction,
            reproduction_segments,
            minimized,
            minimized_segments,
            triage,
        });
    }
    lines.finish()?;
    Ok(occurrences)
}

/// Joins lines with line feeds and terminates the text with one more.
fn canonical_text(lines: Vec<String>) -> Vec<u8> {
    let mut text = lines.join("\n");
    text.push('\n');
    text.into_bytes()
}

/// Sequential reader that accepts exactly one canonical line layout.
struct StrictLines<'a> {
    lines: std::str::Split<'a, char>,
    kind: &'static str,
}

impl<'a> StrictLines<'a> {
    fn new(bytes: &'a [u8], kind: &'static str) -> Result<Self, CliError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| artifact_error(format!("{kind} is not UTF-8")))?;
        let body = text
            .strip_suffix('\n')
            .ok_or_else(|| artifact_error(format!("{kind} does not end with a line feed")))?;
        Ok(Self {
            lines: body.split('\n'),
            kind,
        })
    }

    fn next_line(&mut self) -> Result<&'a str, CliError> {
        let kind = self.kind;
        self.lines
            .next()
            .ok_or_else(|| artifact_error(format!("{kind} ends early")))
    }

    fn expect_line(&mut self, expected: &str) -> Result<(), CliError> {
        if self.next_line()? != expected {
            let kind = self.kind;
            return Err(artifact_error(format!("unsupported {kind} schema")));
        }
        Ok(())
    }

    fn field(&mut self, name: &str) -> Result<&'a str, CliError> {
        let line = self.next_line()?;
        line.strip_prefix(name)
            .and_then(|rest| rest.strip_prefix('='))
            .ok_or_else(|| {
                let kind = self.kind;
                artifact_error(format!(
                    "{kind} is missing `{name}` at its canonical position"
                ))
            })
    }

    fn number(&mut self, name: &str) -> Result<u64, CliError> {
        let value = self.field(name)?;
        let kind = self.kind;
        value
            .parse::<u64>()
            .ok()
            .filter(|number| number.to_string() == value)
            .ok_or_else(|| artifact_error(format!("{kind} `{name}` is not a canonical number")))
    }

    fn exchange(&mut self, name: &str) -> Result<CampaignExchangeRef, CliError> {
        CampaignExchangeRef::parse(name, self.field(name)?)
    }

    fn hash(&mut self, name: &str) -> Result<crucible_engine::ContentHash, CliError> {
        parse_evidence_hash(name, self.field(name)?)
    }

    fn finish(mut self) -> Result<(), CliError> {
        if self.lines.next().is_some() {
            let kind = self.kind;
            return Err(artifact_error(format!("{kind} has trailing lines")));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
    #![allow(clippy::expect_used)]

    use super::*;

    fn exchange(seed: u8) -> CampaignExchangeRef {
        CampaignExchangeRef {
            request: crucible_engine::ContentHash::from_bytes(&[seed, 0]),
            response: crucible_engine::ContentHash::from_bytes(&[seed, 1]),
        }
    }

    fn typed_content(
        kind: crucible_campaign::CampaignRecordKind,
    ) -> crucible_store::content_store::ContentId {
        crucible_store::content_store::ContentId::for_bytes(
            kind.object_kind(),
            kind.schema_version(),
            b"finding evidence record test",
        )
    }

    fn occurrence(seed: u8, triage: bool) -> CampaignOccurrenceExchanges {
        CampaignOccurrenceExchanges {
            page: exchange(seed),
            observation: exchange(seed.wrapping_add(1)),
            reproduction: exchange(seed.wrapping_add(2)),
            reproduction_segments: crucible_engine::ContentHash::from_bytes(&[seed, 2]),
            minimized: exchange(seed.wrapping_add(3)),
            minimized_segments: crucible_engine::ContentHash::from_bytes(&[seed, 3]),
            triage: triage.then(|| {
                [
                    role(vec![exchange(seed.wrapping_add(4))], seed, 4),
                    role(
                        vec![
                            exchange(seed.wrapping_add(5)),
                            exchange(seed.wrapping_add(6)),
                        ],
                        seed,
                        5,
                    ),
                    role(vec![exchange(seed.wrapping_add(7))], seed, 7),
                    role(vec![exchange(seed.wrapping_add(8))], seed, 8),
                ]
            }),
        }
    }

    fn role(segments: Vec<CampaignExchangeRef>, seed: u8, tag: u8) -> CampaignTriageRoleExchanges {
        CampaignTriageRoleExchanges {
            segments,
            log_segments: crucible_engine::ContentHash::from_bytes(&[seed, tag, 0xff]),
        }
    }

    #[test]
    fn occurrence_chunk_round_trips_and_rejects_noncanonical_text() {
        let occurrences = vec![occurrence(10, true), occurrence(40, false)];
        let bytes = encode_occurrence_chunk(1024, &occurrences);

        assert_eq!(
            parse_occurrence_chunk(&bytes, 1024, 2).expect("canonical chunk parses"),
            occurrences
        );

        let text = String::from_utf8(bytes.clone()).expect("chunk is UTF-8");
        for rejected in [
            text.replacen("first_occurrence=1024", "first_occurrence=01024", 1),
            text.replacen("triage=none", "triage=absent", 1),
            text.replacen("segment_count=2", "segment_count=9", 1),
            format!("{text}occurrence.1026.page=x\n"),
            text.trim_end().to_owned(),
        ] {
            assert!(parse_occurrence_chunk(rejected.as_bytes(), 1024, 2).is_err());
        }
        assert!(parse_occurrence_chunk(&bytes, 0, 2).is_err());
        assert!(parse_occurrence_chunk(&bytes, 1024, 1).is_err());
    }

    #[test]
    fn evidence_record_round_trips_and_binds_chunk_count() {
        let record = CampaignFindingEvidenceRecord {
            campaign: crucible_campaign::CampaignName::new("nightly-search").expect("valid name"),
            snapshot: crucible_campaign::CampaignSnapshotId::parse(&format!(
                "crucible.campaign.snapshot@{}",
                typed_content(crucible_campaign::CampaignRecordKind::Snapshot)
            ))
            .expect("snapshot ID"),
            finding: crucible_campaign::FindingId::parse(&format!(
                "crucible.campaign.finding@{}",
                typed_content(crucible_campaign::CampaignRecordKind::Finding)
            ))
            .expect("finding ID"),
            membership: exchange(1),
            observation: exchange(2),
            reproduction: exchange(3),
            reproduction_segments: crucible_engine::ContentHash::from_bytes(
                b"reproduction segments",
            ),
            minimized: None,
            minimized_segments: None,
            report: crucible_engine::ContentHash::from_bytes(b"report"),
            occurrence_count: MAX_OCCURRENCES_PER_CHUNK + 1,
            chunks: vec![
                crucible_engine::ContentHash::from_bytes(b"chunk-0"),
                crucible_engine::ContentHash::from_bytes(b"chunk-1"),
            ],
        };
        let bytes = record.encode();

        assert_eq!(
            CampaignFindingEvidenceRecord::parse(&bytes).expect("canonical record parses"),
            record
        );
        assert_eq!(record.chunk_len(1).expect("final chunk"), 1);
        assert!(record.chunk_len(2).is_err());

        let text = String::from_utf8(bytes).expect("record is UTF-8");
        for rejected in [
            text.replacen("occurrence_chunk_count=2", "occurrence_chunk_count=1", 1),
            text.replacen("minimized=none", "minimized=", 1),
            // A segment list without its minimized reproduction.
            text.replacen(
                "minimized_segments=none",
                &format!(
                    "minimized_segments={}",
                    record.reproduction_segments.to_hex()
                ),
                1,
            ),
            text.replacen(
                FINDING_EVIDENCE_SCHEMA,
                "crucible.failure-triage.finding-evidence.v0",
                1,
            ),
            text.replacen("campaign=", "campaign =", 1),
        ] {
            assert!(CampaignFindingEvidenceRecord::parse(rejected.as_bytes()).is_err());
        }
    }
}
