//! Current-format durable corpus index and authenticated QEMU fuzz entry storage.
//!
//! The mutable `live-fuzz-corpus.json` root names immutable DagStore
//! descriptors. Each descriptor addresses one entry's reproduction artifact,
//! choice replay closure, and deduplicated coverage set. Opening a corpus
//! authenticates every entry one at a time and keeps only a small resident
//! handle; payloads are read back for the one entry chosen as a parent.
//!
//! ```text
//! live-fuzz-corpus.json   { "schema": 2, "entries": [descriptor, ...] }  sorted, unique
//! descriptor (schema 2)   { artifact, replayed_state, closure, coverage,
//!                           coverage_fingerprint, parent, sample_index,
//!                           energy, novel_coverage, resumable_choice }
//! coverage set (schema 2) { "schema": 2, "observations": [observation, ...] }
//!                           distinct, in canonical fingerprint order
//! ```
//!
//! A coverage set holds each distinct basic block or named marker once, so its
//! size is bounded by the guest's distinct coverage rather than by the length
//! of the run that produced it. The fingerprint and coverage identities are
//! recomputed from it on every open.

use super::*;

use std::collections::BTreeSet;
use std::io::Read;

use serde::{Deserialize, Serialize};

const INDEX_NAME: &str = "live-fuzz-corpus.json";
const CORPUS_SCHEMA: u32 = 2;
const MAX_INDEX_BYTES: u64 = 8 * 1024 * 1024;
// Descriptors hold a fixed set of hashes and counters.
const MAX_DESCRIPTOR_BYTES: u64 = 16 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 128 * 1024 * 1024;
const MAX_CLOSURE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_COVERAGE_BYTES: u64 = 64 * 1024 * 1024;
// One artifact, closure, coverage set, and descriptor are written per entry.
const OBJECTS_PER_ENTRY: u64 = 4;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusIndex {
    schema: u32,
    entries: Vec<crucible_engine::ContentHash>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusDescriptor {
    schema: u32,
    artifact: crucible_engine::ContentHash,
    replayed_state: crucible_engine::ContentHash,
    closure: crucible_engine::ContentHash,
    coverage: crucible_engine::ContentHash,
    coverage_fingerprint: crucible_engine::ContentHash,
    parent: Option<crucible_engine::ContentHash>,
    sample_index: u64,
    energy: u64,
    novel_coverage: usize,
    resumable_choice: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CoverageSetBlob {
    schema: u32,
    observations: Vec<CoverageObservationWire>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "kebab-case")]
enum CoverageObservationWire {
    BasicBlock {
        node: String,
        guest_pc: u64,
        block_len: u32,
    },
    Named {
        node: String,
        marker: String,
    },
}

impl From<&crucible_engine::EventLogCoverageObservation> for CoverageObservationWire {
    fn from(observation: &crucible_engine::EventLogCoverageObservation) -> Self {
        match observation {
            crucible_engine::EventLogCoverageObservation::BasicBlock {
                node,
                guest_pc,
                block_len,
            } => Self::BasicBlock {
                node: node.name.clone(),
                guest_pc: *guest_pc,
                block_len: *block_len,
            },
            crucible_engine::EventLogCoverageObservation::Named { node, marker } => Self::Named {
                node: node.name.clone(),
                marker: marker.name.clone(),
            },
        }
    }
}

impl From<CoverageObservationWire> for crucible_engine::EventLogCoverageObservation {
    fn from(observation: CoverageObservationWire) -> Self {
        match observation {
            CoverageObservationWire::BasicBlock {
                node,
                guest_pc,
                block_len,
            } => Self::BasicBlock {
                node: crucible_engine::NodeId { name: node },
                guest_pc,
                block_len,
            },
            CoverageObservationWire::Named { node, marker } => Self::Named {
                node: crucible_engine::NodeId { name: node },
                marker: crucible_engine::MarkerId { name: marker },
            },
        }
    }
}

/// Content-addressed home of corpus entry payloads for one fuzz run.
///
/// With `--corpus`, payloads go straight into the corpus directory, so an
/// admitted entry never waits in memory for the final index publication.
/// Without it, a private scratch store holds them until the run ends.
pub(super) struct CorpusPayloadStore {
    store: crucible_engine::LocalDagStore,
    // Keeps a scratch store's directory alive for the store's lifetime.
    _scratch: Option<tempfile::TempDir>,
}

impl CorpusPayloadStore {
    /// Stores payloads in the durable corpus directory at `path`.
    pub(super) fn durable(path: &Path) -> Self {
        Self {
            store: crucible_engine::LocalDagStore::new(path.to_path_buf()),
            _scratch: None,
        }
    }

    /// Stores payloads in a private directory removed when the store drops.
    pub(super) fn scratch() -> Result<Self, CliError> {
        let directory = tempfile::tempdir().map_err(|error| {
            backend_error(format!("create QEMU fuzz corpus scratch store: {error}"))
        })?;
        Ok(Self {
            store: crucible_engine::LocalDagStore::new(directory.path().to_path_buf()),
            _scratch: Some(directory),
        })
    }
}

/// Opens the corpus at `path`, authenticating every entry one at a time.
///
/// Each entry's artifact replays to its recorded state, its closure validates
/// against the artifact's schedule, and its coverage set reproduces the
/// recorded fingerprint. Only the resident handle survives the check.
pub(super) fn load_qemu_fuzz_corpus(path: &Path) -> Result<Vec<LiveFuzzCorpusEntry>, CliError> {
    fs::create_dir_all(path).map_err(|error| {
        backend_error(format!(
            "create QEMU fuzz corpus `{}`: {error}",
            path.display()
        ))
    })?;
    let index_path = path.join(INDEX_NAME);
    match fs::symlink_metadata(&index_path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // An interrupted first publish may leave unreferenced immutable objects.
            return Ok(Vec::new());
        }
        Err(error) => {
            return Err(artifact_error(format!(
                "inspect QEMU fuzz corpus index: {error}"
            )));
        }
    }

    let index_bytes = read_bounded_file(&index_path, MAX_INDEX_BYTES)?;
    let index: CorpusIndex = serde_json::from_slice(&index_bytes)
        .map_err(|error| artifact_error(format!("decode QEMU fuzz corpus index: {error}")))?;
    if index.schema != CORPUS_SCHEMA || !strictly_sorted(&index.entries) {
        return Err(artifact_error(
            "QEMU fuzz corpus index has an unsupported schema or duplicate entries",
        ));
    }

    let store = crucible_engine::LocalDagStore::new(path.to_path_buf());
    let mut corpus = Vec::with_capacity(index.entries.len());
    for key in index.entries {
        corpus.push(load_entry(&store, key)?.into_entry(false));
    }
    Ok(corpus)
}

/// Writes one admitted candidate's payloads and returns its resident handle.
///
/// The stored entry is reopened through the same authentication as a corpus
/// open before the handle is returned.
pub(super) fn store_qemu_fuzz_entry(
    payloads: &CorpusPayloadStore,
    candidate: LiveFuzzCorpusCandidate,
    novel_coverage: usize,
) -> Result<LiveFuzzCorpusEntry, CliError> {
    let store = &payloads.store;
    if candidate.coverage.is_empty() {
        return Err(artifact_error(
            "QEMU fuzz corpus contains an entry without coverage",
        ));
    }

    let artifact = store
        .put(&candidate.artifact.to_compact_binary())
        .map_err(CliError::Store)?;
    if artifact != candidate.artifact.id() {
        return Err(artifact_error(
            "stored QEMU fuzz artifact changed content identity",
        ));
    }
    let replayed_state = candidate
        .artifact
        .replay()
        .map_err(|error| artifact_error(format!("replay QEMU fuzz corpus artifact: {error}")))?
        .state;
    let closure = store
        .put(
            &candidate
                .replay_closure
                .to_canonical_bytes()
                .map_err(|error| {
                    artifact_error(format!("encode QEMU fuzz choice closure: {error}"))
                })?,
        )
        .map_err(CliError::Store)?;
    let coverage_bytes = serde_json::to_vec(&CoverageSetBlob {
        schema: CORPUS_SCHEMA,
        observations: candidate
            .coverage
            .observations()
            .map(CoverageObservationWire::from)
            .collect(),
    })
    .map_err(|error| artifact_error(format!("encode QEMU fuzz coverage: {error}")))?;
    if coverage_bytes.len() as u64 > MAX_COVERAGE_BYTES {
        return Err(artifact_error(
            "QEMU fuzz coverage set exceeds its size bound",
        ));
    }
    let coverage = store.put(&coverage_bytes).map_err(CliError::Store)?;

    let descriptor = CorpusDescriptor {
        schema: CORPUS_SCHEMA,
        artifact,
        replayed_state,
        closure,
        coverage,
        coverage_fingerprint: candidate.coverage.fingerprint(),
        parent: candidate.parent,
        sample_index: candidate.sample_index,
        energy: candidate.energy,
        novel_coverage,
        resumable_choice: candidate.resumable_choice,
    };
    let descriptor_bytes = serde_json::to_vec(&descriptor)
        .map_err(|error| artifact_error(format!("encode QEMU fuzz corpus entry: {error}")))?;
    if descriptor_bytes.len() as u64 > MAX_DESCRIPTOR_BYTES {
        return Err(artifact_error(
            "QEMU fuzz corpus descriptor exceeds its size bound",
        ));
    }
    let key = store.put(&descriptor_bytes).map_err(CliError::Store)?;
    Ok(load_entry(store, key)?.into_entry(true))
}

/// Reads the reproduction artifact and replay closure of one resident entry.
///
/// Both objects were authenticated when the entry was opened or stored; this
/// read rechecks their content identities against the descriptor.
pub(super) fn load_qemu_fuzz_entry_payload(
    payloads: &CorpusPayloadStore,
    entry: &LiveFuzzCorpusEntry,
) -> Result<
    (
        crucible_engine::ReproductionArtifact,
        crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignReplayClosure,
    ),
    CliError,
> {
    let descriptor = read_descriptor(&payloads.store, entry.descriptor)?;
    let artifact = decode_artifact(&payloads.store, descriptor.artifact)?;
    let closure = decode_closure(&payloads.store, descriptor.closure, &artifact)?;
    if artifact.id() != entry.artifact_id {
        return Err(artifact_error(
            "QEMU fuzz corpus entry names another reproduction artifact",
        ));
    }
    Ok((artifact, closure))
}

/// Publishes the index naming every retained entry's descriptor.
///
/// Returns the retained entry count and the number of objects this run wrote
/// for retained entries. Entries dropped during the run may leave
/// unreferenced immutable objects behind, which the index never names.
pub(super) fn persist_qemu_fuzz_corpus(
    path: &Path,
    entries: &[LiveFuzzCorpusEntry],
) -> Result<(usize, u64), CliError> {
    let mut descriptors = Vec::with_capacity(entries.len());
    let mut stored = BTreeSet::new();
    let mut artifact_coverage = std::collections::BTreeMap::new();

    for entry in entries {
        if let Some(previous) =
            artifact_coverage.insert(entry.artifact_id, entry.coverage_fingerprint)
            && previous != entry.coverage_fingerprint
        {
            return Err(artifact_error(
                "QEMU fuzz produced conflicting coverage for one reproduction artifact",
            ));
        }
        if entry.coverage_ids.is_empty() {
            return Err(artifact_error(
                "QEMU fuzz corpus contains an entry without coverage",
            ));
        }
        if entry.stored_this_run {
            stored.insert(entry.descriptor);
        }
        descriptors.push(entry.descriptor);
    }
    descriptors.sort_unstable();
    descriptors.dedup();
    let puts = OBJECTS_PER_ENTRY.saturating_mul(stored.len() as u64);

    // Publish the mutable root only after every referenced immutable object exists.
    let index = CorpusIndex {
        schema: CORPUS_SCHEMA,
        entries: descriptors,
    };
    let bytes = serde_json::to_vec(&index)
        .map_err(|error| artifact_error(format!("encode QEMU fuzz corpus index: {error}")))?;
    if bytes.len() as u64 > MAX_INDEX_BYTES {
        return Err(artifact_error(
            "QEMU fuzz corpus index exceeds its size bound",
        ));
    }
    let temporary = path.join(format!(".{INDEX_NAME}.{}", std::process::id()));
    fs::write(&temporary, &bytes)
        .map_err(|error| backend_error(format!("write QEMU fuzz corpus index: {error}")))?;
    fs::rename(&temporary, path.join(INDEX_NAME))
        .map_err(|error| backend_error(format!("publish QEMU fuzz corpus index: {error}")))?;
    Ok((index.entries.len(), puts))
}

/// One authenticated corpus entry before its payloads are dropped.
struct LoadedEntry {
    key: crucible_engine::ContentHash,
    descriptor: CorpusDescriptor,
    scenario_form_id: crucible_engine::ContentHash,
    artifact_id: crucible_engine::ContentHash,
    coverage_ids: BTreeSet<crucible_engine::ContentHash>,
}

impl LoadedEntry {
    fn into_entry(self, stored_this_run: bool) -> LiveFuzzCorpusEntry {
        LiveFuzzCorpusEntry {
            descriptor: self.key,
            artifact_id: self.artifact_id,
            scenario_form_id: self.scenario_form_id,
            coverage_fingerprint: self.descriptor.coverage_fingerprint,
            coverage_ids: self.coverage_ids,
            novel_coverage: self.descriptor.novel_coverage,
            resumable_choice: self.descriptor.resumable_choice,
            stored_this_run,
        }
    }
}

fn load_entry(
    store: &crucible_engine::LocalDagStore,
    key: crucible_engine::ContentHash,
) -> Result<LoadedEntry, CliError> {
    let descriptor = read_descriptor(store, key)?;

    let artifact = decode_artifact(store, descriptor.artifact)?;
    artifact
        .verify_replay(descriptor.replayed_state)
        .map_err(|error| {
            artifact_error(format!("replay retained QEMU fuzz reproduction: {error}"))
        })?;
    decode_closure(store, descriptor.closure, &artifact)?;

    let coverage = decode_coverage(store, descriptor.coverage)?;
    if coverage.fingerprint() != descriptor.coverage_fingerprint {
        return Err(artifact_error(
            "QEMU fuzz coverage does not match its retained fingerprint",
        ));
    }

    Ok(LoadedEntry {
        key,
        scenario_form_id: artifact.scenario_form().id(),
        artifact_id: artifact.id(),
        coverage_ids: coverage.identities(),
        descriptor,
    })
}

fn read_descriptor(
    store: &crucible_engine::LocalDagStore,
    key: crucible_engine::ContentHash,
) -> Result<CorpusDescriptor, CliError> {
    let descriptor_bytes = read_bounded_object(store, key, MAX_DESCRIPTOR_BYTES)?;
    let descriptor: CorpusDescriptor = serde_json::from_slice(&descriptor_bytes)
        .map_err(|error| artifact_error(format!("decode QEMU fuzz corpus entry: {error}")))?;
    if descriptor.schema != CORPUS_SCHEMA || descriptor.novel_coverage == 0 {
        return Err(artifact_error(
            "QEMU fuzz corpus entry has invalid current-format metadata",
        ));
    }
    Ok(descriptor)
}

fn decode_artifact(
    store: &crucible_engine::LocalDagStore,
    key: crucible_engine::ContentHash,
) -> Result<crucible_engine::ReproductionArtifact, CliError> {
    let artifact_bytes = read_bounded_object(store, key, MAX_ARTIFACT_BYTES)?;
    let artifact = crucible_engine::ReproductionArtifact::from_compact_binary(&artifact_bytes)
        .map_err(|error| artifact_error(format!("decode QEMU fuzz reproduction: {error}")))?;
    if artifact.id() != key || artifact.to_compact_binary() != artifact_bytes {
        return Err(artifact_error(
            "QEMU fuzz reproduction artifact is noncanonical",
        ));
    }
    Ok(artifact)
}

fn decode_closure(
    store: &crucible_engine::LocalDagStore,
    key: crucible_engine::ContentHash,
    artifact: &crucible_engine::ReproductionArtifact,
) -> Result<crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignReplayClosure, CliError> {
    let closure_bytes = read_bounded_object(store, key, MAX_CLOSURE_BYTES)?;
    crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignReplayClosure::from_canonical_bytes(
        &closure_bytes,
    )
    .and_then(|closure| {
        closure.validate_for_schedule(artifact.scenario_form(), artifact.schedule())?;
        Ok(closure)
    })
    .map_err(|error| artifact_error(format!("authenticate QEMU fuzz choice closure: {error}")))
}

/// Decodes a coverage set and checks that it is distinct and canonically ordered.
fn decode_coverage(
    store: &crucible_engine::LocalDagStore,
    key: crucible_engine::ContentHash,
) -> Result<crucible_engine::EventLogCoverageSet, CliError> {
    let coverage_bytes = read_bounded_object(store, key, MAX_COVERAGE_BYTES)?;
    let blob: CoverageSetBlob = serde_json::from_slice(&coverage_bytes)
        .map_err(|error| artifact_error(format!("decode QEMU fuzz coverage: {error}")))?;
    if blob.schema != CORPUS_SCHEMA || blob.observations.is_empty() {
        return Err(artifact_error(
            "QEMU fuzz coverage set has an unsupported schema or no coverage",
        ));
    }

    let mut coverage = crucible_engine::EventLogCoverageSet::new();
    let mut ordered = Vec::with_capacity(blob.observations.len());
    for observation in blob.observations {
        let observation = crucible_engine::EventLogCoverageObservation::from(observation);
        if !coverage.insert(observation.clone()) {
            return Err(artifact_error(
                "QEMU fuzz coverage set repeats an observation",
            ));
        }
        ordered.push(observation);
    }
    // The set iterates in canonical order, so a canonical blob lists the
    // same observations in the same order.
    if !coverage.observations().eq(ordered.iter()) {
        return Err(artifact_error(
            "QEMU fuzz coverage set is not in canonical order",
        ));
    }
    Ok(coverage)
}

fn read_bounded_object(
    store: &crucible_engine::LocalDagStore,
    key: crucible_engine::ContentHash,
    limit: u64,
) -> Result<Vec<u8>, CliError> {
    let path = store.object_path(&key);
    let bytes = read_bounded_file(&path, limit)?;
    if crucible_engine::ContentHash::from_bytes(&bytes) != key {
        return Err(artifact_error(
            "QEMU fuzz corpus object changed content identity",
        ));
    }
    Ok(bytes)
}

fn read_bounded_file(path: &Path, limit: u64) -> Result<Vec<u8>, CliError> {
    let file = fs::File::open(path)
        .map_err(|error| artifact_error(format!("open QEMU fuzz corpus data: {error}")))?;
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| artifact_error(format!("read QEMU fuzz corpus data: {error}")))?;
    if bytes.len() as u64 > limit {
        return Err(artifact_error(
            "QEMU fuzz corpus data exceeds its size bound",
        ));
    }
    Ok(bytes)
}

fn strictly_sorted(values: &[crucible_engine::ContentHash]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coverage_block(sequence: u64, guest_pc: u64) -> crucible_engine::SchedulerEventLogEntry {
        ::crucible_engine::test_support::condition_observation_entry_for_test(
            sequence,
            &crucible_engine::ObservableEvent::coverage_block(
                crucible_engine::Icount {
                    retired: 10 + sequence,
                },
                crucible_engine::NodeId {
                    name: String::from("node-0"),
                },
                guest_pc,
                0x20,
            ),
        )
    }

    fn candidate(
        form: &crucible_engine::ScenarioDefForm,
        blocks: &[u64],
        parent: Option<crucible_engine::ContentHash>,
    ) -> Result<LiveFuzzCorpusCandidate, Box<dyn std::error::Error>> {
        let configuration = crucible_engine::Configuration::genesis(form.scenario_def());
        let artifact =
            crucible_engine::ReproductionArtifact::capture(form, &configuration.schedule)?;
        let mut coverage = crucible_engine::EventLogCoverageSet::new();
        // Repeated hits of one block collapse to one retained observation.
        for (sequence, guest_pc) in blocks.iter().chain(blocks).enumerate() {
            coverage.observe(&coverage_block(sequence as u64, *guest_pc));
        }
        Ok(LiveFuzzCorpusCandidate {
            artifact,
            coverage_ids: coverage.identities(),
            coverage,
            parent,
            sample_index: 0,
            energy: 1,
            replay_closure:
                crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignReplayClosure::empty(),
            resumable_choice: true,
        })
    }

    #[test]
    fn durable_corpus_reopens_handles_and_payloads_and_rejects_corruption()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = crucible_engine::LocalDagStore::new(directory.path());
        store.put(b"orphaned-before-first-index-publish")?;
        assert!(load_qemu_fuzz_corpus(directory.path())?.is_empty());
        let payloads = CorpusPayloadStore::durable(directory.path());

        let scenario = crucible_engine::happy_path_scenario()?.scenario;
        let first = candidate(&scenario, &[0x4000], None)?;
        assert_eq!(first.coverage.len(), 1);
        assert_eq!(first.coverage.hits(), 2);
        let first_fingerprint = first.coverage.fingerprint();
        let entry = store_qemu_fuzz_entry(&payloads, first, 1)?;
        assert!(entry.stored_this_run);
        assert_eq!(entry.coverage_fingerprint, first_fingerprint);

        assert_eq!(
            persist_qemu_fuzz_corpus(directory.path(), &[entry])?,
            (1, 4)
        );
        let mut reopened = load_qemu_fuzz_corpus(directory.path())?;
        assert_eq!(reopened.len(), 1);
        assert!(!reopened[0].stored_this_run);
        assert_eq!(reopened[0].coverage_ids.len(), 1);
        assert_eq!(reopened[0].coverage_fingerprint, first_fingerprint);
        assert_eq!(reopened[0].scenario_form_id, scenario.id());
        assert_eq!(
            persist_qemu_fuzz_corpus(directory.path(), &reopened)?,
            (1, 0)
        );

        let next_scenario = crucible_engine::fault_campaign_family()?
            .instantiate_sample(0)?
            .into_form();
        let next = candidate(
            &next_scenario,
            &[0x4000, 0x5000],
            Some(reopened[0].artifact_id),
        )?;
        let mut observed = reopened[0].coverage_ids.clone();
        let mut guidance = vec![reopened[0].coverage_fingerprint];
        assert_eq!(
            admit_qemu_fuzz_candidates(
                &mut reopened,
                &mut observed,
                &mut guidance,
                vec![next],
                &payloads,
            )?,
            1,
        );
        assert_eq!(observed.len(), 2);
        assert_eq!(guidance.len(), 2);
        assert_eq!(reopened.len(), 1);
        assert_eq!(reopened[0].coverage_ids.len(), 2);
        assert_eq!(
            persist_qemu_fuzz_corpus(directory.path(), &reopened)?,
            (1, 4)
        );
        let retained = load_qemu_fuzz_corpus(directory.path())?;
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].coverage_ids, reopened[0].coverage_ids);
        let (artifact, _) = load_qemu_fuzz_entry_payload(&payloads, &retained[0])?;
        assert_eq!(artifact.id(), retained[0].artifact_id);
        assert_eq!(artifact.scenario_form().id(), next_scenario.id());

        let descriptor_path = store.object_path(&retained[0].descriptor);
        let descriptor_bytes = fs::read(&descriptor_path)?;
        fs::remove_file(&descriptor_path)?;
        assert!(matches!(
            load_qemu_fuzz_corpus(directory.path()),
            Err(CliError::Artifact(message))
                if message.starts_with("open QEMU fuzz corpus data:")
        ));

        fs::write(&descriptor_path, &descriptor_bytes)?;
        let restored = load_qemu_fuzz_corpus(directory.path())?;
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].artifact_id, retained[0].artifact_id);
        assert_eq!(restored[0].coverage_ids, retained[0].coverage_ids);

        fs::write(&descriptor_path, b"corrupt descriptor")?;
        assert!(load_qemu_fuzz_corpus(directory.path()).is_err());
        Ok(())
    }

    #[test]
    fn coverage_sets_must_be_canonical_and_prior_schemas_are_refused()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = crucible_engine::LocalDagStore::new(directory.path());
        let scenario = crucible_engine::happy_path_scenario()?.scenario;
        let mut coverage = candidate(&scenario, &[0x4000, 0x5000], None)?
            .coverage
            .observations()
            .map(CoverageObservationWire::from)
            .collect::<Vec<_>>();

        let canonical = store.put(&serde_json::to_vec(&CoverageSetBlob {
            schema: CORPUS_SCHEMA,
            observations: coverage.clone(),
        })?)?;
        assert_eq!(decode_coverage(&store, canonical)?.len(), 2);

        coverage.reverse();
        let reordered = store.put(&serde_json::to_vec(&CoverageSetBlob {
            schema: CORPUS_SCHEMA,
            observations: coverage,
        })?)?;
        assert!(decode_coverage(&store, reordered).is_err());

        fs::write(
            directory.path().join(INDEX_NAME),
            serde_json::to_vec(&CorpusIndex {
                schema: 1,
                entries: Vec::new(),
            })?,
        )?;
        assert!(matches!(
            load_qemu_fuzz_corpus(directory.path()),
            Err(CliError::Artifact(message)) if message.contains("unsupported schema")
        ));
        Ok(())
    }
}
