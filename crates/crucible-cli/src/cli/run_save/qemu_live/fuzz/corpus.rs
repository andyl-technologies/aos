//! Current-format durable corpus index and authenticated QEMU fuzz entry reopening.
//!
//! The mutable `live-fuzz-corpus.json` root names immutable DagStore descriptors.
//! Each descriptor addresses the reproduction artifact, choice replay closure, and
//! coverage-only event-log projection used to restore deterministic guidance.

use super::*;

use std::io::Read;

use serde::{Deserialize, Serialize};

const INDEX_NAME: &str = "live-fuzz-corpus.json";
const CORPUS_SCHEMA: u32 = 1;
const MAX_INDEX_BYTES: u64 = 8 * 1024 * 1024;
const MAX_DESCRIPTOR_BYTES: u64 = 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 128 * 1024 * 1024;
const MAX_CLOSURE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_COVERAGE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusIndex {
    schema: u32,
    entries: Vec<crucible::ContentHash>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusDescriptor {
    schema: u32,
    artifact: crucible::ContentHash,
    replayed_state: crucible::ContentHash,
    closure: crucible::ContentHash,
    coverage_events: crucible::ContentHash,
    coverage_fingerprint: crucible::ContentHash,
    coverage_ids: Vec<crucible::ContentHash>,
    parent: Option<crucible::ContentHash>,
    sample_index: u64,
    energy: u64,
    novel_coverage: usize,
    resumable_choice: bool,
}

pub(super) fn load_qemu_fuzz_corpus(path: &Path) -> Result<Vec<LiveFuzzCorpusCandidate>, CliError> {
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

    let store = crucible::LocalDagStore::new(path.to_path_buf());
    let mut corpus = Vec::with_capacity(index.entries.len());
    for key in index.entries {
        corpus.push(load_entry(&store, key)?);
    }
    Ok(corpus)
}

pub(super) fn persist_qemu_fuzz_corpus(
    path: &Path,
    candidates: &[LiveFuzzCorpusCandidate],
) -> Result<(usize, u64), CliError> {
    let store = crucible::LocalDagStore::new(path.to_path_buf());
    let mut descriptors = Vec::with_capacity(candidates.len());
    let mut artifact_coverage = std::collections::BTreeMap::new();
    let mut puts = 0;

    for candidate in candidates {
        let artifact_id = candidate.artifact.id();
        let coverage = candidate.feedback.fingerprint();
        if let Some(previous) = artifact_coverage.insert(artifact_id, coverage)
            && previous != coverage
        {
            return Err(artifact_error(
                "QEMU fuzz produced conflicting coverage for one reproduction artifact",
            ));
        }
        if candidate.coverage_ids.is_empty() {
            return Err(artifact_error(
                "QEMU fuzz corpus contains an entry without coverage",
            ));
        }

        let key = match candidate.descriptor {
            Some(key) => key,
            None => {
                let descriptor = store_candidate(&store, candidate)?;
                puts += 4;
                descriptor
            }
        };
        descriptors.push(key);
    }
    descriptors.sort_unstable();
    descriptors.dedup();

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

fn store_candidate(
    store: &crucible::LocalDagStore,
    candidate: &LiveFuzzCorpusCandidate,
) -> Result<crucible::ContentHash, CliError> {
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
    let coverage_bytes = serde_json::to_vec(&candidate.coverage_entries)
        .map_err(|error| artifact_error(format!("encode QEMU fuzz coverage: {error}")))?;
    if coverage_bytes.len() as u64 > MAX_COVERAGE_BYTES {
        return Err(artifact_error(
            "QEMU fuzz coverage projection exceeds its size bound",
        ));
    }
    let coverage_events = store.put(&coverage_bytes).map_err(CliError::Store)?;
    let descriptor = CorpusDescriptor {
        schema: CORPUS_SCHEMA,
        artifact,
        replayed_state,
        closure,
        coverage_events,
        coverage_fingerprint: candidate.feedback.fingerprint(),
        coverage_ids: candidate.coverage_ids.iter().copied().collect(),
        parent: candidate.parent,
        sample_index: candidate.sample_index,
        energy: candidate.energy,
        novel_coverage: candidate.novel_coverage,
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
    load_entry(store, key)?;
    Ok(key)
}

fn load_entry(
    store: &crucible::LocalDagStore,
    key: crucible::ContentHash,
) -> Result<LiveFuzzCorpusCandidate, CliError> {
    let descriptor_bytes = read_bounded_object(store, key, MAX_DESCRIPTOR_BYTES)?;
    let descriptor: CorpusDescriptor = serde_json::from_slice(&descriptor_bytes)
        .map_err(|error| artifact_error(format!("decode QEMU fuzz corpus entry: {error}")))?;
    if descriptor.schema != CORPUS_SCHEMA
        || descriptor.coverage_ids.is_empty()
        || !strictly_sorted(&descriptor.coverage_ids)
        || descriptor.novel_coverage == 0
    {
        return Err(artifact_error(
            "QEMU fuzz corpus entry has invalid current-format metadata",
        ));
    }

    let artifact_bytes = read_bounded_object(store, descriptor.artifact, MAX_ARTIFACT_BYTES)?;
    let artifact = crucible::ReproductionArtifact::from_compact_binary(&artifact_bytes)
        .map_err(|error| artifact_error(format!("decode QEMU fuzz reproduction: {error}")))?;
    if artifact.id() != descriptor.artifact || artifact.to_compact_binary() != artifact_bytes {
        return Err(artifact_error(
            "QEMU fuzz reproduction artifact is noncanonical",
        ));
    }
    artifact
        .verify_replay(descriptor.replayed_state)
        .map_err(|error| {
            artifact_error(format!("replay retained QEMU fuzz reproduction: {error}"))
        })?;

    let closure_bytes = read_bounded_object(store, descriptor.closure, MAX_CLOSURE_BYTES)?;
    let replay_closure =
        crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignReplayClosure::from_canonical_bytes(
            &closure_bytes,
        )
        .and_then(|closure| {
            closure.validate_for_schedule(artifact.scenario_form(), artifact.schedule())?;
            Ok(closure)
        })
        .map_err(|error| artifact_error(format!("authenticate QEMU fuzz choice closure: {error}")))?;
    let coverage_bytes =
        read_bounded_object(store, descriptor.coverage_events, MAX_COVERAGE_BYTES)?;
    let coverage_entries: Vec<crucible::SchedulerEventLogEntry> =
        serde_json::from_slice(&coverage_bytes)
            .map_err(|error| artifact_error(format!("decode QEMU fuzz coverage: {error}")))?;
    if coverage_entries
        .iter()
        .any(|entry| !entry.has_valid_content_hash())
        || coverage_entries
            .windows(2)
            .any(|pair| pair[0].sequence() >= pair[1].sequence())
    {
        return Err(artifact_error(
            "QEMU fuzz coverage entries fail event-log authentication",
        ));
    }
    let feedback = crucible::EventLogCoverageFeedback::from_event_log(&coverage_entries);
    let coverage_ids: std::collections::BTreeSet<_> = feedback
        .projection()
        .entries()
        .iter()
        .map(|entry| entry.observation.content_hash())
        .collect();
    if feedback.projection().len() != coverage_entries.len()
        || feedback.fingerprint() != descriptor.coverage_fingerprint
        || coverage_ids.iter().copied().collect::<Vec<_>>() != descriptor.coverage_ids
    {
        return Err(artifact_error(
            "QEMU fuzz coverage does not match its retained projection",
        ));
    }

    Ok(LiveFuzzCorpusCandidate {
        artifact,
        feedback,
        coverage_entries,
        coverage_ids,
        novel_coverage: descriptor.novel_coverage,
        parent: descriptor.parent,
        sample_index: descriptor.sample_index,
        energy: descriptor.energy,
        replay_closure,
        resumable_choice: descriptor.resumable_choice,
        descriptor: Some(key),
    })
}

fn read_bounded_object(
    store: &crucible::LocalDagStore,
    key: crucible::ContentHash,
    limit: u64,
) -> Result<Vec<u8>, CliError> {
    let path = store.object_path(&key);
    let bytes = read_bounded_file(&path, limit)?;
    if crucible::ContentHash::from_bytes(&bytes) != key {
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

fn strictly_sorted(values: &[crucible::ContentHash]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durable_corpus_reopens_coverage_and_rejects_corruption()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = crucible::LocalDagStore::new(directory.path());
        store.put(b"orphaned-before-first-index-publish")?;
        assert!(load_qemu_fuzz_corpus(directory.path())?.is_empty());

        let scenario = crucible::happy_path_scenario()?.scenario;
        let configuration = crucible::Configuration::genesis(scenario.scenario_def());
        let artifact = crucible::ReproductionArtifact::capture(&scenario, &configuration.schedule)?;
        let coverage_entries = vec![
            crucible_core::test_support::condition_observation_entry_for_test(
                0,
                &crucible::ObservableEvent::coverage_block(
                    crucible::Icount { retired: 10 },
                    crucible::NodeId {
                        name: String::from("node-0"),
                    },
                    0x4000,
                    0x20,
                ),
            ),
        ];
        let feedback = crucible::EventLogCoverageFeedback::from_event_log(&coverage_entries);
        let coverage_ids = feedback
            .projection()
            .entries()
            .iter()
            .map(|entry| entry.observation.content_hash())
            .collect();
        let replay_closure =
            crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignReplayClosure::from_canonical_bytes(
                b"CCRC\0\0\0\x01\0\0\0\0",
            )?;
        let candidate = LiveFuzzCorpusCandidate {
            artifact,
            feedback,
            coverage_entries,
            coverage_ids,
            novel_coverage: 1,
            parent: None,
            sample_index: 0,
            energy: 1,
            replay_closure,
            resumable_choice: true,
            descriptor: None,
        };

        assert_eq!(
            persist_qemu_fuzz_corpus(directory.path(), &[candidate])?,
            (1, 4)
        );
        let mut reopened = load_qemu_fuzz_corpus(directory.path())?;
        assert_eq!(reopened.len(), 1);
        assert_eq!(reopened[0].coverage_ids.len(), 1);
        assert_eq!(reopened[0].feedback.projection().len(), 1);
        assert_eq!(
            persist_qemu_fuzz_corpus(directory.path(), &reopened)?,
            (1, 0)
        );

        let next_scenario = crucible::fault_campaign_family()?
            .instantiate_sample(0)?
            .into_form();
        let next_configuration = crucible::Configuration::genesis(next_scenario.scenario_def());
        let next_artifact =
            crucible::ReproductionArtifact::capture(&next_scenario, &next_configuration.schedule)?;
        let mut next_events = reopened[0].coverage_entries.clone();
        next_events.push(
            crucible_core::test_support::condition_observation_entry_for_test(
                1,
                &crucible::ObservableEvent::coverage_block(
                    crucible::Icount { retired: 20 },
                    crucible::NodeId {
                        name: String::from("node-0"),
                    },
                    0x5000,
                    0x20,
                ),
            ),
        );
        let next_feedback = crucible::EventLogCoverageFeedback::from_event_log(&next_events);
        let next_ids = next_feedback
            .projection()
            .entries()
            .iter()
            .map(|entry| entry.observation.content_hash())
            .collect();
        let next_candidate = LiveFuzzCorpusCandidate {
            artifact: next_artifact,
            feedback: next_feedback,
            coverage_entries: next_events,
            coverage_ids: next_ids,
            novel_coverage: 0,
            parent: Some(reopened[0].artifact.id()),
            sample_index: 1,
            energy: 2,
            replay_closure: reopened[0].replay_closure.clone(),
            resumable_choice: true,
            descriptor: None,
        };
        let mut observed = reopened[0].coverage_ids.clone();
        let mut guidance = vec![reopened[0].feedback.clone()];
        assert_eq!(
            admit_qemu_fuzz_candidates(
                &mut reopened,
                &mut observed,
                &mut guidance,
                vec![next_candidate],
            ),
            1,
        );
        assert_eq!(observed.len(), 2);
        assert_eq!(reopened.len(), 1);
        assert_eq!(reopened[0].coverage_ids.len(), 2);
        assert_eq!(
            persist_qemu_fuzz_corpus(directory.path(), &reopened)?,
            (1, 4)
        );
        let retained = load_qemu_fuzz_corpus(directory.path())?;
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].coverage_ids.len(), 2);

        let descriptor = retained[0].descriptor.ok_or("missing descriptor")?;
        fs::write(store.object_path(&descriptor), b"corrupt descriptor")?;
        assert!(load_qemu_fuzz_corpus(directory.path()).is_err());
        Ok(())
    }
}
