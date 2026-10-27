//! Exact-ID scenario reuse within a genuine lineage load and fresh-call refusal.

use super::*;

fn lineage_fixture() -> (Corpus, CampaignLineage) {
    let corpus = corpus(0);
    let snapshot = corpus
        .repository
        .read_snapshot(corpus.head)
        .expect("snapshot");
    let lineage = corpus
        .repository
        .read_lineage(snapshot.snapshot.lineage().content_id())
        .expect("initial lineage");
    corpus.backend.reset();
    (corpus, lineage)
}

fn assert_integrity<T>(result: Result<T, CampaignRepositoryError>, expected: &'static str) {
    assert!(matches!(
        result,
        Err(CampaignRepositoryError::Integrity { reason }) if reason == expected
    ));
}

#[test]
fn lineage_authenticates_one_exact_scenario_without_changing_canonical_identity() {
    let (corpus, lineage) = lineage_fixture();
    let scenario_id = lineage.scenario_content().content_id();
    let genesis_id = lineage.genesis_content().content_id();
    let lineage_id = lineage.id().expect("lineage ID").content_id();

    // Genuine standalone readers retain their original independent reads.
    let scenario = corpus
        .repository
        .read_scenario_artifact(scenario_id)
        .expect("scenario");
    let genesis = corpus
        .repository
        .read_configuration_artifact(genesis_id)
        .expect("genesis");
    assert_eq!(corpus.backend.count(scenario_id), 2);
    assert_eq!(
        scenario.id().expect("scenario ID"),
        lineage.scenario_content()
    );
    assert_eq!(genesis.id().expect("genesis ID"), lineage.genesis_content());

    corpus.backend.reset();
    let loaded = corpus.repository.read_lineage(lineage_id).expect("lineage");
    assert_eq!(loaded, lineage);
    assert_eq!(loaded.canonical_bytes(), lineage.canonical_bytes());
    assert_eq!(loaded.id().expect("loaded ID").content_id(), lineage_id);
    assert_eq!(corpus.backend.count(lineage_id), 1);
    assert_eq!(corpus.backend.count(genesis_id), 1);
    assert_eq!(corpus.backend.count(scenario_id), 1);
    assert_eq!(corpus.backend.total(), 3);
}

#[test]
fn lineage_reauthenticates_on_every_call_and_refuses_later_missing_or_corrupt_bytes() {
    let (corpus, lineage) = lineage_fixture();
    let lineage_id = lineage.id().expect("lineage ID").content_id();

    for target in [
        lineage_id,
        lineage.scenario_content().content_id(),
        lineage.genesis_content().content_id(),
    ] {
        for fault in [ReadFault::Missing, ReadFault::Corrupt] {
            corpus.backend.reset();
            corpus.backend.fail_after(target, 1, fault);
            assert_eq!(
                corpus
                    .repository
                    .read_lineage(lineage_id)
                    .expect("first authentic load"),
                lineage
            );
            assert!(corpus.repository.read_lineage(lineage_id).is_err());
            assert_eq!(corpus.backend.count(target), 2);
        }
    }
}

#[test]
fn lineage_refuses_missing_or_corrupt_inputs_before_any_reuse() {
    let (corpus, lineage) = lineage_fixture();
    let lineage_id = lineage.id().expect("lineage ID").content_id();

    for target in [
        lineage_id,
        lineage.scenario_content().content_id(),
        lineage.genesis_content().content_id(),
    ] {
        for fault in [ReadFault::Missing, ReadFault::Corrupt] {
            corpus.backend.reset();
            corpus.backend.fail_after(target, 0, fault);
            assert!(corpus.repository.read_lineage(lineage_id).is_err());
            assert_eq!(corpus.backend.count(target), 1);
        }
    }
}

#[test]
fn lineage_never_substitutes_a_same_semantic_scenario_with_different_content() {
    let (corpus, lineage) = lineage_fixture();
    let repository = &corpus.repository;
    let other = ScenarioArtifact::new(
        lineage.scenario(),
        lineage.scenario_schema(),
        b"other scenario bytes".to_vec(),
    )
    .expect("other scenario");
    let other_id = other.id().expect("other ID");
    repository
        .put_scenario_artifact(&other)
        .expect("publish other scenario");
    let genesis = ConfigurationArtifact::new(
        lineage.scenario(),
        other_id,
        lineage.genesis(),
        1,
        b"other genesis".to_vec(),
    )
    .expect("other genesis");
    let genesis_id = repository
        .put_configuration_artifact(&genesis)
        .expect("publish other genesis");
    let mismatched = CampaignLineage::new(
        lineage.scenario(),
        lineage.scenario_content(),
        lineage.genesis(),
        genesis.id().expect("genesis ID"),
        lineage.crucible_version(),
        "test-execution-model",
        lineage.protocol_versions().clone(),
        lineage.scenario_schema(),
        lineage.exact_closure_schema(),
    )
    .expect("mismatched lineage");
    let id = repository
        .put_lineage(&mismatched)
        .expect("publish mismatched lineage");

    corpus.backend.reset();
    assert_integrity(
        repository.read_lineage(id),
        "lineage-execution-model-artifact-mismatch",
    );
    assert_eq!(
        corpus
            .backend
            .count(lineage.scenario_content().content_id()),
        1
    );
    assert_eq!(corpus.backend.count(genesis_id), 1);
    assert_eq!(corpus.backend.count(other_id.content_id()), 1);

    for fault in [ReadFault::Missing, ReadFault::Corrupt] {
        corpus.backend.reset();
        corpus.backend.fail_after(other_id.content_id(), 0, fault);
        let result = repository.read_lineage(id);
        assert!(result.is_err());
        // The different child is authenticated before the later lineage mismatch.
        assert!(!matches!(
            result,
            Err(CampaignRepositoryError::Integrity {
                reason: "lineage-execution-model-artifact-mismatch"
            })
        ));
        assert_eq!(corpus.backend.count(other_id.content_id()), 1);
    }
}
