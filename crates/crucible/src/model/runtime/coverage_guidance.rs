//! Coverage-guided fuzzing and adaptive strategy helpers.

use super::*;

pub(in crate::model) fn run_coverage_guided_fuzz(
    family: &ScenarioFamily,
    config: CoverageGuidedFuzzConfig,
    feedback: &[EventLogCoverageFeedback],
) -> Result<CoverageGuidedFuzzRun, EngineError> {
    let cardinality = family.space().cardinality()?;
    let mut iterations = Vec::new();
    let mut seen_coverage = BTreeSet::new();
    let mut corpus = vec![coverage_guided_fuzz_seed_corpus_entry(config, cardinality)];

    for sequence in 0..config.iterations {
        let coverage_fingerprint = coverage_guided_fuzz_feedback_fingerprint(feedback, sequence);
        let selected_corpus_entry = coverage_guided_fuzz_select_corpus_entry(
            config,
            sequence,
            coverage_fingerprint,
            &corpus,
        );
        let energy = coverage_guided_fuzz_energy(config, sequence, coverage_fingerprint);
        let sample_index =
            coverage_guided_fuzz_sample_index(config, sequence, coverage_fingerprint, cardinality);
        let scenario = family.instantiate_sample(sample_index)?;
        let params = scenario.params();
        let root = scenario.genesis_configuration();
        let mutation =
            coverage_guided_fuzz_override_decision(config, sequence, sample_index, params);
        let configuration = try_step(root.configuration(), mutation.clone())?;
        let new_coverage = coverage_fingerprint != ContentHash::default()
            && seen_coverage.insert(coverage_fingerprint);
        if new_coverage {
            corpus.push(configuration.id());
        }
        iterations.push(CoverageGuidedFuzzIteration {
            sequence,
            sample_index,
            params,
            scenario,
            selected_corpus_entry,
            energy,
            configuration,
            mutation,
            coverage_fingerprint,
            new_coverage,
        });
    }

    let coverage_biased_order = coverage_guided_fuzz_order(&iterations);
    Ok(CoverageGuidedFuzzRun {
        config,
        iterations,
        coverage_biased_order,
    })
}

pub(in crate::model) fn run_coverage_guided_fuzz_corpus<S>(
    family: &ScenarioFamily,
    store: &S,
    config: CoverageGuidedFuzzConfig,
    corpus_config: CoverageGuidedCorpusConfig,
    feedback: &[EventLogCoverageFeedback],
) -> Result<CoverageGuidedCorpusRun, CoverageGuidedCorpusError>
where
    S: DagStore + ?Sized,
{
    let cardinality =
        family
            .space()
            .cardinality()
            .map_err(|source| CoverageGuidedCorpusError::Engine {
                operation: "count-family-space",
                source: Box::new(source),
            })?;
    let mut corpus = CoverageGuidedCorpus::new();
    let seed =
        family
            .instantiate_sample(0)
            .map_err(|source| CoverageGuidedCorpusError::Engine {
                operation: "instantiate-seed-corpus-entry",
                source: Box::new(source),
            })?;
    let seed_artifact =
        ReproductionArtifact::capture(seed.form(), &Schedule::empty()).map_err(|source| {
            CoverageGuidedCorpusError::Engine {
                operation: "capture-seed-corpus-artifact",
                source: Box::new(source),
            }
        })?;
    let seed_replay =
        seed_artifact
            .replay()
            .map_err(|source| CoverageGuidedCorpusError::Engine {
                operation: "replay-seed-corpus-artifact",
                source: Box::new(source),
            })?;
    let seed_store_key = persist_corpus_artifact(store, &seed_artifact)?;
    let seed_energy = coverage_guided_corpus_energy(
        corpus_config.seed,
        0,
        ContentHash::default(),
        seed_artifact.id(),
    );
    let seed_descriptor_key = persist_corpus_entry_descriptor(
        store,
        CoverageGuidedCorpusEntryDescriptor {
            artifact: seed_artifact.id(),
            store_key: seed_store_key,
            scenario: seed_replay.scenario,
            schedule: seed_replay.schedule,
            replayed_state: seed_replay.state,
            coverage_fingerprint: ContentHash::default(),
            energy: seed_energy,
            parent: None,
            origin: CoverageGuidedCorpusEntryOrigin::Seed,
        },
    )?;
    corpus.insert(CoverageGuidedCorpusEntry {
        artifact: seed_artifact.id(),
        store_key: seed_store_key,
        descriptor_key: seed_descriptor_key,
        scenario: seed_replay.scenario,
        schedule: seed_replay.schedule,
        replayed_state: seed_replay.state,
        coverage_fingerprint: ContentHash::default(),
        energy: seed_energy,
        parent: None,
        origin: CoverageGuidedCorpusEntryOrigin::Seed,
    });

    let mut iterations = Vec::new();
    let mut admissions = Vec::new();
    let mut store_puts = 2u64;
    let mut replay_oracle_validations = 1u64;

    for sequence in 0..config.iterations {
        let coverage_fingerprint = coverage_guided_fuzz_feedback_fingerprint(feedback, sequence);
        let selected_parent = coverage_guided_corpus_select_parent(
            &corpus,
            corpus_config,
            sequence,
            coverage_fingerprint,
        )
        .ok_or_else(|| CoverageGuidedCorpusError::Engine {
            operation: "select-corpus-parent",
            source: Box::new(EngineError::ScenarioFamilyInvalidSpace {
                reason: "coverage-guided corpus has no seed entry",
            }),
        })?;
        let sample_index =
            coverage_guided_fuzz_sample_index(config, sequence, coverage_fingerprint, cardinality);
        let scenario = family.instantiate_sample(sample_index).map_err(|source| {
            CoverageGuidedCorpusError::Engine {
                operation: "instantiate-fuzz-candidate",
                source: Box::new(source),
            }
        })?;
        let params = scenario.params();
        let root = scenario.genesis_configuration();
        let mutation =
            coverage_guided_fuzz_override_decision(config, sequence, sample_index, params);
        let configuration = try_step(root.configuration(), mutation.clone()).map_err(|source| {
            CoverageGuidedCorpusError::Engine {
                operation: "mutate-fuzz-candidate",
                source: Box::new(source),
            }
        })?;
        let artifact = ReproductionArtifact::capture(scenario.form(), &configuration.schedule)
            .map_err(|source| CoverageGuidedCorpusError::Engine {
                operation: "capture-fuzz-candidate-artifact",
                source: Box::new(source),
            })?;
        let replay = artifact
            .replay()
            .map_err(|source| CoverageGuidedCorpusError::Engine {
                operation: "replay-fuzz-candidate-artifact",
                source: Box::new(source),
            })?;
        replay_oracle_validations = replay_oracle_validations.saturating_add(1);
        let energy = coverage_guided_corpus_energy(
            corpus_config.seed,
            sequence.saturating_add(1),
            coverage_fingerprint,
            artifact.id(),
        );
        let decision = if let Some(retained) = corpus.entries.get(&artifact.id()) {
            CoverageGuidedCorpusAdmissionDecision::DuplicateArtifact {
                retained: retained.artifact,
            }
        } else if let Some(retained) = corpus.coverage_owner(coverage_fingerprint) {
            CoverageGuidedCorpusAdmissionDecision::PrunedSubsumedCoverage { retained }
        } else {
            let store_key = persist_corpus_artifact(store, &artifact)?;
            let descriptor_key = persist_corpus_entry_descriptor(
                store,
                CoverageGuidedCorpusEntryDescriptor {
                    artifact: artifact.id(),
                    store_key,
                    scenario: replay.scenario,
                    schedule: replay.schedule,
                    replayed_state: replay.state,
                    coverage_fingerprint,
                    energy,
                    parent: Some(selected_parent),
                    origin: CoverageGuidedCorpusEntryOrigin::FuzzIteration { sequence },
                },
            )?;
            store_puts = store_puts.saturating_add(2);
            corpus.insert(CoverageGuidedCorpusEntry {
                artifact: artifact.id(),
                store_key,
                descriptor_key,
                scenario: replay.scenario,
                schedule: replay.schedule,
                replayed_state: replay.state,
                coverage_fingerprint,
                energy,
                parent: Some(selected_parent),
                origin: CoverageGuidedCorpusEntryOrigin::FuzzIteration { sequence },
            });
            CoverageGuidedCorpusAdmissionDecision::AdmittedNewCoverage { store_key }
        };
        let new_coverage = decision.is_admitted();

        admissions.push(CoverageGuidedCorpusAdmission {
            sequence,
            artifact: artifact.id(),
            coverage_fingerprint,
            selected_parent,
            energy,
            decision,
        });
        iterations.push(CoverageGuidedFuzzIteration {
            sequence,
            sample_index,
            params,
            scenario,
            selected_corpus_entry: selected_parent,
            energy,
            configuration,
            mutation,
            coverage_fingerprint,
            new_coverage,
        });
    }

    let coverage_biased_order = coverage_guided_fuzz_order(&iterations);
    let retained_entries = corpus.len() as u64;
    Ok(CoverageGuidedCorpusRun {
        fuzz: CoverageGuidedFuzzRun {
            config,
            iterations,
            coverage_biased_order,
        },
        corpus,
        admissions,
        throughput: CoverageGuidedFuzzThroughputReport {
            target: corpus_config.throughput_target,
            generated_mutants: config.iterations,
            deterministic_work_units: config.iterations,
            replay_oracle_validations,
            store_puts,
            retained_entries,
        },
    })
}

pub(in crate::model) fn persist_corpus_artifact<S>(
    store: &S,
    artifact: &ReproductionArtifact,
) -> Result<ContentHash, CoverageGuidedCorpusError>
where
    S: DagStore + ?Sized,
{
    let store_key = store.put(&artifact.to_compact_binary()).map_err(|source| {
        CoverageGuidedCorpusError::Store {
            operation: "put-corpus-artifact",
            source,
        }
    })?;
    if store_key != artifact.id() {
        return Err(CoverageGuidedCorpusError::ArtifactStoreKeyMismatch {
            artifact: artifact.id(),
            store_key,
        });
    }
    Ok(store_key)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(in crate::model) struct CoverageGuidedCorpusEntryDescriptor {
    pub(in crate::model) artifact: ContentHash,
    pub(in crate::model) store_key: ContentHash,
    pub(in crate::model) scenario: ContentHash,
    pub(in crate::model) schedule: ContentHash,
    pub(in crate::model) replayed_state: ContentHash,
    pub(in crate::model) coverage_fingerprint: ContentHash,
    pub(in crate::model) energy: u64,
    pub(in crate::model) parent: Option<ContentHash>,
    pub(in crate::model) origin: CoverageGuidedCorpusEntryOrigin,
}

pub(in crate::model) fn persist_corpus_entry_descriptor<S>(
    store: &S,
    descriptor: CoverageGuidedCorpusEntryDescriptor,
) -> Result<ContentHash, CoverageGuidedCorpusError>
where
    S: DagStore + ?Sized,
{
    store
        .put(&coverage_guided_corpus_entry_descriptor_bytes(descriptor))
        .map_err(|source| CoverageGuidedCorpusError::Store {
            operation: "put-corpus-entry-descriptor",
            source,
        })
}

pub(in crate::model) fn coverage_guided_corpus_entry_descriptor_bytes(
    descriptor: CoverageGuidedCorpusEntryDescriptor,
) -> Vec<u8> {
    let origin = match descriptor.origin {
        CoverageGuidedCorpusEntryOrigin::Seed => String::from("seed"),
        CoverageGuidedCorpusEntryOrigin::FuzzIteration { sequence } => {
            format!("fuzz-iteration:{sequence}")
        }
    };
    let parent = descriptor
        .parent
        .map(ContentHash::to_hex)
        .unwrap_or_else(|| String::from("none"));
    format!(
        "crucible.coverage-guided-corpus.entry.v1\nartifact={}\nartifact_store={}\nscenario={}\nschedule={}\nreplayed_state={}\ncoverage={}\nenergy={}\nparent={parent}\norigin={origin}\n",
        descriptor.artifact.to_hex(),
        descriptor.store_key.to_hex(),
        descriptor.scenario.to_hex(),
        descriptor.schedule.to_hex(),
        descriptor.replayed_state.to_hex(),
        descriptor.coverage_fingerprint.to_hex(),
        descriptor.energy
    )
    .into_bytes()
}

pub(in crate::model) fn coverage_guided_fuzz_feedback_fingerprint(
    feedback: &[EventLogCoverageFeedback],
    sequence: u64,
) -> ContentHash {
    if feedback.is_empty() {
        return ContentHash::default();
    }

    let index = (sequence % feedback.len() as u64) as usize;
    feedback[index].fingerprint_for(EventLogCoverageFeedbackConsumer::CoverageGuidedFuzzing)
}

pub(in crate::model) fn coverage_guided_fuzz_seed_corpus_entry(
    config: CoverageGuidedFuzzConfig,
    cardinality: u64,
) -> ContentHash {
    ContentHash::from_canonical_material(
        "crucible.coverage-guided-fuzz.seed-corpus-entry.v1",
        &format!(
            "meta_seed={}\ncardinality={cardinality}",
            config.meta_seed.to_hex()
        ),
    )
}

pub(in crate::model) fn coverage_guided_fuzz_select_corpus_entry(
    config: CoverageGuidedFuzzConfig,
    sequence: u64,
    coverage_fingerprint: ContentHash,
    corpus: &[ContentHash],
) -> ContentHash {
    let material = format!(
        "meta_seed={}\nsequence={sequence}\ncoverage={}\ncorpus_len={}",
        config.meta_seed.to_hex(),
        coverage_fingerprint.to_hex(),
        corpus.len()
    );
    let index = content_hash_low_u64(ContentHash::from_canonical_material(
        "crucible.coverage-guided-fuzz.corpus-selection.v1",
        &material,
    )) as usize
        % corpus.len();
    corpus[index]
}

pub(in crate::model) fn coverage_guided_corpus_select_parent(
    corpus: &CoverageGuidedCorpus,
    config: CoverageGuidedCorpusConfig,
    sequence: u64,
    coverage_fingerprint: ContentHash,
) -> Option<ContentHash> {
    let total_energy = corpus.entries.values().fold(0u64, |total, entry| {
        total.saturating_add(entry.energy.max(1))
    });
    if total_energy == 0 {
        return corpus.entries.keys().next().copied();
    }

    let material = format!(
        "seed={}\nsequence={sequence}\ncoverage={}\ncorpus={}",
        config.seed.to_hex(),
        coverage_fingerprint.to_hex(),
        corpus.fingerprint().to_hex()
    );
    let mut ticket = content_hash_low_u64(ContentHash::from_canonical_material(
        "crucible.coverage-guided-corpus.parent-selection.v1",
        &material,
    )) % total_energy;
    for entry in corpus.entries.values() {
        let weight = entry.energy.max(1);
        if ticket < weight {
            return Some(entry.artifact);
        }
        ticket = ticket.saturating_sub(weight);
    }
    corpus.entries.keys().next_back().copied()
}

pub(in crate::model) fn coverage_guided_corpus_energy(
    seed: Seed,
    sequence: u64,
    coverage_fingerprint: ContentHash,
    artifact: ContentHash,
) -> u64 {
    let material = format!(
        "seed={}\nsequence={sequence}\ncoverage={}\nartifact={}",
        seed.to_hex(),
        coverage_fingerprint.to_hex(),
        artifact.to_hex()
    );
    let base = content_hash_low_u64(ContentHash::from_canonical_material(
        "crucible.coverage-guided-corpus.energy.v1",
        &material,
    ));
    let novelty_floor = if coverage_fingerprint == ContentHash::default() {
        1
    } else {
        GUIDANCE_SCORE_ONE_MICRO
    };
    novelty_floor.saturating_add(base % GUIDANCE_SCORE_ONE_MICRO)
}

pub(in crate::model) fn coverage_guided_fuzz_energy(
    config: CoverageGuidedFuzzConfig,
    sequence: u64,
    coverage_fingerprint: ContentHash,
) -> u64 {
    let material = format!(
        "meta_seed={}\nsequence={sequence}\ncoverage={}",
        config.meta_seed.to_hex(),
        coverage_fingerprint.to_hex()
    );
    let base = content_hash_low_u64(ContentHash::from_canonical_material(
        "crucible.coverage-guided-fuzz.energy.v1",
        &material,
    ));
    1 + (base % 1024)
}

pub(in crate::model) fn coverage_guided_fuzz_sample_index(
    config: CoverageGuidedFuzzConfig,
    sequence: u64,
    coverage_fingerprint: ContentHash,
    cardinality: u64,
) -> u64 {
    let material = format!(
        "meta_seed={}\ncoverage={}",
        config.meta_seed.to_hex(),
        coverage_fingerprint.to_hex()
    );
    let bias = content_hash_low_u64(ContentHash::from_canonical_material(
        COVERAGE_GUIDED_FUZZ_SAMPLE_DOMAIN,
        &material,
    ));
    bias.wrapping_add(sequence) % cardinality
}

pub(in crate::model) fn coverage_guided_fuzz_override_decision(
    config: CoverageGuidedFuzzConfig,
    sequence: u64,
    sample_index: u64,
    params: FamilyParams,
) -> Decision {
    let material = format!(
        "meta_seed={}\nsequence={sequence}\nsample_index={sample_index}\nseed={}\ntopology_size={}\ntopology_shape={:?}",
        config.meta_seed.to_hex(),
        params.seed.to_hex(),
        params.topology_size,
        params.topology_shape
    );
    let choice = content_hash_low_u64(ContentHash::from_canonical_material(
        COVERAGE_GUIDED_FUZZ_OVERRIDE_DOMAIN,
        &material,
    ));
    Decision::Override(OverrideDecision {
        point: SchedulingPoint {
            key: format!("coverage-guided-fuzz/{sequence:016}"),
        },
        choice: ChoiceTag {
            name: format!("mutant-{choice:016x}"),
        },
    })
}

pub(in crate::model) fn coverage_guided_fuzz_order(
    iterations: &[CoverageGuidedFuzzIteration],
) -> Vec<ContentHash> {
    let mut ordered = iterations.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        coverage_guided_fuzz_iteration_key(left)
            .cmp(&coverage_guided_fuzz_iteration_key(right))
            .then_with(|| left.configuration_id().cmp(&right.configuration_id()))
    });
    ordered
        .into_iter()
        .map(CoverageGuidedFuzzIteration::configuration_id)
        .collect()
}

pub(in crate::model) fn coverage_guided_fuzz_iteration_key(
    iteration: &CoverageGuidedFuzzIteration,
) -> (u8, u8, ContentHash) {
    let old_coverage = u8::from(!iteration.new_coverage);
    let unknown_coverage = u8::from(iteration.coverage_fingerprint == ContentHash::default());
    (
        old_coverage,
        unknown_coverage,
        iteration.coverage_fingerprint,
    )
}

pub(in crate::model) fn content_hash_low_u64(hash: ContentHash) -> u64 {
    u64::from_le_bytes([
        hash.bytes[0],
        hash.bytes[1],
        hash.bytes[2],
        hash.bytes[3],
        hash.bytes[4],
        hash.bytes[5],
        hash.bytes[6],
        hash.bytes[7],
    ])
}

pub(in crate::model) fn guidance_signal_score(
    signal: GuidanceSignalKind,
    input: GuidanceSignalInput,
) -> GuidanceScore {
    match signal {
        GuidanceSignalKind::Coverage => CoverageGuidanceSignal.score(input),
        GuidanceSignalKind::NoveltyRarity => NoveltyRarityGuidanceSignal.score(input),
        GuidanceSignalKind::AssertionProximity => AssertionProximityGuidanceSignal.score(input),
    }
}

pub(in crate::model) fn select_adaptive_strategy_arm(
    config: &AdaptiveStrategyConfig,
    graph_fingerprint: ContentHash,
    rewards: &BTreeMap<AdaptiveStrategyArm, AdaptiveStrategyReward>,
    pulls: &BTreeMap<AdaptiveStrategyArm, u64>,
    sequence: u64,
) -> AdaptiveStrategyArm {
    if !config.enabled {
        return AdaptiveStrategyArm::BreadthFirst;
    }
    if config.breadth_first_floor_interval != 0
        && sequence.is_multiple_of(config.breadth_first_floor_interval)
        && config.arms.contains(&AdaptiveStrategyArm::BreadthFirst)
    {
        return AdaptiveStrategyArm::BreadthFirst;
    }

    config
        .arms
        .iter()
        .copied()
        .max_by_key(|arm| {
            (
                adaptive_strategy_arm_score(config, rewards, pulls, *arm),
                adaptive_strategy_arm_tie_break(config.seed, graph_fingerprint, *arm),
                std::cmp::Reverse(*arm),
            )
        })
        .unwrap_or(AdaptiveStrategyArm::BreadthFirst)
}

pub(in crate::model) fn adaptive_strategy_arm_score(
    config: &AdaptiveStrategyConfig,
    rewards: &BTreeMap<AdaptiveStrategyArm, AdaptiveStrategyReward>,
    pulls: &BTreeMap<AdaptiveStrategyArm, u64>,
    arm: AdaptiveStrategyArm,
) -> u64 {
    let pull_count = pulls.get(&arm).copied().unwrap_or_default();
    if pull_count == 0 {
        return u64::MAX;
    }
    let reward = rewards.get(&arm).copied().unwrap_or_default();
    let reward_total = adaptive_strategy_reward_total(reward);
    let exploitation = u128::from(reward_total)
        .saturating_mul(u128::from(ADAPTIVE_UCB_SCORE_ONE_MICRO))
        .checked_div(u128::from(pull_count))
        .unwrap_or_default()
        .min(u128::from(u64::MAX)) as u64;
    let total_pulls = pulls
        .values()
        .copied()
        .fold(0u64, u64::saturating_add)
        .max(1);
    let log2_total_micros = u64::from(total_pulls.saturating_add(1).ilog2())
        .saturating_mul(ADAPTIVE_UCB_SCORE_ONE_MICRO);
    let exploration_root = integer_square_root(
        u128::from(log2_total_micros)
            .saturating_mul(u128::from(ADAPTIVE_UCB_SCORE_ONE_MICRO))
            .checked_div(u128::from(pull_count))
            .unwrap_or_default(),
    );
    let exploration = u128::from(config.ucb_exploration_weight_micros)
        .saturating_mul(exploration_root)
        .checked_div(u128::from(ADAPTIVE_UCB_SCORE_ONE_MICRO))
        .unwrap_or_default()
        .min(u128::from(u64::MAX)) as u64;
    exploitation.saturating_add(exploration)
}

pub(in crate::model) fn adaptive_strategy_reward_total(reward: AdaptiveStrategyReward) -> u64 {
    let failure = if reward.confirmed_failure {
        ADAPTIVE_CONFIRMED_FAILURE_REWARD
    } else {
        0
    };
    reward
        .new_coverage
        .saturating_add(reward.novelty_gain)
        .saturating_add(reward.assertion_proximity_progress)
        .saturating_add(failure)
}

pub(in crate::model) fn adaptive_strategy_arm_tie_break(
    seed: Seed,
    graph_fingerprint: ContentHash,
    arm: AdaptiveStrategyArm,
) -> u64 {
    let material = format!(
        "seed={}\ngraph={}\narm={arm:?}",
        seed.to_hex(),
        graph_fingerprint.to_hex()
    );
    content_hash_low_u64(ContentHash::from_canonical_material(
        "crucible.adaptive-strategy.ucb-tie-break.v1",
        &material,
    ))
}

pub(in crate::model) fn integer_square_root(value: u128) -> u128 {
    if value < 2 {
        return value;
    }
    let mut low = 1u128;
    let mut high = value.min(u128::from(u64::MAX)).saturating_add(1);
    while low.saturating_add(1) < high {
        let midpoint = low.saturating_add(high.saturating_sub(low) / 2);
        if midpoint <= value / midpoint {
            low = midpoint;
        } else {
            high = midpoint;
        }
    }
    low
}

pub(in crate::model) fn adaptive_strategy_rewards_from_credits(
    credits: &[AdaptiveStrategyCredit],
) -> BTreeMap<AdaptiveStrategyArm, AdaptiveStrategyReward> {
    let mut ordered = credits.to_vec();
    ordered.sort_by_key(|credit| (credit.configuration, credit.arm));
    let mut rewards = BTreeMap::<AdaptiveStrategyArm, AdaptiveStrategyReward>::new();
    for credit in ordered {
        rewards
            .entry(credit.arm)
            .and_modify(|reward| {
                *reward = combine_adaptive_strategy_rewards(*reward, credit.reward);
            })
            .or_insert(credit.reward);
    }
    rewards
}

pub(in crate::model) fn combine_adaptive_strategy_rewards(
    left: AdaptiveStrategyReward,
    right: AdaptiveStrategyReward,
) -> AdaptiveStrategyReward {
    AdaptiveStrategyReward {
        new_coverage: left.new_coverage.saturating_add(right.new_coverage),
        novelty_gain: left.novelty_gain.saturating_add(right.novelty_gain),
        assertion_proximity_progress: left
            .assertion_proximity_progress
            .saturating_add(right.assertion_proximity_progress),
        confirmed_failure: left.confirmed_failure || right.confirmed_failure,
    }
}

pub(in crate::model) fn adaptive_strategy_graph_fingerprint(
    graph: &BTreeSet<ContentHash>,
) -> ContentHash {
    if graph.is_empty() {
        return ContentHash::default();
    }
    let material = graph
        .iter()
        .map(|hash| hash.to_hex())
        .collect::<Vec<_>>()
        .join("\n");
    ContentHash::from_canonical_material("crucible.adaptive-strategy.graph.v1", &material)
}

pub(in crate::model) fn adaptive_strategy_config_material(
    config: &AdaptiveStrategyConfig,
) -> String {
    let arms = config
        .arms
        .iter()
        .map(|arm| format!("{arm:?}"))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "seed={}\nenabled={}\nfairness_floor={}\nucb_exploration_weight_micros={}\narms={arms}",
        config.seed.to_hex(),
        config.enabled,
        config.breadth_first_floor_interval,
        config.ucb_exploration_weight_micros
    )
}
