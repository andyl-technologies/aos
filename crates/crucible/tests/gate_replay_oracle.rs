//! Implements `gate:replay-oracle` over the in-process reduction model.

#![forbid(unsafe_code)]

use std::error::Error;

use crucible::{
    AppRandomDecision, Checkpoint, CheckpointKind, Configuration, ContentHash, Decision,
    DeliveryOrderDecision, EventKey, FaultDecision, FaultId, NodeId, RngDecision, RngStreamId,
    ScenarioDef, Schedule, State, VirtualTime, reduce, step,
};
use crucible_harness::replay_oracle::{
    ReplayOracleCheckpointKind, ReplayOracleMaterializedCase, ReplayOracleMismatch,
    check_materialized_replay_oracle,
};

struct SimDouble;

#[derive(Clone, Debug)]
struct MaterializedCheckpoint {
    checkpoint_id: String,
    checkpoint: Checkpoint,
    configuration: Configuration,
    ancestor: Configuration,
    schedule_delta: Schedule,
    state: State,
    observational_entries: Vec<String>,
}

impl SimDouble {
    fn materialize_fat_checkpoint(
        &self,
        checkpoint_id: String,
        ancestor: &Configuration,
        configuration: &Configuration,
    ) -> Result<MaterializedCheckpoint, Box<dyn Error>> {
        let schedule_delta = schedule_delta(&ancestor.schedule, &configuration.schedule)?;
        let state =
            assert_twice_reduce_canonical_digest(&configuration.def, &configuration.schedule)?;
        let checkpoint = Checkpoint {
            id: test_double_checkpoint_hash(
                &checkpoint_id,
                configuration,
                ancestor.content_hash(),
                &schedule_delta,
                &state,
            ),
            configuration: configuration.content_hash(),
            kind: CheckpointKind::Fat,
        };

        Ok(MaterializedCheckpoint {
            checkpoint_id,
            checkpoint,
            configuration: configuration.clone(),
            ancestor: ancestor.clone(),
            schedule_delta,
            state,
            observational_entries: vec![String::from("host-observation:materialized")],
        })
    }

    fn replay_case(
        &self,
        checkpoint: &MaterializedCheckpoint,
    ) -> Result<ReplayOracleMaterializedCase, Box<dyn Error>> {
        self.replay_case_with_delta(checkpoint, &checkpoint.schedule_delta)
    }

    fn replay_case_with_delta(
        &self,
        checkpoint: &MaterializedCheckpoint,
        thin_delta: &Schedule,
    ) -> Result<ReplayOracleMaterializedCase, Box<dyn Error>> {
        let thin_schedule = replay_schedule(&checkpoint.ancestor.schedule, thin_delta);
        let thin_configuration = Configuration {
            def: checkpoint.configuration.def.clone(),
            schedule: thin_schedule,
        };
        let thin_state = reduce(&thin_configuration.def, &thin_configuration.schedule)?;
        let thin_checkpoint_hash = test_double_checkpoint_hash(
            &checkpoint.checkpoint_id,
            &thin_configuration,
            checkpoint.ancestor.content_hash(),
            thin_delta,
            &thin_state,
        );

        Ok(ReplayOracleMaterializedCase {
            checkpoint_id: checkpoint.checkpoint_id.clone(),
            kind: checkpoint_kind(checkpoint.checkpoint.kind),
            fat_checkpoint_hash: hash_bytes(checkpoint.checkpoint.id),
            thin_checkpoint_hash: hash_bytes(thin_checkpoint_hash),
            fat_configuration_hash: hash_bytes(checkpoint.checkpoint.configuration),
            thin_configuration_hash: hash_bytes(thin_configuration.content_hash()),
            fat_ancestor_hash: hash_bytes(checkpoint.ancestor.content_hash()),
            thin_ancestor_hash: hash_bytes(checkpoint.ancestor.content_hash()),
            fat_schedule_delta_hash: hash_bytes(checkpoint.schedule_delta.content_hash()),
            thin_schedule_delta_hash: hash_bytes(thin_delta.content_hash()),
            fat_hash: hash_bytes(checkpoint.state.id),
            thin_hash: hash_bytes(thin_state.id),
        })
    }
}

#[test]
fn gate_replay_oracle_fixed_checkpoint_corpus_matches_thin_reduction() -> Result<(), Box<dyn Error>>
{
    let corpus = assert_replay_oracle_fixed_checkpoint_corpus()?;

    check_materialized_replay_oracle(&corpus)?;
    assert_replay_oracle_excludes_observational_entries(&corpus)?;

    Ok(())
}

#[test]
fn gate_replay_oracle_rejects_corrupt_materialized_checkpoint() -> Result<(), Box<dyn Error>> {
    let corpus = assert_replay_oracle_fixed_checkpoint_corpus()?;
    let configuration_mismatch =
        assert_replay_oracle_rejects_corrupt_configuration_metadata(&corpus)?;
    let delta_mismatch = assert_replay_oracle_rejects_corrupt_schedule_delta_metadata(&corpus)?;
    let body_mismatch = assert_replay_oracle_reports_first_mismatch(&corpus)?;

    assert_eq!(configuration_mismatch.checkpoint_id, "cp-1");
    assert_eq!(delta_mismatch.checkpoint_id, "cp-2");
    assert_eq!(body_mismatch.checkpoint_id, "cp-1");

    Ok(())
}

fn assert_replay_oracle_fixed_checkpoint_corpus()
-> Result<Vec<ReplayOracleMaterializedCase>, Box<dyn Error>> {
    let scenario =
        ScenarioDef::from_canonical_material("crucible.test.replay-oracle", "nodes=a,b\nseed=42");
    let genesis = Configuration::genesis(scenario.clone());
    let first = step(
        &genesis,
        Decision::DeliveryOrder(DeliveryOrderDecision {
            at: VirtualTime { ticks: 5 },
            order: vec![EventKey { sequence: 1 }, EventKey { sequence: 2 }],
        }),
    );
    let second = step(
        &first,
        Decision::FaultFires(FaultDecision {
            at: VirtualTime { ticks: 8 },
            fault: FaultId {
                name: String::from("link-a-b/drop"),
            },
            fired: true,
        }),
    );
    let third = step(
        &second,
        Decision::AppRandom(AppRandomDecision {
            node: NodeId {
                name: String::from("node-a"),
            },
            stream: RngStreamId {
                name: String::from("whitebox/request"),
            },
            request_id: 9,
            width: 32,
            value: 0xabcd,
        }),
    );

    let double = SimDouble;
    let checkpoints = [genesis, first, second, third];
    let mut cases = Vec::new();

    for (index, configuration) in checkpoints.iter().enumerate() {
        let ancestor = if index == 0 {
            configuration
        } else {
            &checkpoints[index - 1]
        };
        let materialized =
            double.materialize_fat_checkpoint(format!("cp-{index}"), ancestor, configuration)?;
        cases.push(double.replay_case(&materialized)?);
    }

    Ok(cases)
}

fn assert_replay_oracle_excludes_observational_entries(
    _corpus: &[ReplayOracleMaterializedCase],
) -> Result<(), Box<dyn Error>> {
    let double = SimDouble;
    let scenario = ScenarioDef::from_canonical_material(
        "crucible.test.replay-oracle",
        "nodes=observation\nseed=7",
    );
    let genesis = Configuration::genesis(scenario.clone());
    let checkpoint = Configuration {
        def: scenario,
        schedule: Schedule::empty().appended(Decision::RngDraw(RngDecision {
            stream: RngStreamId {
                name: String::from("observation/control"),
            },
            value: 11,
        })),
    };
    let materialized =
        double.materialize_fat_checkpoint(String::from("cp-observation"), &genesis, &checkpoint)?;
    let mut with_extra_observation = materialized.clone();
    with_extra_observation
        .observational_entries
        .push(String::from("host-observation:ignored"));

    assert_ne!(
        materialized.observational_entries,
        with_extra_observation.observational_entries
    );
    assert_eq!(
        double.replay_case(&materialized)?,
        double.replay_case(&with_extra_observation)?
    );
    Ok(())
}

fn assert_replay_oracle_rejects_corrupt_configuration_metadata(
    corpus: &[ReplayOracleMaterializedCase],
) -> Result<ReplayOracleMismatch, Box<dyn Error>> {
    let mut corrupted = corpus.to_vec();
    if let Some(case) = corrupted.get_mut(1) {
        case.fat_configuration_hash = hash_bytes(ContentHash::from_canonical_material(
            "crucible.test.replay-oracle.corrupt-config",
            "cp-1",
        ));
    }

    match check_materialized_replay_oracle(&corrupted) {
        Ok(()) => panic!("corrupt materialized configuration hash should fail the replay oracle"),
        Err(mismatch) => Ok(mismatch),
    }
}

fn assert_replay_oracle_rejects_corrupt_schedule_delta_metadata(
    corpus: &[ReplayOracleMaterializedCase],
) -> Result<ReplayOracleMismatch, Box<dyn Error>> {
    let mut corrupted = corpus.to_vec();
    if let Some(case) = corrupted.get_mut(2) {
        case.fat_schedule_delta_hash = hash_bytes(ContentHash::from_canonical_material(
            "crucible.test.replay-oracle.corrupt-delta",
            "cp-2",
        ));
    }

    match check_materialized_replay_oracle(&corrupted) {
        Ok(()) => panic!("corrupt materialized schedule delta should fail the replay oracle"),
        Err(mismatch) => Ok(mismatch),
    }
}

fn assert_replay_oracle_reports_first_mismatch(
    corpus: &[ReplayOracleMaterializedCase],
) -> Result<ReplayOracleMismatch, Box<dyn Error>> {
    let mut corrupted = corpus.to_vec();
    if let Some(case) = corrupted.get_mut(1) {
        case.fat_hash = hash_bytes(ContentHash::from_canonical_material(
            "crucible.test.replay-oracle.corrupt-fat",
            "cp-1",
        ));
    }

    match check_materialized_replay_oracle(&corrupted) {
        Ok(()) => panic!("corrupt materialized checkpoint should fail the replay oracle"),
        Err(mismatch) => Ok(mismatch),
    }
}

fn assert_twice_reduce_canonical_digest(
    scenario: &ScenarioDef,
    schedule: &Schedule,
) -> Result<State, Box<dyn Error>> {
    let first = reduce(scenario, schedule)?;
    let second = reduce(scenario, schedule)?;
    assert_eq!(first, second);
    Ok(first)
}

fn schedule_delta(ancestor: &Schedule, schedule: &Schedule) -> Result<Schedule, Box<dyn Error>> {
    let prefix = schedule.prefix(ancestor.len())?;
    assert_eq!(prefix, *ancestor);

    let mut delta = Schedule::empty();
    for decision in &schedule.decisions()[ancestor.len()..] {
        delta = delta.appended(decision.clone());
    }
    Ok(delta)
}

fn replay_schedule(ancestor: &Schedule, delta: &Schedule) -> Schedule {
    let mut schedule = ancestor.clone();
    for decision in delta.decisions() {
        schedule = schedule.appended(decision.clone());
    }
    schedule
}

fn test_double_checkpoint_hash(
    checkpoint_id: &str,
    configuration: &Configuration,
    ancestor_hash: ContentHash,
    schedule_delta: &Schedule,
    state: &State,
) -> ContentHash {
    let material = format!(
        "checkpoint_id={checkpoint_id}\nkind=fat\nconfiguration={}\nancestor={}\ndelta={}\nstate={}\n",
        hash_hex(configuration.content_hash()),
        hash_hex(ancestor_hash),
        hash_hex(schedule_delta.content_hash()),
        hash_hex(state.id)
    );
    ContentHash::from_canonical_material("crucible.test.replay-oracle.fat-checkpoint", &material)
}

fn checkpoint_kind(kind: CheckpointKind) -> ReplayOracleCheckpointKind {
    match kind {
        CheckpointKind::Fat => ReplayOracleCheckpointKind::Fat,
        CheckpointKind::Thin => ReplayOracleCheckpointKind::Thin,
    }
}

fn hash_bytes(hash: ContentHash) -> Vec<u8> {
    hash.bytes.to_vec()
}

fn hash_hex(hash: ContentHash) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(hash.bytes.len() * 2);
    for byte in hash.bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[test]
fn gate_replay_oracle_is_sensitive_to_schedule_order() -> Result<(), Box<dyn Error>> {
    let scenario =
        ScenarioDef::from_canonical_material("crucible.test.replay-oracle", "nodes=a,b\nseed=99");
    let draw = Decision::RngDraw(RngDecision {
        stream: RngStreamId {
            name: String::from("scheduler/order"),
        },
        value: 1,
    });
    let delivery = Decision::DeliveryOrder(DeliveryOrderDecision {
        at: VirtualTime { ticks: 1 },
        order: vec![EventKey { sequence: 7 }],
    });
    let first_order = Schedule::empty()
        .appended(draw.clone())
        .appended(delivery.clone());
    let second_order = Schedule::empty().appended(delivery).appended(draw);
    let genesis = Configuration::genesis(scenario.clone());
    let first_configuration = Configuration {
        def: scenario.clone(),
        schedule: first_order.clone(),
    };
    let double = SimDouble;
    let materialized = double.materialize_fat_checkpoint(
        String::from("cp-order"),
        &genesis,
        &first_configuration,
    )?;
    let wrong_order_case = double.replay_case_with_delta(&materialized, &second_order)?;

    assert_ne!(
        reduce(&scenario, &first_order)?,
        reduce(&scenario, &second_order)?
    );
    let mismatch = match check_materialized_replay_oracle(&[wrong_order_case]) {
        Ok(()) => panic!("wrong-order thin reconstruction should fail the replay oracle"),
        Err(mismatch) => mismatch,
    };

    assert_eq!(mismatch.checkpoint_id, "cp-order");

    Ok(())
}
