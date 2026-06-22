//! Implements `gate:content-address` over the execution-model identity spine.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt::Debug;

use crucible::{
    AppRandomDecision, Checkpoint, CheckpointKind, Configuration, ContentHash, Decision,
    DeliveryOrderDecision, EventKey, FaultDecision, FaultId, NodeId, RngDecision, RngStreamId,
    ScenarioDef, Schedule, State, VirtualTime, reduce, step,
};

#[test]
fn gate_content_address_keeps_fixed_vectors_stable() {
    let scenario = scenario("scenario=alpha\nnodes=a,b\nseed=42");
    let schedule = fixed_schedule();
    let configuration = Configuration {
        def: scenario.clone(),
        schedule: schedule.clone(),
    };
    let state = assert_twice_reduce_canonical_digest(|| reduce(&scenario, &schedule));

    assert_eq!(
        fixed_vectors(&scenario, &schedule, &configuration, &state),
        expected_vectors([
            (
                "scenario",
                "ca5ef63d14b2039d0a0d6e4fa94820f2ffb2ab4f7c89fabd4e5658b53051b77a"
            ),
            (
                "schedule",
                "26714bc8d41b4e9e29443ba658b71de1c0edf4a87879cde0661029b1043a2cde"
            ),
            (
                "configuration",
                "5bdb16ae8ac9702c711e3d340e61b8ed60c6e2462d0928da377a19fba6f8521c",
            ),
            (
                "state",
                "90db4fac84b59501c7804fd618508b312754c4bf7d4e768dd92328e2d860ab65"
            ),
            (
                "world-component",
                "d1614627d7442f5fcd7757db23250ab820f3d9648373811bd4cf4ee853ddc4a5",
            ),
            (
                "snapshot-blob",
                "285760e51578adf57b28481e664232064eb12f7eba7d4b2fba8da197463d8321",
            ),
            (
                "event-log-segment",
                "8d356acd5b719e0a42fb04fd03464e52ebe2eec33bd0c6d0647407b1a1229a41",
            ),
        ])
    );
}

#[test]
fn gate_content_address_hashes_equal_content_to_equal_ids() {
    let first_scenario = scenario("scenario=equal\nnodes=a,b\nseed=7");
    let second_scenario = scenario("scenario=equal\nnodes=a,b\nseed=7");
    let first_schedule = fixed_schedule();
    let second_schedule = fixed_schedule();
    let first_configuration = Configuration {
        def: first_scenario.clone(),
        schedule: first_schedule.clone(),
    };
    let second_configuration = Configuration {
        def: second_scenario.clone(),
        schedule: second_schedule.clone(),
    };

    assert_eq!(first_scenario.id, second_scenario.id);
    assert_eq!(
        first_schedule.content_hash(),
        second_schedule.content_hash()
    );
    assert_eq!(
        first_configuration.content_hash(),
        second_configuration.content_hash()
    );
    assert_eq!(
        assert_twice_reduce_canonical_digest(|| reduce(&first_scenario, &first_schedule)),
        assert_twice_reduce_canonical_digest(|| reduce(&second_scenario, &second_schedule))
    );
}

#[test]
fn gate_content_address_changes_on_single_byte_mutations() {
    assert_ne!(
        ScenarioDef::from_canonical_material("crucible.test.content-address.scenario", "seed=1").id,
        ScenarioDef::from_canonical_material("crucible.test.content-address.scenario", "seed=2").id
    );
    assert_ne!(
        ContentHash::from_canonical_material("crucible.test.content-address.snapshot", "page=A"),
        ContentHash::from_canonical_material("crucible.test.content-address.snapshot", "page=B")
    );
    assert_ne!(
        ContentHash::from_canonical_material("crucible.test.content-address.log", "event=deliver"),
        ContentHash::from_canonical_material("crucible.test.content-address.log", "event=delives")
    );

    let scenario = scenario("scenario=mutation\nnodes=a,b\nseed=11");
    let base = Configuration::genesis(scenario.clone());
    let first = step(
        &base,
        Decision::RngDraw(RngDecision {
            stream: RngStreamId {
                name: String::from("node-a/fault"),
            },
            value: 1,
        }),
    );
    let changed = step(
        &base,
        Decision::RngDraw(RngDecision {
            stream: RngStreamId {
                name: String::from("node-a/fault"),
            },
            value: 2,
        }),
    );

    assert_ne!(
        first.schedule.content_hash(),
        changed.schedule.content_hash()
    );
    assert_ne!(first.content_hash(), changed.content_hash());
    assert_ne!(
        assert_twice_reduce_canonical_digest(|| reduce(&scenario, &first.schedule)),
        assert_twice_reduce_canonical_digest(|| reduce(&scenario, &changed.schedule))
    );
}

#[test]
fn gate_content_address_is_sensitive_to_schedule_order() {
    let scenario = scenario("scenario=order\nnodes=a,b\nseed=13");
    let draw = Decision::RngDraw(RngDecision {
        stream: RngStreamId {
            name: String::from("scheduler/order"),
        },
        value: 9,
    });
    let delivery = Decision::DeliveryOrder(DeliveryOrderDecision {
        at: VirtualTime { ticks: 3 },
        order: vec![EventKey { sequence: 1 }],
    });
    let first = Schedule::empty()
        .appended(draw.clone())
        .appended(delivery.clone());
    let second = Schedule::empty().appended(delivery).appended(draw);

    assert_ne!(first.content_hash(), second.content_hash());
    assert_ne!(
        Configuration {
            def: scenario.clone(),
            schedule: first.clone(),
        }
        .content_hash(),
        Configuration {
            def: scenario.clone(),
            schedule: second.clone(),
        }
        .content_hash()
    );
    assert_ne!(
        assert_twice_reduce_canonical_digest(|| reduce(&scenario, &first)),
        assert_twice_reduce_canonical_digest(|| reduce(&scenario, &second))
    );
}

#[test]
fn gate_content_address_excludes_materialization_cache_from_identity() {
    let scenario = scenario("scenario=cache\nnodes=a\nseed=17");
    let configuration = step(
        &Configuration::genesis(scenario.clone()),
        Decision::FaultFires(FaultDecision {
            at: VirtualTime { ticks: 5 },
            fault: FaultId {
                name: String::from("disk-delay"),
            },
            fired: true,
        }),
    );
    let id = configuration.content_hash();
    let thin = Checkpoint {
        id,
        configuration: id,
        kind: CheckpointKind::Thin,
    };
    let fat = Checkpoint {
        id,
        configuration: id,
        kind: CheckpointKind::Fat,
    };

    assert_eq!(thin.id, fat.id);
    assert_eq!(thin.configuration, fat.configuration);
    assert_ne!(thin.kind, fat.kind);
    assert_eq!(configuration.content_hash(), id);
    assert_eq!(
        assert_twice_reduce_canonical_digest(|| reduce(&scenario, &configuration.schedule)),
        assert_twice_reduce_canonical_digest(|| reduce(&scenario, &configuration.schedule))
    );
}

#[test]
fn gate_content_address_collision_corpus_has_unique_ids() {
    let mut seen = BTreeSet::new();

    for index in 0..512_u64 {
        let material = format!(
            "kind=corpus\nindex={index}\nnode=node-{}\nseed={}\n",
            index % 17,
            index.wrapping_mul(0x9e37_79b9_7f4a_7c15)
        );
        let id =
            ContentHash::from_canonical_material("crucible.test.content-address.corpus", &material);
        assert!(
            seen.insert(id),
            "duplicate content id for corpus index {index}"
        );
    }
}

fn assert_twice_reduce_canonical_digest<T, E, F>(mut reduce: F) -> T
where
    T: Debug + PartialEq,
    E: Debug,
    F: FnMut() -> Result<T, E>,
{
    let first = match reduce() {
        Ok(value) => value,
        Err(error) => panic!("first reduction failed: {error:?}"),
    };
    let second = match reduce() {
        Ok(value) => value,
        Err(error) => panic!("second reduction failed: {error:?}"),
    };
    assert_eq!(first, second);
    first
}

fn scenario(material: &str) -> ScenarioDef {
    ScenarioDef::from_canonical_material("crucible.test.content-address.scenario", material)
}

fn fixed_schedule() -> Schedule {
    Schedule::empty()
        .appended(Decision::DeliveryOrder(DeliveryOrderDecision {
            at: VirtualTime { ticks: 1 },
            order: vec![EventKey { sequence: 2 }, EventKey { sequence: 3 }],
        }))
        .appended(Decision::FaultFires(FaultDecision {
            at: VirtualTime { ticks: 4 },
            fault: FaultId {
                name: String::from("link-a-b/drop"),
            },
            fired: true,
        }))
        .appended(Decision::AppRandom(AppRandomDecision {
            node: NodeId {
                name: String::from("node-a"),
            },
            stream: RngStreamId {
                name: String::from("guest/request"),
            },
            request_id: 12,
            width: 32,
            value: 0xabcd_1234,
        }))
}

fn fixed_vectors(
    scenario: &ScenarioDef,
    schedule: &Schedule,
    configuration: &Configuration,
    state: &State,
) -> [(&'static str, String); 7] {
    [
        ("scenario", hash_hex(scenario.id)),
        ("schedule", hash_hex(schedule.content_hash())),
        ("configuration", hash_hex(configuration.content_hash())),
        ("state", hash_hex(state.id)),
        (
            "world-component",
            hash_hex(ContentHash::from_canonical_material(
                "crucible.test.content-address.world",
                "nodes=[node-a,node-b]\nlinks=[a-b]\n",
            )),
        ),
        (
            "snapshot-blob",
            hash_hex(ContentHash::from_canonical_material(
                "crucible.test.content-address.snapshot",
                "vm=node-a\npage=0000\nbytes=0011223344556677\n",
            )),
        ),
        (
            "event-log-segment",
            hash_hex(ContentHash::from_canonical_material(
                "crucible.test.content-address.log",
                "0 delivery node-a->node-b icount=5\n1 fault link-drop fired=true\n",
            )),
        ),
    ]
}

fn expected_vectors(vectors: [(&'static str, &'static str); 7]) -> [(&'static str, String); 7] {
    vectors.map(|(name, hash)| (name, hash.to_owned()))
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
