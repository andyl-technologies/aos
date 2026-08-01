//! Checks the shared adversarial host-condition fixture.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::error::Error;

use crucible_harness::adversarial::{
    HostAdversaryProfile, HostAffinity, HostLoad, HostTaskOrder, ProducerConsumerRole,
    ProducerConsumerSkew, adversarial_execution_plan, canonical_host_adversary_matrix,
    ordered_task_indexes, run_profiled_producer_consumer_tasks, run_profiled_tasks,
};

#[test]
fn canonical_host_adversary_matrix_covers_required_dimensions() {
    let profiles = canonical_host_adversary_matrix();
    let names = profiles
        .iter()
        .map(|profile| profile.name)
        .collect::<BTreeSet<_>>();

    assert_eq!(profiles[0].name, "quiet-single-core");
    assert_eq!(
        names,
        BTreeSet::from([
            "quiet-single-core",
            "loaded-single-core",
            "reordered-two-core",
            "loaded-many-core",
        ])
    );
    assert!(
        profiles
            .iter()
            .any(|profile| matches!(profile.task_order, HostTaskOrder::SeededPermutation { .. })),
        "matrix must include seeded randomized scheduling"
    );
    assert!(
        profiles.iter().any(|profile| matches!(
            profile.affinity,
            HostAffinity::Seeded {
                logical_cores: 2..,
                ..
            }
        )),
        "matrix must include seeded randomized logical affinity"
    );
    assert!(
        profiles
            .iter()
            .any(|profile| profile.load.iterations > 0 && profile.load.yield_every > 0),
        "matrix must include injected jitter/load"
    );
    assert!(
        profiles.iter().any(|profile| profile.worker_count > 1),
        "matrix must include varied core counts"
    );
    assert!(
        profiles
            .iter()
            .any(|profile| profile.producer_consumer_skew != ProducerConsumerSkew::None),
        "matrix must include skewed producer/consumer timing"
    );
}

#[test]
fn seeded_task_order_is_stable_and_nontrivial() {
    let order = HostTaskOrder::SeededPermutation {
        seed: 0x5eed_0010_0025,
    };
    let first = ordered_task_indexes(8, order);
    let second = ordered_task_indexes(8, order);
    let canonical = (0..8).collect::<Vec<_>>();

    assert_eq!(first, second);
    assert_ne!(first, canonical);

    let mut sorted = first;
    sorted.sort_unstable();
    assert_eq!(sorted, canonical);
}

#[test]
fn adversarial_execution_plan_records_workers_affinity_and_skew() -> Result<(), Box<dyn Error>> {
    let profile = HostAdversaryProfile::reordered_two_core();
    let plan = adversarial_execution_plan(profile, 7)?;

    assert_eq!(plan.profile, profile);
    assert_eq!(plan.ordered_tasks.len(), 7);
    assert_eq!(plan.worker_tasks.len(), profile.worker_count);
    assert!(
        plan.ordered_tasks.iter().any(|task| task.worker_index == 1),
        "plan must distribute work across the second worker"
    );
    assert!(
        plan.ordered_tasks.iter().any(|task| task.logical_core == 1),
        "plan must carry non-zero logical affinity assignments"
    );
    assert!(
        plan.ordered_tasks
            .iter()
            .all(|task| task.producer_consumer_skew == ProducerConsumerSkew::ConsumerFast),
        "profile-level skew must be projected onto every task"
    );

    Ok(())
}

#[test]
fn affinity_profiles_drive_worker_assignment() -> Result<(), Box<dyn Error>> {
    let round_robin = HostAdversaryProfile {
        name: "test-round-robin-affinity",
        worker_count: 3,
        task_order: HostTaskOrder::Forward,
        affinity: HostAffinity::RoundRobin { logical_cores: 3 },
        load: HostLoad::quiet(),
        producer_consumer_skew: ProducerConsumerSkew::None,
    };
    let seeded = HostAdversaryProfile {
        name: "test-seeded-affinity",
        affinity: HostAffinity::Seeded {
            logical_cores: 3,
            seed: 0xaff1_0010_0025,
        },
        ..round_robin
    };

    let round_robin_workers = run_profiled_tasks(round_robin, 9, |task| task.worker_index)?;
    let seeded_workers = run_profiled_tasks(seeded, 9, |task| task.worker_index)?;

    assert_eq!(round_robin_workers, vec![0, 1, 2, 0, 1, 2, 0, 1, 2]);
    assert_ne!(
        seeded_workers, round_robin_workers,
        "seeded affinity must change the worker partition observed by the runner"
    );
    assert!(
        seeded_workers.iter().any(|worker_index| *worker_index > 0),
        "seeded affinity must still exercise non-baseline workers"
    );

    Ok(())
}

#[test]
fn profiled_runner_returns_results_in_canonical_task_order() -> Result<(), Box<dyn Error>> {
    let profile = HostAdversaryProfile::loaded_many_core();
    let results = run_profiled_tasks(profile, 8, |task| {
        (
            task.index,
            task.worker_index,
            task.logical_core,
            task.producer_consumer_skew,
        )
    })?;

    assert_eq!(
        results
            .iter()
            .map(|(index, _, _, _)| *index)
            .collect::<Vec<_>>(),
        (0..8).collect::<Vec<_>>()
    );
    assert!(
        results
            .iter()
            .any(|(_, worker_index, _, _)| *worker_index > 0),
        "runner must exercise more than one worker"
    );
    assert!(
        results
            .iter()
            .any(|(_, _, logical_core, _)| *logical_core > 0),
        "runner must expose varied logical affinity"
    );
    assert!(
        results
            .iter()
            .any(|(_, _, _, skew)| *skew == ProducerConsumerSkew::ProducerFast)
            && results
                .iter()
                .any(|(_, _, _, skew)| *skew == ProducerConsumerSkew::ConsumerFast),
        "alternating profile must expose both skew directions"
    );

    Ok(())
}

#[test]
fn producer_consumer_fixture_applies_role_aware_skew() -> Result<(), Box<dyn Error>> {
    let producer_fast = HostAdversaryProfile {
        name: "test-producer-fast",
        worker_count: 1,
        task_order: HostTaskOrder::Forward,
        affinity: HostAffinity::SingleCore,
        load: HostLoad::quiet(),
        producer_consumer_skew: ProducerConsumerSkew::ProducerFast,
    };
    let consumer_fast = HostAdversaryProfile {
        name: "test-consumer-fast",
        producer_consumer_skew: ProducerConsumerSkew::ConsumerFast,
        ..producer_fast
    };
    let alternating = HostAdversaryProfile {
        name: "test-alternating",
        producer_consumer_skew: ProducerConsumerSkew::Alternating,
        ..producer_fast
    };

    assert_eq!(
        first_roles(producer_fast, 3)?,
        vec![
            ProducerConsumerRole::Producer,
            ProducerConsumerRole::Producer,
            ProducerConsumerRole::Producer,
        ]
    );
    assert_eq!(
        first_roles(consumer_fast, 3)?,
        vec![
            ProducerConsumerRole::Consumer,
            ProducerConsumerRole::Consumer,
            ProducerConsumerRole::Consumer,
        ]
    );
    assert_eq!(
        first_roles(alternating, 4)?,
        vec![
            ProducerConsumerRole::Producer,
            ProducerConsumerRole::Consumer,
            ProducerConsumerRole::Producer,
            ProducerConsumerRole::Consumer,
        ]
    );

    Ok(())
}

#[test]
fn invalid_profiles_are_rejected_before_spawning_workers() {
    let invalid = HostAdversaryProfile {
        name: "invalid-zero-workers",
        worker_count: 0,
        task_order: HostTaskOrder::Forward,
        affinity: HostAffinity::SingleCore,
        load: HostLoad::quiet(),
        producer_consumer_skew: ProducerConsumerSkew::None,
    };

    assert!(adversarial_execution_plan(invalid, 1).is_err());
}

fn first_roles(
    profile: HostAdversaryProfile,
    task_count: usize,
) -> Result<Vec<ProducerConsumerRole>, Box<dyn Error>> {
    let pairs = run_profiled_producer_consumer_tasks(
        profile,
        task_count,
        |task| task.index,
        |task| task.index,
    )?;
    Ok(pairs.into_iter().map(|pair| pair.first_role).collect())
}
