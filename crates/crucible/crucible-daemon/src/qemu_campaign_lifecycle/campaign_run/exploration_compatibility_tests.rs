//! Parent-writer exploration policy and accepted branch compatibility fixtures.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Fixed parent-writer fixtures deliberately panic on changed policy or original accepted branch identity.
#![allow(clippy::expect_used)]

use super::*;

fn policy_material() -> Vec<u8> {
    let seed = Seed::from_u64(37);
    let (request, _) = request();
    let scenario = crate::encode_crucible_scenario_artifact(&request.scenario)
        .expect("original canonical scenario artifact");
    let configuration =
        crate::encode_crucible_configuration_artifact(&scenario, &request.initial_schedule)
            .expect("original canonical configuration artifact");
    let lineage = default_run_lineage::<io::Error>(
        &request,
        scenario.id().expect("original scenario content identity"),
        configuration
            .id()
            .expect("original configuration content identity"),
    )
    .expect("actual original modeled lineage");
    let stop = StopCondition::NamedBoundary(String::from("original-boundary"));
    let mut material = b"CEXP1".to_vec();

    for strategy in [
        None,
        Some(GuardedCampaignExplorationStrategy::BreadthFirst),
        Some(GuardedCampaignExplorationStrategy::DepthFirst),
        Some(GuardedCampaignExplorationStrategy::Priority { seed }),
        Some(GuardedCampaignExplorationStrategy::CoverageGuided),
    ] {
        let exploration = strategy.map(|strategy| {
            GuardedCampaignExploration::new(3, Some(2), false, strategy)
                .expect("bounded original policy")
                .with_execution_quanta_timeout(17)
                .expect("original attempt timeout")
        });
        let policy = exploration::local_campaign_policy::<io::Error>(
            &lineage,
            seed,
            &stop,
            exploration,
            Some(CampaignHash::derive("test.parent-supplemental", b"source")),
        )
        .expect("parent policy");
        let bytes = policy.canonical_bytes();
        assert_eq!(
            crucible_campaign::CampaignPolicy::from_canonical_bytes(&bytes)
                .expect("complete policy reopens"),
            policy,
        );
        frame(&mut material, &bytes);
    }
    material
}

fn branch_material() -> Vec<u8> {
    let (request, node) = selectable_request();
    let exploration = GuardedCampaignExploration::new(
        3,
        None,
        false,
        GuardedCampaignExplorationStrategy::BreadthFirst,
    )
    .expect("original bounded branch fixture");
    let starts = Arc::new(AtomicUsize::new(0));
    let completed = run_selectable_campaign(
        request.with_exploration(exploration),
        node,
        Arc::clone(&starts),
    );
    assert_eq!(starts.load(Ordering::Relaxed), 3);
    assert_eq!(completed.branch_acceptances().len(), 1);
    assert_eq!(completed.observations().len(), 3);
    assert_eq!(
        completed.exploration_completion(),
        Some(GuardedCampaignExplorationCompletion::Exhausted),
    );

    let original = completed.branch_acceptances()[0];
    assert_eq!(original.maximum_attempts(), 2);
    assert!(original.exhausts_domain());
    let mut material = b"CBRI1".to_vec();
    frame(
        &mut material,
        original.request().content_id().encode().as_bytes(),
    );
    for observation in completed.observations() {
        frame(
            &mut material,
            observation.configuration().id().bytes.as_slice(),
        );
    }
    material
}

fn frame(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(
        &u64::try_from(bytes.len())
            .expect("fixed bounded fixture frame")
            .to_le_bytes(),
    );
    output.extend_from_slice(bytes);
}

#[test]
fn neutral_exploration_preserves_full_parent_policy_bytes() {
    let parent = include_bytes!("../../campaign_exploration/fixtures/parent-policy-v1.cexp");
    assert_eq!(policy_material(), parent.as_slice());
}

#[test]
fn neutral_exploration_preserves_original_branch_and_configuration_order() {
    let parent = include_bytes!("../../campaign_exploration/fixtures/parent-branch-v1.cbri");
    assert_eq!(branch_material(), parent.as_slice());
}

#[test]
fn legacy_exploration_types_and_nominal_codec_error_remain_the_same_items() {
    let neutral = crate::campaign_exploration::GuardedCampaignExploration::new(
        3,
        Some(2),
        true,
        crate::campaign_exploration::GuardedCampaignExplorationStrategy::DepthFirst,
    )
    .expect("neutral public construction");
    let legacy: GuardedCampaignExploration = neutral;
    assert_eq!(legacy, neutral);
    assert_eq!(
        legacy.strategy(),
        GuardedCampaignExplorationStrategy::DepthFirst
    );

    let invalid = GuardedCampaignExploration::new(
        0,
        None,
        false,
        GuardedCampaignExplorationStrategy::BreadthFirst,
    )
    .expect_err("original zero-attempt refusal");
    let original = GuardedDefaultCampaignRunError::<io::Error>::Codec(invalid);
    let alias: crate::GuardedDefaultCampaignRunError<io::Error> = original;
    assert!(matches!(
        alias,
        GuardedDefaultCampaignRunError::Codec(
            crucible_campaign::CampaignCodecError::InvalidValue {
                reason: "guarded campaign exploration attempt budget is zero",
            }
        ),
    ));
    assert!(matches!(
        legacy.with_execution_quanta_timeout(0),
        Err(crucible_campaign::CampaignCodecError::InvalidValue {
            reason: "guarded campaign exploration timeout is zero",
        }),
    ));
}
