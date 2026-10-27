//! The maintained selected-opportunity set agrees with a full history scan.

use std::collections::BTreeSet;

use super::*;

/// Decides the NextChoice stop by decoding every recorded selection.
///
/// This is the history scan the maintained selected-opportunity set
/// replaced; it is kept as the reference the set must agree with.
fn unselected_discovery_by_full_scan(
    configuration: &Configuration,
    discoveries: &[&ChoiceDiscovery],
) -> bool {
    let selected = configuration
        .schedule
        .decision_history()
        .iter()
        .filter_map(|decision| match decision {
            Decision::Selection(selection) => Some(
                selection
                    .selection()
                    .expect("recorded selection decodes")
                    .opportunity(),
            ),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    discoveries.iter().any(|discovery| {
        !selected.contains(&discovery.opportunity().id().expect("opportunity identity"))
    })
}

#[test]
fn unselected_discovery_check_matches_a_full_history_scan() {
    let input = input(StopCondition::NextChoice);
    let scenario = input.lineage().scenario();
    let discoveries = (0..12)
        .map(|index| choice_discovery_named(scenario, &format!("generated-choice-{index}")))
        .collect::<Vec<_>>();
    let mut configuration = starting_configuration(&input);

    // Interleave deliveries with selections in a fixed scrambled order that
    // revisits opportunities, so some are selected twice and some never.
    for step in 0..48_u64 {
        let decision = if step % 3 == 0 {
            Decision::DeliveryOrder(crucible_engine::DeliveryOrderDecision {
                at: VirtualTime { ticks: step },
                order: Vec::new(),
            })
        } else {
            let discovery = &discoveries[usize::try_from(step * 7 % 10).expect("index")];
            let selection = Selection::new(
                discovery.opportunity(),
                discovery.domain(),
                discovery.opportunity().default().clone(),
                SelectionOrigin::Default,
            )
            .expect("default selection");
            Decision::Selection(SelectionDecision::new(&selection))
        };
        configuration.schedule = configuration.schedule.appended(decision);

        let all = discoveries.iter().collect::<Vec<_>>();
        assert_eq!(
            has_unselected_discovery(&configuration, all.iter().copied())
                .expect("well-formed discoveries"),
            unselected_discovery_by_full_scan(&configuration, &all),
            "all discoveries after step {step}"
        );
        for discovery in &discoveries {
            assert_eq!(
                has_unselected_discovery(&configuration, [discovery])
                    .expect("well-formed discovery"),
                unselected_discovery_by_full_scan(&configuration, &[discovery]),
                "single discovery after step {step}"
            );
        }
    }

    // Opportunities 10 and 11 are never selected; every other one is.
    assert!(has_unselected_discovery(&configuration, &discoveries[10..]).expect("discoveries"));
    assert!(!has_unselected_discovery(&configuration, &discoveries[..10]).expect("discoveries"));
    assert!(!has_unselected_discovery(&configuration, []).expect("no discoveries"));
}
