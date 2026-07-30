//! Live World-network search choices for probabilistic frame transforms.

/// One canonical combined choice for a frame's genuine probabilistic axes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::scheduler) struct LiveNetworkBranchChoice {
    /// Canonical ordered `axis-outcome` tokens.
    pub(in crate::scheduler) name: String,
    /// Draw vector that realizes the named combined outcome.
    pub(in crate::scheduler) draws: crucible_device::FrameDraws,
}

/// Enumerates the genuine combined outcomes for one live frame emission.
pub(in crate::scheduler) fn live_network_branch_choices(
    faults: &crucible_device::LinkFaults,
    base: &crucible_device::FrameDraws,
) -> Vec<LiveNetworkBranchChoice> {
    if faults.partitioned {
        return Vec::new();
    }
    let mut choices = vec![LiveNetworkBranchChoice {
        name: String::new(),
        draws: base.clone(),
    }];
    if faults.additional_loss.is_empty() {
        choices = expand_axis(choices, "loss", faults.loss, |draws, value| {
            draws.loss = value;
        });
    }
    if choices.len() == 1
        && choices[0].name.is_empty()
        && faults.loss_fires(base.loss, &base.additional_loss)
    {
        return Vec::new();
    }
    choices = choices
        .into_iter()
        .flat_map(|choice| {
            if choice.name == "loss-fire" {
                vec![choice]
            } else {
                expand_axis(
                    vec![choice],
                    "duplicate",
                    faults.duplicate,
                    |draws, value| draws.duplicate = value,
                )
            }
        })
        .collect();
    choices = choices
        .into_iter()
        .flat_map(|choice| {
            if choice.name == "loss-fire" {
                vec![choice]
            } else {
                expand_axis(vec![choice], "corrupt", faults.corrupt, |draws, value| {
                    draws.corrupt = value
                })
            }
        })
        .collect();
    choices.retain(|choice| !choice.name.is_empty());
    choices
}

/// Resolves a previously enumerated choice name against the current fault table.
pub(in crate::scheduler) fn live_network_branch_draws(
    faults: &crucible_device::LinkFaults,
    base: &crucible_device::FrameDraws,
    name: &str,
) -> Option<crucible_device::FrameDraws> {
    live_network_branch_choices(faults, base)
        .into_iter()
        .find_map(|choice| (choice.name == name).then_some(choice.draws))
}

/// Returns whether a choice name belongs to the closed live-network vocabulary.
pub(in crate::scheduler) fn is_live_network_branch_choice_name(name: &str) -> bool {
    let mut saw_axis = false;
    let mut previous_rank = 0_u8;
    for token in name.split('+') {
        let (axis, outcome) = token.split_once('-').unwrap_or_default();
        if !matches!(outcome, "fire" | "pass") {
            return false;
        }
        let rank = match axis {
            "loss" => 1,
            "duplicate" => 2,
            "corrupt" => 3,
            _ => return false,
        };
        if rank <= previous_rank {
            return false;
        }
        previous_rank = rank;
        saw_axis = true;
    }
    saw_axis
}

fn expand_axis(
    choices: Vec<LiveNetworkBranchChoice>,
    axis: &str,
    probability: crucible_device::Probability,
    set_draw: impl Fn(&mut crucible_device::FrameDraws, u64),
) -> Vec<LiveNetworkBranchChoice> {
    let fire = firing_probability_draw(probability);
    let pass = non_firing_probability_draw(probability);
    if fire.is_none() || pass.is_none() {
        return choices;
    }
    let mut expanded = Vec::with_capacity(choices.len().saturating_mul(2));
    for choice in choices {
        let mut fire_choice = choice.clone();
        append_choice_token(&mut fire_choice.name, axis, "fire");
        set_draw(&mut fire_choice.draws, fire.unwrap_or_default());
        expanded.push(fire_choice);

        let mut pass_choice = choice;
        append_choice_token(&mut pass_choice.name, axis, "pass");
        set_draw(&mut pass_choice.draws, pass.unwrap_or_default());
        expanded.push(pass_choice);
    }
    expanded
}

fn append_choice_token(name: &mut String, axis: &str, outcome: &str) {
    if !name.is_empty() {
        name.push('+');
    }
    name.push_str(axis);
    name.push('-');
    name.push_str(outcome);
}

fn firing_probability_draw(probability: crucible_device::Probability) -> Option<u64> {
    (probability.denominator != 0 && probability.numerator != 0).then_some(0)
}

fn non_firing_probability_draw(probability: crucible_device::Probability) -> Option<u64> {
    (probability.denominator != 0 && probability.numerator < probability.denominator)
        .then_some(probability.numerator)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probability(numerator: u64, denominator: u64) -> crucible_device::Probability {
        crucible_device::Probability::new(numerator, denominator)
    }

    #[test]
    fn live_network_choices_cover_loss_duplicate_and_corrupt_without_dead_axes() {
        let faults = crucible_device::LinkFaults {
            loss: probability(1, 4),
            duplicate: probability(1, 3),
            corrupt: probability(1, 2),
            ..crucible_device::LinkFaults::none()
        };
        let choices = live_network_branch_choices(&faults, &crucible_device::FrameDraws::default());
        let names = choices
            .iter()
            .map(|choice| choice.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                "loss-fire",
                "loss-pass+duplicate-fire+corrupt-fire",
                "loss-pass+duplicate-fire+corrupt-pass",
                "loss-pass+duplicate-pass+corrupt-fire",
                "loss-pass+duplicate-pass+corrupt-pass",
            ]
        );
        assert_eq!(choices[0].draws.loss, 0);
        assert_eq!(choices[1].draws.loss, 1);
        assert_eq!(choices[1].draws.duplicate, 0);
        assert_eq!(choices[1].draws.corrupt, 0);
        assert_eq!(choices[4].draws.duplicate, 1);
        assert_eq!(choices[4].draws.corrupt, 1);
        for choice in &choices {
            assert_eq!(
                faults.loss.fires(choice.draws.loss),
                choice.name.contains("loss-fire")
            );
            if !choice.name.contains("loss-fire") {
                assert_eq!(
                    faults.duplicate.fires(choice.draws.duplicate),
                    choice.name.contains("duplicate-fire")
                );
                assert_eq!(
                    faults.corrupt.fires(choice.draws.corrupt),
                    choice.name.contains("corrupt-fire")
                );
            }
        }
    }

    #[test]
    fn live_network_choice_parser_rejects_unknown_duplicate_and_reordered_axes() {
        assert!(is_live_network_branch_choice_name("loss-fire"));
        assert!(is_live_network_branch_choice_name(
            "loss-pass+duplicate-fire+corrupt-pass"
        ));
        assert!(!is_live_network_branch_choice_name(""));
        assert!(!is_live_network_branch_choice_name("jitter-fire"));
        assert!(!is_live_network_branch_choice_name(
            "duplicate-fire+loss-pass"
        ));
        assert!(!is_live_network_branch_choice_name("loss-pass+loss-fire"));
    }

    #[test]
    fn live_network_choices_do_not_branch_transforms_after_unavoidable_drop() {
        let transform_faults = crucible_device::LinkFaults {
            duplicate: probability(1, 2),
            corrupt: probability(1, 2),
            ..crucible_device::LinkFaults::none()
        };
        let partitioned = crucible_device::LinkFaults {
            partitioned: true,
            ..transform_faults.clone()
        };
        assert!(
            live_network_branch_choices(&partitioned, &crucible_device::FrameDraws::default())
                .is_empty()
        );

        let certain_loss = crucible_device::LinkFaults {
            loss: probability(1, 1),
            ..transform_faults
        };
        assert!(
            live_network_branch_choices(&certain_loss, &crucible_device::FrameDraws::default())
                .is_empty()
        );
    }
}
