//! Live World-network search choices for probabilistic frame transforms.

use std::collections::{BTreeMap, BTreeSet};

use crucible_campaign::{
    AlternativeId, CampaignCodecError, CampaignHash, ChoiceClassContext, ChoiceCoordinate,
    ChoiceDiscovery, ChoiceDomain, ChoiceSource, ChoiceValue, ConfigurationId, DiscreteAlternative,
    DiscreteDomain, ScenarioDefId, SelectableDeclaration, Selection, SelectionOrigin,
};

use crate::{Configuration, SchedulingPoint, VirtualTime};

pub(in crate::scheduler) const LIVE_NETWORK_SELECTABLE_PRODUCER: &str =
    "crucible.live-world-network.v1";

#[derive(Clone, Debug)]
pub(in crate::scheduler) struct LiveNetworkSelectable {
    domain: ChoiceDomain,
    opportunity: crucible_campaign::ChoiceOpportunity,
    discovery: ChoiceDiscovery,
    names: BTreeMap<AlternativeId, String>,
}

impl LiveNetworkSelectable {
    pub(in crate::scheduler) fn new(
        parent: &Configuration,
        at: VirtualTime,
        point: &SchedulingPoint,
        choices: &[LiveNetworkBranchChoice],
        faults: &crucible_device::LinkFaults,
        default_draws: &crucible_device::FrameDraws,
    ) -> Result<Self, CampaignCodecError> {
        let mut alternatives = BTreeMap::new();
        let mut names = BTreeMap::new();
        let mut default = None;
        for choice in choices {
            let id = live_network_alternative_id(&choice.name);
            alternatives.insert(id, DiscreteAlternative::new(id, choice.name.clone(), None)?);
            names.insert(id, choice.name.clone());
            if live_network_choice_matches_draws(&choice.name, faults, default_draws) {
                default = Some(id);
            }
        }
        let default = default.ok_or(CampaignCodecError::InvalidValue {
            reason: "live-network domain does not contain the modeled outcome",
        })?;
        let domain = ChoiceDomain::Discrete(DiscreteDomain::new(1, alternatives)?);
        let declaration = SelectableDeclaration::new(
            "live-world-network-outcome",
            ChoiceSource::Scheduler {
                producer: String::from(LIVE_NETWORK_SELECTABLE_PRODUCER),
            },
            domain.clone(),
            ChoiceValue::Discrete(default),
            ChoiceClassContext::new(BTreeSet::from([
                String::from("per-event"),
                String::from("world-network"),
            ]))?,
            BTreeSet::from([
                String::from("network-fault"),
                String::from("probabilistic-outcome"),
            ]),
            false,
        )?;
        let producer = CampaignHash::derive(
            "crucible.live-world-network.opportunity.v1",
            point.key.as_bytes(),
        );
        let opportunity = crucible_campaign::ChoiceOpportunity::new(
            ScenarioDefId::from_hash(CampaignHash::from_bytes(parent.def.id().bytes)),
            &declaration,
            &domain,
            ChoiceCoordinate {
                scheduler: CampaignHash::from_bytes(parent.id().bytes),
                producer,
            },
            format!("frame-{:016x}", at.ticks),
            None,
        )?;
        let discovery = ChoiceDiscovery::new(declaration, domain.clone(), opportunity.clone())?;
        Ok(Self {
            domain,
            opportunity,
            discovery,
            names,
        })
    }

    pub(in crate::scheduler) fn discovery(&self) -> ChoiceDiscovery {
        self.discovery.clone()
    }

    pub(in crate::scheduler) fn opportunity_id(
        &self,
    ) -> Result<crucible_campaign::ChoiceOpportunityId, CampaignCodecError> {
        self.opportunity.id()
    }

    pub(in crate::scheduler) fn default_selection(&self) -> Result<Selection, CampaignCodecError> {
        Selection::new(
            &self.opportunity,
            &self.domain,
            self.opportunity.default().clone(),
            SelectionOrigin::Default,
        )
    }

    pub(in crate::scheduler) fn branch_selection(
        &self,
        parent: &Configuration,
        name: &str,
    ) -> Result<Selection, CampaignCodecError> {
        Selection::new_campaign_branch(
            &self.opportunity,
            &self.domain,
            ChoiceValue::Discrete(live_network_alternative_id(name)),
            self.opportunity
                .branch_point_id(ConfigurationId::from_hash(CampaignHash::from_bytes(
                    parent.id().bytes,
                ))),
        )
    }

    pub(in crate::scheduler) fn selected_name(
        &self,
        parent: &Configuration,
        selection: &Selection,
    ) -> Result<&str, CampaignCodecError> {
        selection.validate_branch_replay(
            &self.opportunity,
            &self.domain,
            self.opportunity
                .branch_point_id(ConfigurationId::from_hash(CampaignHash::from_bytes(
                    parent.id().bytes,
                ))),
        )?;
        let ChoiceValue::Discrete(id) = selection.value() else {
            return Err(CampaignCodecError::InvalidValue {
                reason: "live-network selection is not discrete",
            });
        };
        self.names
            .get(id)
            .map(String::as_str)
            .ok_or(CampaignCodecError::InvalidValue {
                reason: "live-network selection names an unknown outcome",
            })
    }
}

fn live_network_choice_matches_draws(
    name: &str,
    faults: &crucible_device::LinkFaults,
    draws: &crucible_device::FrameDraws,
) -> bool {
    name.split('+').all(|token| {
        let (axis, outcome) = token.split_once('-').unwrap_or_default();
        let fires = match axis {
            "loss" => faults.loss.fires(draws.loss),
            "duplicate" => faults.duplicate.fires(draws.duplicate),
            "corrupt" => faults.corrupt.fires(draws.corrupt),
            _ => return false,
        };
        fires == (outcome == "fire")
    })
}

pub(in crate::scheduler) fn live_network_alternative_id(name: &str) -> AlternativeId {
    AlternativeId::from_hash(CampaignHash::derive(
        "crucible.live-world-network.alternative.v1",
        name.as_bytes(),
    ))
}

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
#[cfg(test)]
fn is_live_network_branch_choice_name(name: &str) -> bool {
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
