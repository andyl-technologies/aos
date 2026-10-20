//! Converts host-sealed node admission into complete campaign realization identity.
//!
//! This module consumes admitted graph authority. It never qualifies raw provider
//! claims or promotes a legacy QEMU state artifact to a new implementation.

use std::collections::{BTreeMap, BTreeSet};

use crucible_campaign::executor_node_capabilities::{
    ExecutorNodeRoster, ExecutorOwnerRole, NodeExecutionGuarantee, OwnerImplementationBinding,
};
use crucible_campaign::{
    CampaignCodecError, CampaignHash, ConfigurationArtifactId, ScenarioArtifactId,
};
use crucible_engine::node_admission::AdmittedGraph;
use crucible_node_format::{BindingCompatibility, HashRef, Id, OwnerBinding, Repeatability};

/// Constructs a complete owner roster from a host-sealed realized graph.
///
/// The caller must independently authenticate `scenario` and `configuration`
/// against its planned request and the graph's scenario/initialization artifacts.
/// The returned roster binds those planned references to the exact sealed graph
/// and complete owner identities; it does not treat planned state as observed
/// native state. Execution and capture-only owners are retained independently.
///
/// # Errors
///
/// Returns an error for inconsistent sealed ownership, missing participants,
/// unsupported roles, invalid compatibility identities, or an oversized roster.
pub fn roster_from_admitted_graph(
    graph: &AdmittedGraph,
    scenario: ScenarioArtifactId,
    configuration: ConfigurationArtifactId,
) -> Result<ExecutorNodeRoster, CampaignCodecError> {
    roster_from_graph_data(
        graph.owners(),
        |node| graph.binding(node).map(|binding| &binding.compatibility),
        |node| graph.effective_repeatability(node),
        graph.world_binding_hash(),
        scenario,
        configuration,
    )
}

/// Regenerates the same roster from authenticated immutable graph facts.
///
/// This does not seal a graph or authenticate live resources. The historical
/// caller independently checks the exact installed scenario and original request.
///
/// # Errors
/// Refuses missing bindings or classifications, unsupported owner roles, invalid
/// compatibility identities, duplicate owners or an oversized complete roster.
pub(crate) fn roster_from_graph_data<'a>(
    owner_bindings: impl IntoIterator<Item = &'a OwnerBinding>,
    binding_for: impl Fn(&Id) -> Option<&'a BindingCompatibility>,
    repeatability_for: impl Fn(&Id) -> Option<Repeatability>,
    world: &HashRef,
    scenario: ScenarioArtifactId,
    configuration: ConfigurationArtifactId,
) -> Result<ExecutorNodeRoster, CampaignCodecError> {
    let mut owners = BTreeMap::new();
    for owner in owner_bindings {
        let mut providers = BTreeSet::new();
        let mut nodes = BTreeSet::new();
        let mut guarantee = NodeExecutionGuarantee::Repeatable;
        for node in &owner.owner.participant_ids {
            let binding = binding_for(node).ok_or(CampaignCodecError::InvalidValue {
                reason: "admitted owner participant has no node binding",
            })?;
            providers.insert(binding.implementation.implementation_id.as_str());
            nodes.insert(node.as_str().to_owned());

            match repeatability_for(node) {
                Some(Repeatability::Qualified) => {}
                Some(Repeatability::Nondeterministic) => {
                    guarantee = NodeExecutionGuarantee::Nondeterministic;
                }
                Some(Repeatability::Unqualified) => {
                    if guarantee != NodeExecutionGuarantee::Nondeterministic {
                        guarantee = NodeExecutionGuarantee::Unqualified;
                    }
                }
                None => {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "admitted participant has no repeatability classification",
                    });
                }
            }
        }

        let provider = if providers.len() == 1 {
            providers
                .iter()
                .next()
                .ok_or(CampaignCodecError::InvalidValue {
                    reason: "admitted owner has no implementation provider",
                })?
                .to_string()
        } else {
            // The complete owner identity below binds every child implementation;
            // this family label is descriptive and cannot authorize restoration.
            String::from("composite-owner")
        };
        let roles = owner
            .owner_roles
            .iter()
            .map(|role| match role.as_str() {
                "execution" => Ok(ExecutorOwnerRole::Execution),
                "capture" => Ok(ExecutorOwnerRole::Capture),
                _ => Err(CampaignCodecError::InvalidValue {
                    reason: "admitted owner has an unsupported responsibility",
                }),
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        let identity = owner
            .identity()
            .map_err(|_| CampaignCodecError::InvalidValue {
                reason: "sealed owner compatibility identity is invalid",
            })?;
        let compatibility = CampaignHash::parse(&identity.digest)?;
        let binding = OwnerImplementationBinding::new_with_roles(
            provider,
            compatibility,
            nodes,
            guarantee,
            roles,
        )?;
        if owners
            .insert(owner.owner.id.as_str().to_owned(), binding)
            .is_some()
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "admitted owner roster contains duplicate owner identities",
            });
        }
    }

    ExecutorNodeRoster::new(
        scenario,
        configuration,
        CampaignHash::parse(&world.digest)?,
        owners,
    )
}

#[cfg(test)]
// crucible-lint: allow rust-allow -- synthetic codec tests deliberately panic without issuing native evidence.
// crucible-lint: allow panic-shortcut -- These executor node capabilities tests deliberately panic on invalid fixtures or failed invariants.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    //! Checks conversion from a genuinely sealed synthetic graph admission.

    use super::*;

    fn planned_artifacts() -> (ScenarioArtifactId, ConfigurationArtifactId) {
        let digest = CampaignHash::derive("crucible.test-planned-artifact.v1", b"planned").to_hex();
        (
            ScenarioArtifactId::parse(&format!(
                "crucible.campaign.scenario-artifact@scenario.1.{digest}"
            ))
            .unwrap(),
            ConfigurationArtifactId::parse(&format!(
                "crucible.campaign.configuration-artifact@configuration.1.{digest}"
            ))
            .unwrap(),
        )
    }

    #[test]
    fn sealed_graph_conversion_retains_every_owner_and_full_compatibility_identity() {
        let (graph, _) = crucible_engine::node_admission::test_double_graph(false);
        let (scenario, configuration) = planned_artifacts();

        let roster = roster_from_admitted_graph(&graph, scenario, configuration).unwrap();

        assert!(roster.is_repeatable());
        assert_eq!(roster.owners().len(), graph.owners().count());
        assert_eq!(roster.scenario(), scenario);
        assert_eq!(roster.configuration(), configuration);
        assert_eq!(
            roster.graph(),
            CampaignHash::parse(&graph.world_binding_hash().digest).unwrap()
        );
        for owner in graph.owners() {
            let binding = roster.owners().get(owner.owner.id.as_str()).unwrap();
            assert_eq!(
                binding.compatibility(),
                CampaignHash::parse(&owner.identity().unwrap().digest).unwrap()
            );
            assert_eq!(binding.nodes().len(), owner.owner.participant_ids.len());
            assert_eq!(binding.roles().len(), owner.owner_roles.len());
            for role in &owner.owner_roles {
                let expected = match role.as_str() {
                    "execution" => ExecutorOwnerRole::Execution,
                    "capture" => ExecutorOwnerRole::Capture,
                    _ => panic!("unexpected sealed synthetic owner role"),
                };
                assert!(binding.roles().contains(&expected));
            }
        }
    }

    #[test]
    fn admitted_nondeterministic_influence_changes_roster_identity_and_world_guarantee() {
        let (repeatable, _) = crucible_engine::node_admission::test_double_graph(false);
        let (nondeterministic, _) = crucible_engine::node_admission::test_double_graph(true);
        let (scenario, configuration) = planned_artifacts();

        let repeated = roster_from_admitted_graph(&repeatable, scenario, configuration).unwrap();
        let observed =
            roster_from_admitted_graph(&nondeterministic, scenario, configuration).unwrap();

        assert!(repeated.is_repeatable());
        assert!(!observed.is_repeatable());
        assert_ne!(repeated.digest(), observed.digest());
        assert!(
            observed.owners().values().any(|binding| {
                binding.guarantee() == &NodeExecutionGuarantee::Nondeterministic
            })
        );
    }
}
