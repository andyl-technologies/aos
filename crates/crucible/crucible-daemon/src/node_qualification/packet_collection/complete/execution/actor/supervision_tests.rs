//! Tests proposal correspondence only, without accepted complete nodes or Child.

use super::*;
use crucible_engine::node_contract::{ActivationRecord, OwnerIdentity};
use crucible_node_format::U64;

#[test]
fn original_owner_proposal_requires_exact_incarnation_and_bound_activation()
-> Result<(), Box<dyn std::error::Error>> {
    let (graph, _) = crucible_engine::node_admission::test_double_graph(false);
    let owner = graph.owners().next().ok_or("missing modeled owner")?;
    let mut binding = graph
        .binding(&owner.owner.participant_ids[0])
        .ok_or("missing modeled binding")?
        .clone();
    let activation_id = Id::new("modeled-complete-supervision-activation")?;
    binding.authority.activation_id = Some(activation_id.clone());
    let mut proposal = ActivationRecord {
        generation: U64::new(1),
        activation_id,
        world_binding_hash: graph.world_binding_hash().clone(),
        boundary: Position::new(
            U64::new(0),
            U64::new(0),
            crucible_node_format::Phase::BoundaryControl,
        ),
        owners: vec![OwnerIdentity {
            owner: owner.owner.id.clone(),
            incarnation: binding.authority.incarnation_id.clone(),
            generation: binding.authority.owner_generation,
        }],
    };
    assert!(authenticate_proposed_owner(&proposal, owner, &binding).is_ok());
    proposal.owners[0].incarnation = Id::new("modeled-foreign-incarnation")?;
    assert!(authenticate_proposed_owner(&proposal, owner, &binding).is_err());
    proposal.owners[0].incarnation = binding.authority.incarnation_id.clone();
    proposal.activation_id = Id::new("modeled-foreign-activation")?;
    assert!(authenticate_proposed_owner(&proposal, owner, &binding).is_err());
    // Before activation the actual installed authority intentionally has None;
    // the real Core barrier still independently authenticates the whole proposal.
    binding.authority.activation_id = None;
    assert!(authenticate_proposed_owner(&proposal, owner, &binding).is_ok());
    Ok(())
}
