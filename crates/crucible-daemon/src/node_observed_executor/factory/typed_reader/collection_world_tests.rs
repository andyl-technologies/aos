//! Verifies exact three-source graph data and refuses altered pre-Child rosters.

use super::super::TypedReaderProgrammePeer;
use super::*;
use crucible_node_provider::{
    reference_lineage::InputLineageDefinition,
    reference_service::profile::InputLineageProfileSelection,
};

fn original()
-> Result<(TypedReaderProgramme, Vec<ReferenceProfile>, Vec<ContentRef>), ProviderError> {
    let object = canonical::content_ref(b"inert source role", "application/octet-stream")?;
    let peer = |name: &str| -> Result<TypedReaderProgrammePeer, ProviderError> {
        Ok(TypedReaderProgrammePeer {
            node: Id::new(name)?,
            owner: Id::new(format!("{name}/owner"))?,
            incarnation: Id::new(format!("{name}/incarnation"))?,
        })
    };
    let programme = TypedReaderProgramme::new(
        object.clone(),
        [peer("producer-a")?, peer("producer-b")?, peer("consumer")?],
    )?;
    let definition = InputLineageDefinition::build_negotiated(
        object.clone(),
        object.clone(),
        object.clone(),
        object.clone(),
        object.clone(),
    )?;
    let mut profiles = Vec::new();
    for (index, peer) in programme.peers.iter().enumerate() {
        profiles.push(ReferenceProfile::build_public_negotiated_lineage_reader(
            peer.node.clone(),
            peer.owner.clone(),
            object.clone(),
            object.clone(),
            U64::new(1000),
            U64::new(1_000_000_000),
            InputLineageProfileSelection {
                closed_ingress: index < 2,
                definition: definition.clone(),
            },
        )?);
    }
    let mut qualifications = vec![
        canonical::content_ref(b"plan", "application/json")?,
        canonical::content_ref(b"refused audit", "application/json")?,
    ];
    qualifications.sort();
    Ok((programme, profiles, qualifications))
}

#[test]
fn collecting_world_data_closes_exact_sources_routes_and_all_false_capture()
-> Result<(), ProviderError> {
    let (programme, profiles, qualifications) = original()?;
    let world = build(&programme, &profiles, &qualifications)?;

    assert_eq!(world.descriptors.len(), 3);
    assert_eq!(world.world.connections.len(), 2);
    assert_eq!(world.ownership.objects.len(), 5);
    assert_eq!(world.ownership.domains.len(), 3);
    assert!(
        world
            .ownership
            .capture_owners
            .iter()
            .all(|owner| !owner.complete_model
                && !owner.unchanged_cut
                && !owner.exact_continuation
                && !owner.durable_restart
                && !owner.isolated_fork)
    );
    for (reference, bytes) in world.objects() {
        reference.verify(bytes)?;
    }
    for connection in &world.world.connections {
        let policy: ConnectionPolicy = serde_json::from_value(canonical::parse_json(
            &world.content[&connection.policy_ref],
            1024 * 1024,
        )?)
        .map_err(ContractError::from)?;
        assert_eq!(policy.maximum_pending_events.get(), 1);
        assert_eq!(policy.maximum_pending_bytes.get(), 4096);
        assert!(matches!(
            policy.visibility,
            VisibilityConversion::BoundarySampling { .. }
        ));
    }
    assert!(
        !world.requirements.exact_continuation
            && !world.requirements.durable_restart
            && !world.requirements.isolated_fork
    );
    Ok(())
}

#[test]
fn original_qualifications_and_source_owner_are_inseparable_from_whole_world()
-> Result<(), ProviderError> {
    let (programme, mut profiles, qualifications) = original()?;
    let original = build(&programme, &profiles, &qualifications)?
        .world
        .identity()?;
    let mut changed = qualifications.clone();
    changed[0] = canonical::content_ref(b"foreign refused audit", "application/json")?;
    changed.sort();
    assert_ne!(
        build(&programme, &profiles, &changed)?.world.identity()?,
        original
    );
    assert!(build(&programme, &profiles, &[]).is_err());
    assert!(
        build(
            &programme,
            &profiles,
            &[qualifications[0].clone(), qualifications[0].clone()]
        )
        .is_err()
    );
    profiles[0].owner.id = Id::new("foreign/owner")?;
    assert!(build(&programme, &profiles, &qualifications).is_err());
    Ok(())
}

#[test]
fn borrowed_whole_profile_credit_enforces_exact_aggregate_extent() -> Result<(), ProviderError> {
    let (_, profiles, qualifications) = original()?;
    let borrowed = (BorrowedProfiles(&profiles), &qualifications);
    super::super::programme::count(&borrowed, 4 * 1024 * 1024)?;
    let exact = serde_json::to_vec(&borrowed)
        .map_err(ContractError::from)?
        .len();
    assert!(super::super::programme::count(&borrowed, exact - 1).is_err());
    super::super::programme::count(&borrowed, exact)?;
    Ok(())
}
