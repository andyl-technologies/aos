//! Common refusal/lifecycle checks with explicit modeled portable metadata.
//!
//! The child, OS peer, process generation and common supervisory reclamation
//! are real. Portable descriptor/binding bytes below are test models, never
//! admitted native profiles or a substitute for source-owned readiness.

use super::*;
use crucible_node_contract::{
    BindingCompatibility, Extensions, ImplementationIdentity, LiveAuthority, OperatingContract,
    OperatingMode, OwnerRef, SchedulingRole, canonical,
};
use std::error::Error;

fn modeled_node(custody: KvmOwnedComponents) -> Result<KvmPreparedNode, Box<dyn Error>> {
    let id = Id::new("modeled/kvm-component")?;
    let model = canonical::content_ref(b"modeled metadata only", "text/plain")?;
    let world = custody.allocation();
    let owner = world.owners[0].clone();
    let descriptor = NodeDescriptor {
        schema_version: 1,
        id: id.clone(),
        roles: vec![Id::new("compute")?],
        model_ref: model.clone(),
        configuration_ref: model.clone(),
        initialization_ref: model.clone(),
        ports: vec![],
        extensions: Extensions::new(),
    };
    let domains = OwnerRef {
        id: owner.owner.clone(),
        participant_ids: vec![id.clone()],
        state_domain_ids: vec![Id::new("modeled/state")?],
    };
    let binding = NodeBinding {
        compatibility: BindingCompatibility {
            schema_version: 1,
            node_id: id.clone(),
            descriptor_hash: descriptor.identity()?,
            implementation: ImplementationIdentity {
                schema_version: 1,
                implementation_id: Id::new("modeled/not-qualified")?,
                artifacts: vec![],
                model_definitions: vec![model.clone()],
                formats: vec![],
                extensions: Extensions::new(),
            },
            profile_ref: model.clone(),
            configuration_ref: model.clone(),
            operating_contract: OperatingContract {
                schema_version: 1,
                mode: OperatingMode::Quantized,
                scheduling_role: SchedulingRole::Active,
                ordering_profile: "superdense-v1".into(),
                policy_ref: model.clone(),
                resolution_ps: Some(1000.into()),
                phase_ps: Some(0.into()),
                facets: vec![],
                extensions: Extensions::new(),
            },
            execution_owner: domains.clone(),
            capture_owner: domains,
            capabilities_ref: model.clone(),
            guarantees_ref: model.clone(),
            qualification_refs: vec![],
            extensions: Extensions::new(),
        },
        authority: LiveAuthority {
            schema_version: 1,
            session_id: Id::new("modeled/session")?,
            incarnation_id: owner.incarnation.clone(),
            realization_id: Id::new("modeled/realization")?,
            activation_id: None,
            world_generation: 0.into(),
            owner_generation: owner.generation,
            input_epoch: Id::new("modeled/input")?,
            host_receipt: model,
            extensions: Extensions::new(),
        },
        extensions: Extensions::new(),
    };
    Ok(KvmPreparedNode {
        descriptor,
        binding,
        route: NodeRoute {
            node: id,
            owners: vec![owner],
        },
        custody: Some(custody),
        thread: std::thread::current().id(),
        quarantined: false,
    })
}

#[test]
fn actual_owned_common_default_gate_cannot_mint_ready_or_suspension() -> Result<(), Box<dyn Error>>
{
    use crate::kvm_profile::owned_components::tests::{allocation, diagnostic_owner, reclaim};
    use crucible::node_contract::{ReadyAttestation, RuntimeCustodyQueue};

    let queue = RuntimeCustodyQueue::new(1)?;
    let (mut owner, _directory, _socket, _disconnect) = diagnostic_owner(&queue, 2);
    let request = crate::qmp::QmpKvmOriginalWindowRequest {
        operation: crate::qmp::QmpKvmOriginalWindowOperation::Close,
        generation: 0,
        start_ns: 0,
        end_ns: 0,
        stop_budget_ns: 100,
    };
    let original = owner.submit_window(request)?;
    assert!(original.exchange.is_err());
    let before = owner.observations(&original.token)?;
    let original_pid = owner.original_process_id();
    let mut node = modeled_node(owner)?;

    let status = node.status().map_err(|failure| failure.reason)?;
    assert_eq!(status.lifecycle, Lifecycle::Prepared);
    assert_eq!(status.physical, PhysicalState::Unknown);
    assert_eq!(status.boundary, None);
    assert!(node.facets().is_empty());
    assert!(node.arm(&allocation()).is_err());
    assert!(node.facet(FacetKind::QuantizedExecution).is_err());
    assert!(node.facet(FacetKind::Preservation).is_err());
    let modeled_ref =
        canonical::content_ref(b"modeled readiness is not native authority", "text/plain")?;
    let forged = ReadyAttestation {
        owners: allocation().owners,
        boundary: allocation().boundary,
        state_inventory: modeled_ref.clone(),
        ready_receipt: modeled_ref,
    };
    assert!(node.validate_readiness(&allocation(), &forged).is_err());
    let retained = node.custody.as_mut().ok_or("original owner disappeared")?;
    assert_eq!(retained.original_process_id(), original_pid);
    assert_eq!(retained.observations(&original.token)?, before);
    assert!(retained.observe_process_exit()?.is_none());

    node.quarantine_resources();
    node.quarantine_resources();
    assert_eq!(queue.retained_worlds(), 1);
    assert_eq!(
        node.status().map_err(|failure| failure.reason)?.lifecycle,
        Lifecycle::Quarantined
    );
    assert_eq!(
        node.status().map_err(|failure| failure.reason)?.physical,
        PhysicalState::Unknown
    );
    drop(node);
    reclaim(&queue);
    assert_eq!(queue.reserved_worlds(), 0);
    Ok(())
}

#[test]
fn refused_graph_mapping_returns_the_same_actual_peer_and_original_journal()
-> Result<(), Box<dyn Error>> {
    use crate::kvm_profile::owned_components::tests::{diagnostic_owner, reclaim};
    use crucible::node_contract::RuntimeCustodyQueue;

    let queue = RuntimeCustodyQueue::new(1)?;
    let (mut owner, _directory, _socket, _disconnect) = diagnostic_owner(&queue, 2);
    let original = owner.submit_window(crate::qmp::QmpKvmOriginalWindowRequest {
        operation: crate::qmp::QmpKvmOriginalWindowOperation::Close,
        generation: 0,
        start_ns: 0,
        end_ns: 0,
        stop_budget_ns: 100,
    })?;
    assert!(original.exchange.is_err());
    let before = owner.observations(&original.token)?;
    let original_pid = owner.original_process_id();
    // The graph is explicitly test-double metadata, never installed authority.
    let (graph, _objects) = crucible::node_admission::test_double_graph(true);
    let id = &graph.world().node_bindings[0].node_id;
    let failure = match KvmPreparedNode::from_prepared(&graph, id, owner) {
        Ok(_) => panic!("foreign modeled implementation unexpectedly admitted"),
        Err(failure) => failure,
    };
    assert_eq!(failure.error.effects, EffectKnowledge::None);
    assert_eq!(queue.retained_worlds(), 0);
    let mut retained = failure.custody;
    assert_eq!(retained.original_process_id(), original_pid);
    assert_eq!(retained.observations(&original.token)?, before);
    assert!(retained.observe_process_exit()?.is_none());
    drop(retained);
    assert_eq!(queue.retained_worlds(), 1);
    reclaim(&queue);
    Ok(())
}
