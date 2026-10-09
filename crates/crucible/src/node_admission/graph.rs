//! Establishes unique state ownership, consistent-cut closure, and causal progress.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crucible_node_contract::{GuaranteeProfile, HashRef, Id, Repeatability};

use super::error::refuse;
use super::evidence::VerifiedContent;
use super::nodes::ordered_ids;
use super::ports::{CausalEdges, PortPolicies};
use super::{
    AdmissionCode, AdmissionError, AdmissionRequest, AdmissionStage, AdmissionSubject,
    CoordinatorPolicy, ObjectState, OwnershipPolicy, QualificationClaim,
};

pub(super) fn owner_conflicts(
    request: &AdmissionRequest<'_>,
    ownership: &OwnershipPolicy,
    limits: super::AdmissionLimits,
) -> Result<BTreeMap<Id, BTreeSet<Id>>, AdmissionError> {
    let mut conflicts: BTreeMap<_, BTreeSet<_>> = request
        .owners
        .iter()
        .map(|owner| (owner.owner.id.clone(), BTreeSet::new()))
        .collect();
    let mut examined = 0usize;
    let mut retained = 0usize;
    for domain in &ownership.domains {
        let participants: BTreeSet<_> = domain
            .execution_owner_ids
            .iter()
            .chain(std::iter::once(&domain.capture_owner_id))
            .collect();
        for source in &participants {
            for target in &participants {
                if source == target {
                    continue;
                }
                examined = examined
                    .checked_add(1)
                    .filter(|value| *value <= limits.maximum_owner_conflict_checks)
                    .ok_or_else(|| {
                        refuse(
                            AdmissionStage::Graph,
                            AdmissionSubject::Domain(domain.id.clone()),
                            AdmissionCode::BoundMismatch,
                            "shared-domain conflict derivation within admitted work ceiling",
                            "owner conflict examination ceiling exceeded",
                        )
                    })?;
                let peers = conflicts.get_mut(*source).ok_or_else(|| {
                    refuse(
                        AdmissionStage::Graph,
                        AdmissionSubject::Domain(domain.id.clone()),
                        AdmissionCode::OwnerConflict,
                        "every domain writer and capture owner exists in complete roster",
                        "missing conflict owner",
                    )
                })?;
                if !peers.contains(*target) {
                    retained = retained
                        .checked_add(1)
                        .filter(|value| *value <= limits.maximum_owner_conflict_pairs)
                        .ok_or_else(|| {
                            refuse(
                                AdmissionStage::Graph,
                                AdmissionSubject::Domain(domain.id.clone()),
                                AdmissionCode::BoundMismatch,
                                "retained owner conflicts within admitted allocation ceiling",
                                "owner conflict pair ceiling exceeded",
                            )
                        })?;
                    peers.insert((*target).clone());
                }
            }
        }
    }
    Ok(conflicts)
}

pub(super) struct GraphClaims<'a> {
    pub ownership: &'a OwnershipPolicy,
    pub coordinator: &'a CoordinatorPolicy,
    pub guarantees: &'a BTreeMap<Id, GuaranteeProfile>,
    pub ports: &'a PortPolicies,
    pub world_hash: &'a HashRef,
}

pub(super) struct GraphGuarantees {
    pub effective_repeatability: BTreeMap<Id, Repeatability>,
    pub world_repeatability: Repeatability,
}

pub(super) fn check_policy_bounds(
    ownership: &OwnershipPolicy,
    coordinator: &CoordinatorPolicy,
    limits: super::AdmissionLimits,
) -> Result<(), AdmissionError> {
    ordered_ids(
        ownership.domains.iter().map(|domain| &domain.id),
        limits.maximum_state_objects,
    )?;
    ordered_ids(
        ownership.objects.iter().map(|object| &object.id),
        limits.maximum_state_objects,
    )?;
    ordered_ids(
        ownership
            .internal_dependencies
            .iter()
            .map(|dependency| &dependency.id),
        limits.maximum_connections,
    )?;
    ordered_ids(
        ownership.capture_owners.iter().map(|owner| &owner.owner_id),
        limits.maximum_owners,
    )?;
    for domain in &ownership.domains {
        ordered_ids(domain.execution_owner_ids.iter(), limits.maximum_owners)?;
    }
    for object in &ownership.objects {
        ordered_ids(object.node_ids.iter(), limits.maximum_nodes)?;
    }
    for owner in &ownership.capture_owners {
        ordered_ids(owner.dependencies.iter(), limits.maximum_owners)?;
    }
    ordered_ids(
        coordinator
            .same_time_closure
            .iter()
            .map(|closure| &closure.execution_owner_id),
        limits.maximum_owners,
    )?;
    if coordinator.external_inputs.len() > limits.maximum_connections {
        return Err(refuse(
            AdmissionStage::Parse,
            AdmissionSubject::World,
            AdmissionCode::BoundMismatch,
            "external-input roster within admitted causal-path ceiling",
            "oversized external-input roster",
        ));
    }
    Ok(())
}
pub(super) fn validate_graph(
    request: &AdmissionRequest<'_>,
    claims: GraphClaims<'_>,
    mut edges: CausalEdges,
    content: &mut VerifiedContent<'_>,
) -> Result<GraphGuarantees, AdmissionError> {
    let GraphClaims {
        ownership,
        coordinator,
        guarantees,
        ports,
        world_hash,
    } = claims;
    validate_ownership(request, ownership, guarantees, world_hash, content)?;
    validate_coordinator(request, coordinator, ports, world_hash, content)?;
    let public_edge_count = edges.len();
    for dependency in &ownership.internal_dependencies {
        require_node(request, &dependency.producer_node_id)?;
        require_node(request, &dependency.consumer_node_id)?;
        content.verify(&dependency.proof_ref)?;
        content.qualify(
            AdmissionSubject::Connection(dependency.id.clone()),
            QualificationClaim::Connection {
                world_binding_hash: world_hash,
                connection_id: &dependency.id,
                proof_ref: &dependency.proof_ref,
            },
        )?;
        edges.push((
            dependency.producer_node_id.clone(),
            dependency.consumer_node_id.clone(),
            dependency.minimum_latency_ps.get(),
        ));
    }
    validate_zero_cycles(
        request,
        coordinator,
        &edges,
        public_edge_count,
        world_hash,
        content,
    )?;
    propagate_guarantees(request, ownership, guarantees, edges)
}

fn require_node(request: &AdmissionRequest<'_>, id: &Id) -> Result<(), AdmissionError> {
    if request
        .descriptors
        .binary_search_by(|node| node.id.cmp(id))
        .is_err()
    {
        return Err(refuse(
            AdmissionStage::Graph,
            AdmissionSubject::Node(id.clone()),
            AdmissionCode::OwnerConflict,
            "ownership and causal paths name admitted public nodes",
            "undeclared node in ownership inventory",
        ));
    }
    Ok(())
}

fn validate_ownership(
    request: &AdmissionRequest<'_>,
    ownership: &OwnershipPolicy,
    guarantees: &BTreeMap<Id, GuaranteeProfile>,
    world_hash: &HashRef,
    content: &mut VerifiedContent<'_>,
) -> Result<(), AdmissionError> {
    let fail = |subject, required, observed| {
        refuse(
            AdmissionStage::Graph,
            subject,
            AdmissionCode::OwnerConflict,
            required,
            observed,
        )
    };
    if ownership.schema_version != 1
        || !request.world.extensions.is_empty()
        || request
            .world
            .node_bindings
            .iter()
            .any(|binding| !binding.extensions.is_empty())
    {
        return Err(refuse(
            AdmissionStage::Graph,
            AdmissionSubject::World,
            AdmissionCode::InvalidSchema,
            "supported closed world and ownership policy",
            "unknown edition or unregistered extension",
        ));
    }
    ordered_ids(
        ownership.domains.iter().map(|domain| &domain.id),
        content.limits.maximum_state_objects,
    )?;
    ordered_ids(
        ownership.objects.iter().map(|object| &object.id),
        content.limits.maximum_state_objects,
    )?;
    ordered_ids(
        ownership
            .internal_dependencies
            .iter()
            .map(|dependency| &dependency.id),
        content.limits.maximum_connections,
    )?;
    ordered_ids(
        ownership.capture_owners.iter().map(|owner| &owner.owner_id),
        content.limits.maximum_owners,
    )?;
    let owners: BTreeMap<_, _> = request
        .owners
        .iter()
        .map(|owner| (&owner.owner.id, owner))
        .collect();
    if let Some(first) = request.bindings.first() {
        for binding in request.bindings {
            if binding.authority.world_generation != first.authority.world_generation
                || binding.authority.activation_id != first.authority.activation_id
                || binding.authority.world_generation.get() == 0
                    && binding.authority.activation_id.is_some()
            {
                return Err(fail(
                    AdmissionSubject::Node(binding.compatibility.node_id.clone()),
                    "all nodes refer to one coherent world activation generation",
                    "mixed world generations or activation identities",
                ));
            }
        }
    }
    let domains: BTreeMap<_, _> = ownership
        .domains
        .iter()
        .map(|domain| (&domain.id, domain))
        .collect();
    let mut expected_members: BTreeMap<Id, BTreeSet<Id>> = BTreeMap::new();
    let mut expected_domains: BTreeMap<Id, BTreeSet<Id>> = BTreeMap::new();
    for binding in request.bindings {
        for (selected, role) in [
            (&binding.compatibility.execution_owner, "execution"),
            (&binding.compatibility.capture_owner, "capture"),
        ] {
            let owner = owners.get(&selected.id).ok_or_else(|| {
                fail(
                    AdmissionSubject::Owner(selected.id.clone()),
                    "every selected execution and capture owner in complete roster",
                    "undeclared selected owner",
                )
            })?;
            if owner.owner != *selected
                || !owner
                    .owner_roles
                    .iter()
                    .any(|candidate| candidate.as_str() == role)
            {
                return Err(fail(
                    AdmissionSubject::Owner(selected.id.clone()),
                    "actual owner role, membership, and domain roster match selected binding",
                    "selected owner differs from actual owner record",
                ));
            }
            expected_members
                .entry(selected.id.clone())
                .or_default()
                .insert(binding.compatibility.node_id.clone());
        }
    }
    for domain in &ownership.domains {
        ordered_ids(
            domain.execution_owner_ids.iter(),
            content.limits.maximum_owners,
        )?;
        let capture = owners.get(&domain.capture_owner_id).ok_or_else(|| {
            fail(
                AdmissionSubject::Domain(domain.id.clone()),
                "every mutable domain has one declared capture owner",
                "undeclared capture owner",
            )
        })?;
        if !capture
            .owner_roles
            .iter()
            .any(|role| role.as_str() == "capture")
        {
            return Err(fail(
                AdmissionSubject::Domain(domain.id.clone()),
                "domain owner has capture role",
                "owner has no capture authority",
            ));
        }
        expected_domains
            .entry(domain.capture_owner_id.clone())
            .or_default()
            .insert(domain.id.clone());
        for writer in &domain.execution_owner_ids {
            let owner = owners.get(writer).ok_or_else(|| {
                fail(
                    AdmissionSubject::Domain(domain.id.clone()),
                    "every mutable writer has declared execution ownership",
                    "undeclared execution owner",
                )
            })?;
            if !owner
                .owner_roles
                .iter()
                .any(|role| role.as_str() == "execution")
            {
                return Err(fail(
                    AdmissionSubject::Domain(domain.id.clone()),
                    "domain writer has execution role",
                    "writer has no execution role",
                ));
            }
            expected_domains
                .entry(writer.clone())
                .or_default()
                .insert(domain.id.clone());
        }
    }
    for owner in request.owners {
        content.verify(&owner.ownership_ref)?;
        if !owner.extensions.is_empty()
            || owner
                .node_bindings
                .iter()
                .any(|binding| !binding.extensions.is_empty())
        {
            return Err(fail(
                AdmissionSubject::Owner(owner.owner.id.clone()),
                "supported owner constraints",
                "unregistered ownership extension",
            ));
        }
        let members: BTreeSet<_> = owner.owner.participant_ids.iter().cloned().collect();
        let state: BTreeSet<_> = owner.owner.state_domain_ids.iter().cloned().collect();
        if expected_members.get(&owner.owner.id) != Some(&members)
            || state
                != expected_domains
                    .get(&owner.owner.id)
                    .cloned()
                    .unwrap_or_default()
        {
            return Err(fail(
                AdmissionSubject::Owner(owner.owner.id.clone()),
                "complete exact participant and domain ownership with no extra owners",
                "missing, extra, or overlapping owner membership/domain",
            ));
        }
        for selected in &owner.node_bindings {
            let expected = request
                .world
                .node_bindings
                .binary_search_by(|binding| binding.node_id.cmp(&selected.node_id))
                .ok()
                .map(|index| &request.world.node_bindings[index]);
            if expected != Some(selected) {
                return Err(fail(
                    AdmissionSubject::Owner(owner.owner.id.clone()),
                    "owner participants retain actual selected node compatibility",
                    "foreign participant binding hash",
                ));
            }
        }
        if owner
            .owner_roles
            .iter()
            .any(|role| role.as_str() == "execution")
        {
            let mut authority = None;
            let mut operating = None;
            for node_id in &owner.owner.participant_ids {
                let binding = request
                    .bindings
                    .binary_search_by(|binding| binding.compatibility.node_id.cmp(node_id))
                    .ok()
                    .map(|index| &request.bindings[index])
                    .ok_or_else(|| {
                        fail(
                            AdmissionSubject::Owner(owner.owner.id.clone()),
                            "every owner participant appears in admitted graph",
                            "missing owner participant",
                        )
                    })?;
                if binding.compatibility.execution_owner.id == owner.owner.id {
                    if authority.is_some_and(|old| old != &binding.authority)
                        || operating
                            .is_some_and(|old| old != &binding.compatibility.operating_contract)
                    {
                        return Err(fail(
                            AdmissionSubject::Owner(owner.owner.id.clone()),
                            "one indivisible owner has one live incarnation and operating contract",
                            "composite views disagree on authority or mode",
                        ));
                    }
                    authority = Some(&binding.authority);
                    operating = Some(&binding.compatibility.operating_contract);
                }
            }
        }
    }

    let exact = request.requirements.exact_capture || request.requirements.exact_continuation;
    let mut covered_nodes = BTreeSet::new();
    let mut covered_domains = BTreeSet::new();
    for object in &ownership.objects {
        ordered_ids(object.node_ids.iter(), content.limits.maximum_nodes)?;
        for node in &object.node_ids {
            require_node(request, node)?;
            covered_nodes.insert(node.clone());
        }
        match &object.state {
            ObjectState::Mutable { domain_id } => {
                let domain = domains.get(domain_id).ok_or_else(|| {
                    fail(
                        AdmissionSubject::Domain(domain_id.clone()),
                        "every mutable object belongs to declared unique domain",
                        "unknown object domain",
                    )
                })?;
                if object.future_affecting && !domain.future_affecting {
                    return Err(fail(
                        AdmissionSubject::Domain(domain_id.clone()),
                        "future-affecting object retains future-affecting domain classification",
                        "future-affecting state mislabeled operational",
                    ));
                }
                covered_domains.insert(domain_id.clone());
            }
            ObjectState::Immutable { content_ref } => content.verify(content_ref)?,
            ObjectState::OutsideScope
                if object.future_affecting
                    && (exact
                        || object.node_ids.iter().any(|node_id| {
                            guarantees.get(node_id).is_some_and(|guarantee| {
                                guarantee.capture_scope
                                    == crucible_node_contract::CaptureScope::CompleteModel
                            })
                        })) =>
            {
                return Err(refuse(
                    AdmissionStage::Graph,
                    AdmissionSubject::World,
                    AdmissionCode::CaptureUnsupported,
                    "all future-affecting realized objects preserved or content-bound",
                    "future-affecting object excluded from capture",
                ));
            }
            ObjectState::OutsideScope => {}
        }
    }
    if covered_nodes.len() != request.descriptors.len()
        || covered_domains.len() != ownership.domains.len()
    {
        return Err(fail(
            AdmissionSubject::World,
            "coverage inventory includes every public node and mutable domain",
            "incomplete object coverage",
        ));
    }
    let captures: BTreeMap<_, _> = ownership
        .capture_owners
        .iter()
        .map(|owner| (&owner.owner_id, owner))
        .collect();
    for owner in request.owners {
        if !owner
            .owner_roles
            .iter()
            .any(|role| role.as_str() == "capture")
        {
            continue;
        }
        let policy = captures.get(&owner.owner.id).ok_or_else(|| {
            fail(
                AdmissionSubject::Owner(owner.owner.id.clone()),
                "every capture owner has an explicit boundary and dependency contract",
                "missing capture owner contract",
            )
        })?;
        for node_id in &owner.owner.participant_ids {
            let captures_node = request
                .bindings
                .binary_search_by(|binding| binding.compatibility.node_id.cmp(node_id))
                .ok()
                .is_some_and(|index| {
                    request.bindings[index].compatibility.capture_owner.id == owner.owner.id
                });
            if !captures_node {
                continue;
            }
            let guarantee = guarantees.get(node_id).ok_or_else(|| {
                fail(
                    AdmissionSubject::Owner(owner.owner.id.clone()),
                    "owner members have actual selected guarantee profiles",
                    "missing selected owner guarantee",
                )
            })?;
            if guarantee.capture_scope == crucible_node_contract::CaptureScope::CompleteModel
                && (!policy.complete_model || !policy.unchanged_cut)
                || guarantee.continuation == crucible_node_contract::Continuation::Exact
                    && !policy.exact_continuation
                || guarantee.durable_restart && !policy.durable_restart
                || guarantee.isolated_fork && !policy.isolated_fork
            {
                return Err(refuse(
                    AdmissionStage::Graph,
                    AdmissionSubject::Owner(owner.owner.id.clone()),
                    AdmissionCode::CaptureUnsupported,
                    "owner capture contract supports every actually selected preservation claim",
                    "node claims exceed authoritative owner preservation contract",
                ));
            }
        }
        ordered_ids(policy.dependencies.iter(), content.limits.maximum_owners)?;
        for dependency in &policy.dependencies {
            if !captures.contains_key(dependency) {
                return Err(fail(
                    AdmissionSubject::Owner(owner.owner.id.clone()),
                    "capture dependency closes over actual authoritative owners",
                    "missing capture dependency",
                ));
            }
        }
        if exact && (!policy.complete_model || !policy.unchanged_cut)
            || request.requirements.exact_continuation && !policy.exact_continuation
            || request.requirements.durable_restart && !policy.durable_restart
            || request.requirements.isolated_fork && !policy.isolated_fork
        {
            return Err(refuse(
                AdmissionStage::Graph,
                AdmissionSubject::Owner(owner.owner.id.clone()),
                AdmissionCode::CaptureUnsupported,
                "owner covers complete requested unchanged-cut capture and independent continuation axes",
                "owner preservation scope or reconstruction unsupported",
            ));
        }
        content.verify(&policy.cut_procedure_ref)?;
        content.qualify(
            AdmissionSubject::Owner(owner.owner.id.clone()),
            QualificationClaim::Capture {
                world_binding_hash: world_hash,
                capture_owner_id: &owner.owner.id,
                procedure_ref: &policy.cut_procedure_ref,
            },
        )?;
    }
    if captures.len()
        != request
            .owners
            .iter()
            .filter(|owner| {
                owner
                    .owner_roles
                    .iter()
                    .any(|role| role.as_str() == "capture")
            })
            .count()
    {
        return Err(fail(
            AdmissionSubject::World,
            "no extra undeclared capture owner policies",
            "foreign capture owner policy",
        ));
    }
    if exact || request.requirements.durable_restart || request.requirements.isolated_fork {
        for connection in &request.world.connections {
            let cut = captures.get(&connection.capture_owner_id).ok_or_else(|| {
                fail(
                    AdmissionSubject::Connection(connection.id.clone()),
                    "connection custody captured by actual world owner",
                    "missing connection capture contract",
                )
            })?;
            for node_id in [&connection.producer.node_id, &connection.consumer.node_id] {
                let binding = request
                    .bindings
                    .binary_search_by(|binding| binding.compatibility.node_id.cmp(node_id))
                    .ok()
                    .map(|index| &request.bindings[index])
                    .ok_or_else(|| {
                        fail(
                            AdmissionSubject::Connection(connection.id.clone()),
                            "connection endpoints included in capture closure",
                            "missing capture endpoint",
                        )
                    })?;
                let peer = &binding.compatibility.capture_owner.id;
                if peer != &connection.capture_owner_id && !cut.dependencies.contains(peer) {
                    return Err(refuse(
                        AdmissionStage::Graph,
                        AdmissionSubject::Connection(connection.id.clone()),
                        AdmissionCode::CaptureUnsupported,
                        "transfer owner declares both endpoint owners in consistent-cut dependencies",
                        "cross-owner transfer dependency omitted",
                    ));
                }
            }
        }
    }
    content.verify(&ownership.inventory_proof_ref)?;
    content.qualify(
        AdmissionSubject::World,
        QualificationClaim::CompleteInventory {
            world_binding_hash: world_hash,
            ownership_ref: &request.world.ownership_ref,
            proof_ref: &ownership.inventory_proof_ref,
        },
    )
}

fn validate_coordinator(
    request: &AdmissionRequest<'_>,
    coordinator: &CoordinatorPolicy,
    ports: &PortPolicies,
    world_hash: &HashRef,
    content: &mut VerifiedContent<'_>,
) -> Result<(), AdmissionError> {
    if coordinator.schema_version != 1 {
        return Err(refuse(
            AdmissionStage::Graph,
            AdmissionSubject::World,
            AdmissionCode::InvalidSchema,
            "supported coordinator policy edition",
            "unknown coordinator edition",
        ));
    }
    ordered_ids(
        coordinator
            .same_time_closure
            .iter()
            .map(|closure| &closure.execution_owner_id),
        content.limits.maximum_owners,
    )?;
    if coordinator.external_inputs.len() > content.limits.maximum_connections
        || coordinator
            .external_inputs
            .windows(2)
            .any(|pair| endpoint_key(&pair[0]) >= endpoint_key(&pair[1]))
    {
        return Err(refuse(
            AdmissionStage::Graph,
            AdmissionSubject::World,
            AdmissionCode::InvalidSchema,
            "bounded strictly sorted external-input inventory",
            "duplicate, unordered, or oversized external inputs",
        ));
    }
    super::ports::validate_input_roster(request, ports, &coordinator.external_inputs)?;
    content.verify(&coordinator.state_closure_ref)?;
    content.verify(&coordinator.operational_policy_ref)?;
    for closure in &coordinator.same_time_closure {
        if !request.owners.iter().any(|owner| {
            owner.owner.id == closure.execution_owner_id
                && owner
                    .owner_roles
                    .iter()
                    .any(|role| role.as_str() == "execution")
        }) {
            return Err(refuse(
                AdmissionStage::Graph,
                AdmissionSubject::Owner(closure.execution_owner_id.clone()),
                AdmissionCode::OwnerConflict,
                "closure policy names actual execution owner",
                "foreign or capture-only closure owner",
            ));
        }
        content.verify(&closure.proof_ref)?;
    }
    content.qualify(
        AdmissionSubject::World,
        QualificationClaim::Coordinator {
            world_binding_hash: world_hash,
            policy_ref: &request.world.coordinator_contract_ref,
        },
    )
}

fn endpoint_key(endpoint: &crucible_node_contract::Endpoint) -> (&Id, &Id, &Id) {
    (&endpoint.node_id, &endpoint.port_id, &endpoint.lane_id)
}

fn validate_zero_cycles(
    request: &AdmissionRequest<'_>,
    coordinator: &CoordinatorPolicy,
    edges: &CausalEdges,
    public_edge_count: usize,
    world_hash: &HashRef,
    content: &mut VerifiedContent<'_>,
) -> Result<(), AdmissionError> {
    let node_owner: BTreeMap<_, _> = request
        .bindings
        .iter()
        .map(|binding| {
            (
                &binding.compatibility.node_id,
                &binding.compatibility.execution_owner.id,
            )
        })
        .collect();
    let mut adjacency: BTreeMap<Id, BTreeSet<Id>> = BTreeMap::new();
    for (index, (producer, consumer, latency)) in edges.iter().enumerate() {
        if *latency != 0 {
            continue;
        }
        let source = node_owner.get(producer).ok_or_else(|| {
            refuse(
                AdmissionStage::Graph,
                AdmissionSubject::Node(producer.clone()),
                AdmissionCode::OwnerConflict,
                "causal producer has actual execution owner",
                "unknown causal producer",
            )
        })?;
        let target = node_owner.get(consumer).ok_or_else(|| {
            refuse(
                AdmissionStage::Graph,
                AdmissionSubject::Node(consumer.clone()),
                AdmissionCode::OwnerConflict,
                "causal consumer has actual execution owner",
                "unknown causal consumer",
            )
        })?;
        // Private native paths inside one indivisible owner remain qualified
        // by its execution contract. Public coordinator-mediated feedback still
        // requires bounded microstep closure even when both views share it.
        if source != target || index < public_edge_count {
            adjacency
                .entry((*source).clone())
                .or_default()
                .insert((*target).clone());
        }
    }
    let mut cycle_owners = BTreeSet::new();
    // Iterative reachability avoids recursion on vendor-sized graphs. Each
    // bounded owner/path roster limits both work and temporary allocation.
    for start in adjacency.keys() {
        let mut seen = BTreeSet::new();
        let mut pending: Vec<_> = adjacency
            .get(start)
            .into_iter()
            .flatten()
            .cloned()
            .collect();
        while let Some(next) = pending.pop() {
            if &next == start {
                cycle_owners.insert(start.clone());
                break;
            }
            if seen.insert(next.clone()) {
                if let Some(successors) = adjacency.get(&next) {
                    pending.extend(successors.iter().filter(|id| !seen.contains(*id)).cloned());
                }
            }
        }
    }
    for owner in cycle_owners {
        let closure = coordinator
            .same_time_closure
            .iter()
            .find(|closure| closure.execution_owner_id == owner);
        if coordinator.maximum_microsteps_per_instant.get() == 0 || closure.is_none() {
            return Err(refuse(
                AdmissionStage::Graph,
                AdmissionSubject::Owner(owner),
                AdmissionCode::CausalProgressUnavailable,
                "finite positive microstep cap and complete qualified closure for every zero-cycle owner",
                "missing same-time closure or finite cycle bound",
            ));
        }
        if let Some(closure) = closure {
            content.qualify(
                AdmissionSubject::Owner(owner),
                QualificationClaim::SameTimeClosure {
                    world_binding_hash: world_hash,
                    execution_owner_id: &closure.execution_owner_id,
                    proof_ref: &closure.proof_ref,
                },
            )?;
        }
    }
    Ok(())
}

fn propagate_guarantees(
    request: &AdmissionRequest<'_>,
    ownership: &OwnershipPolicy,
    guarantees: &BTreeMap<Id, GuaranteeProfile>,
    edges: CausalEdges,
) -> Result<GraphGuarantees, AdmissionError> {
    let mut adjacency: BTreeMap<Id, BTreeSet<Id>> = BTreeMap::new();
    for (producer, consumer, _) in edges {
        adjacency.entry(producer).or_default().insert(consumer);
    }
    // Shared execution, state, and cut dependencies carry influence even when
    // no network lane directly connects the public views. A star preserves
    // group reachability without allocating a quadratic clique.
    for owner in request.owners {
        connect_group(&mut adjacency, &owner.owner.participant_ids);
    }
    let owners: BTreeMap<_, _> = request
        .owners
        .iter()
        .map(|owner| (&owner.owner.id, owner))
        .collect();
    for domain in &ownership.domains {
        let mut group = BTreeSet::new();
        for owner_id in domain
            .execution_owner_ids
            .iter()
            .chain(std::iter::once(&domain.capture_owner_id))
        {
            if let Some(owner) = owners.get(owner_id) {
                group.extend(owner.owner.participant_ids.iter().cloned());
            }
        }
        connect_group(&mut adjacency, &group.into_iter().collect::<Vec<_>>());
    }
    for capture in &ownership.capture_owners {
        if let Some(owner) = owners.get(&capture.owner_id) {
            for dependency in &capture.dependencies {
                if let Some(peer) = owners.get(dependency) {
                    let mut group = owner.owner.participant_ids.clone();
                    group.extend(peer.owner.participant_ids.iter().cloned());
                    connect_group(&mut adjacency, &group);
                }
            }
        }
    }
    let mut effective: BTreeMap<_, _> = guarantees
        .iter()
        .map(|(id, profile)| (id.clone(), profile.repeatability))
        .collect();
    let mut pending: VecDeque<_> = effective
        .iter()
        .filter(|(_, repeatability)| **repeatability != Repeatability::Qualified)
        .map(|(id, _)| id.clone())
        .collect();
    while let Some(producer) = pending.pop_front() {
        let source = effective.get(&producer).copied().ok_or_else(|| {
            refuse(
                AdmissionStage::Graph,
                AdmissionSubject::Node(producer.clone()),
                AdmissionCode::IdentityMismatch,
                "all propagated nodes admitted",
                "missing propagated node",
            )
        })?;
        if let Some(consumers) = adjacency.get(&producer) {
            for consumer in consumers {
                let target = effective.get_mut(consumer).ok_or_else(|| {
                    refuse(
                        AdmissionStage::Graph,
                        AdmissionSubject::Node(consumer.clone()),
                        AdmissionCode::IdentityMismatch,
                        "all propagated nodes admitted",
                        "missing consumer node",
                    )
                })?;
                if rank(source) > rank(*target) {
                    *target = source;
                    pending.push_back(consumer.clone());
                }
            }
        }
    }
    let world = effective
        .values()
        .copied()
        .max_by_key(|value| rank(*value))
        .unwrap_or(Repeatability::Unqualified);
    Ok(GraphGuarantees {
        effective_repeatability: effective,
        world_repeatability: world,
    })
}

fn connect_group(adjacency: &mut BTreeMap<Id, BTreeSet<Id>>, participants: &[Id]) {
    if let Some(first) = participants.first() {
        for participant in participants.iter().skip(1) {
            if participant != first {
                adjacency
                    .entry(first.clone())
                    .or_default()
                    .insert(participant.clone());
                adjacency
                    .entry(participant.clone())
                    .or_default()
                    .insert(first.clone());
            }
        }
    }
}

fn rank(repeatability: Repeatability) -> u8 {
    match repeatability {
        Repeatability::Qualified => 0,
        Repeatability::Unqualified => 1,
        Repeatability::Nondeterministic => 2,
    }
}
