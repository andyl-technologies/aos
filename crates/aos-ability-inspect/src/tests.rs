//! Portable inspection regression tests.

use std::collections::{BTreeMap, BTreeSet};

use aos_ability_model::document::PackageSubject;
use aos_ability_model::identity::compare_request_ids;
use aos_ability_model::{
    AbilityActivationMode, AbilityValue, DeploymentObligation, ExportDeclaration,
    HandlerDescriptor, ImplementationKind, LocalKey, ObligationKind, PackageDocument,
    PackageImplementation, ProviderImplementation, RequiredFeature, ValueExpression, ValueSchema,
    VersionedDocument,
};
use aos_ability_validate::ValidationContext;
use aos_ability_validate::test_support::{
    checked_effect_plan, plan_fixture, planned_provider_chain_fixture,
};
use aos_contract::Sha256Digest;

use crate::{
    Direction, GraphQuery, InspectionBundle, InspectionBundleError, InspectionDiff, InspectionEdge,
    InspectionNode, InspectionRelation, InspectionView, NodeKey, ProjectionKind, RenderFormat,
    ViewAnchor, render, render_projection, render_slice,
};

#[test]
fn bundle_round_trip_revalidates_and_distinguishes_anchor_status()
-> Result<(), Box<dyn std::error::Error>> {
    let plan = checked_effect_plan();
    let bundle = InspectionBundle::from_checked(&plan)?;
    let digest = bundle.digest()?;
    let bytes = bundle.canonical_bytes()?;

    let unanchored = InspectionBundle::decode(&bytes)?.check(None)?;
    let unanchored_view = InspectionView::from_bundle(&unanchored)?;
    assert!(matches!(
        unanchored_view.anchor(),
        ViewAnchor::UnanchoredBundle { digest: observed } if *observed == digest
    ));

    let anchored = InspectionBundle::decode(&bytes)?.check(Some(digest))?;
    let anchored_view = InspectionView::from_bundle(&anchored)?;
    assert!(matches!(
        anchored_view.anchor(),
        ViewAnchor::ExternallyAnchoredBundle { digest: observed } if *observed == digest
    ));
    assert!(InspectionDiff::between(&unanchored_view, &anchored_view).is_empty());
    Ok(())
}

#[test]
fn bundle_round_trip_accepts_the_implemented_abilities_v1_feature()
-> Result<(), Box<dyn std::error::Error>> {
    let feature = RequiredFeature::new("abilities-v1")?;
    let mut fixture = plan_fixture();
    install_package_with_feature(&mut fixture, feature.clone())?;
    fixture.context =
        ValidationContext::new(BTreeSet::from([feature]), fixture.interfaces.clone())?;

    let bundle = InspectionBundle::from_checked(&fixture.validate()?)?;
    let bytes = bundle.canonical_bytes()?;
    let checked = InspectionBundle::decode(&bytes)?.check(None)?;

    assert_eq!(checked.bundle().canonical_bytes()?, bytes);
    Ok(())
}

fn install_package_with_feature(
    fixture: &mut aos_ability_validate::test_support::PlanFixture,
    feature: RequiredFeature,
) -> Result<(), Box<dyn std::error::Error>> {
    let binding = &mut fixture.binding_plan.bindings[0];
    let artifact = binding.implementation.artifact.clone();
    let handler = LocalKey::new("observe-handler")?;
    let implementation = ProviderImplementation {
        interface: binding.interface.clone(),
        artifact: artifact.clone(),
        requirements: Vec::new(),
        implementation: ImplementationKind::TerminalHandler {
            handler: handler.clone(),
        },
        owns_resource_kinds: Vec::new(),
    };
    let descriptor = implementation.descriptor_digest()?;
    binding.implementation.descriptor = descriptor;
    binding.implementation.handler = Some(handler.clone());
    fixture.binding_inputs.environment.providers[0].implementation = binding.implementation.clone();

    let package = PackageDocument {
        schema: PackageDocument::SCHEMA.to_string(),
        required_features: vec![feature],
        activation_mode: AbilityActivationMode::StructuredEffects,
        package: PackageSubject {
            name: LocalKey::new("feature-provider")?,
            version: "1.0.0".to_string(),
            payload: artifact.clone(),
            source: artifact.clone(),
        },
        artifacts: vec![artifact.clone()],
        exports: vec![ExportDeclaration {
            name: LocalKey::new("provider")?,
            interface: binding.interface.clone(),
            aggregation: None,
            implementation: descriptor,
        }],
        requirements: Vec::new(),
        module_entry_points: BTreeMap::new(),
        implementation: PackageImplementation {
            providers: vec![implementation],
            handlers: BTreeMap::from([(
                handler,
                HandlerDescriptor {
                    artifact,
                    entry_point: "bin/observe".to_string(),
                    arguments: ValueSchema::Boolean,
                    result: ValueSchema::Boolean,
                },
            )]),
        },
        ownership: Vec::new(),
    };
    binding.provider_package = Some(package.content_digest()?);
    fixture.binding_inputs.packages = vec![package];
    fixture.refresh_commitments();
    Ok(())
}

#[test]
fn bundle_rejects_noncanonical_and_mismatched_commitments() -> Result<(), Box<dyn std::error::Error>>
{
    let bundle = InspectionBundle::from_checked(&checked_effect_plan())?;
    let bytes = bundle.canonical_bytes()?;

    let mut noncanonical = b" \n".to_vec();
    noncanonical.extend_from_slice(&bytes);
    assert!(matches!(
        InspectionBundle::decode(&noncanonical),
        Err(InspectionBundleError::NoncanonicalEncoding)
    ));

    let mismatch = Sha256Digest::of_bytes("different external commitment");
    assert!(matches!(
        InspectionBundle::decode(&bytes)?.check(Some(mismatch)),
        Err(InspectionBundleError::CommitmentMismatch)
    ));
    Ok(())
}

#[test]
fn bundle_rejects_a_canonical_false_plan_identity() -> Result<(), Box<dyn std::error::Error>> {
    let bundle = InspectionBundle::from_checked(&checked_effect_plan())?;
    let mut value: serde_json::Value = serde_json::from_slice(&bundle.canonical_bytes()?)?;
    value["effect_plan"] = serde_json::Value::String(Sha256Digest::of_bytes("false").to_string());
    let bytes = aos_contract::canonical::to_vec(&value)?;

    let error = match InspectionBundle::decode(&bytes)?.check(None) {
        Ok(_) => panic!("a false plan identity must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(error, InspectionBundleError::PlanIdentityMismatch));
    Ok(())
}

#[test]
fn bundle_rejects_unsupported_inspection_features() -> Result<(), Box<dyn std::error::Error>> {
    let bundle = InspectionBundle::from_checked(&checked_effect_plan())?;
    let mut value: serde_json::Value = serde_json::from_slice(&bundle.canonical_bytes()?)?;
    value["required_features"] = serde_json::json!(["future-inspection-semantics"]);
    let bytes = aos_contract::canonical::to_vec(&value)?;

    assert!(matches!(
        InspectionBundle::decode(&bytes),
        Err(InspectionBundleError::UnsupportedFeatures)
    ));
    Ok(())
}

#[test]
fn bundle_does_not_infer_support_for_a_nested_future_feature()
-> Result<(), Box<dyn std::error::Error>> {
    let feature = RequiredFeature::new("future-ability-semantics")?;
    let mut fixture = plan_fixture();
    install_package_with_feature(&mut fixture, feature.clone())?;
    fixture.context =
        ValidationContext::new(BTreeSet::from([feature]), fixture.interfaces.clone())?;

    let bundle = InspectionBundle::from_checked(&fixture.validate()?)?;
    assert!(matches!(
        bundle.check(None),
        Err(InspectionBundleError::Validation(_))
    ));
    Ok(())
}

#[test]
fn view_has_stable_nodes_and_no_dangling_edges() -> Result<(), Box<dyn std::error::Error>> {
    let plan = checked_effect_plan();
    let view = InspectionView::from_checked(&plan)?;
    let keys: BTreeSet<_> = view.nodes().iter().map(InspectionNode::key).collect();

    assert!(
        view.nodes()
            .windows(2)
            .all(|pair| pair[0].key() < pair[1].key())
    );
    assert!(
        view.edges()
            .iter()
            .all(|edge| keys.contains(&edge.from) && keys.contains(&edge.to))
    );
    assert!(
        view.nodes()
            .iter()
            .any(|node| matches!(node, InspectionNode::Operation { .. }))
    );
    assert!(
        view.nodes()
            .iter()
            .any(|node| matches!(node, InspectionNode::Resource { .. }))
    );
    assert!(
        view.nodes()
            .iter()
            .any(|node| matches!(node, InspectionNode::Artifact { .. }))
    );
    Ok(())
}

#[test]
fn named_projections_preserve_identities_and_separate_edge_semantics()
-> Result<(), Box<dyn std::error::Error>> {
    let view = InspectionView::from_checked(&checked_effect_plan())?;
    let view_keys: BTreeSet<_> = view.nodes().iter().map(InspectionNode::key).collect();

    let composition = view.project(ProjectionKind::Composition)?;
    assert!(
        composition
            .nodes()
            .iter()
            .all(|node| view_keys.contains(&node.key()))
    );
    assert!(composition.edges().iter().any(|edge| {
        edge.relation == InspectionRelation::ExportsInterface
            || edge.relation == InspectionRelation::ConsumesRequest
    }));
    assert!(
        !composition
            .nodes()
            .iter()
            .any(|node| matches!(node, InspectionNode::Operation { .. }))
    );

    let authority = view.project(ProjectionKind::BindingAuthority)?;
    assert!(
        authority
            .nodes()
            .iter()
            .any(|node| matches!(node, InspectionNode::Binding { .. }))
    );
    assert!(
        authority
            .edges()
            .iter()
            .any(|edge| edge.relation == InspectionRelation::UsesBinding)
    );

    let activation = view.project(ProjectionKind::Activation)?;
    assert!(activation.edges().iter().any(|edge| matches!(
        edge.relation,
        InspectionRelation::ReadsResource
            | InspectionRelation::SharedWritesResource
            | InspectionRelation::ExclusivelyWritesResource
    )));

    let retention = view.project(ProjectionKind::Retention)?;
    assert!(
        retention
            .nodes()
            .iter()
            .any(|node| matches!(node, InspectionNode::Artifact { .. }))
    );
    assert!(retention.edges().iter().any(|edge| matches!(
        edge.relation,
        InspectionRelation::AuthenticatesArtifact
            | InspectionRelation::UsesImplementationArtifact
            | InspectionRelation::RetainsArtifact
    )));
    assert!(render_projection(&retention, RenderFormat::Text)?.contains("projection: retention"));
    assert_eq!(
        render_projection(&retention, RenderFormat::Json)?.into_bytes(),
        retention.canonical_bytes()?
    );
    Ok(())
}

#[test]
fn composition_projection_queries_recursive_provider_selection()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = planned_provider_chain_fixture();
    let binding_b = fixture
        .binding_plan
        .bindings
        .iter()
        .find(|binding| binding.id.0.as_str() == "b")
        .ok_or("fixture is missing binding b")?
        .clone();
    let binding_c = fixture
        .binding_plan
        .bindings
        .iter_mut()
        .find(|binding| binding.id.0.as_str() == "c")
        .ok_or("fixture is missing binding c")?;
    binding_c.request.consumer = binding_b.provider.clone();
    binding_c.caller_grant.principal = binding_b.provider.clone();
    let binding_c_id = binding_c.id.clone();
    let request_c = binding_c.request.clone();
    let provider_c = binding_c.provider.clone();

    fixture
        .binding_plan
        .requests
        .iter_mut()
        .find(|request| request.id.key.as_str() == "c")
        .ok_or("fixture is missing binding-plan request c")?
        .id = request_c.clone();
    fixture
        .binding_inputs
        .desired_state
        .child_requests
        .iter_mut()
        .find(|request| request.id.key.as_str() == "c")
        .ok_or("fixture is missing desired-state request c")?
        .id = request_c.clone();
    fixture
        .binding_plan
        .requests
        .sort_by(|left, right| compare_request_ids(&left.id, &right.id));
    fixture
        .binding_inputs
        .desired_state
        .child_requests
        .sort_by(|left, right| compare_request_ids(&left.id, &right.id));
    fixture.refresh_commitments();

    let view = InspectionView::from_checked(&fixture.validate()?)?;
    let composition = view.project(ProjectionKind::Composition)?;
    let slice = composition.query(&GraphQuery::new(
        [NodeKey::Request(binding_b.request.clone())],
        5,
        32,
    ))?;

    assert_eq!(slice.projection(), Some(ProjectionKind::Composition));
    assert!(!slice.is_truncated());
    assert!(
        slice
            .nodes()
            .iter()
            .any(|node| { matches!(node, InspectionNode::Request { id, .. } if id == &request_c) })
    );
    assert!(
        slice.nodes().iter().any(|node| {
            matches!(node, InspectionNode::Provider { id, .. } if id == &provider_c)
        })
    );
    let chain = [
        InspectionEdge {
            from: NodeKey::Request(binding_b.request),
            to: NodeKey::Binding(binding_b.id.clone()),
            relation: InspectionRelation::SelectsBinding,
        },
        InspectionEdge {
            from: NodeKey::Binding(binding_b.id),
            to: NodeKey::Provider(binding_b.provider.clone()),
            relation: InspectionRelation::SelectsProvider,
        },
        InspectionEdge {
            from: NodeKey::Provider(binding_b.provider),
            to: NodeKey::Request(request_c.clone()),
            relation: InspectionRelation::ConsumesRequest,
        },
        InspectionEdge {
            from: NodeKey::Request(request_c),
            to: NodeKey::Binding(binding_c_id.clone()),
            relation: InspectionRelation::SelectsBinding,
        },
        InspectionEdge {
            from: NodeKey::Binding(binding_c_id),
            to: NodeKey::Provider(provider_c),
            relation: InspectionRelation::SelectsProvider,
        },
    ];
    assert!(chain.iter().all(|edge| slice.edges().contains(edge)));
    Ok(())
}

#[test]
fn literal_and_explicit_nested_artifacts_have_the_same_retention_edge()
-> Result<(), Box<dyn std::error::Error>> {
    let explicit_fixture = plan_fixture();
    let artifact = explicit_fixture.effect_plan.artifacts[0].clone();
    let explicit = ValueExpression::Object {
        fields: BTreeMap::from([(
            "payload".to_string(),
            ValueExpression::List {
                items: vec![ValueExpression::ArtifactReference {
                    reference: artifact.clone(),
                }],
            },
        )]),
    };
    let literal = ValueExpression::Literal {
        value: AbilityValue::new(serde_json::json!({"payload": [artifact]}))?,
    };

    let explicit_view = nested_artifact_view(explicit_fixture, explicit)?;
    let literal_view = nested_artifact_view(plan_fixture(), literal)?;
    let explicit_edges = retention_edges(&explicit_view);
    let literal_edges = retention_edges(&literal_view);

    assert_eq!(explicit_edges.len(), 1);
    assert_eq!(explicit_edges, literal_edges);
    Ok(())
}

fn nested_artifact_view(
    mut fixture: aos_ability_validate::test_support::PlanFixture,
    inputs: ValueExpression,
) -> Result<InspectionView, Box<dyn std::error::Error>> {
    let payload = LocalKey::new("payload")?;
    fixture.interfaces[0]
        .interface
        .methods
        .get_mut("observe")
        .ok_or("fixture is missing observe method")?
        .parameters = ValueSchema::Optional {
        value: Box::new(ValueSchema::Record {
            fields: BTreeMap::from([(
                payload,
                ValueSchema::List {
                    element: Box::new(ValueSchema::ArtifactReference),
                    max_items: 4,
                },
            )]),
            optional_fields: Vec::new(),
        }),
    };
    fixture.effect_plan.operations[0].inputs = inputs;
    fixture.refresh_interface();

    Ok(InspectionView::from_checked(&fixture.validate()?)?)
}

fn retention_edges(view: &InspectionView) -> BTreeSet<InspectionEdge> {
    view.edges()
        .iter()
        .filter(|edge| edge.relation == InspectionRelation::RetainsArtifact)
        .cloned()
        .collect()
}

#[test]
fn exact_node_budget_reports_only_reachable_omissions() -> Result<(), Box<dyn std::error::Error>> {
    let plan = checked_effect_plan();
    let request = plan.binding_plan().document().requests[0].id.clone();
    let terminal_resource = plan.operations()[0].accesses[0].resource.clone();
    let view = InspectionView::from_checked(&plan)?;

    // consumer -> request -> binding/interface: the second hop must be probed
    // even after the first hop exactly fills the two-node budget.
    let limited = view.query(&GraphQuery::new(
        [NodeKey::Provider(request.consumer)],
        8,
        2,
    ))?;
    assert_eq!(limited.nodes().len(), 2);
    assert!(limited.is_truncated());

    // A terminal resource that exactly fills its one-node budget has no omitted
    // outgoing neighbor and must remain complete.
    let complete = view.query(&GraphQuery::new(
        [NodeKey::Resource(terminal_resource)],
        8,
        1,
    ))?;
    assert_eq!(complete.nodes().len(), 1);
    assert!(!complete.is_truncated());
    Ok(())
}

#[test]
fn reverse_query_and_all_renderers_share_the_same_slice() -> Result<(), Box<dyn std::error::Error>>
{
    let plan = checked_effect_plan();
    let binding = plan.binding_plan().bindings()[0].id.clone();
    let view = InspectionView::from_checked(&plan)?;
    let slice = view.query(
        &GraphQuery::new([NodeKey::Binding(binding)], 1, 32).with_direction(Direction::Incoming),
    )?;

    assert!(slice.nodes().len() > 1);
    let text = render_slice(&slice, RenderFormat::Text)?;
    let json = render_slice(&slice, RenderFormat::Json)?;
    let dot = render_slice(&slice, RenderFormat::Dot)?;
    let mermaid = render_slice(&slice, RenderFormat::Mermaid)?;
    assert!(text.contains("query truncated:"));
    assert!(json.contains("\"nodes\""));
    assert!(dot.starts_with("digraph ability_inspection"));
    assert!(mermaid.starts_with("flowchart TD"));
    Ok(())
}

#[test]
fn operation_input_change_is_visible_under_redaction() -> Result<(), Box<dyn std::error::Error>> {
    let before = checked_effect_plan();
    let mut fixture = plan_fixture();
    fixture.effect_plan.operations[0].inputs = ValueExpression::Literal {
        value: AbilityValue::new(serde_json::Value::Bool(false))?,
    };
    let after = fixture.validate()?;

    let before_view = InspectionView::from_checked(&before)?;
    let after_view = InspectionView::from_checked(&after)?;
    let difference = InspectionDiff::between(&before_view, &after_view);
    assert!(difference.semantic_plan_changed);
    assert!(
        difference
            .changed_nodes
            .iter()
            .any(|change| matches!(change.after, InspectionNode::Operation { .. }))
    );
    assert!(!difference.is_empty());

    let json = render(&after_view, RenderFormat::Json)?;
    assert_eq!(json.into_bytes(), after_view.canonical_bytes()?);
    Ok(())
}

#[test]
fn unresolved_obligation_view_is_explicitly_non_executable()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = plan_fixture();
    let obligation = DeploymentObligation {
        key: fixture.binding_plan.requests[0].id.key.clone(),
        kind: ObligationKind::Authorization,
        request: fixture.binding_plan.requests[0].id.clone(),
        resource: None,
        description: "operator approval is absent".to_string(),
    };
    fixture.binding_plan.bindings.clear();
    fixture.binding_plan.obligations = vec![obligation.clone()];
    fixture.effect_plan.operations.clear();
    fixture.effect_plan.edges.clear();
    fixture.effect_plan.provider_readiness.clear();
    fixture.effect_plan.controllers.clear();
    fixture.effect_plan.artifacts.clear();
    fixture.effect_plan.obligations = vec![obligation];
    fixture.refresh_commitments();

    let view = InspectionView::from_checked(&fixture.validate()?)?;
    assert!(!view.is_executable());
    assert!(
        view.nodes()
            .iter()
            .any(|node| matches!(node, InspectionNode::Obligation { .. }))
    );
    assert!(render(&view, RenderFormat::Text)?.contains("executable: false"));
    Ok(())
}
