//! Portable inspection regression tests.

use std::collections::{BTreeMap, BTreeSet};

use aos_ability_model::document::PackageSubject;
use aos_ability_model::{
    AbilityActivationMode, AbilityValue, DeploymentObligation, ExportDeclaration,
    HandlerDescriptor, ImplementationKind, LocalKey, ObligationKind, PackageDocument,
    PackageImplementation, ProviderImplementation, RequiredFeature, ValueExpression, ValueSchema,
    VersionedDocument,
};
use aos_ability_validate::ValidationContext;
use aos_ability_validate::test_support::{checked_effect_plan, plan_fixture};
use aos_contract::Sha256Digest;

use crate::{
    Direction, GraphQuery, InspectionBundle, InspectionBundleError, InspectionDiff, InspectionNode,
    InspectionView, NodeKey, RenderFormat, ViewAnchor, render, render_slice,
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
    Ok(())
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
