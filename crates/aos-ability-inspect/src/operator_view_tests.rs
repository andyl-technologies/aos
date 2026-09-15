//! Tests for interactive operator views.

use aos_ability_model::TransactionId;
use aos_ability_validate::test_support::checked_effect_plan;

use super::*;
use crate::InspectionBundle;

#[test]
fn operator_query_round_trip_preserves_single_focus() -> Result<(), Box<dyn std::error::Error>> {
    let view = InspectionView::from_checked(&checked_effect_plan())?;
    let provider = first_provider(&view)?;
    let query = OperatorQuery::new(
        OperatorFocus::Instance {
            id: provider.clone(),
        },
        ProjectionKind::Activation,
        2,
        32,
    );

    let bytes = query.canonical_bytes()?;
    let decoded = OperatorQuery::decode(&bytes)?;

    assert_eq!(decoded, query);
    assert_eq!(decoded.graph().roots(), [NodeKey::Provider(provider)]);
    Ok(())
}

#[test]
fn operator_view_separates_plan_and_observed_state_and_groups_transaction()
-> Result<(), Box<dyn std::error::Error>> {
    let view = InspectionView::from_checked(&checked_effect_plan())?;
    let request = first_request(&view)?;
    let request_key = NodeKey::Request(request.clone());
    let query = OperatorQuery::new(
        OperatorFocus::FailingRequest {
            id: request.clone(),
        },
        ProjectionKind::Composition,
        4,
        64,
    );
    let observation = OperatorObservation::new(
        view.plan(),
        Sha256Digest::of_bytes("authenticated operator observation"),
        1_725_900_000_000,
        vec![GenerationObservation::new(
            request.consumer.environment.clone(),
            GenerationAxis::Configuration,
            RevisionId(Sha256Digest::of_bytes("desired configuration")),
            Some(RevisionId(Sha256Digest::of_bytes("observed configuration"))),
        )],
        vec![NodeObservation {
            node: request_key.clone(),
            state: ObservedNodeState::Failed,
        }],
        vec![TransactionObservation {
            transaction: TransactionId(LocalKey::new("activate-nginx")?),
            members: vec![request_key.clone()],
        }],
    )?;

    let operator = OperatorView::from_view(&view, &query, Some(&observation))?;
    let status = operator
        .statuses()
        .iter()
        .find(|status| status.node == request_key)
        .ok_or("request status missing")?;

    assert_eq!(status.plan_state, OperatorNodeState::Declared);
    assert_eq!(status.observed_state, Some(OperatorNodeState::Failed));
    assert!(operator.groups().iter().any(|group| matches!(
        &group.key,
        OperatorGroupKey::Transaction(transaction)
            if transaction.0.as_str() == "activate-nginx"
    )));
    assert_ne!(
        operator.generations()[0].desired(),
        operator.generations()[0]
            .observed()
            .ok_or("observed generation missing")?
    );
    assert_eq!(
        operator.generations()[0].convergence(),
        GenerationConvergence::Diverged
    );
    let encoded = String::from_utf8(operator.canonical_bytes()?)?;
    assert!(encoded.contains("\"plan_state\":\"declared\""));
    assert!(encoded.contains("\"observed_state\":\"failed\""));
    Ok(())
}

#[test]
fn operator_view_serializes_exact_desired_anchor_without_current_state_claim()
-> Result<(), Box<dyn std::error::Error>> {
    let plan = checked_effect_plan();
    let bundle = InspectionBundle::from_checked(&plan)?;
    let digest = bundle.digest()?;
    let unanchored_view = InspectionView::from_bundle(&bundle.clone().check(None)?)?;
    let anchored_view = InspectionView::from_bundle(&bundle.check(Some(digest))?)?;
    let provider = first_provider(&unanchored_view)?;
    let query = OperatorQuery::new(
        OperatorFocus::Instance { id: provider },
        ProjectionKind::Composition,
        1,
        8,
    );

    let unanchored = OperatorView::from_view(&unanchored_view, &query, None)?;
    let anchored = OperatorView::from_view(&anchored_view, &query, None)?;
    let unanchored_json: serde_json::Value =
        serde_json::from_slice(&unanchored.canonical_bytes()?)?;
    let anchored_json: serde_json::Value = serde_json::from_slice(&anchored.canonical_bytes()?)?;

    assert_eq!(unanchored.anchor(), unanchored_view.anchor());
    assert_eq!(anchored.anchor(), anchored_view.anchor());
    assert_eq!(unanchored_json["anchor"]["kind"], "unanchored-bundle");
    assert_eq!(
        anchored_json["anchor"]["kind"],
        "externally-anchored-bundle"
    );
    assert_eq!(unanchored_json["anchor"]["digest"], digest.to_string());
    assert_eq!(anchored_json["anchor"]["digest"], digest.to_string());
    assert!(unanchored_json.get("current").is_none());
    assert!(anchored_json.get("current").is_none());
    assert!(unanchored_json.get("authoritative").is_none());
    assert!(anchored_json.get("authoritative").is_none());
    Ok(())
}

#[test]
fn bounded_slice_exposes_stable_lazy_expansion_queries() -> Result<(), Box<dyn std::error::Error>> {
    let view = InspectionView::from_checked(&checked_effect_plan())?;
    let provider = first_provider(&view)?;
    let query = OperatorQuery::new(
        OperatorFocus::Instance { id: provider },
        ProjectionKind::Composition,
        0,
        1,
    );

    let operator = OperatorView::from_view(&view, &query, None)?;
    let projection = view.project(query.projection())?;
    let visible = operator
        .slice()
        .nodes()
        .iter()
        .map(InspectionNode::key)
        .collect::<BTreeSet<_>>();

    assert!(operator.slice().is_truncated());
    assert!(!operator.expansion().is_empty());
    for hint in operator.expansion() {
        assert_eq!(hint.query.roots(), std::slice::from_ref(&hint.node));
        assert_eq!(hint.query.max_depth(), 1);

        let actual_hidden_incoming = projection
            .edges()
            .iter()
            .filter(|edge| edge.to == hint.node && !visible.contains(&edge.from))
            .count();
        let actual_hidden_outgoing = projection
            .edges()
            .iter()
            .filter(|edge| edge.from == hint.node && !visible.contains(&edge.to))
            .count();
        match hint.query.direction() {
            Direction::Incoming => {
                assert_eq!(hint.hidden_incoming, actual_hidden_incoming);
                assert!(hint.hidden_incoming > 0);
                assert_eq!(hint.hidden_outgoing, 0);
            }
            Direction::Outgoing => {
                assert_eq!(hint.hidden_incoming, 0);
                assert_eq!(hint.hidden_outgoing, actual_hidden_outgoing);
                assert!(hint.hidden_outgoing > 0);
            }
            Direction::Both => panic!("continuation queries must be direction-specific"),
        }

        let canonical_query = hint.query.canonical_bytes()?;
        let continuation_query = GraphQuery::decode(&canonical_query)?;
        let continuation = projection.query(&continuation_query)?;
        assert_eq!(continuation.projection(), Some(query.projection()));
        assert!(
            continuation
                .nodes()
                .iter()
                .any(|node| node.key() == hint.node)
        );
        assert!(
            continuation
                .nodes()
                .iter()
                .any(|node| !visible.contains(&node.key()))
        );
    }
    Ok(())
}

#[test]
fn failing_request_focus_requires_retained_failure_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let view = InspectionView::from_checked(&checked_effect_plan())?;
    let request = first_request(&view)?;
    let query = OperatorQuery::new(
        OperatorFocus::FailingRequest {
            id: request.clone(),
        },
        ProjectionKind::Composition,
        2,
        32,
    );

    assert!(matches!(
        OperatorView::from_view(&view, &query, None),
        Err(OperatorViewError::FocusedRequestNotFailed(focused)) if *focused == request
    ));
    Ok(())
}

#[test]
fn overlay_rejects_foreign_nodes_and_plan_identity() -> Result<(), Box<dyn std::error::Error>> {
    let view = InspectionView::from_checked(&checked_effect_plan())?;
    let request = first_request(&view)?;
    let query = OperatorQuery::new(
        OperatorFocus::FailingRequest { id: request },
        ProjectionKind::Composition,
        2,
        32,
    );
    let foreign = NodeKey::Package(Sha256Digest::of_bytes("foreign package"));
    let foreign_node = OperatorObservation::new(
        view.plan(),
        Sha256Digest::of_bytes("observation"),
        1,
        Vec::new(),
        vec![NodeObservation {
            node: foreign.clone(),
            state: ObservedNodeState::Available,
        }],
        Vec::new(),
    )?;
    assert!(matches!(
        OperatorView::from_view(&view, &query, Some(&foreign_node)),
        Err(OperatorViewError::UnknownObservedNode(node)) if *node == foreign
    ));

    let wrong_plan = OperatorObservation::new(
        PlanId(Sha256Digest::of_bytes("another plan")),
        Sha256Digest::of_bytes("observation"),
        1,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )?;
    assert!(matches!(
        OperatorView::from_view(&view, &query, Some(&wrong_plan)),
        Err(OperatorViewError::PlanMismatch)
    ));
    Ok(())
}

#[test]
fn observation_decode_rejects_noncanonical_and_duplicate_state()
-> Result<(), Box<dyn std::error::Error>> {
    let view = InspectionView::from_checked(&checked_effect_plan())?;
    let request = NodeKey::Request(first_request(&view)?);
    let provider_id = first_provider(&view)?;
    let provider = NodeKey::Provider(provider_id.clone());
    let node = NodeObservation {
        node: request,
        state: ObservedNodeState::Unverified,
    };
    let observation = OperatorObservation::new(
        view.plan(),
        Sha256Digest::of_bytes("observation"),
        1,
        Vec::new(),
        vec![node.clone()],
        Vec::new(),
    )?;
    let bytes = observation.canonical_bytes()?;
    assert_eq!(OperatorObservation::decode(&bytes)?, observation);

    let mut noncanonical = b" \n".to_vec();
    noncanonical.extend_from_slice(&bytes);
    assert!(matches!(
        OperatorObservation::decode(&noncanonical),
        Err(OperatorObservationError::NoncanonicalEncoding)
    ));
    assert!(matches!(
        OperatorObservation::new(
            view.plan(),
            Sha256Digest::of_bytes("duplicate"),
            1,
            Vec::new(),
            vec![node.clone(), node.clone()],
            Vec::new(),
        ),
        Err(OperatorObservationError::DuplicateNode)
    ));

    let ordered = OperatorObservation::new(
        view.plan(),
        Sha256Digest::of_bytes("ordering"),
        1,
        Vec::new(),
        vec![
            node.clone(),
            NodeObservation {
                node: provider,
                state: ObservedNodeState::Available,
            },
        ],
        Vec::new(),
    )?;
    let mut reordered = serde_json::to_value(ordered)?;
    reordered["nodes"]
        .as_array_mut()
        .ok_or("node observations are not an array")?
        .reverse();
    let reordered = aos_contract::canonical::to_vec(&reordered)?;
    assert!(matches!(
        OperatorObservation::decode(&reordered),
        Err(OperatorObservationError::NoncanonicalNodeOrder)
    ));

    let inconsistent_generation = OperatorObservation::new(
        view.plan(),
        Sha256Digest::of_bytes("generation consistency"),
        1,
        vec![GenerationObservation::new(
            provider_id.environment,
            GenerationAxis::Image,
            RevisionId(Sha256Digest::of_bytes("desired image")),
            Some(RevisionId(Sha256Digest::of_bytes("observed image"))),
        )],
        Vec::new(),
        Vec::new(),
    )?;
    let mut inconsistent_generation = serde_json::to_value(inconsistent_generation)?;
    inconsistent_generation["generations"][0]["convergence"] =
        serde_json::Value::String("converged".to_string());
    let inconsistent_generation = aos_contract::canonical::to_vec(&inconsistent_generation)?;
    assert!(matches!(
        OperatorObservation::decode(&inconsistent_generation),
        Err(OperatorObservationError::InconsistentGenerationComparison)
    ));
    Ok(())
}

fn first_provider(view: &InspectionView) -> Result<InstanceId, &'static str> {
    view.nodes()
        .iter()
        .find_map(|node| match node {
            InspectionNode::Provider { id, .. } => Some(id.clone()),
            _ => None,
        })
        .ok_or("provider node missing")
}

fn first_request(view: &InspectionView) -> Result<RequestId, &'static str> {
    view.nodes()
        .iter()
        .find_map(|node| match node {
            InspectionNode::Request { id, .. } => Some(id.clone()),
            _ => None,
        })
        .ok_or("request node missing")
}
