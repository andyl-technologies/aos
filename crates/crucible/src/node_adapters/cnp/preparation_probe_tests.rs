//! Verifies local probe credit refusals without claiming native qualification.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crucible_node_contract::Extensions;

fn discovery(request: &str, profiles: &[&str]) -> CnpPreRealizationProbeRequest {
    CnpPreRealizationProbeRequest {
        request: Id::new(request).unwrap(),
        body: CnpPreRealizationProbeBody::Discover(Box::new(DiscoverRequest {
            profile_ids: profiles
                .iter()
                .map(|profile| Id::new(*profile).unwrap())
                .collect(),
            cursor: None,
            extensions: Extensions::new(),
        })),
    }
}

#[test]
fn repeated_original_requests_refuse_before_dispatch() {
    let requests = [discovery("original", &["a"]), discovery("original", &["a"])];

    let error = prepare_bodies(&requests).unwrap_err();

    assert_eq!(error.effects, EffectKnowledge::None);
    assert_eq!(error.reason, "CNP original probe request repeated");
}

#[test]
fn malformed_closed_body_refuses_before_dispatch() {
    let requests = [discovery("original", &["b", "a"])];

    let error = prepare_bodies(&requests).unwrap_err();

    assert_eq!(error.effects, EffectKnowledge::None);
}

#[test]
fn finite_request_population_is_checked_before_dispatch() {
    let requests = (0..=MAXIMUM_REQUESTS)
        .map(|index| discovery(&format!("original/{index}"), &["a"]))
        .collect::<Vec<_>>();

    let error = prepare_bodies(&requests).unwrap_err();

    assert_eq!(error.effects, EffectKnowledge::None);
    assert_eq!(
        error.reason,
        "CNP original probe request population ceiling"
    );
    assert_eq!(
        prepare_bodies(&requests[..MAXIMUM_REQUESTS]).unwrap().len(),
        MAXIMUM_REQUESTS
    );
}

#[test]
fn prepared_bodies_retain_exact_original_source_data() {
    let request = discovery("original", &["a", "b"]);
    let expected = serde_json::json!({"profile_ids":["a","b"],"extensions":{}});

    let bodies = prepare_bodies(&[request]).unwrap();

    assert_eq!(bodies, vec![(Method::Discover, expected)]);
}
