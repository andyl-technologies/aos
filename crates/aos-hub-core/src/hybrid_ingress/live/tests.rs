//! Synthetic protocol checks; no runtime or provider qualification is asserted.

use super::*;

fn request() -> HybridIngressAssertion {
    HybridIngressAssertion {
        version: 1,
        deployment_id: "deployment-1".into(),
        issued_at: 100,
        expires_at: 130,
        request_id: "live-request-1".into(),
        scheme: "https".into(),
        authority: "hub.example.com".into(),
        method: "GET".into(),
        path_and_query: "/registry/HEAD".into(),
        body_sha256: body_sha256(&[]),
        upload_phase: None,
        client_ip: "203.0.113.10".into(),
    }
}

pub(super) fn target() -> HybridLiveDeliveryTarget {
    HybridLiveDeliveryTarget {
        registry_id: 1,
        registry_resource_version: 2,
        mirror_resource_version: 3,
        placement_id: 4,
        placement_resource_version: 5,
        write_spec_version: 8,
        placement_prefix: "registry/live".into(),
        binding_id: 6,
        binding_resource_version: 7,
        protected_profile_digest: "11".repeat(32),
        upstream_base: "https://upstream.example.com/root".into(),
        path: "HEAD".into(),
        class: HybridLiveDeliveryClass::Metadata,
        maximum_bytes: 128 * 1024,
    }
}

#[test]
fn live_grant_binds_complete_original_and_separate_purpose() {
    let key = HybridIngressKey::new([19; 32]).unwrap();
    let request = request();
    let target = target();
    let signed = key.sign_live_delivery(&request, target.clone()).unwrap();

    assert_eq!(
        key.verify_live_delivery(&signed, &request, 101).unwrap(),
        target
    );
    assert!(key.verify_delivery(&signed, &request, 101).is_err());
    assert!(HybridIngressKey::new([20; 32])
        .unwrap()
        .verify_live_delivery(&signed, &request, 101)
        .is_err());
    for changed in [
        "request",
        "path",
        "method",
        "authority",
        "body",
        "expiry",
        "deployment",
    ] {
        let mut foreign = request.clone();
        match changed {
            "request" => foreign.request_id.push('x'),
            "path" => foreign.path_and_query.push('x'),
            "method" => foreign.method = "HEAD".into(),
            "authority" => foreign.authority = "other.example.com".into(),
            "body" => foreign.body_sha256 = body_sha256(b"foreign"),
            "expiry" => foreign.expires_at -= 1,
            _ => foreign.deployment_id.push('x'),
        }
        assert!(
            key.verify_live_delivery(&signed, &foreign, 101).is_err(),
            "{changed}"
        );
    }
    assert!(key.verify_live_delivery(&signed, &request, 99).is_err());
    assert!(key.verify_live_delivery(&signed, &request, 130).is_err());
    // Recording inspection omits current time and MAC authority explicitly.
    assert_eq!(
        decode_hybrid_live_delivery_observation(&signed, &request).unwrap(),
        target
    );
    let ingress = key.sign(&request).unwrap();
    assert_eq!(
        decode_hybrid_ingress_observation(&ingress).unwrap(),
        request
    );
    let mut foreign = request.clone();
    foreign.request_id.push('x');
    assert!(decode_hybrid_live_delivery_observation(&signed, &foreign).is_err());
    let (payload, _) = signed.split_once('.').unwrap();
    let forged = format!("{payload}.{}", URL_SAFE_NO_PAD.encode([0; 32]));
    assert!(decode_hybrid_live_delivery_observation(&forged, &request).is_ok());
    assert!(key.verify_live_delivery(&forged, &request, 101).is_err());
}

#[test]
fn source_containment_class_and_verified_import_boundaries_refuse_substitution() {
    let mut target = target();
    for path in [
        "../HEAD",
        "/HEAD",
        "%2e%2e/HEAD",
        "HEAD?credential=x",
        "nar/a.nar",
        "abc.narinfo",
        "objects/aa/bb",
    ] {
        target.path = path.into();
        assert!(target.validate().is_err(), "{path}");
    }
    target.path = "info/refs".into();
    assert_eq!(
        target.upstream_url().unwrap().as_str(),
        "https://upstream.example.com/root/info/refs"
    );
    target.maximum_bytes += 1;
    assert!(target.validate().is_err());
    target.maximum_bytes = 128 * 1024;
    target.path = "releases/1/2/3/objects/pack/pack-a.pack".into();
    assert!(target.validate().is_err());
    target.class = HybridLiveDeliveryClass::Pack;
    assert!(target.validate().is_ok());
    for upstream in [
        "http://upstream.example.com",
        "https://user:secret@upstream.example.com",
        "https://upstream.example.com/root?token=x",
        "https://127.0.0.1/root",
    ] {
        target.upstream_base = upstream.into();
        assert!(target.validate().is_err(), "{upstream}");
    }
}

#[test]
fn live_body_budget_checks_final_nonempty_eof_and_never_replays_after_end() {
    let mut budget = LiveBodyBudget::new(128 * 1024, Some(64 * 1024 + 17)).unwrap();
    budget.consume(64 * 1024, false).unwrap();
    budget.consume(17, true).unwrap();
    assert!(budget.ended());
    assert!(budget.consume(0, true).is_err());
    assert!(budget.consume(17, true).is_err());
}

#[test]
fn live_body_budget_refuses_oversize_view_cumulative_excess_and_truncation() {
    assert!(LiveBodyBudget::new(10, Some(11)).is_err());
    let mut budget = LiveBodyBudget::new(128 * 1024, None).unwrap();
    assert!(budget.consume(64 * 1024 + 1, false).is_err());
    assert!(budget.consume(0, false).is_err());
    budget.consume(64 * 1024, false).unwrap();
    budget.consume(64 * 1024, false).unwrap();
    assert!(budget.consume(1, true).is_err());
    let mut truncated = LiveBodyBudget::new(10, Some(10)).unwrap();
    assert!(truncated.consume(9, true).is_err());
    let mut excess = LiveBodyBudget::new(10, Some(9)).unwrap();
    assert!(excess.consume(10, true).is_err());
}
