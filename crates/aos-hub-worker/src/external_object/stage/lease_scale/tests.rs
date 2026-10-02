//! Closed original, cutoff and purpose tests of the read-only probe codec.
//!
//! These tests grant no installation or publication readiness and perform no
//! issuer RPC. Configured cohort validation remains the production consumer's.

use super::*;

fn request() -> ProbeRequest {
    ProbeRequest {
        version: 1,
        run_id: "1".repeat(32),
        nonce: "2".repeat(64),
        source_digest: "3".repeat(64),
        configuration_digest: "4".repeat(64),
        cohort_digest: "5".repeat(64),
        issued_at: 100,
        expires_at: 130,
    }
}

fn check(value: &ProbeRequest, at: i64, uncertainty: i64) -> Result<()> {
    value.check(
        &"3".repeat(64),
        &"4".repeat(64),
        &"1".repeat(32),
        LeaseClock {
            observed_at: at,
            uncertainty,
        },
    )
}

#[test]
fn conservative_original_window_is_exclusive_and_never_renewed() {
    let value = request();

    assert!(check(&value, 100, 2).is_ok());
    assert!(check(&value, 127, 2).is_ok());
    assert!(check(&value, 128, 2).is_err());
    assert!(check(&value, 99, 2).is_err());
    assert!(check(&value, 100, -1).is_err());
    assert!(check(&value, i64::MAX, 2).is_err());

    let mut longer = request();
    longer.expires_at = 131;
    assert!(check(&longer, 100, 2).is_err());
}

#[test]
fn source_configuration_and_run_substitutions_refuse() {
    for field in ["source_digest", "configuration_digest", "run_id"] {
        let mut value = request();
        match field {
            "source_digest" => value.source_digest = "6".repeat(64),
            "configuration_digest" => value.configuration_digest = "6".repeat(64),
            "run_id" => value.run_id = "6".repeat(32),
            _ => unreachable!(),
        }

        assert!(check(&value, 100, 2).is_err());
    }
}

#[test]
fn protected_mac_binds_exact_original_and_separates_request_reply_purposes() {
    let key = StorageWorkKey::new("private-fixture-control-key".repeat(2)).unwrap();
    let body = serde_json::to_vec(&request()).unwrap();
    let signature = key
        .sign_body(&domain_body(REQUEST_DOMAIN, &body).unwrap())
        .unwrap();

    assert!(key
        .verify_body(&signature, &domain_body(REQUEST_DOMAIN, &body).unwrap())
        .is_ok());
    assert!(key
        .verify_body(&signature, &domain_body(REPLY_DOMAIN, &body).unwrap())
        .is_err());
    assert!(key.verify_body(&signature, &body).is_err());

    let mut other = request();
    other.cohort_digest = "6".repeat(64);
    assert!(key
        .verify_body(
            &signature,
            &domain_body(REQUEST_DOMAIN, &serde_json::to_vec(&other).unwrap()).unwrap()
        )
        .is_err());
}

#[test]
fn closed_bounded_request_refuses_unknown_fields_and_malformed_nonce() {
    let mut value = request();
    value.nonce = "Z".repeat(64);
    assert!(check(&value, 100, 2).is_err());

    let mut body = serde_json::to_value(request()).unwrap();
    body["admitted_prefix"] = serde_json::json!("caller-selected");
    assert!(serde_json::from_value::<ProbeRequest>(body).is_err());
    assert!(domain_body(REQUEST_DOMAIN, &vec![0; BODY_LIMIT + 1]).is_err());
}

fn configuration(lifetime: i64) -> (FixtureConfiguration, super::super::super::config::Config) {
    let mut object = super::super::tests::config();
    let templates = object.cohorts.clone();
    object.cohorts = (0..32)
        .map(|index| {
            let mut cohort = templates[index % 2].clone();
            cohort.admitted_prefix = format!("{}/scale-{index}", cohort.admitted_prefix);
            cohort
        })
        .collect();
    object.timing_profile.maximum_lifetime =
        aos_hub_core::storage_authority::lease::LeaseInteger::new(lifetime).unwrap();
    object.timing_profile.maximum_clock_uncertainty =
        aos_hub_core::storage_authority::lease::LeaseInteger::new(4).unwrap();
    let installation = IssuerInstallation {
        format_version: 1,
        authority: object.publications[0].authority.clone(),
        issuer_resource_id: "fixture-resource".into(),
        runtime_identity: "fixture-runtime".into(),
        executor_identity: object.executor_identity.clone(),
    };
    (
        FixtureConfiguration {
            version: 1,
            run_id: "1".repeat(32),
            isolate_label: "2".repeat(32),
            installations: vec![installation],
        },
        object,
    )
}

#[test]
fn exactly_32_projected_cohorts_select_only_existing_pins_at_both_declared_lifetimes() {
    for lifetime in [8, 120] {
        let (fixture, object) = configuration(lifetime);

        fixture.validate(&object).unwrap();
        let cohort_digest = digest(&object.cohorts[31]).unwrap();
        assert_eq!(object.cohort(&cohort_digest).unwrap(), &object.cohorts[31]);
        assert!(object.cohort(&"f".repeat(64)).is_err());
        assert!(serde_json::to_vec(&object).unwrap().len() <= 128 * 1024);
    }
}

#[test]
fn incomplete_repeated_or_foreign_configurations_refuse() {
    let (fixture, mut object) = configuration(8);
    object.cohorts.pop();
    assert!(fixture.validate(&object).is_err());

    let (mut fixture, object) = configuration(8);
    fixture.installations.push(fixture.installations[0].clone());
    assert!(fixture.validate(&object).is_err());

    let (mut fixture, object) = configuration(8);
    fixture.installations[0].authority.guard_namespace_id = "foreign-namespace".into();
    assert!(fixture.validate(&object).is_err());

    let (fixture, object) = configuration(30);
    assert!(fixture.validate(&object).is_err());

    let (fixture, mut object) = configuration(120);
    object.clock_uncertainty = 3;
    assert!(fixture.validate(&object).is_err());
}
