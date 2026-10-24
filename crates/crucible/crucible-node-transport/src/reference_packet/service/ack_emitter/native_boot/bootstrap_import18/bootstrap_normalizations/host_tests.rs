//! Checks completed hashes against the actual Host plan and original live SDK.
//!
//! Every fixture uses a separate inherited process/socket flight. Admissions
//! remain models; successful comparisons issue no Source or connection grant.

use super::*;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crate::reference_packet::service::complete_restore::import18::hello::native_import18_hello_declaration_data;
use serde_json::json;
use std::cell::Cell;

pub(in super::super::super) fn prepare_boot(
    case: &str,
    launch: &PacketNative5SourceLaunch,
    boot: &mut Value,
) {
    let declaration = native_import18_hello_declaration_data(launch).unwrap();
    let mut features: Vec<_> = declaration
        .features_data()
        .iter()
        .flatten()
        .copied()
        .collect();
    let mut keys: Vec<_> = declaration
        .keys_data()
        .iter()
        .flatten()
        .map(|(key, _)| *key)
        .collect();
    features.sort_unstable();
    keys.sort_unstable();
    let [binding] = launch.selection.realization.bindings.as_slice() else {
        panic!("one actual binding is required");
    };
    let mut planned = json!({
        "schema": "source-owned.packet-canonical-ack-registration/5",
        "role": "controller",
        "connection_id": "original-planned-controller",
        "session_id": binding.authority.session_id,
        "incarnation_id": binding.authority.incarnation_id,
        "limits": launch.limits,
        "features": features,
        "extensions": [],
        "envelope_extensions": keys,
    });
    match case
        .strip_prefix("initial_policy_kernel_normalizations_host_")
        .unwrap()
    {
        "bad_schema" => planned["schema"] = json!("other-registration"),
        "bad_role" => planned["role"] = json!("native"),
        "bad_connection" => planned["connection_id"] = json!(""),
        "bad_session" => planned["session_id"] = json!("another-session"),
        "bad_incarnation" => planned["incarnation_id"] = json!("another-incarnation"),
        "bad_limits" => planned["limits"]["requests"] = json!("01"),
        "bad_features" => planned["features"][0] = json!("unknown-feature"),
        "bad_extensions" => planned["extensions"] = json!([{}]),
        "bad_keys" => planned["envelope_extensions"][0] = json!("unknown-key"),
        "extra_field" => planned["unknown"] = json!(null),
        "missing_field" => {
            planned.as_object_mut().unwrap().remove("role");
        }
        _ => {}
    }
    boot["expected_host_registration"] = planned;
}

pub(in super::super::super) fn assert_child(
    case: &str,
    original: &mut OriginalImport18RawBootstrap,
) {
    let suffix = case
        .strip_prefix("initial_policy_kernel_normalizations_host_")
        .unwrap();
    let retained = original.retained_requested_bytes().unwrap();
    let raw = original.bodies.each_ref().map(Vec::as_ptr);
    let launch = Rc::as_ptr(original.parsed.shared_launch_data().unwrap());
    let attempt = if suffix == "incomplete" {
        Attempt::empty_data()
    } else {
        super::tests::complete_for_host(original)
    };
    let hashes = attempt.digests;
    let attempt_retained = attempt.retained_requested_bytes_data(original).unwrap();
    let cut = original.cut;
    if suffix == "changed_cut" {
        original.cut = OperationalDeadline::after(Duration::from_secs(3)).unwrap();
    }
    if suffix == "contained" {
        original.hello_registrar.contain_admission_data().unwrap();
    }
    let boot: Value = serde_json::from_slice(&original.bodies[2]).unwrap();
    let expected_host =
        *blake3::hash(&canonical::canonical_json(&boot["expected_host_registration"]).unwrap())
            .as_bytes();
    let entered = Cell::new(false);
    let outcome = attempt.with_host_bound_digests_data(original, |digests| {
        assert!(!entered.replace(true));
        assert_eq!(digests.host_registration, expected_host);
        assert_eq!(
            [
                digests.birth,
                digests.kernel,
                digests.policy,
                digests.native_registration,
                digests.host_registration,
            ]
            .map(Some),
            hashes
        );
        if matches!(suffix, "loan_expired" | "error_expired") {
            std::thread::sleep(Duration::from_secs(5));
        }
        if suffix == "revoked" {
            original
                .hello_registrar
                .retained_authority_fixture_data()
                .unwrap()
                .revoke_epoch_fixture_data();
        }
        if matches!(suffix, "callback_refused" | "error_expired") {
            return Err(ProviderError::Conflict("Host plan callback model"));
        }
        Ok(digests)
    });
    let should_enter = matches!(
        suffix,
        "complete" | "reactive" | "callback_refused" | "loan_expired" | "error_expired" | "revoked"
    );
    assert_eq!(entered.get(), should_enter, "{case}: {outcome:?}");
    assert_eq!(
        outcome.is_ok(),
        matches!(suffix, "complete" | "reactive"),
        "{case}: {outcome:?}; expired={}",
        original.cut.is_expired()
    );
    assert_eq!(attempt.digests, hashes);
    assert_eq!(
        attempt.retained_requested_bytes_data(original).unwrap(),
        attempt_retained
    );
    assert_eq!(original.retained_requested_bytes().unwrap(), retained);
    assert_eq!(original.bodies.each_ref().map(Vec::as_ptr), raw);
    assert_eq!(
        Rc::as_ptr(original.parsed.shared_launch_data().unwrap()),
        launch
    );
    if suffix == "callback_refused" {
        // An inspection error does not fabricate revocation or a spent new grant.
        attempt
            .with_host_bound_digests_data(original, |_| Ok(()))
            .unwrap();
    }
    original.cut = cut;
    assert!(
        Attempt::host_loan_counter_scratch_data::<[u8; 4096]>().unwrap()
            >= Attempt::host_loan_counter_scratch_data::<()>().unwrap() + 4096
    );
    if matches!(suffix, "complete" | "reactive") {
        original.hello_registrar.contain_admission_data().unwrap();
        let entered = Cell::new(false);
        assert!(
            attempt
                .with_host_bound_digests_data(original, |_| {
                    entered.set(true);
                    Ok(())
                })
                .is_err()
        );
        assert!(!entered.get());
    }
}
