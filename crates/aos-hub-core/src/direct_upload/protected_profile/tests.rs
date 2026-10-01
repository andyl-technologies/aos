//! Closed runtime references, original full pins and mandatory wrapper tests.

use super::*;
use crate::direct_upload::capabilities_wire::tests::{
    profile as external_profile, runtime_reference,
};

fn managed() -> DirectProtectedProfile {
    let mut profile = DirectManagedR2Profile {
        deployment_id: "deployment".into(),
        account_id: "account".into(),
        bucket_name: "qualified-bucket".into(),
        bucket_namespace: "permanent-bucket".into(),
        credential_id: "protected-credential".into(),
        credential_generation: WireInteger::new(1),
        secret_version_ref: "protected://fixture/credential/v1".into(),
        credential_fingerprint: "00".repeat(32),
        checksum_algorithm: DirectChecksumAlgorithm::Md5,
        clock_qualification: "11".repeat(32),
        clock_uncertainty_seconds: WireInteger::new(2),
    };
    // Static fixture material is computed, never advertised as runtime qualification.
    profile.credential_fingerprint = profile
        .fingerprint_with_credentials("fixture-access", "fixture-secret")
        .unwrap();
    DirectProtectedProfile::Managed {
        profile,
        private_stage_policy: DirectPrivateStagePolicyRef {
            policy_id: "fixture-private-policy".into(),
            policy_digest: "22".repeat(32),
            namespace: "permanent-bucket".into(),
        },
        runtime_qualification: runtime_reference(),
    }
}

#[test]
fn runtime_reference_rejects_unknown_versions_and_invalid_configured_bounds() {
    let original = runtime_reference();
    original.validate().unwrap();
    for index in 0..9 {
        let mut changed = original.clone();
        match index {
            0 => changed.version = 2,
            1 => changed.qualification_digest = "malformed".into(),
            2 => changed.maximum_object_bytes = WireInteger::new(0),
            3 => changed.maximum_object_bytes = WireInteger::new(MAX_DIRECT_OBJECT_BYTES + 1),
            4 => changed.maximum_verification_seconds = WireInteger::new(0),
            5 => changed.maximum_parallel_objects = WireInteger::new(0),
            6 => changed.maximum_parallel_objects = WireInteger::new(33),
            7 => changed.maximum_parallel_provider_requests = WireInteger::new(33),
            _ => changed.settlement_reserve_seconds = WireInteger::new(0),
        }
        assert!(changed.validate().is_err());
    }
}

#[test]
fn foreground_verification_uses_actual_remainder_uncertainty_and_explicit_reserve() {
    let mut reference = runtime_reference();
    reference.maximum_verification_seconds = WireInteger::new(20);
    reference.validate_foreground_window(30, 2).unwrap();
    assert!(reference.validate_foreground_window(29, 2).is_err());
    assert!(reference.validate_foreground_window(30, 3).is_err());
    reference.settlement_reserve_seconds = WireInteger::new(9);
    assert!(reference.validate_foreground_window(30, 2).is_err());
    reference.settlement_reserve_seconds = WireInteger::new(8);
    for (remaining, uncertainty) in [(0, 2), (31, 2), (30, 0), (30, 30), (1, 2)] {
        assert!(reference
            .validate_foreground_window(remaining, uncertainty)
            .is_err());
    }
    for reserve in [0, u64::MAX] {
        reference.settlement_reserve_seconds = WireInteger::new(reserve);
        assert!(reference.validate_foreground_window(30, 2).is_err());
    }
}

#[test]
fn managed_full_pin_commits_runtime_policy_clock_and_material_without_redefining_material_fp() {
    let original = managed();
    let pin = original.digest().unwrap();
    for index in 0..9 {
        let mut changed = original.clone();
        if let DirectProtectedProfile::Managed {
            profile,
            private_stage_policy,
            runtime_qualification,
        } = &mut changed
        {
            match index {
                0 => runtime_qualification.qualification_digest = "aa".repeat(32),
                1 => runtime_qualification.maximum_object_bytes = WireInteger::new(2_000_000),
                2 => runtime_qualification.maximum_verification_seconds = WireInteger::new(11),
                3 => runtime_qualification.maximum_parallel_objects = WireInteger::new(5),
                4 => runtime_qualification.maximum_parallel_provider_requests = WireInteger::new(9),
                5 => private_stage_policy.policy_digest = "bb".repeat(32),
                6 => profile.clock_qualification = "cc".repeat(32),
                7 => profile.credential_fingerprint = "dd".repeat(32),
                _ => runtime_qualification.settlement_reserve_seconds = WireInteger::new(9),
            }
        }
        assert_ne!(changed.digest().unwrap(), pin);
    }
    if let DirectProtectedProfile::Managed { profile, .. } = original {
        assert_eq!(
            profile.credential_fingerprint,
            profile
                .fingerprint_with_credentials("fixture-access", "fixture-secret")
                .unwrap()
        );
    }
}

#[test]
fn external_full_pin_adds_runtime_without_redefining_legacy_semantic_fingerprint() {
    let raw = external_profile();
    let legacy = raw.fingerprint().unwrap();
    let original = DirectProtectedExternalProfile::new(raw, runtime_reference()).unwrap();
    let full = original.digest().unwrap();
    let mut changed = original.clone();
    changed.runtime_qualification.maximum_object_bytes = WireInteger::new(2_000_000);
    assert_ne!(changed.digest().unwrap(), full);
    assert_eq!(changed.profile.fingerprint().unwrap(), legacy);
    changed = original;
    changed.profile.provider_contract_evidence_digest = "ee".repeat(32);
    assert_ne!(changed.digest().unwrap(), full);
}

#[test]
fn protected_external_baseline_requires_head_without_changing_raw_profile_contract() {
    let mut raw = external_profile();
    raw.read_cohort
        .allowed_effects
        .retain(|effect| *effect != LeaseEffect::Head);
    raw.validate().unwrap();
    raw.fingerprint().unwrap();
    assert!(DirectProtectedExternalProfile::new(raw.clone(), runtime_reference()).is_err());
    assert!(DirectProtectedProfile::external(raw, runtime_reference()).is_err());
}

#[test]
fn managed_capabilities_require_all_three_fields_and_explicit_version_two() {
    let DirectProtectedProfile::Managed {
        profile,
        private_stage_policy,
        runtime_qualification,
    } = managed()
    else {
        panic!("managed fixture required")
    };
    let original = DirectStorageCapabilities {
        version: 2,
        capability: DIRECT_UPLOAD_CAPABILITY.into(),
        profile: Some(profile),
        private_stage_policy: Some(private_stage_policy),
        runtime_qualification: Some(runtime_qualification),
        external_profiles: vec![],
    };
    original.validate("deployment").unwrap();
    for index in 0..4 {
        let mut changed = original.clone();
        match index {
            0 => changed.version = 1,
            1 => changed.profile = None,
            2 => changed.private_stage_policy = None,
            _ => changed.runtime_qualification = None,
        }
        assert!(changed.validate("deployment").is_err());
    }
}

#[test]
fn closed_profile_and_runtime_wire_reject_missing_unknown_duplicate_or_bypass_fields() {
    let original = managed();
    let value = serde_json::to_value(&original).unwrap();
    for field in [
        "version",
        "qualificationDigest",
        "maximumObjectBytes",
        "maximumVerificationSeconds",
        "settlementReserveSeconds",
        "maximumParallelObjects",
        "maximumParallelProviderRequests",
        "cacheDestinationPolicy",
    ] {
        let mut changed = value.clone();
        changed["runtimeQualification"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(serde_json::from_value::<DirectProtectedProfile>(changed).is_err());
    }
    let mut changed = value.clone();
    changed["runtimeQualification"]["cacheDestinationPolicy"] = serde_json::json!("bypass");
    assert!(serde_json::from_value::<DirectProtectedProfile>(changed).is_err());
    changed = value.clone();
    changed["runtimeQualification"]["unknown"] = serde_json::json!(true);
    assert!(serde_json::from_value::<DirectProtectedProfile>(changed).is_err());
    changed = value;
    changed
        .as_object_mut()
        .unwrap()
        .remove("runtimeQualification");
    assert!(serde_json::from_value::<DirectProtectedProfile>(changed).is_err());
    let text = serde_json::to_string(&runtime_reference())
        .unwrap()
        .replacen("{", "{\"version\":1,", 1);
    assert!(serde_json::from_str::<DirectRuntimeQualification>(&text).is_err());
    let raw = serde_json::to_value(external_profile()).unwrap();
    assert!(serde_json::from_value::<DirectProtectedExternalProfile>(raw).is_err());
}
