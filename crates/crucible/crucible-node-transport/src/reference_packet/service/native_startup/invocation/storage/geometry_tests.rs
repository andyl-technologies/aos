//! Compares the real upper caller to the independent original arithmetic.

use super::*;
use crucible_node_format::canonical;
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn compare(
    purpose: &PacketNativeInvocationPurposeData,
    bank: &[u8],
    boot: usize,
    maximum: usize,
) -> TestResult {
    let actual = original_native_invocation_construction_storage_data(purpose, bank, boot, maximum);
    let original = super::original::original_native_invocation_construction_storage_data(
        purpose, bank, boot, maximum,
    );
    match (actual, original) {
        (Ok(actual), Ok(original)) => {
            assert_eq!(
                actual.native_retained_requested_bytes(),
                original.native_retained_requested_bytes()
            );
            assert_eq!(
                actual.native_transient_requested_bytes(),
                original.native_transient_requested_bytes()
            );
            assert_eq!(
                actual.private_retained_requested_bytes(),
                original.private_retained_requested_bytes()
            );
            assert_eq!(
                actual.private_transient_requested_bytes(),
                original.private_transient_requested_bytes()
            );
            assert_eq!(
                actual.source_finalization_requested_bytes(),
                original.source_finalization_requested_bytes()
            );
            assert_eq!(
                actual.wire_growth_requested_bytes(),
                original.wire_growth_requested_bytes()
            );
            assert_eq!(
                actual.maximum_private_boot_body_bytes(),
                original.maximum_private_boot_body_bytes()
            );
            assert_eq!(
                actual.launch_identity_data(),
                original.launch_identity_data()
            );
        }
        (Err(actual), Err(original)) => assert_eq!(actual.to_string(), original.to_string()),
        (actual, original) => panic!(
            "construction outcomes differ: actual={}, original={}",
            actual.is_ok(),
            original.is_ok()
        ),
    }
    Ok(())
}

#[test]
fn original_and_restoration_real_purposes_preserve_all_components_and_actual_hash() -> TestResult {
    let runtime = canonical::content_ref(b"runtime", "application/runtime;note=\\\"quoted\\\"")?;
    let native = canonical::content_ref(b"native", "application/native;note=\\\\path")?;
    let purposes = [
        super::super::tests::original()?,
        super::super::tests::restoration(&runtime, &native)?,
    ];
    for purpose in purposes {
        for value in [
            json!({"schema_version":5}),
            json!({"schema_version":5,"private":"secret-a","nested":[null,{},["\\n",1.0]]}),
        ] {
            let bank = canonical::canonical_json(&value)?;
            for maximum in [0, 1, 4096, usize::MAX] {
                compare(&purpose, &bank, 8192, maximum)?;
            }
        }
    }
    Ok(())
}

#[test]
fn changing_real_nested_bank_changes_identity_without_replacing_geometry_or_prefix() -> TestResult {
    let purpose = super::super::tests::original()?;
    let a = br#"{"private":"alpha","schema_version":5}"#;
    let b = br#"{"private":"omega","schema_version":5}"#;
    let a_row =
        original_native_invocation_construction_storage_data(&purpose, a, 8192, usize::MAX)?;
    let b_row =
        original_native_invocation_construction_storage_data(&purpose, b, 8192, usize::MAX)?;
    assert_eq!(
        a_row.native_retained_requested_bytes(),
        b_row.native_retained_requested_bytes()
    );
    assert_eq!(
        a_row.wire_growth_requested_bytes(),
        b_row.wire_growth_requested_bytes()
    );
    assert_ne!(
        a_row.launch_identity_data().raw_digest,
        b_row.launch_identity_data().raw_digest
    );
    for maximum in [0, 1, 4096, usize::MAX] {
        compare(&purpose, a, 512 * 1024, maximum)?;
    }
    Ok(())
}
