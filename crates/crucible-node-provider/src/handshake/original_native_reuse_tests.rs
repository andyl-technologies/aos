//! Compares original native claim reuse to the unchanged public decode path.

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn actual_normalized_original_hello_matches_legacy_authority_and_callback_guards() -> TestResult {
    let mut claimed = hello();
    claimed.extensions.insert(
        "numeric".into(),
        serde_json::json!([1.0, -0.0, "\u{1d11e}"]),
    );
    let generated = result();
    let (request, response) = envelopes(&claimed, &generated, "original-reuse/1");
    // Keep the actual first native normalization: a direct from_value shortcut
    // would not exercise these Number/escaped extension representations.
    let value = serde_json::to_value(&request)?;
    let normalized = crate::envelope::Envelope::decode(&canonical::canonical_json(&value)?, 65536)?;
    let crate::bodies::RequestBody::Hello(actual) =
        crate::bodies::decode_request(normalized.method, &normalized.body)?
    else {
        return Err("expected actual Hello".into());
    };
    let mut legacy = handshake();
    let mut selected = handshake();
    let mut before = Verifier::default();
    let mut after = Verifier::default();
    let original =
        legacy.admit_envelopes(&normalized, &response, id("original-reuse"), &mut before)?;
    let reused = selected.admit_original_envelopes(
        &normalized,
        &response,
        &actual,
        &generated,
        id("original-reuse"),
        &mut after,
    )?;

    assert_eq!(original.connection_id(), reused.connection_id());
    assert_eq!(original.session_id(), reused.session_id());
    assert_eq!(original.incarnation_id(), reused.incarnation_id());
    assert_eq!(original.limits(), reused.limits());
    assert_eq!(original.selected_features(), reused.selected_features());
    assert_eq!(
        (before.authenticated, before.contracts),
        (after.authenticated, after.contracts)
    );
    original.ensure_live()?;
    reused.ensure_live()?;
    assert!(
        selected
            .admit_original_envelopes(
                &normalized,
                &response,
                &actual,
                &generated,
                id("second"),
                &mut after
            )
            .is_err()
    );
    assert_eq!(after.authenticated, 1);
    Ok(())
}

#[test]
fn native_reuse_refuses_changed_original_claims_fields_tokens_and_verifier() -> TestResult {
    let claimed = hello();
    let generated = result();
    let (request, response) = envelopes(&claimed, &generated, "original-reuse/2");
    let mut changed = generated.clone();
    changed.provider_nonce = Bytes::new(vec![11; 32]);
    let mut verifier = Verifier::default();
    assert!(
        handshake()
            .admit_original_envelopes(
                &request,
                &response,
                &claimed,
                &changed,
                id("wrong-result"),
                &mut verifier
            )
            .is_err()
    );
    let mut foreign = request.clone();
    foreign
        .body
        .insert("unknown-original-field".into(), serde_json::Value::Null);
    assert!(
        handshake()
            .admit_original_envelopes(
                &foreign,
                &response,
                &claimed,
                &generated,
                id("wrong-body"),
                &mut verifier
            )
            .is_err()
    );
    assert_eq!(verifier.authenticated, 0);

    let mut wrong_token = claimed.clone();
    wrong_token.admission_token = Bytes::new(vec![12; 32]);
    let (wrong_request, wrong_response) = envelopes(&wrong_token, &generated, "original-reuse/3");
    assert!(
        handshake()
            .admit_original_envelopes(
                &wrong_request,
                &wrong_response,
                &wrong_token,
                &generated,
                id("wrong-token"),
                &mut verifier
            )
            .is_err()
    );
    assert_eq!(verifier.authenticated, 0);

    verifier.deny_contract = true;
    assert!(
        handshake()
            .admit_original_envelopes(
                &request,
                &response,
                &claimed,
                &generated,
                id("denied-contract"),
                &mut verifier
            )
            .is_err()
    );
    assert_eq!((verifier.authenticated, verifier.contracts), (1, 1));
    Ok(())
}
