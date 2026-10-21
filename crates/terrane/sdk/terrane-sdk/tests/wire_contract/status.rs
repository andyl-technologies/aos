//! Checks normative protocol statuses independently of backend error strings.

use std::time::Duration;
use terrane_sdk::wire::status::{Outcome, ProtocolError, RetryDelay, StatusDetail};

#[cfg(feature = "tokio")]
use terrane_sdk::wire::v1;

fn fixture<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> T {
    serde_json::from_value(value).unwrap()
}

fn outcomes() -> Vec<(Outcome, u32, Option<&'static str>, bool)> {
    vec![
        (
            Outcome::Malformed(fixture(
                serde_json::json!({"name":"hashes", "limit":"4096", "requested":"4097"}),
            )),
            3,
            Some("Limit"),
            false,
        ),
        (Outcome::UnknownEnum, 3, None, false),
        (Outcome::Unauthenticated, 16, None, false),
        (Outcome::GrantDenied, 7, None, false),
        (Outcome::NotFound, 5, None, false),
        (
            Outcome::PackAlreadyHeld(fixture(
                serde_json::json!({"pack":{"value":"AAECAwQFBgcICQoLDA0ODw=="}, "durability":"local", "alreadyPresent":true}),
            )),
            6,
            Some("PackAck"),
            false,
        ),
        (
            Outcome::CasMismatch(fixture(
                serde_json::json!({"name":"refs/heads/main", "stalenessMs":9}),
            )),
            9,
            Some("RefState"),
            false,
        ),
        (
            Outcome::MissingPacks(fixture(
                serde_json::json!({"packs":[{"value":"AAECAwQFBgcICQoLDA0ODw=="}]}),
            )),
            9,
            Some("MissingPacks"),
            false,
        ),
        (
            Outcome::HopLimit(fixture(serde_json::json!({"maxHops":8,"path":["r/z/h"]}))),
            9,
            Some("HopLimit"),
            false,
        ),
        (
            Outcome::WriterFenced(fixture(
                serde_json::json!({"name":"refs/heads/main", "stalenessMs":9}),
            )),
            9,
            Some("RefState"),
            false,
        ),
        (
            Outcome::LeaseExpired(fixture(
                serde_json::json!({"name":"refs/heads/main", "stalenessMs":9}),
            )),
            9,
            Some("RefState"),
            false,
        ),
        (
            Outcome::MergeConflict(fixture(
                serde_json::json!({"paths":["/file"], "attempts":3}),
            )),
            10,
            Some("Conflict"),
            false,
        ),
        (
            Outcome::RebaseExhausted(fixture(
                serde_json::json!({"paths":["/file"], "attempts":3}),
            )),
            10,
            Some("Conflict"),
            false,
        ),
        (Outcome::ReflogTruncated, 11, None, false),
        (Outcome::RangeBeyondEnd, 11, None, false),
        (
            Outcome::RootQuota(fixture(
                serde_json::json!({"root":"root", "limit":"100", "used":"101"}),
            )),
            8,
            Some("Quota"),
            false,
        ),
        (
            Outcome::AdmissionBudget(
                fixture(serde_json::json!({"budget":"admission"})),
                RetryDelay::new(Duration::from_secs(1)).unwrap(),
            ),
            8,
            Some("Budget"),
            false,
        ),
        (
            Outcome::PackTooLarge(fixture(
                serde_json::json!({"name":"hashes", "limit":"4096", "requested":"4097"}),
            )),
            8,
            Some("Limit"),
            false,
        ),
        (
            Outcome::HomeUnavailable(
                fixture(serde_json::json!({"home":{"region":"r", "zone":"z", "host":"h"}})),
                None,
            ),
            14,
            Some("Home"),
            true,
        ),
        (
            Outcome::FreshnessUnavailable(
                fixture(serde_json::json!({"observedMs":5,"boundMs":2})),
                None,
            ),
            14,
            Some("Staleness"),
            true,
        ),
        (
            Outcome::ConditionalWritesUnavailable(fixture(
                serde_json::json!({"backendKind":"bucket", "conditionalPut":true}),
            )),
            9,
            Some("BackendProbe"),
            false,
        ),
        (Outcome::Transient(None), 14, None, true),
        (Outcome::DeadlineExceeded, 4, None, true),
        (Outcome::Cancelled, 1, None, false),
        (
            Outcome::UnsupportedVersion(fixture(
                serde_json::json!({"packFormats":[1],"treeEncodings":["terrane-v1"]}),
            )),
            12,
            Some("Versions"),
            false,
        ),
        (Outcome::MethodUnavailable, 12, None, false),
        (Outcome::Internal, 13, None, false),
    ]
}

fn detail_name(detail: &StatusDetail) -> &'static str {
    match detail {
        StatusDetail::Limit(_) => "Limit",
        StatusDetail::PackAck(_) => "PackAck",
        StatusDetail::RefState(_) => "RefState",
        StatusDetail::MissingPacks(_) => "MissingPacks",
        StatusDetail::HopLimit(_) => "HopLimit",
        StatusDetail::Conflict(_) => "Conflict",
        StatusDetail::Quota(_) => "Quota",
        StatusDetail::Budget(_) => "Budget",
        StatusDetail::Home(_) => "Home",
        StatusDetail::Staleness(_) => "Staleness",
        StatusDetail::BackendProbe(_) => "BackendProbe",
        StatusDetail::Versions(_) => "Versions",
    }
}

#[test]
fn outcome_table_has_exact_status_required_detail_and_retry_policy() {
    let table = outcomes();
    assert_eq!(table.len(), 27);
    for (outcome, code, detail, retryable) in table {
        let error = ProtocolError::from_outcome(outcome, "trace");
        assert_eq!(error.code().grpc_code(), code);
        assert_eq!(error.detail().map(detail_name), detail);
        assert_eq!(error.error_info().retryable, retryable);
        assert_eq!(error.error_info().trace_id, "trace");
        assert!(!error.message().is_empty());
    }
}

#[test]
fn retry_minimum_preserves_subseconds_and_refuses_overflow() {
    for duration in [
        Duration::ZERO,
        Duration::new(12, 345),
        Duration::new(315_576_000_000, 999_999_999),
    ] {
        let delay = RetryDelay::new(duration).unwrap();
        assert_eq!(delay.duration(), duration);
        for outcome in [
            Outcome::Transient(Some(delay)),
            Outcome::HomeUnavailable(
                fixture(serde_json::json!({"home":{"region":"r", "zone":"z", "host":"h"}})),
                Some(delay),
            ),
            Outcome::FreshnessUnavailable(
                fixture(serde_json::json!({"observedMs":5,"boundMs":2})),
                Some(delay),
            ),
        ] {
            let error = ProtocolError::from_outcome(outcome, "");
            assert!(error.error_info().retryable);
            let wire = error.error_info().retry_after.as_option().unwrap();
            assert_eq!(wire.seconds as u64, duration.as_secs());
            assert_eq!(wire.nanos as u32, duration.subsec_nanos());
        }
    }
    assert!(RetryDelay::new(Duration::from_secs(315_576_000_001)).is_err());
    assert!(RetryDelay::new(Duration::MAX).is_err());
    let absent = ProtocolError::from_outcome(Outcome::Transient(None), "");
    assert!(absent.error_info().retry_after.as_option().is_none());
}

#[test]
fn fenced_outcomes_always_retain_fenced_state_and_never_enable_retry() {
    for outcome in [
        Outcome::WriterFenced(fixture(
            serde_json::json!({"name":"refs/heads/main", "stalenessMs":9}),
        )),
        Outcome::LeaseExpired(fixture(
            serde_json::json!({"name":"refs/heads/main", "stalenessMs":9}),
        )),
    ] {
        let error = ProtocolError::from_outcome(outcome, "");
        let Some(StatusDetail::RefState(state)) = error.detail() else {
            panic!("missing fenced RefState")
        };
        assert!(state.fenced);
        assert!(!error.error_info().retryable);
    }
}

#[test]
fn not_found_status_has_only_the_public_error_info_detail() {
    use buffa::Message;
    let error = ProtocolError::from_outcome(Outcome::NotFound, "same-trace");
    assert_eq!(error.code().grpc_code(), 5);
    assert_eq!(error.message(), "not found");
    assert!(error.detail().is_none());
    assert!(!error.error_info().retryable);
    assert_eq!(error.error_info().encode_to_vec(), b"\x1a\x0asame-trace");
    #[cfg(feature = "tokio")]
    {
        let native: connectrpc::ConnectError = error.into();
        assert_eq!(
            serde_json::to_value(native).unwrap(),
            serde_json::json!({
                "code": "not_found", "message": "not found",
                "details": [{"type": "terrane.v1.ErrorInfo", "value": "GgpzYW1lLXRyYWNl"}]
            })
        );
    }
}

#[test]
fn native_conversion_retains_error_info_and_every_required_protobuf_detail() {
    // The portable profile exercises the same table; the native owning check
    // additionally serializes every actual Connect error and decodes its details.
    for (outcome, code, detail, _) in outcomes() {
        let status = ProtocolError::from_outcome(outcome, "retained-trace");
        assert_eq!(status.code().grpc_code(), code);
        assert_eq!(status.detail().map(detail_name), detail);
        #[cfg(feature = "tokio")]
        {
            use buffa::Message;
            let info = status.error_info().clone();
            let expected_detail = status.detail().map(detail_bytes);
            let error: connectrpc::ConnectError = status.into();
            assert_eq!(error.code.grpc_code(), code);
            assert!(std::error::Error::source(&error).is_none());
            assert_eq!(error.details.len(), 1 + usize::from(detail.is_some()));
            assert_eq!(error.details[0].type_url, "terrane.v1.ErrorInfo");
            let bytes = decode_detail(error.details[0].value.as_ref().unwrap());
            assert_eq!(v1::ErrorInfo::decode_from_slice(&bytes).unwrap(), info);
            if let Some(name) = detail {
                assert_eq!(error.details[1].type_url, format!("terrane.v1.{name}"));
                let value = error.details[1].value.as_deref().unwrap();
                assert!(!value.contains('='));
                assert_eq!(decode_detail(value), expected_detail.unwrap());
            }
            let json = serde_json::to_value(error).unwrap();
            assert_eq!(json["details"][0]["type"], "terrane.v1.ErrorInfo");
        }
    }
}

#[cfg(feature = "tokio")]
fn decode_detail(value: &str) -> Vec<u8> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bits = 0_u32;
    let mut length = 0;
    let mut bytes = Vec::new();
    for byte in value.bytes() {
        let value = alphabet
            .iter()
            .position(|candidate| *candidate == byte)
            .unwrap() as u32;
        bits = (bits << 6) | value;
        length += 6;
        if length >= 8 {
            length -= 8;
            bytes.push((bits >> length) as u8);
            bits &= (1 << length) - 1;
        }
    }
    assert_eq!(bits, 0);
    bytes
}

#[cfg(feature = "tokio")]
fn detail_bytes(detail: &StatusDetail) -> Vec<u8> {
    use buffa::Message;
    match detail {
        StatusDetail::Limit(value) => value.encode_to_vec(),
        StatusDetail::PackAck(value) => value.encode_to_vec(),
        StatusDetail::RefState(value) => value.encode_to_vec(),
        StatusDetail::MissingPacks(value) => value.encode_to_vec(),
        StatusDetail::HopLimit(value) => value.encode_to_vec(),
        StatusDetail::Conflict(value) => value.encode_to_vec(),
        StatusDetail::Quota(value) => value.encode_to_vec(),
        StatusDetail::Budget(value) => value.encode_to_vec(),
        StatusDetail::Home(value) => value.encode_to_vec(),
        StatusDetail::Staleness(value) => value.encode_to_vec(),
        StatusDetail::BackendProbe(value) => value.encode_to_vec(),
        StatusDetail::Versions(value) => value.encode_to_vec(),
    }
}
