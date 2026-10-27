//! Compares the actual borrowed identity writer with the defining DOM projection.
//!
//! Arbitrary bodies and native method names here are DATA, not admitted method
//! schemas, native evidence or Source allocation permission.

use super::super::identity as borrowed_identity;
use super::*;

fn compare(request: &Envelope) -> TestResult {
    let (_, bytes) = CompactJson::envelope_extents(request, BANK_BYTES, CONTENT_BYTES)?;
    for origin in [RequestOrigin::Controller, RequestOrigin::Provider] {
        assert_eq!(
            borrowed_identity::request_hash(request, origin, bytes)?,
            request.request_hash(origin)?
        );
    }
    Ok(())
}

#[test]
fn borrowed_projection_matches_all_fields_methods_and_utf16_order() -> TestResult {
    let (_lease, _session, _custody, _peer, mut request) = fixture(BANK_BYTES);
    let controls: String = (0u8..=127).map(char::from).collect();
    request.body = serde_json::from_value(json!({
        "\u{e000}": {"\u{10000}": [null, false, true, {}, [], controls]},
        "\u{10000}": {"\u{e000}": "雪\u{1f642}\u{2028}\u{2029}"},
        "$serde_json::private::RawValue": "ordinary DATA",
        "$serde_json::private::Number": {"nested": "1e+42"}
    }))?;
    request.extensions = serde_json::from_value(json!({
        "\u{e000}": [{"\u{10000}": "extension"}],
        "\u{10000}": {"\u{e000}": 1.0}
    }))?;
    let methods = [
        Method::Discover,
        Method::Realize,
        Method::Admit,
        Method::NativeImport18Bootstrap,
        Method::Activate,
        Method::Input,
        Method::Observe,
        Method::Begin,
        Method::Poll,
        Method::Cancel,
        Method::QuantumClose,
        Method::WorldActivate,
        Method::Abort,
        Method::Retire,
        Method::BlobBegin,
        Method::BlobChunk,
        Method::BlobFinish,
        Method::Release,
    ];
    for populated in [false, true] {
        let id = if populated {
            Some(Id::new("i".repeat(128))?)
        } else {
            None
        };
        request.node_id = Nullable(id.clone());
        request.execution_owner_id = Nullable(id.clone());
        request.capture_owner_id = Nullable(id.clone());
        request.operation_id = Nullable(id);
        for method in methods {
            request.method = method;
            for sequence in [1, 9, 10, 99, 100, u64::MAX] {
                request.sequence = U64::new(sequence);
                compare(&request)?;
            }
        }
    }
    Ok(())
}

#[test]
fn borrowed_projection_preserves_numeric_variants_and_deep_originals() -> TestResult {
    let (_lease, _session, _custody, _peer, mut request) = fixture(BANK_BYTES);
    let mut numbers = vec![
        json!(i64::MIN),
        json!(i64::MAX),
        json!(u64::MAX),
        json!(-0.0),
        json!(f64::from_bits(1)),
        json!(f64::MIN),
        json!(f64::MAX),
        json!(1e20),
    ];
    let mut bits = 0x6a09_e667_f3bc_c909u64;
    for _ in 0..1024 {
        bits ^= bits << 13;
        bits ^= bits >> 7;
        bits ^= bits << 17;
        if let Some(number) = serde_json::Number::from_f64(f64::from_bits(bits)) {
            numbers.push(Value::Number(number));
        }
    }
    request.body.insert("numbers".into(), Value::Array(numbers));
    request.protocol.reserve(1_048_576);
    let spare_capacity = request.protocol.capacity();
    let before = CompactJson::from_envelope(&request, BANK_BYTES)?;

    compare(&request)?;

    let after = CompactJson::from_envelope(&request, BANK_BYTES)?;
    assert_eq!(request.protocol.capacity(), spare_capacity);
    // The lossless bank comparison includes exact floating-point bits and tags.
    assert_eq!(
        serde_json::to_vec(&before.as_serializable())?,
        serde_json::to_vec(&after.as_serializable())?
    );
    let mut deepest = Value::Null;
    for _ in 0..62 {
        deepest = Value::Array(vec![deepest]);
    }
    request.body.clear();
    request.body.insert("deep".into(), deepest);
    compare(&request)?;
    Ok(())
}

#[test]
fn borrowed_projection_has_exact_output_bounds_and_defining_validation() -> TestResult {
    let (_lease, _session, _custody, _peer, request) = fixture(BANK_BYTES);
    let (_, bytes) = CompactJson::envelope_extents(&request, BANK_BYTES, CONTENT_BYTES)?;
    let origin = RequestOrigin::Controller;
    assert!(matches!(
        borrowed_identity::request_hash(&request, origin, bytes - 1),
        Err(ProviderError::ResourceExhausted(_))
    ));
    assert!(matches!(
        borrowed_identity::request_hash(&request, origin, bytes + 1),
        Err(ProviderError::Frame("compact request projection extent"))
    ));
    compare(&request)?;

    let mut invalid = vec![request.clone(); 8];
    invalid[0].protocol = "invalid".into();
    invalid[1].sequence = U64::new(0);
    invalid[2].request_id = Nullable(None);
    invalid[3].message = MessageKind::Response;
    invalid[4].method = Method::Hello;
    invalid[5].method = Method::OperationUpdate;
    invalid[6].method = Method::ObservationReady;
    invalid[7].method = Method::ProviderFault;
    for envelope in invalid {
        let expected = envelope.request_hash(origin).unwrap_err();
        let actual = borrowed_identity::request_hash(&envelope, origin, bytes).unwrap_err();
        assert_eq!(actual.to_string(), expected.to_string());
    }
    Ok(())
}

#[test]
fn borrowed_projection_keeps_origin_and_every_immutable_scope_field() -> TestResult {
    let (_lease, _session, _custody, _peer, request) = fixture(BANK_BYTES);
    let id = || Nullable(Some(Id::new("different-scope").unwrap()));
    let mut changed = vec![request.clone(); 10];
    changed[0].session_id = id();
    changed[1].incarnation_id = id();
    changed[2].node_id = id();
    changed[3].execution_owner_id = id();
    changed[4].capture_owner_id = id();
    changed[5].request_id = id();
    changed[6].operation_id = id();
    changed[7].method = Method::Observe;
    changed[8].body.insert("changed".into(), json!(false));
    changed[9].extensions.insert("changed".into(), json!(false));
    let original = request.request_hash(RequestOrigin::Controller)?;
    for envelope in changed {
        compare(&envelope)?;
        assert_ne!(envelope.request_hash(RequestOrigin::Controller)?, original);
    }
    let mut retry = request.clone();
    retry.sequence = U64::new(u64::MAX);
    compare(&retry)?;
    assert_eq!(retry.request_hash(RequestOrigin::Controller)?, original);
    assert_ne!(retry.request_hash(RequestOrigin::Provider)?, original);
    Ok(())
}
