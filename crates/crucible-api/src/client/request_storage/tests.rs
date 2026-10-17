//! Exact request bytes, physical last-clone custody, and preallocation refusal.

use super::*;
use std::sync::atomic::Ordering;

#[test]
fn request_body_clones_retain_exact_buffer_and_owner_loans()
-> Result<(), Box<dyn std::error::Error>> {
    let (budget, used) = crate::admitted_output::tests::fixture_budget_with_counter()?;
    let _scope = budget.enter();
    let baseline = used.load(Ordering::SeqCst);
    let request = HelloRequest::new("borrowed-client", RPC_PROTOCOL_VERSION);
    let expected = encode_rpc_hello_request(&request.client_name, request.version);
    let body = super::super::requests::encode_hello_request(&request)?;
    assert_eq!(&body[..], expected);
    let retained = used.load(Ordering::SeqCst);
    assert!(retained > baseline + body.len() as u64);
    let clone = body.clone();
    drop(body);
    assert_eq!(used.load(Ordering::SeqCst), retained);
    drop(clone);
    assert_eq!(used.load(Ordering::SeqCst), baseline);

    for _ in 0..20 {
        drop(super::super::requests::encode_hello_request(&request)?);
        assert_eq!(used.load(Ordering::SeqCst), baseline);
    }
    Ok(())
}

#[test]
fn counted_request_refusal_preserves_the_original_typed_cause()
-> Result<(), Box<dyn std::error::Error>> {
    let (budget, used) = crate::admitted_output::tests::fixture_budget_with_counter()?;
    let _scope = budget.enter();
    let baseline = used.load(Ordering::SeqCst);
    let held = budget.reserve_scratch_bytes(1024 * 1024 - baseline - 1)?;
    assert!(matches!(
        encode(|output| output.write_str("request-body")),
        Err(ControlClientError::Streaming {
            source: StreamingApiError::OutputAdmission { .. }
        })
    ));
    drop(held);
    assert_eq!(used.load(Ordering::SeqCst), baseline);
    Ok(())
}

#[test]
fn borrowed_hex_fields_preserve_canonical_request_bytes() -> Result<(), Box<dyn std::error::Error>>
{
    let budget = crate::admitted_output::tests::fixture_budget()?;
    let _scope = budget.enter();
    let body = encode(|output| {
        output.write_str("header\n")?;
        line(output, "data", Hex(&[0, 15, 16, 255]))?;
        line(output, "number", 42)
    })?;
    assert_eq!(&body[..], b"header\ndata=000f10ff\nnumber=42\n");
    Ok(())
}

#[test]
fn operational_request_requires_retained_original_authority() {
    assert!(matches!(
        encode(|output| output.write_str("request-body")),
        Err(ControlClientError::Streaming {
            source: StreamingApiError::OutputAdmission { .. }
        })
    ));
}
