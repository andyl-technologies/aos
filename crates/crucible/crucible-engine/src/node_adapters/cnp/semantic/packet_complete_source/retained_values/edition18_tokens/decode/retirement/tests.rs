//! Exercises real deep decoding and retirement on the ordinary test stack.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::edition18_tokens::{
    LiteralValue18TokenAttempt, quote_read_data, read_into_data,
};

// Only the flat shallow token document is materialized here. No ordinary deep
// Value exists until the real guarded decoder constructs it.
fn nested_tokens(depth: usize, siblings: usize) -> LiteralValue18TokenAttempt {
    let mut tokens = Vec::new();
    if siblings > 1 {
        tokens.push(serde_json::json!({"type":"arrayStart"}));
    }
    for _ in 0..siblings {
        for level in 0..depth {
            if level % 2 == 0 {
                tokens.push(serde_json::json!({"type":"arrayStart"}));
            } else {
                tokens.push(serde_json::json!({"type":"objectStart"}));
                tokens.push(serde_json::json!({"type":"key","value":"child"}));
            }
        }
        tokens.push(serde_json::json!({"type":"null"}));
        for level in (0..depth).rev() {
            let tag = if level % 2 == 0 {
                "arrayEnd"
            } else {
                "objectEnd"
            };
            tokens.push(serde_json::json!({"type":tag}));
        }
    }
    if siblings > 1 {
        tokens.push(serde_json::json!({"type":"arrayEnd"}));
    }
    let chunks: Vec<Vec<Value>> = tokens
        .chunks(MAX_ARRAY_ELEMENTS)
        .map(<[Value]>::to_vec)
        .collect();
    let raw = serde_json::json!({"schema":SCHEMA,"chunks":chunks});
    let quote = quote_read_data(&raw, usize::MAX).unwrap();
    let mut output = LiteralValue18TokenAttempt::new();
    read_into_data(&raw, quote, &mut output, usize::MAX).unwrap();
    output
}

fn decoded(tokens: &LiteralValue18TokenAttempt) -> LiteralValue18DecodeAttempt {
    let quote = quote_decode_data(tokens.data().unwrap(), usize::MAX).unwrap();
    let mut output = LiteralValue18DecodeAttempt::new();
    decode_into_data(tokens.data().unwrap(), quote, &mut output, usize::MAX).unwrap();
    assert!(output.retirement.capacity() >= quote.literal_population_bound_data());
    assert!(output.retirement.is_empty());
    output
}

#[test]
fn completed_deep_array_object_tree_drops_on_the_default_stack() {
    let depth = 32_768;
    let tokens = nested_tokens(depth, 1);
    let quote = quote_decode_data(tokens.data().unwrap(), usize::MAX).unwrap();
    assert_eq!(quote.literal_population_bound_data(), depth + 1);
    let output = decoded(&tokens);
    let mut value = output.value().unwrap();
    for level in 0..depth {
        value = if level % 2 == 0 {
            &value.as_array().unwrap()[0]
        } else {
            value.as_object().unwrap().get("child").unwrap()
        };
    }
    assert!(value.is_null());

    // The actual Drop path must destroy this deep output. Neither a raised
    // stack nor a leaked/forgotten root can make this control pass.
    drop(output);
}

#[test]
fn all_partial_positions_share_the_original_admitted_retirement_bank() {
    let tokens = nested_tokens(10_000, 3);
    let quote = quote_decode_data(tokens.data().unwrap(), usize::MAX).unwrap();
    let mut output = decoded(&tokens);
    let pointer = output.retirement.as_ptr();
    let capacity = output.retirement.capacity();
    let Some(Value::Array(mut children)) = output.value.take() else {
        panic!("real root missing");
    };

    // Repartition the decoder's genuine three child trees across its actual
    // partial-owner positions. No clone, new child or backing bank is created.
    output.pending = children.pop();
    let Some(Value::Array(values)) = children.pop() else {
        panic!("real array child missing");
    };
    output.frames.push(Frame::Array(values));
    output.value = Some(Value::Array(children));
    output.complete = false;
    output.failed = true;
    let retained = output
        .retained_requested_storage_data(quote.literal_population_bound_data(), usize::MAX)
        .unwrap();
    assert!(retained <= quote.requested_storage_data().0);
    assert_eq!(
        output
            .retained_requested_storage_data(quote.literal_population_bound_data(), retained)
            .unwrap(),
        retained
    );
    assert!(
        output
            .retained_requested_storage_data(quote.literal_population_bound_data(), retained - 1)
            .is_err()
    );

    output.retire_values();
    assert!(output.frames.is_empty() && output.pending.is_none() && output.value.is_none());
    assert!(output.retirement.is_empty());
    assert_eq!(output.retirement.capacity(), capacity);
    assert_eq!(output.retirement.as_ptr(), pointer);
    assert!(output.value().is_err());
    // Retiring an already drained owner is idempotent and still deallocates its
    // retained empty frame/worklist banks normally.
    drop(output);
}

#[test]
fn real_decoder_refusal_keeps_deep_children_until_iterative_retirement() {
    let mut tokens = nested_tokens(16_000, 1);
    let last = tokens.data.chunks.last_mut().unwrap().last_mut().unwrap();
    assert!(matches!(last, LiteralToken18::ArrayEnd));
    *last = LiteralToken18::ObjectEnd;
    // The flat extent quote is not chronology authority. The real constructor
    // detects this wrong final kind after retaining the entire deep child.
    let quote = quote_decode_data(tokens.data().unwrap(), usize::MAX).unwrap();
    let mut output = LiteralValue18DecodeAttempt::new();
    assert!(decode_into_data(tokens.data().unwrap(), quote, &mut output, usize::MAX).is_err());
    assert_eq!(output.state_data(), (true, true, false));
    assert_eq!(output.frames.len(), 1);
    assert!(output.retirement.capacity() >= quote.literal_population_bound_data());
    assert!(output.value().is_err());
    assert!(
        output
            .retained_requested_storage_data(quote.literal_population_bound_data(), usize::MAX)
            .unwrap()
            <= quote.requested_storage_data().0
    );
    assert_eq!(
        decode_into_data(tokens.data().unwrap(), quote, &mut output, usize::MAX),
        Err(RuntimeError::DuplicateOperation)
    );
    drop(output);
}

#[test]
fn unwinding_after_real_materialization_uses_the_same_iterative_drop() {
    let tokens = nested_tokens(8_192, 1);
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let output = decoded(&tokens);
        assert!(output.value().is_ok());
        panic!("caller refuses after literal construction");
    }));
    assert!(caught.is_err());
}
