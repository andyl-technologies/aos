//! Exercises the original borrowed cursor's slices and fail-closed framing.

use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn named_spans_borrow_original_input_and_require_original_field_order() -> TestResult {
    let input = br#"{"first":[1,{"nested":"x\\\"y"}],"second":null}"#;
    let mut fields = OrderedFields::object(input)?;
    let first = fields.named("first")?;
    let start = input
        .windows(first.len())
        .position(|bytes| bytes == first)
        .ok_or("missing original span")?;
    assert_eq!(first.as_ptr(), input[start..].as_ptr());
    assert_eq!(fields.named("second")?, b"null");
    fields.finish()?;
    let mut fields = OrderedFields::object(input)?;
    assert!(fields.named("second").is_err());
    assert!(plain_string(br#""escaped\\n""#).is_err());
    Ok(())
}

#[test]
fn exact_span_stack_and_original_terminal_malformed_refusals_are_preserved() -> TestResult {
    let mut input = Vec::new();
    input.push(b'[');
    input.extend(std::iter::repeat_n(b'[', FIELD_SPAN_STACK_BYTES));
    input.push(b'0');
    input.extend(std::iter::repeat_n(b']', FIELD_SPAN_STACK_BYTES));
    input.push(b']');
    let mut fields = OrderedFields::array(&input)?;
    assert!(fields.next_value()?.is_some());
    fields.finish()?;

    input.insert(1, b'[');
    input.insert(input.len() - 1, b']');
    assert!(OrderedFields::array(&input)?.next_value().is_err());

    for malformed in [br#"["unterminated]"#.as_slice(), b"[[}]", b"[0]tail]"] {
        let mut fields = OrderedFields::array(malformed)?;
        assert!(fields.next_value().and_then(|_| fields.finish()).is_err());
    }
    Ok(())
}
