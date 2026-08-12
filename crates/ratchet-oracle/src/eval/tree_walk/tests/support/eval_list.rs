//! Tree-walk test support: list evaluation and captured-stderr helpers.

use super::super::*;
use super::eval::lower;
use super::*;

pub(crate) fn eval_list_string_bytes(source: &str) -> Vec<Vec<u8>> {
    let outcome = eval_whnf_owned(&lower(source)).expect("source evaluates");
    let list = outcome
        .heap()
        .get_list(outcome.value())
        .expect("result is a heap-owned list");
    list.iter()
        .map(|value| {
            outcome
                .heap()
                .get_string(*value)
                .expect("element is a heap-owned string")
                .bytes()
                .to_vec()
        })
        .collect()
}

pub(crate) fn eval_list_string_bytes_with_options(
    source: &str,
    options: TreeWalkOptions,
) -> Vec<Vec<u8>> {
    let outcome = eval_whnf_owned_with_options(&lower(source), options).expect("source evaluates");
    let list = outcome
        .heap()
        .get_list(outcome.value())
        .expect("result is a heap-owned list");
    list.iter()
        .map(|value| {
            outcome
                .heap()
                .get_string(*value)
                .expect("element is a heap-owned string")
                .bytes()
                .to_vec()
        })
        .collect()
}

pub(crate) fn eval_list_ints(source: &str) -> Vec<i64> {
    let outcome = eval_whnf_owned(&lower(source)).expect("source evaluates");
    let list = outcome
        .heap()
        .get_list(outcome.value())
        .expect("result is a heap-owned list");
    list.iter()
        .map(|value| value.as_int().expect("element is an int"))
        .collect()
}

pub(crate) fn eval_owned(source: &str) -> EvalOutcome {
    eval_whnf_owned(&lower(source)).expect("source evaluates")
}

pub(crate) fn eval_owned_with_options(source: &str, options: TreeWalkOptions) -> EvalOutcome {
    eval_whnf_owned_with_options(&lower(source), options).expect("source evaluates")
}

pub(crate) fn assert_trace_output(output: &EvalTraceOutput, kind: EvalTraceKind, message: &[u8]) {
    assert_eq!(output.kind(), kind);
    assert_eq!(output.message(), message);
}

pub(crate) fn assert_warning_output(output: &EvalWarningOutput, message: &[u8]) {
    assert_eq!(output.message(), message);
}

pub(crate) fn eval_captured_stderr_with_options(source: &str, options: TreeWalkOptions) -> Vec<u8> {
    let ir = lower(source);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    evaluator.capture_stderr();
    evaluator.eval_root().expect("source evaluates");
    evaluator.captured_stderr().to_vec()
}

pub(crate) fn eval_captured_stderr_error_with_options(
    source: &str,
    options: TreeWalkOptions,
) -> (TreeWalkError, Vec<u8>) {
    let ir = lower(source);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    evaluator.capture_stderr();
    let error = evaluator.eval_root().expect_err("source fails");
    let stderr = evaluator.captured_stderr().to_vec();
    (error, stderr)
}

pub(crate) fn eval_captured_stderr(source: &str) -> Vec<u8> {
    eval_captured_stderr_with_options(source, TreeWalkOptions::new())
}

pub(crate) fn assert_error_contexts(error: &TreeWalkError, expected: &[&[u8]]) {
    let actual: Vec<&[u8]> = error
        .contexts()
        .iter()
        .map(EvalErrorContext::message)
        .collect();
    assert_eq!(actual, expected);
    let rendered = error.to_string();
    for message in expected {
        let message = String::from_utf8_lossy(message);
        assert!(
            rendered.contains(message.as_ref()),
            "rendered error {rendered:?} omitted context {message:?}"
        );
    }
}
