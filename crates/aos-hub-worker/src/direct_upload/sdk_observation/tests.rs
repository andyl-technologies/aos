//! Promise lifecycle and redaction checks for the actual observation wrapper.

use super::*;
use std::{
    future::{ready, Future},
    task::{Context as TaskContext, Poll},
};

fn take() -> Vec<serde_json::Value> {
    CAPTURE.with(|capture| {
        std::mem::take(&mut *capture.borrow_mut())
            .iter()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    })
}

#[test]
fn returned_and_rejected_results_keep_exact_values_without_error_text() {
    take();
    let mut future = Box::pin(observe(
        Some(Context::new("private-object-canary", None)),
        Some(Operation::Head),
        ready(Ok::<_, &str>(37)),
    ));
    let mut context = TaskContext::from_waker(std::task::Waker::noop());
    assert_eq!(future.as_mut().poll(&mut context), Poll::Ready(Ok(37)));
    drop(future);
    let success = take();
    assert_eq!(success.len(), 2);
    assert_eq!(success[1]["outcome"], "sdk_returned");
    assert!(success
        .iter()
        .all(|event| !event.to_string().contains("private-object-canary")));

    let mut failure = Box::pin(observe(
        Some(Context::new("private-object-canary", None)),
        Some(Operation::Complete),
        ready(Err::<(), _>("secret-error-canary")),
    ));
    assert_eq!(
        failure.as_mut().poll(&mut context),
        Poll::Ready(Err("secret-error-canary"))
    );
    drop(failure);
    let failed = take();
    assert_eq!(failed[1]["outcome"], "unknown");
    assert!(failed
        .iter()
        .all(|event| !event.to_string().contains("secret-error-canary")));
    assert_ne!(failed[0]["attemptOrdinal"], success[0]["attemptOrdinal"]);
}

#[test]
fn dropped_pending_promise_stays_unknown_and_missing_context_is_not_a_receipt() {
    take();
    let mut future = Box::pin(observe(
        Some(Context::new("key", None)),
        Some(Operation::Get),
        std::future::pending::<Result<(), ()>>(),
    ));
    let mut context = TaskContext::from_waker(std::task::Waker::noop());
    assert_eq!(future.as_mut().poll(&mut context), Poll::Pending);
    drop(future);
    let captured = take();
    assert_eq!(captured.len(), 2);
    assert_eq!(captured[1]["outcome"], "unknown");
    assert!(captured[1].get("consumedBytes").is_none());

    let mut disabled = Box::pin(observe(
        None,
        Some(Operation::Delete),
        ready(Err::<(), _>(9)),
    ));
    assert_eq!(disabled.as_mut().poll(&mut context), Poll::Ready(Err(9)));
    drop(disabled);
    assert!(take().is_empty());
}
