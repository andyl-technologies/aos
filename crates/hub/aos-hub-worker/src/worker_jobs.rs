//! Lazy dispatch for jobs owned by the Worker-only control plane.
//!
//! Hybrid owns logical job scheduling in Native. Its Worker must refuse this
//! entry point before reading a seal, decoding a body or attaching Worker SQL,
//! even when bindings intended for a Worker-only deployment are present.

use std::future::Future;

/// Marks an entry point unavailable to the Hybrid Worker role.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct HybridJobRefusal;

/// Requires the Worker-only role before admitting logical job execution.
///
/// # Errors
/// Returns a refusal when the current Worker uses Hybrid topology.
pub(crate) fn require_worker_only(hybrid: bool) -> Result<(), HybridJobRefusal> {
    if hybrid {
        return Err(HybridJobRefusal);
    }
    Ok(())
}

/// Dispatches a Worker-owned job without constructing its work in Hybrid.
///
/// Keeping the entire request handler inside the lazy closure makes role
/// rejection precede credential, request-body and database access.
///
/// # Errors
/// Returns a refusal before invoking the closure when the role is Hybrid.
pub(crate) async fn dispatch<T, F: Future<Output = T>>(
    hybrid: bool,
    worker: impl FnOnce() -> F,
) -> Result<T, HybridJobRefusal> {
    require_worker_only(hybrid)?;
    Ok(worker().await)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    #[tokio::test]
    async fn hybrid_refuses_before_constructing_worker_credentials_body_or_backend() {
        let bindings_present = true;
        let worker_context_reads = Cell::new(0);

        let result = dispatch(true, || {
            // Presence of a seal and database binding cannot change topology.
            assert!(bindings_present);
            worker_context_reads.set(worker_context_reads.get() + 1);
            std::future::ready("a Worker job must not be admitted")
        })
        .await;

        assert_eq!(result, Err(HybridJobRefusal));
        assert_eq!(worker_context_reads.get(), 0);
    }

    #[tokio::test]
    async fn hybrid_refuses_a_worker_future_that_would_never_complete() {
        let result = dispatch(true, std::future::pending::<()>).await;

        assert_eq!(result, Err(HybridJobRefusal));
    }

    #[tokio::test]
    async fn worker_only_preserves_job_completion_and_retry_failure() {
        let executions = Cell::new(0);
        let completed = dispatch(false, || async {
            executions.set(executions.get() + 1);
            Ok::<_, &str>("completed")
        })
        .await;
        let retry = dispatch(false, || async {
            executions.set(executions.get() + 1);
            Err::<(), _>("retain job for retry")
        })
        .await;

        assert_eq!(completed, Ok(Ok("completed")));
        assert_eq!(retry, Ok(Err("retain job for retry")));
        assert_eq!(executions.get(), 2);
    }
}
