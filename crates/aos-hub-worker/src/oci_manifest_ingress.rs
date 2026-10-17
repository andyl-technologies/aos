//! Ordering of current origin authorization before an OCI body is polled.
//!
//! The accepted origin response permits only local body consumption. It is
//! neither a provider grant nor a substitute for the later exact reservation.

use std::future::Future;

pub(crate) enum AuthorizedBody<A, T> {
    Denied(A),
    Read(T),
}

/// Reads a body only after the original protected authority check succeeds.
///
/// # Errors
/// Returns the original authority or read error without polling a denied body.
pub(crate) async fn read_authorized<A, T, E, F: Future<Output = Result<T, E>>>(
    authorization: impl Future<Output = Result<A, E>>,
    accepted: impl FnOnce(&A) -> bool,
    read: impl FnOnce() -> F,
) -> Result<AuthorizedBody<A, T>, E> {
    let response = authorization.await?;
    if !accepted(&response) {
        return Ok(AuthorizedBody::Denied(response));
    }
    Ok(AuthorizedBody::Read(read().await?))
}
