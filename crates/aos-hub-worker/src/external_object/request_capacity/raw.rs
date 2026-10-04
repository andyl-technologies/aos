//! Existing Direct response readers beneath actual configured request ownership.
//!
//! The handler retains its native bounded metadata or integrity reader. Its
//! future drops before the scope cancels Fetch and releases owned capacity.
//! An actual borrowed one-request verification permit is checked instead of
//! acquired again; its caller retains it across this whole awaited handler.

use std::future::Future;

use anyhow::Result;
use worker::{Env, Fetch, Request, Response, ResponseBody};

use super::Scope;
use crate::direct_upload::provider_capacity::{self, policy, Class, Permit};

/// Runs one existing response handler through original cutoff and cancellation.
///
/// This does not settle an unknown mutation or prove remote drain on abort.
///
/// # Errors
/// Refuses malformed policy, stale original, incompatible outer permit, failed
/// Fetch or the existing bounded response validation and body-reader errors.
pub(crate) async fn with_response<T, F>(
    env: &Env,
    request: Request,
    expires_at: i64,
    uncertainty: i64,
    signal: Option<worker::web_sys::AbortSignal>,
    class: Class,
    held: Option<&Permit>,
    fresh: &dyn Fn() -> Result<()>,
    before_dispatch: &dyn Fn(),
    legacy_dispatch_observed: bool,
    handler: impl FnOnce(Response) -> F,
) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    let Some(policy) = policy::installed(env)? else {
        fresh()?;
        before_dispatch();
        if legacy_dispatch_observed {
            provider_capacity::record_dispatch();
        }
        return handler(Fetch::Request(request).send().await?).await;
    };
    let scope = Scope::new(expires_at, uncertainty, signal, fresh)?;
    if let Some(permit) = held {
        policy::request::validate_held(&policy, permit, fresh)?;
    } else {
        let permit = scope
            .run(policy::request::acquire(&policy, class, fresh))
            .await?;
        scope.lifetime.retain_capacity(permit)?;
    }
    scope
        .run(async {
            scope.check()?;
            before_dispatch();
            provider_capacity::record_dispatch();
            let response = Fetch::Request(request)
                .send_with_signal(&worker::AbortSignal::from(scope.controller.signal()))
                .await?;
            // Cancellation ownership precedes every fallible handler header/status
            // check. Native readers retain their own lock-specific cancel-on-drop.
            let _unhanded = match response.body() {
                ResponseBody::Stream(stream) => Some(
                    crate::external_object::oci::byte_stream::UnhandedStream::new(
                        stream.clone().into(),
                    ),
                ),
                _ => None,
            };
            handler(response).await
        })
        .await
}
