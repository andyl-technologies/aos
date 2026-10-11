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

/// Owns one admitted immutable read independently of its dispatch HMAC window.
///
/// The lease-derived window conservatively bounds body resources. Every actual
/// Fetch still repeats dispatch admission; EOF does not gain mutation authority.
///
/// # Errors
/// Refuses invalid policy/window, dispatch admission, current read ownership,
/// cancellation, incompatible capacity or the existing response/reader errors.
pub(crate) async fn with_immutable_response<T, F>(
    env: &Env,
    request: Request,
    signal: Option<worker::web_sys::AbortSignal>,
    class: Class,
    held: Option<&Permit>,
    dispatch_fresh: &dyn Fn() -> Result<()>,
    body_current: &dyn Fn() -> Result<()>,
    read_window: &dyn Fn() -> Result<super::super::read_ownership::ReadWindow>,
    before_dispatch: &dyn Fn(),
    legacy_dispatch_observed: bool,
    handler: impl FnOnce(Response) -> F,
) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    let Some(policy) = policy::installed(env)? else {
        // Preserve the ordinary legacy dispatch/body behavior without selecting
        // a configured resource window or adding response consumption.
        dispatch_fresh()?;
        before_dispatch();
        if legacy_dispatch_observed {
            provider_capacity::record_dispatch();
        }
        return handler(Fetch::Request(request).send().await?).await;
    };
    dispatch_fresh()?;
    let window = read_window()?;
    let mut scope = Scope::new(
        window.expires_at,
        window.uncertainty,
        signal,
        dispatch_fresh,
    )?;
    scope.read_window = Some(window);
    if let Some(permit) = held {
        policy::request::validate_held(&policy, permit, dispatch_fresh)?;
    } else {
        let permit = scope
            .run(policy::request::acquire(&policy, class, dispatch_fresh))
            .await?;
        scope.lifetime.retain_capacity(permit)?;
    }

    // Capacity waiting remains dispatch admission. Only the already admitted
    // response body uses current immutable ownership, never the short HMAC TTL.
    scope.fresh = body_current;
    scope
        .run(async {
            scope.check()?;
            dispatch_fresh()?;
            before_dispatch();
            provider_capacity::record_dispatch();
            let response = Fetch::Request(request)
                .send_with_signal(&worker::AbortSignal::from(scope.controller.signal()))
                .await?;
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
