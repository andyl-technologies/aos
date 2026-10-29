//! Ordered OCI document effects under one immutable accepted scope.
//!
//! A preceding provider await may outlive acceptance. Each next effect invokes
//! the same check immediately before constructing its SDK future. Failures never
//! infer provider rollback and this helper deliberately initiates no cleanup.

use anyhow::Result;
use std::future::Future;

pub(crate) async fn stage<Check, Create, CreateFuture, Part, PartFuture, Complete, CompleteFuture>(
    check: Check,
    create: Create,
    part: Part,
    complete: Complete,
) -> Result<()>
where
    Check: Fn() -> Result<()>,
    Create: FnOnce() -> CreateFuture,
    CreateFuture: Future<Output = Result<String>>,
    Part: FnOnce(String) -> PartFuture,
    PartFuture: Future<Output = Result<String>>,
    Complete: FnOnce(String, String) -> CompleteFuture,
    CompleteFuture: Future<Output = Result<()>>,
{
    check()?;
    let upload = create().await?;
    check()?;
    let etag = part(upload.clone()).await?;
    check()?;
    complete(upload, etag).await
}

/// Rechecks the retained scope after an awaited authority/resource boundary.
///
/// A caller may already have persisted a pending physical intent. A refusal
/// deliberately performs neither dispatch nor settlement of that intent.
pub(crate) async fn dispatch_after<Wait, Value, Check, Dispatch, Effect, Output>(
    wait: Wait,
    check: Check,
    dispatch: Dispatch,
) -> Result<Output>
where
    Wait: Future<Output = Result<Value>>,
    Check: FnOnce(&Value) -> Result<()>,
    Dispatch: FnOnce(Value) -> Effect,
    Effect: Future<Output = Result<Output>>,
{
    let value = wait.await?;
    check(&value)?;
    dispatch(value).await
}

#[cfg(target_arch = "wasm32")]
pub(crate) mod sdk;

#[cfg(target_arch = "wasm32")]
pub(crate) mod read;

#[cfg(test)]
mod tests;
