//! Public cache policy and bounded admission ahead of signed Native proxying.
//!
//! Limits are per Worker isolate; they do not claim a global origin budget.
//! Cached control responses require Native's explicit public immutable policy.
//! Object byte caches still require fresh Native authorization on every request.
//! Each isolate admits 16 active origin calls and retains at most 4096 counters.
//! Client budgets are 120 page reads or 2400 batched controls per minute. Cache
//! entries are capped at 256 KiB and 60 seconds; mutable browse pages stay at Native.

mod policy;
mod shield;

pub(crate) use policy::{delivery_key, origin_class, request_key, response_age};
pub(crate) use shield::{OriginClass, OriginShield, Refusal, ShieldLimits};

#[cfg(target_arch = "wasm32")]
mod runtime;
#[cfg(target_arch = "wasm32")]
pub(crate) use runtime::{cached_response, header_map, proxy, store_response};

/// Provides the same cache/admission ordering for Worker and HTTP fixtures.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub(crate) trait FrontTransport {
    type Response;
    type Error;

    async fn cached(&mut self, key: &str) -> Result<Option<Self::Response>, Self::Error>;
    async fn origin(&mut self) -> Result<Self::Response, Self::Error>;
    async fn store(&mut self, key: &str, response: &mut Self::Response) -> Result<(), Self::Error>;
    fn refused(&self, refusal: Refusal) -> Result<Self::Response, Self::Error>;
}

/// Looks up eligible entries before spending an origin admission.
pub(crate) async fn dispatch<T: FrontTransport>(
    transport: &mut T,
    shield: &OriginShield,
    class: OriginClass,
    client: &str,
    cache_key: Option<&str>,
    now: i64,
) -> Result<T::Response, T::Error> {
    if let Some(key) = cache_key {
        // Derivative-cache failure affects latency, never origin availability.
        if let Ok(Some(response)) = transport.cached(key).await {
            return Ok(response);
        }
    }
    let permit = match shield.enter(class, client, now) {
        Ok(permit) => permit,
        Err(refusal) => return transport.refused(refusal),
    };
    let mut response = transport.origin().await?;
    drop(permit);
    if let Some(key) = cache_key {
        let _ = transport.store(key, &mut response).await;
    }
    Ok(response)
}

#[cfg(test)]
mod tests;
