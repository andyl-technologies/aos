//! Configured compact Fetch ownership through body EOF or cancellation.
//!
//! The legacy branch is unchanged when no common policy is installed. A scoped
//! request retains one real pool reservation and native abort/reader owners
//! through its authenticated original window. Cancel invocation is not proof of
//! remote drain, physical settlement or a positive write acknowledgement.

use anyhow::{ensure, Result};
use futures_util::{
    future::{select, Either},
    StreamExt as _,
};
use std::{future::Future, time::Duration};
use worker::{Env, Fetch, Headers, Request, Response, ResponseBody};

use super::copy::{lifetime::Lifetime, stream::Reader};
use crate::direct_upload::provider_capacity::{self, policy, Class};

pub(super) mod raw;

/// Distinguishes legacy forwarding from an installed scoped request.
pub(super) enum ProviderResponse<'a> {
    Legacy(Response),
    Scoped(ScopedResponse<'a>),
}

struct Scope<'a> {
    lifetime: Lifetime,
    signal: worker::web_sys::AbortSignal,
    expires_at: i64,
    uncertainty: i64,
    fresh: &'a dyn Fn() -> Result<()>,
    controller: worker::web_sys::AbortController,
    _registration: super::copy::lifetime::Registration,
}

/// Keeps native body cancellation ahead of releasing actual request capacity.
pub(super) struct ScopedResponse<'a> {
    reader: Option<Reader>,
    scope: Scope<'a>,
    status: u16,
    headers: Headers,
}

/// Executes one configured request without acquiring a transferred Copy permit.
///
/// # Errors
/// Refuses a malformed installed policy, canceled/stale original, incompatible
/// pool, failed Fetch, unavailable bounded reader or expired response ownership.
pub(super) async fn send<'a>(
    env: &Env,
    request: Request,
    expires_at: i64,
    uncertainty: i64,
    client_signal: Option<worker::web_sys::AbortSignal>,
    class: Class,
    fresh: &'a dyn Fn() -> Result<()>,
) -> Result<ProviderResponse<'a>> {
    let Some(policy) = policy::installed(env)? else {
        // Existing authority checks already precede this exact legacy Fetch.
        return Ok(ProviderResponse::Legacy(
            Fetch::Request(request).send().await?,
        ));
    };
    let scope = Scope::new(expires_at, uncertainty, client_signal, fresh)?;
    let permit = scope
        .run(policy::request::acquire(&policy, class, fresh))
        .await?;
    scope.lifetime.retain_capacity(permit)?;
    let (status, headers, reader) = scope
        .run(async {
            scope.check()?;
            provider_capacity::record_dispatch();
            let response = Fetch::Request(request)
                .send_with_signal(&worker::AbortSignal::from(scope.controller.signal()))
                .await?;
            let status = response.status_code();
            let headers = response.headers().clone();
            let (_, body) = response.into_parts();
            let reader = match body {
                ResponseBody::Empty => None,
                ResponseBody::Stream(body) => {
                    let stream: wasm_bindgen::JsValue = body.into();
                    let mut unhanded = super::oci::byte_stream::UnhandedStream::new(stream.clone());
                    let reader = Reader::new(stream, &scope.lifetime)?;
                    unhanded.disarm();
                    Some(reader)
                }
                _ => anyhow::bail!("configured response requires a native bounded stream"),
            };
            Ok((status, headers, reader))
        })
        .await?;
    Ok(ProviderResponse::Scoped(ScopedResponse {
        reader,
        scope,
        status,
        headers,
    }))
}

impl<'a> Scope<'a> {
    fn new(
        expires_at: i64,
        uncertainty: i64,
        client_signal: Option<worker::web_sys::AbortSignal>,
        fresh: &'a dyn Fn() -> Result<()>,
    ) -> Result<Self> {
        let controller = worker::web_sys::AbortController::new()
            .map_err(|_| anyhow::anyhow!("configured request abort owner unavailable"))?;
        let signal = client_signal.unwrap_or_else(|| controller.signal());
        let lifetime = Lifetime::new(signal.clone())?;
        let registration = lifetime.register(controller.clone().into(), "abort")?;
        Ok(Self {
            lifetime,
            signal,
            expires_at,
            uncertainty,
            fresh,
            controller,
            _registration: registration,
        })
    }

    fn check(&self) -> Result<()> {
        self.lifetime.check()?;
        ensure!(!self.signal.aborted(), "configured request canceled");
        (self.fresh)()?;
        self.remaining()?;
        Ok(())
    }

    fn remaining(&self) -> Result<u64> {
        ensure!(
            (0..=29).contains(&self.uncertainty),
            "configured request clock unqualified"
        );
        let latest = aos_hub_core::clock::now_unix_secs()
            .checked_add(self.uncertainty)
            .ok_or_else(|| anyhow::anyhow!("configured request clock overflow"))?;
        let remaining = self
            .expires_at
            .checked_sub(latest)
            .ok_or_else(|| anyhow::anyhow!("configured request cutoff overflow"))?;
        // This is the existing bounded signed application window, not a new lease.
        ensure!(
            (1..=60).contains(&remaining),
            "configured request expired or unbounded"
        );
        Ok(remaining as u64)
    }

    async fn run<T>(&self, work: impl Future<Output = Result<T>>) -> Result<T> {
        self.check()?;
        let seconds = self.remaining()?;
        let timeout = async {
            worker::Delay::from(Duration::from_secs(seconds)).await;
            anyhow::bail!("configured request original deadline elapsed")
        };
        let cancellation = async {
            loop {
                self.check()?;
                worker::Delay::from(Duration::from_millis(50)).await;
            }
        };
        let stop = async {
            futures_util::pin_mut!(timeout, cancellation);
            match select(timeout, cancellation).await {
                Either::Left((result, _)) | Either::Right((result, _)) => result,
            }
        };
        futures_util::pin_mut!(work, stop);
        match select(work, stop).await {
            Either::Left((result, _)) => {
                self.check()?;
                result
            }
            Either::Right((result, _)) => result,
        }
    }
}

impl ProviderResponse<'_> {
    /// Returns the actual provider status without polling its response body.
    pub(super) fn status_code(&self) -> u16 {
        match self {
            Self::Legacy(response) => response.status_code(),
            Self::Scoped(response) => response.status,
        }
    }

    /// Borrows the actual provider headers while retaining response ownership.
    pub(super) fn headers(&self) -> &Headers {
        match self {
            Self::Legacy(response) => response.headers(),
            Self::Scoped(response) => &response.headers,
        }
    }

    /// Collects only the caller's existing compact probe byte ceiling.
    ///
    /// # Errors
    /// Refuses unavailable/failed streams, oversized chunks or expired ownership.
    pub(super) async fn read_bounded(&mut self, maximum: usize) -> Result<Vec<u8>> {
        match self {
            Self::Legacy(response) => {
                let mut stream = response.stream()?;
                let mut collected = Vec::new();
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk?;
                    ensure!(
                        collected
                            .len()
                            .checked_add(chunk.len())
                            .is_some_and(|size| size <= maximum),
                        "probe body oversized"
                    );
                    collected.extend_from_slice(&chunk);
                }
                Ok(collected)
            }
            Self::Scoped(response) => {
                response
                    .scope
                    .run(async {
                        let mut collected = Vec::new();
                        if let Some(reader) = &response.reader {
                            loop {
                                response.scope.check()?;
                                let (chunk, done) = reader.read().await?;
                                response.scope.check()?;
                                ensure!(
                                    collected
                                        .len()
                                        .checked_add(chunk.length() as usize)
                                        .is_some_and(|size| size <= maximum),
                                    "probe body oversized"
                                );
                                collected.extend_from_slice(&chunk.to_vec());
                                if done {
                                    break;
                                }
                            }
                        }
                        Ok(collected)
                    })
                    .await
            }
        }
    }
}
