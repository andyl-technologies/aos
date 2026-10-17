//! Existing SDK capacity retained until actual native promise settlement.
//!
//! The request or guard registers a detached waiter before awaiting the same
//! promise. Timeout/caller cancellation closes permission immediately, while
//! the waiter retains capacity and any guarded key. It is not a drain receipt.

use anyhow::{Context as _, Result};
use aos_hub_core::hybrid_ingress::OciDocumentEffect;
use futures_util::FutureExt as _;
use js_sys::{Array, Function, Promise, Reflect};
use std::rc::Rc;
use wasm_bindgen::{JsCast as _, JsValue};
use wasm_bindgen_futures::JsFuture;

use crate::{
    direct_upload::provider_capacity,
    oci_projection::lifetime::{Owner, Scope},
};

#[derive(Clone, Copy)]
pub(crate) enum Retainer<'a> {
    Request(&'a worker::Context),
    Guard(&'a worker::State),
}

impl Retainer<'_> {
    fn hold(&self, pending: impl std::future::Future<Output = ()> + 'static) {
        match self {
            Self::Request(context) => context.wait_until(pending),
            Self::Guard(state) => state.wait_until(pending),
        }
    }
}

pub(crate) struct Acknowledged<R> {
    pub(crate) value: JsValue,
    pub(crate) reader: Option<Rc<crate::direct_digest::Reader>>,
    pub(crate) hold: Scope<(R, provider_capacity::Permit)>,
}

pub(crate) async fn invoke<R: 'static>(
    retainer: Retainer<'_>,
    resources: R,
    object: &JsValue,
    method: &str,
    arguments: &[JsValue],
    effect: &OciDocumentEffect,
    check: impl Fn() -> Result<()>,
) -> Result<Acknowledged<R>> {
    let capacity = provider_capacity::acquire_checked(1, &check).await?;
    check()?;
    let owner = Owner::new((resources, capacity));
    let scope = Scope(Rc::clone(&owner));
    let function: Function = Reflect::get(object, &JsValue::from_str(method))
        .map_err(|_| anyhow::anyhow!("OCI SDK method unavailable"))?
        .dyn_into()
        .map_err(|_| anyhow::anyhow!("OCI SDK method unavailable"))?;
    let arguments = arguments.iter().cloned().collect::<Array>();
    // No await separates the final original check from actual SDK dispatch.
    check()?;
    provider_capacity::record_dispatch();
    let promise: Promise = function
        .apply(object, &arguments)
        .map_err(|_| anyhow::anyhow!("OCI SDK dispatch failed"))?
        .dyn_into()
        .map_err(|_| anyhow::anyhow!("OCI SDK promise unavailable"))?;
    let pending = async move {
        JsFuture::from(promise)
            .await
            .map_err(|_| "OCI SDK acknowledgement failed")
    }
    .shared();
    let returned_body = method == "get";
    let retained = pending.clone();
    let retained_owner = Rc::clone(&owner);
    retainer.hold(async move {
        let result = retained.await;
        if returned_body && retained_owner.check_open().is_err() {
            if let Ok(object) = &result {
                if let Ok(body) = Reflect::get(object, &JsValue::from_str("body")) {
                    if !body.is_null() && !body.is_undefined() {
                        if let Ok(reader) = crate::direct_digest::Reader::new(body) {
                            drop(reader);
                        }
                    }
                }
            }
        }
        // Resource destruction happens only after the real promise resolves.
        // A rejection still leaves the durable mutation's unknown fence intact.
        drop(retained_owner);
    });

    let raw_now = u64::try_from(aos_hub_core::clock::now_unix_secs())?;
    let remaining = effect
        .expires_at
        .checked_sub(effect.clock_uncertainty_seconds)
        .and_then(|deadline| deadline.checked_sub(raw_now))
        .filter(|seconds| *seconds > 0)
        .context("original OCI SDK cutoff expired")?;
    let timer = worker::Delay::from(std::time::Duration::from_secs(remaining));
    let result = match futures_util::future::select(Box::pin(pending), Box::pin(timer)).await {
        futures_util::future::Either::Left((result, _)) => result.map_err(anyhow::Error::msg)?,
        futures_util::future::Either::Right(_) => {
            anyhow::bail!("OCI SDK outcome remains unknown after cutoff")
        }
    };
    // Attach a returned GET body before a stale result can be rejected.
    let reader = if returned_body {
        let body = Reflect::get(&result, &JsValue::from_str("body"))
            .map_err(|_| anyhow::anyhow!("OCI SDK body unavailable"))?;
        Some(owner.attach(crate::direct_digest::Reader::new(body)?)?)
    } else {
        None
    };
    owner.check_open()?;
    check()?;
    Ok(Acknowledged {
        value: result,
        reader,
        hold: scope,
    })
}

pub(crate) fn multipart(bucket: &JsValue, key: &str, upload: &str) -> Result<JsValue> {
    crate::surface::resume_r2_multipart(bucket, key, upload)
}

pub(crate) fn text(object: &JsValue, field: &str) -> Result<String> {
    Reflect::get(object, &JsValue::from_str(field))
        .ok()
        .and_then(|value| value.as_string())
        .filter(|value| !value.is_empty())
        .context("OCI SDK returned no upload identity")
}
