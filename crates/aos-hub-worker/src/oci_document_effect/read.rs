//! Bounded staging reads owned by the original document effect lifetime.

use anyhow::{Context as _, Result};
use aos_hub_core::hybrid_ingress::{OciDocumentEffect, MAX_HYBRID_OCI_MANIFEST_BYTES};
use std::rc::Rc;
use wasm_bindgen::JsValue;

use super::sdk::{self, Retainer};

pub(crate) async fn staged_document(
    env: &worker::Env,
    context: &worker::Context,
    key: &str,
    effect: &OciDocumentEffect,
    accepted: &crate::oci_sdk_emulation::OciProviderConfig,
    memory: Rc<crate::mirror_import::buffers::Permit>,
) -> Result<Vec<u8>> {
    let check = || accepted.check_effect(env, effect);
    let bucket = crate::direct_upload::managed::bucket(env)?;
    let result = sdk::invoke(
        Retainer::Request(context),
        memory,
        &bucket,
        "get",
        &[JsValue::from_str(key)],
        effect,
        &check,
    )
    .await?;
    let owner = &result.hold.0;
    let reader = result
        .reader
        .as_ref()
        .context("staged OCI document body unavailable")?;
    let identity = crate::direct_upload::managed::identity(&result.value)?;
    anyhow::ensure!(
        identity.byte_size.get() > 0
            && identity.byte_size.get() <= MAX_HYBRID_OCI_MANIFEST_BYTES as u64,
        "staged OCI document exceeds its shared bound"
    );

    let mut bytes = Vec::new();
    loop {
        check()?;
        let raw_now = u64::try_from(aos_hub_core::clock::now_unix_secs())?;
        let seconds = effect
            .expires_at
            .checked_sub(effect.clock_uncertainty_seconds)
            .and_then(|deadline| deadline.checked_sub(raw_now))
            .filter(|seconds| *seconds > 0)
            .context("original OCI read cutoff expired")?;
        let timer = worker::Delay::from(std::time::Duration::from_secs(seconds));
        let (view, done) =
            match futures_util::future::select(Box::pin(reader.read()), Box::pin(timer)).await {
                futures_util::future::Either::Left((read, _)) => read?,
                futures_util::future::Either::Right(_) => {
                    anyhow::bail!("original OCI read cutoff expired")
                }
            };
        owner.check_open()?;
        check()?;
        anyhow::ensure!(
            bytes
                .len()
                .checked_add(view.length() as usize)
                .is_some_and(|size| size <= MAX_HYBRID_OCI_MANIFEST_BYTES),
            "staged OCI document exceeds its shared bound"
        );
        bytes.extend_from_slice(&view.to_vec());
        if done {
            break;
        }
    }
    anyhow::ensure!(
        bytes.len() as u64 == identity.byte_size.get(),
        "staged OCI document size differs from its SDK receipt"
    );
    Ok(bytes)
}
