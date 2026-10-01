//! Independent ordered guard batches relayed to the actual held per-key journals.
//!
//! Every physical guard authenticates the complete original outer request and
//! its selected index. The edge verifies real physical observations before
//! signing an ordered response; a refused read creates no settlement or effect.

use anyhow::{ensure, Result};
use aos_hub_core::{
    mirror_guard::{
        batch::*, MirrorGuardExecution, SignedMirrorGuardControl, MIRROR_GUARD_MAX_BYTES,
        MIRROR_GUARD_SIGNATURE_HEADER,
    },
    mirror_work::digest,
};
use futures_util::{stream, StreamExt as _};
use sha2::{Digest as _, Sha256};
use worker::{Env, Headers, Method, Request, RequestInit, Response};

use super::{issuer, key, latest_now};
use crate::{direct_upload::config, hybrid_object::HybridObjectGuard};

pub(crate) const PHYSICAL_PATH: &str = "/mirror-final-guard-batch";
pub(crate) const CANDIDATE_PHYSICAL_PATH: &str = "/mirror-candidate-final-guard-batch";
const ITEM_INDEX_HEADER: &str = "x-aos-mirror-guard-item-index";

async fn authenticate(
    request: &mut Request,
    env: &Env,
    candidate: bool,
) -> Result<(MirrorGuardBatchLookup, Vec<u8>, String)> {
    ensure!(
        request.method() == Method::Post,
        "mirror guard batch requires POST"
    );
    ensure!(
        !candidate || cfg!(feature = "do-e2e"),
        "controlled guard batch absent from production"
    );
    let signature = request
        .headers()
        .get(MIRROR_GUARD_SIGNATURE_HEADER)?
        .ok_or_else(|| anyhow::anyhow!("mirror guard batch signature absent"))?;
    let body = crate::hybrid::read_bounded_body(request, MIRROR_GUARD_MAX_BYTES)
        .await?
        .ok_or_else(|| anyhow::anyhow!("mirror guard batch exceeds control bound"))?;
    let lookup = verify_mirror_guard_batch_lookup(
        &key(env)?,
        &signature,
        &body,
        &env.var("HUB_DEPLOYMENT_ID")?.to_string(),
        latest_now(env)?,
    )?;
    let execution = if candidate {
        MirrorGuardExecution::ControlledCandidate
    } else {
        MirrorGuardExecution::Hosted
    };
    ensure!(
        lookup.execution == execution
            && lookup.issuer == issuer(env)?
            && lookup.clock_uncertainty_seconds
                == config::integer(env, "HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS")?.get(),
        "mirror guard batch issuer, execution or clock differs"
    );
    Ok((lookup, body, signature))
}

/// Relays an independently authenticated phase batch with bounded physical reads.
pub(crate) async fn fetch(
    mut request: Request,
    env: &Env,
    candidate: bool,
) -> worker::Result<Response> {
    match relay(&mut request, env, candidate).await {
        Ok((signed, body)) => {
            let response = response(signed)?;
            if !candidate {
                crate::control_receipt::emit_buffered_response(
                    MIRROR_GUARD_BATCH_LOOKUP_PATH,
                    &body,
                    &response,
                )
                .await;
            }
            Ok(response)
        }
        Err(_) => Response::error("mirror final guard batch unavailable", 409),
    }
}

async fn relay(
    request: &mut Request,
    env: &Env,
    candidate: bool,
) -> Result<(SignedMirrorGuardControl, Vec<u8>)> {
    let (lookup, body, signature) = authenticate(request, env, candidate).await?;
    let observations = stream::iter(0..lookup.items.len())
        .map(|index| relay_one(env, &lookup, &body, &signature, index, candidate))
        .buffered(8)
        .collect::<Vec<_>>()
        .await;
    let mut results = Vec::with_capacity(observations.len());
    for (index, observation) in observations.into_iter().enumerate() {
        results.push(match observation {
            Ok(observation) => observation.result,
            Err(_) => MirrorGuardBatchResult::Refused {
                original_digest: digest(&lookup.items[index].original)?,
                refusal: MirrorGuardBatchRefusal::Unavailable,
            },
        });
    }
    let observed_at = latest_now(env)?;
    lookup.validate(&env.var("HUB_DEPLOYMENT_ID")?.to_string(), observed_at)?;
    let reply = MirrorGuardBatchReply {
        version: 1,
        request_digest: digest(&lookup)?,
        request_nonce: lookup.request_nonce.clone(),
        issuer: issuer(env)?,
        results,
        observed_at,
    };
    let signed = sign_mirror_guard_batch_reply(&key(env)?, &reply, &lookup)?;
    Ok((signed, body))
}

async fn relay_one(
    env: &Env,
    lookup: &MirrorGuardBatchLookup,
    body: &[u8],
    signature: &str,
    index: usize,
    candidate: bool,
) -> Result<MirrorGuardBatchObservation> {
    let item = &lookup.items[index];
    let full_key =
        aos_hub_core::keymap::r2_key(&item.original.placement_prefix, &item.original.path);
    let address = format!(
        "{}:{}",
        lookup.deployment_id,
        hex::encode(Sha256::digest(&full_key))
    );
    let headers = Headers::new();
    headers.set(MIRROR_GUARD_SIGNATURE_HEADER, signature)?;
    headers.set(ITEM_INDEX_HEADER, &index.to_string())?;
    headers.set("x-aos-hybrid-object-key", &full_key)?;
    let path = if candidate {
        CANDIDATE_PHYSICAL_PATH
    } else {
        PHYSICAL_PATH
    };
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(js_sys::Uint8Array::from(body).into()));
    let internal = Request::new_with_init(&format!("https://physical-guard{path}"), &init)?;
    lookup.validate(&lookup.deployment_id, latest_now(env)?)?;
    let result = env
        .durable_object("HYBRID_OBJECT_GUARD")?
        .id_from_name(&address)?
        .get_stub()?
        .fetch_with_request(internal)
        .await?;
    ensure!(
        result.status_code() == 200,
        "mirror selected guard read refused"
    );
    let signature = result
        .headers()
        .get(MIRROR_GUARD_SIGNATURE_HEADER)?
        .ok_or_else(|| anyhow::anyhow!("mirror selected guard authentication absent"))?;
    let body = crate::hybrid::read_bounded_response(result, MIRROR_GUARD_MAX_BYTES)
        .await?
        .ok_or_else(|| anyhow::anyhow!("mirror selected guard response exceeds bound"))?;
    verify_mirror_guard_batch_observation(
        &key(env)?,
        &signature,
        &body,
        lookup,
        index,
        latest_now(env)?,
    )
}

/// Reads an exact selected held original while the existing per-key gate is held.
pub(crate) async fn physical_fetch(
    guard: &HybridObjectGuard,
    physical_key: &str,
    request: &mut Request,
    candidate: bool,
) -> worker::Result<Response> {
    match retained_observation(guard, physical_key, request, candidate).await {
        Ok(signed) => response(signed),
        Err(_) => Response::error("mirror selected final guard unavailable", 409),
    }
}

async fn retained_observation(
    guard: &HybridObjectGuard,
    physical_key: &str,
    request: &mut Request,
    candidate: bool,
) -> Result<SignedMirrorGuardControl> {
    let index = request
        .headers()
        .get(ITEM_INDEX_HEADER)?
        .ok_or_else(|| anyhow::anyhow!("mirror guard selected index absent"))?;
    let selected = index.parse::<usize>()?;
    ensure!(
        index == selected.to_string(),
        "mirror guard selected index noncanonical"
    );
    let (lookup, _, _) = authenticate(request, &guard.env, candidate).await?;
    let item = lookup
        .items
        .get(selected)
        .ok_or_else(|| anyhow::anyhow!("mirror guard selected item absent"))?;
    ensure!(
        aos_hub_core::keymap::r2_key(&item.original.placement_prefix, &item.original.path)
            == physical_key,
        "mirror guard selected physical key differs"
    );
    let retained = super::super::runtime::retained_final(guard, physical_key).await;
    let observed_at = latest_now(&guard.env)?;
    lookup.validate(
        &guard.env.var("HUB_DEPLOYMENT_ID")?.to_string(),
        observed_at,
    )?;
    let result = match retained {
        Ok((original, progress)) if original == item.original && progress == item.expected => {
            MirrorGuardBatchResult::Positive {
                original_digest: digest(&original)?,
                progress,
                observed_at,
            }
        }
        _ => MirrorGuardBatchResult::Refused {
            original_digest: digest(&item.original)?,
            refusal: MirrorGuardBatchRefusal::Unavailable,
        },
    };
    let observation = MirrorGuardBatchObservation {
        version: 1,
        request_digest: digest(&lookup)?,
        request_nonce: lookup.request_nonce.clone(),
        issuer: issuer(&guard.env)?,
        item_index: selected,
        result,
        observed_at,
    };
    sign_mirror_guard_batch_observation(&key(&guard.env)?, &observation, &lookup)
}

fn response(signed: SignedMirrorGuardControl) -> worker::Result<Response> {
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    headers.set("cache-control", "private, no-store")?;
    headers.set(MIRROR_GUARD_SIGNATURE_HEADER, &signed.signature)?;
    Ok(Response::from_bytes(signed.body)?.with_headers(headers))
}
