//! Fixture-only authentication around the production bounded query executor.
//!
//! The route has no accepted-runtime flag, production reviewer signature or
//! destination writer. Its fresh control binds actual installed source, script,
//! raw profile and the reserved run namespace before the common source read.

use anyhow::{ensure, Result};
use aos_hub_core::hybrid_ingress::live::candidate::query::{
    sign_mirror_live_query_candidate_reply, verify_mirror_live_query_candidate,
    MirrorLiveQueryCandidateReply,
};
use aos_hub_core::storage_work::{StorageWorkKey, STORAGE_WORK_SIGNATURE_HEADER};
use worker::{Env, Method, Request, Response};

pub(crate) async fn fetch(mut request: Request, env: &Env) -> worker::Result<Response> {
    match execute(&mut request, env).await {
        Ok(response) => Ok(response),
        Err(_) => Response::error("controlled live query refused", 409),
    }
}

async fn execute(request: &mut Request, env: &Env) -> Result<Response> {
    ensure!(
        request.method() == Method::Post && !request.headers().has("range")?,
        "controlled query method or range refused"
    );
    let material = env
        .secret("HUB_MIRROR_LIVE_QUERY_CANDIDATE_KEY")?
        .to_string();
    for other in [
        "HUB_MIRROR_CANDIDATE_KEY",
        "HUB_STORAGE_WORK_KEY",
        "HUB_HYBRID_INGRESS_KEY",
    ] {
        ensure!(
            material != env.secret(other)?.to_string(),
            "controlled query key role reused"
        );
    }
    let key = StorageWorkKey::new(material)?;
    let signature = request
        .headers()
        .get(STORAGE_WORK_SIGNATURE_HEADER)?
        .ok_or_else(|| anyhow::anyhow!("controlled query signature missing"))?;
    let body = crate::hybrid::read_bounded_body(
        request,
        aos_hub_core::hybrid_ingress::live::candidate::LIVE_CANDIDATE_CONTROL_BYTES,
    )
    .await?
    .ok_or_else(|| anyhow::anyhow!("controlled query request exceeds bound"))?;
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let original = verify_mirror_live_query_candidate(
        &key,
        &signature,
        &body,
        &deployment,
        aos_hub_core::clock::now_unix_secs(),
    )?;
    let candidate = &original.candidate;
    ensure!(
        candidate.compiled_source_sha256
            == option_env!("AOS_HUB_WORKER_SOURCE_DIGEST").unwrap_or("")
            && candidate.script_version
                == crate::direct_upload::config::runtime_script_version(env)?,
        "controlled query installed source differs"
    );
    let authority = crate::mirror_import::candidate::load_profile(
        env,
        &candidate.target.protected_profile_digest,
    )?;
    let before_dispatch = || -> Result<()> {
        original.validate(&deployment, i64::try_from(authority.latest_now()?)?)
    };
    let cutoff = candidate
        .request
        .issued_at
        .checked_add(super::super::LIVE_STREAM_SECONDS)
        .ok_or_else(|| anyhow::anyhow!("controlled query cutoff overflow"))?;
    let (outcome, source_bytes) = super::super::query_source(
        &candidate.target,
        cutoff,
        authority.uncertainty_seconds(),
        candidate.target.maximum_bytes,
        &before_dispatch,
        &|| authority.latest_now(),
    )
    .await?;
    let reply = MirrorLiveQueryCandidateReply {
        version: 1,
        request_sha256: aos_hub_core::mirror_work::digest(&original)?,
        nonce: original.nonce.clone(),
        observed_at: i64::try_from(authority.latest_now()?)?,
        outcome,
        source_bytes,
    };
    let signature = sign_mirror_live_query_candidate_reply(&key, &original, &reply)?;
    let response = Response::from_json(&reply)?;
    response
        .headers()
        .set(STORAGE_WORK_SIGNATURE_HEADER, &signature)?;
    Ok(response)
}
