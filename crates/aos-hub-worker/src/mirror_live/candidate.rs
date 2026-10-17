//! Separately compiled, fixture-only execution of the real live stream path.
//!
//! No production acceptance or Native IAM is fabricated. The dedicated key
//! authenticates only reserved controlled source requests; this route never
//! writes a provider object or grants public ingress authority.

pub(crate) mod query;

use anyhow::{ensure, Result};
use aos_hub_core::hybrid_ingress::live::candidate::{
    verify_mirror_live_candidate, LIVE_CANDIDATE_CONTROL_BYTES,
};
use worker::{Env, Method, Request, Response};

pub(crate) async fn fetch(mut request: Request, env: &Env) -> worker::Result<Response> {
    match execute(&mut request, env).await {
        Ok(response) => Ok(response),
        Err(_) => Response::error("controlled live delivery refused", 409),
    }
}

async fn execute(request: &mut Request, env: &Env) -> Result<Response> {
    ensure!(
        request.method() == Method::Post && !request.headers().has("range")?,
        "controlled live request method or range refused"
    );
    let key = crate::mirror_import::candidate::key(env)?;
    ensure!(
        env.secret("HUB_MIRROR_CANDIDATE_KEY")?.to_string()
            != env.secret("HUB_HYBRID_INGRESS_KEY")?.to_string(),
        "controlled live authority must differ from production ingress"
    );
    let signature = request
        .headers()
        .get(aos_hub_core::storage_work::STORAGE_WORK_SIGNATURE_HEADER)?
        .ok_or_else(|| anyhow::anyhow!("controlled live signature missing"))?;
    let body = crate::hybrid::read_bounded_body(request, LIVE_CANDIDATE_CONTROL_BYTES)
        .await?
        .ok_or_else(|| anyhow::anyhow!("controlled live control exceeds bound"))?;
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let original = verify_mirror_live_candidate(
        &key,
        &signature,
        &body,
        &deployment,
        aos_hub_core::clock::now_unix_secs(),
    )?;
    ensure!(
        original.compiled_source_sha256
            == option_env!("AOS_HUB_WORKER_SOURCE_DIGEST").unwrap_or("")
            && original.script_version
                == crate::direct_upload::config::runtime_script_version(env)?,
        "controlled live source or script differs"
    );
    let authority = crate::mirror_import::candidate::load_profile(
        env,
        &original.target.protected_profile_digest,
    )?;
    let uncertainty = authority.uncertainty_seconds();
    let before_dispatch = || -> Result<()> {
        original.validate(&deployment, i64::try_from(authority.latest_now()?)?)?;
        Ok(())
    };
    let cutoff = original
        .request
        .issued_at
        .checked_add(super::LIVE_STREAM_SECONDS)
        .ok_or_else(|| anyhow::anyhow!("controlled stream cutoff overflow"))?;
    let response = super::stream_source(
        original.target.clone(),
        if original.request.method == "HEAD" {
            Method::Head
        } else {
            Method::Get
        },
        cutoff,
        uncertainty,
        original.target.maximum_bytes,
        request.inner().signal(),
        &before_dispatch,
    )
    .await?;
    Ok(response)
}
