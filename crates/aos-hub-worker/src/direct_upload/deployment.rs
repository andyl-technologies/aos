//! Fresh protected discovery of actual bindings before signed KV activation.
//!
//! This endpoint resolves real credential material and hosted metadata, but
//! performs no provider mutation and supplies no acceptance authority.

use anyhow::{ensure, Result};
use aos_hub_core::{direct_upload::*, storage_work::StorageWorkKey};
use worker::{Env, Headers, Method, Request, Response};

use super::config;

pub(crate) async fn fetch(mut request: Request, env: &Env) -> worker::Result<Response> {
    match discover(&mut request, env).await {
        Ok(response) => Ok(response),
        Err(_) => Response::error("direct deployment discovery refused", 409),
    }
}

async fn discover(request: &mut Request, env: &Env) -> Result<Response> {
    ensure!(
        request.method() == Method::Post,
        "direct deployment discovery method invalid"
    );
    let signature = request
        .headers()
        .get(DIRECT_WORKER_DEPLOYMENT_SIGNATURE_HEADER)?
        .ok_or_else(|| anyhow::anyhow!("direct deployment challenge authentication absent"))?;
    let body = crate::hybrid::read_bounded_body(request, MAX_DIRECT_CONTROL_BYTES)
        .await?
        .ok_or_else(|| anyhow::anyhow!("direct deployment challenge exceeds bound"))?;
    let secret = env.secret("HUB_DIRECT_UPLOAD_GUARD_KEY")?.to_string();
    for other in ["HUB_STORAGE_WORK_KEY", "HUB_DIRECT_UPLOAD_JOURNAL_KEY"] {
        ensure!(
            secret != env.secret(other)?.to_string(),
            "direct discovery guard key must be independent"
        );
    }
    let key = StorageWorkKey::new(secret)?;
    let now = u64::try_from(aos_hub_core::clock::now_unix_secs())?;
    let challenge = verify_direct_worker_deployment_request(&key, &signature, &body, now)?;
    let clock = env
        .var("HUB_DIRECT_UPLOAD_CLOCK_QUALIFICATION")?
        .to_string();
    let uncertainty = config::integer(env, "HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS")?;
    ensure!(
        env.var("HUB_DIRECT_UPLOAD_CLOCK_MODE")?.to_string() == "bounded_utc",
        "direct actual clock mode unsupported"
    );
    let clock_policy = DirectClockPolicy {
        version: 1,
        mode: DirectClockPolicyMode::BoundedUtc,
        uncertainty_seconds: uncertainty,
    };
    ensure!(
        clock == clock_policy.commitment()? && (1..30).contains(&uncertainty.get()),
        "direct actual clock projection invalid"
    );

    let managed = env.var("HUB_DIRECT_UPLOAD_MANAGED_R2")?.to_string() == "true";
    ensure!(
        !managed || !cfg!(feature = "do-e2e"),
        "emulated deployment cannot qualify managed R2"
    );
    let managed_profile = if managed {
        Some(config::managed_descriptor(env, &clock, uncertainty.get())?.0)
    } else {
        None
    };
    let private_stage_policy = if managed {
        Some(config::managed_policy(env)?)
    } else {
        None
    };
    let external_profiles =
        crate::external_object::resolve_external_profiles(env, &challenge.external_selectors)
            .await?;
    ensure!(
        u64::try_from(aos_hub_core::clock::now_unix_secs())? < challenge.expires_at.get(),
        "direct discovery expired during actual resolution"
    );
    let identity = DirectWorkerDeploymentIdentity {
        version: 1,
        deployment_id: env.var("HUB_DEPLOYMENT_ID")?.to_string(),
        public_origin: env.var("HUB_DIRECT_UPLOAD_PUBLIC_ORIGIN")?.to_string(),
        source_digest: option_env!("AOS_HUB_WORKER_SOURCE_DIGEST")
            .filter(|source| valid_direct_digest(source))
            .ok_or_else(|| anyhow::anyhow!("hermetic Worker source identity absent"))?
            .into(),
        script_version: config::runtime_script_version(env)?,
        qualification_public_key: env
            .var("HUB_DIRECT_UPLOAD_QUALIFICATION_PUBLIC_KEY")?
            .to_string(),
        clock_qualification: clock,
        clock_mode: clock_policy.mode,
        clock_uncertainty_seconds: uncertainty,
        managed_profile,
        private_stage_policy,
        external_profiles,
        bulk_queue: env.var("HUB_DIRECT_VERIFY_BULK_NAME")?.to_string(),
        metadata_queue: env.var("HUB_DIRECT_VERIFY_METADATA_NAME")?.to_string(),
        bulk_queue_policy: config::queue_policy(
            env,
            super::verification::BULK_QUEUE,
            config::integer(env, "HUB_DIRECT_VERIFY_MAX_PARALLEL_OBJECTS")?
                .get()
                .saturating_sub(1),
        )?,
        metadata_queue_policy: config::queue_policy(
            env,
            super::verification::METADATA_QUEUE,
            config::integer(env, "HUB_DIRECT_VERIFY_MAX_PARALLEL_OBJECTS")?.get(),
        )?,
        maximum_parallel_objects: config::integer(env, "HUB_DIRECT_VERIFY_MAX_PARALLEL_OBJECTS")?,
        qualification_limits: config::qualification_limits(env)?,
    };
    let signed = sign_direct_worker_deployment_reply(
        &key,
        &DirectWorkerDeploymentReply {
            request: challenge,
            identity,
        },
    )?;
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    headers.set("cache-control", "no-store")?;
    headers.set(DIRECT_WORKER_DEPLOYMENT_SIGNATURE_HEADER, &signed.signature)?;
    Ok(Response::from_bytes(signed.body)?.with_headers(headers))
}
