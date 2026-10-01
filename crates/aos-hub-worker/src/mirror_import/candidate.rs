//! Raw protected material for an isolated source-built mirror experiment.
//!
//! This authority is compiled only into the controlled runner. It cannot load
//! production acceptance, address public destinations or qualify hosted R2.

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::{DirectClockPolicy, DirectClockPolicyMode};
use aos_hub_core::mirror_acceptance::mirror_candidate_profile_digest;
use aos_hub_core::mirror_work::MirrorOriginal;
use worker::{Env, Method, Request, Response};

use crate::direct_upload::config;

pub(crate) struct CandidateMirrorAuthority {
    profile_digest: String,
    observed_at: i64,
    uncertainty: u64,
}

impl CandidateMirrorAuthority {
    pub(crate) fn latest_now(&self) -> Result<u64> {
        let now = aos_hub_core::clock::now_unix_secs();
        ensure!(now >= self.observed_at, "mirror candidate clock regressed");
        Ok(u64::try_from(now)?
            .checked_add(self.uncertainty)
            .ok_or_else(|| anyhow::anyhow!("mirror candidate clock overflow"))?)
    }

    /// Reports the exact raw bounded clock selected for this experiment.
    pub(crate) fn uncertainty_seconds(&self) -> u64 {
        self.uncertainty
    }

    pub(crate) fn profile_digest(&self) -> &str {
        &self.profile_digest
    }
}

pub(crate) fn load(env: &Env, original: &MirrorOriginal) -> Result<CandidateMirrorAuthority> {
    load_profile(env, &original.protected_profile_digest)
}

pub(crate) fn load_profile(env: &Env, expected_profile: &str) -> Result<CandidateMirrorAuthority> {
    let source = option_env!("AOS_HUB_WORKER_SOURCE_DIGEST")
        .filter(|source| aos_hub_core::direct_upload::valid_direct_digest(source))
        .ok_or_else(|| anyhow::anyhow!("source-built mirror candidate identity absent"))?;
    ensure!(
        env.var("HUB_MIRROR_CANDIDATE_SOURCE_SHA256")?.to_string() == source
            && env.var("HUB_MIRROR_CANDIDATE_SCRIPT_VERSION")?.to_string()
                == config::runtime_script_version(env)?,
        "mirror candidate differs from the selected source-built script"
    );
    let uncertainty = config::integer(env, "HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS")?;
    let clock = DirectClockPolicy {
        version: 1,
        mode: DirectClockPolicyMode::BoundedUtc,
        uncertainty_seconds: uncertainty,
    };
    ensure!(
        (1..30).contains(&uncertainty.get())
            && env.var("HUB_DIRECT_UPLOAD_CLOCK_MODE")?.to_string() == "bounded_utc"
            && env
                .var("HUB_DIRECT_UPLOAD_CLOCK_QUALIFICATION")?
                .to_string()
                == clock.commitment()?,
        "mirror candidate actual clock projection differs"
    );
    let (raw, _) = config::managed_descriptor(env, &clock.commitment()?, uncertainty.get())?;
    let policy = config::managed_policy(env)?;
    let profile_digest = mirror_candidate_profile_digest(&raw, &policy)?;
    ensure!(
        expected_profile == profile_digest,
        "mirror candidate original differs from actual protected material"
    );
    crate::direct_upload::provider_capacity::configure(4)?;
    Ok(CandidateMirrorAuthority {
        profile_digest,
        observed_at: aos_hub_core::clock::now_unix_secs(),
        uncertainty: uncertainty.get(),
    })
}

pub(crate) fn key(env: &Env) -> Result<aos_hub_core::storage_work::StorageWorkKey> {
    let secret = env.secret("HUB_MIRROR_CANDIDATE_KEY")?.to_string();
    ensure!(
        secret != env.secret("HUB_STORAGE_WORK_KEY")?.to_string(),
        "candidate authority must differ from production work authority"
    );
    Ok(aos_hub_core::storage_work::StorageWorkKey::new(secret)?)
}

pub(crate) async fn fetch(mut request: Request, env: &Env) -> worker::Result<Response> {
    match execute(&mut request, env).await {
        Ok(response) => Ok(response),
        Err(error) => {
            worker::console_error!("mirror_candidate_refused: {error:#}");
            Response::error("controlled mirror plan unavailable or unsettled", 409)
        }
    }
}

async fn execute(request: &mut Request, env: &Env) -> Result<Response> {
    ensure!(
        request.method() == Method::Post,
        "mirror candidate requires POST"
    );
    let signature = request
        .headers()
        .get(aos_hub_core::storage_work::STORAGE_WORK_SIGNATURE_HEADER)?
        .ok_or_else(|| anyhow::anyhow!("mirror candidate signature absent"))?;
    let body = crate::hybrid::read_bounded_body(request, 256 * 1024)
        .await?
        .ok_or_else(|| anyhow::anyhow!("mirror candidate control exceeds bound"))?;
    let plan = aos_hub_core::mirror_candidate::verify_mirror_candidate_plan(
        &key(env)?,
        &signature,
        &body,
        &env.var("HUB_DEPLOYMENT_ID")?.to_string(),
        aos_hub_core::clock::now_unix_secs(),
    )?;
    let original = match &plan.operation {
        aos_hub_core::storage_work::StorageWorkOperation::MirrorTransfer { original, .. } => {
            original
        }
        aos_hub_core::storage_work::StorageWorkOperation::MirrorTransferBatch { items } => {
            &items
                .first()
                .ok_or_else(|| anyhow::anyhow!("mirror candidate batch is empty"))?
                .original
        }
        _ => anyhow::bail!("mirror candidate operation changed"),
    };
    load(env, original)?.latest_now()?;
    let interval = crate::direct_upload::provider_capacity::observe_interval()?;
    let buffers = super::buffers::observe_interval();
    let result = if matches!(
        plan.operation,
        aos_hub_core::storage_work::StorageWorkOperation::MirrorTransferBatch { .. }
    ) {
        super::batch::execute(env, &plan, &body, &signature, true).await?
    } else {
        let (progress, source_bytes) =
            super::runtime::dispatch_candidate(env, &plan, &body, &signature).await?;
        crate::surface::storage_work_result(
            &plan,
            aos_hub_core::storage_work::StorageWorkOutcome::MirrorProgress { progress },
            source_bytes,
        )
    };
    let bytes = serde_json::to_vec(&result)?;
    ensure!(
        bytes.len() <= 256 * 1024,
        "mirror candidate result exceeds bound"
    );
    let headers = worker::Headers::new();
    headers.set("content-type", "application/json")?;
    headers.set("cache-control", "private, no-store")?;
    headers.set(
        "x-aos-mirror-candidate-capacity",
        &serde_json::to_string(&interval.finish())?,
    )?;
    headers.set(
        "x-aos-mirror-candidate-buffers",
        &serde_json::to_string(&buffers.finish())?,
    )?;
    Ok(Response::from_bytes(bytes)?.with_headers(headers))
}
