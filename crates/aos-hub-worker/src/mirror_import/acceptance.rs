//! Requires independently accepted mirror measurements before production effects.
//!
//! Acceptance is installed separately from the measured script. Missing or
//! foreign-purpose artifacts refuse dispatch; there is no candidate fallback.
//! A controlled evidence producer must use its separate closed fixture route.

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::{valid_direct_digest, DirectProtectedProfile};
use aos_hub_core::mirror_acceptance::{
    mirror_acceptance_key, MirrorAcceptanceArtifact, MIRROR_ACCEPTANCE_MAX_BYTES,
};
use aos_hub_core::mirror_work::{MirrorOriginal, MirrorVerification};
use worker::Env;

/// Retains verified review time bounds for the final provider callback.
pub(crate) struct AcceptedMirror {
    artifact: MirrorAcceptanceArtifact,
}

impl AcceptedMirror {
    pub(crate) fn check(&self, latest_now: u64) -> Result<()> {
        self.artifact.validate_dispatch_time(latest_now)
    }
}

pub(crate) async fn require(
    env: &Env,
    profile: &DirectProtectedProfile,
    direct_evidence: &str,
    original: &MirrorOriginal,
) -> Result<AcceptedMirror> {
    ensure!(
        !cfg!(feature = "do-e2e"),
        "controlled mirror runner cannot admit production"
    );
    original.validate()?;
    ensure!(
        original.protected_profile_digest == profile.digest()?,
        "mirror original managed profile changed"
    );
    let DirectProtectedProfile::Managed {
        profile: managed, ..
    } = profile
    else {
        anyhow::bail!("mirror production requires managed profile");
    };

    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let source = option_env!("AOS_HUB_WORKER_SOURCE_DIGEST")
        .filter(|source| valid_direct_digest(source))
        .ok_or_else(|| anyhow::anyhow!("hermetic mirror source identity absent"))?;
    let script = crate::direct_upload::config::runtime_script_version(env)?;
    let key = mirror_acceptance_key(&deployment, source, &script)?;
    let raw = env
        .kv("HUB_MIRROR_ACCEPTANCE")?
        .get(&key)
        .text()
        .await?
        .ok_or_else(|| anyhow::anyhow!("measured mirror acceptance absent"))?;
    ensure!(
        raw.len() <= MIRROR_ACCEPTANCE_MAX_BYTES,
        "mirror acceptance exceeds bound"
    );
    let artifact: MirrorAcceptanceArtifact =
        serde_json::from_str(&raw).map_err(|_| anyhow::anyhow!("mirror acceptance malformed"))?;
    let now = u64::try_from(aos_hub_core::clock::now_unix_secs())?
        .checked_add(managed.clock_uncertainty_seconds.get())
        .ok_or_else(|| anyhow::anyhow!("mirror qualified clock overflow"))?;
    artifact.require_production(
        &deployment,
        &env.var("HUB_DIRECT_UPLOAD_PUBLIC_ORIGIN")?.to_string(),
        source,
        &script,
        profile,
        direct_evidence,
        &env.var("HUB_MIRROR_QUALIFICATION_PUBLIC_KEY")?.to_string(),
        now,
    )?;
    let maximum = match &original.verification {
        MirrorVerification::Nar { nar_size, .. } => original.verification.size().max(*nar_size),
        _ => original.verification.size(),
    };
    ensure!(
        maximum <= artifact.maximum_object_bytes,
        "mirror original exceeds measured workflow ceiling"
    );
    Ok(AcceptedMirror { artifact })
}
