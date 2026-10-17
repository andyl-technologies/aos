//! Do-e2e-only loading of the distinct External Mirror functional statement.
//!
//! This loader never reads Hosted or Managed candidate acceptance slots. The
//! unchanged Direct loader supplies the genuine current External prerequisite;
//! the independent Mirror reviewer supplies finite functional probe authority.

use anyhow::{Context as _, Result, ensure};
use aos_hub_core::{
    direct_upload::{DirectProtectedProfile, valid_direct_digest},
    mirror_acceptance::external_controlled::{
        ControlledExternalMirrorArtifact, controlled_external_mirror_key,
        require_distinct_external_mirror_reviewer, CONTROLLED_EXTERNAL_MIRROR_MAX_BYTES,
    },
};
use worker::Env;

use super::{AcceptedMirror, Review, profile_latest_now};

pub(super) async fn load(
    env: &Env,
    profile: &DirectProtectedProfile,
    evidence: &str,
) -> Result<AcceptedMirror> {
    ensure!(
        env.var("HUB_EXTERNAL_MIRROR_FUNCTIONAL_PROBE")?.to_string() == "1"
            && matches!(profile, DirectProtectedProfile::External { .. }),
        "controlled External Mirror requires explicit local selection and actual External prerequisite"
    );
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let origin = env.var("HUB_DIRECT_UPLOAD_PUBLIC_ORIGIN")?.to_string();
    let source = option_env!("AOS_HUB_WORKER_SOURCE_DIGEST")
        .filter(|source| valid_direct_digest(source))
        .context("compiled functional Mirror source identity absent")?;
    let script = crate::direct_upload::config::runtime_script_version(env)?;
    let reviewer = env
        .var("HUB_EXTERNAL_MIRROR_FUNCTIONAL_REVIEWER_PUBLIC_KEY")?
        .to_string();
    require_distinct_external_mirror_reviewer(
        &reviewer,
        &env.var("HUB_DIRECT_UPLOAD_QUALIFICATION_PUBLIC_KEY")?
            .to_string(),
    )?;
    if let Ok(hosted) = env.var("HUB_MIRROR_QUALIFICATION_PUBLIC_KEY") {
        require_distinct_external_mirror_reviewer(&reviewer, &hosted.to_string())?;
    }
    let address = controlled_external_mirror_key(&deployment, source, &script, profile)?;
    let raw = env
        .kv("HUB_EXTERNAL_MIRROR_FUNCTIONAL_ACCEPTANCE")?
        .get(&address)
        .text()
        .await?
        .context("controlled External Mirror statement not installed")?;
    ensure!(
        raw.len() <= CONTROLLED_EXTERNAL_MIRROR_MAX_BYTES,
        "controlled Mirror statement exceeds bound"
    );
    let artifact: ControlledExternalMirrorArtifact = serde_json::from_str(&raw)?;
    ensure!(
        artifact.reviewer_key_id
            == env
                .var("HUB_EXTERNAL_MIRROR_FUNCTIONAL_REVIEWER_KEY_ID")?
                .to_string(),
        "controlled Mirror reviewer identity differs from initial selection"
    );
    artifact.require_current(
        &deployment,
        &origin,
        source,
        &script,
        profile,
        evidence,
        &reviewer,
        profile_latest_now(profile)?,
    )?;
    Ok(AcceptedMirror {
        artifact: Review::Controlled(artifact),
        pack: None,
    })
}
