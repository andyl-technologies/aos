//! Requires independently accepted mirror measurements before production effects.
//!
//! Acceptance is installed separately from the measured script. Missing or
//! foreign-purpose artifacts refuse dispatch; there is no candidate fallback.
//! A controlled evidence producer must use its separate closed fixture route.

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::{valid_direct_digest, DirectProtectedProfile};
use aos_hub_core::mirror_acceptance::pack::{
    mirror_pack_acceptance_key, MirrorPackAcceptanceArtifact, MIRROR_PACK_ACCEPTANCE_MAX_BYTES,
};
use aos_hub_core::mirror_acceptance::{
    mirror_acceptance_key, MirrorAcceptanceArtifact, MIRROR_ACCEPTANCE_MAX_BYTES,
};
use aos_hub_core::mirror_work::{MirrorOriginal, MirrorVerification};
use worker::Env;

/// Retains verified review time bounds for the final provider callback.
#[derive(Clone)]
pub(crate) struct AcceptedMirror {
    artifact: Review,
    pack: Option<MirrorPackAcceptanceArtifact>,
}

#[derive(Clone)]
enum Review {
    Hosted(MirrorAcceptanceArtifact),
    #[cfg(feature = "do-e2e")]
    Controlled(
        aos_hub_core::mirror_acceptance::external_controlled::ControlledExternalMirrorArtifact,
    ),
}

impl AcceptedMirror {
    pub(crate) fn external_window(
        &self,
        domain_digest: &str,
        original: &MirrorOriginal,
    ) -> Result<aos_hub_core::mirror_work::external::journal::MirrorExternalAcceptance> {
        let selected = original
            .external_destination
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("External mirror acceptance has a Managed original"))?;
        let (artifact_digest, issued, until) = match &self.artifact {
            Review::Hosted(artifact) => {
                ensure!(artifact.purpose == aos_hub_core::mirror_acceptance::MirrorAcceptancePurpose::ExternalMirrorV1
                    && artifact.external_domain_sha256.as_deref() == Some(domain_digest),
                    "mirror acceptance differs from its independently installed External domain");
                (
                    aos_hub_core::mirror_work::digest(artifact)?,
                    artifact.issued_at,
                    artifact.valid_until,
                )
            }
            #[cfg(feature = "do-e2e")]
            Review::Controlled(artifact) => {
                artifact.require_original(
                    original,
                    profile_latest_now(
                        &aos_hub_core::direct_upload::DirectProtectedProfile::External {
                            profile: artifact.protected_profile.profile.clone(),
                            runtime_qualification: artifact
                                .protected_profile
                                .runtime_qualification
                                .clone(),
                        },
                    )?,
                )?;
                ensure!(
                    artifact.external_domain_sha256 == domain_digest,
                    "controlled mirror differs from installed transport domain"
                );
                (
                    aos_hub_core::mirror_work::digest(artifact)?,
                    artifact.issued_at,
                    artifact.valid_until,
                )
            }
        };
        let issued_at = issued.max(selected.issued_at);
        let expires_at = until.min(selected.expires_at);
        ensure!(
            issued_at < expires_at,
            "mirror and prerequisite windows do not intersect"
        );
        Ok(
            aos_hub_core::mirror_work::external::journal::MirrorExternalAcceptance {
                artifact_digest,
                issued_at,
                expires_at,
            },
        )
    }

    pub(crate) fn check(&self, latest_now: u64) -> Result<()> {
        match &self.artifact {
            Review::Hosted(artifact) => artifact.validate_dispatch_time(latest_now)?,
            #[cfg(feature = "do-e2e")]
            Review::Controlled(artifact) => artifact.validate_unsigned(latest_now)?,
        }
        if let Some(pack) = &self.pack {
            pack.validate_dispatch_time(latest_now)?;
        }
        Ok(())
    }

    fn maximum_bytes(&self) -> u64 {
        match &self.artifact {
            Review::Hosted(artifact) => artifact.maximum_object_bytes,
            #[cfg(feature = "do-e2e")]
            Review::Controlled(artifact) => artifact.maximum_object_bytes,
        }
    }

    pub(crate) fn require_scope(
        &self,
        binding_id: i64,
        binding_rv: i64,
        prefix: &str,
        upstream: Option<&str>,
    ) -> Result<()> {
        #[cfg(feature = "do-e2e")]
        if let Review::Controlled(artifact) = &self.artifact {
            let selected = &artifact.protected_profile.profile.selector.association;
            ensure!(binding_id == selected.binding_id.get()
                && binding_rv == selected.binding_resource_version.get()
                && ["full", "pull-through"].iter().any(|mode| prefix == format!("{}/{mode}", artifact.placement_prefix))
                && upstream.is_none_or(|base| base == artifact.upstream_base),
                "controlled mirror inspection escaped its actual binding, source or reserved placement");
        }
        #[cfg(not(feature = "do-e2e"))]
        let _ = (binding_id, binding_rv, prefix, upstream);
        Ok(())
    }

    pub(crate) fn require_plan_scope(
        &self,
        plan: &aos_hub_core::storage_work::StorageWorkPlan,
    ) -> Result<()> {
        #[cfg(feature = "do-e2e")]
        if matches!(self.artifact, Review::Controlled(_)) {
            use aos_hub_core::storage_work::StorageWorkOperation as Op;
            let upstream = match &plan.operation {
                Op::InspectMirrorPack { inspection } => Some(inspection.upstream_base.as_str()),
                Op::InspectMirrorMembership { query } => {
                    Some(query.inspection.upstream_base.as_str())
                }
                Op::InspectMirrorTreeInventory { query } => Some(query.source.upstream_base()),
                Op::InspectStoredGitPack { .. } | Op::FilterStoredGitPackTree { .. } => None,
                _ => anyhow::bail!("controlled Mirror inspection operation not admitted"),
            };
            self.require_scope(
                plan.binding_id,
                plan.binding_resource_version,
                &plan.placement_prefix,
                upstream,
            )?;
        }
        #[cfg(not(feature = "do-e2e"))]
        let _ = plan;
        Ok(())
    }
}

/// Retains only the already verified live review's size and immutable window.
pub(crate) struct AcceptedLive {
    pub(crate) maximum_bytes: u64,
    issued_at: u64,
    valid_until: u64,
}

impl AcceptedLive {
    pub(crate) fn validate_dispatch_time(&self, now: u64) -> Result<()> {
        ensure!(
            self.issued_at <= now && now < self.valid_until,
            "live review expired"
        );
        Ok(())
    }
}

pub(crate) async fn require(
    env: &Env,
    profile: &DirectProtectedProfile,
    direct_evidence: &str,
    original: &MirrorOriginal,
) -> Result<AcceptedMirror> {
    original.validate()?;
    ensure!(
        original.protected_profile_digest == profile.digest()?
            && original.external_destination.is_some()
                == matches!(profile, DirectProtectedProfile::External { .. }),
        "mirror original managed profile changed"
    );
    let accepted = require_profile(env, profile, direct_evidence).await?;
    let maximum = match &original.verification {
        MirrorVerification::Nar { nar_size, .. } => original.verification.size().max(*nar_size),
        _ => original.verification.size(),
    };
    ensure!(
        maximum <= accepted.maximum_bytes(),
        "mirror original exceeds measured workflow ceiling"
    );
    #[cfg(feature = "do-e2e")]
    if let Review::Controlled(artifact) = &accepted.artifact {
        artifact.require_original(original, profile_latest_now(profile)?)?;
    }
    Ok(accepted)
}

/// Requires separately measured pack inspection before reading an upstream pair.
/// No publication original or guessed expected encoded SHA is constructed.
pub(crate) async fn require_pack_inspection(
    env: &Env,
    profile: &DirectProtectedProfile,
    direct_evidence: &str,
    maximum_encoded_bytes: u64,
) -> Result<AcceptedMirror> {
    let mut accepted = require_profile(env, profile, direct_evidence).await?;
    #[cfg(feature = "do-e2e")]
    if matches!(accepted.artifact, Review::Controlled(_)) {
        ensure!(
            maximum_encoded_bytes <= accepted.maximum_bytes(),
            "controlled pack exceeds its explicit probe ceiling"
        );
        return Ok(accepted);
    }
    let Review::Hosted(artifact) = &accepted.artifact else {
        anyhow::bail!("production pack review absent");
    };
    let address = match profile {
        DirectProtectedProfile::Managed { .. } => mirror_pack_acceptance_key(
            &artifact.deployment_id,
            &artifact.source_digest,
            &artifact.script_version,
        )?,
        DirectProtectedProfile::External { .. } => {
            aos_hub_core::mirror_acceptance::pack::external_mirror_pack_acceptance_key(
                &aos_hub_core::mirror_work::digest(artifact)?,
            )?
        }
    };
    let raw = env
        .kv("HUB_MIRROR_ACCEPTANCE")?
        .get(&address)
        .text()
        .await?
        .ok_or_else(|| anyhow::anyhow!("measured pack inspection acceptance absent"))?;
    ensure!(
        raw.len() <= MIRROR_PACK_ACCEPTANCE_MAX_BYTES,
        "pack inspection acceptance exceeds bound"
    );
    let pack: MirrorPackAcceptanceArtifact = serde_json::from_str(&raw)
        .map_err(|_| anyhow::anyhow!("pack inspection acceptance malformed"))?;
    pack.require_production(
        artifact,
        &env.var("HUB_MIRROR_QUALIFICATION_PUBLIC_KEY")?.to_string(),
        profile_latest_now(profile)?,
        maximum_encoded_bytes,
    )?;
    accepted.pack = Some(pack);
    Ok(accepted)
}

async fn require_profile(
    env: &Env,
    profile: &DirectProtectedProfile,
    direct_evidence: &str,
) -> Result<AcceptedMirror> {
    #[cfg(feature = "do-e2e")]
    return controlled::load(env, profile, direct_evidence).await;

    ensure!(
        !cfg!(feature = "do-e2e"),
        "controlled mirror runner cannot admit production"
    );

    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let source = option_env!("AOS_HUB_WORKER_SOURCE_DIGEST")
        .filter(|source| valid_direct_digest(source))
        .ok_or_else(|| anyhow::anyhow!("hermetic mirror source identity absent"))?;
    let script = crate::direct_upload::config::runtime_script_version(env)?;
    let key = match profile {
        DirectProtectedProfile::Managed { .. } => {
            mirror_acceptance_key(&deployment, source, &script)?
        }
        DirectProtectedProfile::External { .. } => {
            aos_hub_core::mirror_acceptance::external_mirror_acceptance_key(
                &deployment,
                source,
                &script,
                profile,
            )?
        }
    };
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
    let now = profile_latest_now(profile)?;
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
    Ok(AcceptedMirror {
        artifact: Review::Hosted(artifact),
        pack: None,
    })
}

/// Requires the separate live streaming purpose before any upstream dispatch.
pub(crate) async fn require_live(
    env: &Env,
    profile: &DirectProtectedProfile,
    direct_evidence: &str,
) -> Result<(AcceptedMirror, AcceptedLive)> {
    use aos_hub_core::mirror_acceptance::live::{
        mirror_live_acceptance_key, MirrorLiveAcceptanceArtifact, LIVE_ACCEPTANCE_MAX_BYTES,
    };

    let accepted = require_profile(env, profile, direct_evidence).await?;
    #[cfg(feature = "do-e2e")]
    if let Review::Controlled(artifact) = &accepted.artifact {
        let live = AcceptedLive {
            maximum_bytes: artifact.maximum_object_bytes,
            issued_at: artifact.issued_at,
            valid_until: artifact.valid_until,
        };
        return Ok((accepted, live));
    }
    let Review::Hosted(artifact) = &accepted.artifact else {
        anyhow::bail!("production live review absent");
    };
    let address = mirror_live_acceptance_key(&aos_hub_core::mirror_work::digest(artifact)?)?;
    let raw = env
        .kv("HUB_MIRROR_ACCEPTANCE")?
        .get(&address)
        .text()
        .await?
        .ok_or_else(|| anyhow::anyhow!("measured live mirror acceptance absent"))?;
    ensure!(
        raw.len() <= LIVE_ACCEPTANCE_MAX_BYTES,
        "live review exceeds bound"
    );
    let live: MirrorLiveAcceptanceArtifact =
        serde_json::from_str(&raw).map_err(|_| anyhow::anyhow!("live review malformed"))?;
    live.require_production(
        artifact,
        &env.var("HUB_MIRROR_QUALIFICATION_PUBLIC_KEY")?.to_string(),
        profile_latest_now(profile)?,
    )?;
    let bounds = AcceptedLive {
        maximum_bytes: live.maximum_bytes,
        issued_at: live.issued_at,
        valid_until: live.valid_until,
    };
    Ok((accepted, bounds))
}

fn profile_latest_now(profile: &DirectProtectedProfile) -> Result<u64> {
    let uncertainty = match profile {
        DirectProtectedProfile::Managed { profile, .. } => profile.clock_uncertainty_seconds.get(),
        DirectProtectedProfile::External { profile, .. } => {
            u64::try_from(profile.clock_uncertainty.get())?
        }
    };
    u64::try_from(aos_hub_core::clock::now_unix_secs())?
        .checked_add(uncertainty)
        .ok_or_else(|| anyhow::anyhow!("mirror qualified clock overflow"))
}

#[cfg(feature = "do-e2e")]
mod controlled;
