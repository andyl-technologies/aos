//! Independently installed OCI material and fresh purpose-specific acceptance.

use anyhow::{ensure, Result};
use aos_hub_core::storage_authority::external_object::oci::{
    qualification::ExternalOciProfile, ExternalOciOriginal,
};
use serde::{Deserialize, Serialize};

use super::super::{config::Config as ObjectConfig, protocol::digest};

const MAX_CONFIG: usize = 256 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    pub version: u8,
    pub profiles: Vec<ExternalOciProfile>,
}

impl Config {
    pub(super) fn parse(raw: &str, object: &ObjectConfig) -> Result<Self> {
        ensure!(
            raw.len() <= MAX_CONFIG,
            "external OCI configuration oversized"
        );
        let config: Self = serde_json::from_str(raw)?;
        config.validate(object)?;
        Ok(config)
    }

    pub(super) fn validate(&self, object: &ObjectConfig) -> Result<()> {
        object.validate()?;
        ensure!(
            self.version == 1 && !self.profiles.is_empty() && self.profiles.len() <= 16,
            "external OCI configuration unsupported"
        );
        let mut profiles = std::collections::BTreeSet::new();
        for profile in &self.profiles {
            profile.validate()?;
            ensure!(
                profile.issuer_installation.executor_identity == object.executor_identity
                    && profile.issuer_installation.authority.guard_namespace_id
                        == object.guard_namespace_id
                    && object.cohorts.contains(&profile.read_cohort)
                    && object.cohorts.contains(&profile.write_cohort)
                    && object.aliases.contains(&profile.read_cohort.alias)
                    && profiles.insert(profile.digest()?),
                "external OCI profile differs from independently installed authority"
            );
        }
        Ok(())
    }

    pub(super) fn profile(&self, original: &ExternalOciOriginal) -> Result<&ExternalOciProfile> {
        original.validate()?;
        let profile = self
            .profiles
            .iter()
            .find(|profile| {
                profile
                    .digest()
                    .is_ok_and(|digest| digest == original.profile_digest)
            })
            .ok_or_else(|| {
                anyhow::anyhow!("external OCI profile is not independently installed")
            })?;
        let association = &profile.write_cohort.association;
        let writer = &original.writer;
        ensure!(
            profile.binding_spec_revision == original.binding_spec_revision
                && profile.write_cohort.authority.authority_id
                    == original.scope.physical_authority_id
                && profile.write_cohort.authority.guard_namespace_id
                    == original.scope.guard_namespace_id
                && association.binding_id == writer.binding_id
                && association.binding_stable_id == writer.binding_stable_id
                && association.binding_resource_version == writer.binding_resource_version
                && association.binding_write_revision == writer.binding_write_revision
                && association.binding_prefix == writer.binding_prefix
                && match &original.object {
                    aos_hub_core::storage_authority::external_object::oci::OciObjectOriginal::Chunk { offset, maximum_bytes, .. } => offset.checked_add(*maximum_bytes).is_some_and(|end| end <= profile.maximum_blob_bytes),
                    aos_hub_core::storage_authority::external_object::oci::OciObjectOriginal::Compose { expected, .. } => expected.size <= profile.maximum_blob_bytes,
                },
            "external OCI original escapes the exact installed profile"
        );
        for cohort in [&profile.read_cohort, &profile.write_cohort] {
            ensure!(
                cohort.admitted_prefix.is_empty()
                    || original
                        .scope
                        .full_key
                        .strip_prefix(&format!("{}/", cohort.admitted_prefix))
                        .is_some(),
                "external OCI key escapes admitted cohort prefix"
            );
        }
        Ok(profile)
    }

    pub(super) fn digest(&self) -> Result<String> {
        digest(self)
    }
}

#[cfg(target_arch = "wasm32")]
pub(super) fn configured(env: &worker::Env, object: &ObjectConfig) -> Result<Config> {
    let raw = env.var("HUB_EXTERNAL_OCI_CONSUMER")?.to_string();
    Config::parse(&raw, object)
}

#[cfg(target_arch = "wasm32")]
#[derive(Clone)]
pub(super) struct Accepted {
    artifact: Option<aos_hub_core::storage_authority::external_object::oci::qualification::ExternalOciAcceptance>,
    #[cfg(feature = "do-e2e")]
    candidate: Option<aos_hub_core::storage_authority::external_object::oci::candidate::ExternalOciCandidate>,
}

#[cfg(target_arch = "wasm32")]
impl Accepted {
    pub(super) fn current(&self, object: &ObjectConfig) -> Result<()> {
        let clock = object.clock();
        let latest = clock
            .observed_at
            .checked_add(clock.uncertainty)
            .ok_or_else(|| anyhow::anyhow!("external OCI clock overflow"))?;
        if let Some(artifact) = &self.artifact {
            return artifact.check_time(latest);
        }
        #[cfg(feature = "do-e2e")]
        if let Some(candidate) = &self.candidate {
            ensure!(candidate.issued_at <= latest && latest < candidate.expires_at,
                "controlled OCI fixture cutoff expired");
            return Ok(());
        }
        anyhow::bail!("external OCI producer lacks its selected purpose")
    }
}

#[cfg(target_arch = "wasm32")]
pub(super) async fn require(
    env: &worker::Env,
    object: &ObjectConfig,
    profile: &ExternalOciProfile,
    placement_prefix: &str,
) -> Result<Accepted> {
    #[cfg(feature = "do-e2e")]
    {
        use aos_hub_core::storage_authority::external_object::oci::candidate::ExternalOciCandidate;
        let key = aos_hub_core::storage_work::StorageWorkKey::new(
            env.secret("HUB_EXTERNAL_OCI_CANDIDATE_KEY")?.to_string())?;
        let work = aos_hub_core::storage_work::StorageWorkKey::new(
            env.secret("HUB_STORAGE_WORK_KEY")?.to_string())?;
        let guard = super::super::storage::key(env)?;
        ensure!(key.sign_body(b"aos.oci.fixture.role-separation")?
            != work.sign_body(b"aos.oci.fixture.role-separation")?
            && key.sign_body(b"aos.oci.fixture.role-separation")?
            != guard.sign_body(b"aos.oci.fixture.role-separation")?,
            "controlled OCI candidate key must differ from producer and guard roles");
        let raw = env.var("HUB_EXTERNAL_OCI_CANDIDATE")?.to_string();
        let signature = env.var("HUB_EXTERNAL_OCI_CANDIDATE_SIGNATURE")?.to_string();
        let candidate = ExternalOciCandidate::authenticate(&key, &signature, raw.as_bytes())?;
        let clock = object.clock();
        let latest = clock.observed_at.checked_add(clock.uncertainty)
            .ok_or_else(|| anyhow::anyhow!("controlled OCI clock overflow"))?;
        candidate.validate(&env.var("HUB_DEPLOYMENT_ID")?.to_string(),
            option_env!("AOS_HUB_WORKER_SOURCE_DIGEST").unwrap_or(""),
            &crate::direct_upload::config::runtime_script_version(env)?,
            profile, placement_prefix, latest)?;
        let accepted = Accepted { artifact: None, candidate: Some(candidate) };
        accepted.current(object)?;
        return Ok(accepted);
    }
    #[cfg(not(feature = "do-e2e"))]
    {
    use aos_hub_core::storage_authority::external_object::oci::qualification::{
        ExternalOciAcceptance, MAX_EXTERNAL_OCI_ACCEPTANCE_BYTES,
    };
    let _ = placement_prefix;
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let source = option_env!("AOS_HUB_WORKER_SOURCE_DIGEST")
        .ok_or_else(|| anyhow::anyhow!("external OCI compiled source identity missing"))?;
    let script = crate::direct_upload::config::runtime_script_version(env)?;
    let address = digest(&(
        "accepted-external-oci-v1",
        &deployment,
        source,
        &script,
        profile.digest()?,
    ))?;
    let raw = env
        .kv("HUB_DIRECT_UPLOAD_ACCEPTANCE")?
        .get(&format!("accepted-external-oci-v1/{address}"))
        .text()
        .await?
        .ok_or_else(|| anyhow::anyhow!("external OCI measured workflow acceptance absent"))?;
    ensure!(
        raw.len() <= MAX_EXTERNAL_OCI_ACCEPTANCE_BYTES,
        "external OCI acceptance oversized"
    );
    let artifact: ExternalOciAcceptance = serde_json::from_str(&raw)?;
    let clock = object.clock();
    let latest = clock
        .observed_at
        .checked_add(clock.uncertainty)
        .ok_or_else(|| anyhow::anyhow!("external OCI clock overflow"))?;
    artifact.require_production(
        &env.var("HUB_EXTERNAL_OCI_QUALIFICATION_PUBLIC_KEY")?
            .to_string(),
        &env.var("HUB_EXTERNAL_OCI_QUALIFICATION_KEY_ID")?
            .to_string(),
        &deployment,
        source,
        &script,
        profile,
        latest,
    )?;
    let accepted = Accepted { artifact: Some(artifact),
        #[cfg(feature = "do-e2e")]
        candidate: None,
    };
    accepted.current(object)?;
    Ok(accepted)
    }
}
