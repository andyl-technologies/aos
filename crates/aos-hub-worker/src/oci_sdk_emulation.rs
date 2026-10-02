//! Explicit local qualification for the OCI document SDK adapter only.
//!
//! The emulator loader is absent from production builds. Hosted use continues
//! through the existing provider verifier. No Direct profile, presigning or
//! mirror permission is produced by this separate purpose artifact.

#[cfg(feature = "do-e2e")]
use anyhow::Context as _;
use anyhow::{ensure, Result};
#[cfg(feature = "do-e2e")]
use aos_hub_core::oci_sdk_emulation::OciSdkEmulationArtifact;
use worker::Env;

use crate::direct_upload::config;

pub(crate) mod anchor;

/// Retains current permission for this OCI document adapter alone.
pub(crate) enum OciProviderConfig {
    Hosted(config::QualifiedConfig),
    #[cfg(feature = "do-e2e")]
    Emulator(OciSdkEmulationArtifact),
}

impl OciProviderConfig {
    /// Resolves hosted permission or explicit local OCI-only acceptance.
    ///
    /// # Errors
    /// Rejects absent, stale or changed acceptance and unsupported execution.
    pub(crate) async fn load(env: &Env) -> Result<Self> {
        Self::load_selected(env, None).await
    }

    /// Adds a private observation without changing loader admission.
    #[cfg(feature = "do-e2e")]
    pub(crate) async fn load_observed(
        env: &Env,
        observation: Option<&crate::oci_profile_load_observer::Trace>,
    ) -> Result<Self> {
        Self::load_selected(env, observation).await
    }

    async fn load_selected(
        env: &Env,
        #[cfg(feature = "do-e2e")] observation: Option<&crate::oci_profile_load_observer::Trace>,
        #[cfg(not(feature = "do-e2e"))] _observation: Option<&()>,
    ) -> Result<Self> {
        let opt_in = env
            .var("HUB_OCI_SDK_EMULATOR_ENABLED")
            .ok()
            .map(|value| value.to_string());
        if opt_in.as_deref() == Some("true") {
            #[cfg(feature = "do-e2e")]
            return Self::load_emulator(env, observation).await;
            #[cfg(not(feature = "do-e2e"))]
            anyhow::bail!("OCI SDK emulator permission is unavailable in a production Worker");
        }
        ensure!(
            opt_in.is_none() || opt_in.as_deref() == Some("false"),
            "OCI SDK emulator opt-in is invalid"
        );
        let qualified = config::QualifiedConfig::load(env).await?;
        qualified.managed(env)?;
        Ok(Self::Hosted(qualified))
    }

    #[cfg(feature = "do-e2e")]
    async fn load_emulator(
        env: &Env,
        observation: Option<&crate::oci_profile_load_observer::Trace>,
    ) -> Result<Self> {
        let deadline = u64::try_from(aos_hub_core::clock::now_unix_secs())?
            .checked_add(30)
            .context("OCI SDK artifact lookup deadline overflow")?;
        let remaining = deadline
            .checked_sub(config::guard_latest_now(env)?)
            .filter(|seconds| *seconds > 0)
            .context("OCI SDK artifact lookup expired")?;
        let timer = worker::Delay::from(std::time::Duration::from_secs(remaining));
        match futures_util::future::select(
            Box::pin(Self::load_emulator_records(env, observation)),
            Box::pin(timer),
        )
        .await
        {
            futures_util::future::Either::Left((result, _)) => {
                ensure!(
                    config::guard_latest_now(env)? < deadline,
                    "OCI SDK artifact lookup expired"
                );
                result
            }
            futures_util::future::Either::Right(_) => {
                anyhow::bail!("OCI SDK artifact lookup expired")
            }
        }
    }

    #[cfg(feature = "do-e2e")]
    async fn load_emulator_records(
        env: &Env,
        observation: Option<&crate::oci_profile_load_observer::Trace>,
    ) -> Result<Self> {
        use aos_hub_core::oci_sdk_emulation::oci_sdk_emulation_acceptance_key;

        let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
        let source = option_env!("AOS_HUB_WORKER_SOURCE_DIGEST")
            .context("installed OCI Worker source identity absent")?;
        let script = config::runtime_script_version(env)?;
        let registry_key = oci_sdk_emulation_acceptance_key(&deployment, source, &script)?;
        let stream = env
            .kv("HUB_OCI_SDK_EMULATOR_ACCEPTANCE")?
            .get(&registry_key)
            .stream()
            .await?
            .context("independently reviewed OCI SDK emulator artifact absent")?;
        // A poisoned registry value must not allocate the KV maximum in this
        // isolate. The same native reader cancels its body on every exit.
        let reader = crate::direct_digest::Reader::new(stream.into())?;
        let mut bytes = Vec::new();
        loop {
            let (view, done) = reader.read().await?;
            ensure!(
                bytes
                    .len()
                    .checked_add(view.length() as usize)
                    .is_some_and(|size| {
                        size
                            <= aos_hub_core::oci_sdk_emulation::MAX_OCI_SDK_EMULATION_ARTIFACT_BYTES
                    }),
                "OCI SDK artifact exceeds bound"
            );
            bytes.extend_from_slice(&view.to_vec());
            if done {
                break;
            }
        }
        let artifact = OciSdkEmulationArtifact::decode(&bytes)?;
        let origin = env.var("HUB_OCI_SDK_EMULATOR_PUBLIC_ORIGIN")?.to_string();
        ensure!(
            artifact.reviewer_key_id
                == env.var("HUB_OCI_SDK_EMULATOR_REVIEWER_KEY_ID")?.to_string()
                && artifact.profile.native_origin == env.var("HUB_HYBRID_ORIGIN_URL")?.to_string()
                && artifact.profile.worker_source_digest == source
                && artifact.profile.worker_script_version == script
                && artifact.profile.clock_policy.commitment()?
                    == env
                        .var("HUB_DIRECT_UPLOAD_CLOCK_QUALIFICATION")?
                        .to_string()
                && artifact.profile.clock_policy.uncertainty_seconds
                    == config::integer(env, "HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS")?
                && artifact.profile.maximum_provider_requests as u64
                    == config::integer(env, "HUB_OCI_SDK_EMULATOR_MAX_PROVIDER_REQUESTS")?.get(),
            "OCI SDK installed audience, source, clock or bounds changed"
        );
        crate::oci_profile_load_observer::verify_artifact(
            observation,
            &artifact,
            &bytes,
            &deployment,
            &origin,
            &env.var("HUB_OCI_SDK_EMULATOR_REVIEWER_PUBLIC_KEY")?
                .to_string(),
            config::guard_latest_now(env)?,
        )?;
        crate::direct_upload::provider_capacity::configure(
            artifact.profile.maximum_provider_requests,
        )?;
        crate::direct_upload::managed::probe(env)?;
        Ok(Self::Emulator(artifact))
    }

    pub(crate) fn check(&self, env: &Env) -> Result<()> {
        match self {
            Self::Hosted(qualified) => {
                qualified.latest_now()?;
                qualified.managed(env)?;
            }
            #[cfg(feature = "do-e2e")]
            Self::Emulator(artifact) => {
                artifact.verify(
                    &env.var("HUB_DEPLOYMENT_ID")?.to_string(),
                    &env.var("HUB_OCI_SDK_EMULATOR_PUBLIC_ORIGIN")?.to_string(),
                    &env.var("HUB_OCI_SDK_EMULATOR_REVIEWER_PUBLIC_KEY")?
                        .to_string(),
                    config::guard_latest_now(env)?,
                )?;
            }
        }
        Ok(())
    }

    pub(crate) fn effect(
        &self,
        env: &Env,
    ) -> Result<aos_hub_core::hybrid_ingress::OciDocumentEffect> {
        self.check(env)?;
        let (acceptance_digest, issued_at, expires_at, uncertainty) = match self {
            Self::Hosted(qualified) => {
                let (issued_at, expires_at) = qualified.acceptance_bounds();
                (
                    qualified.acceptance_evidence.clone(),
                    issued_at,
                    expires_at,
                    qualified.uncertainty,
                )
            }
            #[cfg(feature = "do-e2e")]
            Self::Emulator(artifact) => (
                artifact.evidence_sha256.clone(),
                artifact.issued_at,
                artifact.expires_at,
                artifact.profile.clock_policy.uncertainty_seconds.get(),
            ),
        };
        Ok(aos_hub_core::hybrid_ingress::OciDocumentEffect {
            protected_profile_digest: self.profile_digest(env)?,
            acceptance_digest,
            issued_at,
            expires_at,
            clock_uncertainty_seconds: uncertainty,
        })
    }

    pub(crate) fn check_effect(
        &self,
        env: &Env,
        original: &aos_hub_core::hybrid_ingress::OciDocumentEffect,
    ) -> Result<()> {
        let mut current = self.effect(env)?;
        ensure!(
            original.expires_at <= current.expires_at,
            "OCI effect cutoff changed"
        );
        current.expires_at = original.expires_at;
        ensure!(&current == original, "OCI accepted effect original changed");
        original.check(u64::try_from(aos_hub_core::clock::now_unix_secs())?)
    }

    pub(crate) fn profile_digest(&self, env: &Env) -> Result<String> {
        self.check(env)?;
        match self {
            Self::Hosted(qualified) => qualified.managed(env)?.0.digest(),
            #[cfg(feature = "do-e2e")]
            Self::Emulator(artifact) => artifact.profile.digest(),
        }
    }

    pub(crate) async fn verify_anchor(&self, env: &Env, deadline: Option<u64>) -> Result<()> {
        #[cfg(not(feature = "do-e2e"))]
        let _ = deadline;
        self.check(env)?;
        match self {
            Self::Hosted(_) => Ok(()),
            #[cfg(feature = "do-e2e")]
            Self::Emulator(artifact) => anchor::verify_current(env, artifact, deadline).await,
        }
    }

    #[cfg(feature = "do-e2e")]
    fn artifact(&self) -> Result<&OciSdkEmulationArtifact> {
        match self {
            Self::Emulator(artifact) => Ok(artifact),
            Self::Hosted(_) => anyhow::bail!("OCI SDK anchor is emulator-only"),
        }
    }
}
