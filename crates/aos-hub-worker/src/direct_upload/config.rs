//! Accepted qualification artifacts and actual protected credential resolution.
//!
//! A configured digest cannot enable dispatch. The independently accepted
//! Ed25519 artifact supplies exact clock, capacity, privacy and SDK contract
//! evidence, and the adapter additionally probes the actual native interfaces.
//! Absence or a changed credential/profile fails before first admission.

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::*;
use worker::Env;

pub(crate) struct QualifiedConfig {
    /// Exact independently verified prerequisite measurement commitment.
    pub(crate) acceptance_evidence: String,
    acceptance_window: super::acceptance_window::AcceptedProducerWindow,
    pub(crate) runtime: DirectRuntimeQualification,
    pub(crate) clock_qualification: String,
    pub(crate) uncertainty: u64,
    pub(crate) policy: Option<DirectPrivateStagePolicyRef>,
    accepted_managed: Option<DirectManagedR2Profile>,
    accepted_external: Vec<DirectProtectedExternalProfile>,
}

impl QualifiedConfig {
    pub(crate) async fn load(env: &Env) -> Result<Self> {
        let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
        let source = option_env!("AOS_HUB_WORKER_SOURCE_DIGEST")
            .filter(|source| valid_direct_digest(source))
            .ok_or_else(|| anyhow::anyhow!("hermetic Worker source identity missing"))?;
        let version = runtime_script_version(env)?;
        let key = direct_worker_acceptance_key(&deployment, source, &version)?;
        // Acceptance is installed after measurement without replacing the
        // measured script or bindings. Only the independent signature grants it.
        let raw = env
            .kv("HUB_DIRECT_UPLOAD_ACCEPTANCE")?
            .get(&key)
            .text()
            .await?
            .ok_or_else(|| anyhow::anyhow!("direct measured acceptance absent"))?;
        ensure!(
            raw.len() <= 64 * 1024,
            "direct qualification artifact exceeds bound"
        );
        let artifact: DirectWorkerQualificationArtifact = serde_json::from_str(&raw)
            .map_err(|_| anyhow::anyhow!("direct qualification artifact malformed"))?;
        let now = u64::try_from(aos_hub_core::clock::now_unix_secs())?;
        artifact.verify(
            &deployment,
            &env.var("HUB_DIRECT_UPLOAD_PUBLIC_ORIGIN")?.to_string(),
            &env.var("HUB_DIRECT_UPLOAD_QUALIFICATION_PUBLIC_KEY")?
                .to_string(),
            now,
        )?;
        artifact.verify_runtime_identity(source, &version)?;
        ensure!(
            matches!(
                (cfg!(feature = "do-e2e"), artifact.execution_kind),
                (false, DirectWorkerExecutionKind::Hosted)
                    | (true, DirectWorkerExecutionKind::EmulatedExternal)
            ),
            "direct qualification execution kind differs from runtime"
        );
        let facts = artifact.evidence;
        ensure!(
            qualification_limits(env)? == facts.qualification_limits,
            "direct actual qualification limits differ from accepted measurements"
        );
        ensure!(
            facts.runtime.maximum_parallel_objects.get() >= 2,
            "direct runtime has no reserved metadata capacity"
        );
        ensure!(
            facts.runtime.maximum_parallel_provider_requests.get() >= 2,
            "direct runtime has no reserved metadata provider capacity"
        );
        ensure!(
            env.var("HUB_DIRECT_UPLOAD_CLOCK_QUALIFICATION")?
                .to_string()
                == facts.clock_policy.commitment()?
                && env.var("HUB_DIRECT_UPLOAD_CLOCK_MODE")?.to_string() == "bounded_utc"
                && integer(env, "HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS")?
                    == facts.clock.uncertainty_seconds
                && integer(env, "HUB_DIRECT_VERIFY_MAX_PARALLEL_OBJECTS")?
                    == facts.runtime.maximum_parallel_objects,
            "direct actual clock or consumer binding differs from measured acceptance"
        );
        for (binding, queue) in [
            (super::verification::BULK_QUEUE, &facts.bulk_queue),
            (super::verification::METADATA_QUEUE, &facts.metadata_queue),
        ] {
            ensure!(
                env.var(&format!("{binding}_NAME"))?.to_string() == queue.queue_name,
                "direct measured queue binding differs"
            );
            let ceiling = if binding == super::verification::BULK_QUEUE {
                facts
                    .runtime
                    .maximum_parallel_objects
                    .get()
                    .saturating_sub(1)
            } else {
                facts.runtime.maximum_parallel_objects.get()
            };
            ensure!(
                queue_policy(env, binding, ceiling)? == queue.delivery_policy,
                "direct actual queue delivery policy differs from accepted readback"
            );
            env.queue(binding)?;
        }
        if facts.managed_profile.is_some() {
            ensure!(
                facts.private_stage_policy.as_ref() == Some(&managed_policy(env)?),
                "direct actual private policy differs from measured acceptance"
            );
            ensure!(
                !cfg!(feature = "do-e2e"),
                "emulated runtime cannot activate managed R2"
            );
            super::managed::probe(env)?;
            ensure!(
                facts.runtime.maximum_parallel_provider_requests.get() >= 2,
                "managed streamed copy needs source and upload capacity"
            );
        }
        super::provider_capacity::configure(
            facts.runtime.maximum_parallel_provider_requests.get() as u32,
        )?;
        Ok(Self {
            acceptance_evidence: artifact.evidence_sha256,
            acceptance_window: super::acceptance_window::AcceptedProducerWindow::new(
                facts.issued_at.get(),
                facts.valid_until.get(),
                facts.clock.uncertainty_seconds.get(),
            )?,
            clock_qualification: facts.clock_policy.commitment()?,
            uncertainty: facts.clock.uncertainty_seconds.get(),
            runtime: facts.runtime,
            policy: facts.private_stage_policy,
            accepted_managed: facts.managed_profile,
            accepted_external: facts.external_profiles,
        })
    }

    pub(crate) fn latest_now(&self) -> Result<u64> {
        self.acceptance_window
            .latest_now(u64::try_from(aos_hub_core::clock::now_unix_secs())?)
    }

    pub(crate) async fn protected(
        &self,
        env: &Env,
        placement: &DirectPlacement,
    ) -> Result<DirectProtectedProfile> {
        let profile = match &placement.physical {
            DirectPhysicalContext::DeploymentR2 { .. } => self.managed(env)?.0,
            DirectPhysicalContext::External { write_cohort, .. } => {
                let selector = DirectExternalProfileSelector {
                    physical_authority_id: write_cohort.authority.authority_id.clone(),
                    association: write_cohort.association.clone(),
                    write_credential: placement.write_credential.clone(),
                    read_credential: placement.read_credential.clone(),
                    presign_credential: placement.presign_credential.clone(),
                };
                let mut profiles =
                    crate::external_object::resolve_external_profiles(env, &[selector]).await?;
                let actual = profiles
                    .pop()
                    .ok_or_else(|| anyhow::anyhow!("direct actual external profile absent"))?;
                ensure!(
                    self.accepted_external
                        .iter()
                        .any(|accepted| accepted.profile == actual
                            && accepted.runtime_qualification == self.runtime),
                    "direct actual external profile unaccepted"
                );
                DirectProtectedProfile::external(actual, self.runtime.clone())?
            }
        };
        ensure!(
            profile.digest()? == placement.protected_profile_digest,
            "direct original protected profile changed"
        );
        Ok(profile)
    }

    pub(crate) fn managed(
        &self,
        env: &Env,
    ) -> Result<(DirectProtectedProfile, ManagedCredentials)> {
        let (profile, credentials) =
            managed_descriptor(env, &self.clock_qualification, self.uncertainty)?;
        ensure!(
            self.accepted_managed.as_ref() == Some(&profile),
            "direct actual managed profile differs from measured acceptance"
        );
        let policy = self
            .policy
            .clone()
            .ok_or_else(|| anyhow::anyhow!("direct managed private policy not accepted"))?;
        Ok((
            DirectProtectedProfile::managed(profile, policy, self.runtime.clone())?,
            credentials,
        ))
    }
}

/// Resolves provider identity or an explicitly nonhosted source-built identity.
pub(crate) fn runtime_script_version(env: &Env) -> Result<String> {
    if cfg!(feature = "do-e2e") {
        let source = option_env!("AOS_HUB_WORKER_SOURCE_DIGEST")
            .filter(|source| valid_direct_digest(source))
            .ok_or_else(|| anyhow::anyhow!("emulated source-built Worker identity absent"))?;
        // Emulator evidence additionally records the installed Wasm hash in its
        // independently reviewed report. No configured Cloudflare ID is read.
        return direct_worker_emulated_script_id(source);
    }
    use wasm_bindgen::JsValue;
    let metadata = js_sys::Reflect::get(env, &JsValue::from_str("CF_VERSION_METADATA"))
        .map_err(|_| anyhow::anyhow!("actual hosted version metadata unavailable"))?;
    js_sys::Reflect::get(&metadata, &JsValue::from_str("id"))
        .map_err(|_| anyhow::anyhow!("actual hosted version metadata unavailable"))?
        .as_string()
        .filter(|version| valid_direct_identity(version))
        .ok_or_else(|| anyhow::anyhow!("actual hosted script identity absent"))
}

/// Projects metadata-only guard time without granting provider dispatch.
pub(crate) fn guard_latest_now(env: &Env) -> Result<u64> {
    let uncertainty = integer(env, "HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS")?;
    let policy = DirectClockPolicy {
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
                == policy.commitment()?,
        "guard bounded clock projection differs"
    );
    u64::try_from(aos_hub_core::clock::now_unix_secs())?
        .checked_add(uncertainty.get())
        .ok_or_else(|| anyhow::anyhow!("guard clock overflow"))
}

pub(crate) fn managed_policy(env: &Env) -> Result<DirectPrivateStagePolicyRef> {
    let policy = DirectPrivateStagePolicyRef {
        policy_id: env
            .var("HUB_DIRECT_UPLOAD_R2_PRIVATE_POLICY_ID")?
            .to_string(),
        policy_digest: env
            .var("HUB_DIRECT_UPLOAD_R2_PRIVATE_POLICY_DIGEST")?
            .to_string(),
        namespace: env
            .var("HUB_DIRECT_UPLOAD_R2_BUCKET_NAMESPACE")?
            .to_string(),
    };
    ensure!(
        policy.policy_digest
            == direct_private_stage_policy_commitment(&policy.policy_id, &policy.namespace)?,
        "direct installed private policy commitment differs"
    );
    Ok(policy)
}

/// Resolves explicitly installed fixture bounds without granting production authority.
pub(crate) fn qualification_limits(env: &Env) -> Result<Option<DirectWorkerQualificationLimits>> {
    if !env
        .var("HUB_DIRECT_UPLOAD_QUALIFICATION_ENABLED")
        .is_ok_and(|value| value.to_string() == "true")
    {
        return Ok(None);
    }
    let limits = DirectWorkerQualificationLimits {
        maximum_provider_requests: integer(env, "HUB_DIRECT_QUALIFY_MAX_PROVIDER_REQUESTS")?,
        maximum_object_bytes: integer(env, "HUB_DIRECT_QUALIFY_MAX_OBJECT_BYTES")?,
    };
    limits.validate()?;
    Ok(Some(limits))
}

pub(crate) struct ManagedCredentials {
    pub(crate) access_key: String,
    pub(crate) secret_key: String,
}

pub(crate) fn integer(env: &Env, name: &str) -> Result<WireInteger> {
    let raw = env.var(name)?.to_string();
    let number: u64 = raw.parse()?;
    ensure!(
        number.to_string() == raw && number > 0 && number <= i64::MAX as u64,
        "direct configured counter invalid"
    );
    Ok(WireInteger::new(number))
}

/// Reads fixed delivery bounds separately from participating-isolate capacity.
pub(crate) fn queue_policy(
    env: &Env,
    binding: &str,
    class_ceiling: u64,
) -> Result<DirectQueueDeliveryPolicy> {
    let policy = DirectQueueDeliveryPolicy {
        maximum_batch_size: integer(env, &format!("{binding}_MAX_BATCH_SIZE"))?,
        maximum_concurrent_invocations: if cfg!(feature = "do-e2e") {
            ensure!(
                env.var(&format!("{binding}_MAX_CONCURRENT_INVOCATIONS"))?
                    .to_string()
                    == "unsupported",
                "emulated queue global concurrency must be explicitly unsupported"
            );
            None
        } else {
            Some(integer(
                env,
                &format!("{binding}_MAX_CONCURRENT_INVOCATIONS"),
            )?)
        },
    };
    policy.validate_for_execution(
        class_ceiling,
        if cfg!(feature = "do-e2e") {
            DirectWorkerExecutionKind::EmulatedExternal
        } else {
            DirectWorkerExecutionKind::Hosted
        },
    )?;
    Ok(policy)
}

/// Resolves actual protected material without granting qualification.
pub(crate) fn managed_descriptor(
    env: &Env,
    clock_qualification: &str,
    uncertainty: u64,
) -> Result<(DirectManagedR2Profile, ManagedCredentials)> {
    ensure!(
        env.var("HUB_DIRECT_UPLOAD_MANAGED_R2")?.to_string() == "true",
        "direct managed R2 disabled"
    );
    let credentials = ManagedCredentials {
        access_key: env
            .secret("HUB_DIRECT_UPLOAD_R2_ACCESS_KEY_ID")?
            .to_string(),
        secret_key: env
            .secret("HUB_DIRECT_UPLOAD_R2_SECRET_ACCESS_KEY")?
            .to_string(),
    };
    let mut profile = DirectManagedR2Profile {
        deployment_id: env.var("HUB_DEPLOYMENT_ID")?.to_string(),
        bucket_namespace: env
            .var("HUB_DIRECT_UPLOAD_R2_BUCKET_NAMESPACE")?
            .to_string(),
        account_id: env.var("HUB_DIRECT_UPLOAD_R2_ACCOUNT_ID")?.to_string(),
        bucket_name: env.var("HUB_DIRECT_UPLOAD_R2_BUCKET_NAME")?.to_string(),
        credential_id: env.var("HUB_DIRECT_UPLOAD_R2_CREDENTIAL_ID")?.to_string(),
        credential_generation: integer(env, "HUB_DIRECT_UPLOAD_R2_CREDENTIAL_GENERATION")?,
        secret_version_ref: env
            .var("HUB_DIRECT_UPLOAD_R2_SECRET_VERSION_REF")?
            .to_string(),
        credential_fingerprint: String::new(),
        checksum_algorithm: match env
            .var("HUB_DIRECT_UPLOAD_R2_CHECKSUM")?
            .to_string()
            .as_str()
        {
            "md5" => DirectChecksumAlgorithm::Md5,
            "sha256" => DirectChecksumAlgorithm::Sha256,
            _ => anyhow::bail!("direct managed checksum unqualified"),
        },
        clock_qualification: clock_qualification.to_owned(),
        clock_uncertainty_seconds: WireInteger::new(uncertainty),
    };
    ensure!(
        profile.account_id.len() == 32
            && profile
                .account_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "direct managed account invalid"
    );
    profile.credential_fingerprint =
        profile.fingerprint_with_credentials(&credentials.access_key, &credentials.secret_key)?;

    Ok((profile, credentials))
}
