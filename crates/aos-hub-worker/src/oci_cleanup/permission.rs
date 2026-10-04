//! Ordinary permission and confined emulator selection for terminal cleanup.
//!
//! The owner-installed fixture record uses a separate fixed KV slot. Initial
//! configuration pins the prefix and namespace before any SDK observation.
//! The local selection grants no SQL authority. It only selects the existing
//! physical implementation after the application has authenticated an actual
//! terminal chunk and an independently probed Delete capability.
//!
//! The fixed KV value contains exactly the following closed records:
//!
//! ```text
//! {"version":1,"selection":{deploymentId,placementPrefix,
//!   protectedProfileDigest,sourceDigest,scriptVersion,uncertaintySeconds,
//!   issuedAt,expiresAt},"profile":<raw OciSdkEmulationProfile>}
//! ```
//!
//! The selection is installed immediately before the cleanup case. Its time
//! window never renews the original upload or settles an unknown effect.

#[cfg(any(test, feature = "do-e2e"))]
use anyhow::{ensure, Result};
#[cfg(any(test, feature = "do-e2e"))]
use serde::{Deserialize, Serialize};

#[cfg(target_arch = "wasm32")]
use super::{config, Env, ManagedOciCleanupRequest};

#[cfg(target_arch = "wasm32")]
pub(super) enum Permission {
    Hosted(config::QualifiedConfig),
    #[cfg(feature = "do-e2e")]
    Controlled(
        Selection,
        aos_hub_core::oci_sdk_emulation::OciSdkEmulationProfile,
    ),
}

#[cfg(target_arch = "wasm32")]
impl Permission {
    pub(super) async fn load(env: &Env, work: &ManagedOciCleanupRequest) -> anyhow::Result<Self> {
        #[cfg(feature = "do-e2e")]
        if let Ok(prefix) = env.var("HUB_MANAGED_OCI_CLEANUP_FIXTURE_PREFIX") {
            ensure!(
                prefix.to_string() == work.original.placement_prefix,
                "Managed cleanup fixture selects another prefix"
            );
            let remaining = work
                .expires_at
                .checked_sub(config::guard_latest_now(env)?)
                .filter(|seconds| *seconds > 0)
                .ok_or_else(|| anyhow::anyhow!("Managed cleanup fixture lookup expired"))?;
            let deadline = worker::Delay::from(std::time::Duration::from_secs(remaining));
            let record = match futures_util::future::select(
                Box::pin(Self::load_record(env)),
                Box::pin(deadline),
            )
            .await
            {
                futures_util::future::Either::Left((record, _)) => record?,
                futures_util::future::Either::Right(_) => {
                    anyhow::bail!("Managed cleanup fixture lookup expired")
                }
            };
            work.validate(&work.deployment_id, config::guard_latest_now(env)?)?;
            return Ok(Self::Controlled(record.selection, record.profile));
        }

        #[cfg(not(feature = "do-e2e"))]
        let _ = work;
        Ok(Self::Hosted(config::QualifiedConfig::load(env).await?))
    }

    #[cfg(feature = "do-e2e")]
    async fn load_record(env: &Env) -> anyhow::Result<FixtureRecord> {
        use aos_hub_core::oci_cleanup::{
            MANAGED_OCI_CLEANUP_FIXTURE_KEY, MAX_MANAGED_OCI_CLEANUP_FIXTURE_BYTES,
        };
        // This is a separate fixture identity slot. No acceptance artifact is
        // decoded or verified, and the slot cannot grant Delete authority.
        let stream = env
            .kv("HUB_OCI_SDK_EMULATOR_ACCEPTANCE")?
            .get(MANAGED_OCI_CLEANUP_FIXTURE_KEY)
            .stream()
            .await?
            .ok_or_else(|| anyhow::anyhow!("Managed cleanup fixture record absent"))?;
        let reader = crate::direct_digest::Reader::new(stream.into())?;
        let mut bytes = Vec::new();
        loop {
            let (view, done) = reader.read().await?;
            ensure!(
                bytes
                    .len()
                    .checked_add(view.length() as usize)
                    .is_some_and(|size| size <= MAX_MANAGED_OCI_CLEANUP_FIXTURE_BYTES),
                "Managed cleanup fixture record exceeds bound"
            );
            bytes.extend_from_slice(&view.to_vec());
            if done {
                break;
            }
        }
        FixtureRecord::decode(&bytes)
    }

    pub(super) fn check(&self, env: &Env, work: &ManagedOciCleanupRequest) -> anyhow::Result<()> {
        match self {
            Self::Hosted(accepted) => {
                accepted.latest_now()?;
                anyhow::ensure!(
                    accepted.managed(env)?.0.digest()? == work.protected_profile_digest,
                    "Managed cleanup ordinary provider profile changed"
                );
            }
            #[cfg(feature = "do-e2e")]
            Self::Controlled(selection, actual) => {
                let policy = env
                    .var("HUB_DIRECT_UPLOAD_CLOCK_QUALIFICATION")?
                    .to_string();
                let uncertainty =
                    config::integer(env, "HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS")?.get();
                actual.validate()?;
                ensure!(
                    actual.public_origin
                        == env.var("HUB_OCI_SDK_EMULATOR_PUBLIC_ORIGIN")?.to_string()
                        && actual.native_origin == env.var("HUB_HYBRID_ORIGIN_URL")?.to_string()
                        && actual.clock_policy.commitment()? == policy
                        && actual.clock_policy.uncertainty_seconds.get() == uncertainty
                        && actual.namespace_id
                            == env
                                .var("HUB_MANAGED_OCI_CLEANUP_FIXTURE_NAMESPACE")?
                                .to_string()
                        && actual.maximum_provider_requests as u64
                            == config::integer(env, "HUB_OCI_SDK_EMULATOR_MAX_PROVIDER_REQUESTS")?
                                .get()
                        && actual.worker_source_digest == selection.source_digest
                        && actual.worker_script_version == selection.script_version
                        && actual.deployment_id == selection.deployment_id,
                    "Managed cleanup actual fixture pair or clock differs"
                );
                crate::direct_upload::provider_capacity::policy::configure_exact(
                    env,
                    actual.maximum_provider_requests,
                )?;
                crate::direct_upload::managed::probe(env)?;
                selection.validate(
                    &env.var("HUB_DEPLOYMENT_ID")?.to_string(),
                    &work.original.placement_prefix,
                    &aos_hub_core::oci_cleanup::managed_cleanup_fixture_profile_digest(actual)?,
                    option_env!("AOS_HUB_WORKER_SOURCE_DIGEST").unwrap_or(""),
                    &config::runtime_script_version(env)?,
                    uncertainty,
                    config::guard_latest_now(env)?,
                )?;
                ensure!(
                    work.protected_profile_digest == selection.protected_profile_digest,
                    "Managed cleanup selected another fixture profile"
                );
            }
        }
        Ok(())
    }
}

/// Contains raw physical identity and a fresh confined test window, not approval.
#[cfg(any(test, feature = "do-e2e"))]
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FixtureRecord {
    version: u32,
    selection: Selection,
    profile: aos_hub_core::oci_sdk_emulation::OciSdkEmulationProfile,
}

#[cfg(any(test, feature = "do-e2e"))]
impl FixtureRecord {
    fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= aos_hub_core::oci_cleanup::MAX_MANAGED_OCI_CLEANUP_FIXTURE_BYTES,
            "Managed cleanup fixture record exceeds bound"
        );
        let record: Self = serde_json::from_slice(bytes)?;
        ensure!(
            record.version == 1,
            "Managed cleanup fixture version differs"
        );
        record.profile.validate()?;
        ensure!(
            record.selection.deployment_id == record.profile.deployment_id
                && record.selection.source_digest == record.profile.worker_source_digest
                && record.selection.script_version == record.profile.worker_script_version
                && record.selection.uncertainty_seconds
                    == record.profile.clock_policy.uncertainty_seconds.get(),
            "Managed cleanup fixture selection and raw identity differ"
        );
        ensure!(
            record.selection.protected_profile_digest
                == aos_hub_core::oci_cleanup::managed_cleanup_fixture_profile_digest(
                    &record.profile
                )?,
            "Managed cleanup fixture raw profile digest differs"
        );
        Ok(record)
    }
}

#[cfg(any(test, feature = "do-e2e"))]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Selection {
    deployment_id: String,
    placement_prefix: String,
    protected_profile_digest: String,
    source_digest: String,
    script_version: String,
    uncertainty_seconds: u64,
    issued_at: u64,
    expires_at: u64,
}

#[cfg(any(test, feature = "do-e2e"))]
impl Selection {
    #[allow(clippy::too_many_arguments)]
    fn validate(
        &self,
        deployment: &str,
        prefix: &str,
        profile: &str,
        source: &str,
        script: &str,
        uncertainty: u64,
        latest_now: u64,
    ) -> Result<()> {
        let run = self
            .placement_prefix
            .strip_prefix("qualification/oci-terminal-cleanup/");
        ensure!(
            run.is_some_and(|run| !run.is_empty()
                && run.len() <= 64
                && run.bytes().all(|byte| byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || byte == b'-')),
            "Managed cleanup fixture prefix is not confined"
        );
        ensure!(
            self.deployment_id == deployment
                && self.placement_prefix == prefix
                && self.protected_profile_digest == profile
                && self.source_digest == source
                && self.script_version == script
                && self.uncertainty_seconds == uncertainty
                && (1..30).contains(&uncertainty)
                && aos_hub_core::direct_upload::valid_direct_digest(profile)
                && aos_hub_core::direct_upload::valid_direct_digest(source)
                && aos_hub_core::direct_upload::valid_direct_identity(script),
            "Managed cleanup fixture identity differs"
        );
        ensure!(
            self.issued_at <= latest_now
                && self.issued_at < self.expires_at
                && self
                    .expires_at
                    .checked_sub(self.issued_at)
                    .is_some_and(|seconds| seconds <= 600)
                && latest_now < self.expires_at,
            "Managed cleanup fixture window is unavailable"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selection() -> Selection {
        Selection {
            deployment_id: "fixture".into(),
            placement_prefix: "qualification/oci-terminal-cleanup/run".into(),
            protected_profile_digest: "a".repeat(64),
            source_digest: "b".repeat(64),
            script_version: "fixture-script".into(),
            uncertainty_seconds: 1,
            issued_at: 100,
            expires_at: 400,
        }
    }

    fn check(value: &Selection, now: u64) -> Result<()> {
        value.validate(
            "fixture",
            "qualification/oci-terminal-cleanup/run",
            &"a".repeat(64),
            &"b".repeat(64),
            "fixture-script",
            1,
            now,
        )
    }

    #[test]
    fn confined_current_selection_is_not_transferable() {
        let value = selection();
        check(&value, 101).unwrap();
        for changed in [
            "deployment",
            "prefix",
            "profile",
            "source",
            "script",
            "clock",
        ] {
            let mut value = selection();
            match changed {
                "deployment" => value.deployment_id = "other".into(),
                "prefix" => value.placement_prefix.push_str("/other"),
                "profile" => value.protected_profile_digest = "c".repeat(64),
                "source" => value.source_digest = "c".repeat(64),
                "script" => value.script_version = "other".into(),
                "clock" => value.uncertainty_seconds = 2,
                _ => unreachable!(),
            }
            assert!(check(&value, 101).is_err(), "{changed}");
        }
    }

    #[test]
    fn original_window_refuses_future_expired_and_oversized_intervals() {
        let mut value = selection();
        assert!(check(&value, 99).is_err());
        assert!(check(&value, 400).is_err());
        value.expires_at = 701;
        assert!(check(&value, 101).is_err());
    }

    #[test]
    fn unknown_fields_cannot_enable_another_permission() {
        let raw = r#"{"deploymentId":"fixture","placementPrefix":"qualification/oci-terminal-cleanup/run","protectedProfileDigest":"a","sourceDigest":"b","scriptVersion":"fixture","uncertaintySeconds":1,"issuedAt":100,"expiresAt":400,"accepted":true}"#;
        assert!(serde_json::from_str::<Selection>(raw).is_err());
    }
    fn raw_record() -> serde_json::Value {
        use aos_hub_core::{
            direct_upload::{
                DirectClockPolicy, DirectClockPolicyMode, DirectPrivateStagePolicyRef, WireInteger,
            },
            oci_sdk_emulation::{OciSdkEmulationProfile, OciSdkObjectObservation},
            storage_work::StorageObjectIdentity,
        };
        let source = "10".repeat(32);
        let namespace = "oci-sdk-qualification-0123456789abcdef0123456789abcdef";
        let profile = OciSdkEmulationProfile {
            deployment_id: "fixture".into(),
            public_origin: "https://worker.oci.test".into(),
            native_origin: "https://native.oci.test".into(),
            worker_source_digest: source.clone(),
            worker_script_version: aos_hub_core::direct_upload::direct_worker_emulated_script_id(
                &source,
            )
            .unwrap(),
            worker_name: "fixture-worker".into(),
            binding_name: "REGISTRY_BUCKET".into(),
            namespace_id: namespace.into(),
            namespace_object_id: "11".repeat(32),
            namespace_unique_key: "miniflare-R2BucketObject".into(),
            clock_policy: DirectClockPolicy {
                version: 1,
                mode: DirectClockPolicyMode::BoundedUtc,
                uncertainty_seconds: WireInteger::new(1),
            },
            maximum_provider_requests: 8,
            private_stage_policy: DirectPrivateStagePolicyRef {
                policy_id: "fixture-private".into(),
                policy_digest: aos_hub_core::direct_upload::direct_private_stage_policy_commitment(
                    "fixture-private",
                    namespace,
                )
                .unwrap(),
                namespace: namespace.into(),
            },
            anchor: OciSdkObjectObservation {
                object: StorageObjectIdentity {
                    key: ".aos-oci-sdk-qualification/0123456789abcdef0123456789abcdef/anchor"
                        .into(),
                    size: 64,
                    etag: "\"fixture-etag\"".into(),
                    provider_version: Some("fixture-version".into()),
                },
                sha256: "15".repeat(32),
            },
        };
        let mut selected = selection();
        selected.deployment_id = profile.deployment_id.clone();
        selected.source_digest = profile.worker_source_digest.clone();
        selected.script_version = profile.worker_script_version.clone();
        selected.uncertainty_seconds = profile.clock_policy.uncertainty_seconds.get();
        selected.protected_profile_digest =
            aos_hub_core::oci_cleanup::managed_cleanup_fixture_profile_digest(&profile).unwrap();
        serde_json::json!({"version": 1, "selection": selected, "profile": profile})
    }

    #[test]
    fn closed_record_binds_full_raw_identity_without_acceptance_fields() {
        let original = raw_record();
        let bytes = serde_json::to_vec(&original).unwrap();
        FixtureRecord::decode(&bytes).unwrap();
        eprintln!("synthetic cleanup record bytes={}", bytes.len());
        assert!(bytes.len() < 4096);

        let mut changed = original.clone();
        changed["profile"]["namespaceObjectId"] = "f".repeat(64).into();
        assert!(FixtureRecord::decode(&serde_json::to_vec(&changed).unwrap()).is_err());
        changed = original.clone();
        changed["selection"]["sourceDigest"] = "f".repeat(64).into();
        assert!(FixtureRecord::decode(&serde_json::to_vec(&changed).unwrap()).is_err());
        changed = original.clone();
        changed["accepted"] = true.into();
        assert!(FixtureRecord::decode(&serde_json::to_vec(&changed).unwrap()).is_err());
        changed = original;
        changed["version"] = 2.into();
        assert!(FixtureRecord::decode(&serde_json::to_vec(&changed).unwrap()).is_err());

        let mut oversized = bytes;
        oversized.resize(4097, b' ');
        assert!(FixtureRecord::decode(&oversized).is_err());
    }
}
