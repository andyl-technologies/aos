//! Secret-free managed R2 deployment coordinates for direct upload rendering.
//!
//! This operator file selects reviewed provider and namespace policy. It neither
//! contains signing keys nor proves provider behavior; the Worker derives its
//! public credential commitment from separately installed protected secrets.
//!
//! ```json
//! {
//!   "version": 1,
//!   "deploymentId": "aos-hybrid-staging",
//!   "bucketNamespace": "staging-surfaces",
//!   "accountId": "0123456789abcdef0123456789abcdef",
//!   "bucketName": "aos-hub-hybrid-staging-surfaces",
//!   "credentialId": "staging-direct",
//!   "credentialGeneration": "1",
//!   "secretVersionRef": "staging-direct/v1",
//!   "checksumAlgorithm": "md5",
//!   "clockQualification": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
//!   "clockUncertaintySeconds": "1",
//!   "privateStagePolicy": {
//!     "policyId": "staging-private",
//!     "namespace": "staging-surfaces",
//!     "policyDigest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
//!   }
//! }
//! ```

use std::io::Read as _;
use std::path::Path;

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::direct_upload::DirectPrivateStagePolicyRef;
use serde::Deserialize;

mod acceptance;
mod clock;
mod deployment;

pub use acceptance::{
    HybridDirectUploadAcceptanceConfig, HybridDirectUploadQueueConfig,
    HybridDirectUploadTrustConfig,
};
pub use aos_hub_core::direct_upload::DirectWorkerQualificationLimits as HybridDirectUploadQualificationConfig;
pub use clock::HybridDirectUploadClockConfig;
pub use deployment::{
    activate_hybrid_direct_upload, deploy_hybrid, inspect_hybrid_direct_upload,
    read_hybrid_direct_upload_selectors, HybridDeploySecretFiles,
};

/// Secret-free operator selection for the managed R2 direct upload broker.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HybridDirectUploadDeployConfig {
    /// Closed operator-file format, currently one.
    pub version: u8,
    /// Exact paired deployment covered by the reviewed operator evidence.
    pub deployment_id: String,
    /// Permanent physical bucket namespace shared with the Native admission.
    pub bucket_namespace: String,
    /// Cloudflare account hosting the selected R2 bucket.
    pub account_id: String,
    /// Existing bucket attached to the Worker storage binding.
    pub bucket_name: String,
    /// Stable identity of the protected signer publication.
    pub credential_id: String,
    /// Exact immutable signer generation, within the Hub signed integer range.
    pub credential_generation: String,
    /// Public immutable version locator of the Worker signing secret.
    pub secret_version_ref: String,
    /// Provider-qualified checksum algorithm: `md5` or `sha256`.
    pub checksum_algorithm: String,
    /// Stable commitment to the installed bounded UTC clock policy.
    pub clock_qualification: String,
    /// Canonical decimal uncertainty in seconds, positive and below thirty.
    pub clock_uncertainty_seconds: String,
    /// Independently reviewed provider and Worker policy for this exact namespace.
    pub private_stage_policy: DirectPrivateStagePolicyRef,
}

impl HybridDirectUploadDeployConfig {
    /// Reads a bounded closed operator file containing no provider secrets.
    ///
    /// # Errors
    ///
    /// Returns an error for file I/O, oversized input, malformed JSON or unknown
    /// fields, including secret-bearing and manually configured fingerprint fields.
    pub fn from_file(path: &Path) -> Result<Self> {
        read_config_file(path)
    }

    pub(super) fn validate(&self, deployment_id: &str, attached_bucket: &str) -> Result<()> {
        use aos_hub_core::direct_upload::valid_direct_identity;

        ensure!(
            self.version == 1,
            "direct upload profile version is unsupported"
        );
        ensure!(
            self.deployment_id == deployment_id,
            "direct upload deployment differs from its Worker binding"
        );
        ensure!(
            self.bucket_name == attached_bucket,
            "direct upload bucket differs from its Worker binding"
        );
        let generation = self
            .credential_generation
            .parse::<u64>()
            .map_err(|_| anyhow::anyhow!("direct upload credential generation is invalid"))?;
        let uncertainty = self
            .clock_uncertainty_seconds
            .parse::<u64>()
            .map_err(|_| anyhow::anyhow!("direct upload clock uncertainty is invalid"))?;
        ensure!(
            self.account_id.len() == 32
                && self
                    .account_id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
            "direct upload account identity is invalid"
        );
        ensure!(
            (3..=63).contains(&self.bucket_name.len())
                && self
                    .bucket_name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && self
                    .bucket_name
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && self
                    .bucket_name
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric),
            "direct upload bucket identity is invalid"
        );
        ensure!(
            valid_direct_identity(&self.bucket_namespace)
                && valid_direct_identity(&self.credential_id)
                && valid_direct_identity(&self.private_stage_policy.policy_id)
                && self.private_stage_policy.policy_digest
                    == aos_hub_core::direct_upload::direct_private_stage_policy_commitment(
                        &self.private_stage_policy.policy_id,
                        &self.bucket_namespace,
                    )?
                && self.private_stage_policy.namespace == self.bucket_namespace
                && (1..=i64::MAX as u64).contains(&generation)
                && self.credential_generation == generation.to_string()
                && self.clock_qualification
                    == aos_hub_core::direct_upload::DirectClockPolicy {
                        version: 1,
                        mode: aos_hub_core::direct_upload::DirectClockPolicyMode::BoundedUtc,
                        uncertainty_seconds: aos_hub_core::direct_upload::WireInteger::new(
                            uncertainty
                        ),
                    }
                    .commitment()?
                && (1..30).contains(&uncertainty)
                && self.clock_uncertainty_seconds == uncertainty.to_string()
                && valid_direct_identity(&self.secret_version_ref)
                && matches!(self.checksum_algorithm.as_str(), "md5" | "sha256"),
            "direct upload profile coordinates are invalid"
        );
        Ok(())
    }

    pub(super) fn render_variables(&self) -> String {
        let fields = [
            ("BUCKET_NAMESPACE", self.bucket_namespace.as_str()),
            ("ACCOUNT_ID", self.account_id.as_str()),
            ("BUCKET_NAME", self.bucket_name.as_str()),
            ("CREDENTIAL_ID", self.credential_id.as_str()),
            ("SECRET_VERSION_REF", self.secret_version_ref.as_str()),
            ("CHECKSUM", self.checksum_algorithm.as_str()),
            (
                "PRIVATE_POLICY_ID",
                self.private_stage_policy.policy_id.as_str(),
            ),
            (
                "PRIVATE_POLICY_DIGEST",
                self.private_stage_policy.policy_digest.as_str(),
            ),
        ];
        let mut rendered = String::from("HUB_DIRECT_UPLOAD_MANAGED_R2 = \"true\"\n");
        for (name, value) in fields {
            rendered.push_str(&format!(
                "HUB_DIRECT_UPLOAD_R2_{name} = {}\n",
                super::toml_string(value)
            ));
        }
        rendered.push_str(&format!(
            "HUB_DIRECT_UPLOAD_R2_CREDENTIAL_GENERATION = {}\n",
            super::toml_string(&self.credential_generation)
        ));
        rendered.push_str(&format!(
            "HUB_DIRECT_UPLOAD_CLOCK_MODE = \"bounded_utc\"\nHUB_DIRECT_UPLOAD_CLOCK_QUALIFICATION = {}\nHUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS = {}\n",
            super::toml_string(&self.clock_qualification),
            super::toml_string(&self.clock_uncertainty_seconds)
        ));
        rendered
    }
}

fn read_config_file<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    read_config_file_with_limit(path, 16 * 1024)
}

pub(in crate::cloudflare) fn read_config_file_with_limit<T: serde::de::DeserializeOwned>(
    path: &Path,
    maximum_bytes: usize,
) -> Result<T> {
    let bytes = read_config_bytes_with_limit(path, maximum_bytes)?;
    serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("direct upload deployment file is invalid"))
}

fn read_config_bytes_with_limit(path: &Path, maximum_bytes: usize) -> Result<Vec<u8>> {
    // Check the opened descriptor without allowing a FIFO to wait for a writer.
    #[cfg(unix)]
    let file = {
        let descriptor = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )
        .context("opening direct upload deployment file")?;
        std::fs::File::from(descriptor)
    };
    #[cfg(not(unix))]
    let file = std::fs::File::open(path).context("opening direct upload deployment file")?;
    ensure!(
        file.metadata()
            .context("inspecting direct upload deployment file")?
            .is_file(),
        "direct upload deployment file must be an ordinary file"
    );

    let mut bytes = Vec::new();
    file.take((maximum_bytes + 1) as u64)
        .read_to_end(&mut bytes)
        .context("reading direct upload deployment file")?;
    ensure!(
        bytes.len() <= maximum_bytes,
        "direct upload deployment file is too large"
    );
    Ok(bytes)
}

pub(super) const DIRECT_UPLOAD_BINDING: &str = "\n[[durable_objects.bindings]]\nname = \"HYBRID_DIRECT_UPLOAD\"\nclass_name = \"HybridDirectUpload\"\n\n[[migrations]]\ntag = \"hybrid-direct-upload-v1\"\nnew_sqlite_classes = [\"HybridDirectUpload\"]\n";

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::cloudflare::{render_hybrid_wrangler_toml, HybridDeployConfig};

    fn profile() -> HybridDirectUploadDeployConfig {
        HybridDirectUploadDeployConfig {
            version: 1,
            deployment_id: "deployment-1".into(),
            bucket_namespace: "staging-surfaces".into(),
            account_id: "0123456789abcdef0123456789abcdef".into(),
            bucket_name: "aos-hybrid-surfaces".into(),
            credential_id: "staging-direct".into(),
            credential_generation: "1".into(),
            secret_version_ref: "staging-direct/v1".into(),
            checksum_algorithm: "md5".into(),
            clock_qualification: aos_hub_core::direct_upload::DirectClockPolicy {
                version: 1,
                mode: aos_hub_core::direct_upload::DirectClockPolicyMode::BoundedUtc,
                uncertainty_seconds: aos_hub_core::direct_upload::WireInteger::new(1),
            }
            .commitment()
            .unwrap(),
            clock_uncertainty_seconds: "1".into(),
            private_stage_policy: DirectPrivateStagePolicyRef {
                policy_id: "staging-private".into(),
                policy_digest: aos_hub_core::direct_upload::direct_private_stage_policy_commitment(
                    "staging-private",
                    "staging-surfaces",
                )
                .unwrap(),
                namespace: "staging-surfaces".into(),
            },
        }
    }

    pub(in crate::cloudflare) fn config() -> HybridDeployConfig {
        HybridDeployConfig {
            name: "aos-hybrid".into(),
            bucket: "aos-hybrid-surfaces".into(),
            deployment_id: "deployment-1".into(),
            external_url: "https://hub.example.test".into(),
            native_origin_url: "https://native.example.test".into(),
            custom_domains: Vec::new(),
            serve_assets: false,
            direct_upload: Some(profile()),
            direct_upload_clock: None,
            mirror_trust: None,
            direct_upload_trust: Some(HybridDirectUploadTrustConfig {
                public_key: aos_hub_core::direct_upload::direct_worker_qualification_fixture().1,
                namespace_id: "operator-namespace".into(),
            }),
            direct_upload_queues: Some(HybridDirectUploadQueueConfig {
                bulk: "direct-content".into(),
                metadata: "direct-metadata".into(),
                maximum_parallel_objects: 4,
                bulk_delivery_policy: aos_hub_core::direct_upload::DirectQueueDeliveryPolicy {
                    maximum_batch_size: aos_hub_core::direct_upload::WireInteger::new(3),
                    maximum_concurrent_invocations: Some(
                        aos_hub_core::direct_upload::WireInteger::new(2),
                    ),
                },
                metadata_delivery_policy: aos_hub_core::direct_upload::DirectQueueDeliveryPolicy {
                    maximum_batch_size: aos_hub_core::direct_upload::WireInteger::new(4),
                    maximum_concurrent_invocations: Some(
                        aos_hub_core::direct_upload::WireInteger::new(2),
                    ),
                },
            }),
            direct_upload_acceptance: None,
            direct_upload_conformance: false,
            direct_upload_qualification: None,
        }
    }

    #[test]
    fn renders_optional_broker_without_secrets_or_configured_fingerprint() {
        let mut cfg = config();
        let source = render_hybrid_wrangler_toml(&cfg).unwrap();
        let rendered: toml::Value = toml::from_str(&source).unwrap();

        assert_eq!(
            rendered["vars"]["HUB_DIRECT_UPLOAD_MANAGED_R2"].as_str(),
            Some("true")
        );
        assert_eq!(
            rendered["vars"]["HUB_DIRECT_UPLOAD_R2_CREDENTIAL_GENERATION"].as_str(),
            Some("1")
        );
        assert_eq!(
            rendered["vars"]["HUB_DIRECT_UPLOAD_R2_PRIVATE_POLICY_DIGEST"].as_str(),
            Some(profile().private_stage_policy.policy_digest.as_str())
        );
        assert_eq!(
            rendered["durable_objects"]["bindings"][3]["name"].as_str(),
            Some("HYBRID_DIRECT_UPLOAD")
        );
        assert_eq!(
            rendered["migrations"][3]["new_sqlite_classes"][0].as_str(),
            Some("HybridDirectUpload")
        );
        assert!(!source.contains("ACCESS_KEY"));
        assert!(!source.contains("FINGERPRINT"));

        cfg.direct_upload = None;
        cfg.direct_upload_trust = None;
        cfg.direct_upload_queues = None;
        let source = render_hybrid_wrangler_toml(&cfg).unwrap();
        assert!(!source.contains("HYBRID_DIRECT_UPLOAD"));
        assert!(!source.contains("HUB_DIRECT_UPLOAD_MANAGED_R2"));
    }

    #[test]
    fn refuses_mismatched_deployment_bucket_and_private_namespace() {
        let mut cfg = config();
        cfg.deployment_id = "another-deployment".into();
        assert!(render_hybrid_wrangler_toml(&cfg).is_err());

        let mut cfg = config();
        cfg.bucket = "another-bucket".into();
        assert!(render_hybrid_wrangler_toml(&cfg).is_err());

        let mut cfg = config();
        cfg.direct_upload
            .as_mut()
            .unwrap()
            .private_stage_policy
            .namespace = "another-namespace".into();
        assert!(render_hybrid_wrangler_toml(&cfg).is_err());
    }

    #[test]
    fn refuses_noncanonical_generation_account_checksum_and_policy() {
        for generation in [
            "0",
            "01",
            "-1",
            "9223372036854775808",
            "18446744073709551616",
        ] {
            let mut selected = profile();
            selected.credential_generation = generation.into();
            assert!(selected
                .validate("deployment-1", "aos-hybrid-surfaces")
                .is_err());
        }
        for uncertainty in ["0", "01", "30", "-1", "18446744073709551616"] {
            let mut selected = profile();
            selected.clock_uncertainty_seconds = uncertainty.into();
            assert!(selected
                .validate("deployment-1", "aos-hybrid-surfaces")
                .is_err());
        }

        let mut selected = profile();
        selected.account_id = "unexpected.example.test".into();
        assert!(selected
            .validate("deployment-1", "aos-hybrid-surfaces")
            .is_err());

        let mut selected = profile();
        selected.checksum_algorithm = "none".into();
        assert!(selected
            .validate("deployment-1", "aos-hybrid-surfaces")
            .is_err());

        let mut selected = profile();
        selected.private_stage_policy.policy_digest = "unverified".into();
        assert!(selected
            .validate("deployment-1", "aos-hybrid-surfaces")
            .is_err());
    }

    #[test]
    fn independent_global_queue_invocation_limits_preserve_elastic_local_metadata_capacity() {
        use aos_hub_core::direct_upload::WireInteger;

        let mut cfg = config();
        let queues = cfg.direct_upload_queues.as_mut().unwrap();
        queues.bulk_delivery_policy.maximum_concurrent_invocations = Some(WireInteger::new(1));
        queues
            .metadata_delivery_policy
            .maximum_concurrent_invocations = Some(WireInteger::new(8));
        let source = render_hybrid_wrangler_toml(&cfg).unwrap();
        let rendered: toml::Value = toml::from_str(&source).unwrap();
        assert_eq!(
            rendered["queues"]["consumers"][0]["max_concurrency"].as_integer(),
            Some(1)
        );
        assert_eq!(
            rendered["queues"]["consumers"][1]["max_concurrency"].as_integer(),
            Some(8)
        );
        assert_eq!(
            rendered["queues"]["consumers"][1]["max_batch_size"].as_integer(),
            Some(4)
        );
        assert_eq!(
            rendered["vars"]["HUB_DIRECT_VERIFY_MAX_PARALLEL_OBJECTS"].as_str(),
            Some("4")
        );
        assert_eq!(
            rendered["vars"]["HUB_DIRECT_VERIFY_METADATA_MAX_CONCURRENT_INVOCATIONS"].as_str(),
            Some("8")
        );

        for (batch, invocations) in [(0, 1), (5, 1), (4, 0), (4, 33)] {
            let policy = &mut cfg
                .direct_upload_queues
                .as_mut()
                .unwrap()
                .metadata_delivery_policy;
            policy.maximum_batch_size = WireInteger::new(batch);
            policy.maximum_concurrent_invocations = Some(WireInteger::new(invocations));
            assert!(render_hybrid_wrangler_toml(&cfg).is_err());
        }
        let policy = &mut cfg
            .direct_upload_queues
            .as_mut()
            .unwrap()
            .metadata_delivery_policy;
        policy.maximum_batch_size = WireInteger::new(4);
        policy.maximum_concurrent_invocations = None;
        assert!(render_hybrid_wrangler_toml(&cfg).is_err());
    }

    #[test]
    fn isolated_qualification_requires_explicit_bounded_candidate_configuration() {
        use aos_hub_core::direct_upload::{WireInteger, MAX_DIRECT_OBJECT_BYTES};

        let mut cfg = config();
        let source = render_hybrid_wrangler_toml(&cfg).unwrap();
        assert!(source.contains("HUB_DIRECT_UPLOAD_QUALIFICATION_ENABLED = \"false\""));
        assert!(!source.contains("HUB_DIRECT_QUALIFY_MAX_"));

        cfg.direct_upload_qualification = Some(HybridDirectUploadQualificationConfig {
            maximum_provider_requests: WireInteger::new(8),
            maximum_object_bytes: WireInteger::new(1024 * 1024),
        });
        let source = render_hybrid_wrangler_toml(&cfg).unwrap();
        let rendered: toml::Value = toml::from_str(&source).unwrap();
        assert_eq!(
            rendered["vars"]["HUB_DIRECT_UPLOAD_QUALIFICATION_ENABLED"].as_str(),
            Some("true")
        );
        assert_eq!(
            rendered["vars"]["HUB_DIRECT_UPLOAD_CONFORMANCE_ENABLED"].as_str(),
            Some("false")
        );
        assert_eq!(
            rendered["vars"]["HUB_DIRECT_QUALIFY_MAX_PROVIDER_REQUESTS"].as_str(),
            Some("8")
        );
        assert_eq!(
            rendered["vars"]["HUB_DIRECT_QUALIFY_MAX_OBJECT_BYTES"].as_str(),
            Some("1048576")
        );
        assert_eq!(
            rendered["queues"]["consumers"][0]["max_concurrency"].as_integer(),
            Some(2)
        );
        assert_eq!(
            rendered["queues"]["consumers"][1]["max_concurrency"].as_integer(),
            Some(2)
        );
        assert!(!source.contains("ACCEPTED_QUALIFICATION"));

        for (requests, bytes) in [(1, 1), (33, 1), (2, 0), (2, MAX_DIRECT_OBJECT_BYTES + 1)] {
            cfg.direct_upload_qualification = Some(HybridDirectUploadQualificationConfig {
                maximum_provider_requests: WireInteger::new(requests),
                maximum_object_bytes: WireInteger::new(bytes),
            });
            assert!(render_hybrid_wrangler_toml(&cfg).is_err());
        }
    }

    #[test]
    fn independent_acceptance_matches_every_rendered_coordinate_and_capacity() {
        use aos_hub_core::direct_upload::DirectChecksumAlgorithm;

        let (artifact, key) = aos_hub_core::direct_upload::direct_worker_qualification_fixture();
        let accepted = artifact.evidence.managed_profile.as_ref().unwrap();
        let mut cfg = config();
        cfg.bucket = accepted.bucket_name.clone();
        cfg.direct_upload = Some(HybridDirectUploadDeployConfig {
            version: 1,
            deployment_id: accepted.deployment_id.clone(),
            bucket_namespace: accepted.bucket_namespace.clone(),
            account_id: accepted.account_id.clone(),
            bucket_name: accepted.bucket_name.clone(),
            credential_id: accepted.credential_id.clone(),
            credential_generation: accepted.credential_generation.get().to_string(),
            secret_version_ref: accepted.secret_version_ref.clone(),
            checksum_algorithm: match accepted.checksum_algorithm {
                DirectChecksumAlgorithm::Md5 => "md5",
                DirectChecksumAlgorithm::Sha256 => "sha256",
            }
            .into(),
            clock_qualification: accepted.clock_qualification.clone(),
            clock_uncertainty_seconds: accepted.clock_uncertainty_seconds.get().to_string(),
            private_stage_policy: artifact.evidence.private_stage_policy.clone().unwrap(),
        });
        cfg.direct_upload_trust.as_mut().unwrap().public_key = key;
        cfg.direct_upload_acceptance = Some(HybridDirectUploadAcceptanceConfig { artifact });

        let source = render_hybrid_wrangler_toml(&cfg).unwrap();
        let rendered: toml::Value = toml::from_str(&source).unwrap();

        assert_eq!(
            rendered["vars"]["HUB_DIRECT_UPLOAD_PUBLIC_ORIGIN"].as_str(),
            Some("https://hub.example.test")
        );
        assert_eq!(
            rendered["vars"]["HUB_DIRECT_VERIFY_BULK_NAME"].as_str(),
            Some("direct-content")
        );
        assert_eq!(
            rendered["vars"]["HUB_DIRECT_VERIFY_METADATA_NAME"].as_str(),
            Some("direct-metadata")
        );
        assert_eq!(
            rendered["kv_namespaces"][0]["binding"].as_str(),
            Some("HUB_DIRECT_UPLOAD_ACCEPTANCE")
        );
        assert_eq!(
            rendered["version_metadata"]["binding"].as_str(),
            Some("CF_VERSION_METADATA")
        );
        assert_eq!(rendered["queues"]["producers"].as_array().unwrap().len(), 2);
        assert_eq!(
            rendered["queues"]["consumers"][0]["max_concurrency"].as_integer(),
            Some(2)
        );
        assert_eq!(
            rendered["queues"]["consumers"][1]["max_batch_size"].as_integer(),
            Some(4)
        );
        assert!(!source.contains("signature"));
        assert!(!source.contains("HUB_DIRECT_UPLOAD_ACCEPTED_QUALIFICATION"));
        assert!(!source.contains("credentialFingerprint"));

        cfg.direct_upload_queues
            .as_mut()
            .unwrap()
            .maximum_parallel_objects = 8;
        assert!(render_hybrid_wrangler_toml(&cfg).is_err());
        cfg.direct_upload_queues
            .as_mut()
            .unwrap()
            .maximum_parallel_objects = 4;
        cfg.direct_upload.as_mut().unwrap().secret_version_ref = "persistent-direct/v2".into();
        assert!(render_hybrid_wrangler_toml(&cfg).is_err());
    }

    #[test]
    fn prequalification_bindings_grant_no_production_acceptance_and_probe_is_explicit() {
        let mut cfg = config();
        let source = render_hybrid_wrangler_toml(&cfg).unwrap();
        let rendered: toml::Value = toml::from_str(&source).unwrap();
        assert_eq!(
            rendered["vars"]["HUB_DIRECT_UPLOAD_CONFORMANCE_ENABLED"].as_str(),
            Some("false")
        );
        assert!(!source.contains("HUB_DIRECT_UPLOAD_ACCEPTED_QUALIFICATION"));

        cfg.direct_upload_conformance = true;
        let source = render_hybrid_wrangler_toml(&cfg).unwrap();
        assert!(source.contains("HUB_DIRECT_UPLOAD_CONFORMANCE_ENABLED = \"true\""));
        assert!(!source.contains("HUB_DIRECT_UPLOAD_CONFORMANCE_KEY"));

        cfg.direct_upload_trust = None;
        assert!(render_hybrid_wrangler_toml(&cfg).is_err());
        cfg.direct_upload_trust = config().direct_upload_trust;
        cfg.direct_upload_queues.as_mut().unwrap().metadata = "direct-content".into();
        assert!(render_hybrid_wrangler_toml(&cfg).is_err());
    }

    #[test]
    fn profile_reader_refuses_oversized_and_secret_bearing_files_without_echoing_values() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profile.json");
        std::fs::write(&path, vec![b' '; 16 * 1024 + 1]).unwrap();
        assert!(HybridDirectUploadDeployConfig::from_file(&path).is_err());

        std::fs::write(
            &path,
            br#"{"version":1,"secretAccessKey":"private-marker"}"#,
        )
        .unwrap();
        let error = HybridDirectUploadDeployConfig::from_file(&path).unwrap_err();
        assert!(!error.to_string().contains("private-marker"));
    }

    #[test]
    fn acceptance_reader_and_independent_verifier_file_are_bounded_and_separate() {
        let directory = tempfile::tempdir().unwrap();
        let artifact_path = directory.path().join("accepted.json");
        let key_path = directory.path().join("reviewer-public.hex");
        let (artifact, public) = aos_hub_core::direct_upload::direct_worker_qualification_fixture();
        std::fs::write(&artifact_path, serde_json::to_vec(&artifact).unwrap()).unwrap();
        std::fs::write(&key_path, format!("{public}\n")).unwrap();

        let acceptance = HybridDirectUploadAcceptanceConfig::from_file(&artifact_path).unwrap();
        let trust = HybridDirectUploadTrustConfig::from_public_key_file(
            &key_path,
            "operator-namespace".into(),
        )
        .unwrap();
        acceptance
            .artifact
            .verify(
                "deployment-1",
                "https://hub.example.test",
                &trust.public_key,
                100,
            )
            .unwrap();

        std::fs::write(&artifact_path, vec![b' '; 64 * 1024 + 1]).unwrap();
        assert!(HybridDirectUploadAcceptanceConfig::from_file(&artifact_path).is_err());
        std::fs::write(&key_path, "private-verifier-marker").unwrap();
        let error = HybridDirectUploadTrustConfig::from_public_key_file(
            &key_path,
            "operator-namespace".into(),
        )
        .unwrap_err();
        assert!(!error.to_string().contains("private-verifier-marker"));
    }

    #[test]
    fn profile_reader_accepts_the_operator_wire_format_and_refuses_manual_fingerprints() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profile.json");
        let selected = profile();
        let mut value = serde_json::json!({
            "version": selected.version,
            "deploymentId": selected.deployment_id,
            "bucketNamespace": selected.bucket_namespace,
            "accountId": selected.account_id,
            "bucketName": selected.bucket_name,
            "credentialId": selected.credential_id,
            "credentialGeneration": selected.credential_generation,
            "secretVersionRef": selected.secret_version_ref,
            "checksumAlgorithm": selected.checksum_algorithm,
            "clockQualification": selected.clock_qualification,
            "clockUncertaintySeconds": selected.clock_uncertainty_seconds,
            "privateStagePolicy": selected.private_stage_policy,
        });
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        let parsed = HybridDirectUploadDeployConfig::from_file(&path).unwrap();
        parsed
            .validate("deployment-1", "aos-hybrid-surfaces")
            .unwrap();
        assert_eq!(parsed.credential_generation, "1");
        assert_eq!(parsed.private_stage_policy.namespace, "staging-surfaces");

        value["credentialFingerprint"] = "manual-private-marker".into();
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let error = HybridDirectUploadDeployConfig::from_file(&path).unwrap_err();
        assert!(!error.to_string().contains("manual-private-marker"));
    }

    fn clock() -> HybridDirectUploadClockConfig {
        HybridDirectUploadClockConfig {
            version: 1,
            deployment_id: "deployment-1".into(),
            mode: aos_hub_core::direct_upload::DirectClockPolicyMode::BoundedUtc,
            qualification: profile().clock_qualification,
            uncertainty_seconds: "1".into(),
        }
    }

    #[test]
    fn external_only_clock_file_renders_the_broker_without_managed_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("clock.json");
        let mut value = serde_json::json!({
            "version": 1,
            "deploymentId": "deployment-1",
            "mode": "bounded_utc",
            "qualification": profile().clock_qualification,
            "uncertaintySeconds": "1",
        });
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let mut cfg = config();
        cfg.direct_upload = None;
        cfg.direct_upload_clock = Some(HybridDirectUploadClockConfig::from_file(&path).unwrap());

        let source = render_hybrid_wrangler_toml(&cfg).unwrap();
        let rendered: toml::Value = toml::from_str(&source).unwrap();
        assert_eq!(
            rendered["vars"]["HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS"].as_str(),
            Some("1")
        );
        assert_eq!(
            rendered["durable_objects"]["bindings"][3]["name"].as_str(),
            Some("HYBRID_DIRECT_UPLOAD")
        );
        assert!(!source.contains("HUB_DIRECT_UPLOAD_MANAGED_R2"));
        assert!(!source.contains("HUB_DIRECT_UPLOAD_R2_"));

        value["secretAccessKey"] = "private-clock-marker".into();
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let error = HybridDirectUploadClockConfig::from_file(&path).unwrap_err();
        assert!(!error.to_string().contains("private-clock-marker"));
    }

    #[test]
    fn transport_clock_refuses_foreign_noncanonical_and_conflicting_coordinates() {
        let mut selected = clock();
        selected.deployment_id = "another-deployment".into();
        assert!(selected.validate("deployment-1").is_err());

        let mut selected = clock();
        selected.version = 2;
        assert!(selected.validate("deployment-1").is_err());

        let mut selected = clock();
        selected.qualification = "not-reviewed".into();
        assert!(selected.validate("deployment-1").is_err());

        for uncertainty in ["0", "01", "30", "-1", "18446744073709551616"] {
            let mut selected = clock();
            selected.uncertainty_seconds = uncertainty.into();
            assert!(selected.validate("deployment-1").is_err());
        }

        let mut cfg = config();
        cfg.direct_upload_clock = Some(clock());
        let source = render_hybrid_wrangler_toml(&cfg).unwrap();
        assert_eq!(
            source
                .matches("HUB_DIRECT_UPLOAD_CLOCK_QUALIFICATION =")
                .count(),
            1
        );
        assert!(toml::from_str::<toml::Value>(&source).is_ok());

        cfg.direct_upload_clock.as_mut().unwrap().qualification = "ef".repeat(32);
        assert!(render_hybrid_wrangler_toml(&cfg).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn profile_reader_refuses_a_fifo_without_waiting_for_a_writer() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profile.fifo");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &path,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .unwrap();

        assert!(HybridDirectUploadDeployConfig::from_file(&path).is_err());
    }
}
