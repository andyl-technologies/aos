//! Independent reviewer trust and bounded signed acceptance registry inputs.
//!
//! ```text
//! predeployment: fixed public reviewer key + purpose-specific KV binding
//! unchanged hosted deployment -> measurements -> independent signed acceptance
//! acceptance upload: aos.direct-upload.acceptance.v1/deployment/source/script
//! ```

use std::path::Path;

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::{DirectWorkerExecutionKind, DirectWorkerQualificationArtifact};

/// Stable reviewer trust and the purpose-specific acceptance registry binding.
#[derive(Clone, Debug)]
pub struct HybridDirectUploadTrustConfig {
    /// Independently installed Ed25519 public key, in lowercase hexadecimal.
    pub public_key: String,
    /// Operator-selected Cloudflare KV namespace identifier.
    pub namespace_id: String,
}

impl HybridDirectUploadTrustConfig {
    /// Reads a bounded public verifier file independently of the acceptance.
    ///
    /// # Errors
    /// Returns an error for I/O, nonregular files or an invalid public verifier.
    pub fn from_public_key_file(path: &Path, namespace_id: String) -> Result<Self> {
        let bytes = super::read_config_bytes_with_limit(path, 256)?;
        let key = std::str::from_utf8(&bytes)
            .map_err(|_| anyhow::anyhow!("direct acceptance verifier malformed"))?
            .trim_end_matches(['\r', '\n'])
            .to_owned();
        let trust = Self {
            public_key: key,
            namespace_id,
        };
        trust.validate()?;
        Ok(trust)
    }

    pub(in crate::cloudflare) fn validate(&self) -> Result<()> {
        ensure!(
            aos_hub_core::direct_upload::valid_direct_digest(&self.public_key)
                && (1..=128).contains(&self.namespace_id.len())
                && self
                    .namespace_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
            "direct acceptance verifier or namespace invalid"
        );
        let public: [u8; 32] = hex::decode(&self.public_key)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| anyhow::anyhow!("direct acceptance verifier malformed"))?;
        ed25519_dalek::VerifyingKey::from_bytes(&public)
            .map_err(|_| anyhow::anyhow!("direct acceptance verifier malformed"))?;
        Ok(())
    }
}

/// Closed independently signed acceptance prepared for an unchanged deployment.
#[derive(Clone, Debug)]
pub struct HybridDirectUploadAcceptanceConfig {
    /// Full signed public artifact; it contains no credential secret values.
    pub artifact: DirectWorkerQualificationArtifact,
}

impl HybridDirectUploadAcceptanceConfig {
    /// Reads one bounded closed signed Worker acceptance document.
    ///
    /// # Errors
    /// Returns a value-free error for nonregular, oversized or malformed input.
    pub fn from_file(path: &Path) -> Result<Self> {
        Ok(Self {
            artifact: super::read_config_file_with_limit(path, 64 * 1024)?,
        })
    }

    pub(in crate::cloudflare) fn validate(
        &self,
        cfg: &crate::cloudflare::HybridDeployConfig,
    ) -> Result<()> {
        let trust = cfg.direct_upload_trust.as_ref().ok_or_else(|| {
            anyhow::anyhow!("direct acceptance requires independent reviewer trust")
        })?;
        let now = u64::try_from(aos_hub_core::clock::now_unix_secs())
            .map_err(|_| anyhow::anyhow!("direct acceptance clock invalid"))?;
        self.artifact.verify(
            &cfg.deployment_id,
            &cfg.external_url,
            &trust.public_key,
            now,
        )?;
        ensure!(
            self.artifact.execution_kind == DirectWorkerExecutionKind::Hosted,
            "production installer requires hosted Worker qualification"
        );
        let evidence = &self.artifact.evidence;
        ensure!(
            cfg.direct_upload_qualification == evidence.qualification_limits,
            "direct installed qualification controls differ from independent acceptance"
        );
        let clock_digest = evidence.clock_policy.commitment()?;
        match (
            &cfg.direct_upload,
            &evidence.managed_profile,
            &evidence.private_stage_policy,
        ) {
            (Some(selected), Some(accepted), Some(policy)) => {
                ensure!(
                    selected.bucket_namespace == accepted.bucket_namespace
                        && selected.account_id == accepted.account_id
                        && selected.bucket_name == accepted.bucket_name
                        && selected.credential_id == accepted.credential_id
                        && selected.credential_generation
                            == accepted.credential_generation.get().to_string()
                        && selected.secret_version_ref == accepted.secret_version_ref
                        && selected.checksum_algorithm
                            == match accepted.checksum_algorithm {
                                aos_hub_core::direct_upload::DirectChecksumAlgorithm::Md5 => "md5",
                                aos_hub_core::direct_upload::DirectChecksumAlgorithm::Sha256 =>
                                    "sha256",
                            }
                        && selected.clock_qualification == clock_digest
                        && selected.clock_uncertainty_seconds
                            == evidence.clock.uncertainty_seconds.get().to_string()
                        && &selected.private_stage_policy == policy,
                    "direct selected managed profile differs from independent acceptance"
                );
            }
            (None, None, None) => {}
            _ => anyhow::bail!("direct selected managed mode differs from independent acceptance"),
        }
        if let Some(clock) = &cfg.direct_upload_clock {
            ensure!(
                clock.qualification == clock_digest
                    && clock.uncertainty_seconds
                        == evidence.clock.uncertainty_seconds.get().to_string(),
                "direct selected transport clock differs from independent acceptance"
            );
        }
        let queues = cfg.direct_upload_queues.as_ref().ok_or_else(|| {
            anyhow::anyhow!("direct acceptance requires separate verification queues")
        })?;
        ensure!(
            queues.bulk == evidence.bulk_queue.queue_name
                && queues.metadata == evidence.metadata_queue.queue_name
                && queues.bulk_delivery_policy == evidence.bulk_queue.delivery_policy
                && queues.metadata_delivery_policy == evidence.metadata_queue.delivery_policy
                && u64::from(queues.maximum_parallel_objects)
                    == evidence.runtime.maximum_parallel_objects.get(),
            "direct verification queue bindings differ from independent acceptance"
        );
        Ok(())
    }
}

/// Separate bounded queue bindings installed before hosted qualification.
#[derive(Clone, Debug)]
pub struct HybridDirectUploadQueueConfig {
    /// Operator-selected bulk verification queue name.
    pub bulk: String,
    /// Distinct operator-selected semantic metadata verification queue name.
    pub metadata: String,
    /// Consumer concurrency ceiling that must match the independent acceptance.
    pub maximum_parallel_objects: u32,
    /// Independently selected global bulk invocation and batch limits.
    pub bulk_delivery_policy: aos_hub_core::direct_upload::DirectQueueDeliveryPolicy,
    /// Independently selected global metadata invocation and batch limits.
    pub metadata_delivery_policy: aos_hub_core::direct_upload::DirectQueueDeliveryPolicy,
}

impl HybridDirectUploadQueueConfig {
    pub(in crate::cloudflare) fn validate(&self) -> Result<()> {
        ensure!(
            aos_hub_core::direct_upload::valid_direct_queue_name(&self.bulk)
                && aos_hub_core::direct_upload::valid_direct_queue_name(&self.metadata)
                && self.bulk != self.metadata
                && (2..=32).contains(&self.maximum_parallel_objects),
            "direct verification queue coordinates invalid"
        );
        self.bulk_delivery_policy.validate_for_execution(
            u64::from(self.maximum_parallel_objects - 1),
            aos_hub_core::direct_upload::DirectWorkerExecutionKind::Hosted,
        )?;
        self.metadata_delivery_policy.validate_for_execution(
            u64::from(self.maximum_parallel_objects),
            aos_hub_core::direct_upload::DirectWorkerExecutionKind::Hosted,
        )?;
        Ok(())
    }

    pub(in crate::cloudflare) fn render_bindings(&self) -> Result<String> {
        self.validate()?;
        let mut rendered = String::new();
        for (binding, name, policy) in [
            (
                "HUB_DIRECT_VERIFY_BULK",
                &self.bulk,
                &self.bulk_delivery_policy,
            ),
            (
                "HUB_DIRECT_VERIFY_METADATA",
                &self.metadata,
                &self.metadata_delivery_policy,
            ),
        ] {
            rendered.push_str(&format!(
                "\n[[queues.producers]]\nbinding = {}\nqueue = {}\n\n[[queues.consumers]]\nqueue = {}\nmax_batch_size = {}\nmax_batch_timeout = 1\nmax_concurrency = {}\nmax_retries = 3\n",
                crate::cloudflare::toml_string(binding), crate::cloudflare::toml_string(name),
                crate::cloudflare::toml_string(name), policy.maximum_batch_size.get(),
                policy.maximum_concurrent_invocations.as_ref()
                    .ok_or_else(|| anyhow::anyhow!("hosted queue invocation bound absent"))?.get(),
            ));
        }
        Ok(rendered)
    }
}
