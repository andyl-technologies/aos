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

mod clock;

pub use clock::HybridDirectUploadClockConfig;

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
    /// Commitment to separately reviewed mutation-clock qualification evidence.
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
        use aos_hub_core::direct_upload::{valid_direct_digest, valid_direct_identity};

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
                && valid_direct_digest(&self.private_stage_policy.policy_digest)
                && self.private_stage_policy.namespace == self.bucket_namespace
                && (1..=i64::MAX as u64).contains(&generation)
                && self.credential_generation == generation.to_string()
                && valid_direct_digest(&self.clock_qualification)
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
            "HUB_DIRECT_UPLOAD_CLOCK_QUALIFICATION = {}\nHUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS = {}\n",
            super::toml_string(&self.clock_qualification),
            super::toml_string(&self.clock_uncertainty_seconds)
        ));
        rendered
    }
}

fn read_config_file<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    const MAX_CONFIG_BYTES: usize = 16 * 1024;

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
    file.take((MAX_CONFIG_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .context("reading direct upload deployment file")?;
    ensure!(
        bytes.len() <= MAX_CONFIG_BYTES,
        "direct upload deployment file is too large"
    );
    serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("direct upload deployment file is invalid"))
}

pub(super) const DIRECT_UPLOAD_BINDING: &str = "\n[[durable_objects.bindings]]\nname = \"HYBRID_DIRECT_UPLOAD\"\nclass_name = \"HybridDirectUpload\"\n\n[[migrations]]\ntag = \"hybrid-direct-upload-v1\"\nnew_sqlite_classes = [\"HybridDirectUpload\"]\n";

#[cfg(test)]
mod tests {
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
            clock_qualification: "cd".repeat(32),
            clock_uncertainty_seconds: "1".into(),
            private_stage_policy: DirectPrivateStagePolicyRef {
                policy_id: "staging-private".into(),
                policy_digest: "ab".repeat(32),
                namespace: "staging-surfaces".into(),
            },
        }
    }

    fn config() -> HybridDeployConfig {
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
            Some("ab".repeat(32).as_str())
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
            qualification: "cd".repeat(32),
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
            "qualification": "cd".repeat(32),
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
