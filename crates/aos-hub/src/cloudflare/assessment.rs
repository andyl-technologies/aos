//! Explicit assessment executor provisioning and protected source secret delivery.
//!
//! Worker-only deployments may additionally install the shared coordinator.
//! Hybrid installs physical evidence custody and attempt journals; Native keeps
//! its logical database and reviewed schedule authority.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context as _, Result};
use aos_assessment_runtime::credentials::SourceCredentialSetV1;
use aos_assessment_runtime::installation::WorkerAssessmentInstallationV1;
use aos_contract::limits::JsonLimits;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{toml_string, Assets};

/// Installs separately authenticated assessment execution on an edge deployment.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AssessmentEdgeProfileV1 {
    /// Exact supported closed deployment profile.
    pub schema: String,
    /// Installed Native/Worker deployment incarnation.
    pub deployment_id: String,
    /// Independently installed coordinator identity.
    pub coordinator_id: String,
    /// Independently installed physical executor identity.
    pub executor_id: String,
    /// Dedicated R2 bucket retaining raw bodies in this executor's custody.
    pub evidence_bucket: String,
    /// Explicit source observation freshness, from one second through one day.
    pub source_ttl_seconds: u32,
    /// Reviewed source credentials containing binding references only.
    pub credentials: SourceCredentialSetV1,
    /// Optional logical coordinator; prohibited on Hybrid edge deployments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker: Option<WorkerAssessmentInstallationV1>,
}

impl AssessmentEdgeProfileV1 {
    /// Reads a bounded closed profile from an owner-private operator file.
    ///
    /// # Errors
    /// Returns an error for insecure file custody, ambiguous JSON or invalid profile.
    pub fn from_file(path: &Path) -> Result<Self> {
        let bytes = crate::auth::seal::read_secret_file(path)?;
        let profile: Self = JsonLimits {
            max_bytes: 262_144,
            max_depth: 24,
            max_items: 32_768,
            max_string_bytes: 4096,
        }
        .decode(&bytes, "assessment edge installation")?;
        profile.validate(&profile.deployment_id, false)?;
        Ok(profile)
    }

    /// Validates exact deployment pairing and logical coordinator placement.
    ///
    /// # Errors
    /// Returns an error for incompatible identity, scope, quota, freshness or custody.
    pub fn validate(&self, deployment: &str, hybrid: bool) -> Result<()> {
        ensure!(
            self.schema == "aos.assessment-edge-profile/v1" && self.deployment_id == deployment,
            "assessment edge deployment differs from its pairing"
        );
        for identity in [&self.deployment_id, &self.coordinator_id, &self.executor_id] {
            ensure!(
                !identity.is_empty()
                    && identity.len() <= 128
                    && identity
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)),
                "assessment edge identity is invalid"
            );
        }
        ensure!(
            self.evidence_bucket.len() >= 3
                && self.evidence_bucket.len() <= 63
                && self
                    .evidence_bucket
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
            "assessment evidence bucket is invalid"
        );
        ensure!(
            (1..=86400).contains(&self.source_ttl_seconds),
            "assessment freshness exceeds its bounds"
        );
        self.credentials.validate()?;
        for grant in &self.credentials.grants {
            ensure!(
                grant.secret_binding.starts_with("ASSESSMENT_")
                    && grant.secret_binding != "ASSESSMENT_EVIDENCE"
                    && grant.secret_binding != "ASSESSMENT_PROVIDER_TASKS",
                "assessment source secrets require separate ASSESSMENT_ bindings"
            );
        }
        ensure!(
            !hybrid || self.worker.is_none(),
            "Hybrid assessment coordination remains Native"
        );
        if let Some(worker) = &self.worker {
            worker.validate()?;
            ensure!(
                worker.routes.deployment_id == self.deployment_id
                    && worker.routes.coordinator_id == self.coordinator_id
                    && worker.routes.executor_id == self.executor_id
                    && worker.credentials == self.credentials,
                "assessment edge and coordinator installations differ"
            );
        }
        Ok(())
    }

    pub(super) fn variables(&self) -> Result<String> {
        let mut variables = format!(
            "HUB_ASSESSMENT_COORDINATOR_ID = {}\nHUB_ASSESSMENT_EXECUTOR_ID = {}\nHUB_ASSESSMENT_SOURCE_TTL_SECONDS = {}\nHUB_ASSESSMENT_CREDENTIALS = {}\n",
            toml_string(&self.coordinator_id), toml_string(&self.executor_id),
            toml_string(&self.source_ttl_seconds.to_string()),
            toml_string(&serde_json::to_string(&self.credentials)?),
        );
        if let Some(worker) = &self.worker {
            variables.push_str(&format!(
                "HUB_ASSESSMENT_CONFIG = {}\n",
                toml_string(&serde_json::to_string(worker)?)
            ));
        }
        Ok(variables)
    }

    pub(super) fn bindings(&self) -> String {
        format!("\n[[r2_buckets]]\nbinding = \"ASSESSMENT_EVIDENCE\"\nbucket_name = {}\n\n[[durable_objects.bindings]]\nname = \"ASSESSMENT_PROVIDER_TASKS\"\nclass_name = \"AssessmentProviderObject\"\n\n[[migrations]]\ntag = \"assessment-provider-attempt-v1\"\nnew_classes = [\"AssessmentProviderObject\"]\n",
            toml_string(&self.evidence_bucket))
    }

    fn required_secret_bindings(&self) -> BTreeSet<String> {
        self.credentials
            .grants
            .iter()
            .map(|grant| grant.secret_binding.clone())
            .chain(std::iter::once("HUB_ASSESSMENT_WORK_KEY".into()))
            .collect()
    }
}

/// Supplies explicit rotations while preserving omitted deployed assessment secrets.
///
/// Secret bytes are zeroized and never rendered into generated configuration.
pub struct AssessmentDeploymentSecrets {
    entries: BTreeMap<String, Zeroizing<String>>,
}

impl AssessmentDeploymentSecrets {
    /// Reads a work key and a bounded binding-to-private-file source manifest.
    ///
    /// # Errors
    /// Returns an error for insecure custody, unselected bindings or invalid secrets.
    pub fn from_files(
        profile: Option<&AssessmentEdgeProfileV1>,
        work_key: Option<&Path>,
        source_manifest: Option<&Path>,
    ) -> Result<Self> {
        ensure!(
            profile.is_some() || (work_key.is_none() && source_manifest.is_none()),
            "assessment secret files require an explicit edge profile"
        );
        let mut entries = BTreeMap::new();
        if let Some(path) = work_key {
            let value = private_text(path)?;
            ensure!(
                value.len() >= 32,
                "assessment work key requires at least thirty-two bytes"
            );
            entries.insert("HUB_ASSESSMENT_WORK_KEY".into(), value);
        }
        if let Some(path) = source_manifest {
            let bytes = crate::auth::seal::read_secret_file(path)?;
            let files: BTreeMap<String, PathBuf> = JsonLimits {
                max_bytes: 65_536,
                max_depth: 4,
                max_items: 512,
                max_string_bytes: 4096,
            }
            .decode(&bytes, "assessment source secret file manifest")?;
            let profile = profile.context("assessment profile is absent")?;
            let allowed = profile.required_secret_bindings();
            for (binding, path) in files {
                ensure!(
                    binding != "HUB_ASSESSMENT_WORK_KEY"
                        && allowed.contains(&binding)
                        && path.is_absolute(),
                    "source secret file is outside the reviewed installation"
                );
                entries.insert(binding, private_text(&path)?);
            }
        }
        Ok(Self { entries })
    }

    pub(super) fn require_bindings(
        &self,
        profile: Option<&AssessmentEdgeProfileV1>,
        existing: &[String],
    ) -> Result<()> {
        if let Some(profile) = profile {
            for binding in profile.required_secret_bindings() {
                ensure!(
                    self.entries.contains_key(&binding) || existing.contains(&binding),
                    "assessment installation requires protected binding {binding}"
                );
            }
        }
        Ok(())
    }

    pub(super) fn require_separate(&self, controls: &[&str]) -> Result<()> {
        if let Some(key) = self.entries.get("HUB_ASSESSMENT_WORK_KEY") {
            ensure!(
                controls.iter().all(|other| *other != key.as_str()),
                "assessment work key requires independent control material"
            );
        }
        Ok(())
    }

    pub(super) async fn apply(&self, assets: &Assets, config: &Path) -> Result<()> {
        for (binding, value) in &self.entries {
            super::run_wrangler(
                assets,
                &super::secret_put_args(binding, config),
                Some(value.as_str()),
                None,
            )
            .await
            .map_err(|_| {
                anyhow::anyhow!("applying protected assessment binding {binding} failed")
            })?;
        }
        Ok(())
    }
}

fn private_text(path: &Path) -> Result<Zeroizing<String>> {
    let bytes = Zeroizing::new(crate::auth::seal::read_secret_file(path)?);
    let value = Zeroizing::new(
        std::str::from_utf8(&bytes)
            .context("assessment secret must be UTF-8")?
            .trim_end_matches(['\n', '\r'])
            .to_owned(),
    );
    ensure!(
        !value.is_empty() && value.len() <= 2048 && !value.chars().any(char::is_control),
        "assessment secret has invalid text or length"
    );
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_assessment::time::Timestamp;
    use aos_assessment_runtime::provider::ProviderLimits;
    use aos_assessment_runtime::routes::{
        InstalledSourceBudget, InstalledSourceRoute, InstalledSourceRoutesV1,
    };

    fn profile() -> AssessmentEdgeProfileV1 {
        AssessmentEdgeProfileV1 {
            schema: "aos.assessment-edge-profile/v1".into(),
            deployment_id: "deployment-1".into(),
            coordinator_id: "coordinator".into(),
            executor_id: "executor".into(),
            evidence_bucket: "assessment-evidence".into(),
            source_ttl_seconds: 3600,
            credentials: SourceCredentialSetV1 {
                schema: "aos.assessment-source-credentials/v1".into(),
                grants: vec![],
            },
            worker: None,
        }
    }

    fn worker_configuration(profile: &AssessmentEdgeProfileV1) -> WorkerAssessmentInstallationV1 {
        WorkerAssessmentInstallationV1 {
            schema: "aos.assessment-worker-installation/v1".into(),
            routes: InstalledSourceRoutesV1 {
                schema: "aos.assessment-source-routes/v1".into(),
                deployment_id: profile.deployment_id.clone(),
                coordinator_id: profile.coordinator_id.clone(),
                executor_id: profile.executor_id.clone(),
                routes: vec![InstalledSourceRoute {
                    partition: "registry-partition".into(),
                    provider: "github-tags".into(),
                    budget_key: "github-public".into(),
                    credential_ref: None,
                    expires_at: Timestamp::parse("2099-01-01T00:00:00Z").unwrap(),
                    limits: ProviderLimits::default(),
                }],
            },
            budgets: vec![InstalledSourceBudget {
                key: "github-public".into(),
                window_seconds: 3600,
                allowance: 100,
                min_interval_seconds: 0,
            }],
            credentials: profile.credentials.clone(),
            policy: serde_json::from_value(serde_json::json!({
                "schema": "aos.assessment-policy/v1", "upstreamMaxAgeSeconds": 86400,
                "advisoryMaxAgeSeconds": 86400, "requiredAdvisorySources": [],
                "requireDependencyCoverage": true
            }))
            .unwrap(),
        }
    }

    #[test]
    fn hybrid_profile_installs_raw_custody_without_logical_worker_authority() {
        let mut cfg = super::super::direct_upload::tests::config();
        cfg.assessment = Some(profile());
        let rendered = super::super::render_hybrid_wrangler_toml(&cfg).unwrap();
        let parsed: toml::Value = toml::from_str(&rendered).unwrap();
        assert_eq!(
            parsed["vars"]["HUB_ASSESSMENT_COORDINATOR_ID"].as_str(),
            Some("coordinator")
        );
        assert!(rendered.contains("AssessmentProviderObject"));
        assert!(rendered.contains("ASSESSMENT_EVIDENCE"));
        assert!(!rendered.contains("HUB_ASSESSMENT_CONFIG"));
        assert!(!rendered.contains("HUB_DB"));
        assert!(parsed.get("triggers").is_none());

        let profile = cfg.assessment.as_mut().unwrap();
        profile.worker = Some(worker_configuration(profile));
        assert!(super::super::render_hybrid_wrangler_toml(&cfg).is_err());
    }

    #[test]
    fn worker_profile_preserves_maintenance_cron_and_adds_independent_assessment_ticks() {
        let mut profile = profile();
        profile.worker = Some(worker_configuration(&profile));
        let cfg = super::super::DeployConfig {
            assessment: Some(profile),
            name: "assessment-hub".into(),
            bucket: "assessment-surfaces".into(),
            kv_id: "kv-id".into(),
            queue: "assessment-jobs".into(),
            rate_limit_namespaces: super::super::RateLimitNamespaces::from_base(1000).unwrap(),
            egress_gateway_url: None,
            external_url: "https://hub.fixture.invalid".into(),
            deployment_id: Some("deployment-1".into()),
            container_rollout: Default::default(),
            database_instance: "hub".into(),
            email_relay_url: None,
            email_from: None,
            custom_domains: vec![],
            serve_assets: false,
            observability: false,
            head_sampling_rate: 1.0,
            logpush: false,
        };
        let rendered = super::super::render_wrangler_toml(&cfg).unwrap();
        let parsed: toml::Value = toml::from_str(&rendered).unwrap();
        assert_eq!(
            parsed["triggers"]["crons"][0].as_str(),
            Some(super::super::INDEXER_CRON)
        );
        assert_eq!(parsed["triggers"]["crons"][1].as_str(), Some("* * * * *"));
        let configuration: WorkerAssessmentInstallationV1 =
            serde_json::from_str(parsed["vars"]["HUB_ASSESSMENT_CONFIG"].as_str().unwrap())
                .unwrap();
        configuration.validate().unwrap();
        assert!(rendered.contains("ASSESSMENT_EVIDENCE"));
        assert!(rendered.contains("HUB_DB"));
    }

    #[test]
    fn paired_keys_are_required_preserved_and_separate_from_other_control_roles() {
        let profile = profile();
        let empty = AssessmentDeploymentSecrets::from_files(Some(&profile), None, None).unwrap();
        assert!(empty.require_bindings(Some(&profile), &[]).is_err());
        empty
            .require_bindings(Some(&profile), &["HUB_ASSESSMENT_WORK_KEY".into()])
            .unwrap();
        let mut supplied = AssessmentDeploymentSecrets {
            entries: BTreeMap::new(),
        };
        supplied.entries.insert(
            "HUB_ASSESSMENT_WORK_KEY".into(),
            Zeroizing::new("k".repeat(64)),
        );
        supplied.require_bindings(Some(&profile), &[]).unwrap();
        assert!(supplied.require_separate(&[&"k".repeat(64)]).is_err());
        supplied.require_separate(&[&"s".repeat(64)]).unwrap();
        assert!(!profile.variables().unwrap().contains(&"k".repeat(64)));
        assert!(profile.validate("replacement-deployment", false).is_err());
    }
}
