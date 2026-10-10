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
use aos_assessment_runtime::notifications::WorkerNotificationInstallationV1;
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
    /// Optional separately authenticated physical callbacks in every edge topology.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notifications: Option<WorkerNotificationInstallationV1>,
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
                    && !grant.secret_binding.starts_with("ASSESSMENT_NOTIFICATION_")
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
        if let Some(notifications) = &self.notifications {
            notifications.validate()?;
            ensure!(
                notifications.installation.deployment_id == self.deployment_id,
                "notification edge and coordinator pairing differs"
            );
            for version in &notifications.secret_bindings {
                aos_hub_core::secret_version::validate_secret_version_ref(
                    &version.version_reference,
                )?;
            }
            if let Some(worker) = &self.worker {
                ensure!(
                    worker.budgets.iter().all(|source| notifications
                        .installation
                        .budgets
                        .iter()
                        .all(|callback| callback.key != source.key)),
                    "source and callback quota domains must remain independent"
                );
            }
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
        if let Some(notifications) = &self.notifications {
            variables.push_str(&format!(
                "HUB_ASSESSMENT_NOTIFICATION_CONFIG = {}\nHUB_ASSESSMENT_NOTIFICATION_COORDINATOR_ID = {}\nHUB_ASSESSMENT_NOTIFICATION_EXECUTOR_ID = {}\n",
                toml_string(&serde_json::to_string(notifications)?),
                toml_string(&notifications.installation.coordinator_id),
                toml_string(&notifications.installation.executor_id),
            ));
        }
        Ok(variables)
    }

    pub(super) fn bindings(&self) -> String {
        let mut bindings = format!("\n[[r2_buckets]]\nbinding = \"ASSESSMENT_EVIDENCE\"\nbucket_name = {}\n\n[[durable_objects.bindings]]\nname = \"ASSESSMENT_PROVIDER_TASKS\"\nclass_name = \"AssessmentProviderObject\"\n\n[[migrations]]\ntag = \"assessment-provider-attempt-v1\"\nnew_classes = [\"AssessmentProviderObject\"]\n",
            toml_string(&self.evidence_bucket));
        if self.notifications.is_some() {
            bindings.push_str("\n[[durable_objects.bindings]]\nname = \"ASSESSMENT_NOTIFICATION_TASKS\"\nclass_name = \"AssessmentNotificationObject\"\n\n[[migrations]]\ntag = \"assessment-notification-attempt-v1\"\nnew_classes = [\"AssessmentNotificationObject\"]\n");
        }
        bindings
    }

    fn required_secret_bindings(&self) -> BTreeSet<String> {
        let mut bindings: BTreeSet<_> = self
            .credentials
            .grants
            .iter()
            .map(|grant| grant.secret_binding.clone())
            .chain(std::iter::once("HUB_ASSESSMENT_WORK_KEY".into()))
            .collect();
        if let Some(notifications) = &self.notifications {
            bindings.extend(
                notifications
                    .secret_bindings
                    .iter()
                    .map(|secret| secret.binding.clone()),
            );
            bindings.insert("HUB_ASSESSMENT_NOTIFICATION_WORK_KEY".into());
            bindings.insert("HUB_EGRESS_GATEWAY_KEY".into());
        }
        bindings
    }
}

/// Supplies explicit rotations while preserving omitted deployed assessment secrets.
///
/// Secret bytes are zeroized and never rendered into generated configuration.
pub struct AssessmentDeploymentSecrets {
    entries: BTreeMap<String, Zeroizing<String>>,
}

impl AssessmentDeploymentSecrets {
    /// Reads explicitly selected notification work, gateway and callback key files.
    ///
    /// Omitted installed secrets retain their deployed versions. The manifest
    /// selects only dedicated callback bindings and `HUB_EGRESS_GATEWAY_KEY`.
    ///
    /// # Errors
    /// Returns an error for absent installation, insecure files, unselected
    /// bindings, weak work keys or callback fingerprint mismatch.
    pub fn with_notifications(
        mut self,
        profile: Option<&AssessmentEdgeProfileV1>,
        work_key: Option<&Path>,
        manifest: Option<&Path>,
    ) -> Result<Self> {
        let installation = profile.and_then(|profile| profile.notifications.as_ref());
        ensure!(
            installation.is_some() || (work_key.is_none() && manifest.is_none()),
            "notification secret files require an explicit notification installation"
        );
        if let Some(path) = work_key {
            let value = private_text(path)?;
            ensure!(
                value.len() >= 32,
                "notification work key requires at least thirty-two bytes"
            );
            self.entries
                .insert("HUB_ASSESSMENT_NOTIFICATION_WORK_KEY".into(), value);
        }
        if let Some(path) = manifest {
            let installation = installation.context("notification installation is absent")?;
            let bytes = crate::auth::seal::read_secret_file(path)?;
            let files: BTreeMap<String, PathBuf> = JsonLimits {
                max_bytes: 65_536,
                max_depth: 4,
                max_items: 512,
                max_string_bytes: 4096,
            }
            .decode(&bytes, "notification secret file manifest")?;
            for (binding, path) in files {
                ensure!(
                    path.is_absolute(),
                    "notification secret paths must be absolute"
                );
                let selected = installation
                    .secret_bindings
                    .iter()
                    .find(|secret| secret.binding == binding);
                ensure!(
                    selected.is_some() || binding == "HUB_EGRESS_GATEWAY_KEY",
                    "notification secret binding is not explicitly installed"
                );
                let value = private_text(&path)?;
                if let Some(selected) = selected {
                    for destination in &installation.installation.destinations {
                        if destination.destination.secret_version_reference
                            == selected.version_reference
                        {
                            ensure!(
                                value.len() >= 32
                                    && aos_contract::Sha256Digest::of_bytes(value.as_bytes())
                                        == destination.destination.credential_fingerprint,
                                "notification key differs from its immutable fingerprint"
                            );
                        }
                    }
                }
                ensure!(
                    !self.entries.contains_key(&binding),
                    "notification secret binding is already selected"
                );
                self.entries.insert(binding, value);
            }
        }
        self.require_separate(&[])?;
        Ok(self)
    }

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
                    allowed.contains(&binding)
                        && profile
                            .credentials
                            .grants
                            .iter()
                            .any(|grant| grant.secret_binding == binding)
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
        for (binding, key) in &self.entries {
            if binding != "HUB_ASSESSMENT_WORK_KEY"
                && binding != "HUB_ASSESSMENT_NOTIFICATION_WORK_KEY"
                && !binding.starts_with("ASSESSMENT_NOTIFICATION_")
            {
                continue;
            }
            ensure!(
                controls.iter().all(|other| *other != key.as_str())
                    && self.entries.iter().all(|(other_binding, other)| {
                        other_binding == binding || other.as_str() != key.as_str()
                    }),
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

    pub(super) async fn confirm_notification_gateway(
        &self,
        profile: Option<&AssessmentEdgeProfileV1>,
    ) -> Result<()> {
        let Some(notifications) = profile.and_then(|profile| profile.notifications.as_ref()) else {
            return Ok(());
        };
        let key = self.entries.get("HUB_EGRESS_GATEWAY_KEY").context(
            "notification deployment requires the gateway key to qualify its callback contract",
        )?;
        super::authenticate_notification_gateway_contract(&notifications.egress_gateway_url, key)
            .await
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
            notifications: None,
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

    fn notification_configuration(
        profile: &AssessmentEdgeProfileV1,
    ) -> WorkerNotificationInstallationV1 {
        use aos_assessment_runtime::notifications::{
            InstalledNotificationDestination, NotificationDestinationV1,
            NotificationInstallationV1, NotificationSecretBinding,
        };
        WorkerNotificationInstallationV1 {
            schema: "aos.assessment-worker-notification-installation/v1".into(),
            egress_gateway_url: "https://egress.fixture.invalid/v1/fetch".into(),
            installation: NotificationInstallationV1 {
                schema: "aos.assessment-notification-installation/v1".into(),
                deployment_id: profile.deployment_id.clone(),
                coordinator_id: profile.coordinator_id.clone(),
                executor_id: profile.executor_id.clone(),
                destinations: vec![InstalledNotificationDestination {
                    destination: NotificationDestinationV1 {
                        schema: "aos.assessment-notification-destination/v1".into(),
                        destination_reference: "webhook:1".into(),
                        revision: 1,
                        resource_scope: "registry-partition".into(),
                        url: "https://receiver.example/callback".into(),
                        secret_version_reference: "worker://assessment/notification/v1".into(),
                        credential_fingerprint: aos_contract::Sha256Digest::of_bytes(
                            b"fixture-callback-key-thirty-two-bytes",
                        ),
                        expires_at: Timestamp::parse("2099-01-01T00:00:00Z").unwrap(),
                    },
                    budget_key: "notification:account".into(),
                }],
                budgets: vec![InstalledSourceBudget {
                    key: "notification:account".into(),
                    window_seconds: 60,
                    allowance: 10,
                    min_interval_seconds: 0,
                }],
            },
            secret_bindings: vec![NotificationSecretBinding {
                version_reference: "worker://assessment/notification/v1".into(),
                binding: "ASSESSMENT_NOTIFICATION_CALLBACK_V1".into(),
            }],
        }
    }

    #[test]
    fn notification_profiles_install_independent_attempts_without_hybrid_logical_authority() {
        let mut cfg = super::super::direct_upload::tests::config();
        let mut profile = profile();
        profile.notifications = Some(notification_configuration(&profile));
        cfg.assessment = Some(profile.clone());

        let rendered = super::super::render_hybrid_wrangler_toml(&cfg).unwrap();
        let parsed: toml::Value = toml::from_str(&rendered).unwrap();
        let notification: WorkerNotificationInstallationV1 = serde_json::from_str(
            parsed["vars"]["HUB_ASSESSMENT_NOTIFICATION_CONFIG"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(Some(notification), profile.notifications);
        assert!(rendered.contains("AssessmentNotificationObject"));
        assert!(!rendered.contains("HUB_DB"));
        assert!(!rendered.contains("fixture-callback-key-thirty-two-bytes"));
        assert!(parsed.get("triggers").is_none());
        let required = profile.required_secret_bindings();
        assert!(required.contains("HUB_ASSESSMENT_NOTIFICATION_WORK_KEY"));
        assert!(required.contains("HUB_EGRESS_GATEWAY_KEY"));
        assert!(required.contains("ASSESSMENT_NOTIFICATION_CALLBACK_V1"));

        let notifications = profile.notifications.as_mut().unwrap();
        notifications.installation.deployment_id = "unpaired".into();
        assert!(profile.validate("deployment-1", true).is_err());
    }

    #[test]
    fn notification_secret_selection_requires_installation_and_separate_material() {
        let empty = AssessmentDeploymentSecrets::from_files(None, None, None).unwrap();
        assert!(empty
            .with_notifications(None, Some(Path::new("/unselected")), None)
            .is_err());
        let mut entries = BTreeMap::new();
        entries.insert(
            "HUB_ASSESSMENT_WORK_KEY".into(),
            Zeroizing::new("shared-fixture-key-thirty-two-bytes".into()),
        );
        entries.insert(
            "HUB_ASSESSMENT_NOTIFICATION_WORK_KEY".into(),
            Zeroizing::new("shared-fixture-key-thirty-two-bytes".into()),
        );
        assert!(AssessmentDeploymentSecrets { entries }
            .require_separate(&[])
            .is_err());
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
