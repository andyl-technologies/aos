//! Independently installed destination routes and shared notification quota domains.
//!
//! Subscription metadata cannot choose an executor, callback URL, signing key or
//! quota domain. A deployment installs these exact destination commitments before
//! its coordinator may claim work in any topology.

use std::collections::BTreeSet;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use super::NotificationDestinationV1;
use crate::routes::InstalledSourceBudget;
use crate::validation::{decode, encoded, text};

/// Binds one independently reviewed destination to its global callback allowance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct InstalledNotificationDestination {
    /// Exact destination, resource incarnation and immutable signing-key commitment.
    pub destination: NotificationDestinationV1,
    /// Global notification-only account allowance shared across execution lanes.
    pub budget_key: String,
}

/// Installs bounded notification effects independently of source-provider authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NotificationInstallationV1 {
    /// Exact supported installation discriminator.
    pub schema: String,
    /// Non-reusable deployment incarnation.
    pub deployment_id: String,
    /// Independently paired logical coordinator identity.
    pub coordinator_id: String,
    /// Independently paired physical notification executor identity.
    pub executor_id: String,
    /// Sorted unique resource/destination grants, at most 64.
    pub destinations: Vec<InstalledNotificationDestination>,
    /// Complete sorted notification-only quota domains, at most 64.
    pub budgets: Vec<InstalledSourceBudget>,
}

impl NotificationInstallationV1 {
    /// Decodes a closed bounded installation without installing keys or permissions.
    ///
    /// # Errors
    /// Returns an error for unknown fields, malformed grants or conflicting quotas.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let installation: Self = decode(bytes, "notification installation")?;
        installation.validate()?;
        Ok(installation)
    }

    /// Validates complete independent grants, quota domains and service pairing.
    ///
    /// # Errors
    /// Returns an error for unbounded, unsorted, repeated, missing or unused grants.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == "aos.assessment-notification-installation/v1"
                && (1..=64).contains(&self.destinations.len())
                && (1..=64).contains(&self.budgets.len()),
            "notification installation exceeds its schema or route bounds"
        );
        for identity in [&self.deployment_id, &self.coordinator_id, &self.executor_id] {
            text(identity, 128, "notification service identity")?;
        }
        ensure!(
            self.destinations.windows(2).all(|pair| {
                (
                    &pair[0].destination.resource_scope,
                    &pair[0].destination.destination_reference,
                ) < (
                    &pair[1].destination.resource_scope,
                    &pair[1].destination.destination_reference,
                )
            }) && self
                .budgets
                .windows(2)
                .all(|pair| pair[0].key < pair[1].key),
            "notification grants and quotas require sorted unique identities"
        );
        for route in &self.destinations {
            route.destination.validate()?;
            text(&route.budget_key, 128, "notification quota domain")?;
            ensure!(
                route.budget_key.starts_with("notification:"),
                "notification quotas require an independent domain"
            );
        }
        for budget in &self.budgets {
            text(&budget.key, 128, "notification quota domain")?;
            ensure!(
                budget.key.starts_with("notification:")
                    && (1..=86400).contains(&budget.window_seconds)
                    && (1..=1_000_000).contains(&budget.allowance)
                    && budget.min_interval_seconds <= 3600,
                "notification quota exceeds its independent effect ceilings"
            );
        }
        let declared: BTreeSet<_> = self.budgets.iter().map(|budget| &budget.key).collect();
        let required: BTreeSet<_> = self
            .destinations
            .iter()
            .map(|route| &route.budget_key)
            .collect();
        ensure!(
            declared == required,
            "notification quotas differ from exactly installed destinations"
        );
        encoded(self)?;
        Ok(())
    }
}

/// Maps one immutable callback key version to a dedicated Worker secret binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NotificationSecretBinding {
    /// Exact immutable version referenced by the installed destinations.
    pub version_reference: String,
    /// Dedicated `ASSESSMENT_NOTIFICATION_` binding containing the callback key.
    pub binding: String,
}

/// Installs finite Worker callback routes without retaining credential material.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WorkerNotificationInstallationV1 {
    /// Exact supported Worker installation discriminator.
    pub schema: String,
    /// Shared service pairing, destination grants and notification-only quotas.
    pub installation: NotificationInstallationV1,
    /// Exact HTTPS `/v1/fetch` gateway; native Worker Fetch cannot pin public DNS.
    pub egress_gateway_url: String,
    /// Sorted exact key versions and unique dedicated physical secret bindings.
    pub secret_bindings: Vec<NotificationSecretBinding>,
}

impl WorkerNotificationInstallationV1 {
    /// Decodes bounded installed references without resolving Worker credentials.
    ///
    /// # Errors
    /// Returns an error for unknown fields, conflicting authority or secret mappings.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let installation: Self = decode(bytes, "Worker notification installation")?;
        installation.validate()?;
        Ok(installation)
    }

    /// Requires exactly the independently installed immutable callback versions.
    ///
    /// Hosts additionally validate version references against their secret provider
    /// profile before deployment or resolution. These declarations contain no keys.
    ///
    /// # Errors
    /// Returns an error for unbounded, duplicated, missing or unused bindings.
    pub fn validate(&self) -> Result<()> {
        self.installation.validate()?;
        text(&self.egress_gateway_url, 2048, "notification gateway URL")?;
        let gateway = url::Url::parse(&self.egress_gateway_url)?;
        ensure!(
            gateway.scheme() == "https"
                && gateway.host_str().is_some()
                && gateway.path() == "/v1/fetch"
                && gateway.query().is_none()
                && gateway.fragment().is_none()
                && gateway.username().is_empty()
                && gateway.password().is_none(),
            "notification gateway requires its exact HTTPS route"
        );
        ensure!(
            self.schema == "aos.assessment-worker-notification-installation/v1"
                && (1..=64).contains(&self.secret_bindings.len())
                && self
                    .secret_bindings
                    .windows(2)
                    .all(|pair| { pair[0].version_reference < pair[1].version_reference }),
            "Worker notification versions require sorted unique bounded identities"
        );
        for secret in &self.secret_bindings {
            text(&secret.version_reference, 128, "notification key version")?;
            ensure!(
                secret.binding.starts_with("ASSESSMENT_NOTIFICATION_")
                    && secret.binding.len() > "ASSESSMENT_NOTIFICATION_".len()
                    && secret.binding.len() <= 96
                    && secret.binding.bytes().all(|byte| {
                        byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
                    }),
                "notification callback keys require dedicated Worker secret bindings"
            );
        }
        let required: BTreeSet<_> = self
            .installation
            .destinations
            .iter()
            .map(|route| &route.destination.secret_version_reference)
            .collect();
        let declared: BTreeSet<_> = self
            .secret_bindings
            .iter()
            .map(|secret| &secret.version_reference)
            .collect();
        let bindings: BTreeSet<_> = self
            .secret_bindings
            .iter()
            .map(|secret| &secret.binding)
            .collect();
        ensure!(
            required == declared && bindings.len() == self.secret_bindings.len(),
            "notification key versions differ from their exact unique custody bindings"
        );
        encoded(self)?;
        Ok(())
    }
}
