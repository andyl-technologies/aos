//! Loads trusted GCE assignment policy before any signing-file or network access.
//!
//! The signing issuer names an entry in `static_workload_issuers`. Assignments
//! come solely from operator configuration, including job identity and grants.
//! Presented identity tokens supply authentication evidence, never this policy.
//!
//! ```toml
//! [gcp_instance_issuers.runner]
//! signing_issuer = "ci"
//! audience = "https://warehouse.example/identity"
//! timeout_ms = 10000
//! [[gcp_instance_issuers.runner.assignments]]
//! project_id = "build-project"
//! project_number = 123
//! zone = "us-central1-a"
//! instance_id = "456"
//! creation_timestamp = 1700000000
//! service_account_subject = "789"
//! [gcp_instance_issuers.runner.assignments.job]
//! subject = "ci"
//! workload = "run-123"
//! expected_end = 1700000900
//! groups = []
//! grants = [{ pattern = "refs/heads/ci/pr/123", verbs = ["commit"] }]
//! ```

use std::collections::BTreeMap;

use serde::Deserialize;

use super::{ConfigError, StaticWorkloadIssuer};
use crate::config::local_repository::TrustedAclVerb;

/// Supplies trusted instance exchange policy and a configured signing issuer.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpInstanceIssuer {
    /// Selects an entry in the trusted static workload issuer map.
    pub signing_issuer: String,
    /// Requires the Google identity token's audience to match exactly.
    pub audience: String,
    /// Bounds the whole exchange in milliseconds, from 1 through 30000.
    pub timeout_ms: u64,
    /// Assigns each exact instance to one job and its independently trusted grants.
    pub assignments: Vec<InstanceAssignment>,
}

/// Binds one declared GCE incarnation and service account to a configured job.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceAssignment {
    /// Names the project containing the assigned VM.
    pub project_id: String,
    /// Gives the project's immutable numeric identifier.
    pub project_number: u64,
    /// Names the assigned zone.
    pub zone: String,
    /// Gives the immutable decimal instance identifier.
    pub instance_id: String,
    /// Binds the assignment to its VM creation timestamp in Unix seconds.
    pub creation_timestamp: u64,
    /// Gives the service account's decimal subject, independently of its email.
    pub service_account_subject: String,
    /// Supplies trusted job identity, lifetime and initial grant policy.
    pub job: Job,
}

/// Holds workload claims supplied only by trusted provisioning configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Job {
    /// Names the workload principal.
    pub subject: String,
    /// Identifies the concrete assigned job or run.
    pub workload: String,
    /// Supplies independently trusted groups; omission grants no membership.
    #[serde(default)]
    pub groups: Vec<String>,
    /// Supplies initial grants; no grant comes from the Google token.
    pub grants: Vec<Grant>,
    /// Gives the expected job completion time in Unix seconds.
    pub expected_end: u64,
    /// Requests an optional earlier token expiry bound.
    pub not_after: Option<u64>,
}

/// Supplies one configured token grant using the registered verb vocabulary.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    /// Names the exact ref or validated ref glob covered by this grant.
    pub pattern: String,
    /// Selects the granted operations; an empty list is invalid.
    pub verbs: Vec<TrustedAclVerb>,
}

pub(in crate::config) fn validate(
    issuers: &BTreeMap<String, GcpInstanceIssuer>,
    signing: &BTreeMap<String, StaticWorkloadIssuer>,
) -> Result<(), ConfigError> {
    #[cfg(not(feature = "tokio"))]
    if !issuers.is_empty() {
        return Err(ConfigError::Invalid(
            "GCP workload issuers require tokio support",
        ));
    }

    for (name, issuer) in issuers {
        if name.is_empty() || !signing.contains_key(&issuer.signing_issuer) {
            return Err(ConfigError::Invalid("unknown GCP workload signing issuer"));
        }
        #[cfg(feature = "tokio")]
        issuer.settings()?;
    }
    Ok(())
}

#[cfg(feature = "tokio")]
pub(super) struct Settings {
    pub(super) assignments: Vec<crate::workload::gcp::InstanceAssignment>,
    pub(super) timeout: std::time::Duration,
}

#[cfg(feature = "tokio")]
impl GcpInstanceIssuer {
    pub(super) fn settings(&self) -> Result<Settings, ConfigError> {
        let assignments = self
            .assignments
            .iter()
            .map(|assignment| {
                Ok(crate::workload::gcp::InstanceAssignment {
                    project_id: assignment.project_id.clone(),
                    project_number: assignment.project_number,
                    zone: assignment.zone.clone(),
                    instance_id: assignment.instance_id.clone(),
                    creation_timestamp: assignment.creation_timestamp,
                    service_account_subject: assignment.service_account_subject.clone(),
                    job: assignment.job.claims()?,
                })
            })
            .collect::<Result<Vec<_>, ConfigError>>()?;
        let timeout = std::time::Duration::from_millis(self.timeout_ms);
        crate::workload::gcp::validate_configuration(&self.audience, &assignments, timeout)
            .map_err(|_| ConfigError::Invalid("invalid GCP workload assignment policy"))?;

        Ok(Settings {
            assignments,
            timeout,
        })
    }
}

#[cfg(feature = "tokio")]
impl Job {
    fn claims(&self) -> Result<crate::workload::WorkloadClaims, ConfigError> {
        if self.expected_end == 0
            || self.expected_end == u64::MAX
            || self
                .not_after
                .is_some_and(|expiry| expiry == 0 || expiry == u64::MAX)
            || self.groups.iter().any(String::is_empty)
        {
            return Err(ConfigError::Invalid("invalid GCP workload job claims"));
        }
        let grants = self
            .grants
            .iter()
            .map(Grant::grant)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(crate::workload::WorkloadClaims {
            subject: self.subject.clone(),
            workload: self.workload.clone(),
            groups: self.groups.clone(),
            grants,
            expected_end: self.expected_end,
            not_after: self.not_after,
        })
    }
}

#[cfg(feature = "tokio")]
impl Grant {
    fn grant(&self) -> Result<terrane_format::auth::Grant, ConfigError> {
        use terrane_format::auth::{Grant, Verb, Verbs};

        let mask = self.verbs.iter().fold(0, |mask, verb| {
            mask | match verb {
                TrustedAclVerb::Read => Verb::Read as u8,
                TrustedAclVerb::Fork => Verb::Fork as u8,
                TrustedAclVerb::Commit => Verb::Commit as u8,
                TrustedAclVerb::Tag => Verb::Tag as u8,
                TrustedAclVerb::Admin => Verb::Admin as u8,
            }
        });
        Verbs::new(mask)
            .and_then(|verbs| Grant::new(self.pattern.clone(), verbs))
            .map_err(|_| ConfigError::Invalid("invalid GCP workload grant"))
    }
}
