//! Independently configured versioned-delete cohorts and issuer installations.
//!
//! ```text
//! HUB_EXTERNAL_DELETE_CONSUMER = {version: 1, domains: [
//!   {issuer_installation, delete_cohort,
//!    versioned_conditional_delete_evidence_digest}
//! ]}
//! ```
//!
//! The evidence pin names a separately reviewed provider contract. Parsing it
//! establishes no provider capability: Native still requires the actual bounded
//! conditional-delete probe for the exact SQL binding revision.

use anyhow::{ensure, Result};
use aos_hub_core::storage_authority::lease::{
    control::IssuerInstallation, LeaseCohort, LeaseEffect, LeasePurpose,
};
use serde::{Deserialize, Serialize};

use super::{config::Config as ObjectConfig, protocol::digest_string};

pub(super) const CONFIG_VAR: &str = "HUB_EXTERNAL_DELETE_CONSUMER";
const MAX_CONFIG: usize = 128 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Retains one independently configured delete issuer and exact cohort.
pub(super) struct DeleteDomain {
    /// Existing issuer installation trusted for this delete cohort.
    pub issuer_installation: IssuerInstallation,
    /// Exact delete-only cohort already admitted by the object configuration.
    pub delete_cohort: LeaseCohort,
    /// Independent provider-contract evidence pin, without enabling capability.
    pub versioned_conditional_delete_evidence_digest: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Bounds the independently configured versioned-delete domains.
pub(super) struct DeleteConfig {
    /// Closed configuration format version.
    pub version: u8,
    /// At most sixteen distinct independently admitted delete domains.
    pub domains: Vec<DeleteDomain>,
}

impl DeleteConfig {
    /// Parses bounded configuration against the existing admitted object cohorts.
    ///
    /// # Errors
    /// Returns an error for invalid bounds, duplicate domains, another issuer,
    /// non-delete authority, or a missing provider-contract evidence pin.
    pub(super) fn parse(raw: &str, object: &ObjectConfig) -> Result<Self> {
        ensure!(raw.len() <= MAX_CONFIG, "oversized delete configuration");
        let value: Self = serde_json::from_str(raw)?;
        object.validate()?;
        ensure!(
            value.version == 1 && !value.domains.is_empty() && value.domains.len() <= 16,
            "invalid delete configuration bounds"
        );
        let mut identities = std::collections::BTreeSet::new();
        for domain in &value.domains {
            domain.issuer_installation.validate()?;
            ensure!(
                domain.issuer_installation.authority == domain.delete_cohort.authority
                    && domain.issuer_installation.executor_identity == object.executor_identity
                    && domain.delete_cohort.credential.purpose == LeasePurpose::Delete
                    && domain.delete_cohort.allowed_effects == [LeaseEffect::ConditionalDelete]
                    && object.cohorts.contains(&domain.delete_cohort)
                    && digest_string(&domain.versioned_conditional_delete_evidence_digest)
                    && identities.insert(super::protocol::digest(&domain.delete_cohort)?),
                "delete domain differs from independently admitted cohorts"
            );
        }
        Ok(value)
    }

    /// Selects exactly one independently configured delete domain.
    ///
    /// # Errors
    /// Returns an error when the exact cohort is missing or ambiguous.
    pub(super) fn domain(&self, cohort: &LeaseCohort) -> Result<&DeleteDomain> {
        let mut domains = self
            .domains
            .iter()
            .filter(|domain| &domain.delete_cohort == cohort);
        let domain = domains
            .next()
            .ok_or_else(|| anyhow::anyhow!("delete domain unavailable"))?;
        ensure!(domains.next().is_none(), "delete domain ambiguous");
        Ok(domain)
    }
}

#[cfg(target_arch = "wasm32")]
/// Loads the explicit delete configuration without constructing new authority.
///
/// # Errors
/// Returns an error when configuration is absent, inaccessible, or invalid.
pub(super) fn configured(env: &worker::Env, object: &ObjectConfig) -> Result<DeleteConfig> {
    let raw = js_sys::Reflect::get(env.as_ref(), &wasm_bindgen::JsValue::from_str(CONFIG_VAR))
        .map_err(|_| anyhow::anyhow!("delete configuration unavailable"))?
        .as_string()
        .ok_or_else(|| anyhow::anyhow!("delete consumer disabled"))?;
    DeleteConfig::parse(&raw, object)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delete_configuration_cannot_project_read_authority_or_another_issuer() {
        let mut object = crate::external_object::tests::config();
        let cohort = LeaseCohort::from_publication(
            &object.publications[0],
            &object.executor_identity,
            "association-one",
            LeasePurpose::Delete,
            "managed/binding/objects",
            vec![LeaseEffect::ConditionalDelete],
        )
        .unwrap();
        object.cohorts.push(cohort.clone());
        let domain = DeleteDomain {
            issuer_installation: IssuerInstallation {
                format_version: 1,
                authority: cohort.authority.clone(),
                issuer_resource_id: "fixture-issuer-resource".into(),
                runtime_identity: "fixture-issuer-runtime".into(),
                executor_identity: object.executor_identity.clone(),
            },
            delete_cohort: cohort,
            versioned_conditional_delete_evidence_digest: "d".repeat(64),
        };
        let original = DeleteConfig {
            version: 1,
            domains: vec![domain.clone()],
        };
        let parsed =
            DeleteConfig::parse(&serde_json::to_string(&original).unwrap(), &object).unwrap();
        assert!(parsed.domain(&domain.delete_cohort).is_ok());

        let mut changed = original.clone();
        changed.domains[0].issuer_installation.executor_identity = "another-executor".into();
        assert!(DeleteConfig::parse(&serde_json::to_string(&changed).unwrap(), &object).is_err());
        changed = original.clone();
        changed.domains[0].delete_cohort = object.cohorts[1].clone();
        assert!(DeleteConfig::parse(&serde_json::to_string(&changed).unwrap(), &object).is_err());
        changed = original.clone();
        changed.domains.push(domain);
        assert!(DeleteConfig::parse(&serde_json::to_string(&changed).unwrap(), &object).is_err());
        changed = original;
        changed.domains[0]
            .versioned_conditional_delete_evidence_digest
            .clear();
        assert!(DeleteConfig::parse(&serde_json::to_string(&changed).unwrap(), &object).is_err());
    }
}
