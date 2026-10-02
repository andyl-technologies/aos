//! Independently installed copy domains and provider closure requirements.
//!
//! Copy requests cannot install cohorts, narrow the qualification requirements
//! or select a larger provider pool. A profile commitment covers the entire
//! configured domain; the permanent owner compares it on every control. These
//! structural checks do not perform or replace actual provider qualification.
//!
//! ```text
//! config = {version: 1, domains: [{issuer_installation,
//!           producer_profile_digest, provider_contract,
//!           read_cohort, list_cohort, write_cohort, part_bytes,
//!           provider_concurrency, maximum_list_page_objects, maximum_list_pages}]}
//! ```

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::{MAX_DIRECT_PART_BYTES, MIN_DIRECT_PART_BYTES};
use aos_hub_core::storage_authority::{
    control::StorageAuthorityObjectScope,
    external_object::copy::ExternalCopyOriginal,
    lease::{control::IssuerInstallation, LeaseCohort, LeaseEffect, LeaseInteger, LeasePurpose},
};
use serde::{Deserialize, Serialize};

use super::super::{
    config::Config as ObjectConfig,
    protocol::{digest, digest_string},
};

pub(super) const CONFIG_VAR: &str = "HUB_EXTERNAL_COPY_CONSUMER";
const MAX_CONFIG_BYTES: usize = 256 * 1024;

/// Records independently reviewed copy-specific provider behavior.
///
/// The evidence must describe the actual configured provider and runtime.
/// Existing private-stage or deletion qualification alone supplies none of
/// these properties. In particular, a null version cannot satisfy either
/// versioned read or positive completion identity.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProviderContract {
    pub contract_id: String,
    pub evidence_digest: String,
    pub versioned_conditional_range_read: bool,
    pub versioned_multipart_complete: bool,
    pub private_incomplete_upload: bool,
    pub completed_upload_rejects_late_parts: bool,
    pub abort_closes_upload_id: bool,
    pub upload_part_checksum_enforced: bool,
    pub versioned_empty_put: bool,
}

/// Binds one exact installed provider domain to its purpose-local cohorts.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Domain {
    pub issuer_installation: IssuerInstallation,
    pub producer_profile_digest: String,
    pub provider_contract: ProviderContract,
    pub read_cohort: LeaseCohort,
    pub list_cohort: LeaseCohort,
    pub write_cohort: LeaseCohort,
    pub part_bytes: LeaseInteger,
    pub provider_concurrency: u8,
    pub maximum_list_page_objects: u32,
    pub maximum_list_pages: u32,
}

impl Domain {
    /// Commits the exact installed provider, cohorts and execution bounds.
    ///
    /// # Errors
    /// Returns an error when canonical serialization fails.
    pub(super) fn commitment(&self) -> Result<String> {
        digest(&("aos.external-copy-configured-domain.v1", self))
    }

    fn validate(&self, object: &ObjectConfig) -> Result<()> {
        self.issuer_installation.validate()?;
        ensure!(
            self.issuer_installation.authority == self.write_cohort.authority
                && self.issuer_installation.executor_identity == object.executor_identity
                && digest_string(&self.producer_profile_digest)
                && (MIN_DIRECT_PART_BYTES..=MAX_DIRECT_PART_BYTES)
                    .contains(&(self.part_bytes.get() as u64))
                && (3..=32).contains(&self.provider_concurrency)
                && self.maximum_list_page_objects > 0
                && self.maximum_list_page_objects
                    <= aos_hub_core::fetch::WORKER_MAX_SURFACE_LIST_PAGE_OBJECTS as u32
                && self.maximum_list_pages > 0
                && self.maximum_list_pages
                    <= aos_hub_core::fetch::WORKER_MAX_SURFACE_LIST_PAGES as u32,
            "copy execution bounds or protected producer profile differ"
        );
        let provider = &self.provider_contract;
        ensure!(
            !provider.contract_id.is_empty()
                && provider.contract_id.len() <= 128
                && !provider.contract_id.chars().any(char::is_control)
                && digest_string(&provider.evidence_digest)
                && provider.versioned_conditional_range_read
                && provider.versioned_multipart_complete
                && provider.private_incomplete_upload
                && provider.completed_upload_rejects_late_parts
                && provider.abort_closes_upload_id
                && provider.upload_part_checksum_enforced,
            "copy-specific provider closure is unqualified"
        );

        // ObjectConfig validates the actual reviewed publication projection.
        // Equality here prevents a request or copy-only configuration from
        // introducing an otherwise valid but independently uninstalled cohort.
        for (cohort, purpose, effects) in [
            (
                &self.read_cohort,
                LeasePurpose::Read,
                &[LeaseEffect::Head, LeaseEffect::Read][..],
            ),
            (
                &self.list_cohort,
                LeasePurpose::List,
                &[LeaseEffect::List][..],
            ),
            (
                &self.write_cohort,
                LeasePurpose::Write,
                &[
                    LeaseEffect::MultipartCreate,
                    LeaseEffect::MultipartPart,
                    LeaseEffect::MultipartComplete,
                    LeaseEffect::MultipartAbort,
                ][..],
            ),
        ] {
            ensure!(
                object.cohort(&digest(cohort)?)? == cohort
                    && cohort.credential.purpose == purpose
                    && effects
                        .iter()
                        .all(|effect| cohort.allowed_effects.contains(effect)),
                "copy purpose cohort is not independently installed"
            );
            ensure!(
                cohort.authority == self.write_cohort.authority
                    && cohort.association == self.write_cohort.association
                    && cohort.alias == self.write_cohort.alias
                    && cohort.admitted_prefix == self.write_cohort.admitted_prefix
                    && cohort.publication_digest == self.write_cohort.publication_digest,
                "copy purpose cohorts select different physical domains"
            );
        }
        ensure!(
            !provider.versioned_empty_put
                || self
                    .write_cohort
                    .allowed_effects
                    .contains(&LeaseEffect::Put),
            "empty copy requires separately configured PUT permission"
        );
        Ok(())
    }

    /// Compares an owner with the installed domain before any provider effect.
    ///
    /// # Errors
    /// Refuses changed profile, association, credential generation, part geometry,
    /// unqualified empty PUT or either physical key outside the admitted prefix.
    pub(super) fn validate_original(
        &self,
        object: &ObjectConfig,
        original: &ExternalCopyOriginal,
    ) -> Result<()> {
        self.validate(object)?;
        original.validate()?;
        let association = &self.write_cohort.association;
        ensure!(
            original.profile_digest == self.commitment()?
                && original.binding_id == association.binding_id
                && original.binding_stable_id == association.binding_stable_id
                && original.binding_resource_version == association.binding_resource_version
                && original.binding_write_revision == association.binding_write_revision
                && original.read_generation == self.read_cohort.credential.generation
                && original.write_generation == self.write_cohort.credential.generation
                && original.part_bytes == self.part_bytes
                && (original.source_object.bytes.get() > 0
                    || self.provider_contract.versioned_empty_put),
            "copy owner differs from independently installed domain"
        );
        let mut keys = Vec::with_capacity(2);
        for placement in [&original.source, &original.destination] {
            let relative = aos_hub_core::keymap::r2_key(&placement.prefix, &original.path);
            let key = aos_hub_core::keymap::r2_key(&association.binding_prefix, &relative);
            ensure!(
                contained(&self.write_cohort.admitted_prefix, &key),
                "copy physical key escapes configured domain"
            );
            object.scope(&self.write_cohort, key)?;
            keys.push(aos_hub_core::keymap::r2_key(
                &association.binding_prefix,
                &relative,
            ));
        }
        ensure!(
            keys[0] != keys[1],
            "copy source and destination resolve to the same key"
        );
        Ok(())
    }

    /// Resolves a read-only SQL selector without selecting a fresh source incarnation.
    ///
    /// # Errors
    /// Refuses a foreign profile, binding pin, collapsed key or escaped prefix.
    pub(super) fn selector_scope(
        &self,
        object: &ObjectConfig,
        selector: &aos_hub_core::storage_authority::external_object::copy::original_lookup::CopyOriginalSelector,
    ) -> Result<StorageAuthorityObjectScope> {
        self.validate(object)?;
        selector.validate()?;
        let association = &self.write_cohort.association;
        ensure!(
            selector.profile_digest == self.commitment()?
                && selector.destination.binding_id == association.binding_id
                && selector.binding_stable_id == association.binding_stable_id
                && selector.binding_resource_version == association.binding_resource_version,
            "copy lookup selects a different installed binding"
        );
        let mut keys = Vec::with_capacity(2);
        for placement in [&selector.source, &selector.destination] {
            let relative = aos_hub_core::keymap::r2_key(&placement.prefix, &selector.path);
            let key = aos_hub_core::keymap::r2_key(&association.binding_prefix, &relative);
            ensure!(
                contained(&self.write_cohort.admitted_prefix, &key),
                "copy lookup escapes configured domain"
            );
            keys.push(key);
        }
        ensure!(keys[0] != keys[1], "copy lookup collapses physical keys");
        object.scope(&self.write_cohort, keys.remove(1))
    }

    /// Resolves the original physical key under its independently installed cohort.
    ///
    /// # Errors
    /// Refuses changed originals, profile pins or a key outside the admitted domain.
    pub(super) fn scope(
        &self,
        object: &ObjectConfig,
        original: &ExternalCopyOriginal,
        destination: bool,
    ) -> Result<StorageAuthorityObjectScope> {
        self.validate_original(object, original)?;
        let placement = if destination {
            &original.destination
        } else {
            &original.source
        };
        let relative = aos_hub_core::keymap::r2_key(&placement.prefix, &original.path);
        let key =
            aos_hub_core::keymap::r2_key(&self.write_cohort.association.binding_prefix, &relative);
        object.scope(&self.write_cohort, key)
    }
}

/// Bounds all installed copy domains without deriving them from a work request.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    pub version: u8,
    pub domains: Vec<Domain>,
}

impl Config {
    /// Parses independently supplied configuration within a fixed input budget.
    ///
    /// # Errors
    /// Refuses oversized, malformed, duplicate, uninstalled or unqualified domains.
    pub(super) fn parse(raw: &str, object: &ObjectConfig) -> Result<Self> {
        ensure!(
            raw.len() <= MAX_CONFIG_BYTES,
            "copy configuration oversized"
        );
        let value: Self = serde_json::from_str(raw)?;
        value.validate(object)?;
        Ok(value)
    }

    fn validate(&self, object: &ObjectConfig) -> Result<()> {
        object.validate()?;
        ensure!(
            self.version == 1 && !self.domains.is_empty() && self.domains.len() <= 16,
            "invalid copy configuration bounds"
        );
        let mut bindings = std::collections::BTreeSet::new();
        for domain in &self.domains {
            domain.validate(object)?;
            ensure!(
                bindings.insert(domain.write_cohort.association.binding_id),
                "ambiguous installed copy binding"
            );
            ensure!(
                domain.provider_concurrency == self.domains[0].provider_concurrency,
                "copy domains select different isolate provider capacities"
            );
        }
        Ok(())
    }

    /// Resolves only the installed domain named by the retained owner commitment.
    ///
    /// # Errors
    /// Refuses an absent or changed commitment and any original pin mismatch.
    pub(super) fn domain(
        &self,
        object: &ObjectConfig,
        original: &ExternalCopyOriginal,
    ) -> Result<&Domain> {
        self.validate(object)?;
        let domain = self
            .domains
            .iter()
            .find(|domain| {
                domain
                    .commitment()
                    .is_ok_and(|value| value == original.profile_digest)
            })
            .ok_or_else(|| anyhow::anyhow!("copy profile is not independently installed"))?;
        domain.validate_original(object, original)?;
        Ok(domain)
    }
}

fn contained(prefix: &str, key: &str) -> bool {
    prefix.is_empty()
        || key == prefix
        || key
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

#[cfg(target_arch = "wasm32")]
pub(super) fn configured(env: &worker::Env, object: &ObjectConfig) -> Result<Option<Config>> {
    let raw = js_sys::Reflect::get(env.as_ref(), &wasm_bindgen::JsValue::from_str(CONFIG_VAR))
        .map_err(|_| anyhow::anyhow!("copy configuration unavailable"))?;
    if raw.is_undefined() {
        return Ok(None);
    }
    let raw = raw
        .as_string()
        .ok_or_else(|| anyhow::anyhow!("copy configuration must be a JSON string"))?;
    Config::parse(&raw, object).map(Some)
}

#[cfg(test)]
pub(super) mod tests;
