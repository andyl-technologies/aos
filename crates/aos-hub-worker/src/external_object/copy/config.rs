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

use anyhow::{Result, ensure};
use aos_hub_core::direct_upload::{MAX_DIRECT_PART_BYTES, MIN_DIRECT_PART_BYTES};
use aos_hub_core::storage_authority::{
    control::StorageAuthorityObjectScope,
    external_object::copy::{CopyIncarnationMode, ExternalCopyOriginal},
    lease::{LeaseCohort, LeaseEffect, LeaseInteger, LeasePurpose, control::IssuerInstallation},
};
use serde::{Deserialize, Serialize};

use super::super::{
    config::Config as ObjectConfig,
    protocol::{digest, digest_string},
};

pub(in crate::external_object) const CONFIG_VAR: &str = "HUB_EXTERNAL_COPY_CONSUMER";
const MAX_CONFIG_BYTES: usize = 256 * 1024;

/// Records independently reviewed copy-specific provider behavior.
///
/// The evidence must describe the actual configured provider and runtime.
/// Existing private-stage or deletion qualification alone supplies none of
/// these properties. In particular, a null version cannot satisfy either
/// versioned read or positive completion identity.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::external_object) struct ProviderContract {
    pub contract_id: String,
    pub evidence_digest: String,
    pub versioned_conditional_range_read: bool,
    pub versioned_multipart_complete: bool,
    pub private_incomplete_upload: bool,
    pub completed_upload_rejects_late_parts: bool,
    pub abort_closes_upload_id: bool,
    pub upload_part_checksum_enforced: bool,
    pub versioned_empty_put: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protected_versionless: Option<VersionlessProviderContract>,
    /// Actual accepted conditional Read range bound, independent of writer parts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_copy_read_range_bytes: Option<LeaseInteger>,
}

/// Describes separately reviewed versionless transport beneath physical guards.
///
/// These facts do not create source custody: every read still requires an
/// independently retained positive receipt and a gate held through source EOF.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::external_object) struct VersionlessProviderContract {
    pub strong_conditional_range_read: bool,
    pub positive_multipart_complete: bool,
}

/// Binds one exact installed provider domain to its purpose-local cohorts.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::external_object) struct Domain {
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
    pub(in crate::external_object) fn commitment(&self) -> Result<String> {
        let version = if self
            .provider_contract
            .maximum_copy_read_range_bytes
            .is_some()
        {
            "aos.external-copy-configured-domain.v3"
        } else if self.provider_contract.protected_versionless.is_some() {
            "aos.external-copy-configured-domain.v2"
        } else {
            "aos.external-copy-configured-domain.v1"
        };
        digest(&(version, self))
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
            provider
                .maximum_copy_read_range_bytes
                .is_none_or(|maximum| {
                    maximum.get() > 0 && maximum.get() as u64 <= MAX_DIRECT_PART_BYTES
                }),
            "copy provider accepted source range bound invalid"
        );
        ensure!(
            !provider.contract_id.is_empty()
                && provider.contract_id.len() <= 128
                && !provider.contract_id.chars().any(char::is_control)
                && digest_string(&provider.evidence_digest)
                && match &provider.protected_versionless {
                    None =>
                        provider.versioned_conditional_range_read
                            && provider.versioned_multipart_complete,
                    Some(contract) =>
                        !provider.versioned_conditional_range_read
                            && !provider.versioned_multipart_complete
                            && !provider.versioned_empty_put
                            && contract.strong_conditional_range_read
                            && contract.positive_multipart_complete,
                }
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
    pub(in crate::external_object) fn validate_original(
        &self,
        object: &ObjectConfig,
        original: &ExternalCopyOriginal,
    ) -> Result<()> {
        self.validate(object)?;
        original.validate()?;
        let association = &self.write_cohort.association;
        ensure!(
            original.profile_digest == self.commitment()?
                && (original.destination_incarnation()? == CopyIncarnationMode::GuardedClosure)
                    == self.provider_contract.protected_versionless.is_some()
                && original.binding_id == association.binding_id
                && original.binding_stable_id == association.binding_stable_id
                && original.binding_resource_version == association.binding_resource_version
                && original.binding_write_revision == association.binding_write_revision
                && (original.version == 3
                    || original.read_generation == self.read_cohort.credential.generation)
                && original.write_generation == self.write_cohort.credential.generation
                && original.part_bytes == self.part_bytes
                && original
                    .transfer
                    .as_ref()
                    .is_none_or(|pins| pins.destination_physical_authority_id
                        == self.write_cohort.authority.authority_id)
                && (original.source_object.bytes.get() > 0
                    || self.provider_contract.versioned_empty_put),
            "copy owner differs from independently installed domain"
        );
        let mut keys = Vec::with_capacity(2);
        for placement in if original.version == 3 {
            vec![&original.destination]
        } else {
            vec![&original.source, &original.destination]
        } {
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
            keys.len() == 1 || keys[0] != keys[1],
            "copy source and destination resolve to the same key"
        );
        Ok(())
    }

    /// Resolves a read-only SQL selector without selecting a fresh source incarnation.
    ///
    /// # Errors
    /// Refuses a foreign profile, binding pin, collapsed key or escaped prefix.
    pub(in crate::external_object) fn selector_scope(
        &self,
        object: &ObjectConfig,
        selector: &aos_hub_core::storage_authority::external_object::copy::original_lookup::CopyOriginalSelector,
    ) -> Result<StorageAuthorityObjectScope> {
        self.selector_scope_for(object, selector, true)
    }

    /// Resolves either sealed physical key for read-only source discovery.
    ///
    /// # Errors
    /// Refuses foreign pins, collapsed keys or a key outside the configured domain.
    pub(in crate::external_object) fn selector_scope_for(
        &self,
        object: &ObjectConfig,
        selector: &aos_hub_core::storage_authority::external_object::copy::original_lookup::CopyOriginalSelector,
        destination: bool,
    ) -> Result<StorageAuthorityObjectScope> {
        self.validate(object)?;
        selector.validate()?;
        if !destination && selector.transfer.is_some() {
            return self.source_selector_scope(object, selector);
        }
        let association = &self.write_cohort.association;
        ensure!(
            selector.profile_digest == self.commitment()?
                && selector.destination.binding_id == association.binding_id
                && selector.binding_stable_id == association.binding_stable_id
                && selector.binding_resource_version == association.binding_resource_version,
            "copy lookup selects a different installed binding"
        );
        let placement = if destination {
            &selector.destination
        } else {
            &selector.source
        };
        let key = aos_hub_core::keymap::r2_key(
            &association.binding_prefix,
            &aos_hub_core::keymap::r2_key(&placement.prefix, &selector.path),
        );
        ensure!(
            contained(&self.write_cohort.admitted_prefix, &key),
            "copy lookup escapes configured domain"
        );
        object.scope(&self.write_cohort, key)
    }

    /// Resolves a cross-binding source under its independently installed Read domain.
    ///
    /// # Errors
    /// Refuses changed source profile, binding, Read generation, authority or range evidence.
    pub(in crate::external_object) fn source_selector_scope(
        &self,
        object: &ObjectConfig,
        selector: &aos_hub_core::storage_authority::external_object::copy::original_lookup::CopyOriginalSelector,
    ) -> Result<StorageAuthorityObjectScope> {
        self.validate(object)?;
        selector.validate()?;
        let transfer = selector
            .transfer
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("paired source pins absent"))?;
        let pin = &transfer.source_binding;
        let cohort = &self.read_cohort;
        let association = &cohort.association;
        ensure!(
            pin.profile_digest == self.commitment()?
                && pin.binding_id == association.binding_id
                && pin.binding_stable_id == association.binding_stable_id
                && pin.binding_resource_version == association.binding_resource_version
                && pin.binding_read_revision == association.binding_write_revision
                && pin.read_generation == cohort.credential.generation
                && pin.physical_authority_id == cohort.authority.authority_id
                && (transfer.source_incarnation == CopyIncarnationMode::GuardedClosure)
                    == self.provider_contract.protected_versionless.is_some()
                && self.provider_contract.maximum_copy_read_range_bytes
                    == Some(transfer.maximum_source_range_bytes),
            "paired source differs from independently installed Read domain"
        );
        let key = aos_hub_core::keymap::r2_key(
            &association.binding_prefix,
            &aos_hub_core::keymap::r2_key(&selector.source.prefix, &selector.path),
        );
        ensure!(
            contained(&cohort.admitted_prefix, &key),
            "copy source escapes admitted Read prefix"
        );
        object.scope(cohort, key)
    }

    /// Checks the full original against its independently installed source profile.
    ///
    /// # Errors
    /// Refuses changed Read pins, mode, authority, range geometry or source key.
    pub(in crate::external_object) fn validate_source_original(
        &self,
        object: &ObjectConfig,
        original: &ExternalCopyOriginal,
    ) -> Result<()> {
        original.validate()?;
        let selector = aos_hub_core::storage_authority::external_object::copy::original_lookup::CopyOriginalSelector::from_original(original)?;
        self.source_selector_scope(object, &selector)?;
        Ok(())
    }

    /// Resolves the original physical key under its independently installed cohort.
    ///
    /// # Errors
    /// Refuses changed originals, profile pins or a key outside the admitted domain.
    pub(in crate::external_object) fn scope(
        &self,
        object: &ObjectConfig,
        original: &ExternalCopyOriginal,
        destination: bool,
    ) -> Result<StorageAuthorityObjectScope> {
        if !destination && original.transfer.is_some() {
            return self.source_selector_scope(object,
                &aos_hub_core::storage_authority::external_object::copy::original_lookup::CopyOriginalSelector::from_original(original)?);
        }
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
pub(in crate::external_object) struct Config {
    pub version: u8,
    pub domains: Vec<Domain>,
}

impl Config {
    /// Preserves legacy whole-isolate maxima and checks the new admitted bounds.
    fn validate_capacity(
        &self,
        policy: Option<&crate::direct_upload::provider_capacity::policy::Policy>,
    ) -> Result<()> {
        let Some(policy) = policy else {
            ensure!(
                self.version == 1,
                "copy version two requires the common capacity policy"
            );
            return Ok(());
        };
        for domain in &self.domains {
            let maximum = u32::from(domain.provider_concurrency);
            match self.version {
                1 => {
                    policy.exact(maximum)?;
                }
                2 => {
                    policy.bounded(maximum, 3)?;
                }
                _ => anyhow::bail!("unsupported copy capacity contract"),
            }
        }
        Ok(())
    }

    /// Parses independently supplied configuration within a fixed input budget.
    ///
    /// # Errors
    /// Refuses oversized, malformed, duplicate, uninstalled or unqualified domains.
    pub(in crate::external_object) fn parse(raw: &str, object: &ObjectConfig) -> Result<Self> {
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
            matches!(self.version, 1 | 2) && !self.domains.is_empty() && self.domains.len() <= 16,
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
                self.version == 2
                    || domain.provider_concurrency == self.domains[0].provider_concurrency,
                "copy domains select different isolate provider capacities"
            );
        }
        Ok(())
    }

    /// Resolves the independently committed source Read profile for a paired original.
    ///
    /// # Errors
    /// Refuses an absent, changed or uninstalled source Read domain.
    pub(in crate::external_object) fn source_domain(
        &self,
        object: &ObjectConfig,
        original: &ExternalCopyOriginal,
    ) -> Result<&Domain> {
        let Some(transfer) = &original.transfer else {
            return self.domain(object, original);
        };
        self.validate(object)?;
        let domain = self
            .domains
            .iter()
            .find(|domain| {
                domain
                    .commitment()
                    .is_ok_and(|value| value == transfer.source_binding.profile_digest)
            })
            .ok_or_else(|| {
                anyhow::anyhow!("copy source Read profile is not independently installed")
            })?;
        domain.validate_source_original(object, original)?;
        Ok(domain)
    }

    /// Refuses a transfer whose independently resolved domains address one physical key.
    ///
    /// # Errors
    /// Refuses equal permanent guard identities or equal approved addresses and keys.
    pub(in crate::external_object) fn validate_pair(
        &self,
        object: &ObjectConfig,
        original: &ExternalCopyOriginal,
    ) -> Result<()> {
        let destination = self.domain(object, original)?;
        let source = self.source_domain(object, original)?;
        let source_scope = source.scope(object, original, false)?;
        let destination_scope = destination.scope(object, original, true)?;
        distinct_physical_keys(
            &source.read_cohort,
            &source_scope,
            &destination.write_cohort,
            &destination_scope,
        )
    }

    /// Resolves only the installed domain named by the retained owner commitment.
    ///
    /// # Errors
    /// Refuses an absent or changed commitment and any original pin mismatch.
    pub(in crate::external_object) fn domain(
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

fn distinct_physical_keys(
    source: &LeaseCohort,
    source_scope: &StorageAuthorityObjectScope,
    destination: &LeaseCohort,
    destination_scope: &StorageAuthorityObjectScope,
) -> Result<()> {
    ensure!(
        source_scope.guard_name()? != destination_scope.guard_name()?
            && (source_scope.full_key != destination_scope.full_key
                || source.alias.spec != destination.alias.spec),
        "copy source and destination alias one physical key"
    );
    Ok(())
}

fn contained(prefix: &str, key: &str) -> bool {
    prefix.is_empty()
        || key == prefix
        || key
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

#[cfg(target_arch = "wasm32")]
pub(in crate::external_object) fn configured(
    env: &worker::Env,
    object: &ObjectConfig,
) -> Result<Option<Config>> {
    let raw = js_sys::Reflect::get(env.as_ref(), &wasm_bindgen::JsValue::from_str(CONFIG_VAR))
        .map_err(|_| anyhow::anyhow!("copy configuration unavailable"))?;
    if raw.is_undefined() {
        return Ok(None);
    }
    let raw = raw
        .as_string()
        .ok_or_else(|| anyhow::anyhow!("copy configuration must be a JSON string"))?;
    let config = Config::parse(&raw, object)?;
    let policy = crate::direct_upload::provider_capacity::policy::installed(env)?;
    config.validate_capacity(policy.as_ref())?;
    Ok(Some(config))
}

#[cfg(test)]
pub(in crate::external_object) mod tests;
