//! Independent private-stage/provider qualification and exact credential context.

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::{
    DirectCredentialRevision, DirectPhysicalContext, DirectPrivateStagePolicyRef, WireInteger,
};
use aos_hub_core::storage_authority::external_object::stage::ExternalStageContext;
use aos_hub_core::storage_authority::{
    control::StorageAuthorityPublication,
    lease::{LeaseCohort, LeasePurpose},
};
use serde::{Deserialize, Serialize};

use super::super::{
    config::Config as ObjectConfig,
    protocol::{digest, digest_string},
};

pub(super) const CONFIG_VAR: &str = "HUB_EXTERNAL_STAGING_CONSUMER";
const MAX_CONFIG: usize = 256 * 1024;

/// Static operator-reviewed storage-side closure properties, not token assertions.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProviderContract {
    pub contract_id: String,
    pub evidence_digest: String,
    pub private_completed_stage: bool,
    pub completed_upload_id_rejects_late_parts: bool,
    pub multipart_abort_closes_upload_id: bool,
    pub multipart_copy_from_immutable_source: bool,
    pub upload_part_checksum_enforced: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Domain {
    pub issuer_installation: aos_hub_core::storage_authority::lease::control::IssuerInstallation,
    pub publication: StorageAuthorityPublication,
    pub write_cohort: LeaseCohort,
    pub read_cohort: LeaseCohort,
    pub write_credential: DirectCredentialRevision,
    pub read_credential: DirectCredentialRevision,
    pub presign_credential: DirectCredentialRevision,
    pub private_stage_policy: DirectPrivateStagePolicyRef,
    pub staging_prefix: String,
    pub checksum_algorithm: aos_hub_core::direct_upload::DirectChecksumAlgorithm,
    pub maximum_grant_lifetime: WireInteger,
    pub provider_contract: ProviderContract,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    pub version: u8,
    pub domains: Vec<Domain>,
}

impl Config {
    /// Resolves only one already configured read cohort, without token-derived pins.
    ///
    /// # Errors
    /// Returns an error when no domain or multiple domains match the exact cohort.
    pub(super) fn observation_domain(&self, cohort: &LeaseCohort) -> Result<&Domain> {
        let mut candidates = self
            .domains
            .iter()
            .filter(|domain| &domain.read_cohort == cohort);
        let domain = candidates
            .next()
            .ok_or_else(|| anyhow::anyhow!("read issuer domain unavailable"))?;
        ensure!(candidates.next().is_none(), "read issuer domain ambiguous");
        Ok(domain)
    }

    pub(super) fn parse(raw: &str, object: &ObjectConfig) -> Result<Self> {
        ensure!(
            raw.len() <= MAX_CONFIG,
            "external staging configuration oversized"
        );
        let value: Self = serde_json::from_str(raw)?;
        value.validate(object)?;
        Ok(value)
    }

    pub(super) fn validate(&self, object: &ObjectConfig) -> Result<()> {
        object.validate()?;
        ensure!(
            self.version == 1 && !self.domains.is_empty() && self.domains.len() <= 16,
            "invalid staging configuration"
        );
        let mut domains = std::collections::BTreeSet::new();
        for domain in &self.domains {
            domain.issuer_installation.validate()?;
            ensure!(
                domain.issuer_installation.authority == domain.write_cohort.authority
                    && domain.issuer_installation.executor_identity == object.executor_identity,
                "stage issuer resource differs from independent authority"
            );
            domain
                .publication
                .validate(&object.guard_namespace_id, &object.executor_identity)?;
            for (cohort, purpose) in [
                (&domain.write_cohort, LeasePurpose::Write),
                (&domain.read_cohort, LeasePurpose::Read),
            ] {
                let approved = LeaseCohort::from_publication(
                    &domain.publication,
                    &object.executor_identity,
                    &cohort.association.association_id,
                    purpose,
                    &cohort.admitted_prefix,
                    cohort.allowed_effects.clone(),
                )?;
                ensure!(
                    &approved == cohort
                        && object.aliases.iter().any(|alias| alias == &cohort.alias),
                    "staging cohort differs from independent publication"
                );
            }
            ensure!(
                domain.write_cohort.authority == domain.read_cohort.authority
                    && domain.write_cohort.association == domain.read_cohort.association
                    && domain.write_cohort.alias == domain.read_cohort.alias,
                "staging read/write physical domain differs"
            );
            ensure!(
                domains.insert(digest(&domain.write_cohort)?),
                "duplicate staging cohort"
            );
            ensure!(
                domain.maximum_grant_lifetime.get() > 0
                    && domain.maximum_grant_lifetime.get() <= 3600,
                "staging delegated horizon exceeds bound"
            );
            let policy = &domain.private_stage_policy;
            ensure!(
                !policy.policy_id.is_empty()
                    && policy.policy_id.len() <= 128
                    && digest_string(&policy.policy_digest)
                    && aos_hub_core::direct_upload::valid_direct_identity(&policy.namespace),
                "staging private policy differs"
            );
            ensure!(
                !domain.staging_prefix.is_empty()
                    && domain.staging_prefix.len() <= 512
                    && domain
                        .staging_prefix
                        .split('/')
                        .all(|part| !part.is_empty() && part != "." && part != "..")
                    && domain.staging_prefix.split('/').last() == Some(".aos-direct-upload")
                    && !domain
                        .staging_prefix
                        .chars()
                        .any(|c| c.is_control() || matches!(c, '\\' | '?' | '#'))
                    && contained(&domain.write_cohort.admitted_prefix, &domain.staging_prefix)
                    && contained(&domain.read_cohort.admitted_prefix, &domain.staging_prefix),
                "private stage escapes admitted prefix"
            );
            let provider = &domain.provider_contract;
            ensure!(
                !provider.contract_id.is_empty()
                    && provider.contract_id.len() <= 128
                    && digest_string(&provider.evidence_digest)
                    && provider.private_completed_stage
                    && provider.completed_upload_id_rejects_late_parts
                    && provider.multipart_abort_closes_upload_id
                    && provider.multipart_copy_from_immutable_source
                    && provider.upload_part_checksum_enforced,
                "external provider staging contract unqualified"
            );
            for (credential, purpose) in [
                (&domain.write_credential, "write"),
                (&domain.read_credential, "read"),
                (&domain.presign_credential, "presign"),
            ] {
                ensure!(
                    credential.purpose == purpose
                        && credential.generation.get() > 0
                        && !credential.credential_id.is_empty()
                        && credential.credential_id.len() <= 128
                        && !credential.secret_version_ref.is_empty()
                        && credential.secret_version_ref.len() <= 255
                        && digest_string(&credential.credential_fingerprint),
                    "invalid staged credential pin"
                );
                let attestation = domain
                    .publication
                    .attestation
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("staging exclusivity attestation absent"))?;
                ensure!(
                    attestation
                        .credentials
                        .iter()
                        .any(|member| member.association_id
                            == domain.write_cohort.association.association_id
                            && member.purpose == credential.purpose
                            && u64::try_from(member.generation).ok()
                                == Some(credential.generation.get())
                            && member.secret_version_ref == credential.secret_version_ref
                            && member.credential_fingerprint == credential.credential_fingerprint),
                    "staged credential is outside reviewed provider closure"
                );
            }
        }
        Ok(())
    }

    pub(super) fn domain(&self, context: &ExternalStageContext) -> Result<&Domain> {
        context.validate()?;
        let DirectPhysicalContext::External {
            write_cohort,
            read_cohort,
        } = &context.placement.physical
        else {
            anyhow::bail!("staging requires external authority");
        };
        let domain = self
            .domains
            .iter()
            .find(|domain| {
                domain.write_cohort == **write_cohort && domain.read_cohort == **read_cohort
            })
            .ok_or_else(|| anyhow::anyhow!("staging domain not independently approved"))?;
        let placement = &context.placement;
        ensure!(
            placement.binding_id.get() == domain.write_cohort.association.binding_id.get() as u64
                && placement.binding_resource_version.get()
                    == domain
                        .write_cohort
                        .association
                        .binding_resource_version
                        .get() as u64
                && placement.binding_write_revision.get()
                    == domain.write_cohort.association.binding_write_revision.get() as u64
                && placement.private_stage_policy == domain.private_stage_policy
                && placement.staging_prefix == domain.staging_prefix
                && placement.checksum_algorithm == domain.checksum_algorithm
                && placement.write_credential == domain.write_credential
                && placement.read_credential == domain.read_credential
                && placement.presign_credential == domain.presign_credential
                && contained(&domain.write_cohort.admitted_prefix, &placement.final_key)
                && placement.final_key != context.stage_key()?
                && !contained(&domain.staging_prefix, &placement.final_key),
            "staging original placement differs from approved domain"
        );
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
    let value = js_sys::Reflect::get(env, &wasm_bindgen::JsValue::from_str(CONFIG_VAR))
        .map_err(|_| anyhow::anyhow!("staging configuration unavailable"))?;
    if value.is_undefined() {
        return Ok(None);
    }
    let raw = value
        .as_string()
        .ok_or_else(|| anyhow::anyhow!("staging configuration must be JSON string"))?;
    Ok(Some(Config::parse(&raw, object)?))
}
