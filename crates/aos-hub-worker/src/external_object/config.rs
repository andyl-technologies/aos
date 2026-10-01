//! Independently configured physical domains, cohorts and trust pins.
//!
//! These facts are not loaded from work requests, signed lease payloads or SQL.
//! Historical aliases remain deny entries even when their cohort is removed.
//! This slice pins one configuration for each used namespace; no reconfiguration
//! or namespace rotation establishes settlement or fresh-provider qualification.
//!
//! ```text
//! config = {version, guard_namespace_id, executor_identity, issuer_key_id,
//!           issuer_public_key, timing_profile, clock_uncertainty,
//!           aliases, cohorts, publications}
//! ```

use anyhow::{ensure, Result};
use aos_hub_core::storage_authority::{
    control::{StorageAuthorityObjectScope, StorageAuthorityPublication},
    lease::{EpochLeaseVerifier, LeaseClock, LeaseCohort, LeaseTimingProfile},
    ApproveStorageAuthorityAlias, StorageAuthorityAliasSpec, StorageAuthorityHost,
};
use aos_hub_core::storage_work::StorageBindingSnapshot;
use serde::{Deserialize, Serialize};

use super::protocol::{digest, digest_string};

pub(super) const CONFIG_VAR: &str = "HUB_EXTERNAL_OBJECT_CONSUMER";
const MAX_CONFIG: usize = 128 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    pub version: u8,
    pub guard_namespace_id: String,
    pub executor_identity: String,
    pub issuer_key_id: String,
    pub issuer_public_key: String,
    pub timing_profile: LeaseTimingProfile,
    pub clock_uncertainty: i64,
    pub aliases: Vec<ApproveStorageAuthorityAlias>,
    pub cohorts: Vec<LeaseCohort>,
    pub publications: Vec<StorageAuthorityPublication>,
}

impl Config {
    pub(super) fn parse(raw: &str) -> Result<Self> {
        ensure!(raw.len() <= MAX_CONFIG, "oversized consumer configuration");
        let value: Self = serde_json::from_str(raw)?;
        value.validate()?;
        Ok(value)
    }

    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1
                && !self.aliases.is_empty()
                && self.aliases.len() <= 256
                && !self.cohorts.is_empty()
                && self.cohorts.len() <= 32
                && !self.publications.is_empty()
                && self.publications.len() <= 16,
            "invalid consumer configuration bounds"
        );
        self.timing_profile.validate()?;
        ensure!(
            self.clock_uncertainty >= 0
                && self.clock_uncertainty <= self.timing_profile.maximum_clock_uncertainty.get(),
            "unreviewed consumer clock bound"
        );
        self.verifier()?;
        let mut aliases = std::collections::BTreeSet::new();
        let mut cohorts = std::collections::BTreeSet::new();
        for alias in &self.aliases {
            alias.spec.validate()?;
            ensure!(
                digest_string(&alias.equivalence_evidence_digest)
                    && aliases.insert(alias.spec.digest()?),
                "duplicate or malformed approved alias"
            );
        }
        for cohort in &self.cohorts {
            let publication = self
                .publications
                .iter()
                .find(|publication| {
                    publication.authority == cohort.authority
                        && publication.generation == cohort.admission_generation.get()
                        && publication.digest == cohort.admission_digest
                })
                .ok_or_else(|| anyhow::anyhow!("configured cohort publication missing"))?;
            let projected = LeaseCohort::from_publication(
                publication,
                &self.executor_identity,
                &cohort.association.association_id,
                cohort.credential.purpose,
                &cohort.admitted_prefix,
                cohort.allowed_effects.clone(),
            )?;
            ensure!(
                projected == *cohort && digest(publication)? == cohort.publication_digest,
                "configured cohort differs from reviewed publication"
            );
            ensure!(
                cohort.authority.guard_namespace_id == self.guard_namespace_id
                    && cohort.executor_identity == self.executor_identity
                    && self.aliases.contains(&cohort.alias),
                "consumer permanent context mismatch"
            );
            ensure!(
                cohorts.insert(digest(cohort)?),
                "duplicate configured cohort"
            );
            for other in &self.cohorts {
                if other.authority.authority_id == cohort.authority.authority_id {
                    ensure!(
                        other.authority == cohort.authority,
                        "authority creation fork"
                    );
                }
            }
        }
        Ok(())
    }

    pub(super) fn verifier(&self) -> Result<EpochLeaseVerifier> {
        ensure!(
            digest_string(&self.issuer_public_key),
            "invalid configured issuer pin"
        );
        let public: [u8; 32] = hex::decode(&self.issuer_public_key)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid issuer pin"))?;
        EpochLeaseVerifier::from_bytes(self.issuer_key_id.clone(), &public)
    }

    pub(super) fn clock(&self) -> LeaseClock {
        LeaseClock {
            observed_at: aos_hub_core::clock::now_unix_secs(),
            uncertainty: self.clock_uncertainty,
        }
    }

    pub(super) fn cohort(&self, commitment: &str) -> Result<&LeaseCohort> {
        self.cohorts
            .iter()
            .find(|value| digest(*value).is_ok_and(|found| found == commitment))
            .ok_or_else(|| anyhow::anyhow!("cohort is not independently configured"))
    }

    pub(super) fn manages(&self, snapshot: &StorageBindingSnapshot) -> Result<bool> {
        if snapshot.endpoint_scheme != "https" {
            return Ok(false);
        }
        let coordinates = coordinates(snapshot)?;
        Ok(self.aliases.iter().any(|alias| alias.spec == coordinates))
    }

    pub(super) fn scope(
        &self,
        cohort: &LeaseCohort,
        key: String,
    ) -> Result<StorageAuthorityObjectScope> {
        let scope = StorageAuthorityObjectScope {
            guard_namespace_id: self.guard_namespace_id.clone(),
            physical_authority_id: cohort.authority.authority_id.clone(),
            full_key: key,
        };
        scope.guard_name()?;
        Ok(scope)
    }
}

pub(super) fn coordinates(snapshot: &StorageBindingSnapshot) -> Result<StorageAuthorityAliasSpec> {
    ensure!(
        snapshot.endpoint_scheme == "https",
        "managed authority requires HTTPS"
    );
    let bytes = &snapshot.endpoint_host_bytes;
    let host = match snapshot.endpoint_host_kind.as_str() {
        "dns" => StorageAuthorityHost::Dns(String::from_utf8(bytes.clone())?),
        "ipv4" => StorageAuthorityHost::Ipv4(bytes.as_slice().try_into()?),
        "ipv6" => StorageAuthorityHost::Ipv6(bytes.as_slice().try_into()?),
        _ => anyhow::bail!("invalid external host"),
    };
    let spec = StorageAuthorityAliasSpec {
        host,
        port: u16::try_from(snapshot.endpoint_port.unwrap_or(443))?,
        bucket: snapshot.object_bucket.clone(),
    };
    spec.validate()?;
    Ok(spec)
}

#[cfg(target_arch = "wasm32")]
pub(super) fn configured(env: &worker::Env) -> Result<Option<Config>> {
    let raw = js_sys::Reflect::get(env.as_ref(), &wasm_bindgen::JsValue::from_str(CONFIG_VAR))
        .map_err(|_| anyhow::anyhow!("consumer configuration unavailable"))?;
    if raw.is_undefined() {
        return Ok(None);
    }
    let raw = raw
        .as_string()
        .ok_or_else(|| anyhow::anyhow!("consumer configuration must be a JSON string"))?;
    Config::parse(&raw).map(Some)
}
