//! Independently installed External mirror transport and purpose-local cohorts.
//!
//! Configuration alone grants no dispatch authority. The exact domain commitment
//! must also match the separately signed Mirror purpose artifact. Read closure
//! observations are separate from the prerequisite Direct Write qualification.
//!
//! ```text
//! config = {version: 1, domains: [{profile, list_cohort, issuer_installation,
//!            provider_contract}]}
//! ```

use anyhow::{Context as _, Result, ensure};
use aos_hub_core::{
    direct_upload::DirectProtectedExternalProfile,
    mirror_work::{MIRROR_PART_BYTES, MirrorOriginal},
    storage_authority::lease::{
        LeaseCohort, LeaseEffect, LeaseInteger, control::IssuerInstallation,
    },
};
use serde::{Deserialize, Serialize};

use super::super::{
    config::Config as ObjectConfig,
    protocol::{digest, digest_string},
};

/// Selects actual observed provider identity without inventing a null version.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum ReadIdentity {
    /// Every positive completion returns a real provider version.
    Versioned,
    /// Strong conditional reads use a separately retained guard closure.
    GuardedVersionless,
}

/// Retains the independently reviewed mirror-specific provider behavior.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProviderContract {
    pub observation_sha256: String,
    pub read_identity: ReadIdentity,
    pub maximum_conditional_read_bytes: LeaseInteger,
    pub strong_conditional_read: bool,
    pub private_incomplete_upload: bool,
    pub completed_upload_rejects_late_parts: bool,
    pub checksum_enforced: bool,
    pub positive_complete_identity: bool,
    pub positive_empty_put_identity: bool,
}

/// Commits the exact prerequisite and installed transport, not a Copy approval.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Domain {
    pub profile: DirectProtectedExternalProfile,
    pub list_cohort: LeaseCohort,
    pub issuer_installation: IssuerInstallation,
    pub provider_contract: ProviderContract,
}

impl Domain {
    pub(super) fn commitment(&self) -> Result<String> {
        digest(&("aos.external-mirror-installed-domain.v1", self))
    }

    pub(super) fn validate(&self, object: &ObjectConfig) -> Result<()> {
        self.profile.validate()?;
        self.issuer_installation.validate()?;
        let profile = &self.profile.profile;
        let read = &profile.read_cohort;
        let write = &profile.write_cohort;
        let list = &self.list_cohort;
        ensure!(
            self.issuer_installation.authority == write.authority
                && self.issuer_installation.executor_identity == object.executor_identity
                && list.authority == read.authority
                && list.association == read.association
                && list.alias == read.alias
                && list.publication_digest == read.publication_digest
                && list.admission_digest == read.admission_digest
                && list.admission_generation == read.admission_generation
                && list.admitted_prefix == read.admitted_prefix
                && list.credential.purpose
                    == aos_hub_core::storage_authority::lease::LeasePurpose::List
                && list.allowed_effects.contains(&LeaseEffect::List),
            "mirror installed issuer or inventory cohort differs from prerequisite"
        );
        for cohort in [read, write, list] {
            ensure!(
                object.cohort(&digest(cohort)?)? == cohort
                    && cohort.executor_identity == object.executor_identity,
                "mirror purpose cohort is not independently installed"
            );
        }
        let provider = &self.provider_contract;
        ensure!(
            digest_string(&provider.observation_sha256)
                && provider.maximum_conditional_read_bytes.get() as u64 >= MIRROR_PART_BYTES
                && provider.maximum_conditional_read_bytes.get() as u64 <= 64 * 1024 * 1024
                && provider.strong_conditional_read
                && provider.private_incomplete_upload
                && provider.completed_upload_rejects_late_parts
                && provider.checksum_enforced
                && provider.positive_complete_identity,
            "mirror provider closure or conditional Read contract is unqualified"
        );
        Ok(())
    }

    pub(super) fn validate_original(
        &self,
        object: &ObjectConfig,
        original: &MirrorOriginal,
    ) -> Result<()> {
        self.validate(object)?;
        original.validate()?;
        let selected = original
            .external_destination
            .as_ref()
            .context("External mirror domain received a Managed original")?;
        ensure!(
            selected.protected_profile == self.profile && selected.list_cohort == self.list_cohort,
            "mirror original differs from installed exact prerequisite"
        );
        if original.verification.size() == 0 {
            ensure!(
                self.provider_contract.positive_empty_put_identity
                    && self
                        .profile
                        .profile
                        .write_cohort
                        .allowed_effects
                        .contains(&LeaseEffect::Put),
                "empty mirror representation lacks separately qualified PUT identity"
            );
        }
        Ok(())
    }

    pub(super) fn require_version(&self, actual: Option<&str>) -> Result<()> {
        ensure!(
            match self.provider_contract.read_identity {
                ReadIdentity::Versioned => actual.is_some_and(|version| version != "null"
                    && aos_hub_core::storage_work::valid_provider_version(version)),
                ReadIdentity::GuardedVersionless => actual.is_none(),
            },
            "mirror provider completion differs from its actual qualified identity mode"
        );
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    pub version: u8,
    pub domains: Vec<Domain>,
}

impl Config {
    pub(super) fn parse(raw: &str, object: &ObjectConfig) -> Result<Self> {
        ensure!(
            raw.len() <= 256 * 1024,
            "External mirror configuration exceeds bound"
        );
        let value: Self = serde_json::from_str(raw)?;
        ensure!(
            value.version == 1 && !value.domains.is_empty() && value.domains.len() <= 16,
            "External mirror configuration shape unsupported"
        );
        let mut selected = std::collections::BTreeSet::new();
        for domain in &value.domains {
            domain.validate(object)?;
            ensure!(
                selected.insert(domain.profile.digest()?),
                "duplicate mirror prerequisite domain"
            );
        }
        Ok(value)
    }

    pub(super) fn domain(&self, original: &MirrorOriginal) -> Result<&Domain> {
        self.domains
            .iter()
            .find(|domain| {
                domain
                    .profile
                    .digest()
                    .is_ok_and(|digest| digest == original.protected_profile_digest)
            })
            .context("mirror prerequisite is not independently installed")
    }
}

#[cfg(target_arch = "wasm32")]
pub(super) fn configured(env: &worker::Env, object: &ObjectConfig) -> Result<Config> {
    Config::parse(
        &env.var("HUB_EXTERNAL_MIRROR_CONSUMER")?.to_string(),
        object,
    )
}
