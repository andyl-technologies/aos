//! Requested protected external profiles, without a global binding inventory.

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::storage_authority::{
    lease::{
        control::IssuerInstallation, LeaseAssociation, LeaseCohort, LeaseEffect, LeaseInteger,
        LeasePurpose, LeaseTimingProfile,
    },
    PhysicalStorageAuthorityId,
};

use super::*;

/// Exact server-resolved external binding and purpose projections to challenge.
///
/// Public upload callers cannot choose this selector. Native derives it from
/// authorized current placement rows and independently reviewed authority facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectExternalProfileSelector {
    /// Permanent physical authority, independent of SQL reset or aliases.
    pub physical_authority_id: PhysicalStorageAuthorityId,
    /// Exact alias, immutable binding identity, prefix and writer revision.
    pub association: LeaseAssociation,
    /// Exact selected visible-write publication member.
    pub write_credential: DirectCredentialRevision,
    /// Separate selected verification-read publication member.
    pub read_credential: DirectCredentialRevision,
    /// Separate selected delegated-grant publication member.
    pub presign_credential: DirectCredentialRevision,
}

impl DirectExternalProfileSelector {
    /// Checks bounded immutable association and exact purpose-local references.
    ///
    /// This validates a projection; it does not resolve provider credentials.
    ///
    /// # Errors
    /// Returns an error for invalid identities, counters, prefixes or purposes.
    pub fn validate(&self) -> Result<()> {
        for identity in [&self.association.association_id, &self.association.alias_id] {
            ensure!(
                valid_direct_identity(identity) && identity.len() <= 64,
                "invalid direct external selector identity"
            );
        }
        ensure!(
            valid_direct_identity(&self.association.binding_stable_id)
                && self.association.binding_id.get() > 0
                && self.association.binding_resource_version.get() > 0
                && self.association.binding_write_revision.get() > 0
                && canonical_prefix(&self.association.binding_prefix),
            "invalid direct external binding selector"
        );
        super::admission_validation::credential(&self.write_credential, "write")?;
        super::admission_validation::credential(&self.read_credential, "read")?;
        super::admission_validation::credential(&self.presign_credential, "presign")?;
        Ok(())
    }

    /// Computes a compact exact selector identity for duplicate detection.
    ///
    /// # Errors
    /// Returns an error for malformed or oversized selector encoding.
    pub fn fingerprint(&self) -> Result<String> {
        self.validate()?;
        let mut digest = Sha256::new();
        digest.update(b"aos.direct-upload.external-selector.v1\0");
        digest.update(encode_direct_control(self)?);
        Ok(hex::encode(digest.finalize()))
    }
}

/// Public profile emitted only after actual protected binding/material resolution.
///
/// The Worker adapter validates its configured publication and resolves every
/// selected credential against the current protected binding. Native requires
/// exact independent reviewed pin equality; a valid MAC alone is insufficient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectExternalStorageCapabilities {
    /// Exact requested server-resolved binding/purpose selector.
    pub selector: DirectExternalProfileSelector,
    /// Independent retained issuer resource and immutable authority attachment.
    pub issuer_installation: IssuerInstallation,
    /// Independently configured issuer verifier identity.
    pub issuer_key_id: String,
    /// Canonical lowercase hexadecimal Ed25519 public key, never a signing seed.
    pub issuer_public_key: String,
    /// Exact currently admitted write projection from the protected publication.
    pub write_cohort: LeaseCohort,
    /// Separate current read projection from the same protected publication.
    pub read_cohort: LeaseCohort,
    /// Independently qualified provider/Worker private namespace policy.
    pub private_stage_policy: DirectPrivateStagePolicyRef,
    /// Exact reserved stage prefix, not supplied by public callers.
    pub staging_prefix: String,
    /// Actual independently qualified UploadPart checksum profile.
    pub checksum_algorithm: DirectChecksumAlgorithm,
    /// Explicit bounded delegated-grant lifetime ceiling.
    pub maximum_grant_lifetime: WireInteger,
    /// Reviewed provider closure contract identity.
    pub provider_contract_id: String,
    /// Commitment to actual provider closure/immutability qualification evidence.
    pub provider_contract_evidence_digest: String,
    /// Explicit accepted lease lifetime and timing evidence.
    pub timing_profile: LeaseTimingProfile,
    /// Actual configured conservative clock uncertainty, not an invented default.
    pub clock_uncertainty: LeaseInteger,
}

impl DirectExternalStorageCapabilities {
    /// Checks the exact selected profile association and bounded public facts.
    ///
    /// This does not replace full protected publication validation, actual
    /// credential resolution, fresh leases, independent pins or provider gates.
    ///
    /// # Errors
    /// Returns an error for foreign domains, changed purposes/material refs,
    /// invalid verifier/policy/timing facts or excessive profile encoding.
    pub fn validate(&self) -> Result<()> {
        self.selector.validate()?;
        self.issuer_installation.validate()?;
        self.timing_profile.validate()?;
        ensure!(
            valid_direct_identity(&self.issuer_key_id)
                && valid_direct_digest(&self.issuer_public_key)
                && valid_direct_identity(&self.provider_contract_id)
                && self.provider_contract_id.len() <= 128
                && valid_direct_digest(&self.provider_contract_evidence_digest)
                && self.maximum_grant_lifetime.get() > 0
                && self.maximum_grant_lifetime.get() <= 3600
                && self.clock_uncertainty.get()
                    <= self.timing_profile.maximum_clock_uncertainty.get(),
            "invalid direct external verifier or qualification"
        );
        ensure!(
            valid_direct_identity(&self.private_stage_policy.policy_id)
                && valid_direct_digest(&self.private_stage_policy.policy_digest)
                && valid_direct_identity(&self.private_stage_policy.namespace)
                && self.staging_prefix.len() <= 512
                && super::admission_validation::private_prefix(&self.staging_prefix),
            "invalid direct external private policy"
        );
        let write = &self.write_cohort;
        let read = &self.read_cohort;
        ensure!(
            write.authority == read.authority
                && write.authority == self.issuer_installation.authority
                && write.authority.authority_id == self.selector.physical_authority_id
                && write.executor_identity == read.executor_identity
                && write.executor_identity == self.issuer_installation.executor_identity
                && write.alias == read.alias
                && write.association == read.association
                && write.association == self.selector.association
                && write.admission_generation == read.admission_generation
                && write.admission_generation.get() > 0
                && write.admission_digest == read.admission_digest
                && write.publication_digest == read.publication_digest
                && valid_direct_digest(&write.admission_digest)
                && valid_direct_digest(&write.publication_digest),
            "direct external protected domain mismatch"
        );
        write
            .alias
            .spec
            .validate()
            .map_err(|_| anyhow::anyhow!("invalid direct external alias coordinates"))?;
        ensure!(
            write.alias.authority_id == write.authority.authority_id
                && write.alias.alias_id == self.selector.association.alias_id
                && valid_direct_digest(&write.alias.equivalence_evidence_digest),
            "direct external alias mismatch"
        );
        for (cohort, selected, purpose) in [
            (write, &self.selector.write_credential, LeasePurpose::Write),
            (read, &self.selector.read_credential, LeasePurpose::Read),
        ] {
            ensure!(
                cohort.credential.purpose == purpose
                    && cohort.credential.association_id == self.selector.association.association_id
                    && u64::try_from(cohort.credential.generation.get()).ok()
                        == Some(selected.generation.get())
                    && cohort.credential.secret_version_ref == selected.secret_version_ref
                    && cohort.credential.credential_fingerprint == selected.credential_fingerprint
                    && canonical_prefix(&cohort.admitted_prefix)
                    && contained(&cohort.admitted_prefix, &self.staging_prefix)
                    && contained(
                        &self.selector.association.binding_prefix,
                        &self.staging_prefix
                    )
                    && contained(
                        &cohort.authority.qualified_managed_prefix,
                        &self.staging_prefix
                    )
                    && cohort.attestation_valid_until.get() > 0,
                "direct external purpose or stage scope mismatch"
            );
        }
        ensure!(
            read.allowed_effects.contains(&LeaseEffect::Read)
                && [
                    LeaseEffect::Put,
                    LeaseEffect::MultipartCreate,
                    LeaseEffect::MultipartPart,
                    LeaseEffect::MultipartComplete,
                    LeaseEffect::MultipartAbort
                ]
                .iter()
                .all(|effect| write.allowed_effects.contains(effect)),
            "direct external required effects are unavailable"
        );
        ensure!(
            encode_direct_control(self)?.len() <= MAX_DIRECT_CAPABILITY_BYTES,
            "direct external profile exceeds capability limit"
        );
        Ok(())
    }

    /// Commits public resolved profile facts without accepting raw credentials.
    ///
    /// The adapter must first perform actual protected credential/material
    /// resolution. This helper alone establishes neither resolution nor trust.
    ///
    /// # Errors
    /// Returns an error for an invalid or excessively encoded profile.
    pub fn fingerprint(&self) -> Result<String> {
        self.validate()?;
        let mut digest = Sha256::new();
        digest.update(b"aos.direct-upload.external-profile.v1\0");
        digest.update(encode_direct_control(self)?);
        Ok(hex::encode(digest.finalize()))
    }
}

fn canonical_prefix(value: &str) -> bool {
    value.len() <= 512
        && value.trim() == value
        && !value.starts_with('/')
        && !value
            .chars()
            .any(|c| c.is_control() || matches!(c, '\\' | '?' | '#'))
        && (value.is_empty()
            || value
                .split('/')
                .all(|segment| !segment.is_empty() && segment != "." && segment != ".."))
}

fn contained(prefix: &str, key: &str) -> bool {
    prefix.is_empty()
        || key == prefix
        || key
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
}
