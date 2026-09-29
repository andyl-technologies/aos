//! Immutable server admission checks and shared private staging coordinates.

use anyhow::{ensure, Result};
use sha2::{Digest as _, Sha256};

use crate::storage_authority::lease::{LeaseEffect, LeasePurpose};

use super::*;

impl DirectPlacement {
    /// Checks structural placement/purpose bindings without asserting freshness.
    ///
    /// The broker must independently match protected configuration, admitted
    /// publications and actual private-policy qualification before effects.
    ///
    /// # Errors
    /// Returns a value-free error for malformed counters, coordinates, policy,
    /// credentials or inconsistent external read/write cohort projections.
    pub fn validate(&self, deployment: &str) -> Result<()> {
        for counter in [
            self.placement_id,
            self.placement_resource_version,
            self.write_spec_version,
            self.binding_id,
            self.binding_resource_version,
            self.binding_write_revision,
        ] {
            ensure!(
                (1..=i64::MAX as u64).contains(&counter.get()),
                "invalid direct placement counter"
            );
        }
        ensure!(
            valid_direct_digest(&self.protected_profile_digest),
            "invalid direct protected profile digest"
        );
        ensure!(
            valid_direct_path(&self.final_key),
            "invalid direct final key"
        );
        ensure!(
            private_prefix(&self.staging_prefix),
            "invalid direct staging prefix"
        );
        ensure!(
            valid_direct_identity(&self.private_stage_policy.policy_id)
                && valid_direct_digest(&self.private_stage_policy.policy_digest)
                && valid_direct_identity(&self.private_stage_policy.namespace),
            "invalid direct private policy"
        );
        credential(&self.write_credential, "write")?;
        credential(&self.read_credential, "read")?;
        credential(&self.presign_credential, "presign")?;

        match &self.physical {
            DirectPhysicalContext::DeploymentR2 {
                deployment_id,
                bucket_namespace,
            } => {
                ensure!(
                    deployment_id == deployment && valid_direct_identity(bucket_namespace),
                    "direct deployment physical context mismatch"
                );
            }
            DirectPhysicalContext::External {
                write_cohort,
                read_cohort,
            } => {
                ensure!(
                    write_cohort.authority == read_cohort.authority
                        && write_cohort.executor_identity == read_cohort.executor_identity
                        && write_cohort.admission_generation == read_cohort.admission_generation
                        && write_cohort.admission_digest == read_cohort.admission_digest
                        && write_cohort.publication_digest == read_cohort.publication_digest
                        && write_cohort.alias == read_cohort.alias
                        && write_cohort.association == read_cohort.association,
                    "direct external cohort domain mismatch"
                );
                for cohort in [write_cohort, read_cohort] {
                    ensure!(
                        u64::try_from(cohort.association.binding_id.get()).ok()
                            == Some(self.binding_id.get())
                            && u64::try_from(cohort.association.binding_resource_version.get())
                                .ok()
                                == Some(self.binding_resource_version.get())
                            && u64::try_from(cohort.association.binding_write_revision.get()).ok()
                                == Some(self.binding_write_revision.get())
                            && contains_key(&cohort.admitted_prefix, &self.final_key)
                            && contains_key(&cohort.admitted_prefix, &self.staging_prefix)
                            && valid_direct_digest(&cohort.admission_digest)
                            && valid_direct_digest(&cohort.publication_digest),
                        "direct external binding mismatch"
                    );
                }
                ensure!(
                    write_cohort.credential.purpose == LeasePurpose::Write
                        && read_cohort.credential.purpose == LeasePurpose::Read
                        && read_cohort.allowed_effects.contains(&LeaseEffect::Read),
                    "direct external credential purpose mismatch"
                );
                for (cohort, selected) in [
                    (write_cohort, &self.write_credential),
                    (read_cohort, &self.read_credential),
                ] {
                    ensure!(
                        u64::try_from(cohort.credential.generation.get()).ok()
                            == Some(selected.generation.get())
                            && cohort.credential.credential_fingerprint
                                == selected.credential_fingerprint
                            && cohort.credential.secret_version_ref == selected.secret_version_ref,
                        "direct external credential revision mismatch"
                    );
                }
            }
        }
        Ok(())
    }

    /// Computes the domain-separated immutable full placement commitment.
    ///
    /// # Errors
    /// Returns an error for invalid structure or excessive encoded control size.
    pub fn fingerprint(&self, deployment: &str) -> Result<String> {
        self.validate(deployment)?;
        digest_projection(b"aos.direct-upload.placement.v1\0", self)
    }

    /// Returns the public placement/checksum projection of this exact snapshot.
    ///
    /// # Errors
    /// Returns an error for invalid structure or commitment encoding.
    pub fn public_ref(&self, deployment: &str) -> Result<DirectPlacementRef> {
        Ok(DirectPlacementRef {
            placement_id: self.placement_id,
            placement_fingerprint: self.fingerprint(deployment)?,
            placement_resource_version: self.placement_resource_version,
            write_spec_version: self.write_spec_version,
            binding_id: self.binding_id,
            binding_resource_version: self.binding_resource_version,
            binding_write_revision: self.binding_write_revision,
            profile_fingerprint: self.presign_credential.credential_fingerprint.clone(),
            private_policy_digest: self.private_stage_policy.policy_digest.clone(),
            checksum_algorithm: self.checksum_algorithm,
        })
    }
}

impl DirectUploadAdmission {
    /// Checks an immutable Native admission against an external deployment pin.
    ///
    /// This establishes neither ACL approval nor live provider qualification.
    /// The exact authenticated original must be durably reserved before effects.
    ///
    /// # Errors
    /// Returns an error for malformed identities, source, sorted destinations,
    /// physical scope or a changed immutable admission fingerprint.
    pub fn validate(&self, deployment: &str) -> Result<()> {
        self.validate_projection(deployment)?;
        ensure!(
            valid_direct_digest(&self.logical_fingerprint)
                && self.logical_fingerprint == self.fingerprint(deployment)?,
            "direct admission fingerprint mismatch"
        );
        Ok(())
    }

    /// Computes the immutable admission fingerprint excluding its own field.
    ///
    /// The original deadline is part of the admission; envelope freshness may
    /// be renewed without changing or replacing this retained projection.
    ///
    /// # Errors
    /// Returns an error for invalid immutable projection or encoded size.
    pub fn fingerprint(&self, deployment: &str) -> Result<String> {
        self.validate_projection(deployment)?;
        #[derive(serde::Serialize)]
        struct Projection<'a> {
            deployment: &'a str,
            session_id: &'a str,
            principal_id: &'a str,
            actor_slot: &'a super::DirectActorSlot,
            intent: &'a DirectUploadIntent,
            expires_at: WireInteger,
            placements: &'a [DirectPlacement],
        }
        digest_projection(
            b"aos.direct-upload.admission.v1\0",
            &Projection {
                deployment,
                session_id: &self.session_id,
                principal_id: &self.principal_id,
                actor_slot: &self.actor_slot,
                intent: &self.intent,
                expires_at: self.expires_at,
                placements: &self.placements,
            },
        )
    }

    fn validate_projection(&self, deployment: &str) -> Result<()> {
        ensure!(
            valid_direct_identity(deployment)
                && valid_direct_identity(&self.session_id)
                && valid_direct_identity(&self.principal_id)
                && self.expires_at.get() > 0,
            "invalid direct admission identity"
        );
        ensure!(
            self.principal_id == self.actor_slot.principal_id(deployment)?,
            "direct actor principal commitment mismatch"
        );
        self.intent.validate()?;
        ensure!(
            !self.placements.is_empty() && self.placements.len() <= MAX_DIRECT_PLACEMENTS,
            "invalid direct admission placement count"
        );
        let mut previous = 0;
        for placement in &self.placements {
            placement.validate(deployment)?;
            ensure!(
                placement.placement_id.get() > previous,
                "unsorted direct admission placements"
            );
            previous = placement.placement_id.get();
            direct_staging_key(&self.session_id, placement)?;
        }
        Ok(())
    }
}

/// Derives the one exact private stage key shared by broker and provider guard.
///
/// The original admission/session must first be retained at the independent
/// business reservation address; restored SQL cannot introduce a new session.
///
/// # Errors
/// Returns an error for invalid session, placement or excessive full key length.
pub fn direct_staging_key(session_id: &str, placement: &DirectPlacement) -> Result<String> {
    ensure!(
        valid_direct_identity(session_id)
            && private_prefix(&placement.staging_prefix)
            && (1..=i64::MAX as u64).contains(&placement.placement_id.get()),
        "invalid direct stage coordinates"
    );
    let key = format!(
        "{}/{}/{}/payload",
        placement.staging_prefix,
        hex::encode(Sha256::digest(session_id.as_bytes())),
        placement.placement_id.get()
    );
    ensure!(key.len() <= 1024, "direct stage key exceeds limit");
    Ok(key)
}

pub(super) fn private_prefix(value: &str) -> bool {
    value.len() <= 900
        && !value.starts_with('/')
        && value.trim() == value
        && value
            .split('/')
            .any(|segment| segment == ".aos-direct-upload")
        && value
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
        && !value
            .chars()
            .any(|c| c.is_control() || matches!(c, '\\' | '?' | '#'))
}

fn contains_key(prefix: &str, key: &str) -> bool {
    prefix.is_empty()
        || key == prefix
        || key
            .strip_prefix(prefix)
            .is_some_and(|tail| tail.starts_with('/'))
}

pub(super) fn credential(value: &DirectCredentialRevision, purpose: &str) -> Result<()> {
    ensure!(
        value.purpose == purpose
            && valid_direct_identity(&value.credential_id)
            && (1..=i64::MAX as u64).contains(&value.generation.get())
            && valid_direct_identity(&value.secret_version_ref)
            && valid_direct_digest(&value.credential_fingerprint),
        "invalid direct credential revision"
    );
    Ok(())
}

fn digest_projection<T: serde::Serialize>(domain: &[u8], value: &T) -> Result<String> {
    let encoded = encode_direct_control(value)?;
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(encoded);
    Ok(hex::encode(hash.finalize()))
}
