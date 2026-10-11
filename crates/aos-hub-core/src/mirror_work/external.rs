//! Immutable admitted External destinations for storage-local mirror work.
//!
//! This projection is selected from independently accepted profiles and current
//! SQL publication. Its shape check grants neither a lease nor provider access.
//! Fresh controls still authenticate their binding snapshot and signed epoch
//! leases under the permanent physical-key guard.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use crate::{
    direct_upload::{DirectProtectedExternalProfile, valid_direct_digest},
    storage_authority::lease::{LeaseCohort, LeaseEffect, LeasePurpose},
    storage_authority::{StorageGuardStamp, control::StorageAuthorityObjectScope},
    storage_work::{
        StorageCredentialSelector, StorageObjectIdentity, StorageWorkOperation, StorageWorkPlan,
    },
};

use super::MirrorOriginal;

pub mod journal;

/// Describes positively closed private bytes still requiring qualified cleanup.
///
/// This state reports residual cost. It grants no Delete permission and never
/// treats a Native commit, acknowledgement, deadline or replay as provider drain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MirrorStageRetention {
    /// Retains the exact stage closure until an independent cleanup workflow.
    RetainedForQualifiedCleanup,
}

/// Retains the original External publication without raw provider credentials.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorExternalDestination {
    /// Exact supported executor binding kind selected by current SQL.
    pub binding_kind: String,
    /// Immutable endpoint, bucket and binding-material revision, excluding TTL.
    pub binding_spec_revision: String,
    /// Independently reviewed Read/Write publication and runtime prerequisite.
    pub protected_profile: DirectProtectedExternalProfile,
    /// Separately selected current inventory credential from the same publication.
    pub list_cohort: LeaseCohort,
    /// First accepted prerequisite timestamp, retained across fresh controls.
    pub issued_at: u64,
    /// Immutable prerequisite cutoff; a new profile cannot renew this original.
    pub expires_at: u64,
    /// Actual independent Direct acceptance evidence commitment.
    pub acceptance_digest: String,
}

/// Projects an actual positive mirror completion on one permanent physical key.
///
/// It is not a provider version or a self-authenticating read grant. Consumers
/// must authenticate the producer reply and independently load its exact held
/// original, visible head and immutable completion receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorExternalClosure {
    /// Complete physical key and permanent guard namespace from the original.
    pub scope: StorageAuthorityObjectScope,
    /// Actual guard-issued incarnation, never assigned to `provider_version`.
    pub guard_stamp: StorageGuardStamp,
    /// Canonical positive provider receipt commitment retained before the reply.
    pub receipt_digest: String,
    /// Actual provider identity; a missing provider version remains absent.
    pub object: StorageObjectIdentity,
}

impl MirrorExternalClosure {
    /// Checks intrinsic receipt correlation with the retained original.
    ///
    /// # Errors
    /// Refuses another key, guard namespace, provider identity or receipt shape.
    pub fn validate_for(&self, original: &MirrorOriginal, destination: bool) -> Result<()> {
        let selected = original
            .external_destination
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("External closure supplied for managed mirror"))?;
        let authority = &selected.protected_profile.profile.write_cohort.authority;
        self.scope.guard_name()?;
        self.scope.validate_stamp(&self.guard_stamp)?;
        let key = if destination {
            original.destination_key()
        } else {
            original.stage_key()
        };
        ensure!(
            self.scope.physical_authority_id == authority.authority_id
                && self.scope.guard_namespace_id == authority.guard_namespace_id
                && self.scope.full_key == key
                && self.guard_stamp.incarnation.as_str() != "0"
                && valid_direct_digest(&self.receipt_digest)
                && self.object.key == key
                && self.object.size == original.verification.size()
                && self
                    .object
                    .provider_version
                    .as_deref()
                    .is_none_or(|version| {
                        version != "null" && crate::storage_work::valid_provider_version(version)
                    })
                && crate::surface_write::strong_if_match_etag(&self.object.etag).is_ok(),
            "mirror External closure differs from its physical original"
        );
        Ok(())
    }
}

impl MirrorExternalDestination {
    /// Checks the exact profile, publication membership and original SQL pins.
    ///
    /// # Errors
    /// Refuses changed audiences, credentials, epochs, bindings or key scope.
    pub fn validate_for(&self, original: &MirrorOriginal) -> Result<()> {
        self.protected_profile.validate()?;
        let profile = &self.protected_profile.profile;
        let read = &profile.read_cohort;
        let list = &self.list_cohort;
        let association = &profile.selector.association;
        ensure!(
            matches!(self.binding_kind.as_str(), "s3" | "r2")
                && valid_direct_digest(&self.binding_spec_revision)
                && self.protected_profile.digest()? == original.protected_profile_digest
                && association.binding_id.get() == original.binding_id
                && association.binding_resource_version.get() == original.binding_resource_version
                && original.verification.size()
                    <= self
                        .protected_profile
                        .runtime_qualification
                        .maximum_object_bytes
                        .get()
                && self.issued_at < self.expires_at
                && valid_direct_digest(&self.acceptance_digest)
                && list.authority == read.authority
                && list.executor_identity == read.executor_identity
                && list.admission_generation == read.admission_generation
                && list.admission_digest == read.admission_digest
                && list.publication_digest == read.publication_digest
                && list.alias == read.alias
                && list.association == read.association
                && list.attestation_id == read.attestation_id
                && list.attestation_prefix == read.attestation_prefix
                && list.attestation_valid_until == read.attestation_valid_until
                && list.admitted_prefix == read.admitted_prefix
                && list.credential.association_id == association.association_id
                && list.credential.purpose == LeasePurpose::List
                && list.credential.generation.get() > 0
                && !list.credential.secret_version_ref.is_empty()
                && valid_direct_digest(&list.credential.credential_fingerprint)
                && list.allowed_effects == [LeaseEffect::List],
            "mirror External destination differs from its admitted original"
        );
        for cohort in [&profile.read_cohort, &profile.write_cohort, list] {
            ensure!(
                self.expires_at <= u64::try_from(cohort.attestation_valid_until.get())?,
                "mirror original outlives its admitted publication"
            );
            for key in [original.stage_key(), original.destination_key()] {
                ensure!(
                    within(&cohort.admitted_prefix, &key),
                    "mirror physical key escapes its admitted cohort"
                );
            }
        }
        Ok(())
    }

    /// Binds a fresh snapshot control to the original credential generations.
    ///
    /// # Errors
    /// Refuses a missing snapshot, changed credential or renewed cutoff.
    pub fn validate_plan(&self, plan: &StorageWorkPlan) -> Result<()> {
        let replay_only = match &plan.operation {
            StorageWorkOperation::MirrorTransfer { step, .. } => replay_step(step),
            StorageWorkOperation::MirrorTransferBatch { items } => {
                items.iter().all(|item| replay_step(&item.step))
            }
            _ => false,
        };
        let selector = &self.protected_profile.profile.selector;
        let expected = [
            StorageCredentialSelector {
                purpose: "read".into(),
                generation: i64::try_from(selector.read_credential.generation.get())?,
            },
            StorageCredentialSelector {
                purpose: "write".into(),
                generation: i64::try_from(selector.write_credential.generation.get())?,
            },
        ];
        ensure!(
            plan.binding_kind == self.binding_kind
                && plan
                    .binding_snapshot_revision
                    .as_deref()
                    .is_some_and(valid_direct_digest)
                && plan.credential_references == expected
                && u64::try_from(plan.issued_at)? >= self.issued_at
                && (replay_only || u64::try_from(plan.expires_at)? < self.expires_at),
            "mirror External control changed snapshot, credential or cutoff"
        );
        Ok(())
    }
}

fn replay_step(step: &super::MirrorStep) -> bool {
    matches!(
        step,
        super::MirrorStep::Status { .. } | super::MirrorStep::Acknowledge { .. }
    )
}

fn within(prefix: &str, key: &str) -> bool {
    prefix.is_empty()
        || key == prefix
        || key
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
}
