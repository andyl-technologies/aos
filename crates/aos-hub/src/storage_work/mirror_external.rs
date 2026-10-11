//! Current accepted External destinations selected for mirror orchestration.
//!
//! No provider body enters this module. Independent acceptance is joined with
//! the actual current SQL authority publication and acknowledged secret-free
//! binding snapshot before a mirror original or delivery grant is issued.

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::{
    db::{BindingRecord, Database},
    direct_upload::{DirectProtectedExternalProfile, DirectProtectedProfile},
    mirror_work::MirrorExternalDestination,
    storage_authority::lease::{LeaseCohort, LeaseEffect, LeasePurpose},
};

use super::RemoteStorageWorkClient;

#[cfg(test)]
pub(super) mod controlled;

impl RemoteStorageWorkClient {
    /// Resolves the current prerequisite for either supported mirror destination.
    ///
    /// # Errors
    /// Refuses an absent or changed independently accepted provider publication.
    pub(crate) async fn mirror_destination_profile_digest(
        &self,
        db: &Database,
        binding: &BindingRecord,
    ) -> Result<String> {
        if binding.kind == "deployment_r2" && binding.is_instance_default {
            self.mirror_managed_profile_digest()
        } else {
            self.mirror_external_destination(db, binding)
                .await?
                .protected_profile
                .digest()
        }
    }

    /// Resolves current External mirror prerequisites without granting an effect.
    ///
    /// # Errors
    /// Refuses unaccepted bindings, stale material, changed cohorts or expiry.
    pub(crate) async fn mirror_external_destination(
        &self,
        db: &Database,
        binding: &BindingRecord,
    ) -> Result<MirrorExternalDestination> {
        ensure!(
            matches!(binding.kind.as_str(), "s3" | "r2") && !binding.is_instance_default,
            "mirror External destination requires an External writer"
        );
        let accepted = self
            .mirror_profiles
            .as_ref()
            .context("mirror requires independently accepted External provider evidence")?;
        let origin = self.executor_origin()?;
        let initial_now = aos_hub_core::clock::now_unix_secs();
        let mut selected = accepted
            .profiles(&self.deployment_id, &origin, u64::try_from(initial_now)?)?
            .into_iter()
            .filter(|candidate| match candidate {
                DirectProtectedProfile::External { profile, .. } => {
                    let association = &profile.selector.association;
                    association.binding_id.get() == binding.id
                        && association.binding_stable_id == binding.stable_id
                        && association.binding_resource_version.get() == binding.resource_version
                }
                _ => false,
            });
        let selected_profile = selected
            .next()
            .context("mirror External profile absent or changed")?;
        ensure!(
            selected.next().is_none(),
            "mirror External profile is ambiguous"
        );
        let DirectProtectedProfile::External {
            profile,
            runtime_qualification,
        } = &selected_profile
        else {
            anyhow::bail!("mirror prerequisite changed provider kind");
        };
        let snapshot = self.acknowledged_binding_snapshot(binding.id)?;
        let credentials = db.list_current_binding_credentials(binding.id).await?;
        self.validate_published_binding_snapshot(binding, &credentials, &snapshot.revision()?)?;
        let read = &profile.read_cohort;
        let publication = db
            .storage_authority_publication(
                &read.authority.authority_id,
                &read.authority.guard_namespace_id,
                &read.executor_identity,
            )
            .await?;
        for (purpose, expected) in [
            (LeasePurpose::Read, &profile.read_cohort),
            (LeasePurpose::Write, &profile.write_cohort),
        ] {
            let current = LeaseCohort::from_publication(
                &publication,
                &read.executor_identity,
                &read.association.association_id,
                purpose,
                &expected.admitted_prefix,
                expected.allowed_effects.clone(),
            )?;
            ensure!(current == *expected, "mirror External publication changed");
        }
        let list_cohort = LeaseCohort::from_publication(
            &publication,
            &read.executor_identity,
            &read.association.association_id,
            LeasePurpose::List,
            &read.admitted_prefix,
            vec![LeaseEffect::List],
        )?;
        // Re-sample after the final SQL await. An earlier admission timestamp
        // cannot authorize returned rows after their acceptance or attestation.
        let observed_at = aos_hub_core::clock::now_unix_secs();
        ensure!(
            observed_at >= initial_now,
            "mirror clock moved backward during selection"
        );
        let latest = observed_at
            .checked_add(profile.clock_uncertainty.get())
            .context("mirror qualified clock overflow")?;
        let now = u64::try_from(latest)?;
        ensure!(
            accepted
                .profiles(&self.deployment_id, &origin, now)?
                .contains(&selected_profile),
            "mirror External prerequisite expired during SQL selection"
        );
        snapshot.validate(&self.deployment_id, latest)?;
        ensure!(
            snapshot.binding_id == binding.id
                && snapshot.binding_resource_version == binding.resource_version
                && snapshot.binding_stable_id == binding.stable_id
                && snapshot.object_prefix == profile.selector.association.binding_prefix,
            "mirror External snapshot changed binding scope"
        );
        for expected in [
            &profile.selector.read_credential,
            &profile.selector.write_credential,
        ] {
            ensure!(
                snapshot
                    .credentials
                    .iter()
                    .any(|actual| actual.purpose == expected.purpose
                        && u64::try_from(actual.generation).ok()
                            == Some(expected.generation.get())
                        && actual.secret_version_ref == expected.secret_version_ref
                        && actual.fingerprint == expected.credential_fingerprint),
                "mirror External snapshot changed credential membership"
            );
        }
        let (issued_at, accepted_until, acceptance_digest) = accepted.external_profile_window(
            &self.deployment_id,
            &origin,
            &selected_profile.digest()?,
            now,
        )?;
        let expires_at = accepted_until
            .min(u64::try_from(list_cohort.attestation_valid_until.get())?)
            .min(u64::try_from(
                profile.read_cohort.attestation_valid_until.get(),
            )?)
            .min(u64::try_from(
                profile.write_cohort.attestation_valid_until.get(),
            )?);
        ensure!(
            issued_at <= now && now < expires_at,
            "mirror External publication expired"
        );
        Ok(MirrorExternalDestination {
            binding_kind: binding.kind.clone(),
            binding_spec_revision: snapshot.binding_spec_revision()?,
            protected_profile: DirectProtectedExternalProfile::new(
                profile.clone(),
                runtime_qualification.clone(),
            )?,
            list_cohort,
            issued_at,
            expires_at,
            acceptance_digest,
        })
    }
}
