//! Current External mirror publication and same-transaction admission fences.
//!
//! Provider permission still belongs to the separately authenticated executor
//! lease. These checks prevent SQL originals, progress and catalogue commits
//! from surviving changes to the exact admitted publication or credential heads.

use anyhow::{ensure, Context as _, Result};

use crate::{
    backend::CheckedStatement,
    mirror_work::MirrorOriginal,
    storage_authority::lease::{LeaseCohort, LeaseEffect, LeasePurpose},
};

use super::super::{BindingRecord, Database};

impl Database {
    pub(in crate::db) async fn validate_external_mirror_binding(
        &self,
        original: &MirrorOriginal,
        binding: &BindingRecord,
    ) -> Result<()> {
        let selected = original
            .external_destination
            .as_ref()
            .context("External mirror destination absent")?;
        let profile = &selected.protected_profile.profile;
        let association = &profile.selector.association;
        ensure!(
            binding.kind == selected.binding_kind
                && !binding.is_instance_default
                && binding.id == association.binding_id.get()
                && binding.stable_id == association.binding_stable_id
                && binding.resource_version == association.binding_resource_version.get()
                && binding.object_prefix.as_deref() == Some(association.binding_prefix.as_str()),
            "mirror External binding changed original"
        );
        let read = &profile.read_cohort;
        let publication = self
            .storage_authority_publication(
                &read.authority.authority_id,
                &read.authority.guard_namespace_id,
                &read.executor_identity,
            )
            .await?;
        for (purpose, expected) in [
            (LeasePurpose::Read, read),
            (LeasePurpose::Write, &profile.write_cohort),
            (LeasePurpose::List, &selected.list_cohort),
        ] {
            let current = LeaseCohort::from_publication(
                &publication,
                &expected.executor_identity,
                &expected.association.association_id,
                purpose,
                &expected.admitted_prefix,
                expected.allowed_effects.clone(),
            )?;
            ensure!(
                current == *expected,
                "mirror External publication changed original"
            );
        }
        let writer = self
            .reconciled_surface_writer(super::super::SurfaceTarget::Registry(original.registry_id))
            .await?;
        ensure!(
            writer.authority_observed_binding_write_revision
                == Some(association.binding_write_revision.get()),
            "mirror External writer revision changed original"
        );
        let latest = super::super::unix_now()
            .checked_add(profile.clock_uncertainty.get())
            .context("mirror External clock overflow")?;
        ensure!(
            u64::try_from(latest)? < selected.expires_at,
            "mirror External original publication expired"
        );
        Ok(())
    }

    /// Locks the exact mutable admission and credential heads through commit.
    pub(in crate::db) fn mirror_external_authority_locks(
        original: &MirrorOriginal,
    ) -> Result<Vec<CheckedStatement>> {
        let Some(selected) = &original.external_destination else {
            return Ok(Vec::new());
        };
        let profile = &selected.protected_profile.profile;
        let cohort = &profile.read_cohort;
        let association = &profile.selector.association;
        let mut locks = vec![
            CheckedStatement::exact(
                "UPDATE storage_authority_admission_heads SET resource_version = resource_version
             WHERE authority_id = ?1 AND desired_generation = ?2
               AND EXISTS (SELECT 1 FROM storage_authority_admission_revisions revision
                 WHERE revision.authority_id = ?1 AND revision.generation = ?2
                   AND revision.state = 'admitted' AND revision.specification_digest = ?3
                   AND revision.attestation_id = ?4)",
                vals![
                    cohort.authority.authority_id.as_str(),
                    cohort.admission_generation.get(),
                    cohort.admission_digest,
                    cohort.attestation_id
                ],
                1,
            ),
            CheckedStatement::exact(
                "UPDATE bindings SET updated_at = updated_at
             WHERE id = ?1 AND stable_id = ?2 AND resource_version = ?3
               AND kind = ?4 AND is_instance_default = 0 AND object_prefix = ?5",
                vals![
                    original.binding_id,
                    association.binding_stable_id,
                    original.binding_resource_version,
                    selected.binding_kind,
                    association.binding_prefix
                ],
                1,
            ),
            CheckedStatement::exact(
                "UPDATE binding_write_state SET updated_at = updated_at
             WHERE binding_id = ?1 AND current_write_revision = ?2",
                vals![
                    original.binding_id,
                    association.binding_write_revision.get()
                ],
                1,
            ),
        ];
        for cohort in [
            &profile.read_cohort,
            &profile.write_cohort,
            &selected.list_cohort,
        ] {
            let credential = &cohort.credential;
            let purpose = match credential.purpose {
                LeasePurpose::Read => "read",
                LeasePurpose::Write => "write",
                LeasePurpose::List => "list",
                _ => anyhow::bail!("mirror cohort changed credential purpose"),
            };
            ensure!(
                purpose != "list" || cohort.allowed_effects == [LeaseEffect::List],
                "mirror List cohort changed effects"
            );
            locks.push(CheckedStatement::exact(
                "UPDATE binding_credential_heads SET updated_at = updated_at
                 WHERE binding_id = ?1 AND purpose = ?2 AND current_generation = ?3",
                vals![original.binding_id, purpose, credential.generation.get()],
                1,
            ));
            locks.push(CheckedStatement::exact(
                "UPDATE binding_credential_revisions SET created_at = created_at
                 WHERE binding_id = ?1 AND purpose = ?2 AND generation = ?3
                   AND secret_version_ref = ?4 AND credential_fingerprint = ?5
                   AND validation_state = 'valid'",
                vals![
                    original.binding_id,
                    purpose,
                    credential.generation.get(),
                    credential.secret_version_ref,
                    credential.credential_fingerprint
                ],
                1,
            ));
        }
        Ok(locks)
    }
}
