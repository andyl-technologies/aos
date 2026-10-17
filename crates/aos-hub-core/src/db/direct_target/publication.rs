//! Verified DirectUpload publication presence and exact source-link writes.

use anyhow::{ensure, Context as _, Result};

use super::super::{Database, DirectUploadSessionRecord};
use crate::{
    backend::CheckedStatement,
    direct_upload::{DirectCompletionEvidence, DirectObjectIncarnation, DirectUploadTarget},
    value::Value,
};

impl Database {
    /// Builds billing and publication parent locks before the retained source session.
    ///
    /// Mirror publication uses the same order when consuming an immutable Direct
    /// source receipt. An unowned registry still holds its publication parents.
    ///
    /// # Errors
    /// Returns an error for a disappeared publication, invalid target ID or SQL failure.
    pub(crate) async fn direct_publication_accounting_prefix(
        &self,
        record: &DirectUploadSessionRecord,
    ) -> Result<Vec<CheckedStatement>> {
        let DirectUploadTarget::PublicationObject {
            publication_id,
            surface_object_id,
            ..
        } = &record.admission.intent.target
        else {
            return Ok(Vec::new());
        };
        let row = self.backend.query_opt(
            "SELECT registry.org_id, registry.id FROM registry_publications publication JOIN registries registry
               ON registry.id = publication.registry_id WHERE publication.publication_id = ?1",
            &vals![publication_id],
        ).await?.context("direct publication billing parent absent")?;
        let org = row.get::<Option<i64>>(0)?;
        let registry = row.get::<i64>(1)?;
        let mut statements = Self::verified_registry_accounting_owner_locks(org);
        statements.extend([
            CheckedStatement::exact("UPDATE registries SET updated_at = updated_at WHERE id = ?1",
                vals![registry], 1),
            CheckedStatement::exact("UPDATE registry_publication_state SET resource_version = resource_version WHERE registry_id = ?1",
                vals![registry], 1),
            CheckedStatement::exact("UPDATE registry_publications SET mutation_version = mutation_version WHERE publication_id = ?1 AND registry_id = ?2",
                vals![publication_id, registry], 1),
            CheckedStatement::exact("UPDATE surface_objects SET updated_at = updated_at WHERE id = ?1 AND registry_id = ?2",
                vals![i64::try_from(surface_object_id.get())?, registry], 1),
        ]);
        Ok(statements)
    }

    /// Builds publication copy writes bound to the exact independently verified final source.
    ///
    /// The authority must authenticate fresh final guard readback before executing
    /// this plan. The session's terminal receipt commits in the same transaction;
    /// neither observations nor a configured profile can install this source link.
    ///
    /// # Errors
    /// Rejects a nonpublication target, changed source or unrepresentable SQL pins.
    pub async fn direct_publication_presence_statements(
        &self,
        record: &DirectUploadSessionRecord,
        evidence: &DirectCompletionEvidence,
        deployment: &str,
        now: i64,
    ) -> Result<Vec<CheckedStatement>> {
        evidence.validate_against(&record.admission, deployment)?;
        let DirectUploadTarget::PublicationObject {
            publication_id,
            surface_object_id,
            ..
        } = &record.admission.intent.target
        else {
            anyhow::bail!("direct final target is not a publication object");
        };
        let object_id = i64::try_from(surface_object_id.get())?;
        let org = self.backend.query_opt(
            "SELECT registry.org_id FROM surface_objects object JOIN registries registry ON registry.id = object.registry_id
             JOIN registry_publications publication ON publication.registry_id = registry.id
             WHERE object.id = ?1 AND publication.publication_id = ?2 AND object.lifecycle_state = 'active'",
            &vals![object_id, publication_id],
        ).await?.context("direct publication accounting owner absent")?.get::<Option<i64>>(0)?;
        let prior = self.surface_object_usage(object_id).await?;
        let mut statements = Self::verified_registry_accounting_owner_locks(org);
        statements.push(CheckedStatement::exact(
            "UPDATE registries SET updated_at = updated_at WHERE id =
               (SELECT registry_id FROM registry_publications WHERE publication_id = ?1)",
            vals![publication_id],
            1,
        ));
        statements.push(CheckedStatement::exact(
            "UPDATE surface_objects SET updated_at = updated_at WHERE id = ?1
               AND registry_id = (SELECT registry_id FROM registry_publications WHERE publication_id = ?2)
               AND lifecycle_state = 'active'",
            vals![object_id, publication_id], 1,
        ));
        statements.extend(
            self.verified_registry_object_usage_statements(
                object_id,
                org,
                prior.as_ref(),
                i64::try_from(evidence.byte_size.get())?,
                now,
            )
            .await?,
        );
        for placement in &evidence.placements {
            statements.extend(Self::registry_publication_object_presence_statements(
                publication_id,
                i64::try_from(surface_object_id.get())?,
                i64::try_from(placement.placement_id.get())?,
                &evidence.sha256,
                i64::try_from(evidence.byte_size.get())?,
                Some(&placement.final_etag),
                now,
                Some((
                    i64::try_from(placement.placement_resource_version.get())?,
                    i64::try_from(placement.binding_resource_version.get())?,
                )),
            )?);
            let provider = match &placement.final_incarnation {
                DirectObjectIncarnation::ProviderVersion { version } => {
                    ensure!(
                        version.len() <= 512,
                        "direct provider version exceeds catalogue bound"
                    );
                    Value::Text(version.clone())
                }
                DirectObjectIncarnation::GuardStamp { .. } => Value::Null,
            };
            statements.push(CheckedStatement::exact(
                "UPDATE object_placements SET observed_placement_resource_version = ?3,
                   observed_write_spec_version = ?4, observed_binding_resource_version = ?5,
                   provider_version = ?6, direct_upload_session_id = ?7
                 WHERE surface_object_id = ?1 AND placement_id = ?2 AND state = 'present'
                   AND observed_hash = ?8 AND observed_size = ?9 AND etag = ?10",
                vals![
                    i64::try_from(surface_object_id.get())?,
                    i64::try_from(placement.placement_id.get())?,
                    i64::try_from(placement.placement_resource_version.get())?,
                    i64::try_from(placement.write_spec_version.get())?,
                    i64::try_from(placement.binding_resource_version.get())?,
                    provider,
                    record.admission.session_id,
                    evidence.sha256,
                    i64::try_from(evidence.byte_size.get())?,
                    placement.final_etag
                ],
                1,
            ));
        }
        Ok(statements)
    }
}
