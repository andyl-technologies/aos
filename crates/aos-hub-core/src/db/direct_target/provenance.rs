//! Exact committed DirectUpload provenance for a current catalogue copy.
//!
//! An observationally equal hash or ETag cannot reconstruct this source link.
//! Only the verified final transaction installs it; ordinary replacement clears it.

use anyhow::{ensure, Context as _, Result};
use sha2::Digest as _;

use crate::direct_upload::{DirectObjectIncarnation, DirectSessionState, DirectUploadTarget};

use super::super::DirectUploadSessionRecord;
use crate::{backend::CheckedStatement, db::Database};

/// Describes the SQL copy whose explicit DirectUpload source is being checked.
#[derive(Debug, Clone)]
pub struct DirectPresenceProvenance<'a> {
    /// Deployment that owns the retained admission and receipt.
    pub deployment_id: &'a str,
    /// Exact retained session selected by the copy, never a searched receipt.
    pub session_id: &'a str,
    /// Current logical catalogue identity.
    pub surface_object_id: i64,
    /// Current physical placement identity.
    pub placement_id: i64,
    /// Current copy content SHA-256.
    pub sha256: &'a str,
    /// Current copy byte count.
    pub byte_size: i64,
    /// Strong ETag retained by this copy.
    pub etag: &'a str,
    /// Actual provider version; absent for a nonversioned guard stamp.
    pub provider_version: Option<&'a str>,
    /// Placement version observed by the verified final commit.
    pub placement_resource_version: i64,
    /// Writer specification observed by the verified final commit.
    pub write_spec_version: i64,
    /// Binding version observed by the verified final commit.
    pub binding_resource_version: i64,
}

/// Checks a current copy against its exact canonical committed DirectUpload record.
///
/// The caller must load the record named by `copy.session_id`, validate its SQL
/// scalar/document consistency, and fence the copy, receipt and session rows in
/// the transaction that consumes this proof. This pure check neither performs
/// physical discovery nor grants a new provider effect.
///
/// # Errors
/// Rejects a nonterminal or unrelated session, changed source or placement pins,
/// missing original Complete/baseline/guard, or a different final incarnation.
pub fn validate_direct_presence_provenance(
    record: &DirectUploadSessionRecord,
    copy: &DirectPresenceProvenance<'_>,
) -> Result<()> {
    ensure!(
        record.state == DirectSessionState::Committed,
        "direct copy source is not committed"
    );
    ensure!(
        record.admission.session_id == copy.session_id,
        "direct copy source identity differs"
    );
    let DirectUploadTarget::PublicationObject {
        surface_object_id, ..
    } = &record.admission.intent.target
    else {
        anyhow::bail!("direct copy source is not a publication object");
    };
    ensure!(
        i64::try_from(surface_object_id.get())? == copy.surface_object_id,
        "direct copy catalogue differs"
    );
    let complete = record
        .complete_intent
        .as_ref()
        .context("direct copy original Complete absent")?;
    let evidence = record
        .completion_evidence
        .as_ref()
        .context("direct copy positive receipt absent")?;
    evidence.validate_against(&record.admission, copy.deployment_id)?;
    ensure!(
        evidence.sha256 == copy.sha256
            && i64::try_from(evidence.byte_size.get())? == copy.byte_size,
        "direct copy verified source differs"
    );
    let placement = evidence
        .placements
        .iter()
        .find(|item| i64::try_from(item.placement_id.get()).ok() == Some(copy.placement_id))
        .context("direct copy receipt placement absent")?;
    ensure!(
        i64::try_from(placement.placement_resource_version.get())?
            == copy.placement_resource_version
            && i64::try_from(placement.write_spec_version.get())? == copy.write_spec_version
            && i64::try_from(placement.binding_resource_version.get())?
                == copy.binding_resource_version
            && placement.final_etag == copy.etag,
        "direct copy authority or ETag differs"
    );
    let guard = record
        .final_guards
        .iter()
        .find(|item| item.reservation.placement.placement_id == placement.placement_id)
        .context("direct copy final guard absent")?;
    guard.validate_for(&record.admission, complete, evidence, copy.deployment_id)?;
    ensure!(
        record
            .baselines
            .iter()
            .any(|item| item.binding == guard.reservation),
        "direct copy original reservation absent"
    );
    match &placement.final_incarnation {
        DirectObjectIncarnation::ProviderVersion { version } => ensure!(
            copy.provider_version == Some(version.as_str()),
            "direct copy provider incarnation differs"
        ),
        DirectObjectIncarnation::GuardStamp { .. } => ensure!(
            copy.provider_version.is_none(),
            "direct guard stamp is not a provider version"
        ),
    }
    Ok(())
}

impl Database {
    /// Locks and checks exact terminal sources of required immutable Direct copies.
    ///
    /// At most one full canonical record is retained. Compact source tuples and
    /// exact copy tuples are bounded to 65,536 copies and 11,000 checked statements;
    /// exceeding either limit refuses before pointer effects. Predicates are grouped
    /// below 96 parameters for every backend. Terminal originals and receipts are
    /// immutable through production APIs: completion inserts once, exact replay is
    /// read-only, and Abort cannot alter a committed source.
    ///
    /// Callers append this plan after catalogue locks and before presence locks,
    /// then recheck the immutable barrier in the same checked transaction.
    ///
    /// # Errors
    /// Rejects missing or noncanonical sources, unrelated copies, changed tuples,
    /// excessive dependency sets, or database failure. Provider bytes are not read.
    pub async fn direct_publication_provenance_locks(
        &self,
        publication: &str,
    ) -> Result<Vec<CheckedStatement>> {
        const MAX_COPIES: i64 = 65_536;
        const MAX_STATEMENTS: usize = 11_000;
        let count = self.backend.query_opt(
            "SELECT COUNT(*) FROM registry_publication_objects object
             JOIN registry_publication_placements required ON required.publication_id = object.publication_id AND required.required = 1
             JOIN object_placements presence ON presence.surface_object_id = object.surface_object_id AND presence.placement_id = required.placement_id
             WHERE object.publication_id = ?1 AND object.object_kind = 'immutable' AND presence.direct_upload_session_id IS NOT NULL",
            &vals![publication],
        ).await?.context("direct copy count absent")?.get::<i64>(0)?;
        ensure!(
            (0..=MAX_COPIES).contains(&count),
            "direct provenance dependency set exceeds bound"
        );

        let mut sources = std::collections::BTreeMap::<String, (String, i64, String)>::new();
        let mut current_source: Option<(String, DirectUploadSessionRecord)> = None;
        let mut copy_checks = Vec::new();
        let mut copy_predicates = Vec::new();
        let mut copy_values = Vec::new();
        let mut cursor = (0_i64, 0_i64);
        let mut seen = 0_i64;
        loop {
            let rows = self.backend.query(
                "SELECT presence.surface_object_id, presence.placement_id, presence.direct_upload_session_id,
                        presence.observed_hash, presence.observed_size, presence.etag, presence.provider_version,
                        presence.observed_placement_resource_version, presence.observed_write_spec_version,
                        presence.observed_binding_resource_version, session.deployment_id
                 FROM registry_publication_objects object
                 JOIN registry_publication_placements required ON required.publication_id = object.publication_id AND required.required = 1
                 JOIN object_placements presence ON presence.surface_object_id = object.surface_object_id AND presence.placement_id = required.placement_id
                 JOIN direct_upload_sessions session ON session.session_id = presence.direct_upload_session_id
                 WHERE object.publication_id = ?1 AND object.object_kind = 'immutable'
                   AND (presence.surface_object_id > ?2 OR (presence.surface_object_id = ?2 AND presence.placement_id > ?3))
                 ORDER BY presence.surface_object_id, presence.placement_id LIMIT 128",
                &vals![publication, cursor.0, cursor.1],
            ).await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                seen = seen.checked_add(1).context("direct copy count overflow")?;
                ensure!(
                    seen <= MAX_COPIES,
                    "direct provenance dependency set exceeds bound"
                );
                let object: i64 = row.get(0)?;
                let placement: i64 = row.get(1)?;
                let session: String = row.get(2)?;
                let deployment: String = row.get(10)?;
                if current_source.as_ref().is_none_or(|(id, _)| id != &session) {
                    current_source = Some((
                        session.clone(),
                        self.direct_upload_session(&deployment, &session)
                            .await?
                            .context("direct copy source disappeared")?,
                    ));
                }
                let record = &current_source
                    .as_ref()
                    .context("direct copy source absent")?
                    .1;
                let hash: String = row.get(3)?;
                let size: i64 = row.get(4)?;
                let etag: String = row.get(5)?;
                let provider: Option<String> = row.get(6)?;
                let placement_version: i64 = row.get(7)?;
                let write_spec: i64 = row.get(8)?;
                let binding_version: i64 = row.get(9)?;
                validate_direct_presence_provenance(
                    record,
                    &DirectPresenceProvenance {
                        deployment_id: &deployment,
                        session_id: &session,
                        surface_object_id: object,
                        placement_id: placement,
                        sha256: &hash,
                        byte_size: size,
                        etag: &etag,
                        provider_version: provider.as_deref(),
                        placement_resource_version: placement_version,
                        write_spec_version: write_spec,
                        binding_resource_version: binding_version,
                    },
                )?;
                let evidence = record
                    .completion_evidence
                    .as_ref()
                    .context("direct copy receipt absent")?;
                let source_tuple = (
                    record.admission.logical_fingerprint.clone(),
                    i64::try_from(record.resource_version.get())?,
                    hex::encode(sha2::Sha256::digest(
                        crate::direct_upload::encode_direct_control(evidence)?,
                    )),
                );
                if let Some(original) = sources.insert(session.clone(), source_tuple.clone()) {
                    ensure!(
                        original == source_tuple,
                        "direct source changed during provenance read"
                    );
                }
                let start = copy_values.len() + 1;
                copy_predicates.push(format!("(surface_object_id = ?{start} AND placement_id = ?{} AND direct_upload_session_id = ?{}
                    AND state = 'present' AND observed_hash = ?{} AND observed_size = ?{} AND etag = ?{}
                    AND ((CAST(?{} AS VARCHAR) IS NULL AND provider_version IS NULL) OR provider_version = ?{})
                    AND observed_placement_resource_version = ?{} AND observed_write_spec_version = ?{} AND observed_binding_resource_version = ?{})",
                    start+1, start+2, start+3, start+4, start+5, start+6, start+6, start+7, start+8, start+9));
                copy_values.extend(vals![
                    object,
                    placement,
                    session,
                    hash,
                    size,
                    etag,
                    provider,
                    placement_version,
                    write_spec,
                    binding_version
                ]);
                if copy_predicates.len() == 8 {
                    copy_checks.push(CheckedStatement::exact(
                        format!(
                            "UPDATE object_placements SET observed_at = observed_at WHERE {}",
                            copy_predicates.join(" OR ")
                        ),
                        std::mem::take(&mut copy_values),
                        copy_predicates.len() as u64,
                    ));
                    copy_predicates.clear();
                }
                cursor = (object, placement);
            }
        }
        ensure!(
            seen == count,
            "direct provenance source set changed during read"
        );
        if !copy_predicates.is_empty() {
            copy_checks.push(CheckedStatement::exact(
                format!(
                    "UPDATE object_placements SET observed_at = observed_at WHERE {}",
                    copy_predicates.join(" OR ")
                ),
                copy_values,
                copy_predicates.len() as u64,
            ));
        }

        // These fixed set-based locks precede all exact copy locks. Original and
        // evidence digests fence immutable terminal facts without duplicating JSON.
        let selected = "SELECT DISTINCT presence.direct_upload_session_id FROM registry_publication_objects object
            JOIN registry_publication_placements required ON required.publication_id = object.publication_id AND required.required = 1
            JOIN object_placements presence ON presence.surface_object_id = object.surface_object_id AND presence.placement_id = required.placement_id
            WHERE object.publication_id = ?1 AND object.object_kind = 'immutable' AND presence.direct_upload_session_id IS NOT NULL";
        let mut statements = vec![
            CheckedStatement::exact(format!("UPDATE direct_upload_sessions SET updated_at = updated_at WHERE state = 'committed' AND session_id IN ({selected})"), vals![publication], sources.len() as u64),
            CheckedStatement::exact(format!("UPDATE direct_upload_completion_receipts SET committed_at = committed_at WHERE session_id IN ({selected})"), vals![publication], sources.len() as u64),
        ];
        let source_rows = sources.into_iter().collect::<Vec<_>>();
        for group in source_rows.chunks(24) {
            let mut predicates = Vec::new();
            let mut values = Vec::new();
            for (session, (fingerprint, version, evidence_digest)) in group {
                let start = values.len() + 1;
                predicates.push(format!("(session_id = ?{start} AND logical_fingerprint = ?{} AND resource_version = ?{}
                    AND EXISTS (SELECT 1 FROM direct_upload_completion_receipts receipt WHERE receipt.session_id = direct_upload_sessions.session_id AND receipt.evidence_digest = ?{}))", start+1, start+2, start+3));
                values.extend(vals![session, fingerprint, version, evidence_digest]);
            }
            statements.push(CheckedStatement::exact(format!("UPDATE direct_upload_sessions SET updated_at = updated_at WHERE state = 'committed' AND ({})", predicates.join(" OR ")), values, group.len() as u64));
        }
        statements.extend(copy_checks);
        // New links appearing after preflight cannot bypass typed validation.
        statements.push(CheckedStatement::exact(
            "UPDATE registry_publications SET mutation_version = mutation_version WHERE publication_id = ?1
               AND (SELECT COUNT(*) FROM registry_publication_objects object
                 JOIN registry_publication_placements required ON required.publication_id = object.publication_id AND required.required = 1
                 JOIN object_placements presence ON presence.surface_object_id = object.surface_object_id AND presence.placement_id = required.placement_id
                 WHERE object.publication_id = ?1 AND object.object_kind = 'immutable' AND presence.direct_upload_session_id IS NOT NULL) = ?2",
            vals![publication, count], 1,
        ));
        ensure!(
            statements.len() <= MAX_STATEMENTS,
            "direct provenance SQL plan exceeds bound"
        );
        Ok(statements)
    }
}
