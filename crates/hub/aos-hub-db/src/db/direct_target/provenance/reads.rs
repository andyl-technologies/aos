//! Bounded overlapping canonical source reads for exact immutable copy fences.

use anyhow::{ensure, Context as _, Result};
use futures_util::{stream, Stream, StreamExt as _, TryStreamExt as _};
use sha2::Digest as _;

use super::{validate_direct_presence_provenance, DirectPresenceProvenance};
use crate::db::{Database, DirectUploadSessionRecord};
use crate::value::{Row, Value};

/// Retains compact checked SQL pins after dropping the full canonical source.
pub(super) struct VerifiedCopy {
    /// Exact terminal source named by this catalogue copy.
    pub(super) session: String,
    /// Canonical source fingerprint, resource version and final evidence digest.
    pub(super) source_tuple: (String, i64, String),
    /// Bound parameters for this copy's exact transactional row lock.
    pub(super) values: Vec<Value>,
    /// Catalogue/placement pair for ordered keyset pagination.
    pub(super) cursor: (i64, i64),
}

struct SourceGroup {
    deployment: String,
    session: String,
    copies: Vec<Row>,
}

/// Loads at most four full sources concurrently, preserving catalogue order.
///
/// Consecutive placements for one source share a load. Each source still passes
/// the ordinary complete reader and every copy passes canonical provenance
/// validation; concurrency neither caches permissions nor skips SQL fences.
///
/// # Errors
/// Refuses malformed copy rows, missing or inconsistent canonical sources, or
/// SQL failures. Source validation errors are yielded by the returned stream.
pub(super) fn copies(
    db: &Database,
    rows: Vec<Row>,
) -> Result<impl Stream<Item = Result<VerifiedCopy>> + '_> {
    let mut groups: Vec<SourceGroup> = Vec::new();
    for row in rows {
        let session: String = row.get(2)?;
        let deployment: String = row.get(10)?;
        if let Some(last) = groups.last_mut() {
            if last.deployment == deployment && last.session == session {
                last.copies.push(row);
                continue;
            }
        }
        groups.push(SourceGroup {
            deployment,
            session,
            copies: vec![row],
        });
    }

    Ok(stream::iter(groups)
        .map(move |group| async move {
            let record = db
                .direct_upload_session(&group.deployment, &group.session)
                .await?
                .context("direct copy source disappeared")?;
            group
                .copies
                .iter()
                .map(|row| verify(&record, row))
                .collect::<Result<Vec<_>>>()
        })
        .buffered(4)
        .map_ok(|copies| stream::iter(copies.into_iter().map(Ok)))
        .try_flatten())
}

fn verify(record: &DirectUploadSessionRecord, row: &Row) -> Result<VerifiedCopy> {
    let object: i64 = row.get(0)?;
    let placement: i64 = row.get(1)?;
    let session: String = row.get(2)?;
    let deployment: String = row.get(10)?;
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
    ensure!(
        record.admission.session_id == session,
        "direct source group changed"
    );
    Ok(VerifiedCopy {
        session: session.clone(),
        source_tuple,
        values: vals![
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
        ],
        cursor: (object, placement),
    })
}
