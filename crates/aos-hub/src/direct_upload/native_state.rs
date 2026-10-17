//! Persisted Native multipart progress, without credentials or signed URLs.
//!
//! Each provider mutation has a durable pending marker before dispatch. An
//! interrupted mutation remains uncertain; only read-only verification can be
//! restarted from a known completed object. Public resource versions advance
//! only when completion or abort freezes the original upload.
//!
//! The JSON journal retains provider coordinates and positive observations, for
//! example this excerpt (credentials and bearer URLs are never journal fields):
//!
//! ```json
//! {"pending":"process-id:complete-stage-0","integrity_failed":false}
//! ```

use std::collections::BTreeMap;

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::direct_upload::*;
use serde::{Deserialize, Serialize};

use super::{
    native_provider::{NativeBaseline, NativeObject},
    native_targets::NativeUploadOriginal,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Retains a part grant's immutable geometry and the client's provider observation.
pub(crate) struct NativePartState {
    /// Stable identifier that binds a report to its original grant.
    pub grant_id: String,
    /// Revision of the current short-lived grant.
    pub grant_revision: WireInteger,
    /// Client operation used to make grant retries idempotent.
    pub operation_id: String,
    /// Authorized byte range, size and checksum.
    pub part: DirectPart,
    /// Exact expiration of the current signed provider URL.
    pub expires_at: WireInteger,
    /// Positive UploadPart result reported by the client.
    pub observed: Option<DirectManifestPart>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Retains one placement's private staging and final-copy progress.
pub(crate) struct NativeDestination {
    /// Public placement reference without credentials.
    pub placement: DirectPlacementRef,
    /// Private path relative to the placement prefix.
    pub staging_path: String,
    /// Provider's original private multipart identifier.
    pub staging_upload: Option<String>,
    /// Positive closure identity for the private stage.
    pub staging_object: Option<NativeObject>,
    /// Whether Native measured the stage's full SHA-256 and size.
    pub verified: bool,
    /// Provider multipart identifier for the final server-side copy.
    pub final_upload: Option<String>,
    /// Positive server-copy part results retained for completion retries.
    pub copied_parts: Vec<DirectManifestPart>,
    /// Positive closure identity for the final object.
    pub final_object: Option<NativeObject>,
    /// Current grants and positive client observations indexed by part number.
    pub parts: BTreeMap<u32, NativePartState>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Stores the original authorization and restartable Native upload progress.
pub(crate) struct NativeUploadState {
    /// Immutable actor, source identity, target and placement credential pins.
    pub original: NativeUploadOriginal,
    /// Shared public session identity.
    pub session: DirectSessionRef,
    /// Public revision; independent of the SQL journal's CAS version.
    pub resource_version: WireInteger,
    /// Current public upload phase.
    pub state: DirectSessionState,
    /// Provider progress for every required placement.
    pub destinations: Vec<NativeDestination>,
    /// Exact frozen completion request and client manifests.
    pub complete: Option<DirectCompleteRequest>,
    /// Exact frozen abort request.
    pub abort: Option<DirectAbortRequest>,
    /// Process and operation marker retained before each provider mutation.
    pub pending: Option<String>,
    /// Bounded parsed metadata produced only after full source verification.
    pub projection: Option<aos_hub_core::hybrid_ingress::HybridObjectProjection>,
    /// Full-object SHA-256 independently measured from a closed stage.
    pub verified_sha256: Option<String>,
    /// Exact stage byte count measured to EOF.
    pub verified_size: Option<u64>,
    /// Whether the prior cache object has been measured for quota accounting.
    pub baseline_checked: bool,
    /// Prior cache object identity used by the existing write ticket.
    pub baseline: Option<NativeBaseline>,
    /// Permanent content mismatch, preventing repeated expensive verification.
    pub integrity_failed: bool,
}

impl NativeUploadState {
    /// Projects bounded public status without exposing provider control secrets.
    ///
    /// # Errors
    /// Returns an error for a foreign cursor or invalid public wire values.
    pub(crate) fn status(&self, query: Option<&DirectStatusQuery>) -> Result<DirectSessionStatus> {
        let maximum = query.map_or(0, |query| query.maximum_parts as usize);
        let after = query
            .and_then(|query| query.after.as_ref())
            .map(|cursor| (cursor.placement.placement_id.get(), cursor.part_number));
        if let Some(cursor) = query.and_then(|query| query.after.as_ref()) {
            ensure!(
                self.destinations
                    .iter()
                    .any(|destination| destination.placement == cursor.placement),
                "foreign Native status cursor"
            );
        }
        let mut parts = Vec::new();
        let mut more = false;
        for destination in &self.destinations {
            for (&part_number, part) in &destination.parts {
                if after.is_some_and(|after| {
                    (destination.placement.placement_id.get(), part_number) <= after
                }) {
                    continue;
                }
                if parts.len() == maximum {
                    more = true;
                    break;
                }
                parts.push(DirectPartStatus {
                    placement: destination.placement.clone(),
                    part_number,
                    observed: part.observed.clone(),
                    pending_operation_id: None,
                    unknown: false,
                });
            }
        }
        let next_cursor = if more {
            parts.last().map(|part| DirectPartCursor {
                placement: part.placement.clone(),
                part_number: part.part_number,
            })
        } else {
            None
        };
        let status = DirectSessionStatus {
            session: self.session.clone(),
            resource_version: self.resource_version,
            intent: self.original.intent.clone(),
            placements: self
                .destinations
                .iter()
                .map(|destination| destination.placement.clone())
                .collect(),
            state: self.state,
            parts,
            next_cursor,
            outstanding_grants: !matches!(
                self.state,
                DirectSessionState::Committed | DirectSessionState::Aborted
            ),
        };
        status.validate()?;
        Ok(status)
    }

    /// Reconstructs and checks a frozen manifest against retained part reports.
    ///
    /// # Errors
    /// Returns an error for absent completion, inconsistent geometry or digest,
    /// missing observations, or an unknown destination.
    pub(crate) fn manifest(&self, index: usize) -> Result<Vec<DirectManifestPart>> {
        let destination = self
            .destinations
            .get(index)
            .context("Native destination absent")?;
        let parts = destination
            .parts
            .values()
            .map(|part| part.observed.clone().context("Native part report absent"))
            .collect::<Result<Vec<_>>>()?;
        let complete = self
            .complete
            .as_ref()
            .context("Native Complete original absent")?;
        let commitment = complete
            .manifests
            .iter()
            .find(|manifest| manifest.placement == destination.placement)
            .context("Native destination manifest absent")?;
        ensure!(
            commitment.part_count == self.original.intent.part_count()?
                && canonical_manifest_digest(
                    &self.original.intent,
                    &destination.placement,
                    &parts
                )? == commitment.manifest_digest,
            "Native complete manifest differs"
        );
        Ok(parts)
    }
}

/// Hashes the canonical serialized value used by Native immutable identities.
///
/// # Errors
/// Returns an error when the value cannot be serialized to JSON.
pub(crate) fn digest<T: Serialize>(value: &T) -> Result<String> {
    use sha2::Digest as _;
    Ok(hex::encode(sha2::Sha256::digest(serde_json::to_vec(
        value,
    )?)))
}
