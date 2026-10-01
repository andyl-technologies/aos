//! Independent metadata readback before a Native mirror publication commit.
//!
//! The producer result is retained first. This client challenges the physical
//! guard under a separate role and revalidates its complete original, positive
//! receipt, implementation pins and immutable deadline. No source bytes or
//! provider credentials pass through this transport.

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::mirror_guard::{
    sign_mirror_guard_lookup, verify_mirror_guard_reply, MirrorGuardExecution, MirrorGuardIssuer,
    MirrorGuardLookup, VerifiedMirrorGuardProof, MIRROR_GUARD_LOOKUP_PATH, MIRROR_GUARD_MAX_BYTES,
    MIRROR_GUARD_SIGNATURE_HEADER,
};
use aos_hub_core::mirror_work::{MirrorOriginal, MirrorProgress};
use futures_util::StreamExt as _;

use super::RemoteStorageWorkClient;

mod batch;

impl RemoteStorageWorkClient {
    /// Reads an independent positive final receipt for an exact retained import.
    ///
    /// Producer acceptance expiry does not grant a new effect, and does not
    /// remove this metadata readback. Public issuer pins must still match the
    /// independently reviewed original profile and actual current guard code.
    ///
    /// # Errors
    /// Returns an error for absent guard authority, changed original/profile,
    /// oversized or unauthenticated replies, stale proofs or transport failure.
    pub async fn lookup_mirror_final_guard(
        &self,
        original: &MirrorOriginal,
        progress: &MirrorProgress,
    ) -> Result<VerifiedMirrorGuardProof> {
        original.validate()?;
        progress.commit_digest(original)?;
        let key = self
            .mirror_guard_key
            .as_ref()
            .context("independent mirror guard authority is not configured")?;
        let origin = url::Url::parse(&self.endpoint)?
            .origin()
            .ascii_serialization();
        #[cfg(test)]
        let candidate = self.controlled_mirror.as_ref();
        #[cfg(test)]
        let selected = candidate.map(|candidate| {
            (
                candidate.issuer.source_digest.clone(),
                candidate.issuer.script_version.clone(),
                candidate.uncertainty,
            )
        });
        #[cfg(not(test))]
        let selected: Option<(String, String, u64)> = None;
        let (source_digest, script_version, uncertainty) = match selected {
            Some(selected) => selected,
            None => {
                let profiles = self
                    .mirror_profiles
                    .as_ref()
                    .context("mirror original has no independently selected issuer pins")?;
                profiles.retained_guard_issuer(
                    &self.deployment_id,
                    &origin,
                    &original.protected_profile_digest,
                )?
            }
        };
        #[cfg(test)]
        let (execution, path) = if candidate.is_some() {
            (
                MirrorGuardExecution::ControlledCandidate,
                aos_hub_core::mirror_guard::MIRROR_CANDIDATE_GUARD_LOOKUP_PATH,
            )
        } else {
            (MirrorGuardExecution::Hosted, MIRROR_GUARD_LOOKUP_PATH)
        };
        #[cfg(not(test))]
        let (execution, path) = (MirrorGuardExecution::Hosted, MIRROR_GUARD_LOOKUP_PATH);

        // Issue the immutable challenge after capacity admission. Waiting does
        // not renew an earlier deadline or consume the available guard horizon.
        let _capacity = self.in_flight.acquire().await?;
        let issued_at = u64::try_from(aos_hub_core::clock::now_unix_secs())?;
        let challenge = MirrorGuardLookup {
            version: 1,
            deployment_id: self.deployment_id.clone(),
            execution,
            issuer: MirrorGuardIssuer {
                source_digest,
                script_version,
            },
            clock_uncertainty_seconds: uncertainty,
            original: original.clone(),
            expected: progress.clone(),
            request_nonce: format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            ),
            issued_at,
            expires_at: issued_at
                .checked_add(30)
                .context("mirror guard deadline overflow")?,
        };
        let signed = sign_mirror_guard_lookup(key, &challenge)?;
        let request_bytes = signed.body.len();
        let response = self
            .http
            .post(format!("{origin}{path}"))
            .header("content-type", "application/json")
            .header(MIRROR_GUARD_SIGNATURE_HEADER, signed.signature)
            .body(signed.body)
            .send()
            .await
            .context("reading independent mirror final guard")?;
        ensure!(
            response.status().is_success(),
            "mirror final guard refused exact held receipt"
        );
        let signature = response
            .headers()
            .get(MIRROR_GUARD_SIGNATURE_HEADER)
            .context("mirror guard reply signature absent")?
            .to_str()?
            .to_owned();
        let mut bytes = Vec::new();
        let mut chunks = response.bytes_stream();
        while let Some(chunk) = chunks.next().await {
            let chunk = chunk?;
            ensure!(
                bytes
                    .len()
                    .checked_add(chunk.len())
                    .is_some_and(|size| size <= MIRROR_GUARD_MAX_BYTES),
                "mirror guard reply exceeds its explicit control bound"
            );
            bytes.extend_from_slice(&chunk);
        }
        let latest = u64::try_from(aos_hub_core::clock::now_unix_secs())?
            .checked_add(uncertainty)
            .context("mirror guard clock overflow")?;
        let proof = verify_mirror_guard_reply(key, &signature, &bytes, &challenge, latest)?;
        tracing::info!(job_id = %original.job_id, request_bytes, result_bytes = bytes.len(),
            "independent mirror final guard verified");
        Ok(proof)
    }
}
