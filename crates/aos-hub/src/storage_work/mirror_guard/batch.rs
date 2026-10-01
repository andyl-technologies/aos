//! One real authenticated guard exchange for bounded final publication proofs.
//!
//! The physical guard independently checks each exact held original. This
//! consumer preserves response order and explicit per-item refusals; it does
//! not synthesize individual signatures or cache provider mutation permission.

use aos_hub_core::mirror_guard::batch::{
    sign_mirror_guard_batch_lookup, verify_mirror_guard_batch_reply, MirrorGuardBatchItem,
    MirrorGuardBatchLookup, VerifiedMirrorGuardBatchItem, MIRROR_CANDIDATE_GUARD_BATCH_LOOKUP_PATH,
    MIRROR_GUARD_BATCH_LOOKUP_PATH, MIRROR_GUARD_BATCH_MAX_ITEMS,
};

use super::*;

impl RemoteStorageWorkClient {
    /// Obtains ordered independent proofs or refusals in one bounded exchange.
    ///
    /// # Errors
    /// Returns an error for excessive or repeated items, different issuer pins,
    /// missing guard authority, stale or oversized controls, or invalid replies.
    pub async fn lookup_mirror_final_guards(
        &self,
        items: &[(MirrorOriginal, MirrorProgress)],
    ) -> Result<Vec<VerifiedMirrorGuardBatchItem>> {
        ensure!(
            !items.is_empty() && items.len() <= MIRROR_GUARD_BATCH_MAX_ITEMS,
            "mirror guard publication batch exceeds its item bound"
        );
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
        let controlled = candidate.map(|candidate| {
            (
                candidate.issuer.source_digest.clone(),
                candidate.issuer.script_version.clone(),
                candidate.uncertainty,
            )
        });
        #[cfg(not(test))]
        let controlled: Option<(String, String, u64)> = None;
        let mut selected = None;
        for (original, progress) in items {
            original.validate()?;
            progress.commit_digest(original)?;
            let issuer = match &controlled {
                Some(issuer) => issuer.clone(),
                None => self
                    .mirror_profiles
                    .as_ref()
                    .context("mirror batch has no independently selected issuer pins")?
                    .retained_guard_issuer(
                        &self.deployment_id,
                        &origin,
                        &original.protected_profile_digest,
                    )?,
            };
            if let Some(expected) = &selected {
                ensure!(
                    expected == &issuer,
                    "mirror guard batch crosses issuer or clock pins"
                );
            } else {
                selected = Some(issuer);
            }
        }
        let (source_digest, script_version, uncertainty) =
            selected.context("mirror guard publication batch is empty")?;
        #[cfg(test)]
        let (execution, path) = if candidate.is_some() {
            (
                MirrorGuardExecution::ControlledCandidate,
                MIRROR_CANDIDATE_GUARD_BATCH_LOOKUP_PATH,
            )
        } else {
            (MirrorGuardExecution::Hosted, MIRROR_GUARD_BATCH_LOOKUP_PATH)
        };
        #[cfg(not(test))]
        let (execution, path) = (MirrorGuardExecution::Hosted, MIRROR_GUARD_BATCH_LOOKUP_PATH);

        let _capacity = self.in_flight.acquire().await?;
        let issued_at = u64::try_from(aos_hub_core::clock::now_unix_secs())?;
        let challenge = MirrorGuardBatchLookup {
            version: 1,
            deployment_id: self.deployment_id.clone(),
            execution,
            issuer: MirrorGuardIssuer {
                source_digest,
                script_version,
            },
            clock_uncertainty_seconds: uncertainty,
            items: items
                .iter()
                .map(|(original, progress)| MirrorGuardBatchItem {
                    original: original.clone(),
                    expected: progress.clone(),
                })
                .collect(),
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
        let signed = sign_mirror_guard_batch_lookup(key, &challenge)?;
        let request_bytes = signed.body.len();
        let response = self
            .http
            .post(format!("{origin}{path}"))
            .header("content-type", "application/json")
            .header(MIRROR_GUARD_SIGNATURE_HEADER, signed.signature)
            .body(signed.body)
            .send()
            .await
            .context("reading independent mirror guard batch")?;
        ensure!(
            response.status().is_success(),
            "mirror guard batch refused its exact challenge"
        );
        let signature = response
            .headers()
            .get(MIRROR_GUARD_SIGNATURE_HEADER)
            .context("mirror guard batch reply signature absent")?
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
                "mirror guard batch reply exceeds its control bound"
            );
            bytes.extend_from_slice(&chunk);
        }
        let latest = u64::try_from(aos_hub_core::clock::now_unix_secs())?
            .checked_add(uncertainty)
            .context("mirror guard clock overflow")?;
        let proofs = verify_mirror_guard_batch_reply(key, &signature, &bytes, &challenge, latest)?;
        tracing::info!(
            items = items.len(),
            request_bytes,
            result_bytes = bytes.len(),
            "independent mirror final guard batch verified"
        );
        Ok(proofs)
    }
}
