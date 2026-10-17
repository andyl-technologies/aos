//! Canonical durable progress for one bounded OCI inventory page.
//!
//! The stored source receipt and portable hash state are observations. Every
//! resumed provider read still needs its existing current permission checks.
//! The production page limit is one; no uncommitted page prefix is discarded.
//!
//! ```text
//! progress = {version: 1, generation_id, next_provider_cursor?, object: {
//!   placement_id, checkpoint_ordinal, provider_cursor?, object_key,
//!   object_digest, expected_size, strong_etag, provider_version?,
//!   guarded_source?, next_offset, sha_version, sha_words,
//!   sha_total_bytes, sha_tail_hex}}
//! ```

use anyhow::{Context, Result, ensure};
use aos_oci_types::Sha256Digest;
use serde::{Deserialize, Serialize};

use super::inventory::OciProviderInventoryGenerationRecord;
use crate::db::OciSha256State;
use crate::storage_work::protected_inspection::ProtectedInspectionSource;

/// Maximum encoded durable progress, independent of the queue cursor bound.
pub const MAX_OCI_INVENTORY_PROGRESS_BYTES: usize = 16 * 1024;

/// Exact partial object and sole-page selection retained across controller restarts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciInventoryProgress {
    /// Explicit durable progress encoding version.
    pub version: u32,
    /// Generation whose collector and checkpoint fence this observation.
    pub generation_id: String,
    /// Original next-page cursor returned with this sole object.
    pub next_provider_cursor: Option<String>,
    /// Frozen source identity and portable hash state for the current object.
    pub object: OciInventoryObjectProgress,
}

impl OciInventoryProgress {
    /// Validates intrinsic progress without granting provider or collector authority.
    ///
    /// # Errors
    /// Rejects malformed generation, cursor, source, hash geometry or encoded size.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1
                && self
                    .generation_id
                    .strip_prefix("ociinv-")
                    .is_some_and(|id| { id.len() == 32 && lower_hex(id) })
                && valid_cursor(self.next_provider_cursor.as_deref()),
            "OCI inventory progress selector is invalid"
        );
        self.object.validate()?;
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_OCI_INVENTORY_PROGRESS_BYTES,
            "OCI inventory progress exceeds its encoded bound"
        );
        Ok(())
    }

    /// Checks the exact current SQL generation and original requested page cursor.
    ///
    /// # Errors
    /// Rejects another generation, placement, checkpoint or provider cursor.
    pub fn validate_for(&self, generation: &OciProviderInventoryGenerationRecord) -> Result<()> {
        self.validate()?;
        ensure!(
            self.generation_id == generation.id,
            "OCI inventory progress generation differs"
        );
        self.object
            .validate_for(generation, generation.provider_cursor.as_deref())
    }

    /// Encodes the bounded canonical postimage used by SQL compare-and-swap.
    ///
    /// # Errors
    /// Rejects malformed or excessive progress.
    pub fn encode(&self) -> Result<String> {
        self.validate()?;
        Ok(serde_json::to_string(self)?)
    }

    /// Decodes a bounded exact canonical postimage without trusting imported authority.
    ///
    /// # Errors
    /// Rejects oversized, unknown-field, noncanonical or intrinsically invalid cells.
    pub fn decode(encoded: &str) -> Result<Self> {
        ensure!(
            !encoded.is_empty() && encoded.len() <= MAX_OCI_INVENTORY_PROGRESS_BYTES,
            "OCI inventory progress encoded length is invalid"
        );
        let value: Self =
            serde_json::from_str(encoded).context("OCI inventory progress shape is invalid")?;
        ensure!(
            value.encode()? == encoded,
            "OCI inventory progress is not canonical"
        );
        Ok(value)
    }

    pub(super) fn validate_successor(&self, next: &Self) -> Result<()> {
        self.validate()?;
        next.validate()?;
        let mut previous = self.clone();
        previous.object.next_offset = next.object.next_offset;
        previous.object.sha_version = next.object.sha_version;
        previous.object.sha_words = next.object.sha_words;
        previous.object.sha_total_bytes = next.object.sha_total_bytes;
        previous
            .object
            .sha_tail_hex
            .clone_from(&next.object.sha_tail_hex);
        ensure!(
            previous == *next
                && next.object.next_offset > self.object.next_offset
                && next.object.next_offset - self.object.next_offset
                    <= crate::storage_work::MAX_OCI_HASH_RANGE_BYTES as u64,
            "OCI inventory progress changed its source or bounded interval"
        );
        Ok(())
    }
}

/// Frozen object identity plus SHA state after exactly the saved byte offset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciInventoryObjectProgress {
    /// Exact placement selected by the durable generation.
    pub placement_id: i64,
    /// Page ordinal before this object is committed.
    pub checkpoint_ordinal: u64,
    /// Original provider cursor used to list the sole object.
    pub provider_cursor: Option<String>,
    /// Canonical relative OCI blob key.
    pub object_key: String,
    /// Digest encoded by the selected canonical key.
    pub object_digest: String,
    /// Full observed length, bounded independently of one range.
    pub expected_size: u64,
    /// Frozen strong conditional-read tag.
    pub strong_etag: String,
    /// Real provider incarnation, omitted for protected versionless sources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_version: Option<String>,
    /// Actual immutable protected source receipt; not provider permission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guarded_source: Option<ProtectedInspectionSource>,
    /// Exact bytes incorporated into the saved portable state.
    pub next_offset: u64,
    /// Portable SHA format version.
    pub sha_version: u32,
    /// Portable SHA compression words.
    pub sha_words: [u32; 8],
    /// Portable SHA byte count, equal to the next offset.
    pub sha_total_bytes: u64,
    /// Canonical hexadecimal uncompressed tail.
    pub sha_tail_hex: String,
}

impl OciInventoryObjectProgress {
    pub(crate) fn initial(
        placement_id: i64,
        checkpoint_ordinal: u64,
        provider_cursor: Option<String>,
        object_key: &str,
        object_digest: Sha256Digest,
        expected_size: u64,
        strong_etag: String,
        provider_version: Option<String>,
    ) -> Result<Self> {
        let state = OciSha256State::initial();
        let value = Self {
            placement_id,
            checkpoint_ordinal,
            provider_cursor,
            object_key: object_key.to_owned(),
            object_digest: object_digest.to_string(),
            expected_size,
            strong_etag,
            provider_version,
            guarded_source: None,
            next_offset: 0,
            sha_version: state.version,
            sha_words: state.words,
            sha_total_bytes: state.total_bytes,
            sha_tail_hex: state.tail_hex,
        };
        value.validate()?;
        Ok(value)
    }

    /// Checks intrinsic frozen identity and portable SHA geometry.
    ///
    /// # Errors
    /// Rejects noncanonical keys, malformed evidence, mixed identities or corrupt state.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.placement_id > 0
                && self.expected_size <= 1024 * 1024 * 1024
                && self.next_offset <= self.expected_size
                && self.sha_total_bytes == self.next_offset
                && self.strong_etag.len() <= 512
                && valid_cursor(self.provider_cursor.as_deref())
                && self
                    .provider_version
                    .as_deref()
                    .is_none_or(crate::storage_work::valid_provider_version),
            "OCI inventory object progress identity is invalid"
        );
        let digest = Sha256Digest::parse(&self.object_digest)?;
        ensure!(
            self.object_key == format!("oci/blobs/sha256/{}", digest.encoded()),
            "OCI inventory progress key and digest differ"
        );
        crate::surface_write::strong_if_match_etag(&self.strong_etag)?;
        if let Some(source) = &self.guarded_source {
            source.validate()?;
            ensure!(
                self.provider_version.is_none()
                    && (source.scope.full_key == self.object_key
                        || source
                            .scope
                            .full_key
                            .ends_with(&format!("/{}", self.object_key)))
                    && source.closure.sha256 == digest.encoded()
                    && source.closure.bytes.get() as u64 == self.expected_size
                    && source
                        .closure
                        .etag
                        .as_ref()
                        .is_none_or(|tag| tag == &self.strong_etag),
                "OCI inventory progress protected receipt differs"
            );
        }
        let state = self.sha_state()?;
        if self.next_offset == 0 {
            ensure!(
                state == OciSha256State::initial(),
                "OCI inventory initial hash differs"
            );
        }
        Ok(())
    }

    pub(crate) fn validate_for(
        &self,
        generation: &OciProviderInventoryGenerationRecord,
        provider_cursor: Option<&str>,
    ) -> Result<()> {
        self.validate()?;
        ensure!(
            self.placement_id == generation.placement_id
                && self.checkpoint_ordinal == generation.checkpoint_ordinal
                && self.provider_cursor.as_deref() == provider_cursor,
            "OCI inventory object does not bind the durable checkpoint"
        );
        Ok(())
    }

    pub(crate) fn sha_state(&self) -> Result<OciSha256State> {
        let state = OciSha256State {
            version: self.sha_version,
            words: self.sha_words,
            total_bytes: self.sha_total_bytes,
            tail_hex: self.sha_tail_hex.clone(),
        };
        state.validate()?;
        Ok(state)
    }

    pub(crate) fn set_sha_state(&mut self, state: &OciSha256State) -> Result<()> {
        state.validate()?;
        ensure!(
            state.total_bytes == self.next_offset,
            "OCI inventory hash offset differs"
        );
        self.sha_version = state.version;
        self.sha_words = state.words;
        self.sha_total_bytes = state.total_bytes;
        self.sha_tail_hex.clone_from(&state.tail_hex);
        Ok(())
    }
}

fn valid_cursor(value: Option<&str>) -> bool {
    value.is_none_or(|value| {
        value.len() <= 512
            && value.strip_prefix("oci-blobs-v1:").is_some_and(|raw| !raw.is_empty())
    })
}

fn lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl crate::db::Database {
    /// Persists one exact bounded source selection or successful hash-range postimage.
    ///
    /// The supplied generation must be the freshly returned collector heartbeat.
    /// A replay can observe its exact stored postimage; this grants no new read
    /// permission and does not renew a provider cutoff.
    ///
    /// # Errors
    /// Refuses a stale collector, changed topology/checkpoint/source, invalid
    /// progress transition, expired lease or failed transactional compare-and-swap.
    pub async fn persist_oci_inventory_progress(
        &self,
        generation: &OciProviderInventoryGenerationRecord,
        next: &OciInventoryProgress,
        now: i64,
    ) -> Result<OciProviderInventoryGenerationRecord> {
        use crate::backend::Statement;
        use crate::value::Value;

        next.validate_for(generation)?;
        ensure!(
            now >= 0
                && generation.state == "collecting"
                && generation
                    .collector_lease_expires_at
                    .is_some_and(|expiry| expiry > now),
            "OCI inventory progress collector is not current"
        );
        if let Some(previous) = &generation.object_progress {
            previous.validate_successor(next)?;
        } else {
            ensure!(
                next.object.next_offset == 0,
                "OCI inventory source selection skipped bytes"
            );
        }
        let encoded = next.encode()?.into_bytes();
        let prior = generation
            .object_progress
            .as_ref()
            .map(|value| value.encode().map(String::into_bytes))
            .transpose()?;
        let prior_value = prior.map(Value::Bytes).unwrap_or(Value::Null);
        let changed = self.backend.checked_batch(&[Statement::new(
            "UPDATE oci_provider_inventory_generations
             SET object_progress = ?1, resource_version = resource_version + 1
             WHERE id = ?2 AND collector_id = ?3 AND collector_claim_token = ?4
               AND collector_lease_expires_at > ?5 AND state = 'collecting'
               AND resource_version = ?6 AND checkpoint_ordinal = ?7
               AND (provider_cursor = ?8
                 OR (provider_cursor IS NULL AND CAST(?8 AS VARCHAR) IS NULL))
               AND (object_progress = ?9 OR (object_progress IS NULL AND ?9 IS NULL))
               AND EXISTS (SELECT 1 FROM oci_registry_state registry_state
                 WHERE registry_state.registry_id = oci_provider_inventory_generations.registry_id
                   AND registry_state.mutation_epoch = oci_provider_inventory_generations.captured_mutation_epoch)
               AND EXISTS (SELECT 1 FROM surface_placements placement
                 JOIN surface_placement_observations observation ON observation.placement_id = placement.id
                 JOIN bindings binding ON binding.id = placement.binding_id
                 JOIN binding_write_state write_state ON write_state.binding_id = binding.id
                 WHERE placement.id = oci_provider_inventory_generations.placement_id
                   AND placement.resource_version = oci_provider_inventory_generations.placement_resource_version
                   AND placement.write_spec_version = oci_provider_inventory_generations.placement_write_spec_version
                   AND observation.observation_version = oci_provider_inventory_generations.placement_observation_version
                   AND observation.state = 'ready' AND observation.completeness = 'complete'
                   AND binding.resource_version = oci_provider_inventory_generations.binding_resource_version
                   AND write_state.current_write_revision = oci_provider_inventory_generations.binding_write_revision)",
            vals![encoded, generation.id, generation.collector_id,
                generation.collector_claim_token, now, generation.resource_version,
                i64::try_from(generation.checkpoint_ordinal)?, generation.provider_cursor, prior_value],
        ).expecting(1)]).await;

        let current = self
            .oci_provider_inventory_generation(&generation.id)
            .await?
            .context("OCI inventory disappeared after progress persistence")?;
        if let Err(error) = changed {
            // Returning a lost-ACK postimage is an observation, not a new lease.
            let exact_replay = current.object_progress.as_ref() == Some(next)
                && current.resource_version
                    == generation
                        .resource_version
                        .checked_add(1)
                        .context("OCI inventory record version overflowed")?
                && current.collector_id == generation.collector_id
                && current.collector_claim_token == generation.collector_claim_token
                && current.collector_lease_expires_at == generation.collector_lease_expires_at
                && current.state == "collecting"
                && current.checkpoint_ordinal == generation.checkpoint_ordinal
                && current.provider_cursor == generation.provider_cursor;
            if !exact_replay {
                return Err(error);
            }
        }
        ensure!(
            current.object_progress.as_ref() == Some(next),
            "OCI inventory progress postimage differs"
        );
        Ok(current)
    }
}

#[cfg(test)]
mod tests;
