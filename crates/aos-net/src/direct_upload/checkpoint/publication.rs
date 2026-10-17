//! Exact before-effect publication manifest identity and private lease custody.
//!
//! Metadata admission records bind the original Hub/registry/inventory selector
//! before a publication exists, including the genuinely authenticated original
//! actor/deployment and registry incarnation. They confer no provider authority.
//! The later direct object journal reconciles complete target capabilities.

use super::{SqliteDirectCheckpoints, sqlite};
use crate::direct_upload::DirectClientError;
use aos_proto_types::{RegistryPublicationManifestSession, direct_upload::*};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Exact original bounded manifest request retained before logical admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectPublicationHeader {
    /// Explicit canonical registry selector, never inferred from an object URL.
    pub registry: String,
    /// Authenticated original immutable registry incarnation.
    pub registry_stable_id: String,
    /// Original authenticated deployment namespace.
    pub deployment_id: String,
    /// Original authenticated immutable actor commitment.
    pub principal_id: String,
    /// Existing canonical sorted inventory generation commitment.
    pub generation: String,
    /// SHA-256 of exact frozen info/refs bytes.
    pub refs_digest: String,
    /// Exact SHA-256 commit resolved from frozen HEAD/info/refs.
    pub default_commit: String,
    /// Original committed publication parent; empty only for initial publication.
    pub parent_publication_id: String,
    /// Exact canonical tuple inventory digest used by Native admission.
    pub manifest_digest: String,
    /// Exact complete inventory count, including mutable metadata.
    pub object_count: u32,
}

impl DirectPublicationHeader {
    fn validate(&self) -> Result<(), DirectClientError> {
        if !valid_direct_identity(&self.registry)
            || !valid_direct_identity(&self.registry_stable_id)
            || !valid_direct_identity(&self.deployment_id)
            || !valid_direct_digest(&self.principal_id)
            || !valid_direct_digest(&self.generation)
            || !valid_direct_digest(&self.refs_digest)
            || !valid_direct_digest(&self.default_commit)
            || !valid_direct_digest(&self.manifest_digest)
            || (!self.parent_publication_id.is_empty()
                && !valid_direct_identity(&self.parent_publication_id))
            || self.object_count == 0
            || self.object_count > 50_000
        {
            return Err(DirectClientError::Checkpoint);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Admission {
    publication_id: String,
    lease_token: String,
    manifest_digest: String,
    object_count: u32,
    admitted_object_count: u32,
    next_chunk_index: u32,
    state: String,
    lease_expires_at: i64,
}

/// Private retained logical owner/progress with value-free Debug output.
///
/// This wrapper has no general serialization implementation. Explicit reply
/// reconstruction is confined to the metadata adapter's authenticated RPCs;
/// its lease must never be logged or forwarded to a provider.
#[derive(Clone)]
pub struct DirectPublicationAdmission(Admission);

impl fmt::Debug for DirectPublicationAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DirectPublicationAdmission([private lease])")
    }
}

impl DirectPublicationAdmission {
    /// Reconstructs the exact private metadata session for same-owner RPC replay.
    pub fn reply(&self) -> RegistryPublicationManifestSession {
        let value = &self.0;
        RegistryPublicationManifestSession {
            publication_id: value.publication_id.clone(),
            lease_token: value.lease_token.clone(),
            manifest_digest: value.manifest_digest.clone(),
            object_count: value.object_count,
            admitted_object_count: value.admitted_object_count,
            next_chunk_index: value.next_chunk_index,
            state: value.state.clone(),
            lease_expires_at: value.lease_expires_at,
        }
    }
}

impl SqliteDirectCheckpoints {
    /// Loads the original header before resolving a new current parent.
    ///
    /// # Errors
    /// Refuses corrupted/unknown metadata or private file/SQLite custody failure.
    pub async fn publication_header(
        &self,
    ) -> Result<Option<DirectPublicationHeader>, DirectClientError> {
        let permit = self.reserve().await?;
        self.wave(permit, |transaction| {
            let header: Option<DirectPublicationHeader> =
                sqlite::read(transaction, "publication_header", "publication", 0, 0)?;
            if let Some(value) = &header {
                value.validate()?;
            }
            Ok(header)
        })
        .await
    }

    /// Durably commits the complete original header before Begin dispatch.
    ///
    /// # Errors
    /// Rejects invalid or changed inventory, parent/registry identity or custody.
    pub async fn retain_publication_header(
        &self,
        header: &DirectPublicationHeader,
    ) -> Result<(), DirectClientError> {
        let permit = self.reserve().await?;
        header.validate()?;
        let header = header.clone();
        self.wave(permit, move |transaction| {
            sqlite::immutable(
                transaction,
                "publication_header",
                "publication",
                0,
                0,
                &header,
            )
        })
        .await
    }

    /// Retains an exact owner and monotonic Native-admitted manifest continuation.
    ///
    /// An expired lease may rotate only under the same original publication,
    /// manifest/count and monotonic accepted progress. This changes metadata
    /// lease custody, never a provider grant or an unknown provider effect.
    ///
    /// # Errors
    /// Rejects missing original intent, changed owner/manifest/count, regressing
    /// progress, unsupported state or private persistence failure.
    pub async fn retain_publication_admission(
        &self,
        reply: &RegistryPublicationManifestSession,
    ) -> Result<DirectPublicationAdmission, DirectClientError> {
        let permit = self.reserve().await?;
        let value = Admission {
            publication_id: reply.publication_id.clone(),
            lease_token: reply.lease_token.clone(),
            manifest_digest: reply.manifest_digest.clone(),
            object_count: reply.object_count,
            admitted_object_count: reply.admitted_object_count,
            next_chunk_index: reply.next_chunk_index,
            state: reply.state.clone(),
            lease_expires_at: reply.lease_expires_at,
        };
        self.wave(permit, move |transaction| {
            let original: DirectPublicationHeader =
                sqlite::read(transaction, "publication_header", "publication", 0, 0)?
                    .ok_or(DirectClientError::Checkpoint)?;
            original.validate()?;
            if !valid_direct_identity(&value.publication_id)
                || !valid_direct_identity(&value.lease_token)
                || value.manifest_digest != original.manifest_digest
                || value.object_count != original.object_count
                || value.admitted_object_count > value.object_count
                || value.next_chunk_index > value.object_count
                || !matches!(value.state.as_str(), "accepting" | "sealed")
                || value.lease_expires_at < 0
                || (value.state == "sealed" && value.admitted_object_count != value.object_count)
            {
                return Err(DirectClientError::Checkpoint);
            }
            let previous: Option<Admission> =
                sqlite::read(transaction, "publication_admission", "publication", 0, 0)?;
            if let Some(previous) = previous {
                if value.publication_id != previous.publication_id
                    || value.admitted_object_count < previous.admitted_object_count
                    || value.next_chunk_index < previous.next_chunk_index
                    || (previous.state == "sealed" && value != previous)
                {
                    return Err(DirectClientError::Checkpoint);
                }
            }
            sqlite::write(
                transaction,
                "publication_admission",
                "publication",
                0,
                0,
                &value,
            )?;
            Ok(DirectPublicationAdmission(value))
        })
        .await
    }
}
