//! Before-effect OCI logical allocation identity, excluding provider state.
//!
//! A logical OCI upload ID is a Native business owner, not an S3 UploadId. Its
//! original bodyless URI operation and full source fingerprint survive restart.

use aos_proto_types::direct_upload::{
    MAX_DIRECT_OBJECT_BYTES, valid_direct_digest, valid_direct_identity,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{SqliteDirectCheckpoints, sqlite};
use crate::direct_upload::DirectClientError;

/// Original exact source commitment and stable logical allocation operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectOciAllocation {
    /// Stable client operation retained before any bodyless allocation effect.
    pub operation_id: String,
    /// Exact full lowercase blob SHA-256.
    pub sha256: String,
    /// Exact bounded original source length.
    pub byte_size: u64,
    /// Original logical OCI upload identity, absent before allocation reply.
    pub upload_id: Option<String>,
}

impl SqliteDirectCheckpoints {
    /// Retains an original source and deterministic operation before allocation.
    ///
    /// # Errors
    /// Refuses invalid source geometry, changed prior source or custody failure.
    pub async fn prepare_oci_allocation(
        &self,
        sha256: &str,
        byte_size: u64,
    ) -> Result<DirectOciAllocation, DirectClientError> {
        if !valid_direct_digest(sha256) || byte_size > MAX_DIRECT_OBJECT_BYTES {
            return Err(DirectClientError::Invalid);
        }
        let permit = self.reserve().await?;
        let sha256 = sha256.to_owned();
        let mut digest = Sha256::new();
        digest.update(b"aos.direct.oci.logical-allocation.v1\0");
        digest.update(self.run_id().as_bytes());
        digest.update(sha256.as_bytes());
        let operation_id = hex::encode(digest.finalize());
        self.wave(permit, move |transaction| {
            let prior: Option<DirectOciAllocation> =
                sqlite::read(transaction, "oci_allocation", &sha256, 0, 0)?;
            if let Some(prior) = prior {
                if prior.operation_id != operation_id
                    || prior.sha256 != sha256
                    || prior.byte_size != byte_size
                    || prior
                        .upload_id
                        .as_ref()
                        .is_some_and(|value| !valid_direct_identity(value))
                {
                    return Err(DirectClientError::Checkpoint);
                }
                return Ok(prior);
            }
            let value = DirectOciAllocation {
                operation_id,
                sha256,
                byte_size,
                upload_id: None,
            };
            sqlite::write(transaction, "oci_allocation", &value.sha256, 0, 0, &value)?;
            Ok(value)
        })
        .await
    }

    /// Retains the original logical reply without adopting a second owner.
    ///
    /// # Errors
    /// Refuses missing original intent, altered source/operation or owner change.
    pub async fn retain_oci_allocation(
        &self,
        original: &DirectOciAllocation,
        upload_id: &str,
    ) -> Result<DirectOciAllocation, DirectClientError> {
        if !valid_direct_identity(upload_id) {
            return Err(DirectClientError::Invalid);
        }
        let permit = self.reserve().await?;
        let original = original.clone();
        let upload_id = upload_id.to_owned();
        self.wave(permit, move |transaction| {
            let mut prior: DirectOciAllocation =
                sqlite::read(transaction, "oci_allocation", &original.sha256, 0, 0)?
                    .ok_or(DirectClientError::Checkpoint)?;
            if prior.operation_id != original.operation_id
                || prior.sha256 != original.sha256
                || prior.byte_size != original.byte_size
                || prior.upload_id.as_ref().is_some_and(|id| id != &upload_id)
            {
                return Err(DirectClientError::Checkpoint);
            }
            prior.upload_id = Some(upload_id);
            sqlite::write(transaction, "oci_allocation", &prior.sha256, 0, 0, &prior)?;
            Ok(prior)
        })
        .await
    }
}
