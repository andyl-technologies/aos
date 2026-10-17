//! Exact Managed terminal cleanup originals and actual R2 receipt replay.
//!
//! ```text
//! oci-cleanup:<stable-original> = {original, object, mutation}
//! mutation-receipt:<stable-original> = {mutation, acknowledged}
//! ```
//!
//! A retained record without its exact positive mutation receipt is unknown.
//! Neither HEAD absence nor a different key incarnation settles that record.

use anyhow::{Result, ensure};
use aos_hub_core::{oci_cleanup::*, storage_work::StorageObjectIdentity};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::hybrid_object_state::{Mutation, MutationKind, MutationOutcome, MutationReceipt};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    pub(crate) original: ManagedOciCleanupOriginal,
    pub(crate) object: StorageObjectIdentity,
    pub(crate) mutation: Mutation,
}

fn canonical_digest(value: &impl Serialize) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

impl Record {
    pub(crate) fn new(
        original: ManagedOciCleanupOriginal,
        object: StorageObjectIdentity,
    ) -> Result<Self> {
        let mutation = Mutation::new(
            &original.key(),
            &original.fingerprint()?,
            MutationKind::StagingDelete,
            &(&original, &object),
        )?;
        let value = Self {
            original,
            object,
            mutation,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<()> {
        self.original.validate()?;
        ensure!(
            self.object.key == self.original.key()
                && self.object.size == self.original.size
                && self
                    .object
                    .provider_version
                    .as_deref()
                    .is_some_and(aos_hub_core::storage_work::valid_provider_version),
            "Managed OCI cleanup has no exact actual R2 incarnation"
        );
        aos_hub_core::surface_write::strong_if_match_etag(&self.object.etag)?;
        ensure!(
            self.mutation
                == Mutation::new(
                    &self.original.key(),
                    &self.original.fingerprint()?,
                    MutationKind::StagingDelete,
                    &(&self.original, &self.object)
                )?,
            "Managed OCI cleanup pending identity changed"
        );
        Ok(())
    }

    pub(crate) fn reply(
        &self,
        request: &ManagedOciCleanupRequest,
        receipt: Option<&MutationReceipt>,
    ) -> Result<ManagedOciCleanupReply> {
        self.validate()?;
        ensure!(
            self.original == request.original,
            "Managed OCI cleanup substituted its SQL original"
        );
        let receipt = receipt
            .ok_or_else(|| anyhow::anyhow!("Managed OCI cleanup outcome remains unknown"))?;
        ensure!(
            receipt.mutation == self.mutation
                && matches!(receipt.outcome, MutationOutcome::Acknowledged),
            "Managed OCI cleanup has no exact positive Delete receipt"
        );
        let reply = ManagedOciCleanupReply {
            request_digest: canonical_digest(request)?,
            original_digest: self.original.fingerprint()?,
            nonce: request.nonce.clone(),
            object: self.object.clone(),
            receipt_digest: canonical_digest(receipt)?,
        };
        reply.validate(request)?;
        Ok(reply)
    }
}

#[cfg(test)]
mod tests;
