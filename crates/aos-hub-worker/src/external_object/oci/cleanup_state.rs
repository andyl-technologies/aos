//! Positive-only terminal chunk deletion through the existing permanent turn.
//!
//! The cleanup cell retains the real chunk closure and exact Delete turn. A
//! pending cell is never a dispatch permit; cold positive replay uses the same
//! receipt even after the physical visible pointer was cleared by deletion.

use anyhow::{Result, ensure};
use aos_hub_core::storage_authority::external_object::oci::{
    ExternalOciOriginal, OciObjectOriginal, OciProviderIncarnation,
    cleanup::{OciCleanupOriginal, OciCleanupReply, OciCleanupRequest},
    reply::OciClosedObject,
};
use serde::{Deserialize, Serialize};

use super::super::protocol::{Effect, Intent, Outcome, Pending, Receipt, digest};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub original: OciCleanupOriginal,
    pub source: ExternalOciOriginal,
    pub closed: OciClosedObject,
    pub turn: Pending,
    pub positive: Option<Receipt>,
}

impl Record {
    pub(super) fn validate(&self, work: &OciCleanupRequest) -> Result<()> {
        self.original.validate()?;
        self.source.validate()?;
        self.closed.bytes.validate()?;
        self.turn.intent.validate()?;
        let source = &self.source;
        let original = &self.original;
        ensure!(
            original == &work.original
                && source.scope == work.scope
                && source.deployment_id == work.deployment_id
                && source.upload.upload_id == original.upload_id
                && source.upload.registry_id.get() == original.registry_id
                && source.upload.repository_id.get() == original.repository_id
                && source.upload.writer_id == original.writer_id
                && source.upload.token_id == original.token_id
                && source.writer.placement_id.get() == original.placement_id
                && source.writer.placement_resource_version.get()
                    == original.placement_resource_version
                && source.writer.placement_prefix == original.placement_prefix
                && source.writer.binding_id.get() == original.binding_id
                && source.writer.binding_resource_version.get()
                    == original.binding_resource_version
                && source.writer.binding_write_revision.get() == original.binding_write_revision
                && source.binding_spec_revision == original.binding_spec_revision
                && self.closed.bytes == original.bytes
                && matches!(source.object, OciObjectOriginal::Chunk { ordinal, offset, .. }
                if ordinal == original.ordinal && offset == original.offset)
                && self.turn.intent.scope == work.scope
                && self.turn.intent.operation_id == original.fingerprint()?
                && self.turn.intent.context == original.fingerprint()?
                && super::super::protocol::digest_string(&self.turn.dispatch_nonce),
            "OCI terminal cleanup does not match its retained SQL and physical chunk"
        );
        let expected = self.precondition()?;
        ensure!(
            self.turn.intent.effect == (Effect::Delete { expected }),
            "OCI cleanup turn substituted another provider incarnation"
        );
        if let Some(receipt) = &self.positive {
            receipt.validate()?;
            ensure!(
                receipt.turn == self.turn
                    && matches!(receipt.outcome, Outcome::DeleteAcknowledged { .. }),
                "OCI cleanup absence or another effect cannot settle a chunk"
            );
        }
        Ok(())
    }

    pub(super) fn precondition(
        &self,
    ) -> Result<
        aos_hub_core::storage_authority::external_object::deletion::ExternalDeletePrecondition,
    > {
        let provider_version = match &self.closed.incarnation {
            OciProviderIncarnation::Versioned {
                provider_version, ..
            } => provider_version.clone(),
            OciProviderIncarnation::Guarded { .. } => {
                anyhow::bail!("OCI chunk cleanup requires actual provider version")
            }
        };
        let expected = aos_hub_core::storage_authority::external_object::deletion::ExternalDeletePrecondition {
            provider_version, etag: self.closed.etag.clone(), bytes: self.closed.bytes.size.to_string(),
            content_hash: Some(self.closed.bytes.sha256.clone()),
        };
        expected.validate()?;
        Ok(expected)
    }

    pub(super) fn declare(
        work: &OciCleanupRequest,
        source: ExternalOciOriginal,
        closed: OciClosedObject,
        cohort_digest: String,
        nonce: String,
    ) -> Result<Self> {
        let mut value = Self {
            original: work.original.clone(),
            source,
            closed,
            turn: Pending {
                intent: Intent {
                    scope: work.scope.clone(),
                    operation_id: work.original.fingerprint()?,
                    context: work.original.fingerprint()?,
                    cohort_digest,
                    effect: Effect::Head,
                },
                dispatch_nonce: nonce,
            },
            positive: None,
        };
        value.turn.intent.effect = Effect::Delete {
            expected: value.precondition()?,
        };
        value.validate(work)?;
        Ok(value)
    }

    pub(super) fn acknowledge(&self, work: &OciCleanupRequest, receipt: Receipt) -> Result<Self> {
        self.validate(work)?;
        ensure!(
            self.positive
                .as_ref()
                .is_none_or(|retained| retained == &receipt),
            "OCI cleanup positive receipt changed"
        );
        let mut next = self.clone();
        next.positive = Some(receipt);
        next.validate(work)?;
        Ok(next)
    }

    pub(super) fn reply(&self, work: &OciCleanupRequest) -> Result<OciCleanupReply> {
        self.validate(work)?;
        let receipt = self
            .positive
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("OCI chunk delete remains unknown"))?;
        let reply = OciCleanupReply {
            request_digest: digest(work)?,
            original_digest: self.original.fingerprint()?,
            nonce: work.nonce.clone(),
            closed: self.closed.clone(),
            delete_receipt_digest: digest(receipt)?,
        };
        reply.validate_for(work)?;
        Ok(reply)
    }
}

#[cfg(test)]
mod tests;
