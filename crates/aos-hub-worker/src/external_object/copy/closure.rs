//! Exact current source receipt projection beneath the physical-key gate.
//!
//! No provider observation can create a closure. The caller holds the source
//! gate while checking its compact head and producer-specific immutable record.

use anyhow::{ensure, Result};
use aos_hub_core::storage_authority::{
    external_object::copy::source::CopySourceClosure, lease::LeaseInteger, GuardIncarnation,
    StorageGuardStamp,
};
use worker::{Env, Storage};

use super::super::{
    config::Config,
    protocol::{digest, Effect, Outcome},
    state::{Head, VisibleKind},
};

/// Loads actual current closure facts without provider I/O or mutation permission.
///
/// # Errors
/// Refuses unknown/discovered keys, active owners or missing/altered producer proof.
pub(in crate::external_object) async fn current(
    env: &Env,
    storage: &Storage,
    head: &Head,
    object: &Config,
) -> Result<CopySourceClosure> {
    head.validate(object, &head.scope)?;
    ensure!(
        head.pending.is_none()
            && head.observation.is_none()
            && head.stage.is_none()
            && head.copy.is_none()
            && head.oci.is_none()
            && head.mirror.is_none(),
        "protected copy source remains active or unknown"
    );
    let visible = head
        .visible_receipt
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("protected copy source has no positive receipt"))?;
    visible.validate(head)?;
    let closure = match visible.kind {
        VisibleKind::MetadataPut => {
            let receipt = super::super::storage::load_receipt(storage, &visible.operation_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("protected metadata receipt absent"))?;
            receipt.validate()?;
            ensure!(
                receipt.turn.intent.scope == head.scope
                    && receipt.turn.intent.operation_id == visible.operation_id
                    && receipt.turn.intent.context == visible.context_digest
                    && digest(&receipt)? == visible.receipt_digest
                    && matches!(receipt.outcome, Outcome::PutAcknowledged),
                "protected metadata receipt changed"
            );
            let Effect::Put { sha256, bytes } = &receipt.turn.intent.effect else {
                anyhow::bail!("protected metadata receipt is not a positive PUT");
            };
            CopySourceClosure {
                guard_stamp: StorageGuardStamp {
                    physical_authority_id: head.scope.physical_authority_id.clone(),
                    incarnation: GuardIncarnation::parse(head.incarnation.get().to_string())?,
                },
                receipt_digest: visible.receipt_digest.clone(),
                sha256: sha256.clone(),
                bytes: LeaseInteger::new(i64::from(*bytes))?,
                etag: None,
            }
        }
        VisibleKind::DestinationClose => {
            super::super::stage::closed_copy_source(env, storage, head, object).await?
        }
        VisibleKind::OciStage | VisibleKind::OciDestination => {
            super::super::oci::closed_copy_source(storage, object, &head.scope).await?
        }
        VisibleKind::MirrorStage | VisibleKind::MirrorDestination => {
            super::super::mirror::closed_source(storage, object, head).await?
        }
        VisibleKind::CopyDestination => {
            super::storage::closed_copy_source(storage, head, object).await?
        }
    };
    closure.validate()?;
    ensure!(
        closure.guard_stamp.physical_authority_id == head.scope.physical_authority_id
            && closure.guard_stamp.incarnation.as_str() == head.incarnation.get().to_string()
            && closure.receipt_digest == visible.receipt_digest,
        "protected source receipt differs from current physical incarnation"
    );
    Ok(closure)
}
