//! Purpose-closed canonical floor comparisons, never physical floor authority.
//!
//! Broker adapters retain their original wire/error contracts. Host055 uses
//! distinct typed DATA and fixed record/hash domains. Neither a decoded claim
//! nor a recovery classification authenticates NV, durable preparation,
//! original journals or a live process. Genuine purpose owners must supply and
//! retain all those observations separately before any effect.

mod digest;
mod format;
mod store;

pub(super) use store::{
    HostSidecarStoreV1, HostSuffixPreflightV1, host_finalize_transaction,
    host_initial_transaction, host_prepare_transaction,
};

pub(crate) use store::{
    BrokerSidecarStoreV1, CHECKPOINT_KEY, FinalSuffixPreflightV1, INTENT_KEY,
    StoredBrokerFloorV1, TRANSACTION_KEY, sidecar_limits,
};

pub(crate) use digest::{
    broker_cut_from_records_v1, broker_transaction_digest_v1, hash_parts,
    sidecar_sequence_v1, successor_sequence,
};
pub(crate) use format::{
    CHECKPOINT_BYTES, FloorCheckpointV1, FloorCutV1, FloorEndpointV1, FloorIntentV1,
    FloorProfileV1, HostFloorCheckpointDataV1, HostFloorIntentDataV1, INTENT_BYTES,
    NV_ATTRIBUTES_DEFINED, NV_ATTRIBUTES_WRITTEN, PROFILE_BYTES,
};

use format::{CheckpointBodyV1, IntentBodyV1};

/// Selects only canonical DATA domains, never a privileged purpose owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecordPurposeDataV1 {
    BrokerV1,
    RuntimeDeploymentV1,
}

impl RecordPurposeDataV1 {
    const fn checkpoint_magic(self) -> &'static [u8; 8] {
        match self {
            Self::BrokerV1 => b"AOSBTF01",
            Self::RuntimeDeploymentV1 => b"AOSRDF01",
        }
    }

    const fn intent_magic(self) -> &'static [u8; 8] {
        match self {
            Self::BrokerV1 => b"AOSBTI01",
            Self::RuntimeDeploymentV1 => b"AOSRDI01",
        }
    }

    const fn extend_domain(self) -> &'static [u8] {
        match self {
            Self::BrokerV1 => b"aos.sandbox.broker-session.tpm-floor.extend.v1\0",
            Self::RuntimeDeploymentV1 => b"aos.runtime-deployment.tpm-floor.extend.v1\0",
        }
    }

    const fn transaction_domain(self) -> &'static [u8] {
        match self {
            Self::BrokerV1 => b"aos.sandbox.broker-session.tpm-floor.transaction.v1\0",
            Self::RuntimeDeploymentV1 => b"aos.runtime-deployment.tpm-floor.transaction.v1\0",
        }
    }

    const fn namespace(self) -> aos_sandbox::RecordNamespace {
        match self {
            Self::BrokerV1 => aos_sandbox::RecordNamespace::BrokerSessionTraffic,
            Self::RuntimeDeploymentV1 => aos_sandbox::RecordNamespace::HostCatalogReconciliation,
        }
    }
}

/// Classifies comparison DATA without granting journal, retry or effect authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FloorRecoveryV1 {
    /// The compared checkpoint, cut and value agree without prepared claims.
    Current,
    /// Only the claimed exact preparation could be extended by a genuine owner.
    ExtendPrepared,
    /// The compared target value would require the persisted exact transaction.
    CommitPrepared,
    /// The compared target cut and value would require checkpoint finalization.
    FinalizePrepared,
}

/// Reports the original redacted Broker floor failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum FloorErrorV1 {
    /// The fixed framing, fields or arithmetic are noncanonical.
    #[error("TPM floor encoding is noncanonical")]
    Encoding,
    /// The compared immutable provisioning scopes differ.
    #[error("TPM floor provisioning does not match")]
    Provisioning,
    /// The original protected owner cannot obtain its required observations.
    #[error("TPM floor is unavailable or unprovisioned")]
    Unavailable,
    /// The compared cut/value does not admit the prescribed recovery ordering.
    #[error("TPM floor rollback, fork, or incomplete recovery detected")]
    Diverged,
    /// The claimed predecessor, transaction or target is not the exact successor.
    #[error("TPM floor transition is not the exact successor")]
    Successor,
}

/// Applies the original Broker reduction without authenticating its inputs.
///
/// # Errors
///
/// Preserves scope/predecessor rejection and every divergent cut/value outcome.
pub(crate) fn reconcile_floor_v1(
    profile: FloorProfileV1,
    checkpoint: FloorCheckpointV1,
    prepared: Option<FloorIntentV1>,
    journal: FloorCutV1,
    nv: [u8; 32],
) -> Result<FloorRecoveryV1, FloorErrorV1> {
    reconcile_records_v1(
        RecordPurposeDataV1::BrokerV1,
        profile.scope(),
        checkpoint.body,
        prepared.map(|intent| intent.body),
        journal,
        nv,
    )
}

/// Classifies only typed Host055 claims, never live currentness or recovery rights.
///
/// # Errors
///
/// Rejects a different scope, predecessor equation or compared cut/value.
pub(crate) fn reconcile_host_floor_data_v1(
    scope: [u8; 32],
    checkpoint: HostFloorCheckpointDataV1,
    prepared: Option<HostFloorIntentDataV1>,
    journal: FloorCutV1,
    nv: [u8; 32],
) -> Result<FloorRecoveryV1, FloorErrorV1> {
    reconcile_records_v1(
        RecordPurposeDataV1::RuntimeDeploymentV1,
        scope,
        checkpoint.body,
        prepared.map(|intent| intent.body),
        journal,
        nv,
    )
}

fn reconcile_records_v1(
    purpose: RecordPurposeDataV1,
    scope: [u8; 32],
    checkpoint: CheckpointBodyV1,
    prepared: Option<IntentBodyV1>,
    journal: FloorCutV1,
    nv: [u8; 32],
) -> Result<FloorRecoveryV1, FloorErrorV1> {
    checkpoint.require_scope(scope)?;
    let Some(prepared) = prepared else {
        return if checkpoint.cut() == journal && checkpoint.nv_value(purpose) == nv {
            Ok(FloorRecoveryV1::Current)
        } else {
            Err(FloorErrorV1::Diverged)
        };
    };
    prepared.require_predecessor(purpose, scope, checkpoint)?;

    let old_nv = checkpoint.nv_value(purpose);
    let target = prepared.target();
    match (nv == old_nv, nv == target.nv_value(purpose), journal) {
        (true, false, cut) if cut == checkpoint.cut() => Ok(FloorRecoveryV1::ExtendPrepared),
        (false, true, cut) if cut == checkpoint.cut() => Ok(FloorRecoveryV1::CommitPrepared),
        (false, true, cut) if cut == target.cut() => Ok(FloorRecoveryV1::FinalizePrepared),
        // Target disk with old NV violates NV-first ordering. A third cut/value
        // includes lost preparation, an interrupted NV write, or a competing writer.
        _ => Err(FloorErrorV1::Diverged),
    }
}

#[cfg(test)]
mod tests;
