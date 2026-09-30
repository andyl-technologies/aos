//! Closed TPM NV floor and durable recovery for the two method-46 Storage endpoints.
//!
//! A non-ORDERLY SHA-256 NV extend index authenticates a scoped journal HEAD,
//! not merely an integer. This module owns canonical claims, protected HEAD
//! derivation, checked NV extension, a protected exact-transaction sidecar, and
//! crash reconciliation. Its private composition borrows the real fixed owner
//! and retains a fixed-image ESYS child over a private carrier. It does not
//! provision a TPM, activate an endpoint, advertise method 46, or produce a
//! readiness/effect capability.
//!
//! The durable composition retains both protected writers and durably saves
//! the exact existing `JournalTransaction` before extending NV. Required mode
//! funnels every scoped writer/read/use boundary through that composition;
//! physical and installed qualification remains outstanding, so method 46 is
//! deliberately closed. None of the scalar inputs
//! or pure reducer classifications below proves protected preparation.
//!
//! ```text
//! AOSBTP01 | version:u16be | reserved:u16be | role:u8 | reserved:3 |
//! node:16 | deployment-epoch:16 | stable-endpoint:32 | salt-key-name-digest:32
//! AOSBTF01 | version:u16be | reserved:u16be | ordinal:u64be | scope:32 |
//! journal-sequence:u64be | journal-head:32 | predecessor-NV:32 |
//! exact-transaction-digest:32
//! AOSBTI01 | version:u16be | reserved:u16be | predecessor:156 | target:156
//! ```

mod backend;
mod durable;
mod format;
mod head;
mod provisioning;
pub(super) mod runtime;

use sha2::{Digest as _, Sha256};

use format::{FloorCheckpointV1, FloorCutV1, FloorIntentV1};

pub(crate) use format::FloorProfileV1;
pub(crate) use backend::{
    AuthenticatedNvObservationV1, BrokerPhysicalOpenV1, HelperObservationV1, HelperOperationV1,
    LOCK_ACK_BYTES, MeasuredHelperImageV1, NV_ATTRIBUTES_WRITTEN, RESPONSE_BYTES,
    RetainedFloorServicePolicyV1, decode_response_v2, encode_auth_v2, encode_hello_v2,
    encode_request_v2, require_broker_floor_helper_v1, require_broker_floor_owner_v1,
    require_lock_ack_v2,
};

/// Classifies one exact recovery cut without granting journal or effect authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FloorRecoveryV1 {
    /// The exact checkpoint, journal cut, and TPM agree; no prepared write exists.
    Current,
    /// Only the exact durably retained preparation may be extended.
    ExtendPrepared,
    /// NV already contains the target; commit only the retained exact transaction.
    CommitPrepared,
    /// Journal and NV contain the target; finalize only the matching checkpoint.
    FinalizePrepared,
}

/// Reports redacted failures without exposing index auth or configured identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum FloorErrorV1 {
    #[error("TPM floor encoding is noncanonical")]
    Encoding,
    #[error("TPM floor provisioning does not match")]
    Provisioning,
    #[error("TPM floor is unavailable or unprovisioned")]
    Unavailable,
    #[error("TPM floor rollback, fork, or incomplete recovery detected")]
    Diverged,
    #[error("TPM floor transition is not the exact successor")]
    Successor,
}

/// Reduces only the prescribed prepare → NV → journal → checkpoint ordering.
///
/// A prepared intent is still a claim: the caller must separately authenticate
/// its protected persistence and exact transaction bytes. In particular this
/// reducer cannot authorize re-execution of a previously dispatched request.
fn reconcile_floor_v1(
    profile: FloorProfileV1,
    checkpoint: FloorCheckpointV1,
    prepared: Option<FloorIntentV1>,
    journal: FloorCutV1,
    nv: [u8; 32],
) -> Result<FloorRecoveryV1, FloorErrorV1> {
    checkpoint.require_profile(profile)?;
    let Some(prepared) = prepared else {
        return if checkpoint.cut() == journal && checkpoint.nv_value() == nv {
            Ok(FloorRecoveryV1::Current)
        } else {
            Err(FloorErrorV1::Diverged)
        };
    };
    prepared.require_predecessor(profile, checkpoint)?;

    let old_nv = checkpoint.nv_value();
    let target = prepared.target();
    match (nv == old_nv, nv == target.nv_value(), journal) {
        (true, false, cut) if cut == checkpoint.cut() => Ok(FloorRecoveryV1::ExtendPrepared),
        (false, true, cut) if cut == checkpoint.cut() => Ok(FloorRecoveryV1::CommitPrepared),
        (false, true, cut) if cut == target.cut() => Ok(FloorRecoveryV1::FinalizePrepared),
        // Target disk with old NV violates NV-first ordering. A third cut/value
        // includes lost preparation, an interrupted NV write, or a competing writer.
        _ => Err(FloorErrorV1::Diverged),
    }
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    for part in parts {
        digest.update(part);
    }
    digest.finalize().into()
}

#[cfg(test)]
mod tests;
