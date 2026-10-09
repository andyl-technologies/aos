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
pub(crate) use durable::BrokerSidecarCustodyV1;
mod format;
mod head;
mod provisioning;
pub(super) mod runtime;

use format::{FloorCheckpointV1, FloorCutV1, FloorIntentV1};
use crate::tpm_nv_custody::{FloorRecoveryV1, hash_parts, reconcile_floor_v1};
pub(crate) use crate::tpm_nv_custody::FloorErrorV1;

pub(crate) use format::FloorProfileV1;
pub(crate) use provisioning::ModePinV1;
pub(crate) use backend::{
    AuthenticatedNvObservationV1, BrokerPhysicalOpenV1, HelperObservationV1, HelperOperationV1,
    LOCK_ACK_BYTES, MeasuredHelperImageV1, NV_ATTRIBUTES_WRITTEN, RESPONSE_BYTES,
    RetainedFloorServicePolicyV1, decode_response_v2, encode_auth_v2, encode_hello_v2,
    encode_request_v2, require_broker_floor_helper_v1, require_broker_floor_owner_v1,
    require_lock_ack_v2,
};

#[cfg(test)]
mod tests;
