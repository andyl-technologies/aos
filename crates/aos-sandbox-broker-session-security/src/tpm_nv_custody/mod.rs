//! Private shared TPM carrier mechanics, not provisioning or role authority.
//!
//! Fixed callers supply a closed endpoint. Two lock loans, exact version-two
//! frames, bounded waits and owned child teardown are shared. The single
//! retained physical owner keeps its complete Broker custody binding; purpose
//! modules still own credential/image/MAC/service checks, protected journal
//! schemas, reconciliation and NV scope.
//! No public or injected transport factory exists here.

pub(crate) mod framing;
pub(crate) mod child;
pub(crate) mod physical;

#[allow(
    dead_code,
    reason = "Host input admission has no physical coordinator or activation"
)]
mod host;

mod floor;

use floor::{
    HostSidecarStoreV1, HostSuffixPreflightV1, host_finalize_transaction,
    host_initial_transaction, host_prepare_transaction,
};

pub(crate) use floor::{
    BrokerSidecarStoreV1, CHECKPOINT_KEY, FinalSuffixPreflightV1, INTENT_KEY,
    StoredBrokerFloorV1, TRANSACTION_KEY, sidecar_limits,
};

// Sibling owners share only canonical DATA, never physical or durable permits.
pub(crate) use floor::{
    CHECKPOINT_BYTES, FloorCheckpointV1, FloorCutV1, FloorEndpointV1, FloorErrorV1,
    FloorIntentV1, FloorProfileV1, FloorRecoveryV1, HostFloorCheckpointDataV1,
    HostFloorIntentDataV1, INTENT_BYTES, NV_ATTRIBUTES_DEFINED, NV_ATTRIBUTES_WRITTEN,
    PROFILE_BYTES, broker_cut_from_records_v1, broker_transaction_digest_v1, hash_parts,
    reconcile_floor_v1, reconcile_host_floor_data_v1, sidecar_sequence_v1, successor_sequence,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NvCustodyEndpointV1 {
    ControllerStorageClient,
    StorageBroker,
    RuntimeDeployment,
}

impl NvCustodyEndpointV1 {
    pub(crate) const fn nv_index(self) -> u32 {
        match self {
            Self::ControllerStorageClient => 0x0180_a046,
            Self::StorageBroker => 0x0180_a047,
            Self::RuntimeDeployment => 0x0180_a055,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum NvCustodyErrorV1 {
    #[error("invalid private TPM carrier framing")]
    Encoding,
    #[error("private TPM carrier provisioning mismatch")]
    Provisioning,
    #[error("private TPM carrier unavailable")]
    Unavailable,
}
