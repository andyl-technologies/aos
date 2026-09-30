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
