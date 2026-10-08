//! Provides the closed sealed compositions used by the concrete Controller owner.
//!
//! Broker Session Security retains protected files, fixed credentials, native
//! history, and all authentication. These named ports let Controller retain the
//! original opaque custody and inspect inert DATA; they expose no scalar signer,
//! caller-selected root, verification context, or replacement authority. Fixed
//! lifecycle completions and online Nix recipes preserve their existing lower
//! authentication and native commit engines.

mod history;
mod lifecycle;
#[cfg(feature = "online-nix")]
mod online;

pub use history::{
    ArchivedStorageInventoryHeadDataV1, HistoricalAtomicStorageHistoryDataV1,
    HistoricalAtomicStorageHistoryV1, HistoricalAtomicStorageHistoryViewV1,
};
#[cfg(feature = "online-nix")]
pub use online::{
    ControllerOnlineNixEndpointCustodyV1, ControllerOnlineNixHandshakeErrorV1,
    ControllerOnlineNixHandshakeProgressV1, ControllerOnlineNixHandshakeV1,
    ControllerOnlineNixHelloV1, ControllerOnlineNixNativeRequestCustodyV1,
    ControllerOnlineNixOutcomeOpeningV1,
    ControllerOnlineNixPreparedRequestV1, ControllerOnlineNixProvisionV1,
    ControllerOnlineNixSessionV1, ControllerOnlineNixVerifiedHandshakeV1,
    OnlineTransportFailureV1,
};

pub use crate::dormant_handshake::{
    ExecutionPublicationReceiveCustodyV1, ProtectedStorageSessionBindingV1,
    check_production_deadline, wait_for_handshake_readiness,
};
pub use crate::handshake::{
    OriginalBrokerColdDeadlineV1, OutputCurrentnessBoundaryV1,
    RetainedStorageColdOpenV1, protected_boottime_nanoseconds,
};
pub use crate::handshake::output_registration_continuation::{
    HeldOutputPreparationV1, OriginalOutputClientFlightV1, OutputPreparationClosedV1,
    OutputPreparationCustodyV1,
};
pub use crate::ownership_clock::{CLOCK_PROVENANCE, sample_ownership_clock};
pub use crate::production_startup::{ControllerStartupContinuationV1, Pid1LaunchImageV1};
pub use crate::recovery::{
    ArchivedStorageInventoryHeadV1, AuthenticatedOriginalHostArgumentArchiveV1,
    AuthenticatedOriginalHostNoApplyJoinV1, RetainedFailedCreateOriginalsDataV3,
};
#[cfg(feature = "online-nix")]
pub use crate::tpm_nv_custody::FloorErrorV1;
