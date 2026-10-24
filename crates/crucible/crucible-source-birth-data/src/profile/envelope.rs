//! Defines inert protocol operation vocabulary, never a dispatch authority.

use serde::{Deserialize, Serialize};

/// Selects a baseline or explicitly negotiated profile-specific operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    /// Negotiates protocol, limits and admitted connection identity.
    Hello,
    /// Enumerates supported profiles without realization or execution.
    Discover,
    /// Prepares stopped resources under bounded allowances.
    Realize,
    /// Installs the host-authenticated realized binding.
    Admit,
    /// Authenticates the negotiated import18 bootstrap without realizing a model.
    ///
    /// The exact versioned feature, dedicated Source/native bootstrap owner and
    /// profile body decoder are required. Ordinary method dispatch refuses it.
    NativeImport18Bootstrap,
    /// Arms owner readiness while withholding execution.
    Activate,
    /// Retains an original admitted input batch.
    Input,
    /// Reads bounded observations without releasing staged effects.
    Observe,
    /// Registers one effectful operation and its original identity.
    Begin,
    /// Reads the retained state of an existing operation.
    Poll,
    /// Requests cancellation while retaining the eventual completion duty.
    Cancel,
    /// Settles the original quantized window's visibility obligations.
    QuantumClose,
    /// Publishes the complete all-owner activation transaction.
    WorldActivate,
    /// Contains an unactivated preparation transaction.
    Abort,
    /// Retires consumed outcomes without permitting identity reuse.
    Retire,
    /// Starts a bounded inert content transfer.
    BlobBegin,
    /// Adds an authenticated transfer's next bounded chunk.
    BlobChunk,
    /// Verifies complete transferred content before its use.
    BlobFinish,
    /// Discharges resources after reaping or authenticated transfer.
    Release,
    /// Notifies retained operation status without settling its original request.
    OperationUpdate,
    /// Notifies the availability of bounded retained observations.
    ObservationReady,
    /// Notifies a provider failure without implying physical containment.
    ProviderFault,
}

/// Classifies a stream message without granting effect authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    /// Starts or retries an origin-scoped request.
    Request,
    /// Reports the original request's retained status or result.
    Response,
    /// Reports an unsolicited observation subject to its visibility contract.
    Event,
}

/// States registered operation progress independently of transport delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    /// Proves the operation has not started.
    NotStarted,
    /// Retains running operation custody.
    Running,
    /// Retains completed operation custody.
    Completed,
    /// Discloses unresolved native effects requiring containment.
    Unknown,
}
