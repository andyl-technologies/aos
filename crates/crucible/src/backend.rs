//! Backend boundary shared by the pure engine and concrete drivers.
//!
//! This module owns the trait and data contracts that backend adapters must
//! implement. Keeping it separate from the execution model prevents QEMU-shaped
//! concepts from leaking into the pure state vocabulary.

use std::error::Error;
use std::fmt;

use crate::{Checkpoint, ContentHash, Icount, NodeId};

/// A VM backend boundary declared by the engine.
pub trait Backend {
    /// Advances the backend to `horizon`.
    ///
    /// # Errors
    ///
    /// Returns a [`BackendError`] when the backend cannot advance to the
    /// requested horizon.
    fn advance_to_horizon(
        &mut self,
        horizon: ExecutionHorizon,
    ) -> Result<AdvanceOutcome, BackendError>;

    /// Reads the backend's current execution fingerprint.
    ///
    /// # Errors
    ///
    /// Returns a [`BackendError`] when the fingerprint cannot be read.
    fn fingerprint(&mut self) -> Result<ExecutionFingerprint, BackendError>;

    /// Delivers deterministic input to the backend.
    ///
    /// This is a backend delivery surface for already-scheduled model events and
    /// guest-host channel replies. It is not a host-side workload generator and
    /// MUST NOT be used to originate application traffic for a scenario.
    ///
    /// # Errors
    ///
    /// Returns a [`BackendError`] when the input cannot be delivered.
    fn deliver_input(&mut self, input: BackendInput) -> Result<(), BackendError>;

    /// Captures a backend checkpoint.
    ///
    /// # Errors
    ///
    /// Returns a [`BackendError`] when snapshot capture fails.
    fn snapshot(&mut self) -> Result<Checkpoint, BackendError>;

    /// Restores a backend checkpoint.
    ///
    /// # Errors
    ///
    /// Returns a [`BackendError`] when the checkpoint cannot be restored.
    fn restore(&mut self, checkpoint: &Checkpoint) -> Result<(), BackendError>;

    /// Shuts the backend down.
    ///
    /// # Errors
    ///
    /// Returns a [`BackendError`] when shutdown fails.
    fn shutdown(&mut self) -> Result<(), BackendError>;
}

/// A horizon to which a backend should advance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExecutionHorizon {
    /// The target instruction count.
    pub icount: Icount,
}

/// The result of advancing a backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AdvanceOutcome {
    /// The backend advanced to the requested horizon.
    ReachedHorizon,
    /// The backend paused before reaching the requested horizon.
    Paused {
        /// The instruction count at which the backend paused.
        at: Icount,
    },
}

/// A backend execution fingerprint.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ExecutionFingerprint {
    /// The fingerprint content address.
    pub hash: ContentHash,
}

/// Deterministic input delivered to a backend.
///
/// This payload represents backend delivery for model-controlled inputs, not a
/// host-side workload generator. Application workload traffic must originate
/// from guest execution and cross modeled devices as ordinary guest/device I/O.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BackendInput {
    /// The target node.
    pub node: NodeId,
    /// The payload bytes.
    pub payload: Vec<u8>,
}

/// A backend-boundary error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackendError {
    /// The backend operation is not implemented by this backend.
    NotImplemented {
        /// The operation whose implementation is deferred.
        operation: &'static str,
    },
    /// The backend rejected a request.
    Rejected {
        /// A deterministic diagnostic message.
        message: String,
    },
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotImplemented { operation } => {
                write!(f, "backend operation {operation} is not implemented yet")
            }
            Self::Rejected { message } => f.write_str(message),
        }
    }
}

impl Error for BackendError {}
