//! Redacted errors for protected Broker Session Authentication state.
//!
//! Errors expose stable object and operation labels only. They intentionally
//! omit configured paths, file bytes, seeds, public-key fingerprints, and
//! manifest digests.

use aos_sandbox_broker_session_protocol::manifest::BrokerSessionManifestErrorV1;
use aos_sandbox_protocol::authenticated_session::historical_checkpoint::HistoricalCheckpointErrorV1;

/// Reports a fail-closed protected-state or entropy failure.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BrokerSessionSecurityError {
    /// A fixed manifest field or encoding is invalid.
    #[error("invalid Broker Session Authentication security manifest: {field}")]
    Manifest {
        /// Stable field class, never content from the manifest.
        field: &'static str,
    },
    /// The signed hello transcript did not negotiate the requested method.
    #[error("broker method is not negotiated")]
    UnnegotiatedMethod,
    /// A protected endpoint path is not an absolute fixed path.
    #[error("invalid protected endpoint directory path")]
    DirectoryPath,
    /// A protected filesystem operation failed.
    #[error("protected {object} {operation} failed")]
    Filesystem {
        /// Stable object label.
        object: &'static str,
        /// Stable operation label.
        operation: &'static str,
    },
    /// A protected object has an invalid type, owner, mode, link count, or size.
    #[error("protected {object} metadata is invalid")]
    Metadata {
        /// Stable object label.
        object: &'static str,
    },
    /// A forbidden opposite-role secret name exists.
    #[error("opposite-role protected secret is present")]
    OppositeRoleSecret,
    /// Another endpoint already holds the manifest lock.
    #[error("protected manifest is already in use")]
    AlreadyInUse,
    /// A local signing seed or key identifier does not match the manifest.
    #[error("protected {object} key material does not match the manifest")]
    KeyMaterial {
        /// Stable role label.
        object: &'static str,
    },
    /// The process or kernel incarnation changed.
    #[error("protected endpoint execution identity changed")]
    ExecutionChanged,
    /// Revalidation detected any protected-state change.
    #[error("protected endpoint currentness check failed")]
    Currentness,
    /// This same selected Session retained the actual native transaction error.
    #[error("protected captured journal mutation retained its native failure")]
    CapturedJournalMutation {
        /// Actual transaction whose entered native return selected the cause.
        transaction: [u8; 16],
    },
    /// The same selected Controller physical owner retained its first cause.
    #[error("protected floor retained Controller physical operation failed")]
    ControllerPhysicalFloor,
    /// A selected floor writer comparison retained its precise native cause.
    #[error("protected floor retained journal currentness observation failed")]
    FloorRevalidation {
        /// Fixed failed/owed observation slot in the originating journal owner.
        observation: usize,
    },
    /// A selected endpoint observation retained its precise native cause.
    ///
    /// The index is comparison DATA within the same protected endpoint. It
    /// conveys neither currentness nor permission to observe another endpoint.
    #[error("protected endpoint retained currentness observation failed")]
    EndpointRevalidation {
        /// Fixed resident observation slot in the originating endpoint.
        observation: usize,
    },
    /// Kernel entropy acquisition failed its bounded policy.
    #[error("kernel entropy acquisition failed")]
    Entropy,
    /// A nonce counter reached its terminal value.
    #[error("protected endpoint nonce space is exhausted")]
    NonceExhausted,
    /// A previous failure permanently poisoned the endpoint.
    #[error("protected endpoint is permanently poisoned")]
    Poisoned,
}

impl BrokerSessionSecurityError {
    /// Constructs a redacted manifest failure from its stable field class.
    pub const fn manifest(field: &'static str) -> Self {
        Self::Manifest { field }
    }

    pub(crate) const fn filesystem(object: &'static str, operation: &'static str) -> Self {
        Self::Filesystem { object, operation }
    }
}

impl From<HistoricalCheckpointErrorV1> for BrokerSessionSecurityError {
    fn from(_: HistoricalCheckpointErrorV1) -> Self {
        // Historical DATA failures retain the protected owner's redacted class.
        Self::Currentness
    }
}

impl From<BrokerSessionManifestErrorV1> for BrokerSessionSecurityError {
    fn from(error: BrokerSessionManifestErrorV1) -> Self {
        // Canonical DATA failures retain the protected owner's original field class.
        Self::manifest(error.field)
    }
}
