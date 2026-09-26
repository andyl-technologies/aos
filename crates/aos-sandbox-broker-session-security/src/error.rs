//! Redacted errors for protected Broker Session Authentication state.
//!
//! Errors expose stable object and operation labels only. They intentionally
//! omit configured paths, file bytes, seeds, public-key fingerprints, and
//! manifest digests.

/// Reports a fail-closed protected-state or entropy failure.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BrokerSessionSecurityError {
    /// A fixed manifest field or encoding is invalid.
    #[error("invalid Broker Session Authentication security manifest: {field}")]
    Manifest {
        /// Stable field class, never content from the manifest.
        field: &'static str,
    },
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
    pub(crate) const fn manifest(field: &'static str) -> Self {
        Self::Manifest { field }
    }

    pub(crate) const fn filesystem(object: &'static str, operation: &'static str) -> Self {
        Self::Filesystem { object, operation }
    }
}
