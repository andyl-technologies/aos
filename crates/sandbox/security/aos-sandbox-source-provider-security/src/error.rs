//! Redacted errors for protected SourceProvider custody.

/// Reports a fail-closed protected-state or kernel-evidence failure.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SourceProviderSecurityError {
    /// A fixed protected record is malformed.
    #[error("invalid protected SourceProvider {object}: {field}")]
    Format {
        /// Stable object label.
        object: &'static str,
        /// Stable field class.
        field: &'static str,
    },
    /// A protected directory path is not fixed and normalized.
    #[error("invalid protected SourceProvider directory path")]
    DirectoryPath,
    /// A protected filesystem operation failed.
    #[error("protected SourceProvider {object} {operation} failed")]
    Filesystem {
        /// Stable object label.
        object: &'static str,
        /// Stable operation label.
        operation: &'static str,
    },
    /// Protected metadata violates ownership, type, mode, link, or size policy.
    #[error("protected SourceProvider {object} metadata is invalid")]
    Metadata {
        /// Stable object label.
        object: &'static str,
    },
    /// Directory contents differ from the exact role-local file set.
    #[error("protected SourceProvider directory contents are invalid")]
    DirectoryContents,
    /// A role-local secret differs from its protected key pin.
    #[error("protected SourceProvider {object} key material is invalid")]
    KeyMaterial {
        /// Stable key-role label.
        object: &'static str,
    },
    /// Another custody instance already owns this protected generation.
    #[error("protected SourceProvider manifest is already in use")]
    AlreadyInUse,
    /// Protected configuration or retained file identity changed.
    #[error("protected SourceProvider configuration changed")]
    Currentness,
    /// The retained process execution or kernel boot changed.
    #[error("protected SourceProvider execution changed")]
    ExecutionChanged,
    /// Kernel entropy acquisition failed its bounded policy.
    #[error("SourceProvider kernel entropy acquisition failed")]
    Entropy,
    /// A process-exclusive nonce counter reached its terminal value.
    #[error("SourceProvider hello nonce space is exhausted")]
    NonceExhausted,
    /// Kernel descriptor observation was incomplete or inconsistent.
    #[error("SourceProvider descriptor observation failed")]
    DescriptorObservation,
    /// Peer, record-subject, or application transcript continuity failed.
    #[error("SourceProvider session continuity failed")]
    SessionContinuity,
    /// Required death evidence was not conclusive.
    #[error("SourceProvider process death is not established")]
    DeathNotEstablished,
    /// A previous authority-sensitive failure permanently poisoned this object.
    #[error("SourceProvider protected state is permanently poisoned")]
    Poisoned,
}

impl SourceProviderSecurityError {
    pub(crate) const fn format(object: &'static str, field: &'static str) -> Self {
        Self::Format { object, field }
    }

    pub(crate) const fn filesystem(object: &'static str, operation: &'static str) -> Self {
        Self::Filesystem { object, operation }
    }
}
