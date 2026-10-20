//! Redacts failures crossing the configured credential and repository boundary.

use std::{fmt, io};

use terrane_sdk::{
    config::local_repository::LocalOpenError, repository::Error as RepositoryError, role::RoleError,
};

/// Identifies the failed configuration check or native startup phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureKind {
    /// Explicit role sources disagree or select no role.
    RoleSelection,
    /// A process role other than `serve` requested repository ownership.
    ServeOnly,
    /// Native host-tier composition is not implemented by this adapter.
    HostTierUnavailable,
    /// The store is not one exact local file-bucket leaf.
    UnsupportedStore,
    /// Existing local authority and policy inputs were not supplied.
    MissingLocalTrust,
    /// No SDK snapshot was requested.
    EmptyExposures,
    /// Instance credentials require a different role composition.
    InstanceCredentialsUnavailable,
    /// An exposure is not the compiled SDK surface.
    UnavailableSurface,
    /// An exposure requests unsupported consistency, writes or options.
    UnsupportedPresentation,
    /// A native path is not canonical, absolute and non-root.
    InvalidPath,
    /// Presentation endpoints overlap each other or repository state.
    OverlappingEndpoint,
    /// A credential requires an unsupported provider.
    UnsupportedCredentialReference,
    /// A Tokio executor already exists on the calling thread.
    ExistingRuntime,
    /// Initial irreversible kernel confinement failed.
    Confinement,
    /// The retained kernel receipt no longer validates.
    ConfinementChanged,
    /// Creation of the native executor failed.
    Runtime,
    /// Existing repository authority or state could not be reopened.
    RepositoryOpen,
    /// Whole-list credential, authority or schema preparation failed.
    Preparation,
    /// Physical SDK presentation failed.
    Presentation,
    /// SDK completion, draining or stopping failed.
    Completion,
}

/// Reports a startup failure without exposing credential bytes or source text.
///
/// The underlying typed failure is retained privately. Its diagnostic boundary
/// deliberately stops at a redacted source: repository errors and parser text
/// must never become a capability disclosure through `Display`, `Debug` or an
/// error-chain formatter.
pub struct Error {
    kind: FailureKind,
    cause: Option<Cause>,
}

impl Error {
    pub(super) const fn refused(kind: FailureKind) -> Self {
        Self { kind, cause: None }
    }

    pub(super) fn role(cause: RoleError) -> Self {
        Self {
            kind: FailureKind::RoleSelection,
            cause: Some(Cause::Role(cause)),
        }
    }

    pub(super) fn io(kind: FailureKind, cause: io::Error) -> Self {
        Self {
            kind,
            cause: Some(Cause::Io(cause)),
        }
    }

    pub(super) fn local(cause: LocalOpenError) -> Self {
        Self {
            kind: FailureKind::RepositoryOpen,
            cause: Some(Cause::Local(cause)),
        }
    }

    pub(super) fn repository(kind: FailureKind, cause: RepositoryError) -> Self {
        Self {
            kind,
            cause: Some(Cause::Repository(cause)),
        }
    }

    /// Returns the failed check or native phase without private diagnostics.
    pub const fn kind(&self) -> FailureKind {
        self.kind
    }

    /// Returns the native I/O category when the immediate cause carries one.
    pub fn io_kind(&self) -> Option<io::ErrorKind> {
        self.cause.as_ref().and_then(Cause::io_kind)
    }

    /// Reports whether startup attempted irreversible process confinement.
    ///
    /// After such a failure the caller must terminate the process; retrying a
    /// different role or runtime in that process is not supported.
    pub const fn requires_process_exit(&self) -> bool {
        matches!(
            self.kind,
            FailureKind::Confinement
                | FailureKind::ConfinementChanged
                | FailureKind::Runtime
                | FailureKind::RepositoryOpen
                | FailureKind::Preparation
                | FailureKind::Presentation
                | FailureKind::Completion
        )
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfiguredSdkError")
            .field("kind", &self.kind)
            .field("io_kind", &self.io_kind())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.kind {
            FailureKind::RoleSelection => "configured SDK role selection failed",
            FailureKind::ServeOnly => "only the serve role may run configured SDK snapshots",
            FailureKind::HostTierUnavailable => {
                "configured SDK startup does not compose a native host tier"
            }
            FailureKind::UnsupportedStore => {
                "configured SDK startup requires one exact local file-bucket leaf"
            }
            FailureKind::MissingLocalTrust => {
                "explicit existing local repository trust is required"
            }
            FailureKind::EmptyExposures => "configured SDK startup requires at least one exposure",
            FailureKind::InstanceCredentialsUnavailable => {
                "configured SDK startup does not resolve instance credentials"
            }
            FailureKind::UnavailableSurface => "configured SDK surface is unavailable",
            FailureKind::UnsupportedPresentation => "configured SDK presentation is unsupported",
            FailureKind::InvalidPath => {
                "configured SDK path must be canonical, absolute and non-root"
            }
            FailureKind::OverlappingEndpoint => "configured SDK endpoint overlaps another resource",
            FailureKind::UnsupportedCredentialReference => {
                "configured SDK credentials require absolute native file references"
            }
            FailureKind::ExistingRuntime => {
                "configured SDK startup requires a fresh synchronous process"
            }
            FailureKind::Confinement => {
                "configured SDK kernel confinement failed; terminate the process"
            }
            FailureKind::ConfinementChanged => {
                "configured SDK kernel confinement changed; terminate the process"
            }
            FailureKind::Runtime => "configured SDK executor creation failed",
            FailureKind::RepositoryOpen => "configured SDK repository reopening failed",
            FailureKind::Preparation => "configured SDK exposure preparation failed",
            FailureKind::Presentation => "configured SDK presentation failed",
            FailureKind::Completion => "configured SDK snapshot completion failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause
            .as_ref()
            .map(|cause| cause as &(dyn std::error::Error + 'static))
    }
}

enum Cause {
    Io(io::Error),
    Role(RoleError),
    Local(LocalOpenError),
    Repository(RepositoryError),
}

impl Cause {
    fn io_kind(&self) -> Option<io::ErrorKind> {
        match self {
            Self::Io(error)
            | Self::Local(LocalOpenError::Repository(RepositoryError::Io(error)))
            | Self::Repository(RepositoryError::Io(error)) => Some(error.kind()),
            Self::Role(error) => {
                // Role errors contain only closed role names, but their source
                // still stops at the same deliberate redaction boundary.
                let _ = error;
                None
            }
            Self::Local(_) | Self::Repository(_) => None,
        }
    }
}

impl fmt::Debug for Cause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RedactedConfiguredSdkCause")
    }
}

impl fmt::Display for Cause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("private configured SDK failure (diagnostics redacted)")
    }
}

impl std::error::Error for Cause {}
