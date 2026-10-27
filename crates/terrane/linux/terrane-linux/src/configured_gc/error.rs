//! Preserves configuration, confinement and native collector failures.

use std::{fmt, io};

use terrane_sdk::{
    config::{ConfigError, local_repository::LocalOpenError},
    gc::runner::CollectionError,
    role::RoleError,
};

/// Reports refused startup or failed configured local collection.
#[derive(Debug)]
pub enum Error {
    /// Preserves explicit role selection mismatch or absence.
    Role(RoleError),
    /// Rejects an unsupported whole composition or exhausted scheduling deadline.
    Refused(&'static str),
    /// Preserves validated scheduling or publication-window diagnostics.
    Configuration(ConfigError),
    /// Preserves confinement, executor, signal, notification or randomness failures.
    Io(io::Error),
    /// Preserves public-key and original native maintenance-reopen failures.
    Repository(LocalOpenError),
    /// Preserves original collector, lease and protected effect failures.
    Collection(CollectionError),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Role(error) => error.fmt(formatter),
            Self::Refused(message) => write!(formatter, "local collector refused: {message}"),
            Self::Configuration(error) => error.fmt(formatter),
            Self::Io(error) => error.fmt(formatter),
            Self::Repository(error) => error.fmt(formatter),
            Self::Collection(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Role(error) => Some(error),
            Self::Refused(_) => None,
            Self::Configuration(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Repository(error) => Some(error),
            Self::Collection(error) => Some(error),
        }
    }
}

impl From<CollectionError> for Error {
    fn from(error: CollectionError) -> Self {
        Self::Collection(error)
    }
}
