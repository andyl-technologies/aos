//! Returns unsubmitted inputs without discarding accepted physical custody.

use std::{fmt, io};
use terrane_format::identity::Descriptor;
use terrane_sdk::{pack::PackId, store::ChunkPosition};

/// Reports a refused submission or a physically accepted chunk command failure.
pub enum NativeChunkAdmissionError {
    /// Returns untouched input when no physical command was accepted.
    Unsubmitted {
        /// Actual validation or bounded-queue error.
        error: io::Error,
        /// Untrusted original content declaration.
        descriptor: Descriptor,
        /// Original chunk boundary context.
        position: ChunkPosition,
        /// Original untrusted encoded bytes.
        encoded: Vec<u8>,
    },
    /// Reports failure whose resources remain owned by the physical executor.
    Accepted(io::Error),
}

/// Reports a refused submission or a physically accepted metadata command failure.
pub enum NativeMetadataAdmissionError {
    /// Returns untouched inputs when no physical command was accepted.
    Unsubmitted {
        /// Actual validation or bounded-queue error.
        error: io::Error,
        /// Original untrusted canonical pack identifier.
        expected_id: PackId,
        /// Original untrusted complete pack bytes.
        pack: Vec<u8>,
        /// Original untrusted detached index bytes.
        detached_index: Vec<u8>,
    },
    /// Reports failure whose resources remain owned by the physical executor.
    Accepted(io::Error),
}

macro_rules! admission_error {
    ($name:ident) => {
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    Self::Unsubmitted { error, .. } => {
                        f.debug_tuple("Unsubmitted").field(error).finish()
                    }
                    Self::Accepted(error) => f.debug_tuple("Accepted").field(error).finish(),
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    Self::Unsubmitted { error, .. } | Self::Accepted(error) => {
                        fmt::Display::fmt(error, f)
                    }
                }
            }
        }

        impl std::error::Error for $name {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                match self {
                    Self::Unsubmitted { error, .. } | Self::Accepted(error) => Some(error),
                }
            }
        }
    };
}

admission_error!(NativeChunkAdmissionError);
admission_error!(NativeMetadataAdmissionError);
