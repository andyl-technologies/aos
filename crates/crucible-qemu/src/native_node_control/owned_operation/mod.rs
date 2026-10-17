//! Bounded durable custody of original native command retirement evidence.
//!
//! This private host prototype stores complete original records before requesting
//! native slot retirement. It grants no native authority: a copied proposal or
//! receipt is correlation data until the owning adapter validates it through the
//! genuine original native retirement operation. The storage state has no method
//! that dispatches a new command.
//!
//! Reservation precedes command exposure. Terminal history precedes retirement;
//! receipt durability precedes host slot turnover. Restore retains an unfinished
//! reservation or retirement and rejects a torn tail rather than forgetting it.
//! One command occupies memory; every archived record remains on disk within the
//! declared lifetime budget. Exhaustion fences new work without evicting history.

// SPDX-License-Identifier: Apache-2.0

mod child;
mod codec;
mod evidence;
mod initial_driver;
mod initial_store;
mod operation;
mod session;
mod session_creation;
mod store;
mod transport;

pub use child::{NativeOwnedPrefixOperation, NativeOwnedPrefixRefusal};

pub use evidence::{PrefixEvidence, TerminalEvidence};
pub use initial_driver::{
    OriginalInitialEvidence, OriginalPreparationDriver, OriginalPreparationProgress,
};
pub use initial_store::{InitialEvidenceBudget, InitialEvidenceStore};
pub use operation::OriginalPrefixJournal;
pub use session::{NativeOwnedPrefixSession, NativePrefixStartFailure};
pub use session_creation::NativeSessionCreateFailure;
pub use store::{Archive, ArchiveBudget, StoredOriginal, TurnoverState};
pub use transport::{
    OriginalOperationDriver, OriginalOperationEndpoint, OriginalOperationProgress,
};

use std::{fmt, io};

/// Identifies a storage or original-correlation failure that fences turnover.
#[derive(Debug)]
pub enum ArchiveError {
    /// Preserves the underlying filesystem failure.
    Io(io::Error),
    /// Preserves the actual prepared native endpoint failure.
    Transport(crate::native_node_control::NativeQemuControlError),
    /// Reports a foreign original, an invalid transition or a changed exact retry.
    Conflict,
    /// Reports a declared lifetime, record or prefix budget being exhausted.
    Budget,
    /// Reports malformed, truncated or altered durable bytes.
    Corrupt,
    /// Reports that a failed append leaves this owner unable to prove durability.
    Failed,
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "native command archive I/O: {error}"),
            Self::Transport(error) => write!(f, "native command endpoint: {error}"),
            Self::Conflict => f.write_str("native command archive original correlation conflict"),
            Self::Budget => f.write_str("native command archive declared budget exhausted"),
            Self::Corrupt => {
                f.write_str("native command archive has uncertain or corrupt evidence")
            }
            Self::Failed => {
                f.write_str("native command archive owner retains uncertain durability")
            }
        }
    }
}

impl std::error::Error for ArchiveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Transport(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for ArchiveError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<crucible_protocol::node_control::NativeCommandError> for ArchiveError {
    fn from(_: crucible_protocol::node_control::NativeCommandError) -> Self {
        Self::Conflict
    }
}
