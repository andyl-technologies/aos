//! Keeps Source provider snapshots bound to their actual journal and purpose.
//!
//! The private instance payload occupies the same allocation created by the
//! completed ordinary opening. A copied sequence or snapshot cannot construct
//! a writer, challenge view, signing basis, or current Source original.

use std::sync::Arc;

use aos_sandbox_model::RecordNamespace;

/// Identifies the same actual provider or challenge journal allocation.
pub(super) struct JournalAuthorityInstance;

/// Distinguishes the existing closed Source provider claim purposes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProtectedAuthorityScope {
    SingleNamespace,
    SourceProviderNativeTerminal,
    SourceProviderHeldReadOnly,
    SourceOriginalNativeV5,
}

/// Retains one exact Source provider journal instance, sequence, and purpose.
///
/// The actual held authority mints this snapshot after its native checks. Every
/// use must revalidate that same owner; the sequence alone is diagnostic DATA.
#[must_use = "retain the snapshot and revalidate its actual owner at use"]
pub struct ProtectedJournalSnapshot {
    pub(super) instance: Arc<JournalAuthorityInstance>,
    pub(super) namespace: RecordNamespace,
    pub(super) sequence: u64,
    pub(super) scope: ProtectedAuthorityScope,
}

impl ProtectedJournalSnapshot {
    pub(super) fn duplicate_provenance(&self) -> Self {
        Self {
            instance: Arc::clone(&self.instance),
            namespace: self.namespace,
            sequence: self.sequence,
            scope: self.scope,
        }
    }

    /// Returns the retained sequence without granting currentness or mutation.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// Retains exact transaction preflight at its actual protected Source cut.
#[must_use = "a preflight remains tied to its same journal and transaction"]
pub struct ProtectedJournalPreflight {
    pub(super) snapshot: ProtectedJournalSnapshot,
    pub(super) transaction_digest: [u8; 32],
}
