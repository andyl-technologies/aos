//! Borrows the actual original Unix observation before installed issuance.
//!
//! Only the owning runner constructs this witness. Public report bytes remain
//! portable data; this short-lived view proves which report the runner actually
//! retained from its original transport attempt, without granting class authority.

use crucible_node_contract::ContentRef;

use super::ProtocolObservation;

/// Borrows a privately constructed original protocol observation and its body.
///
/// It cannot be constructed, cloned or decoded by a provider. Installed policy
/// still authenticates the source fixture, actual peer and independent oracle;
/// this view supplies original runner custody rather than an accepted verdict.
pub struct OriginalProtocolWitness<'a> {
    observation: &'a ProtocolObservation,
    reference: &'a ContentRef,
    bytes: &'a [u8],
}

impl<'a> OriginalProtocolWitness<'a> {
    pub(super) fn new(
        observation: &'a ProtocolObservation,
        reference: &'a ContentRef,
        bytes: &'a [u8],
    ) -> Self {
        Self {
            observation,
            reference,
            bytes,
        }
    }

    /// Borrows the complete original report and independently installed scope.
    pub fn observation(&self) -> &ProtocolObservation {
        self.observation
    }

    /// Borrows the full reference to the exact retained canonical body.
    pub fn reference(&self) -> &ContentRef {
        self.reference
    }

    /// Borrows all original canonical observation bytes without copying them.
    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }
}
