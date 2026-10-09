//! Names signed layer inputs and their independently selected current policy refs.

use terrane_core::identity::Digest;

/// Names one signed input and the current policy used to authorize its use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OverlayInput {
    /// Current policy reference against which source Read permission is checked.
    pub reference: String,
    /// Exact signed source commit whose root is used at this layer position.
    pub commit: Digest,
}
