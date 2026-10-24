//! Retains the original planned ACK registration operands as ordinary data.

use crucible_node_format::{ExtensionSelection, Id, IdSet};

/// Selects one full planned controller registration for preparation only.
///
/// The Source derives session and incarnation from its original binding. It
/// checks these planned values against the actual post-Hello authority before
/// any proof signature. Construction or deserialization grants no authority.
pub struct PacketCompleteAckHostRegistrationPlan {
    /// Names the independently planned host-local physical connection.
    pub connection_id: Id,
    /// Retains the exact mutually selected feature roster expected after Hello.
    pub features: IdSet,
    /// Retains complete typed extension selections expected after Hello.
    pub extensions: Vec<ExtensionSelection>,
    /// Names the exact sorted envelope-extension roster expected after Hello.
    pub envelope_extensions: Vec<String>,
}
