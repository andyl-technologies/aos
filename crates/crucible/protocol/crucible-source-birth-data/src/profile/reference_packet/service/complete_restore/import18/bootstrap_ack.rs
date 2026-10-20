//! Shares the original immutable protocol identifiers without authority.

/// Requires explicit negotiation before the profile-specific bootstrap method.
pub const NATIVE_IMPORT18_BOOTSTRAP_FEATURE: &str =
    "source-owned.packet-native-import-bootstrap/18";

/// Names the sole new request proof key, explicitly selected by import18.
pub const NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF: &str =
    "source-owned.packet-native-import-bootstrap-ack-proof/18";

/// Names the sole new correlated response receipt key.
pub const NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT: &str =
    "source-owned.packet-native-import-bootstrap-ack-receipt/18";
