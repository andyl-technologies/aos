//! Names the existing deployment and administrative-pin journal DATA keys.
//!
//! These byte strings are comparison and encoding DATA. They are not a closed
//! Root-key grammar, protected provenance, a currentness proof or permission to
//! mutate a journal. Actual native role owners retain their existing gates.

/// Names the protected deployment-head record in the DesiredState namespace.
pub const HEAD_KEY: &[u8] = b"\0aos-policy-deployment-head-v1\0";

/// Names the saved deployment signer-pin pair in DesiredState.
pub const SIGNER_PINS_KEY: &[u8] = b"\0aos-policy-signer-pins-v1\0";

/// Names the administrative Controller hold public pin in DesiredState.
pub const CONTROLLER_HOLD_PIN_KEY: &[u8] = b"\0aos-policy-controller-hold-pin-v1\0";

/// Names the administrative Source hold public pin in DesiredState.
pub const SOURCE_HOLD_PIN_KEY: &[u8] = b"\0aos-policy-source-hold-pin-v1\0";
