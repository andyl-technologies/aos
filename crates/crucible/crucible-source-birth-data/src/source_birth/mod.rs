//! Provides pure SourceBirth/profile codecs and candidate-bank derivation.
//!
//! The literal codec preserves actual JSON values without interpreting serde
//! marker keys. The request codec streams secret-free operands into the contained
//! worker; the derivation follows the original validation and serialization order.
//! Result verification checks ordinary bytes and correlations only. Installation,
//! process containment, Source custody and native admission remain upper owners.

/// Streams literal Values with guarded partial-read ownership.
pub mod literal_value;

/// Borrows the original SourceBirth and registration serialization fields.
pub mod views;

/// Runs the contained child's pure candidate-bank derivation schedule.
pub mod derive;

/// Verifies the closed worker result framing without issuing authority.
pub mod result_wire;

/// Streams the original secret-free request and executes one contained request.
pub mod request_wire;
