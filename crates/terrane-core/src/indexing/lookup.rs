//! Queries canonical primary, occurrence and gap data after complete preparation.
//!
//! Immutable candidate discovery and local route traversal expose their work
//! separately from preparation and the caller's current occurrence checks.
//! Primary keys retain the existing registered format:
//!
//! ```text
//! canonical-CBOR(value) || object-identity[32]
//! ```
