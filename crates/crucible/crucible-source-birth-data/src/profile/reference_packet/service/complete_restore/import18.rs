//! Shares import18 immutable roster, phase and prospective registration DATA.
//!
//! No constructor in this module authenticates a live connection or grants a
//! native operation; those original authority owners remain in Transport.

/// Defines the unchanged bootstrap acknowledgement identifiers.
pub mod bootstrap_ack;
/// Defines the unchanged versioned import18 identifiers.
pub mod definitions;
/// Defines the unchanged Hello roster and pure from-fields constructor.
pub mod hello;
/// Defines the unchanged inert import18 phase vocabulary.
pub mod phase;
/// Defines the unchanged inert stage identifier.
pub mod stage_contract;

pub use definitions::{NATIVE_IMPORT18_EXTENSION, NATIVE_IMPORT18_RESTORED_RECORD_SCHEMA};
pub use phase::PacketNativeImport18Phase;
pub use stage_contract::NATIVE_IMPORT18_STAGE_SELECTION;
