//! Owns Mount's fixed native journal, startup capture and private custody issuers.
//!
//! The journal retains the actual canonical writer and its resident replay index.
//! Startup classifies the real inherited descriptor table against protected
//! history before releasing purpose-limited lenders. Root5, Query6 and kind2/5
//! readbacks remain physical evidence; Security separately owns signing and
//! Session authority, and Mount separately owns its installed live table.
//!
//! Canonical framing, replay, append and currentness mechanics remain in their
//! existing lower packages. This crate creates no Root receiving account,
//! Source signer, Session, effect permission or replacement native identity.

#![cfg(target_os = "linux")]

mod journal;
pub mod mount_manager_startup;

pub use journal::*;
pub use mount_manager_startup::*;

// Moved private issuer bodies keep their existing short internal name. The
// public owner is the concrete MountJournalV1, with no Domain Journal wrapper.
use journal::MountJournalV1 as Journal;
use journal::MountJournalErrorV1 as JournalError;
