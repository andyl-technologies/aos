//! Versioned durable journal framing and prefix recovery.
//!
//! Each record is encoded as a fixed binary header followed by a canonical
//! JSON body:
//!
//! ```text
//! magic | version | flags | body length | sequence | body digest | header digest | body
//! ```
//!
//! The header digest and body digest detect damaged frames, and the sequence
//! field detects removed or reordered interior frames. A partial final header
//! or body is a torn tail. Any invalid complete frame is corruption and is
//! retained for investigation. Journals written in the earlier chained format
//! remain readable; see the frame module for both layouts.

mod file;
mod frame;

pub use file::{FileJournal, JournalOpenResult, JournalReader, JournalSnapshot};
pub use frame::{JournalError, JournalLimits, JournalPayload, JournalRecord, RecoveryReport};
