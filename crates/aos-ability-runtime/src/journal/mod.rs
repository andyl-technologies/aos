//! Versioned durable journal framing and prefix recovery.
//!
//! Each record is encoded as a fixed binary header followed by a canonical
//! JSON body:
//!
//! ```text
//! magic | version | flags | body length | sequence | previous digest | body digest | header digest | body
//! ```
//!
//! The frame digest covers the complete header and body. Its value becomes the
//! next frame's `previous digest`, making interior record removal, reordering,
//! or replacement detectable. Detecting loss of an entire valid suffix requires
//! the caller to retain the expected head digest separately. A partial final
//! header or body is a torn tail. Any invalid complete frame is corruption and
//! is retained for investigation.

mod file;
mod frame;

pub use file::{FileJournal, JournalOpenResult};
pub use frame::{JournalError, JournalLimits, JournalPayload, JournalRecord, RecoveryReport};
