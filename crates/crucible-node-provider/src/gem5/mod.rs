//! Authenticated native gem5 control beneath the common CNP custody journal.
//!
//! The private driver retains actual pre-event receipts and process-image
//! lineage. Native boundary mechanics do not qualify a complete CPU/device
//! profile: public exact admission requires installed clock/input qualification
//! and independently authenticated complete native custody. Complete modeled
//! diagnostics and audited whole-process capture are distinct proof mechanisms;
//! partial diagnostic coverage never becomes a claim of complete typed state.

mod images;
mod journal;
mod process;
mod protocol;
pub mod service;

pub use images::*;
pub use journal::*;
pub use process::*;
pub use protocol::*;

#[cfg(test)]
mod tests;
