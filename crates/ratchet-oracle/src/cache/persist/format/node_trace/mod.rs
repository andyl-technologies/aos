//! Demand-node verifying trace payload and append log format adapters.

mod log;
mod payload;

pub use log::{PersistNodeTraceLog, PersistNodeTraceLogEntry};
pub use payload::PersistNodeTracePayload;
